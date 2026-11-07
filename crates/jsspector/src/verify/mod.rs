//! `scan --verify`: confirm a finding by running the scanned app in a throwaway container and
//! sending the request the finding implies. Opt-in; nothing here runs without `--verify`.
//!
//! The work splits in two: [`plan`] and [`payload`] decide what to send and how to recognize a
//! hit, with no I/O (unit-tested directly); [`sandbox`] builds the image, starts the app with no
//! network reach beyond a marker service, sends the requests and tears everything down. A
//! finding the planner cannot drive is reported `skipped` with the reason, never a false
//! "clean".

mod browser;
mod payload;
mod plan;
mod sandbox;

use jss_core::Finding;
use serde::Serialize;

/// What verification concluded about one finding.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum Outcome {
    /// The app reproduced the finding; `how` names the request that did it.
    Verified { how: String, poc: Reproduction },
    /// Every derived request was sent and none tripped the marker.
    NotReproduced { tried: usize },
    /// The finding was not driven; `reason` says why.
    Skipped { reason: String },
}

/// The exact request that reproduced a finding plus a copyable, parameterized command and the
/// signal the sandbox observed. Keeping this in the JSON report makes `verified` independently
/// auditable instead of forcing callers to infer a proof from debug stderr.
#[derive(Debug, Clone, Serialize)]
pub struct Reproduction {
    pub command: String,
    pub method: String,
    pub target: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub evidence: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub response: String,
}

impl Outcome {
    /// A short, stable label for a report property: `verified`, `not-reproduced` or `skipped`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "verified",
            Self::NotReproduced { .. } => "not-reproduced",
            Self::Skipped { .. } => "skipped",
        }
    }
}

/// A finding's verdict, for the report.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    pub class: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

/// How a run should behave when Docker is not reachable.
pub enum Missing {
    /// Mark every finding skipped (the default: `--verify` is best-effort).
    Skip,
    /// Fail the command (`--verify=strict`): the user asked to verify and means it.
    Fail,
}

/// Verifies `findings` against the app rooted at `root`. Returns one verdict per finding, in the
/// same order. Builds at most one HTTP image and one browser image, reused across findings.
pub fn run(
    root: &std::path::Path,
    findings: &[Finding],
    missing: Missing,
) -> Result<Vec<Verdict>, String> {
    // A custom or convention-based router may leave a handler without an inventory entry. For an
    // HTTP finding, try a conservative route derived from a recognized controller/routes tree.
    // A wrong guess can only fail to reproduce; it never creates a verified outcome by itself.
    let owned: Vec<Finding> = findings
        .iter()
        .map(|finding| {
            if finding.entry.is_none() && finding.source.kind == "http" {
                // A conventional routing directory, or — failing that — a route the module registers
                // on a host-provided web-server service (`webServer.register({ path, handler })`), for
                // a plug-in that publishes no inventory entry. Either only creates a request
                // candidate; a wrong guess can still only fail to reproduce.
                let entry = plan::derive_http_entry(finding).or_else(|| {
                    std::fs::read_to_string(root.join(&finding.file))
                        .ok()
                        .and_then(|source| plan::registered_route_entry(&source))
                });
                if let Some(entry) = entry {
                    let mut derived = finding.clone();
                    derived.entry = Some(entry);
                    return derived;
                }
            }
            finding.clone()
        })
        .collect();
    let findings = owned.as_slice();
    // Plan each finding, giving the planner the handler's own source so it can resolve a request
    // input the finding only names coarsely (a `req.headers` source whose specific header the
    // handler reads in a host/URL position).
    let mut plans: Vec<Result<plan::Plan, plan::Skip>> = findings
        .iter()
        .map(|finding| {
            let source = std::fs::read_to_string(root.join(&finding.file)).ok();
            plan::plan_with_source(finding, source.as_deref())
        })
        .collect();
    // A route the host app mounts under a prefix the module declares (`mountPath: "/auth"`).
    for (finding, planned) in findings.iter().zip(plans.iter_mut()) {
        if let Ok(plan::Plan::Http(probe)) = planned
            && let Some(at) = &finding.entry_at
            && let Ok(source) = std::fs::read_to_string(root.join(&at.file))
            && let Some(prefix) = plan::declared_mount_prefix(&source)
            && !probe.path.starts_with(&format!("{prefix}/"))
        {
            probe.path = if probe.path == "/" {
                prefix
            } else {
                format!("{prefix}{}", probe.path)
            };
        }
    }
    // Other request parameters the handler requires alongside the tainted one: without them it
    // rejects the request before the sink is reached. Read from the handler source.
    for (finding, planned) in findings.iter().zip(plans.iter_mut()) {
        if let Ok(plan::Plan::Http(probe)) = planned
            && let Some((part, target)) = probe.entry_part().map(|(p, t)| (p, t.to_owned()))
            && let Ok(source) = std::fs::read_to_string(root.join(&finding.file))
        {
            let mut siblings = plan::required_siblings(&source, part, &target);
            // A handler may reach its sink only on a guarded branch (`else if (agentKey)`,
            // `if (mode === 'raw')`); the member that gates it must be present, or the request takes
            // a different branch and never reaches the sink. Add any such field of the same part.
            for (name, value) in plan::guard_required_fields(
                &source,
                part,
                &target,
                &plan::guard_anchor_lines(finding),
            ) {
                if siblings.iter().all(|(k, _)| *k != name) {
                    siblings.push((name, value));
                }
            }
            probe.siblings = siblings;
        }
    }
    // A route often reaches the sink on only one value of a non-payload path segment
    // (`if (platform === 'truuze')`), or rejects unknown segments outright; fill those slots with the
    // literal a guard enclosing the sink pins them to, instead of the generic placeholder.
    for (finding, planned) in findings.iter().zip(plans.iter_mut()) {
        if let Ok(plan::Plan::Http(probe)) = planned
            && let Ok(source) = std::fs::read_to_string(root.join(&finding.file))
        {
            probe.path_fillers = plan::path_slot_fillers(
                &source,
                &probe.path,
                &probe.entry,
                &plan::guard_anchor_lines(finding),
            );
        }
    }
    // A route whose express-validator middleware constrains a non-payload path parameter
    // (`param("email").isEmail()`, `param("id").isMongoId()`) rejects the generic `1` slot
    // placeholder before the sink. Resolve the route's validator middleware and use a type-valid
    // filler for every constrained path slot except the payload-bearing one.
    for (finding, planned) in findings.iter().zip(plans.iter_mut()) {
        if let Ok(plan::Plan::Http(probe)) = planned
            && probe.path.contains('{')
            && let Some(at) = &finding.entry_at
            && let Ok(route_src) = std::fs::read_to_string(root.join(&at.file))
        {
            let payload_slot = match &probe.entry {
                plan::Entry::PathParam(name) => Some(name.as_str()),
                _ => None,
            };
            let resolve = |name: &str| resolve_middleware_source(root, &at.file, &route_src, name);
            let mined = plan::validator_path_fillers(
                &route_src,
                at.line,
                &probe.path,
                payload_slot,
                &resolve,
            );
            if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                let roots = plan::route_middleware_roots(&route_src, at.line);
                let resolved = roots
                    .iter()
                    .map(|name| (name.clone(), resolve(name).is_some()))
                    .collect::<Vec<_>>();
                eprintln!(
                    "[verify] validator-path at={}:{} path={} roots={resolved:?} mined={mined:?}",
                    at.file, at.line, probe.path
                );
            }
            for (slot, value) in mined {
                if probe.path_fillers.iter().all(|(name, _)| *name != slot) {
                    probe.path_fillers.push((slot, value));
                }
            }
        }
    }
    // A sink reached only past a guard on a body field the payload does not itself ride (the payload
    // enters through a path segment or query parameter, but `const { id } = req.body; if (!id) throw`
    // rejects the request first). Mine those required body fields so the request carries them and
    // reaches the sink. Only when the payload is not already in the body (that part's siblings cover
    // it) and the method can carry a body.
    for (finding, planned) in findings.iter().zip(plans.iter_mut()) {
        if let Ok(plan::Plan::Http(probe)) = planned
            && !matches!(probe.entry, plan::Entry::Body(_))
            && probe.method.verb(&probe.entry) != "GET"
            && let Ok(source) = std::fs::read_to_string(root.join(&finding.file))
        {
            probe.body_requires = plan::guard_required_fields(
                &source,
                "body",
                "",
                &plan::guard_anchor_lines(finding),
            );
        }
    }
    // A route guarded by express-validator middleware (`body("device_names").exists().isArray(...)`)
    // rejects the request with a 400 before the sink unless the body carries every field the chain
    // requires. Mine those required fields from the validator arrays the route mounts — resolving the
    // middleware through the route's imports/requires, including `module-alias` specifiers — and carry
    // a type-valid filler for each, so a body-delivered payload (a whole-body NoSQL operator object or
    // a named body field) reaches the sink instead of the validation error.
    for (finding, planned) in findings.iter().zip(plans.iter_mut()) {
        if let Ok(plan::Plan::Http(probe)) = planned
            && matches!(probe.entry, plan::Entry::Body(_))
            && let Some(at) = &finding.entry_at
            && let Ok(route_src) = std::fs::read_to_string(root.join(&at.file))
        {
            let payload_field = match &probe.entry {
                plan::Entry::Body(Some(name)) => name.clone(),
                _ => String::new(),
            };
            let resolve = |name: &str| resolve_middleware_source(root, &at.file, &route_src, name);
            let mined =
                plan::validator_required_body_fields(&route_src, at.line, &payload_field, &resolve);
            if probe.body_query_override.is_some()
                && let Some(value) =
                    plan::validator_body_field_filler(&route_src, at.line, &payload_field, &resolve)
            {
                probe.body_query_override = Some(value);
            }
            if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                let idents = plan::route_middleware_idents(&route_src, at.line);
                let resolved: Vec<(String, bool, bool)> = idents
                    .iter()
                    .map(|n| {
                        let src = resolve(n);
                        let has = src.is_some();
                        let arr = src
                            .as_deref()
                            .map(|s| plan::defines_const_array(s, n))
                            .unwrap_or(false);
                        (n.clone(), has, arr)
                    })
                    .collect();
                eprintln!(
                    "[verify] validator-siblings entry={:?} at={}:{} payload={payload_field:?} idents={resolved:?} mined={mined:?}",
                    probe.entry, at.file, at.line
                );
            }
            for (field, value) in mined {
                if probe.siblings.iter().all(|(k, _)| *k != field) {
                    probe.siblings.push((field, value));
                }
            }
        }
    }
    // A SQL injection whose tainted value is interpolated in a table-identifier position
    // (`FROM ${tbl}`): mine the columns the statements interpolating that identifier reference and the
    // body fields the handler reads, so the probe can replace the table with a sub-select that both
    // satisfies those columns and returns a database-computed value.
    for (finding, planned) in findings.iter().zip(plans.iter_mut()) {
        if let Ok(plan::Plan::Http(probe)) = planned
            && finding.class == jss_core::VulnClass::SqlInjection
            && let Ok(source) = std::fs::read_to_string(root.join(&finding.file))
        {
            probe.sql = plan::sql_plan_for(finding, &probe.entry, &source);
        }
    }
    // An entry that forwards the request URL often reaches its sink only for paths the handler
    // recognizes, and may read the tainted value from a query parameter of the parsed URL rather
    // than from the path — the outbound host of an SSRF, or the file path of a traversal. Mine the
    // gate paths (for an upgrade entry or a URL-sourced forward proxy/file read) and, for the
    // URL-sourced case, the query parameters, so the request can be sent the way the handler reads it.
    for (finding, planned) in findings.iter().zip(plans.iter_mut()) {
        if let Ok(plan::Plan::Http(probe)) = planned {
            let url_sourced = probe.entry == plan::Entry::Url
                && matches!(
                    probe.class,
                    jss_core::VulnClass::Ssrf
                        | jss_core::VulnClass::PathTraversal
                        | jss_core::VulnClass::CommandInjection
                        | jss_core::VulnClass::CodeInjection
                );
            if probe.method.is_upgrade() || url_sourced {
                // A catch-all entry (`req.url` dispatched by `http.createServer`) recognizes the
                // path and reads the tainted query parameter inside the route module that owns the
                // sink, not the entry file. Mine the gate paths and query parameters from both the
                // handler file and the sink's own file so the request is sent the way the dispatched
                // handler reads it.
                let files = [Some(finding.file.as_str()), finding.sink.file.as_deref()];
                for file in files.into_iter().flatten() {
                    let Ok(source) = std::fs::read_to_string(root.join(file)) else {
                        continue;
                    };
                    for gate in plan::gate_paths(&source) {
                        if !probe.gate_paths.contains(&gate) {
                            probe.gate_paths.push(gate);
                        }
                    }
                    if url_sourced {
                        for param in plan::url_search_params(&source) {
                            if !probe.url_query_params.contains(&param) {
                                probe.url_query_params.push(param);
                            }
                        }
                        // The handler may parse the URL here but read its fields in a render/transform
                        // function it forwards the whole search-parameters object to (possibly in
                        // another module). Follow that one call hop and add the fields the callee
                        // reads, so the payload is tried under the query name the sink actually
                        // consumes.
                        for extra in plan::forwarded_search_params(&source, &|fn_name| {
                            resolve_module_source(root, file, &source, fn_name)
                        }) {
                            if !probe.url_query_params.contains(&extra) {
                                probe.url_query_params.push(extra);
                            }
                        }
                    }
                }
            }
        }
    }

    // A URL-sourced forward proxy / file sink that reads several query parameters off the parsed
    // request URL reaches its sink only when the parameters other than the payload carrier are also
    // present and valid (`if (!url || !type) return`; `const filter = FILTERS[type]; if (!filter)
    // return`). Mine a valid filler for each parameter so the payload-bearing request carries its
    // required siblings instead of being rejected before the sink.
    for (finding, planned) in findings.iter().zip(plans.iter_mut()) {
        if let Ok(plan::Plan::Http(probe)) = planned
            && probe.entry == plan::Entry::Url
            && probe.url_query_params.len() > 1
            && matches!(
                probe.class,
                jss_core::VulnClass::Ssrf
                    | jss_core::VulnClass::PathTraversal
                    | jss_core::VulnClass::CommandInjection
                    | jss_core::VulnClass::CodeInjection
            )
            && let Ok(source) = std::fs::read_to_string(root.join(&finding.file))
        {
            let params = probe.url_query_params.clone();
            probe.siblings = plan::url_query_fillers(&source, &params, &|name| {
                resolve_module_source(root, &finding.file, &source, name)
            });
        }
    }

    // An SSRF whose tainted body field is a structured document a parse function turns into an object
    // before the sink reads one of its members (`const parsed = parseDocument(body); fetch(
    // `${parsed.endpoint}/...`)`) never reaches the sink with a raw URL: the input must be a document
    // the parser accepts. Mine the document scaffold and the member->JSON-key mapping from the handler
    // and the parse function's own source (resolving an import when the function lives in another
    // module), so the payload can be packed the way the handler actually reads it.
    for (finding, planned) in findings.iter().zip(plans.iter_mut()) {
        if let Ok(plan::Plan::Http(probe)) = planned
            && probe.class == jss_core::VulnClass::Ssrf
            && matches!(probe.entry, plan::Entry::Body(Some(_)))
            && let Ok(handler) = std::fs::read_to_string(root.join(&finding.file))
            && let Some(fn_name) = plan::parse_transform_fn(finding, &probe.entry, &handler)
            && let Some(module_src) = resolve_module_source(root, &finding.file, &handler, &fn_name)
        {
            probe.doc_envelope = plan::doc_envelope(finding, &probe.entry, &handler, &module_src);
        }
    }

    let needs_http = plans.iter().any(|p| matches!(p, Ok(plan::Plan::Http(_))));
    let needs_browser = plans
        .iter()
        .any(|p| matches!(p, Ok(plan::Plan::Browser(_))));

    // Nothing drivable: answer without building anything.
    if !needs_http && !needs_browser {
        return Ok(findings
            .iter()
            .zip(&plans)
            .map(|(f, p)| {
                let reason = match p {
                    Err(skip) => skip.0.clone(),
                    Ok(_) => "not attempted".to_owned(),
                };
                verdict(f, Outcome::Skipped { reason })
            })
            .collect());
    }
    if !sandbox::available() {
        return match missing {
            Missing::Fail => Err(
                "--verify needs a running Docker daemon; none is reachable (start Docker, or drop --verify)"
                    .to_owned(),
            ),
            Missing::Skip => Ok(findings
                .iter()
                .map(|f| {
                    verdict(f, Outcome::Skipped {
                        reason: "no Docker daemon reachable".to_owned(),
                    })
                })
                .collect()),
        };
    }

    // Build the sessions the plans need. A build failure for one phase skips only that phase's
    // findings, with the failure as the reason.
    // An HTTP finding runs against the package that serves its route: a repo can hold several
    // apps (a web front end and a separate API or worker service). One session per launched
    // server (see `session_key`), started on first use and reused.
    let mut http: Vec<(std::path::PathBuf, Result<sandbox::Session, String>)> = Vec::new();
    let mut browser = needs_browser.then(|| sandbox::BrowserSession::start(root));

    let verdicts = findings
        .iter()
        .zip(&plans)
        .map(|(finding, plan)| {
            let outcome = match plan {
                Err(skip) => Outcome::Skipped {
                    reason: skip.0.clone(),
                },
                Ok(plan::Plan::Http(probe)) => {
                    let declared = finding
                        .entry_at
                        .as_ref()
                        .map_or(&finding.file, |at| &at.file);
                    let declared = std::path::Path::new(declared);
                    let app = sandbox::app_dir(root, declared);
                    let key = sandbox::session_key(root, &app, declared);
                    let index = match http.iter().position(|(existing, _)| *existing == key) {
                        Some(index) => index,
                        None => {
                            let gating = gating_env_sources(root, finding);
                            let session =
                                sandbox::Session::start_in(root, &app, Some(declared), &gating);
                            http.push((key, session));
                            http.len() - 1
                        }
                    };
                    match http.get_mut(index).map(|(_, session)| session) {
                        Some(Ok(session)) => session.exercise(probe),
                        Some(Err(err)) => Outcome::Skipped {
                            reason: format!("the app could not be launched: {err}"),
                        },
                        None => Outcome::Skipped {
                            reason: "not attempted".to_owned(),
                        },
                    }
                }
                Ok(plan::Plan::Browser(probe)) => match browser.as_mut() {
                    Some(Ok(session)) => session.exercise(probe),
                    Some(Err(err)) => Outcome::Skipped {
                        reason: format!("the browser phase could not start: {err}"),
                    },
                    None => Outcome::Skipped {
                        reason: "not attempted".to_owned(),
                    },
                },
            };
            verdict(finding, outcome)
        })
        .collect();

    for (_, session) in &mut http {
        if let Ok(session) = session {
            session.teardown();
        }
    }
    if let Some(Ok(session)) = browser.as_mut() {
        session.teardown();
    }
    Ok(verdicts)
}

/// The source of the module that defines `fn_name`, for a parse function the handler consumes: the
/// handler's own source when the function is local, otherwise the imported module resolved relative to
/// the handler file (trying the common JavaScript module file names). `None` when it cannot be found.
fn resolve_module_source(
    root: &std::path::Path,
    handler_file: &str,
    handler: &str,
    fn_name: &str,
) -> Option<String> {
    if plan::defines_function(handler, fn_name) {
        return Some(handler.to_owned());
    }
    let spec = plan::import_source_path(handler, fn_name)?;
    resolve_relative_source(root, handler_file, &spec)
}

/// The source text a relative module `spec` imported from `from_file` resolves to, trying the common
/// JavaScript module file names and an `index.*`. Confined to the repository tree. `None` for a bare
/// package specifier or a file that cannot be read.
fn resolve_relative_source(root: &std::path::Path, from_file: &str, spec: &str) -> Option<String> {
    // Only resolve relative specifiers; a bare package import is not part of the app tree.
    if !spec.starts_with('.') {
        return None;
    }
    let dir = std::path::Path::new(from_file).parent()?;
    let base = dir.join(spec);
    let base_str = base.to_string_lossy().into_owned();
    let canonical_root = root.canonicalize().ok()?;
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    // The specifier as written first (it may already name a file, extension and all).
    candidates.push(base.clone());
    for ext in ["js", "mjs", "cjs", "ts", "jsx", "tsx"] {
        // Append the extension to the whole path (`./device.validators` -> `device.validators.js`)
        // rather than replacing its last dotted segment, so a dotted module file name resolves.
        candidates.push(std::path::PathBuf::from(format!("{base_str}.{ext}")));
        candidates.push(base.join(format!("index.{ext}")));
    }
    for candidate in candidates {
        let Ok(candidate) = canonical_root.join(candidate).canonicalize() else {
            continue;
        };
        if !candidate.starts_with(&canonical_root) {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(candidate) {
            return Some(text);
        }
    }
    None
}

/// The source of the module that defines a route middleware `name`: the route file itself when it
/// declares the middleware (a local `const name = [...]` validator array or function), else the
/// module it imports/`require`s `name` from — resolved through a relative specifier or a
/// `module-alias` `_moduleAliases` entry. Confined to the repository tree.
fn resolve_middleware_source(
    root: &std::path::Path,
    route_file: &str,
    route_src: &str,
    name: &str,
) -> Option<String> {
    // Resolve an explicit import/require binding before testing for a local function. The generic
    // function-body recognizer deliberately accepts several assignment forms and can otherwise
    // mistake `const name = require(...)` for a function when a later object literal supplies the
    // first `{` after that binding.
    if let Some(spec) = plan::import_or_require_source_path(route_src, name) {
        return resolve_import_source(root, route_file, &spec);
    }
    if plan::defines_const_array(route_src, name) || plan::defines_function(route_src, name) {
        return Some(route_src.to_owned());
    }
    None
}

/// The source a module specifier resolves to from `from_file`: a relative specifier through
/// [`resolve_relative_source`], or a bare specifier through a `module-alias` `_moduleAliases` entry
/// (`@validators/device.validators`). `None` for an unresolved or non-aliased package specifier.
fn resolve_import_source(root: &std::path::Path, from_file: &str, spec: &str) -> Option<String> {
    if spec.starts_with('.') {
        return resolve_relative_source(root, from_file, spec);
    }
    let rooted = resolve_module_alias(root, from_file, spec)?;
    resolve_rooted_source(root, &rooted)
}

/// A bare specifier rewritten through the nearest enclosing `package.json`'s `module-alias`
/// `_moduleAliases` map (`@validators/x` with `"@validators": "validators"` declared in
/// `src/app/package.json` -> `src/app/validators/x`), as a repository-root-relative path without an
/// extension. `None` when no ancestor package declares the alias.
fn resolve_module_alias(root: &std::path::Path, from_file: &str, spec: &str) -> Option<String> {
    let (alias, rest) = match spec.split_once('/') {
        Some((a, r)) => (a, Some(r)),
        None => (spec, None),
    };
    let mut dir = std::path::Path::new(from_file).parent();
    while let Some(d) = dir {
        let pkg = root.join(d).join("package.json");
        if let Ok(text) = std::fs::read_to_string(&pkg)
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
            && let Some(target) = json
                .get("_moduleAliases")
                .and_then(|v| v.as_object())
                .and_then(|m| m.get(alias))
                .and_then(|v| v.as_str())
        {
            let target = target.trim_start_matches("./").trim_end_matches('/');
            let mut path = d.to_path_buf();
            if !target.is_empty() && target != "." {
                path = path.join(target);
            }
            if let Some(rest) = rest {
                path = path.join(rest);
            }
            return Some(path.to_string_lossy().into_owned());
        }
        dir = d.parent();
    }
    None
}

/// The source text of a repository-root-relative module path (without extension), trying the common
/// JavaScript file names and an `index.*`. Confined to the repository tree.
fn resolve_rooted_source(root: &std::path::Path, rooted: &str) -> Option<String> {
    let canonical_root = root.canonicalize().ok()?;
    let base = std::path::Path::new(rooted);
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    // Try the specifier as written first (it may already name a file, extension and all).
    candidates.push(base.to_path_buf());
    for ext in ["js", "mjs", "cjs", "ts", "jsx", "tsx"] {
        // Append the extension to the whole specifier (`device.validators` -> `device.validators.js`)
        // rather than replacing its last dotted segment, so a module whose file name itself contains a
        // dot resolves correctly.
        candidates.push(std::path::PathBuf::from(format!("{rooted}.{ext}")));
        candidates.push(base.join(format!("index.{ext}")));
    }
    for candidate in candidates {
        let Ok(candidate) = canonical_root.join(candidate).canonicalize() else {
            continue;
        };
        if !candidate.starts_with(&canonical_root) {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(candidate) {
            return Some(text);
        }
    }
    None
}

/// The source texts the sandbox scans for a credential the finding's sink is gated on: the sink's own
/// module and the modules it imports one hop out (where a `createGithubAuthEnv`-style helper reads the
/// token). Bounded to relative imports within the repository tree. Empty when the sink file cannot be
/// read.
fn gating_env_sources(root: &std::path::Path, finding: &Finding) -> Vec<String> {
    // The credential gate that must be satisfied to reach the sink may sit either in the sink's own
    // module (the branch directly around the call) or in the entry/handler module that calls into it
    // (an integration the route requires configured before it forwards the request). Scan both files
    // and their relative imports so a gate read anywhere along that path is reproduced.
    let sink_file = finding
        .sink
        .file
        .as_deref()
        .unwrap_or(finding.file.as_str());
    let mut sources = Vec::new();
    let mut seen_files = Vec::new();
    for file in [sink_file, finding.file.as_str()] {
        if seen_files.iter().any(|f| f == file) {
            continue;
        }
        seen_files.push(file.to_owned());
        let Ok(src) = std::fs::read_to_string(root.join(file)) else {
            continue;
        };
        for spec in plan::relative_import_specifiers(&src) {
            if let Some(text) = resolve_relative_source(root, file, &spec) {
                sources.push(text);
            }
        }
        sources.push(src);
    }
    sources
}

fn verdict(finding: &Finding, outcome: Outcome) -> Verdict {
    Verdict {
        fingerprint: finding.fingerprint.clone(),
        entry: finding.entry.clone(),
        class: finding.class.name().to_owned(),
        outcome,
    }
}

/// Renders the verification section of the text report: a line per finding that was driven, then
/// a count. Nothing when no finding was driven.
pub fn write_text(
    out: &mut dyn std::io::Write,
    verdicts: &[Verdict],
    color: bool,
) -> std::io::Result<()> {
    if verdicts.is_empty() {
        return Ok(());
    }
    let (bold, green, yellow, dim, reset) = if color {
        ("\x1b[1m", "\x1b[32m", "\x1b[33m", "\x1b[2m", "\x1b[0m")
    } else {
        ("", "", "", "", "")
    };
    let (mut verified, mut not_reproduced, mut skipped) = (0, 0, 0);
    writeln!(out, "\n  {bold}Verification{reset}")?;
    for v in verdicts {
        let entry = v.entry.as_deref().unwrap_or(&v.class);
        match &v.outcome {
            Outcome::Verified { how, .. } => {
                verified += 1;
                writeln!(
                    out,
                    "  {green}✔ verified{reset} {entry} {dim}{}{reset}  ({how})",
                    v.fingerprint
                )?;
            }
            Outcome::NotReproduced { tried } => {
                not_reproduced += 1;
                writeln!(
                    out,
                    "  {yellow}• not reproduced{reset} {entry} {dim}{}{reset}  ({tried} request(s) sent)",
                    v.fingerprint
                )?;
            }
            Outcome::Skipped { .. } => skipped += 1,
        }
    }
    writeln!(
        out,
        "  {dim}verified {verified}, not reproduced {not_reproduced}, skipped {skipped}{reset}"
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{resolve_middleware_source, resolve_module_source};

    #[test]
    fn imported_transform_modules_cannot_escape_the_scan_root() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("repo");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("parser.js"), "export function parseDoc() {}").unwrap();
        std::fs::write(parent.path().join("outside.js"), "outside").unwrap();

        let internal = "import { parseDoc } from '../parser.js';";
        assert_eq!(
            resolve_module_source(&root, "src/server.js", internal, "parseDoc").as_deref(),
            Some("export function parseDoc() {}")
        );

        let escaping = "import { parseDoc } from '../../outside.js';";
        assert!(resolve_module_source(&root, "src/server.js", escaping, "parseDoc").is_none());

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(parent.path().join("outside.js"), root.join("linked.js"))
                .unwrap();
            let linked = "import { parseDoc } from '../linked.js';";
            assert!(resolve_module_source(&root, "src/server.js", linked, "parseDoc").is_none());
        }
    }

    #[test]
    fn module_alias_namespace_validator_resolves_for_path_fillers() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let route_file = "src/routes/analytics.routes.js";
        let route = r#"const analyticsValidations = require("@validators/analytics.validators");
router.get(
  "/:email/health-score",
  analyticsValidations.healthScoreValidators.getHealthScore,
  controller.getEngagementHealth
);
module.exports = { router };
"#;
        let validator = "const validateUserEmail = param(\"email\").isEmail();\n\
const healthScoreValidators = { getHealthScore: [validateUserEmail] };\n\
module.exports = { healthScoreValidators };\n";
        std::fs::create_dir_all(root.join("src/routes")).unwrap();
        std::fs::create_dir_all(root.join("src/validators")).unwrap();
        std::fs::write(
            root.join("src/package.json"),
            r#"{"_moduleAliases":{"@validators":"validators"}}"#,
        )
        .unwrap();
        std::fs::write(root.join(route_file), route).unwrap();
        std::fs::write(
            root.join("src/validators/analytics.validators.js"),
            validator,
        )
        .unwrap();

        let resolve = |name: &str| resolve_middleware_source(root, route_file, route, name);
        assert_eq!(
            super::plan::validator_path_fillers(
                route,
                2,
                "/api/v2/users/analytics/{email}/health-score",
                None,
                &resolve,
            ),
            vec![("email".to_owned(), "jss@jsspector.test".to_owned())]
        );
    }
}
