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
    // An entry that forwards the request URL (SSRF) often reaches its sink only for paths the handler
    // recognizes, and may choose the outbound host from a query parameter of the parsed URL. Mine the
    // gate paths (for an upgrade entry or a URL-sourced forward proxy) and, for the URL-sourced case,
    // the query parameters, so the marker request can be sent the way the handler actually reads it.
    for (finding, planned) in findings.iter().zip(plans.iter_mut()) {
        if let Ok(plan::Plan::Http(probe)) = planned {
            let url_ssrf =
                probe.class == jss_core::VulnClass::Ssrf && probe.entry == plan::Entry::Url;
            if (probe.method.is_upgrade() || url_ssrf)
                && let Ok(source) = std::fs::read_to_string(root.join(&finding.file))
            {
                probe.gate_paths = plan::gate_paths(&source);
                if url_ssrf {
                    probe.url_query_params = plan::url_search_params(&source);
                }
            }
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
                            let session = sandbox::Session::start_in(root, &app, Some(declared));
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
    // Only resolve relative specifiers; a bare package import is not part of the app tree.
    if !spec.starts_with('.') {
        return None;
    }
    let dir = std::path::Path::new(handler_file).parent()?;
    let base = dir.join(&spec);
    let canonical_root = root.canonicalize().ok()?;
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if base.extension().is_some() {
        candidates.push(base.clone());
    }
    for ext in ["js", "mjs", "cjs", "ts", "jsx", "tsx"] {
        candidates.push(base.with_extension(ext));
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
    use super::resolve_module_source;

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
}
