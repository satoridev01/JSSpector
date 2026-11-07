//! The entry-point inventory: every route with its full path, linked across files.
//!
//! Each file reports the routes it registers (on a router variable), the routers it mounts under
//! a prefix, and its exports and resolved imports. Mounts are followed across files (imports
//! resolve to a file, exports name the router there), prefixes are joined, and file-system
//! conventions (Next.js `app/**/route.ts`, `pages/api/**`) give the path of file routes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use jss_core::Auth;
use serde::Serialize;

use crate::scan::{ScanReport, ScanStatus};

/// One entry point.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Route {
    /// HTTP method, `ANY`, or the event kind (`SOCKET`, `IPC`, `QUEUE`, ...).
    pub method: String,
    /// Full path with mount prefixes (OpenAPI style: `{id}`), or the event name.
    pub path: String,
    pub file: String,
    pub line: u32,
    /// For a route a helper registers: its own `router.get(...)` call (file, line).
    #[serde(skip)]
    pub at: Option<(String, u32)>,
    pub handler: String,
    /// What the IR resolves the handler by: the handler, or a function written in another file
    /// (`<at>:file#name`, a route a helper registers inline).
    #[serde(skip)]
    pub handler_ref: String,
    pub auth: Auth,
    /// `http`, `socket`, `ipc`, `graphql`, `trpc`, `queue`, ...
    pub kind: String,
    /// Request inputs the handler reads: `query.q`, `body.email`.
    pub inputs: Vec<String>,
    /// An inline handler walked as part of `handler` (its enclosing function): the handler's
    /// first and last lines. It reaches the findings there, not the whole of `handler`.
    #[serde(skip)]
    pub lines: Option<(u32, u32)>,
}

/// Links findings to the entry points that reach them: each route's handler is resolved to a
/// function through the IR, the call graph is followed from the handlers, and every finding in a
/// reached function gets the route (`entry`) and, when stronger, the route's authentication (an
/// admin-only route lowers the severity one level).
pub fn attach_entries(root: &Path, reports: &mut [ScanReport]) {
    let (scoped, routes): (Vec<Route>, Vec<Route>) = inventory(root, reports)
        .into_iter()
        .partition(|r| r.lines.is_some());
    let modules: Vec<jss_core::ir::Module> = reports.iter().map(|r| r.module.clone()).collect();
    let by_file: BTreeMap<&str, &jss_core::ir::Module> =
        modules.iter().map(|m| (m.file.as_str(), m)).collect();
    let graph = jss_core::ir::link(&modules);
    // Weakest authentication first: a function reached from a public route and from an admin
    // route is reachable without logging in.
    let mut entries: Vec<(Auth, String, jss_core::ir::FunctionId, jss_core::EntryLoc)> = routes
        .iter()
        .filter_map(|route| {
            jss_core::ir::resolve_reference(&by_file, &route.file, &route.handler_ref).map(
                |target| {
                    (
                        route.auth,
                        format!("{} {}", route.method, route.path),
                        target,
                        match &route.at {
                            Some((file, line)) => jss_core::EntryLoc {
                                file: file.clone(),
                                line: *line,
                            },
                            None => jss_core::EntryLoc {
                                file: route.file.clone(),
                                line: route.line,
                            },
                        },
                    )
                },
            )
        })
        .collect();
    entries.sort();
    let roots: Vec<jss_core::ir::FunctionId> = entries
        .iter()
        .map(|(_, _, target, _)| target.clone())
        .collect();
    let labels: Vec<(String, Auth, jss_core::EntryLoc)> = entries
        .into_iter()
        .map(|(auth, label, _, at)| (label, auth, at))
        .collect();
    let reached = jss_core::ir::reachable(&graph, &roots);
    // For a request-sourced finding, prefer the route that actually forwards the request object
    // into the function reading it. A route whose call graph reaches the function only by passing a
    // freshly constructed object (a background job rebuilding `{ query, body }`) does not deliver the
    // attacker's `req.query.<field>` there, so it is not a genuine HTTP entry; fall back to plain
    // reachability when no route forwards a request (nothing is lost that was linked before).
    let reached_fwd = jss_core::ir::reachable_forwarding(&modules, &roots);
    let model = crate::taint::models::model();
    for report in reports.iter_mut() {
        for finding in &mut report.findings {
            let id = (finding.file.clone(), finding.function.clone());
            let index = if finding.source.kind == "http" {
                reached_fwd.get(&id).or_else(|| reached.get(&id))
            } else {
                reached.get(&id)
            };
            let Some((label, auth, at)) = index.and_then(|index| labels.get(*index)) else {
                // Browser-side data no route reaches: the page or the component it enters.
                let kind: &str = finding.source.kind;
                if model.page_kinds.iter().any(|k| k == kind) {
                    finding.entry = Some(format!("PAGE {}", finding.file));
                } else if model.props_kind.as_deref() == Some(kind) {
                    finding.entry = Some(format!("COMPONENT {}", finding.function));
                }
                continue;
            };
            finding.entry = Some(label.clone());
            finding.entry_at = Some(at.clone());
            raise_auth(finding, *auth);
        }
    }
    // Inline handlers walked inside another function: the findings whose source and sink both
    // lie in the handler's lines (and in this file), weakest authentication first.
    let mut scoped = scoped;
    scoped.sort_by_key(|r| r.auth);
    for report in reports.iter_mut() {
        for finding in &mut report.findings {
            if finding.entry.is_some() || finding.sink.file.is_some() {
                continue;
            }
            let Some(route) = scoped.iter().find(|r| {
                r.file == finding.file
                    && r.handler_ref == finding.function
                    && r.lines.is_some_and(|(first, last)| {
                        (first..=last).contains(&finding.sink.line)
                            && (first..=last).contains(&finding.source.line)
                    })
            }) else {
                continue;
            };
            finding.entry = Some(format!("{} {}", route.method, route.path));
            finding.entry_at = Some(jss_core::EntryLoc {
                file: route.file.clone(),
                line: route.line,
            });
            raise_auth(finding, route.auth);
        }
    }
}

/// A finding takes the stronger authentication of the entry that reaches it; an admin-only
/// entry lowers its severity one level.
fn raise_auth(finding: &mut jss_core::Finding, auth: Auth) {
    if auth > finding.auth {
        if auth == Auth::Admin && finding.auth != Auth::Admin {
            finding.severity = match finding.severity {
                jss_core::Severity::Critical => jss_core::Severity::High,
                jss_core::Severity::High => jss_core::Severity::Medium,
                _ => jss_core::Severity::Low,
            };
        }
        finding.auth = auth;
    }
}

/// A router: a variable in a file.
type RouterId = (String, String);

/// Builds the inventory from scan reports.
pub fn inventory(root: &Path, reports: &[ScanReport]) -> Vec<Route> {
    let by_file: BTreeMap<&str, &ScanReport> = reports
        .iter()
        .filter(|r| r.status == ScanStatus::Scanned)
        .map(|r| (r.rel_path.as_str(), r))
        .collect();
    let next_middleware = next_middleware_policies(root, reports);
    // Directory-prefix routing applied by `@fastify/autoload` (computed once for the repo).
    let autoload_dirs = autoload_dir_names(root);

    // Mount edges: child router -> (parent router, prefix).
    let mut parents: BTreeMap<RouterId, Vec<(RouterId, String, Auth)>> = BTreeMap::new();
    for (file, report) in &by_file {
        for mount in &report.module.mounts {
            let Some(parent) = &mount.receiver else {
                continue;
            };
            let child = match (&mount.target, &mount.target_file) {
                (Some(local), _) => resolve_local(&by_file, file, local),
                (None, Some(target_file)) => locate_export(
                    &by_file,
                    target_file,
                    mount.target_export.as_deref().unwrap_or("default"),
                    0,
                ),
                (None, None) => None,
            };
            if let Some(child) = child {
                parents.entry(child).or_default().push((
                    (file.to_string(), parent.clone()),
                    mount.prefix.clone(),
                    mount.auth,
                ));
            }
        }
    }

    let mut routes = BTreeSet::new();
    let mut memo = BTreeMap::new();
    for (file, report) in &by_file {
        for entry in &report.module.entries {
            let prefixes = match &entry.receiver {
                // A route added through another file's helper is on that file's router.
                Some(receiver) => {
                    let owner = entry.receiver_file.as_deref().unwrap_or(file);
                    prefixes(&parents, &(owner.to_string(), receiver.clone()), &mut memo)
                }
                None => vec![(String::new(), Auth::NoneDetected)],
            };
            let path = match entry.kind.as_str() {
                kind @ ("file-route" | "default-export") => match file_route_path(file, kind) {
                    Some(path) => path,
                    None => continue,
                },
                _ => entry.path.clone(),
            };
            let provider = resource_prefix(root, file, entry.line).unwrap_or_default();
            let autoload = autoload_prefix(&autoload_dirs, file).unwrap_or_default();
            for (prefix, mount_auth) in prefixes {
                let full = if entry.kind == "http" || entry.kind == "file-route" {
                    openapi_path(&join(&prefix, &join(&autoload, &join(&provider, &path))))
                } else {
                    path.clone()
                };
                let middleware_auth =
                    matches!(entry.kind.as_str(), "file-route" | "default-export")
                        .then(|| next_middleware_auth(&next_middleware, file, &full))
                        .unwrap_or_default();
                let auth = entry.auth.max(mount_auth).max(middleware_auth);
                routes.insert(Route {
                    method: entry.method.clone(),
                    path: full,
                    file: file.to_string(),
                    line: entry.line,
                    at: entry.at.clone(),
                    // `<at>:src/api/admin.js#POST /x` reads as the function's name.
                    handler: entry
                        .handler
                        .strip_prefix(jss_core::ir::ELSEWHERE)
                        .and_then(|r| r.split_once('#'))
                        .map_or_else(|| entry.handler.clone(), |(_, name)| name.to_owned()),
                    handler_ref: entry.handler.clone(),
                    auth,
                    kind: if entry.kind == "default-export" || entry.kind == "file-route" {
                        "http".to_owned()
                    } else {
                        entry.kind.clone()
                    },
                    inputs: entry
                        .inputs
                        .iter()
                        .map(|(l, n)| format!("{l}.{n}"))
                        .collect(),
                    lines: entry.lines,
                });
            }
        }
    }
    routes.into_iter().collect()
}

#[derive(Debug)]
struct NextMiddleware {
    scope: String,
    exclusions: Vec<String>,
}

/// Authentication enforced by a Next.js `middleware.ts` before file-system routes run.
///
/// Middleware is project-wide and therefore cannot be attached while scanning one route file.
/// Recover the conservative, common shape here: a cookie/session/authorization check that returns
/// a `NextResponse.redirect` (or a 401/403 response), with either no matcher or a negative-lookahead
/// matcher whose literal public prefixes can be honored exactly.
fn next_middleware_policies(root: &Path, reports: &[ScanReport]) -> Vec<NextMiddleware> {
    reports
        .iter()
        .filter(|report| report.status == ScanStatus::Scanned)
        .filter_map(|report| {
            let path = Path::new(&report.rel_path);
            let name = path.file_name()?.to_str()?;
            if !matches!(name, "middleware.js" | "middleware.ts") {
                return None;
            }
            let source = std::fs::read_to_string(root.join(path)).ok()?;
            let lower = source.to_ascii_lowercase();
            let reads_identity = [
                "authorization",
                "accesstoken",
                "access_token",
                "idtoken",
                "id_token",
                "session",
                "currentuser",
                "current_user",
                "gettoken(",
                "get_token(",
            ]
            .iter()
            .any(|marker| lower.contains(marker));
            let rejects = lower.contains("nextresponse.redirect")
                || lower.contains("status: 401")
                || lower.contains("status:401")
                || lower.contains("status: 403")
                || lower.contains("status:403");
            if !reads_identity || !rejects {
                return None;
            }
            let exclusions = next_matcher_exclusions(&source)?;
            let parent = path.parent()?;
            let scope = if parent.file_name().and_then(|part| part.to_str()) == Some("src") {
                parent.parent().unwrap_or_else(|| Path::new(""))
            } else {
                parent
            };
            Some(NextMiddleware {
                scope: scope.to_string_lossy().trim_matches('/').to_owned(),
                exclusions,
            })
        })
        .collect()
}

/// Literal public prefixes in `/((?!api/auth|_next/static|...).*)`; an unfamiliar explicit
/// matcher is left unclassified rather than claiming authentication outside its scope.
fn next_matcher_exclusions(source: &str) -> Option<Vec<String>> {
    if !source.contains("matcher") {
        return Some(Vec::new());
    }
    let after = source.split_once("(?!")?.1;
    let group = after.split_once(')')?.0;
    let exclusions: Vec<String> = group
        .split('|')
        .map(|part| part.trim().trim_start_matches('^').trim_start_matches('/'))
        .filter(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '-' | '.'))
        })
        .map(str::to_owned)
        .collect();
    (!exclusions.is_empty()).then_some(exclusions)
}

fn next_middleware_auth(policies: &[NextMiddleware], file: &str, route: &str) -> Auth {
    let route = route.trim_start_matches('/');
    policies
        .iter()
        .filter(|policy| {
            policy.scope.is_empty()
                || file == policy.scope
                || file
                    .strip_prefix(&policy.scope)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
        .filter(|policy| {
            !policy.exclusions.iter().any(|public| {
                route == public
                    || route
                        .strip_prefix(public)
                        .is_some_and(|rest| rest.starts_with('/'))
            })
        })
        .map(|_| Auth::User)
        .max()
        .unwrap_or_default()
}

/// The directory basenames a repository autoloads with `@fastify/autoload`. Each autoloaded
/// directory turns its subdirectory names into route prefixes (`dirNameRoutePrefix`, on by default),
/// so a route plugin's deployed path carries the directory chain above it. A bounded scan reads the
/// source files that import `@fastify/autoload` and extracts the trailing path-literal of each `dir:`
/// option (`dir: path.join(__dirname, "routes")` -> `routes`); the basename alone is kept so the
/// prefix can be anchored on the matching ancestor directory without resolving the app's own base
/// path (`__dirname`, a custom `rootPath` helper). Empty when the repo does not use autoload.
fn autoload_dir_names(root: &Path) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    let mut stack = vec![(root.to_path_buf(), 0u32)];
    let mut budget: u32 = 4000;
    while let Some((dir, depth)) = stack.pop() {
        if depth > 10 {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if budget == 0 {
                return names;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if kind.is_dir() {
                if name == "node_modules" || name.starts_with('.') {
                    continue;
                }
                stack.push((entry.path(), depth + 1));
            } else if matches!(
                std::path::Path::new(name.as_ref())
                    .extension()
                    .and_then(|e| e.to_str()),
                Some("js" | "mjs" | "cjs" | "ts" | "mts" | "cts")
            ) {
                budget -= 1;
                let Ok(source) = std::fs::read_to_string(entry.path()) else {
                    continue;
                };
                if !source.contains("@fastify/autoload") {
                    continue;
                }
                for line in source.lines() {
                    if let Some(rest) = line.split_once("dir:").map(|(_, r)| r)
                        && let Some(basename) = autoload_dir_literal(rest)
                    {
                        names.insert(basename);
                    }
                }
            }
        }
    }
    names
}

/// The directory basename named by the last quoted string literal in a `dir:` option expression:
/// `path.join(__dirname, "./routes")` -> `routes`. `None` when the expression has no string literal
/// (a fully computed directory the scan cannot read).
fn autoload_dir_literal(expr: &str) -> Option<String> {
    let mut last = None;
    let mut chars = expr.char_indices();
    while let Some((at, quote)) = chars.next() {
        if matches!(quote, '"' | '\'' | '`') {
            let start = at + quote.len_utf8();
            let Some((end, _)) = chars.by_ref().find(|(_, candidate)| *candidate == quote) else {
                break;
            };
            last = expr.get(start..end);
        }
    }
    let literal = last?.trim_end_matches('/');
    let basename = literal.rsplit('/').next()?.trim();
    if basename.is_empty()
        || basename == "."
        || basename == ".."
        || !basename
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(basename.to_owned())
}

/// The route prefix `@fastify/autoload` derives from a route plugin's directory position. For a file
/// under an autoloaded directory, the subdirectory names between that directory and the file become
/// the prefix (`<autoload-dir>/api/utils/index.js` -> `/api/utils`); the file name itself never
/// contributes a segment. `None` when the repo does not autoload, or the file sits at an autoloaded
/// directory root (no enclosing subdirectory, so no prefix).
fn autoload_prefix(dir_names: &std::collections::BTreeSet<String>, file: &str) -> Option<String> {
    if dir_names.is_empty() {
        return None;
    }
    let components: Vec<&str> = Path::new(file)
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect();
    let file_idx = components.len().checked_sub(1)?;
    // The deepest autoloaded ancestor directory yields the most specific prefix.
    let anchor = components
        .get(..file_idx)?
        .iter()
        .rposition(|segment| dir_names.contains(*segment))?;
    let segments = components.get(anchor + 1..file_idx)?;
    if segments.is_empty() {
        return None;
    }
    Some(format!("/{}", segments.join("/")))
}

/// OS.js-style provider modules register routes through `proc.resource(path)`, which prefixes the
/// deployed path with `/apps/<metadata.name>`. Recover that prefix from the package's metadata so
/// findings, verification requests and exported inventories all name the real endpoint.
fn resource_prefix(root: &Path, file: &str, line: u32) -> Option<String> {
    let source_path = root.join(file);
    let source = std::fs::read_to_string(&source_path).ok()?;
    let first = line.saturating_sub(2) as usize;
    let uses_resource = source
        .lines()
        .skip(first)
        .take(5)
        .any(|text| text.contains(".resource("));
    if !uses_resource {
        return None;
    }
    let metadata = source_path.parent()?.join("metadata.json");
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(metadata).ok()?).ok()?;
    let name = value.get("name")?.as_str()?;
    if name.is_empty()
        || name
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return None;
    }
    Some(format!("/apps/{name}"))
}

/// The router a local name in `file` refers to: imported (followed to the exporting file) or local.
fn resolve_local(
    by_file: &BTreeMap<&str, &ScanReport>,
    file: &str,
    local: &str,
) -> Option<RouterId> {
    let report = by_file.get(file)?;
    // `api.router` with `api` an import: that module's `router` export.
    let (head, member) = match local.split_once('.') {
        Some((head, member)) => (head, Some(member)),
        None => (local, None),
    };
    match report.module.imports.iter().find(|i| i.local == head) {
        Some(import) => {
            let target_file = import.resolved.as_ref()?;
            let name = match (member, import.export.as_deref()) {
                (Some(member), _) => member,
                (None, export) => export.unwrap_or("default"),
            };
            locate_export(by_file, target_file, name, 0)
        }
        // A local router, or what a local factory returns (`app.use('/x', makeRouter())`).
        None => Some((file.to_owned(), product(report, local))),
    }
}

/// The router a module exports as `name`, followed through barrels: `export * from './users'`
/// and `export { usersRouter as users } from './users'` (up to 8 levels).
fn locate_export(
    by_file: &BTreeMap<&str, &ScanReport>,
    file: &str,
    name: &str,
    depth: usize,
) -> Option<RouterId> {
    let report = by_file.get(file)?;
    let reexports = &report.module.reexports;
    match report.module.exports.get(name) {
        // `exports.users = require('./users')`: that module's router.
        Some(local) if local.starts_with(crate::taint::NAMESPACE) && depth < 8 => {
            let target = local.trim_start_matches(crate::taint::NAMESPACE);
            locate_export(by_file, target, "default", depth + 1)
        }
        // Defined here, unless this file only re-exports it from another one.
        Some(local) => {
            if depth < 8 {
                for barrel in reexports {
                    if let Some(found) = locate_export(by_file, barrel, local, depth + 1) {
                        return Some(found);
                    }
                }
            }
            Some((file.to_owned(), product(report, local)))
        }
        None if depth < 8 => reexports
            .iter()
            .find_map(|barrel| locate_export(by_file, barrel, name, depth + 1)),
        None => None,
    }
}

/// The router an export stands for: itself, what it returns when it is a factory
/// (`module.exports = function () { ...; return router; }`), or, for a plugin that registers
/// on its first parameter (`async function users(fastify) { fastify.get(...) }`), that
/// parameter.
fn product(report: &ScanReport, exported: &str) -> String {
    let function = report.module.functions.iter().find(|f| f.name == exported);
    if let Some(local) = function.and_then(|f| f.returns_local.clone()) {
        return local;
    }
    if let Some(first) = function.and_then(|f| f.params.first())
        && (report
            .module
            .entries
            .iter()
            .any(|e| e.receiver.as_deref() == Some(first.as_str()))
            || report
                .module
                .mounts
                .iter()
                .any(|m| m.receiver.as_deref() == Some(first.as_str())))
    {
        return first.clone();
    }
    exported.to_owned()
}

/// Every prefix a router is reachable under (`""` for a root).
/// Every (prefix, mount authentication) a router is reachable under (`""` for a root).
fn prefixes(
    parents: &BTreeMap<RouterId, Vec<(RouterId, String, Auth)>>,
    router: &RouterId,
    memo: &mut BTreeMap<RouterId, Vec<(String, Auth)>>,
) -> Vec<(String, Auth)> {
    let mut path = Vec::new();
    prefixes_from(parents, router, &mut path, memo)
}

/// The prefixes a router is reachable under: every chain of mounts above it, each with the
/// strongest authentication on the way. A router mounted into itself (directly or through
/// others) is a root on the second visit, and at most `MAX_PREFIXES` prefixes are kept.
fn prefixes_from(
    parents: &BTreeMap<RouterId, Vec<(RouterId, String, Auth)>>,
    router: &RouterId,
    path: &mut Vec<RouterId>,
    memo: &mut BTreeMap<RouterId, Vec<(String, Auth)>>,
) -> Vec<(String, Auth)> {
    const MAX_PREFIXES: usize = 64;
    if let Some(known) = memo.get(router) {
        return known.clone();
    }
    let root = || vec![(String::new(), Auth::NoneDetected)];
    let Some(edges) = parents.get(router) else {
        return root();
    };
    if path.contains(router) || path.len() >= 8 {
        return root();
    }
    path.push(router.clone());
    let mut found: Vec<(String, Auth)> = Vec::new();
    for (parent, prefix, auth) in edges {
        if parent == router {
            // `router.use('/p', router)`: no prefix comes from mounting a router into itself.
            continue;
        }
        for (above, above_auth) in prefixes_from(parents, parent, path, memo) {
            let entry = (join(&above, prefix), above_auth.max(*auth));
            if !found.contains(&entry) && found.len() < MAX_PREFIXES {
                found.push(entry);
            }
        }
    }
    path.pop();
    if found.is_empty() {
        found = root();
    }
    // Only a complete result is reusable (one computed inside a cycle may miss its prefixes).
    if path.is_empty() {
        memo.insert(router.clone(), found.clone());
    }
    found
}

/// Joins URL path parts with exactly one `/` between them.
fn join(prefix: &str, path: &str) -> String {
    let joined = format!(
        "{}/{}",
        prefix.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let trimmed = if joined.len() > 1 {
        joined.trim_end_matches('/')
    } else {
        &joined
    };
    if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

/// Express parameters as OpenAPI templates: `/users/:id` becomes `/users/{id}`.
pub fn openapi_path(path: &str) -> String {
    let mut out = String::new();
    let mut chars = path.chars().peekable();
    let identifier = |chars: &mut std::iter::Peekable<std::str::Chars<'_>>| {
        let mut name = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                name.push(c);
                chars.next();
            } else {
                break;
            }
        }
        name
    };
    while let Some(c) = chars.next() {
        match c {
            // `:id`, `:id(\\d+)` (Express 4), `:date{[0-9]+}` (Hono), `:id?`, `:path*`.
            ':' => {
                let name = identifier(&mut chars);
                if let Some(&open @ ('(' | '{')) = chars.peek() {
                    let close = if open == '(' { ')' } else { '}' };
                    let mut depth = 0usize;
                    for inner in chars.by_ref() {
                        if inner == open {
                            depth += 1;
                        } else if inner == close {
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                break;
                            }
                        }
                    }
                }
                while chars.peek().is_some_and(|m| matches!(m, '?' | '*' | '+')) {
                    chars.next();
                }
                if name.is_empty() {
                    out.push(':');
                } else {
                    out.push_str(&format!("{{{name}}}"));
                }
            }
            // Express 5 named wildcard `*filepath`, or a bare `*`.
            '*' => {
                let name = identifier(&mut chars);
                let name = if name.is_empty() {
                    "wildcard".to_owned()
                } else {
                    name
                };
                out.push_str(&format!("{{{name}}}"));
            }
            // `{id}` already a parameter; `{/:id}` or `{.:format}` an Express 5 optional group.
            '{' => {
                let mut look = chars.clone();
                let name = identifier(&mut look);
                if !name.is_empty() && look.peek() == Some(&'}') {
                    look.next();
                    chars = look;
                    out.push_str(&format!("{{{name}}}"));
                }
            }
            '}' => {}
            other => out.push(other),
        }
    }
    out
}

/// The URL path of a file route: a named `GET`/`POST`/... export of a Next.js `app/**/route.ts`
/// (`kind` "file-route"), or the default export of a `pages/api/**` module ("default-export").
fn file_route_path(file: &str, kind: &str) -> Option<String> {
    let segments: Vec<&str> = file.split('/').collect();
    let stem = |s: &str| s.split('.').next().unwrap_or("").to_owned();
    let convert = |parts: &[&str]| -> String {
        let mut out = Vec::new();
        for part in parts {
            if part.starts_with('(') && part.ends_with(')') {
                continue; // route group
            }
            if part.starts_with('@') {
                continue; // parallel route slot
            }
            let inner = part.trim_start_matches('[').trim_end_matches(']');
            if part.starts_with("[[...") || part.starts_with("[...") {
                out.push(format!(
                    "{{{}}}",
                    inner.trim_start_matches("[...").trim_start_matches("...")
                ));
            } else if part.starts_with('[') {
                out.push(format!("{{{inner}}}"));
            } else {
                out.push((*part).to_owned());
            }
        }
        format!("/{}", out.join("/"))
    };
    if kind == "file-route" {
        if !segments.last().is_some_and(|last| stem(last) == "route") {
            return None;
        }
        // The app directory: `src/app`, else the first `app` that is not a package named `app`
        // (`packages/app/app/api/route.ts`).
        let at = segments
            .windows(2)
            .position(|w| w == ["src", "app"])
            .map(|i| i + 1)
            .or_else(|| {
                (0..segments.len()).find(|&i| {
                    segments.get(i) == Some(&"app")
                        && !matches!(segments.get(i + 1), Some(&"app" | &"src"))
                })
            })?;
        let parts = segments.get(at + 1..segments.len() - 1)?;
        return Some(convert(parts));
    }
    if let Some(at) = segments.windows(2).position(|w| w == ["pages", "api"]) {
        let mut parts: Vec<&str> = segments.get(at + 1..)?.to_vec();
        let last = parts.pop()?;
        let name = stem(last);
        let mut path = convert(&parts);
        if name != "index" {
            let converted = convert(&[name.as_str()]);
            path = join(&path, &converted);
        }
        return Some(path);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_join_and_convert() {
        assert_eq!(join("/api", "/users/"), "/api/users");
        assert_eq!(join("", "/"), "/");
        assert_eq!(
            openapi_path("/users/:id/posts/:post?"),
            "/users/{id}/posts/{post}"
        );
    }

    #[test]
    fn nextjs_file_routes() {
        assert_eq!(
            file_route_path("app/api/users/[id]/route.ts", "file-route").as_deref(),
            Some("/api/users/{id}")
        );
        assert_eq!(
            file_route_path("src/app/(admin)/x/route.js", "file-route").as_deref(),
            Some("/x")
        );
        assert_eq!(
            file_route_path("pages/api/hello.ts", "default-export").as_deref(),
            Some("/api/hello")
        );
        assert_eq!(
            file_route_path("pages/api/users/index.ts", "default-export").as_deref(),
            Some("/api/users")
        );
        assert_eq!(file_route_path("src/lib/util.ts", "file-route"), None);
        assert_eq!(file_route_path("src/lib/util.ts", "default-export"), None);
        // Each export form counts only where Next.js reads it.
        assert_eq!(
            file_route_path("app/api/x/route.ts", "default-export"),
            None
        );
        assert_eq!(file_route_path("pages/api/x.ts", "file-route"), None);
        assert_eq!(
            file_route_path("packages/app/app/api/x/route.ts", "file-route").as_deref(),
            Some("/api/x")
        );
        assert_eq!(
            file_route_path("packages/app/src/app/api/x/route.ts", "file-route").as_deref(),
            Some("/api/x")
        );
        assert_eq!(
            file_route_path("app/(dashboard)/app/route.ts", "file-route").as_deref(),
            Some("/app")
        );
    }

    #[test]
    fn autoload_directory_prefix() {
        let dirs: std::collections::BTreeSet<String> = ["routes".to_owned()].into_iter().collect();
        // Subdirectory names between the autoload dir and the route file become the prefix; the file
        // name itself never contributes a segment.
        assert_eq!(
            autoload_prefix(&dirs, "server/routes/api/utils/index.js").as_deref(),
            Some("/api/utils")
        );
        assert_eq!(
            autoload_prefix(&dirs, "server/routes/api/users.js").as_deref(),
            Some("/api")
        );
        // A file at the autoload root has no enclosing subdirectory, so no prefix.
        assert_eq!(autoload_prefix(&dirs, "server/routes/index.js"), None);
        // A repo that does not autoload gets no prefix.
        assert_eq!(
            autoload_prefix(
                &std::collections::BTreeSet::new(),
                "server/routes/api/x/index.js"
            ),
            None
        );
    }

    #[test]
    fn autoload_dir_literal_takes_the_trailing_segment() {
        assert_eq!(
            autoload_dir_literal(r#" path.join(__dirname, "./routes"),"#).as_deref(),
            Some("routes")
        );
        assert_eq!(
            autoload_dir_literal(r#" fs.joinPath(fs.rootPath, './plugins')"#).as_deref(),
            Some("plugins")
        );
        // A fully computed directory with no string literal is not recoverable.
        assert_eq!(autoload_dir_literal(" resolveRoutesDir(),"), None);
    }

    #[test]
    fn autoload_dir_names_reads_fastify_autoload_registration() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("server/plugins")).unwrap();
        std::fs::write(
            root.join("server/plugins/config.js"),
            "import FastifyAutoLoad from \"@fastify/autoload\";\n\
             fastify.register(FastifyAutoLoad, { dir: fs.joinPath(fs.rootPath, \"./routes\") });\n",
        )
        .unwrap();
        let names = autoload_dir_names(root);
        assert!(names.contains("routes"), "{names:?}");
    }
}
