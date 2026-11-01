//! The entry-point inventory: every route with its full path, linked across files.
//!
//! Each file reports the routes it registers (on a router variable), the routers it mounts under
//! a prefix, and its exports and resolved imports. Mounts are followed across files (imports
//! resolve to a file, exports name the router there), prefixes are joined, and file-system
//! conventions (Next.js `app/**/route.ts`, `pages/api/**`) give the path of file routes.

use std::collections::{BTreeMap, BTreeSet};

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
    pub handler: String,
    pub auth: Auth,
    /// `http`, `socket`, `ipc`, `graphql`, `trpc`, `queue`, ...
    pub kind: String,
    /// Request inputs the handler reads: `query.q`, `body.email`.
    pub inputs: Vec<String>,
}

/// A router: a variable in a file.
type RouterId = (String, String);

/// Builds the inventory from scan reports.
pub fn inventory(reports: &[ScanReport]) -> Vec<Route> {
    let by_file: BTreeMap<&str, &ScanReport> = reports
        .iter()
        .filter(|r| r.status == ScanStatus::Scanned)
        .map(|r| (r.rel_path.as_str(), r))
        .collect();

    // Mount edges: child router -> (parent router, prefix).
    let mut parents: BTreeMap<RouterId, Vec<(RouterId, String)>> = BTreeMap::new();
    for (file, report) in &by_file {
        for mount in &report.module.mounts {
            let Some(parent) = &mount.receiver else {
                continue;
            };
            let child = match (&mount.target, &mount.target_file) {
                (Some(local), _) => resolve_local(&by_file, file, local),
                (None, Some(target_file)) => default_export(&by_file, target_file),
                (None, None) => None,
            };
            if let Some(child) = child {
                parents
                    .entry(child)
                    .or_default()
                    .push(((file.to_string(), parent.clone()), mount.prefix.clone()));
            }
        }
    }

    let mut routes = BTreeSet::new();
    for (file, report) in &by_file {
        for entry in &report.module.entries {
            let prefixes = match &entry.receiver {
                Some(receiver) => prefixes(&parents, &(file.to_string(), receiver.clone()), 0),
                None => vec![String::new()],
            };
            let path = match entry.kind.as_str() {
                "file-route" | "default-export" => match file_route_path(file) {
                    Some(path) => path,
                    None => continue,
                },
                _ => entry.path.clone(),
            };
            for prefix in prefixes {
                let full = if entry.kind == "http" || entry.kind == "file-route" {
                    openapi_path(&join(&prefix, &path))
                } else {
                    path.clone()
                };
                routes.insert(Route {
                    method: entry.method.clone(),
                    path: full,
                    file: file.to_string(),
                    line: entry.line,
                    handler: entry.handler.clone(),
                    auth: entry.auth,
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
                });
            }
        }
    }
    routes.into_iter().collect()
}

/// The router a local name in `file` refers to: imported (followed to the exporting file) or local.
fn resolve_local(
    by_file: &BTreeMap<&str, &ScanReport>,
    file: &str,
    local: &str,
) -> Option<RouterId> {
    let report = by_file.get(file)?;
    match report.module.imports.iter().find(|i| i.local == local) {
        Some(import) => {
            let target_file = import.resolved.as_ref()?;
            let target = by_file.get(target_file.as_str())?;
            let name = import.export.as_deref().unwrap_or("default");
            let exported = target.module.exports.get(name)?;
            Some((target_file.clone(), product(target, exported)))
        }
        None => Some((file.to_owned(), local.to_owned())),
    }
}

fn default_export(by_file: &BTreeMap<&str, &ScanReport>, file: &str) -> Option<RouterId> {
    let report = by_file.get(file)?;
    let exported = report.module.exports.get("default")?;
    Some((file.to_owned(), product(report, exported)))
}

/// The router an export stands for: itself, or what it returns when it is a factory
/// (`module.exports = function () { ...; return router; }`).
fn product(report: &ScanReport, exported: &str) -> String {
    report
        .module
        .functions
        .iter()
        .find(|f| f.name == exported)
        .and_then(|f| f.returns_local.clone())
        .unwrap_or_else(|| exported.to_owned())
}

/// Every prefix a router is reachable under (`""` for a root).
fn prefixes(
    parents: &BTreeMap<RouterId, Vec<(RouterId, String)>>,
    router: &RouterId,
    depth: usize,
) -> Vec<String> {
    match parents.get(router) {
        Some(edges) if depth < 8 => edges
            .iter()
            .flat_map(|(parent, prefix)| {
                prefixes(parents, parent, depth + 1)
                    .into_iter()
                    .map(move |above| join(&above, prefix))
            })
            .collect(),
        _ => vec![String::new()],
    }
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
    // Express 5 optional groups: `/exchange{/:id}` is `/exchange/:id` or `/exchange`.
    let path = if path.contains(':') {
        path.replace(['{', '}'], "")
    } else {
        path.to_owned()
    };
    path.split('/')
        .map(|segment| match segment.strip_prefix(':') {
            Some(name) => format!("{{{}}}", name.trim_end_matches('?')),
            None => segment.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The URL path of a file route: Next.js `app/**/route.ts` or `pages/api/**`.
fn file_route_path(file: &str) -> Option<String> {
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
    if let Some(at) = segments.iter().position(|s| *s == "app")
        && segments.last().is_some_and(|last| stem(last) == "route")
    {
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
            file_route_path("app/api/users/[id]/route.ts").as_deref(),
            Some("/api/users/{id}")
        );
        assert_eq!(
            file_route_path("src/app/(admin)/x/route.js").as_deref(),
            Some("/x")
        );
        assert_eq!(
            file_route_path("pages/api/hello.ts").as_deref(),
            Some("/api/hello")
        );
        assert_eq!(
            file_route_path("pages/api/users/index.ts").as_deref(),
            Some("/api/users")
        );
        assert_eq!(file_route_path("src/lib/util.ts"), None);
    }
}
