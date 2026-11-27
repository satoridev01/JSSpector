use super::*;

/// Login and account-registration endpoints mined from every route source in the project, for a
/// login-gated finding whose entry and handler files do not themselves register the auth routes
/// (routes split across modules). Sources are concatenated and read once by [`auth_endpoints`], so
/// the exact-verb login tier is ranked across the whole project. Skips dependencies, build output and
/// VCS metadata, and stops after a bounded amount of source so a huge repository stays cheap.
pub fn project_auth_endpoints(root: &std::path::Path) -> (Vec<String>, Vec<String>) {
    let mut text = String::new();
    for_each_project_source(root, |src| {
        text.push_str(src);
        text.push_str("\n;\n");
    });
    auth_endpoints(&text)
}

/// The account fields a registration handler requires beyond the generic credentials
/// [`super::payload::credential_post`] sends: a confirmation (`cpassword`), a display `name`. Read from
/// the request-body fields of every project source that reads a password from the body (the signup
/// route, or a passport strategy in its own module). Only credential and identity fields are taken —
/// password/confirmation, email, and name-like (`name`, `fullName`, `login`) — so the throwaway account
/// never sets a role, a flag or any other attribute the app would not let a visitor choose.
pub fn registration_fields(root: &std::path::Path) -> Vec<String> {
    const MAX_FIELDS: usize = 12;
    let mut fields: Vec<String> = Vec::new();
    for_each_project_source(root, |src| {
        let names = body_field_names(src);
        if !names
            .iter()
            .any(|name| credential_field(name) == Some(CredentialField::Password))
        {
            return;
        }
        for name in names {
            if credential_field(&name).is_some()
                && !fields.contains(&name)
                && fields.len() < MAX_FIELDS
            {
                fields.push(name);
            }
        }
    });
    fields
}

/// Which credential a registration field carries, by its name; `None` for any other attribute.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CredentialField {
    Password,
    Email,
    Name,
}

pub fn credential_field(name: &str) -> Option<CredentialField> {
    let lower = name.to_ascii_lowercase();
    if lower.contains("pass") || lower.contains("pwd") {
        Some(CredentialField::Password)
    } else if lower.contains("mail") {
        Some(CredentialField::Email)
    } else if ["name", "user", "login", "nick"]
        .iter()
        .any(|word| lower.contains(word))
    {
        Some(CredentialField::Name)
    } else {
        None
    }
}

/// The request-body field names a source reads: `req.body.x`, `body['x']`, and the names
/// destructured from it (`const { a, b: c } = req.body`).
fn body_field_names(src: &str) -> Vec<String> {
    let ident = |s: &str| -> String {
        s.chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
            .collect()
    };
    let mut names: Vec<String> = Vec::new();
    let mut push = |name: String| {
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
    };
    for (at, _) in src.match_indices("body") {
        let rest = &src[at + "body".len()..];
        if let Some(after) = rest.strip_prefix('.') {
            push(ident(after));
        } else if let Some(after) = rest.strip_prefix("['").or_else(|| rest.strip_prefix("[\"")) {
            push(ident(after));
        }
    }
    // `{ a, b: c } = req.body`: the keys before `}` that precede `= <x>.body`.
    for (at, _) in src.match_indices(".body") {
        let before = src[..at].trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
        let Some(before) = before.trim_end().strip_suffix('=') else {
            continue;
        };
        let Some(close) = before.trim_end().strip_suffix('}') else {
            continue;
        };
        let Some(open) = close.rfind('{') else {
            continue;
        };
        for key in close[open + 1..].split(',') {
            let key = key.split(':').next().unwrap_or_default().trim();
            push(ident(key));
        }
    }
    names
}

/// Calls `visit` with the text of every JavaScript/TypeScript source in the project, skipping
/// dependencies, build output and VCS metadata, up to a bounded total.
fn for_each_project_source(root: &std::path::Path, mut visit: impl FnMut(&str)) {
    const MAX_BYTES: usize = 8 * 1024 * 1024;
    let mut seen = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if !matches!(
                    name.as_ref(),
                    "node_modules" | ".git" | ".next" | "dist" | "build" | "coverage" | "vendor"
                ) {
                    stack.push(path);
                }
                continue;
            }
            let script = path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs" | "ts" | "mts" | "cts"));
            if !script || name.ends_with(".min.js") || name.ends_with(".d.ts") {
                continue;
            }
            if let Ok(src) = std::fs::read_to_string(&path) {
                seen += src.len();
                visit(&src);
                if seen > MAX_BYTES {
                    return;
                }
            }
        }
    }
}

/// Login endpoints to mint a first-run session against when a finding's route is gated by a
/// framework request-middleware (a Next.js `middleware` with a `matcher`, a global request proxy)
/// rather than an in-handler check. Returns `Some(login_paths)` — most-conventional first — when
/// (a) the repository has such a middleware whose matcher covers the route and whose own source or a
/// module it imports enforces authentication (a 401/`Unauthorized` gated on a session/login state),
/// and (b) at least one login endpoint is discoverable. `None` otherwise. Everything is mined by
/// generic framework convention and authentication vocabulary; nothing names a specific app.
pub fn framework_auth_login_paths(root: &std::path::Path, route_path: &str) -> Option<Vec<String>> {
    if !middleware_auth_gate_covers(root, route_path) {
        return None;
    }
    let mut paths = next_app_router_login_paths(root);
    // Also mine the middleware and route-registration sources for login endpoints, reusing the
    // generic auth vocabulary. Covers routers that list routes in a central module.
    for file in middleware_source_files(root) {
        if let Ok(src) = std::fs::read_to_string(&file) {
            let (login, _) = auth_endpoints(&src);
            for p in login {
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
    }
    (!paths.is_empty()).then_some(paths)
}

/// Login endpoints to mint a first-run session against when a finding's route is gated by a classic
/// request-level authentication middleware the app mounts on itself (an Express/Connect
/// `app.use(requireAuth())` with no path, or `app.use('/api', requireAuth())` whose mount prefix
/// covers the route). The engine reports such a route as having no in-handler authentication because
/// the gate is a separate middleware registered once on the app, yet an anonymous probe is turned
/// away before the sink. The gate is real route-level authentication a deployment configures, so it
/// is reproduced like the framework-middleware case: mint a session through the app's own login route
/// with the deployment's configured credential and carry it back on the gated request. Returns
/// `Some(login_paths)` when (a) the project registers a route-covering `.use(...)` whose middleware
/// function — found in a project module that enforces authentication — is an auth gate, and (b) a
/// login endpoint is discoverable. `None` otherwise. Everything is mined by framework convention and
/// authentication vocabulary; nothing names a specific app.
pub fn request_middleware_login_paths(
    root: &std::path::Path,
    route_path: &str,
) -> Option<Vec<String>> {
    if !global_request_auth_gate(root, route_path) {
        return None;
    }
    let (login, _) = project_auth_endpoints(root);
    (!login.is_empty()).then_some(login)
}

/// Whether the project registers a route-level authentication middleware via `.use()` whose mount
/// covers `route_path` and whose middleware function enforces authentication. Two passes over the
/// project sources: collect the identifiers passed to a route-covering `.use(...)`, then confirm at
/// least one resolves to a module that enforces auth ([`source_enforces_auth`]). Conservative: a
/// `.use()` of a body parser, a static-file handler or a host guard that produces no 401/`Unauthorized`
/// does not read as an auth gate.
fn global_request_auth_gate(root: &std::path::Path, route_path: &str) -> bool {
    let mut idents: Vec<String> = Vec::new();
    for_each_project_source(root, |src| {
        for ident in use_middleware_idents(src, route_path) {
            if !idents.contains(&ident) {
                idents.push(ident);
            }
        }
    });
    if idents.is_empty() {
        return false;
    }
    let mut gated = false;
    for_each_project_source(root, |src| {
        if !gated
            && source_enforces_auth(src)
            && idents.iter().any(|ident| source_defines(src, ident))
        {
            gated = true;
        }
    });
    gated
}

/// Identifiers of middlewares the source mounts with a route-covering `.use(...)`: the bare function
/// called/referenced in `app.use(requireAuth())` / `router.use(requireAuth)` (global mount, covers
/// every route) or in `app.use('/api', requireAuth())` whose string mount prefix covers `route_path`.
/// A `.use()` whose only argument is a path string (a static mount with no middleware identifier) and
/// one whose mount prefix does not cover the route contribute nothing.
fn use_middleware_idents(src: &str, route_path: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (at, _) in src.match_indices(".use(") {
        let arg = src[at + ".use(".len()..].trim_start();
        let (middleware, covered) = match first_string_literal(arg) {
            // A path-mounted middleware: the prefix decides coverage, the middleware is the next arg.
            Some(prefix) => (
                arg.split_once(',').map_or("", |x| x.1).trim_start(),
                mount_prefix_covers(&prefix, route_path),
            ),
            // A global mount with no path argument covers every route.
            None => (arg, true),
        };
        if !covered {
            continue;
        }
        if let Some(ident) = leading_ident(middleware) {
            out.push(ident);
        }
    }
    out
}

/// Whether a `.use()` mount prefix covers a concrete route path: an empty or `/` prefix mounts
/// globally, otherwise the route must equal the prefix or sit under it.
fn mount_prefix_covers(prefix: &str, route_path: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    prefix.is_empty() || route_path == prefix || route_path.starts_with(&format!("{prefix}/"))
}

/// The leading identifier of an expression: `requireAuth()` -> `requireAuth`, `express.json()` ->
/// `express`, `requireAuth` -> `requireAuth`. `None` when the expression does not start with an
/// identifier character (a nested call, an object literal, another string).
fn leading_ident(expr: &str) -> Option<String> {
    let ident: String = expr
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
        .collect();
    (!ident.is_empty()).then_some(ident)
}

/// Whether a source defines a binding named `ident` as a function/const/class (its own module, where
/// the auth middleware is implemented). Whole-identifier match so `requireAuth` does not match
/// `requireAuthToken`.
fn source_defines(src: &str, ident: &str) -> bool {
    for keyword in ["function ", "const ", "let ", "var ", "class "] {
        let needle = format!("{keyword}{ident}");
        let mut from = 0;
        while let Some(pos) = src[from..].find(&needle) {
            let end = from + pos + needle.len();
            if src.as_bytes().get(end).is_none_or(|byte| !is_ident(*byte)) {
                return true;
            }
            from = end;
        }
    }
    false
}

/// Candidate Next.js / global request-middleware source files: a module that exports a default
/// function *and* an `export const config` naming a `matcher`. Excludes build output and
/// dependencies. The file name is not required to be `middleware` — some projects export their
/// middleware from a differently named module re-exported through the framework's entry.
fn middleware_source_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = entry.file_name();
                if name != "node_modules" && name != ".git" && name != ".next" && name != "dist" {
                    stack.push(path);
                }
            } else if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs" | "ts" | "tsx"))
                && let Ok(src) = std::fs::read_to_string(&path)
                && declares_middleware_matcher(&src)
            {
                found.push(path);
            }
        }
        if found.len() >= 8 {
            break;
        }
    }
    found
}

/// Whether a source declares a framework request-middleware: a default export plus a `config` with a
/// `matcher`. This is the Next.js middleware contract, and a reliable, framework-generic marker that
/// the module gates requests.
fn declares_middleware_matcher(src: &str) -> bool {
    let has_default = src.contains("export default") || src.contains("export { default");
    let has_matcher = src.contains("matcher")
        && (src.contains("export const config") || src.contains("export let config"));
    has_default && has_matcher
}

/// Whether a repository middleware's matcher covers `route_path` and the middleware enforces
/// authentication. Conservative: requires an actual auth gate (a 401/`Unauthorized`, or a
/// session/login/`requireLogin` check) in the middleware file or a sibling module, so an unrelated
/// rewriting middleware does not trigger a login bootstrap.
fn middleware_auth_gate_covers(root: &std::path::Path, route_path: &str) -> bool {
    for file in middleware_source_files(root) {
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        if !matcher_covers_route(&src, route_path) {
            continue;
        }
        if source_enforces_auth(&src) {
            return true;
        }
        // The gate may live in a guard module the middleware imports (a common split: the middleware
        // delegates to `dashboardGuard`/`authMiddleware`). Check sibling modules in the same folder.
        if let Some(parent) = file.parent()
            && let Ok(entries) = std::fs::read_dir(parent)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                if path == file || !path.is_file() {
                    continue;
                }
                if path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs" | "ts" | "tsx"))
                    && let Ok(guard) = std::fs::read_to_string(&path)
                    && source_enforces_auth(&guard)
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Whether a source enforces authentication: it produces an unauthorized response (`401`, the word
/// `Unauthorized`) and reads an authentication state (a session/login/token check). Both are required
/// so a module that merely mentions one word in passing does not read as an auth gate.
pub(super) fn source_enforces_auth(src: &str) -> bool {
    let denies =
        src.contains("401") || src.contains("Unauthorized") || src.contains("unauthorized");
    let checks = [
        "isAuthenticated",
        "requireLogin",
        "auth_token",
        "getToken",
        "verify",
    ]
    .iter()
    .any(|needle| src.contains(needle))
        || (src.contains("cookies") && (src.contains("token") || src.contains("session")));
    denies && checks
}

/// Whether any `matcher` entry in a middleware source covers `route_path`. Handles the two common
/// matcher forms: a catch-all negative-lookahead (`/((?!_next|favicon).*)`) that matches every path
/// except the excluded static assets, and a path-prefix form (`/api/:path*`, `/dashboard/:path*`).
fn matcher_covers_route(src: &str, route_path: &str) -> bool {
    for literal in matcher_literals(src) {
        if matcher_entry_covers(&literal, route_path) {
            return true;
        }
    }
    false
}

/// The string literals inside a `matcher: [ ... ]` (or `matcher: "..."`) declaration.
fn matcher_literals(src: &str) -> Vec<String> {
    let Some(pos) = src.find("matcher") else {
        return Vec::new();
    };
    let after = &src[pos..];
    // Bound the scan to the matcher's own array/string, not the rest of the file.
    let end = after
        .find(']')
        .or_else(|| after.find('}'))
        .map(|e| e + 1)
        .unwrap_or_else(|| super::capped_end(after, after.len(), 400));
    let region = &after[..end.min(after.len())];
    let mut out = Vec::new();
    for quote in ['"', '\'', '`'] {
        let mut from = 0;
        while let Some(start) = region[from..].find(quote) {
            let s = from + start + 1;
            if let Some(len) = region[s..].find(quote) {
                out.push(region[s..s + len].to_owned());
                from = s + len + 1;
            } else {
                break;
            }
        }
    }
    out
}

/// Whether a single matcher entry covers a concrete route path.
pub(super) fn matcher_entry_covers(entry: &str, route_path: &str) -> bool {
    if !entry.starts_with('/') {
        return false;
    }
    // A negative-lookahead catch-all (`/((?!a|b).*)`) matches everything except the listed prefixes.
    if entry.contains("(?!") {
        if let Some(start) = entry.find("(?!") {
            let rest = &entry[start + 3..];
            let group = rest.split(')').next().unwrap_or("");
            for excluded in group.split('|') {
                let excluded = excluded.trim().trim_start_matches('/');
                let excluded = excluded
                    .split(['\\', '(', '.', '*', '?'])
                    .next()
                    .unwrap_or("");
                if !excluded.is_empty() && route_path.trim_start_matches('/').starts_with(excluded)
                {
                    return false;
                }
            }
        }
        return true;
    }
    // A path-prefix form: the static prefix before any pattern token must prefix the route.
    let prefix: String = entry
        .chars()
        .take_while(|c| !matches!(c, ':' | '*' | '(' | '[' | '?'))
        .collect();
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        // Bare `/` or `/:path*` catch-all.
        return true;
    }
    route_path == prefix || route_path.starts_with(&format!("{prefix}/"))
}

/// Login endpoint URL paths discovered from a Next.js App Router layout: a `route.{js,ts,...}` file
/// whose directory chain's last concrete segment is generic login vocabulary (`login`, `signin`,
/// `authenticate`, `session`). The file path under `app/` becomes the URL path, route-group segments
/// (`(auth)`) dropped and dynamic segments (`[id]`) skipped. Convention-based; no app-specific names.
pub fn next_app_router_login_paths(root: &std::path::Path) -> Vec<String> {
    const LOGIN_SEGMENTS: [&str; 6] = [
        "login",
        "signin",
        "sign-in",
        "authenticate",
        "session",
        "sessions",
    ];
    let mut paths = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = entry.file_name();
                if name != "node_modules" && name != ".git" && name != ".next" {
                    stack.push(path);
                }
            } else if path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| stem == "route")
                && let Some(url) = app_router_route_url(root, &path)
                && url
                    .rsplit('/')
                    .find(|seg| !seg.is_empty())
                    .is_some_and(|last| LOGIN_SEGMENTS.contains(&last))
                && !paths.contains(&url)
            {
                paths.push(url);
            }
        }
    }
    paths
}

/// The URL path a Next.js App Router `route` file serves: the segments after an `app/` (or
/// `src/app/`) directory, with route-group segments `(group)` dropped. `None` for a file not under
/// an `app` directory, or one whose path still contains a dynamic `[param]` segment (no concrete URL).
fn app_router_route_url(root: &std::path::Path, route_file: &std::path::Path) -> Option<String> {
    let rel = route_file.strip_prefix(root).ok()?;
    let components: Vec<String> = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str().map(str::to_owned))
        .collect();
    let app_idx = components.iter().rposition(|c| c == "app")?;
    let mut segments = Vec::new();
    for seg in components.get(app_idx + 1..).unwrap_or_default() {
        if seg.ends_with(".js")
            || seg.ends_with(".ts")
            || seg.ends_with(".tsx")
            || seg.ends_with(".mjs")
            || seg.ends_with(".cjs")
        {
            break; // the `route.*` file itself
        }
        if seg.starts_with('(') && seg.ends_with(')') {
            continue; // route group: not part of the URL
        }
        if seg.starts_with('[') {
            return None; // dynamic segment: no single concrete URL
        }
        segments.push(seg.clone());
    }
    Some(format!("/{}", segments.join("/")))
}

/// The cookie name a handler reads a session token from when the sink sits on a branch guarded by
/// that session (`const u = sessions.get(req.cookies.token); if (u) { fetch(url) }`): the sink is
/// reachable only for a request whose `req.cookies.<name>` resolves to a live session, so the
/// verifier must mint one and carry it under that cookie. Returns the cookie name when the handler
/// (a) reads `req.cookies.<name>` into a local, (b) branches on that local (`if (local)` /
/// `if (!local)`), and (c) the sink line falls after that branch. `None` when no such in-handler
/// session guard precedes the sink — the common unauthenticated case, left untouched. Recognizes
/// only the handler's *own* credential read, never a route-level auth middleware (which the engine
/// already reports through `finding.auth`); nothing here is tied to a specific app.
pub fn session_cookie_gate(source: &str, sink_line: usize) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        // A local bound to a value read from a request cookie: `const u = X.get(req.cookies.token)`,
        // `let u = req.cookies.token`. Capture the bound local and the cookie name.
        let Some((local, cookie)) = cookie_binding(line) else {
            continue;
        };
        let read_line = idx + 1;
        // The sink must sit after the cookie read, and the local must gate a branch between the read
        // and the sink. A guard that references the local anywhere before the sink line is enough: it
        // is the authentication check the handler performs before reaching the sink.
        if read_line >= sink_line {
            continue;
        }
        // Scan from the cookie read up to and including the sink line: the guard may sit on its own
        // line above the sink (`if (u) {` then `fetch(url)`) or wrap it inline (`if (u) { fetch(url) }`).
        let guards = lines
            .iter()
            .take(sink_line)
            .skip(idx)
            .any(|l| branches_on_local(l, &local));
        if guards {
            return Some(cookie);
        }
    }
    None
}

/// The `(local, cookie)` of a line binding a local to a request-cookie read: `const u =
/// sessions.get(req.cookies.token)`, `let token = req.cookies.sid`. `None` for a line that is not
/// such a binding.
fn cookie_binding(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    let rest = ["const ", "let ", "var "]
        .iter()
        .find_map(|kw| trimmed.strip_prefix(kw))?;
    let (local, rhs) = rest.split_once('=')?;
    let local = local.trim();
    // A single plain identifier on the left (not a destructure), used later as a boolean guard.
    if local.is_empty() || !local.bytes().all(is_ident) {
        return None;
    }
    let cookie = cookie_name_in(rhs)?;
    Some((local.to_owned(), cookie))
}

/// The cookie name read in an expression: the `<name>` of the first `req.cookies.<name>` (or
/// `request.cookies.<name>`, `.cookies["<name>"]`) accessor. `None` when the expression reads no
/// request cookie.
fn cookie_name_in(expr: &str) -> Option<String> {
    let marker = ".cookies";
    let mut from = 0;
    while let Some(pos) = expr[from..].find(marker) {
        let after = &expr[from + pos + marker.len()..];
        // Preceding token should be a request object (`req`/`request`/`ctx.req`); keep it permissive
        // but require the accessor to read a concrete cookie name.
        if let Some(rest) = after.strip_prefix('.') {
            let name: String = rest
                .bytes()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        } else if let Some(rest) = after.strip_prefix('[')
            && let Some(name) = unquote(rest.split(']').next().unwrap_or("").trim())
            && !name.is_empty()
        {
            return Some(name);
        }
        from += pos + marker.len();
    }
    None
}

/// Whether a line is a boolean branch on `local`: `if (local)`, `if (!local)`, `if (local &&`,
/// `} else if (local`, a ternary `local ?`. Used to confirm the session local gates the sink.
fn branches_on_local(line: &str, local: &str) -> bool {
    let trimmed = line.trim_start();
    if !(trimmed.contains("if (") || trimmed.contains("if(") || trimmed.contains('?')) {
        return false;
    }
    // Find `local` as a whole word adjacent to a boolean context (`(`, `!`, `&&`, `||`, whitespace).
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(pos) = line[from..].find(local) {
        let start = from + pos;
        let end = start + local.len();
        let before_ok = bytes
            .get(start.wrapping_sub(1))
            .is_none_or(|byte| !is_ident(*byte));
        let after_ok = bytes.get(end).is_none_or(|byte| !is_ident(*byte));
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// Candidate login and account-registration endpoints mined from route-registration `source`, for a
/// sink gated behind an in-handler session the verifier must mint. Returns `(login, register)` path
/// lists: login paths are those whose final concrete segment is generic authentication vocabulary
/// (`login`, `signin`, `authenticate`, `session`, `token`), register paths those whose final
/// concrete segment is a user/account collection (`users`, `accounts`, `register`, `signup`). Static
/// absolute paths only (`'/rest/user/login'`); parameterized and relative specifiers are dropped.
/// The vocabulary is generic HTTP-auth naming, not any one app's routes.
pub fn auth_endpoints(source: &str) -> (Vec<String>, Vec<String>) {
    const LOGIN_WORDS: [&str; 7] = [
        "login",
        "signin",
        "sign-in",
        "authenticate",
        "session",
        "sessions",
        "token",
    ];
    const REGISTER_WORDS: [&str; 10] = [
        "users",
        "user",
        "accounts",
        "account",
        "register",
        "signup",
        "sign-up",
        "registration",
        "customers",
        "members",
    ];
    // Login endpoints are ranked: an endpoint whose final segment is exactly an auth verb
    // (`/rest/user/login`) is a far stronger candidate than one that merely contains the word
    // (`/rest/passkey/login-options`, `/rest/saveLoginIp`), which may return an unrelated challenge
    // token. The exact-match tier is tried first so the real session login is reached before a weaker
    // lookalike can short-circuit the bootstrap.
    let mut login_exact = Vec::new();
    let mut login_loose = Vec::new();
    let mut register = Vec::new();
    for path in route_path_literals(source) {
        // Only directly driveable paths: a parameterized segment (`/api/Users/:id`, `/x/{id}`) cannot
        // be filled with a real value here, so skip it.
        if path.contains("/:") || path.contains('{') {
            continue;
        }
        let Some(last) = path.rsplit('/').find(|seg| !seg.is_empty()) else {
            continue;
        };
        let last = last.to_ascii_lowercase();
        let lower = path.to_ascii_lowercase();
        if LOGIN_WORDS.contains(&last.as_str()) {
            if !login_exact.contains(&path) {
                login_exact.push(path);
            }
        } else if lower.contains("login") || lower.contains("signin") {
            if !login_loose.contains(&path) {
                login_loose.push(path);
            }
        } else if REGISTER_WORDS.contains(&last.as_str()) && !register.contains(&path) {
            register.push(path);
        }
    }
    login_exact.extend(login_loose);
    (login_exact, register)
}

/// Absolute route path string literals a router-registration source declares: the first string
/// argument of a `.get(`/`.post(`/`.put(`/`.patch(`/`.delete(`/`.all(`/`.use(`/`.route(` call that is
/// an absolute path (`'/rest/user/login'`). Parameterized and query-bearing noise is tolerated — the
/// raw literal is returned for the caller to classify and drive.
fn route_path_literals(source: &str) -> Vec<String> {
    const CALLS: [&str; 9] = [
        ".get(", ".post(", ".put(", ".patch(", ".delete(", ".all(", ".use(", ".route(", ".head(",
    ];
    let mut out = Vec::new();
    for call in CALLS {
        let mut from = 0;
        while let Some(pos) = source[from..].find(call) {
            let after = &source[from + pos + call.len()..];
            from += pos + call.len();
            let arg = after.trim_start();
            let Some(lit) = first_string_literal(arg) else {
                continue;
            };
            if lit.starts_with('/') && lit.len() > 1 && !out.contains(&lit) {
                out.push(lit);
            }
        }
    }
    out
}

/// The first single- or double-quoted string literal at the start of `text` (allowing a leading
/// quote only), without escapes handling beyond what a route literal needs. `None` when `text` does
/// not begin with a quote.
fn first_string_literal(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let quote = *bytes.first()?;
    if quote != b'\'' && quote != b'"' && quote != b'`' {
        return None;
    }
    let mut value = String::new();
    for &b in bytes.get(1..)? {
        if b == quote {
            return Some(value);
        }
        if b == b'\n' {
            return None;
        }
        value.push(b as char);
    }
    None
}
