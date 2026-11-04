//! Deciding what a finding implies as an HTTP request, with no I/O. `--verify` runs the derived
//! request against the app in a container (see [`super::sandbox`]); this module only works out
//! what to send and how to tell a reproduction from a miss, so it can be unit-tested on its own.

use jss_core::{Auth, Finding, VulnClass};

/// Where in the request a tainted value enters, read from the finding's source expression
/// (`req.query.name`, `req.body.path`, `req.params.id`, `req.headers['x']`, `req.url`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// `?name=...`
    Query(String),
    /// A field of the JSON body (`{ "path": ... }`), or the whole body when the name is unknown.
    Body(Option<String>),
    /// A `{param}` segment of the route path, filled with the payload.
    PathParam(String),
    /// A request header.
    Header(String),
    /// The request path itself (`req.url`, a catch-all route): the payload is the path.
    Url,
}

/// A finding we know how to drive: a method, a route path (with `{param}` slots), where the
/// payload enters, and the class that decides the payload and the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub method: Method,
    /// The route path, `{param}` segments kept (`/barcode/{key}`); never empty, always leads
    /// with `/`.
    pub path: String,
    pub entry: Entry,
    pub class: VulnClass,
    /// Other request parameters, in the same part as `entry` (query or body), the handler needs
    /// present and valid before the tainted one reaches the sink — name and value. Filled from the
    /// handler source (see [`required_siblings`]); empty for a handler that guards nothing else.
    pub siblings: Vec<(String, String)>,
    /// URL path prefixes the handler compares the request path against before it reaches the sink
    /// (`pathname === "/ide"`, `pathname.startsWith("/ide/")`). Mined from the handler source, so a
    /// gated forward-proxy sink can be reached under a path it actually accepts. Empty when the
    /// handler guards no path.
    pub gate_paths: Vec<String>,
}

impl Probe {
    /// The request part and parameter name the payload enters through, when it is a named query or
    /// body field — the only entries that take sibling parameters. `None` for a header, path
    /// segment, whole body or raw URL.
    pub fn entry_part(&self) -> Option<(&'static str, &str)> {
        match &self.entry {
            Entry::Query(name) => Some(("query", name)),
            Entry::Body(Some(name)) => Some(("body", name)),
            _ => None,
        }
    }
}

/// What the sandbox should do with a finding: drive it as an HTTP request (the server-side
/// phase) or load it in a headless browser (a DOM-source XSS or client-side redirect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Http(Probe),
    Browser(BrowserProbe),
}

/// A finding whose attacker input is the page's own URL and whose sink runs in the browser: the
/// file holding the vulnerable script (to find the page that loads it), where in the URL the
/// value enters, and whether the sink writes HTML or navigates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserProbe {
    pub file: String,
    pub vector: UrlVector,
    pub sink: BrowserSink,
}

/// Where in the page URL the attacker value is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlVector {
    /// `location.search` (`?x=...`).
    Search,
    /// `location.hash` (`#...`).
    Hash,
    /// `location.href` / `new URL(location.href)` / `location` (anywhere in the URL).
    Href,
    /// `document.referrer` (the referring page's URL).
    Referrer,
}

/// What the browser sink does with the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserSink {
    /// Written as HTML (`innerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()`).
    Html,
    /// Used to navigate (`location =`, `location.href =`, `window.open`, `location.assign`).
    Navigation,
}

/// The sandbox's decision for a finding: drive it, or skip it with a reason. The source-free
/// convenience form of [`plan_with_source`], used where the handler source is not at hand.
#[allow(dead_code)]
pub fn plan(finding: &Finding) -> Result<Plan, Skip> {
    plan_with_source(finding, None)
}

/// Like [`plan`], but given the handler's own source (the finding's file) it can resolve a
/// request input the finding only names coarsely — e.g. a `req.headers` source whose specific
/// header the handler reads in a URL/host position. `None` source falls back to finding fields
/// alone.
pub fn plan_with_source(finding: &Finding, source: Option<&str>) -> Result<Plan, Skip> {
    // Server-side HTTP findings first.
    match Probe::from_finding_with_source(finding, source) {
        Ok(probe) => return Ok(Plan::Http(probe)),
        Err(http_skip) => {
            // Only fall through to the browser phase for a page-side (DOM) source; otherwise the
            // HTTP skip reason is the right one.
            if finding.source.kind != "dom" {
                return Err(http_skip);
            }
        }
    }
    browser_probe(finding).map(Plan::Browser)
}

/// A DOM-source XSS or client-side redirect the browser phase can drive, or why not.
fn browser_probe(finding: &Finding) -> Result<BrowserProbe, Skip> {
    if finding.class != VulnClass::Xss {
        return Err(Skip(format!(
            "{} from a DOM source is not driven by verify v1 (DOM XSS and client-side redirects only)",
            finding.class.name()
        )));
    }
    let vector = url_vector(&finding.source.expr).ok_or_else(|| {
        Skip(format!(
            "the DOM source `{}` is not a URL input the browser phase can place a payload in",
            finding.source.expr
        ))
    })?;
    let sink = browser_sink(&finding.sink.api).ok_or_else(|| {
        Skip(format!(
            "the sink `{}` is not an HTML or navigation sink the browser phase recognizes",
            finding.sink.api
        ))
    })?;
    Ok(BrowserProbe {
        file: finding
            .sink
            .file
            .clone()
            .unwrap_or_else(|| finding.file.clone()),
        vector,
        sink,
    })
}

/// The URL part a DOM source reads from.
fn url_vector(expr: &str) -> Option<UrlVector> {
    if expr.contains("location.search") {
        Some(UrlVector::Search)
    } else if expr.contains("location.hash") {
        Some(UrlVector::Hash)
    } else if expr.contains("document.referrer") {
        Some(UrlVector::Referrer)
    } else if expr.contains("location.href") || expr.contains("location") || expr.contains("URL") {
        Some(UrlVector::Href)
    } else {
        None
    }
}

/// Classifies a browser sink as writing HTML or navigating.
fn browser_sink(api: &str) -> Option<BrowserSink> {
    let api = api.trim_end_matches(" =").trim();
    let last = api.rsplit('.').next().unwrap_or(api);
    const HTML: [&str; 6] = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "write",
        "writeln",
        "html",
    ];
    const NAV: [&str; 5] = ["location", "href", "open", "assign", "replace"];
    if HTML.contains(&last) {
        Some(BrowserSink::Html)
    } else if NAV.contains(&last) {
        Some(BrowserSink::Navigation)
    } else {
        None
    }
}

/// The HTTP method to send. `Any` (a catch-all route) is sent as GET, or POST when the payload
/// is in the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Any,
    /// An HTTP upgrade (WebSocket) entry: `server.on('upgrade', ...)`. Driven as a GET carrying
    /// the upgrade handshake headers, so it reaches the upgrade handler rather than the request one.
    Upgrade,
}

impl Method {
    fn parse(token: &str) -> Option<Self> {
        Some(match token {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            "ANY" => Self::Any,
            "UPGRADE" => Self::Upgrade,
            _ => return None,
        })
    }

    /// The verb to send: a catch-all becomes POST when the payload is in the body, else GET.
    pub fn verb(self, entry: &Entry) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Any if matches!(entry, Entry::Body(_)) => "POST",
            Self::Any | Self::Upgrade => "GET",
        }
    }

    /// Whether this entry is reached by an HTTP upgrade request.
    pub fn is_upgrade(self) -> bool {
        matches!(self, Self::Upgrade)
    }
}

/// Why a finding cannot be driven as an HTTP request. Reported verbatim as the skip reason, so a
/// reader knows what would have to change for `--verify` to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skip(pub String);

impl Probe {
    /// The request a finding implies, or why it cannot be driven. Only unauthenticated HTTP
    /// findings of a class the sandbox can exercise are eligible; everything else is skipped
    /// with a reason, never guessed at.
    #[allow(dead_code)]
    pub fn from_finding(finding: &Finding) -> Result<Self, Skip> {
        Self::from_finding_with_source(finding, None)
    }

    /// Like [`Self::from_finding`], but may consult the handler's `source` to resolve a coarsely
    /// named request input (see [`plan_with_source`]).
    pub fn from_finding_with_source(finding: &Finding, source: Option<&str>) -> Result<Self, Skip> {
        let skip = |reason: &str| Err(Skip(reason.to_owned()));
        if !matches!(
            finding.class,
            VulnClass::PathTraversal
                | VulnClass::CommandInjection
                | VulnClass::CodeInjection
                | VulnClass::Ssrf
        ) {
            return skip(&format!(
                "{} is not driven by verify v1 (HTTP path-traversal, command/code-injection and SSRF only)",
                finding.class.name()
            ));
        }
        if finding.source.kind != "http" {
            return skip(&format!(
                "source is {}, not an HTTP request",
                finding.source.kind
            ));
        }
        if finding.auth != Auth::NoneDetected {
            return skip(&format!(
                "reaching it needs {} authentication, which verify v1 does not perform",
                finding.auth.name()
            ));
        }
        let Some(entry_point) = finding.entry.as_deref() else {
            return skip("no entry point maps to this sink; nothing to send");
        };
        let (method, path) = parse_entry(entry_point)
            .ok_or_else(|| Skip(format!("entry `{entry_point}` is not a routable HTTP path")))?;
        // The engine's `source.expr` is often the coarse request object (`req.query`); the
        // specific accessor (`req.query.name`) tends to appear in the sink argument. Gather the
        // request-access paths from both and keep the most specific.
        let entry = best_entry(finding, &path, source).ok_or_else(|| {
            Skip(format!(
                "cannot tell which request input reaches the sink (source `{}`, argument `{}`)",
                finding.source.expr, finding.sink.arg
            ))
        })?;
        Ok(Self {
            method,
            path,
            entry,
            class: finding.class,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
        })
    }
}

/// Request parameters, besides the one under test, that a handler requires present and valid
/// before the tainted parameter reaches the sink, each paired with a value chosen to pass the
/// handler's own validation. A handler often reaches its sink only after a cluster of parameters
/// checks out (`client_id` alongside a `redirect_uri`, a `response_type` and a `state`); a probe
/// that drives one parameter and omits the rest is rejected early and the sink is never reached.
///
/// Mined from the handler source only, so nothing here is specific to an app: the names it reads
/// from the same request part by explicit member access (the ones it handles individually, which
/// tend to be the required ones — destructured-only names are often optional and left out), and,
/// for each, a value that gets past its guard — a string literal the source constrains it to, a
/// URL when the name asks for one, or a neutral filler.
pub fn required_siblings(source: &str, part: &str, target: &str) -> Vec<(String, String)> {
    let mut names: Vec<String> = member_params(source, part)
        .into_iter()
        .filter(|name| name != target)
        .collect();
    names.sort();
    names.dedup();
    names.truncate(12);
    names
        .into_iter()
        .map(|name| {
            let value = sibling_value(source, part, &name);
            (name, value)
        })
        .collect()
}

/// Parameter names read by explicit member access on a request part (`request.query.name`,
/// `req.body["name"]`): the parameters a handler names one by one.
fn member_params(source: &str, part: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (needle, bracket) in [(format!(".{part}."), false), (format!(".{part}["), true)] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            if !receiver_before(&source[..at]) {
                continue;
            }
            let after = &source[at + needle.len()..];
            let name = if bracket {
                bracket_literal(after)
            } else {
                let ident: String = after.chars().take_while(|c| is_ident(*c as u8)).collect();
                (!ident.is_empty()).then_some(ident)
            };
            if let Some(name) = name {
                out.push(name);
            }
        }
    }
    out
}

/// Whether the identifier ending a string is a request receiver (`req`, `request`, `ctx`), so
/// `request.query` is one but `this.query` is not.
fn receiver_before(pre: &str) -> bool {
    let token: String = pre
        .bytes()
        .rev()
        .take_while(|b| is_ident(*b))
        .map(|b| b as char)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    matches!(token.as_str(), "req" | "request" | "ctx")
}

/// The string literal at the start of `after` (just past a `[`): `"name"]` -> `name`.
fn bracket_literal(after: &str) -> Option<String> {
    let after = after.trim_start();
    let quote = after
        .chars()
        .next()
        .filter(|c| matches!(c, '"' | '\'' | '`'))?;
    let body = &after[1..];
    let end = body.find(quote)?;
    let name = &body[..end];
    (!name.is_empty() && name.bytes().all(is_ident)).then(|| name.to_owned())
}

/// A value for a sibling parameter that satisfies the handler's guard on it.
fn sibling_value(source: &str, part: &str, name: &str) -> String {
    if let Some(literal) = constrained_literal(source, part, name) {
        return literal;
    }
    if is_urlish(name) {
        // A syntactically valid absolute URL that does not resolve to the marker service, so it
        // passes a `URL.canParse` / `new URL()` guard without tripping the probe's own signal.
        return "http://jss-filler.test/".to_owned();
    }
    "jsspector".to_owned()
}

/// Whether a parameter name asks for a URL, so a URL-shaped filler passes its guard.
fn is_urlish(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "url", "uri", "redirect", "endpoint", "callback", "href", "webhook", "link", "return",
        "origin",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// A string literal the handler constrains a parameter to: a value it compares the parameter (or a
/// variable bound from it) against with `===`/`==`, or an alternative of a `/^(a|b)$/.test(...)`
/// guard. `None` when the parameter is not pinned to a literal.
fn constrained_literal(source: &str, part: &str, name: &str) -> Option<String> {
    let mut ids = aliases(source, part, name);
    ids.push(name.to_owned());
    for id in &ids {
        if let Some(literal) = regex_literal(source, id).or_else(|| equality_literal(source, id)) {
            return Some(literal);
        }
    }
    None
}

/// Local variables bound directly from `<receiver>.<part>.<name>`
/// (`const responseType = request.query.response_type ?? ...` -> `responseType`).
fn aliases(source: &str, part: &str, name: &str) -> Vec<String> {
    let access = format!(".{part}.{name}");
    let mut out = Vec::new();
    for keyword in ["const ", "let ", "var "] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(keyword) {
            let at = from + rel + keyword.len();
            from = at;
            let rest = &source[at..];
            let ident: String = rest.chars().take_while(|c| is_ident(*c as u8)).collect();
            if ident.is_empty() {
                continue;
            }
            let tail = rest[ident.len()..].trim_start();
            // A binding, not a comparison: a single `=`.
            let Some(rhs) = tail.strip_prefix('=').filter(|r| !r.starts_with('=')) else {
                continue;
            };
            // A statement ends at `;`; it may span lines, so do not stop at a newline. Capped so a
            // missing semicolon cannot scan the whole file.
            let end = rhs.find(';').unwrap_or(rhs.len()).min(300);
            let stmt = &rhs[..end];
            if let Some(pos) = stmt.find(&access)
                && receiver_before(&stmt[..pos])
            {
                out.push(ident);
            }
        }
    }
    out
}

/// A plain-word alternative of a `/^(a|b|c)$/.test(ARG)` guard whose `ARG` mentions `id`.
fn regex_literal(source: &str, id: &str) -> Option<String> {
    let mut from = 0;
    while let Some(rel) = source[from..].find(".test(") {
        let dot = from + rel;
        from = dot + ".test(".len();
        let Some(body) = regex_before(source, dot) else {
            continue;
        };
        let Some(arg) = balanced_arg(&source[from..]) else {
            continue;
        };
        if !mentions(arg, id) {
            continue;
        }
        let trimmed = body.trim_start_matches('^').trim_end_matches('$');
        let trimmed = trimmed
            .strip_prefix('(')
            .and_then(|t| t.strip_suffix(')'))
            .unwrap_or(trimmed);
        if let Some(alt) = trimmed
            .split('|')
            .map(str::trim)
            .find(|a| !a.is_empty() && a.bytes().all(|b| is_ident(b) || b == b'-'))
        {
            return Some(alt.to_owned());
        }
    }
    None
}

/// The body of the regular-expression literal ending just before `.test(` at `dot`: the text
/// between its delimiting slashes. Backslash-escaped slashes inside are not the delimiter.
fn regex_before(source: &str, dot: usize) -> Option<&str> {
    let bytes = source.as_bytes();
    if dot == 0 || bytes.get(dot - 1) != Some(&b'/') {
        return None;
    }
    let close = dot - 1;
    let mut i = close;
    while i > 0 {
        i -= 1;
        if bytes.get(i) == Some(&b'/') && (i == 0 || bytes.get(i - 1) != Some(&b'\\')) {
            return source.get(i + 1..close);
        }
    }
    None
}

/// The text of the first argument inside a just-opened `(`: up to the matching close paren.
fn balanced_arg(after: &str) -> Option<&str> {
    let mut depth = 1usize;
    for (i, c) in after.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&after[..i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// A string literal the handler compares `id` against with `===`/`==`, in either order.
fn equality_literal(source: &str, id: &str) -> Option<String> {
    let bytes = source.as_bytes();
    let mut from = 0;
    while let Some(rel) = source[from..].find(id) {
        let at = from + rel;
        from = at + id.len();
        // A whole-word match, not a substring of a longer identifier.
        let before_ok = at == 0 || bytes.get(at - 1).is_none_or(|b| !is_ident(*b));
        let after_idx = at + id.len();
        let after_ok = source[after_idx..]
            .chars()
            .next()
            .is_none_or(|c| !is_ident(c as u8));
        if !before_ok || !after_ok {
            continue;
        }
        // `id === 'lit'`
        let tail = source[after_idx..].trim_start();
        if let Some(rest) = tail.strip_prefix("===").or_else(|| tail.strip_prefix("=="))
            && let Some(lit) = leading_string(rest.trim_start())
        {
            return Some(lit);
        }
        // `'lit' === id`
        let head = source[..at].trim_end();
        if let Some(head) = head.strip_suffix("===").or_else(|| head.strip_suffix("=="))
            && let Some(lit) = trailing_string(head.trim_end())
        {
            return Some(lit);
        }
    }
    None
}

/// Whether `text` contains `id` as a whole word.
fn mentions(text: &str, id: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(rel) = text[from..].find(id) {
        let at = from + rel;
        from = at + id.len();
        let before = at == 0 || bytes.get(at - 1).is_none_or(|b| !is_ident(*b));
        let after = text[at + id.len()..]
            .chars()
            .next()
            .is_none_or(|c| !is_ident(c as u8));
        if before && after {
            return true;
        }
    }
    false
}

/// The string literal at the start of `text` (`'code'` / `"code"`), its contents.
fn leading_string(text: &str) -> Option<String> {
    let quote = text
        .chars()
        .next()
        .filter(|c| matches!(c, '"' | '\'' | '`'))?;
    let body = &text[1..];
    let end = body.find(quote)?;
    Some(body[..end].to_owned())
}

/// The string literal at the end of `text` (`'code'` / `"code"`), its contents.
fn trailing_string(text: &str) -> Option<String> {
    let quote = text
        .chars()
        .last()
        .filter(|c| matches!(c, '"' | '\'' | '`'))?;
    let body = &text[..text.len() - 1];
    let start = body.rfind(quote)?;
    Some(body[start + 1..].to_owned())
}

/// The prefix a plug-in-style app mounts a module's routes under, when the module declares it as
/// a literal: `mountPath: "/auth"` or `mountPath = '/auth'`. The routes are registered on a
/// router the host mounts at that path at startup, which no call in the module shows.
pub fn declared_mount_prefix(source: &str) -> Option<String> {
    const KEYS: [&str; 2] = ["mountPath", "mountpath"];
    for key in KEYS {
        let mut from = 0;
        while let Some(found) = source[from..].find(key) {
            let after = from + found + key.len();
            from = after;
            let rest = source[after..].trim_start();
            let Some(rest) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) else {
                continue;
            };
            let rest = rest.trim_start();
            let Some(quote) = rest
                .chars()
                .next()
                .filter(|c| matches!(c, '"' | '\'' | '`'))
            else {
                continue;
            };
            let body = &rest[1..];
            let Some(end) = body.find(quote) else {
                continue;
            };
            let value = &body[..end];
            if value.starts_with('/')
                && value.len() > 1
                && !value.contains(['$', ' ', '{', '*', ':'])
            {
                return Some(value.trim_end_matches('/').to_owned());
            }
        }
    }
    None
}

/// URL path prefixes a handler compares the request path against before forwarding
/// (`pathname === "/ide"`, `pathname.startsWith("/ide/")`, `["/logs/ws"].includes(pathname)`).
/// Mined from the handler source so a gated forward-proxy (SSRF through `req.url`) can be reached
/// under a path it actually accepts. Any absolute-path string literal that is an operand of an
/// equality test or the argument of a `startsWith`/`includes` call qualifies; this is derived from
/// the app's own source, never a built-in list of paths. Deduplicated and bounded.
pub fn gate_paths(source: &str) -> Vec<String> {
    const MAX: usize = 16;
    let mut out: Vec<String> = Vec::new();
    let mut push = |value: &str| {
        let value = value.trim_end_matches('/');
        if value.len() > 1
            && value.starts_with('/')
            && !value.contains(['$', ' ', '{', '}', '*', ':', '\\', '\n'])
            && !out.iter().any(|existing| existing == value)
            && out.len() < MAX
        {
            out.push(value.to_owned());
        }
    };
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if matches!(c, b'"' | b'\'' | b'`') {
            // A string literal; keep it only when its surroundings are a path comparison.
            if let Some(end) = source[i + 1..].find(c as char) {
                let literal = &source[i + 1..i + 1 + end];
                let before = source[..i].trim_end();
                let after = source[i + 1 + end + 1..].trim_start();
                let compared = before.ends_with("===")
                    || before.ends_with("==")
                    || before.ends_with("startsWith(")
                    || before.ends_with("includes(")
                    || after.starts_with("===")
                    || after.starts_with("==")
                    || after.starts_with("].includes(");
                if compared && literal.starts_with('/') {
                    push(literal);
                }
                i += 1 + end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// The most specific request entry among the finding's sink argument and source expression: a
/// named query/body/path/header parameter is preferred over a whole-object body or the raw URL.
fn best_entry(finding: &Finding, path: &str, source: Option<&str>) -> Option<Entry> {
    // A file-based route's dynamic segment is merged into the request parameters, so a handler that
    // reads it via `req.query.<name>` is reading the URL path. Driving it as a query string is
    // overridden by the real path segment and never reaches the sink, so this placement wins.
    if let Some(entry) = file_route_path_param(finding, path, source) {
        return Some(entry);
    }
    let mut candidates: Vec<Entry> = Vec::new();
    for text in [finding.sink.arg.as_str(), finding.source.expr.as_str()] {
        for accessor in request_accessors(text) {
            if let Some(entry) = source_entry(&accessor, path) {
                candidates.push(entry);
            }
        }
    }
    // Rank: a named vector first, the vaguer ones last.
    candidates.sort_by_key(|entry| match entry {
        Entry::Query(_) | Entry::PathParam(_) | Entry::Header(_) | Entry::Body(Some(_)) => 0,
        Entry::Body(None) => 1,
        Entry::Url => 2,
    });
    candidates
        .into_iter()
        .next()
        .or_else(|| destructured_entry(finding, path))
        .or_else(|| source.and_then(|src| coarse_header_entry(finding, src)))
}

/// The names of dynamic route segments a file-based router declares in a path, by the shared
/// convention of bracketing the parameter: `[id]` (single), `[...path]` (catch-all) and
/// `[[...slug]]` (optional catch-all) each name a path parameter. Next.js, SvelteKit, Remix and
/// Nuxt file routers use this shape, and the handler reads those names from the merged request
/// parameters (`req.query.path`, `params.id`). Not tied to any one app: it is the framework
/// convention encoded in the file path.
fn dynamic_route_params(file: &str) -> Vec<String> {
    let mut out = Vec::new();
    for segment in file.split(['/', '\\']) {
        let (Some(open), Some(close)) = (segment.find('['), segment.rfind(']')) else {
            continue;
        };
        if close <= open {
            continue;
        }
        let name = segment[open + 1..close]
            .trim_matches(|c| c == '[' || c == ']')
            .trim_start_matches('.');
        if !name.is_empty() && name.bytes().all(is_ident) {
            out.push(name.to_owned());
        }
    }
    out
}

/// The route's path-param slot to place a payload in: the slot named for `name` when the route
/// carries it, else the sole `{...}` slot the route declares (a catch-all the baseline rendered
/// without a name, `/api/md/{}`). `None` when no slot, or more than one and none matches, so the
/// placement would be ambiguous.
fn path_param_slot(path: &str, name: &str) -> Option<String> {
    if path.contains(&format!("{{{name}}}")) {
        return Some(name.to_owned());
    }
    let mut slots: Vec<String> = Vec::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let close = after.find('}')?;
        slots.push(after[..close].to_owned());
        rest = &after[close + 1..];
    }
    (slots.len() == 1).then(|| slots.remove(0))
}

/// When the tainted input is a file-based route's path parameter, the entry that places the payload
/// in the URL path. The finding's source must be a request parameter (`query`/`params`), the file
/// path must declare a dynamic segment, the handler must actually read one of those segment names
/// from the request, and the route must carry a slot to fill. Otherwise `None`, and entry
/// selection proceeds as usual.
fn file_route_path_param(finding: &Finding, path: &str, source: Option<&str>) -> Option<Entry> {
    let part = strip_request_receiver(finding.source.expr.trim())?;
    let part = part.split(['.', '[']).next().unwrap_or(part);
    if !matches!(part, "query" | "params") {
        return None;
    }
    let dynamic = dynamic_route_params(&finding.file);
    if dynamic.is_empty() {
        return None;
    }
    let src = source?;
    let reads = |name: &str| {
        ["query", "params"].iter().any(|p| {
            src.contains(&format!("{p}.{name}"))
                || src.contains(&format!("{p}[\"{name}\"]"))
                || src.contains(&format!("{p}['{name}']"))
        })
    };
    let used = dynamic.iter().find(|name| reads(name))?;
    path_param_slot(path, used).map(Entry::PathParam)
}

/// The specific header a finding whose source is the whole `req.headers` object actually reads in
/// a URL/host position, recovered from the handler source: `host: req.headers["wx-host"]` yields
/// `Entry::Header("wx-host")`. Only a header the handler uses to build an outbound request's
/// target is taken, so an unrelated header (a logged `pragma`) is not mistaken for the input.
fn coarse_header_entry(finding: &Finding, source: &str) -> Option<Entry> {
    // Only when the source expression is the whole headers object, with no specific name already.
    let part = strip_request_receiver(finding.source.expr.trim())?;
    if !matches!(part, "headers" | "header") {
        return None;
    }
    header_in_target_position(source).map(Entry::Header)
}

/// The name of the request header a handler assigns to an outbound request's target property
/// (`host`, `hostname`, `url`, ...): the header value that chooses where the server-side request
/// goes. Prefers the host-choosing keys. `None` when no header sits in such a position.
fn header_in_target_position(source: &str) -> Option<String> {
    const KEYS: [&str; 8] = [
        "host", "hostname", "url", "uri", "href", "endpoint", "baseURL", "target",
    ];
    KEYS.iter().find_map(|key| header_value_of_key(source, key))
}

/// The header named by the first request header accessor that begins the value of object key
/// `key` (`host: req.headers["wx-host"]` -> `wx-host`). `key` must appear as a whole-word object
/// key immediately followed by `:` and then the accessor.
fn header_value_of_key(source: &str, key: &str) -> Option<String> {
    let bytes = source.as_bytes();
    let mut from = 0;
    while let Some(rel) = source[from..].find(key) {
        let at = from + rel;
        from = at + key.len();
        let whole_word = at == 0 || bytes.get(at - 1).is_none_or(|b| !is_ident(*b));
        if !whole_word {
            continue;
        }
        let Some(after) = source[at + key.len()..].trim_start().strip_prefix(':') else {
            continue;
        };
        let value = after.trim_start();
        // The accessor must open the value, so `key` really takes it (not some later expression).
        if let Some(accessor) = request_accessors(value).into_iter().next()
            && value.starts_with(&accessor)
            && let Some(Entry::Header(name)) = source_entry(&accessor, "")
        {
            return Some(name);
        }
    }
    None
}

/// `const { client_id } = request.query`: the source is the whole request object, and the sink
/// argument is a variable the first trace step says was assigned from it. The destructured key
/// is the parameter name.
fn destructured_entry(finding: &Finding, path: &str) -> Option<Entry> {
    let part = strip_request_receiver(finding.source.expr.trim())?;
    if !matches!(part, "query" | "body" | "params") {
        return None;
    }
    let step = finding.trace.first().filter(|s| s.file.is_none())?;
    let name = step.note.strip_prefix("assigned to `")?.strip_suffix('`')?;
    if name.is_empty() || !name.bytes().all(is_ident) {
        return None;
    }
    source_entry(&format!("request.{part}.{name}"), path)
}

/// The request-access paths inside an expression: `path.join(ROOT, req.query.name)` yields
/// `req.query.name`. Each run starts at a request receiver and runs through identifier, `.`,
/// and bracket/paren characters. Optional chaining reads the same input (`request?.url` is
/// `request.url`, `req.headers?.["x"]` is `req.headers["x"]`).
fn request_accessors(text: &str) -> Vec<String> {
    const RECEIVERS: [&str; 3] = ["req", "request", "ctx"];
    let text = &without_optional_chaining(text);
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // A receiver must start at a word boundary.
        let at_boundary = i == 0 || bytes.get(i - 1).is_none_or(|b| !is_ident(*b));
        let rest = text.get(i..).unwrap_or("");
        if at_boundary
            && let Some(receiver) = RECEIVERS
                .iter()
                .find(|r| rest.starts_with(**r) && boundary_after(text, i + r.len()))
        {
            let start = i;
            let mut j = i + receiver.len();
            while bytes.get(j).is_some_and(|b| is_accessor(*b)) {
                j += 1;
            }
            if let Some(acc) = text.get(start..j) {
                out.push(acc.to_owned());
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

/// `a?.b` -> `a.b`, `a?.[k]` -> `a[k]`, `a?.(x)` -> `a(x)`. A `?.` before a digit is a
/// conditional and a number (`c ?.5 : 1`), left alone.
fn without_optional_chaining(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("?.") {
        let (head, tail) = rest.split_at(at);
        out.push_str(head);
        let after = &tail[2..];
        match after.as_bytes().first() {
            Some(b) if b.is_ascii_digit() => out.push_str("?."),
            Some(b'[' | b'(') => {}
            _ => out.push('.'),
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// After a receiver, the access path continues through members, calls and bracket keys.
fn is_accessor(b: u8) -> bool {
    is_ident(b)
        || matches!(
            b,
            b'.' | b'[' | b']' | b'(' | b')' | b'\'' | b'"' | b'`' | b'-'
        )
}

/// A receiver token ends at `.`, `[`, `(` or the end — not another identifier character.
fn boundary_after(text: &str, at: usize) -> bool {
    text.as_bytes()
        .get(at)
        .is_none_or(|b| matches!(b, b'.' | b'[' | b'('))
}

/// `GET /api/files`, `POST /a/b`, `ANY /{wildcard}`: the method and the path. The path keeps its
/// `{param}` segments and always starts with `/`.
fn parse_entry(entry: &str) -> Option<(Method, String)> {
    let (verb, path) = entry.split_once(' ')?;
    let method = Method::parse(verb)?;
    let path = path.trim();
    if !path.starts_with('/') {
        return None;
    }
    Some((method, path.to_owned()))
}

/// Which part of the request the source expression reads. Only the shapes verify v1 can place a
/// payload in; anything else returns `None` and the finding is skipped.
fn source_entry(expr: &str, path: &str) -> Option<Entry> {
    // `req.get('X-Thing')`, `request.header('x')`: a header by its string argument.
    if let Some(name) = call_arg(expr, &["get", "header"]) {
        return Some(Entry::Header(name.to_ascii_lowercase()));
    }
    // A member chain: strip a leading `req`/`request`/`ctx.request`/`ctx`.
    let chain = strip_request_receiver(expr)?;
    // `req.headers['x']`: a bracket key right after `headers`, with no dot to split on.
    if chain.starts_with("headers[") || chain.starts_with("header[") {
        return bracket_key(expr).map(|k| Entry::Header(k.to_ascii_lowercase()));
    }
    let mut parts = chain.split('.');
    let first = parts.next()?;
    let rest: Vec<&str> = parts.filter(|p| !p.is_empty()).collect();
    match first {
        "query" => rest.first().map(|name| Entry::Query((*name).to_owned())),
        "body" | "payload" => Some(Entry::Body(rest.first().map(|n| (*n).to_owned()))),
        "params" => {
            let name = rest.first().copied()?;
            // Only a param the route actually has a slot for.
            path.contains(&format!("{{{name}}}"))
                .then(|| Entry::PathParam(name.to_owned()))
        }
        "headers" | "header" => {
            let name = rest
                .first()
                .map(|n| (*n).to_owned())
                .or_else(|| bracket_key(expr))?;
            Some(Entry::Header(name.to_ascii_lowercase()))
        }
        // The path/URL itself reaches the sink (a catch-all static server).
        "url" | "originalUrl" | "path" => Some(Entry::Url),
        _ => None,
    }
}

/// `req.get('X')` / `request.header("x")`: the string literal argument, when the method is one of
/// `names`.
fn call_arg(expr: &str, names: &[&str]) -> Option<String> {
    let open = expr.find('(')?;
    let head = &expr[..open];
    let method = head.rsplit('.').next()?;
    if !names.contains(&method) {
        return None;
    }
    let inside = &expr[open + 1..expr.rfind(')')?];
    unquote(inside.trim())
}

/// `req.headers['x-thing']`: the bracket key as a string literal.
fn bracket_key(expr: &str) -> Option<String> {
    let open = expr.find('[')?;
    let close = expr[open..].find(']')? + open;
    unquote(expr[open + 1..close].trim())
}

/// Drops a `req` / `request` / `ctx.request` / `ctx.req` receiver, returning the rest of the
/// access path (`req.query.name` -> `query.name`). `None` if it is not a request object.
fn strip_request_receiver(expr: &str) -> Option<&str> {
    for prefix in ["req.", "request.", "ctx.request.", "ctx.req.", "ctx."] {
        if let Some(rest) = expr.strip_prefix(prefix) {
            return Some(rest);
        }
    }
    None
}

/// `'x'` / `"x"` / `` `x` ``: the text inside matching quotes.
fn unquote(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let (first, last) = (*bytes.first()?, *bytes.last()?);
    if text.len() >= 2 && first == last && matches!(first, b'\'' | b'"' | b'`') {
        Some(text[1..text.len() - 1].to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn declared_mount_prefix_reads_a_literal_default() {
        use super::declared_mount_prefix as p;
        assert_eq!(
            p("const defaults = {\n  mountPath: \"/auth\",\n};").as_deref(),
            Some("/auth")
        );
        assert_eq!(p("this.mountPath = '/files/'").as_deref(), Some("/files"));
        assert_eq!(p("this.mountPath = this.options.mountPath;"), None);
        assert_eq!(p("mountPath: \"/\""), None);
    }

    #[test]
    fn required_siblings_fill_a_handlers_other_guards() {
        // A handler that reaches its sink only after a cluster of query parameters checks out: one
        // pinned to a literal by a regex guard (via an aliased variable), one that wants a URL,
        // and one merely required present.
        let source = r#"
          const responseType =
            request.query.response_type ?? (deprecated ? "id" : undefined);
          const required = {
            client_id: request.query.client_id,
            redirect_uri: request.query.redirect_uri,
            response_type: responseType,
            state: request.query.state,
          };
          if (!/^(code|id)$/.test(String(responseType))) throw new Error("bad");
        "#;
        let siblings = required_siblings(source, "query", "client_id");
        assert_eq!(
            siblings,
            vec![
                (
                    "redirect_uri".to_owned(),
                    "http://jss-filler.test/".to_owned()
                ),
                ("response_type".to_owned(), "code".to_owned()),
                ("state".to_owned(), "jsspector".to_owned()),
            ]
        );
    }

    #[test]
    fn required_siblings_read_an_equality_guard_and_skip_destructured_only_names() {
        // `mode` is pinned by `===`; `token` is only destructured (optional), so it is not sent.
        let source = r#"
          const { token } = req.query;
          if (req.query.mode === 'strict') { use(req.query.name); }
        "#;
        let siblings = required_siblings(source, "query", "name");
        assert_eq!(siblings, vec![("mode".to_owned(), "strict".to_owned())]);
    }

    use super::*;
    use jss_core::{SinkLoc, SourceLoc, TraceStep};

    fn finding(class: VulnClass, auth: Auth, entry: Option<&str>, expr: &str) -> Finding {
        Finding {
            file: "server.js".to_owned(),
            sink: SinkLoc {
                file: None,
                api: "fs.readFile".to_owned(),
                arg: "p".to_owned(),
                line: 1,
                col: 1,
            },
            class,
            severity: jss_core::Severity::High,
            confidence: "heuristic",
            auth,
            function: "GET /x".to_owned(),
            entry: entry.map(str::to_owned),
            entry_at: None,
            source: SourceLoc {
                kind: "http",
                expr: expr.to_owned(),
                line: 1,
                col: 1,
            },
            trace: Vec::<TraceStep>::new(),
            key: "k".to_owned(),
            fingerprint: "f".to_owned(),
        }
    }

    /// A DOM finding: a browser-side source and sink, in a static front-end file.
    fn dom_finding(expr: &str, sink_api: &str, file: &str) -> Finding {
        let mut f = finding(VulnClass::Xss, Auth::NoneDetected, None, expr);
        f.source.kind = "dom";
        f.file = file.to_owned();
        f.sink.api = sink_api.to_owned();
        f
    }

    #[test]
    fn a_dom_search_into_inner_html_is_a_browser_html_probe() {
        let plan = plan(&dom_finding(
            "location.search",
            ".innerHTML =",
            "web/pages.js",
        ))
        .unwrap();
        let Plan::Browser(probe) = plan else {
            panic!("expected a browser probe, got {plan:?}");
        };
        assert_eq!(probe.vector, UrlVector::Search);
        assert_eq!(probe.sink, BrowserSink::Html);
        assert_eq!(probe.file, "web/pages.js");
    }

    #[test]
    fn a_location_assignment_is_a_navigation_probe() {
        let plan = plan(&dom_finding(
            "location.search",
            "window.location =",
            "app.js",
        ))
        .unwrap();
        let Plan::Browser(probe) = plan else {
            panic!("expected a browser probe");
        };
        assert_eq!(probe.sink, BrowserSink::Navigation);
    }

    #[test]
    fn dom_vectors_and_sinks_are_classified() {
        assert_eq!(url_vector("location.hash.slice(1)"), Some(UrlVector::Hash));
        assert_eq!(
            url_vector("new URL(location.href).searchParams"),
            Some(UrlVector::Href)
        );
        assert_eq!(url_vector("document.referrer"), Some(UrlVector::Referrer));
        assert_eq!(url_vector("req.query.name"), None);
        assert_eq!(browser_sink("el.innerHTML ="), Some(BrowserSink::Html));
        assert_eq!(browser_sink("insertAdjacentHTML"), Some(BrowserSink::Html));
        assert_eq!(
            browser_sink("location.href ="),
            Some(BrowserSink::Navigation)
        );
        assert_eq!(browser_sink("fs.readFile"), None);
    }

    #[test]
    fn a_non_url_dom_source_is_skipped_with_a_reason() {
        // A postMessage source is DOM but not a URL input: skipped, not driven.
        let mut f = dom_finding("event.data.html", ".innerHTML =", "w.js");
        f.source.kind = "dom";
        let err = plan(&f).unwrap_err();
        assert!(err.0.contains("not a URL input"), "{}", err.0);
    }

    #[test]
    fn query_path_traversal_is_a_get_with_a_query_param() {
        let probe = Probe::from_finding(&finding(
            VulnClass::PathTraversal,
            Auth::NoneDetected,
            Some("GET /api/files"),
            "req.query.name",
        ))
        .unwrap();
        assert_eq!(probe.method, Method::Get);
        assert_eq!(probe.path, "/api/files");
        assert_eq!(probe.entry, Entry::Query("name".to_owned()));
    }

    #[test]
    fn a_file_based_catch_all_param_is_driven_through_the_path() {
        // `pages/api/md/[...path].ts` reads `req.query.path`: a file router merges the catch-all
        // segment into the request params, so the payload must fill the URL path slot, not a
        // `?path=` query that the real path segment would override.
        let mut f = finding(
            VulnClass::PathTraversal,
            Auth::NoneDetected,
            Some("ANY /api/md/{}"),
            "req.query",
        );
        f.file = "src/pages/api/md/[...path].ts".to_owned();
        let source =
            "export default function handler(req, res){ const pathSegments = req.query.path; }";
        let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
        assert_eq!(probe.entry, Entry::PathParam(String::new()));
        assert_eq!(probe.path, "/api/md/{}");
    }

    #[test]
    fn a_plain_query_traversal_is_not_mistaken_for_a_path_param() {
        // No dynamic route segment in the file path: the query parameter stays a query entry.
        let probe = Probe::from_finding_with_source(
            &finding(
                VulnClass::PathTraversal,
                Auth::NoneDetected,
                Some("GET /api/files"),
                "req.query.name",
            ),
            Some("const n = req.query.name;"),
        )
        .unwrap();
        assert_eq!(probe.entry, Entry::Query("name".to_owned()));
    }

    #[test]
    fn dynamic_route_params_reads_the_framework_bracket_convention() {
        assert_eq!(
            dynamic_route_params("api/md/[...path].ts"),
            vec!["path".to_owned()]
        );
        assert_eq!(
            dynamic_route_params("routes/[id].js"),
            vec!["id".to_owned()]
        );
        assert_eq!(
            dynamic_route_params("app/[[...slug]]/route.ts"),
            vec!["slug".to_owned()]
        );
        assert!(dynamic_route_params("api/files.ts").is_empty());
    }

    #[test]
    fn body_field_ssrf_is_a_post() {
        let probe = Probe::from_finding(&finding(
            VulnClass::Ssrf,
            Auth::NoneDetected,
            Some("POST /fetch"),
            "req.body.url",
        ))
        .unwrap();
        assert_eq!(probe.method.verb(&probe.entry), "POST");
        assert_eq!(probe.entry, Entry::Body(Some("url".to_owned())));
    }

    #[test]
    fn an_upgrade_entry_is_a_get_marked_for_upgrade() {
        let probe = Probe::from_finding(&finding(
            VulnClass::Ssrf,
            Auth::NoneDetected,
            Some("UPGRADE /{wildcard}"),
            "request?.url",
        ))
        .unwrap();
        assert_eq!(probe.method, Method::Upgrade);
        assert!(probe.method.is_upgrade());
        assert_eq!(probe.method.verb(&probe.entry), "GET");
        assert_eq!(probe.entry, Entry::Url);
        assert!(!Method::Any.is_upgrade());
    }

    #[test]
    fn gate_paths_are_mined_from_the_handlers_own_comparisons() {
        let source = "function isIde(p) { return p === \"/ide\" || p.startsWith(\"/ide/\"); }\n\
             function isLog(p) { return p === '/logs/ws' || p === '/api/logs/ws'; }\n\
             const ok = [\"/health\"].includes(path);\n\
             const name = user.name === \"alice\";\n\
             const rel = \"./static/\" + req.url;\n";
        let paths = super::gate_paths(source);
        assert!(paths.contains(&"/ide".to_owned()), "{paths:?}");
        assert!(paths.contains(&"/logs/ws".to_owned()), "{paths:?}");
        assert!(paths.contains(&"/api/logs/ws".to_owned()), "{paths:?}");
        assert!(paths.contains(&"/health".to_owned()), "{paths:?}");
        // `startsWith("/ide/")` collapses onto `/ide`; non-path and non-compared literals are left out.
        assert!(!paths.iter().any(|p| p == "/ide/"), "{paths:?}");
        assert!(!paths.iter().any(|p| p == "./static/"), "{paths:?}");
        assert!(!paths.iter().any(|p| p == "alice"), "{paths:?}");
    }

    #[test]
    fn a_path_param_must_have_a_slot_in_the_route() {
        let ok = Probe::from_finding(&finding(
            VulnClass::PathTraversal,
            Auth::NoneDetected,
            Some("GET /barcode/{key}"),
            "req.params.key",
        ))
        .unwrap();
        assert_eq!(ok.entry, Entry::PathParam("key".to_owned()));
        // No slot for `id`: skipped, not guessed.
        assert!(
            Probe::from_finding(&finding(
                VulnClass::PathTraversal,
                Auth::NoneDetected,
                Some("GET /barcode/{key}"),
                "req.params.id",
            ))
            .is_err()
        );
    }

    #[test]
    fn a_coarse_headers_source_resolves_the_host_header_from_the_handler() {
        // The finding names only `req.headers`; the handler reads `req.headers["wx-host"]` as the
        // request host (and an unrelated header in a logged field). The host one is recovered.
        let source = r#"
          const proxyRequestSettings = {
            host: req.headers["wx-host"] ?? "api.weather.gov",
            port: 443,
            headers: { pragma: req.headers.pragma },
          };
          https.request(proxyRequestSettings);
        "#;
        let mut f = finding(
            VulnClass::Ssrf,
            Auth::NoneDetected,
            Some("GET /{any}"),
            "req.headers",
        );
        f.sink.arg = "proxyRequestSettings".to_owned();
        let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
        assert_eq!(probe.entry, Entry::Header("wx-host".to_owned()));
        // Without the source it stays unresolved, not guessed.
        assert!(Probe::from_finding(&f).is_err());
    }

    #[test]
    fn an_unrelated_coarse_header_is_not_taken() {
        // No header sits in a request-target position: nothing is resolved.
        let source = r#"
          log({ pragma: req.headers.pragma });
          fetch("https://api.example.test/fixed");
        "#;
        let f = finding(
            VulnClass::Ssrf,
            Auth::NoneDetected,
            Some("GET /{any}"),
            "req.headers",
        );
        assert!(Probe::from_finding_with_source(&f, Some(source)).is_err());
    }

    #[test]
    fn headers_in_both_forms() {
        for expr in ["req.headers['x-forward']", "req.get('X-Forward')"] {
            let probe = Probe::from_finding(&finding(
                VulnClass::Ssrf,
                Auth::NoneDetected,
                Some("GET /proxy"),
                expr,
            ))
            .unwrap();
            assert_eq!(probe.entry, Entry::Header("x-forward".to_owned()));
        }
    }

    #[test]
    fn a_catch_all_reads_the_url_itself() {
        let probe = Probe::from_finding(&finding(
            VulnClass::PathTraversal,
            Auth::NoneDetected,
            Some("ANY /{wildcard}"),
            "req.url",
        ))
        .unwrap();
        assert_eq!(probe.entry, Entry::Url);
        assert_eq!(probe.method.verb(&probe.entry), "GET");
    }

    /// Optional chaining reads the same request input: `request?.url`, `req.query?.name`,
    /// `req.headers?.["x"]`. A conditional before a number is not optional chaining.
    #[test]
    fn optional_chaining_names_the_same_input() {
        for (expr, entry) in [
            ("request?.url", Entry::Url),
            ("req?.query?.name", Entry::Query("name".to_owned())),
            (
                "req.headers?.['x-forward']",
                Entry::Header("x-forward".to_owned()),
            ),
        ] {
            let probe = Probe::from_finding(&finding(
                VulnClass::Ssrf,
                Auth::NoneDetected,
                Some("ANY /{wildcard}"),
                expr,
            ))
            .unwrap();
            assert_eq!(probe.entry, entry, "{expr}");
        }
        assert_eq!(
            super::without_optional_chaining("a?.b?.[c]?.(d) ? x :y?.5:1"),
            "a.b[c](d) ? x :y?.5:1"
        );
    }

    #[test]
    fn ineligible_findings_are_skipped_with_a_reason() {
        // Needs auth.
        assert_eq!(
            Probe::from_finding(&finding(
                VulnClass::PathTraversal,
                Auth::User,
                Some("GET /x"),
                "req.query.n"
            ))
            .unwrap_err()
            .0,
            "reaching it needs user authentication, which verify v1 does not perform"
        );
        // Not an HTTP source.
        let mut dom = finding(
            VulnClass::Xss,
            Auth::NoneDetected,
            Some("GET /x"),
            "req.query.n",
        );
        dom.source.kind = "dom";
        assert!(Probe::from_finding(&dom).is_err());
        // SQL injection is out of v1.
        assert!(
            Probe::from_finding(&finding(
                VulnClass::SqlInjection,
                Auth::NoneDetected,
                Some("GET /x"),
                "req.query.n"
            ))
            .is_err()
        );
        // No entry point.
        assert!(
            Probe::from_finding(&finding(
                VulnClass::PathTraversal,
                Auth::NoneDetected,
                None,
                "req.query.n"
            ))
            .is_err()
        );
    }
}
