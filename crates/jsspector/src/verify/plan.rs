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

/// The sandbox's decision for a finding: drive it, or skip it with a reason.
pub fn plan(finding: &Finding) -> Result<Plan, Skip> {
    // Server-side HTTP findings first.
    match Probe::from_finding(finding) {
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
            Self::Any => "GET",
        }
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
    pub fn from_finding(finding: &Finding) -> Result<Self, Skip> {
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
        let entry = best_entry(finding, &path).ok_or_else(|| {
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
        })
    }
}

/// The most specific request entry among the finding's sink argument and source expression: a
/// named query/body/path/header parameter is preferred over a whole-object body or the raw URL.
fn best_entry(finding: &Finding, path: &str) -> Option<Entry> {
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
    candidates.into_iter().next()
}

/// The request-access paths inside an expression: `path.join(ROOT, req.query.name)` yields
/// `req.query.name`. Each run starts at a request receiver and runs through identifier, `.`,
/// and bracket/paren characters.
fn request_accessors(text: &str) -> Vec<String> {
    const RECEIVERS: [&str; 3] = ["req", "request", "ctx"];
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
