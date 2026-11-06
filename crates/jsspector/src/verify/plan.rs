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
    /// For an SSRF whose source is the whole request URL (`req.url`), the query-parameter names the
    /// handler reads off the parsed URL's search parameters: a member of a variable bound from them
    /// (`const q = Object.fromEntries(url.searchParams); fetch(q.base + ...)` -> `base`) or a direct
    /// `url.searchParams.get("target")`. When the outbound host is chosen by one of these, the marker
    /// URL is tried in each, under each gate path the handler dispatches on. Mined from the handler
    /// source only; empty when the request URL feeds no query parameter into the sink here.
    pub url_query_params: Vec<String>,
    /// For a path-traversal sink, the fixed path segment(s) the handler appends *after* the tainted
    /// input in its `path.join(...)` (`path.join(base, id, 'session.json')` -> `session.json`).
    /// When set, the tainted value is a directory the read descends into, so the canary must be
    /// planted as `<traversed-dir>/<suffix>` rather than as the leaf itself. `None` for the common
    /// case where the tainted value is (or ends) the read path. Mined from the handler source only.
    pub read_suffix: Option<String>,
    /// When set, the tainted request input is not the raw payload but a base64-encoded JSON envelope
    /// the handler decodes (`JSON.parse(Buffer.from(id, 'base64url'))`), and the sink consumes one
    /// member of the decoded object. The payload value is therefore wrapped — placed under the
    /// envelope's field alongside the other members the handler reads — then JSON-serialized and
    /// base64-encoded before it enters the request. `None` for the common case where the input
    /// reaches the sink directly. Mined from the handler source only.
    pub envelope: Option<Envelope>,
    /// When set, the tainted body field is not the raw payload but a structured text *document* that a
    /// parse function (`parseDocument(body)`) extracts an embedded JSON object from, and the
    /// sink consumes one member of the parsed result (`parsed.apiBase`). The payload value is placed
    /// under the JSON key that maps to that member, inside the literal scaffold the parse function's
    /// extraction requires (frontmatter delimiters, a `metadata:` label), with the other members the
    /// handler reads filled by a placeholder so an early presence/validity guard passes. `None` for the
    /// common case where the body field reaches the sink directly. Mined from the handler and the parse
    /// function's own source only.
    pub doc_envelope: Option<DocEnvelope>,
    /// When the sink enumerates a directory (`fs.readdirSync`, `fs.opendirSync`) rather than reading
    /// a file's bytes, the traversal proof is a planted file *name* that appears in the returned
    /// listing. The canary is then planted as a file *inside* the climbed-to directory, and a hit is
    /// the token surfacing as an entry name. Derived from the sink API only.
    pub lists_dir: bool,
    /// When the sink removes a filesystem entry (`fs.unlink`, `fs.rm`, `fs.rmdir`, `rimraf`) rather
    /// than reading it, the traversal cannot be proved by reflected content: the proof is a planted
    /// file outside the base directory disappearing after the request while a sibling control file
    /// planted alongside it survives. Derived from the sink API only.
    pub removes: bool,
    /// For a listing whose read path is `<tainted-dir>/<sibling>`, the sibling route parameter the
    /// handler appends after the tainted one and the fixed values it constrains that sibling to (an
    /// enum / whitelist guard). The canary directory is planted under each value and the sibling slot
    /// driven with it, so the handler reaches a real planted directory to enumerate. Mined from the
    /// route and handler source only; `None` when the tainted value is itself the listed directory.
    pub appended_param: Option<AppendedParam>,
    /// Values for route `{slot}` segments other than the payload-bearing one, chosen so the request
    /// reaches the sink rather than being rejected by a segment guard. A handler often routes on a
    /// path segment and only reaches the sink on one branch (`if (platform === 'truuze')`) or rejects
    /// unknown segments outright (`validPlatforms.includes(platform)`); the generic `1` filler then
    /// never arrives. Each pair is a slot name and the literal a guard enclosing the sink constrains
    /// it to. Mined from the handler source only; empty when no such guard pins a non-payload slot.
    pub path_fillers: Vec<(String, String)>,
}

/// A sibling route parameter appended after the tainted one in a directory read path, constrained by
/// the handler to a fixed set of values. Mined from the route slots and the handler source only, so
/// nothing here is tied to a specific app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendedParam {
    /// The route slot to fill (`kind` for `/resources/{module}/{kind}`).
    pub name: String,
    /// The values the handler accepts for it (`['info','docs','examples']`): the probe tries each.
    pub values: Vec<String>,
}

/// A base64-encoded JSON envelope a handler decodes before using one of its members: the member the
/// payload must fill (the one that reaches the sink), the other members the handler requires present
/// (filled with a harmless placeholder so an early `!obj.field` guard passes), and whether the
/// decode is base64url (`-_`) rather than standard base64. Mined from the handler source only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub field: String,
    pub siblings: Vec<String>,
    pub url_safe: bool,
}

/// A structured-document body field a parse function turns into an object before the sink reads one
/// of its members. `prefix`/`suffix` are the literal scaffold the parse function's extraction regexes
/// require around an embedded JSON object (so a `---`-fenced frontmatter block carrying a
/// `metadata: {...}` label is reconstructed); `sink_key` is the JSON key whose value becomes the
/// member that reaches the sink, and `filler_keys` are the other JSON keys the handler reads off the
/// parsed result (filled with a harmless placeholder so a presence/validity guard passes). The
/// payload is `prefix` + `{ "<sink_key>": <value>, "<filler>": "<placeholder>", ... }` + `suffix`.
/// Mined from the handler and the parse function's source only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocEnvelope {
    pub prefix: String,
    pub suffix: String,
    pub sink_key: String,
    pub filler_keys: Vec<String>,
}

impl Probe {
    /// The request part and parameter name the payload enters through, when it is a named query,
    /// body or header field — the entries that take sibling parameters. A handler often reads other
    /// members of the same request part (another `req.query.*`, `req.headers.*`) and forwards or
    /// validates them before the sink; without a value the request is rejected or errors early
    /// (`axios` rejects an outbound header set to `undefined`). `None` for a path segment, whole
    /// body or raw URL.
    pub fn entry_part(&self) -> Option<(&'static str, &str)> {
        match &self.entry {
            Entry::Query(name) => Some(("query", name)),
            Entry::Body(Some(name)) => Some(("body", name)),
            Entry::Header(name) => Some(("headers", name)),
            _ => None,
        }
    }
}

/// What the sandbox should do with a finding: drive it as an HTTP request (the server-side
/// phase) or load it in a headless browser (a DOM-source XSS or client-side redirect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Http(Box<Probe>),
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
        Ok(probe) => return Ok(Plan::Http(Box::new(probe))),
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
                | VulnClass::NosqlInjection
        ) {
            return skip(&format!(
                "{} is not driven by verify v1 (HTTP path-traversal, command/code-injection, SSRF and NoSQL injection only)",
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
        let mut tainted = tainted_identifiers(finding, &entry);
        if let Some(src) = source {
            propagate_path_derived_taint(src, &mut tainted);
        }
        let read_suffix = (finding.class == VulnClass::PathTraversal)
            .then(|| source.and_then(|src| appended_path_suffix(src, &tainted)))
            .flatten();
        let envelope = source.and_then(|src| json_envelope(src, &tainted, &finding.sink.arg));
        let lists_dir =
            finding.class == VulnClass::PathTraversal && sink_lists_directory(&finding.sink.api);
        let removes = finding.class == VulnClass::PathTraversal && sink_removes(&finding.sink.api);
        // A listing whose read path is `<tainted-dir>/<sibling>` reaches a real directory only when
        // the sibling route parameter carries a value the handler accepts; recover it from the route
        // and the handler's own guard so the probe can drive it.
        let appended_param = (lists_dir && matches!(entry, Entry::PathParam(_)))
            .then(|| {
                source.and_then(|src| appended_enum_param(finding, &path, src, &entry, &tainted))
            })
            .flatten()
            .map(|(name, values)| AppendedParam { name, values });
        Ok(Self {
            method,
            path,
            entry,
            class: finding.class,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
            url_query_params: Vec::new(),
            read_suffix,
            envelope,
            doc_envelope: None,
            lists_dir,
            removes,
            appended_param,
            path_fillers: Vec::new(),
        })
    }
}

/// Identifiers that carry the tainted value in the handler source: the request parameter's own
/// name and every local it was `assigned to` along the finding's trace. Used to find which
/// argument of a `path.join(...)` is the attacker-controlled one.
fn tainted_identifiers(finding: &Finding, entry: &Entry) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    match entry {
        Entry::Query(name)
        | Entry::PathParam(name)
        | Entry::Header(name)
        | Entry::Body(Some(name)) => {
            names.push(name.clone());
        }
        _ => {}
    }
    for step in &finding.trace {
        if let Some(rest) = step.note.strip_prefix("assigned to `")
            && let Some(name) = rest.strip_suffix('`')
            && !name.is_empty()
            && name.bytes().all(is_ident)
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Extends the tainted-identifier set with locals bound directly from a `path.resolve(...)`,
/// `path.join(...)` or `path.normalize(...)` call one of whose arguments is already tainted. A
/// handler commonly builds a base directory from the tainted input (`const base =
/// path.resolve(root, mod)`) and later appends a sibling slot to it (`path.join(base, kind)`); the
/// base carries the taint, so the sibling is appended *after* a tainted value and its enum guard can
/// be recovered. Iterates to a fixpoint over chains of such bindings. Mined from the handler source
/// only; adds a local solely when an assignment derives it from an already-tainted value.
fn propagate_path_derived_taint(source: &str, names: &mut Vec<String>) {
    loop {
        let mut added = false;
        for (local, args) in path_build_bindings(source) {
            if names.contains(&local) {
                continue;
            }
            if args
                .iter()
                .any(|arg| names.iter().any(|name| name == arg.trim()))
            {
                names.push(local);
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    names.sort();
    names.dedup();
}

/// Each `(local, args)` binding in `source` of the form `const|let|var local = <...>.join|resolve|
/// normalize(args)`, where the call is the whole right-hand side: the local a path-building call is
/// assigned to and that call's top-level arguments. Used to carry taint from an input through a base
/// directory built from it. Mined from the handler source only.
fn path_build_bindings(source: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for kw in ["const ", "let ", "var "] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(kw) {
            let at = from + rel;
            from = at + kw.len();
            if at > 0
                && source
                    .as_bytes()
                    .get(at - 1)
                    .is_some_and(|byte| is_ident(*byte))
            {
                continue;
            }
            let after_kw = &source[at + kw.len()..];
            let name: String = after_kw
                .bytes()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect();
            if name.is_empty() {
                continue;
            }
            let rhs = after_kw[name.len()..].trim_start();
            let Some(rhs) = rhs.strip_prefix('=') else {
                continue;
            };
            let rhs = rhs.trim_start();
            // The right-hand side must be a single path-building call.
            let Some(open_rel) = rhs.find('(') else {
                continue;
            };
            let callee = rhs[..open_rel].trim_end();
            if !(callee.ends_with(".resolve")
                || callee.ends_with(".join")
                || callee.ends_with(".normalize"))
            {
                continue;
            }
            let Some(arglist) = balanced_arg(&rhs[open_rel + 1..]) else {
                continue;
            };
            let args = split_top_level_commas(arglist)
                .into_iter()
                .map(|a| a.trim().to_owned())
                .collect();
            out.push((name, args));
        }
    }
    out
}

/// The fixed path segment(s) a handler appends after a tainted argument inside a `path.join(...)`
/// call: in `path.join(base, id, 'session.json')`, where `id` is tainted, the suffix is
/// `session.json`. Scans every `.join(` call, finds one whose argument is exactly a tainted
/// identifier, and collects the string-literal arguments that follow it (stopping at the first
/// non-literal). A tainted value interpolated into a template (`` `${id}.json` ``) is not a bare
/// argument, so an appended *extension* stays with the existing suffix-variant planting. Returns a
/// filesystem-safe relative path, or `None`.
fn appended_path_suffix(source: &str, names: &[String]) -> Option<String> {
    if names.is_empty() {
        return None;
    }
    let needle = ".join(";
    let mut from = 0;
    while let Some(rel) = source[from..].find(needle) {
        let open = from + rel + needle.len();
        from = open;
        let Some(arglist) = balanced_arg(&source[open..]) else {
            continue;
        };
        let args = split_top_level_commas(arglist);
        let Some(idx) = args
            .iter()
            .position(|arg| names.iter().any(|name| name == arg.trim()))
        else {
            continue;
        };
        let mut parts: Vec<String> = Vec::new();
        for arg in args.get(idx + 1..).unwrap_or_default() {
            match string_literal_arg(arg.trim()) {
                Some(literal) => parts.push(literal),
                None => break,
            }
        }
        if parts.is_empty() {
            continue;
        }
        let suffix = parts.join("/");
        if is_safe_suffix(&suffix) {
            return Some(suffix);
        }
    }
    None
}

/// Splits an argument list on commas that are not inside nested brackets, parentheses, or a string
/// or template literal.
fn split_top_level_commas(arglist: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut start = 0usize;
    let bytes = arglist.as_bytes();
    let mut i = 0usize;
    while i < arglist.len() {
        let Some(c) = bytes.get(i).copied().map(char::from) else {
            break;
        };
        if let Some(q) = quote {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
        } else {
            match c {
                '\'' | '"' | '`' => quote = Some(c),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                ',' if depth == 0 => {
                    out.push(arglist[start..i].to_owned());
                    start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    out.push(arglist[start..].to_owned());
    out
}

/// The contents of an argument that is wholly a single string or template literal with no
/// interpolation (`'session.json'`, `` `index.html` ``). `None` for anything else.
fn string_literal_arg(arg: &str) -> Option<String> {
    let quote = arg
        .chars()
        .next()
        .filter(|c| matches!(c, '\'' | '"' | '`'))?;
    if arg.chars().count() < 2 || !arg.ends_with(quote) {
        return None;
    }
    let inner = &arg[1..arg.len() - 1];
    if inner.contains(quote) || inner.contains("${") {
        return None;
    }
    Some(inner.to_owned())
}

/// Recognizes a handler that decodes its tainted input as a base64-encoded JSON envelope and then
/// uses one member of the decoded object (`const p = JSON.parse(Buffer.from(id, 'base64url'));
/// fetch(p.url)`). Returns the [`Envelope`] describing how the payload must be packed: the member
/// that reaches the sink, the other members the handler reads (so an early `!p.field` guard passes),
/// and whether the decode is base64url. Scans each `JSON.parse(...)` whose argument base64-decodes a
/// tainted identifier, finds the variable it binds, and collects that variable's members. `None`
/// when the input is not wrapped this way. Mined from the handler source only.
fn json_envelope(source: &str, names: &[String], sink_arg: &str) -> Option<Envelope> {
    if names.is_empty() {
        return None;
    }
    const URLISH: [&str; 9] = [
        "url", "uri", "href", "endpoint", "target", "callback", "host", "hostname", "link",
    ];
    let needle = "JSON.parse(";
    let mut search = 0;
    while let Some(rel) = source[search..].find(needle) {
        let js_start = search + rel;
        let open = js_start + needle.len();
        search = open;
        let Some(arg) = balanced_arg(&source[open..]) else {
            continue;
        };
        let Some(url_safe) = decoded_tainted_buffer(arg, names) else {
            continue;
        };
        let Some(var) = assigned_target(source, js_start) else {
            continue;
        };
        let members = object_members(source, &var);
        if members.is_empty() {
            continue;
        }
        let field = members
            .iter()
            .find(|m| m.eq_ignore_ascii_case(sink_arg))
            .or_else(|| {
                members
                    .iter()
                    .find(|m| URLISH.iter().any(|u| m.eq_ignore_ascii_case(u)))
            })
            .cloned()?;
        let siblings = members.into_iter().filter(|m| *m != field).collect();
        return Some(Envelope {
            field,
            siblings,
            url_safe,
        });
    }
    None
}

/// The name of the parse function a tainted body field is passed to, when its result feeds the sink
/// (`const parsed = parseDocument(body)`). Used by the caller to resolve the module the
/// function is defined in. `None` when the tainted input is not consumed by such a call. Mined from
/// the handler source only.
pub fn parse_transform_fn(finding: &Finding, entry: &Entry, handler: &str) -> Option<String> {
    let tainted = tainted_identifiers(finding, entry);
    transform_call(handler, &tainted).map(|(name, _)| name)
}

/// Whether `source` defines a function named `name` (so the parse function is local, not imported).
pub fn defines_function(source: &str, name: &str) -> bool {
    function_body(source, name).is_some()
}

/// The module specifier a named import of `name` comes from (`import { name } from '<path>'` ->
/// `<path>`). Used to locate a parse function defined in another module. Mined from the import
/// statements only.
pub fn import_source_path(source: &str, name: &str) -> Option<String> {
    let mut from = 0;
    while let Some(rel) = source[from..].find("import") {
        let at = from + rel;
        from = at + "import".len();
        if at > 0 && source.as_bytes().get(at - 1).is_some_and(|b| is_ident(*b)) {
            continue;
        }
        let end = source[at..]
            .find(';')
            .map(|i| at + i)
            .unwrap_or_else(|| source.len().min(at + 400));
        let stmt = &source[at..end];
        if !contains_word(stmt, name) {
            continue;
        }
        if let Some(fpos) = stmt.find(" from ") {
            let tail = stmt[fpos + " from ".len()..].trim_start();
            if let Some(path) = string_literal_arg(tail) {
                return Some(path);
            }
        }
    }
    None
}

/// Recognizes a handler that passes a tainted body field to a parse function and reads one member of
/// the parsed result in the sink (`const parsed = parseDocument(body); const url =
/// parsed.endpoint || ...; fetch(`${url}/...`)`). `module_src` is the source of the module the parse
/// function is defined in (the handler's own source when it is local). Returns the [`DocEnvelope`]
/// that packs the payload into the structured document the parse function will accept: the JSON key
/// that reaches the sink, the other members the handler reads (filled with a placeholder so a
/// presence/validity guard passes), and the literal scaffold the extraction regexes require. Mined
/// from the handler and parse-function source only; `None` when the body field is not consumed this
/// way.
pub fn doc_envelope(
    finding: &Finding,
    entry: &Entry,
    handler: &str,
    module_src: &str,
) -> Option<DocEnvelope> {
    let tainted = tainted_identifiers(finding, entry);
    let (fn_name, result_var) = transform_call(handler, &tainted)?;
    let fn_body = function_body(module_src, &fn_name)?;

    // The members the handler reads off the parsed result. One reaches the sink (carries the canary);
    // the rest are presence/validity guards (filled with a placeholder).
    let members = object_members(handler, &result_var);
    if members.is_empty() {
        return None;
    }
    let sink_member = sink_result_member(handler, &result_var, &members, &tainted)?;

    // How the parse function names the embedded JSON keys behind each returned member
    // (`apiBase: metadata.api_base`): map returned member -> JSON key.
    let key_map = parsed_member_json_keys(&fn_body)?;
    let sink_key = key_map
        .iter()
        .find(|(member, _)| *member == sink_member)
        .map(|(_, key)| key.clone())?;
    let filler_keys: Vec<String> = members
        .iter()
        .filter(|member| **member != sink_member)
        .filter_map(|member| {
            key_map
                .iter()
                .find(|(returned, _)| returned == member)
                .map(|(_, key)| key.clone())
        })
        .collect();

    // The literal scaffold the parse function's extraction regexes require around the JSON object.
    let (prefix, suffix) = extraction_scaffold(&fn_body)?;

    Some(DocEnvelope {
        prefix,
        suffix,
        sink_key,
        filler_keys,
    })
}

/// A `const|let|var <var> = <ident>(<args>)` binding whose callee is a bare function identifier and
/// one of whose arguments is a tainted identifier: the parse call and the local it binds. `await` is
/// tolerated. Returns `(callee, var)`. Mined from the handler source only.
fn transform_call(source: &str, tainted: &[String]) -> Option<(String, String)> {
    for kw in ["const ", "let ", "var "] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(kw) {
            let at = from + rel;
            from = at + kw.len();
            if at > 0 && source.as_bytes().get(at - 1).is_some_and(|b| is_ident(*b)) {
                continue;
            }
            let after_kw = &source[at + kw.len()..];
            let name: String = after_kw
                .bytes()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect();
            if name.is_empty() {
                continue;
            }
            let rhs = after_kw[name.len()..].trim_start();
            let Some(rhs) = rhs.strip_prefix('=') else {
                continue;
            };
            let mut rhs = rhs.trim_start();
            if let Some(stripped) = rhs.strip_prefix("await ") {
                rhs = stripped.trim_start();
            }
            let Some(open_rel) = rhs.find('(') else {
                continue;
            };
            let callee = rhs[..open_rel].trim_end();
            if callee.is_empty() || !callee.bytes().all(is_ident) {
                continue;
            }
            let Some(arglist) = balanced_arg(&rhs[open_rel + 1..]) else {
                continue;
            };
            if split_top_level_commas(arglist)
                .iter()
                .any(|arg| tainted.iter().any(|t| t == arg.trim()))
            {
                return Some((callee.to_owned(), name));
            }
        }
    }
    None
}

/// The body (between the outermost braces) of a function named `name` defined in `source`: a
/// `function name(...) { ... }` declaration or a `const name = (...) => { ... }` / `name =
/// function(...) { ... }` binding. Brace matching is naive (does not skip strings), which is adequate
/// for the balanced bodies these parse helpers have. `None` when no such definition is found.
fn function_body(source: &str, name: &str) -> Option<String> {
    let markers = [
        format!("function {name}"),
        format!("function* {name}"),
        format!("const {name}"),
        format!("let {name}"),
        format!("var {name}"),
        format!("{name} ="),
    ];
    for marker in &markers {
        if let Some(body) = body_after_marker(source, marker) {
            return Some(body);
        }
    }
    None
}

/// The brace-balanced block that opens at the first `{` after a whole-word occurrence of `marker`.
fn body_after_marker(source: &str, marker: &str) -> Option<String> {
    let mut from = 0;
    while let Some(rel) = source[from..].find(marker) {
        let at = from + rel;
        from = at + marker.len();
        if at > 0 && source.as_bytes().get(at - 1).is_some_and(|b| is_ident(*b)) {
            continue;
        }
        let after = &source[at + marker.len()..];
        if marker.bytes().last().is_some_and(is_ident) && after.bytes().next().is_some_and(is_ident)
        {
            continue;
        }
        if let Some(open) = after.find('{')
            && let Some(body) = balanced_braces(&after[open + 1..])
        {
            return Some(body.to_owned());
        }
    }
    None
}

/// The brace-balanced slice up to the matching `}` for a block already entered (depth 1). Naive: does
/// not skip strings or comments.
fn balanced_braces(after: &str) -> Option<&str> {
    let mut depth = 1usize;
    for (i, c) in after.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
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

/// The member of the parsed-result object that reaches the sink: the one read on the right-hand side
/// of an assignment to a tainted local (`const url = parsed.apiBase || ...`). Falls back to a member
/// whose name reads like a URL/host. `None` when none qualifies.
fn sink_result_member(
    handler: &str,
    var: &str,
    members: &[String],
    tainted: &[String],
) -> Option<String> {
    for member in members {
        let full = format!("{var}.{member}");
        let mut from = 0;
        while let Some(rel) = handler[from..].find(&full) {
            let at = from + rel;
            from = at + full.len();
            if handler
                .as_bytes()
                .get(at + full.len())
                .is_some_and(|b| is_ident(*b))
            {
                continue;
            }
            if let Some(lhs) = assigned_lhs_ident(handler, at)
                && tainted.contains(&lhs)
            {
                return Some(member.clone());
            }
        }
    }
    const URLISH: [&str; 9] = [
        "url", "uri", "href", "endpoint", "target", "callback", "host", "hostname", "link",
    ];
    members
        .iter()
        .find(|member| {
            let lower = member.to_ascii_lowercase();
            URLISH.iter().any(|u| lower.contains(u))
        })
        .cloned()
}

/// The identifier assigned on the statement containing byte offset `pos` (`const url = ...` -> `url`).
/// Reads back to the statement start (a `;`, `{`, `}` or newline) and takes the name before the `=`.
fn assigned_lhs_ident(source: &str, pos: usize) -> Option<String> {
    let start = source[..pos]
        .rfind([';', '{', '}', '\n'])
        .map(|i| i + 1)
        .unwrap_or(0);
    let stmt = source[start..pos].trim_start();
    let stmt = stmt
        .strip_prefix("const ")
        .or_else(|| stmt.strip_prefix("let "))
        .or_else(|| stmt.strip_prefix("var "))
        .unwrap_or(stmt);
    let eq = stmt.find('=')?;
    let lhs = stmt[..eq].trim();
    (!lhs.is_empty() && lhs.bytes().all(is_ident)).then(|| lhs.to_owned())
}

/// Maps each member a parse function returns to the embedded JSON key it reads: for `const metadata =
/// JSON.parse(...); return { apiBase: metadata.api_base, ... }`, returns `[("apiBase", "api_base"),
/// ...]`. `None` when the function has no `JSON.parse` result or no such return object.
fn parsed_member_json_keys(fn_body: &str) -> Option<Vec<(String, String)>> {
    let js_start = fn_body.find("JSON.parse(")?;
    let json_var = assigned_target(fn_body, js_start)?;
    let object = return_object_literal(fn_body)?;
    let member_prefix = format!("{json_var}.");
    let mut out = Vec::new();
    for entry in split_top_level_commas(&object) {
        let entry = entry.trim();
        let Some((member, value)) = entry.split_once(':') else {
            continue;
        };
        let member = member.trim();
        if member.is_empty() || !member.bytes().all(is_ident) {
            continue;
        }
        if let Some(pos) = value.find(&member_prefix) {
            let json_key: String = value[pos + member_prefix.len()..]
                .bytes()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect();
            if !json_key.is_empty() {
                out.push((member.to_owned(), json_key));
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The first `return { ... }` object literal in `source`.
fn return_object_literal(source: &str) -> Option<String> {
    let mut from = 0;
    while let Some(rel) = source[from..].find("return") {
        let at = from + rel;
        from = at + "return".len();
        if at > 0 && source.as_bytes().get(at - 1).is_some_and(|b| is_ident(*b)) {
            continue;
        }
        let rest = source[at + "return".len()..].trim_start();
        if let Some(inner) = rest.strip_prefix('{')
            && let Some(object) = balanced_braces(inner)
        {
            return Some(object.to_owned());
        }
    }
    None
}

/// The literal `(prefix, suffix)` the extraction regexes in a parse function require around the
/// embedded JSON object. Collects the `.match`/`.exec` regexes that run before the `JSON.parse`, in
/// source order (outer extraction first), and nests their capture-group scaffolds so the payload sits
/// in the innermost capture. `None` when no capturing extraction regex is found.
fn extraction_scaffold(fn_body: &str) -> Option<(String, String)> {
    let parse_at = fn_body.find("JSON.parse(").unwrap_or(fn_body.len());
    let mut regexes: Vec<(usize, String)> = Vec::new();
    for op in [".match(", ".exec(", ".matchAll("] {
        let mut from = 0;
        while let Some(rel) = fn_body[from..].find(op) {
            let at = from + rel;
            from = at + op.len();
            if at >= parse_at {
                continue;
            }
            if let Some(arg) = balanced_arg(&fn_body[at + op.len()..])
                && let Some(pattern) = regex_pattern(arg.trim())
            {
                regexes.push((at, pattern));
            }
        }
    }
    regexes.sort_by_key(|(at, _)| *at);
    let mut prefix = String::new();
    let mut suffix = String::new();
    let mut any = false;
    for (_, pattern) in &regexes {
        if let Some((pre, suf)) = regex_scaffold(pattern) {
            prefix.push_str(&pre);
            suffix = format!("{suf}{suffix}");
            any = true;
        }
    }
    any.then_some((prefix, suffix))
}

/// The pattern body of a regex literal argument (`/^---\n(...)/m` -> `^---\n(...)`), stopping at the
/// first unescaped `/` outside a character class. `None` when the argument is not a regex literal.
fn regex_pattern(arg: &str) -> Option<String> {
    let rest = arg.strip_prefix('/')?;
    let bytes = rest.as_bytes();
    let mut i = 0;
    let mut in_class = false;
    while let Some(&c) = bytes.get(i) {
        match c {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' => in_class = true,
            b']' => in_class = false,
            b'/' if !in_class => return rest.get(..i).map(str::to_owned),
            _ => {}
        }
        i += 1;
    }
    None
}

/// The literal `(prefix, suffix)` around the first capturing group of a regex pattern: the literal
/// text the pattern requires before and after the capture the payload fills. `None` when the pattern
/// has no capturing group.
fn regex_scaffold(pattern: &str) -> Option<(String, String)> {
    let (open, close) = first_capture_group(pattern)?;
    let before = decode_regex_literal(&pattern[..open]);
    let after = decode_regex_literal(&pattern[close + 1..]);
    Some((before, after))
}

/// The byte range `(open, close)` of the first capturing group in a regex pattern, skipping escaped
/// characters, character classes and non-capturing `(?...)` groups.
fn first_capture_group(pattern: &str) -> Option<(usize, usize)> {
    let b = pattern.as_bytes();
    let mut i = 0;
    let mut in_class = false;
    while let Some(&c) = b.get(i) {
        match c {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' => in_class = true,
            b']' => in_class = false,
            b'(' if !in_class && b.get(i + 1) != Some(&b'?') => {
                let open = i;
                let mut depth = 1usize;
                let mut j = i + 1;
                let mut inner_class = false;
                while let Some(&d) = b.get(j) {
                    match d {
                        b'\\' => {
                            j += 2;
                            continue;
                        }
                        b'[' => inner_class = true,
                        b']' => inner_class = false,
                        b'(' if !inner_class => depth += 1,
                        b')' if !inner_class => {
                            depth -= 1;
                            if depth == 0 {
                                return Some((open, j));
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                return None;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// A minimal literal string that satisfies a regex fragment with no capture: literal characters and
/// common escapes are emitted, anchors are dropped, `\s*`/`\s?`/`[...]*` become empty, `\s+` becomes
/// one space, and a quantified literal keeps a single occurrence. Non-literal classes it cannot
/// satisfy are dropped. Used to rebuild the scaffold around an extracted JSON object.
fn decode_regex_literal(fragment: &str) -> String {
    let b = fragment.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        match c {
            b'^' | b'$' => i += 1,
            b'\\' => match b.get(i + 1).copied() {
                Some(b'n') => {
                    out.push('\n');
                    i += 2;
                }
                Some(b't') => {
                    out.push('\t');
                    i += 2;
                }
                Some(b'r') => {
                    out.push('\r');
                    i += 2;
                }
                Some(c @ (b's' | b'S' | b'w' | b'W' | b'd' | b'D' | b'b' | b'B')) => {
                    match b.get(i + 2).copied() {
                        Some(b'*') | Some(b'?') => i += 3,
                        Some(b'+') => {
                            if c == b's' {
                                out.push(' ');
                            }
                            i += 3;
                        }
                        _ => {
                            if c == b's' {
                                out.push(' ');
                            }
                            i += 2;
                        }
                    }
                }
                Some(c) => {
                    out.push(c as char);
                    i += 2;
                }
                None => i += 1,
            },
            b'[' => {
                let mut j = i + 1;
                let mut open = true;
                while open {
                    match b.get(j).copied() {
                        Some(b'\\') => {
                            j += 2;
                            continue;
                        }
                        Some(b']') => {
                            open = false;
                            j += 1;
                        }
                        Some(_) => j += 1,
                        None => break,
                    }
                }
                match b.get(j).copied() {
                    Some(b'*') | Some(b'?') | Some(b'+') => i = j + 1,
                    _ => i = j,
                }
            }
            b'(' | b')' | b'*' | b'+' | b'?' => i += 1,
            b'.' => match b.get(i + 1).copied() {
                Some(b'*') | Some(b'?') => i += 2,
                Some(b'+') => {
                    out.push('x');
                    i += 2;
                }
                _ => {
                    out.push('x');
                    i += 1;
                }
            },
            other => match b.get(i + 1).copied() {
                Some(b'*') | Some(b'?') | Some(b'+') => {
                    out.push(other as char);
                    i += 2;
                }
                _ => {
                    out.push(other as char);
                    i += 1;
                }
            },
        }
    }
    out
}

/// Whether `text` contains `word` bounded by non-identifier characters.
fn contains_word(text: &str, word: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(rel) = text[from..].find(word) {
        let at = from + rel;
        from = at + word.len();
        let before_ok = at == 0 || bytes.get(at - 1).is_none_or(|b| !is_ident(*b));
        let after_ok = bytes.get(at + word.len()).is_none_or(|b| !is_ident(*b));
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Whether an expression base64-decodes one of the tainted identifiers, and if so whether as
/// base64url: `Buffer.from(id, 'base64url')` -> `Some(true)`, `Buffer.from(id, 'base64')` or
/// `atob(id)` -> `Some(false)`. `None` when no tainted value is base64-decoded here.
fn decoded_tainted_buffer(expr: &str, names: &[String]) -> Option<bool> {
    let needle = "Buffer.from(";
    let mut search = 0;
    while let Some(rel) = expr[search..].find(needle) {
        let open = search + rel + needle.len();
        search = open;
        let Some(inner) = balanced_arg(&expr[open..]) else {
            continue;
        };
        let args = split_top_level_commas(inner);
        let Some(first) = args.first() else {
            continue;
        };
        if !names.iter().any(|name| name == first.trim()) {
            continue;
        }
        for enc in args.get(1..).unwrap_or_default() {
            match string_literal_arg(enc.trim()).as_deref() {
                Some("base64url") => return Some(true),
                Some("base64") => return Some(false),
                _ => {}
            }
        }
    }
    // `atob(id)`: standard base64.
    let needle = "atob(";
    let mut search = 0;
    while let Some(rel) = expr[search..].find(needle) {
        let open = search + rel + needle.len();
        search = open;
        let before_ok = (search + rel) < needle.len()
            || expr
                .as_bytes()
                .get(search + rel - 1)
                .is_none_or(|b| !is_ident(*b));
        if let Some(inner) = balanced_arg(&expr[open..])
            && before_ok
            && names.iter().any(|name| name == inner.trim())
        {
            return Some(false);
        }
    }
    None
}

/// The identifier a `JSON.parse(...)` at byte offset `js_start` is assigned to, by reading back over
/// the `= ` just before it (`const payload = JSON.parse(...)` -> `payload`). `None` when the result
/// is not bound to a plain identifier (an inline `fetch(JSON.parse(x).url)`, or a comparison like
/// `== JSON.parse(x)`).
fn assigned_target(source: &str, js_start: usize) -> Option<String> {
    let head = source[..js_start].trim_end();
    let head = head.strip_suffix('=')?;
    // Not `==`, `===`, `!=`, `<=`, `>=`: those are comparisons, not assignments.
    if head.ends_with(['=', '!', '<', '>']) {
        return None;
    }
    let head = head.trim_end();
    let ident: String = head
        .bytes()
        .rev()
        .take_while(|b| is_ident(*b))
        .map(|b| b as char)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    ident
        .as_bytes()
        .first()
        .is_some_and(|first| !first.is_ascii_digit())
        .then_some(ident)
}

/// The members read off object variable `var` in the source: `payload.url`, `payload?.from`,
/// `payload["to"]` -> `["url", "from", "to"]`, in first-seen order and deduplicated.
fn object_members(source: &str, var: &str) -> Vec<String> {
    let text = without_optional_chaining(source);
    let bytes = text.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while let Some(rel) = text[i..].find(var) {
        let at = i + rel;
        i = at + var.len();
        let before_ok = at == 0 || bytes.get(at - 1).is_none_or(|b| !is_ident(*b));
        if !before_ok {
            continue;
        }
        let after = &text[at + var.len()..];
        if let Some(rest) = after.strip_prefix('.') {
            let name: String = rest
                .bytes()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect();
            if !name.is_empty() && !out.contains(&name) {
                out.push(name);
            }
        } else if after.starts_with('[')
            && let Some(key) = bracket_key(after)
            && !key.is_empty()
            && !out.contains(&key)
        {
            out.push(key);
        }
    }
    out
}

/// Whether an appended suffix is a safe relative path to plant: non-empty, no absolute or parent
/// segments, and only ordinary filename characters.
fn is_safe_suffix(suffix: &str) -> bool {
    !suffix.is_empty()
        && !suffix.starts_with('/')
        && suffix
            .split('/')
            .all(|seg| !seg.is_empty() && seg != ".." && seg != ".")
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
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
        let Some(&c) = bytes.get(i) else {
            break;
        };
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

/// The query-parameter names a handler reads off the parsed request URL's search parameters, for an
/// SSRF whose source is the whole request URL (`req.url`). Two shapes are mined, both from the
/// handler's own source: a member read off a variable bound from the search parameters
/// (`const query = Object.fromEntries(url.searchParams); ... query.base` -> `base`) and a direct
/// `searchParams.get("name")` / `.getAll("name")`. The attacker chooses the outbound host through one
/// of these, so the marker URL is tried in each. Deduplicated and bounded; empty when the request URL
/// feeds no query parameter here. Not tied to any one app: it reads the standard `URLSearchParams`
/// shape from the handler's own code.
pub fn url_search_params(source: &str) -> Vec<String> {
    const MAX: usize = 16;
    let mut out: Vec<String> = Vec::new();
    // `searchParams.get("name")` / `.getAll("name")`.
    for needle in [".get(", ".getAll("] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(needle) {
            let at = from + rel;
            from = at + needle.len();
            if !source[..at].trim_end().ends_with("searchParams") {
                continue;
            }
            if let Some(arg) = balanced_arg(&source[from..])
                && let Some(name) = unquote(arg.trim())
            {
                push_param(&mut out, &name, MAX);
            }
        }
    }
    // A variable bound from an expression mentioning `searchParams`, then every member read off it.
    for var in vars_bound_from(source, "searchParams") {
        for member in object_members(source, &var) {
            push_param(&mut out, &member, MAX);
        }
    }
    out
}

/// Appends a plain identifier parameter name if it is new and the list is under its cap.
fn push_param(out: &mut Vec<String>, name: &str, max: usize) {
    if name
        .as_bytes()
        .first()
        .is_some_and(|first| !first.is_ascii_digit())
        && name.bytes().all(is_ident)
        && !out.iter().any(|existing| existing == name)
        && out.len() < max
    {
        out.push(name.to_owned());
    }
}

/// The local variables a module binds from an expression that mentions `needle`
/// (`const query = Object.fromEntries(url.searchParams)` for `needle = "searchParams"` -> `query`).
/// The right-hand side is read up to the statement's `;` (capped), so a multi-line initializer is
/// still seen. A binding only (single `=`), never a comparison.
fn vars_bound_from(source: &str, needle: &str) -> Vec<String> {
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
            let Some(rhs) = tail.strip_prefix('=').filter(|r| !r.starts_with('=')) else {
                continue;
            };
            let end = rhs.floor_char_boundary(rhs.find(';').unwrap_or(rhs.len()).min(300));
            if rhs[..end].contains(needle) && !out.contains(&ident) {
                out.push(ident);
            }
        }
    }
    out
}

/// The HTTP route a module registers on a host-provided web-server service, when no route inventory
/// named one: `webServer.register({ kind: "prefix", path: "/x", handler })`,
/// `router.route("/x", handler)`. The registered path is the mount point; such a handler often
/// dispatches sub-paths itself (recovered separately via [`gate_paths`]). Only a registration call
/// whose arguments carry a request `handler` is taken, so an unrelated `register(...)` is not
/// mistaken for a route. Returns `GET <path>`; `None` when no such registration is present. Derived
/// from the module's own source, so nothing here is specific to one app.
pub fn registered_route_entry(source: &str) -> Option<String> {
    for needle in [".register(", ".route(", ".addRoute("] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(needle) {
            let open = from + rel + needle.len();
            from = open;
            let Some(args) = balanced_arg(&source[open..]) else {
                continue;
            };
            if !args.contains("handler") {
                continue;
            }
            if let Some(path) = registered_path_literal(args) {
                return Some(format!("GET {path}"));
            }
        }
    }
    None
}

/// The `path` string literal of a route-registration object (`{ path: "/x", handler }`): a whole-word
/// `path` key followed by `:` and an absolute-path string literal. `None` when absent or not a fixed
/// absolute path.
fn registered_path_literal(args: &str) -> Option<String> {
    let bytes = args.as_bytes();
    let mut from = 0;
    while let Some(rel) = args[from..].find("path") {
        let at = from + rel;
        from = at + "path".len();
        let before_ok = at == 0 || bytes.get(at - 1).is_none_or(|b| !is_ident(*b));
        if !before_ok {
            continue;
        }
        let after = args[at + "path".len()..].trim_start();
        let Some(after) = after.strip_prefix(':') else {
            continue;
        };
        if let Some(lit) = leading_string(after.trim_start())
            && lit.starts_with('/')
            && lit.len() > 1
            && !lit.contains(['$', ' ', '{', '}', '*', ':'])
        {
            return Some(lit.trim_end_matches('/').to_owned());
        }
    }
    None
}

/// The most specific request entry among the finding's sink argument and source expression: a
/// named query/body/path/header parameter is preferred over a whole-object body or the raw URL.
fn best_entry(finding: &Finding, path: &str, source: Option<&str>) -> Option<Entry> {
    // A Hono handler reads its request through method calls on a context object (`c.req.param('id')`,
    // `c.req.query('q')`, `c.req.header('x')`), and often destructures the whole-params object
    // (`const { module: mod } = c.req.param()`). The generic member-access logic names none of these,
    // so resolve the Hono shape first.
    if let Some(entry) = hono_entry(finding, path, source) {
        return Some(entry);
    }
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
    // A whole-body/query source (`req.body`) the trace immediately destructures into a named local
    // (`const { baseUrl } = req.body`) names the specific field; keep it as a candidate so the ranking
    // prefers it over the vaguer whole-part entry. Without this the payload has no field to ride and
    // the handler's other required members are never sent.
    if let Some(entry) = destructured_entry(finding, path) {
        candidates.push(entry);
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
        .or_else(|| coarse_params_entry(finding, path, source))
        .or_else(|| source.and_then(|src| coarse_header_entry(finding, src)))
}

/// When the finding's source is the whole `req.params` object with no segment named, the path
/// parameter the handler actually reads (`req.params.id`) and the route declares a slot for.
/// Mirrors [`coarse_header_entry`] for path parameters: the coarse source is refined from the
/// handler source and the route's own slots, never guessed. `None` unless a read `params.<name>`
/// lines up with a `{name}` the route carries.
fn coarse_params_entry(finding: &Finding, path: &str, source: Option<&str>) -> Option<Entry> {
    if strip_request_receiver(finding.source.expr.trim())? != "params" {
        return None;
    }
    let src = source?;
    for accessor in request_accessors(src) {
        let Some(rest) = strip_request_receiver(&accessor) else {
            continue;
        };
        let mut parts = rest.split('.');
        if parts.next() != Some("params") {
            continue;
        }
        if let Some(name) = parts
            .next()
            .filter(|n| !n.is_empty() && n.bytes().all(is_ident))
            && let Some(slot) = path_param_slot(path, name)
        {
            return Some(Entry::PathParam(slot));
        }
    }
    None
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

/// Whether a sink API enumerates a directory's entries (rather than reading a file's bytes):
/// `fs.readdirSync`, `fs.promises.readdir`, `fs.opendirSync`. For these the traversal proof is a
/// planted file name appearing in the listing, not file content. Framework-agnostic: keyed on the
/// standard filesystem API name alone.
fn sink_lists_directory(api: &str) -> bool {
    let lower = api.to_ascii_lowercase();
    lower.contains("readdir") || lower.contains("opendir") || lower.contains("scandir")
}

/// Whether a sink API removes a filesystem entry (rather than reading one): `fs.unlink(Sync)`,
/// `fs.rm(Sync)`, `fs.rmdir(Sync)`, `rimraf`, `fs.remove`. For these the traversal proof is a planted
/// file outside the base directory disappearing after the request, not reflected content. Keyed on
/// the standard filesystem API name alone, so it is framework-agnostic. The final `.`-segment is
/// matched exactly so an unrelated method whose name merely contains `rm` is not mistaken for one.
fn sink_removes(api: &str) -> bool {
    let name = api.rsplit('.').next().unwrap_or(api).to_ascii_lowercase();
    matches!(
        name.as_str(),
        "unlink"
            | "unlinksync"
            | "rm"
            | "rmsync"
            | "rmdir"
            | "rmdirsync"
            | "rimraf"
            | "remove"
            | "removesync"
    )
}

/// A Hono request accessor call (`<ctx>.req.<method>(<arg?>)`): the method and its string-literal
/// argument, if any. `c.req.param('id')` -> `("param", Some("id"))`; `c.req.param()` -> `("param",
/// None)`; a bare `req.query('q')` is accepted too. `None` when the expression is not a `.req.`
/// method call.
fn hono_req_call(expr: &str) -> Option<(&str, Option<String>)> {
    let expr = expr.trim();
    let after = if let Some(rest) = expr.strip_prefix("req.") {
        rest
    } else {
        let at = expr.find(".req.")?;
        &expr[at + ".req.".len()..]
    };
    let paren = after.find('(')?;
    let method = &after[..paren];
    if method.is_empty() || !method.bytes().all(is_ident) {
        return None;
    }
    let close = after.rfind(')')?;
    if close < paren {
        return None;
    }
    let inner = after[paren + 1..close].trim();
    let arg = (!inner.is_empty()).then(|| unquote(inner)).flatten();
    Some((method, arg))
}

/// The request part a Hono accessor method reads: `param` -> path params, `query`/`queries` ->
/// query, `header` -> headers, `json`/`parseBody`/`text`/`formData` -> body. `None` for a method
/// that is not a request input (`valid`, `method`, `url`).
fn hono_part(method: &str) -> Option<&'static str> {
    Some(match method {
        "param" => "params",
        "query" | "queries" => "query",
        "header" => "headers",
        "json" | "parseBody" | "text" | "formData" | "arrayBuffer" | "blob" => "body",
        _ => return None,
    })
}

/// The request entry a Hono handler's source expression resolves to: an explicit accessor
/// (`c.req.param('module')`) or the destructured whole-collection form (`const { module: mod } =
/// c.req.param()`), where the tainted local is mapped back through the destructuring to the request
/// key. `None` unless the source expression is a Hono `.req.` accessor.
fn hono_entry(finding: &Finding, path: &str, source: Option<&str>) -> Option<Entry> {
    let (method, arg) = hono_req_call(finding.source.expr.trim())?;
    let part = hono_part(method)?;
    if let Some(name) = arg {
        return named_request_entry(part, &name, path);
    }
    // No argument: the call returns the whole collection, destructured into locals. The tainted
    // local is the first thing the value was assigned to; map it back to the request key.
    let src = source?;
    let local = first_assigned_local(finding)?;
    let key = destructuring_key_for_local(src, method, &local)?;
    named_request_entry(part, &key, path)
}

/// The entry for a named request input in a given part. A path parameter is taken only when the
/// route declares a matching slot.
fn named_request_entry(part: &str, name: &str, path: &str) -> Option<Entry> {
    match part {
        "query" => Some(Entry::Query(name.to_owned())),
        "body" => Some(Entry::Body(Some(name.to_owned()))),
        "headers" => Some(Entry::Header(name.to_ascii_lowercase())),
        "params" => path_param_slot(path, name).map(Entry::PathParam),
        _ => None,
    }
}

/// The first local a finding's value was assigned to at the source (its first in-file `assigned to
/// \`x\`` trace step): the destructured local that carries the tainted request key.
fn first_assigned_local(finding: &Finding) -> Option<String> {
    finding.trace.iter().find_map(|step| {
        if step.file.is_some() {
            return None;
        }
        let name = step.note.strip_prefix("assigned to `")?.strip_suffix('`')?;
        (!name.is_empty() && name.bytes().all(is_ident)).then(|| name.to_owned())
    })
}

/// Given a destructuring bound from a no-argument Hono accessor (`const { module: mod, kind } =
/// c.req.<method>()`), the request key a local was bound from: local `mod` -> key `module`,
/// shorthand `kind` -> `kind`. `None` when no such binding names the local.
fn destructuring_key_for_local(source: &str, method: &str, local: &str) -> Option<String> {
    hono_destructuring(source, method)
        .into_iter()
        .find(|(_, bound)| bound == local)
        .map(|(key, _)| key)
}

/// The route key a destructuring binds to a slot's local (`const { module: mod } = c.req.param()`,
/// slot `module` -> local `mod`); shorthand binds a slot to a local of the same name.
fn local_for_key(source: &str, method: &str, key: &str) -> Option<String> {
    hono_destructuring(source, method)
        .into_iter()
        .find(|(bound_key, _)| bound_key == key)
        .map(|(_, local)| local)
}

/// Every `key -> local` pair of an object-destructuring bound from a no-argument `<ctx>.req.
/// <method>()` call *anywhere* in the source. Shorthand `{ a }` yields `("a","a")`; renamed
/// `{ a: b }` yields `("a","b")`; a default (`{ a = 1 }`) keeps the key as its own local. A file
/// registers many handlers, each destructuring its own params, so all bindings are gathered and the
/// caller selects the one naming the local or key it is resolving.
fn hono_destructuring(source: &str, method: &str) -> Vec<(String, String)> {
    let needle = format!(".req.{method}(");
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = source[from..].find(&needle) {
        let at = from + rel;
        from = at + needle.len();
        // The call must take no argument: the next non-space byte after `(` is `)`.
        if source[from..].trim_start().as_bytes().first() != Some(&b')') {
            continue;
        }
        // Walk back over the context identifier and the `=` to the destructuring pattern.
        let head = source[..at].trim_end();
        let head = head.trim_end_matches(|c: char| is_ident(c as u8) && c.is_ascii());
        let head = head.trim_end();
        let Some(head) = head.strip_suffix('=') else {
            continue;
        };
        if head.ends_with(['=', '!', '<', '>']) {
            continue;
        }
        let head = head.trim_end();
        if !head.ends_with('}') {
            continue;
        }
        let close = head.len() - 1;
        let Some(open) = matching_open_brace(head, close) else {
            continue;
        };
        for entry in split_top_level_commas(&head[open + 1..close]) {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (key, local) = match entry.split_once(':') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => (entry, entry),
            };
            // Drop a default value on the local (`a = 1`) and a rest element (`...rest`).
            let local = local.split('=').next().unwrap_or(local).trim();
            let key = key.trim_start_matches("...").trim();
            let local = local.trim_start_matches("...").trim();
            if !key.is_empty()
                && key.bytes().all(is_ident)
                && !local.is_empty()
                && local.bytes().all(is_ident)
            {
                out.push((key.to_owned(), local.to_owned()));
            }
        }
    }
    out
}

/// The index of the `{` matching the `}` at `close` in `text`, scanning backward and honoring
/// nesting. `None` when unbalanced.
fn matching_open_brace(text: &str, close: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut i = close as isize;
    while i >= 0 {
        match bytes.get(i as usize).copied()? {
            b'}' => depth += 1,
            b'{' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i as usize);
                }
            }
            _ => {}
        }
        i -= 1;
    }
    None
}

/// The index of the `}` matching the `{` at `open` in `text`, scanning forward and honoring
/// nesting. `None` when unbalanced. The mirror of [`matching_open_brace`].
fn matching_close_brace(text: &str, open: usize) -> Option<usize> {
    delimiter_close(text, open, b'{', b'}')
}

/// The index of the `)` matching the `(` at `open` in `text`, scanning forward and honoring nesting.
fn matching_close_paren(text: &str, open: usize) -> Option<usize> {
    delimiter_close(text, open, b'(', b')')
}

/// Forward-match an open delimiter to its close, honoring nesting. String- and comment-naive, as the
/// rest of this module's brace handling is: the handler bodies it reads keep their delimiters
/// balanced within string and template literals.
fn delimiter_close(text: &str, open: usize, open_b: u8, close_b: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        let b = bytes.get(i).copied()?;
        if b == open_b {
            depth += 1;
        } else if b == close_b {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// The byte offset where the 1-based `line` begins, or `None` when the source has fewer lines.
fn line_offset(source: &str, line: usize) -> Option<usize> {
    if line == 0 {
        return None;
    }
    let mut off = 0usize;
    for (i, chunk) in source.split_inclusive('\n').enumerate() {
        if i + 1 == line {
            return Some(off);
        }
        off += chunk.len();
    }
    (line == source.split_inclusive('\n').count() + 1).then_some(source.len())
}

/// The conditions of every `if` / `else if` whose braced block spans the sink line: each guard's
/// identifier and, when it is an equality against a string literal, that literal
/// (`platform === 'truuze'` -> `("platform", Some("truuze"))`, `if (agentKey)` -> `("agentKey",
/// None)`). Only blocks that actually enclose the sink are returned, so a sibling branch that closes
/// before the sink (`if (skillContent) { ... }` preceding the branch that holds the sink) is
/// excluded. Mined from the handler source by brace matching; nothing here is tied to an app.
pub fn enclosing_guards(source: &str, sink_line: u32) -> Vec<(String, Option<String>)> {
    let Some(sink_off) = line_offset(source, sink_line as usize) else {
        return Vec::new();
    };
    let bytes = source.as_bytes();
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    let mut i = 0usize;
    while i + 2 <= source.len() {
        // `if` is ASCII, so byte comparisons avoid slicing at a non-char boundary in a source that
        // carries multibyte characters. `i + 2` lands just past `f`, always a char boundary.
        let at_boundary = i == 0 || bytes.get(i - 1).is_some_and(|byte| !is_ident(*byte));
        if at_boundary
            && bytes.get(i) == Some(&b'i')
            && bytes.get(i + 1) == Some(&b'f')
            && bytes.get(i + 2).is_none_or(|b| !is_ident(*b))
            && let Some(popen) = source[i + 2..].find('(').map(|r| i + 2 + r)
            && source[i + 2..popen].trim().is_empty()
            && let Some(pclose) = matching_close_paren(source, popen)
        {
            let cond = &source[popen + 1..pclose];
            let after = &source[pclose + 1..];
            let ws = after.len() - after.trim_start().len();
            if after[ws..].starts_with('{') {
                let bopen = pclose + 1 + ws;
                if let Some(bclose) = matching_close_brace(source, bopen)
                    && sink_off > bopen
                    && sink_off < bclose
                {
                    for guard in parse_condition(cond) {
                        if !out.iter().any(|(id, _)| *id == guard.0) {
                            out.push(guard);
                        }
                    }
                }
            }
            i = popen + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// The guards of a condition: split on top-level `&&`, each operand read as an equality against a
/// string literal or a bare identifier truthiness test. Operands that are negations, calls or
/// comparisons against non-literals yield nothing.
fn parse_condition(cond: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    for part in cond.split("&&") {
        let part = part.trim();
        if let Some((id, lit)) = equality_guard(part) {
            out.push((id, Some(lit)));
        } else if is_plain_identifier(part) {
            out.push((part.to_owned(), None));
        }
    }
    out
}

/// `ident === "lit"` / `ident == 'lit'` (either order) -> `(ident, lit)`. Rejects `!==`, `>=`, `<=`
/// and comparisons where neither side is a plain identifier or neither is a string literal.
fn equality_guard(part: &str) -> Option<(String, String)> {
    for op in ["===", "=="] {
        let mut from = 0;
        while let Some(rel) = part[from..].find(op) {
            let at = from + rel;
            from = at + op.len();
            let before = part.as_bytes().get(at.wrapping_sub(1)).copied();
            let after = part.as_bytes().get(at + op.len()).copied();
            // Skip `!==`, `>==`, `<==`, and an `==` that is really the tail of `===`.
            if before.is_some_and(|b| matches!(b, b'!' | b'<' | b'>' | b'='))
                || after.is_some_and(|b| b == b'=')
            {
                continue;
            }
            let lhs = part[..at].trim();
            let rhs = part[at + op.len()..].trim();
            let guard = guard_from_sides(lhs, rhs);
            if guard.is_some() {
                return guard;
            }
        }
    }
    None
}

/// Pairs an identifier side with a string-literal side, in either order.
fn guard_from_sides(lhs: &str, rhs: &str) -> Option<(String, String)> {
    if is_plain_identifier(lhs)
        && let Some(lit) = string_literal_value(rhs)
    {
        return Some((lhs.to_owned(), lit));
    }
    if is_plain_identifier(rhs)
        && let Some(lit) = string_literal_value(lhs)
    {
        return Some((rhs.to_owned(), lit));
    }
    None
}

/// Whether `text` is a single bare identifier (not a keyword literal, not a number).
fn is_plain_identifier(text: &str) -> bool {
    text.as_bytes()
        .first()
        .is_some_and(|first| !first.is_ascii_digit())
        && text.bytes().all(is_ident)
        && !matches!(text, "true" | "false" | "null" | "undefined")
}

/// The content of a single quoted/backtick string literal with no interpolation (`'truuze'`,
/// `"http"`, `` `relay` ``), or `None` when `text` is not a plain string literal.
fn string_literal_value(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let quote = *bytes.first()?;
    if !matches!(quote, b'\'' | b'"' | b'`') || bytes.len() < 2 || *bytes.last()? != quote {
        return None;
    }
    let inner = &text[1..text.len() - 1];
    if inner.contains(quote as char) || inner.contains("${") || inner.contains('\\') {
        return None;
    }
    Some(inner.to_owned())
}

/// The lines in the finding's own source file where a guard gating the sink may sit: the source
/// line, the sink line (only when the sink is in this file), and every same-file trace step. For a
/// cross-function sink the guard that pins a non-payload path segment (`platform === 'truuze'`) or
/// selects the branch that reaches the sink (`else if (token)`) encloses the in-handler point where
/// the taint is read or passed into the callee — a trace step — not the sink line inside the callee.
/// Considering every same-file flow position, rather than the sink line alone, lets a guard be found
/// wherever along the flow it sits. Mined from the finding's own locations; nothing is app-specific.
pub fn guard_anchor_lines(finding: &Finding) -> Vec<u32> {
    let mut lines = vec![finding.source.line];
    if finding.sink.file.is_none() {
        lines.push(finding.sink.line);
    }
    for step in &finding.trace {
        if step.file.is_none() {
            lines.push(step.line);
        }
    }
    lines.sort_unstable();
    lines.dedup();
    lines
}

/// The union of [`enclosing_guards`] taken at each anchor line: every guard that encloses any of the
/// flow's same-file positions. The first binding of each identifier is kept, except that a literal
/// equality (`id === "lit"`) upgrades an earlier bare truthiness binding of the same identifier, so a
/// pinned value is preferred over a placeholder when the same field is both tested and compared.
fn enclosing_guards_over(source: &str, anchors: &[u32]) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    for &line in anchors {
        for (id, lit) in enclosing_guards(source, line) {
            match out.iter_mut().find(|(existing, _)| *existing == id) {
                Some(slot) if slot.1.is_none() && lit.is_some() => slot.1 = lit,
                Some(_) => {}
                None => out.push((id, lit)),
            }
        }
    }
    out
}

/// Values for route `{slot}` segments other than the payload-bearing one, chosen from a guard that
/// encloses the flow. When a non-payload segment's local is pinned by an equality guard around a
/// flow position (`platform === 'truuze'`), the request must carry that literal to reach the sink;
/// the generic placeholder is rejected. Mined from the route and handler source only.
pub fn path_slot_fillers(
    source: &str,
    path: &str,
    entry: &Entry,
    anchors: &[u32],
) -> Vec<(String, String)> {
    let payload_slot = match entry {
        Entry::PathParam(name) => Some(name.as_str()),
        _ => None,
    };
    let guards = enclosing_guards_over(source, anchors);
    let mut out = Vec::new();
    for slot in route_slots(path) {
        if Some(slot.as_str()) == payload_slot {
            continue;
        }
        if let Some((_, Some(lit))) = guards.iter().find(|(id, lit)| *id == slot && lit.is_some()) {
            out.push((slot, lit.clone()));
        }
    }
    out
}

/// Request fields of `part` that a guard enclosing the sink requires present or equal to a literal,
/// besides the payload field `target`: the extra body/query members a probe must send to reach the
/// sink past a branch like `else if (agentKey)` or `if (mode === 'raw')`. Each is paired with a value
/// that satisfies its guard — the pinned literal, or a non-empty placeholder for a bare truthiness
/// test. Only members the handler reads from this request part (destructured or accessed) are
/// included. Mined from the handler source only.
pub fn guard_required_fields(
    source: &str,
    part: &str,
    target: &str,
    anchors: &[u32],
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (id, lit) in enclosing_guards_over(source, anchors) {
        if id == target || !is_request_field(source, part, &id) {
            continue;
        }
        let value = lit.unwrap_or_else(|| "jsspector".to_owned());
        out.push((id, value));
    }
    out
}

/// Whether the handler reads `name` from request `part`: by member access (`req.body.name`) or by
/// destructuring the whole part (`const { name } = req.body`).
fn is_request_field(source: &str, part: &str, name: &str) -> bool {
    member_params(source, part).iter().any(|n| n == name)
        || destructured_fields(source, part).iter().any(|n| n == name)
}

/// The locals a handler destructures from `<receiver>.<part>` (`const { a, b: c } = req.body` -> `a`,
/// `c`). Member-access reads are covered by [`member_params`]; this covers the destructured shape.
fn destructured_fields(source: &str, part: &str) -> Vec<String> {
    let mut out = Vec::new();
    for recv in ["req", "request", "ctx"] {
        let needle = format!("{recv}.{part}");
        let mut from = 0;
        while let Some(rel) = source[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            // Require a word boundary before the receiver and after the part (`req.body`, not
            // `req.bodyText` or `xreq.body`).
            if at > 0
                && source
                    .as_bytes()
                    .get(at - 1)
                    .is_some_and(|byte| is_ident(*byte))
            {
                continue;
            }
            if source.as_bytes().get(from).is_some_and(|b| is_ident(*b)) {
                continue;
            }
            let head = source[..at].trim_end();
            let Some(head) = head.strip_suffix('=') else {
                continue;
            };
            if head.ends_with(['=', '!', '<', '>']) {
                continue;
            }
            let head = head.trim_end();
            if !head.ends_with('}') {
                continue;
            }
            let close = head.len() - 1;
            let Some(open) = matching_open_brace(head, close) else {
                continue;
            };
            for entry in split_top_level_commas(&head[open + 1..close]) {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                let local = match entry.split_once(':') {
                    Some((_, v)) => v.trim(),
                    None => entry,
                };
                let local = local
                    .split('=')
                    .next()
                    .unwrap_or(local)
                    .trim()
                    .trim_start_matches("...")
                    .trim();
                if !local.is_empty() && local.bytes().all(is_ident) {
                    out.push(local.to_owned());
                }
            }
        }
    }
    out
}

/// For a directory-listing path-traversal whose read path appends a sibling route parameter after
/// the tainted one (`path.join(resolve(base, mod), kind)`), the sibling slot and the fixed values
/// the handler constrains it to. Requires: another route slot besides the tainted one, that slot's
/// local appearing in a path-building call *after* a tainted value, and an enum/whitelist guard on
/// it. Mined from the route and handler source only. `None` otherwise.
fn appended_enum_param(
    finding: &Finding,
    path: &str,
    source: &str,
    entry: &Entry,
    tainted: &[String],
) -> Option<(String, Vec<String>)> {
    let Entry::PathParam(tainted_slot) = entry else {
        return None;
    };
    for slot in route_slots(path) {
        if &slot == tainted_slot {
            continue;
        }
        let local = hono_req_call(finding.source.expr.trim())
            .and_then(|(method, _)| local_for_key(source, method, &slot))
            .unwrap_or_else(|| slot.clone());
        let values = enum_values(source, &local);
        if values.is_empty() {
            continue;
        }
        if !appended_after_tainted(source, &local, tainted) {
            continue;
        }
        let safe: Vec<String> = values
            .into_iter()
            .filter(|v| is_safe_dir_segment(v))
            .collect();
        if safe.is_empty() {
            continue;
        }
        return Some((slot, safe));
    }
    None
}

/// Every `{name}` slot a route path declares, in order.
fn route_slots(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            break;
        };
        let name = &after[..close];
        if !name.is_empty() && name.bytes().all(is_ident) {
            out.push(name.to_owned());
        }
        rest = &after[close + 1..];
    }
    out
}

/// The fixed values a handler constrains `id` to with an array membership guard
/// (`['info','docs','examples'].includes(id)`, `[...].indexOf(id) !== -1`): the string literals of
/// the array it is tested against. Empty when `id` is not guarded this way.
fn enum_values(source: &str, id: &str) -> Vec<String> {
    for method in [".includes(", ".indexOf("] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(method) {
            let dot = from + rel;
            from = dot + method.len();
            let Some(arg) = balanced_arg(&source[from..]) else {
                continue;
            };
            if arg.trim() != id {
                continue;
            }
            if let Some(values) = array_before(source, dot) {
                return values;
            }
        }
    }
    Vec::new()
}

/// The string-literal elements of an array literal ending with `]` immediately before `dot`
/// (`['a','b'].includes(x)` at the `.includes` -> `["a","b"]`). `None` when the receiver is not an
/// array literal of string literals.
fn array_before(source: &str, dot: usize) -> Option<Vec<String>> {
    let head = source[..dot].trim_end();
    if !head.ends_with(']') {
        return None;
    }
    let close = head.len() - 1;
    let open = matching_bracket(head, close)?;
    let elems = split_top_level_commas(&head[open + 1..close]);
    let mut out = Vec::new();
    for elem in elems {
        let literal = string_literal_arg(elem.trim())?;
        out.push(literal);
    }
    (!out.is_empty()).then_some(out)
}

/// The index of the `[` matching the `]` at `close`, scanning backward and honoring nesting.
fn matching_bracket(text: &str, close: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut i = close as isize;
    while i >= 0 {
        match bytes.get(i as usize).copied()? {
            b']' => depth += 1,
            b'[' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i as usize);
                }
            }
            _ => {}
        }
        i -= 1;
    }
    None
}

/// Whether `local` appears as an argument *after* a tainted value in a `path.join(...)` or
/// `path.resolve(...)` call: evidence the sibling is appended onto the tainted path.
fn appended_after_tainted(source: &str, local: &str, tainted: &[String]) -> bool {
    for needle in [".join(", ".resolve("] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(needle) {
            let open = from + rel + needle.len();
            from = open;
            let Some(arglist) = balanced_arg(&source[open..]) else {
                continue;
            };
            let args: Vec<String> = split_top_level_commas(arglist)
                .into_iter()
                .map(|a| a.trim().to_owned())
                .collect();
            let tainted_at = args
                .iter()
                .position(|a| tainted.iter().any(|name| name == a));
            let local_at = args.iter().position(|a| a == local);
            if let (Some(t), Some(l)) = (tainted_at, local_at)
                && l > t
            {
                return true;
            }
        }
    }
    false
}

/// Whether a value is safe to plant and drive as a single path segment: non-empty, ordinary
/// filename characters only, and not a `.`/`..` traversal element.
fn is_safe_dir_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
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

/// Derives a conservative HTTP entry for a handler under a conventional routing directory when
/// static route registration was unavailable. This only creates a request candidate; dynamic
/// verification still needs independent runtime evidence before reporting success.
pub fn derive_http_entry(finding: &Finding) -> Option<String> {
    const ROOTS: [&str; 8] = [
        "controllers",
        "controller",
        "routes",
        "route",
        "handlers",
        "handler",
        "endpoints",
        "resolvers",
    ];
    let file = finding.file.replace('\\', "/");
    let parts: Vec<&str> = file.split('/').filter(|part| !part.is_empty()).collect();
    let root = parts.iter().position(|part| ROOTS.contains(part))?;
    let mut segments: Vec<&str> = parts.get(root + 1..)?.to_vec();
    let last = segments.pop()?;
    let stem = last.rsplit_once('.').map_or(last, |(name, _)| name);
    if stem != "index" && stem != "route" {
        segments.push(stem);
    }
    if segments.is_empty()
        || !segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return None;
    }
    let method = if finding.source.expr.contains("body") || finding.source.expr.contains("payload")
    {
        "POST"
    } else {
        "GET"
    };
    Some(format!("{method} /{}", segments.join("/")))
}

#[cfg(test)]
mod tests {
    #[test]
    fn removal_sinks_are_recognized_by_their_api_name() {
        use super::sink_removes;
        assert!(sink_removes("fs.unlinkSync"));
        assert!(sink_removes("fs.unlink"));
        assert!(sink_removes("fs.promises.unlink"));
        assert!(sink_removes("fs.rmSync"));
        assert!(sink_removes("fs.rmdir"));
        assert!(sink_removes("rimraf"));
        // A read or write sink is not a removal, and a method whose name merely contains `rm` is not
        // mistaken for one.
        assert!(!sink_removes("fs.readFileSync"));
        assert!(!sink_removes("fs.writeFileSync"));
        assert!(!sink_removes("db.confirmSync"));
    }

    #[test]
    fn convention_based_http_entries_are_conservative() {
        let mut body = finding(
            VulnClass::NosqlInjection,
            Auth::NoneDetected,
            None,
            "request.body",
        );
        body.file = "app/controllers/api/user.js".to_owned();
        assert_eq!(derive_http_entry(&body).as_deref(), Some("POST /api/user"));
        body.entry = derive_http_entry(&body);
        let probe = Probe::from_finding(&body).unwrap();
        assert_eq!(probe.class, VulnClass::NosqlInjection);
        assert_eq!(probe.path, "/api/user");

        let mut query = finding(
            VulnClass::NosqlInjection,
            Auth::NoneDetected,
            None,
            "req.query.id",
        );
        query.file = "src/routes/users/index.js".to_owned();
        assert_eq!(derive_http_entry(&query).as_deref(), Some("GET /users"));
        query.file = "lib/helpers/db.js".to_owned();
        assert_eq!(derive_http_entry(&query), None);
    }

    #[test]
    fn a_registered_route_and_its_url_search_params_are_mined() {
        // A plug-in that mounts a prefix handler on a host web-server service and dispatches
        // sub-paths itself, choosing the outbound host from a query parameter of the parsed URL.
        let source = r#"
          ctx.inject(['webServer'], (ctx) => {
            const webServer = ctx.webServer;
            ctx.effect(() => webServer.register({
              kind: 'prefix',
              path: '/dsh-wallpaper-bg',
              handler: async (req, res) => {
                const url = new URL(req.url, 'http://localhost');
                const p = url.pathname;
                if (p === '/dsh-wallpaper-bg/we') {
                  const query = Object.fromEntries(url.searchParams);
                  return weApi(query);
                }
              },
            }));
          });
          async function weApi(query) {
            const base = query.base || DEFAULT;
            const action = query.action;
            await fetch(base + '/api/wallpapers');
          }
        "#;
        assert_eq!(
            super::registered_route_entry(source).as_deref(),
            Some("GET /dsh-wallpaper-bg")
        );
        let params = super::url_search_params(source);
        assert!(params.contains(&"base".to_owned()), "mined {params:?}");
        assert!(params.contains(&"action".to_owned()), "mined {params:?}");
        // The dispatched sub-path is recovered as a gate path.
        assert!(super::gate_paths(source).contains(&"/dsh-wallpaper-bg/we".to_owned()));
        // A registration without a request handler is not mistaken for a route.
        assert_eq!(
            super::registered_route_entry("thing.register({ path: '/x' })"),
            None
        );
    }

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
    fn a_header_entry_takes_its_other_forwarded_headers_as_siblings() {
        // A handler that forwards a second request header into the outbound request: the tainted
        // header chooses the host, the sibling must still be sent so the request is constructed.
        let source = r#"
          axios({
            method: 'get',
            url: `${req.headers.backendurl}/jsonapi/${model}/${req.params.objectId}`,
            headers: { Authorization: req.headers.authorization },
          });
        "#;
        let entry = Entry::Header("backendurl".to_owned());
        let probe = Probe {
            method: Method::Get,
            path: "/jsonapi/stagedAssets/{objectId}".to_owned(),
            entry,
            class: VulnClass::Ssrf,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
            url_query_params: Vec::new(),
            read_suffix: None,
            envelope: None,
            doc_envelope: None,
            lists_dir: false,
            removes: false,
            appended_param: None,
            path_fillers: Vec::new(),
        };
        let (part, target) = probe.entry_part().expect("a header entry takes siblings");
        assert_eq!((part, target), ("headers", "backendurl"));
        let siblings = required_siblings(source, part, target);
        assert_eq!(
            siblings,
            vec![("authorization".to_owned(), "jsspector".to_owned())]
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

    #[test]
    fn guards_enclosing_the_sink_pin_a_path_segment_and_require_a_branch_field() {
        // A handler routes on a path segment, reaches the sink only on one segment value and only on
        // a truthiness branch over a sibling body field. The branch over `note`, which closes before
        // the sink, and the branch over `token`, which opens after it, are not enclosing and excluded.
        let source = r#"
          router.post('/svc/:kind', async (req, res) => {
            const valid = ['go', 'stop'];
            if (!valid.includes(kind)) return;
            if (kind === 'go') {
              const { token, agent, base, note } = req.body;
              if (note) {
                handleNote(note);
              } else if (agent) {
                const url = base || 'https://default';
                const r = await fetch(`${url}/profile`);
              } else if (token) {
                handleToken(token);
              }
            }
          });
        "#;
        let sink_line = source
            .lines()
            .position(|l| l.contains("fetch("))
            .map(|i| i as u32 + 1)
            .unwrap();

        let guards = enclosing_guards(source, sink_line);
        assert!(guards.contains(&("kind".to_owned(), Some("go".to_owned()))));
        assert!(guards.contains(&("agent".to_owned(), None)));
        assert!(guards.iter().all(|(id, _)| id != "note" && id != "token"));

        let fillers = path_slot_fillers(
            source,
            "/svc/{kind}",
            &Entry::Body(Some("base".to_owned())),
            &[sink_line],
        );
        assert_eq!(fillers, vec![("kind".to_owned(), "go".to_owned())]);

        let required = guard_required_fields(source, "body", "base", &[sink_line]);
        assert_eq!(required, vec![("agent".to_owned(), "jsspector".to_owned())]);
    }

    #[test]
    fn a_cross_function_sink_picks_up_guards_enclosing_the_in_handler_flow() {
        // The tainted URL is forwarded into a helper, so the sink `fetch` sits in the callee with no
        // enclosing guard of its own. The guards that gate reaching it — a non-payload path segment
        // (`kind === 'go'`) and the branch field (`token`) — enclose the handler-side flow positions:
        // the source read and the call site. Anchoring the guard search on every same-file flow line,
        // not the callee's sink line alone, recovers both. (With the sink line alone, neither is seen.)
        let source = r#"
          async function upload(base) {
            const r = await fetch(`${base}/account/agent/profile/`);
            return r;
          }
          router.post('/svc/:kind', async (req, res) => {
            const valid = ['go', 'stop'];
            if (!valid.includes(kind)) return;
            if (kind === 'go') {
              const { token, base } = req.body;
              if (token) {
                await upload(base);
              }
            }
          });
        "#;
        let line_of = |needle: &str| {
            source
                .lines()
                .position(|l| l.contains(needle))
                .map(|i| i as u32 + 1)
                .unwrap()
        };
        let sink_line = line_of("fetch(");
        let source_line = line_of("const { token, base }");
        let call_line = line_of("await upload(base)");

        // The finding's own locations: source in the handler, sink in the callee, a trace step at the
        // call site. All share the finding's file, so each contributes an anchor line.
        let mut f = finding(
            VulnClass::Ssrf,
            Auth::NoneDetected,
            Some("POST /svc/{kind}"),
            "req.body",
        );
        f.source.line = source_line;
        f.sink.line = sink_line;
        f.trace = vec![TraceStep {
            file: None,
            line: call_line,
            col: 1,
            note: "passed to upload()".to_owned(),
        }];
        let anchors = guard_anchor_lines(&f);

        // The sink line alone finds nothing; the full flow recovers both guards.
        assert!(
            path_slot_fillers(
                source,
                "/svc/{kind}",
                &Entry::Body(Some("base".to_owned())),
                &[sink_line]
            )
            .is_empty()
        );
        let fillers = path_slot_fillers(
            source,
            "/svc/{kind}",
            &Entry::Body(Some("base".to_owned())),
            &anchors,
        );
        assert_eq!(fillers, vec![("kind".to_owned(), "go".to_owned())]);

        assert!(guard_required_fields(source, "body", "base", &[sink_line]).is_empty());
        let required = guard_required_fields(source, "body", "base", &anchors);
        assert_eq!(required, vec![("token".to_owned(), "jsspector".to_owned())]);
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
    fn a_coarse_params_base64_json_envelope_is_resolved_and_packed() {
        // The finding names only `req.params`; the handler reads `req.params.id`, base64url-decodes
        // it as a JSON envelope, and makes the outbound request to `payload.url`. The route's `{id}`
        // slot is recovered as the entry, and the envelope describes how to pack the payload.
        let source = r#"
          export async function handle(req, res) {
            const raw = req.params.id;
            const payload = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
            if (!payload.url || !payload.from || !payload.to) return res.status(400).end();
            const r = await axios.get(payload.url);
          }
        "#;
        let mut f = finding(
            VulnClass::Ssrf,
            Auth::NoneDetected,
            Some("GET /proxy/translated/{id}.srt"),
            "req.params",
        );
        f.file = "lib/translated.js".to_owned();
        f.sink.arg = "url".to_owned();
        f.trace = vec![TraceStep {
            file: None,
            line: 1,
            col: 1,
            note: "assigned to `raw`".to_owned(),
        }];
        let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
        assert_eq!(probe.entry, Entry::PathParam("id".to_owned()));
        let env = probe.envelope.expect("envelope recognized");
        assert_eq!(env.field, "url");
        assert_eq!(env.siblings, vec!["from".to_owned(), "to".to_owned()]);
        assert!(env.url_safe);
        // Without the handler source the coarse `req.params` stays unresolved, never guessed.
        assert!(Probe::from_finding(&f).is_err());
    }

    #[test]
    fn a_hono_param_destructuring_into_a_directory_listing_resolves_the_tainted_slot() {
        // A Hono handler destructures all path params from `c.req.param()`, uses one as a directory
        // ancestor and appends a sibling path param (enum-constrained) before listing it. The planner
        // must map the tainted local back to its route slot, recognize the listing sink, and recover
        // the sibling slot and its accepted values.
        let source = r#"
          app.get('/resources/:module/:kind', async c => {
            const { module: mod, kind } = c.req.param();
            const base = path.resolve(__dirname, '..', '..', 'mcp_resources', mod);
            if (!['info', 'docs', 'examples'].includes(kind)) {
              return c.json({ error: 'nope' }, 400);
            }
            const dirPath = path.join(base, kind);
            const files = fs.readdirSync(dirPath, { withFileTypes: true });
            return c.json({ files });
          });
        "#;
        let mut f = finding(
            VulnClass::PathTraversal,
            Auth::NoneDetected,
            Some("GET /resources/{module}/{kind}"),
            "c.req.param()",
        );
        f.sink.api = "fs.readdirSync".to_owned();
        f.sink.arg = "abs".to_owned();
        f.trace = vec![
            TraceStep {
                file: None,
                line: 1,
                col: 1,
                note: "assigned to `mod`".to_owned(),
            },
            TraceStep {
                file: None,
                line: 1,
                col: 1,
                note: "assigned to `base`".to_owned(),
            },
            TraceStep {
                file: None,
                line: 1,
                col: 1,
                note: "assigned to `dirPath`".to_owned(),
            },
        ];
        let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
        assert_eq!(probe.entry, Entry::PathParam("module".to_owned()));
        assert!(probe.lists_dir);
        let ap = probe.appended_param.expect("sibling path param recovered");
        assert_eq!(ap.name, "kind");
        assert_eq!(
            ap.values,
            vec!["info".to_owned(), "docs".to_owned(), "examples".to_owned()]
        );
        // Without the handler source the coarse `c.req.param()` stays unresolved, never guessed.
        assert!(Probe::from_finding(&f).is_err());
    }

    #[test]
    fn a_base_dir_built_from_the_tainted_param_carries_taint_to_an_appended_enum_slot() {
        // The real handler builds a base directory from the tainted param (`path.resolve(.., mod)`),
        // guards a sibling slot with an enum, then appends it (`path.join(base, kind)`) before a
        // directory read — and the taint trace runs through a *different* branch, so `base` is not in
        // the trace. Taint must still propagate through the base-building assignment so the appended
        // enum slot and its accepted values are recovered.
        let source = r#"
          app.get('/resources/:module/:kind', async c => {
            const { module: mod, kind } = c.req.param();
            const base = path.resolve(__dirname, '..', '..', 'mcp_resources', mod);
            if (!['info', 'docs', 'examples'].includes(kind)) {
              return c.json({ error: 'nope' }, 400);
            }
            const dirPath = path.join(base, kind);
            if (!fs.existsSync(dirPath)) {
              const moduleDir = path.resolve(__dirname, '..', '..', 'mcp_modules', mod);
              const fallbackDir = path.join(moduleDir, 'docs');
              const walk = dir => {
                const abs = path.join(dir, '.');
                return fs.readdirSync(abs, { withFileTypes: true });
              };
              return c.json({ files: walk(fallbackDir) });
            }
          });
        "#;
        let mut f = finding(
            VulnClass::PathTraversal,
            Auth::NoneDetected,
            Some("GET /resources/{module}/{kind}"),
            "c.req.param()",
        );
        f.sink.api = "fs.readdirSync".to_owned();
        f.sink.arg = "abs".to_owned();
        // The reported trace runs through the fallback branch (moduleDir/fallbackDir), never `base`.
        f.trace = ["mod", "moduleDir", "fallbackDir", "dir", "abs"]
            .iter()
            .map(|name| TraceStep {
                file: None,
                line: 1,
                col: 1,
                note: format!("assigned to `{name}`"),
            })
            .collect();
        let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
        assert_eq!(probe.entry, Entry::PathParam("module".to_owned()));
        assert!(probe.lists_dir);
        // Taint reaching `base` through `path.resolve(.., mod)` is what lets the appended enum slot be
        // recovered: without it the sibling is appended after an untainted name and never driven.
        let ap = probe
            .appended_param
            .expect("enum slot recovered through the base-derived taint");
        assert_eq!(ap.name, "kind");
        assert_eq!(
            ap.values,
            vec!["info".to_owned(), "docs".to_owned(), "examples".to_owned()]
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

    #[test]
    fn a_parsed_document_body_field_is_packed_into_the_scaffold_the_parser_requires() {
        // A handler passes a tainted body field to a parse function defined in another module, then
        // chooses the outbound host from one member of the parsed result and guards on another. The
        // planner must recover, from the handler and the parser's own source, which JSON key reaches
        // the sink, which other members to fill, and the literal frontmatter scaffold the parser's
        // extraction regexes require around the embedded JSON object.
        let handler = r#"
          router.post('/connect', async (req, res) => {
            const { blob } = req.body;
            const parsed = parseDoc(blob);
            if (!parsed) return res.status(400).json({ error: 'bad' });
            const dest = parsed.endpoint || 'https://default';
            if (!parsed.ticket) return res.status(400).json({ error: 'no ticket' });
            const resp = await fetch(`${dest}/go`, { method: 'POST' });
          });
        "#;
        let module = r#"
          export function parseDoc(content) {
            if (!content) return null;
            const fm = content.match(/^===\s*\n([\s\S]*?)\n===/);
            if (!fm) return null;
            const m = fm[1].match(/meta:\s*(\{[\s\S]*?\})\s*$/m);
            if (!m) return null;
            try {
              const obj = JSON.parse(m[1]);
              return { endpoint: obj.host_url, ticket: obj.token };
            } catch { return null; }
          }
        "#;
        let mut f = finding(
            VulnClass::Ssrf,
            Auth::NoneDetected,
            Some("POST /connect"),
            "req.body",
        );
        f.sink.api = "fetch".to_owned();
        f.sink.arg = "dest".to_owned();
        f.trace = vec![TraceStep {
            file: None,
            line: 1,
            col: 1,
            note: "assigned to `dest`".to_owned(),
        }];

        let entry = Entry::Body(Some("blob".to_owned()));
        let doc = doc_envelope(&f, &entry, handler, module).expect("document envelope recognized");
        assert_eq!(doc.sink_key, "host_url");
        assert_eq!(doc.filler_keys, vec!["token".to_owned()]);
        assert_eq!(doc.prefix, "===\nmeta:");
        assert_eq!(doc.suffix, "\n===");
    }
}
