//! The concrete requests a [`Probe`] turns into, and how a reproduction is recognized. Pure: the
//! sandbox ([`super::sandbox`]) sends these and reports back what it observed, and
//! [`reproduced`] decides. A payload only ever makes a benign, self-identifying signal — read a
//! planted marker file, write a marker file, or call a marker service — so a hit is unambiguous
//! and leaves nothing behind but the marker.

use super::plan::{Entry, Probe};
use jss_core::VulnClass;

/// A per-run marker. Everything a payload does is tagged with `token`, so a reproduction is told
/// from the app's normal behavior by the token alone.
#[derive(Debug, Clone)]
pub struct Canary {
    pub token: String,
}

impl Canary {
    pub fn new(token: String) -> Self {
        Self { token }
    }

    /// The file planted in the image for a read to find (`/jss-marker-<token>`), holding the
    /// token.
    pub fn planted_file(&self) -> String {
        format!("/jss-marker-{}", self.token)
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
        format!("http://jss-marker/{}", self.service_token(nonce))
    }
}

/// How a hit is observed, out of band from the HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// The token appears in the HTTP response body (a planted file was read back).
    InResponse,
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
            // Absolute, then climbing from several depths, raw and with an encoded separator.
            let mut out = vec![file.clone(), format!("/{name}")];
            for depth in [1usize, 3, 6, 10] {
                let up = "../".repeat(depth);
                out.push(format!("{up}{name}"));
                out.push(format!("{}{name}", "..%2f".repeat(depth)));
            }
            out.into_iter()
                .map(|value| (value, Signal::InResponse))
                .collect()
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
        Signal::FileWritten(_) => marker_file_exists,
        Signal::ServiceReached(_) => service_reached,
    }
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
        assert!(a.iter().all(|x| x.signal == Signal::InResponse));
        // The planted marker's name rides in every payload.
        assert!(a.iter().all(|x| x.target.contains("marker-abc123")));
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
