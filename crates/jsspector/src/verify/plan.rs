//! Deciding what a finding implies as an HTTP request, with no I/O. `--verify` runs the derived
//! request against the app in a container (see [`super::sandbox`]); this module only works out
//! what to send and how to tell a reproduction from a miss, so it can be unit-tested on its own.

use jss_core::{Auth, Finding, VulnClass};

mod auth;
pub(super) use auth::*;

use super::mcp::McpHints;

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

/// The literal text a handler requires immediately before and after the tainted value itself
/// before it reaches the sink (`username?.match(/#{(.*)}/) !== null`, then `username.substring(2,
/// username.length - 1)`): a hand-rolled delimiter convention, distinct from [`Envelope`]/
/// [`DocEnvelope`] (which pack the payload into a JSON object). The payload becomes `prefix` +
/// `value` + `suffix`. Mined from the handler source only (see [`text_wrap`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextWrap {
    pub prefix: String,
    pub suffix: String,
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
    /// A literal filename suffix appended to the tainted value itself (`${userId}.json` or
    /// `userId + '.json'`). Unlike [`Self::read_suffix`], the input still names the file stem rather
    /// than a directory. Verification therefore plants `<stem><suffix>` and reports that effective
    /// crafted filename. `None` when the handler does not transform the filename this way.
    pub read_filename_suffix: Option<String>,
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
    /// filesystem entry outside the base directory disappearing after the request while a sibling
    /// control entry planted alongside it survives. Derived from the sink API only.
    pub removes: bool,
    /// When the removing sink only operates on a *directory* (`fs.rmdir(Sync)`, or a recursive helper
    /// guarded by `isDirectory()` whose terminal sink is `rmdir`), the planted target and control must
    /// be directories, not files: `rmdirSync` on a plain file errors and the differential would never
    /// fire. Derived from the sink API only; `false` for `unlink`/`rm` which remove a file.
    pub removes_dir: bool,
    /// When the sink creates a filesystem entry (`fs.mkdir`, `fs.writeFile`, `fs.createWriteStream`,
    /// a file-upload move) rather than reading one, the traversal cannot be proved by reflected
    /// content either: the proof is a new entry appearing inside an attacker-named directory planted
    /// *outside* the base directory while a sibling control directory planted alongside it stays
    /// empty. Derived from the sink API only.
    pub creates: bool,
    /// The tainted path is an entry name inside an uploaded archive. Verification must send a
    /// multipart ZIP rather than place a traversal string in a normal request field.
    pub archive_upload: bool,
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
    /// JSON body fields the handler requires present before the sink is reached, when the payload
    /// itself enters through a different part (a path segment or query parameter): a scalar body
    /// member a guard clause rejects the request without (`const { id } = req.body; if (!id) throw`).
    /// Each is a field name and a value that satisfies its guard — a pinned literal, or a non-empty
    /// placeholder for a bare presence test. Sent as a JSON body alongside the payload so the request
    /// passes the guard and reaches the sink. Mined from the handler source only; empty when the
    /// handler requires no such body field, or the payload already rides the body.
    pub body_requires: Vec<(String, String)>,
    /// When the handler forwards the *whole* request body (`req.body`, not a single member) into the
    /// path that reaches the sink — directly as a call argument, a spread, or a bare assignment — and
    /// downstream code requires it to be a non-null object before the sink runs (`if (typeof body !==
    /// "object") throw`, a destructure, a property access), a request with no body is rejected or
    /// crashes before the sink. When set, and the payload rides a different request part on a
    /// body-carrying method, a minimal JSON object body is sent (merged with any [`Self::body_requires`]
    /// fields) so the body-shape precondition is satisfied and the tainted value reaches the sink. An
    /// empty object can never fabricate a finding: it only lets the request past a body-presence guard.
    /// Mined from the handler source only; `false` when the handler reads no whole-body value.
    pub body_object: bool,
    /// For a NoSQL finding sourced from a body field that is later overwritten by a same-named
    /// query field through an ordered spread merge (`{ ...req.body, ...req.query }`), the scalar
    /// value to keep in the body while the operator object rides in the query string. This models a
    /// validator bypass where middleware validates only `body("field")`, then the handler merges the
    /// unvalidated query after it. `None` when no such overwrite is present. The initial generic
    /// scalar is replaced with a validator-typed filler when route middleware declares one.
    pub body_query_override: Option<String>,
    /// For a SQL injection whose tainted value is interpolated in a table-identifier position, how to
    /// drive it (see [`SqlPlan`]). `None` for a non-SQL class or a value-position SQL injection, which
    /// is driven through [`Self::sql_value`] instead. Mined from the handler source only.
    pub sql: Option<SqlPlan>,
    /// For a SQL injection whose tainted value is interpolated inside a quoted string-literal position
    /// of the statement (`WHERE email = '${x}'`), how to break out of that quote (see [`SqlValue`]).
    /// Such an injection can never surface a computed sub-select (it is a value, not a table name), so
    /// it is proved by a boolean differential: a quote-breakout carrying an always-true boolean changes
    /// the handler's observable response while otherwise-identical always-false breakouts do not. `None`
    /// for a non-SQL class or an identifier-position injection. Mined from the handler source only.
    pub sql_value: Option<SqlValue>,
    /// For a NoSQL body injection whose tainted value reaches the sink as an *element* of the body
    /// field rather than the field itself: the handler iterates the field (`for (const d of
    /// device_names) ... findOne({ name: d })`, `field.forEach(d => ...)`) and queries each element, so
    /// a bare operator object as the field value is both rejected by an `.isArray()` validator and
    /// never queried. When set, the operator must ride inside a single-element array
    /// (`{"device_names":[{"$ne":...}]}`), so it passes array validation and becomes the per-element
    /// query filter. Mined from the handler source only; `false` for the common case where the field
    /// value reaches the sink directly.
    pub array_element: bool,
    /// For a path-traversal sink, the request fields the handler appends *after* the tainted input as
    /// further `path.join(...)` arguments (`path.join(base, type, id)` with `type` tainted -> `id`),
    /// in order. Unlike [`Self::read_suffix`] these segments are themselves attacker-controlled (other
    /// members of the same request part), so the exploit climbs with the tainted field and supplies the
    /// terminal filename through these fields: the tainted value is a directory prefix, not the leaf.
    /// Mined from the handler source only; empty for the common case where the tainted value ends the
    /// path or only fixed literals follow it.
    pub appended_fields: Vec<String>,
    /// For a path-traversal *removal* sink whose argument is not the tainted value itself but a child
    /// enumerated from the tainted directory (`for (const f of fs.readdirSync(dir)) unlink(dir/f)`),
    /// the filename substring an entry must contain for the handler to remove it — the
    /// `.indexOf('.png') > -1` / `.endsWith('.png')` filter on the loop variable, or an empty string
    /// when the handler removes every child unfiltered. When set, the delete oracle plants the climbed
    /// path as a *directory* holding a matching child (the target, which disappears) rather than as a
    /// file the value names directly, so a sink that removes directory entries is exercised honestly.
    /// `None` for the common removal whose tainted value directly names the removed entry. Mined from
    /// the handler source only.
    pub removed_child_marker: Option<String>,
    /// For a prototype-pollution finding whose sink is a nested object write `obj[k1][k2] = v` with
    /// both keys attacker-controlled, how to drive it: the request input that chooses the *outer* key
    /// (driven with `__proto__`, so `obj["__proto__"]` resolves to `Object.prototype`) and the one
    /// that chooses the *inner* key (the polluted property name). `None` for a class other than
    /// prototype-pollution, or a nested write whose two keys verify v1 cannot both map to request
    /// inputs. Mined from the sink argument and handler source only.
    pub proto_pollution: Option<ProtoPollution>,
    /// Full request paths of *sibling* routes that register the same handler (`router.put('/a', h)`
    /// and `router.put('/b', h)` both reach `h`), other than [`Self::path`]. A single controller
    /// method is often mounted on several paths that differ only in which branch of the handler runs;
    /// a write-overwrite oracle whose observable effect depends on that branch tries each sibling so
    /// the one whose branch performs the write is exercised. Filled from the route-registration source
    /// only; empty when the handler is registered on a single path. Nothing here is target-specific.
    pub alt_paths: Vec<String>,
    /// When the handler reaches its sink only on a branch guarded by a session the handler looks up
    /// from a request credential it reads itself (`const u = sessions.get(req.cookies.token); if (u)
    /// { fetch(url) }`), how to mint that session honestly against the app's own authentication: the
    /// credential name to carry the minted token under, and the login/registration endpoints the
    /// sandbox exercises to obtain it. Such an in-handler check is an exploit precondition, not input
    /// neutralization: an authenticated user still drives the sink, so the verifier satisfies it by
    /// registering and logging in through the app's own routes and replaying the request with the
    /// returned token. `None` when no in-handler session guard sits between the entry and the sink.
    /// Mined from the handler and route-registration source only; nothing here is target-specific.
    pub auth: Option<AuthBootstrap>,
    /// A body field read through the Web `Request.formData()` API must be sent as a real multipart
    /// request, not as the JSON body used for ordinary `req.body` inputs.  The descriptor records
    /// every field the handler reads and which of them it treats as a `File`/`Blob`, so the payload
    /// builder can put the tainted value in its text part and provide harmless file parts for the
    /// siblings needed to reach the sink. `None` for JSON, urlencoded and raw bodies.
    pub multipart: Option<MultipartForm>,
    /// For a command-injection sink, the shell quote character the tainted value is interpolated
    /// inside when the command string is built (`exec('open "' + folder + '"')` -> `"`,
    /// `exec("ping '" + host + "'")` -> `'`). The payload must first close that quote before its
    /// command separator is seen by the shell, otherwise the metacharacters stay inside a quoted
    /// argument and run nothing. `None` when the value sits unquoted (`exec('ls ' + dir)`) or the
    /// class is not command injection. Mined from the sink argument text only.
    pub cmd_quote: Option<char>,
    /// For a command-injection sink, whether the tainted value passes through `path.dirname()` on its
    /// way to the sink (`folder = path.dirname(path.join(base, relpath))`). `dirname` drops the final
    /// `/`-segment, so a payload placed as the last segment is discarded before the shell sees it; the
    /// payload must therefore carry a trailing `/<segment>` that `dirname` removes, leaving the
    /// injection in the surviving parent portion. `false` when the value reaches the sink without a
    /// `dirname` step, or the class is not command injection. Mined from the finding trace only.
    pub cmd_dir_segment: bool,
    /// For a NoSQL injection whose sink *filters* existing documents (`findOne`/`find`/`updateOne`/
    /// `deleteMany`/`countDocuments`/…), rather than inserting new ones. The operator only takes
    /// effect against a pre-existing record, so the differential needs a seeded document the sink
    /// query selects, and every non-injected sibling the query ANDs in must therefore carry the
    /// *same* value across the match-all and match-none probes (and match that seeded record) instead
    /// of a per-probe-unique one. `false` for an insert-style sink (registration), which keeps the
    /// per-probe-unique fillers that avoid unique-key collisions, and for every non-NoSQL class.
    /// Derived from the sink API only.
    pub nosql_lookup: bool,
    /// Whether the handler inserts a request-derived document before reaching the lookup sink. Such
    /// probes need distinct identity siblings even though the sink itself filters existing records,
    /// otherwise the first request trips a unique index for both differential controls.
    pub nosql_inserts_before_sink: bool,
    /// Whether the NoSQL sink can mutate existing documents. Database-state differentials are
    /// useful only for update/delete sinks; running them against a read-only `findOne` burns request
    /// budget and can trip application rate limiters before the response differential runs.
    pub nosql_mutates: bool,
    /// When the handler base64-decodes its tainted input into a *raw* string that reaches the sink
    /// directly (`const decoded = Buffer.from(c, 'base64').toString(); eval(decoded)`), rather than
    /// `JSON.parse`-ing it into an envelope object (see [`Self::envelope`]). The payload must then be
    /// base64-encoded before it enters the request, so the handler's decode reconstructs the exact
    /// payload the sink evaluates. `Some(true)` for a base64url decode, `Some(false)` for standard
    /// base64. `None` for the common case where the input reaches the sink without a base64 decode.
    /// Mutually exclusive with [`Self::envelope`]; mined from the handler source only.
    pub decode_base64: Option<bool>,
    /// For an SSRF whose handler gates the outbound URL on a *substring* allowlist
    /// (`if (!url.includes("site.com")) return 403`, `url.startsWith("https://site.com")`), the
    /// host-like substrings the URL must contain to pass that gate. A substring/prefix check never
    /// constrains the request's real host, so the marker URL is re-shaped to carry each token in a
    /// position that keeps the marker as the effective host (the URL userinfo, path, query or fragment)
    /// — reaching the sink the allowlist was meant to close. Only must-contain (negated) checks are
    /// mined; a non-negated `url.includes("169.254.169.254")` is a blocklist and is left out. Mined
    /// from the handler source only; empty when the handler gates the URL on no such substring.
    pub allow_tokens: Vec<String>,
    /// The literal delimiter a handler requires immediately around the tainted value before it
    /// reaches the sink (see [`TextWrap`]). `None` for the common case where the value reaches the
    /// sink unwrapped. Mutually exclusive with [`Self::envelope`]/[`Self::doc_envelope`] (which pack
    /// the payload into a JSON object instead of wrapping it as plain text).
    pub text_wrap: Option<TextWrap>,
    /// For a second-order finding (`finding.source.kind == "stored"`): the request that must run
    /// first to save the payload, so a later request to [`Self::path`] loads it back into the sink.
    /// `None` for the ordinary case where the payload rides the same request that reaches the sink.
    pub stored_write: Option<StoredWrite>,
    /// For a coarse `req.query`-sourced SSRF whose handler is a query-selector dispatcher
    /// (`const q = req.query; switch (q.action) { case 'x': fetchHelper(q.url) }`,
    /// `if (q.action === 'x') { ... }`): the branches that forward a query member onward, each with the
    /// selector field, the branch's selector value, and the candidate URL-bearing query members read in
    /// that branch. The marker URL is tried in each member with the branch's selector carried, under
    /// each gate path, so the request takes the branch that reaches the request sink. Empty for a
    /// handler with no such query dispatch. Mined from the handler source only; nothing here is
    /// target-specific.
    pub query_dispatch: Vec<QueryDispatch>,
    /// For an MCP tool call, what the source says about where the server is mounted and which
    /// arguments it reads; `None` for every other transport.
    pub mcp: Option<McpHints>,
    /// When the tainted body field is an *array of objects* the handler iterates, and the sink reads a
    /// property of each element (`for (const t of tasks) fetch(t.downloadUrl)` /
    /// `const t = tasks[i]; fetch(t.downloadUrl)`): the payload for the body field must be a
    /// one-element array holding an object that carries the marker under the sink-reached property and
    /// the element-level guard properties the sink branch requires (`t.action === 'video'`). `None` for
    /// the common case where the body field reaches the sink as a scalar. Mined from the handler source
    /// and the finding trace only; nothing here is target-specific.
    pub element_body: Option<ElementBody>,
}

/// How to shape an array-of-objects body field whose element property reaches the sink (see
/// [`Probe::element_body`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementBody {
    /// The element property the marker rides under: the sink reads `element.<sink_key>`.
    pub sink_key: String,
    /// Other element properties a guard requires for the sink branch (`action` == `"video"`), each a
    /// name and the value that enters the branch.
    pub required: Vec<(String, String)>,
}

impl Probe {
    /// A probe for a call that is not an HTTP request (a socket.io event, an MCP tool call): the
    /// event or tool name as its `path`, the payload in the body entry, nothing else mined yet.
    /// The caller fills in what the class needs.
    pub(crate) fn call(method: Method, path: String, entry: Entry, class: VulnClass) -> Self {
        Self {
            method,
            path,
            entry,
            class,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
            url_query_params: Vec::new(),
            read_suffix: None,
            read_filename_suffix: None,
            envelope: None,
            doc_envelope: None,
            lists_dir: false,
            removes: false,
            removes_dir: false,
            creates: false,
            archive_upload: false,
            appended_param: None,
            path_fillers: Vec::new(),
            body_requires: Vec::new(),
            body_object: false,
            body_query_override: None,
            sql: None,
            sql_value: None,
            array_element: false,
            appended_fields: Vec::new(),
            removed_child_marker: None,
            proto_pollution: None,
            alt_paths: Vec::new(),
            auth: None,
            multipart: None,
            cmd_quote: None,
            cmd_dir_segment: false,
            nosql_lookup: false,
            nosql_inserts_before_sink: false,
            nosql_mutates: false,
            decode_base64: None,
            allow_tokens: Vec::new(),
            stored_write: None,
            query_dispatch: Vec::new(),
            text_wrap: None,
            mcp: None,
            element_body: None,
        }
    }

    /// Fills in, for a call that is not an HTTP request, what its class needs beyond the payload's
    /// place: the fixed segment a traversal appends, whether a path sink removes or creates, the
    /// quoting of a shell argument, the host tokens an SSRF allowlist checks. All mined from the
    /// handler source, as for an HTTP route.
    fn enrich_remote_call(&mut self, finding: &Finding, source: Option<&str>) {
        let mut tainted = tainted_identifiers(finding, &self.entry);
        if let Some(src) = source {
            propagate_path_derived_taint(src, &mut tainted);
        }
        let path_class = finding.class == VulnClass::PathTraversal;
        self.read_suffix = path_class
            .then(|| source.and_then(|src| appended_path_suffix(src, &tainted)))
            .flatten();
        self.read_filename_suffix = path_class
            .then(|| source.and_then(|src| appended_filename_suffix(src, &tainted)))
            .flatten();
        self.removes = path_class && sink_removes(&finding.sink.api);
        self.removes_dir = path_class && sink_removes_dir(&finding.sink.api);
        self.creates = path_class && sink_creates(&finding.sink.api);
        self.removed_child_marker = self
            .removes
            .then(|| {
                source.and_then(|src| {
                    removed_dir_child_marker(
                        handler_source(src, finding.source.line),
                        &finding.sink.arg,
                        &tainted,
                    )
                })
            })
            .flatten();
        if finding.class == VulnClass::CommandInjection {
            self.cmd_quote = command_quote_context(finding);
            self.cmd_dir_segment = finding
                .trace
                .iter()
                .any(|step| step.note.contains("path.dirname"));
        }
        if finding.class == VulnClass::Ssrf {
            self.allow_tokens = source
                .map(|src| {
                    ssrf_allowlist_host_tokens(handler_source(src, finding.source.line), &tainted)
                })
                .unwrap_or_default();
        }
    }
}

/// One branch of a query-selector dispatcher that forwards a query member toward the request sink
/// (see [`Probe::query_dispatch`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDispatch {
    /// The query field the handler dispatches on (`q.action` -> `action`).
    pub selector: String,
    /// The literal value of this branch (`case 'addon_check'` -> `addon_check`).
    pub value: String,
    /// Candidate URL-bearing query members read inside this branch (`q.url` -> `url`), other than the
    /// selector field.
    pub params: Vec<String>,
}

/// Where and how a second-order finding's payload is saved before the read that reaches the sink
/// (see [`Probe::stored_write`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredWrite {
    pub method: Method,
    pub path: String,
    /// Where in that request the payload goes (the request field the write handler reads it from).
    pub entry: Entry,
}

/// How to obtain a genuine authenticated session for a sink gated behind an in-handler credential
/// check, by exercising the app's own login (and, when needed, registration) routes. The token the
/// login returns is carried back to the gated request under [`Self::cookie`]. Nothing here names a
/// specific app: the endpoints are mined by generic authentication vocabulary from the route source,
/// and the credentials are freshly generated for the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthBootstrap {
    /// The cookie name the handler reads the session token from (`req.cookies.<name>`): the minted
    /// token is sent back under this cookie so the handler's `sessions.get(req.cookies.<name>)`
    /// resolves to the registered session and its guarded branch runs.
    pub cookie: String,
    /// Candidate account-creation endpoints (a user/account collection the run registers a throwaway
    /// account on before logging in), most-specific first. Empty when the app seeds accounts and no
    /// registration route is needed.
    pub register_paths: Vec<String>,
    /// Candidate login endpoints that exchange the generated credentials for a session token, tried
    /// in order until one returns a token.
    pub login_paths: Vec<String>,
    /// Whether the gate is a framework request-middleware (a Next.js `middleware`/matcher, a global
    /// request proxy) that denies the route unless authenticated, rather than an in-handler credential
    /// read. In that case the session is minted through the app's own login route using the
    /// deployment's first-run credential — the public default an operator is expected to change —
    /// and captured from the login's `Set-Cookie` (or a bearer token in the body). This reproduces a
    /// realistic default-deployment exploit; a session the app itself never issues cannot be forged,
    /// so it only reaches a sink an open/default-credentialed deployment already exposes.
    pub default_credentials: bool,
    /// Whether the gate is route-level login middleware the engine recognized (the finding's auth is
    /// `user`), rather than an in-handler session read. The session is a throwaway account the run
    /// registers and logs in through the app's own routes, carried back as a bearer token (under
    /// [`Self::cookie`] and the `Authorization` header) or as the session cookie the login set. When
    /// no session can be minted the finding is skipped with that reason instead of being sent
    /// anonymously. Login and registration endpoints start empty and are mined from the project's
    /// route sources before the run; only role-free login is attempted (an admin gate stays skipped).
    pub route_gate: bool,
}

impl AuthBootstrap {
    /// A pending route-level bootstrap for a login-gated finding: the endpoints are mined later from
    /// the project's route sources (see [`project_auth_endpoints`]).
    pub fn route_gate() -> Self {
        Self {
            cookie: String::new(),
            register_paths: Vec::new(),
            login_paths: Vec::new(),
            default_credentials: false,
            route_gate: true,
        }
    }
}

// Authentication endpoint discovery lives in `plan/auth.rs`.
/// The shape of a body parsed with `Request.formData()`. `fields` contains every named `.get(...)`
/// access other than the tainted field; members of `file_fields` are emitted with a filename and
/// content type so calls such as `file.arrayBuffer()` receive a real `File` rather than a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartForm {
    pub fields: Vec<String>,
    pub file_fields: Vec<String>,
}

/// How to drive a nested-write prototype-pollution sink (`obj[outer][inner] = v`). Both keys are
/// attacker-controlled request inputs; the verifier drives the outer with `__proto__` (so the write
/// lands on `Object.prototype`) and the inner with a fresh marker property name, then reads that same
/// property back off a *different*, freshly created object through the handler itself to prove the
/// whole-process prototype was polluted. Nothing here is tied to a specific app: it names only the two
/// request inputs the sink's two keys come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoPollution {
    /// The request input that selects the outer object (`obj[outer]`): driven with `__proto__`.
    pub outer: Entry,
    /// The request input that selects the inner property (`obj[outer][inner]`): driven with a fresh
    /// marker key, then read back off a fresh outer to confirm `Object.prototype` was polluted.
    pub inner: Entry,
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

/// One column a SQL statement interpolating the tainted identifier references. `filter` is set when
/// the column is matched by equality (`col = ?`, `LOWER(col) = LOWER(?)`): a request the probe drives
/// reaches the sink only if that comparison is satisfied, so such a column must carry the sentinel the
/// probe also binds. A column that only appears in a projection (`SELECT col`) carries the canary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlColumn {
    pub name: String,
    pub filter: bool,
}

/// How to drive a SQL injection whose tainted value is interpolated in an *identifier* position of a
/// SQL statement (a table name after `FROM`/`JOIN`/`INTO`/`UPDATE`). Such an injection can never be a
/// bound parameter: the probe replaces the table with a sub-select that both supplies every column the
/// surrounding statements reference and returns a value the database must *compute* (a string
/// concatenation whose result is absent from the request text), so that computed value surfacing in
/// the response proves the statement's meaning changed. Mined from the handler source only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlPlan {
    /// Every column any statement interpolating the tainted identifier references, each marked a
    /// filter (equality-matched) or value (projected) column.
    pub columns: Vec<SqlColumn>,
    /// The request body fields the handler reads (`const { id } = req.body`), filled with the sentinel
    /// so the bound parameters the sink supplies match the sub-select's filter columns.
    pub body_fields: Vec<String>,
    /// When the tainted value reaches the sink as a *named* member of the request body (`const { type }
    /// = req.body` interpolated as `UPDATE ${type}`), the name of that member. The injection must enter
    /// through this exact field; a whole-body source (`req.body`) otherwise leaves the entry as
    /// `Body(None)`, which would place the sub-select in a generic default field the sink never uses as
    /// the table identifier. `None` when the tainted identifier is not a plain body member.
    pub identifier_field: Option<String>,
    /// When the tainted identifier is interpolated into the table position of a *row-destroying*
    /// statement whose effect the handler never reflects (`DELETE FROM "<id>" WHERE ...`), how to
    /// drive a quote-breakout that deletes every row of the named table. Such a sink cannot be
    /// proved by a reflected sub-select (a `DELETE` target is a table name, never a sub-query, and a
    /// quoted identifier is not evaluated) nor by a response differential (the delete echoes
    /// nothing); it is proved instead by a planted row disappearing. `None` for a non-destructive
    /// identifier injection (a `SELECT ... FROM <id>` the reflected/blind oracles already drive).
    pub delete: Option<SqlDelete>,
}

/// How to drive a SQL injection whose tainted value is interpolated inside a quoted string-literal
/// position of a SQL statement (`WHERE email = '${x}'`). Unlike an identifier substitution this is a
/// value that a safe sink would pass as a bound parameter, so it is proved by a boolean differential:
/// the probe closes the enclosing quote and appends an always-true boolean followed by a line comment
/// that neutralizes the statement's remaining text. The only thing that varies between the exploit and
/// its controls is the truth value of that injected boolean, so a response difference can come only
/// from the database evaluating injected SQL. Mined from the handler source only; nothing here is tied
/// to a specific app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlValue {
    /// The quote character enclosing the interpolated value (`'` or `"`); the breakout emits it to
    /// close the literal before the injected boolean.
    pub quote: char,
    /// How many grouping parentheses are still open at the interpolation point (`WHERE ((name LIKE
    /// '%${x}%' ...)` opens two). The breakout closes exactly this many before the injected boolean so
    /// the statement stays balanced once a line comment removes the original tail; otherwise the
    /// unmatched `)` of the original predicate make every leg a syntax error and nothing is observable.
    pub open_parens: usize,
}

/// How to drive a quote-breakout against a destructive table-identifier injection
/// (`DELETE FROM "<id>" WHERE ... = ?`): the opening identifier quote (`"`, `` ` ``, `[`) if the
/// position is quoted, so the breakout can close it, and the number of bound `?` placeholders the
/// statement carries, so the injected tail supplies the same count and the handler's `.run(...)`
/// binding succeeds. Mined from the handler source only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlDelete {
    /// The identifier's opening quote character when the position is quoted (`"`, `` ` ``, `[`), or
    /// `None` for a bare identifier. The breakout emits the matching closing quote (`]` for `[`).
    pub quote: Option<char>,
    /// The number of `?` placeholders in the statement, equal to the count of values the handler
    /// binds; the injected tail reproduces exactly this many so the binding is accepted.
    pub placeholders: usize,
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
    /// A server-reflected XSS: the attacker value arrives over HTTP and the server writes it into the
    /// HTML response it renders (`c.html`, a template string), so it runs in the victim's browser.
    /// Driven by running the app and loading its response in a headless browser (see
    /// [`ReflectedXss`]).
    ReflectedXss(ReflectedXss),
    /// A socket.io event payload reaches the sink (`socket.on('run', (data, cb) => exec(data.cmd))`).
    /// The app is started the same way an HTTP finding's is (the same `http.Server`/`express` app
    /// usually also mounts socket.io); only the request is different: an Engine.IO client connects
    /// and emits the named event, acked when the handler takes one. Uses the same [`Probe`] shape and
    /// payload machinery as [`Self::Http`] (the event payload is a JSON object exactly like a body),
    /// restricted for now to the classes that need neither `siblings`/`envelope` enrichment (done in
    /// `verify/mod.rs`, keyed to `Plan::Http` only) nor a second request input: path traversal,
    /// command/code injection and SSRF.
    Socket(Box<Probe>),
    /// An MCP tool call (`server.tool('run', schema, handler)`): the app is started like an HTTP
    /// finding's, then the server is found at its endpoint, its tools are read back through
    /// `tools/list`, and the payload rides in the tool's arguments (see [`super::mcp`]). Restricted
    /// for now to the classes whose oracles need no per-request enrichment: path traversal,
    /// command/code injection and SSRF.
    Mcp(Box<Probe>),
}

/// A server-reflected (reflected, not DOM-based) XSS the sandbox can drive: run the app, request the
/// route with a context-breakout canary placed in a URL input, and load the rendered response in a
/// headless browser to confirm the injected script executed. Unlike [`BrowserProbe`] (a DOM XSS whose
/// script already ships in a static page), the dangerous HTML here is produced by the server from the
/// request, so the live application must serve it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectedXss {
    pub method: Method,
    /// The route path, `{param}` slots kept; always leads with `/`.
    pub path: String,
    /// Where the payload rides into the request. Only URL-placed inputs (a query parameter, a path
    /// segment, or the raw URL) are driven, since the browser reaches the sink by navigating to a URL.
    pub entry: Entry,
}

/// A finding whose attacker input is the page's own URL and whose sink runs in the browser: the
/// file holding the vulnerable script (to find the page that loads it), where in the URL the
/// value enters, and whether the sink writes HTML or navigates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserProbe {
    pub file: String,
    pub vector: UrlVector,
    pub sink: BrowserSink,
    /// The exact query/hash parameter names the script reads off the page URL
    /// (`new URLSearchParams(location.search).get('state')` -> `state`). Mined from the script
    /// source only; the browser phase tries these before the generic candidate names, so a page
    /// that reads an uncommon parameter is still driven. Empty when the source is unavailable or
    /// reads no named parameter (the value is the whole search/hash).
    pub params: Vec<String>,
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
    /// A cross-origin window sends the attacker value with `postMessage`.
    Message,
}

/// What the browser sink does with the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserSink {
    /// Written as HTML (`innerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()`).
    Html,
    /// Used to navigate (`location =`, `location.href =`, `window.open`, `location.assign`).
    Navigation,
    /// Loaded as code from a URL: a dynamic `import()` of a computed module specifier (or a worker's
    /// `importScripts`). The attacker value is itself a URL — the origin the module is fetched from —
    /// so the payload is a module URL pointing at the marker, not an HTML/JS snippet. The page
    /// fetching the module from the marker origin is the reproduction.
    Import,
    /// Evaluated as JavaScript (`eval`/`Function`) after arriving in a message event.
    Eval,
}

/// The sandbox's decision for a finding: drive it, or skip it with a reason. The source-free
/// convenience form of [`plan_with_source`], used where the handler source is not at hand.
#[cfg(test)]
pub fn plan(finding: &Finding) -> Result<Plan, Skip> {
    plan_with_source(finding, None)
}

/// Like [`plan`], but given the handler's own source (the finding's file) it can resolve a
/// request input the finding only names coarsely — e.g. a `req.headers` source whose specific
/// header the handler reads in a URL/host position. `None` source falls back to finding fields
/// alone.
pub fn plan_with_source(finding: &Finding, source: Option<&str>) -> Result<Plan, Skip> {
    // A reflected XSS whose tainted value arrives over HTTP and is written into the server's HTML
    // response runs in the victim's browser, not on the server, so neither the server-side HTTP
    // oracle nor the static-page browser phase drives it: the live app must render the response and a
    // headless browser must load it. Route it to the dedicated reflected-XSS plan.
    if finding.class == VulnClass::Xss && finding.source.kind == "http" {
        return reflected_xss_probe(finding, source).map(Plan::ReflectedXss);
    }
    // A socket.io event payload: a different entry point (an event, not a route) and transport
    // (Engine.IO, not a plain HTTP request), driven over the same app session an HTTP finding uses.
    // Routed before the HTTP path, which would otherwise reject its `"SOCKET <event>"` entry as an
    // unroutable path.
    if finding.source.kind == "socket" {
        return Probe::socket_probe(finding, source).map(|probe| Plan::Socket(Box::new(probe)));
    }
    // An MCP tool's arguments: driven through the server's own protocol over the app's HTTP port.
    if finding.source.kind == "mcp" {
        return Probe::mcp_probe(finding, source).map(|probe| Plan::Mcp(Box::new(probe)));
    }
    // `postMessage` is a browser transport rather than an HTTP request. Drive it from a distinct
    // attacker origin so an origin check (or its absence) is part of the proof.
    if finding.source.kind == "postmessage" {
        return postmessage_probe(finding).map(Plan::Browser);
    }
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
    browser_probe(finding, source).map(Plan::Browser)
}

fn postmessage_probe(finding: &Finding) -> Result<BrowserProbe, Skip> {
    if finding.class != VulnClass::CodeInjection {
        return Err(Skip(format!(
            "{} from postMessage is not driven by verify v1",
            finding.class.name()
        )));
    }
    let last = finding
        .sink
        .api
        .trim()
        .rsplit('.')
        .next()
        .unwrap_or(&finding.sink.api)
        .trim();
    if !matches!(last, "eval" | "Function") {
        return Err(Skip(format!(
            "the postMessage sink `{}` is not a string-evaluating browser sink",
            finding.sink.api
        )));
    }
    Ok(BrowserProbe {
        file: finding
            .sink
            .file
            .clone()
            .unwrap_or_else(|| finding.file.clone()),
        vector: UrlVector::Message,
        sink: BrowserSink::Eval,
        params: Vec::new(),
    })
}

/// A server-reflected XSS the sandbox can drive, or why not. The payload must enter through a
/// URL-placed input (a query parameter, a path segment, or the raw URL) reachable without
/// authentication, so a headless browser can deliver it by navigating to a single URL. A body-only
/// reflection, an authenticated route, or an entry that is not a routable HTTP path is skipped with
/// a reason, never guessed at.
fn reflected_xss_probe(finding: &Finding, source: Option<&str>) -> Result<ReflectedXss, Skip> {
    if finding.auth != Auth::NoneDetected {
        return Err(Skip(format!(
            "reaching it needs {} authentication, which verify v1 does not perform",
            finding.auth.name()
        )));
    }
    let Some(entry_point) = finding.entry.as_deref() else {
        return Err(Skip(
            "no entry point maps to this sink; nothing to send".to_owned(),
        ));
    };
    let (method, path) = parse_entry(entry_point)
        .ok_or_else(|| Skip(format!("entry `{entry_point}` is not a routable HTTP path")))?;
    let entry = best_entry(finding, &path, source).ok_or_else(|| {
        Skip(format!(
            "cannot tell which request input reaches the sink (source `{}`, argument `{}`)",
            finding.source.expr, finding.sink.arg
        ))
    })?;
    if !matches!(entry, Entry::Query(_) | Entry::PathParam(_) | Entry::Url) {
        return Err(Skip(
            "verify v1 drives a reflected XSS only through a URL-placed input (query, path segment \
             or raw URL), which a browser can deliver by navigation"
                .to_owned(),
        ));
    }
    Ok(ReflectedXss {
        method,
        path,
        entry,
    })
}

/// A DOM-source XSS, client-side redirect, or code-loaded-from-a-URL finding the browser phase can
/// drive, or why not.
fn browser_probe(finding: &Finding, source: Option<&str>) -> Result<BrowserProbe, Skip> {
    let sink = match finding.class {
        VulnClass::Xss => browser_sink(&finding.sink.api).ok_or_else(|| {
            Skip(format!(
                "the sink `{}` is not an HTML or navigation sink the browser phase recognizes",
                finding.sink.api
            ))
        })?,
        // A DOM-source code injection whose sink loads code from a URL (a dynamic `import()` of a
        // computed specifier) runs attacker-chosen code in the victim's browser when the attacker
        // controls where the module is fetched from. The browser phase drives it by pointing the
        // URL at the marker origin and confirming the page fetches the module from there.
        VulnClass::CodeInjection => code_url_sink(&finding.sink.api).ok_or_else(|| {
            Skip(format!(
                "the sink `{}` does not load code from a URL the browser phase can repoint",
                finding.sink.api
            ))
        })?,
        other => {
            return Err(Skip(format!(
                "{} from a DOM source is not driven by verify v1 (DOM XSS, client-side redirect \
                 and code loaded from a URL only)",
                other.name()
            )));
        }
    };
    let vector = url_vector(&finding.source.expr).ok_or_else(|| {
        Skip(format!(
            "the DOM source `{}` is not a URL input the browser phase can place a payload in",
            finding.source.expr
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
        params: source.map(mined_url_params).unwrap_or_default(),
    })
}

/// Every parameter name worth trying first for this handler: the ones it reads via
/// `URLSearchParams`/`.searchParams` ([`url_param_reads`]), then the ones a hand-rolled
/// `key=value&key=value` split recognizes ([`manual_split_param_reads`]) -- two different,
/// common ways a script names which query/hash key it wants.
fn mined_url_params(source: &str) -> Vec<String> {
    let mut out = url_param_reads(source);
    for name in manual_split_param_reads(source) {
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// The query/hash parameter names a DOM script reads off the page URL through a `URLSearchParams`
/// or a `URL`'s `searchParams` (`new URLSearchParams(location.search).get('state')`,
/// `url.searchParams.get('q')`, `params.getAll('id')`). Returns the string-literal argument of each
/// such `.get(...)`/`.getAll(...)`, first-seen and deduplicated. Gated on the source actually
/// building search parameters, so an unrelated `map.get('x')` is not mistaken for a URL parameter.
/// Mined from the script source only, so nothing here is tied to a specific app.
fn url_param_reads(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for op in [".get(", ".getAll("] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(op) {
            let at = from + rel;
            let open = at + op.len();
            from = open;
            if !url_params_receiver(source, at) {
                continue;
            }
            let Some(inner) = balanced_arg(&source[open..]) else {
                continue;
            };
            let Some(first) = split_top_level_commas(inner).into_iter().next() else {
                continue;
            };
            if let Some(name) = string_literal_arg(first.trim())
                && !name.is_empty()
                && !out.contains(&name)
            {
                out.push(name);
            }
        }
    }
    out
}

/// Whether the expression immediately before `.get`/`.getAll` is known to hold URL search
/// parameters: a direct constructor chain, a `.searchParams` member, or a local initialized from
/// either. This keeps an unrelated `map.get('x')` out even when the same file also reads the URL.
fn url_params_receiver(source: &str, dot: usize) -> bool {
    let before = source.get(..dot).unwrap_or("").trim_end();
    if before.ends_with(".searchParams") {
        return true;
    }
    if before.ends_with(')') {
        let mut depth = 0usize;
        for (at, ch) in before.char_indices().rev() {
            match ch {
                ')' => depth += 1,
                '(' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return before[..at].trim_end().ends_with("URLSearchParams");
                    }
                }
                _ => {}
            }
        }
        return false;
    }
    let start = before
        .as_bytes()
        .iter()
        .rposition(|byte| !is_ident(*byte))
        .map_or(0, |at| at + 1);
    let name = &before[start..];
    !name.is_empty() && assigned_url_params(source, name)
}

fn assigned_url_params(source: &str, name: &str) -> bool {
    let bytes = source.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = source[from..].find(name) {
        let at = from + rel;
        from = at + name.len();
        if (at > 0 && bytes.get(at - 1).is_some_and(|byte| is_ident(*byte)))
            || bytes.get(from).is_some_and(|byte| is_ident(*byte))
        {
            continue;
        }
        let Some(value) = source[from..].trim_start().strip_prefix('=') else {
            continue;
        };
        if value.starts_with('=') {
            continue;
        }
        let value = value.trim_start();
        let value = value.split([';', '\n']).next().unwrap_or(value).trim_end();
        if value.starts_with("new URLSearchParams(") || value.ends_with(".searchParams") {
            return true;
        }
    }
    false
}

/// Parameter names a script reads off a hand-rolled `key=value&key=value` split of the URL
/// (`hashStr.split('&').forEach(pair => { const [k, v] = pair.split('='); if (k && v)
/// params[k] = v; })`), a common idiom predating `URLSearchParams` that [`url_param_reads`]
/// does not recognize. Finds each `.split('&')` ... `.split('=')` pair, the object the loop
/// assigns `[k]` into right after, and every property later read off that same object elsewhere
/// in the file (`params.naics`, `params['naics']`) -- the keys the parser actually recognizes.
/// Mined from the script source only, so nothing here is tied to a specific app.
fn manual_split_param_reads(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut from = 0usize;
    while let Some((at, len)) = find_first_of(source, from, &[".split('&')", ".split(\"&\")"]) {
        from = at + len;
        let window_end = (from + 400).min(source.len());
        let Some((eq_at, eq_len)) = find_first_of(
            source,
            from,
            &[
                ".split('=')",
                ".split(\"=\")",
                ".indexOf('=')",
                ".indexOf(\"=\")",
            ],
        )
        .filter(|(eq_at, _)| *eq_at < window_end) else {
            continue;
        };
        let after_eq = eq_at + eq_len;
        let assign_end = (after_eq + 200).min(source.len());
        if let Some(obj) = assigned_bracket_target(&source[after_eq..assign_end]) {
            for name in object_property_reads(source, &obj) {
                if !out.contains(&name) {
                    out.push(name);
                }
                if out.len() >= 8 {
                    return out;
                }
            }
        }
        // A hand-written parser may dispatch each pair directly instead of first filling an object:
        // `const [k, v] = pair.split('='); if (k === 'name') selected = v`. The comparison literal
        // is the query parameter name. Keep the search close to the `=` split so unrelated string
        // comparisons elsewhere in a monolithic server do not become candidates.
        let compare_end = (after_eq + 1600).min(source.len());
        for name in compared_parameter_literals(&source[after_eq..compare_end]) {
            if !out.contains(&name) {
                out.push(name);
            }
            if out.len() >= 8 {
                return out;
            }
        }
    }
    out
}

/// Identifier-like string literals used in an equality comparison. Within a hand-written query
/// parser these are the recognized key names (`k === 'name'`), while numeric values such as the
/// accompanying `secrets === '1'` are intentionally excluded.
fn compared_parameter_literals(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let Some(&quote @ (b'\'' | b'"')) = bytes.get(i) else {
            i += 1;
            continue;
        };
        let mut end = i + 1;
        while let Some(&current) = bytes.get(end) {
            if current == quote {
                break;
            }
            end += if current == b'\\' { 2 } else { 1 };
        }
        if end >= bytes.len() {
            break;
        }
        let value = &source[i + 1..end];
        let before = source[..i].trim_end();
        let after = source[end + 1..].trim_start();
        let compared = before.ends_with("===")
            || before.ends_with("==")
            || after.starts_with("===")
            || (after.starts_with("==") && !after.starts_with("=>"));
        let identifier_like = value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b'$'))
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'$'));
        if compared && identifier_like && value.len() <= 64 && !out.iter().any(|v| v == value) {
            out.push(value.to_owned());
        }
        i = end + 1;
    }
    out
}

/// The earliest occurrence, at or after `from`, of any of `needles` in `source`, with its byte
/// length. `None` if none occur.
fn find_first_of(source: &str, from: usize, needles: &[&str]) -> Option<(usize, usize)> {
    needles
        .iter()
        .filter_map(|needle| {
            source[from..]
                .find(needle)
                .map(|rel| (from + rel, needle.len()))
        })
        .min_by_key(|(at, _)| *at)
}

/// The identifier of the first `IDENT[...] = ` (a single `=`, not `==`/`===`) found in `text`,
/// treated as the object a manual query/hash parser's loop body writes decoded keys into.
fn assigned_bracket_target(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < text.len() {
        if bytes.get(i) != Some(&b'[') {
            i += 1;
            continue;
        }
        let start = bytes
            .get(..i)
            .unwrap_or_default()
            .iter()
            .rposition(|byte| !is_ident(*byte))
            .map_or(0, |at| at + 1);
        let name = &text[start..i];
        if name.is_empty() {
            i += 1;
            continue;
        }
        let Some(close_rel) = text[i..].find(']') else {
            i += 1;
            continue;
        };
        let after = &text[i + close_rel + 1..];
        let after = after.trim_start();
        if let Some(rest) = after.strip_prefix('=')
            && !rest.starts_with('=')
        {
            return Some(name.to_owned());
        }
        i += close_rel + 1;
    }
    None
}

/// Every property name read off `obj.prop` or `obj['prop']`/`obj["prop"]` in `source`, first-seen
/// order, deduplicated. `obj` must be a plain local the manual parser assigned into, so this is
/// not confused with a method call (`obj.hasOwnProperty(...)`) by excluding names immediately
/// followed by `(`.
fn object_property_reads(source: &str, obj: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = source.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = source[from..].find(obj) {
        let at = from + rel;
        from = at + obj.len();
        if (at > 0 && bytes.get(at - 1).is_some_and(|byte| is_ident(*byte)))
            || bytes.get(from).is_some_and(|byte| is_ident(*byte))
        {
            continue;
        }
        let rest = &source[from..];
        if let Some(stripped) = rest.strip_prefix('.') {
            let end = stripped
                .as_bytes()
                .iter()
                .position(|byte| !is_ident(*byte))
                .unwrap_or(stripped.len());
            let name = &stripped[..end];
            if !name.is_empty()
                && !stripped[end..].starts_with('(')
                && !out.iter().any(|n| n == name)
            {
                out.push(name.to_owned());
            }
        } else if let Some(stripped) = rest.strip_prefix('[')
            && let Some(name) = string_literal_arg(stripped.split(']').next().unwrap_or("").trim())
            && !name.is_empty()
            && !out.iter().any(|n| n == &name)
        {
            out.push(name);
        }
        if out.len() >= 8 {
            break;
        }
    }
    out
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

/// Classifies a browser code sink that loads executable code from a URL the browser phase can
/// repoint at the marker: a dynamic `import()` of a computed specifier, or a worker's
/// `importScripts`. Returns the `Import` sink so the payload is delivered as a module URL rather
/// than an HTML/JS snippet. Nothing here is tied to a particular app — it keys off the sink API the
/// static engine already names.
fn code_url_sink(api: &str) -> Option<BrowserSink> {
    let last = api.trim().rsplit('.').next().unwrap_or(api).trim();
    matches!(last, "import" | "importScripts").then_some(BrowserSink::Import)
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
    /// A middleware mounted at a path prefix (`app.use('/clients', handler)`). It runs for every
    /// method on any request whose path begins with the mount prefix, so it is driven like `Any`
    /// but the payload is placed *under* the mount path rather than at the root.
    Use,
    /// An HTTP upgrade (WebSocket) entry: `server.on('upgrade', ...)`. Driven as a GET carrying
    /// the upgrade handshake headers, so it reaches the upgrade handler rather than the request one.
    Upgrade,
    /// A socket.io event (`socket.on('run', ...)`): the probe's `path` is the event name and its
    /// payload is the JSON the event is emitted with. Not an HTTP request at all, but it is carried
    /// by the same [`Probe`]/`Attempt` machinery, so every oracle that works over HTTP works over it.
    Socket,
    /// An MCP tool call: the probe's `path` is the tool name (empty when it has to be discovered
    /// from the server's `tools/list`) and its payload is the call's `arguments` object.
    Mcp,
}

impl Method {
    fn parse(token: &str) -> Option<Self> {
        Some(match token {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            // `app.all(...)` / `router.all(...)` register one handler for every HTTP method, which
            // is exactly what `Any` models; the engine uppercases the `all` verb to `ALL`.
            "ANY" | "ALL" => Self::Any,
            "USE" => Self::Use,
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
            Self::Any | Self::Use if matches!(entry, Entry::Body(_)) => "POST",
            Self::Any | Self::Use | Self::Upgrade => "GET",
            Self::Socket => "SOCKET",
            Self::Mcp => "MCP",
        }
    }

    /// Whether this entry is reached by an HTTP upgrade request.
    pub fn is_upgrade(self) -> bool {
        matches!(self, Self::Upgrade)
    }

    /// Whether the call is not an HTTP request (a socket.io event, an MCP tool call): sent through
    /// its own driver, with no HTTP verb, cookies or forwarding headers to vary between passes.
    pub fn is_remote_call(self) -> bool {
        matches!(self, Self::Socket | Self::Mcp)
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
    #[cfg(test)]
    pub fn from_finding(finding: &Finding) -> Result<Self, Skip> {
        Self::from_finding_with_source(finding, None)
    }

    /// Like [`Self::from_finding`], but may consult the handler's `source` to resolve a coarsely
    /// named request input (see [`plan_with_source`]).
    pub fn from_finding_with_source(finding: &Finding, source: Option<&str>) -> Result<Self, Skip> {
        let skip = |reason: &str| Err(Skip(reason.to_owned()));
        // A nested-write prototype-pollution sink (`obj[k1][k2] = v`) is driven by its own dedicated
        // read-back oracle, not the single-entry request machinery below (it needs two request inputs,
        // not one). Resolve both keys to request inputs here, or skip with a reason.
        if finding.class == VulnClass::PrototypePollution {
            return Self::proto_pollution_probe(finding, source);
        }
        if !matches!(
            finding.class,
            VulnClass::PathTraversal
                | VulnClass::CommandInjection
                | VulnClass::CodeInjection
                | VulnClass::Ssrf
                | VulnClass::NosqlInjection
                | VulnClass::SqlInjection
        ) {
            return skip(&format!(
                "{} is not driven by verify v1 (HTTP path-traversal, command/code-injection, SSRF, NoSQL and SQL injection only)",
                finding.class.name()
            ));
        }
        if finding.source.kind == "archive" {
            if finding.class != VulnClass::PathTraversal || !sink_creates(&finding.sink.api) {
                return skip(
                    "archive verification currently supports filesystem-create sinks only",
                );
            }
            if finding.auth != Auth::NoneDetected {
                return skip(&format!(
                    "reaching it needs {} authentication, which verify v1 does not perform",
                    finding.auth.name()
                ));
            }
            let Some(entry_point) = finding.entry.as_deref() else {
                return skip("no entry point maps to this archive sink; nothing to upload");
            };
            let (method, path) = parse_entry(entry_point).ok_or_else(|| {
                Skip(format!("entry `{entry_point}` is not a routable HTTP path"))
            })?;
            return Ok(Self {
                method,
                path,
                entry: Entry::Body(None),
                class: finding.class,
                siblings: Vec::new(),
                gate_paths: Vec::new(),
                url_query_params: Vec::new(),
                read_suffix: None,
                read_filename_suffix: None,
                envelope: None,
                doc_envelope: None,
                lists_dir: false,
                removes: false,
                removes_dir: false,
                creates: true,
                archive_upload: true,
                appended_param: None,
                path_fillers: Vec::new(),
                body_requires: Vec::new(),
                body_object: false,
                body_query_override: None,
                sql: None,
                sql_value: None,
                array_element: false,
                appended_fields: Vec::new(),
                removed_child_marker: None,
                proto_pollution: None,
                alt_paths: Vec::new(),
                auth: None,
                multipart: None,
                cmd_quote: None,
                cmd_dir_segment: false,
                nosql_lookup: false,
                nosql_inserts_before_sink: false,
                nosql_mutates: false,
                decode_base64: None,
                allow_tokens: Vec::new(),
                stored_write: None,
                query_dispatch: Vec::new(),
                text_wrap: None,
                mcp: None,
                element_body: None,
            });
        }
        if finding.source.kind == "stored" {
            return Self::stored_probe(finding);
        }
        if finding.source.kind != "http" {
            return skip(&format!(
                "source is {}, not an HTTP request",
                finding.source.kind
            ));
        }
        // A login-gated route is driven as a throwaway account the run registers through the app's
        // own routes (see `AuthBootstrap::route_gate`). A role gate is not: a self-registered account
        // is not an admin, and reaching it would mean forging privileges.
        if finding.auth == Auth::Admin {
            return skip(&format!(
                "reaching it needs {} authentication, which verify v1 does not perform",
                finding.auth.name()
            ));
        }
        let login_gated = finding.auth == Auth::User;
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
            .then(|| {
                source.and_then(|src| {
                    // Scope the suffix search to the sink's own handler block: a sibling route in the
                    // same module may build `path.join(<same-named dir>, 'other.json')`, and scanning
                    // the whole enclosing function would borrow that unrelated leaf as this sink's
                    // suffix — fatal for a removal sink, whose argument is the tainted path itself.
                    let handler = handler_source(src, finding.source.line);
                    appended_path_suffix(handler, &tainted)
                        .or_else(|| appended_listing_suffix(handler, &finding.sink.arg, &tainted))
                })
            })
            .flatten();
        let read_filename_suffix = (finding.class == VulnClass::PathTraversal)
            .then(|| {
                source.and_then(|src| {
                    appended_filename_suffix(handler_source(src, finding.source.line), &tainted)
                })
            })
            .flatten();
        // Request fields the handler appends after the tainted segment in the same `path.join(...)`
        // (`path.join(base, type, id)`): other members of the same request part, so themselves
        // attacker-controlled. The traversal then climbs with the tainted field and names the terminal
        // leaf through these fields.
        let appended_fields = if finding.class == VulnClass::PathTraversal {
            source
                .map(|src| appended_path_fields(src, &tainted, &entry))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let envelope = source.and_then(|src| json_envelope(src, &tainted, &finding.sink.arg));
        // A handler that base64-decodes its tainted input into a raw string the sink consumes directly
        // (`eval(Buffer.from(c, 'base64').toString())`) — not JSON-parsed into an envelope object —
        // needs the payload base64-encoded so the decode reconstructs it verbatim at the sink. Mutually
        // exclusive with the JSON-envelope case, which already handles the decode as part of packing.
        let decode_base64 = if envelope.is_some() {
            None
        } else {
            source.and_then(|src| base64_decoded_into_sink(src, &tainted, &finding.sink.arg))
        };
        // A copy sink whose flagged (source) argument is read out of a tainted directory the handler
        // enumerates (`for (f of readdirSync(dir)) copyFileSync(dir + '/' + f, base + '/' + f)`) is a
        // directory-enumerating read, not a create: the attacker-named path is the file being read and
        // copied out, while the destination stays confined to the base. Prove it by the read
        // differential (the handler reaches the planted out-of-base directory), not by a new entry
        // appearing in a planted directory — nothing is created there.
        let copy_reads_dir = finding.class == VulnClass::PathTraversal
            && source
                .map(|src| {
                    copy_reads_enumerated_dir(
                        &finding.sink.api,
                        &finding.sink.arg,
                        handler_source(src, finding.source.line),
                        &tainted,
                    )
                })
                .unwrap_or(false);
        let lists_dir = (finding.class == VulnClass::PathTraversal
            && sink_lists_directory(&finding.sink.api))
            || copy_reads_dir;
        let removes = finding.class == VulnClass::PathTraversal && sink_removes(&finding.sink.api);
        // A removal whose argument is a child enumerated from the tainted directory
        // (`fs.unlinkSync(dir + '/' + f)` with `f` from `fs.readdirSync(dir)`): the tainted value is
        // the directory, not the removed leaf, so the oracle must plant a matching child inside it.
        let removed_child_marker = (removes)
            .then(|| {
                source.and_then(|src| {
                    removed_dir_child_marker(
                        handler_source(src, finding.source.line),
                        &finding.sink.arg,
                        &tainted,
                    )
                })
            })
            .flatten();
        let removes_dir =
            finding.class == VulnClass::PathTraversal && sink_removes_dir(&finding.sink.api);
        let creates = finding.class == VulnClass::PathTraversal
            && sink_creates(&finding.sink.api)
            && !copy_reads_dir;
        // A listing whose read path is `<tainted-dir>/<sibling>` reaches a real directory only when
        // the sibling route parameter carries a value the handler accepts; recover it from the route
        // and the handler's own guard so the probe can drive it.
        let appended_param = (lists_dir && matches!(entry, Entry::PathParam(_)))
            .then(|| {
                source.and_then(|src| appended_enum_param(finding, &path, src, &entry, &tainted))
            })
            .flatten()
            .map(|(name, values)| AppendedParam { name, values });
        // A NoSQL body field the handler iterates and queries per element (`for (const d of
        // device_names) findOne({ name: d })`): the operator must ride inside a one-element array.
        let array_element = finding.class == VulnClass::NosqlInjection
            && match (&entry, source) {
                (Entry::Body(Some(field)), Some(src)) => {
                    body_field_reaches_sink_as_element(src, field, &finding.sink.arg)
                }
                _ => false,
            };
        let body_query_override = (finding.class == VulnClass::NosqlInjection)
            .then(|| match (&entry, source) {
                (Entry::Body(Some(field)), Some(src)) if query_overrides_body_field(src, field) => {
                    Some("jsspector".to_owned())
                }
                _ => None,
            })
            .flatten();
        // A command-injection value interpolated inside a shell quote must break out of that quote,
        // and a value passed through `path.dirname()` must carry a sacrificial trailing segment; both
        // are read off the finding itself so the payload lands as a live command separator.
        let (cmd_quote, cmd_dir_segment) = if finding.class == VulnClass::CommandInjection {
            (
                command_quote_context(finding),
                finding
                    .trace
                    .iter()
                    .any(|step| step.note.contains("path.dirname")),
            )
        } else {
            (None, false)
        };
        // A NoSQL sink that filters existing documents (a `find`/`update`/`delete`/`count` family
        // call), as opposed to one that inserts new ones: the operator can only act on a pre-existing
        // record, so the differential needs a seeded record the sink query selects and the siblings
        // the query ANDs in must stay constant across probes to keep matching it.
        let nosql_lookup =
            finding.class == VulnClass::NosqlInjection && sink_filters_documents(&finding.sink.api);
        let (nosql_inserts_before_sink, downstream_nosql_mutation) =
            if finding.class == VulnClass::NosqlInjection {
                source
                    .map(|source| {
                        nosql_handler_effects(
                            source,
                            finding.sink.line,
                            finding.entry_at.as_ref().map(|at| at.line),
                        )
                    })
                    .unwrap_or_default()
            } else {
                (false, false)
            };
        let nosql_mutates = finding.class == VulnClass::NosqlInjection
            && (sink_mutates_documents(&finding.sink.api) || downstream_nosql_mutation);
        // An SSRF whose handler checks the outbound URL against a substring/prefix allowlist
        // (`if (!url.includes("site.com")) return 403`) rejects a marker URL before the sink; mine the
        // host tokens that gate it so the payload builder can carry one in a host-preserving position.
        let allow_tokens = if finding.class == VulnClass::Ssrf {
            source
                .map(|src| {
                    ssrf_allowlist_host_tokens(handler_source(src, finding.source.line), &tainted)
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(Self {
            method,
            path,
            entry,
            class: finding.class,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
            url_query_params: Vec::new(),
            read_suffix,
            read_filename_suffix,
            envelope,
            doc_envelope: None,
            lists_dir,
            removes,
            removes_dir,
            creates,
            archive_upload: false,
            appended_param,
            path_fillers: Vec::new(),
            body_requires: Vec::new(),
            body_object: false,
            body_query_override,
            sql: None,
            sql_value: None,
            array_element,
            appended_fields,
            removed_child_marker,
            proto_pollution: None,
            alt_paths: Vec::new(),
            auth: login_gated.then(AuthBootstrap::route_gate),
            multipart: None,
            cmd_quote,
            cmd_dir_segment,
            nosql_lookup,
            nosql_inserts_before_sink,
            nosql_mutates,
            decode_base64,
            allow_tokens,
            stored_write: None,
            query_dispatch: Vec::new(),
            text_wrap: None,
            mcp: None,
            element_body: None,
        })
    }

    /// Build the probe for a finding whose source is a socket.io event payload (`source.kind ==
    /// "socket"`). Restricted to path traversal, command/code injection and SSRF: the classes that
    /// need neither the `siblings`/`envelope`/`multipart` enrichment `verify/mod.rs` only applies to
    /// `Plan::Http` (re-reading the handler's file from the scanned root) nor a second request input
    /// (NoSQL/SQL injection's own differentials, prototype pollution's nested write). A finding of
    /// another class, or whose payload field cannot be resolved, is skipped with a reason rather than
    /// driven with reduced fidelity.
    fn socket_probe(finding: &Finding, source: Option<&str>) -> Result<Self, Skip> {
        let skip = |reason: &str| Err(Skip(reason.to_owned()));
        if !remote_call_class(finding.class) {
            return skip(&format!(
                "{} over a socket.io event is not driven yet (path traversal, command/code \
                 injection and SSRF only)",
                finding.class.name()
            ));
        }
        if finding.auth != Auth::NoneDetected {
            return skip(&format!(
                "reaching it needs {} authentication, which the socket.io driver does not \
                 perform yet",
                finding.auth.name()
            ));
        }
        let Some(entry_point) = finding.entry.as_deref() else {
            return skip("no entry point maps to this sink; nothing to send");
        };
        let event = parse_socket_entry(entry_point).ok_or_else(|| {
            Skip(format!(
                "entry `{entry_point}` is not a socket.io event registration"
            ))
        })?;
        let entry = socket_field(finding, source).ok_or_else(|| {
            Skip(format!(
                "cannot tell which field of the socket payload reaches the sink (source `{}`, \
                 argument `{}`)",
                finding.source.expr, finding.sink.arg
            ))
        })?;
        let mut probe = Self::call(Method::Socket, event, entry, finding.class);
        probe.enrich_remote_call(finding, source);
        Ok(probe)
    }

    /// Build the probe for a finding whose source is an MCP tool's arguments (`source.kind ==
    /// "mcp"`). Unlike a socket event, the tool and the argument carrying the payload are often not
    /// recoverable from the source — a handler named by a protocol schema (`CallToolRequestSchema`),
    /// or the whole arguments object handed to helpers — so what is not known is left open here
    /// (`path` empty, `Entry::Body(None)`) and settled at run time against the schemas the server
    /// itself lists (see [`super::mcp::candidates`]).
    fn mcp_probe(finding: &Finding, source: Option<&str>) -> Result<Self, Skip> {
        let skip = |reason: &str| Err(Skip(reason.to_owned()));
        if !remote_call_class(finding.class) {
            return skip(&format!(
                "{} through an MCP tool is not driven yet (path traversal, command/code injection \
                 and SSRF only)",
                finding.class.name()
            ));
        }
        if finding.auth != Auth::NoneDetected {
            return skip(&format!(
                "reaching it needs {} authentication, which the MCP driver does not perform yet",
                finding.auth.name()
            ));
        }
        let tool = finding.entry.as_deref().and_then(parse_mcp_entry);
        let entry = Entry::Body(mcp_field(finding, source));
        let mut probe = Self::call(Method::Mcp, tool.unwrap_or_default(), entry, finding.class);
        probe.enrich_remote_call(finding, source);
        probe.mcp = Some(McpHints {
            endpoints: source.map(mcp_endpoint_paths).unwrap_or_default(),
            fields: mcp_field_hints(finding),
        });
        Ok(probe)
    }

    /// Build the probe for a nested-write prototype-pollution finding (`obj[k1][k2] = v`). Both keys
    /// must resolve to anonymous HTTP request inputs; the outer is driven with `__proto__` and the
    /// inner with a marker property, then read back off a fresh outer (see the sandbox's read-back
    /// oracle). Skips with a reason when the source is not an anonymous HTTP request, the entry is not
    /// routable, or the two keys cannot both be mapped to request inputs.
    fn proto_pollution_probe(finding: &Finding, source: Option<&str>) -> Result<Self, Skip> {
        let skip = |reason: &str| Err(Skip(reason.to_owned()));
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
        let (outer, inner) = proto_pollution_keys(finding, &path, source).ok_or_else(|| {
            Skip(format!(
                "cannot map both keys of the nested write `{}` to request inputs",
                finding.sink.arg
            ))
        })?;
        Ok(Self {
            method,
            path,
            entry: outer.clone(),
            class: finding.class,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
            url_query_params: Vec::new(),
            read_suffix: None,
            read_filename_suffix: None,
            envelope: None,
            doc_envelope: None,
            lists_dir: false,
            removes: false,
            removes_dir: false,
            creates: false,
            archive_upload: false,
            appended_param: None,
            path_fillers: Vec::new(),
            body_requires: Vec::new(),
            body_object: false,
            body_query_override: None,
            sql: None,
            sql_value: None,
            array_element: false,
            appended_fields: Vec::new(),
            removed_child_marker: None,
            proto_pollution: Some(ProtoPollution { outer, inner }),
            alt_paths: Vec::new(),
            auth: None,
            multipart: None,
            cmd_quote: None,
            cmd_dir_segment: false,
            nosql_lookup: false,
            nosql_inserts_before_sink: false,
            nosql_mutates: false,
            decode_base64: None,
            allow_tokens: Vec::new(),
            stored_write: None,
            query_dispatch: Vec::new(),
            text_wrap: None,
            mcp: None,
            element_body: None,
        })
    }

    /// Plans a second-order finding (`finding.source.kind == "stored"`): the payload must be saved
    /// through the request named by [`Finding::stored_by`] before the request named by
    /// [`Finding::entry`] loads it back into the sink. Driven only for the classes the generic
    /// single-request matrix already covers; SQL/NoSQL run their own oracles that do not yet carry
    /// a second request, and a nested-write prototype-pollution sink has its own two-key planner.
    fn stored_probe(finding: &Finding) -> Result<Self, Skip> {
        let skip = |reason: &str| Err(Skip(reason.to_owned()));
        if !matches!(
            finding.class,
            VulnClass::PathTraversal
                | VulnClass::CommandInjection
                | VulnClass::CodeInjection
                | VulnClass::Ssrf
        ) {
            return skip(&format!(
                "a second-order {} (one request stores the value, another reads it back) is not driven by verify v1 yet",
                finding.class.name()
            ));
        }
        if finding.auth == Auth::Admin {
            return skip(&format!(
                "reaching it needs {} authentication, which verify v1 does not perform",
                finding.auth.name()
            ));
        }
        let Some(stored_by) = &finding.stored_by else {
            return skip("no entry point saves the value this sink reads back from the store");
        };
        let Some(write_entry) = stored_by.entry.as_deref() else {
            return skip("no entry point saves the value this sink reads back from the store");
        };
        let Some(entry_point) = finding.entry.as_deref() else {
            return skip("no entry point maps to this sink; nothing to send");
        };
        let (method, path) = parse_entry(entry_point)
            .ok_or_else(|| Skip(format!("entry `{entry_point}` is not a routable HTTP path")))?;
        let (write_method, write_path) = parse_entry(write_entry)
            .ok_or_else(|| Skip(format!("entry `{write_entry}` is not a routable HTTP path")))?;
        let Some(write_input) = entry_from_request_expr(&stored_by.expr) else {
            return skip(&format!(
                "cannot tell where `{}` enters the request that saves it",
                stored_by.expr
            ));
        };
        Ok(Self {
            method,
            path,
            entry: Entry::Body(None),
            class: finding.class,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
            url_query_params: Vec::new(),
            read_suffix: None,
            read_filename_suffix: None,
            envelope: None,
            doc_envelope: None,
            lists_dir: false,
            removes: false,
            removes_dir: false,
            creates: false,
            archive_upload: false,
            appended_param: None,
            path_fillers: Vec::new(),
            body_requires: Vec::new(),
            body_object: false,
            body_query_override: None,
            sql: None,
            sql_value: None,
            array_element: false,
            appended_fields: Vec::new(),
            removed_child_marker: None,
            proto_pollution: None,
            alt_paths: Vec::new(),
            auth: (finding.auth == Auth::User).then(AuthBootstrap::route_gate),
            multipart: None,
            cmd_quote: None,
            cmd_dir_segment: false,
            nosql_lookup: false,
            nosql_inserts_before_sink: false,
            nosql_mutates: false,
            decode_base64: None,
            allow_tokens: Vec::new(),
            stored_write: Some(StoredWrite {
                method: write_method,
                path: write_path,
                entry: write_input,
            }),
            query_dispatch: Vec::new(),
            text_wrap: None,
            mcp: None,
            element_body: None,
        })
    }
}

/// Where in a request a plain request-access expression (`req.body.username`, `req.query.x`,
/// `req.params.id`) places its value — the generic shapes [`StoredWrite::entry`] needs. `None` for
/// any other shape (a header, the whole body, a computed access): the write side is skipped rather
/// than guessed.
fn entry_from_request_expr(expr: &str) -> Option<Entry> {
    let field = |rest: &str| -> String {
        rest.trim_end_matches(']')
            .trim_matches(|c: char| c == '\'' || c == '"')
            .to_owned()
    };
    if let Some(at) = expr.find(".body.") {
        return Some(Entry::Body(Some(field(&expr[at + ".body.".len()..]))));
    }
    if let Some(at) = expr.find(".query.") {
        return Some(Entry::Query(field(&expr[at + ".query.".len()..])));
    }
    if let Some(at) = expr.find(".params.") {
        return Some(Entry::PathParam(field(&expr[at + ".params.".len()..])));
    }
    None
}

/// A literal-delimited wrap a handler requires around the tainted value itself before it reaches
/// the sink (see [`TextWrap`]): a regex the handler tests or matches one of the tainted identifiers
/// against (`username?.match(/#{(.*)}/) !== null`, `/^\[(.*)\]$/.test(id)`), whose pattern has a
/// capturing group. The literal text around that group's first and last occurrence is the scaffold a
/// value must carry for the handler's own guard to accept it and unwrap it into the sink. Tried for
/// every identifier the finding's trace names (the sink's own argument and everything it was
/// assigned from), so the convention is found whichever alias the handler tests. Mined from the
/// handler source only.
pub fn text_wrap(source: &str, tainted: &[String]) -> Option<TextWrap> {
    for name in tainted {
        for call in [".match(", ".test("] {
            for optional in ["?", ""] {
                let marker = format!("{name}{optional}{call}");
                let Some(at) = source.find(&marker) else {
                    continue;
                };
                let rest = &source[at + marker.len()..];
                let Some(pattern) = regex_pattern(rest) else {
                    continue;
                };
                if let Some((prefix, suffix)) = regex_scaffold(&pattern)
                    && (!prefix.is_empty() || !suffix.is_empty())
                {
                    return Some(TextWrap { prefix, suffix });
                }
            }
        }
    }
    None
}

/// The two request inputs the two keys of a nested write `obj[outer][inner] = v` come from, for a
/// prototype-pollution sink. Reads the two bracketed index expressions out of the sink argument and
/// resolves each to a request input — directly (`req.params.bid`, `req.query.k`), or by following a
/// local binding in the handler source (`const key = req.params.id; ... obj[bid][key] =`). `None` when
/// both cannot be mapped — the oracle then cannot drive it without guessing.
fn proto_pollution_keys(
    finding: &Finding,
    path: &str,
    source: Option<&str>,
) -> Option<(Entry, Entry)> {
    let (outer_expr, inner_expr) = nested_index_exprs(&finding.sink.arg)?;
    let outer = resolve_request_entry(&outer_expr, path, source);
    let inner = resolve_request_entry(&inner_expr, path, source);
    match (outer, inner) {
        (Some(outer), Some(inner)) if outer != inner => Some((outer, inner)),
        _ => None,
    }
}

/// The two outermost `[...]` index expressions of a nested member write `base[a][b]`, as source text
/// (`req.params.bid`, `key`). `None` when the argument does not have at least two bracketed indices.
/// Quoted strings inside an index are returned verbatim.
fn nested_index_exprs(arg: &str) -> Option<(String, String)> {
    let mut indices: Vec<String> = Vec::new();
    let bytes = arg.as_bytes();
    let mut i = 0;
    while i < bytes.len() && indices.len() < 2 {
        if bytes.get(i) == Some(&b'[') {
            let start = i + 1;
            let mut depth = 1;
            let mut j = start;
            while let Some(&b) = bytes.get(j) {
                match b {
                    b'[' => depth += 1,
                    b']' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    break;
                }
                j += 1;
            }
            if depth != 0 {
                return None;
            }
            indices.push(arg.get(start..j)?.trim().to_owned());
            i = j + 1;
        } else {
            i += 1;
        }
    }
    match indices.len() {
        2 => Some((indices.remove(0), indices.remove(0))),
        _ => None,
    }
}

/// Resolve an index expression to the anonymous HTTP request input it reads, directly or through one
/// hop of a local binding in the handler source. Direct forms: `req.params.NAME`, `req.query.NAME`,
/// `req.body.NAME`, `req.headers.NAME` / `req.headers['NAME']` (any request receiver name). A bare
/// identifier is looked up as `const/let/var NAME = <rhs>` in the source and resolved from its
/// right-hand side. `None` when it is neither.
fn resolve_request_entry(expr: &str, path: &str, source: Option<&str>) -> Option<Entry> {
    let expr = expr.trim();
    if let Some(entry) = request_member_entry(expr, path) {
        return Some(entry);
    }
    // A plain identifier: resolve one binding hop (`const key = req.params.id`).
    if expr
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        && !expr.is_empty()
        && expr.chars().next().is_some_and(|c| !c.is_ascii_digit())
    {
        let rhs = source.and_then(|src| local_binding_rhs(src, expr))?;
        return request_member_entry(rhs.trim(), path);
    }
    None
}

/// A request-member access (`<recv>.params.NAME`, `<recv>.query.NAME`, `<recv>.body.NAME`,
/// `<recv>.headers.NAME` / `['NAME']`) resolved to the entry that places a value there. The receiver
/// name is not fixed to `req`. A `params` member is only accepted when the route declares a slot for
/// it.
fn request_member_entry(expr: &str, path: &str) -> Option<Entry> {
    let expr = expr.trim();
    for part in ["params", "query", "body", "headers"] {
        let dot = format!(".{part}.");
        if let Some(pos) = expr.find(&dot) {
            let rest = &expr[pos + dot.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            if name.is_empty() {
                continue;
            }
            return request_entry(part, &name, path);
        }
        // Bracketed member: `<recv>.headers['x']`, `<recv>.params["id"]`.
        let bracket = format!(".{part}[");
        if let Some(pos) = expr.find(&bracket) {
            let rest = &expr[pos + bracket.len()..];
            let name = rest
                .trim_start()
                .trim_start_matches(['\'', '"'])
                .split(['\'', '"'])
                .next()
                .unwrap_or("");
            if !name.is_empty() {
                return request_entry(part, name, path);
            }
        }
    }
    None
}

/// Map a request part and member name to an [`Entry`]. A `params` member must correspond to a route
/// slot; otherwise it cannot be placed in the URL.
fn request_entry(part: &str, name: &str, path: &str) -> Option<Entry> {
    match part {
        "params" => path_param_slot(path, name).map(Entry::PathParam),
        "query" => Some(Entry::Query(name.to_owned())),
        "body" => Some(Entry::Body(Some(name.to_owned()))),
        "headers" => Some(Entry::Header(name.to_owned())),
        _ => None,
    }
}

/// The right-hand side of the first `const`/`let`/`var NAME = <rhs>;` binding of `name` in `source`.
/// Used to follow one hop from an index local to the request member it reads (`const key =
/// req.params.id`). `None` when there is no such simple binding.
fn local_binding_rhs(source: &str, name: &str) -> Option<String> {
    for kw in ["const", "let", "var"] {
        let needle = format!("{kw} {name}");
        let mut from = 0;
        while let Some(rel) = source[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            // Must be a whole-word match on both sides.
            let before_ok = source[..at]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '$');
            let after = &source[at + needle.len()..];
            let after_ok = after
                .chars()
                .next()
                .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '$');
            if !before_ok || !after_ok {
                continue;
            }
            let after = after.trim_start();
            let Some(rest) = after.strip_prefix('=') else {
                continue;
            };
            let rest = rest.trim_start();
            if rest.starts_with('=') || rest.starts_with('>') {
                continue; // `==`/`=>`, not an assignment.
            }
            let end = rest.find([';', '\n']).unwrap_or(rest.len());
            return Some(rest[..end].trim().to_owned());
        }
    }
    None
}

/// Whether `field` is destructured from an object literal in which a query object is spread after a
/// body object from the same request (`const { field } = { ...req.body, ...req.query }`). JavaScript
/// applies later spreads last, so the unvalidated query value replaces a body value that middleware
/// may already have validated. Conservative by construction: both spreads must be in the same object
/// literal, in that order, and `field` must appear in the immediately assigned destructuring pattern.
pub fn query_overrides_body_field(source: &str, field: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = source[from..].find(".body") {
        let body_dot = from + rel;
        from = body_dot + ".body".len();
        let root_start = source[..body_dot]
            .char_indices()
            .rev()
            .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '$')
            .last()
            .map(|(at, _)| at)
            .unwrap_or(body_dot);
        if root_start == body_dot || !source[..root_start].trim_end().ends_with("...") {
            continue;
        }
        let root = &source[root_start..body_dot];
        let Some(open) = source[..root_start].rfind('{') else {
            continue;
        };
        let Some(close) = delimiter_close(source, open, b'{', b'}') else {
            continue;
        };
        if close <= body_dot {
            continue;
        }
        let query = format!("...{root}.query");
        let Some(query_rel) = source[body_dot + ".body".len()..close].find(&query) else {
            continue;
        };
        let query_at = body_dot + ".body".len() + query_rel;
        if query_at <= body_dot {
            continue;
        }
        let before_object = source[..open].trim_end();
        let Some(eq) = before_object.rfind('=') else {
            continue;
        };
        if !before_object[eq + 1..].trim().is_empty() {
            continue;
        }
        let Some(lhs_open) = before_object[..eq].rfind('{') else {
            continue;
        };
        let Some(lhs_close) = delimiter_close(source, lhs_open, b'{', b'}') else {
            continue;
        };
        if lhs_close > eq {
            continue;
        }
        if source[lhs_open + 1..lhs_close]
            .split([',', ':', '=', ' ', '\n', '\r', '\t'])
            .any(|token| token == field)
        {
            return true;
        }
    }
    false
}

/// Whether the body `field` reaches the sink as an *element* of an iteration, so a NoSQL operator
/// must ride inside an array (`{"field":[{"$ne":...}]}`) rather than as the field value itself. True
/// when the handler iterates the field (`for (const e of field)`, `field.forEach(e => ...)`,
/// `field.map(e => ...)`) binding an element identifier that the sink's own argument then reads. Mined
/// from the handler source and the finding's sink argument only; nothing here is tied to a specific
/// application.
pub fn body_field_reaches_sink_as_element(source: &str, field: &str, sink_arg: &str) -> bool {
    if field.is_empty() {
        return false;
    }
    let sink_idents = identifier_tokens(sink_arg);
    iteration_element_idents(source, field)
        .iter()
        .any(|elem| sink_idents.iter().any(|t| t == elem))
}

/// Element identifiers the handler binds when iterating `field`: a `for (const e of field)` loop
/// variable, or the first callback parameter of a `field.forEach(e => ...)` / `.map` / `.filter` /
/// similar array-iteration call. Mined from the handler source only.
fn iteration_element_idents(source: &str, field: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = source.as_bytes();
    // `for (const e of field)` / `for (let e of field)` / `for (e of field)`.
    let mut from = 0;
    while let Some(rel) = source[from..].find("for") {
        let at = from + rel;
        from = at + 3;
        if at
            .checked_sub(1)
            .and_then(|previous| bytes.get(previous))
            .is_some_and(|byte| is_ident(*byte))
        {
            continue;
        }
        let after = source[at + 3..].trim_start();
        if !after.starts_with('(') {
            continue;
        }
        let popen = at + 3 + (source[at + 3..].len() - after.len());
        let Some(pclose) = matching_close_paren(source, popen) else {
            continue;
        };
        let header = &source[popen + 1..pclose];
        if let Some((lhs, rhs)) = header.split_once(" of ")
            && rhs.trim() == field
            && let Some(id) = last_ident(lhs)
        {
            out.push(id);
        }
    }
    // `field.forEach(e => ...)` and the other element-wise array iterators.
    for method in [
        "forEach", "map", "filter", "flatMap", "find", "some", "every", "reduce",
    ] {
        let needle = format!("{field}.{method}(");
        let mut from = 0;
        while let Some(rel) = source[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            if at
                .checked_sub(1)
                .and_then(|previous| bytes.get(previous))
                .is_some_and(|byte| is_ident(*byte) || *byte == b'.')
            {
                continue;
            }
            if let Some(id) = callback_first_param(&source[at + needle.len()..]) {
                out.push(id);
            }
        }
    }
    out
}

/// Element identifiers the handler binds from a C-style indexed read of `field`
/// (`const task = tasks[index]`, `let t = tasks[i]`): the local on the left of a `const`/`let`/`var`
/// binding whose right-hand side begins by indexing `field`. Mined from the handler source only.
fn indexed_element_idents(source: &str, field: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = format!("{field}[");
    for kw in ["const ", "let ", "var "] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(kw) {
            let at = from + rel;
            from = at + kw.len();
            if at
                .checked_sub(1)
                .and_then(|previous| source.as_bytes().get(previous))
                .is_some_and(|byte| is_ident(*byte))
            {
                continue;
            }
            let after = &source[at + kw.len()..];
            let name: String = after
                .bytes()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect();
            if name.is_empty() {
                continue;
            }
            let rhs = after[name.len()..].trim_start();
            let Some(rhs) = rhs.strip_prefix('=') else {
                continue;
            };
            if rhs.trim_start().starts_with(&needle) {
                out.push(name);
            }
        }
    }
    out
}

/// Every element identifier the handler binds while iterating body array `field`: a `for..of` /
/// `.forEach`-style element and a C-style `const e = field[i]` element. Mined from the handler
/// source only.
fn element_idents(source: &str, field: &str) -> Vec<String> {
    let mut out = iteration_element_idents(source, field);
    out.extend(indexed_element_idents(source, field));
    out.sort();
    out.dedup();
    out
}

/// For an HTTP body finding whose tainted field is an array of objects the handler iterates, the
/// shape of the element object the sink reads (see [`Probe::element_body`]). `None` unless the field
/// binds element identifiers and one of them forwards a property to the sink. Mined from the handler
/// source and the finding trace only; nothing here is target-specific.
pub fn element_body(source: &str, field: &str, finding: &Finding) -> Option<ElementBody> {
    if field.is_empty() {
        return None;
    }
    let elements = element_idents(source, field);
    if elements.is_empty() {
        return None;
    }
    let anchors = guard_anchor_lines(finding);
    let sink_key = forwarded_element_key(source, &elements, &anchors)?;
    let required = element_guard_fields(source, &elements, &anchors, &sink_key);
    Some(ElementBody { sink_key, required })
}

/// The element property forwarded to the sink: the `<elem>.<prop>` member read on the deepest flow
/// anchor line, where `<elem>` is one of the iterated element identifiers. Mined from the handler
/// source and finding trace only.
fn forwarded_element_key(source: &str, elements: &[String], anchors: &[u32]) -> Option<String> {
    let mut lines: Vec<u32> = anchors.to_vec();
    lines.sort_unstable();
    for &line in lines.iter().rev() {
        let Some(off) = line_offset(source, line as usize) else {
            continue;
        };
        let end = source[off..]
            .find('\n')
            .map(|rel| off + rel)
            .unwrap_or(source.len());
        if let Some(prop) = element_member_read(&source[off..end], elements) {
            return Some(prop);
        }
    }
    None
}

/// The first `<elem>.<prop>` (or `<elem>?.<prop>`) member read in `text` for one of `elements`, with
/// `<elem>` matched as a whole identifier.
fn element_member_read(text: &str, elements: &[String]) -> Option<String> {
    for elem in elements {
        let mut from = 0;
        while let Some(rel) = text[from..].find(elem.as_str()) {
            let at = from + rel;
            from = at + elem.len();
            if at
                .checked_sub(1)
                .and_then(|previous| text.as_bytes().get(previous))
                .is_some_and(|byte| is_ident(*byte))
            {
                continue;
            }
            let rest = &text[at + elem.len()..];
            let Some(rest) = rest.strip_prefix("?.").or_else(|| rest.strip_prefix('.')) else {
                continue;
            };
            let prop: String = rest
                .bytes()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect();
            if !prop.is_empty() {
                return Some(prop);
            }
        }
    }
    None
}

/// Element-level equality guards (`t.action === 'video'`, `t?.action == 'x'`) that enclose the
/// sink-forwarding flow position, besides the sink property itself: the element object must carry each
/// so the handler takes the branch the sink sits on. Mined from the handler source only.
fn element_guard_fields(
    source: &str,
    elements: &[String],
    anchors: &[u32],
    sink_key: &str,
) -> Vec<(String, String)> {
    let Some(&anchor) = anchors.iter().max() else {
        return Vec::new();
    };
    let Some(sink_off) = line_offset(source, anchor as usize) else {
        return Vec::new();
    };
    let bytes = source.as_bytes();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut i = 0usize;
    while i + 2 <= source.len() {
        let at_boundary = i == 0 || bytes.get(i - 1).is_some_and(|byte| !is_ident(*byte));
        if at_boundary
            && bytes.get(i) == Some(&b'i')
            && bytes.get(i + 1) == Some(&b'f')
            && bytes.get(i + 2).is_none_or(|b| !is_ident(*b))
            && let Some(popen) = source[i + 2..].find('(').map(|rel| i + 2 + rel)
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
                    for (prop, lit) in element_equalities(cond, elements) {
                        if prop != sink_key && out.iter().all(|(key, _)| *key != prop) {
                            out.push((prop, lit));
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

/// Element-property equality guards (`<elem>.<prop> === "lit"`) in a condition, for one of `elements`.
fn element_equalities(cond: &str, elements: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for part in cond.split("&&") {
        let part = part.trim();
        for op in ["===", "=="] {
            let mut from = 0;
            while let Some(rel) = part[from..].find(op) {
                let at = from + rel;
                from = at + op.len();
                let before = part.as_bytes().get(at.wrapping_sub(1)).copied();
                let after = part.as_bytes().get(at + op.len()).copied();
                if before.is_some_and(|b| matches!(b, b'!' | b'<' | b'>' | b'='))
                    || after.is_some_and(|b| b == b'=')
                {
                    continue;
                }
                let lhs = part[..at].trim();
                let rhs = part[at + op.len()..].trim();
                let member = element_member_read(lhs, elements)
                    .map(|prop| (prop, rhs))
                    .or_else(|| element_member_read(rhs, elements).map(|prop| (prop, lhs)));
                if let Some((prop, lit_side)) = member
                    && let Some(lit) = string_literal_value(lit_side)
                {
                    out.push((prop, lit));
                }
            }
        }
    }
    out
}

/// The first callback parameter named just after a `(` that an iterator call opened: `e => ...`,
/// `(e) => ...`, `(e, i) => ...`, `function (e) { ... }`, `async (e) => ...`. `None` when the first
/// parameter is a destructuring pattern or absent.
fn callback_first_param(rest: &str) -> Option<String> {
    let t = rest.trim_start();
    let t = t.strip_prefix("async").map(str::trim_start).unwrap_or(t);
    let inner = if let Some(f) = t.strip_prefix("function") {
        let f = f.trim_start();
        let open = f.find('(')?;
        &f[open + 1..]
    } else if let Some(p) = t.strip_prefix('(') {
        p
    } else {
        return leading_ident(t);
    };
    let end = inner.find([',', ')'])?;
    leading_ident(inner[..end].trim())
}

/// The last run of identifier characters in `s` (`const deviceName` -> `deviceName`), or `None` when
/// `s` does not end in an identifier (a destructuring pattern `{ a, b }`).
fn last_ident(s: &str) -> Option<String> {
    let id: String = s
        .trim_end()
        .bytes()
        .rev()
        .take_while(|b| is_ident(*b))
        .map(|b| b as char)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (!id.is_empty()).then_some(id)
}

/// The leading identifier of `s` (`e => ...` -> `e`), or `None` when `s` does not begin with one.
fn leading_ident(s: &str) -> Option<String> {
    let id: String = s
        .bytes()
        .take_while(|b| is_ident(*b))
        .map(|b| b as char)
        .collect();
    id.as_bytes()
        .first()
        .is_some_and(|byte| !byte.is_ascii_digit())
        .then_some(id)
}

/// Every identifier token in `text` (`{ name: deviceName }` -> `["name", "deviceName"]`), used to
/// test whether an iteration's element variable is read by the sink's argument.
fn identifier_tokens(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let Some(&byte) = bytes.get(i) else {
            break;
        };
        if is_ident(byte) && !byte.is_ascii_digit() {
            let start = i;
            while bytes.get(i).is_some_and(|byte| is_ident(*byte)) {
                i += 1;
            }
            out.push(text[start..i].to_owned());
        } else {
            i += 1;
        }
    }
    out
}

/// Identifiers that carry the tainted value in the handler source: the request parameter's own
/// name and every local it was `assigned to` along the finding's trace. Used to find which
/// argument of a `path.join(...)` is the attacker-controlled one.
pub(crate) fn tainted_identifiers(finding: &Finding, entry: &Entry) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    match entry {
        // A catch-all route may represent its sole anonymous `{}` slot as an empty name. Empty
        // strings are not identifiers and searching source text for one never advances.
        Entry::Query(name)
        | Entry::PathParam(name)
        | Entry::Header(name)
        | Entry::Body(Some(name))
            if !name.is_empty() =>
        {
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

/// A literal suffix the handler attaches to the tainted filename itself. This differs from
/// [`appended_path_suffix`]: `` `${userId}.json` `` reads `<attacker-value>.json`, while
/// `path.join(base, userId, 'record.json')` reads below an attacker-selected directory. Keep the
/// suffix narrow and filesystem-local so it can only describe a filename constraint, never supply
/// an extra traversal segment.
fn appended_filename_suffix(source: &str, names: &[String]) -> Option<String> {
    if names.is_empty() {
        return None;
    }

    // Template interpolation: `${userId}.json` (allow whitespace around the identifier).
    let mut from = 0usize;
    while let Some(rel) = source[from..].find("${") {
        let open = from + rel;
        let Some(close_rel) = source[open + 2..].find('}') else {
            break;
        };
        let close = open + 2 + close_rel;
        let ident = source[open + 2..close].trim();
        if names.iter().any(|name| name == ident) {
            let rest = &source[close + 1..];
            let end = rest.find('`').unwrap_or(rest.len());
            let suffix = &rest[..end];
            if is_safe_filename_suffix(suffix) {
                return Some(suffix.to_owned());
            }
        }
        from = close + 1;
    }

    // String concatenation: `userId + '.json'`. Restrict the search to the remainder of the same
    // line and require the right operand to be one complete string literal.
    for name in names {
        let mut from = 0usize;
        while let Some(rel) = source[from..].find(name) {
            let at = from + rel;
            from = at + name.len();
            let before_ok = at == 0
                || source
                    .as_bytes()
                    .get(at - 1)
                    .is_none_or(|byte| !is_ident(*byte));
            let after_ok = source
                .as_bytes()
                .get(from)
                .is_none_or(|byte| !is_ident(*byte));
            if !before_ok || !after_ok {
                continue;
            }
            let line = source[from..].split('\n').next().unwrap_or_default();
            let Some(rhs) = line.trim_start().strip_prefix('+').map(str::trim_start) else {
                continue;
            };
            let Some(quote) = rhs
                .as_bytes()
                .first()
                .copied()
                .filter(|q| matches!(q, b'\'' | b'"'))
            else {
                continue;
            };
            let Some(end) = rhs[1..].find(quote as char).map(|end| end + 1) else {
                continue;
            };
            let suffix = &rhs[1..end];
            if is_safe_filename_suffix(suffix) {
                return Some(suffix.to_owned());
            }
        }
    }
    None
}

fn is_safe_filename_suffix(value: &str) -> bool {
    value.starts_with('.')
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// A read sink built by `+`-concatenation that places a *server-selected* directory segment between
/// the tainted directory and a fixed leaf file (`base + '/' + id + '/' + version + '/music.gq'`, with
/// `id` tainted and `version` chosen from a listing of that directory). The read reaches the leaf only
/// after the handler enumerates the tainted directory and picks one child, so the traversal proof must
/// plant `<dir>/<child>/<leaf>`, not a bare file. Returns the suffix to plant below the climbed-to
/// directory: a single numeric child the handler's own selection accepts, then the fixed leaf (e.g.
/// `0/music.gq`). `None` unless an intermediate server-chosen segment is enumerated from the tainted
/// directory and numerically coerced, and a fixed leaf file follows it. Mined from the handler source
/// only; nothing here is tied to a specific application.
fn appended_listing_suffix(source: &str, sink_arg: &str, names: &[String]) -> Option<String> {
    if names.is_empty() || sink_arg.contains(".join(") {
        return None;
    }
    let operands = concat_operands(sink_arg);
    let idx = operands
        .iter()
        .position(|op| names.iter().any(|name| name == op.trim()))?;
    let mut suffix = String::new();
    let mut saw_listing_segment = false;
    for op in operands.get(idx + 1..).unwrap_or_default() {
        let op = op.trim();
        if let Some(literal) = string_literal_arg(op) {
            suffix.push_str(&literal);
            continue;
        }
        // A further tainted operand is an attacker-controlled segment, handled by
        // `appended_path_fields`, not here.
        if names.iter().any(|name| name == op) {
            return None;
        }
        // A server-selected directory segment picked from a listing of the tainted directory: plant a
        // single numeric child the handler's own selection accepts. Any other local is uncontrollable.
        if op.bytes().all(is_ident)
            && !op.is_empty()
            && enumerates_tainted_dir(source, names)
            && numeric_assignment(source, op)
        {
            suffix.push('0');
            saw_listing_segment = true;
            continue;
        }
        return None;
    }
    if !saw_listing_segment {
        return None;
    }
    let suffix = suffix.trim_start_matches('/').to_owned();
    // A fixed leaf file must follow the selected segment, so the planted document is read directly.
    if !suffix.rsplit('/').next().unwrap_or_default().contains('.') {
        return None;
    }
    is_safe_suffix(&suffix).then_some(suffix)
}

/// The operands of a top-level `+`-concatenation expression, each trimmed of nothing (callers trim).
/// String literals and bracketed sub-expressions are kept whole.
fn concat_operands(expr: &str) -> Vec<&str> {
    let bytes = expr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        if i >= expr.len() {
            break;
        }
        let (operand, next) = concat_operand(expr, i);
        out.push(operand);
        i = next;
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        if bytes.get(i) == Some(&b'+') {
            i += 1;
        } else {
            break;
        }
    }
    out
}

/// Whether the handler enumerates a tainted directory (`fs.readdirSync`/`fs.opendirSync`/`fs.readdir`
/// /`fs.scandir` of a path mentioning a tainted name). The listing supplies the server-selected
/// segment a traversal read then descends through.
fn enumerates_tainted_dir(source: &str, names: &[String]) -> bool {
    for kw in ["readdir", "opendir", "scandir"] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(kw) {
            let open_rel = from + rel + kw.len();
            from = open_rel;
            let rest = source[open_rel..].trim_start();
            let rest = rest.strip_prefix("Sync").unwrap_or(rest).trim_start();
            let Some(after) = rest.strip_prefix('(') else {
                continue;
            };
            let Some(arglist) = balanced_arg(after) else {
                continue;
            };
            if names.iter().any(|name| mentions(arglist, name)) {
                return true;
            }
        }
    }
    false
}

/// Whether `name` is assigned from a numeric coercion somewhere in the handler (`version =
/// Math.max(version, Number(v))`, `n = parseInt(x)`): an assignment whose right-hand side applies a
/// numeric conversion. Confirms a planted numeric child segment the handler selects passes its own
/// numeric filter.
fn numeric_assignment(source: &str, name: &str) -> bool {
    let bytes = source.as_bytes();
    let mut from = 0;
    while let Some(rel) = source[from..].find(name) {
        let at = from + rel;
        from = at + name.len();
        let before = at == 0 || bytes.get(at - 1).is_none_or(|b| !is_ident(*b));
        let after_name = at + name.len();
        if !before
            || bytes
                .get(after_name)
                .is_some_and(|b| is_ident(*b) || *b == b'.')
        {
            continue;
        }
        let tail = source[after_name..].trim_start();
        let Some(rhs) = tail.strip_prefix('=').filter(|r| {
            !r.starts_with('=') && !r.starts_with('>') && !r.trim_start().starts_with('=')
        }) else {
            continue;
        };
        let end = binding_rhs_end(rhs).min(300);
        let stmt = &rhs[..end];
        if [
            "Number(",
            "parseInt(",
            "parseFloat(",
            "Math.max(",
            "Math.min(",
        ]
        .iter()
        .any(|coerce| stmt.contains(coerce))
        {
            return true;
        }
    }
    false
}

/// The request fields a handler appends after the tainted argument inside a `path.join(...)` call
/// (`path.join(base, type, id)` with `type` tainted -> `["id"]`): the bare-identifier arguments that
/// follow the tainted one and are themselves members of the same request part as `entry`, in order.
/// Stops at the first argument that is neither such a field nor a plain string literal, so a
/// server-computed local (`folderName`) is not mistaken for attacker-controlled input. The tainted
/// argument itself is excluded even though it is a request field. Mined from the handler source only.
fn appended_path_fields(source: &str, names: &[String], entry: &Entry) -> Vec<String> {
    if names.is_empty() {
        return Vec::new();
    }
    let part = match entry {
        Entry::Body(_) => "body",
        Entry::Query(_) => "query",
        _ => return Vec::new(),
    };
    let fields = request_part_fields(source, part);
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
        let mut out: Vec<String> = Vec::new();
        for arg in args.get(idx + 1..).unwrap_or_default() {
            let arg = arg.trim();
            // A plain string literal belongs to the fixed-suffix path, not here; keep scanning past it
            // so a field after a literal is still recovered, but do not record the literal.
            if string_literal_arg(arg).is_some() {
                continue;
            }
            // A bare identifier that is a member of the request part is attacker-controlled; record it.
            if arg.bytes().all(is_ident)
                && !arg.is_empty()
                && !names.iter().any(|name| name == arg)
                && fields.iter().any(|f| f == arg)
            {
                if !out.contains(&arg.to_owned()) {
                    out.push(arg.to_owned());
                }
                continue;
            }
            // Anything else (a server-computed local, a call, an expression) is not controllable: stop.
            break;
        }
        if !out.is_empty() {
            return out;
        }
    }
    appended_concat_fields(source, names, &fields)
}

/// The request fields a handler appends after the tainted value inside a *string concatenation* that
/// builds the path (`serverpath + "Flash" + mypath + "/" + req.query.filename`, with `mypath`
/// tainted -> `["filename"]`). Fixed string-literal separators (`"/"`) are skipped; each operand that
/// is a member of the same request part (`req.query.filename`, or a bare destructured field) is
/// recorded, in order, stopping at the first operand that is neither a literal nor such a field (a
/// server-computed local, a call) so nothing uncontrolled is mistaken for attacker input. Mined from
/// the handler source only.
fn appended_concat_fields(source: &str, names: &[String], fields: &[String]) -> Vec<String> {
    let bytes = source.as_bytes();
    for name in names {
        let mut from = 0;
        while let Some(rel) = source[from..].find(name.as_str()) {
            let at = from + rel;
            from = at + name.len();
            // The occurrence must be a standalone identifier operand, not a member access
            // (`a.mypath`), a property name, or a longer identifier (`mypathx`).
            let before = at.checked_sub(1).and_then(|i| bytes.get(i)).copied();
            if before.is_some_and(|b| is_ident(b) || b == b'.') {
                continue;
            }
            let after_name = at + name.len();
            if bytes
                .get(after_name)
                .is_some_and(|b| is_ident(*b) || *b == b'.')
            {
                continue;
            }
            let appended = concat_operand_fields(source, after_name, names, fields);
            if !appended.is_empty() {
                return appended;
            }
        }
    }
    Vec::new()
}

/// For a removal sink whose argument is a child *enumerated* from the tainted directory, the filename
/// substring an entry must contain to be removed, or an empty string when the handler removes every
/// child unfiltered. `None` when the removed path is the tainted value itself (the common direct-name
/// removal, handled by the ordinary delete oracle). The argument must be `dir + '/' + child` (string
/// concatenation) or `path.join(dir, child)` whose final operand is a local bound from a directory
/// listing (`fs.readdirSync`/`fs.opendirSync`/`fs.readdir`) of a tainted directory; the filter is read
/// from a `.indexOf('x') > -1` / `.includes` / `.endsWith` / `.startsWith` guard on that loop
/// variable. Mined from the handler source only; nothing here is tied to a specific application.
fn removed_dir_child_marker(source: &str, sink_arg: &str, tainted: &[String]) -> Option<String> {
    let child = removed_child_operand(sink_arg)?;
    let child_base = ident_prefix(&child)?;
    // A child that is itself the tainted value names the removed entry directly — not an enumeration.
    if tainted.contains(&child_base) {
        return None;
    }
    if !bound_from_directory_listing(source, &child_base, tainted) {
        return None;
    }
    Some(child_name_filter(source, &child_base).unwrap_or_default())
}

/// Whether a copy sink (`fs.copyFile(Sync)`, `fs-extra` `cp`/`copy`) reads its flagged *source*
/// argument out of a tainted directory the handler enumerates
/// (`for (const f of fs.readdirSync(dir)) fs.copyFileSync(dir + '/' + f, base + '/' + f)`). The
/// tainted path is the file being *read* (copied out of the attacker-named directory into a confined
/// destination), not a created destination, so the traversal is a directory-enumerating read /
/// exfiltration — proved by a file-found/not-found differential, not by a new entry appearing inside
/// a planted directory. The flagged argument (`sink_arg`) is the source operand, so when its final
/// operand is a child bound from a listing of a tainted directory the copy reads out of that tainted
/// directory. Mined from the handler source only; framework-agnostic.
fn copy_reads_enumerated_dir(api: &str, sink_arg: &str, source: &str, tainted: &[String]) -> bool {
    if !sink_copies(api) {
        return false;
    }
    let Some(child) = removed_child_operand(sink_arg) else {
        return false;
    };
    let Some(child_base) = ident_prefix(&child) else {
        return false;
    };
    // A child that is itself the tainted value names the read entry directly, not an enumeration of
    // the tainted directory's listing.
    if tainted.contains(&child_base) {
        return false;
    }
    bound_from_directory_listing(source, &child_base, tainted)
        && enumerates_tainted_dir(source, tainted)
}

/// Whether a sink API copies a file (`fs.copyFile(Sync)`, `fs-extra` `cp`/`copy`), matched on the
/// final `.`-segment so an unrelated method whose name merely contains one of these is not mistaken
/// for it. Framework-agnostic; used to tell a copy whose *source* is attacker-controlled (a read /
/// exfiltration) from a plain create.
fn sink_copies(api: &str) -> bool {
    let name = api.rsplit('.').next().unwrap_or(api).to_ascii_lowercase();
    matches!(
        name.as_str(),
        "copyfile" | "copyfilesync" | "cp" | "cpsync" | "copy" | "copysync"
    )
}

/// The final operand of a removal sink's path argument: the last `path.join(...)` argument, or the
/// last non-literal operand of a `+`-concatenation. Fixed string-literal separators are ignored.
fn removed_child_operand(sink_arg: &str) -> Option<String> {
    if let Some(rel) = sink_arg.find(".join(") {
        let open = rel + ".join(".len();
        if let Some(args) = balanced_arg(&sink_arg[open..])
            && let Some(last) = split_top_level_commas(args).last()
        {
            return Some(last.trim().to_owned());
        }
    }
    let bytes = sink_arg.as_bytes();
    let mut i = 0usize;
    let mut last: Option<String> = None;
    loop {
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        if i >= sink_arg.len() {
            break;
        }
        let (operand, next) = concat_operand(sink_arg, i);
        let operand = operand.trim();
        if !operand.is_empty() && string_literal_arg(operand).is_none() {
            last = Some(operand.to_owned());
        }
        i = next;
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        if bytes.get(i) == Some(&b'+') {
            i += 1;
        } else {
            break;
        }
    }
    last
}

/// The leading identifier of an expression (`currFiles[i]` -> `currFiles`, `files` -> `files`), or
/// `None` when it does not begin with an identifier character.
fn ident_prefix(expr: &str) -> Option<String> {
    let ident: String = expr.chars().take_while(|c| is_ident(*c as u8)).collect();
    ident
        .bytes()
        .next()
        .is_some_and(|b| !b.is_ascii_digit())
        .then_some(ident)
}

/// Whether `child` is a local bound from a directory listing (`fs.readdirSync`/`fs.opendirSync`/
/// `fs.readdir`) whose argument mentions a tainted directory. Honors ASI so a semicolon-free binding
/// does not bleed into the next statement.
fn bound_from_directory_listing(source: &str, child: &str, tainted: &[String]) -> bool {
    for kw in ["const ", "let ", "var "] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(kw) {
            let at = from + rel + kw.len();
            from = at;
            let rest = &source[at..];
            let ident: String = rest.chars().take_while(|c| is_ident(*c as u8)).collect();
            if ident != child {
                continue;
            }
            let tail = rest[ident.len()..].trim_start();
            let Some(rhs) = tail.strip_prefix('=').filter(|r| !r.starts_with('=')) else {
                continue;
            };
            let end = binding_rhs_end(rhs).min(300);
            let stmt = &rhs[..end];
            if (stmt.contains("readdir") || stmt.contains("opendir"))
                && tainted.iter().any(|name| mentions(stmt, name))
            {
                return true;
            }
        }
    }
    false
}

/// The filename substring a `.indexOf('x') > -1` / `.includes('x')` / `.endsWith('x')` /
/// `.startsWith('x')` guard whose receiver mentions `child` requires, or `None` when the handler
/// removes every enumerated child without a name filter.
fn child_name_filter(source: &str, child: &str) -> Option<String> {
    for marker in [".indexOf(", ".includes(", ".endsWith(", ".startsWith("] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(marker) {
            let at = from + rel;
            from = at + marker.len();
            // The receiver is the trailing run of member/index characters ending at the `.`; take it
            // by char boundaries so a multibyte character earlier in the source cannot split a slice.
            let recv_start = source[..at]
                .char_indices()
                .rev()
                .take_while(|(_, c)| {
                    c.is_ascii_alphanumeric() || matches!(c, '_' | '[' | ']' | '.')
                })
                .last()
                .map(|(i, _)| i)
                .unwrap_or(at);
            if !mentions(source.get(recv_start..at).unwrap_or(""), child) {
                continue;
            }
            if let Some(lit) = leading_string(source[at + marker.len()..].trim_start())
                && !lit.is_empty()
            {
                return Some(lit);
            }
        }
    }
    None
}

/// Walks the `+`-concatenation operands that follow position `start`, collecting request-part fields
/// (see [`appended_concat_fields`]). Returns the ordered field names, or empty when the tainted value
/// is the last operand or the next operand is not controllable.
fn concat_operand_fields(
    source: &str,
    start: usize,
    names: &[String],
    fields: &[String],
) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = start;
    loop {
        // Skip whitespace to the next operator.
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        // Only a `+` continues the concatenation; anything else ends it.
        if bytes.get(i) != Some(&b'+') {
            break;
        }
        i += 1;
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        let (operand, next) = concat_operand(source, i);
        let operand = operand.trim();
        i = next;
        if operand.is_empty() {
            break;
        }
        // A string literal is a fixed separator (`"/"`, `"Flash"`): not attacker input, keep scanning.
        if string_literal_arg(operand).is_some() {
            continue;
        }
        // A member of the same request part (`req.query.filename`) or a bare destructured field is
        // attacker-controlled: record it. Anything else stops the scan.
        match concat_field(operand, fields) {
            Some(field) if !names.iter().any(|n| n == &field) => {
                if !out.contains(&field) {
                    out.push(field);
                }
            }
            _ => break,
        }
    }
    out
}

/// One concatenation operand beginning at `start`: the text up to the next top-level `+` or the
/// top-level `)`/`]`/`}`/`,`/`;` that ends the enclosing expression, honoring `()`/`[]`/`{}` nesting
/// and skipping string/template literals. Returns the operand text and the offset of the terminator.
fn concat_operand(source: &str, start: usize) -> (&str, usize) {
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut i = start;
    while let Some(b) = bytes.get(i).copied() {
        match b {
            b'\'' | b'"' | b'`' => {
                i = skip_string_literal(source, i);
                continue;
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return (&source[start..i], i);
                }
                depth -= 1;
            }
            b'+' if depth == 0 => return (&source[start..i], i),
            b',' | b';' if depth == 0 => return (&source[start..i], i),
            _ => {}
        }
        i += 1;
    }
    (&source[start..], bytes.len())
}

/// The index just past the string/template literal that starts at `start` (an opening quote), honoring
/// `\`-escapes. A template literal is skipped to its closing backtick without descending into `${...}`.
fn skip_string_literal(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let Some(quote) = bytes.get(start).copied() else {
        return bytes.len();
    };
    let mut i = start + 1;
    while let Some(b) = bytes.get(i).copied() {
        if b == b'\\' {
            i += 2;
            continue;
        }
        if b == quote {
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

/// The request-part field a concatenation operand names: the member of a `req`/`request`/`ctx`
/// `.query`/`.body`/`.params` access (`req.query.filename` -> `filename`), or a bare identifier that
/// is a known field of the part (`fields`). `None` for anything else.
fn concat_field(operand: &str, fields: &[String]) -> Option<String> {
    for recv in ["req.", "request.", "ctx."] {
        if let Some(rest) = operand.strip_prefix(recv) {
            for part in ["query.", "body.", "params."] {
                if let Some(member) = rest.strip_prefix(part) {
                    let field: String = member
                        .bytes()
                        .take_while(|b| is_ident(*b))
                        .map(char::from)
                        .collect();
                    // The access must be exactly `recv.part.field` with nothing chained after it.
                    if !field.is_empty() && member.len() == field.len() {
                        return Some(field);
                    }
                }
            }
        }
    }
    if operand.bytes().all(is_ident) && !operand.is_empty() && fields.iter().any(|f| f == operand) {
        return Some(operand.to_owned());
    }
    None
}

/// The field names a handler reads from a request part: members accessed directly
/// (`req.body.id`) and the fields bound by destructuring the whole part (`const { id, type } =
/// req.body`), the latter with any default-value (`type = "Anime"`) stripped. Covers the `req`,
/// `request`, and `ctx` receivers. Mined from the handler source only.
fn request_part_fields(source: &str, part: &str) -> Vec<String> {
    let mut out = member_params(source, part);
    for recv in ["req", "request", "ctx"] {
        let needle = format!("{recv}.{part}");
        let bytes = source.as_bytes();
        let mut from = 0;
        while let Some(rel) = source[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            let before_ok = at == 0 || bytes.get(at - 1).is_none_or(|b| !is_ident(*b));
            let after_ok = bytes
                .get(at + needle.len())
                .is_none_or(|b| !is_ident(*b) && *b != b'.' && *b != b'[' && *b != b'(');
            if !before_ok || !after_ok {
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
                let entry = entry.trim().trim_start_matches("...").trim();
                if entry.is_empty() {
                    continue;
                }
                let field = match entry.split_once(':') {
                    Some((k, _)) => k.trim(),
                    None => entry.split('=').next().unwrap_or(entry).trim(),
                };
                if !field.is_empty() && field.bytes().all(is_ident) {
                    out.push(field.to_owned());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
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
    if name.is_empty() {
        return None;
    }
    let mut from = 0;
    while let Some(rel) = source[from..].find("import") {
        let at = from + rel;
        from = at + "import".len();
        if at > 0 && source.as_bytes().get(at - 1).is_some_and(|b| is_ident(*b)) {
            continue;
        }
        // Bound the match to this import's own statement: its `;`, or — absent one (ASI) — the
        // newline that ends the (possibly multi-line named) import at bracket depth 0. Without this
        // a semicolon-free file would merge the import with following statements and could read a
        // later import's specifier.
        let end = source.floor_char_boundary(source.len().min(at.saturating_add(400)));
        let window = &source[at..end];
        let stmt = &window[..import_statement_end(window)];
        if !contains_word(stmt, name) {
            continue;
        }
        if let Some(fpos) = stmt.find(" from ") {
            let tail = stmt[fpos + " from ".len()..].trim_start();
            if let Some(path) = leading_string(tail) {
                return Some(path);
            }
        }
    }
    None
}

/// The module specifier a CommonJS binding of `name` comes from: `const name = require('<path>')`
/// or `const { a, name, b } = require('<path>')` (with an optional `name: local` rename) ->
/// `<path>`. Used to locate a middleware defined in another module the route `require`s. Mined from
/// the require bindings only.
pub fn require_source_path(source: &str, name: &str) -> Option<String> {
    let needle = "require(";
    let mut from = 0;
    while let Some(rel) = source[from..].find(needle) {
        let at = from + rel;
        from = at + needle.len();
        // Only a `= require(...)` binding, not a nested `app.use(require(...))`.
        let head = source[..at].trim_end();
        let Some(before_eq) = head.strip_suffix('=') else {
            continue;
        };
        // Exclude `==`, `!=`, `>=`, `<=`, `=>` which also end in `=`/precede a `=`.
        if before_eq.ends_with(['=', '!', '<', '>']) {
            continue;
        }
        let Some(spec) = leading_string(source[at + needle.len()..].trim_start()) else {
            continue;
        };
        let lhs = before_eq.trim_end();
        let bound = if lhs.ends_with('}') {
            let close = lhs.len() - 1;
            matching_open_brace(lhs, close).is_some_and(|open| {
                split_top_level_commas(&lhs[open + 1..close])
                    .iter()
                    .any(|e| {
                        let field = e.trim().split(':').next().unwrap_or("").trim();
                        field == name
                    })
            })
        } else {
            let ident: String = lhs
                .bytes()
                .rev()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            ident == name
        };
        if bound {
            return Some(spec);
        }
    }
    None
}

/// The module specifier a named import *or* CommonJS require of `name` comes from: ES `import`
/// first, then a `require` binding. Used to follow one module hop to where a middleware is defined.
pub fn import_or_require_source_path(source: &str, name: &str) -> Option<String> {
    import_source_path(source, name).or_else(|| require_source_path(source, name))
}

/// Every relative module specifier the source imports or requires (`import x from './a'`,
/// `export { b } from '../b'`, `require('./c')`, `import('./d')`), deduplicated and first-seen. Bare
/// package specifiers are excluded — they are not part of the app's own source tree. Used to follow
/// one import hop to the module that reads a credential a sink is gated on.
pub fn relative_import_specifiers(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for marker in [" from ", "require(", "import("] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(marker) {
            let at = from + rel;
            from = at + marker.len();
            let tail = source[at + marker.len()..].trim_start();
            if let Some(spec) = leading_string(tail)
                && spec.starts_with('.')
                && !out.contains(&spec)
            {
                out.push(spec);
            }
        }
    }
    out
}

/// The length of the import statement at the start of `stmt`: up to its `;`, or — absent one (ASI) —
/// the first newline at bracket depth 0 outside any string, so a multi-line named import
/// (`import {\n  a,\n  b\n} from "x"`) stays whole while the statement does not run past its line.
fn import_statement_end(stmt: &str) -> usize {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in stmt.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth -= 1,
            ';' | '\n' if depth <= 0 => return i,
            _ => {}
        }
    }
    stmt.len()
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
    if word.is_empty() {
        return false;
    }
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

/// Whether the handler base64-decodes a tainted value into a *raw* string the sink consumes directly
/// (`const decoded = Buffer.from(c, 'base64').toString(); eval(decoded)`), returning whether the
/// decode alphabet is base64url. Unlike [`json_envelope`], the decoded bytes are not `JSON.parse`d into
/// an object: the whole decoded string is the sink argument, so a payload must be base64-encoded to
/// survive the decode and reach the sink verbatim. Recognized two ways — the sink argument expression
/// itself decodes a tainted identifier (`eval(Buffer.from(c, 'base64').toString())`), or a tainted
/// local is bound to such a decode (`const decoded = Buffer.from(c, 'base64').toString()`) and carries
/// the taint onward to the sink. A right-hand side that wraps the decode in `JSON.parse` is excluded
/// (that is the envelope case). `None` otherwise. Mined from the handler source only.
fn base64_decoded_into_sink(source: &str, names: &[String], sink_arg: &str) -> Option<bool> {
    if !sink_arg.contains("JSON.parse")
        && let Some(url_safe) = decoded_tainted_buffer(sink_arg, names)
    {
        return Some(url_safe);
    }
    for (local, rhs) in decode_bindings(source) {
        if !names.iter().any(|name| name == &local) {
            continue;
        }
        if rhs.contains("JSON.parse") {
            continue;
        }
        if let Some(url_safe) = decoded_tainted_buffer(&rhs, names) {
            return Some(url_safe);
        }
    }
    None
}

/// Each `const|let|var <name> = <rhs>` binding in `source`, as `(name, rhs)` where `rhs` is the
/// initializer up to its statement end (see [`statement_rhs`]). Used to find a local a base64 decode is
/// bound to. Mined from the handler source only.
fn decode_bindings(source: &str) -> Vec<(String, String)> {
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
            out.push((name, statement_rhs(rhs.trim_start()).to_owned()));
        }
    }
    out
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
    let mut names = member_params(source, part);
    // Body handlers commonly need a complete object for a create/update operation, so consumed
    // destructured fields are useful shape requirements. Query destructuring, by contrast, usually
    // collects optional filters, pagination and tenant overrides; sending every consumed field
    // changes application defaults and can redirect a probe away from the real datastore. Explicit
    // member reads and control-flow guards below remain the evidence for required query siblings.
    if part == "body" {
        names.extend(destructured_field_keys(source, part));
    }
    names.retain(|name| name != target && !joi_field_is_optional(source, name));
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

/// Body fields an express-validator middleware chain attached to the route requires — a
/// `body("name")`/`check("name")` chain without `.optional()` — other than the payload field, each
/// paired with a value that satisfies the chain's declared type: a JSON array (`["jsspector"]`) for
/// `.isArray(...)`, the first `.isIn([...])` alternative, a Mongo-id / email / number / boolean
/// filler for the matching assertion, else the scalar `jsspector`. A value that is a JSON literal
/// (array, object, number, boolean) is returned verbatim so the body builder emits it unquoted; a
/// scalar is returned bare so the builder quotes it. `route_source` is the file registering the
/// route, `route_line` the 1-based registration line, `resolve` maps a middleware identifier to the
/// source of the module that defines it. Mined from the route registration and the validator array
/// definitions only; nothing here is tied to a specific application.
pub fn validator_required_body_fields(
    route_source: &str,
    route_line: u32,
    payload_field: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    // Resolve each middleware argument as a full expression so a member-expression validator
    // (`userValidations.syncAnalyticsAndMobile`) is handled, not only a bare identifier bound to a
    // local array. The resolved chain text is scanned for required `body(...)`/`check(...)` fields.
    for expr in route_middleware_exprs(route_source, route_line) {
        let mut parts = expr.split('.');
        let Some(root) = parts.next() else {
            continue;
        };
        let Some(module) = resolve(root) else {
            continue;
        };
        let leaf: Vec<&str> = parts.collect();
        let chain = validator_chain_text(&module, root, &leaf);
        for (field, value) in validator_body_requirements(&chain) {
            if field == payload_field {
                continue;
            }
            if out.iter().all(|(k, _)| *k != field) {
                out.push((field, value));
            }
        }
    }
    out
}

/// Body fields that an express-validator middleware attached to the route explicitly marks
/// `.optional()`. Handler-wide mining can otherwise mistake every destructured body property for a
/// request precondition and send a neutral scalar for an optional array/object field, causing the
/// validator to reject a request that would have passed had the field simply been omitted.
pub fn validator_optional_body_fields(
    route_source: &str,
    route_line: u32,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for expr in route_middleware_exprs(route_source, route_line) {
        let mut parts = expr.split('.');
        let Some(root) = parts.next() else {
            continue;
        };
        let Some(module) = resolve(root) else {
            continue;
        };
        let leaf: Vec<&str> = parts.collect();
        let chain = validator_chain_text(&module, root, &leaf);
        let starts = chain_starts(&chain);
        for (idx, (pos, field, builder)) in starts.iter().enumerate() {
            if builder != "body" && builder != "check" {
                continue;
            }
            let Some(field) = field else {
                continue;
            };
            let end = starts
                .get(idx + 1)
                .map(|item| item.0)
                .unwrap_or(chain.len());
            if chain[*pos..end].contains(".optional(") && !out.contains(field) {
                out.push(field.clone());
            }
        }
    }
    out
}

/// A type-valid value for the payload body field itself, when an express-validator middleware chain
/// requires it. This is used by the ordered body/query overwrite probe: the body must satisfy its
/// validator while the same-named, later query value carries the operator object.
pub fn validator_body_field_filler(
    route_source: &str,
    route_line: u32,
    payload_field: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    for root in route_middleware_roots(route_source, route_line) {
        let Some(module) = resolve(&root) else {
            continue;
        };
        // A bare middleware identifier can be narrowed to its declared array. A member expression
        // (`validators.group.rule`) resolves only through its namespace root, so inspect the module's
        // validator chains and select only the requested field; unrelated chains cannot leak into
        // the request because this function returns a single exact-field filler.
        let requirements = const_array_body(&module, &root)
            .map(|array| validator_body_requirements(&array))
            .unwrap_or_else(|| validator_body_requirements(&module));
        if let Some((_, value)) = requirements
            .into_iter()
            .find(|(field, _)| field == payload_field)
        {
            return Some(value);
        }
    }
    None
}

/// Type-valid fillers for non-payload path slots constrained by required express-validator
/// `param("slot")` chains attached to the route. Middleware member expressions are resolved through
/// their root namespace (`validators.group.rule` -> `validators`).
pub fn validator_path_fillers(
    route_source: &str,
    route_line: u32,
    path: &str,
    payload_slot: Option<&str>,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    let slots = route_slots(path);
    if slots.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for middleware in route_middleware_roots(route_source, route_line) {
        let Some(module) = resolve(&middleware) else {
            continue;
        };
        let requirements = validator_param_requirements(&module);
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] validator-path-module root={middleware} requirements={requirements:?}"
            );
        }
        for (slot, value) in requirements {
            if Some(slot.as_str()) == payload_slot {
                continue;
            }
            if slots.contains(&slot) && out.iter().all(|(name, _)| *name != slot) {
                out.push((slot, value));
            }
        }
    }
    out
}

/// Type-valid fillers for required express-validator `query("name")` chains the route mounts, other
/// than the payload-bearing field. A GET/query handler that enforces its validators (reading
/// `validationResult`, e.g. `extractErrorsFromRequest`) rejects the request with a 400 before the
/// sink unless every required query parameter is present and type-valid; carrying each one lets the
/// tainted value reach the sink. Only the chain each middleware argument actually references is
/// inspected — resolved through the middleware member expression (`validators.group.rule`) and the
/// named sub-chains it is assembled from — so unrelated routes' query validators declared in the same
/// module are never pulled in. Nothing here is tied to a specific application.
pub fn validator_query_fillers(
    route_source: &str,
    route_line: u32,
    payload_field: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for expr in route_middleware_exprs(route_source, route_line) {
        let mut parts = expr.split('.');
        let Some(root) = parts.next() else {
            continue;
        };
        let Some(module) = resolve(root) else {
            continue;
        };
        let leaf: Vec<&str> = parts.collect();
        let chain = validator_chain_text(&module, root, &leaf);
        for (field, value) in validator_query_requirements(&chain) {
            if field == payload_field {
                continue;
            }
            if out.iter().all(|(name, _)| *name != field) {
                out.push((field, value));
            }
        }
    }
    out
}

/// Query fields that attached express-validator middleware makes optional, either directly with
/// `.optional()` or conditionally with `.if(...)`. These override handler-wide sibling guesses: an
/// omitted optional tenant lets the application use its configured database, while a fabricated
/// tenant can silently redirect the sink into a different, lazily-created database.
pub fn validator_optional_query_fields(
    route_source: &str,
    route_line: u32,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for expr in route_middleware_exprs(route_source, route_line) {
        let mut parts = expr.split('.');
        let Some(root) = parts.next() else {
            continue;
        };
        let Some(module) = resolve(root) else {
            continue;
        };
        let leaf: Vec<&str> = parts.collect();
        let chain = validator_chain_text(&module, root, &leaf);
        let starts = chain_starts(&chain);
        for (idx, (pos, field, builder)) in starts.iter().enumerate() {
            if builder != "query" {
                continue;
            }
            let Some(field) = field else {
                continue;
            };
            let end = starts
                .get(idx + 1)
                .map(|item| item.0)
                .unwrap_or(chain.len());
            let window = &chain[*pos..end];
            if (window.contains(".optional(") || window.contains(".if(")) && !out.contains(field) {
                out.push(field.clone());
            }
        }
    }
    out
}

/// The route registration's middleware arguments as full identifier/member expressions
/// (`analyticsValidations.userEngagementValidators.getMetrics`, `pagination`), excluding the path
/// string literal and any call expression. These name the express-validator chains the route mounts.
pub fn route_middleware_exprs(source: &str, line: u32) -> Vec<String> {
    let Some(start) = line_offset(source, line as usize) else {
        return Vec::new();
    };
    let Some(prel) = source[start..].find('(') else {
        return Vec::new();
    };
    let popen = start + prel;
    let Some(pclose) = matching_close_paren(source, popen) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for arg in split_top_level_commas(&source[popen + 1..pclose]) {
        let arg = arg.trim();
        if arg.is_empty() {
            continue;
        }
        if arg.bytes().all(|byte| is_ident(byte) || byte == b'.')
            && arg
                .bytes()
                .next()
                .is_some_and(|byte| !byte.is_ascii_digit() && byte != b'.')
            && !out.iter().any(|existing| existing == arg)
        {
            out.push(arg.to_owned());
        }
    }
    out
}

/// The source text of the validator chain a middleware argument references, plus the definitions of
/// the named sub-chains it is assembled from (`[validateUserEmail, ...validateYearMonth]`), resolved
/// up to a few levels so the builder calls in the sub-chains are visible to [`chain_starts`]. `leaf`
/// is the member path after the resolved module root (`["userEngagementValidators", "getMetrics"]`).
fn validator_chain_text(module: &str, root: &str, leaf: &[&str]) -> String {
    let seed = resolve_member_chain(module, root, leaf).unwrap_or_default();
    let mut text = seed.clone();
    let mut seen: Vec<String> = Vec::new();
    let mut frontier: Vec<String> = referenced_idents(&seed)
        .into_iter()
        .chain(referenced_member_exprs(&seed))
        .collect();
    let mut depth = 0;
    while depth < 3 && !frontier.is_empty() {
        let mut next: Vec<String> = Vec::new();
        for expr in std::mem::take(&mut frontier) {
            if seen.contains(&expr) {
                continue;
            }
            seen.push(expr.clone());
            let mut parts = expr.split('.');
            let Some(binding) = parts.next() else {
                continue;
            };
            let leaf: Vec<&str> = parts.collect();
            let definition = if leaf.is_empty() {
                const_definition_text(module, binding)
            } else {
                resolve_member_chain(module, binding, &leaf)
            };
            if let Some(def) = definition {
                next.extend(referenced_idents(&def));
                next.extend(referenced_member_exprs(&def));
                text.push('\n');
                text.push_str(&def);
            }
        }
        frontier = next;
        depth += 1;
    }
    text
}

/// Resolves a middleware member expression within its module without confusing same-named leaves
/// in unrelated validator groups. For `validators.userEngagement.getMetrics`, first narrow to the
/// `userEngagement` binding/export, then look up `getMetrics` only inside that object.
fn resolve_member_chain(module: &str, root: &str, leaf: &[&str]) -> Option<String> {
    let Some((first, rest)) = leaf.split_first() else {
        return const_definition_text(module, root);
    };
    let mut current =
        const_definition_text(module, first).or_else(|| object_property_value(module, first))?;
    for member in rest {
        if current
            .bytes()
            .all(|byte| is_ident(byte) || byte.is_ascii_whitespace())
            && let Some(binding) = const_definition_text(module, current.trim())
        {
            current = binding;
        }
        current = object_property_value(&current, member)?;
    }
    Some(current)
}

/// Required `query("field")` chains in `text` that are not `.optional()` and not conditional
/// (`.if(...)`), each paired with a value satisfying the declared type.
fn validator_query_requirements(text: &str) -> Vec<(String, String)> {
    let starts = chain_starts(text);
    let mut out: Vec<(String, String)> = Vec::new();
    for (idx, (pos, field, builder)) in starts.iter().enumerate() {
        if builder != "query" {
            continue;
        }
        let Some(field) = field else {
            continue;
        };
        let end = starts.get(idx + 1).map(|s| s.0).unwrap_or(text.len());
        let window = &text[*pos..end];
        // `.optional()` lets the field be absent; `.if(...)` only requires it under another field's
        // value — neither is unconditionally required, so sending it is not needed to reach the sink.
        if window.contains(".optional(") || window.contains(".if(") {
            continue;
        }
        if out.iter().all(|(name, _)| name != field) {
            out.push((field.clone(), validator_filler(field, window)));
        }
    }
    out
}

/// The initializer expression bound to `const <name> = ...` (`let`/`var` too): the array body of a
/// chain list, or the chain/expression up to the statement terminator. `None` when `name` is not a
/// module-level binding here.
fn const_definition_text(module: &str, name: &str) -> Option<String> {
    if let Some(body) = const_array_body(module, name) {
        return Some(body);
    }
    for keyword in ["const ", "let ", "var "] {
        let needle = format!("{keyword}{name}");
        let mut from = 0;
        while let Some(rel) = module[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            let after = &module[at + needle.len()..];
            if after.bytes().next().is_some_and(is_ident) {
                continue;
            }
            let Some(rest) = after.trim_start().strip_prefix('=') else {
                continue;
            };
            let rest = rest.trim_start();
            let start = module.len() - rest.len();
            let end = statement_end(module, start);
            return Some(module[start..end].to_owned());
        }
    }
    None
}

/// The value expression of an object property `name: <value>` (`getMetrics: [ ... ]`): the text after
/// the colon up to the top-level `,` or `;` that ends it. `None` when no such standalone key exists.
fn object_property_value(module: &str, name: &str) -> Option<String> {
    let mut from = 0;
    while let Some(rel) = module[from..].find(name) {
        let at = from + rel;
        from = at + name.len();
        let before = at
            .checked_sub(1)
            .and_then(|i| module.as_bytes().get(i))
            .copied();
        if before.is_some_and(|byte| is_ident(byte) || byte == b'.') {
            continue;
        }
        let after = &module[at + name.len()..];
        if after.bytes().next().is_some_and(is_ident) {
            continue;
        }
        let Some(rest) = after.trim_start().strip_prefix(':') else {
            continue;
        };
        let rest = rest.trim_start();
        let start = module.len() - rest.len();
        let end = statement_end(module, start);
        return Some(module[start..end].to_owned());
    }
    None
}

/// The offset of the top-level `,` or `;` that terminates the expression starting at `start`,
/// honoring `()`/`[]`/`{}` nesting; the end of `text` when none is found.
fn statement_end(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut i = start;
    while let Some(byte) = bytes.get(i).copied() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return i;
                }
                depth -= 1;
            }
            b',' | b';' if depth == 0 => return i,
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// Bare identifier references in `text` (array elements, spread elements) that are not immediately a
/// call (`query(` is a builder, not a referenced chain binding). Used to follow a chain assembled
/// from named sub-chains to their definitions.
fn referenced_idents(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while let Some(b) = bytes.get(i).copied() {
        if is_ident(b) && !b.is_ascii_digit() {
            let before = i.checked_sub(1).and_then(|j| bytes.get(j)).copied();
            let start = i;
            while bytes.get(i).copied().is_some_and(is_ident) {
                i += 1;
            }
            // Skip member accesses (`a.b`) and call targets (`query(`): only standalone bindings.
            // A spread element (`...validateYearMonth`) is a reference, not a member access, even
            // though its leading `.` precedes the identifier.
            let after = bytes.get(i).copied();
            let is_spread = start
                .checked_sub(3)
                .and_then(|begin| bytes.get(begin..start))
                .is_some_and(|prefix| prefix == b"...");
            let is_member = before.is_some_and(|c| c == b'.' || is_ident(c)) && !is_spread;
            let is_call_or_member_root = matches!(after, Some(b'(' | b'.'));
            if !is_member && !is_call_or_member_root {
                let ident = &text[start..i];
                if !out.iter().any(|existing| existing == ident) {
                    out.push(ident.to_owned());
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Member expressions used as validator-chain elements (`...common.tenant`). They must be resolved
/// to the named property rather than expanding the root object's entire definition, which would mix
/// unrelated validators from sibling routes into this request.
fn referenced_member_exprs(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let Some(byte) = bytes.get(i).copied() else {
            break;
        };
        if !byte.is_ascii_alphabetic() && byte != b'_' && byte != b'$' {
            i += 1;
            continue;
        }
        let start = i;
        while bytes.get(i).copied().is_some_and(is_ident) {
            i += 1;
        }
        let mut members = 0;
        loop {
            if bytes.get(i) != Some(&b'.')
                || !bytes
                    .get(i + 1)
                    .copied()
                    .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_' || b == b'$')
            {
                break;
            }
            i += 1;
            while bytes.get(i).copied().is_some_and(is_ident) {
                i += 1;
            }
            members += 1;
        }
        if members == 0 || bytes.get(i) == Some(&b'(') {
            continue;
        }
        let before = text[..start].trim_end();
        let chain_element = before.is_empty()
            || before.ends_with("...")
            || before.ends_with(['[', ',', '=', '(', '{']);
        if chain_element {
            let expr = text[start..i].to_owned();
            if !out.contains(&expr) {
                out.push(expr);
            }
        }
    }
    out
}

/// Required `param("slot")` chains and values satisfying their declared type.
fn validator_param_requirements(module: &str) -> Vec<(String, String)> {
    let starts = chain_starts(module);
    let mut out: Vec<(String, String)> = Vec::new();
    for (idx, (pos, field, builder)) in starts.iter().enumerate() {
        if builder != "param" {
            continue;
        }
        let Some(field) = field else {
            continue;
        };
        let end = starts
            .get(idx + 1)
            .map(|item| item.0)
            .unwrap_or(module.len());
        let window = &module[*pos..end];
        if window.contains(".optional(") {
            continue;
        }
        if out.iter().all(|(name, _)| name != field) {
            out.push((field.clone(), validator_filler(field, window)));
        }
    }
    out
}

/// The bare-identifier arguments of the route registration on `line` (`router.post("/x", mwA, mwB,
/// controller)` -> `["mwA", "mwB"]`, skipping the path string and a `obj.method` controller). These
/// are the middleware names the route mounts, among them any express-validator array.
pub fn route_middleware_idents(source: &str, line: u32) -> Vec<String> {
    let Some(start) = line_offset(source, line as usize) else {
        return Vec::new();
    };
    let Some(prel) = source[start..].find('(') else {
        return Vec::new();
    };
    let popen = start + prel;
    let Some(pclose) = matching_close_paren(source, popen) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for arg in split_top_level_commas(&source[popen + 1..pclose]) {
        let arg = arg.trim();
        if !arg.is_empty() && arg.bytes().all(is_ident) {
            out.push(arg.to_owned());
        }
    }
    out
}

/// Root identifiers of the route's middleware arguments, including member expressions
/// (`validators.group.rule` -> `validators`). The path string itself is ignored.
pub fn route_middleware_roots(source: &str, line: u32) -> Vec<String> {
    let Some(start) = line_offset(source, line as usize) else {
        return Vec::new();
    };
    let Some(prel) = source[start..].find('(') else {
        return Vec::new();
    };
    let popen = start + prel;
    let Some(pclose) = matching_close_paren(source, popen) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for arg in split_top_level_commas(&source[popen + 1..pclose]) {
        let root = arg.trim().split(['.', '(', '[', ' ']).next().unwrap_or("");
        if !root.is_empty()
            && root.bytes().all(is_ident)
            && root
                .bytes()
                .next()
                .is_some_and(|byte| !byte.is_ascii_digit())
            && !out.iter().any(|existing| existing == root)
        {
            out.push(root.to_owned());
        }
    }
    out
}

/// The text between the brackets of `const <name> = [ ... ]` (`let`/`var` too): the elements of a
/// declared array, used to read an express-validator chain list. Boundary-checked so `name` is not a
/// prefix of a longer identifier. `None` when `name` is not bound to an array literal here.
fn const_array_body(source: &str, name: &str) -> Option<String> {
    for keyword in ["const ", "let ", "var "] {
        let needle = format!("{keyword}{name}");
        let mut from = 0;
        while let Some(rel) = source[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            let after = &source[at + needle.len()..];
            // `name` must end here, not continue into a longer identifier.
            if after.bytes().next().is_some_and(is_ident) {
                continue;
            }
            let Some(rest) = after.trim_start().strip_prefix('=') else {
                continue;
            };
            let rest = rest.trim_start();
            if !rest.starts_with('[') {
                continue;
            }
            let open = source.len() - rest.len();
            let close = delimiter_close(source, open, b'[', b']')?;
            return Some(source[open + 1..close].to_owned());
        }
    }
    None
}

/// Whether `source` binds `name` to an array literal (`const name = [ ... ]`): a declared
/// express-validator chain list lives in the module that owns it.
pub fn defines_const_array(source: &str, name: &str) -> bool {
    const_array_body(source, name).is_some()
}

/// When a sink argument reads a property of a tainted object (`printer.logFilePath`) that the
/// application does not take from the request but *computes* from a different field of that object
/// (`{ logFilePath: path.join(dir, `${entry.id}.log`) }`), the request field that actually controls
/// the sink. `member` is the sink property name; `tainted` are the object aliases the taint flows
/// through (the callee parameter and the runtime object built from it, from the finding trace). Returns
/// the first `<alias>.<field>` the property's value expression reads (excluding `member` itself).
/// `None` when the property is not derived from a tainted alias's field — the common case where the
/// member genuinely is a request field, left to the ordinary resolver. Mined from the sink module
/// source; nothing is tied to a specific app.
pub fn derived_sink_field(sink_src: &str, member: &str, tainted: &[String]) -> Option<String> {
    let bytes = sink_src.as_bytes();
    let mut from = 0;
    while let Some(rel) = sink_src.get(from..)?.find(member) {
        let at = from + rel;
        from = at + member.len();
        let before = at.checked_sub(1).and_then(|i| bytes.get(i)).copied();
        if before.is_some_and(|b| is_ident(b) || b == b'.') {
            continue;
        }
        let after = sink_src.get(at + member.len()..).unwrap_or("").trim_start();
        let value = if let Some(rest) = after.strip_prefix(':') {
            rest.trim_start()
        } else if let Some(rest) = after.strip_prefix('=') {
            // An assignment (`x.logFilePath = ...`), but not `==`/`===`/`=>`.
            if rest.starts_with(['=', '>']) {
                continue;
            }
            rest.trim_start()
        } else {
            continue;
        };
        if let Some(field) = tainted_field_read(balanced_value(value), tainted, member) {
            return Some(field);
        }
    }
    None
}

/// The value expression at the start of `text`, up to the first top-level `,`, `;`, newline or closing
/// `}` (nesting of `()`, `[]`, `{}` respected). Isolates one object-literal property value or one
/// assignment right-hand side from the rest of the source.
fn balanced_value(text: &str) -> &str {
    let bytes = text.as_bytes();
    let (mut paren, mut bracket, mut brace) = (0i32, 0i32, 0i32);
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' if brace > 0 => brace -= 1,
            b'}' => break,
            b',' | b';' | b'\n' if paren == 0 && bracket == 0 && brace == 0 => break,
            _ => {}
        }
        i += 1;
    }
    text.get(..i).unwrap_or(text)
}

/// The first `<alias>.<field>` read in `expr` for an alias in `tainted`, excluding a field equal to
/// `exclude`. Whole-identifier match on the alias so `entry` does not match `entryList`.
fn tainted_field_read(expr: &str, tainted: &[String], exclude: &str) -> Option<String> {
    let bytes = expr.as_bytes();
    for alias in tainted {
        let needle = format!("{alias}.");
        let mut from = 0;
        while let Some(rel) = expr.get(from..)?.find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            let before = at.checked_sub(1).and_then(|i| bytes.get(i)).copied();
            if before.is_some_and(|b| is_ident(b) || b == b'.') {
                continue;
            }
            let field: String = expr
                .get(at + needle.len()..)
                .unwrap_or("")
                .bytes()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect();
            if !field.is_empty() && field != exclude {
                return Some(field);
            }
        }
    }
    None
}

/// The object fields a callee validates as required non-empty strings before the sink: a
/// `for (const f of <ARR>) { ... <alias>[f] ... return|throw ... }` loop that rejects when a listed
/// member is missing or not a string, where `<alias>` is one of the tainted aliases and `<ARR>` is a
/// module-level const array of field-name string literals. Returns those field names so the driving
/// request carries a filler for each and passes the callee's own validation. Empty when no such list
/// validator guards the body. Mined from the sink module source; nothing names a specific app.
pub fn object_required_string_fields(sink_src: &str, tainted: &[String]) -> Vec<String> {
    let bytes = sink_src.as_bytes();
    let mut from = 0;
    while let Some(rel) = sink_src.get(from..).and_then(|s| s.find("for")) {
        let at = from + rel;
        from = at + 3;
        if at
            .checked_sub(1)
            .and_then(|i| bytes.get(i))
            .copied()
            .is_some_and(is_ident)
        {
            continue;
        }
        let head = sink_src.get(at + 3..).unwrap_or("").trim_start();
        let Some(inner) = head.strip_prefix('(') else {
            continue;
        };
        let inner = inner.trim_start();
        let inner = ["const ", "let ", "var "]
            .iter()
            .find_map(|kw| inner.strip_prefix(kw))
            .unwrap_or(inner);
        let loopvar: String = inner
            .bytes()
            .take_while(|b| is_ident(*b))
            .map(|b| b as char)
            .collect();
        if loopvar.is_empty() {
            continue;
        }
        let after_var = inner.get(loopvar.len()..).unwrap_or("").trim_start();
        let Some(after_of) = after_var.strip_prefix("of ") else {
            continue;
        };
        let arr: String = after_of
            .trim_start()
            .bytes()
            .take_while(|b| is_ident(*b))
            .map(|b| b as char)
            .collect();
        if arr.is_empty() {
            continue;
        }
        let Some(brace_rel) = sink_src.get(at..).and_then(|s| s.find('{')) else {
            continue;
        };
        let brace = at + brace_rel;
        let Some(close) = delimiter_close(sink_src, brace, b'{', b'}') else {
            continue;
        };
        let body = sink_src.get(brace..=close).unwrap_or("");
        let indexes_alias = tainted
            .iter()
            .any(|alias| body.contains(&format!("{alias}[{loopvar}]")));
        let rejects =
            (body.contains("return") || body.contains("throw")) && body.contains("string");
        if indexes_alias
            && rejects
            && let Some(arr_body) = const_array_body(sink_src, &arr)
        {
            let fields = array_string_literals(&arr_body);
            if !fields.is_empty() {
                return fields;
            }
        }
    }
    Vec::new()
}

/// The non-empty string literals of a `[ "a", "b", ... ]` array body.
fn array_string_literals(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in body.split(',') {
        if let Some(value) = unquote(part.trim())
            && !value.is_empty()
        {
            out.push(value);
        }
    }
    out
}

/// The required body requirements of an express-validator array: for each `body("field")` /
/// `check("field")` chain in `array` that is not `.optional()`, the field and a type-valid filler.
fn validator_body_requirements(array: &str) -> Vec<(String, String)> {
    let starts = chain_starts(array);
    let mut out: Vec<(String, String)> = Vec::new();
    for (idx, (pos, field, builder)) in starts.iter().enumerate() {
        if builder != "body" && builder != "check" {
            continue;
        }
        let Some(field) = field else {
            continue;
        };
        let end = starts.get(idx + 1).map(|s| s.0).unwrap_or(array.len());
        let window = &array[*pos..end];
        // `.optional()` lets the field be absent, so the request is not rejected without it.
        if window.contains(".optional(") {
            continue;
        }
        if out.iter().all(|(k, _)| k != field) {
            out.push((field.clone(), validator_filler(field, window)));
        }
    }
    out
}

/// Every express-validator chain builder call in `array` (`body("x")`, `query(...)`, `check(...)`,
/// ...) as `(byte offset, first-string-literal argument, builder name)`, in source order. Used to
/// carve each chain's own window of chained assertions.
fn chain_starts(array: &str) -> Vec<(usize, Option<String>, String)> {
    let mut out: Vec<(usize, Option<String>, String)> = Vec::new();
    for builder in ["body", "check", "query", "param", "header", "cookie"] {
        let needle = format!("{builder}(");
        let mut from = 0;
        while let Some(rel) = array[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            // Not a member call (`.body(`) and not the tail of a longer identifier (`somebody(`).
            let before = at
                .checked_sub(1)
                .and_then(|i| array.as_bytes().get(i))
                .copied();
            if before.is_some_and(|b| is_ident(b) || b == b'.') {
                continue;
            }
            // A builder call that sits as the direct argument of another chain's method call
            // (`.if(query("timeframe").equals("custom"))`, `oneOf(query(...))`) is part of a
            // condition, not an independently required field: its field is not unconditionally
            // present. A genuine top-level chain element is preceded by `[`, `,`, `=`, `;`, `{`,
            // `>` (arrow body) or the start of the text, never by an opening `(`.
            let prefix = array[..at].trim_end();
            if let Some(before_open) = prefix.strip_suffix('(').map(str::trim_end)
                && before_open
                    .as_bytes()
                    .last()
                    .is_some_and(|b| is_ident(*b) || matches!(b, b'.' | b')'))
            {
                continue;
            }
            let field = leading_string(array[at + needle.len()..].trim_start());
            out.push((at, field, builder.to_owned()));
        }
    }
    out.sort_by_key(|s| s.0);
    out
}

/// A value that satisfies the type a validator chain declares for its field: a JSON array for
/// `.isArray`, the first `.isIn` alternative, a Mongo-id / email / number / boolean / URL filler for
/// the matching assertion, else the scalar `jsspector`. A JSON-literal return (array/number/boolean)
/// is emitted unquoted by the body builder; a scalar is quoted.
fn validator_filler(field: &str, window: &str) -> String {
    if window.contains(".isArray(") {
        return "[\"jsspector\"]".to_owned();
    }
    if window.contains(".isIn(")
        && let Some(literal) = first_isin_literal(window)
    {
        return literal;
    }
    if window.contains(".isInt(")
        || window.contains(".isNumeric(")
        || window.contains(".isFloat(")
        || window.contains(".isDecimal(")
    {
        return "1".to_owned();
    }
    if window.contains(".isBoolean(") {
        return "true".to_owned();
    }
    if window.contains(".isMongoId(") {
        return "18e5afe44388ba2819a79000".to_owned();
    }
    if window.contains(".isEmail(") {
        return "jss@jsspector.test".to_owned();
    }
    if is_urlish(field) {
        return "http://jss-filler.test/".to_owned();
    }
    "jsspector".to_owned()
}

/// JSON-safe neutral values declared by a Mongoose schema. These refine otherwise generic body
/// siblings so the request reaches the sink instead of failing model casting first (`coin: Number`
/// must receive a number, not the string `jsspector`). Only direct top-level schema properties are
/// considered; unknown and nested declarations are left untouched.
pub fn mongoose_schema_fillers(source: &str) -> Vec<(String, String)> {
    let Some(schema_at) = source.find(".Schema(").or_else(|| source.find("Schema(")) else {
        return Vec::new();
    };
    let after = &source[schema_at..];
    let Some(open) = after.find('{') else {
        return Vec::new();
    };
    let Some(object) = balanced_braces(&after[open + 1..]) else {
        return Vec::new();
    };
    split_top_level_commas(object)
        .into_iter()
        .filter_map(|property| {
            let (field, declaration) = property.split_once(':')?;
            let field = field.trim().trim_matches(['\'', '"']);
            if field.is_empty()
                || !field
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
            {
                return None;
            }
            let declaration = declaration.trim();
            let value = if declaration.starts_with("Number")
                || declaration.starts_with("mongoose.Schema.Types.Number")
            {
                "1".to_owned()
            } else if declaration.starts_with("Boolean") {
                "true".to_owned()
            } else if declaration.starts_with("[String") {
                "[\"jsspector\"]".to_owned()
            } else if declaration.starts_with("[Number") {
                "[1]".to_owned()
            } else if declaration.starts_with("String") {
                "jsspector".to_owned()
            } else if declaration.starts_with('{') {
                // A direct schema property commonly uses an options object. Prefer a declared enum
                // member (or string default) so generated sibling data passes model validation.
                let configured = declaration
                    .find("enum:")
                    .and_then(|at| {
                        declaration[at + "enum:".len()..]
                            .find('[')
                            .map(|n| at + "enum:".len() + n + 1)
                    })
                    .and_then(|at| leading_string(declaration[at..].trim_start()))
                    .or_else(|| {
                        declaration.find("default:").and_then(|at| {
                            leading_string(declaration[at + "default:".len()..].trim_start())
                        })
                    });
                configured?
            } else {
                return None;
            };
            Some((field.to_owned(), value))
        })
        .collect()
}

/// The first string-literal alternative of an `.isIn(["a", "b"])` assertion (`a`), returned as a bare
/// scalar. `None` when the argument is not a literal array of strings.
fn first_isin_literal(window: &str) -> Option<String> {
    let at = window.find(".isIn(")? + ".isIn(".len();
    let after = window[at..].trim_start();
    let open = after.find('[')?;
    leading_string(after[open + 1..].trim_start())
}

/// Parameter names read by explicit member access on a request part (`request.query.name`,
/// `req.body["name"]`): the parameters a handler names one by one. Reads through a local bound to the
/// whole part (`const cfg = req.body; cfg.host`) count too, so the fields a handler reads off such an
/// alias are recovered just like direct `req.body.host` reads.
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
    for alias in part_aliases(source, part) {
        out.extend(alias_member_reads(source, &alias));
    }
    out.sort();
    out.dedup();
    out
}

/// Local identifiers a handler binds to the whole request part (`const connectionConfig = req.body`,
/// `const q = request.query || {}`): their `.member` reads are reads of that part's fields. Mined from
/// the handler source only via [`locals_bound_from_expr`] over each request receiver; nothing here is
/// tied to a specific application.
fn part_aliases(source: &str, part: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for recv in ["req", "request", "ctx"] {
        for local in locals_bound_from_expr(source, &format!("{recv}.{part}")) {
            if !out.contains(&local) {
                out.push(local);
            }
        }
    }
    out
}

/// The member names read off a local `alias` by explicit member access (`alias.host`, `alias["port"]`),
/// with a word boundary before the alias so a longer identifier or another object's member is not
/// mistaken for it. Used to recover the request fields a handler reads through a whole-part alias.
fn alias_member_reads(source: &str, alias: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    for (needle, bracket) in [(format!("{alias}."), false), (format!("{alias}["), true)] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            if at > 0
                && bytes
                    .get(at - 1)
                    .is_some_and(|b| is_ident(*b) || *b == b'.')
            {
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
    // A prefix guard (`key.startsWith("sk-")`) on the sibling — or on a local derived from it — must
    // be satisfied for the branch holding the sink to run. Lead the generated filler with the required
    // prefix so the guard passes; the rest is an ordinary placeholder.
    if let Some(prefix) = prefix_literal(source, part, name) {
        return format!("{prefix}jsspector");
    }
    if let Some(value) = joi_field_filler(source, name) {
        return value;
    }
    if is_urlish(name) {
        // A syntactically valid absolute URL that does not resolve to the marker service, so it
        // passes a `URL.canParse` / `new URL()` guard without tripping the probe's own signal.
        return "http://jss-filler.test/".to_owned();
    }
    "jsspector".to_owned()
}

/// The route-handler block enclosing the finding source line. Callers that mine request siblings use
/// this instead of the whole module so fields read by unrelated routes do not leak into the probe.
pub fn handler_source(source: &str, line: u32) -> &str {
    handler_scope(source, line).unwrap_or(source)
}

/// The callback block that begins on or after a route registration line and contains the finding
/// source. This includes validation/schema setup immediately before an inner `try` block while still
/// excluding sibling routes in the same module.
pub fn route_handler_source(source: &str, route_line: u32, source_line: u32) -> &str {
    let Some(route_offset) = line_offset(source, route_line as usize) else {
        return handler_source(source, source_line);
    };
    let Some(source_offset) = line_offset(source, source_line as usize) else {
        return source;
    };
    let mut stack = Vec::new();
    for (at, byte) in source.bytes().enumerate().take(source_offset) {
        match byte {
            b'{' => stack.push(at),
            b'}' => {
                stack.pop();
            }
            _ => {}
        }
    }
    let Some(open) = stack.into_iter().find(|open| *open >= route_offset) else {
        return handler_source(source, source_line);
    };
    let Some(close) = matching_close_brace(source, open) else {
        return handler_source(source, source_line);
    };
    source.get(open..=close).unwrap_or(source)
}

fn joi_field_chain<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let bytes = source.as_bytes();
    let mut from = 0;
    while let Some(rel) = source[from..].find(name) {
        let at = from + rel;
        from = at + name.len();
        let before_ok = bytes
            .get(at.wrapping_sub(1))
            .is_none_or(|byte| !is_ident(*byte));
        let after = source.get(at + name.len()..)?;
        if !before_ok || after.bytes().next().is_some_and(is_ident) {
            continue;
        }
        let Some(rest) = after.trim_start().strip_prefix(':') else {
            continue;
        };
        let rest = rest.trim_start();
        if !rest.starts_with("Joi.") {
            continue;
        }
        let start = source.len() - rest.len();
        let end = statement_end(source, start);
        return source.get(start..end);
    }
    None
}

fn joi_field_is_optional(source: &str, name: &str) -> bool {
    joi_field_chain(source, name)
        .is_some_and(|chain| chain.contains(".default(") || chain.contains(".optional("))
}

fn joi_field_filler(source: &str, name: &str) -> Option<String> {
    let chain = joi_field_chain(source, name)?;
    if chain.contains(".boolean(") {
        return Some("true".to_owned());
    }
    if chain.contains(".array(") {
        return Some("[\"jsspector\"]".to_owned());
    }
    if chain.contains(".number(") || chain.contains(".integer(") {
        return Some("1".to_owned());
    }
    if chain.contains(".uri(") {
        return Some("http://jss-filler.test/".to_owned());
    }
    Some("jsspector".to_owned())
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

/// The string literal a `.startsWith(...)` guard on the sibling (or a local derived from it) requires
/// its value to begin with. `None` when the sibling is under no such prefix guard. Handles the common
/// rename-and-normalize shape (`const key = apiKey.trim(); if (!key.startsWith("sk-")) ...`): the
/// guarded receiver may be the sibling itself, an alias bound from `req.<part>.<name>`, or a local
/// assigned from the destructured sibling identifier.
fn prefix_literal(source: &str, part: &str, name: &str) -> Option<String> {
    let mut ids = aliases(source, part, name);
    ids.extend(derived_locals(source, name));
    ids.push(name.to_owned());
    let marker = ".startsWith(";
    let mut from = 0;
    while let Some(rel) = source[from..].find(marker) {
        let at = from + rel;
        from = at + marker.len();
        // The receiver is the expression immediately before `.startsWith`, back to the previous
        // boundary (`!key` -> `key`, `apiKey.trim()` -> mentions `apiKey`).
        let start = source[..at]
            .rfind(|c: char| "(!&|;{},=? \t\n".contains(c))
            .map(|i| i + 1)
            .unwrap_or(0);
        let receiver = &source[start..at];
        let Some(arg) = balanced_arg(&source[from..]) else {
            continue;
        };
        let Some(literal) = string_literal_value(arg.trim()) else {
            continue;
        };
        if !literal.is_empty() && ids.iter().any(|id| mentions(receiver, id)) {
            return Some(literal);
        }
    }
    None
}

/// Plain locals assigned from an expression that mentions the destructured sibling `name`
/// (`const key = apiKey.trim()` -> `key` for `name = apiKey`). Lets a guard on the renamed local be
/// traced back to the request sibling the verifier controls.
fn derived_locals(source: &str, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for keyword in ["const ", "let ", "var "] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(keyword) {
            let at = from + rel + keyword.len();
            from = at;
            let rest = &source[at..];
            let ident: String = rest.chars().take_while(|c| is_ident(*c as u8)).collect();
            if ident.is_empty() || ident == name {
                continue;
            }
            let tail = rest[ident.len()..].trim_start();
            let Some(rhs) = tail.strip_prefix('=').filter(|r| !r.starts_with('=')) else {
                continue;
            };
            let end = rhs.find(';').unwrap_or(rhs.len()).min(300);
            if mentions(&rhs[..end], name) {
                out.push(ident);
            }
        }
    }
    out
}

/// The length of a binding's right-hand side up to the statement boundary, honouring automatic
/// semicolon insertion. Scanning stops at a `;` at bracket depth 0, or at a newline at depth 0 that
/// is not a line continuation — the text so far does not end with an operator/opening bracket and the
/// next non-blank character does not begin a continuation (`.`, `?`, `:`, `)`, `]`, `}`, or a binary
/// operator). A balanced `(`/`[`/`{` keeps a multi-line object/array/call RHS together.
fn binding_rhs_end(rhs: &str) -> usize {
    let bytes = rhs.as_bytes();
    let mut depth = 0i32;
    let mut i = 0usize;
    let mut last_significant: Option<u8> = None;
    while let Some(byte) = bytes.get(i).copied() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth > 0 => depth -= 1,
            b';' if depth == 0 => return i,
            b'\n' if depth == 0 => {
                // A newline before any content is still part of the assignment (`const x =\n value`),
                // so it never ends the statement; otherwise continue only across an explicit operator
                // at either side of the break.
                let continues_before = last_significant.is_none_or(is_continuation_before);
                let next = rhs[i + 1..].bytes().find(|b| !b.is_ascii_whitespace());
                let continues_after = next.is_some_and(is_continuation_after);
                if !continues_before && !continues_after {
                    return i;
                }
            }
            _ => {}
        }
        if !byte.is_ascii_whitespace() {
            last_significant = Some(byte);
        }
        i += 1;
    }
    rhs.len()
}

/// Whether a line ending with `byte` continues onto the next line (a trailing operator or an open
/// bracket, so the statement is unfinished).
fn is_continuation_before(byte: u8) -> bool {
    matches!(
        byte,
        b'+' | b'-'
            | b'*'
            | b'/'
            | b'%'
            | b'&'
            | b'|'
            | b'^'
            | b'<'
            | b'>'
            | b'='
            | b','
            | b'.'
            | b'?'
            | b':'
            | b'('
            | b'['
            | b'{'
    )
}

/// Whether a line starting with `byte` continues the previous line (a leading operator, member
/// access, ternary arm, or a closing bracket of a multi-line expression).
fn is_continuation_after(byte: u8) -> bool {
    matches!(
        byte,
        b'.' | b'?'
            | b':'
            | b')'
            | b']'
            | b'}'
            | b'+'
            | b'-'
            | b'*'
            | b'/'
            | b'%'
            | b'&'
            | b'|'
            | b'^'
            | b'<'
            | b'>'
            | b'='
    )
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
            // A statement ends at `;`, or — under automatic semicolon insertion, common in
            // semicolon-free code — at a newline that is not a line continuation. Without ASI
            // handling a `var a = req.body.a` with no trailing `;` would swallow the following
            // statements and borrow their literals (`var b = req.body.b == "true" ? ...`),
            // pinning `a` to `"true"`. Capped so a runaway scan cannot read the whole file.
            let end = binding_rhs_end(rhs).min(300);
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
        // `id === 'lit'`. A `typeof id === 'string'` is a type guard, not a value constraint: the
        // literal names a JS type, not a value the parameter must equal, so skip it.
        let tail = source[after_idx..].trim_start();
        let after_typeof = source[..at].trim_end().ends_with("typeof");
        if !after_typeof
            && let Some(rest) = tail.strip_prefix("===").or_else(|| tail.strip_prefix("=="))
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

/// Branches of a query-selector dispatcher that forward a query member toward the request sink, for a
/// coarse `req.query`-sourced SSRF (see [`Probe::query_dispatch`]). A handler that binds the whole
/// request query to a local (`const q = req.query`) and dispatches on one of its fields — a
/// `switch (q.action) { case 'x': ... }` or an `if (q.action === 'x') { ... }` — reaches the request
/// sink only inside the matching branch, and chooses the outbound host through another query member it
/// reads there (`addonInfo(q.url)`). For each branch this returns the selector field, the branch's
/// literal value, and the other query members read inside it, so the verifier can drive the marker in
/// each member under the branch the selector chooses. A bounded scan of the handler source only; empty
/// when the handler has no such query dispatch, so nothing here is tied to one app.
pub fn query_dispatch_cases(source: &str) -> Vec<QueryDispatch> {
    const MAX: usize = 32;
    let receivers = query_receivers(source);
    if receivers.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<QueryDispatch> = Vec::new();
    for receiver in &receivers {
        switch_dispatch_cases(source, receiver, &receivers, &mut out);
        if_equality_dispatch_cases(source, receiver, &receivers, &mut out);
        if out.len() >= MAX {
            break;
        }
    }
    out.truncate(MAX);
    out
}

/// The receiver expressions through which a handler reads members of the request query: a local bound
/// from the whole query object (`const q = req.query` -> `q`) and the direct member form
/// (`req.query`/`request.query`) when the handler accesses it that way. Mined from the handler source
/// only.
fn query_receivers(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for prefix in ["req.query", "request.query"] {
        if source.contains(&format!("{prefix}.")) && !out.iter().any(|r| r == prefix) {
            out.push(prefix.to_owned());
        }
        for local in locals_bound_from_expr(source, prefix) {
            if !out.contains(&local) {
                out.push(local);
            }
        }
    }
    out
}

/// Locals a `const`/`let`/`var` binds to the whole expression `expr` (`const q = req.query || {}` ->
/// `q`): the declared name whose right-hand side begins with `expr` taken as a whole (not a member or
/// longer identifier of it). A destructuring binding (`const { x } = req.query`) names no such local
/// and is skipped. Mined from the handler source only.
fn locals_bound_from_expr(source: &str, expr: &str) -> Vec<String> {
    let mut out = Vec::new();
    for kw in ["const ", "let ", "var "] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(kw) {
            let at = from + rel;
            from = at + kw.len();
            if at > 0 && source.as_bytes().get(at - 1).is_some_and(|b| is_ident(*b)) {
                continue;
            }
            let after = &source[at + kw.len()..];
            let name: String = after
                .bytes()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect();
            if name.is_empty() {
                continue;
            }
            let rhs = after[name.len()..].trim_start();
            let Some(rhs) = rhs.strip_prefix('=') else {
                continue;
            };
            let rhs = rhs.trim_start();
            if let Some(tail) = rhs.strip_prefix(expr)
                && !tail
                    .chars()
                    .next()
                    .is_some_and(|c| c == '.' || c == '_' || c.is_ascii_alphanumeric())
            {
                out.push(name);
            }
        }
    }
    out
}

/// The field a `switch (<receiver>.<field>)` dispatches on, when the parenthesized condition is exactly
/// that member access and nothing more.
fn member_of(receiver: &str, expr: &str) -> Option<String> {
    let tail = expr.strip_prefix(receiver)?.strip_prefix('.')?;
    let field: String = tail
        .bytes()
        .take_while(|b| is_ident(*b))
        .map(|b| b as char)
        .collect();
    if field.is_empty()
        || field.len() != tail.len()
        || field.as_bytes().first().is_some_and(u8::is_ascii_digit)
    {
        return None;
    }
    Some(field)
}

/// Appends a [`QueryDispatch`] for each `case '<value>':` of a `switch (<receiver>.<field>)` whose body
/// reads another query member, to `out`. Mined from the handler source only.
fn switch_dispatch_cases(
    source: &str,
    receiver: &str,
    receivers: &[String],
    out: &mut Vec<QueryDispatch>,
) {
    let bytes = source.as_bytes();
    let mut from = 0;
    while let Some(rel) = source[from..].find("switch") {
        let kw = from + rel;
        from = kw + "switch".len();
        if kw > 0 && bytes.get(kw - 1).is_some_and(|b| is_ident(*b)) {
            continue;
        }
        if bytes.get(kw + 6).is_some_and(|b| is_ident(*b)) {
            continue;
        }
        let Some(popen) = source[kw + 6..].find('(').map(|r| kw + 6 + r) else {
            continue;
        };
        if !source[kw + 6..popen].trim().is_empty() {
            continue;
        }
        let Some(pclose) = matching_close_paren(source, popen) else {
            continue;
        };
        let cond = source[popen + 1..pclose].trim();
        let Some(field) = member_of(receiver, cond) else {
            continue;
        };
        let after = &source[pclose + 1..];
        let ws = after.len() - after.trim_start().len();
        if !after[ws..].starts_with('{') {
            continue;
        }
        let bopen = pclose + 1 + ws;
        let Some(bclose) = matching_close_brace(source, bopen) else {
            continue;
        };
        for (value, body) in switch_case_bodies(&source[bopen + 1..bclose]) {
            let params = members_read(body, receivers, &field);
            if !params.is_empty() {
                push_dispatch(out, &field, &value, params);
            }
        }
        from = bclose;
    }
}

/// Appends a [`QueryDispatch`] for each `if (<receiver>.<field> === '<value>')` whose block reads
/// another query member, to `out`. Covers a handler that dispatches with an if/else-if chain rather
/// than a switch. Mined from the handler source only.
fn if_equality_dispatch_cases(
    source: &str,
    receiver: &str,
    receivers: &[String],
    out: &mut Vec<QueryDispatch>,
) {
    let bytes = source.as_bytes();
    let mut i = 0usize;
    while i + 2 <= source.len() {
        let at_boundary = i == 0 || bytes.get(i - 1).is_some_and(|b| !is_ident(*b));
        if at_boundary
            && bytes.get(i) == Some(&b'i')
            && bytes.get(i + 1) == Some(&b'f')
            && bytes.get(i + 2).is_none_or(|b| !is_ident(*b))
            && let Some(popen) = source[i + 2..].find('(').map(|r| i + 2 + r)
            && source[i + 2..popen].trim().is_empty()
            && let Some(pclose) = matching_close_paren(source, popen)
        {
            let cond = &source[popen + 1..pclose];
            if let Some((field, value)) = equality_dispatch(receiver, cond) {
                let after = &source[pclose + 1..];
                let ws = after.len() - after.trim_start().len();
                if after[ws..].starts_with('{') {
                    let bopen = pclose + 1 + ws;
                    if let Some(bclose) = matching_close_brace(source, bopen) {
                        let params = members_read(&source[bopen + 1..bclose], receivers, &field);
                        if !params.is_empty() {
                            push_dispatch(out, &field, &value, params);
                        }
                    }
                }
            }
            i = popen + 1;
            continue;
        }
        i += 1;
    }
}

/// The `(field, value)` of an `<receiver>.<field> === '<value>'` equality (either operand order), or
/// `None` when the condition is not such a comparison against a string literal.
fn equality_dispatch(receiver: &str, cond: &str) -> Option<(String, String)> {
    for op in ["===", "=="] {
        if let Some((lhs, rhs)) = cond.split_once(op) {
            let (lhs, rhs) = (lhs.trim(), rhs.trim());
            if let Some(field) = member_of(receiver, lhs)
                && let Some(value) = string_literal_arg(rhs)
            {
                return Some((field, value));
            }
            if let Some(field) = member_of(receiver, rhs)
                && let Some(value) = string_literal_arg(lhs)
            {
                return Some((field, value));
            }
        }
    }
    None
}

/// The `(value, body)` of each top-level `case '<value>':` inside a switch block's inner text: the
/// string-literal label and the source between that label and the next `case`/`default` (or the end).
/// Nested braces, parens, brackets, strings and comments are skipped so a `case` token inside a nested
/// block or string is not mistaken for a label.
fn switch_case_bodies(body: &str) -> Vec<(String, &str)> {
    let bytes = body.as_bytes();
    let len = bytes.len();
    // (label value or None for `default`, keyword start, body start)
    let mut markers: Vec<(Option<String>, usize, usize)> = Vec::new();
    let mut depth = 0i32;
    let mut i = 0usize;
    let byte = |at: usize| bytes.get(at).copied();
    while i < len {
        let Some(c) = byte(i) else {
            break;
        };
        match c {
            b'{' | b'(' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b')' | b']' => {
                depth -= 1;
                i += 1;
            }
            b'"' | b'\'' | b'`' => {
                i += 1;
                while i < len && byte(i) != Some(c) {
                    if byte(i) == Some(b'\\') {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < len && byte(i) != Some(b'\n') {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < len && !(byte(i) == Some(b'*') && byte(i + 1) == Some(b'/')) {
                    i += 1;
                }
                i += 2;
            }
            _ if depth == 0
                && !i.checked_sub(1).and_then(byte).is_some_and(is_ident)
                && (body[i..].starts_with("case")
                    && bytes.get(i + 4).is_some_and(|b| !is_ident(*b))) =>
            {
                let after = &body[i + 4..];
                if let Some(colon_rel) = after.find(':') {
                    let label = after[..colon_rel].trim();
                    let body_start = i + 4 + colon_rel + 1;
                    markers.push((string_literal_arg(label), i, body_start));
                    i = body_start;
                    continue;
                }
                i += 1;
            }
            _ if depth == 0
                && !i.checked_sub(1).and_then(byte).is_some_and(is_ident)
                && body[i..].starts_with("default")
                && bytes.get(i + 7).is_some_and(|b| !is_ident(*b)) =>
            {
                if let Some(colon_rel) = body[i + 7..].find(':') {
                    let body_start = i + 7 + colon_rel + 1;
                    markers.push((None, i, body_start));
                    i = body_start;
                    continue;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    let mut out = Vec::new();
    for (idx, (value, _, body_start)) in markers.iter().enumerate() {
        let Some(value) = value else {
            continue;
        };
        let end = markers.get(idx + 1).map(|(_, kw, _)| *kw).unwrap_or(len);
        if *body_start <= end {
            out.push((value.clone(), &body[*body_start..end]));
        }
    }
    out
}

/// The distinct query members a branch reads through any query `receiver` (`q.url` -> `url`), other
/// than the selector field `exclude`. The outbound host of the request sink is chosen through one of
/// these, so each is a candidate to carry the marker. Mined from the branch source only.
fn members_read(body: &str, receivers: &[String], exclude: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for receiver in receivers {
        let needle = format!("{receiver}.");
        let mut from = 0;
        while let Some(rel) = body[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            if at > 0 && body.as_bytes().get(at - 1).is_some_and(|b| is_ident(*b)) {
                continue;
            }
            let member: String = body[at + needle.len()..]
                .bytes()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect();
            if member.is_empty()
                || member.as_bytes().first().is_some_and(u8::is_ascii_digit)
                || member == exclude
                || out.contains(&member)
            {
                continue;
            }
            out.push(member);
        }
    }
    out
}

/// Records a dispatch branch, merging its members into an existing `(selector, value)` entry rather
/// than duplicating it.
fn push_dispatch(out: &mut Vec<QueryDispatch>, selector: &str, value: &str, params: Vec<String>) {
    if let Some(existing) = out
        .iter_mut()
        .find(|d| d.selector == selector && d.value == value)
    {
        for param in params {
            if !existing.params.contains(&param) {
                existing.params.push(param);
            }
        }
        return;
    }
    out.push(QueryDispatch {
        selector: selector.to_owned(),
        value: value.to_owned(),
        params,
    });
}

/// The prefix a plug-in-style app mounts a module's routes under, when the module declares it as
/// a literal: `mountPath: "/auth"`, `mountPath = '/auth'`, or a module header saying its REST
/// surface is "mounted at /api/cells". The routes are registered on a router the host mounts at
/// that path at startup, which no call in the module shows. A prose-derived prefix is only a request
/// candidate: an inaccurate comment can make verification miss, but cannot produce a verified hit.
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

    // Small router modules often document the host-owned mount in their header instead of exposing
    // it as executable metadata. Keep this deliberately narrow: only a literal absolute path
    // immediately following "mounted at/under" qualifies, and never accept route syntax or prose.
    for line in source.lines().take(40) {
        let lower = line.to_ascii_lowercase();
        for marker in ["mounted at", "mounted under"] {
            let Some(at) = lower.find(marker) else {
                continue;
            };
            let rest = line[at + marker.len()..].trim_start();
            let value: String = rest
                .chars()
                .take_while(|c| !c.is_whitespace() && !matches!(c, '`' | '"' | '\'' | ',' | ';'))
                .collect();
            let value = value.trim_end_matches(['.', ')', ']', '}', ':', '/']);
            if value.starts_with('/')
                && value.len() > 1
                && !value.contains(['$', ' ', '{', '*', ':', '?', '#'])
            {
                return Some(value.to_owned());
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
    gate_paths_at(source, 16)
        .into_iter()
        .map(|(_, path)| path)
        .collect()
}

/// Dispatch paths nearest to the finding's same-file flow positions. A monolithic raw HTTP handler
/// can compare dozens of routes before the branch that calls the sink helper; the route comparison
/// adjacent to a trace step is substantially more likely to reach that sink than an earlier,
/// unrelated branch. Stable source order breaks equal-distance ties. Empty anchors deliberately
/// produce no guesses, leaving [`gate_paths`] as the fallback.
pub fn gate_paths_near(source: &str, anchor_lines: &[u32]) -> Vec<String> {
    const MAX: usize = 16;
    if anchor_lines.is_empty() {
        return Vec::new();
    }
    let mut gates = gate_paths_at(source, usize::MAX);
    gates.sort_by_key(|(at, _)| {
        let line = source[..*at].bytes().filter(|byte| *byte == b'\n').count() as u32 + 1;
        anchor_lines
            .iter()
            .map(|anchor| anchor.abs_diff(line))
            .min()
            .unwrap_or(u32::MAX)
    });
    gates.truncate(MAX);
    gates.into_iter().map(|(_, path)| path).collect()
}

/// Dispatch paths whose branch reads a URL-shaped query parameter. Large catch-all handlers often
/// contain hundreds of route comparisons, so the global first-N path list can omit the one that
/// actually forwards a URL. Pair each direct `searchParams.get("url-like")` read with the nearest
/// preceding path gate and put those routes ahead of the broad fallback list. The bounded distance
/// prevents a parameter in an unrelated later function from inheriting an old route comparison.
pub fn url_query_gate_paths(source: &str) -> Vec<String> {
    const MAX: usize = 16;
    const BRANCH_WINDOW: usize = 4096;
    let gates = gate_paths_at(source, usize::MAX);
    let mut out = Vec::new();
    for needle in [".get(", ".getAll("] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(needle) {
            let at = from + rel;
            from = at + needle.len();
            if !source[..at].trim_end().ends_with("searchParams") {
                continue;
            }
            let Some(arg) = balanced_arg(&source[from..]) else {
                continue;
            };
            let Some(name) = unquote(arg.trim()) else {
                continue;
            };
            if !is_urlish(&name) {
                continue;
            }
            let Some((_, gate)) = gates
                .iter()
                .rev()
                .find(|(pos, _)| *pos <= at && at.saturating_sub(*pos) <= BRANCH_WINDOW)
            else {
                continue;
            };
            if !out.contains(gate) {
                out.push(gate.clone());
                if out.len() == MAX {
                    return out;
                }
            }
        }
    }
    out
}

fn gate_paths_at(source: &str, max: usize) -> Vec<(usize, String)> {
    let mut out: Vec<String> = Vec::new();
    let mut positions = Vec::new();
    let mut push = |at: usize, value: &str| {
        let value = value.trim_end_matches('/');
        if value.len() > 1
            && value.starts_with('/')
            && !value.contains(['$', ' ', '{', '}', '*', ':', '\\', '\n'])
            && !out.iter().any(|existing| existing == value)
            && out.len() < max
        {
            out.push(value.to_owned());
            positions.push((at, value.to_owned()));
        }
    };
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let Some(&c) = bytes.get(i) else {
            break;
        };
        // Skip comments so an apostrophe inside one (`// Anivexa's getMedia`) is not mistaken for a
        // string-literal opener, which would swallow real path comparisons until the next quote.
        if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            i += 2;
            while i < bytes.len() && bytes.get(i) != Some(&b'\n') {
                i += 1;
            }
            continue;
        }
        if c == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len()
                && !(bytes.get(i) == Some(&b'*') && bytes.get(i + 1) == Some(&b'/'))
            {
                i += 1;
            }
            i += 2;
            continue;
        }
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
                    || before.ends_with("indexOf(")
                    || before.ends_with("lastIndexOf(")
                    || after.starts_with("===")
                    || after.starts_with("==")
                    || after.starts_with("].includes(");
                if compared && literal.starts_with('/') {
                    push(i, literal);
                }
                i += 1 + end + 1;
                continue;
            }
        }
        i += 1;
    }
    positions
}

/// The query-parameter names a handler reads off the parsed request URL's search parameters, for an
/// SSRF whose source is the whole request URL (`req.url`). The common parsed-query shapes are mined
/// from the handler's own source: a member read off a variable bound from either the standard URL
/// search parameters or Node's legacy `querystring.parse(...)`
/// (`const query = Object.fromEntries(url.searchParams); ... query.base` -> `base`) and a direct
/// `searchParams.get("name")` / `.getAll("name")`. The attacker chooses the outbound host through one
/// of these, so the marker URL is tried in each. Deduplicated and bounded; empty when the request URL
/// feeds no query parameter here. Not tied to any one app: it reads the standard `URLSearchParams`
/// shape from the handler's own code.
pub fn url_search_params(source: &str) -> Vec<String> {
    const MAX: usize = 16;
    // Discover beyond the report cap before ranking. In a monolithic router the URL-bearing field
    // may occur after many pagination/filter fields; truncating during discovery makes a dynamic
    // proof impossible even though the exact parameter is present in source.
    const DISCOVERY_MAX: usize = 256;
    let mut out: Vec<String> = Vec::new();
    // Node applications predating `URLSearchParams` commonly parse `url.parse(req.url).query`
    // through the built-in `querystring` module and then read the resulting object's members. Mine
    // this explicit whole-URL parse before broader `searchParams` uses elsewhere in a large module;
    // otherwise unrelated helpers can consume the bounded candidate list before the handler's
    // actual parameter is reached.
    for var in vars_bound_from(source, "querystring.parse") {
        for member in object_members(source, &var) {
            push_param(&mut out, &member, DISCOVERY_MAX);
        }
    }
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
                push_param(&mut out, &name, DISCOVERY_MAX);
            }
        }
    }
    // A variable bound from an expression mentioning `searchParams`, then every member read off it.
    for var in vars_bound_from(source, "searchParams") {
        for member in object_members(source, &var) {
            push_param(&mut out, &member, DISCOVERY_MAX);
        }
    }
    for name in manual_split_param_reads(source) {
        push_param(&mut out, &name, DISCOVERY_MAX);
    }
    // A member read inline off the object form of the search parameters, with no intermediate
    // variable (`Object.fromEntries(url.searchParams).url` -> `url`, or the bracket form
    // `Object.fromEntries(url.searchParams)["url"]`). The variable-binding shape above misses this
    // because the member is read directly on the `fromEntries` call. `Object.fromEntries` over
    // `URLSearchParams` is the standard idiom for turning query parameters into a plain object, so
    // nothing here is tied to one app.
    let mut from = 0;
    while let Some(rel) = source[from..].find("fromEntries(") {
        let open = from + rel + "fromEntries(".len();
        from = open;
        let Some(arg) = balanced_arg(&source[open..]) else {
            continue;
        };
        if !arg.contains("searchParams") {
            continue;
        }
        // `balanced_arg` stops just before the closing paren, so the member access follows it.
        let Some(after) = source[open + arg.len()..].strip_prefix(')') else {
            continue;
        };
        let after = after.trim_start();
        if let Some(rest) = after.strip_prefix('.') {
            let name: String = rest
                .bytes()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect();
            if !name.is_empty() {
                push_param(&mut out, &name, DISCOVERY_MAX);
            }
        } else if after.starts_with('[')
            && let Some(key) = bracket_key(after)
            && !key.is_empty()
        {
            push_param(&mut out, &key, DISCOVERY_MAX);
        }
    }
    // Stable: URL-shaped names lead, while relative source order is retained inside each group.
    out.sort_by_key(|name| !is_urlish(name));
    out.truncate(MAX);
    out
}

/// Additional query-parameter names reached when a parsed-query object is not read in this handler
/// but forwarded whole into a called function, which reads its fields
/// (`const params = Object.fromEntries(url.searchParams); renderStoryPng(params)` and, in the
/// callee, `fetch(params.coinIcon)` -> `coinIcon`). For each variable bound from the search
/// parameters, each call that passes it as a whole argument is resolved to the callee's definition
/// (local, or imported — via `resolve`), the argument is mapped to the callee's parameter by
/// position, and that parameter's members are mined from the callee body. One call hop; the attacker
/// still chooses the outbound host through one of these. Deduplicated and bounded; empty when the
/// object is not forwarded or the callee cannot be resolved. Mined from the handler and callee source
/// only, so nothing here is tied to one app.
pub fn forwarded_search_params(
    source: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
    anchor_lines: &[u32],
) -> Vec<String> {
    const MAX: usize = 16;
    let mut out: Vec<String> = Vec::new();
    let mut calls: Vec<(String, usize, u32)> = Vec::new();
    for marker in ["searchParams", "querystring.parse"] {
        for var in vars_bound_from(source, marker) {
            push_forwarding_calls(&mut calls, forwarding_calls(source, &var));
        }
    }
    // The parsed query object can be passed inline without ever receiving a local name:
    // `serveSongAudio(Object.fromEntries(url.searchParams), res)`. Follow that argument into the
    // callee exactly like a named object. Restrict the match to standard query-object construction,
    // rather than treating every argument that merely mentions `searchParams` as one whole object.
    push_forwarding_calls(
        &mut calls,
        forwarding_calls_matching(source, |arg| {
            (arg.contains("Object.fromEntries") && arg.contains("searchParams"))
                || arg.contains("querystring.parse")
        }),
    );
    if !anchor_lines.is_empty() {
        calls.sort_by_key(|(_, _, line)| {
            anchor_lines
                .iter()
                .map(|anchor| anchor.abs_diff(*line))
                .min()
                .unwrap_or(u32::MAX)
        });
    }
    for (callee, pos, _) in calls {
        let Some(module) = resolve(&callee) else {
            continue;
        };
        let Some(param) = nth_param(&module, &callee, pos) else {
            continue;
        };
        let Some(body) = function_body(&module, &callee) else {
            continue;
        };
        for member in object_members(&body, &param) {
            push_param(&mut out, &member, MAX);
        }
    }
    out
}

fn push_forwarding_calls(out: &mut Vec<(String, usize, u32)>, calls: Vec<(String, usize, u32)>) {
    for call in calls {
        if !out
            .iter()
            .any(|(callee, pos, _)| callee == &call.0 && *pos == call.1)
        {
            out.push(call);
        }
    }
}

fn forwarding_calls_matching(
    source: &str,
    matches: impl Fn(&str) -> bool,
) -> Vec<(String, usize, u32)> {
    const KEYWORDS: [&str; 9] = [
        "if", "for", "while", "switch", "catch", "return", "function", "await", "typeof",
    ];
    let mut out: Vec<(String, usize, u32)> = Vec::new();
    let mut from = 0;
    while let Some(rel) = source[from..].find('(') {
        let open = from + rel;
        from = open + 1;
        let before = source[..open].trim_end();
        let name_start = before.len() - before.bytes().rev().take_while(|b| is_ident(*b)).count();
        let callee = &before[name_start..];
        if callee.is_empty() || KEYWORDS.contains(&callee) {
            continue;
        }
        let Some(arglist) = balanced_arg(&source[open + 1..]) else {
            continue;
        };
        for (pos, arg) in split_top_level_commas(arglist).iter().enumerate() {
            if matches(arg.trim()) {
                let entry = (
                    callee.to_owned(),
                    pos,
                    source[..open].bytes().filter(|b| *b == b'\n').count() as u32 + 1,
                );
                if !out
                    .iter()
                    .any(|(existing, existing_pos, _)| existing == callee && *existing_pos == pos)
                {
                    out.push(entry);
                }
            }
        }
    }
    out
}

/// Calls in `source` that pass `var` as one whole argument (`renderStoryPng(params, assets)` for
/// `var = "params"` -> `("renderStoryPng", 0, line)`): the plain-identifier callee, the zero-based
/// position `var` occupies in its argument list, and the call line. A control-flow keyword before
/// `(` (`if (params)`) is not a callee. Deduplicated by (callee, position).
fn forwarding_calls(source: &str, var: &str) -> Vec<(String, usize, u32)> {
    forwarding_calls_matching(source, |arg| arg == var)
}

/// The identifier of the `pos`-th parameter of the function named `name` in `source`
/// (`renderStoryPng(params, assets)`, `pos = 0` -> `params`). A default value is stripped; a
/// destructured or rest parameter yields `None`, as does a missing function or position.
fn nth_param(source: &str, name: &str, pos: usize) -> Option<String> {
    let list = function_param_list(source, name)?;
    let raw = split_top_level_commas(&list).into_iter().nth(pos)?;
    let base = raw.split('=').next().unwrap_or(&raw).trim();
    if base.is_empty()
        || base.as_bytes().first().is_some_and(u8::is_ascii_digit)
        || !base.bytes().all(is_ident)
    {
        return None;
    }
    Some(base.to_owned())
}

/// Resolve a coarse whole-query source through one local helper and into the parameter that the
/// sink actually consumes. A common shape is `helper(req.query)`, followed by a destructure inside
/// the helper and a call into the sink's module. Static analysis can conservatively report
/// `req.query`, but driving the first query member it sees may exercise a branch selector rather
/// than the dangerous argument. This returns the sink-bound request field plus the sibling values
/// needed by enclosing equality/presence guards.
///
/// The resolution is source-derived: the sink function and parameter come from the sink line and
/// argument, the call argument is mapped through an object destructure, and guard literals are read
/// from the two function bodies. Nothing is tied to a route or application name.
pub fn forwarded_query_context(
    route_source: &str,
    sink_source: &str,
    sink_line: u32,
    sink_argument: &str,
) -> Option<(String, Vec<(String, String)>)> {
    let sink_name = enclosing_function_name(sink_source, sink_line)?;
    let sink_params = split_top_level_commas(&function_param_list(sink_source, &sink_name)?)
        .into_iter()
        .map(|param| param.split('=').next().unwrap_or(&param).trim().to_owned())
        .collect::<Vec<_>>();
    let target_pos = sink_params.iter().position(|param| {
        !param.is_empty() && param.bytes().all(is_ident) && mentions(sink_argument, param)
    })?;

    let (call_at, call_args) = named_call_arguments(route_source, &sink_name, target_pos + 1)?;
    let target_local = call_args.get(target_pos)?.trim();
    if target_local.is_empty() || !target_local.bytes().all(is_ident) {
        return None;
    }
    let (caller_open, caller_close) = enclosing_function_block(route_source, call_at)?;
    let caller_line = route_source[..call_at]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count() as u32
        + 1;
    let caller_name = enclosing_function_name(route_source, caller_line)?;
    let caller_body = &route_source[caller_open + 1..caller_close];
    let caller_params = split_top_level_commas(&function_param_list(route_source, &caller_name)?)
        .into_iter()
        .map(|param| param.split('=').next().unwrap_or(&param).trim().to_owned())
        .filter(|param| !param.is_empty() && param.bytes().all(is_ident))
        .collect::<Vec<_>>();

    let mut bindings: Vec<(String, String)> = Vec::new(); // (field, local)
    for object in &caller_params {
        for pair in destructured_fields_of(caller_body, object) {
            if !bindings.contains(&pair) {
                bindings.push(pair);
            }
        }
    }
    // Also map locals assigned directly from req.query.<field>, including the caller's branch
    // selector (`const provider = req.query.provider`).
    for field in member_params(route_source, "query") {
        for local in aliases(route_source, "query", &field) {
            let pair = (field.clone(), local);
            if !bindings.contains(&pair) {
                bindings.push(pair);
            }
        }
    }
    let target_field = bindings
        .iter()
        .find_map(|(field, local)| (local == target_local).then(|| field.clone()))?;

    let mut siblings: Vec<(String, String)> = Vec::new();
    let mut add = |field: String, value: String| {
        if field != target_field && siblings.iter().all(|(seen, _)| seen != &field) {
            siblings.push((field, value));
        }
    };

    // Guards in the helper that calls the sink: branch selectors and required companion fields.
    for (local, literal) in enclosing_guards(route_source, caller_line) {
        if let Some((field, _)) = bindings.iter().find(|(_, bound)| bound == &local) {
            add(
                field.clone(),
                literal.unwrap_or_else(|| validator_filler(field, "")),
            );
        }
    }
    for local in presence_guard_fields(route_source, &[caller_line]) {
        if let Some((field, _)) = bindings.iter().find(|(_, bound)| bound == &local) {
            add(field.clone(), validator_filler(field, ""));
        }
    }

    // A guard inside the sink function can constrain a sibling argument (`store ===
    // 'gcp-secret'`). Map its formal position back through this call and then through the helper's
    // destructure to the original request field.
    for (pos, param) in sink_params.iter().enumerate() {
        if pos == target_pos || param.is_empty() || !param.bytes().all(is_ident) {
            continue;
        }
        let Some(value) = equality_literal(sink_source, param) else {
            continue;
        };
        let Some(local) = call_args.get(pos).map(|arg| arg.trim()) else {
            continue;
        };
        if let Some((field, _)) = bindings.iter().find(|(_, bound)| bound == local) {
            add(field.clone(), value);
        }
    }

    Some((target_field, siblings))
}

fn enclosing_function_name(source: &str, line: u32) -> Option<String> {
    let offset = line_offset(source, line as usize)?;
    let (open, _) = enclosing_function_block(source, offset)?;
    let before = source[..open].trim_end();
    let close = before.rfind(')')?;
    let paren = matching_open_paren(source, close)?;
    let head = source[..paren].trim_end();
    let name: String = head
        .bytes()
        .rev()
        .take_while(|byte| is_ident(*byte))
        .map(|byte| byte as char)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (!name.is_empty()).then_some(name)
}

fn named_call_arguments(source: &str, name: &str, minimum: usize) -> Option<(usize, Vec<String>)> {
    let bytes = source.as_bytes();
    let mut from = 0;
    while let Some(rel) = source[from..].find(name) {
        let at = from + rel;
        from = at + name.len();
        if at > 0 && bytes.get(at - 1).is_some_and(|byte| is_ident(*byte)) {
            continue;
        }
        if bytes
            .get(at + name.len())
            .is_some_and(|byte| is_ident(*byte))
        {
            continue;
        }
        let rest = &source[at + name.len()..];
        let ws = rest.len() - rest.trim_start().len();
        let open = at + name.len() + ws;
        if bytes.get(open) != Some(&b'(') {
            continue;
        }
        let prefix = source[..at].trim_end();
        if prefix.ends_with("function") || prefix.ends_with("function*") {
            continue;
        }
        let close = matching_close_paren(source, open)?;
        let args = split_top_level_commas(&source[open + 1..close]);
        if args.len() >= minimum {
            return Some((at, args));
        }
    }
    None
}

/// For a URL-sourced forward proxy / file sink that reads several query parameters off the parsed
/// request URL, the value each parameter needs so the request reaches the sink instead of a guard's
/// early return — each parameter paired with its filler. A parameter the handler only tests for
/// presence (`if (!type) return`) gets a non-empty placeholder; one it pins to a value gets that
/// value: a string literal it is compared against (`===`) or matched by (`/^(a|b)$/.test`), or, when
/// it indexes an object the handler then requires (`const f = FILTERS[type]; if (!f) return`), a key
/// of that object — resolved from an imported module (`resolve`) when the object is defined
/// elsewhere. A URL-shaped name gets a syntactically valid non-marker URL. Mined from the handler and
/// resolved module source only, so nothing here is tied to one app.
pub fn url_query_fillers(
    source: &str,
    params: &[String],
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    params
        .iter()
        .map(|param| (param.clone(), query_filler_value(source, param, resolve)))
        .collect()
}

fn query_filler_value(
    source: &str,
    param: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> String {
    let mut ids = vec![param.to_owned()];
    if let Some(var) = searchparam_var(source, param)
        && var != param
    {
        ids.push(var);
    }
    for id in &ids {
        if let Some(lit) = regex_literal(source, id).or_else(|| equality_literal(source, id)) {
            return lit;
        }
    }
    if let Some(key) = object_index_key(source, &ids, resolve) {
        return key;
    }
    if is_urlish(param) {
        return "http://jss-filler.test/".to_owned();
    }
    "jsspector".to_owned()
}

/// The local variable a handler binds a search parameter to
/// (`const type = searchParams.get("type")` -> `type`), so a guard written against that variable can
/// be found. `None` when the parameter is read inline without a binding, or not bound to a plain name.
fn searchparam_var(source: &str, param: &str) -> Option<String> {
    let bytes = source.as_bytes();
    for needle in [".get(", ".getAll("] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(needle) {
            let at = from + rel;
            from = at + needle.len();
            if !source[..at].trim_end().ends_with("searchParams") {
                continue;
            }
            let Some(arg) = balanced_arg(&source[at + needle.len()..]) else {
                continue;
            };
            if unquote(arg.trim()).as_deref() != Some(param) {
                continue;
            }
            // Walk back over the receiver chain (`url.searchParams` / `searchParams`) to its start,
            // then read the identifier it is assigned to.
            let mut i = at;
            while i
                .checked_sub(1)
                .and_then(|previous| bytes.get(previous))
                .is_some_and(|byte| is_ident(*byte) || *byte == b'.')
            {
                i -= 1;
            }
            if let Some(var) = assigned_target(source, i) {
                return Some(var);
            }
        }
    }
    None
}

/// Object identifiers a handler indexes by one of `ids` (`FILTERS[type]` -> `FILTERS`): the receiver
/// immediately before `[<id>]`. First-seen and deduplicated.
fn index_receivers(source: &str, ids: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for id in ids {
        let pat = format!("[{id}]");
        let mut from = 0;
        while let Some(rel) = source[from..].find(&pat) {
            let at = from + rel;
            from = at + pat.len();
            let recv: String = source[..at]
                .bytes()
                .rev()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            if recv
                .as_bytes()
                .first()
                .is_some_and(|byte| !byte.is_ascii_digit())
                && !out.contains(&recv)
            {
                out.push(recv);
            }
        }
    }
    out
}

/// A key of an object the handler indexes by a search parameter and then requires
/// (`const f = FILTERS[type]; if (!f) return`): the object's first literal key, so the probe sends a
/// value the lookup accepts. The object is read from this source, or — when imported — from the module
/// `resolve` returns for its name. `None` when no such object/key is found.
fn object_index_key(
    source: &str,
    ids: &[String],
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    for obj in index_receivers(source, ids) {
        if let Some(key) = first_object_key(source, &obj) {
            return Some(key);
        }
        if let Some(module) = resolve(&obj)
            && let Some(key) = first_object_key(&module, &obj)
        {
            return Some(key);
        }
    }
    None
}

/// The first literal key of an object bound to `ident` (`const FILTERS = { "a-b": ..., c: ... }` ->
/// `a-b`), skipping comments. `None` when `ident` is not bound to an object literal, or the object has
/// no leading literal key.
fn first_object_key(source: &str, ident: &str) -> Option<String> {
    let bytes = source.as_bytes();
    let mut from = 0;
    while let Some(rel) = source[from..].find(ident) {
        let at = from + rel;
        from = at + ident.len();
        let before_ok = at == 0 || bytes.get(at - 1).is_none_or(|b| !is_ident(*b));
        if !before_ok {
            continue;
        }
        let after = &source[at + ident.len()..];
        if after.chars().next().is_some_and(|c| is_ident(c as u8)) {
            continue;
        }
        let Some(rest) = after.trim_start().strip_prefix('=') else {
            continue;
        };
        if rest.starts_with('=') {
            continue;
        }
        let Some(body) = rest.trim_start().strip_prefix('{') else {
            continue;
        };
        if let Some(key) = first_key_in_object(body) {
            return Some(key);
        }
    }
    None
}

/// The first property key inside an object body (just past its `{`): a quoted key (`"a-b"`) or a
/// bareword key (`foo`) followed by `:`. Line and block comments are skipped. `None` when the first
/// token is not a plain key (an empty object, a spread, a computed key).
fn first_key_in_object(body: &str) -> Option<String> {
    let mut rest = body;
    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix("//") {
            rest = after.split_once('\n').map_or("", |(_, r)| r);
            continue;
        }
        if let Some(after) = rest.strip_prefix("/*") {
            rest = after.split_once("*/").map_or("", |(_, r)| r);
            continue;
        }
        break;
    }
    let first = rest.chars().next()?;
    if matches!(first, '"' | '\'' | '`') {
        let key = leading_string(rest)?;
        let after = rest.get(1 + key.len() + 1..)?.trim_start();
        return after.starts_with(':').then_some(key);
    }
    let key: String = rest
        .bytes()
        .take_while(|b| is_ident(*b))
        .map(|b| b as char)
        .collect();
    if key.is_empty() {
        return None;
    }
    let after = rest[key.len()..].trim_start();
    after.starts_with(':').then_some(key)
}

/// The parenthesized parameter list of a function named `name` defined in `source`: the first `(`
/// after a `function name` / `const name =` / `name =` marker (and before any `{`), read balanced.
/// `None` when no such definition is found.
fn function_param_list(source: &str, name: &str) -> Option<String> {
    let markers = [
        format!("function {name}"),
        format!("function* {name}"),
        format!("const {name}"),
        format!("let {name}"),
        format!("var {name}"),
        format!("{name} ="),
    ];
    for marker in &markers {
        let mut from = 0;
        while let Some(rel) = source[from..].find(marker.as_str()) {
            let at = from + rel;
            from = at + marker.len();
            if at > 0 && source.as_bytes().get(at - 1).is_some_and(|b| is_ident(*b)) {
                continue;
            }
            let after = &source[at + marker.len()..];
            if marker.bytes().last().is_some_and(is_ident)
                && after.bytes().next().is_some_and(is_ident)
            {
                continue;
            }
            let Some(open) = after.find('(') else {
                continue;
            };
            if after[..open].contains('{') {
                continue;
            }
            if let Some(list) = balanced_arg(&after[open + 1..]) {
                return Some(list.to_owned());
            }
        }
    }
    None
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
/// Only the binding's own initializer is examined (see [`statement_rhs`]), so a semicolon-free
/// (ASI) file does not bleed one binding's right-hand side into the following statements and mistake
/// an unrelated local for one bound from `needle`. A binding only (single `=`), never a comparison.
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
            if statement_rhs(rhs).contains(needle) && !out.contains(&ident) {
                out.push(ident);
            }
        }
    }
    out
}

/// The initializer on the right of a binding, up to the end of its statement: the first `;`, or —
/// absent one (ASI) — the first newline at bracket depth 0 outside any string. Capped so a
/// pathological line is still bounded. A multi-line initializer stays intact because its unbalanced
/// brackets (`Object.fromEntries(\n  url.searchParams\n)`) keep the depth above 0 across the
/// newlines, while a plain `const x = f()` on one line ends at its newline instead of running on.
fn statement_rhs(rhs: &str) -> &str {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in rhs.char_indices() {
        if i >= 300 {
            return &rhs[..rhs.floor_char_boundary(i)];
        }
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ';' | '\n' if depth <= 0 => return &rhs[..i],
            _ => {}
        }
    }
    rhs
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

/// The absolute static path literals of every route registered to a given handler method in a
/// route-registration source: for `router.put("/a", c.save).put("/b", c.save)` and method `save`,
/// `["/a", "/b"]`. For each whole-word occurrence of `method`, the enclosing call's first string-
/// literal argument is the registered path. Only fixed absolute paths are kept — a literal with a
/// `:param`, `{slot}`, wildcard or interpolation is skipped, since a sibling with an unfilled slot
/// could not be driven. Mined from the route source only; nothing here is target-specific.
pub fn handler_route_literals(source: &str, method: &str) -> Vec<String> {
    if method.is_empty() {
        return Vec::new();
    }
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = source[from..].find(method) {
        let at = from + rel;
        from = at + method.len();
        let before = at.checked_sub(1).and_then(|i| bytes.get(i)).copied();
        if before.is_some_and(is_ident) {
            continue;
        }
        if bytes.get(at + method.len()).copied().is_some_and(is_ident) {
            continue;
        }
        // Scan back to the `(` that opens the call this handler reference is an argument of.
        let mut depth = 0i32;
        let mut open = None;
        let mut i = at;
        while i > 0 {
            i -= 1;
            let Some(byte) = bytes.get(i).copied() else {
                break;
            };
            match byte {
                b')' | b']' | b'}' => depth += 1,
                b'(' if depth == 0 => {
                    open = Some(i);
                    break;
                }
                b'(' | b'[' | b'{' => depth -= 1,
                _ => {}
            }
        }
        let Some(open) = open else { continue };
        if let Some(lit) = leading_string(source[open + 1..at].trim_start())
            && lit.starts_with('/')
            && lit.len() > 1
            && !lit.contains(['$', ' ', '{', '}', '*', ':'])
        {
            let lit = lit.trim_end_matches('/').to_owned();
            if !out.contains(&lit) {
                out.push(lit);
            }
        }
    }
    out
}

/// The full request paths of the sibling routes among `literals`, given the probe's own full `current`
/// path: the literal `current` ends with identifies the live route, and the segment before it is the
/// mount prefix the other literals share. For `current = "/api/v2/settings/layermenu"` and literals
/// `["/layermenu", "/mapsettings"]`, `["/api/v2/settings/mapsettings"]`. Empty when `current` matches
/// none of the literals (so the prefix is unknown). Nothing here is target-specific.
pub fn sibling_paths(current: &str, literals: &[String]) -> Vec<String> {
    // Each literal starts with `/`, so `ends_with` already lands on a clean path-segment boundary;
    // prefer the longest match so a `/a` literal does not win over `/settings/a`.
    let Some(matched) = literals
        .iter()
        .filter(|lit| lit.starts_with('/') && current.ends_with(lit.as_str()))
        .max_by_key(|lit| lit.len())
    else {
        return Vec::new();
    };
    let prefix = &current[..current.len() - matched.len()];
    literals
        .iter()
        .filter(|lit| lit.as_str() != matched.as_str())
        .map(|lit| format!("{prefix}{lit}"))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FormDataAccess {
    field: String,
    local: Option<String>,
    file: bool,
}

/// The multipart shape for a named body field read through `Request.formData()`. Returns `None`
/// unless the handler both calls `.formData()` and reads the target with `.get("target")`. A target
/// that is itself consumed as a `File` is deliberately left unsupported: driving a file-name taint
/// requires controlling the multipart filename, whereas this descriptor drives a textual field.
pub fn multipart_form(source: &str, target: &str) -> Option<MultipartForm> {
    let accesses = form_data_accesses(source);
    let target_access = accesses.iter().find(|access| access.field == target)?;
    if target_access.file {
        return None;
    }
    let mut fields = Vec::new();
    let mut file_fields = Vec::new();
    for access in accesses {
        if access.field == target {
            continue;
        }
        if !fields.contains(&access.field) {
            fields.push(access.field.clone());
        }
        if access.file && !file_fields.contains(&access.field) {
            file_fields.push(access.field);
        }
    }
    Some(MultipartForm {
        fields,
        file_fields,
    })
}

/// A specific named field read from a Web `FormData` object. The taint engine reports the source as
/// the coarse `request.formData()` call, so ordinary `req.body.name` member matching cannot locate
/// the payload. Prefer a `.get()` binding named by the trace/sink; when there is exactly one textual
/// field (the rest are file parts), it is unambiguous and can be driven directly.
fn form_data_entry(finding: &Finding, source: Option<&str>) -> Option<Entry> {
    if !finding.source.expr.contains("formData(") {
        return None;
    }
    let accesses = form_data_accesses(source?);
    let mut tainted: Vec<String> = finding
        .trace
        .iter()
        .filter_map(|step| {
            step.note
                .strip_prefix("assigned to `")?
                .strip_suffix('`')
                .map(str::to_owned)
        })
        .collect();
    tainted.extend(identifier_tokens(&finding.sink.arg));
    if let Some(access) = accesses.iter().find(|access| {
        !access.file
            && access
                .local
                .as_ref()
                .is_some_and(|local| tainted.contains(local))
    }) {
        return Some(Entry::Body(Some(access.field.clone())));
    }
    let textual: Vec<&FormDataAccess> = accesses.iter().filter(|access| !access.file).collect();
    match textual.as_slice() {
        [only] => Some(Entry::Body(Some(only.field.clone()))),
        _ => None,
    }
}

/// Every `const local = form.get("field")` access for a value returned by a Web
/// `request.formData()` call. File/Blob fields are recognized only from strong uses (`arrayBuffer`,
/// `stream`, `text`, or `instanceof File/Blob`), so an ordinary text part is never promoted merely
/// because of its name.
fn form_data_accesses(source: &str) -> Vec<FormDataAccess> {
    let mut form_locals: Vec<String> = Vec::new();
    let mut from = 0;
    while let Some(rel) = source[from..].find(".formData(") {
        let at = from + rel;
        from = at + ".formData(".len();
        if let Some(local) = assigned_identifier_before(source, at)
            && !form_locals.contains(&local)
        {
            form_locals.push(local);
        }
    }
    let mut out: Vec<FormDataAccess> = Vec::new();
    for form in form_locals {
        let needle = format!("{form}.get(");
        let mut from = 0;
        while let Some(rel) = source[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            let open = at + needle.len() - 1;
            let Some(close) = matching_close_paren(source, open) else {
                continue;
            };
            let Some(field) = unquote(source[open + 1..close].trim()) else {
                continue;
            };
            if !safe_form_field(&field) {
                continue;
            }
            let local = assigned_identifier_before(source, at);
            let direct_tail = source[close + 1..].trim_start();
            let file = ["arrayBuffer", "stream", "text"].iter().any(|method| {
                direct_tail.starts_with(&format!(".{method}("))
                    || local
                        .as_deref()
                        .is_some_and(|name| identifier_member_call(source, name, method))
            }) || local.as_deref().is_some_and(|name| {
                identifier_instanceof(source, name, "File")
                    || identifier_instanceof(source, name, "Blob")
            });
            if let Some(existing) = out.iter_mut().find(|access| access.field == field) {
                existing.file |= file;
                if existing.local.is_none() {
                    existing.local = local;
                }
            } else {
                out.push(FormDataAccess { field, local, file });
            }
        }
    }
    out
}

/// The identifier assigned immediately before a call (`const file = form.get(...)` -> `file`).
/// Restricting this to a simple declaration/assignment in the same statement avoids treating a
/// comparison or callback expression as a binding.
fn assigned_identifier_before(source: &str, at: usize) -> Option<String> {
    let prefix = source.get(..at)?;
    let eq = prefix.rfind('=')?;
    if prefix.as_bytes().get(eq.wrapping_sub(1)) == Some(&b'=')
        || prefix.as_bytes().get(eq + 1) == Some(&b'>')
    {
        return None;
    }
    let start = prefix[..eq]
        .rfind([';', '\n', '{', '}'])
        .map_or(0, |index| index + 1);
    let lhs = prefix[start..eq].trim();
    let name = lhs
        .split_whitespace()
        .last()?
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$');
    (!name.is_empty()
        && name.bytes().all(is_ident)
        && name
            .as_bytes()
            .first()
            .is_some_and(|byte| !byte.is_ascii_digit()))
    .then(|| name.to_owned())
}

fn safe_form_field(field: &str) -> bool {
    !field.is_empty()
        && field.len() <= 128
        && field.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'[' | b']')
        })
}

fn identifier_member_call(source: &str, name: &str, method: &str) -> bool {
    let needle = format!("{name}.{method}(");
    source.match_indices(&needle).any(|(at, _)| {
        source[..at]
            .bytes()
            .next_back()
            .is_none_or(|byte| !is_ident(byte))
    })
}

fn identifier_instanceof(source: &str, name: &str, class: &str) -> bool {
    let needle = format!("{name} instanceof {class}");
    source.match_indices(&needle).any(|(at, _)| {
        source[..at]
            .bytes()
            .next_back()
            .is_none_or(|byte| !is_ident(byte))
    })
}

/// The most specific request entry among the finding's sink argument and source expression: a
/// named query/body/path/header parameter is preferred over a whole-object body or the raw URL.
fn best_entry(finding: &Finding, path: &str, source: Option<&str>) -> Option<Entry> {
    if let Some(entry) = form_data_entry(finding, source) {
        return Some(entry);
    }
    // A Hono handler reads its request through method calls on a context object (`c.req.param('id')`,
    // `c.req.query('q')`, `c.req.header('x')`), and often destructures the whole-params object
    // (`const { module: mod } = c.req.param()`). The generic member-access logic names none of these,
    // so resolve the Hono shape first.
    if let Some(entry) = hono_entry(finding, path, source) {
        return Some(entry);
    }
    // A Web Fetch / Next.js App Router handler parses its body with a method call on the request
    // object (`const { token } = await request.json()`). The engine records the source as the bare
    // parse call, which names no field; resolve the destructured body key that carries taint.
    if let Some(entry) = web_body_entry(finding, source) {
        return Some(entry);
    }
    // A file-based route's dynamic segment is merged into the request parameters, so a handler that
    // reads it via `req.query.<name>` is reading the URL path. Driving it as a query string is
    // overridden by the real path segment and never reaches the sink, so this placement wins.
    if let Some(entry) = file_route_path_param(finding, path, source) {
        return Some(entry);
    }
    // A coarse `req.params` source whose specific tainted segment is the identifier the sink string
    // interpolates (`FROM ${tableName}`): resolve it to that route slot when the handler binds the
    // identifier from the request params (destructured or accessed) and the route declares the slot.
    // Mirrors `coarse_params_entry` for the destructured shape, and disambiguates a handler that reads
    // several path params by pinning the one that actually reaches the sink.
    if let Some(entry) = params_sink_entry(finding, path, source) {
        return Some(entry);
    }
    // A source the engine named by the bare request part (`query`) because the handler destructures
    // the whole part off the request (`let { query, body } = req`), not through a `req.query` member
    // access: resolve the specific field of that part that carries taint to the sink.
    if let Some(entry) = bare_part_entry(finding, path, source) {
        return Some(entry);
    }
    // A coarse member source (`req.query`) the engine recorded without the specific field — the
    // handler reads `req.query.<name>` and forwards it to a callee whose parameter the sink names:
    // resolve the field whose name the flow trace records the value being assigned to.
    if let Some(entry) = coarse_part_field_entry(finding, path, source) {
        return Some(entry);
    }
    // A coarse `req.body`/`req.query` source whose specific member is read only in a callee, where the
    // whole part was bound to the callee's parameter (`testTrinoConnection(req.body)` then `config
    // .galaxyDomain` in the sink). The handler source never shows `req.body.<member>`, but the sink
    // argument interpolates `<tainted>.<member>` where `<tainted>` is an alias of the whole part
    // recorded in the flow trace. Resolve that member so the payload rides the exact field the sink
    // reads instead of a generic default or the vaguer whole-part body.
    if let Some(entry) = coarse_sink_member_entry(finding, path) {
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
    if let Some(entry) = destructured_entry(finding, path, source) {
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
        .or_else(|| destructured_entry(finding, path, source))
        .or_else(|| coarse_params_entry(finding, path, source))
        .or_else(|| source.and_then(|src| coarse_header_entry(finding, src)))
}

/// When the finding's source is a bare request part (`query`/`body`/`params`/`headers`) — the name
/// a handler binds by destructuring the request object itself (`let { query, body } = req`) rather
/// than through a `req.query` member access — the specific field of that part that carries taint to
/// the sink. The field is read from the part by a further destructuring (`let { tenant, id } =
/// query`); the finding's trace names the local it flows through (`id`), so among the part's
/// destructured fields the one whose local is tainted is the attacker input. Returns the request
/// entry for that field, or `None`. Mined from the handler source only.
fn bare_part_entry(finding: &Finding, path: &str, source: Option<&str>) -> Option<Entry> {
    let part = finding.source.expr.trim();
    if !matches!(part, "query" | "body" | "params" | "headers") {
        return None;
    }
    // Only when the source is the bare part; a source that already carries a receiver (`req.query`)
    // is handled by the generic member-access logic.
    if strip_request_receiver(part).is_some() {
        return None;
    }
    let src = source?;
    // The part must itself be destructured off the request object, so `query` here really is
    // `req.query` and not an unrelated local that happens to share the name.
    let from_request = ["req", "request", "ctx"].iter().any(|recv| {
        destructured_fields_of(src, recv)
            .iter()
            .any(|(field, local)| field == part || local == part)
    });
    if !from_request {
        return None;
    }
    let tainted = tainted_identifiers(finding, &Entry::Url);
    for (field, local) in destructured_fields_of(src, part) {
        if tainted.contains(&local)
            && let Some(entry) = source_entry(&format!("request.{part}.{field}"), path)
        {
            return Some(entry);
        }
    }
    None
}

/// When the finding's source is a coarse request member with a receiver but no specific field
/// (`req.query`, `req.body`, `req.params`, `req.headers`) — the engine recorded only the part the
/// handler reads, not the member — the specific field of that part that reaches the sink. The handler
/// reads `req.<part>.<name>` and forwards it (commonly into a callee whose parameter the sink argument
/// names); the finding's flow trace records that value being `assigned to \`<name>\``, so among the
/// part's accessors in the handler source the one whose field is a tainted identifier is the attacker
/// input. Returns that request entry, or `None`. Mined from the handler source only; nothing here is
/// tied to a specific target.
fn coarse_part_field_entry(finding: &Finding, path: &str, source: Option<&str>) -> Option<Entry> {
    let part = strip_request_receiver(finding.source.expr.trim())?;
    // Only a bare part with no member of its own (`req.query`); `req.query.name` already carries the
    // field and is resolved by the generic member-access logic, and a call/bracket form is not a part.
    if !matches!(part, "query" | "body" | "params" | "headers" | "header") {
        return None;
    }
    let whole = source?;
    // Resolve the coarse part's field from the handler that actually reaches the sink, not the whole
    // file: a sibling route elsewhere in the same module may read `req.body.<other>` (a CSRF token on
    // an unrelated endpoint), and the single-field fallback below would otherwise pick that unrelated
    // member instead of the field this handler reads. Scope to the enclosing block of the source line
    // when it can be isolated; fall back to the whole file when it cannot.
    let src = handler_scope(whole, finding.source.line).unwrap_or(whole);
    let tainted = tainted_identifiers(finding, &Entry::Url);
    // The distinct fields of this part the handler actually reads (`req.query.q` -> `q`), in source
    // order. A field whose name is itself a tainted identifier (the handler destructured it, so the
    // field and the local coincide) pins the attacker input directly.
    let mut fields: Vec<String> = Vec::new();
    for accessor in request_accessors(src) {
        let Some(chain) = strip_request_receiver(&accessor) else {
            continue;
        };
        let mut segments = chain.split('.');
        if segments.next() != Some(part) {
            continue;
        }
        let Some(field) = segments
            .next()
            .filter(|field| !field.is_empty() && field.bytes().all(is_ident))
        else {
            continue;
        };
        if tainted.iter().any(|name| name == field)
            && let Some(entry) = source_entry(&format!("request.{part}.{field}"), path)
        {
            return Some(entry);
        }
        if !fields.iter().any(|f| f == field) {
            fields.push(field.to_owned());
        }
    }
    // No field name coincided with a tainted local — the handler read the member into a differently
    // named local (`let criteria = req.query.q`, so the trace's tainted local is `criteria`, not `q`).
    // When the handler reads exactly one distinct field of this part, that field is unambiguously where
    // the coarse-part taint enters, so drive it; with several fields there is nothing to disambiguate
    // them and we leave it to the generic ranking rather than guess. Restricted to directly
    // attacker-placeable parts: a header is resolved by its own request-target logic (`coarse_header_
    // entry`), which handles non-identifier names and rejects a header that sits in no sink position.
    if matches!(part, "query" | "body" | "params")
        && let [only] = fields.as_slice()
    {
        return source_entry(&format!("request.{part}.{only}"), path);
    }
    None
}

/// When the finding's source is a coarse request part with no specific member (`req.body`, `req.query`)
/// and the sink argument interpolates `<tainted>.<member>` — a member access on an identifier the flow
/// trace records the whole part being assigned to (`const connectionConfig = req.body;
/// testTrinoConnection(connectionConfig)` then `config.galaxyDomain` at the sink) — the request entry
/// for that `<member>`. This resolves the field a cross-function sink reads off the part even though the
/// handler source never shows `req.<part>.<member>` directly. Keyed on the sink argument and the flow
/// trace only; nothing here is tied to a specific application.
fn coarse_sink_member_entry(finding: &Finding, path: &str) -> Option<Entry> {
    let part = strip_request_receiver(finding.source.expr.trim()).or_else(|| {
        matches!(finding.source.expr.trim(), "body" | "query").then_some(finding.source.expr.trim())
    })?;
    // Only a bare part with no member of its own; a source that already names the member is resolved by
    // the generic member-access logic.
    if !matches!(part, "body" | "query") {
        return None;
    }
    let tainted = tainted_identifiers(finding, &Entry::Url);
    let arg = finding.sink.arg.as_str();
    for ident in &tainted {
        for member in alias_member_reads(arg, ident) {
            if let Some(entry) = source_entry(&format!("request.{part}.{member}"), path) {
                return Some(entry);
            }
        }
    }
    None
}

/// The `(field, local)` pairs a `const { a, b: c, ...rest } = <rhs>` destructuring binds, where
/// `<rhs>` is exactly the identifier `rhs`: `{ a }` yields `("a", "a")`, `{ b: c }` yields
/// `("b", "c")`. Boundary-checked so `query` does not also match `req.query`, `queryText` or a
/// `.query` member tail. Mined from the handler source only.
fn destructured_fields_of(source: &str, rhs: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut from = 0;
    while let Some(rel) = source[from..].find(rhs) {
        let at = from + rel;
        from = at + rhs.len();
        let before = at.checked_sub(1).and_then(|i| bytes.get(i)).copied();
        if before.is_some_and(|b| is_ident(b) || b == b'.') {
            continue;
        }
        let after = bytes.get(at + rhs.len()).copied();
        if after.is_some_and(|b| is_ident(b) || b == b'.' || b == b'[' || b == b'(') {
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
            let entry = entry.trim().trim_start_matches("...").trim();
            if entry.is_empty() {
                continue;
            }
            let (field, local) = match entry.split_once(':') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => (entry, entry),
            };
            let local = local.split('=').next().unwrap_or(local).trim();
            if !field.is_empty()
                && field.bytes().all(is_ident)
                && !local.is_empty()
                && local.bytes().all(is_ident)
            {
                out.push((field.to_owned(), local.to_owned()));
            }
        }
    }
    out
}

/// The tainted path parameter when the sink's own argument interpolates a route-slot identifier the
/// handler binds from the request parameters. The finding's source must be a request parameter, the
/// sink argument must interpolate an identifier (`${name}` in the query template, or `+ name +`
/// concatenation) that the route declares a `{name}` slot for and the handler derives from
/// `req.params` (destructured `const { name } = req.params`, accessed `req.params.name`, or recorded
/// in the flow trace as `assigned to \`name\``). This pins the exact segment that reaches the sink,
/// instead of the first params member the handler happens to read. `None` when nothing lines up.
fn params_sink_entry(finding: &Finding, path: &str, source: Option<&str>) -> Option<Entry> {
    let receiver = strip_request_receiver(finding.source.expr.trim());
    if receiver != Some("params") && finding.source.expr.trim() != "params" {
        return None;
    }
    let derived = params_derived_names(finding, source);
    for name in interpolated_identifiers(&finding.sink.arg) {
        if path.contains(&format!("{{{name}}}")) && derived.contains(&name) {
            return Some(Entry::PathParam(name));
        }
    }
    // A path param passed as a positional argument rather than interpolated (`path.join(base,
    // '../client', filePath)`): a params-derived identifier the route declares a slot for and the
    // sink argument names as a bare token. The route slot keeps this from matching an unrelated local.
    let tokens = identifier_tokens(&finding.sink.arg);
    for name in &derived {
        if path.contains(&format!("{{{name}}}")) && tokens.contains(name) {
            return Some(Entry::PathParam(name.clone()));
        }
    }
    None
}

/// The identifiers a handler binds from the request params: locals destructured from `req.params`
/// (`const { a, b } = req.params`), members read off it (`req.params.a`), and names the finding's
/// flow trace records the params value being `assigned to`.
fn params_derived_names(finding: &Finding, source: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for step in &finding.trace {
        if let Some(rest) = step.note.strip_prefix("assigned to `")
            && let Some(name) = rest.strip_suffix('`')
            && !name.is_empty()
            && name.bytes().all(is_ident)
        {
            out.push(name.to_owned());
        }
    }
    if let Some(src) = source {
        out.extend(destructured_fields(src, "params"));
        for accessor in request_accessors(src) {
            if let Some(rest) = strip_request_receiver(&accessor) {
                let mut parts = rest.split('.');
                if parts.next() == Some("params")
                    && let Some(name) = parts.next()
                    && !name.is_empty()
                    && name.bytes().all(is_ident)
                {
                    out.push(name.to_owned());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The plain identifiers a string argument interpolates: each `${name}` template placeholder and each
/// `+ name +` / `+ name` concatenation operand that is a bare identifier. Complex expressions
/// (`${a.b}`, `${f(x)}`) are ignored — only a lone identifier names a single request value a route
/// slot can carry. Used to find which tainted segment the sink's own text builds in.
fn interpolated_identifiers(arg: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = arg.as_bytes();
    // `${ identifier }` template placeholders.
    let mut rest = arg;
    while let Some(at) = rest.find("${") {
        let after = &rest[at + 2..];
        let end = after.find('}').unwrap_or(after.len());
        let inner = after[..end].trim();
        if !inner.is_empty() && inner.bytes().all(is_ident) {
            out.push(inner.to_owned());
        }
        rest = &after[end.min(after.len())..];
    }
    // `+ identifier +` / `+ identifier` concatenation operands.
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte == b'+' {
            let mut j = i + 1;
            while bytes.get(j).is_some_and(|byte| byte.is_ascii_whitespace()) {
                j += 1;
            }
            let start = j;
            while bytes.get(j).is_some_and(|byte| is_ident(*byte)) {
                j += 1;
            }
            if j > start {
                let name = &arg[start..j];
                // Must be a lone operand: followed by whitespace then `+`, `)`, `,` or end.
                let mut k = j;
                while bytes.get(k).is_some_and(|byte| byte.is_ascii_whitespace()) {
                    k += 1;
                }
                let boundary = bytes
                    .get(k)
                    .is_none_or(|byte| matches!(byte, b'+' | b')' | b',' | b';'));
                let leads = start > 0 && bytes.get(start - 1).is_some_and(|byte| !is_ident(*byte));
                if boundary && leads && !name.chars().next().unwrap_or('0').is_ascii_digit() {
                    out.push(name.to_owned());
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out.sort();
    out.dedup();
    out
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

/// The shell quote character a command-injection sink interpolates its tainted value inside, read
/// from the sink argument's source text. A command is built either by concatenation
/// (`'open "' + folder + '"'`) or a template literal (`` `open "${folder}"` ``); in both the literal
/// text that precedes the first interpolation determines the open quote the value sits within. The
/// preceding literal is scanned tracking single/double quote state (a quote toggles its own state
/// only when not inside the other), and the state still open at the interpolation point is returned:
/// `"` or `'`, or `None` when the value is unquoted. Nothing here is target-specific — it reads only
/// the argument's own quoting.
fn shell_quote_context(arg: &str) -> Option<char> {
    let prefix = command_literal_prefix(arg)?;
    let mut in_single = false;
    let mut in_double = false;
    for ch in prefix.chars() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            _ => {}
        }
    }
    match (in_single, in_double) {
        (true, _) => Some('\''),
        (_, true) => Some('"'),
        _ => None,
    }
}

/// The shell quoting a tainted command value reaches after simple string transforms in the trace.
///
/// `JSON.stringify(userValue)` always emits a double-quoted JavaScript string. That does not make
/// the value shell-safe: POSIX shells still perform command substitution inside double quotes. By
/// recording this as a double-quoted command context, the payload generator can add `$()` probes
/// instead of trying only separators, which stay inert inside the generated quotes.
fn command_quote_context(finding: &Finding) -> Option<char> {
    shell_quote_context(&finding.sink.arg).or_else(|| {
        finding
            .trace
            .iter()
            .any(|step| step.note.contains("JSON.stringify"))
            .then_some('"')
    })
}

/// The runtime shell text a command-injection sink argument emits *before* the tainted interpolation.
/// For a template literal (`` `cmd "${x}"` ``) it is the characters up to that `${...}`, with every
/// intervening interpolation skipped (its runtime value is opaque, so it contributes no quote state);
/// for a concatenation (`'cmd "' + x`) it is the first string literal's decoded contents. The tainted
/// interpolation is taken to be the last `${...}` whose body is a plain variable/member read — one with
/// no call `(`, since helper interpolations such as `${fnFile("ids.js")}` are transforms, not the
/// attacker value (`` `node ${fnFile("ids.js")} '${query}'` `` -> the `'` opened just before
/// `${query}`). Falls back to the first interpolation when none is a plain read. Only the common `\"`,
/// `\'`, `` \` `` and `\\` escapes are unescaped, which is enough to track shell quote state. `None`
/// when no leading string literal is found (the value is the whole argument, or a bare variable).
fn command_literal_prefix(arg: &str) -> Option<String> {
    let arg = arg.trim_start();
    let bytes = arg.as_bytes();
    let first = *bytes.first()?;
    if first != b'`' {
        // A concatenation (`'cmd "' + x`): the first string literal's decoded contents.
        let open = match first {
            b'\'' | b'"' => first,
            _ => return None,
        };
        let mut out = String::new();
        let mut chars = arg[1..].chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => {
                    if let Some(next) = chars.next() {
                        out.push(next);
                    }
                }
                c if c as u32 == open as u32 => return Some(out),
                c => out.push(c),
            }
        }
        return Some(out);
    }
    // A template literal: accumulate literal text, skipping each `${...}` interpolation (its braces
    // balanced), and record the literal prefix at the first interpolation and at the last plain-read
    // interpolation (the tainted value). Prefer the latter.
    let mut literal = String::new();
    let mut first_prefix: Option<String> = None;
    let mut tainted_prefix: Option<String> = None;
    let mut chars = arg[1..].chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(next) = chars.next() {
                    literal.push(next);
                }
            }
            '`' => break,
            '$' if chars.peek() == Some(&'{') => {
                chars.next();
                let mut depth = 1usize;
                let mut body = String::new();
                for c in chars.by_ref() {
                    match c {
                        '{' => {
                            depth += 1;
                            body.push(c);
                        }
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                            body.push(c);
                        }
                        _ => body.push(c),
                    }
                }
                if first_prefix.is_none() {
                    first_prefix = Some(literal.clone());
                }
                if !body.contains('(') {
                    tainted_prefix = Some(literal.clone());
                }
            }
            c => literal.push(c),
        }
    }
    // A template literal with no interpolation is a constant command: no tainted prefix.
    Some(tainted_prefix.or(first_prefix).unwrap_or(literal))
}

/// Whether a sink API enumerates a directory's entries (rather than reading a file's bytes):
/// `fs.readdirSync`, `fs.promises.readdir`, `fs.opendirSync`. For these the traversal proof is a
/// planted file name appearing in the listing, not file content. Framework-agnostic: keyed on the
/// standard filesystem API name alone.
fn sink_lists_directory(api: &str) -> bool {
    let lower = api.to_ascii_lowercase();
    lower.contains("readdir") || lower.contains("opendir") || lower.contains("scandir")
}

/// Whether a NoSQL sink API *filters* existing documents — the `find`/`update`/`delete`/`count`
/// family a Mongoose model or MongoDB collection exposes — as opposed to inserting new ones
/// (`insertOne`, `insertMany`, `create`, `save`). An injected operator only changes what such a
/// filtering query matches, so the differential needs a pre-existing record the query selects and
/// the siblings the filter ANDs in must stay constant across probes. Keyed on the final `.`-segment
/// of the API name so it is driver-agnostic; defaults to filtering for an unrecognized query method,
/// since an unknown name is far more likely a read/update than an insert.
fn sink_filters_documents(api: &str) -> bool {
    let name = api.rsplit('.').next().unwrap_or(api).to_ascii_lowercase();
    !(name.starts_with("insert")
        || name == "create"
        || name == "insert"
        || name == "save"
        || name == "bulkwrite")
}

/// Whether a NoSQL sink changes existing records rather than only reading/filtering them.
fn sink_mutates_documents(api: &str) -> bool {
    let name = api.rsplit('.').next().unwrap_or(api).to_ascii_lowercase();
    name.contains("update")
        || name.contains("delete")
        || name.contains("remove")
        || name.contains("replace")
        || name == "findandmodify"
        || name == "bulkwrite"
}

/// Request handlers can insert the submitted document before a tainted lookup and mutate the
/// selected record afterwards (registration/referral flows are the common shape). Return those two
/// effects separately: the first requires unique probe identities, while the second enables the
/// database-state oracle even though the tainted sink itself is read-only.
fn nosql_handler_effects(source: &str, sink_line: u32, route_line: Option<u32>) -> (bool, bool) {
    let handler = route_line
        .map(|route_line| route_handler_source(source, route_line, sink_line))
        .unwrap_or_else(|| handler_source(source, sink_line));
    let handler_start = handler.as_ptr() as usize - source.as_ptr() as usize;
    let Some(sink_start) = line_offset(source, sink_line as usize) else {
        return (false, false);
    };
    let split = sink_start.saturating_sub(handler_start).min(handler.len());
    let (before, after) = handler.split_at(split);
    let inserts = [".create(", ".insertOne(", ".insertMany(", ".save("]
        .iter()
        .any(|needle| before.contains(needle));
    let mutates = [
        ".update",
        ".findOneAndUpdate(",
        ".findByIdAndUpdate(",
        ".delete",
        ".remove(",
        ".replace",
        ".bulkWrite(",
    ]
    .iter()
    .any(|needle| after.contains(needle));
    (inserts, mutates)
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

/// Whether a removing sink API only operates on a *directory* (`fs.rmdir(Sync)`): the delete proof
/// must plant a directory, not a file, since `rmdir` on a plain file errors (`ENOTDIR`) and the
/// destructive differential would never fire. `fs.unlink`/`fs.rm` remove a file, so they stay file-
/// based. Keyed on the final `.`-segment of the API name, so it is framework-agnostic.
fn sink_removes_dir(api: &str) -> bool {
    let name = api.rsplit('.').next().unwrap_or(api).to_ascii_lowercase();
    matches!(name.as_str(), "rmdir" | "rmdirsync")
}

/// Whether a sink API creates a filesystem entry (rather than reading or removing one): `fs.mkdir(Sync)`,
/// `fs.writeFile(Sync)`, `fs.appendFile(Sync)`, `fs.createWriteStream`, `fs.copyFile(Sync)`, and a
/// file-upload move (`.mv`). For these the traversal proof is a new entry appearing inside an
/// attacker-named directory planted outside the base directory, not reflected content. Keyed on the
/// standard filesystem API name alone, matched on the final `.`-segment so an unrelated method whose
/// name merely contains one of these is not mistaken for it. Framework-agnostic.
fn sink_creates(api: &str) -> bool {
    let name = api.rsplit('.').next().unwrap_or(api).to_ascii_lowercase();
    matches!(
        name.as_str(),
        "mkdir"
            | "mkdirsync"
            | "writefile"
            | "writefilesync"
            | "appendfile"
            | "appendfilesync"
            | "createwritestream"
            | "copyfile"
            | "copyfilesync"
            | "mv"
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

/// The request entry a Web Fetch / Next.js App Router handler resolves to when it parses its body
/// through a method call on the request object (`const { token } = await request.json()`). The engine
/// records such a source as the bare parse call (`request.json()`), which names no field; map the
/// finding's tainted local back to the destructured body key. Only `json()` destructures into named
/// fields — `text()`/`arrayBuffer()`/`blob()` carry a single scalar body and `formData()` is resolved
/// by [`form_data_entry`] — so other parse methods return `None`. A shorthand destructure binds the
/// key to a local of the same name, which is the fallback when no rename pattern is found.
fn web_body_entry(finding: &Finding, source: Option<&str>) -> Option<Entry> {
    let (recv, method) = web_request_body_call(finding.source.expr.trim())?;
    if method != "json" {
        return None;
    }
    let local = first_assigned_local(finding)?;
    let key = source
        .and_then(|src| {
            destructuring_bound_from_call(src, &format!("{recv}.{method}("))
                .into_iter()
                .find(|(_, bound)| *bound == local)
                .map(|(key, _)| key)
        })
        .unwrap_or(local);
    Some(Entry::Body(Some(key)))
}

/// A Web `Request` body-parse call on a bare `request`/`req` receiver (`request.json()`,
/// `req.text()`, `request.formData()`): the receiver name and the parse method. A Hono
/// `c.req.json()` carries a `.req.` receiver and is resolved by [`hono_entry`] instead, so only the
/// bare App Router / Web Fetch handler parameter is matched here. The call must take no argument.
fn web_request_body_call(expr: &str) -> Option<(&'static str, String)> {
    for recv in ["request", "req"] {
        let Some(after) = expr.strip_prefix(recv).and_then(|r| r.strip_prefix('.')) else {
            continue;
        };
        let Some(paren) = after.find('(') else {
            continue;
        };
        let method = &after[..paren];
        if method.is_empty() || !method.bytes().all(is_ident) {
            continue;
        }
        if after[paren + 1..].trim_start().starts_with(')') {
            return Some((recv, method.to_owned()));
        }
    }
    None
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
    destructuring_bound_from_call(source, &format!(".req.{method}("))
}

/// Every `key -> local` pair of an object-destructuring bound from a no-argument call whose text ends
/// with `needle` (`const { token, password } = await request.json()` for needle `request.json(`).
/// Shares its destructure-pattern walk-back with [`hono_destructuring`]. When `needle` begins with an
/// identifier character (a bare receiver like `request.json(`), a word boundary is required before it
/// so a longer identifier (`myrequest.json(`) is not matched; a needle beginning with `.` is already
/// boundary-anchored.
fn destructuring_bound_from_call(source: &str, needle: &str) -> Vec<(String, String)> {
    let bytes = source.as_bytes();
    let check_boundary = needle.as_bytes().first().is_some_and(|b| is_ident(*b));
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = source[from..].find(needle) {
        let at = from + rel;
        from = at + needle.len();
        if check_boundary && at > 0 && bytes.get(at - 1).is_some_and(|b| is_ident(*b)) {
            continue;
        }
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

/// The index of the `(` matching the `)` at `close` in `text`, scanning backward and honoring nesting.
/// The mirror of [`matching_close_paren`].
fn matching_open_paren(text: &str, close: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut i = close as isize;
    while i >= 0 {
        match bytes.get(i as usize).copied()? {
            b')' => depth += 1,
            b'(' => {
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

/// Request fields of `part` whose *positive* `if (req.<part>.<field>) { ... }` block selects a branch
/// that holds none of the flow anchors, so the tainted flow runs only when the field is ABSENT (the
/// handler falls through to the `else` or following code). Such a field must not be sent as a sibling:
/// setting it would divert control into the wrong branch and the sink would never run. A negated test
/// (`if (!req.<part>.<field>) return`) marks the field *required*, not diverting, and is excluded; a
/// block that does enclose a flow anchor is a real gate kept elsewhere. Mined from the handler source
/// by brace matching against the anchors; nothing is app-specific.
pub fn diverting_guard_fields(source: &str, part: &str, anchors: &[u32]) -> Vec<String> {
    let anchor_offsets: Vec<usize> = anchors
        .iter()
        .filter_map(|line| line_offset(source, *line as usize))
        .collect();
    let bytes = source.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i + 2 <= source.len() {
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
                if let Some(bclose) = matching_close_brace(source, bopen) {
                    let encloses_flow = anchor_offsets
                        .iter()
                        .any(|&off| off > bopen && off < bclose);
                    if !encloses_flow {
                        for name in positive_member_params(cond, part) {
                            if !out.contains(&name) {
                                out.push(name);
                            }
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

/// Request fields of `part` whose branch is selected through a LOCAL bound from the field, where that
/// branch does not enclose the sink. Companion to [`diverting_guard_fields`], which reads the field
/// directly as `req.<part>.<field>` inside the condition; this resolves the field through the locals it
/// is assigned to (`var keep = req.body.keep; if (keep == 'yes') {...}`) or destructured into
/// (`const { tempId } = req.body; if (tempId != undefined) {...}`), so a handler that copies a request
/// field into a variable before branching on it is handled too. A branch is *positive* — entered when
/// the field is present/truthy or equal to the compared literal — when the local appears as a bare
/// truthiness operand, an `== 'lit'`/`=== 'lit'` equality, or a `!= undefined`/`!== undefined`/
/// `!= null` presence test. Returns each such field whose positive branch holds none of the flow
/// anchors, so sending it would divert control away from the sink (dropping it leaves the field
/// undefined, which fails every positive test and lets execution fall through to the branch holding the
/// sink). A field that also gates a branch enclosing a flow anchor is a real gate and is excluded, so a
/// genuine `else if (local === 'raw') { sink }` precondition is never dropped. Mined from the handler
/// source only; nothing is app-specific.
pub fn diverting_local_guard_fields(source: &str, part: &str, anchors: &[u32]) -> Vec<String> {
    let anchor_offsets: Vec<usize> = anchors
        .iter()
        .filter_map(|line| line_offset(source, *line as usize))
        .collect();
    if anchor_offsets.is_empty() {
        return Vec::new();
    }
    // (local identifier -> request field name) for every field the handler copies into a local before
    // branching on it: an alias binding (`var keep = req.body.keep`) or a destructured rename
    // (`const { a: keep } = req.body`).
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut fields = member_params(source, part);
    if part == "body" {
        fields.extend(destructured_field_keys(source, part));
    }
    fields.sort();
    fields.dedup();
    for field in &fields {
        for local in aliases(source, part, field) {
            pairs.push((local, field.clone()));
        }
    }
    for recv in ["req", "request", "ctx"] {
        for (field, local) in destructured_fields_of(source, &format!("{recv}.{part}")) {
            pairs.push((local, field));
        }
    }
    if pairs.is_empty() {
        return Vec::new();
    }
    // A field that gates a branch enclosing a flow anchor is a real precondition pinned elsewhere;
    // dropping it would make the sink unreachable, so never divert it.
    let enclosing: std::collections::BTreeSet<String> = enclosing_guards_over(source, anchors)
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    let bytes = source.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i + 2 <= source.len() {
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
                if let Some(bclose) = matching_close_brace(source, bopen) {
                    let encloses_flow = anchor_offsets
                        .iter()
                        .any(|&off| off > bopen && off < bclose);
                    if !encloses_flow {
                        for (local, field) in &pairs {
                            if !enclosing.contains(field)
                                && !out.contains(field)
                                && local_positively_gates(cond, local)
                            {
                                out.push(field.clone());
                            }
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

/// Whether `cond` selects its branch when `local` is present or matches a literal: `local` as a bare
/// truthiness operand, `local == 'lit'`/`local === 'lit'`, or `local != undefined`/`local !== undefined`
/// /`local != null`/`local !== null`. A negated test (`!local`) is excluded — it keeps the branch for the
/// ABSENT field, which sending the field avoids, so it is not diverting.
fn local_positively_gates(cond: &str, local: &str) -> bool {
    for (id, _lit) in parse_condition(cond) {
        if id == local {
            return true;
        }
    }
    let bytes = cond.as_bytes();
    let mut from = 0;
    while let Some(rel) = cond[from..].find(local) {
        let at = from + rel;
        from = at + local.len();
        let before_ok = at == 0 || bytes.get(at - 1).is_none_or(|b| !is_ident(*b));
        let after = &cond[at + local.len()..];
        let after_ok = after.as_bytes().first().is_none_or(|b| !is_ident(*b));
        if !before_ok || !after_ok {
            continue;
        }
        let rest = after.trim_start();
        if let Some(rest) = rest.strip_prefix("!==").or_else(|| rest.strip_prefix("!=")) {
            let rest = rest.trim_start();
            if rest.starts_with("undefined") || rest.starts_with("null") {
                return true;
            }
        }
    }
    false
}

/// Request fields of `part` read positively (not under a `!`) inside a condition
/// (`req.query.openFolderOnly` -> `openFolderOnly`, but `!req.query.id` yields nothing). Used to find
/// branch-selecting guards; a negated occurrence is a presence requirement handled elsewhere, so it is
/// skipped here.
fn positive_member_params(cond: &str, part: &str) -> Vec<String> {
    let needle = format!(".{part}.");
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = cond[from..].find(&needle) {
        let at = from + rel;
        from = at + needle.len();
        if !receiver_before(&cond[..at]) {
            continue;
        }
        // The receiver token that owns this access, and whatever precedes it: a `!` (optionally
        // spaced) means a negated, required field, not a diverting one.
        let recv_len = cond[..at]
            .bytes()
            .rev()
            .take_while(|b| is_ident(*b))
            .count();
        let before = cond[..at - recv_len].trim_end();
        if before.ends_with('!') {
            continue;
        }
        let after = &cond[at + needle.len()..];
        let ident: String = after.chars().take_while(|c| is_ident(*c as u8)).collect();
        if !ident.is_empty() {
            out.push(ident);
        }
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

/// Request fields of `part` that select a branch which *provisions* the filesystem resource the
/// sink's post-join flow depends on, and so must be SENT rather than diverted away. A handler may
/// split on a "create new vs. reuse existing" selector
/// (`var makenew = req.body.makenew == "true" ? true : false; if (makenew) { folder = ...;
/// fs.mkdirSync(folder, {recursive:true}) } else { fs.readdirSync(dir) ... }`) where the sink sits
/// *after* the branches rejoin and later code writes into the directory the positive branch created.
/// The positive block does not enclose the sink, so [`diverting_guard_fields`] /
/// [`diverting_local_guard_fields`] would classify the selector as diverting and drop it — but the
/// complementary branch (taken when the field is absent) reads attacker-absent filesystem state and
/// throws before the sink is ever reached. Returns each such field paired with the value that enters
/// the provisioning branch, so the request takes the branch that reaches the sink. Mined from the
/// handler source only: a branch is only kept when its block provisions a directory
/// (`mkdirSync`/`mkdir`/`mkdtemp`/`ensureDir`) and lies on the control-flow span between the tainted
/// read and the sink; empty for a handler with no such provisioning selector.
pub fn provisioning_branch_fields(
    source: &str,
    part: &str,
    anchors: &[u32],
) -> Vec<(String, String)> {
    let anchor_offsets: Vec<usize> = anchors
        .iter()
        .filter_map(|line| line_offset(source, *line as usize))
        .collect();
    let (Some(&min_anchor), Some(&max_anchor)) =
        (anchor_offsets.iter().min(), anchor_offsets.iter().max())
    else {
        return Vec::new();
    };
    let bytes = source.as_bytes();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut i = 0usize;
    while i + 2 <= source.len() {
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
                    // The whole `if` statement sits on the control-flow span between the tainted read
                    // and the sink (so it belongs to the flow's handler), and its block rejoins before
                    // the sink rather than enclosing it.
                    && popen > min_anchor
                    && bclose < max_anchor
                    && block_provisions_directory(&source[bopen..=bclose])
                {
                    for (field, value) in branch_selector_values(source, part, cond) {
                        if out.iter().all(|(existing, _)| *existing != field) {
                            out.push((field, value));
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

/// Whether `block` provisions a directory on disk — a `mkdirSync`/`mkdir`/`mkdtemp`/`ensureDir` call
/// (sync or async, `fs`, `fs/promises`, or `fs-extra`). This is the signal that a branch creates the
/// resource that post-join code depends on, distinguishing it from a branch that only reads
/// preexisting (attacker-absent) state.
fn block_provisions_directory(block: &str) -> bool {
    block.contains("mkdirSync")
        || block.contains("mkdirsSync")
        || block.contains(".mkdir(")
        || block.contains("mkdtemp")
        || block.contains("ensureDir")
}

/// For a branch condition `cond`, the request fields of `part` that select it, each paired with the
/// value that makes the branch taken. Handles the condition read directly as `req.<part>.<field> ==
/// "lit"`, and the common indirection where the condition is a bare local the handler bound from the
/// field through a truthy ternary (`var makenew = req.body.makenew == "true" ? true : false; if
/// (makenew)`). Empty when the condition names no request field of `part`.
fn branch_selector_values(source: &str, part: &str, cond: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    // The condition compares a request member directly against a literal.
    if let Some((field, value)) = member_equality_literal(cond, part) {
        out.push((field, value));
    }
    // The condition is a bare local the handler bound from a request field via a truthy ternary.
    for local in cond
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty() && !t.bytes().next().is_some_and(|b| b.is_ascii_digit()))
    {
        if let Some((field, value)) = local_ternary_selector(source, part, local)
            && out.iter().all(|(existing, _)| *existing != field)
        {
            out.push((field, value));
        }
    }
    out
}

/// `(field, literal)` when `local` is bound as `var local = req.<part>.<field> == "literal" ?
/// <truthy> : <falsy>` (or `===`), so entering the `if (local)` branch requires the field to equal
/// `literal`. Only a ternary whose *then* side is truthy qualifies, so the positive branch really is
/// the one the equality selects. Returns `None` when `local` has no such binding.
fn local_ternary_selector(source: &str, part: &str, local: &str) -> Option<(String, String)> {
    for keyword in ["const ", "let ", "var "] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(keyword) {
            let at = from + rel + keyword.len();
            from = at;
            let rest = &source[at..];
            let ident: String = rest.chars().take_while(|c| is_ident(*c as u8)).collect();
            if ident != local {
                continue;
            }
            let tail = rest[ident.len()..].trim_start();
            let Some(rhs) = tail.strip_prefix('=').filter(|r| !r.starts_with('=')) else {
                continue;
            };
            let end = binding_rhs_end(rhs).min(300);
            let stmt = &rhs[..end];
            let Some(q) = top_level_index(stmt, '?') else {
                continue;
            };
            // Reject optional chaining / nullish coalescing masquerading as a ternary `?`.
            if stmt[q + 1..].starts_with('.') || stmt[q + 1..].starts_with('?') {
                continue;
            }
            let Some(colon_rel) = top_level_index(&stmt[q + 1..], ':') else {
                continue;
            };
            let then = stmt[q + 1..q + 1 + colon_rel].trim();
            if !is_truthy_literal(then) {
                continue;
            }
            if let Some(pair) = member_equality_literal(stmt[..q].trim(), part) {
                return Some(pair);
            }
        }
    }
    None
}

/// `(field, literal)` for a `req.<part>.<field> == "literal"` / `=== "literal"` comparison (either
/// operand order) inside `expr`; `None` when `expr` holds no such request-member equality.
fn member_equality_literal(expr: &str, part: &str) -> Option<(String, String)> {
    for op in ["===", "=="] {
        let mut from = 0;
        while let Some(rel) = expr[from..].find(op) {
            let at = from + rel;
            from = at + op.len();
            let before = expr.as_bytes().get(at.wrapping_sub(1)).copied();
            let after = expr.as_bytes().get(at + op.len()).copied();
            if before.is_some_and(|b| matches!(b, b'!' | b'<' | b'>' | b'='))
                || after.is_some_and(|b| b == b'=')
            {
                continue;
            }
            let lhs = expr[..at].trim();
            let rhs = expr[at + op.len()..].trim();
            if let (Some(field), Some(lit)) = (member_field(lhs, part), string_literal_value(rhs)) {
                return Some((field, lit));
            }
            if let (Some(field), Some(lit)) = (member_field(rhs, part), string_literal_value(lhs)) {
                return Some((field, lit));
            }
        }
    }
    None
}

/// The field name when `expr` is exactly a request member access `req.<part>.<field>` (receiver
/// `req`/`request`/`ctx`); `None` otherwise.
fn member_field(expr: &str, part: &str) -> Option<String> {
    let needle = format!(".{part}.");
    let at = expr.rfind(&needle)?;
    if !receiver_before(&expr[..at]) {
        return None;
    }
    let after = &expr[at + needle.len()..];
    let field: String = after.chars().take_while(|c| is_ident(*c as u8)).collect();
    // Nothing but the field name may trail (`req.body.makenew`, not `req.body.makenew.length`).
    if field.is_empty() || after.len() != field.len() {
        return None;
    }
    Some(field)
}

/// Whether `text` is a literal that is truthy in JavaScript: `true`, a non-zero number, or a
/// non-empty string literal. Used to confirm a ternary's *then* side selects the positive branch.
fn is_truthy_literal(text: &str) -> bool {
    if text == "true" {
        return true;
    }
    if let Some(inner) = string_literal_value(text) {
        return !inner.is_empty();
    }
    match text.parse::<f64>() {
        Ok(number) => number != 0.0,
        Err(_) => false,
    }
}

/// The byte index of the first top-level occurrence of `target` in `s` — outside any string literal
/// and at paren/bracket/brace depth zero. `target` must be an ASCII character.
fn top_level_index(s: &str, target: char) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        match quote {
            Some(q) => {
                if b == b'\\' {
                    i += 2;
                    continue;
                }
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' | b'`' => quote = Some(b),
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' if depth > 0 => depth -= 1,
                _ if depth == 0 && b == target as u8 => return Some(i),
                _ => {}
            },
        }
        i += 1;
    }
    None
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
    // Guard clauses reject missing fields before the sink instead of enclosing the sink. Their
    // negated disjuncts must all be truthy for execution to continue.
    for id in presence_guard_fields(source, anchors) {
        if id != target
            && is_request_field(source, part, &id)
            && out.iter().all(|(name, _)| *name != id)
        {
            out.push((id, "jsspector".to_owned()));
        }
    }
    out
}

/// Query-string `key=value` fragments that a substring guard on the request URL requires present
/// before the sink is reached: a handler that dispatches on the raw URL rather than a parsed field
/// (`const url = req.originalUrl; if (url.indexOf("action=createdir") !== -1) fs.mkdirSync(filepath)`)
/// never reaches the sink unless the URL carries that fragment. Scans every `if` block that encloses
/// a flow anchor for a `<url>.indexOf("<lit>")` / `<url>.includes("<lit>")` test whose receiver
/// derives from the request URL, and returns each `<lit>` that is a `key=value` pair as a query
/// sibling to carry. Mined from the handler source only; empty when no such URL-substring guard gates
/// the sink, so a handler with no raw-URL dispatch is unaffected.
pub fn url_substring_query_gates(source: &str, anchors: &[u32]) -> Vec<(String, String)> {
    let offsets: Vec<usize> = anchors
        .iter()
        .filter_map(|line| line_offset(source, *line as usize))
        .collect();
    if offsets.is_empty() {
        return Vec::new();
    }
    let bytes = source.as_bytes();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut i = 0usize;
    while i + 2 <= source.len() {
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
                    && offsets.iter().any(|&off| off > bopen && off < bclose)
                {
                    for (key, value) in url_substring_fragments(source, cond) {
                        if out.iter().all(|(existing, _)| *existing != key) {
                            out.push((key, value));
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

/// The `key=value` query fragments a condition tests the request URL for by substring (`url.indexOf(
/// "action=createdir")`, `url.includes("mode=raw")`): the string-literal argument of each `.indexOf`
/// / `.includes` whose receiver derives from the request URL, split on its first `=`. A literal with
/// no `=` is skipped — only a query-pair fragment maps cleanly to a request the verifier can send.
fn url_substring_fragments(source: &str, cond: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for method in [".indexOf(", ".includes("] {
        let mut from = 0;
        while let Some(rel) = cond[from..].find(method) {
            let dot = from + rel;
            let open = dot + method.len();
            from = open;
            // The receiver is the identifier (allowing member access) just before `.indexOf`/`.includes`.
            let recv = cond[..dot]
                .trim_end()
                .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                .next()
                .unwrap_or("")
                .trim_matches('.');
            if recv.is_empty() || !is_url_derived(source, recv) {
                continue;
            }
            let Some(arglist) = balanced_arg(&cond[open..]) else {
                continue;
            };
            let first = split_top_level_commas(arglist)
                .into_iter()
                .next()
                .unwrap_or_default();
            let Some(lit) = string_literal_arg(first.trim()) else {
                continue;
            };
            if let Some(eq) = lit.find('=') {
                let key = lit[..eq].trim();
                let value = lit[eq + 1..].trim();
                if !key.is_empty() && key.bytes().all(is_ident) {
                    out.push((key.to_owned(), value.to_owned()));
                }
            }
        }
    }
    out
}

/// The host-like substrings an SSRF handler requires the tainted outbound URL to contain before it
/// reaches the request sink, when the allowlist is implemented as a *substring* or *prefix* test rather
/// than a parsed-host comparison (`if (!url.includes("site.com")) return 403`,
/// `if (!url.startsWith("https://site.com")) throw`). Each token is the string argument of a *negated*
/// `.includes` / `.indexOf(...) === -1` / `.startsWith` / `.endsWith` whose receiver is a tainted
/// URL-derived identifier, reduced to its host portion. Only must-contain (negated) checks are mined:
/// a non-negated `url.includes("169.254.169.254")` is a blocklist and embedding its token would defeat
/// the request, so it is left out. A receiver that is not the tainted URL (`allowed.includes(host)`
/// over an allow array, or `new URL(url).hostname === "site.com"`) is also left out — it constrains the
/// real host and is not bypassable by substring placement. Mined from the handler source only; empty
/// when the handler gates the URL on no such substring.
pub fn ssrf_allowlist_host_tokens(source: &str, names: &[String]) -> Vec<String> {
    if names.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    for method in [".includes(", ".indexOf(", ".startsWith(", ".endsWith("] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(method) {
            let dot = from + rel;
            let open = dot + method.len();
            from = open;
            // The receiver is the identifier (allowing member access) just before the method call.
            let before = &source[..dot];
            let recv_start = before
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                .map(|i| i + 1)
                .unwrap_or(0);
            let recv = before[recv_start..].trim_matches('.');
            if recv.is_empty() {
                continue;
            }
            // The receiver, or the local it is a member of, must carry the tainted URL; a check on an
            // allow array or a parsed hostname does not qualify.
            let root = recv.split('.').next().unwrap_or(recv);
            if !names.iter().any(|name| name == recv || name == root) {
                continue;
            }
            let Some(arglist) = balanced_arg(&source[open..]) else {
                continue;
            };
            let close = open + arglist.len();
            let Some(first) = split_top_level_commas(arglist).into_iter().next() else {
                continue;
            };
            let Some(lit) = string_literal_arg(first.trim()) else {
                continue;
            };
            // Keep only must-contain checks. `.includes`/`.startsWith`/`.endsWith` qualify when the call
            // is negated with a leading `!`; `.indexOf` qualifies when its result is compared for
            // absence (`=== -1`, `< 0`).
            let negated = if method == ".indexOf(" {
                let after: String = source[close + 1..]
                    .chars()
                    .take(8)
                    .filter(|c| !c.is_whitespace())
                    .collect();
                after.starts_with("===-1") || after.starts_with("==-1") || after.starts_with("<0")
            } else {
                before[..recv_start].trim_end().ends_with('!')
            };
            if !negated {
                continue;
            }
            if let Some(token) = host_substring(&lit)
                && !out.contains(&token)
            {
                out.push(token);
            }
        }
    }
    out
}

/// The host portion of an allowlist literal, for carrying in a bypass URL: the literal with any scheme
/// (`https://`, `http://`, `//`) and any path/query/fragment/userinfo stripped. `None` when what remains
/// is not host-like — too short, missing a dot, or holding a character no hostname/authority carries —
/// so a free-text allowlist token is not mistaken for a host.
fn host_substring(lit: &str) -> Option<String> {
    let mut rest = lit.trim();
    for scheme in ["https://", "http://", "//"] {
        if let Some(stripped) = rest.strip_prefix(scheme) {
            rest = stripped;
            break;
        }
    }
    let host = rest
        .split(['/', '?', '#', '@'])
        .next()
        .unwrap_or(rest)
        .trim();
    if host.len() < 4 || !host.contains('.') {
        return None;
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_'))
    {
        return None;
    }
    Some(host.to_owned())
}

/// Whether `recv` holds (part of) the request URL: a `req.originalUrl`/`req.url` accessor itself, or a
/// local bound from one (`const url = req.originalUrl`). Keeps the substring-gate miner from treating
/// an unrelated `.indexOf` receiver as a URL dispatch.
fn is_url_derived(source: &str, recv: &str) -> bool {
    if recv.contains("originalUrl") || recv == "req.url" || recv == "request.url" {
        return true;
    }
    for line in source.lines() {
        let Some(eq) = assign_eq(line) else {
            continue;
        };
        let (lhs, rhs) = line.split_at(eq);
        if mentions(lhs, recv)
            && (rhs.contains("originalUrl")
                || rhs.contains("req.url")
                || rhs.contains("request.url"))
        {
            return true;
        }
    }
    false
}

/// The byte index of a line's binding `=`, skipping `==`/`===`/`!=`/`<=`/`>=` and `=>`. `None` for a
/// line with no plain assignment.
fn assign_eq(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes.get(i) == Some(&b'=') {
            let before = bytes.get(i.wrapping_sub(1)).copied();
            let after = bytes.get(i + 1).copied();
            let is_cmp = before.is_some_and(|b| matches!(b, b'!' | b'<' | b'>' | b'='))
                || after.is_some_and(|b| matches!(b, b'=' | b'>'));
            if !is_cmp {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Fields required by an early exit such as `if (!email || !name) return`: only pure top-level
/// disjunctions of negated identifiers are accepted, and only before the latest flow anchor inside
/// the same enclosing block.
fn presence_guard_fields(source: &str, anchors: &[u32]) -> Vec<String> {
    let offsets: Vec<usize> = anchors
        .iter()
        .filter_map(|line| line_offset(source, *line as usize))
        .collect();
    let (Some(&lo), Some(&hi)) = (offsets.iter().min(), offsets.iter().max()) else {
        return Vec::new();
    };
    // Scope to the enclosing *function* body, not the innermost brace block: the lowest flow anchor can
    // sit inside a non-scope brace pair (a multi-line `{ ... } = req.query` destructure), which would
    // otherwise hide the handler's early-return presence guards from the scan.
    let Some((open, close)) = enclosing_function_block(source, lo) else {
        return Vec::new();
    };
    let upper = hi.min(close);
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = open;
    while i + 2 <= upper {
        let boundary = i == 0 || bytes.get(i - 1).is_some_and(|byte| !is_ident(*byte));
        if boundary
            && bytes.get(i..i + 2) == Some(b"if")
            && bytes.get(i + 2).is_none_or(|byte| !is_ident(*byte))
            && let Some(paren) = source[i + 2..].find('(').map(|at| i + 2 + at)
            && source[i + 2..paren].trim().is_empty()
            && let Some(end) = matching_close_paren(source, paren)
        {
            if end + 1 < upper && guard_clause_exits(&source[end + 1..]) {
                for id in negated_disjuncts(&source[paren + 1..end]) {
                    if !out.contains(&id) {
                        out.push(id);
                    }
                }
            }
            i = paren + 1;
        } else {
            i += 1;
        }
    }
    out
}

fn enclosing_block(source: &str, offset: usize) -> Option<(usize, usize)> {
    let mut stack = Vec::new();
    for (at, byte) in source.bytes().enumerate().take(offset) {
        match byte {
            b'{' => stack.push(at),
            b'}' => {
                stack.pop();
            }
            _ => {}
        }
    }
    let open = *stack.last()?;
    Some((open, matching_close_brace(source, open)?))
}

/// The nearest ancestor brace block of `offset` whose open brace begins a *function body* — an arrow
/// `=> {` or a `function (...) {` / method `name(...) {` — rather than a control block, object literal
/// or destructuring pattern. Handler-wide guard mining needs the whole function body as its scope, but
/// the innermost enclosing block can be a non-scope brace pair: a multi-line `{ ... } = req.query`
/// destructuring whose interior lines are flow anchors, or an object literal. Walking out to the
/// enclosing function recovers the real handler body in those cases. Falls back to the innermost
/// enclosing block when no function body encloses the offset (top-level code), preserving the prior
/// behavior. Mined by brace/paren matching; nothing here is tied to a specific app.
fn enclosing_function_block(source: &str, offset: usize) -> Option<(usize, usize)> {
    let mut opens = Vec::new();
    for (at, byte) in source.bytes().enumerate().take(offset) {
        match byte {
            b'{' => opens.push(at),
            b'}' => {
                opens.pop();
            }
            _ => {}
        }
    }
    for &open in opens.iter().rev() {
        if is_function_body_open(source, open) {
            return matching_close_brace(source, open).map(|close| (open, close));
        }
    }
    opens
        .last()
        .and_then(|&open| matching_close_brace(source, open).map(|close| (open, close)))
}

/// Whether the `{` at `open` begins a function body: it directly follows an arrow (`=> {`) or a `)`
/// that closes a parameter list — a `)` whose matching `(` is not preceded by a control keyword
/// (`if`/`for`/`while`/`switch`/`catch`/`with`), whose `(...)` is a condition rather than parameters.
/// String/comment-naive, like the rest of this module's brace handling.
fn is_function_body_open(source: &str, open: usize) -> bool {
    let pre = source[..open].trim_end();
    if pre.ends_with("=>") {
        return true;
    }
    if pre.ends_with(')') {
        let close_paren = pre.len() - 1;
        if let Some(open_paren) = matching_open_paren(source, close_paren) {
            let before = source[..open_paren].trim_end();
            let word: String = before
                .bytes()
                .rev()
                .take_while(|b| is_ident(*b))
                .map(|b| b as char)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            return !matches!(
                word.as_str(),
                "if" | "for" | "while" | "switch" | "catch" | "with"
            );
        }
    }
    false
}

/// The source of the braced block that encloses `line` (a route handler's body), used to resolve a
/// request input from the handler that reaches the sink rather than from the whole module — so an
/// unrelated sibling route's member reads do not leak into the resolution. Returns `None` when `line`
/// is not inside any block (top-level code) or cannot be located, leaving the caller to use the whole
/// source. Not tied to any app: it is brace matching around the finding's own source line.
fn handler_scope(source: &str, line: u32) -> Option<&str> {
    let offset = line_offset(source, line as usize)?;
    let (open, close) = enclosing_block(source, offset)?;
    source.get(open..=close)
}

fn guard_clause_exits(after: &str) -> bool {
    let trimmed = after.trim_start();
    let body = if trimmed.starts_with('{') {
        let close = matching_close_brace(trimmed, 0).unwrap_or(trimmed.len());
        &trimmed[1..close]
    } else {
        &trimmed[..trimmed.find(';').unwrap_or(trimmed.len())]
    };
    let body = body.trim_start();
    ["return", "throw", "next"]
        .iter()
        .any(|keyword| starts_with_keyword(body, keyword))
}

fn starts_with_keyword(text: &str, keyword: &str) -> bool {
    text.strip_prefix(keyword)
        .is_some_and(|rest| rest.as_bytes().first().is_none_or(|byte| !is_ident(*byte)))
}

fn negated_disjuncts(condition: &str) -> Vec<String> {
    if split_top_level(condition, "&&").len() > 1 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for part in split_top_level(condition, "||") {
        let Some(id) = part.trim().strip_prefix('!').map(str::trim) else {
            return Vec::new();
        };
        if !is_plain_identifier(id) {
            return Vec::new();
        }
        out.push(id.to_owned());
    }
    out
}

fn split_top_level(input: &str, separator: &str) -> Vec<String> {
    let separator = separator.as_bytes();
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let Some(&byte) = bytes.get(i) else {
            break;
        };
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ => {}
        }
        if depth == 0
            && i + separator.len() <= bytes.len()
            && bytes.get(i..i + separator.len()) == Some(separator)
        {
            out.push(input[start..i].to_owned());
            i += separator.len();
            start = i;
        } else {
            i += 1;
        }
    }
    out.push(input[start..].to_owned());
    out
}

/// Whether the handler forwards the *whole* request body somewhere (a call argument `Service.update(
/// req.body)`, a spread `{ ...req.body }`, a bare assignment `const b = req.body`, or a whole-body
/// destructure `const { x } = req.body`) rather than only reading individual members. Detected as a
/// `<receiver>.body` access that is not itself a member read (`req.body.name`, `req.body['name']`) and
/// not the tail of a longer identifier (`req.bodyText`). Such code needs the request to carry a body
/// *object*, so downstream code that destructures it or guards its type (`if (typeof b !== "object")
/// throw`) rejects or crashes on a body-less request before the sink. Receiver names match the rest of
/// the planner; nothing here is tied to a specific target.
pub fn handler_consumes_whole_body(source: &str) -> bool {
    for recv in ["req", "request", "ctx"] {
        let needle = format!("{recv}.body");
        let mut from = 0;
        while let Some(rel) = source[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            // Word boundary before the receiver (`req.body`, not `xreq.body`).
            if at > 0
                && source
                    .as_bytes()
                    .get(at - 1)
                    .is_some_and(|byte| is_ident(*byte))
            {
                continue;
            }
            // The character right after `body`: an identifier byte means a longer name (`bodyText`);
            // a `.` or `[` means a member read (`req.body.name`), which the field-level machinery
            // already covers. Anything else (`)`, `,`, `;`, `}`, whitespace, end) is a whole-body use.
            match source.as_bytes().get(from) {
                Some(byte) if is_ident(*byte) => continue,
                Some(b'.') | Some(b'[') => continue,
                _ => return true,
            }
        }
    }
    false
}

/// Whether the handler reads `name` from request `part`: by member access (`req.body.name`) or by
/// destructuring the whole part (`const { name } = req.body`).
fn is_request_field(source: &str, part: &str, name: &str) -> bool {
    member_params(source, part).iter().any(|n| n == name)
        || destructured_fields(source, part).iter().any(|n| n == name)
}

/// The request field KEYS a handler destructures from `<receiver>.<part>`, or — for a body — from a
/// `request.json()`/`req.body` call result (`const { a, b: c } = await request.json()` -> `a`, `b`).
/// Companion to [`member_params`] (member-access reads) for the destructured shape, returning the
/// request field names (not the renamed locals), so a sibling is sent under the key the handler reads.
/// Used by [`required_siblings`] so a handler that destructures its other required fields still gets
/// them supplied. A field whose local binding is never referenced beyond the destructuring itself is
/// an optional, unused read and is left out — only fields the handler actually consumes (`const {
/// username } = await request.json(); User.create({ username })`) are returned. Mined from the handler
/// source only.
fn destructured_field_keys(source: &str, part: &str) -> Vec<String> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for recv in ["req", "request", "ctx"] {
        pairs.extend(destructured_fields_of(source, &format!("{recv}.{part}")));
    }
    if part == "body" {
        for recv in ["request", "req"] {
            pairs.extend(destructuring_bound_from_call(
                source,
                &format!("{recv}.json("),
            ));
        }
    }
    pairs
        .into_iter()
        .filter(|(_field, local)| ident_occurrences(source, local) > 1)
        .map(|(field, _local)| field)
        .collect()
}

/// The number of whole-identifier occurrences of `name` in `source` (bounded by non-identifier
/// bytes). A destructured binding that appears only once is its own declaration and nothing else — an
/// unused optional read; more than once means the handler references it.
fn ident_occurrences(source: &str, name: &str) -> usize {
    if name.is_empty() {
        return 0;
    }
    let bytes = source.as_bytes();
    let mut count = 0;
    let mut from = 0;
    while let Some(rel) = source[from..].find(name) {
        let at = from + rel;
        from = at + name.len();
        let before_ok = bytes
            .get(at.wrapping_sub(1))
            .is_none_or(|byte| !is_ident(*byte));
        let after_ok = bytes.get(at + name.len()).is_none_or(|b| !is_ident(*b));
        if before_ok && after_ok {
            count += 1;
        }
    }
    count
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
    // A Web Fetch / Next.js App Router handler parses its body with a method call and destructures the
    // result (`const { token, password } = await request.json()`); those locals are read from the body
    // just as a `const { token } = req.body` destructure would be.
    if part == "body" {
        for recv in ["request", "req"] {
            for (_, local) in destructuring_bound_from_call(source, &format!("{recv}.json(")) {
                out.push(local);
            }
        }
    }
    out
}

/// The [`SqlPlan`] for a SQL-injection finding, resolving the tainted identifiers from the finding and
/// its entry first. `None` for a non-SQL finding or a value-position injection. Mined from the handler
/// source only.
pub fn sql_plan_for(finding: &Finding, entry: &Entry, source: &str) -> Option<SqlPlan> {
    if finding.class != VulnClass::SqlInjection {
        return None;
    }
    let mut tainted = tainted_identifiers(finding, entry);
    propagate_path_derived_taint(source, &mut tainted);
    let mut plan = sql_identifier_plan(source, &tainted)?;
    // A handler can contain several statements that interpolate the same request field. The
    // destructive oracle applies only when this finding's reported sink argument is itself a DELETE;
    // selecting a later DELETE elsewhere in the handler misclassifies a SELECT finding and makes the
    // verifier observe the wrong statement.
    plan.delete = sql_delete_identifier(&finding.sink.arg, &tainted);
    Some(plan)
}

/// The [`SqlValue`] for a SQL-injection finding whose tainted value is interpolated inside a quoted
/// string-literal position of a SQL statement (`WHERE email = '${x}'`). `None` for a non-SQL finding,
/// an identifier-position injection (driven through [`sql_plan_for`] instead), or a value that is not
/// interpolated inside a quoted SQL literal. Mined from the handler source only.
pub fn sql_value_plan_for(finding: &Finding, entry: &Entry, source: &str) -> Option<SqlValue> {
    if finding.class != VulnClass::SqlInjection {
        return None;
    }
    let mut tainted = tainted_identifiers(finding, entry);
    propagate_path_derived_taint(source, &mut tainted);
    sql_value_plan(source, &tainted)
}

/// Scans `source` for a tainted value interpolated inside a quoted string-literal position of a SQL
/// template (`'${x}'` / `"${x}"` within a statement that reads like SQL), returning the enclosing
/// quote so the verifier can break out of it. An interpolation in an identifier position (`FROM ${x}`),
/// or one not wrapped in a matching value quote, is not matched here. Mined textually from the handler
/// source only; conservative — it returns the first quoted tainted interpolation it recognizes.
fn sql_value_plan(source: &str, tainted: &[String]) -> Option<SqlValue> {
    let mut from = 0;
    while let Some(rel) = source[from..].find("${") {
        let at = from + rel;
        from = at + 2;
        let Some(close) = source[at + 2..].find('}').map(|c| at + 2 + c) else {
            continue;
        };
        let inner = source[at + 2..close].trim();
        // The interpolation must actually carry attacker input — a tainted identifier used as a word,
        // or a direct request accessor — so an interpolated constant is never mistaken for a sink.
        if !interpolation_carries_taint(inner, tainted) {
            continue;
        }
        // A value position sits inside an *open* string literal of the statement: scanning the
        // enclosing template from its start to this interpolation leaves a quote open. This covers a
        // bare `'${x}'` as well as a value with surrounding text such as a `LIKE` pattern
        // (`'%${x}%'`), where the quote is not immediately adjacent to the interpolation. An
        // identifier position (`FROM ${x}`) leaves no quote open and is handled elsewhere. The same
        // scan reports how many grouping parens are still open so the breakout can re-balance them.
        let Some((quote, open_parens)) = open_string_context(source, at) else {
            continue;
        };
        let Some(stmt) = enclosing_template_literal(source, at) else {
            continue;
        };
        if !looks_like_sql(&stmt) {
            continue;
        }
        return Some(SqlValue { quote, open_parens });
    }
    None
}

/// The string-literal quote (`'` or `"`) left open at `interp_at` (the offset of a `${`) together with
/// the number of grouping parentheses still open there, found by scanning the enclosing template
/// literal from its start. `None` when no literal is open at that point (an identifier/bare position).
/// Nested `${...}` interpolations are skipped whole so quote and paren characters inside an earlier
/// expression do not corrupt the state — in a template literal `${` always begins an interpolation
/// regardless of surrounding quotes. Parens inside string literals are not counted. This recognizes a
/// value whether or not the quote is adjacent to the interpolation (`'${x}'` and the `LIKE` pattern
/// `'%${x}%'` both report `'`), and reports the open-paren depth the breakout must re-balance.
fn open_string_context(source: &str, interp_at: usize) -> Option<(char, usize)> {
    let open = source[..interp_at].rfind('`')?;
    let segment = &source[open + 1..interp_at];
    let bytes = segment.as_bytes();
    let mut quote: Option<char> = None;
    let mut depth: usize = 0;
    let mut i = 0;
    while let Some(byte) = bytes.get(i) {
        if *byte == b'$' && bytes.get(i + 1) == Some(&b'{') {
            match segment[i + 2..].find('}') {
                Some(end) => {
                    i = i + 2 + end + 1;
                    continue;
                }
                None => return quote.map(|q| (q, depth)),
            }
        }
        let c = *byte as char;
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c == '(' => depth += 1,
            None if c == ')' => depth = depth.saturating_sub(1),
            None => {}
        }
        i += 1;
    }
    quote.map(|q| (q, depth))
}

/// Whether an interpolated expression carries attacker input: it reads a request object directly
/// (`req.`/`request.`) or mentions one of the tainted identifiers as a whole word.
fn interpolation_carries_taint(inner: &str, tainted: &[String]) -> bool {
    if inner.contains("req.") || inner.contains("request.") {
        return true;
    }
    tainted.iter().any(|name| {
        !name.is_empty()
            && inner.match_indices(name.as_str()).any(|(at, _)| {
                let before = inner[..at].chars().next_back();
                let after = inner[at + name.len()..].chars().next();
                let boundary = |c: Option<char>| {
                    c.map(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
                        .unwrap_or(true)
                };
                boundary(before) && boundary(after)
            })
    })
}

/// Whether a placeholder-substituted template literal reads like a SQL statement: it contains a SQL
/// verb and a clause keyword, so an ordinary interpolated string is not mistaken for a query.
fn looks_like_sql(stmt: &str) -> bool {
    let low = stmt.to_ascii_lowercase();
    let verb = ["select ", "insert ", "update ", "delete "]
        .iter()
        .any(|kw| low.contains(kw));
    let clause = [" from ", " where ", " values", " set ", " into "]
        .iter()
        .any(|kw| low.contains(kw));
    verb && clause
}

/// The plan to drive a SQL injection whose tainted value is interpolated in a table-identifier
/// position (`FROM ${tbl}`, `JOIN ${tbl}`, `UPDATE ${tbl}`, `INTO ${tbl}`): every column the statements
/// interpolating that identifier reference (classified filter/value) and the request body fields the
/// handler reads. `None` when no statement interpolates a tainted identifier in such a position — a
/// value-position injection (`'${x}'`) is not an identifier substitution and is driven differently.
/// Mined from the handler source only; nothing here is tied to a specific app.
pub fn sql_identifier_plan(source: &str, tainted: &[String]) -> Option<SqlPlan> {
    let statements = identifier_interpolating_statements(source, tainted);
    if statements.is_empty() {
        return None;
    }
    let mut columns: Vec<SqlColumn> = Vec::new();
    for stmt in &statements {
        for (name, filter) in sql_statement_columns(stmt) {
            match columns.iter_mut().find(|c| c.name == name) {
                Some(existing) => existing.filter |= filter,
                None => columns.push(SqlColumn { name, filter }),
            }
        }
    }
    if columns.is_empty() {
        return None;
    }
    let mut body_fields: Vec<String> = Vec::new();
    for field in destructured_fields(source, "body")
        .into_iter()
        .chain(member_params(source, "body"))
    {
        if !body_fields.contains(&field) {
            body_fields.push(field);
        }
    }
    // The tainted identifier interpolated in the table position is a plain body member exactly when it
    // is one of the names destructured from `req.body`; then the injection must enter through that
    // field rather than a generic default.
    let identifier_field = table_identifier_name(source, tainted).filter(|name| {
        destructured_fields(source, "body")
            .iter()
            .any(|f| f == name)
    });
    Some(SqlPlan {
        columns,
        body_fields,
        identifier_field,
        delete: sql_delete_identifier(source, tainted),
    })
}

/// For a tainted identifier interpolated into the table position of a `DELETE` statement, the
/// quote-breakout parameters (see [`SqlDelete`]). Shares the quote-aware table-position scan of
/// [`table_identifier_name`], but additionally requires the enclosing template literal to be a
/// `DELETE` and records the opening identifier quote and the statement's `?` count. `None` when no
/// such `DELETE` interpolates a tainted identifier. Mined from the handler source only.
fn sql_delete_identifier(source: &str, tainted: &[String]) -> Option<SqlDelete> {
    let mut from = 0;
    while let Some(rel) = source[from..].find("${") {
        let at = from + rel;
        from = at + 2;
        let Some(close) = source[at + 2..].find('}').map(|c| at + 2 + c) else {
            continue;
        };
        let inner = source[at + 2..close].trim();
        if !tainted.iter().any(|name| name == inner) {
            continue;
        }
        let pre_raw = source[..at].trim_end();
        let quote = pre_raw
            .chars()
            .next_back()
            .filter(|c| *c == '"' || *c == '`' || *c == '[');
        let pre = match quote {
            Some(_) => pre_raw[..pre_raw.len() - 1].trim_end(),
            None => pre_raw,
        };
        let last_word: String = pre
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        if !last_word.eq_ignore_ascii_case("from") {
            continue;
        }
        let Some(stmt) = enclosing_template_literal(source, at) else {
            continue;
        };
        if !stmt.trim_start().to_ascii_lowercase().starts_with("delete") {
            continue;
        }
        return Some(SqlDelete {
            quote,
            placeholders: stmt.matches('?').count(),
        });
    }
    None
}

/// The first tainted identifier interpolated in a table-identifier position (`FROM`/`JOIN`/`INTO`/
/// `UPDATE`/`TABLE` `${x}`). This is the request field whose value becomes the SQL table name, so an
/// injection has to enter through it; the surrounding statements' columns are mined separately. Shares
/// the scan shape of [`identifier_interpolating_statements`], returning the matched identifier rather
/// than the statements. `None` when no tainted identifier sits in such a position.
fn table_identifier_name(source: &str, tainted: &[String]) -> Option<String> {
    let mut from = 0;
    while let Some(rel) = source[from..].find("${") {
        let at = from + rel;
        from = at + 2;
        let Some(close) = source[at + 2..].find('}').map(|c| at + 2 + c) else {
            continue;
        };
        let inner = source[at + 2..close].trim();
        if !tainted.iter().any(|name| name == inner) {
            continue;
        }
        // A quoted-identifier position (`FROM "${x}"`, `` FROM `${x}` ``, `FROM [${x}]`) puts the
        // opening quote immediately before `${`; strip one such quote so the preceding SQL keyword is
        // still recognized. A value-position quote (`'${x}'`) is not an identifier quote and is left
        // in place, so a value injection is not misclassified as an identifier one.
        let pre = source[..at].trim_end();
        let pre = pre
            .strip_suffix(|c| c == '"' || c == '`' || c == '[')
            .map(str::trim_end)
            .unwrap_or(pre);
        let last_word: String = pre
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        if matches!(
            last_word.to_ascii_lowercase().as_str(),
            "from" | "join" | "into" | "update" | "table"
        ) {
            return Some(inner.to_owned());
        }
    }
    None
}

/// Each SQL statement in `source` that interpolates one of the tainted identifiers in a
/// table-identifier position: a template-literal whose `${tainted}` is immediately preceded by a
/// `FROM`/`JOIN`/`INTO`/`UPDATE`/`TABLE` keyword. The literal is returned lowercased with every
/// `${...}` replaced by a neutral placeholder, ready for column parsing. Mined textually; a template
/// expression containing a backtick (never the case for a SQL string) would end the scan early.
fn identifier_interpolating_statements(source: &str, tainted: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut from = 0;
    while let Some(rel) = source[from..].find("${") {
        let at = from + rel;
        from = at + 2;
        let Some(close) = source[at + 2..].find('}').map(|c| at + 2 + c) else {
            continue;
        };
        let inner = source[at + 2..close].trim();
        if !tainted.iter().any(|name| name == inner) {
            continue;
        }
        // A quoted-identifier position (`FROM "${x}"`, `` FROM `${x}` ``, `FROM [${x}]`) puts the
        // opening quote immediately before `${`; strip one such quote so the preceding SQL keyword is
        // still recognized. A value-position quote (`'${x}'`) is not an identifier quote and is left
        // in place, so a value injection is not misclassified as an identifier one.
        let pre = source[..at].trim_end();
        let pre = pre
            .strip_suffix(|c| c == '"' || c == '`' || c == '[')
            .map(str::trim_end)
            .unwrap_or(pre);
        let last_word: String = pre
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        if !matches!(
            last_word.to_ascii_lowercase().as_str(),
            "from" | "join" | "into" | "update" | "table"
        ) {
            continue;
        }
        if let Some(stmt) = enclosing_template_literal(source, at)
            && !out.contains(&stmt)
        {
            out.push(stmt);
        }
    }
    out
}

/// The template literal enclosing byte `offset`, in its original case, with each `${...}` replaced by
/// a neutral placeholder identifier so only the fixed SQL text (keywords, column names) remains for
/// parsing. The case is preserved because a column alias's case is the key the handler reads off the
/// result row (`row.DisplayValue`), and JavaScript property access is case-sensitive.
fn enclosing_template_literal(source: &str, offset: usize) -> Option<String> {
    let open = source[..offset].rfind('`')?;
    let rest = &source[open + 1..];
    let close = rest.find('`')?;
    let raw = &rest[..close];
    let mut text = String::with_capacity(raw.len());
    let mut remaining = raw;
    while let Some(at) = remaining.find("${") {
        text.push_str(&remaining[..at]);
        text.push_str(" jsstbl ");
        match remaining[at + 2..].find('}') {
            Some(end) => remaining = &remaining[at + 2 + end + 1..],
            None => {
                remaining = "";
                break;
            }
        }
    }
    text.push_str(remaining);
    Some(text)
}

/// The columns a single (placeholder-substituted) SQL statement references, each marked a filter column
/// when it is matched by equality (`col = ...`, `lower(col) = ...`) or a value column when it only
/// appears in the `SELECT` projection. Column names keep their original case (the key the handler reads
/// off the result row). Keywords are matched case-insensitively. Textual and deliberately conservative:
/// a column it cannot classify is simply omitted, which at worst leaves a statement unproven.
fn sql_statement_columns(stmt: &str) -> Vec<(String, bool)> {
    let low = stmt.to_ascii_lowercase();
    let mut cols: Vec<(String, bool)> = Vec::new();
    let mut mark = |name: &str, filter: bool| {
        if name.is_empty() || name.eq_ignore_ascii_case("jsstbl") || !name.bytes().all(is_ident) {
            return;
        }
        if name
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_digit())
        {
            return;
        }
        match cols.iter_mut().find(|(n, _)| n == name) {
            Some(existing) => existing.1 |= filter,
            None => cols.push((name.to_owned(), filter)),
        }
    };
    // Projection columns: everything between `select` and the first ` from ` (indices from the
    // lowercased copy, slices from the original so names keep their case).
    if let Some(sel) = low.find("select ") {
        let after = sel + "select ".len();
        if let Some(rel) = low[after..].find(" from ") {
            for item in split_top_level_commas(&stmt[after..after + rel]) {
                let main = match item.to_ascii_lowercase().find(" as ") {
                    Some(at) => &item[..at],
                    None => &item,
                };
                if let Some(name) = last_identifier(main.trim()) {
                    mark(&name, false);
                }
            }
        }
    }
    // Equality-matched columns: the identifier to the left of each `=` that is not `==`/`!=`/`<=`/`>=`.
    let bytes = stmt.as_bytes();
    for (i, _) in stmt.match_indices('=') {
        if matches!(bytes.get(i + 1), Some(b'='))
            || matches!(
                bytes.get(i.wrapping_sub(1)),
                Some(b'=' | b'!' | b'<' | b'>')
            )
        {
            continue;
        }
        let left = stmt[..i].trim_end();
        let column = if let Some(inner) = left.strip_suffix(')') {
            // `lower(col) =` — the column is the last identifier inside the parentheses.
            inner.rsplit('(').next().and_then(last_identifier)
        } else {
            last_identifier(left)
        };
        if let Some(name) = column {
            mark(&name, true);
        }
    }
    cols
}

/// The trailing identifier of a SQL expression fragment (`a.b` -> `b`, `lower(title` -> `title`,
/// `customtag` -> `customtag`), or `None` when it ends in no identifier (`*`).
fn last_identifier(fragment: &str) -> Option<String> {
    let name: String = fragment
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (!name.is_empty()).then_some(name)
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

/// `const { client_id } = request.query`: the source is the whole request part, and the sink
/// argument is a variable a trace step says was assigned from it. The parameter name is
/// recovered from how that local is bound in the handler source. Two shapes both record the same
/// `assigned to `name`` trace step: a destructuring bind (`const { file } = req.query`), where the
/// local *is* the parameter name; and a member read (`let subtitlePath = req.query.file`), where the
/// parameter is the member accessed, not the local it is stored in. The member read is resolved from
/// the handler source so the real parameter name (`file`) is driven, not the local (`subtitlePath`).
///
/// The `assigned to` step is not necessarily the first trace step: a transform may precede it
/// (`const u = req.body.queryURL.split("?")[0]` records `through .split()` before `assigned to
/// `u``), so the assignment step is located wherever it appears among the in-file steps rather than
/// assumed to lead the trace.
fn destructured_entry(finding: &Finding, path: &str, source: Option<&str>) -> Option<Entry> {
    let part = strip_request_receiver(finding.source.expr.trim())?;
    if !matches!(part, "query" | "body" | "params") {
        return None;
    }
    let name = finding
        .trace
        .iter()
        .filter(|s| s.file.is_none())
        .find_map(|s| {
            s.note
                .strip_prefix("assigned to `")
                .and_then(|rest| rest.strip_suffix('`'))
        })?;
    if name.is_empty() || !name.bytes().all(is_ident) {
        return None;
    }
    // A member read assigned to the local names the real parameter; prefer it over the local's own
    // name, which equals the parameter only for a destructuring bind.
    if let Some(src) = source
        && let Some(entry) = request_field_assigned_to(src, name, part, path)
    {
        return Some(entry);
    }
    source_entry(&format!("request.{part}.{name}"), path)
}

/// The request-part field a local is assigned from in the handler source: for `let subtitlePath =
/// req.query.file`, the `file` of `req.query.<field>` (or `req.query['field']`). Scans every
/// assignment whose target is `local` and returns the first whose right-hand side reads the given
/// request `part` by a named member. `None` when the local is bound some other way (a bare
/// destructuring of the whole part, a transform with no request access), leaving the caller to fall
/// back to the local's own name.
fn request_field_assigned_to(source: &str, local: &str, part: &str, path: &str) -> Option<Entry> {
    for rhs in assignment_rhs(source, local) {
        for accessor in request_accessors(rhs) {
            let names_part = strip_request_receiver(&accessor)
                .and_then(|chain| chain.split('.').next().map(str::to_owned))
                .is_some_and(|first| first == part);
            if names_part && let Some(entry) = source_entry(&accessor, path) {
                return Some(entry);
            }
        }
    }
    None
}

/// The right-hand sides of assignments whose target is the identifier `local`: `local = <rhs>`,
/// with or without a `let`/`const`/`var` keyword, each cut at the end of its statement. A comparison
/// (`==`, `===`) or an arrow (`=>`) is not an assignment and is skipped, and so is a default-value
/// binding inside a destructuring pattern or parameter list (`const { id, type = "x" } = req.body`),
/// where the `=` sets a default for a binding target rather than assigning to `local`.
fn assignment_rhs<'a>(source: &'a str, local: &str) -> Vec<&'a str> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = source[from..].find(local) {
        let at = from + rel;
        from = at + local.len();
        let boundary_before = at == 0 || bytes.get(at - 1).is_none_or(|b| !is_ident(*b));
        let boundary_after = bytes.get(at + local.len()).is_none_or(|b| !is_ident(*b));
        if !boundary_before || !boundary_after {
            continue;
        }
        let mut i = at + local.len();
        while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        if bytes.get(i) != Some(&b'=') || matches!(bytes.get(i + 1), Some(b'=' | b'>')) {
            continue;
        }
        // The value may begin on a following line (`const scrapeURL =\n  req.body.queryURL...`): the
        // characters right after `=` up to the first newline are only whitespace, so cutting the RHS at
        // that newline yields an empty slice and the real value is missed. Skip leading whitespace,
        // including newlines, so the captured RHS starts at the statement's actual value.
        let value_start = i
            + 1
            + source[i + 1..]
                .bytes()
                .take_while(u8::is_ascii_whitespace)
                .count();
        let end = source[value_start..]
            .find(['\n', ';'])
            .map_or(source.len(), |e| value_start + e);
        let rhs = &source[value_start..end];
        // A default-value binding inside a destructuring pattern or parameter list (`{ id, type =
        // "x" } = req.body`) looks like `type = "x"` but is not an assignment to `type`: the `=` is a
        // default, and the pattern's own `}`/`]`/`)` closes within the captured slice before any
        // delimiter it opened. A genuine assignment's RHS never closes a delimiter it did not open,
        // so an unbalanced closer marks this match as a binding default and it is skipped.
        if closes_unopened_delimiter(rhs) {
            continue;
        }
        out.push(rhs);
    }
    out
}

/// Whether `text` contains a `)`, `]`, or `}` that closes a delimiter never opened within `text`
/// (depth goes negative). Quoted strings are skipped so a bracket inside a literal does not count.
fn closes_unopened_delimiter(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut depth: i32 = 0;
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let Some(&b) = bytes.get(i) else {
            break;
        };
        match quote {
            Some(q) => {
                if b == b'\\' {
                    i += 2;
                    continue;
                }
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'\'' | b'"' | b'`' => quote = Some(b),
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => {
                    depth -= 1;
                    if depth < 0 {
                        return true;
                    }
                }
                _ => {}
            },
        }
        i += 1;
    }
    false
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

/// The event name of a socket.io entry (`"SOCKET run"` -> `"run"`), as the engine names a
/// `socket.on(name, handler)` registration.
fn parse_socket_entry(entry: &str) -> Option<String> {
    let name = entry.strip_prefix("SOCKET ")?.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

/// The classes a remote call (a socket.io event, an MCP tool call) is driven for: those whose
/// oracles need no per-request enrichment beyond the payload's place.
fn remote_call_class(class: VulnClass) -> bool {
    matches!(
        class,
        VulnClass::PathTraversal
            | VulnClass::CommandInjection
            | VulnClass::CodeInjection
            | VulnClass::Ssrf
    )
}

/// The tool an MCP entry (`"MCP run"`) names, or `None` when what follows is not a tool: a
/// protocol request schema (`CallToolRequestSchema`) a low-level handler dispatches on, whose tools
/// are only visible in the handler's own branches.
fn parse_mcp_entry(entry: &str) -> Option<String> {
    let name = entry.strip_prefix("MCP ")?.trim();
    (!name.is_empty() && !name.ends_with("Schema") && !name.contains(' ')).then(|| name.to_owned())
}

/// The `(argument, local)` pairs a destructured parameter binds (`{ cmd, path: p }` -> `("cmd",
/// "cmd")`, `("path", "p")`); empty for anything that is not an object pattern.
fn destructured_pairs(expr: &str) -> Vec<(String, String)> {
    let inner = expr.trim();
    let Some(inner) = inner
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return Vec::new();
    };
    inner
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() || part.starts_with("...") {
                return None;
            }
            let (field, local) = match part.split_once(':') {
                Some((field, local)) => (field.trim(), local.trim()),
                None => (part, part),
            };
            // A default (`limit = 10`) or a nested pattern is not a plain binding.
            let local = local.split('=').next().unwrap_or(local).trim();
            let ident = |text: &str| !text.is_empty() && text.bytes().all(is_ident);
            (ident(field) && ident(local)).then(|| (field.to_owned(), local.to_owned()))
        })
        .collect()
}

/// The argument of an MCP tool the payload rides in, when the source says: a destructured
/// parameter whose local reaches the sink (`async ({ cmd }) => exec(cmd)`), a member read of the
/// arguments object (`args.cmd`, `request.params.arguments.cmd`), directly or one hop through a
/// local built from it. `None` leaves the choice to the schema the server lists.
fn mcp_field(finding: &Finding, source: Option<&str>) -> Option<String> {
    let tainted = tainted_identifiers(finding, &Entry::Url);
    let reaches = |local: &str| {
        tainted.iter().any(|name| name == local)
            || identifier_tokens(&finding.sink.arg)
                .iter()
                .any(|token| token == local)
    };
    let pairs = destructured_pairs(&finding.source.expr);
    let hits: Vec<&(String, String)> = pairs.iter().filter(|(_, local)| reaches(local)).collect();
    if let [(field, _)] = hits.as_slice() {
        return Some(field.clone());
    }
    if let Some(field) = arguments_member(&finding.sink.arg) {
        return Some(field);
    }
    match socket_field(finding, source) {
        Some(Entry::Body(Some(field))) => Some(field),
        // A bare value is not an arguments object: the schema has to say which member it is.
        _ => None,
    }
}

/// The member read off an `arguments` object in `text` (`request.params.arguments.path` -> `path`,
/// `params.arguments['path']` -> `path`).
fn arguments_member(text: &str) -> Option<String> {
    let at = text.find("arguments")?;
    let rest = &text[at + "arguments".len()..];
    if let Some(member) = rest.strip_prefix('.') {
        let name: String = member
            .bytes()
            .take_while(|b| is_ident(*b))
            .map(char::from)
            .collect();
        return (!name.is_empty()).then_some(name);
    }
    bracket_literal(rest.strip_prefix('[')?)
}

/// Names the source reads off the call's arguments or builds the sink's value from: what ranks
/// which argument of an undiscovered tool carries the payload.
fn mcp_field_hints(finding: &Finding) -> Vec<String> {
    let mut hints: Vec<String> = destructured_pairs(&finding.source.expr)
        .into_iter()
        .map(|(field, _)| field)
        .collect();
    for ident in tainted_identifiers(finding, &Entry::Url) {
        for member in alias_member_reads(&finding.sink.arg, &ident) {
            hints.push(member);
        }
        hints.push(ident);
    }
    hints.extend(identifier_tokens(&finding.sink.arg));
    let mut seen: Vec<String> = Vec::new();
    for hint in hints {
        if !seen.contains(&hint) {
            seen.push(hint);
        }
    }
    seen
}

/// URL paths the source mounts or dispatches an endpoint at, likeliest MCP endpoint first: the
/// string literals that look like routes on a line that registers or compares one (`app.post('/mcp',
/// ...)`, `pathname === '/sse'`, `new SSEServerTransport('/messages', res)`, `endpoint: '/mcp'`).
fn mcp_endpoint_paths(source: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in source.lines() {
        let routed = [
            ".get(",
            ".post(",
            ".all(",
            ".use(",
            ".route(",
            ".put(",
            "pathname",
            "url ===",
            "Transport(",
            "endpoint",
        ]
        .iter()
        .any(|marker| line.contains(marker));
        if !routed {
            continue;
        }
        let mut rest = line;
        while let Some((at, quote)) = rest
            .char_indices()
            .find(|(_, character)| matches!(character, '\'' | '"' | '`'))
        {
            let after = &rest[at + 1..];
            let Some(end) = after.find(quote) else { break };
            let literal = &after[..end];
            rest = &after[end + 1..];
            let trimmed = literal.trim_end_matches("/*").trim_end_matches('*');
            let plausible = trimmed.starts_with('/')
                && trimmed.len() <= 64
                && !trimmed.contains(':')
                && !trimmed.contains(' ')
                && trimmed
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'));
            if plausible && !found.iter().any(|seen| seen == trimmed) {
                found.push(trimmed.to_owned());
            }
        }
    }
    let rank = |path: &String| {
        let lower = path.to_ascii_lowercase();
        usize::from(!(lower.contains("mcp") || lower.contains("sse") || lower.contains("message")))
    };
    found.sort_by_key(rank);
    found.truncate(6);
    found
}

/// The single field of a socket event's payload that carries the tainted value (`data.cmd` ->
/// `"cmd"`), or `None` when the whole payload itself reaches the sink untouched (no member access
/// anywhere). Unlike an HTTP request part (`req.body`), the engine's `source.expr` for a socket
/// finding is already the literal parameter name the handler bound (`data`): no "which request
/// part" step is needed, only where it is read. Tried, in order:
///
/// 1. a direct member access of the parameter in the sink argument itself (`exec(data.cmd)`);
/// 2. one hop through a local the handler binds from a member of the parameter before the sink
///    reads *that* local (`const filepath = path.join(base, data.name); readFile(filepath)`) —
///    `source` is searched for `data`'s member read in that local's own binding, not in the sink
///    argument, which names only the built local;
/// 3. the parameter itself reaching the sink bare, with no member access anywhere (the whole
///    payload is the tainted value).
///
/// A handler that destructures the payload into a *renamed* local (`const { cmd: command } =
/// data`) is not resolved by either step (the wire field name and the local differ); the finding
/// is skipped with a reason rather than guessing.
fn socket_field(finding: &Finding, source: Option<&str>) -> Option<Entry> {
    let param = finding.source.expr.trim();
    if param.is_empty() || !param.bytes().all(is_ident) {
        return None;
    }
    if let [field] = alias_member_reads(&finding.sink.arg, param).as_slice() {
        return Some(Entry::Body(Some(field.clone())));
    }
    if let Some(src) = source {
        for local in tainted_identifiers(finding, &Entry::Url) {
            if local == param {
                continue;
            }
            if let Some(rhs) = local_binding_rhs(src, &local)
                && let [field] = alias_member_reads(&rhs, param).as_slice()
            {
                return Some(Entry::Body(Some(field.clone())));
            }
        }
    }
    identifier_tokens(&finding.sink.arg)
        .iter()
        .any(|token| token == param)
        .then_some(Entry::Body(None))
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
    // A dot-accessed field name is an identifier: cut whatever trails it in the source text it was
    // read from (`req.query.name)` inside `path.resolve(base, req.query.name)`, a `,` or `;`), so the
    // request carries the payload under the field the handler actually reads.
    let rest: Vec<&str> = parts
        .map(|p| {
            let end = p.bytes().position(|b| !is_ident(b)).unwrap_or(p.len());
            &p[..end]
        })
        .filter(|p| !p.is_empty())
        .collect();
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

// Session-gate parsing and route classification live in `plan/auth.rs`.
#[cfg(test)]
mod tests;
