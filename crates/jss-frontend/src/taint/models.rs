//! The taint model, loaded from the YAML packs in `packs/` (embedded at build time).
//!
//! The engine holds no framework or library names: every source, sink, propagator, sanitizer
//! and route convention comes from a pack. Packs share one schema; every section is optional and
//! packs are merged by concatenation. A pack that fails to load is reported in
//! [`Model::errors`], never silently dropped.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use jss_core::{Severity, VulnClass};
use serde::Deserialize;

/// The packs built into the binary, in load order.
pub const BUILTIN_PACKS: &[(&str, &str)] = &[
    ("node", include_str!("../../../../packs/node.yaml")),
    (
        "http-clients",
        include_str!("../../../../packs/http-clients.yaml"),
    ),
    ("sql", include_str!("../../../../packs/sql.yaml")),
    ("nosql", include_str!("../../../../packs/nosql.yaml")),
    ("express", include_str!("../../../../packs/express.yaml")),
    ("koa", include_str!("../../../../packs/koa.yaml")),
    ("hono", include_str!("../../../../packs/hono.yaml")),
    ("fastify", include_str!("../../../../packs/fastify.yaml")),
    ("socketio", include_str!("../../../../packs/socketio.yaml")),
    ("nextjs", include_str!("../../../../packs/nextjs.yaml")),
    ("nestjs", include_str!("../../../../packs/nestjs.yaml")),
    (
        "decorator-controllers",
        include_str!("../../../../packs/decorator-controllers.yaml"),
    ),
    ("graphql", include_str!("../../../../packs/graphql.yaml")),
    ("trpc", include_str!("../../../../packs/trpc.yaml")),
    ("queues", include_str!("../../../../packs/queues.yaml")),
    ("meteor", include_str!("../../../../packs/meteor.yaml")),
    ("electron", include_str!("../../../../packs/electron.yaml")),
    ("browser", include_str!("../../../../packs/browser.yaml")),
    ("archive", include_str!("../../../../packs/archive.yaml")),
    ("auth", include_str!("../../../../packs/auth.yaml")),
    ("react", include_str!("../../../../packs/react.yaml")),
    ("dom", include_str!("../../../../packs/dom.yaml")),
    (
        "prototype-pollution",
        include_str!("../../../../packs/prototype-pollution.yaml"),
    ),
    (
        "dev-servers",
        include_str!("../../../../packs/dev-servers.yaml"),
    ),
    ("mcp", include_str!("../../../../packs/mcp.yaml")),
    (
        "n8n-nodes",
        include_str!("../../../../packs/n8n-nodes.yaml"),
    ),
    (
        "llm-tools",
        include_str!("../../../../packs/llm-tools.yaml"),
    ),
    ("git-ssh", include_str!("../../../../packs/git-ssh.yaml")),
    (
        "multipart",
        include_str!("../../../../packs/multipart.yaml"),
    ),
];

/// One pack file, as written.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    pub name: String,
    #[serde(default)]
    pub modules: BTreeMap<String, String>,
    #[serde(default)]
    pub sinks: Vec<SinkSpec>,
    #[serde(default)]
    pub request: RequestSpec,
    #[serde(default)]
    pub routes: RouteSpec,
    #[serde(default)]
    pub sockets: SocketSpec,
    #[serde(default)]
    pub client_sources: Vec<ClientSource>,
    #[serde(default)]
    pub result_sources: Vec<ResultSource>,
    #[serde(default)]
    pub propagation: Propagation,
    #[serde(default)]
    pub sanitizers: Sanitizers,
    #[serde(default)]
    pub html_props: Vec<String>,
    /// Source kinds of a page in the browser (`location.hash`, messages): a finding they
    /// reach is labeled with its page when no route reaches it.
    #[serde(default)]
    pub page_kinds: Vec<String>,
    /// Classes whose objects hold no HTML and are no DOM node: method sinks (`append`, `html`)
    /// do not apply to `new C()` of them.
    #[serde(default)]
    pub plain_constructors: Vec<String>,
    /// Calls that create a DOM node (`document.createElement('iframe')`): appending one is no
    /// HTML injection, whatever its attributes hold.
    #[serde(default)]
    pub node_factories: Vec<String>,
    /// Element attributes (and DOM properties) whose URL the browser loads or navigates to.
    #[serde(default)]
    pub url_attributes: Option<UrlAttributesSpec>,
    /// What makes a file a service worker, whose `request`s are the page's.
    #[serde(default)]
    pub service_worker: Option<ServiceWorkerSpec>,
    /// Object literals that define a tool for a language model: their handler's first
    /// parameter is the model's (attacker-steerable) input.
    #[serde(default)]
    pub tool_objects: Vec<ToolObjectSpec>,
    /// Instances of a module family: what `axios.create()`, `simpleGit()` or `new NodeSSH()`
    /// returns is the family's client, whose methods are its sinks.
    #[serde(default)]
    pub instances: BTreeMap<String, InstanceSpec>,
    /// Query operators whose operand is compared as a value (`{ email: { $eq: x } }`), and
    /// ORM option keys that wrap the filter (`{ where: { email } }`): not NoSQL injection points.
    #[serde(default)]
    pub literal_operators: Vec<String>,
    #[serde(default)]
    pub orm_options: Vec<String>,
    #[serde(default)]
    pub sql_keywords: Vec<String>,
    /// Keyword pairs that make text SQL wherever they appear, in order (`select` .. `from`).
    #[serde(default)]
    pub sql_pairs: Vec<(String, String)>,
    /// Member reads that are client data: `process.argv`.
    #[serde(default)]
    pub member_sources: Vec<MemberSource>,
    /// The highest severity a source kind can reach: `cli: low`.
    #[serde(default)]
    pub severity_caps: BTreeMap<String, SeverityName>,
    /// Caps that hold unless the repository constructs one of `unless_new` (a server only
    /// reachable locally unless it is also served over HTTP).
    #[serde(default)]
    pub local_caps: Vec<LocalCapSpec>,
    /// Module families also usable without an import, by their own name: `fs.readFile(...)`.
    #[serde(default)]
    pub implicit_modules: Vec<String>,
    /// Sub-objects of a module that are the same family: `fs.promises`.
    #[serde(default)]
    pub module_namespaces: Vec<String>,
    /// Option keys that hold a request's URL: `{ url }`, `{ host }`.
    #[serde(default)]
    pub url_option_keys: Vec<String>,
    /// `family.export` calls whose result carries their arguments' taint.
    #[serde(default)]
    pub module_pass: Vec<String>,
    #[serde(default)]
    pub auth: AuthSpec,
    #[serde(default)]
    pub jsx: JsxSpec,
    /// Fields of a procedure's options that are client input (`params: input` sources).
    #[serde(default)]
    pub input_fields: Vec<String>,
}

/// JSX: props that take raw HTML, and how component props count as input.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsxSpec {
    #[serde(default)]
    pub html_props: Vec<String>,
    #[serde(default)]
    pub html_value_keys: Vec<String>,
    #[serde(default)]
    pub props_kind: Option<String>,
    /// Calls that wrap a component and return it (`memo`, `forwardRef`, `observer`): the
    /// function they wrap is the component the const names.
    #[serde(default)]
    pub component_wrappers: Vec<String>,
}

/// How authentication shows in code.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSpec {
    #[serde(default)]
    pub middleware: Vec<String>,
    #[serde(default)]
    pub admin: Vec<String>,
    #[serde(default)]
    pub request_fields: Vec<String>,
    #[serde(default)]
    pub decorators: Vec<String>,
    /// Middleware whose names contain an auth word but that check nothing (exact names,
    /// case-insensitive): `session(...)`, `passport.initialize()`.
    #[serde(default)]
    pub setup: Vec<String>,
}

/// An authentication level in a pack.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeverityAuth {
    User,
    Admin,
}

/// A member read whose value is client data.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberSource {
    pub object: String,
    pub property: String,
    pub kind: String,
    /// The value starts with something the attacker does not choose (`location.href` starts
    /// with the page's own origin): no URL-start rule (`javascript:`, open redirects) applies.
    #[serde(default)]
    pub fixed_start: bool,
}

/// An option that raises a sink's severity and the arguments it checks: `spawn(.., { shell: true })`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Escalate {
    pub option: String,
    pub severity: SeverityName,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkSpec {
    /// A module family and its exports (`""` is the module called as a function).
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub exports: Vec<String>,
    /// Free functions, by name.
    #[serde(default)]
    pub global: Vec<String>,
    /// Methods, on any receiver (`write`) or a named one (`document.write`).
    #[serde(default)]
    pub methods: Vec<String>,
    /// Assignment targets: `location.href = value`.
    #[serde(default)]
    pub assign: Vec<String>,
    pub class: VulnClassName,
    pub severity: SeverityName,
    /// `any:N`, `built:N`, `url:N`, `html:N` or `object:N`.
    pub args: Vec<String>,
    /// Option keys (in a later object argument) that confine the sink: `sendFile(p, { root })`.
    #[serde(default)]
    pub confined_by: Vec<String>,
    #[serde(default)]
    pub escalate: Option<Escalate>,
    /// Weaker matches checked when `args` find nothing: `spawn('git', ['clone', url])`.
    #[serde(default)]
    pub also: Vec<AlsoSpec>,
    /// Source kinds this sink does not apply to: a browser page's URL is no SSRF.
    #[serde(default)]
    pub ignore_kinds: Vec<String>,
    /// Other classes whose checks and escapers make a value safe here too: `shell.openPath`
    /// opens the file a path names, so a path confined to a directory is safe for it.
    #[serde(default)]
    pub cleared_by: Vec<VulnClassName>,
    /// Packages one of which the file's project must depend on for the sink to apply
    /// (`.find()` is a MongoDB query only where a MongoDB driver is a dependency).
    #[serde(default)]
    pub requires: Vec<String>,
    /// `url`: the call returns the response of the URL its `url:N` rule checks, which is the
    /// attacker's when they chose that URL's start (`await fetch(url)`).
    #[serde(default)]
    pub result: Option<String>,
}

/// A secondary argument rule with its own severity.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlsoSpec {
    pub args: Vec<String>,
    pub severity: SeverityName,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSpec {
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub props: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub upload_server_fields: Vec<String>,
    #[serde(default)]
    pub context_names: Vec<String>,
    #[serde(default)]
    pub hono_context_names: Vec<String>,
    #[serde(default)]
    pub decorators: Vec<String>,
    /// Functions whose callback receives `(req, res)`: `http.createServer(handler)`.
    #[serde(default)]
    pub server_factories: Vec<String>,
    /// Properties of a context that are the request: `ctx.request`, `c.req`.
    #[serde(default)]
    pub sub_objects: Vec<String>,
    /// Request properties that can hold objects (parsed JSON bodies, `qs` queries).
    #[serde(default)]
    pub object_props: Vec<String>,
    /// Properties holding uploads, whose `upload_server_fields` the server chooses.
    #[serde(default)]
    pub upload_objects: Vec<String>,
    /// From these package versions on, these request props hold only strings and arrays:
    /// Express 5 parses the query string with the simple parser.
    #[serde(default)]
    pub scalar_props_from: Vec<ScalarFrom>,
    /// Parameter decorators whose value is always a string (`@Param('id')`, `@Headers()`).
    #[serde(default)]
    pub scalar_decorators: Vec<String>,
    /// Pipes that parse a decorated parameter into a safe value (`@Query('n', ParseIntPipe)`).
    #[serde(default)]
    pub sanitizing_pipes: Vec<String>,
    /// Client-source kinds whose values the framework types (GraphQL arguments): no operator
    /// objects.
    #[serde(default)]
    pub scalar_kinds: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSpec {
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub exports: Vec<String>,
    /// Object-style registrations: `fastify.route({ method, url, handler })`.
    #[serde(default)]
    pub object_methods: Vec<String>,
    #[serde(default)]
    pub handler_keys: Vec<String>,
    #[serde(default)]
    pub method_keys: Vec<String>,
    /// Methods that mount a child router: `router.use('/prefix', child)`.
    #[serde(default)]
    pub mount_methods: Vec<String>,
    /// Methods that give a route object for one path, whose method calls register handlers on
    /// it: `app.route('/book').get(list).post(create)`.
    #[serde(default)]
    pub chain_methods: Vec<String>,
    /// Methods that take the HTTP method first: `router.route('POST', '/users', handler)`.
    #[serde(default)]
    pub verb_first_methods: Vec<String>,
    /// HTTP method names (as `route('POST', ...)` takes them, any case).
    #[serde(default)]
    pub verbs: Vec<String>,
    /// Options keys that give a router (or a mounted plugin) its path prefix:
    /// `new Router({ prefix: '/api' })`, `fastify.register(users, { prefix: '/users' })`.
    #[serde(default)]
    pub prefix_keys: Vec<String>,
    /// Methods that set a router's own path prefix: `new Hono().basePath('/api')`.
    #[serde(default)]
    pub prefix_methods: Vec<String>,
    /// Calls that create a router or app: `express()`, `express.Router()`, `new Koa()`.
    #[serde(default)]
    pub factories: Vec<String>,
    /// Conventional names of routers and apps (lower case; also matched as a suffix).
    #[serde(default)]
    pub names: Vec<String>,
    /// Class decorators that make a controller with a path prefix: `@Controller('users')`.
    #[serde(default)]
    pub controller_decorators: Vec<String>,
    /// Method decorators that register a route: `@Get(':id')`.
    #[serde(default)]
    pub route_decorators: Vec<String>,
    /// Authentication a controller decorator implies for its routes: `RestController: user`.
    #[serde(default)]
    pub controller_auth: BTreeMap<String, SeverityAuth>,
    /// Route options that make a route public: `@Post('/login', { skipAuth: true })`.
    #[serde(default)]
    pub public_options: Vec<String>,
    #[serde(default)]
    pub path_keys: Vec<String>,
    /// Handler registrations on a property of a server: `server.middlewares.use(handler)`.
    #[serde(default)]
    pub middleware_registrations: Vec<MiddlewareRegistration>,
    /// Methods of a promise: `api.get(url).then(...)` (or `await api.get(url)`) sends a request;
    /// a registration returns its router, never a promise.
    #[serde(default)]
    pub promise_methods: Vec<String>,
    /// First parameters of an error-first callback (`api.get(url, (err, data) => ...)`), which
    /// answers a request sent: a route's handler takes the request first (an error handler,
    /// four parameters).
    #[serde(default)]
    pub callback_error_params: Vec<String>,
}

/// `X.<via>.<method>(handler)` registers `(req, res)` handlers whose requests are `kind`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiddlewareRegistration {
    pub via: Vec<String>,
    pub methods: Vec<String>,
    pub kind: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketSpec {
    #[serde(default)]
    pub name_contains: Vec<String>,
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub connection_events: Vec<String>,
    #[serde(default)]
    pub builtin_events: Vec<String>,
    #[serde(default)]
    pub ack_names: Vec<String>,
    /// Catch-all listeners whose first parameter is the event name: `socket.onAny((ev, ...args))`.
    #[serde(default)]
    pub any_methods: Vec<String>,
}

/// A callback registration whose parameters are client data.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSource {
    /// The receiver's name, when it must match.
    #[serde(default)]
    pub object: Option<String>,
    pub methods: Vec<String>,
    /// The first argument, when it must be this string literal.
    #[serde(default)]
    pub event: Option<String>,
    /// The receiver must be `X.<via>` for one of these.
    #[serde(default)]
    pub via: Vec<String>,
    /// The receiver's name, class or chain must contain one of these (lower case):
    /// `emailQueue.process(..)`, `q.process(..)` on a `new Queue()`, `this.mcpServer.tool(..)`,
    /// `t.procedure.input(schema).query(..)`; never `posthtml().process(..)`,
    /// `bootbox.prompt(..)` or `connection.query(sql)`.
    #[serde(default)]
    pub object_contains: Vec<String>,
    /// The callee must be an export of a module of this family: BullMQ's `new Worker(..)`,
    /// never the browser's.
    #[serde(default)]
    pub family: Option<String>,
    /// `callback` (default: any function argument), `last-callback`, `object-of-functions`
    /// (each function-valued property of an object argument) or `resolver-map` (an object
    /// property named like a method whose value is an object of resolver functions).
    #[serde(default)]
    pub shape: Option<String>,
    /// The registration takes exactly this many arguments: tRPC's `.query(resolver)`.
    #[serde(default)]
    pub arity: Option<usize>,
    /// `all`, `first`, `second`, `after-first` or `input` (the `input` field of the first param).
    pub params: String,
    pub kind: String,
    /// Fields of the callback's object parameters that the server chose, not the client: an
    /// upload's temporary `path`.
    #[serde(default)]
    pub server_fields: Vec<String>,
}

/// Request props that hold no objects from a major version of a package on.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScalarFrom {
    pub package: String,
    pub major: u64,
    pub props: Vec<String>,
}

/// A call whose result is client data.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultSource {
    pub methods: Vec<String>,
    pub kind: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Propagation {
    #[serde(default)]
    pub pass_methods: Vec<String>,
    /// Methods that read a value out of their receiver, never out of their arguments
    /// (`params.get('next')` on a URLSearchParams, Headers, FormData or Map): what the
    /// receiver holds, all of it the attacker's when the receiver is.
    #[serde(default)]
    pub receiver_reads: Vec<String>,
    #[serde(default)]
    pub build_methods: Vec<String>,
    #[serde(default)]
    pub iteration_methods: Vec<String>,
    #[serde(default)]
    pub pass_globals: Vec<String>,
    /// The `pass_globals` whose result can be an object built from the text (`JSON.parse`):
    /// a NoSQL operator object. The others give strings.
    #[serde(default)]
    pub object_globals: Vec<String>,
    /// Methods that, with a global negated class and an empty replacement, strip everything
    /// but an allowlist: `s.replace(/[^a-z0-9]/g, '')`.
    #[serde(default)]
    pub strip_methods: Vec<String>,
    /// Array methods whose result is (elements of) the receiver, never their arguments:
    /// `items.find(..)`, `list.filter(..)`, `args.pop()`.
    #[serde(default)]
    pub element_methods: Vec<String>,
    /// Methods that store their arguments, from the given index on, in the receiver:
    /// `args.push(x)` (0), `list.splice(i, n, x)` (2), `map.set(k, v)` (1).
    #[serde(default)]
    pub store_methods: BTreeMap<String, usize>,
    /// Globals that store their later arguments in the first: `Object.assign(target, src)`.
    #[serde(default)]
    pub store_globals: Vec<String>,
    /// Globals whose result holds the keys of their first argument: `Object.keys(o)`.
    #[serde(default)]
    pub key_globals: Vec<String>,
    /// Module functions that return (part of) their first argument, objects included:
    /// `_.cloneDeep(o)`, `_.get(o, path)`, `deepcopy(o)`.
    #[serde(default)]
    pub object_module_pass: Vec<String>,
    /// Methods that call back with the receiver's elements: `list.map((x) => ...)`,
    /// `p.then((v) => ...)`, `s.replace(re, (m, g1) => ...)`.
    #[serde(default)]
    pub callbacks: BTreeMap<String, CallbackSpec>,
    /// Functions that call a function argument with the arguments after it:
    /// `setImmediate(fn, a)`, `setTimeout(fn, ms, a)`.
    #[serde(default)]
    pub forwarders: Vec<ForwarderSpec>,
    /// Schema methods whose result is their (validated) input: `schema.safeParse(req.body)`.
    #[serde(default)]
    pub validating_methods: Vec<String>,
    /// Fields of a validation result that are no input (`r.success`, `r.error`).
    #[serde(default)]
    pub validation_clean_fields: Vec<String>,
    /// Methods of a regular expression that return parts of their argument (`re.exec(s)`).
    #[serde(default)]
    pub regex_methods: Vec<String>,
    /// String methods taking a regular expression that return parts of the receiver
    /// (`s.match(re)`).
    #[serde(default)]
    pub match_methods: Vec<String>,
    /// Globals that return `[key, value]` tuples of their argument (`Object.entries(o)`).
    #[serde(default)]
    pub entry_globals: Vec<String>,
    /// Module functions whose result starts with their first argument (`path.join(root, x)`).
    #[serde(default)]
    pub root_joins: Vec<String>,
    /// Function methods that call the function with the arguments after `this`
    /// (`f.call(that, a, b)`) ...
    #[serde(default)]
    pub call_methods: Vec<String>,
    /// ... or with the elements of an array (`f.apply(that, [a, b])`).
    #[serde(default)]
    pub apply_methods: Vec<String>,
}

/// How a module family makes instances (see [`Pack::instances`]).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceSpec {
    /// Functions of the module that return an instance (`""`: the module called itself).
    #[serde(default)]
    pub factories: Vec<String>,
    /// Classes of the module whose `new` is an instance.
    #[serde(default)]
    pub classes: Vec<String>,
    /// Methods of an instance that return it again (`git.env(..).cwd(..)`).
    #[serde(default)]
    pub fluent: Vec<String>,
}

/// An LLM tool definition (see [`Pack::tool_objects`]).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolObjectSpec {
    /// Keys of the argument schema (a non-array value).
    pub schema_keys: Vec<String>,
    /// Keys of the handler function.
    pub handler_keys: Vec<String>,
    /// Keys that make the object something else (a route configuration).
    #[serde(default)]
    pub not_keys: Vec<String>,
    /// The handler's parameters that hold client data (`first`, `second`, ...): `first` by
    /// default.
    #[serde(default)]
    pub params: Option<String>,
    /// Keys whose literal value names the tool (`name: 'run-sql'`): the entry point's name.
    #[serde(default)]
    pub name_keys: Vec<String>,
    pub kind: String,
}

/// A service worker (see [`Pack::service_worker`]): `self.addEventListener('fetch', ...)`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceWorkerSpec {
    /// Listener registrations (`self.addEventListener`) ...
    #[serde(default)]
    pub registrations: Vec<String>,
    /// ... for these events.
    #[serde(default)]
    pub events: Vec<String>,
    /// Calls only a service worker makes (`self.skipWaiting`).
    #[serde(default)]
    pub calls: Vec<String>,
    /// The source kind of a `request` there.
    pub kind: String,
}

/// A function that forwards arguments to a callback (see [`Propagation::forwarders`]).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwarderSpec {
    /// The forwarding functions, by name (`setImmediate`, `process.nextTick`).
    pub functions: Vec<String>,
    /// The argument that is the callback.
    pub callback: usize,
    /// The first forwarded argument.
    pub from: usize,
}

/// How a method calls its callback (see [`Propagation::callbacks`]).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackSpec {
    /// The argument that is the callback (0 unless given: `replace`'s is 1).
    #[serde(default)]
    pub callback: usize,
    /// The callback's parameters that receive an element of the receiver.
    #[serde(default)]
    pub element: Vec<usize>,
    /// Every parameter receives (a part of) the receiver: `replace`'s match and groups.
    #[serde(default)]
    pub element_all: bool,
    /// The accumulator parameter, seeded with the initial value (the argument after the
    /// callback): `reduce`.
    #[serde(default)]
    pub accumulator: Option<usize>,
    /// The call returns what the callback returns (`map`, `then`; with the initial value for
    /// `reduce`).
    #[serde(default)]
    pub returns: bool,
    /// The call's result is still the receiver's value (`catch`, `finally`: the promise's).
    #[serde(default)]
    pub keeps_receiver: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sanitizers {
    /// Calls whose result is clean.
    #[serde(default)]
    pub calls: Vec<String>,
    /// Calls whose result is a URL with a harmless scheme (`sanitizeUrl(u)`): the attacker no
    /// longer chooses its start. Not an HTML escaper.
    #[serde(default)]
    pub url_checks: Vec<String>,
    /// Calls that, used as a guard (`if (!isValid(x)) return`), clear their argument.
    #[serde(default)]
    pub validators: Vec<String>,
    /// Methods that, true, validate their receiver: `p.startsWith(base)`.
    #[serde(default)]
    pub receiver_validators: Vec<String>,
    /// Objects whose text form is percent-encoded (`${new URLSearchParams(q)}`): no markup,
    /// quote, separator or shell character survives in it.
    #[serde(default)]
    pub encoding_constructors: Vec<String>,
    /// Lookups of a value in a list the server holds, by equality
    /// (`docs.find((d) => d.filename === name)`): found, the value is one of the server's.
    #[serde(default)]
    pub lookup_methods: Vec<String>,
    /// Statements that throw unless their first argument has a type: `check(x, String)`.
    #[serde(default)]
    pub type_assertions: Vec<String>,
    /// Type patterns of those assertions that still admit an object (`check(x, Object)`,
    /// `Match.Any`): no fact. Other patterns (String, `[Number]`, `{ id: String }`, a named
    /// shape) leave scalars.
    #[serde(default)]
    pub object_patterns: Vec<String>,
    /// Checks and clearing calls that make a value safe for some classes only, by class name
    /// (`none` for format checks such as `isURL`, which only prove a string): exact names
    /// (`isPathInside`, `path.basename`) and, for predicates matched by name, words.
    #[serde(default)]
    pub scoped: BTreeMap<String, Vec<String>>,
    /// Callee names (last segment, lower case) starting with these return trusted data:
    /// `jwt.verify(token)`, `verifySig(cookie)`.
    #[serde(default)]
    pub result_cleaning_prefixes: Vec<String>,
    /// Of those, names with one of these words are signature checks whose result is trusted
    /// even when the function is ours (`verifySig(token)`); others (`verifyRequired(x)`) only
    /// when we cannot see them.
    #[serde(default)]
    pub signed_words: Vec<String>,
    /// Words that make a predicate (`isX`, `hasX`, `validateX`) a validator: true means safe.
    #[serde(default)]
    pub validator_words: Vec<String>,
    /// Words that make a predicate a rejecter: true means bad (`isPathTraversal`).
    #[serde(default)]
    pub rejecter_words: Vec<String>,
    /// Methods that, false for a marker, clean their receiver: `p.includes('..')`.
    #[serde(default)]
    pub receiver_rejecters: Vec<String>,
    /// Methods that, true for `-`, reject an option: `p.startsWith('-')` (no argument
    /// injection after it).
    #[serde(default)]
    pub leading_dash_checks: Vec<String>,
    /// Name prefixes that make a function a yes/no question (`isSafe`, `checkPath`).
    #[serde(default)]
    pub predicate_prefixes: Vec<String>,
    /// After such a prefix, words that negate it (`isNotValid`, `isUnsafe`, `isInvalid`).
    #[serde(default)]
    pub negations: Vec<String>,
    /// Prefixes of statements that throw on bad input (`assertSafe(x)`, `ensureValid(x)`).
    #[serde(default)]
    pub assertion_prefixes: Vec<String>,
    #[serde(default)]
    pub rejected_markers: Vec<String>,
    /// Calls that escape for one class only: `class: [calls]`.
    #[serde(default)]
    pub escapers: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VulnClassName {
    CommandInjection,
    CodeInjection,
    SqlInjection,
    NosqlInjection,
    PathTraversal,
    Ssrf,
    Xss,
    PrototypePollution,
}

impl VulnClassName {
    fn class(self) -> VulnClass {
        match self {
            Self::CommandInjection => VulnClass::CommandInjection,
            Self::CodeInjection => VulnClass::CodeInjection,
            Self::SqlInjection => VulnClass::SqlInjection,
            Self::NosqlInjection => VulnClass::NosqlInjection,
            Self::PathTraversal => VulnClass::PathTraversal,
            Self::Ssrf => VulnClass::Ssrf,
            Self::Xss => VulnClass::Xss,
            Self::PrototypePollution => VulnClass::PrototypePollution,
        }
    }
}

/// `url_attributes`: per element tag, the attributes whose URL the browser loads or navigates
/// to (`<a href>`, `<embed src>`, `link.href = v` on `document.createElement('a')`), and the
/// sink they make.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlAttributesSpec {
    pub class: VulnClassName,
    pub severity: SeverityName,
    pub tags: BTreeMap<String, Vec<String>>,
    /// Element methods that set an attribute by name: `a.setAttribute('href', v)`.
    #[serde(default)]
    pub setters: Vec<String>,
}

/// A severity cap for a source kind that holds unless the repository constructs one of
/// `unless_new` anywhere (`new StreamableHTTPServerTransport(..)`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCapSpec {
    pub kind: String,
    pub cap: SeverityName,
    pub unless_new: Vec<String>,
}

/// [`UrlAttributesSpec`], resolved: the sink a URL attribute makes, and the attributes by tag
/// (lower case).
#[derive(Debug, Clone)]
pub struct UrlAttributes {
    pub sink: Sink,
    pub tags: BTreeMap<String, Vec<String>>,
    pub setters: Vec<String>,
}

/// [`LocalCapSpec`], resolved.
#[derive(Debug, Clone)]
pub struct LocalCap {
    pub kind: String,
    pub cap: Severity,
    pub unless_new: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityName {
    Critical,
    High,
    Medium,
    Low,
}

impl SeverityName {
    fn severity(self) -> Severity {
        match self {
            Self::Critical => Severity::Critical,
            Self::High => Severity::High,
            Self::Medium => Severity::Medium,
            Self::Low => Severity::Low,
        }
    }
}

/// How a sink matches its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgRule {
    /// The argument at this index is tainted.
    Any(usize),
    /// Tainted and built by concatenation or a template (and SQL-looking, for SQL sinks).
    Built(usize),
    /// A URL whose start (scheme and host) is tainted, or an options object whose url/host is.
    UrlPrefix(usize),
    /// Tainted and built (string HTML), not a bare value.
    Html(usize),
    /// A tainted value that can be an object: a NoSQL query where `{ "$ne": null }` changes it.
    Object(usize),
    /// [`Self::Object`], when the argument before it names a collection or class with a
    /// literal or a constant: `database.find('_User', { token })`.
    ObjectAfterName(usize),
    /// SQL by contract (`orderByRaw`, `whereRaw`, a column type): any tainted text, built
    /// or not, SQL-looking or not.
    Fragment(usize),
    /// A value (or an element of an argument list) whose start the attacker chooses: an
    /// argument that can begin with `-` (argument injection).
    Start(usize),
}

impl ArgRule {
    fn parse(text: &str) -> Option<Self> {
        let (kind, index) = text.split_once(':')?;
        let index = index.trim().parse().ok()?;
        Some(match kind.trim() {
            "any" => Self::Any(index),
            "built" => Self::Built(index),
            "url" => Self::UrlPrefix(index),
            "start" => Self::Start(index),
            "html" => Self::Html(index),
            "object" => Self::Object(index),
            "object-after-name" => Self::ObjectAfterName(index),
            "fragment" => Self::Fragment(index),
            _ => return None,
        })
    }
}

/// A resolved sink.
#[derive(Debug, Clone)]
pub struct Sink {
    pub class: VulnClass,
    pub severity: Severity,
    pub args: Vec<ArgRule>,
    pub confined_by: Vec<String>,
    /// (option, severity, rules)
    pub escalate: Option<(String, Severity, Vec<ArgRule>)>,
    /// (severity, rules) tried when `args` match nothing.
    pub also: Vec<(Severity, Vec<ArgRule>)>,
    pub ignore_kinds: Vec<String>,
    /// See [`SinkSpec::cleared_by`].
    pub cleared_by: Vec<VulnClass>,
    /// See [`SinkSpec::requires`].
    pub requires: Vec<String>,
    /// See [`SinkSpec::result`]: the call returns the response of its URL.
    pub response: bool,
}

/// Every pack merged.
#[derive(Debug, Default)]
pub struct Model {
    pub modules: BTreeMap<String, String>,
    module_sinks: BTreeMap<(String, String), Sink>,
    global_sinks: BTreeMap<String, Sink>,
    method_sinks: BTreeMap<String, Sink>,
    assign_sinks: BTreeMap<String, Sink>,
    pub request_names: Vec<String>,
    pub request_props: Vec<String>,
    pub request_methods: Vec<String>,
    pub upload_server_fields: Vec<String>,
    pub context_names: Vec<String>,
    pub hono_context_names: Vec<String>,
    pub decorators: Vec<String>,
    pub server_factories: Vec<String>,
    pub route_methods: Vec<String>,
    pub route_exports: Vec<String>,
    pub route_object_methods: Vec<String>,
    pub route_handler_keys: Vec<String>,
    pub socket_name_contains: Vec<String>,
    pub socket_names: Vec<String>,
    pub socket_methods: Vec<String>,
    pub socket_connection_events: Vec<String>,
    pub socket_builtin_events: Vec<String>,
    pub socket_ack_names: Vec<String>,
    pub socket_any_methods: Vec<String>,
    pub client_sources: Vec<ClientSource>,
    pub result_sources: Vec<ResultSource>,
    pub pass_methods: Vec<String>,
    pub receiver_reads: Vec<String>,
    pub build_methods: Vec<String>,
    pub iteration_methods: Vec<String>,
    pub strip_methods: Vec<String>,
    pub element_methods: Vec<String>,
    pub store_methods: BTreeMap<String, usize>,
    pub store_globals: Vec<String>,
    pub key_globals: Vec<String>,
    pub object_module_pass: Vec<String>,
    pub callbacks: BTreeMap<String, CallbackSpec>,
    pub forwarders: Vec<ForwarderSpec>,
    pub validating_methods: Vec<String>,
    pub validation_clean_fields: Vec<String>,
    pub regex_methods: Vec<String>,
    pub match_methods: Vec<String>,
    pub entry_globals: Vec<String>,
    pub root_joins: Vec<String>,
    pub call_methods: Vec<String>,
    pub apply_methods: Vec<String>,
    pub leading_dash_checks: Vec<String>,
    pub predicate_prefixes: Vec<String>,
    pub negations: Vec<String>,
    pub assertion_prefixes: Vec<String>,
    pub route_verbs: Vec<String>,
    pub service_worker: ServiceWorkerSpec,
    pub tool_objects: Vec<ToolObjectSpec>,
    pub instances: BTreeMap<String, InstanceSpec>,
    pub jsx_html_props: Vec<String>,
    pub jsx_html_value_keys: Vec<String>,
    pub component_wrappers: Vec<String>,
    pub props_kind: Option<String>,
    pub page_kinds: Vec<String>,
    pub pass_globals: Vec<String>,
    pub object_globals: Vec<String>,
    pub clearing: Vec<String>,
    pub validators: Vec<String>,
    pub receiver_validators: Vec<String>,
    pub lookup_methods: Vec<String>,
    pub encoding_constructors: Vec<String>,
    pub type_assertions: Vec<String>,
    pub object_patterns: Vec<String>,
    pub scoped_sanitizers: BTreeMap<String, Vec<String>>,
    pub validator_words: Vec<String>,
    pub result_cleaning_prefixes: Vec<String>,
    pub signed_words: Vec<String>,
    pub rejecter_words: Vec<String>,
    pub receiver_rejecters: Vec<String>,
    pub rejected_markers: Vec<String>,
    pub escapers: BTreeMap<String, Vec<String>>,
    pub html_props: Vec<String>,
    pub plain_constructors: Vec<String>,
    pub node_factories: Vec<String>,
    pub sql_keywords: Vec<String>,
    pub sql_pairs: Vec<(String, String)>,
    pub literal_operators: Vec<String>,
    pub orm_options: Vec<String>,
    pub scalar_decorators: Vec<String>,
    pub sanitizing_pipes: Vec<String>,
    pub scalar_kinds: Vec<String>,
    pub sub_objects: Vec<String>,
    pub upload_objects: Vec<String>,
    pub object_props: Vec<String>,
    pub scalar_props_from: Vec<ScalarFrom>,
    /// Every package a sink `requires` (see [`SinkSpec::requires`]).
    pub sink_packages: std::collections::BTreeSet<String>,
    pub member_sources: Vec<MemberSource>,
    pub severity_caps: BTreeMap<String, Severity>,
    pub local_caps: Vec<LocalCap>,
    pub url_checks: Vec<String>,
    pub url_attributes: Option<UrlAttributes>,
    pub implicit_modules: Vec<String>,
    pub module_namespaces: Vec<String>,
    pub url_option_keys: Vec<String>,
    pub module_pass: Vec<String>,
    pub input_fields: Vec<String>,
    pub auth_middleware: Vec<String>,
    pub auth_admin: Vec<String>,
    pub auth_request_fields: Vec<String>,
    pub auth_decorators: Vec<String>,
    pub auth_setup: Vec<String>,
    pub route_method_keys: Vec<String>,
    pub mount_methods: Vec<String>,
    pub route_chain_methods: Vec<String>,
    pub route_verb_first_methods: Vec<String>,
    pub promise_methods: Vec<String>,
    pub callback_error_params: Vec<String>,
    pub route_prefix_keys: Vec<String>,
    pub route_prefix_methods: Vec<String>,
    pub router_factories: Vec<String>,
    pub router_names: Vec<String>,
    pub controller_decorators: Vec<String>,
    pub route_decorators: Vec<String>,
    pub controller_auth: BTreeMap<String, jss_core::Auth>,
    pub public_options: Vec<String>,
    pub middleware_registrations: Vec<MiddlewareRegistration>,
    pub route_path_keys: Vec<String>,
    /// Packs that failed to load, with the reason.
    pub errors: Vec<String>,
}

impl Model {
    /// Merges packs given as (name, YAML text).
    pub fn from_packs<'a>(packs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut model = Model::default();
        for (name, text) in packs {
            match serde_norway::from_str::<Pack>(text) {
                Ok(pack) => model.add(pack),
                Err(err) => model.errors.push(format!("pack {name}: {err}")),
            }
        }
        model
    }

    fn add(&mut self, pack: Pack) {
        self.modules.extend(pack.modules);
        for spec in pack.sinks {
            let args: Vec<ArgRule> = spec.args.iter().filter_map(|a| ArgRule::parse(a)).collect();
            if args.len() != spec.args.len() {
                self.errors.push(format!(
                    "pack {}: bad argument rule in {:?}",
                    pack.name, spec.args
                ));
            }
            let escalate = spec.escalate.as_ref().map(|e| {
                (
                    e.option.clone(),
                    e.severity.severity(),
                    e.args.iter().filter_map(|a| ArgRule::parse(a)).collect(),
                )
            });
            let sink = Sink {
                class: spec.class.class(),
                severity: spec.severity.severity(),
                args,
                confined_by: spec.confined_by.clone(),
                escalate,
                also: spec
                    .also
                    .iter()
                    .map(|a| {
                        (
                            a.severity.severity(),
                            a.args.iter().filter_map(|r| ArgRule::parse(r)).collect(),
                        )
                    })
                    .collect(),
                ignore_kinds: spec.ignore_kinds.clone(),
                cleared_by: spec.cleared_by.iter().map(|c| c.class()).collect(),
                requires: spec.requires.clone(),
                response: spec.result.as_deref() == Some("url"),
            };
            self.sink_packages.extend(spec.requires.iter().cloned());
            if let Some(module) = &spec.module {
                for export in &spec.exports {
                    self.module_sinks
                        .insert((module.clone(), export.clone()), sink.clone());
                }
            }
            for name in &spec.global {
                self.global_sinks.insert(name.clone(), sink.clone());
            }
            for name in &spec.methods {
                self.method_sinks.insert(name.clone(), sink.clone());
            }
            for target in &spec.assign {
                self.assign_sinks.insert(target.clone(), sink.clone());
            }
        }
        let r = pack.request;
        self.request_names.extend(r.names);
        self.request_props.extend(r.props);
        self.request_methods.extend(r.methods);
        self.upload_server_fields.extend(r.upload_server_fields);
        self.context_names.extend(r.context_names);
        self.hono_context_names.extend(r.hono_context_names);
        self.decorators.extend(r.decorators);
        self.server_factories.extend(r.server_factories);
        self.route_methods.extend(pack.routes.methods);
        self.route_exports.extend(pack.routes.exports);
        self.route_object_methods.extend(pack.routes.object_methods);
        self.route_handler_keys.extend(pack.routes.handler_keys);
        let s = pack.sockets;
        self.socket_name_contains.extend(s.name_contains);
        self.socket_names.extend(s.names);
        self.socket_methods.extend(s.methods);
        self.socket_connection_events.extend(s.connection_events);
        self.socket_builtin_events.extend(s.builtin_events);
        self.socket_ack_names.extend(s.ack_names);
        self.socket_any_methods.extend(s.any_methods);
        self.client_sources.extend(pack.client_sources);
        self.result_sources.extend(pack.result_sources);
        self.pass_methods.extend(pack.propagation.pass_methods);
        self.receiver_reads.extend(pack.propagation.receiver_reads);
        self.build_methods.extend(pack.propagation.build_methods);
        self.iteration_methods
            .extend(pack.propagation.iteration_methods);
        self.strip_methods.extend(pack.propagation.strip_methods);
        self.element_methods
            .extend(pack.propagation.element_methods);
        self.store_methods.extend(pack.propagation.store_methods);
        self.store_globals.extend(pack.propagation.store_globals);
        self.key_globals.extend(pack.propagation.key_globals);
        self.object_module_pass
            .extend(pack.propagation.object_module_pass);
        self.callbacks.extend(pack.propagation.callbacks);
        self.forwarders.extend(pack.propagation.forwarders);
        self.validating_methods
            .extend(pack.propagation.validating_methods);
        self.validation_clean_fields
            .extend(pack.propagation.validation_clean_fields);
        self.regex_methods.extend(pack.propagation.regex_methods);
        self.match_methods.extend(pack.propagation.match_methods);
        self.entry_globals.extend(pack.propagation.entry_globals);
        self.root_joins.extend(pack.propagation.root_joins);
        self.call_methods.extend(pack.propagation.call_methods);
        self.apply_methods.extend(pack.propagation.apply_methods);
        self.leading_dash_checks
            .extend(pack.sanitizers.leading_dash_checks);
        self.predicate_prefixes
            .extend(pack.sanitizers.predicate_prefixes);
        self.negations.extend(pack.sanitizers.negations);
        self.assertion_prefixes
            .extend(pack.sanitizers.assertion_prefixes);
        self.route_verbs
            .extend(pack.routes.verbs.iter().map(|v| v.to_ascii_lowercase()));
        self.tool_objects.extend(pack.tool_objects);
        for (family, spec) in pack.instances {
            let entry = self.instances.entry(family).or_default();
            entry.factories.extend(spec.factories);
            entry.classes.extend(spec.classes);
            entry.fluent.extend(spec.fluent);
        }
        if let Some(worker) = pack.service_worker {
            self.service_worker
                .registrations
                .extend(worker.registrations);
            self.service_worker.events.extend(worker.events);
            self.service_worker.calls.extend(worker.calls);
            self.service_worker.kind = worker.kind;
        }
        self.jsx_html_props.extend(pack.jsx.html_props);
        self.component_wrappers.extend(pack.jsx.component_wrappers);
        self.jsx_html_value_keys.extend(pack.jsx.html_value_keys);
        if pack.jsx.props_kind.is_some() {
            self.props_kind = pack.jsx.props_kind;
        }
        self.pass_globals.extend(pack.propagation.pass_globals);
        self.object_globals.extend(pack.propagation.object_globals);
        self.clearing.extend(pack.sanitizers.calls);
        self.url_checks.extend(pack.sanitizers.url_checks);
        if let Some(spec) = pack.url_attributes {
            self.url_attributes = Some(UrlAttributes {
                sink: Sink {
                    class: spec.class.class(),
                    severity: spec.severity.severity(),
                    args: vec![ArgRule::UrlPrefix(0)],
                    confined_by: Vec::new(),
                    escalate: None,
                    also: Vec::new(),
                    ignore_kinds: Vec::new(),
                    cleared_by: Vec::new(),
                    requires: Vec::new(),
                    response: false,
                },
                tags: spec.tags,
                setters: spec.setters,
            });
        }
        self.validators.extend(pack.sanitizers.validators);
        self.receiver_validators
            .extend(pack.sanitizers.receiver_validators);
        self.lookup_methods.extend(pack.sanitizers.lookup_methods);
        self.encoding_constructors
            .extend(pack.sanitizers.encoding_constructors);
        self.type_assertions.extend(pack.sanitizers.type_assertions);
        self.object_patterns.extend(pack.sanitizers.object_patterns);
        for (class, names) in pack.sanitizers.scoped {
            self.scoped_sanitizers
                .entry(class)
                .or_default()
                .extend(names);
        }
        self.validator_words.extend(pack.sanitizers.validator_words);
        self.result_cleaning_prefixes
            .extend(pack.sanitizers.result_cleaning_prefixes);
        self.signed_words.extend(pack.sanitizers.signed_words);
        self.rejecter_words.extend(pack.sanitizers.rejecter_words);
        self.receiver_rejecters
            .extend(pack.sanitizers.receiver_rejecters);
        self.rejected_markers
            .extend(pack.sanitizers.rejected_markers);
        for (class, calls) in pack.sanitizers.escapers {
            self.escapers.entry(class).or_default().extend(calls);
        }
        self.html_props.extend(pack.html_props);
        self.page_kinds.extend(pack.page_kinds);
        self.plain_constructors.extend(pack.plain_constructors);
        self.node_factories.extend(pack.node_factories);
        self.sql_keywords.extend(pack.sql_keywords);
        self.sql_pairs.extend(pack.sql_pairs);
        self.literal_operators.extend(pack.literal_operators);
        self.orm_options.extend(pack.orm_options);
        self.sub_objects.extend(r.sub_objects);
        self.upload_objects.extend(r.upload_objects);
        self.object_props.extend(r.object_props);
        self.scalar_decorators.extend(r.scalar_decorators);
        self.sanitizing_pipes.extend(r.sanitizing_pipes);
        self.scalar_kinds.extend(r.scalar_kinds);
        self.scalar_props_from.extend(r.scalar_props_from);
        self.member_sources.extend(pack.member_sources);
        for (kind, cap) in pack.severity_caps {
            self.severity_caps.insert(kind, cap.severity());
        }
        self.local_caps
            .extend(pack.local_caps.into_iter().map(|c| LocalCap {
                kind: c.kind,
                cap: c.cap.severity(),
                unless_new: c.unless_new,
            }));
        self.implicit_modules.extend(pack.implicit_modules);
        self.module_namespaces.extend(pack.module_namespaces);
        self.url_option_keys.extend(pack.url_option_keys);
        self.module_pass.extend(pack.module_pass);
        self.auth_middleware.extend(pack.auth.middleware);
        self.auth_admin.extend(pack.auth.admin);
        self.auth_request_fields.extend(pack.auth.request_fields);
        self.auth_setup
            .extend(pack.auth.setup.iter().map(|n| n.to_ascii_lowercase()));
        self.auth_decorators.extend(pack.auth.decorators);
        self.input_fields.extend(pack.input_fields);
        self.route_method_keys.extend(pack.routes.method_keys);
        self.mount_methods.extend(pack.routes.mount_methods);
        self.route_chain_methods.extend(pack.routes.chain_methods);
        self.route_verb_first_methods
            .extend(pack.routes.verb_first_methods);
        self.promise_methods.extend(pack.routes.promise_methods);
        self.callback_error_params
            .extend(pack.routes.callback_error_params);
        self.route_prefix_keys.extend(pack.routes.prefix_keys);
        self.route_prefix_methods.extend(pack.routes.prefix_methods);
        self.router_factories.extend(pack.routes.factories);
        self.router_names.extend(pack.routes.names);
        self.controller_decorators
            .extend(pack.routes.controller_decorators);
        self.route_decorators.extend(pack.routes.route_decorators);
        for (decorator, auth) in pack.routes.controller_auth {
            let auth = match auth {
                SeverityAuth::User => jss_core::Auth::User,
                SeverityAuth::Admin => jss_core::Auth::Admin,
            };
            self.controller_auth.insert(decorator, auth);
        }
        self.public_options.extend(pack.routes.public_options);
        self.middleware_registrations
            .extend(pack.routes.middleware_registrations);
        self.route_path_keys.extend(pack.routes.path_keys);
    }

    /// The family of a module specifier (`node:` prefix ignored).
    pub fn module_family(&self, spec: &str) -> Option<&str> {
        let spec = spec.strip_prefix("node:").unwrap_or(spec);
        self.modules.get(spec).map(String::as_str)
    }

    pub fn module_sink(&self, family: &str, export: &str) -> Option<&Sink> {
        self.module_sinks
            .get(&(family.to_owned(), export.to_owned()))
    }

    pub fn global_sink(&self, name: &str) -> Option<&Sink> {
        self.global_sinks.get(name)
    }

    pub fn method_sink(&self, method: &str) -> Option<&Sink> {
        self.method_sinks.get(method)
    }

    /// The sink an assignment to `target` (an access path) is.
    pub fn assign_sink(&self, target: &str) -> Option<&Sink> {
        self.assign_sinks.get(target)
    }

    /// Literal text that looks like part of an SQL statement (a keyword as a whole word).
    pub fn looks_like_sql(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        let words: Vec<&str> = lower
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty())
            .collect();
        // A statement or a clause starts it: `SELECT ...`, `" WHERE id = "`, `"' AND x = '"`.
        if words
            .first()
            .is_some_and(|first| has(&self.sql_keywords, first))
        {
            return true;
        }
        // A statement's keywords in order: `... select name from ...`. One keyword anywhere
        // (`rate-limit:`, `?from=`) is no SQL.
        self.sql_pairs.iter().any(|(a, b)| {
            words
                .iter()
                .position(|w| w == a)
                .is_some_and(|at| words.iter().skip(at + 1).any(|w| w == b))
        })
    }

    /// The authentication a middleware or guard name implies, if any.
    pub fn auth_of(&self, name: &str) -> Option<jss_core::Auth> {
        let lower = name.to_ascii_lowercase();
        // `session ` from `session({...})`: the callee, without its string arguments.
        let head = lower.split_whitespace().next().unwrap_or("");
        if self.auth_setup.iter().any(|s| s == head) {
            return None;
        }
        if self.auth_admin.iter().any(|a| lower.contains(a.as_str())) {
            Some(jss_core::Auth::Admin)
        } else if self
            .auth_middleware
            .iter()
            .any(|a| lower.contains(a.as_str()))
        {
            Some(jss_core::Auth::User)
        } else {
            None
        }
    }

    /// Every sink API of `class`, as written in the packs: `child_process.exec`, `eval`,
    /// `.query` (a method on any receiver), `innerHTML =` (an assignment). Sorted, deduplicated.
    pub fn sink_names(&self, class: VulnClass) -> Vec<String> {
        let mut names: Vec<String> = self
            .module_sinks
            .iter()
            .filter(|(_, sink)| sink.class == class)
            .map(|((module, export), _)| {
                if export.is_empty() {
                    format!("{module}()")
                } else {
                    format!("{module}.{export}")
                }
            })
            .chain(
                self.global_sinks
                    .iter()
                    .filter(|(_, sink)| sink.class == class)
                    .map(|(name, _)| name.clone()),
            )
            .chain(
                self.method_sinks
                    .iter()
                    .filter(|(_, sink)| sink.class == class)
                    .map(|(name, _)| {
                        if name.contains('.') {
                            name.clone()
                        } else {
                            format!(".{name}")
                        }
                    }),
            )
            .chain(
                self.assign_sinks
                    .iter()
                    .filter(|(_, sink)| sink.class == class)
                    .map(|(target, _)| format!("{target} =")),
            )
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Caps `severity` by the source kind's cap (a lower severity sorts later).
    pub fn cap(&self, kind: &str, severity: Severity) -> Severity {
        match self.severity_caps.get(kind) {
            Some(cap) if severity < *cap => *cap,
            _ => severity,
        }
    }

    /// The sink `tag`'s attribute (or DOM property) `attribute` makes when it holds a URL the
    /// browser loads or navigates to: `<a href>`, `<embed src>`, `a.href = v`.
    pub fn url_attribute(&self, tag: &str, attribute: &str) -> Option<&Sink> {
        let spec = self.url_attributes.as_ref()?;
        spec.tags
            .get(&tag.to_ascii_lowercase())?
            .iter()
            .any(|a| a.eq_ignore_ascii_case(attribute))
            .then_some(&spec.sink)
    }

    /// Whether `call` (a callee name, `obj.method` or `method`) escapes data for `class`.
    pub fn escapes(&self, class: VulnClass, call: &str) -> bool {
        // `escapeHTML` and `escapeHtml` are the same escaper.
        self.escapers
            .get(class.name())
            .is_some_and(|calls| calls.iter().any(|c| c.eq_ignore_ascii_case(call)))
    }
}

/// The model in use: the built-in packs, plus the extra ones given to [`install`].
static MODEL: OnceLock<Model> = OnceLock::new();

/// Installs the model: the built-in packs followed by `extra` (name, YAML text), merged the same
/// way. Call it once, before the first [`model`] call (that is, before scanning); afterwards the
/// model is fixed and this fails. A pack that fails to load fails the install, with every error.
pub fn install(extra: &[(String, String)]) -> Result<(), Vec<String>> {
    let model = Model::from_packs(
        BUILTIN_PACKS.iter().copied().chain(
            extra
                .iter()
                .map(|(name, text)| (name.as_str(), text.as_str())),
        ),
    );
    if !model.errors.is_empty() {
        return Err(model.errors);
    }
    MODEL
        .set(model)
        .map_err(|_| vec!["the taint model is already in use".to_owned()])
}

/// The model: the one [`install`]ed, or else the built-in packs alone.
pub fn model() -> &'static Model {
    MODEL.get_or_init(|| Model::from_packs(BUILTIN_PACKS.iter().copied()))
}

/// `list` contains `name`.
pub fn has(list: &[String], name: &str) -> bool {
    list.iter().any(|item| item == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_pack_loads() {
        let model = model();
        assert!(model.errors.is_empty(), "{:?}", model.errors);
        assert!(model.module_sink("child_process", "exec").is_some());
        assert!(model.global_sink("eval").is_some());
        assert!(model.method_sink("query").is_some());
        assert_eq!(model.module_family("node:fs"), Some("fs"));
    }

    #[test]
    fn sinks_are_listed_by_class() {
        let model = Model::from_packs(BUILTIN_PACKS.iter().copied());
        let commands = model.sink_names(VulnClass::CommandInjection);
        assert!(
            commands.iter().any(|n| n == "child_process.exec"),
            "{commands:?}"
        );
        assert!(!commands.iter().any(|n| n == "eval"));
        let code = model.sink_names(VulnClass::CodeInjection);
        assert!(code.iter().any(|n| n == "eval"), "{code:?}");
    }

    #[test]
    fn a_bad_pack_is_reported_not_dropped() {
        let model = Model::from_packs([("bad", "name: bad\nsinks: [{class: nope}]\n")]);
        assert_eq!(model.errors.len(), 1);
    }
}
