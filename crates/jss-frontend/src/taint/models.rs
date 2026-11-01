//! The taint model, loaded from the YAML packs in `packs/` (embedded at build time).
//!
//! The engine holds no framework or library names: every source, sink, propagator, sanitizer
//! and route convention comes from a pack. Packs share one schema; every section is optional and
//! packs are merged by concatenation. A pack that fails to load is reported in
//! [`Model::errors`], never silently dropped.

use std::collections::BTreeMap;
use std::sync::LazyLock;

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
    ("graphql", include_str!("../../../../packs/graphql.yaml")),
    ("trpc", include_str!("../../../../packs/trpc.yaml")),
    ("queues", include_str!("../../../../packs/queues.yaml")),
    ("meteor", include_str!("../../../../packs/meteor.yaml")),
    ("electron", include_str!("../../../../packs/electron.yaml")),
    ("browser", include_str!("../../../../packs/browser.yaml")),
    ("archive", include_str!("../../../../packs/archive.yaml")),
    ("auth", include_str!("../../../../packs/auth.yaml")),
    ("react", include_str!("../../../../packs/react.yaml")),
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
    #[serde(default)]
    pub sql_keywords: Vec<String>,
    /// Member reads that are client data: `process.argv`.
    #[serde(default)]
    pub member_sources: Vec<MemberSource>,
    /// The highest severity a source kind can reach: `cli: low`.
    #[serde(default)]
    pub severity_caps: BTreeMap<String, SeverityName>,
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
}

/// A member read whose value is client data.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberSource {
    pub object: String,
    pub property: String,
    pub kind: String,
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
    /// Methods, on any receiver.
    #[serde(default)]
    pub methods: Vec<String>,
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
    #[serde(default)]
    pub path_keys: Vec<String>,
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
    #[serde(default)]
    pub build_methods: Vec<String>,
    #[serde(default)]
    pub iteration_methods: Vec<String>,
    #[serde(default)]
    pub pass_globals: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sanitizers {
    /// Calls whose result is clean.
    #[serde(default)]
    pub calls: Vec<String>,
    /// Calls that, used as a guard (`if (!isValid(x)) return`), clear their argument.
    #[serde(default)]
    pub validators: Vec<String>,
    /// Methods that, true, validate their receiver: `p.startsWith(base)`.
    #[serde(default)]
    pub receiver_validators: Vec<String>,
    /// Statements that throw unless their first argument has a type: `check(x, String)`.
    #[serde(default)]
    pub type_assertions: Vec<String>,
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
}

impl ArgRule {
    fn parse(text: &str) -> Option<Self> {
        let (kind, index) = text.split_once(':')?;
        let index = index.trim().parse().ok()?;
        Some(match kind.trim() {
            "any" => Self::Any(index),
            "built" => Self::Built(index),
            "url" => Self::UrlPrefix(index),
            "html" => Self::Html(index),
            "object" => Self::Object(index),
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
}

/// Every pack merged.
#[derive(Debug, Default)]
pub struct Model {
    pub modules: BTreeMap<String, String>,
    module_sinks: BTreeMap<(String, String), Sink>,
    global_sinks: BTreeMap<String, Sink>,
    method_sinks: BTreeMap<String, Sink>,
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
    pub build_methods: Vec<String>,
    pub iteration_methods: Vec<String>,
    pub jsx_html_props: Vec<String>,
    pub jsx_html_value_keys: Vec<String>,
    pub props_kind: Option<String>,
    pub pass_globals: Vec<String>,
    pub clearing: Vec<String>,
    pub validators: Vec<String>,
    pub receiver_validators: Vec<String>,
    pub type_assertions: Vec<String>,
    pub escapers: BTreeMap<String, Vec<String>>,
    pub html_props: Vec<String>,
    pub sql_keywords: Vec<String>,
    pub sub_objects: Vec<String>,
    pub upload_objects: Vec<String>,
    pub object_props: Vec<String>,
    pub member_sources: Vec<MemberSource>,
    pub severity_caps: BTreeMap<String, Severity>,
    pub implicit_modules: Vec<String>,
    pub module_namespaces: Vec<String>,
    pub url_option_keys: Vec<String>,
    pub module_pass: Vec<String>,
    pub input_fields: Vec<String>,
    pub auth_middleware: Vec<String>,
    pub auth_admin: Vec<String>,
    pub auth_request_fields: Vec<String>,
    pub auth_decorators: Vec<String>,
    pub route_method_keys: Vec<String>,
    pub mount_methods: Vec<String>,
    pub router_factories: Vec<String>,
    pub router_names: Vec<String>,
    pub controller_decorators: Vec<String>,
    pub route_decorators: Vec<String>,
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
            };
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
        self.build_methods.extend(pack.propagation.build_methods);
        self.iteration_methods
            .extend(pack.propagation.iteration_methods);
        self.jsx_html_props.extend(pack.jsx.html_props);
        self.jsx_html_value_keys.extend(pack.jsx.html_value_keys);
        if pack.jsx.props_kind.is_some() {
            self.props_kind = pack.jsx.props_kind;
        }
        self.pass_globals.extend(pack.propagation.pass_globals);
        self.clearing.extend(pack.sanitizers.calls);
        self.validators.extend(pack.sanitizers.validators);
        self.receiver_validators
            .extend(pack.sanitizers.receiver_validators);
        self.type_assertions.extend(pack.sanitizers.type_assertions);
        for (class, calls) in pack.sanitizers.escapers {
            self.escapers.entry(class).or_default().extend(calls);
        }
        self.html_props.extend(pack.html_props);
        self.sql_keywords.extend(pack.sql_keywords);
        self.sub_objects.extend(r.sub_objects);
        self.upload_objects.extend(r.upload_objects);
        self.object_props.extend(r.object_props);
        self.member_sources.extend(pack.member_sources);
        for (kind, cap) in pack.severity_caps {
            self.severity_caps.insert(kind, cap.severity());
        }
        self.implicit_modules.extend(pack.implicit_modules);
        self.module_namespaces.extend(pack.module_namespaces);
        self.url_option_keys.extend(pack.url_option_keys);
        self.module_pass.extend(pack.module_pass);
        self.auth_middleware.extend(pack.auth.middleware);
        self.auth_admin.extend(pack.auth.admin);
        self.auth_request_fields.extend(pack.auth.request_fields);
        self.auth_decorators.extend(pack.auth.decorators);
        self.input_fields.extend(pack.input_fields);
        self.route_method_keys.extend(pack.routes.method_keys);
        self.mount_methods.extend(pack.routes.mount_methods);
        self.router_factories.extend(pack.routes.factories);
        self.router_names.extend(pack.routes.names);
        self.controller_decorators
            .extend(pack.routes.controller_decorators);
        self.route_decorators.extend(pack.routes.route_decorators);
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

    /// Literal text that looks like part of an SQL statement (a keyword as a whole word).
    pub fn looks_like_sql(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        self.sql_keywords.iter().any(|keyword| {
            lower.match_indices(keyword.as_str()).any(|(at, _)| {
                let before = lower.get(..at).and_then(|s| s.chars().next_back());
                let after = lower
                    .get(at + keyword.len()..)
                    .and_then(|s| s.chars().next());
                let boundary =
                    |c: Option<char>| c.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
                boundary(before) && boundary(after)
            })
        })
    }

    /// The authentication a middleware or guard name implies, if any.
    pub fn auth_of(&self, name: &str) -> Option<jss_core::Auth> {
        let lower = name.to_ascii_lowercase();
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

    /// Caps `severity` by the source kind's cap (a lower severity sorts later).
    pub fn cap(&self, kind: &str, severity: Severity) -> Severity {
        match self.severity_caps.get(kind) {
            Some(cap) if severity < *cap => *cap,
            _ => severity,
        }
    }

    /// Whether `call` (a callee name, `obj.method` or `method`) escapes data for `class`.
    pub fn escapes(&self, class: VulnClass, call: &str) -> bool {
        self.escapers
            .get(class.name())
            .is_some_and(|calls| calls.iter().any(|c| c == call))
    }
}

/// The built-in model.
static MODEL: LazyLock<Model> = LazyLock::new(|| Model::from_packs(BUILTIN_PACKS.iter().copied()));

/// The built-in model.
pub fn model() -> &'static Model {
    &MODEL
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
    fn a_bad_pack_is_reported_not_dropped() {
        let model = Model::from_packs([("bad", "name: bad\nsinks: [{class: nope}]\n")]);
        assert_eq!(model.errors.len(), 1);
    }
}
