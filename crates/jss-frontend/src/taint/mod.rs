//! `scan` v0: a single-file, intra-procedural taint spike over the oxc AST.
//!
//! Scope, stated so nobody mistakes it for the plan's M1 engine:
//! - A hand-rolled walker; symbols are keyed by name per function (shadowing is not modeled).
//! - Closures see a copy of their parent's tainted names. Calls into user functions are NOT
//!   followed: an unknown call's result is untainted unless listed in [`models`].
//! - Sources and sinks are heuristic tables ([`models`]). Regex/allowlist guards are not
//!   recognized. Every finding is a triage candidate, never a verdict.
//! - Assignments inside a branch or loop only ever add taint; outside them, an untainted
//!   assignment clears it.
//! - Recursion is capped at [`MAX_DEPTH`]; a capped file says so (`truncated`).

mod guards;
pub mod models;

use std::collections::{BTreeMap, BTreeSet};

use jss_core::{Auth, Severity, VulnClass};
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, ArrowFunctionBody, AssignmentTarget, BindingPattern,
    CallExpression, Class, ClassElement, Declaration, ExportDefaultDeclarationKind, Expression,
    ForStatementInit, ForStatementLeft, FormalParameters, Function, ModuleDeclaration,
    ObjectPropertyKind, Program, PropertyKey, Statement, UnaryOperator, VariableDeclaration,
    VariableDeclarationKind,
};
use oxc_ast::ast::{BinaryOperator, SimpleAssignmentTarget};
use oxc_span::{GetSpan, Span};

use models::{ArgRule, Model, has};

fn m() -> &'static Model {
    models::model()
}

/// Deepest AST recursion the walker follows before giving up on a subtree.
pub const MAX_DEPTH: u32 = 300;
/// Steps kept per trace.
const MAX_STEPS: usize = 16;

/// Where a tainted value came from, and how it got here.
#[derive(Debug, Clone)]
pub struct Origin {
    pub kind: &'static str,
    pub span: Span,
    /// (offset, note) for each step since the source.
    pub steps: Vec<(u32, String)>,
    /// Passed through string concatenation, a template or a formatter.
    pub built: bool,
    /// The tainted data is (still) at the start of the string.
    pub prefix: bool,
    /// Concatenated with literal text that looks like SQL.
    pub sqlish: bool,
    /// Summary pass only: this is the value of the enclosing function's parameter `n`.
    pub param: Option<usize>,
    /// Can be an object (JSON body, qs query, socket payload), not only a string.
    pub object: bool,
    /// Escaped for these classes (bit [`class_bit`]) by an escaper from the packs: an HTML
    /// escaper makes a value safe in HTML, not in a shell command.
    pub escaped: u8,
}

/// The bit of `class` in [`Origin::escaped`].
fn class_bit(class: VulnClass) -> u8 {
    1 << (class as u8)
}

/// The `param` of a return summary whose value is client data, whatever the arguments.
const RETURNS_SOURCE: usize = usize::MAX;

/// The `api` of a summary that says "the function returns this parameter" (not a sink).
pub const RETURNS: &str = "<return>";

/// The `api` of a summary that says "the function throws unless this parameter is valid": a
/// void helper whose exit-on-failure guards clean it (`function assertSafe(p) { if (!ok(p))
/// throw ... }`). After a call returns, the argument is clean.
pub const VALIDATES: &str = "<validates>";

/// The request-kind marker for a context object whose request data is under `.req`.
const CONTEXT: &str = "context";

impl Origin {
    /// A fresh source of `kind` at `span`.
    fn source(kind: &'static str, span: Span) -> Self {
        Origin {
            kind,
            span,
            steps: Vec::new(),
            built: false,
            prefix: true,
            sqlish: false,
            escaped: 0,
            param: None,
            object: true,
        }
    }

    fn step(mut self, offset: u32, note: String) -> Self {
        if self.steps.len() < MAX_STEPS {
            self.steps.push((offset, note));
        }
        self
    }
}

/// A sink reached by a tainted value, with byte offsets (the caller makes lines of them).
#[derive(Debug, Clone)]
pub struct RawFinding {
    pub class: VulnClass,
    pub severity: Severity,
    pub api: String,
    pub arg: Span,
    pub call: Span,
    pub function: String,
    pub origin: Origin,
    /// The sink is in another file (reached through a repo-wide summary).
    pub ext: Option<ExtSink>,
    /// Authentication recognized on the way (set when the finding is recorded).
    pub auth: Auth,
}

/// A sink in another file, already resolved to a location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtSink {
    pub file: String,
    pub line: u32,
    pub col: u32,
    pub arg: String,
    /// The helper's own steps, located in its file.
    pub steps: Vec<jss_core::TraceStep>,
}

/// Repo-wide summaries: function name -> parameters that reach a sink.
pub type Summaries = BTreeMap<String, Vec<Summary>>;

/// Result of scanning one program.
#[derive(Debug, Default)]
pub struct ScanResult {
    pub findings: Vec<RawFinding>,
    pub truncated: bool,
    /// This file's named functions whose parameters reach a sink.
    pub summaries: Summaries,
    /// Entry points, mounts, exports and imports, for the inventory.
    pub facts: FileFacts,
    /// This file's route templates (functions that register routes from their parameters).
    pub templates: BTreeMap<String, Vec<RouteTemplate>>,
    /// This file's constants: `Enum.Member`, `NAME`, `OBJ.key` -> text.
    pub constants: BTreeMap<String, String>,
}

/// Scans a parsed program on its own.
#[cfg(test)]
fn scan_program(program: &Program<'_>, _text: &str) -> ScanResult {
    scan_program_with(program, &Summaries::new())
}

/// Scans a parsed program, with summaries of the repository's other files.
pub fn scan_program_with(program: &Program<'_>, external: &Summaries) -> ScanResult {
    let files = BTreeSet::new();
    let workspace = jss_core::resolve::Workspace::default();
    let reexports = BTreeMap::new();
    let templates = Templates::new();
    let constants = BTreeMap::new();
    let exports = BTreeMap::new();
    let linking = Linking {
        file: "",
        files: &files,
        workspace: &workspace,
        reexports: &reexports,
        templates: &templates,
        constants: &constants,
        exports: &exports,
        scalar_props: &[],
    };
    scan_file_program(program, &linking, external)
}

/// Where a program sits in its scan root: its path and every file next to it, for resolving
/// relative imports.
#[derive(Debug, Clone, Copy)]
pub struct Linking<'a> {
    pub file: &'a str,
    pub files: &'a BTreeSet<String>,
    /// The monorepo's own packages, for bare specifiers that name one.
    pub workspace: &'a jss_core::resolve::Workspace,
    /// File -> every file it re-exports (transitively): barrels (`export * from './x'`).
    pub reexports: &'a BTreeMap<String, BTreeSet<String>>,
    /// Route templates found in every file (from the previous round).
    pub templates: &'a Templates,
    /// Constants of every file (enum members, `const` strings): file -> name -> value.
    pub constants: &'a BTreeMap<String, BTreeMap<String, String>>,
    /// Exports of every file (from the previous round): file -> export name -> local name.
    pub exports: &'a BTreeMap<String, BTreeMap<String, String>>,
    /// Request props that hold only strings and arrays in this file's package (`query` with
    /// Express 5).
    pub scalar_props: &'a [String],
}

impl Linking<'_> {
    /// The file `spec` names from this file: relative, or a package of the workspace.
    pub fn resolve(&self, spec: &str) -> Option<String> {
        if spec.starts_with('.') {
            jss_core::resolve::resolve(self.file, spec, self.files)
        } else {
            self.workspace.resolve(spec, self.files).or_else(|| {
                self.workspace
                    .resolve_typescript(self.file, spec, self.files)
            })
        }
    }

    /// Whether `spec` is one of our own modules (relative, or a workspace package).
    pub fn is_own(&self, spec: &str) -> bool {
        spec.starts_with('.') || (!self.workspace.is_empty() && self.resolve(spec).is_some())
    }
}

/// Scans a parsed program that is `linking.file` in a scan root, with the root's summaries.
pub fn scan_file_program(
    program: &Program<'_>,
    linking: &Linking<'_>,
    external: &Summaries,
) -> ScanResult {
    let mut walker = Walker {
        external,
        linking,
        facts: FileFacts::default(),
        field_of: BTreeMap::new(),
        pending_auth: Auth::NoneDetected,
        pending_request_kind: std::cell::Cell::new(None),
        pending_server_fields: std::cell::Cell::new(None),
        router_auth: BTreeMap::new(),
        inline_names: BTreeMap::new(),
        routers: BTreeSet::new(),
        injected: BTreeMap::new(),
        export_aliases: BTreeSet::new(),
        constants: BTreeMap::new(),
        last_returned_fields: None,
        route_templates: BTreeMap::new(),
        record_only: false,
        current_class: None,
        class_fields: BTreeMap::new(),
        ctor_params: BTreeMap::new(),
        modules: BTreeMap::new(),
        relative: BTreeMap::new(),
        result: ScanResult::default(),
        depth: 0,
        summarize: true,
        summaries: BTreeMap::new(),
    };
    // Two summary passes: the second sees the first's summaries (helpers calling helpers).
    for _ in 0..2 {
        walker.modules.clear();
        // Middleware applies to the routes registered after it, in program order: never carry
        // a later `use(auth)` into an earlier route through a previous pass.
        walker.router_auth.clear();
        let mut env = Env::new("<module>".to_owned());
        walker.statements(&program.body, &mut env);
    }
    walker.summarize = false;
    walker.modules.clear();
    walker.router_auth.clear();
    walker.result = ScanResult {
        findings: Vec::new(),
        truncated: walker.result.truncated,
        summaries: Summaries::new(),
        facts: FileFacts::default(),
        templates: BTreeMap::new(),
        constants: BTreeMap::new(),
    };
    walker.facts = FileFacts::default();
    let mut env = Env::new("<module>".to_owned());
    walker.statements(&program.body, &mut env);
    let mut result = walker.result;
    result.summaries = walker.summaries;
    let mut facts = walker.facts;
    for (local, (spec, export)) in &walker.relative {
        facts.imports.push(jss_core::ir::Import {
            local: local.clone(),
            specifier: spec.clone(),
            export: export.clone(),
            resolved: linking.resolve(spec),
        });
    }
    result.facts = facts;
    result.templates = walker.route_templates;
    result.constants = walker.constants;
    result
}

/// What a file contributes to the entry-point inventory.
#[derive(Debug, Default, Clone)]
pub struct FileFacts {
    pub routes: Vec<RouteFact>,
    pub mounts: Vec<MountFact>,
    /// Export name (`default` for `module.exports =` / `export default`) to local name.
    pub exports: BTreeMap<String, String>,
    /// Relative imports, resolved where the file exists in the scan root.
    pub imports: Vec<jss_core::ir::Import>,
    /// Files this one re-exports from (`export * from`, `export { x } from`).
    pub reexports: Vec<String>,
    /// The local variable each function returns (`return router`).
    pub returned_locals: BTreeMap<String, String>,
    /// Request inputs each function reads: function -> (location, name).
    pub inputs: BTreeMap<String, BTreeSet<(String, String)>>,
    /// Named functions: name -> (start offset, parameter names).
    pub functions: BTreeMap<String, (u32, Vec<String>)>,
    /// Calls each function makes: (callee, offset, arguments).
    pub calls: BTreeMap<String, Vec<(String, u32, Vec<jss_core::ir::Value>)>>,
}

/// One entry point registered in this file.
#[derive(Debug, Clone)]
pub struct RouteFact {
    /// The router or app it is registered on, when it is a variable.
    pub receiver: Option<String>,
    /// HTTP method (upper case), or `SOCKET`, `IPC`, `QUERY`, `MUTATION`, `TRPC`, `QUEUE`, `ANY`.
    pub method: String,
    pub path: String,
    /// The function that handles it (walker name).
    pub handler: String,
    pub span: Span,
    pub auth: Auth,
    pub kind: &'static str,
}

/// A route registered from a function's parameters, instantiated at each call (in this file or,
/// through imports, in others).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTemplate {
    /// The router: a variable of the defining file, or the index of the parameter holding it.
    pub receiver: Result<Option<String>, usize>,
    /// The method, or the index of the parameter holding it.
    pub method: Result<String, usize>,
    pub path: Vec<PathPart>,
    pub auth: Auth,
}

/// A piece of a route path a helper builds: literal text, or one of its parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathPart {
    Lit(String),
    Param(usize),
}

/// Route templates of every file: file -> function -> templates.
pub type Templates = BTreeMap<String, BTreeMap<String, Vec<RouteTemplate>>>;

/// `router.use('/prefix', child)`: `child` is mounted under `prefix`.
#[derive(Debug, Clone)]
pub struct MountFact {
    pub receiver: Option<String>,
    pub prefix: String,
    /// The mounted router: a local name, or a file when mounted as `require('./x')`.
    pub target: Option<String>,
    pub target_file: Option<String>,
    /// Authentication middleware on the mount (`app.use('/admin', requireAdmin, router)`).
    pub auth: Auth,
}

/// A named function's parameter that reaches a sink in its body.
#[derive(Debug, Clone)]
pub struct Summary {
    pub param: usize,
    pub class: VulnClass,
    pub severity: Severity,
    pub api: String,
    pub arg: Span,
    pub call: Span,
    pub steps: Vec<(u32, String)>,
    /// State of the parameter's value at the sink, so the caller's value can be checked
    /// against the sink's rule (URL start, built SQL/HTML).
    pub at_sink: Origin,
    /// Set once the summary leaves its file (spans are then meaningless).
    pub ext: Option<ExtSink>,
    /// The field of the parameter that reaches the sink, when the helper destructures it:
    /// `function f({ table, ids })` reaches a sink with `ids` only.
    pub field: Option<String>,
    /// Return summaries only: the field of the returned object literal that carries the
    /// parameter (`return { command: bin, args }`).
    pub out_field: Option<String>,
    /// The file that defines the function (set once the summary leaves its file). Imports
    /// are matched against it; `ext` says where the sink is, which can be files further away.
    pub defined_in: Option<String>,
}

/// What a local name was bound to by `require` or `import`.
#[derive(Debug, Clone)]
struct Imported {
    family: &'static str,
    /// The export, or `None` for the module object itself.
    export: Option<String>,
}

/// Per-function state.
#[derive(Debug, Clone)]
struct Env {
    vars: BTreeMap<String, Origin>,
    /// Names bound to request objects, with the source kind they produce.
    requests: BTreeMap<String, &'static str>,
    /// Names bound to a connected client socket (`io.on('connection', (s) => ...)`).
    sockets: BTreeSet<String>,
    /// Names whose `.input` field is client data (tRPC procedure options).
    inputs: BTreeMap<String, &'static str>,
    /// Authentication recognized for this function's entry point.
    auth: Auth,
    /// This function's parameter names, in order.
    params: Vec<String>,
    /// Arrays of object literals (route tables): name -> rows of field -> text.
    tables: BTreeMap<String, Vec<BTreeMap<String, String>>>,
    /// The row a table loop variable stands for in this walk: `r` -> fields.
    rows: BTreeMap<String, BTreeMap<String, String>>,
    /// Variables bound to an object literal: the taint of each field.
    fields: BTreeMap<String, BTreeMap<String, Origin>>,
    /// Access paths a guard validated: no longer tainted.
    clean: BTreeSet<String>,
    /// Access paths a guard proved scalar: never an object.
    scalars: BTreeSet<String>,
    /// Names bound to `new C()` of a class whose objects hold no HTML (`URLSearchParams`):
    /// method sinks such as `.append()` do not apply to them.
    plain: BTreeSet<String>,
    /// Client-source parameters whose listed fields the server chose (`file.path` of an upload).
    server_fields: BTreeMap<String, &'static [String]>,
    /// Variables holding an instance of an imported class (`const shell = new ShellService()`):
    /// the imported binding of the class.
    instances: BTreeMap<String, String>,
    /// Variables holding what an auth call returned (`const user = verifyToken(token)`): a
    /// falsy one means the caller is not logged in (or not an admin).
    auth_vars: BTreeMap<String, Auth>,
    /// Variables initialized by a call (routers, apps), by name: where they were declared, so
    /// same-named variables of different functions are told apart.
    declared: BTreeMap<String, u32>,
    /// Inside a branch or loop: assignments only add taint.
    branch: u32,
    function: String,
}

impl Env {
    /// Records what a guard established.
    fn learn(&mut self, facts: Vec<(String, guards::Fact)>) {
        for (key, fact) in facts {
            match fact {
                guards::Fact::Clean => {
                    self.vars.remove(&key);
                    self.clean.insert(key);
                }
                guards::Fact::Scalar => {
                    if let Some(origin) = self.vars.get_mut(&key) {
                        origin.object = false;
                    }
                    self.scalars.insert(key);
                }
            }
        }
    }

    fn new(function: String) -> Self {
        Self {
            vars: BTreeMap::new(),
            requests: BTreeMap::new(),
            sockets: BTreeSet::new(),
            inputs: BTreeMap::new(),
            fields: BTreeMap::new(),
            auth: Auth::NoneDetected,
            params: Vec::new(),
            tables: BTreeMap::new(),
            rows: BTreeMap::new(),
            clean: BTreeSet::new(),
            scalars: BTreeSet::new(),
            plain: BTreeSet::new(),
            server_fields: BTreeMap::new(),
            declared: BTreeMap::new(),
            auth_vars: BTreeMap::new(),
            instances: BTreeMap::new(),
            branch: 0,
            function,
        }
    }

    fn closure(&self, function: String) -> Self {
        Self {
            vars: self.vars.clone(),
            requests: self.requests.clone(),
            sockets: self.sockets.clone(),
            inputs: self.inputs.clone(),
            fields: self.fields.clone(),
            auth: self.auth,
            params: Vec::new(),
            tables: self.tables.clone(),
            rows: self.rows.clone(),
            clean: self.clean.clone(),
            scalars: self.scalars.clone(),
            plain: self.plain.clone(),
            server_fields: self.server_fields.clone(),
            declared: self.declared.clone(),
            auth_vars: self.auth_vars.clone(),
            instances: self.instances.clone(),
            branch: 0,
            function,
        }
    }

    fn bind(&mut self, name: &str, taint: Option<Origin>) {
        match taint {
            Some(origin) => {
                self.vars.insert(name.to_owned(), origin);
            }
            None if self.branch == 0 => {
                self.vars.remove(name);
            }
            None => {}
        }
    }
}

/// How a function is entered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Plain,
    /// Registered as a route handler (`app.post(path, fn)`).
    Route,
    /// A callback whose selected parameters are client data of this source kind.
    Client(&'static str, Params),
    /// A server's connection callback: the first parameter is a client socket.
    SocketConnection,
}

/// Which parameters of a client callback carry client data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Params {
    All,
    First,
    Second,
    /// All but the first (an event object).
    AfterFirst,
    /// The `input` field of the first parameter (tRPC).
    Input,
}

impl Params {
    fn parse(text: &str) -> Self {
        match text {
            "first" => Self::First,
            "second" => Self::Second,
            "after-first" => Self::AfterFirst,
            "input" => Self::Input,
            _ => Self::All,
        }
    }

    fn wants(self, index: usize) -> bool {
        match self {
            Self::All => true,
            Self::First | Self::Input => index == 0,
            Self::Second => index == 1,
            Self::AfterFirst => index > 0,
        }
    }
}

/// Which arguments of a registration are its callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Callback,
    LastCallback,
    ObjectOfFunctions,
    /// `fastify.route({ method, url, handler })`
    RouteObject,
}

struct Walker<'e> {
    external: &'e Summaries,
    linking: &'e Linking<'e>,
    /// Entry-point facts (kept from the final pass only).
    facts: FileFacts,
    /// Summary pass: the field each destructured parameter source stands for, by span start.
    field_of: BTreeMap<u32, String>,
    /// Authentication for the next function entered (route middleware, guard decorators).
    pending_auth: Auth,
    /// The request kind for the next route handler entered (`dev-server`), when not plain `http`.
    pending_request_kind: std::cell::Cell<Option<&'static str>>,
    /// The `server_fields` of the client source the next callback is registered for.
    pending_server_fields: std::cell::Cell<Option<&'static [String]>>,
    /// Routers with authentication middleware applied to every later route: `router.use(auth)`.
    /// Middleware added with `use(...)` on each router (by [`router_key`]): the path prefix it
    /// guards (`""` for all) and the authentication it requires, in registration order.
    router_auth: BTreeMap<String, Vec<(String, Auth)>>,
    /// Names given to inline route handlers (`GET /items`), with the registration that took
    /// each: kept across passes so every pass names a handler the same way.
    inline_names: BTreeMap<String, u32>,
    /// Variables bound to a router or app from a factory: `const router = express.Router()`.
    routers: BTreeSet<String>,
    /// Constructor-injected fields of the class being walked: `this.users` -> `UsersService`.
    injected: BTreeMap<String, String>,
    /// Names bound to `module.exports` (`const helpers = module.exports`).
    export_aliases: BTreeSet<String>,
    /// Constants of this file: `Enum.Member`, `NAME`, `OBJ.key` -> text.
    constants: BTreeMap<String, String>,
    /// The per-field taint of the object the last helper call returned (for `const x = f()`).
    last_returned_fields: Option<BTreeMap<String, Origin>>,
    /// Functions that register a route from their parameters: `add(path, handler)`.
    route_templates: BTreeMap<String, Vec<RouteTemplate>>,
    /// Re-walking a route-table loop for one row: record routes, emit no findings.
    record_only: bool,
    /// The named class whose methods are being walked.
    current_class: Option<String>,
    /// Taint stored in instance fields (`this.url = url`), per class.
    class_fields: BTreeMap<String, BTreeMap<String, Origin>>,
    /// Summary pass: constructor parameter spans, so what reaches a sink through a field is
    /// summarized under `Class.constructor`.
    ctor_params: BTreeMap<u32, String>,
    modules: BTreeMap<String, Imported>,
    /// Local names bound to relative modules: name -> (specifier, export or None).
    relative: BTreeMap<String, (String, Option<String>)>,
    result: ScanResult,
    depth: u32,
    /// Summary pass: parameters of named functions are tainted, and findings become summaries.
    summarize: bool,
    summaries: BTreeMap<String, Vec<Summary>>,
}

fn union(a: Option<Origin>, b: Option<Origin>) -> Option<Origin> {
    match (a, b) {
        (Some(a), Some(b)) => Some(Origin {
            built: a.built || b.built,
            sqlish: a.sqlish || b.sqlish,
            // Escaped only if every part is.
            escaped: a.escaped & b.escaped,
            ..a
        }),
        (a, b) => a.or(b),
    }
}

/// The authentication an initializer's auth call implies: `verifyToken(t)`, `await auth()`,
/// `token ? verifyToken(token) : null`.
fn auth_call_level(init: &Expression<'_>) -> Option<Auth> {
    match init.get_inner_expression() {
        Expression::AwaitExpression(a) => auth_call_level(&a.argument),
        Expression::ConditionalExpression(c) => {
            auth_call_level(&c.consequent).max(auth_call_level(&c.alternate))
        }
        Expression::LogicalExpression(l) => auth_call_level(&l.left).max(auth_call_level(&l.right)),
        Expression::CallExpression(call) => {
            callee_name(&call.callee).and_then(|name| m().auth_of(&name))
        }
        _ => None,
    }
}

/// Whether a function body returns a value somewhere (not counting nested functions).
fn returns_value(statements: &[Statement<'_>]) -> bool {
    statements.iter().any(statement_returns_value)
}

fn statement_returns_value(statement: &Statement<'_>) -> bool {
    match statement {
        Statement::ReturnStatement(r) => r.argument.is_some(),
        Statement::BlockStatement(b) => returns_value(&b.body),
        Statement::IfStatement(i) => {
            statement_returns_value(&i.consequent)
                || i.alternate.as_ref().is_some_and(statement_returns_value)
        }
        Statement::TryStatement(t) => {
            returns_value(&t.block.body)
                || t.handler
                    .as_ref()
                    .is_some_and(|h| returns_value(&h.body.body))
                || t.finalizer.as_ref().is_some_and(|f| returns_value(&f.body))
        }
        Statement::SwitchStatement(sw) => sw.cases.iter().any(|c| returns_value(&c.consequent)),
        Statement::ForStatement(f) => statement_returns_value(&f.body),
        Statement::ForInStatement(f) => statement_returns_value(&f.body),
        Statement::ForOfStatement(f) => statement_returns_value(&f.body),
        Statement::WhileStatement(w) => statement_returns_value(&w.body),
        Statement::DoWhileStatement(d) => statement_returns_value(&d.body),
        Statement::LabeledStatement(l) => statement_returns_value(&l.body),
        _ => false,
    }
}

/// Whether middleware `use`d under `prefix` runs for a route at `path` (`None`: unknown path,
/// covered only by router-wide middleware).
fn covers(prefix: &str, path: Option<&str>) -> bool {
    let prefix = prefix.trim_end_matches('*').trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    path.is_some_and(|path| {
        let path = path.trim_end_matches('/');
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// The key of a router's middleware state: its name and where it was declared (or, for a
/// parameter or a global, the function using it).
fn router_key(name: &str, env: &Env) -> String {
    match env.declared.get(name) {
        Some(at) => format!("{name}@{at}"),
        None => format!("{name}@{}", env.function),
    }
}

/// The classes a call escapes for, from the packs' escapers: `escapeHtml`, `mysql.escape`, a
/// method `.escape()` on any receiver, `he.encode`.
fn escaper_classes(callee: &Callee) -> u8 {
    let names: Vec<String> = match callee {
        Callee::Global(name) => vec![name.clone()],
        Callee::Method { object, method } => {
            let mut names = vec![method.clone()];
            if let Some(object) = object {
                names.push(format!("{object}.{method}"));
            }
            names
        }
        Callee::Module { family, export } => match export.as_deref() {
            Some(export) if !export.is_empty() => {
                vec![export.to_owned(), format!("{family}.{export}")]
            }
            _ => vec![(*family).to_owned()],
        },
    };
    let model = m();
    [
        VulnClass::CommandInjection,
        VulnClass::CodeInjection,
        VulnClass::SqlInjection,
        VulnClass::NosqlInjection,
        VulnClass::PathTraversal,
        VulnClass::Ssrf,
        VulnClass::Xss,
        VulnClass::PrototypePollution,
    ]
    .into_iter()
    .filter(|class| names.iter().any(|name| model.escapes(*class, name)))
    .fold(0, |bits, class| bits | class_bit(class))
}

fn contains(list: &[&str], name: &str) -> bool {
    list.contains(&name)
}

fn prop_name(key: &PropertyKey<'_>) -> Option<String> {
    key.static_name()
        .and_then(|name| name.as_str().map(str::to_owned))
}

/// Whether a relative import specifier (`./lib/db`, `../service.js`) can name `file`
/// (root-relative): the last segment matches the file's stem, or the directory of an index.
fn spec_names_file(spec: &str, file: &str) -> bool {
    let last = spec.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    let last = last.split('.').next().unwrap_or("");
    let mut parts = file.rsplit('/');
    let stem = parts.next().unwrap_or("").split('.').next().unwrap_or("");
    let dir = parts.next().unwrap_or("");
    !last.is_empty() && (last == stem || (stem == "index" && last == dir))
}

/// The rows of an array of object literals: each field as text (a literal, or a name).
fn table_rows(array: &oxc_ast::ast::ArrayExpression<'_>) -> Vec<BTreeMap<String, String>> {
    let mut rows = Vec::new();
    for element in array.elements.iter().take(200) {
        let Some(Expression::ObjectExpression(object)) = element
            .as_expression()
            .map(Expression::get_inner_expression)
        else {
            return Vec::new();
        };
        let mut row = BTreeMap::new();
        for property in &object.properties {
            if let ObjectPropertyKind::ObjectProperty(p) = property
                && let Some(key) = prop_name(&p.key)
                && let Some(value) = literal_path(&p.value).or_else(|| callee_name(&p.value))
            {
                row.insert(key, value);
            }
        }
        rows.push(row);
    }
    rows
}

/// The pack sink a finding's `api` names: `fetch`, `http-client.get`, `.query`, `db.query`.
fn sink_for_api(api: &str) -> Option<&'static models::Sink> {
    let model = m();
    if let Some((family, export)) = api.split_once('.')
        && let Some(sink) = model.module_sink(family, export)
    {
        return Some(sink);
    }
    let last = api.rsplit('.').next().unwrap_or(api);
    model
        .global_sink(api)
        .or_else(|| model.module_sink(api, ""))
        .or_else(|| model.method_sink(api))
        .or_else(|| model.method_sink(last))
}

/// `(/[^a-z0-9]/g, '')`: a global negated character class replaced by nothing.
fn allowlist_strip(arguments: &[Argument<'_>]) -> bool {
    let (Some(Argument::RegExpLiteral(regex)), Some(Argument::StringLiteral(replacement))) =
        (arguments.first(), arguments.get(1))
    else {
        return false;
    };
    let pattern = regex.regex.pattern.text.as_str();
    let class = pattern
        .strip_suffix('+')
        .or_else(|| pattern.strip_suffix('*'))
        .unwrap_or(pattern);
    replacement.value.as_str() == Some("")
        && regex.regex.flags.contains(oxc_ast::ast::RegExpFlags::G)
        && class.starts_with("[^")
        && class.ends_with(']')
        && !class.get(2..class.len() - 1).unwrap_or("").contains(']')
}

/// A route path written as a literal, or built from literals: `urljoin(base, 'api/x')`,
/// `prefix + '/x'`, `` `${base}/x` `` (unknown parts are dropped).
fn literal_path(expr: &Expression<'_>) -> Option<String> {
    match expr.get_inner_expression() {
        Expression::StringLiteral(lit) => lit.value.as_str().map(str::to_owned),
        Expression::TemplateLiteral(t) => {
            let text: String = t
                .quasis
                .iter()
                .filter_map(|q| q.value.cooked.and_then(|c| c.as_str()))
                .collect();
            (!text.is_empty()).then_some(text)
        }
        Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
            let left = literal_path(&b.left).unwrap_or_default();
            let right = literal_path(&b.right).unwrap_or_default();
            let text = format!("{left}{right}");
            (!text.is_empty()).then_some(text)
        }
        Expression::CallExpression(call) => {
            let parts: Vec<String> = call
                .arguments
                .iter()
                .filter_map(|a| a.as_expression().and_then(literal_path))
                .collect();
            (!parts.is_empty()).then(|| format!("/{}", parts.join("/")))
        }
        _ => None,
    }
}

/// The name a middleware argument goes by: `requireLogin`, `auth.required`, `passport.authenticate('jwt')`.
fn callee_name(expr: &Expression<'_>) -> Option<String> {
    match expr.get_inner_expression() {
        Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
        Expression::CallExpression(call) => {
            let inner = callee_name(&call.callee)?;
            // `passport.authenticate('jwt')`, `requireRole('admin')`: the arguments count too.
            let args: Vec<String> = call
                .arguments
                .iter()
                .filter_map(|a| match a {
                    Argument::StringLiteral(l) => l.value.as_str().map(str::to_owned),
                    _ => None,
                })
                .collect();
            Some(format!("{inner} {}", args.join(" ")))
        }
        other => other.as_member_expression().and_then(|m| {
            let object = callee_name(m.object()).unwrap_or_default();
            let property = m
                .static_property_name()
                .and_then(|p| p.as_str().map(str::to_owned))?;
            Some(format!("{object}.{property}"))
        }),
    }
}

/// `require('x')` → `x`.
fn require_spec(expr: &Expression<'_>) -> Option<String> {
    let Expression::CallExpression(call) = expr.get_inner_expression() else {
        return None;
    };
    if !call.callee.is_specific_id("require") {
        return None;
    }
    match call.arguments.first()? {
        Argument::StringLiteral(lit) => lit.value.as_str().map(str::to_owned),
        _ => None,
    }
}

/// `{ name: value }` → value, for the first of `names` present.
fn object_prop<'a, 'e>(expr: &'e Expression<'a>, names: &[&str]) -> Option<&'e Expression<'a>> {
    let Expression::ObjectExpression(object) = expr.get_inner_expression() else {
        return None;
    };
    object
        .properties
        .iter()
        .find_map(|property| match property {
            ObjectPropertyKind::ObjectProperty(p)
                if prop_name(&p.key).is_some_and(|key| contains(names, &key)) =>
            {
                Some(&p.value)
            }
            _ => None,
        })
}

impl Walker<'_> {
    /// Enters one recursion level; false when the cap is reached.
    fn enter(&mut self) -> bool {
        if self.depth >= MAX_DEPTH {
            self.result.truncated = true;
            return false;
        }
        self.depth += 1;
        true
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    // ----- statements -------------------------------------------------------------------

    fn statements(&mut self, statements: &[Statement<'_>], env: &mut Env) {
        for statement in statements {
            self.statement(statement, env);
        }
    }

    fn branch(&mut self, statement: &Statement<'_>, env: &mut Env) {
        env.branch += 1;
        self.statement(statement, env);
        env.branch -= 1;
    }

    fn statement(&mut self, statement: &Statement<'_>, env: &mut Env) {
        if !self.enter() {
            return;
        }
        self.statement_inner(statement, env);
        self.leave();
    }

    fn statement_inner(&mut self, statement: &Statement<'_>, env: &mut Env) {
        match statement {
            Statement::ExpressionStatement(s) => {
                self.expr(&s.expression, env);
                // `check(x, String)`, `assertSafe(x)`: past this line, the assertion held.
                let mut asserted = Vec::new();
                guards::assertion(statement, &mut asserted);
                env.learn(asserted);
            }
            Statement::VariableDeclaration(d) => self.var_decl(d, env),
            Statement::FunctionDeclaration(f) => {
                let name = f.id.as_ref().map(|id| id.name.as_str().to_owned());
                self.function(f, env, name, Role::Plain);
            }
            Statement::ClassDeclaration(c) => self.class(c, env),
            Statement::BlockStatement(b) => self.statements(&b.body, env),
            Statement::IfStatement(s) => {
                self.expr(&s.test, env);
                // Inside the consequent, the test held; inside the alternate, it failed.
                let mut held = Vec::new();
                guards::facts(&s.test, true, &mut held);
                let mut failed = Vec::new();
                guards::facts(&s.test, false, &mut failed);
                let saved = (env.vars.clone(), env.clean.clone(), env.scalars.clone());
                env.learn(held);
                self.branch(&s.consequent, env);
                let consequent_exits = guards::exits(&s.consequent);
                // `if (!req.user) return res.status(401)...`: past here, the caller is logged in.
                if consequent_exits && let Some(level) = self.requires_login(&s.test, env) {
                    env.auth = env.auth.max(level);
                }
                if consequent_exits {
                    // Taint added in an exiting branch never reaches what follows.
                    (env.vars, env.clean, env.scalars) = saved;
                } else {
                    // The guard only held inside: what it cleaned is tainted again after.
                    for (name, origin) in saved.0 {
                        env.vars.entry(name).or_insert(origin);
                    }
                    env.clean = saved.1;
                    env.scalars = saved.2;
                }
                if let Some(alternate) = &s.alternate {
                    let saved = (env.vars.clone(), env.clean.clone(), env.scalars.clone());
                    env.learn(failed.clone());
                    self.branch(alternate, env);
                    for (name, origin) in saved.0 {
                        env.vars.entry(name).or_insert(origin);
                    }
                    (env.clean, env.scalars) = (saved.1, saved.2);
                }
                // `if (!valid(x)) return;`: what follows only runs when the test failed.
                if consequent_exits {
                    env.learn(failed);
                }
            }
            Statement::ReturnStatement(s) => {
                if let Some(argument) = &s.argument {
                    let taint = self.expr(argument, env);
                    self.record_returned(argument, taint, env);
                    // `return router`: a factory's product (for mounts of `require('./x')()`).
                    if let Expression::Identifier(id) = argument.get_inner_expression() {
                        self.facts
                            .returned_locals
                            .entry(env.function.clone())
                            .or_insert_with(|| id.name.as_str().to_owned());
                    }
                }
            }
            Statement::ThrowStatement(s) => {
                self.expr(&s.argument, env);
            }
            Statement::TryStatement(s) => {
                env.branch += 1;
                self.statements(&s.block.body, env);
                if let Some(handler) = &s.handler {
                    self.statements(&handler.body.body, env);
                }
                env.branch -= 1;
                if let Some(finalizer) = &s.finalizer {
                    self.statements(&finalizer.body, env);
                }
            }
            Statement::ForStatement(s) => {
                env.branch += 1;
                match &s.init {
                    Some(ForStatementInit::VariableDeclaration(d)) => self.var_decl(d, env),
                    Some(init) => {
                        if let Some(expr) = init.as_expression() {
                            self.expr(expr, env);
                        }
                    }
                    None => {}
                }
                if let Some(test) = &s.test {
                    self.expr(test, env);
                }
                if let Some(update) = &s.update {
                    self.expr(update, env);
                }
                self.statement(&s.body, env);
                env.branch -= 1;
            }
            Statement::ForOfStatement(s) => {
                let taint = self.expr(&s.right, env);
                env.branch += 1;
                self.for_left(&s.left, taint, env);
                self.statement(&s.body, env);
                env.branch -= 1;
                // `for (const r of routes) router[r.method](r.path, r.handler)`: one record-only
                // walk per known row.
                if !self.summarize
                    && let Expression::Identifier(table) = s.right.get_inner_expression()
                    && let Some(rows) = env.tables.get(table.name.as_str()).cloned()
                    && let ForStatementLeft::VariableDeclaration(d) = &s.left
                    && let Some(BindingPattern::BindingIdentifier(var)) =
                        d.declarations.first().map(|d| &d.id)
                {
                    for row in rows.into_iter().take(100) {
                        let mut inner = env.clone();
                        inner.rows.insert(var.name.as_str().to_owned(), row);
                        let saved = std::mem::replace(&mut self.record_only, true);
                        self.statement(&s.body, &mut inner);
                        self.record_only = saved;
                    }
                }
            }
            Statement::ForInStatement(s) => {
                // Keys of a tainted object are attacker-chosen too.
                let taint = self.expr(&s.right, env);
                env.branch += 1;
                self.for_left(&s.left, taint, env);
                self.statement(&s.body, env);
                env.branch -= 1;
            }
            Statement::WhileStatement(s) => {
                self.expr(&s.test, env);
                self.branch(&s.body, env);
            }
            Statement::DoWhileStatement(s) => {
                self.branch(&s.body, env);
                self.expr(&s.test, env);
            }
            Statement::SwitchStatement(s) => {
                self.expr(&s.discriminant, env);
                env.branch += 1;
                for case in &s.cases {
                    if let Some(test) = &case.test {
                        self.expr(test, env);
                    }
                    self.statements(&case.consequent, env);
                }
                env.branch -= 1;
            }
            Statement::LabeledStatement(s) => self.statement(&s.body, env),
            Statement::TSEnumDeclaration(e) => self.record_enum(e),
            Statement::WithStatement(s) => {
                self.expr(&s.object, env);
                self.branch(&s.body, env);
            }
            _ => {
                if let Some(module) = statement.as_module_declaration() {
                    self.module_decl(module, env);
                }
            }
        }
    }

    fn module_decl(&mut self, module: &ModuleDeclaration<'_>, env: &mut Env) {
        match module {
            ModuleDeclaration::ImportDeclaration(import) => {
                let spec = import.source.value.as_str().unwrap_or("");
                if self.linking.is_own(spec) {
                    for specifier in import.specifiers.iter().flatten() {
                        use oxc_ast::ast::ImportDeclarationSpecifier as S;
                        let (local, export) = match specifier {
                            S::ImportSpecifier(s) => (
                                s.local.name.as_str(),
                                Some(s.imported.name().as_str().to_owned()),
                            ),
                            S::ImportDefaultSpecifier(s) => (s.local.name.as_str(), None),
                            S::ImportNamespaceSpecifier(s) => (s.local.name.as_str(), None),
                        };
                        self.relative
                            .insert(local.to_owned(), (spec.to_owned(), export));
                    }
                    return;
                }
                let Some(family) = m().module_family(spec) else {
                    return;
                };
                for specifier in import.specifiers.iter().flatten() {
                    use oxc_ast::ast::ImportDeclarationSpecifier as S;
                    let (local, export) = match specifier {
                        S::ImportSpecifier(s) => {
                            (s.local.name.as_str(), s.imported.name().as_str().to_owned())
                        }
                        S::ImportDefaultSpecifier(s) => (s.local.name.as_str(), String::new()),
                        S::ImportNamespaceSpecifier(s) => (s.local.name.as_str(), String::new()),
                    };
                    self.modules.insert(
                        local.to_owned(),
                        Imported {
                            family,
                            export: (!export.is_empty()).then_some(export),
                        },
                    );
                }
            }
            ModuleDeclaration::ExportAllDeclaration(export) => {
                if let Some(target) = export
                    .source
                    .value
                    .as_str()
                    .and_then(|s| self.linking.resolve(s))
                {
                    self.facts.reexports.push(target);
                }
            }
            ModuleDeclaration::ExportFromDeclaration(export) => {
                if let Some(target) = export
                    .source
                    .value
                    .as_str()
                    .and_then(|s| self.linking.resolve(s))
                {
                    self.facts.reexports.push(target);
                }
                // `export { runCommand as run } from './shell'`: `run` is the other file's
                // `runCommand`.
                for specifier in &export.specifiers {
                    self.facts.exports.insert(
                        specifier.exported.name().as_str().to_owned(),
                        specifier.local.name().as_str().to_owned(),
                    );
                }
            }
            ModuleDeclaration::ExportNamedDeclaration(export) => {
                for specifier in &export.specifiers {
                    self.facts.exports.insert(
                        specifier.exported.name().as_str().to_owned(),
                        specifier.local.name().as_str().to_owned(),
                    );
                }
            }
            ModuleDeclaration::ExportDeclaration(export) => match &export.declaration {
                Declaration::FunctionDeclaration(f) => {
                    let name = f.id.as_ref().map(|id| id.name.as_str().to_owned());
                    if let Some(name) = &name {
                        self.facts.exports.insert(name.clone(), name.clone());
                    }
                    if let Some(name) = &name
                        && has(&m().route_exports, name)
                    {
                        self.facts.routes.push(RouteFact {
                            receiver: None,
                            method: name.clone(),
                            path: String::new(),
                            handler: name.clone(),
                            span: f.span,
                            auth: Auth::NoneDetected,
                            kind: "file-route",
                        });
                    }
                    let role = if name.as_deref().is_some_and(|n| has(&m().route_exports, n)) {
                        Role::Route
                    } else {
                        Role::Plain
                    };
                    self.function(f, env, name, role);
                }
                Declaration::VariableDeclaration(d) => {
                    for declarator in &d.declarations {
                        if let BindingPattern::BindingIdentifier(id) = &declarator.id {
                            let name = id.name.as_str().to_owned();
                            if has(&m().route_exports, &name) {
                                self.facts.routes.push(RouteFact {
                                    receiver: None,
                                    method: name.clone(),
                                    path: String::new(),
                                    handler: name.clone(),
                                    span: declarator.span,
                                    auth: Auth::NoneDetected,
                                    kind: "file-route",
                                });
                            }
                            self.facts.exports.insert(name.clone(), name);
                        }
                    }
                    self.var_decl(d, env);
                }
                Declaration::ClassDeclaration(c) => {
                    if let Some(id) = &c.id {
                        self.facts
                            .exports
                            .insert(id.name.as_str().to_owned(), id.name.as_str().to_owned());
                    }
                    self.class(c, env);
                }
                Declaration::TSEnumDeclaration(e) => self.record_enum(e),
                _ => {}
            },
            ModuleDeclaration::ExportDefaultDeclaration(export) => match &export.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
                    let name = f.id.as_ref().map(|id| id.name.as_str().to_owned());
                    self.facts.exports.insert(
                        "default".to_owned(),
                        name.clone().unwrap_or_else(|| "<default>".to_owned()),
                    );
                    // A default-exported `(req, res)` handler (Next.js `pages/api`).
                    if f.params.items.len() >= 2 {
                        self.facts.routes.push(RouteFact {
                            receiver: None,
                            method: "ANY".to_owned(),
                            path: String::new(),
                            handler: name.clone().unwrap_or_else(|| "<default>".to_owned()),
                            span: f.span,
                            auth: Auth::NoneDetected,
                            kind: "default-export",
                        });
                    }
                    self.function(f, env, name, Role::Plain);
                }
                ExportDefaultDeclarationKind::ClassDeclaration(c) => {
                    if let Some(id) = &c.id {
                        self.facts
                            .exports
                            .insert("default".to_owned(), id.name.as_str().to_owned());
                    }
                    self.class(c, env);
                }
                other => {
                    if let Some(expr) = other.as_expression() {
                        if let Expression::Identifier(id) = expr.get_inner_expression() {
                            self.facts
                                .exports
                                .insert("default".to_owned(), id.name.as_str().to_owned());
                        }
                        self.expr(expr, env);
                    }
                }
            },
            _ => {}
        }
    }

    fn for_left(&mut self, left: &ForStatementLeft<'_>, taint: Option<Origin>, env: &mut Env) {
        match left {
            ForStatementLeft::VariableDeclaration(d) => {
                for declarator in &d.declarations {
                    self.bind_pattern(&declarator.id, taint.clone(), None, env);
                }
            }
            other => {
                if let Some(target) = other.as_assignment_target() {
                    self.assign_target(target, taint, env);
                }
            }
        }
    }

    fn var_decl(&mut self, declaration: &VariableDeclaration<'_>, env: &mut Env) {
        for declarator in &declaration.declarations {
            let Some(init) = &declarator.init else {
                continue;
            };
            if let Some(spec) = require_spec(init) {
                self.bind_require(&declarator.id, &spec, None);
                continue;
            }
            // `const { exec } = require('child_process').promises` and `require('fs').promises`
            if let Some(member) = init.get_inner_expression().as_member_expression()
                && let Some(spec) = require_spec(member.object())
            {
                let export = member
                    .static_property_name()
                    .and_then(|name| name.as_str().map(str::to_owned));
                self.bind_require(&declarator.id, &spec, export);
                continue;
            }
            let name_hint = match &declarator.id {
                BindingPattern::BindingIdentifier(id) => Some(id.name.as_str().to_owned()),
                _ => None,
            };
            // `const PREFIX = '/api'`, `const ROUTES = { users: '/users' }`: constants.
            if let (Some(name), VariableDeclarationKind::Const) = (&name_hint, declaration.kind) {
                if let Some(text) = literal_path(init).filter(|_| {
                    matches!(
                        init.get_inner_expression(),
                        Expression::StringLiteral(_) | Expression::TemplateLiteral(_)
                    )
                }) {
                    self.constants.insert(name.clone(), text);
                } else if let Expression::ObjectExpression(object) = init.get_inner_expression() {
                    for property in &object.properties {
                        if let ObjectPropertyKind::ObjectProperty(p) = property
                            && let Some(key) = prop_name(&p.key)
                            && let Expression::StringLiteral(value) = p.value.get_inner_expression()
                            && let Some(text) = value.value.as_str()
                        {
                            self.constants
                                .insert(format!("{name}.{key}"), text.to_owned());
                        }
                    }
                }
            }
            // `const helpers = module.exports`
            if let Some(name) = &name_hint
                && guards::path_key(init).is_some_and(|k| k == "module.exports" || k == "exports")
            {
                self.export_aliases.insert(name.clone());
            }
            // `const { setupApiRoute } = routeHelpers`, where `routeHelpers` is one of our modules.
            if let (BindingPattern::ObjectPattern(object), Expression::Identifier(module)) =
                (&declarator.id, init.get_inner_expression())
                && let Some((spec, None)) = self.relative.get(module.name.as_str()).cloned()
            {
                for property in &object.properties {
                    if let (Some(key), BindingPattern::BindingIdentifier(local)) =
                        (prop_name(&property.key), &property.value)
                    {
                        self.relative
                            .insert(local.name.as_str().to_owned(), (spec.clone(), Some(key)));
                    }
                }
            }
            // `const routes = [{ method: 'get', path: '/x', handler: list }]`
            if let (Some(name), Expression::ArrayExpression(array)) =
                (&name_hint, init.get_inner_expression())
            {
                let rows = table_rows(array);
                if !rows.is_empty() {
                    env.tables.insert(name.clone(), rows);
                }
            }
            // `const user = verifyToken(token)`, `const session = await getServerSession()`,
            // `const { user } = await auth()`: what an auth call returned.
            let auth_call = auth_call_level(init);
            let mut bound = Vec::new();
            match &declarator.id {
                BindingPattern::BindingIdentifier(id) => bound.push(id.name.as_str().to_owned()),
                BindingPattern::ObjectPattern(object) => {
                    for property in &object.properties {
                        if let BindingPattern::BindingIdentifier(id) = &property.value {
                            bound.push(id.name.as_str().to_owned());
                        }
                    }
                }
                _ => {}
            }
            for name in bound {
                match auth_call {
                    Some(level) => {
                        env.auth_vars.insert(name, level);
                    }
                    None => {
                        env.auth_vars.remove(&name);
                    }
                }
            }
            // `const upload = req.files.upload`: an upload object, whose `path` and stored
            // `filename` are the server's.
            if let Some(name) = &name_hint {
                if self.is_upload_object(init, env) {
                    env.server_fields
                        .insert(name.clone(), m().upload_server_fields.as_slice());
                } else {
                    env.server_fields.remove(name);
                }
            }
            // `const shell = new ShellService()`, with `ShellService` imported from our files.
            if let Some(name) = &name_hint {
                let class = match init.get_inner_expression() {
                    Expression::NewExpression(n) => match n.callee.get_inner_expression() {
                        Expression::Identifier(id)
                            if self.relative.contains_key(id.name.as_str()) =>
                        {
                            Some(id.name.as_str().to_owned())
                        }
                        _ => None,
                    },
                    _ => None,
                };
                match class {
                    Some(class) => {
                        env.instances.insert(name.clone(), class);
                    }
                    None => {
                        env.instances.remove(name);
                    }
                }
            }
            // `const router = express.Router()`, `const app = fastify()`
            if let Some(name) = &name_hint {
                if matches!(
                    init.get_inner_expression(),
                    Expression::CallExpression(_) | Expression::NewExpression(_)
                ) {
                    env.declared.insert(name.clone(), declarator.span.start);
                } else {
                    env.declared.remove(name);
                }
                let factory = match init.get_inner_expression() {
                    Expression::CallExpression(c) => callee_name(&c.callee),
                    Expression::NewExpression(n) => callee_name(&n.callee),
                    _ => None,
                };
                if factory.is_some_and(|f| {
                    let last = f.rsplit('.').next().unwrap_or(&f);
                    has(&m().router_factories, last) || has(&m().router_factories, &f)
                }) {
                    self.routers.insert(name.clone());
                }
                // `const params = new URLSearchParams()`: never a DOM node or jQuery set.
                let plain = match init.get_inner_expression() {
                    Expression::NewExpression(n) => {
                        callee_name(&n.callee).is_some_and(|c| has(&m().plain_constructors, &c))
                    }
                    _ => false,
                };
                if plain {
                    env.plain.insert(name.clone());
                } else {
                    env.plain.remove(name);
                }
            }
            self.last_returned_fields = None;
            let taint = self.expr_named(init, env, name_hint.clone());
            // `const launch = prepare(bin, args)`, returning `{ command, args }`: field by field.
            let is_call = match init.get_inner_expression() {
                Expression::CallExpression(_) => true,
                Expression::AwaitExpression(a) => {
                    matches!(
                        a.argument.get_inner_expression(),
                        Expression::CallExpression(_)
                    )
                }
                _ => false,
            };
            if let (true, Some(fields)) = (is_call, self.last_returned_fields.take()) {
                match &declarator.id {
                    BindingPattern::BindingIdentifier(id) => {
                        env.fields.insert(id.name.as_str().to_owned(), fields);
                        env.bind(id.name.as_str(), taint);
                        continue;
                    }
                    BindingPattern::ObjectPattern(object) if object.rest.is_none() => {
                        for property in &object.properties {
                            let field =
                                prop_name(&property.key).and_then(|k| fields.get(&k).cloned());
                            self.bind_pattern(&property.value, field, None, env);
                        }
                        continue;
                    }
                    _ => {}
                }
            }
            // `const opts = { table: 'x', ids: req.body.ids }`: remember each field's taint.
            if let (Some(name), Expression::ObjectExpression(object)) =
                (&name_hint, init.get_inner_expression())
            {
                let mut fields = BTreeMap::new();
                let mut spread = false;
                for property in &object.properties {
                    match property {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            if let Some(key) = prop_name(&p.key) {
                                let mut probe = env.clone();
                                if let Some(origin) = self.expr(&p.value, &mut probe) {
                                    fields.insert(key, origin);
                                }
                            }
                        }
                        ObjectPropertyKind::SpreadProperty(_) => spread = true,
                    }
                }
                if spread {
                    env.fields.remove(name);
                } else {
                    env.fields.insert(name.clone(), fields);
                }
            } else if let Some(name) = &name_hint {
                env.fields.remove(name);
            }
            // `const { body, query } = req`
            let request = match init.get_inner_expression() {
                Expression::Identifier(id) => env.requests.get(id.name.as_str()).copied(),
                _ => None,
            };
            self.bind_pattern(
                &declarator.id,
                taint,
                request.map(|kind| (kind, init.span())),
                env,
            );
        }
    }

    /// Binds `const x = require(spec)` and `const { a, b: c } = require(spec)`.
    fn bind_require(&mut self, pattern: &BindingPattern<'_>, spec: &str, export: Option<String>) {
        if self.linking.is_own(spec) {
            match pattern {
                BindingPattern::BindingIdentifier(id) => {
                    self.relative
                        .insert(id.name.as_str().to_owned(), (spec.to_owned(), export));
                }
                BindingPattern::ObjectPattern(object) => {
                    for property in &object.properties {
                        if let (Some(key), BindingPattern::BindingIdentifier(local)) =
                            (prop_name(&property.key), &property.value)
                        {
                            self.relative.insert(
                                local.name.as_str().to_owned(),
                                (spec.to_owned(), Some(key)),
                            );
                        }
                    }
                }
                _ => {}
            }
            return;
        }
        let Some(family) = m().module_family(spec) else {
            return;
        };
        // `require('fs').promises` is still fs.
        let export = export.filter(|e| !has(&m().module_namespaces, e));
        match pattern {
            BindingPattern::BindingIdentifier(id) => {
                self.modules
                    .insert(id.name.as_str().to_owned(), Imported { family, export });
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    let Some(key) = prop_name(&property.key) else {
                        continue;
                    };
                    if let BindingPattern::BindingIdentifier(local) = &property.value {
                        let export = if has(&m().module_namespaces, &key) {
                            None
                        } else {
                            Some(key)
                        };
                        self.modules
                            .insert(local.name.as_str().to_owned(), Imported { family, export });
                    }
                }
            }
            _ => {}
        }
    }

    /// Binds every name in `pattern` to `taint`. With `request`, the value is a request object:
    /// destructured properties named like request data become sources.
    fn bind_pattern(
        &mut self,
        pattern: &BindingPattern<'_>,
        taint: Option<Origin>,
        request: Option<(&'static str, Span)>,
        env: &mut Env,
    ) {
        if !self.enter() {
            return;
        }
        match pattern {
            BindingPattern::BindingIdentifier(id) => {
                let taint =
                    taint.map(|o| o.step(id.span.start, format!("assigned to `{}`", id.name)));
                env.bind(id.name.as_str(), taint);
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    let key = prop_name(&property.key);
                    let field = match (request, key.as_deref()) {
                        (Some((kind, _)), Some(key)) if has(&m().request_props, key) => {
                            Some(Origin {
                                kind,
                                span: property.span,
                                steps: Vec::new(),
                                built: false,
                                prefix: true,
                                sqlish: false,
                                escaped: 0,
                                param: None,
                                // As for `req.body`: only a parsed body or query can hold objects.
                                object: has(&m().object_props, key)
                                    && !has(self.linking.scalar_props, key),
                            })
                        }
                        (Some(_), _) => None,
                        (None, _) => taint.clone(),
                    };
                    // `const { files } = request`: an upload object, whose `path` is the server's.
                    if request.is_some()
                        && key.as_deref().is_some_and(|k| has(&m().upload_objects, k))
                        && let BindingPattern::BindingIdentifier(id) = &property.value
                    {
                        env.server_fields.insert(
                            id.name.as_str().to_owned(),
                            m().upload_server_fields.as_slice(),
                        );
                    }
                    self.bind_pattern(&property.value, field, None, env);
                }
                if let Some(rest) = &object.rest {
                    self.bind_pattern(&rest.argument, taint.clone(), None, env);
                }
            }
            BindingPattern::ArrayPattern(array) => {
                for element in array.elements.iter().flatten() {
                    self.bind_pattern(element, taint.clone(), None, env);
                }
                if let Some(rest) = &array.rest {
                    self.bind_pattern(&rest.argument, taint.clone(), None, env);
                }
            }
            BindingPattern::AssignmentPattern(assign) => {
                let default = self.expr(&assign.right, env);
                self.bind_pattern(&assign.left, union(taint, default), request, env);
            }
        }
        self.leave();
    }

    fn class(&mut self, class: &Class<'_>, env: &mut Env) {
        let class_name = class.id.as_ref().map(|id| id.name.as_str().to_owned());
        // `@UseGuards(AuthGuard)` on the class or a method: every request passes the guard.
        // Rated by the guards it names (`@UseGuards(ThrottlerGuard)` is no login check,
        // `@UseGuards(AdminGuard)` an admin one); a bare auth decorator (`@Authorized()`) is a
        // login check.
        let guarded = |decorators: &[oxc_ast::ast::Decorator<'_>]| {
            decorators
                .iter()
                .filter_map(|d| {
                    let name = callee_name(&d.expression)?;
                    let head = name.split([' ', '(', '.']).next().unwrap_or("").to_owned();
                    if !has(&m().auth_decorators, &head) {
                        return None;
                    }
                    let Expression::CallExpression(call) = d.expression.get_inner_expression()
                    else {
                        return Some(Auth::User);
                    };
                    if call.arguments.is_empty() {
                        return Some(Auth::User);
                    }
                    let named: Vec<Auth> = call
                        .arguments
                        .iter()
                        .filter_map(Argument::as_expression)
                        .filter_map(|a| match a.get_inner_expression() {
                            Expression::StringLiteral(l) => l.value.as_str().map(str::to_owned),
                            other => callee_name(other),
                        })
                        .filter_map(|guard| m().auth_of(&guard))
                        .collect();
                    named.into_iter().max()
                })
                .max()
        };
        let class_auth = guarded(&class.decorators).unwrap_or_default();
        // NestJS-style controller prefix: `@Controller('users')`.
        // The controller decorator's own authentication default (`RestController: user`).
        let controller_default_auth = class
            .decorators
            .iter()
            .filter_map(|d| match &d.expression {
                Expression::CallExpression(call) => callee_name(&call.callee),
                _ => None,
            })
            .filter_map(|name| m().controller_auth.get(&name).copied())
            .max()
            .unwrap_or_default();
        let controller_prefix = class.decorators.iter().find_map(|d| {
            let Expression::CallExpression(call) = &d.expression else {
                return None;
            };
            let name = callee_name(&call.callee)?;
            has(&m().controller_decorators, &name).then(|| {
                call.arguments
                    .first()
                    .and_then(Argument::as_expression)
                    .and_then(|e| {
                        // `@Controller('users')`, `@Controller(RouteKey.User)` or
                        // `@Controller({ path: 'users' })`.
                        let keys: Vec<&str> =
                            m().route_path_keys.iter().map(String::as_str).collect();
                        let path = object_prop(e, &keys).unwrap_or(e);
                        self.resolve_text(path, env)
                    })
                    .unwrap_or_default()
            })
        });
        // Constructor injection: `constructor(private readonly users: UsersService)`.
        let saved_injected = std::mem::take(&mut self.injected);
        for element in &class.body.body {
            if let ClassElement::MethodDefinition(method) = element
                && method.kind == oxc_ast::ast::MethodDefinitionKind::Constructor
            {
                for param in &method.value.params.items {
                    let (BindingPattern::BindingIdentifier(id), Some(annotation)) =
                        (&param.pattern, &param.type_annotation)
                    else {
                        continue;
                    };
                    if let oxc_ast::ast::TSType::TSTypeReference(reference) =
                        &annotation.type_annotation
                        && let oxc_ast::ast::TSTypeName::IdentifierReference(type_name) =
                            &reference.type_name
                    {
                        self.injected.insert(
                            id.name.as_str().to_owned(),
                            type_name.name.as_str().to_owned(),
                        );
                    }
                }
            }
        }
        for element in &class.body.body {
            // `@Get(':id')` on a method of a controller: a route.
            if let (Some(prefix), ClassElement::MethodDefinition(method)) =
                (&controller_prefix, element)
                && !self.summarize
            {
                for decorator in &method.decorators {
                    let Expression::CallExpression(call) = &decorator.expression else {
                        continue;
                    };
                    let Some(verb) = callee_name(&call.callee) else {
                        continue;
                    };
                    if !has(&m().route_decorators, &verb) {
                        continue;
                    }
                    let sub = call
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .and_then(|e| self.resolve_text(e, env))
                        .unwrap_or_default();
                    let key = prop_name(&method.key).unwrap_or_default();
                    self.facts.routes.push(RouteFact {
                        receiver: None,
                        method: verb.to_ascii_uppercase(),
                        path: {
                            let parts: Vec<&str> =
                                [prefix.trim_matches('/'), sub.trim_matches('/')]
                                    .into_iter()
                                    .filter(|p| !p.is_empty())
                                    .collect();
                            format!("/{}", parts.join("/"))
                        },
                        handler: format!("{}.{key}", class_name.as_deref().unwrap_or("<class>")),
                        span: method.span,
                        auth: {
                            // `@Post('/login', { skipAuth: true })` opts out of the default.
                            let public = call.arguments.iter().skip(1).any(|a| {
                                a.as_expression().is_some_and(|e| {
                                    m().public_options.iter().any(|key| {
                                        object_prop(e, &[key.as_str()]).is_some_and(|v| {
                                            matches!(v.get_inner_expression(), Expression::BooleanLiteral(b) if b.value)
                                        })
                                    })
                                })
                            });
                            let default = if public { Auth::NoneDetected } else { controller_default_auth };
                            class_auth
                                .max(default)
                                .max(guarded(&method.decorators).unwrap_or_default())
                        },
                        kind: "http",
                    });
                }
            }
            match element {
                ClassElement::MethodDefinition(method) => {
                    let name = prop_name(&method.key).map(|key| match &class_name {
                        Some(class) => format!("{class}.{key}"),
                        None => key,
                    });
                    self.pending_auth =
                        class_auth.max(guarded(&method.decorators).unwrap_or_default());
                    if self.summarize
                        && method.kind == oxc_ast::ast::MethodDefinitionKind::Constructor
                        && let Some(class) = &class_name
                    {
                        for param in &method.value.params.items {
                            self.ctor_params.insert(param.span.start, class.clone());
                            if let BindingPattern::ObjectPattern(object) = &param.pattern {
                                for property in &object.properties {
                                    self.ctor_params.insert(property.span.start, class.clone());
                                }
                            }
                        }
                    }
                    let saved_class =
                        std::mem::replace(&mut self.current_class, class_name.clone());
                    self.function(&method.value, env, name, Role::Plain);
                    self.current_class = saved_class;
                }
                ClassElement::PropertyDefinition(property) => {
                    if let Some(value) = &property.value {
                        let name = prop_name(&property.key);
                        self.expr_named(value, env, name);
                    }
                }
                ClassElement::StaticBlock(block) => {
                    let mut inner = env.closure(env.function.clone());
                    self.statements(&block.body, &mut inner);
                }
                _ => {}
            }
        }
        self.injected = saved_injected;
    }

    // ----- functions --------------------------------------------------------------------

    fn function(&mut self, f: &Function<'_>, parent: &Env, name: Option<String>, role: Role) {
        let Some(body) = &f.body else {
            return;
        };
        let mut env = self.enter_function(&f.params, parent, name, role);
        if self.enter() {
            self.statements(&body.statements, &mut env);
            self.record_validated(&body.statements, f.params.span, &env);
            self.leave();
        }
    }

    fn enter_function(
        &mut self,
        params: &FormalParameters<'_>,
        parent: &Env,
        name: Option<String>,
        role: Role,
    ) -> Env {
        let name = name.unwrap_or_else(|| "<anonymous>".to_owned());
        let mut env = parent.closure(name);
        env.auth = env.auth.max(std::mem::take(&mut self.pending_auth));
        let names: Vec<Option<&str>> = params
            .items
            .iter()
            .map(|p| match &p.pattern {
                BindingPattern::BindingIdentifier(id) => Some(id.name.as_str()),
                _ => None,
            })
            .collect();
        // Parameters shadow outer taint of the same name.
        for name in names.iter().flatten() {
            env.vars.remove(*name);
            env.requests.remove(*name);
        }
        let first = names.first().copied().flatten();
        env.params = names.iter().map(|n| n.unwrap_or("").to_owned()).collect();
        if !self.summarize && env.function != "<anonymous>" {
            self.facts
                .functions
                .entry(env.function.clone())
                .or_insert((params.span.start, env.params.clone()));
        }
        // A component (`function UserCard(props)` / `const UserCard = ({ name }) => ...`): its
        // props carry stored or user data.
        if role == Role::Plain
            && !self.summarize
            && names.len() <= 2
            && let Some(kind) = m().props_kind.as_deref()
            && env.function.chars().next().is_some_and(char::is_uppercase)
            && !env.function.contains(['.', ' '])
            && let Some(param) = params.items.first()
        {
            self.bind_pattern(
                &param.pattern,
                Some(Origin::source(kind, param.span)),
                None,
                &mut env,
            );
        }
        // NestJS: `@Body() dto`, `@Query('q') q`, `@Param('id') id`, `@Headers() h`.
        for param in &params.items {
            let decorated = param.decorators.iter().any(|d| match &d.expression {
                Expression::CallExpression(call) => matches!(
                    call.callee.get_inner_expression(),
                    Expression::Identifier(id)
                        if has(&m().decorators, id.name.as_str())
                ),
                _ => false,
            });
            if decorated {
                let origin = Origin {
                    kind: "http",
                    span: param.span,
                    steps: Vec::new(),
                    built: false,
                    prefix: true,
                    sqlish: false,
                    escaped: 0,
                    param: None,
                    object: true,
                };
                self.bind_pattern(&param.pattern, Some(origin), None, &mut env);
            }
        }
        if self.summarize && role == Role::Plain && env.function != "<anonymous>" {
            for (index, param) in params.items.iter().enumerate() {
                if let BindingPattern::ObjectPattern(object) = &param.pattern {
                    // `function f({ table, ids })`: one summary source per field.
                    for property in &object.properties {
                        let Some(key) = prop_name(&property.key) else {
                            continue;
                        };
                        self.field_of.insert(property.span.start, key);
                        let mut origin = Origin::source("param", property.span);
                        origin.param = Some(index);
                        self.bind_pattern(&property.value, Some(origin), None, &mut env);
                    }
                    if let Some(rest) = &object.rest {
                        let mut origin = Origin::source("param", param.span);
                        origin.param = Some(index);
                        self.bind_pattern(&rest.argument, Some(origin), None, &mut env);
                    }
                    continue;
                }
                let origin = Origin {
                    kind: "param",
                    span: param.span,
                    steps: Vec::new(),
                    built: false,
                    prefix: true,
                    sqlish: false,
                    escaped: 0,
                    param: Some(index),
                    object: true,
                };
                self.bind_pattern(&param.pattern, Some(origin), None, &mut env);
            }
        }
        match role {
            Role::Client(kind, selected) => {
                let server_fields = self.pending_server_fields.take();
                for (index, (param, name)) in params.items.iter().zip(&names).enumerate() {
                    if !selected.wants(index) {
                        continue;
                    }
                    if let (Some(fields), Some(name)) = (server_fields, name) {
                        env.server_fields.insert((*name).to_owned(), fields);
                    }
                    if selected == Params::Input {
                        // tRPC: `({ input, ctx }) => ...` or `(opts) => opts.input`
                        match &param.pattern {
                            BindingPattern::ObjectPattern(object) => {
                                for property in &object.properties {
                                    if prop_name(&property.key)
                                        .is_some_and(|k| has(&m().input_fields, &k))
                                    {
                                        let origin = Origin::source(kind, property.span);
                                        self.bind_pattern(
                                            &property.value,
                                            Some(origin),
                                            None,
                                            &mut env,
                                        );
                                    }
                                }
                            }
                            BindingPattern::BindingIdentifier(id) => {
                                env.inputs.insert(id.name.as_str().to_owned(), kind);
                            }
                            _ => {}
                        }
                        continue;
                    }
                    if name.is_some_and(|n| has(&m().socket_ack_names, n)) {
                        continue;
                    }
                    let origin = Origin {
                        kind,
                        span: param.span,
                        steps: Vec::new(),
                        built: false,
                        prefix: true,
                        sqlish: false,
                        escaped: 0,
                        param: None,
                        object: true,
                    };
                    self.bind_pattern(&param.pattern, Some(origin), None, &mut env);
                }
            }
            Role::SocketConnection => {
                if let Some(first) = first {
                    env.sockets.insert(first.to_owned());
                }
            }
            Role::Route | Role::Plain => {
                let model = m();
                // `(req, res)` handlers, and helpers that take the request (`getDir(req)`).
                let conventional = first.is_some_and(|n| has(&model.request_names, n));
                if let Some(first) = first {
                    if has(&model.context_names, first) && role == Role::Route {
                        // Koa: the context is the request too.
                        env.requests.insert(first.to_owned(), "http");
                    } else if role == Role::Route
                        && names.len() == 1
                        && has(&model.hono_context_names, first)
                    {
                        // Hono: request data is under `c.req`; `c` itself is context.
                        env.requests.insert(first.to_owned(), CONTEXT);
                    } else if conventional || (role == Role::Route && names.len() >= 2) {
                        let kind = if role == Role::Route {
                            self.pending_request_kind.take().unwrap_or("http")
                        } else {
                            "http"
                        };
                        env.requests.insert(first.to_owned(), kind);
                    }
                } else if role == Role::Route
                    && let Some(param) = params.items.first()
                {
                    // `({ body, query }, res) => ...`
                    self.bind_pattern(&param.pattern, None, Some(("http", param.span)), &mut env);
                }
            }
        }
        env
    }

    fn arrow(
        &mut self,
        params: &FormalParameters<'_>,
        body: &ArrowFunctionBody<'_>,
        parent: &Env,
        name: Option<String>,
        role: Role,
    ) {
        let mut env = self.enter_function(params, parent, name, role);
        if !self.enter() {
            return;
        }
        match body {
            ArrowFunctionBody::FunctionBody(body) => {
                self.statements(&body.statements, &mut env);
                self.record_validated(&body.statements, params.span, &env);
            }
            other => {
                if let Some(expr) = other.as_expression() {
                    let taint = self.expr(expr, &mut env);
                    self.record_returned(expr, taint, &env);
                }
            }
        }
        self.leave();
    }

    /// Summary pass: a void function that throws unless its parameters are valid
    /// (`isValidRequest(req, fileName)` throwing on a bad name) validates them for its callers.
    fn record_validated(&mut self, body: &[Statement<'_>], span: Span, env: &Env) {
        if !self.summarize
            || env.function == "<anonymous>"
            || env.function == "<module>"
            || returns_value(body)
        {
            return;
        }
        for (index, param) in env.params.iter().enumerate() {
            if param.is_empty() || !env.clean.contains(param) {
                continue;
            }
            let list = self.summaries.entry(env.function.clone()).or_default();
            if list.iter().any(|s| s.api == VALIDATES && s.param == index) {
                continue;
            }
            list.push(Summary {
                param: index,
                class: VulnClass::CodeInjection,
                severity: Severity::Low,
                api: VALIDATES.to_owned(),
                arg: span,
                call: span,
                steps: Vec::new(),
                at_sink: Origin::source("param", span),
                ext: None,
                field: None,
                out_field: None,
                defined_in: None,
            });
        }
    }

    /// Summary pass: a function that returns (a value derived from) its parameter.
    fn record_return(
        &mut self,
        taint: Option<Origin>,
        span: Span,
        env: &Env,
        out_field: Option<String>,
    ) {
        let Some(origin) = taint else { return };
        if !self.summarize || env.function == "<anonymous>" || env.function == "<module>" {
            return;
        }
        // `function getDir(req) { return req.query.dir }`: returns client data itself.
        let param = origin.param.unwrap_or(RETURNS_SOURCE);
        let field = self.field_of.get(&origin.span.start).cloned();
        let list = self.summaries.entry(env.function.clone()).or_default();
        if list.iter().any(|s| {
            s.api == RETURNS && s.param == param && s.field == field && s.out_field == out_field
        }) {
            return;
        }
        list.push(Summary {
            param,
            class: VulnClass::CodeInjection,
            severity: Severity::Low,
            api: RETURNS.to_owned(),
            arg: span,
            call: span,
            steps: origin.steps.clone(),
            at_sink: origin,
            ext: None,
            field,
            out_field,
            defined_in: None,
        });
    }

    /// Records what a returned value carries: per field for an object literal
    /// (`return { command, args }`), as a whole otherwise.
    fn record_returned(&mut self, argument: &Expression<'_>, whole: Option<Origin>, env: &Env) {
        if !self.summarize {
            return;
        }
        if let Expression::ObjectExpression(object) = argument.get_inner_expression()
            && object
                .properties
                .iter()
                .all(|p| matches!(p, ObjectPropertyKind::ObjectProperty(_)))
        {
            for property in &object.properties {
                if let ObjectPropertyKind::ObjectProperty(p) = property
                    && let Some(key) = prop_name(&p.key)
                {
                    let mut probe = env.clone();
                    let taint = self.expr(&p.value, &mut probe);
                    self.record_return(taint, p.span, env, Some(key));
                }
            }
            return;
        }
        self.record_return(whole, argument.span(), env, None);
    }

    /// Walks a function-valued expression, if it is one. Returns whether it was.
    fn maybe_function(
        &mut self,
        expr: &Expression<'_>,
        env: &Env,
        name: Option<String>,
        role: Role,
    ) -> bool {
        match expr.get_inner_expression() {
            Expression::ArrowFunctionExpression(arrow) => {
                self.arrow(&arrow.params, &arrow.body, env, name, role);
                true
            }
            Expression::FunctionExpression(f) => {
                let name = name.or_else(|| f.id.as_ref().map(|id| id.name.as_str().to_owned()));
                self.function(f, env, name, role);
                true
            }
            _ => false,
        }
    }

    // ----- expressions ------------------------------------------------------------------

    fn expr_named(
        &mut self,
        expr: &Expression<'_>,
        env: &mut Env,
        name: Option<String>,
    ) -> Option<Origin> {
        // `export const POST = async (request) => ...` (Next.js route handlers)
        let role = if name.as_deref().is_some_and(|n| has(&m().route_exports, n)) {
            Role::Route
        } else {
            Role::Plain
        };
        if self.maybe_function(expr, env, name, role) {
            return None;
        }
        self.expr(expr, env)
    }

    fn expr(&mut self, expr: &Expression<'_>, env: &mut Env) -> Option<Origin> {
        if !self.enter() {
            return None;
        }
        let taint = self.expr_inner(expr, env);
        self.leave();
        taint
    }

    fn expr_inner(&mut self, expr: &Expression<'_>, env: &mut Env) -> Option<Origin> {
        match expr {
            Expression::Identifier(id) => env.vars.get(id.name.as_str()).cloned().map(|mut o| {
                if env.scalars.contains(id.name.as_str()) {
                    o.object = false;
                }
                o
            }),
            Expression::StaticMemberExpression(_)
            | Expression::ComputedMemberExpression(_)
            | Expression::PrivateFieldExpression(_) => self.member(expr, env),
            Expression::TemplateLiteral(template) => {
                let mut taint = None;
                for (index, expression) in template.expressions.iter().enumerate() {
                    if let Some(mut origin) = self.expr(expression, env) {
                        origin.built = true;
                        origin.sqlish |= template
                            .quasis
                            .iter()
                            .any(|q| m().looks_like_sql(q.value.raw.as_str()));
                        let leading = index == 0
                            && template.quasis.first().is_some_and(|q| {
                                q.value
                                    .cooked
                                    .and_then(|c| c.as_str())
                                    .unwrap_or("x")
                                    .trim()
                                    .is_empty()
                            });
                        origin.prefix = origin.prefix && leading;
                        let origin = origin.step(
                            expression.span().start,
                            "interpolated into a template".to_owned(),
                        );
                        taint = union(taint, Some(origin));
                    }
                }
                taint
            }
            Expression::TaggedTemplateExpression(tagged) => {
                self.expr(&tagged.tag, env);
                for expression in &tagged.quasi.expressions {
                    self.expr(expression, env);
                }
                None
            }
            Expression::BinaryExpression(binary) => {
                let left = self.expr(&binary.left, env);
                let right = self.expr(&binary.right, env);
                if binary.operator == BinaryOperator::Addition {
                    let sqlish = [&binary.left, &binary.right].iter().any(|side| {
                        matches!(side.get_inner_expression(), Expression::StringLiteral(lit)
                            if lit.value.as_str().is_some_and(|t: &str| m().looks_like_sql(t)))
                    });
                    let left = left.map(|mut o| {
                        o.built = true;
                        o.sqlish |= sqlish;
                        o
                    });
                    let right = right.map(|mut o| {
                        o.built = true;
                        o.sqlish |= sqlish;
                        o.prefix = false;
                        o.step(binary.span.start, "concatenated".to_owned())
                    });
                    union(left, right)
                } else {
                    None
                }
            }
            Expression::LogicalExpression(logical) => {
                let left = self.expr(&logical.left, env);
                let right = self.expr(&logical.right, env);
                union(left, right)
            }
            Expression::ConditionalExpression(c) => {
                self.expr(&c.test, env);
                // `ALLOWED.includes(x) ? x : 'id'`: what the test establishes holds in its branch.
                let mut held = Vec::new();
                guards::facts(&c.test, true, &mut held);
                let mut failed = Vec::new();
                guards::facts(&c.test, false, &mut failed);
                let a = if held.is_empty() {
                    self.expr(&c.consequent, env)
                } else {
                    let mut probe = env.clone();
                    probe.learn(held);
                    self.expr(&c.consequent, &mut probe)
                };
                let b = if failed.is_empty() {
                    self.expr(&c.alternate, env)
                } else {
                    let mut probe = env.clone();
                    probe.learn(failed);
                    self.expr(&c.alternate, &mut probe)
                };
                union(a, b)
            }
            Expression::AwaitExpression(a) => self.expr(&a.argument, env),
            Expression::ParenthesizedExpression(p) => self.expr(&p.expression, env),
            Expression::TSAsExpression(e) => self.expr(&e.expression, env),
            Expression::TSSatisfiesExpression(e) => self.expr(&e.expression, env),
            Expression::TSNonNullExpression(e) => self.expr(&e.expression, env),
            Expression::TSTypeAssertion(e) => self.expr(&e.expression, env),
            Expression::TSInstantiationExpression(e) => self.expr(&e.expression, env),
            Expression::SequenceExpression(s) => {
                let mut last = None;
                for expression in &s.expressions {
                    last = self.expr(expression, env);
                }
                last
            }
            Expression::UnaryExpression(u) => {
                self.expr(&u.argument, env);
                // `+x`, `-x`, `!x`, `typeof x`, `void x`, `~x`: none carries the string.
                None
            }
            Expression::UpdateExpression(_) => None,
            Expression::AssignmentExpression(assign) => {
                let name = match (&assign.left, assign.right.get_inner_expression()) {
                    // `module.exports = function runCommand() {}`: its own name, as exported.
                    (_, Expression::FunctionExpression(f)) if f.id.is_some() => {
                        f.id.as_ref().map(|id| id.name.as_str().to_owned())
                    }
                    (AssignmentTarget::AssignmentTargetIdentifier(id), _) => {
                        Some(id.name.as_str().to_owned())
                    }
                    (target, _) => target
                        .as_simple_assignment_target()
                        .and_then(|t| t.as_member_expression())
                        .and_then(|m| m.static_property_name())
                        .and_then(|n| n.as_str().map(str::to_owned)),
                };
                // CommonJS exports: `module.exports = router`, `exports.list = list`.
                if let Some(target) = assign
                    .left
                    .as_simple_assignment_target()
                    .and_then(SimpleAssignmentTarget::as_member_expression)
                    && let Some(key) = guards::member_key(target)
                {
                    // A function is exported under the name the walker gives it: its own, or the
                    // property it is assigned to (`module.exports = function () {}` is `exports`).
                    let property = target
                        .static_property_name()
                        .and_then(|n| n.as_str().map(str::to_owned));
                    let local = match assign.right.get_inner_expression() {
                        Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
                        Expression::FunctionExpression(f) => {
                            f.id.as_ref()
                                .map(|id| id.name.as_str().to_owned())
                                .or_else(|| property.clone())
                        }
                        Expression::ArrowFunctionExpression(_) => property.clone(),
                        _ => None,
                    };
                    let (head, rest) = key.split_once('.').unwrap_or((key.as_str(), ""));
                    let export = match key.as_str() {
                        "module.exports" => Some("default".to_owned()),
                        // `const helpers = module.exports; helpers.setup = ...`
                        _ if self.export_aliases.contains(head) && !rest.contains('.') => {
                            Some(rest.to_owned())
                        }
                        k => k
                            .strip_prefix("module.exports.")
                            .or_else(|| k.strip_prefix("exports."))
                            .map(str::to_owned),
                    };
                    if let (Some(export), Some(local)) = (export, local) {
                        self.facts.exports.insert(export, local);
                    }
                    // `module.exports = { list, create }`
                    if key == "module.exports"
                        && let Expression::ObjectExpression(object) =
                            assign.right.get_inner_expression()
                    {
                        for property in &object.properties {
                            if let ObjectPropertyKind::ObjectProperty(p) = property
                                && let (Some(k), Expression::Identifier(v)) =
                                    (prop_name(&p.key), p.value.get_inner_expression())
                            {
                                self.facts.exports.insert(k, v.name.as_str().to_owned());
                            }
                        }
                    }
                }
                let taint = self.expr_named(&assign.right, env, name);
                // `x += tainted` keeps x's own taint too.
                let taint = if assign.operator.is_assign() {
                    taint
                } else {
                    let own = match &assign.left {
                        AssignmentTarget::AssignmentTargetIdentifier(id) => {
                            env.vars.get(id.name.as_str()).cloned()
                        }
                        _ => None,
                    };
                    union(own, taint).map(|mut o| {
                        o.built = true;
                        o
                    })
                };
                // `location.href = value`
                if let Some(origin) = &taint
                    && let Some(target) =
                        assign
                            .left
                            .as_simple_assignment_target()
                            .and_then(|t| match t {
                                SimpleAssignmentTarget::AssignmentTargetIdentifier(id) => {
                                    Some(id.name.as_str().to_owned())
                                }
                                other => other.as_member_expression().and_then(guards::member_key),
                            })
                    && let Some(sink) = m().assign_sink(&target)
                {
                    let url_rule = sink.args.iter().any(|r| matches!(r, ArgRule::UrlPrefix(_)));
                    if !url_rule || origin.prefix {
                        self.emit(
                            RawFinding {
                                class: sink.class,
                                severity: m().cap(origin.kind, sink.severity),
                                api: format!("{target} ="),
                                arg: assign.right.span(),
                                call: assign.span,
                                function: env.function.clone(),
                                origin: origin.clone(),
                                ext: None,
                                auth: Auth::NoneDetected,
                            },
                            env,
                        );
                    }
                }
                self.assign_target(&assign.left, taint.clone(), env);
                taint
            }
            Expression::ArrayExpression(array) => {
                let mut taint = None;
                for element in &array.elements {
                    let t = match element {
                        ArrayExpressionElement::SpreadElement(s) => self.expr(&s.argument, env),
                        ArrayExpressionElement::Elision(_) => None,
                        other => other.as_expression().and_then(|e| self.expr(e, env)),
                    };
                    taint = union(taint, t);
                }
                taint
            }
            Expression::ObjectExpression(object) => {
                let mut taint = None;
                for property in &object.properties {
                    let t = match property {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            if let Some(key) = p.key.as_expression()
                                && p.computed
                            {
                                self.expr(key, env);
                            }
                            let name = prop_name(&p.key);
                            // GraphQL: `{ Query: { user(parent, args) { ... } } }`
                            let resolver = name.as_deref().and_then(|key| {
                                m().client_sources.iter().find(|s| {
                                    s.shape.as_deref() == Some("resolver-map")
                                        && has(&s.methods, key)
                                })
                            });
                            match (resolver, p.value.get_inner_expression()) {
                                (Some(source), Expression::ObjectExpression(map)) => {
                                    let role = Role::Client(
                                        source.kind.as_str(),
                                        Params::parse(&source.params),
                                    );
                                    for field in &map.properties {
                                        if let ObjectPropertyKind::ObjectProperty(f) = field {
                                            let field_name = prop_name(&f.key).map(|n| {
                                                format!("{} {n}", name.as_deref().unwrap_or(""))
                                            });
                                            if !self.summarize
                                                && let Some(field_key) = prop_name(&f.key)
                                            {
                                                self.facts.routes.push(RouteFact {
                                                    receiver: None,
                                                    method: name
                                                        .as_deref()
                                                        .unwrap_or("")
                                                        .to_ascii_uppercase(),
                                                    path: field_key,
                                                    handler: field_name.clone().unwrap_or_default(),
                                                    span: f.span,
                                                    auth: env.auth,
                                                    kind: source.kind.as_str(),
                                                });
                                            }
                                            self.maybe_function(&f.value, env, field_name, role);
                                        }
                                    }
                                    None
                                }
                                _ => {
                                    // tRPC: `{ getUser: t.procedure.input(...).query(fn) }`
                                    if !self.summarize
                                        && let (Some(key), Expression::CallExpression(c)) =
                                            (&name, p.value.get_inner_expression())
                                        && let Some(method) = c
                                            .callee
                                            .get_inner_expression()
                                            .as_member_expression()
                                            .and_then(|m| m.static_property_name())
                                            .and_then(|n| n.as_str().map(str::to_owned))
                                        && let Some(source) = m().client_sources.iter().find(|s| {
                                            s.params == "input"
                                                && has(&s.methods, &method)
                                                && s.arity.is_none_or(|a| a == c.arguments.len())
                                        })
                                    {
                                        self.facts.routes.push(RouteFact {
                                            receiver: None,
                                            method: format!(
                                                "{}.{}",
                                                source.kind.to_ascii_uppercase(),
                                                method.to_ascii_uppercase()
                                            ),
                                            path: key.clone(),
                                            handler: key.clone(),
                                            span: p.span,
                                            auth: env.auth,
                                            kind: source.kind.as_str(),
                                        });
                                    }
                                    self.expr_named(&p.value, env, name)
                                }
                            }
                        }
                        ObjectPropertyKind::SpreadProperty(s) => self.expr(&s.argument, env),
                    };
                    taint = union(taint, t);
                }
                taint
            }
            Expression::CallExpression(call) => self.call(call, env),
            Expression::NewExpression(new) => {
                let callee = self.callee(&new.callee);
                // `new Worker('jobs', async (job) => ...)`: client callbacks as with calls.
                let (role, shape) = self.client_role(&callee, &new.callee, &new.arguments, env);
                let last = new.arguments.len().saturating_sub(1);
                let mut taints = Vec::new();
                for (index, argument) in new.arguments.iter().enumerate() {
                    let role = match shape {
                        Shape::LastCallback if index != last => Role::Plain,
                        _ => role,
                    };
                    taints.push(self.argument(argument, env, role));
                }
                let sink = match &callee {
                    Callee::Module { family, export } => {
                        m().module_sink(family, export.as_deref().unwrap_or(""))
                    }
                    Callee::Global(name) => m().global_sink(name),
                    Callee::Method { .. } => None,
                };
                if let Some(sink) = sink {
                    self.check_sink(
                        sink.clone(),
                        &callee,
                        &new.arguments,
                        &taints,
                        new.span,
                        env,
                    );
                }
                // `new Executor(config)`: what the constructor's fields reach in any method.
                if let Callee::Global(class) = &callee
                    && let Some((name, summaries)) = self.constructor_summaries(class)
                {
                    self.apply_summaries(
                        &name,
                        &summaries,
                        &taints,
                        Some(&new.arguments),
                        new.span,
                        env,
                    );
                }
                // `new URL(input)` keeps the input.
                match &callee {
                    Callee::Global(name) if has(&m().pass_globals, name) => taints
                        .iter()
                        .flatten()
                        .next()
                        .cloned()
                        .map(|o| o.step(new.span.start, format!("through new {name}()"))),
                    _ => None,
                }
            }
            Expression::ChainExpression(chain) => {
                use oxc_ast::ast::ChainElement;
                match &chain.expression {
                    ChainElement::CallExpression(call) => self.call(call, env),
                    ChainElement::TSNonNullExpression(e) => self.expr(&e.expression, env),
                    other => other
                        .as_member_expression()
                        .and_then(|m| self.member_of(m, env)),
                }
            }
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {
                self.maybe_function(expr, env, None, Role::Plain);
                None
            }
            Expression::ClassExpression(class) => {
                self.class(class, env);
                None
            }
            Expression::YieldExpression(y) => {
                if let Some(argument) = &y.argument {
                    self.expr(argument, env);
                }
                None
            }
            Expression::ImportExpression(import) => {
                self.expr(&import.source, env);
                None
            }
            Expression::JSXElement(element) => {
                self.jsx_element(element, env);
                None
            }
            Expression::JSXFragment(fragment) => {
                self.jsx_children(&fragment.children, env);
                None
            }
            _ => None,
        }
    }

    /// Walks a JSX element: raw-HTML props are sinks; expressions and children are walked.
    fn jsx_element(&mut self, element: &oxc_ast::ast::JSXElement<'_>, env: &mut Env) {
        use oxc_ast::ast::{JSXAttributeItem, JSXAttributeName, JSXAttributeValue};
        if !self.enter() {
            return;
        }
        for item in &element.opening_element.attributes {
            match item {
                JSXAttributeItem::SpreadAttribute(spread) => {
                    self.expr(&spread.argument, env);
                }
                JSXAttributeItem::Attribute(attribute) => {
                    let name = match &attribute.name {
                        JSXAttributeName::Identifier(id) => id.name.as_str(),
                        JSXAttributeName::NamespacedName(_) => "",
                    };
                    match &attribute.value {
                        Some(JSXAttributeValue::ExpressionContainer(container)) => {
                            let Some(expr) = container.expression.as_expression() else {
                                continue;
                            };
                            if has(&m().jsx_html_props, name) {
                                // `dangerouslySetInnerHTML={{ __html: value }}`
                                let keys: Vec<&str> =
                                    m().jsx_html_value_keys.iter().map(String::as_str).collect();
                                let value = object_prop(expr, &keys).unwrap_or(expr);
                                if let Some(origin) = self.expr(value, env) {
                                    self.emit(
                                        RawFinding {
                                            class: VulnClass::Xss,
                                            severity: Severity::High,
                                            api: name.to_owned(),
                                            arg: value.span(),
                                            call: attribute.span,
                                            function: env.function.clone(),
                                            origin,
                                            ext: None,
                                            auth: Auth::NoneDetected,
                                        },
                                        env,
                                    );
                                }
                            } else if !self.maybe_function(expr, env, None, Role::Plain) {
                                self.expr(expr, env);
                            }
                        }
                        Some(JSXAttributeValue::Element(child)) => self.jsx_element(child, env),
                        Some(JSXAttributeValue::Fragment(child)) => {
                            self.jsx_children(&child.children, env);
                        }
                        _ => {}
                    }
                }
            }
        }
        self.jsx_children(&element.children, env);
        self.leave();
    }

    fn jsx_children(&mut self, children: &[oxc_ast::ast::JSXChild<'_>], env: &mut Env) {
        use oxc_ast::ast::JSXChild;
        for child in children {
            match child {
                JSXChild::Element(element) => self.jsx_element(element, env),
                JSXChild::Fragment(fragment) => self.jsx_children(&fragment.children, env),
                JSXChild::ExpressionContainer(container) => {
                    if let Some(expr) = container.expression.as_expression() {
                        self.expr(expr, env);
                    }
                }
                JSXChild::Spread(spread) => {
                    self.expr(&spread.expression, env);
                }
                JSXChild::Text(_) => {}
            }
        }
    }

    fn assign_target(
        &mut self,
        target: &AssignmentTarget<'_>,
        taint: Option<Origin>,
        env: &mut Env,
    ) {
        match target {
            AssignmentTarget::AssignmentTargetIdentifier(id) => {
                let taint =
                    taint.map(|o| o.step(id.span.start, format!("assigned to `{}`", id.name)));
                env.fields.remove(id.name.as_str());
                env.bind(id.name.as_str(), taint);
            }
            other => {
                if let Some(member) = other
                    .as_simple_assignment_target()
                    .and_then(SimpleAssignmentTarget::as_member_expression)
                {
                    // `target[key][key2] = value` with attacker-chosen keys.
                    if let oxc_ast::ast::MemberExpression::ComputedMemberExpression(outer) = member
                        && let Expression::ComputedMemberExpression(inner) =
                            outer.object.get_inner_expression()
                    {
                        let mut probe = env.clone();
                        let outer_key = self.expr(&outer.expression, &mut probe);
                        let inner_key = self.expr(&inner.expression, &mut probe);
                        if let (Some(origin), Some(_)) = (inner_key, outer_key)
                            && origin.param.is_none() == !self.summarize
                        {
                            self.emit(
                                RawFinding {
                                    class: VulnClass::PrototypePollution,
                                    severity: Severity::High,
                                    api: "obj[key][key] =".to_owned(),
                                    arg: outer.span,
                                    call: outer.span,
                                    function: env.function.clone(),
                                    origin,
                                    ext: None,
                                    auth: Auth::NoneDetected,
                                },
                                env,
                            );
                        }
                    }
                    // `el.innerHTML = tainted`
                    if let Some(origin) = &taint
                        && member
                            .static_property_name()
                            .is_some_and(|p| has(&m().html_props, p.as_str().unwrap_or("")))
                    {
                        let property = member
                            .static_property_name()
                            .and_then(|p| p.as_str().map(str::to_owned))
                            .unwrap_or_default();
                        self.emit(
                            RawFinding {
                                class: VulnClass::Xss,
                                severity: Severity::High,
                                api: format!(".{property} ="),
                                arg: member.span(),
                                call: member.span(),
                                function: env.function.clone(),
                                origin: origin.clone(),
                                ext: None,
                                auth: Auth::NoneDetected,
                            },
                            env,
                        );
                    }
                    // `this.url = url` in a class: remembered for the class's other methods.
                    if let (Expression::ThisExpression(_), Some(class), Some(field)) = (
                        member.object().get_inner_expression(),
                        self.current_class.clone(),
                        member
                            .static_property_name()
                            .and_then(|p| p.as_str().map(str::to_owned)),
                    ) {
                        let fields = self.class_fields.entry(class).or_default();
                        match taint {
                            Some(origin) => {
                                let origin = origin
                                    .step(member.span().start, format!("stored in `this.{field}`"));
                                fields.insert(field, origin);
                            }
                            None if env.branch == 0 => {
                                fields.remove(&field);
                            }
                            None => {}
                        }
                        return;
                    }
                    // `opts.ids = tainted` on a tracked object: that field only.
                    if let (Expression::Identifier(root), Some(property)) = (
                        member.object().get_inner_expression(),
                        member
                            .static_property_name()
                            .and_then(|p| p.as_str().map(str::to_owned)),
                    ) && env.fields.contains_key(root.name.as_str())
                    {
                        if let Some(fields) = env.fields.get_mut(root.name.as_str()) {
                            match taint {
                                Some(origin) => {
                                    fields.insert(property, origin);
                                }
                                None => {
                                    fields.remove(&property);
                                }
                            }
                        }
                        return;
                    }
                    // `obj.x = tainted` taints `obj` (coarse: other objects' fields are not tracked).
                    if let (Some(origin), Expression::Identifier(root)) =
                        (taint, member.object().get_inner_expression())
                    {
                        let origin = origin.step(
                            member.span().start,
                            format!("stored in a field of `{}`", root.name),
                        );
                        env.vars.insert(root.name.as_str().to_owned(), origin);
                    }
                }
            }
        }
    }

    fn member(&mut self, expr: &Expression<'_>, env: &mut Env) -> Option<Origin> {
        let member = expr.as_member_expression()?;
        self.member_of(member, env)
    }

    fn member_of(
        &mut self,
        member: &oxc_ast::ast::MemberExpression<'_>,
        env: &mut Env,
    ) -> Option<Origin> {
        // A guard validated this access path or one of its prefixes.
        let key = guards::member_key(member);
        let prefixes = || {
            key.iter().flat_map(|k| {
                k.match_indices('.')
                    .map(|(at, _)| k.get(..at).unwrap_or(""))
                    .chain(std::iter::once(k.as_str()))
            })
        };
        if prefixes().any(|p| env.clean.contains(p)) {
            if let oxc_ast::ast::MemberExpression::ComputedMemberExpression(c) = member {
                self.expr(&c.expression, env);
            }
            return None;
        }
        let scalar = prefixes().any(|p| env.scalars.contains(p));
        self.member_of_inner(member, env).map(|mut o| {
            if scalar {
                o.object = false;
            }
            o
        })
    }

    fn member_of_inner(
        &mut self,
        member: &oxc_ast::ast::MemberExpression<'_>,
        env: &mut Env,
    ) -> Option<Origin> {
        use oxc_ast::ast::MemberExpression as M;
        if let M::ComputedMemberExpression(computed) = member {
            self.expr(&computed.expression, env);
        }

        let property = member
            .static_property_name()
            .and_then(|name| name.as_str().map(str::to_owned));
        let object = member.object().get_inner_expression();
        if let Some(kind) = self.request_kind(object, env)
            && property
                .as_deref()
                .is_some_and(|p| has(&m().request_props, p))
        {
            return Some(Origin {
                kind,
                span: member.span(),
                steps: Vec::new(),
                built: false,
                prefix: true,
                sqlish: false,
                escaped: 0,
                param: None,
                object: property.as_deref().is_some_and(|p| {
                    has(&m().object_props, p) && !has(self.linking.scalar_props, p)
                }),
            });
        }
        // `this.url` in a class method: what another method stored there.
        if let (Expression::ThisExpression(_), Some(field), Some(class)) =
            (object, property.as_deref(), self.current_class.as_ref())
            && let Some(origin) = self.class_fields.get(class).and_then(|f| f.get(field))
        {
            return Some(origin.clone());
        }
        // tRPC: `opts.input`
        if let (Expression::Identifier(id), Some(field)) = (object, property.as_deref())
            && has(&m().input_fields, field)
            && let Some(kind) = env.inputs.get(id.name.as_str())
        {
            return Some(Origin::source(kind, member.span()));
        }
        // Pack member sources: `process.argv`, `window.location.hash`.
        if let Some(property) = property.as_deref()
            && let Some(path) = guards::path_key(object)
            && let Some(source) = m()
                .member_sources
                .iter()
                .find(|s| s.object == path && s.property == property)
        {
            return Some(Origin::source(source.kind.as_str(), member.span()));
        }
        // multer: the server chooses where an upload is stored (`req.file.path`,
        // `req.files[0].path`, `req.files.avatar[0].path`).
        let upload = {
            let mut cursor = object;
            while let Expression::ComputedMemberExpression(c) = cursor {
                cursor = c.object.get_inner_expression();
            }
            cursor
        };
        if let Some(inner) = upload.as_member_expression()
            && inner
                .static_property_name()
                .is_some_and(|p| has(&m().upload_objects, p.as_str().unwrap_or("")))
            && property
                .as_deref()
                .is_some_and(|p| has(&m().upload_server_fields, p))
            && self
                .request_kind(inner.object().get_inner_expression(), env)
                .is_some()
        {
            return None;
        }
        // `req.query.q`: an input this function reads.
        if let (Some(inner), Some(name)) = (object.as_member_expression(), property.as_deref())
            && let Some(location) = inner
                .static_property_name()
                .and_then(|p| p.as_str().map(str::to_owned))
            && has(&m().request_props, &location)
            && self
                .request_kind(inner.object().get_inner_expression(), env)
                .is_some()
            && !self.summarize
        {
            self.facts
                .inputs
                .entry(env.function.clone())
                .or_default()
                .insert((location, name.to_owned()));
        }
        // A field of an object literal we tracked: only that field's taint.
        if let (Expression::Identifier(id), Some(property)) = (object, property.as_deref())
            && let Some(fields) = env.fields.get(id.name.as_str())
        {
            return fields.get(property).cloned();
        }
        // `file.path` of an upload event: chosen by the server.
        if let (Expression::Identifier(id), Some(property)) = (object, property.as_deref())
            && env
                .server_fields
                .get(id.name.as_str())
                .is_some_and(|fields| has(fields, property))
        {
            return None;
        }
        // Any property of a tainted object is tainted. In the summary pass, `opts.cmd` of a
        // parameter is recorded as that field: a call then passes only that field of its
        // argument (`run({ cmd: 'ls', user })`, `discard(req.file)` reading `file.path`).
        let whole = self.expr(member.object(), env);
        if self.summarize
            && let (Expression::Identifier(_), Some(property)) = (object, property.as_deref())
            && let Some(origin) = &whole
            && origin.param.is_some()
            && !self.field_of.contains_key(&origin.span.start)
        {
            let mut field = origin.clone();
            field.span = member.span();
            self.field_of
                .insert(member.span().start, property.to_owned());
            if let Some(class) = self.ctor_params.get(&origin.span.start).cloned() {
                self.ctor_params.insert(member.span().start, class);
            }
            return Some(field);
        }
        whole
    }

    /// `!req.user`, `!req.session.userId`, `!req.isAuthenticated()`, `!isAdmin(req)`, or `!user`
    /// after `const user = verifyToken(token)`: a test that is true when the caller is not
    /// logged in (or not an admin). The level it establishes once it failed.
    fn requires_login(&self, test: &Expression<'_>, env: &Env) -> Option<Auth> {
        let Expression::UnaryExpression(u) = test.get_inner_expression() else {
            if let Expression::LogicalExpression(l) = test.get_inner_expression() {
                return self
                    .requires_login(&l.left, env)
                    .max(self.requires_login(&l.right, env));
            }
            return None;
        };
        if u.operator != UnaryOperator::LogicalNot {
            return None;
        }
        let argument = u.argument.get_inner_expression();
        // `!user`, where `user` came from an auth call: someone is logged in (whatever an
        // admin-sounding name says: `const owner = findOwner(id)` is a lookup).
        if let Expression::Identifier(id) = argument
            && env.auth_vars.contains_key(id.name.as_str())
        {
            return Some(Auth::User);
        }
        let target = match argument {
            // `!isAdmin(req)`, `!verifyToken(token)`: a yes/no check named like auth.
            Expression::CallExpression(call) => {
                let name = callee_name(&call.callee).unwrap_or_default();
                let last = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
                if guards::is_predicate(&last)
                    && let Some(level) = m().auth_of(&name)
                {
                    return Some(level);
                }
                &call.callee
            }
            other => other,
        };
        let key = guards::path_key(target)?;
        let mut parts = key.split('.');
        let root = parts.next().unwrap_or("");
        (env.requests.contains_key(root) && parts.any(|p| has(&m().auth_request_fields, p)))
            .then_some(Auth::User)
    }

    /// The source kind when `expr` is a request object: a request parameter, or `ctx.request`.
    fn request_kind(&self, expr: &Expression<'_>, env: &Env) -> Option<&'static str> {
        match expr {
            Expression::Identifier(id) => env
                .requests
                .get(id.name.as_str())
                .copied()
                .filter(|kind| *kind != CONTEXT),
            Expression::StaticMemberExpression(mem)
                if has(&m().sub_objects, mem.property.name.as_str()) =>
            {
                match mem.object.get_inner_expression() {
                    Expression::Identifier(id) => env
                        .requests
                        .get(id.name.as_str())
                        .map(|kind| if *kind == CONTEXT { "http" } else { kind }),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn argument(&mut self, argument: &Argument<'_>, env: &mut Env, role: Role) -> Option<Origin> {
        match argument {
            Argument::SpreadElement(spread) => self.expr(&spread.argument, env),
            other => {
                let expr = other.as_expression()?;
                if self.maybe_function(expr, env, None, role) {
                    None
                } else {
                    self.expr(expr, env)
                }
            }
        }
    }

    fn callee(&self, callee: &Expression<'_>) -> Callee {
        let callee = callee.get_inner_expression();
        match callee {
            Expression::Identifier(id) => match self.modules.get(id.name.as_str()) {
                Some(imported) => Callee::Module {
                    family: imported.family,
                    export: imported.export.clone(),
                },
                None => Callee::Global(id.name.as_str().to_owned()),
            },
            _ => {
                let Some(member) = callee.as_member_expression() else {
                    return Callee::Method {
                        object: None,
                        method: String::new(),
                    };
                };
                let method = member
                    .static_property_name()
                    .and_then(|name| name.as_str().map(str::to_owned))
                    .unwrap_or_default();
                let object = member.object().get_inner_expression();
                let family = match object {
                    Expression::Identifier(id) => self
                        .modules
                        .get(id.name.as_str())
                        .filter(|imported| {
                            imported.export.is_none()
                                || imported.export.as_deref() == Some("default")
                        })
                        .map(|imported| imported.family)
                        .or_else(|| {
                            // Unimported but conventional: `child_process.exec`, `fs.readFile`.
                            m().module_family(id.name.as_str())
                                .filter(|f| has(&m().implicit_modules, f))
                        }),
                    // `fs.promises.readFile`
                    Expression::StaticMemberExpression(inner)
                        if has(&m().module_namespaces, inner.property.name.as_str()) =>
                    {
                        match inner.object.get_inner_expression() {
                            Expression::Identifier(id) => {
                                self.modules.get(id.name.as_str()).map(|i| i.family)
                            }
                            _ => None,
                        }
                    }
                    other => require_spec(other).and_then(|spec| m().module_family(&spec)),
                };
                match family {
                    Some(family) => Callee::Module {
                        family,
                        export: Some(method),
                    },
                    None => {
                        let object_name = match object {
                            Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
                            // `this.users.find(...)` on an injected `UsersService`.
                            Expression::StaticMemberExpression(field)
                                if matches!(field.object, Expression::ThisExpression(_)) =>
                            {
                                self.injected.get(field.property.name.as_str()).cloned()
                            }
                            _ => None,
                        };
                        // `Buffer.from`, `JSON.parse`, `util.format` as globals.
                        if let Some(object) = &object_name
                            && has(&m().pass_globals, &format!("{object}.{method}"))
                        {
                            return Callee::Global(format!("{object}.{method}"));
                        }
                        Callee::Method {
                            object: object_name,
                            method,
                        }
                    }
                }
            }
        }
    }

    fn call(&mut self, call: &CallExpression<'_>, env: &mut Env) -> Option<Origin> {
        let callee = self.callee(&call.callee);
        // Receiver taint (for pass-through methods), walking the callee once.
        let receiver = match call.callee.get_inner_expression().as_member_expression() {
            Some(member) => self.expr(member.object(), env),
            None => {
                self.expr(&call.callee, env);
                None
            }
        };

        // How function arguments are entered.
        let (role, shape) = self.client_role(&callee, &call.callee, &call.arguments, env);
        let route_name = match (
            &callee,
            call.arguments.first().and_then(Argument::as_expression),
        ) {
            (Callee::Method { method, object }, Some(first)) if role == Role::Route => {
                self.resolve_text(first, env).map(|path| {
                    self.inline_route_name(method, &path, object.as_deref(), call.span.start)
                })
            }
            _ => None,
        };
        let last = call.arguments.len().saturating_sub(1);
        // Authentication middleware: `app.get(path, requireLogin, handler)`, an earlier
        // `router.use(auth)`, or `router.use(auth)` itself.
        let receiver_name = match &callee {
            Callee::Method {
                object: Some(o), ..
            } => Some(o.clone()),
            _ => None,
        };
        let middleware_auth = call
            .arguments
            .iter()
            .take(last)
            .filter_map(|a| a.as_expression().and_then(callee_name))
            .filter_map(|name| m().auth_of(&name))
            .max()
            .unwrap_or_default();
        // What earlier `use(...)` calls on this router require under this route's path.
        let route_path = call
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .and_then(|e| self.mount_path(e, env));
        let route_auth = receiver_name
            .as_deref()
            .and_then(|r| self.router_auth.get(&router_key(r, env)))
            .map(|guards| {
                guards
                    .iter()
                    .filter(|(prefix, _)| covers(prefix, route_path.as_deref()))
                    .map(|(_, auth)| *auth)
                    .max()
                    .unwrap_or_default()
            })
            .unwrap_or_default()
            .max(middleware_auth);
        // `router.use(auth)`, `app.use('/api', jwt())`: middleware for the routes registered after
        // it on this router (under that path). A use() that mounts routers (`use(adminRouter)`,
        // `use('/admin', requireAdmin, child)`) guards only what it mounts.
        if let Callee::Method {
            object: Some(object),
            method,
        } = &callee
            && has(&m().mount_methods, method)
        {
            let arguments: Vec<&Expression<'_>> = call
                .arguments
                .iter()
                .filter_map(Argument::as_expression)
                .collect();
            let prefix = arguments.first().and_then(|e| self.mount_path(e, env));
            let middleware = arguments
                .get(usize::from(prefix.is_some())..)
                .unwrap_or(&[]);
            if !middleware.iter().any(|e| self.mountable(e)) {
                let used = middleware
                    .iter()
                    .filter_map(|e| callee_name(e))
                    .filter_map(|name| m().auth_of(&name))
                    .max();
                if let Some(level) = used {
                    self.router_auth
                        .entry(router_key(object, env))
                        .or_default()
                        .push((prefix.unwrap_or_default(), level));
                }
            }
        }
        // Routes are kept from the final pass only (facts reset before it); templates from any.
        {
            self.record_entry(&callee, call, role, route_auth, env);
            // `routes.forEach((r) => router[r.method](r.path, r.handler))`: one record-only
            // walk of the callback per known row.
            if let Callee::Method {
                object: Some(table),
                method,
            } = &callee
                && has(&m().iteration_methods, method)
                && let Some(rows) = env.tables.get(table).cloned()
                && let Some(callback) = call.arguments.first().and_then(Argument::as_expression)
            {
                let params = match callback.get_inner_expression() {
                    Expression::ArrowFunctionExpression(f) => Some(&f.params),
                    Expression::FunctionExpression(f) => Some(&f.params),
                    _ => None,
                };
                let var = params
                    .and_then(|p| p.items.first())
                    .and_then(|p| match &p.pattern {
                        BindingPattern::BindingIdentifier(id) => Some(id.name.as_str().to_owned()),
                        _ => None,
                    });
                if let Some(var) = var {
                    for row in rows.into_iter().take(100) {
                        let mut inner = env.clone();
                        inner.rows.insert(var.clone(), row);
                        let saved = std::mem::replace(&mut self.record_only, true);
                        self.maybe_function(callback, &inner, None, Role::Plain);
                        self.record_only = saved;
                    }
                }
            }
        }
        let mut taints = Vec::with_capacity(call.arguments.len());
        for (index, argument) in call.arguments.iter().enumerate() {
            let arg_role = match shape {
                Shape::LastCallback if index != last => Role::Plain,
                Shape::ObjectOfFunctions => Role::Plain,
                _ => role,
            };
            // `items.map((item) => ...)` on tainted items: the callback's element is tainted.
            let arg_role = match (&callee, &receiver) {
                (Callee::Method { method, .. }, Some(origin))
                    if arg_role == Role::Plain && has(&m().iteration_methods, method) =>
                {
                    Role::Client(origin.kind, Params::First)
                }
                _ => arg_role,
            };
            let callbacks_object = matches!(shape, Shape::ObjectOfFunctions | Shape::RouteObject)
                && matches!(
                    argument
                        .as_expression()
                        .map(Expression::get_inner_expression),
                    Some(Expression::ObjectExpression(_))
                );
            if arg_role == Role::Route {
                self.pending_auth = route_auth;
            }
            let taint = match (argument.as_expression(), &route_name) {
                // Walked below, once, as callbacks.
                _ if callbacks_object => None,
                (Some(expr), Some(name)) if arg_role == Role::Route => {
                    if self.maybe_function(expr, env, Some(name.clone()), arg_role) {
                        None
                    } else {
                        self.expr(expr, env)
                    }
                }
                _ => self.argument(argument, env, arg_role),
            };
            taints.push(taint);
        }
        // `Meteor.methods({ name(args) { ... } })`, `fastify.route({ method, url, handler })`:
        // the function-valued properties of an object argument are the callbacks.
        if shape == Shape::ObjectOfFunctions || shape == Shape::RouteObject {
            for argument in &call.arguments {
                let Some(Expression::ObjectExpression(object)) = argument
                    .as_expression()
                    .map(Expression::get_inner_expression)
                else {
                    continue;
                };
                let route = (shape == Shape::RouteObject).then(|| {
                    let text = |key: &str| {
                        object_prop(argument.as_expression()?, &[key]).and_then(|v| {
                            match v.get_inner_expression() {
                                Expression::StringLiteral(l) => l.value.as_str().map(str::to_owned),
                                _ => None,
                            }
                        })
                    };
                    format!(
                        "{} {}",
                        m().route_method_keys
                            .iter()
                            .find_map(|k| text(k))
                            .unwrap_or_default()
                            .to_ascii_uppercase(),
                        m().route_path_keys
                            .iter()
                            .find_map(|k| text(k))
                            .unwrap_or_default()
                    )
                });
                if let (Some(route), false) = (&route, self.summarize)
                    && let Some((verb, path)) = route.split_once(' ')
                    && !path.is_empty()
                {
                    let receiver = match &callee {
                        Callee::Method { object, .. } => object.clone(),
                        _ => None,
                    };
                    self.facts.routes.push(RouteFact {
                        receiver,
                        method: if verb.is_empty() {
                            "ANY".to_owned()
                        } else {
                            verb.to_owned()
                        },
                        path: path.to_owned(),
                        handler: route.clone(),
                        span: call.span,
                        auth: Auth::NoneDetected,
                        kind: "http",
                    });
                }
                for property in &object.properties {
                    let ObjectPropertyKind::ObjectProperty(p) = property else {
                        continue;
                    };
                    let key = prop_name(&p.key);
                    if shape == Shape::RouteObject {
                        if key
                            .as_deref()
                            .is_some_and(|k| has(&m().route_handler_keys, k))
                        {
                            self.maybe_function(&p.value, env, route.clone(), Role::Route);
                        }
                        continue;
                    }
                    let name = match (&callee, key) {
                        (
                            Callee::Method {
                                object: Some(o),
                                method,
                            },
                            Some(k),
                        ) => Some(format!("{o}.{method} {k}")),
                        (_, key) => key,
                    };
                    self.maybe_function(&p.value, env, name, role);
                }
            }
        }

        // Lowering: the call, its callee and what each argument is.
        if !self.summarize
            && !self.record_only
            && let Some(callee_text) = callee_name(&call.callee)
        {
            let args = call
                .arguments
                .iter()
                .zip(&taints)
                .map(|(argument, taint)| {
                    let expr = argument
                        .as_expression()
                        .map(Expression::get_inner_expression);
                    match (expr, taint) {
                        (Some(Expression::StringLiteral(l)), _) => {
                            jss_core::ir::Value::Literal(l.value.as_str().unwrap_or("").to_owned())
                        }
                        (Some(Expression::NumericLiteral(n)), _) => {
                            jss_core::ir::Value::Literal(n.value.to_string())
                        }
                        (Some(Expression::Identifier(id)), _)
                            if env.params.iter().any(|p| p == id.name.as_str()) =>
                        {
                            jss_core::ir::Value::Param(
                                env.params
                                    .iter()
                                    .position(|p| p == id.name.as_str())
                                    .unwrap_or(0),
                            )
                        }
                        (_, Some(origin)) => jss_core::ir::Value::Source(origin.kind.to_owned()),
                        _ => jss_core::ir::Value::Other,
                    }
                })
                .collect();
            self.facts
                .calls
                .entry(env.function.clone())
                .or_default()
                .push((callee_text, call.span.start, args));
        }

        // Sinks.
        let sink = match &callee {
            Callee::Module { family, export } => {
                m().module_sink(family, export.as_deref().unwrap_or(""))
            }
            Callee::Global(name) => m().global_sink(name),
            // A method of one of our own modules is user code: followed through summaries.
            Callee::Method {
                object: Some(object),
                method,
            } if self.own_function_followed(object, method) => None,
            // `params.append(k, v)` on a `new URLSearchParams()`.
            Callee::Method {
                object: Some(object),
                ..
            } if env.plain.contains(object) => None,
            Callee::Method { method, .. } => {
                // `document.write(...)` before any `write(...)`.
                let qualified = call
                    .callee
                    .get_inner_expression()
                    .as_member_expression()
                    .and_then(|mem| guards::path_key(mem.object()))
                    .map(|object| format!("{object}.{method}"));
                qualified
                    .and_then(|q| m().method_sink(&q))
                    .or_else(|| m().method_sink(method))
            }
        };
        if let Some(sink) = sink {
            self.check_sink(
                sink.clone(),
                &callee,
                &call.arguments,
                &taints,
                call.span,
                env,
            );
        }

        // Same-file helpers whose parameters reach a sink (never for a method of an imported
        // module: `users.find()` is the other file's `find`, not this file's).
        let helper = match &callee {
            Callee::Global(name) => self.summaries.get(name).map(|s| (name.clone(), s.clone())),
            Callee::Method {
                object: Some(object),
                ..
            } if self.relative.contains_key(object)
                || self.modules.contains_key(object)
                || env.instances.contains_key(object) =>
            {
                None
            }
            Callee::Method { method, .. } if !method.is_empty() => {
                let suffix = format!(".{method}");
                let mut matching = self
                    .summaries
                    .iter()
                    .filter(|(k, _)| k.ends_with(&suffix) || *k == method);
                match (matching.next(), matching.next()) {
                    (Some((k, s)), None) => Some((k.clone(), s.clone())),
                    _ => None,
                }
            }
            _ => None,
        };
        // Then other files of the repository, by unique name.
        // Only through a relative import, and only to the file that import names.
        // The function an import names, through the exporting file's export table:
        // `import run from './shell'` is its default export (`export default function runCommand`,
        // `module.exports = runCommand`), `import { run }` may be an alias, `shell.run()` on a
        // whole module is its `run` export (`module.exports = { run: runCommand }`).
        // The function a call names in another of our files, through the exporting file's
        // export table: `import run from './shell'` is its default export (`export default
        // function runCommand`, `module.exports = runCommand`), `import { run }` may be an
        // alias, `shell.run()` on a whole module is its `run` export (`module.exports = { run:
        // runCommand }`), `svc.find()` on `new UsersService()` is `UsersService.find`.
        struct Target {
            spec: String,
            /// The defining file and local name, when the export table knows them.
            exact: Option<(String, String)>,
            /// Names to try otherwise (or for a class's methods), best first.
            names: Vec<String>,
        }
        let class_target =
            |this: &Self, spec: &String, export: Option<&str>, local: &str, method: &str| {
                let class = match export {
                    Some(e) if e != "default" => this
                        .exported_function(spec, e)
                        .map_or_else(|| e.to_owned(), |(_, name)| name),
                    _ => this
                        .exported_function(spec, "default")
                        .map_or_else(|| local.to_owned(), |(_, name)| name),
                };
                Target {
                    spec: spec.clone(),
                    exact: None,
                    names: vec![format!("{class}.{method}"), method.to_owned()],
                }
            };
        let linked: Option<Target> = match &callee {
            Callee::Global(name) => self.relative.get(name).map(|(spec, export)| {
                let export = export.as_deref().unwrap_or("default");
                Target {
                    spec: spec.clone(),
                    exact: self.exported_function(spec, export),
                    names: vec![export.to_owned()],
                }
            }),
            Callee::Method {
                object: Some(object),
                method,
            } if !method.is_empty() && env.instances.contains_key(object) => env
                .instances
                .get(object)
                .and_then(|class| self.relative.get(class).map(|r| (class, r)))
                .map(|(class, (spec, export))| {
                    class_target(self, spec, export.as_deref(), class, method)
                }),
            Callee::Method {
                object: Some(object),
                method,
            } if !method.is_empty() => {
                self.relative
                    .get(object)
                    .map(|(spec, export)| match export.as_deref() {
                        // `import { UsersService } ...; users.find()`: the class's method.
                        Some(class) if class != "default" => {
                            class_target(self, spec, Some(class), object, method)
                        }
                        _ => Target {
                            spec: spec.clone(),
                            exact: self.exported_function(spec, method),
                            names: vec![method.clone()],
                        },
                    })
            }
            _ => None,
        };
        let helper = helper.or_else(|| {
            let target = linked?;
            // Known exactly: that function of that file, or nothing (no flow to a sink).
            if let Some((file, name)) = &target.exact {
                let list: Vec<Summary> = self
                    .external
                    .get(name)?
                    .iter()
                    .filter(|s| s.defined_in.as_deref() == Some(file.as_str()))
                    .cloned()
                    .collect();
                return (!list.is_empty()).then(|| (name.clone(), list));
            }
            let spec = target.spec;
            let defined_there = |s: &Summary| {
                s.defined_in
                    .as_deref()
                    .or(s.ext.as_ref().map(|e| e.file.as_str()))
                    .is_some_and(|file| self.names_file(&spec, file))
            };
            // An exact name first; else one unique method of that name in that file.
            for name in &target.names {
                if let Some(list) = self.external.get(name) {
                    let list: Vec<Summary> =
                        list.iter().filter(|s| defined_there(s)).cloned().collect();
                    if !list.is_empty() {
                        return Some((name.clone(), list));
                    }
                }
            }
            let name = target.names.first()?.clone();
            let suffix = format!(".{name}");
            let mut matching = self
                .external
                .iter()
                .filter(|(k, list)| k.ends_with(&suffix) && list.iter().any(&defined_there));
            match (matching.next(), matching.next()) {
                (Some((k, list)), None) => Some((
                    k.clone(),
                    list.iter()
                        .filter(|s| defined_there(s))
                        .cloned()
                        .collect::<Vec<_>>(),
                )),
                _ => None,
            }
        });
        // What the helper returns: the taint of the arguments its return summaries name, field
        // by field when it returns an object literal.
        let mut returned_fields: BTreeMap<String, Origin> = BTreeMap::new();
        let returned = helper.as_ref().and_then(|(name, summaries)| {
            let mut whole = None;
            for s in summaries.iter().filter(|s| s.api == RETURNS) {
                let origin = if s.param == RETURNS_SOURCE {
                    let mut origin = Origin::source(s.at_sink.kind, call.span);
                    origin.object = s.at_sink.object;
                    Some(origin)
                } else {
                    let arg = taints.get(s.param).cloned().flatten();
                    match &s.field {
                        Some(field) => {
                            self.field_taint(call.arguments.get(s.param), field, env, arg)
                        }
                        None => arg,
                    }
                };
                // What the helper did to the value on its way out: built into a string,
                // put after a prefix, converted to a string, escaped.
                let at = &s.at_sink;
                let Some(origin) = origin.map(|mut o| {
                    o.built |= at.built;
                    o.sqlish |= at.sqlish;
                    o.prefix &= at.prefix;
                    o.object &= at.object;
                    o.escaped |= at.escaped;
                    o.step(call.span.start, format!("returned by `{name}()`"))
                }) else {
                    continue;
                };
                if let Some(field) = &s.out_field {
                    let entry = returned_fields.remove(field);
                    returned_fields.insert(
                        field.clone(),
                        union(entry, Some(origin.clone())).unwrap_or(origin.clone()),
                    );
                }
                whole = union(whole, Some(origin));
            }
            whole
        });
        self.last_returned_fields = (!returned_fields.is_empty()).then_some(returned_fields);
        // `isValidRequest(req, fileName)`: past the call, what it validates is clean.
        if let Some((_, summaries)) = &helper {
            let validated: Vec<(String, guards::Fact)> = summaries
                .iter()
                .filter(|s| s.api == VALIDATES)
                .filter_map(|s| {
                    call.arguments
                        .get(s.param)
                        .and_then(Argument::as_expression)
                        .and_then(guards::path_key)
                })
                .map(|key| (key, guards::Fact::Clean))
                .collect();
            env.learn(validated);
        }
        if let Some((name, summaries)) = helper {
            self.apply_summaries(
                &name,
                &summaries,
                &taints,
                Some(&call.arguments),
                call.span,
                env,
            );
        }
        // Handlers passed by reference: `socket.on('ev', onEvent)`, `ipcMain.handle(ch, fn)`.
        if let Role::Client(kind, selected) = role {
            for argument in &call.arguments {
                let Some(expr) = argument.as_expression() else {
                    continue;
                };
                let referenced = match expr.get_inner_expression() {
                    Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
                    other => other
                        .as_member_expression()
                        .and_then(|m| m.static_property_name())
                        .and_then(|n| n.as_str().map(str::to_owned)),
                };
                let Some(referenced) = referenced else {
                    continue;
                };
                let suffix = format!(".{referenced}");
                let found = self
                    .summaries
                    .iter()
                    .find(|(k, _)| **k == referenced || k.ends_with(&suffix))
                    .map(|(k, list)| (k.clone(), list.clone()));
                let Some((name, summaries)) = found else {
                    continue;
                };
                let most = summaries.iter().map(|s| s.param + 1).max().unwrap_or(0);
                let synthetic: Vec<Option<Origin>> = (0..most)
                    .map(|index| {
                        selected.wants(index).then(|| Origin {
                            kind,
                            span: expr.span(),
                            steps: Vec::new(),
                            built: false,
                            prefix: true,
                            sqlish: false,
                            escaped: 0,
                            param: None,
                            object: true,
                        })
                    })
                    .collect();
                self.apply_summaries(&name, &summaries, &synthetic, None, call.span, env);
            }
        }

        // Result taint. A verification's result (`jwt.verify(token)`) is trusted, whatever the
        // callee's return summary says.
        let callee_text = callee_name(&call.callee).unwrap_or_default();
        let last_segment = callee_text
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if m()
            .result_cleaning_prefixes
            .iter()
            .any(|p| last_segment.starts_with(p.as_str()))
        {
            return None;
        }
        // A helper named like an escaper from the packs (`function escapeHtml(s) {...}`): what it
        // returns is safe for that class only, though its return summary passes the value on.
        // (A library escaper has no summary: its result is not followed at all.)
        let escaped = escaper_classes(&callee);
        if escaped != 0
            && let Some(mut origin) = returned.clone()
        {
            origin.escaped |= escaped;
            return Some(origin.step(call.span.start, format!("escaped by `{callee_text}()`")));
        }
        if returned.is_some() {
            return returned;
        }
        let any_arg = || taints.iter().flatten().next().cloned();
        match &callee {
            Callee::Method { method, .. } => {
                // `req.get('x')`, `await request.json()`
                if let Some(member) = call.callee.get_inner_expression().as_member_expression()
                    && let Some(kind) =
                        self.request_kind(member.object().get_inner_expression(), env)
                    && has(&m().request_methods, method)
                {
                    return Some(Origin {
                        kind,
                        span: call.span,
                        steps: Vec::new(),
                        built: false,
                        prefix: true,
                        sqlish: false,
                        escaped: 0,
                        param: None,
                        object: true,
                    });
                }
                // Pack result sources: `zip.getEntries()`.
                if let Some(source) = m().result_sources.iter().find(|s| has(&s.methods, method)) {
                    return Some(Origin::source(source.kind.as_str(), call.span));
                }
                // `s.replace(/[^a-z0-9_-]/gi, '')`: an allowlist strip leaves only safe characters.
                if has(&m().strip_methods, method) && allowlist_strip(&call.arguments) {
                    return None;
                }
                if has(&m().pass_methods, method) {
                    let built = has(&m().build_methods, method);
                    let taint = union(receiver, any_arg());
                    return taint.map(|mut o| {
                        o.built |= built;
                        o.object = false;
                        o.step(call.span.start, format!("through .{method}()"))
                    });
                }
                None
            }
            Callee::Module { family, export } => {
                let export = export.as_deref().unwrap_or("");
                let qualified = format!("{family}.{export}");
                if has(&m().clearing, &qualified) {
                    return None;
                }
                if has(&m().module_pass, &qualified) {
                    let built = has(&m().build_methods, export);
                    return any_arg().map(|mut o| {
                        o.built |= built;
                        // `path.join(...)`, `util.format(...)`: a string.
                        o.object = false;
                        o.step(call.span.start, format!("through {qualified}()"))
                    });
                }
                None
            }
            Callee::Global(name) => {
                if has(&m().clearing, name) {
                    return None;
                }
                if has(&m().pass_globals, name) {
                    let built = name
                        .rsplit('.')
                        .next()
                        .is_some_and(|last| last != name && has(&m().build_methods, last));
                    return any_arg().map(|mut o| {
                        o.built |= built;
                        // `String(x)` is a string; `JSON.parse(x)` can be an operator object.
                        o.object = has(&m().object_globals, name);
                        o.step(call.span.start, format!("through {name}()"))
                    });
                }
                None
            }
        }
    }

    /// How a call's function arguments are entered, from the packs' route, socket and
    /// client-source conventions.
    fn client_role(
        &self,
        callee: &Callee,
        callee_expr: &Expression<'_>,
        arguments: &[Argument<'_>],
        env: &Env,
    ) -> (Role, Shape) {
        let model = m();
        self.pending_request_kind.set(None);
        self.pending_server_fields.set(None);
        let event = match arguments.first() {
            Some(Argument::StringLiteral(lit)) => lit.value.as_str(),
            _ => None,
        };
        let (object, method) = match callee {
            Callee::Method { object, method } => (object.as_deref(), method.as_str()),
            Callee::Global(name) => (None, name.as_str()),
            Callee::Module { export, .. } => (None, export.as_deref().unwrap_or("")),
        };
        // The property the receiver was read from: `chrome.runtime.onMessage.addListener`.
        let via = callee_expr
            .get_inner_expression()
            .as_member_expression()
            .and_then(|mem| mem.object().as_member_expression())
            .and_then(|o| o.static_property_name())
            .and_then(|p| p.as_str().map(str::to_owned));
        for source in &model.client_sources {
            if !has(&source.methods, method)
                || source.object.as_deref().is_some_and(|o| object != Some(o))
                || source.event.as_deref().is_some_and(|e| event != Some(e))
                || (!source.via.is_empty() && !via.as_deref().is_some_and(|v| has(&source.via, v)))
                || source.shape.as_deref() == Some("resolver-map")
                || source.arity.is_some_and(|n| n != arguments.len())
                || (source.shape.as_deref().unwrap_or("callback") == "callback"
                    && !arguments.iter().any(|a| {
                        a.as_expression().is_some_and(|e| {
                            matches!(
                                e.get_inner_expression(),
                                Expression::ArrowFunctionExpression(_)
                                    | Expression::FunctionExpression(_)
                                    | Expression::Identifier(_)
                                    | Expression::StaticMemberExpression(_)
                            )
                        })
                    }))
            {
                continue;
            }
            let params = Params::parse(&source.params);
            if !source.server_fields.is_empty() {
                self.pending_server_fields
                    .set(Some(source.server_fields.as_slice()));
            }
            let shape = match source.shape.as_deref() {
                Some("last-callback") => Shape::LastCallback,
                Some("object-of-functions") => Shape::ObjectOfFunctions,
                _ => Shape::Callback,
            };
            return (Role::Client(source.kind.as_str(), params), shape);
        }
        if has(&model.socket_methods, method) || has(&model.socket_any_methods, method) {
            if event.is_some_and(|e| has(&model.socket_connection_events, e)) {
                return (Role::SocketConnection, Shape::Callback);
            }
            let socketish = object.is_some_and(|o| {
                env.sockets.contains(o) || {
                    let lower = o.to_ascii_lowercase();
                    model
                        .socket_name_contains
                        .iter()
                        .any(|n| lower.contains(n.as_str()))
                        || has(&model.socket_names, &lower)
                }
            });
            if socketish && has(&model.socket_any_methods, method) {
                // `socket.onAny((event, ...args) => ...)`
                return (Role::Client("socket", Params::AfterFirst), Shape::Callback);
            }
            if socketish && event.is_some_and(|e| !has(&model.socket_builtin_events, e)) {
                return (Role::Client("socket", Params::All), Shape::Callback);
            }
        }
        if has(&model.server_factories, method) {
            return (Role::Route, Shape::Callback);
        }
        // `server.middlewares.use((req, res, next) => ...)`: a dev server's handlers.
        if let Some(registration) = model
            .middleware_registrations
            .iter()
            .find(|r| has(&r.methods, method) && via.as_deref().is_some_and(|v| has(&r.via, v)))
        {
            self.pending_request_kind
                .set(Some(registration.kind.as_str()));
            return (Role::Route, Shape::Callback);
        }
        if let Callee::Method { .. } = callee {
            if has(&model.route_object_methods, method)
                && matches!(
                    arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .map(Expression::get_inner_expression),
                    Some(Expression::ObjectExpression(_))
                )
            {
                return (Role::Plain, Shape::RouteObject);
            }
            if has(&model.route_methods, method) && arguments.len() >= 2 {
                return (Role::Route, Shape::Callback);
            }
        }
        (Role::Plain, Shape::Callback)
    }

    /// The taint of `argument.field`: from an object literal's property, a variable's tracked
    /// fields, or (when neither is known) the whole argument.
    fn field_taint(
        &mut self,
        argument: Option<&Argument<'_>>,
        field: &str,
        env: &Env,
        whole: Option<Origin>,
    ) -> Option<Origin> {
        let expr = argument?.as_expression()?.get_inner_expression();
        // The server chose this field: an upload's `path` (`move(req.file)`), or a field a
        // client source lists as the server's.
        if has(&m().upload_server_fields, field) && self.is_upload_object(expr, env) {
            return None;
        }
        if let Expression::Identifier(id) = expr
            && env
                .server_fields
                .get(id.name.as_str())
                .is_some_and(|fields| has(fields, field))
        {
            return None;
        }
        match expr {
            Expression::ObjectExpression(object) => {
                let mut taint = None;
                for property in &object.properties {
                    match property {
                        ObjectPropertyKind::ObjectProperty(p)
                            if prop_name(&p.key).as_deref() == Some(field) =>
                        {
                            let mut probe = env.clone();
                            taint = union(taint, self.expr(&p.value, &mut probe));
                        }
                        // `{ ...opts }` may carry the field.
                        ObjectPropertyKind::SpreadProperty(spread) => {
                            let mut probe = env.clone();
                            taint = union(taint, self.expr(&spread.argument, &mut probe));
                        }
                        ObjectPropertyKind::ObjectProperty(_) => {}
                    }
                }
                taint
            }
            Expression::Identifier(id) => match env.fields.get(id.name.as_str()) {
                Some(fields) => fields.get(field).cloned(),
                None => whole,
            },
            _ => whole,
        }
    }

    /// Records the entry point or mount a registration call makes.
    /// The name of an inline route handler: `GET /items`, or, when another registration in
    /// this file already took that name, with its receiver (`GET / [settings]`).
    fn inline_route_name(
        &mut self,
        method: &str,
        path: &str,
        receiver: Option<&str>,
        at: u32,
    ) -> String {
        let base = format!("{} {path}", method.to_ascii_uppercase());
        match self.inline_names.get(&base) {
            None => {
                self.inline_names.insert(base.clone(), at);
                base
            }
            Some(first) if *first == at => base,
            Some(_) => match receiver {
                Some(receiver) => format!("{base} [{receiver}]"),
                None => base,
            },
        }
    }

    fn record_entry(
        &mut self,
        callee: &Callee,
        call: &CallExpression<'_>,
        role: Role,
        auth: Auth,
        env: &Env,
    ) {
        // A helper that registers routes from its parameters: `add('/x', handler)` here or in
        // another file instantiates its routes (or, called with this function's own parameters,
        // makes this function a template too).
        if let Some((name, templates)) = self.templates_for(callee) {
            for template in templates {
                self.instantiate(&name, &template, call, auth, env);
            }
            return;
        }
        // `router.get(...)`, or `router[r.method](...)` with the method from a table row or a
        // parameter.
        let computed = match call.callee.get_inner_expression() {
            Expression::ComputedMemberExpression(c) => Some(c),
            _ => None,
        };
        let (object, method, method_param) = match (callee, computed) {
            (Callee::Method { object, method }, _) if !method.is_empty() => {
                (object.clone(), method.clone(), None)
            }
            (_, Some(c)) => {
                let object = match c.object.get_inner_expression() {
                    Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
                    _ => None,
                };
                match self.resolve_text(&c.expression, env) {
                    Some(method) => (object, method, None),
                    None => {
                        let param = match c.expression.get_inner_expression() {
                            Expression::Identifier(id) => {
                                env.params.iter().position(|p| p == id.name.as_str())
                            }
                            _ => None,
                        };
                        let Some(param) = param else { return };
                        (object, String::new(), Some(param))
                    }
                }
            }
            _ => return,
        };
        let role = if role == Role::Plain
            && (has(&m().route_methods, &method) || method_param.is_some())
            && call.arguments.len() >= 2
        {
            Role::Route
        } else {
            role
        };
        let first = call.arguments.first().and_then(Argument::as_expression);
        // A client source: an event, channel or schema name (`socket.on('join', ...)`,
        // `server.setRequestHandler(CallToolRequestSchema, ...)`), never the callback itself.
        if let Role::Client(kind, _) = role {
            let event = match call.arguments.first() {
                _ if call.arguments.len() < 2 => None,
                Some(Argument::StringLiteral(name)) => name.value.as_str().map(str::to_owned),
                Some(Argument::Identifier(id)) => Some(
                    self.constant(id.name.as_str())
                        .unwrap_or_else(|| id.name.as_str().to_owned()),
                ),
                _ => None,
            };
            if let Some(event) =
                event.filter(|n| !n.is_empty() && !n.contains(char::is_whitespace) && n.len() < 120)
            {
                let handler = call
                    .arguments
                    .last()
                    .and_then(Argument::as_expression)
                    .and_then(|e| match e.get_inner_expression() {
                        Expression::ArrowFunctionExpression(_)
                        | Expression::FunctionExpression(_) => None,
                        other => callee_name(other),
                    })
                    .unwrap_or_else(|| format!("{} {event}", kind.to_ascii_uppercase()));
                self.facts.routes.push(RouteFact {
                    receiver: object.clone(),
                    method: kind.to_ascii_uppercase(),
                    path: event,
                    handler,
                    span: call.span,
                    auth,
                    kind,
                });
            }
            return;
        }
        // `function add(path, h) { router.get(path, h) }`: a template, not a route.
        let parts = first.and_then(|e| self.path_parts(e, env));
        let receiver_param = object
            .as_deref()
            .and_then(|o| env.params.iter().position(|p| p == o));
        let depends_on_params = parts
            .as_ref()
            .is_some_and(|p| p.iter().any(|part| matches!(part, PathPart::Param(_))))
            || method_param.is_some();
        // A template must register on a router: a parameter (checked when instantiated) or a
        // router-like variable (not `Options.get(module, option)`).
        let router_receiver =
            receiver_param.is_some() || object.as_deref().is_some_and(|o| self.is_router(o));
        if role == Role::Route
            && depends_on_params
            && router_receiver
            && env.function != "<anonymous>"
            && env.function != "<module>"
            && let Some(parts) = parts
        {
            let template = RouteTemplate {
                receiver: match receiver_param {
                    Some(index) => Err(index),
                    None => Ok(object.clone()),
                },
                method: match method_param {
                    Some(index) => Err(index),
                    None => Ok(method.clone()),
                },
                path: parts,
                auth,
            };
            let list = self
                .route_templates
                .entry(env.function.clone())
                .or_default();
            if !list.contains(&template) {
                list.push(template);
            }
            return;
        }
        if method_param.is_some() {
            return;
        }
        // `router.use(child)`, `app.use(requireAuth, api)`: path-less mounts.
        if has(&m().mount_methods, &method)
            && object.as_deref().is_some_and(|o| self.is_router(o))
            && first.is_some_and(|e| self.mount_path(e, env).is_none())
        {
            for argument in call.arguments.iter().filter_map(Argument::as_expression) {
                if !self.mountable(argument) {
                    continue;
                }
                let (target, target_file) = self.mount_target(argument);
                self.facts.mounts.push(MountFact {
                    receiver: object.clone(),
                    prefix: String::new(),
                    target,
                    target_file,
                    auth,
                });
            }
            return;
        }
        let Some(path) = first.and_then(|e| self.resolve_text(e, env)) else {
            return;
        };
        let object = &object;
        let method = &method;
        // Only registrations on a router or app: not `$http.get('/x', config)` in a client.
        let is_router = object.as_deref().is_some_and(|o| self.is_router(o));
        let handler_like = call
            .arguments
            .last()
            .and_then(Argument::as_expression)
            .is_some_and(|e| {
                !matches!(
                    e.get_inner_expression(),
                    Expression::ObjectExpression(_)
                        | Expression::StringLiteral(_)
                        | Expression::TemplateLiteral(_)
                        | Expression::NumericLiteral(_)
                        | Expression::ArrayExpression(_)
                )
            });
        if role == Role::Route && !(is_router && handler_like) {
            return;
        }
        let last = call.arguments.last().and_then(Argument::as_expression);
        let handler = last
            .and_then(|e| match e.get_inner_expression() {
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => None,
                other => callee_name(other),
            })
            .unwrap_or_else(|| {
                self.inline_route_name(method, &path, object.as_deref(), call.span.start)
            });
        let is_function = last.is_some_and(|e| {
            matches!(
                e.get_inner_expression(),
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
            )
        });
        if role == Role::Route {
            {
                // `router.use('/api', child)`: a mount, unless the last argument is a handler.
                if has(&m().mount_methods, method) && !is_function {
                    let (target, target_file) = match last {
                        Some(e) => self.mount_target(e),
                        None => (None, None),
                    };
                    self.facts.mounts.push(MountFact {
                        receiver: object.clone(),
                        prefix: path,
                        target,
                        target_file,
                        auth,
                    });
                    return;
                }
                self.facts.routes.push(RouteFact {
                    receiver: object.clone(),
                    method: method.to_ascii_uppercase(),
                    path,
                    handler,
                    span: call.span,
                    auth,
                    kind: "http",
                });
            }
        }
    }

    /// The summaries of `class`'s constructor: this file's, or the imported class's.
    fn constructor_summaries(&self, class: &str) -> Option<(String, Vec<Summary>)> {
        let key = format!("{class}.constructor");
        if let Some(list) = self.summaries.get(&key) {
            return Some((key, list.clone()));
        }
        let (spec, export) = self.relative.get(class)?;
        // `import Job from './runner'` with `export default class Runner`: `Runner`.
        let exported = match export.as_deref() {
            Some(e) if e != "default" => self
                .exported_function(spec, e)
                .map_or_else(|| e.to_owned(), |(_, name)| name),
            _ => self
                .exported_function(spec, "default")
                .map_or_else(|| class.to_owned(), |(_, name)| name),
        };
        let key = format!("{exported}.constructor");
        let list: Vec<Summary> = self
            .external
            .get(&key)?
            .iter()
            .filter(|s| {
                s.defined_in
                    .as_deref()
                    .or(s.ext.as_ref().map(|e| e.file.as_str()))
                    .is_some_and(|file| self.names_file(spec, file))
            })
            .cloned()
            .collect();
        (!list.is_empty()).then_some((key, list))
    }

    /// Whether `object.method` is a function of one of our own modules that a summary describes
    /// (so the call is followed into it, rather than matched as a library sink by its name).
    fn own_function_followed(&self, object: &str, method: &str) -> bool {
        let Some((spec, _)) = self.relative.get(object) else {
            return false;
        };
        // A function the module exports (`exports.find = function find`): our code, not a
        // library call named like a sink.
        if self.exported_function(spec, method).is_some() {
            return true;
        }
        let suffix = format!(".{method}");
        self.external.iter().any(|(name, list)| {
            (name == method || name.ends_with(&suffix))
                && list.iter().any(|s| {
                    s.defined_in
                        .as_deref()
                        .or(s.ext.as_ref().map(|e| e.file.as_str()))
                        .is_some_and(|file| self.names_file(spec, file))
                })
        })
    }

    /// Whether `expr` is an upload object of the request: `req.file`, `req.files[0]`,
    /// `req.files.avatar[0]`.
    fn is_upload_object(&self, expr: &Expression<'_>, env: &Env) -> bool {
        // `req.files || {}`, `req.files && req.files.avatar[0]`, `x ? req.file : null`.
        match expr.get_inner_expression() {
            Expression::LogicalExpression(l) => {
                return self.is_upload_object(&l.left, env) || self.is_upload_object(&l.right, env);
            }
            Expression::ConditionalExpression(c) => {
                return self.is_upload_object(&c.consequent, env)
                    || self.is_upload_object(&c.alternate, env);
            }
            _ => {}
        }
        let mut cursor = expr.get_inner_expression();
        while let Expression::ComputedMemberExpression(c) = cursor {
            cursor = c.object.get_inner_expression();
        }
        let model = m();
        let upload = |member: &oxc_ast::ast::MemberExpression<'_>| {
            member
                .static_property_name()
                .is_some_and(|p| has(&model.upload_objects, p.as_str().unwrap_or("")))
        };
        // `req.files.avatar`: the field under the upload object.
        let member = match cursor.as_member_expression() {
            Some(outer) if upload(outer) => Some(outer),
            Some(outer) => outer
                .object()
                .get_inner_expression()
                .as_member_expression()
                .filter(|inner| upload(inner)),
            None => None,
        };
        member.is_some_and(|member| {
            self.request_kind(member.object().get_inner_expression(), env)
                .is_some()
        })
    }

    /// The path a `use(path, ...)` or a route starts with: text, or a call that joins text
    /// (`urljoin(root, 'api')`), never auth middleware (`passport.authenticate('jwt')`).
    fn mount_path(&self, expr: &Expression<'_>, env: &Env) -> Option<String> {
        if matches!(expr.get_inner_expression(), Expression::CallExpression(_))
            && callee_name(expr).is_some_and(|name| m().auth_of(&name).is_some())
        {
            return None;
        }
        self.resolve_text(expr, env)
    }

    /// Whether a `use(...)` argument mounts routes rather than adding middleware: a router, a
    /// router imported from our own files, or `require('./routes')` (or a factory call of it).
    fn mountable(&self, expr: &Expression<'_>) -> bool {
        match expr.get_inner_expression() {
            Expression::Identifier(id) => {
                let name = id.name.as_str();
                self.is_router(name)
                    || (self.relative.contains_key(name) && m().auth_of(name).is_none())
            }
            e @ Expression::CallExpression(c) => {
                require_spec(e).is_some() || require_spec(&c.callee).is_some()
            }
            _ => false,
        }
    }

    /// What a mount argument names: a local router, or the file of `require('./users')` (or of
    /// a factory `require('./users')()`).
    fn mount_target(&self, expr: &Expression<'_>) -> (Option<String>, Option<String>) {
        match expr.get_inner_expression() {
            Expression::Identifier(id) => (Some(id.name.as_str().to_owned()), None),
            e => {
                let required = match e {
                    Expression::CallExpression(c) if require_spec(e).is_none() => {
                        require_spec(&c.callee)
                    }
                    _ => require_spec(e),
                };
                (None, required.and_then(|spec| self.linking.resolve(&spec)))
            }
        }
    }

    /// A router or app variable: from a factory, or named like one.
    fn is_router(&self, name: &str) -> bool {
        self.routers.contains(name) || {
            let lower = name.to_ascii_lowercase();
            m().router_names
                .iter()
                .any(|n| lower == *n || lower.ends_with(n.as_str()))
        }
    }

    /// The route templates a callee has: this file's, or (through an import) another file's.
    fn templates_for(&self, callee: &Callee) -> Option<(String, Vec<RouteTemplate>)> {
        let (local, linked) = match callee {
            Callee::Global(name) => (
                Some(name.clone()),
                self.relative.get(name).map(|(spec, export)| {
                    let key = export
                        .clone()
                        .filter(|e| e != "default")
                        .unwrap_or_else(|| name.clone());
                    (spec.clone(), key)
                }),
            ),
            Callee::Method {
                object: Some(object),
                method,
            } => (
                // `helpers.setupPageRoute(...)` inside the file that defines it.
                (!self.relative.contains_key(object)).then(|| method.clone()),
                self.relative
                    .get(object)
                    .map(|(spec, _)| (spec.clone(), method.clone())),
            ),
            _ => (None, None),
        };
        if let Some(name) = local
            && let Some(list) = self.route_templates.get(&name)
        {
            return Some((name, list.clone()));
        }
        let (spec, key) = linked?;
        let file = self.linking.resolve(&spec)?;
        let mut files = vec![file.clone()];
        if let Some(more) = self.linking.reexports.get(&file) {
            files.extend(more.iter().cloned());
        }
        files.iter().find_map(|f| {
            self.linking
                .templates
                .get(f)
                .and_then(|by_name| by_name.get(&key))
                .map(|list| (key.clone(), list.clone()))
        })
    }

    /// Instantiates a route template at a call: a route when every part is known, otherwise a
    /// template of the calling function (when it passes its own parameters along).
    fn instantiate(
        &mut self,
        name: &str,
        template: &RouteTemplate,
        call: &CallExpression<'_>,
        auth: Auth,
        env: &Env,
    ) {
        let arg = |index: usize| call.arguments.get(index).and_then(Argument::as_expression);
        let mut path = Vec::new();
        for part in &template.path {
            match part {
                PathPart::Lit(text) => path.push(PathPart::Lit(text.clone())),
                PathPart::Param(index) => {
                    let Some(parts) = arg(*index).and_then(|e| self.path_parts(e, env)) else {
                        return;
                    };
                    path.extend(parts);
                }
            }
        }
        let param_of =
            |expr: Option<&Expression<'_>>| match expr.map(Expression::get_inner_expression) {
                Some(Expression::Identifier(id)) => {
                    env.params.iter().position(|p| p == id.name.as_str())
                }
                _ => None,
            };
        let method = match &template.method {
            Ok(method) => Ok(method.clone()),
            Err(index) => match arg(*index).and_then(|e| self.resolve_text(e, env)) {
                Some(method) => Ok(method),
                None => match param_of(arg(*index)) {
                    Some(own) => Err(own),
                    None => return,
                },
            },
        };
        let receiver = match &template.receiver {
            Ok(receiver) => Ok(receiver.clone()),
            Err(index) => match param_of(arg(*index)) {
                Some(own) => Err(own),
                None => Ok(match arg(*index).map(Expression::get_inner_expression) {
                    Some(Expression::Identifier(id)) => Some(id.name.as_str().to_owned()),
                    _ => None,
                }),
            },
        };
        let open = path.iter().any(|p| matches!(p, PathPart::Param(_))) || method.is_err();
        if open {
            if env.function != "<anonymous>" && env.function != "<module>" {
                let derived = RouteTemplate {
                    receiver,
                    method,
                    path,
                    auth: template.auth.max(auth),
                };
                let list = self
                    .route_templates
                    .entry(env.function.clone())
                    .or_default();
                if !list.contains(&derived) {
                    list.push(derived);
                }
            }
            return;
        }
        let text: String = path
            .iter()
            .map(|p| match p {
                PathPart::Lit(text) => text.as_str(),
                PathPart::Param(_) => "",
            })
            .collect();
        let Ok(method) = method else { return };
        // Registered on a variable of the caller that is not a router: not a route.
        if let Ok(Some(receiver)) = &receiver
            && !self.is_router(receiver)
        {
            return;
        }
        self.facts.routes.push(RouteFact {
            receiver: receiver.ok().flatten(),
            method: method.to_ascii_uppercase(),
            path: text,
            handler: call
                .arguments
                .last()
                .and_then(Argument::as_expression)
                .and_then(callee_name)
                .unwrap_or_else(|| format!("{name}()")),
            span: call.span,
            auth: template.auth.max(auth),
            kind: "http",
        });
    }

    /// A path expression in terms of this function's parameters: `` `/api${name}` `` is
    /// `["/api", Param(name)]`. Unknown pieces fall back to the literal text around them.
    fn path_parts(&self, expr: &Expression<'_>, env: &Env) -> Option<Vec<PathPart>> {
        let param = |name: &str| env.params.iter().position(|p| p == name);
        match expr.get_inner_expression() {
            Expression::Identifier(id) if param(id.name.as_str()).is_some() => {
                param(id.name.as_str()).map(|i| vec![PathPart::Param(i)])
            }
            Expression::TemplateLiteral(template) => {
                let mut parts = Vec::new();
                for (index, quasi) in template.quasis.iter().enumerate() {
                    if let Some(text) = quasi.value.cooked.and_then(|c| c.as_str())
                        && !text.is_empty()
                    {
                        parts.push(PathPart::Lit(text.to_owned()));
                    }
                    if let Some(expression) = template.expressions.get(index) {
                        // An unknown piece (`${relativePath}`) is dropped, as for literal paths.
                        parts.extend(self.path_parts(expression, env).unwrap_or_default());
                    }
                }
                Some(parts)
            }
            Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
                let mut parts = self.path_parts(&b.left, env).unwrap_or_default();
                parts.extend(self.path_parts(&b.right, env).unwrap_or_default());
                (!parts.is_empty()).then_some(parts)
            }
            _ => self
                .resolve_text(expr, env)
                .map(|text| vec![PathPart::Lit(text)]),
        }
    }

    /// Text an expression stands for: a literal path, a field of the current table row, or a
    /// constant (an enum member or `const` string, here or in an imported module).
    fn resolve_text(&self, expr: &Expression<'_>, env: &Env) -> Option<String> {
        literal_path(expr).or_else(|| {
            let key = guards::path_key(expr)?;
            if let Some((var, field)) = key.split_once('.')
                && let Some(value) = env.rows.get(var).and_then(|row| row.get(field))
            {
                return Some(value.clone());
            }
            self.constant(&key)
        })
    }

    /// A constant by access path: this file's, or an imported module's (`RouteKey.Asset`).
    fn constant(&self, key: &str) -> Option<String> {
        if let Some(value) = self.constants.get(key) {
            return Some(value.clone());
        }
        let (head, rest) = match key.split_once('.') {
            Some((head, rest)) => (head, Some(rest)),
            None => (key, None),
        };
        let (spec, export) = self.relative.get(head)?;
        let file = self.linking.resolve(spec)?;
        let name = match (export.as_deref(), rest) {
            (Some(e), Some(rest)) if e != "default" => format!("{e}.{rest}"),
            (Some(e), None) if e != "default" => e.to_owned(),
            (_, Some(rest)) => rest.to_owned(),
            (_, None) => return None,
        };
        let mut files = vec![file.clone()];
        if let Some(more) = self.linking.reexports.get(&file) {
            files.extend(more.iter().cloned());
        }
        files.iter().find_map(|f| {
            self.linking
                .constants
                .get(f)
                .and_then(|c| c.get(&name))
                .cloned()
        })
    }

    /// Records a TypeScript enum's members with literal values.
    fn record_enum(&mut self, declaration: &oxc_ast::ast::TSEnumDeclaration<'_>) {
        use oxc_ast::ast::TSEnumMemberName;
        let enum_name = declaration.id.name.as_str();
        for member in &declaration.body.members {
            let key = match &member.id {
                TSEnumMemberName::Identifier(id) => id.name.as_str().to_owned(),
                TSEnumMemberName::String(lit) | TSEnumMemberName::ComputedString(lit) => {
                    lit.value.as_str().unwrap_or("").to_owned()
                }
                TSEnumMemberName::ComputedTemplateString(_) => continue,
            };
            let value = match member
                .initializer
                .as_ref()
                .map(Expression::get_inner_expression)
            {
                Some(Expression::StringLiteral(lit)) => lit.value.as_str().map(str::to_owned),
                Some(Expression::NumericLiteral(n)) => Some(n.value.to_string()),
                _ => None,
            };
            if let Some(value) = value {
                self.constants.insert(format!("{enum_name}.{key}"), value);
            }
        }
    }

    /// Whether the relative import `spec` names `file`: resolved exactly when the scan root's
    /// files are known, by name otherwise (a single file scanned alone).
    /// The function a module exports as `export` (`default` for `export default` /
    /// `module.exports =`): the file that defines it (the module itself, or a file a barrel
    /// re-exports) and its local name there. `None` when unknown (first round, or no such
    /// recorded export).
    fn exported_function(&self, spec: &str, export: &str) -> Option<(String, String)> {
        let file = self.linking.resolve(spec)?;
        let table = |f: &str| self.linking.exports.get(f);
        let reexported: Vec<&String> = self
            .linking
            .reexports
            .get(&file)
            .map(|set| set.iter().collect())
            .unwrap_or_default();
        match table(&file).and_then(|t| t.get(export)) {
            // A barrel's `export { default as runDefault } from './shell'`: the name it maps to
            // is an export of the file it re-exports.
            Some(local) => Some(
                reexported
                    .iter()
                    .find_map(|f| {
                        table(f)
                            .and_then(|t| t.get(local))
                            .map(|name| ((*f).clone(), name.clone()))
                    })
                    .unwrap_or_else(|| (file.clone(), local.clone())),
            ),
            None => reexported.iter().find_map(|f| {
                table(f)
                    .and_then(|t| t.get(export))
                    .map(|name| ((*f).clone(), name.clone()))
            }),
        }
    }

    fn names_file(&self, spec: &str, file: &str) -> bool {
        if self.linking.files.is_empty() {
            return spec_names_file(spec, file);
        }
        match self.linking.resolve(spec) {
            Some(resolved) => {
                resolved == file
                    || self
                        .linking
                        .reexports
                        .get(&resolved)
                        .is_some_and(|set| set.contains(file))
            }
            None => false,
        }
    }

    /// Reports each summary whose parameter receives a tainted value at a call.
    fn apply_summaries(
        &mut self,
        name: &str,
        summaries: &[Summary],
        taints: &[Option<Origin>],
        arguments: Option<&[Argument<'_>]>,
        call_span: Span,
        env: &Env,
    ) {
        for summary in summaries
            .iter()
            .filter(|s| s.api != RETURNS && s.api != VALIDATES)
        {
            let whole = taints.get(summary.param).cloned().flatten();
            let origin = match (&summary.field, arguments) {
                (Some(field), Some(arguments)) => {
                    self.field_taint(arguments.get(summary.param), field, env, whole)
                }
                _ => whole,
            };
            let Some(origin) = origin else {
                continue;
            };
            let at_sink = &summary.at_sink;
            let url_rule = summary.class == VulnClass::Ssrf || {
                let last = summary.api.rsplit('.').next().unwrap_or("");
                m().method_sink(last)
                    .or_else(|| m().global_sink(last))
                    .is_some_and(|s| s.args.iter().any(|r| matches!(r, ArgRule::UrlPrefix(_))))
            };
            // The helper used the parameter as the URL start: the caller must control it.
            if url_rule && at_sink.prefix && !origin.prefix {
                continue;
            }
            let built = at_sink.built || origin.built;
            let sqlish = at_sink.sqlish || origin.sqlish;
            if summary.class == VulnClass::SqlInjection && !(built && sqlish) {
                continue;
            }
            if summary.class == VulnClass::Xss && !built {
                continue;
            }
            // Route params and headers are strings: no NoSQL operator objects.
            if summary.class == VulnClass::NosqlInjection && !origin.object {
                continue;
            }
            // The sink ignores this kind of source (a browser URL is no SSRF).
            if sink_for_api(&summary.api).is_some_and(|s| has(&s.ignore_kinds, origin.kind)) {
                continue;
            }
            let mut origin = origin.step(call_span.start, format!("passed to `{name}()`"));
            for step in summary.steps.iter().filter(|_| summary.ext.is_none()) {
                if origin.steps.len() < MAX_STEPS {
                    origin.steps.push(step.clone());
                }
            }
            self.emit(
                RawFinding {
                    class: summary.class,
                    severity: summary.severity,
                    api: summary.api.clone(),
                    arg: if summary.ext.is_some() {
                        call_span
                    } else {
                        summary.arg
                    },
                    call: if summary.ext.is_some() {
                        call_span
                    } else {
                        summary.call
                    },
                    function: env.function.clone(),
                    origin,
                    ext: summary.ext.clone(),
                    auth: Auth::NoneDetected,
                },
                env,
            );
        }
    }

    /// Records a finding, or in the summary pass, a summary of a parameter that reaches a sink.
    fn emit(&mut self, mut finding: RawFinding, env: &Env) {
        // Escaped for this class on the way (every sink kind ends here).
        if self.record_only || finding.origin.escaped & class_bit(finding.class) != 0 {
            return;
        }
        finding.auth = finding.auth.max(env.auth);
        // Reachable by admins only: one level lower.
        if finding.auth == Auth::Admin {
            finding.severity = match finding.severity {
                Severity::Critical => Severity::High,
                Severity::High => Severity::Medium,
                Severity::Medium | Severity::Low => Severity::Low,
            };
        }
        // The CLI is the user's own machine: never above low.
        finding.severity = m().cap(finding.origin.kind, finding.severity);
        match (self.summarize, finding.origin.param) {
            (true, Some(param)) => {
                // Reached through an instance field set from a constructor parameter.
                let owner = match self.ctor_params.get(&finding.origin.span.start) {
                    Some(class) => format!("{class}.constructor"),
                    None => env.function.clone(),
                };
                let list = self.summaries.entry(owner).or_default();
                let duplicate = list
                    .iter()
                    .any(|s| s.param == param && s.call == finding.call && s.api == finding.api);
                if !duplicate {
                    list.push(Summary {
                        param,
                        class: finding.class,
                        severity: finding.severity,
                        api: finding.api,
                        arg: finding.arg,
                        call: finding.call,
                        steps: finding.origin.steps.clone(),
                        field: self.field_of.get(&finding.origin.span.start).cloned(),
                        at_sink: finding.origin,
                        ext: finding.ext,
                        out_field: None,
                        defined_in: None,
                    });
                }
            }
            (false, None) => self.result.findings.push(finding),
            _ => {}
        }
    }

    fn check_sink(
        &mut self,
        sink: models::Sink,
        callee: &Callee,
        arguments: &[Argument<'_>],
        taints: &[Option<Origin>],
        span: Span,
        env: &Env,
    ) {
        let api = match callee {
            Callee::Module { family, export } => match export.as_deref() {
                Some(export) if !export.is_empty() => format!("{family}.{export}"),
                _ => (*family).to_owned(),
            },
            Callee::Global(name) => name.clone(),
            Callee::Method { object, method } => match object {
                Some(object) => format!("{object}.{method}"),
                None => format!(".{method}"),
            },
        };
        // An option that confines the sink: `res.sendFile(p, { root })`.
        let confined = arguments
            .iter()
            .skip(1)
            .filter_map(Argument::as_expression)
            .any(|e| {
                sink.confined_by
                    .iter()
                    .any(|key| object_prop(e, &[key.as_str()]).is_some())
            });
        if confined {
            return;
        }
        let mut severity = sink.severity;
        let mut rules: Vec<ArgRule> = sink.args.clone();
        // An option that escalates: `spawn(cmd, args, { shell: true })`.
        if let Some((option, escalated, escalated_rules)) = &sink.escalate
            && arguments
                .iter()
                .filter_map(Argument::as_expression)
                .any(|e| {
                    object_prop(e, &[option.as_str()]).is_some_and(|v| {
                    !matches!(v.get_inner_expression(), Expression::BooleanLiteral(b) if !b.value)
                })
                })
        {
            severity = *escalated;
            rules = escalated_rules.clone();
        }
        let mut groups = vec![(severity, rules)];
        groups.extend(sink.also.iter().cloned());
        for (severity, rules) in groups {
            if self.check_rules(&sink, &api, severity, &rules, arguments, taints, span, env) {
                return;
            }
        }
    }

    /// Checks one group of argument rules; true when a finding was recorded.
    #[allow(clippy::too_many_arguments)]
    fn check_rules(
        &mut self,
        sink: &models::Sink,
        api: &str,
        severity: Severity,
        rules: &[ArgRule],
        arguments: &[Argument<'_>],
        taints: &[Option<Origin>],
        span: Span,
        env: &Env,
    ) -> bool {
        for &rule in rules {
            let (index, origin) =
                match rule {
                    ArgRule::Any(index) => (index, taints.get(index).cloned().flatten()),
                    ArgRule::Html(index) => (
                        index,
                        taints.get(index).cloned().flatten().filter(|o| o.built),
                    ),
                    ArgRule::Object(index) => {
                        // `find(req.body.filter)` or `find({ email: req.body.email })`: a value that
                        // JSON or qs can turn into `{ "$ne": null }`.
                        let arg = arguments.get(index).and_then(Argument::as_expression);
                        let from_fields = match arg.map(Expression::get_inner_expression) {
                            Some(Expression::ObjectExpression(object)) => object
                                .properties
                                .iter()
                                .find_map(|property| match property {
                                    ObjectPropertyKind::ObjectProperty(p) => {
                                        let mut probe = env.clone();
                                        self.expr(&p.value, &mut probe)
                                            .filter(|o| !o.built && o.object)
                                    }
                                    ObjectPropertyKind::SpreadProperty(_) => None,
                                }),
                            _ => None,
                        };
                        let direct = taints.get(index).cloned().flatten().filter(|o| {
                            !o.built
                                && o.object
                                && !matches!(
                                    arg.map(Expression::get_inner_expression),
                                    Some(Expression::ObjectExpression(_))
                                )
                        });
                        (index, from_fields.or(direct))
                    }
                    ArgRule::Built(index) => (
                        index,
                        taints.get(index).cloned().flatten().filter(|o| {
                            o.built && (o.sqlish || sink.class != VulnClass::SqlInjection)
                        }),
                    ),
                    ArgRule::UrlPrefix(index) => {
                        let is_object = arguments
                            .get(index)
                            .and_then(Argument::as_expression)
                            .is_some_and(|e| {
                                matches!(e.get_inner_expression(), Expression::ObjectExpression(_))
                            });
                        let direct = taints
                            .get(index)
                            .cloned()
                            .flatten()
                            .filter(|o| o.prefix && !is_object);
                        let from_options = arguments
                            .get(index)
                            .and_then(Argument::as_expression)
                            .and_then(|e| {
                                let keys: Vec<&str> =
                                    m().url_option_keys.iter().map(String::as_str).collect();
                                object_prop(e, &keys)
                            })
                            .and_then(|value| {
                                let mut probe = env.clone();
                                self.expr(value, &mut probe)
                            })
                            .filter(|o| o.prefix);
                        (index, direct.or(from_options))
                    }
                };
            let Some(origin) = origin else { continue };
            if has(&sink.ignore_kinds, origin.kind) || origin.escaped & class_bit(sink.class) != 0 {
                // Another rule of the group may still match an unescaped argument.
                continue;
            }
            // The CLI is the user's own machine: never above low.
            let severity = m().cap(origin.kind, severity);
            let Some(arg) = arguments.get(index) else {
                continue;
            };
            self.emit(
                RawFinding {
                    class: sink.class,
                    severity,
                    api: api.to_owned(),
                    arg: arg.span(),
                    call: span,
                    function: env.function.clone(),
                    origin,
                    ext: None,
                    auth: Auth::NoneDetected,
                },
                env,
            );
            return true;
        }
        false
    }
}

/// A callee, resolved as far as the file allows.
#[derive(Debug, Clone)]
enum Callee {
    /// A function of a known module family (`export` `None`/empty: the module itself).
    Module {
        family: &'static str,
        export: Option<String>,
    },
    /// A free identifier (or a known `Object.method` global).
    Global(String),
    /// A method on something else.
    Method {
        object: Option<String>,
        method: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{parse_options, source_type};
    use jss_core::{PackageType, SourceKind};
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;

    /// (class, sink api, source kind) for every finding in `src`.
    fn scan(src: &str) -> Vec<(VulnClass, Severity, String, &'static str)> {
        let allocator = Allocator::default();
        let ret = Parser::new(
            &allocator,
            src,
            source_type(SourceKind::Js, PackageType::CommonJs),
        )
        .with_options(parse_options())
        .parse();
        assert!(!ret.fatal_error, "{:?}", ret.diagnostics);
        scan_program(&ret.program, src)
            .findings
            .into_iter()
            .map(|f| (f.class, f.severity, f.api, f.origin.kind))
            .collect()
    }

    const HEAD: &str = "const { exec, spawn } = require('child_process');\n\
        const fs = require('fs');\nconst path = require('path');\n\
        const axios = require('axios');\n";

    fn one(body: &str) -> Vec<(VulnClass, Severity, String, &'static str)> {
        scan(&format!("{HEAD}{body}"))
    }

    #[test]
    fn command_injection_through_concatenation() {
        let found =
            one("app.get('/p', (req, res) => { const h = req.query.host; exec('ping ' + h); });");
        assert_eq!(
            found,
            vec![(
                VulnClass::CommandInjection,
                Severity::Critical,
                "child_process.exec".to_owned(),
                "http"
            )]
        );
    }

    #[test]
    fn literal_commands_and_numeric_conversions_are_not_findings() {
        assert!(one("app.get('/p', (req, res) => { exec('uptime'); const n = parseInt(req.query.n, 10); exec(`echo ${n}`); });").is_empty());
    }

    #[test]
    fn regex_exec_is_not_child_process_exec() {
        assert!(scan("app.get('/p', (req, res) => { /x/.exec(req.query.a); });").is_empty());
    }

    #[test]
    fn spawn_with_shell_true_is_critical() {
        let found = one(
            "app.post('/r', (req, res) => { spawn('sh', ['-c', req.body.c], { shell: true }); });",
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, Severity::Critical);
    }

    #[test]
    fn path_traversal_and_basename() {
        let tp = one(
            "router.post('/f', function (r, s) { const { name } = r.body; fs.readFile(path.join(__dirname, name), cb); });",
        );
        assert_eq!(tp.len(), 1);
        assert_eq!(tp[0].0, VulnClass::PathTraversal);
        let fp = one(
            "router.post('/f', function (r, s) { const { name } = r.body; fs.readFile(path.join(__dirname, path.basename(name)), cb); s.sendFile(name, { root: __dirname }); });",
        );
        assert!(fp.is_empty(), "{fp:?}");
    }

    #[test]
    fn sql_built_by_template_but_not_parameterized() {
        let tp = one(
            "app.get('/u', async (req, res) => { const id = req.params.id; await db.query(`SELECT * FROM t WHERE id = ${id}`); });",
        );
        assert_eq!(tp.len(), 1);
        assert_eq!(tp[0].0, VulnClass::SqlInjection);
        assert!(one("app.get('/u', async (req, res) => { await db.query('SELECT * FROM t WHERE id = ?', [req.params.id]); });").is_empty());
    }

    #[test]
    fn ssrf_needs_control_of_the_url_start() {
        let tp = one(
            "app.post('/x', async (req, res) => { const u = req.body.url; await axios.get(u); await fetch(`${u}/x`); });",
        );
        assert_eq!(tp.len(), 2, "{tp:?}");
        assert!(one("app.post('/x', async (req, res) => { await axios.get('https://api.example.com/' + req.body.id); });").is_empty());
    }

    #[test]
    fn eval_socket_and_web_request_sources() {
        assert_eq!(
            one("app.post('/e', (req, res) => { eval(req.body.code); });")[0].0,
            VulnClass::CodeInjection
        );
        assert_eq!(one("io.on('connection', (socket) => { socket.on('run', (data, cb) => exec(data.cmd)); });")[0].3, "socket");
        let next = scan(
            "import { exec } from 'node:child_process';\nexport async function POST(request) { const b = await request.json(); exec(b.cmd); }",
        );
        assert_eq!(next.len(), 1, "{next:?}");
    }

    #[test]
    fn untainted_reassignment_clears_but_branches_only_add() {
        assert!(
            one("app.get('/p', (req, res) => { let h = req.query.h; h = 'x'; exec(h); });")
                .is_empty()
        );
        assert_eq!(one("app.get('/p', (req, res) => { let h = 'x'; if (a) { h = req.query.h; } exec(h); });").len(), 1);
    }

    #[test]
    fn runtime_code_shaped_like_handlers_without_requests_is_quiet() {
        // `(a, b)` callbacks that are not route registrations carry no request.
        assert!(one("list.forEach((item, i) => exec(item.cmd));").is_empty());
        assert!(one("function helper(cmd) { exec(cmd); }").is_empty());
    }

    #[test]
    fn options_objects_count_only_through_their_url_fields() {
        assert!(scan("const http = require('http');\napp.get('/p', (req, res) => { http.request({ host: 'w', path: '/', headers: { ...req.headers } }); });").is_empty());
        assert_eq!(scan("const http = require('http');\napp.get('/p', (req, res) => { http.request({ host: req.query.h }); });").len(), 1);
    }

    #[test]
    fn multer_storage_fields_are_not_client_data() {
        assert!(
            one("app.post('/u', up.single('f'), (req, res) => { fs.unlinkSync(req.file.path); });")
                .is_empty()
        );
        assert_eq!(one("app.post('/u', up.single('f'), (req, res) => { fs.unlinkSync(req.file.originalname); });").len(), 1);
    }

    #[test]
    fn sql_needs_sql_looking_text() {
        assert_eq!(one("app.get('/u', (req, res) => { db.exec('SELECT * FROM t WHERE id = ' + req.query.id); });").len(), 1);
        assert!(
            one("app.get('/u', (req, res) => { cache.get('user:' + req.query.id); });").is_empty()
        );
    }

    #[test]
    fn meteor_methods_and_hono_context_are_sources() {
        let meteor = one("Meteor.methods({ run(cmd) { exec('ls ' + cmd); } });");
        assert_eq!(meteor.len(), 1);
        assert_eq!(meteor[0].3, "meteor");
        assert_eq!(
            one("app.get('/x', async (c) => { const q = c.req.query('d'); exec(`ls ${q}`); });")
                .len(),
            1
        );
    }

    #[test]
    fn same_file_helpers_are_followed_two_levels() {
        let src = "function run(cmd) { exec('sh -c ' + cmd); }\n\
                   const wrap = (x) => run(x);\n\
                   app.post('/r', (req, res) => { wrap(req.body.c); });";
        let found = one(src);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].3, "http");
        // A helper alone is not a finding, and a literal argument is not tainted.
        assert!(
            one("function run(cmd) { exec(cmd); }\napp.post('/r', (req, res) => { run('ls'); });")
                .is_empty()
        );
    }

    #[test]
    fn client_side_sources_reach_html_and_open_external() {
        let pm = scan(
            "window.addEventListener('message', (e) => { el.innerHTML = '<b>' + e.data.name + '</b>'; });",
        );
        assert_eq!(pm.len(), 1, "{pm:?}");
        assert_eq!(pm[0].0, VulnClass::Xss);
        let ext = scan(
            "chrome.runtime.onMessage.addListener((msg, sender, reply) => { $('#x').html(`<i>${msg.t}</i>`); });",
        );
        assert_eq!(ext.len(), 1, "{ext:?}");
        let ipc = scan("ipcMain.handle('open', (event, url) => { shell.openExternal(url); });");
        assert_eq!(ipc.len(), 1, "{ipc:?}");
        assert_eq!(ipc[0].3, "ipc");
        // The IPC event object is not client data; a jQuery node append is not HTML.
        assert!(
            scan("ipcMain.on('x', (event) => { shell.openExternal(event.senderFrame.url); });")
                .is_empty()
        );
        assert!(
            scan("window.addEventListener('message', (e) => { $('#x').append(e.data); });")
                .is_empty()
        );
    }

    #[test]
    fn nest_decorators_connection_sockets_and_prototype_pollution() {
        let src = "import { exec } from 'child_process';\nclass C { @Get() find(@Query('p') p) { exec('ls ' + p); } }";
        let allocator = Allocator::default();
        let ret = Parser::new(
            &allocator,
            src,
            source_type(SourceKind::Ts, PackageType::CommonJs),
        )
        .with_options(parse_options())
        .parse();
        assert_eq!(scan_program(&ret.program, src).findings.len(), 1);
        assert_eq!(
            one("io.on('connection', (s) => { s.on('cmd', (d) => exec(d)); });").len(),
            1
        );
        let pp =
            one("app.post('/s', (req, res) => { const { a, b, v } = req.body; cfg[a][b] = v; });");
        assert_eq!(pp.len(), 1, "{pp:?}");
        assert_eq!(pp[0].0, VulnClass::PrototypePollution);
        assert!(one("app.post('/s', (req, res) => { cfg['x'][req.body.k] = 1; });").is_empty());
    }

    #[test]
    fn helper_sinks_recheck_the_callers_value() {
        let fixed = "async function get(url) { return fetch(url); }\n\
                     app.get('/i/:c', async (req, res) => { await get(`https://x.org/${req.params.c}.png`); });";
        assert!(one(fixed).is_empty());
        let open = "async function get(url) { return fetch(url); }\n\
                    app.get('/i', async (req, res) => { await get(req.query.u); });";
        assert_eq!(one(open).len(), 1);
    }

    #[test]
    fn archive_entry_names_are_sources() {
        let yauzl = one(
            "zip.on('entry', (entry) => { fs.createWriteStream(path.join(dest, entry.fileName)); });",
        );
        assert_eq!(yauzl.len(), 1, "{yauzl:?}");
        assert_eq!(yauzl[0].3, "archive");
        let adm = one(
            "for (const e of zip.getEntries()) { fs.writeFileSync(path.join(out, e.entryName), e.getData()); }",
        );
        assert_eq!(adm.len(), 1, "{adm:?}");
        assert!(one("for (const e of zip.getEntries()) { fs.writeFileSync(path.join(out, path.basename(e.entryName)), x); }").is_empty());
    }

    #[test]
    fn next_const_handlers_and_hono_context_values() {
        assert_eq!(one("export const POST = async (request) => { const b = await request.json(); exec(b.cmd); };").len(), 1);
        assert!(
            one("app.get('/x', async (c) => { exec('ls ' + c.get('session').id); });").is_empty()
        );
    }

    #[test]
    fn handlers_passed_by_reference_get_client_data() {
        let src = "function onRun(data, cb) { exec('ls ' + data.dir); }\n\
                   io.on('connection', (socket) => { socket.on('run', onRun); });";
        assert_eq!(one(src).len(), 1);
        let ipc = "function openIt(event, url) { exec(url); }\nipcMain.handle('open', openIt);";
        assert_eq!(one(ipc).len(), 1);
    }

    #[test]
    fn nosql_operator_injection_needs_an_object_capable_value() {
        let tp = one(
            "app.post('/login', async (req, res) => { await User.findOne({ email: req.body.email, password: req.body.password }); });",
        );
        assert_eq!(tp.len(), 1, "{tp:?}");
        assert_eq!(tp[0].0, VulnClass::NosqlInjection);
        assert!(one("app.post('/l', async (req, res) => { await User.findOne({ email: String(req.body.email) + '' }); });").is_empty());
        // Route params are always strings.
        assert!(
            one("app.get('/u/:id', async (req, res) => { await User.findById(req.params.id); });")
                .is_empty()
        );
    }

    #[test]
    fn raw_http_servers_and_fastify_route_objects_are_routes() {
        let raw = scan(
            "const http = require('http');\nconst { exec } = require('child_process');\nhttp.createServer((req, res) => { exec('ls ' + req.url); });",
        );
        assert_eq!(raw.len(), 1, "{raw:?}");
        let fastify = one(
            "fastify.route({ method: 'GET', url: '/x', handler: async (request, reply) => { exec('ls ' + request.query.d); } });",
        );
        assert_eq!(fastify.len(), 1, "{fastify:?}");
    }

    #[test]
    fn graphql_trpc_queues_and_socket_on_any() {
        let gql = one(
            "const resolvers = { Query: { file(parent, args) { return fs.readFileSync(args.path); } } };",
        );
        assert_eq!(gql.len(), 1, "{gql:?}");
        assert_eq!(gql[0].3, "graphql");
        let trpc = one(
            "const r = t.procedure.input(z.string()).mutation(({ input, ctx }) => exec('ls ' + input));",
        );
        assert_eq!(trpc.len(), 1, "{trpc:?}");
        let trpc_opts = one("const r = t.procedure.query((opts) => exec('ls ' + opts.input.dir));");
        assert_eq!(trpc_opts.len(), 1, "{trpc_opts:?}");
        let queue =
            one("queue.process('convert', async (job) => { exec('convert ' + job.data.file); });");
        assert_eq!(queue.len(), 1, "{queue:?}");
        let any =
            one("io.on('connection', (socket) => { socket.onAny((event, data) => exec(data)); });");
        assert_eq!(any.len(), 1, "{any:?}");
    }

    #[test]
    fn guards_from_real_false_positives_clean_the_value() {
        // uptime-kuma: regex allowlist before path.join
        assert!(one("io.on('connection', (socket) => { socket.on('ex', async (language, cb) => { if (!/^[a-z-]+$/.test(language)) { throw new Error('bad'); } fs.readdir(path.join('./x', language), cb); }); });").is_empty());
        // Haven: hex id regex, then a temp path
        assert!(one("app.post('/i', (req, res) => { const { importId } = req.body; if (!/^[a-f0-9]{32}$/.test(importId)) { return res.status(400).end(); } fs.readFile(path.join(tmp, importId), cb); });").is_empty());
        // mirotalksfu / OpenWhispr: resolved path must stay under the base
        assert!(one("app.post('/r', (req, res) => { const p = path.resolve(base, req.query.f); if (!p.startsWith(base)) { return res.status(400).end(); } fs.createWriteStream(p); });").is_empty());
        // positive form: use inside the validated block only
        assert!(one("app.get('/a', (req, res) => { const n = req.query.n; if (ALLOWED.includes(n)) { exec('run ' + n); } });").is_empty());
        assert_eq!(one("app.get('/a', (req, res) => { const n = req.query.n; if (ALLOWED.includes(n)) { log(n); } exec('run ' + n); });").len(), 1);
        // a guard that does not exit cleans nothing after it
        assert_eq!(one("app.get('/a', (req, res) => { const n = req.query.n; if (!/^\\w+$/.test(n)) { log('bad'); } exec('run ' + n); });").len(), 1);
        // a guard on a request field
        assert!(one("app.get('/a', (req, res) => { if (!isValidId(req.query.id)) return res.end(); exec('run ' + req.query.id); });").is_empty());
        // comparison with a constant
        assert!(one("app.get('/a', (req, res) => { const m = req.query.m; if (m !== 'fast' && m !== 'slow') return; exec('run ' + m); });").is_empty());
    }

    #[test]
    fn type_assertions_rule_out_nosql_objects_only() {
        assert!(one("Meteor.methods({ load(boardId) { check(boardId, String); return Boards.find({ _id: boardId }); } });").is_empty());
        assert!(one("app.post('/l', async (req, res) => { const e = req.body.email; if (typeof e !== 'string') return; await User.findOne({ email: e }); });").is_empty());
        // a string check does not make SQL text safe
        assert_eq!(one("app.post('/l', async (req, res) => { const e = req.body.email; if (typeof e !== 'string') return; await db.query('SELECT * FROM u WHERE e = ' + e); });").len(), 1);
    }

    #[test]
    fn object_fields_and_destructured_parameters_are_tracked_one_by_one() {
        // yuvomi: constant table name, tainted ids in another field
        let helper = "function replaceLinks(db, { table, ids }) { db.prepare(`DELETE FROM ${table} WHERE x = 1`).run(); }\n";
        assert!(one(&format!("{helper}app.post('/i', (req, res) => {{ replaceLinks(db, {{ table: 'docs', ids: req.body.ids }}); }});")).is_empty());
        assert_eq!(one(&format!("{helper}app.post('/i', (req, res) => {{ replaceLinks(db, {{ table: req.body.t, ids: 1 }}); }});")).len(), 1);
        // a variable holding an object literal
        assert!(one("app.get('/x', (req, res) => { const meta = { name: req.query.name, dir: '/srv' }; fs.readFileSync(path.join(meta.dir, 'a')); });").is_empty());
        assert_eq!(one("app.get('/x', (req, res) => { const meta = { name: req.query.name, dir: '/srv' }; fs.readFileSync(path.join(meta.dir, meta.name)); });").len(), 1);
        // a field written later
        assert_eq!(one("app.get('/x', (req, res) => { const o = { dir: '/srv' }; o.dir = req.query.d; fs.readFileSync(o.dir); });").len(), 1);
    }

    fn auth_of(src: &str) -> Vec<(Auth, Severity)> {
        let src = format!("{HEAD}{src}");
        let allocator = Allocator::default();
        let ret = Parser::new(
            &allocator,
            &src,
            source_type(SourceKind::Js, PackageType::CommonJs),
        )
        .with_options(parse_options())
        .parse();
        scan_program(&ret.program, &src)
            .findings
            .into_iter()
            .map(|f| (f.auth, f.severity))
            .collect()
    }

    #[test]
    fn authentication_is_recognized_and_admin_only_lowers_severity() {
        assert_eq!(
            auth_of("app.get('/p', (req, res) => { exec('ping ' + req.query.h); });"),
            vec![(Auth::NoneDetected, Severity::Critical)]
        );
        assert_eq!(
            auth_of("app.get('/p', requireLogin, (req, res) => { exec('ping ' + req.query.h); });"),
            vec![(Auth::User, Severity::Critical)]
        );
        assert_eq!(
            auth_of(
                "router.use(passport.authenticate('jwt'));\nrouter.get('/p', (req, res) => { exec('ping ' + req.query.h); });"
            ),
            vec![(Auth::User, Severity::Critical)]
        );
        assert_eq!(
            auth_of("app.post('/p', isAdmin, (req, res) => { exec('ping ' + req.body.h); });"),
            vec![(Auth::Admin, Severity::High)]
        );
        assert_eq!(
            auth_of(
                "app.get('/p', (req, res) => { if (!req.user) { return res.sendStatus(401); } exec('ping ' + req.query.h); });"
            ),
            vec![(Auth::User, Severity::Critical)]
        );
    }

    fn scan_jsx(src: &str) -> Vec<(VulnClass, Severity, String, &'static str)> {
        let allocator = Allocator::default();
        let ret = Parser::new(
            &allocator,
            src,
            source_type(SourceKind::Jsx, PackageType::Module),
        )
        .with_options(parse_options())
        .parse();
        assert!(!ret.fatal_error, "{:?}", ret.diagnostics);
        scan_program(&ret.program, src)
            .findings
            .into_iter()
            .map(|f| (f.class, f.severity, f.api, f.origin.kind))
            .collect()
    }

    #[test]
    fn dangerously_set_inner_html_with_props_or_request_data() {
        let found = scan_jsx(
            "export function Label({ label }) { return <span dangerouslySetInnerHTML={{ __html: label }} />; }",
        );
        assert_eq!(
            found,
            vec![(
                VulnClass::Xss,
                Severity::Medium,
                "dangerouslySetInnerHTML".to_owned(),
                "props"
            )]
        );
        // array elements of tainted props, through a markdown renderer
        let mapped = scan_jsx(
            "function Chat({ messages }) { return <div>{messages.map((m) => <p dangerouslySetInnerHTML={{ __html: renderMarkdown(m.text) }} />)}</div>; }",
        );
        assert_eq!(mapped.len(), 1, "{mapped:?}");
        assert!(scan_jsx("function A({ x }) { return <p dangerouslySetInnerHTML={{ __html: '<b>static</b>' }} title={x} />; }").is_empty());
    }

    #[test]
    fn a_tainted_argument_list_is_argument_injection() {
        let found = one(
            "io.on('connection', (s) => { s.on('install', (url) => { spawn('git', ['clone', url, dir]); }); });",
        );
        assert_eq!(
            found,
            vec![(
                VulnClass::CommandInjection,
                Severity::Medium,
                "child_process.spawn".to_owned(),
                "socket"
            )]
        );
    }

    #[test]
    fn dom_xss_sources_and_sinks() {
        let found = scan(
            "const q = new URLSearchParams(location.search); el.innerHTML = '<b>' + location.hash.slice(1) + '</b>';",
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].3, "dom");
        assert_eq!(
            scan("document.write('<p>' + document.referrer + '</p>');").len(),
            1
        );
        assert_eq!(
            scan("window.location.href = location.hash.slice(1);").len(),
            1
        );
        // a fixed origin before the tainted part cannot become `javascript:`
        assert!(scan("location.href = '/search?q=' + location.hash.slice(1);").is_empty());
        assert_eq!(
            scan("setTimeout('render(' + location.hash + ')', 10);").len(),
            1
        );
        // `stream.write` is not `document.write`
        assert!(scan("stream.write(location.hash);").is_empty());
    }

    #[test]
    fn electron_sinks_and_bullmq_workers() {
        assert_eq!(scan("ipcMain.handle('run', (event, code) => { win.webContents.executeJavaScript(code); });")[0].1, Severity::Critical);
        assert_eq!(
            scan("ipcMain.on('open', (event, p) => shell.openPath(p));").len(),
            1
        );
        let worker = one(
            "const w = new Worker('convert', async (job) => { exec('convert ' + job.data.file); });",
        );
        assert_eq!(worker.len(), 1, "{worker:?}");
        assert_eq!(worker[0].3, "queue");
    }

    #[test]
    fn return_values_carry_parameter_taint() {
        let helper = "function clean(v) { return v.trim(); }\nfunction getDir(req) { return req.query.dir; }\n";
        assert_eq!(
            one(&format!(
                "{helper}app.get('/a', (req, res) => {{ exec('ls ' + clean(req.query.d)); }});"
            ))
            .len(),
            1
        );
        assert_eq!(
            one(&format!(
                "{helper}app.get('/a', (req, res) => {{ exec('ls ' + getDir(req)); }});"
            ))
            .len(),
            1
        );
        // a helper that returns a constant does not
        assert!(one("function fixed(v) { return 'x'; }\napp.get('/a', (req, res) => { exec('ls ' + fixed(req.query.d)); });").is_empty());
        // arrow helpers with expression bodies
        assert_eq!(one("const wrap = (v) => `\"${v}\"`;\napp.get('/a', (req, res) => { exec('ls ' + wrap(req.query.d)); });").len(), 1);
    }

    #[test]
    fn deep_set_helpers_with_tainted_paths() {
        let found = scan(
            "const _ = require('lodash');\napp.post('/s', (req, res) => { _.set(settings, req.body.path, req.body.value); });",
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, VulnClass::PrototypePollution);
        assert!(scan("const _ = require('lodash');\napp.post('/s', (req, res) => { _.set(settings, 'theme', req.body.value); });").is_empty());
        // Map.set is not a deep write
        assert!(scan("app.post('/s', (req, res) => { cache.set(req.body.k, 1); });").is_empty());
    }

    #[test]
    fn instance_fields_carry_taint_between_methods_and_through_constructors() {
        let class = "class Executor {\n  constructor(config) { this.url = config.url; }\n  execute() { return axios.get(this.url); }\n}\n";
        let found = one(&format!(
            "{class}app.post('/run', async (req, res) => {{ const e = new Executor(req.body); await e.execute(); }});"
        ));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, VulnClass::Ssrf);
        // a constant field stays clean
        assert!(one("class E { constructor() { this.url = 'https://api.example.com'; } run() { return axios.get(this.url); } }").is_empty());
    }

    #[test]
    fn rejecting_and_named_validators_clean_values() {
        // Flowise's fix: a predicate that is true for bad input, then an exit
        let fixed = "app.get('/f', (req, res) => { const id = req.query.id; if (isPathTraversal(id)) { throw new Error('bad'); } fs.createReadStream(path.join(base, id)); });";
        assert!(one(fixed).is_empty());
        let vulnerable = "app.get('/f', (req, res) => { const id = req.query.id; fs.createReadStream(path.join(base, id)); });";
        assert_eq!(one(vulnerable).len(), 1);
        assert!(one("app.get('/f', (req, res) => { const p = req.query.p; if (p.includes('..')) return res.end(); fs.readFileSync(p); });").is_empty());
        assert!(one("app.get('/f', (req, res) => { const u = req.query.u; if (!isValidUUID(u)) return; exec('x ' + u); });").is_empty());
        // `isInvalid` is a rejecter, not a validator
        assert_eq!(one("app.get('/f', (req, res) => { const u = req.query.u; if (!isInvalidName(u)) return; exec('x ' + u); });").len(), 1);
    }

    #[test]
    fn returned_objects_keep_their_fields_apart() {
        let helper = "function prepare(bin, args) { return { command: bin, args: args }; }\n";
        // The message goes into the argument list, not the program: argument injection at most.
        let found = one(&format!(
            "{helper}app.post('/a', (req, res) => {{ const launch = prepare('codex', ['exec', req.body.message]); spawn(launch.command, launch.args); }});"
        ));
        assert_eq!(
            found,
            vec![(
                VulnClass::CommandInjection,
                Severity::Medium,
                "child_process.spawn".to_owned(),
                "http"
            )]
        );
        // The program itself from the request is the real thing.
        let found = one(&format!(
            "{helper}app.post('/a', (req, res) => {{ const {{ command, args }} = prepare(req.body.bin, []); spawn(command, args); }});"
        ));
        assert_eq!(
            found,
            vec![(
                VulnClass::CommandInjection,
                Severity::High,
                "child_process.spawn".to_owned(),
                "http"
            )]
        );
    }

    #[test]
    fn allowlist_strips_clean_but_partial_replacements_do_not() {
        assert!(one("app.post('/s', (req, res) => { const id = String(req.body.id).replace(/[^a-z0-9_-]/gi, ''); fs.writeFileSync(path.join(dir, id + '.md'), x); });").is_empty());
        // removing `../` once is bypassable (`....//`): still a finding
        assert_eq!(one("app.post('/s', (req, res) => { const id = req.body.id.replace(/\\.\\.\\//g, ''); fs.writeFileSync(path.join(dir, id), x); });").len(), 1);
        // not global: only the first bad character goes
        assert_eq!(one("app.post('/s', (req, res) => { const id = req.body.id.replace(/[^a-z]/, ''); fs.writeFileSync(path.join(dir, id), x); });").len(), 1);
    }

    #[test]
    fn library_deep_sets_are_medium() {
        let found = scan(
            "const _ = require('lodash');\napp.post('/s', (req, res) => { _.set(settings, req.body.path, 1); });",
        );
        assert_eq!(found[0].1, Severity::Medium);
    }

    #[test]
    fn dev_server_middleware_is_capped_and_mcp_tool_arguments_are_sources() {
        let dev = one(
            "export default { plugins: [{ configureServer(server) { server.middlewares.use((req, res, next) => { res.end(fs.readFileSync(path.join(root, req.url))); }); } }] };",
        );
        assert_eq!(
            dev,
            vec![(
                VulnClass::PathTraversal,
                Severity::Medium,
                "fs.readFileSync".to_owned(),
                "dev-server"
            )]
        );
        let mcp = one(
            "server.tool('run', 'Run a command', { cmd: z.string() }, async ({ cmd }) => { exec(cmd); });",
        );
        assert_eq!(
            mcp,
            vec![(
                VulnClass::CommandInjection,
                Severity::Critical,
                "child_process.exec".to_owned(),
                "mcp"
            )]
        );
        let low_level = one(
            "server.setRequestHandler(CallToolRequestSchema, async (request) => { const { path } = request.params.arguments; return fs.readFileSync(path); });",
        );
        assert_eq!(low_level.len(), 1, "{low_level:?}");
        let fastmcp = one(
            "server.addTool({ name: 'read', execute: async (args) => fs.readFileSync(args.file) });",
        );
        assert_eq!(fastmcp.len(), 1, "{fastmcp:?}");
    }

    #[test]
    fn a_local_escaper_makes_values_safe_for_its_class_only() {
        let classes =
            |body: &str| -> Vec<VulnClass> { one(body).into_iter().map(|f| f.0).collect() };
        let helper = "function escapeHtml(s) { return String(s).replace(/</g, '&lt;'); }\n";
        assert!(
            classes(&format!(
                "{helper}app.get('/p', (req, res) => {{ document.body.innerHTML = '<b>' + escapeHtml(req.query.n); }});"
            ))
            .is_empty()
        );
        // Escaped for HTML is not escaped for a shell.
        assert_eq!(
            classes(&format!(
                "{helper}app.get('/p', (req, res) => {{ exec('echo ' + escapeHtml(req.query.n)); }});"
            )),
            vec![VulnClass::CommandInjection]
        );
        // A helper that is no escaper still passes the value on.
        assert_eq!(
            classes(
                "function bold(s) { return '<b>' + s; }\n\
                 app.get('/p', (req, res) => { document.body.innerHTML = bold(req.query.n); });"
            ),
            vec![VulnClass::Xss]
        );
    }

    #[test]
    fn mcp_stdio_transports_run_programs() {
        let found = scan(
            "import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';\n\
             app.post('/servers', (req, res) => {\n\
               const { command, args } = req.body;\n\
               const transport = new StdioClientTransport({ command, args });\n\
             });",
        );
        assert_eq!(
            found.iter().map(|f| (f.0, f.1)).collect::<Vec<_>>(),
            vec![(VulnClass::CommandInjection, Severity::Critical)],
            "{found:?}"
        );
        assert!(
            scan(
                "import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';\n\
                 const transport = new StdioClientTransport({ command: 'node', args: ['server.js'] });"
            )
            .is_empty()
        );
    }

    #[test]
    fn json_stringify_passes_strings_on_and_strings_are_no_operator_objects() {
        assert_eq!(
            one(
                "app.get('/p', (req, res) => { exec('notify ' + JSON.stringify(req.query.msg)); });"
            )
            .len(),
            1
        );
        // A string cannot carry `{ \"$ne\": null }`.
        assert!(
            one("app.post('/l', async (req, res) => { await User.findOne({ email: String(req.body.email) }); });")
                .is_empty()
        );
        // JSON.parse can.
        assert_eq!(
            one("app.post('/l', async (req, res) => { await User.findOne({ email: JSON.parse(req.body.q) }); });")
                .iter()
                .map(|f| f.0)
                .collect::<Vec<_>>(),
            vec![VulnClass::NosqlInjection]
        );
    }

    #[test]
    fn multipart_parser_events_carry_request_data() {
        let found = one("app.post('/up', (req, res) => {\n\
               const bb = busboy({ headers: req.headers });\n\
               bb.on('file', (name, stream, info) => {\n\
                 stream.pipe(fs.createWriteStream(path.join(dir, info.filename)));\n\
               });\n\
               req.pipe(bb);\n\
             });");
        assert_eq!(
            found.iter().map(|f| f.0).collect::<Vec<_>>(),
            vec![VulnClass::PathTraversal],
            "{found:?}"
        );
        // The temporary path is the parser's.
        assert!(
            one("app.post('/up', (req, res) => {\n\
                   const form = new multiparty.Form();\n\
                   form.on('file', (name, file) => { fs.remove(file.path); });\n\
                 });")
            .is_empty()
        );
    }

    #[test]
    fn parameter_summaries_follow_the_field_that_reaches_the_sink() {
        let helper = "function run(opts) { exec('cmd ' + opts.cmd); }\n";
        assert!(
            one(&format!(
                "{helper}app.get('/p', (req, res) => {{ run({{ cmd: 'ls', user: req.query.u }}); }});"
            ))
            .is_empty()
        );
        assert_eq!(
            one(&format!(
                "{helper}app.get('/p', (req, res) => {{ run({{ cmd: req.query.c, user: 'x' }}); }});"
            ))
            .len(),
            1
        );
        // An upload's temporary path is the server's; its original name is the client's.
        let helpers = "function discard(file) { fs.unlink(file.path, () => {}); }\n\
                       function keep(file) { fs.writeFileSync(path.join(dir, file.originalname), x); }\n";
        assert!(
            one(&format!(
                "{helpers}app.post('/u', upload.single('f'), (req, res) => {{ discard(req.file); }});"
            ))
            .is_empty()
        );
        assert_eq!(
            one(&format!(
                "{helpers}app.post('/u', upload.single('f'), (req, res) => {{ keep(req.file); }});"
            ))
            .iter()
            .map(|f| f.0)
            .collect::<Vec<_>>(),
            vec![VulnClass::PathTraversal]
        );
    }

    #[test]
    fn auth_checks_on_what_an_auth_call_returned() {
        assert_eq!(
            auth_of(
                "app.post('/p', (req, res) => { const token = req.headers.authorization;\n\
                 const user = token ? verifyToken(token) : null;\n\
                 if (!user) return res.status(401).end();\n\
                 exec('ping ' + req.body.h); });"
            ),
            vec![(Auth::User, Severity::Critical)]
        );
        assert_eq!(
            auth_of(
                "app.post('/p', async (req, res) => { const session = await getServerSession(opts);\n\
                 if (!session) { return res.status(401).end(); }\n\
                 exec('ping ' + req.body.h); });"
            ),
            vec![(Auth::User, Severity::Critical)]
        );
        assert_eq!(
            auth_of(
                "app.post('/p', (req, res) => { if (!isAdmin(req)) return res.sendStatus(403);\n\
                 exec('ping ' + req.body.h); });"
            ),
            vec![(Auth::Admin, Severity::High)]
        );
        // A value from any other call proves nothing.
        assert_eq!(
            auth_of(
                "app.post('/p', (req, res) => { const item = lookup(req.body.id);\n\
                 if (!item) return res.status(404).end();\n\
                 exec('ping ' + req.body.h); });"
            ),
            vec![(Auth::NoneDetected, Severity::Critical)]
        );
    }

    #[test]
    fn void_helpers_that_throw_validate_their_arguments() {
        let helper = "function assertSafeName(name) {\n\
                        if (!/^[\\w.-]+$/.test(name)) { throw new Error('bad name'); }\n\
                      }\n";
        assert!(
            one(&format!(
                "{helper}app.get('/f', (req, res) => {{ const name = req.query.name;\n\
                 assertSafeName(name);\n\
                 fs.readFile(path.join(dir, name), () => {{}}); }});"
            ))
            .is_empty()
        );
        // A predicate that returns its verdict validates nothing when the result is ignored.
        let predicate = "function looksFine(name) {\n\
                           if (!/^[\\w.-]+$/.test(name)) { return false; }\n\
                           return true;\n\
                         }\n";
        assert_eq!(
            one(&format!(
                "{predicate}app.get('/f', (req, res) => {{ const name = req.query.name;\n\
                 looksFine(name);\n\
                 fs.readFile(path.join(dir, name), () => {{}}); }});"
            ))
            .len(),
            1
        );
    }

    #[test]
    fn method_sinks_skip_objects_that_hold_no_html() {
        assert!(
            one(
                "app.get('/p', (req, res) => { const out = new URLSearchParams(); \
                 out.append('q', '<b>' + req.query.n); res.json(out.toString()); });"
            )
            .is_empty()
        );
        assert_eq!(
            one("app.get('/p', (req, res) => { const out = $('#list'); \
                 out.append('<b>' + req.query.n); });")
            .len(),
            1
        );
    }

    #[test]
    fn return_summaries_keep_what_the_helper_did() {
        // The helper puts a fixed base before the value: no attacker-chosen host.
        assert!(
            one(
                "function apiUrl(p) { return 'https://api.example.com/items/' + p; }\n\
                 app.get('/p', async (req, res) => { await axios.get(apiUrl(req.query.id)); });"
            )
            .is_empty()
        );
        // The helper builds SQL text around the value.
        let sql = one("function byTable(t) { return 'SELECT * FROM ' + t; }\n\
             app.get('/p', (req, res) => { db.query(byTable(req.query.t)); });");
        assert_eq!(
            sql.iter().map(|f| f.0).collect::<Vec<_>>(),
            vec![VulnClass::SqlInjection],
            "{sql:?}"
        );
        // A plain pass-through helper changes nothing.
        assert_eq!(
            one("function id(u) { return u; }\n\
                 app.get('/p', async (req, res) => { await axios.get(id(req.query.u)); });")
            .len(),
            1
        );
    }

    #[test]
    fn deep_nesting_is_capped_not_overflowed() {
        let deep = format!("x = {}1{};", "f(".repeat(2000), ")".repeat(2000));
        let deep_arr = format!("x = {}1{};", "[".repeat(2000), "]".repeat(2000));
        for src in [deep, deep_arr] {
            // The parser needs its bounded stack (never a default thread); the walker's own
            // recursion is capped.
            let stack = crate::process::parser_stack_bound(src.as_bytes());
            let truncated = std::thread::Builder::new()
                .stack_size(stack)
                .spawn(move || {
                    let allocator = Allocator::default();
                    let ret = Parser::new(
                        &allocator,
                        &src,
                        source_type(SourceKind::Js, PackageType::CommonJs),
                    )
                    .with_options(parse_options())
                    .parse();
                    let result = scan_program(&ret.program, &src);
                    assert!(result.findings.is_empty());
                    result.truncated
                })
                .unwrap()
                .join()
                .unwrap();
            assert!(truncated);
        }
    }
}
