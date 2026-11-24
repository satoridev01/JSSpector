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
mod walker_calls;
mod walker_expressions;
mod walker_functions;
mod walker_routes;
mod walker_statements;

use std::collections::{BTreeMap, BTreeSet};

use jss_core::{Auth, Severity, VulnClass};
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, ArrowFunctionBody, AssignmentTarget, BindingPattern,
    CallExpression, Class, ClassElement, Declaration, ExportDefaultDeclarationKind, Expression,
    ForStatementInit, ForStatementLeft, FormalParameters, Function, ModuleDeclaration,
    ObjectPropertyKind, Program, PropertyKey, Statement, UnaryOperator, VariableDeclaration,
    VariableDeclarationKind,
};
use oxc_ast::ast::{
    AssignmentOperator, BinaryOperator, LogicalOperator, ObjectExpression, SimpleAssignmentTarget,
};
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
    /// Concatenated with literal text that holds HTML markup (`<h1>`, `</p>`).
    pub htmlish: bool,
    /// Summary pass only: this is the value of the enclosing function's parameter `n`.
    pub param: Option<usize>,
    /// Can be an object (JSON body, qs query, socket payload), not only a string.
    pub object: bool,
    /// Escaped for these classes (bit [`class_bit`]) by an escaper from the packs: an HTML
    /// escaper makes a value safe in HTML, not in a shell command.
    pub escaped: u8,
    /// Summary pass only: other parameters the value also carries, as (index, span start of
    /// their origin, for its field, whether that parameter's data can be at the start of the
    /// value), at most [`MAX_ALSO`]: `exec(b + a)` carries both, `a` after `b`.
    pub also: Vec<(usize, u32, bool, u8)>,
    /// Upload objects (`req.files`, wherever they went): the fields the server chose (`path`,
    /// `filename`, `destination`) are not the attacker's.
    pub upload: bool,
    /// Checked not to start with `-` (`if (p.startsWith('-')) throw`): no argument injection.
    pub dash_free: bool,
    /// The response of a request to this value's URL (`await fetch(url)`): the attacker's only
    /// where they chose the URL's start.
    pub response: bool,
    /// Classes the primary parameter was escaped for on its own path before this value was
    /// merged with others (on top of `escaped`, which holds for the whole value). Each entry of
    /// `also` keeps its own the same way.
    pub primary_escaped: u8,
}

/// The source kind of a value a request stored and a later request reads back.
const STORED: &str = "stored";

/// The key under which a tracked object keeps what its fields of unknown name may hold
/// (spreads of unknown shape, computed keys).
const REST_FIELD: &str = "<rest>";

/// A tracked object's values written under computed keys the attacker does not choose
/// (`fields[key] = value` with `key` from a fixed list): read like [`REST_FIELD`], keys clean.
const VALUES_FIELD: &str = "<values>";

/// A tracked object's keys written by an attacker-chosen computed key (`o[req.query.k] = 1`).
const KEYED_FIELD: &str = "<keyed>";

/// The pseudo-field of a summary that names the keys of a parameter (`Object.keys(fields)`):
/// a call site takes the keys of its argument, not its values.
const KEYS_FIELD: &str = "<keys>";

/// What the fields a tracked object does not name may hold: its unknown spreads' values and the
/// values written under computed keys.
fn unnamed_fields(fields: &BTreeMap<String, Origin>) -> Option<Origin> {
    union(
        fields.get(REST_FIELD).cloned(),
        fields.get(VALUES_FIELD).cloned(),
    )
}

/// How an export table names a namespace export: `users` -> `<namespace>:src/api/users.js`
/// (`exports.users = require('./users')`, `export * as users from './users'`).
pub const NAMESPACE: &str = jss_core::ir::NAMESPACE;

/// The classes percent-encoded text is safe for: no markup, quote, separator or shell character
/// survives encoding.
const ENCODED: u8 = class_bit(VulnClass::Xss)
    | class_bit(VulnClass::SqlInjection)
    | class_bit(VulnClass::CommandInjection)
    | class_bit(VulnClass::CodeInjection)
    | class_bit(VulnClass::PathTraversal);

/// Most extra parameters an [`Origin`] remembers.
const MAX_ALSO: usize = 4;

impl Origin {
    /// Every parameter this value carries, with the span start that names its field and
    /// whether its data can be at the start of the value: its own, then the others it was
    /// merged with (never at the start once the whole value is not).
    /// ... and the classes each one was escaped for on its way in (`cwd = sanitized(url)`
    /// merged with an unchecked `cwd` parameter: the first is safe, the second is not).
    fn contributors(&self) -> Vec<(usize, u32, bool, u8)> {
        let mut all: Vec<(usize, u32, bool, u8)> = self
            .param
            .map(|p| {
                (
                    p,
                    self.span.start,
                    self.prefix,
                    self.primary_escaped | self.escaped,
                )
            })
            .into_iter()
            .collect();
        for &(param, at, prefix, escaped) in &self.also {
            if !all.iter().any(|&(p, a, _, _)| (p, a) == (param, at)) {
                all.push((param, at, prefix && self.prefix, escaped | self.escaped));
            }
        }
        all
    }

    /// Remembers `other`'s parameters as carried by this value too.
    fn absorb(&mut self, other: &Origin) {
        let own = self.param.map(|p| (p, self.span.start));
        // What the own parameter was escaped for so far, before the merge's value-level `and`.
        self.primary_escaped |= self.escaped;
        for (param, at, prefix, escaped) in other.contributors() {
            if own == Some((param, at)) {
                // The same parameter on two paths: escaped only where both escaped it.
                self.primary_escaped &= escaped;
                continue;
            }
            if let Some(entry) = self
                .also
                .iter_mut()
                .find(|(p, a, _, _)| (*p, *a) == (param, at))
            {
                // Seen on two paths: at the start if either put it there, escaped only if both
                // escaped it.
                entry.2 |= prefix;
                entry.3 &= escaped;
            } else if self.also.len() < MAX_ALSO {
                self.also.push((param, at, prefix, escaped));
            }
        }
    }
}

/// Whether a sink of `class` reached through `api` takes a URL whose start matters: SSRF, or
/// a sink with a `url:N` argument rule (`location.href =`, `window.open`).
fn url_rule(class: VulnClass, api: &str) -> bool {
    class == VulnClass::Ssrf || {
        let last = api.trim_end_matches(" =").rsplit('.').next().unwrap_or("");
        m().method_sink(last)
            .or_else(|| m().global_sink(last))
            .or_else(|| m().assign_sink(api.trim_end_matches(" =")))
            .is_some_and(|s| s.args.iter().any(|r| matches!(r, ArgRule::UrlPrefix(_))))
    }
}

/// The bit of `class` in [`Origin::escaped`].
const fn class_bit(class: VulnClass) -> u8 {
    1 << (class as u8)
}

/// Prefix of the constants that hold a regular expression's capture mask (see
/// [`Walker::regex_mask`]): no path or name lookup ever builds such a key.
const REGEX_CONSTANT: &str = "\u{1}regex:";

/// The `param` of a return summary whose value is client data, whatever the arguments.
const RETURNS_SOURCE: usize = usize::MAX;

/// Most route templates kept per function, and most parts in a template's path: a route helper
/// has a handful and a module handed the router (NodeBB's admin routes) a few hundred; more is a
/// generator, or recursion.
const MAX_TEMPLATES: usize = 1024;
const MAX_TEMPLATE_PARTS: usize = 32;

/// The `api` of a summary that says "the function returns this parameter" (not a sink).
pub const RETURNS: &str = "<return>";

/// The `api` of a summary that says "the function throws unless this parameter is valid": a
/// void helper whose exit-on-failure guards clean it (`function assertSafe(p) { if (!ok(p))
/// throw ... }`). After a call returns, the argument is clean.
pub const VALIDATES: &str = "<validates>";

/// The `api` of a summary that says "the function throws unless this parameter is a string,
/// number or boolean" (`if (channel && typeof channel !== 'string') throw ...`): after a call
/// returns, the argument is never an object (no query operators).
pub const SCALARS: &str = "<scalar>";

/// The `api` of a summary that says "the function returns true only when this parameter is
/// safe for the classes in `at_sink.escaped`": a predicate by what it does
/// (`const identity = (v) => typeof v === 'string' && /^[\w.-]+$/.test(v)`), used as a guard
/// by its callers (`if (!identity(id)) throw`).
pub const PREDICATE: &str = "<predicate>";

/// The `api` of a summary that says "the function returns an instance of this class"
/// ([`Summary::instance_of`]), whole or as one field of a returned object (`out_field`):
/// factories (`return new PgClient(cfg)`), singleton accessors (`return Registry.instance`) and
/// functions annotated to return a class. Callers type the receiver of what it returns.
pub const INSTANCE: &str = "<instance>";

/// Most classes an instance-returning function is known to return (a factory's `switch`).
const MAX_RETURNED_CLASSES: usize = 4;

/// A class (or interface) where it is declared: (file, name in that file).
pub type ClassRef = (String, String);

/// An export that is a member of a class declared in another file (`module.exports = {
/// getRegistry: Registry.getInstance }` with `Registry` imported): `<at>:file#Registry.getInstance`.
pub const ELSEWHERE: &str = jss_core::ir::ELSEWHERE;

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
            htmlish: false,
            escaped: 0,
            param: None,
            object: true,
            also: Vec::new(),
            upload: false,
            dash_free: false,
            response: false,
            primary_escaped: 0,
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
    /// Found by a rule that needs the attacker to choose the start of the value (`url:N`,
    /// `start:N`): a summary of it applies only to values that are at the start.
    pub start: bool,
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

/// A field a request stores from its own data (`user.update({ name: req.body.name })`), where, and
/// the request expression it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredWrite {
    pub file: String,
    pub line: u32,
    pub expr: String,
    /// Whether the written value could be an object (`origin.object`) rather than a proven scalar
    /// (`check(x, String)`, a validator) at the write site. A read-back of a field proven scalar
    /// there is marked the same way: an operator-shaped sink argument (`{ $ne: null }`) needs an
    /// object, so a value already proven a string there can never carry one.
    pub object: bool,
}

/// Every stored field of the project by name (see [`StoredWrite`]).
pub type StoredFields = BTreeMap<String, StoredWrite>;

/// Result of scanning one program.
#[derive(Debug, Default)]
pub struct ScanResult {
    /// The fields this file stores from request data.
    pub stored: StoredFields,
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
    let subclasses = BTreeMap::new();
    let names = BTreeMap::new();
    let properties = BTreeMap::new();
    let stored = StoredFields::new();
    let linking = Linking {
        stored: &stored,
        file: "",
        files: &files,
        workspace: &workspace,
        reexports: &reexports,
        templates: &templates,
        constants: &constants,
        exports: &exports,
        subclasses: &subclasses,
        scalar_props: &[],
        packages: None,
        external_names: &names,
        properties: &properties,
    };
    scan_file_program(program, &linking, external)
}

/// Where a program sits in its scan root: its path and every file next to it, for resolving
/// relative imports.
#[derive(Debug, Clone, Copy)]
pub struct Linking<'a> {
    /// The fields requests store, from every file of the last round.
    pub stored: &'a StoredFields,
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
    /// Every class extending or implementing each class or interface (see `scan.rs`).
    pub subclasses: &'a BTreeMap<(String, String), Vec<(String, String)>>,
    /// Request props that hold only strings and arrays in this file's package (`query` with
    /// Express 5).
    pub scalar_props: &'a [String],
    /// The packages sinks require that the file's project depends on (`None`: the scan saw no
    /// manifest, so no sink is held back).
    pub packages: Option<&'a BTreeSet<String>>,
    /// The repository's summary names by their last segment (`find` -> `UsersService.find`,
    /// `find`): built once per round, so a lookup never scans every summary.
    pub external_names: &'a BTreeMap<String, Vec<String>>,
    /// Properties every typed assignment in the repository gives the same class
    /// (`config.database = new DatabaseController(..)`): property name -> class.
    pub properties: &'a BTreeMap<String, ClassRef>,
}

/// [`Linking::external_names`] of a summary map.
pub fn index_names(summaries: &Summaries) -> BTreeMap<String, Vec<String>> {
    let mut index: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for name in summaries.keys() {
        let last = name.rsplit('.').next().unwrap_or(name);
        index.entry(last.to_owned()).or_default().push(name.clone());
    }
    index
}

impl Linking<'_> {
    /// The file `spec` names from this file: relative, or a package of the workspace.
    pub fn resolve(&self, spec: &str) -> Option<String> {
        if spec.starts_with('.') {
            jss_core::resolve::resolve(self.file, spec, self.files)
        } else {
            // tsconfig `paths` first, as tsc does, then `module-alias` aliases, then the
            // workspace's packages.
            self.workspace
                .resolve_typescript(self.file, spec, self.files)
                .or_else(|| self.workspace.resolve_alias(self.file, spec, self.files))
                .or_else(|| self.workspace.resolve(spec, self.files))
        }
    }

    /// Whether `spec` is one of our own modules (relative, or a workspace package).
    pub fn is_own(&self, spec: &str) -> bool {
        spec.starts_with('.') || (!self.workspace.is_empty() && self.resolve(spec).is_some())
    }
}

/// Most summary passes over one file: enough for a chain of helpers five deep declared
/// callers first.
const MAX_SUMMARY_PASSES: usize = 6;

/// Scans a parsed program that is `linking.file` in a scan root, with the root's summaries.
pub fn scan_file_program(
    program: &Program<'_>,
    linking: &Linking<'_>,
    external: &Summaries,
) -> ScanResult {
    guards::set_analyzed([]);
    let result = scan_file_program_inner(program, linking, external);
    guards::set_analyzed([]);
    result
}

fn scan_file_program_inner(
    program: &Program<'_>,
    linking: &Linking<'_>,
    external: &Summaries,
) -> ScanResult {
    let mut walker = Walker {
        external,
        linking,
        source: program.source_text,
        facts: FileFacts::default(),
        field_of: BTreeMap::new(),
        pending_auth: Auth::NoneDetected,
        pending_request_kind: std::cell::Cell::new(None),
        pending_server_fields: std::cell::Cell::new(None),
        resolved: std::cell::RefCell::new(BTreeMap::new()),
        router_auth: BTreeMap::new(),
        inline_names: BTreeMap::new(),
        routers: BTreeSet::new(),
        servers: BTreeSet::new(),
        closure_factories: closure_factories(&program.body),
        named_server_handlers: Vec::new(),
        router_prefixes: BTreeMap::new(),
        chain_receiver: None,
        injected: BTreeMap::new(),
        export_aliases: BTreeSet::new(),
        constants: BTreeMap::new(),
        stored_writes: BTreeMap::new(),
        last_returned_fields: None,
        route_templates: BTreeMap::new(),
        require_wrappers: BTreeMap::new(),
        record_only: false,
        current_class: None,
        class_fields: BTreeMap::new(),
        ctor_params: BTreeMap::new(),
        param_owner: BTreeMap::new(),
        rest_params: BTreeSet::new(),
        pending_element: None,
        fn_returns: None,
        callback_returns: None,
        closure_writes: Vec::new(),
        pending_param_props: None,
        field_types: BTreeMap::new(),
        field_refs: BTreeMap::new(),
        call_classes: BTreeMap::new(),
        declared_classes: BTreeSet::new(),
        caller_kinds: BTreeMap::new(),
        emit_field: None,
        emit_with_param: None,
        field_slots: BTreeMap::new(),
        field_reads: BTreeMap::new(),
        call_fields: BTreeMap::new(),
        fn_tables: BTreeMap::new(),
        promised: BTreeSet::new(),
        keyed_entries: BTreeMap::new(),
        jumps: Vec::new(),
        regexes: BTreeMap::new(),
        service_worker: false,
        modules: BTreeMap::new(),
        relative: BTreeMap::new(),
        dyn_imports: BTreeMap::new(),
        factory_bindings: BTreeMap::new(),
        result: ScanResult::default(),
        depth: 0,
        summarize: true,
        summaries: BTreeMap::new(),
        scope_stack: Vec::new(),
        nested_fns: BTreeMap::new(),
        declaring: false,
        pending_archive: None,
    };
    // Summary passes until a pass learns nothing new: each pass sees the previous one's
    // summaries, so a helper declared before the helper it calls gets its summary one pass
    // later (`a -> b -> c -> exec` declared in that order needs three). At least two, at most
    // `MAX_SUMMARY_PASSES`.
    let mut learned = usize::MAX;
    for pass in 0..MAX_SUMMARY_PASSES {
        guards::set_analyzed(walker.predicate_names());
        walker.modules.clear();
        // Middleware applies to the routes registered after it, in program order: never carry
        // a later `use(auth)` into an earlier route through a previous pass.
        walker.router_auth.clear();
        walker.router_prefixes.clear();
        let mut env = Env::new("<module>".to_owned());
        walker.statements(&program.body, &mut env);
        // Summaries and instance fields are only ever added (deduplicated), so their count
        // grows until nothing changes.
        let now = walker.summaries.values().map(Vec::len).sum::<usize>()
            + walker
                .class_fields
                .values()
                .map(BTreeMap::len)
                .sum::<usize>();
        if pass >= 1 && now == learned {
            break;
        }
        learned = now;
    }
    walker.summarize = false;
    guards::set_analyzed(walker.predicate_names());
    walker.modules.clear();
    walker.router_auth.clear();
    walker.router_prefixes.clear();
    walker.result = ScanResult {
        findings: Vec::new(),
        truncated: walker.result.truncated,
        summaries: Summaries::new(),
        facts: FileFacts::default(),
        templates: BTreeMap::new(),
        constants: BTreeMap::new(),
        stored: StoredFields::new(),
    };
    walker.facts = FileFacts::default();
    let mut env = Env::new("<module>".to_owned());
    walker.statements(&program.body, &mut env);
    let mut result = walker.result;
    result.summaries = walker.summaries;
    let mut facts = walker.facts;
    // `http.createServer(handle)`: an entry only when `handle` is a function of this file (not
    // `http.createServer(app)` on an app whose own routes are listed already).
    let named = std::mem::take(&mut walker.named_server_handlers);
    facts.routes.extend(
        named
            .into_iter()
            .filter(|route| facts.functions.contains_key(&route.handler)),
    );
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
    result.stored = walker.stored_writes;
    result
}

/// What a file contributes to the entry-point inventory.
#[derive(Debug, Default, Clone)]
pub struct FileFacts {
    pub routes: Vec<RouteFact>,
    /// Entries whose handler is an inline callback walked as part of its enclosing function
    /// (`handler` names that function): they reach only the findings inside the span.
    pub scoped_routes: Vec<(RouteFact, Span)>,
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
    /// Named middleware reached by a route registration, keyed by that registration's span.
    /// Each value carries the authentication in force before that middleware runs.
    pub route_handlers: BTreeMap<(u32, u32), Vec<(String, Auth)>>,
    /// Classes declared here, with their bases.
    pub classes: Vec<jss_core::ir::ClassDecl>,
    /// Properties assigned an instance of one of our classes: (property, class).
    pub properties: Vec<(String, ClassRef)>,
    /// Constructors named by a pack's local cap that this file calls (see
    /// [`models::LocalCapSpec`]).
    pub constructed: BTreeSet<String>,
}

/// One entry point registered in this file.
#[derive(Debug, Clone)]
pub struct RouteFact {
    /// The router or app it is registered on, when it is a variable.
    pub receiver: Option<String>,
    /// The file that declares `receiver`, when it is another file's router (a route added
    /// through a helper that registers on its own module's router).
    pub receiver_file: Option<String>,
    /// HTTP method (upper case), or `SOCKET`, `IPC`, `QUERY`, `MUTATION`, `TRPC`, `QUEUE`, `ANY`.
    pub method: String,
    pub path: String,
    /// The function that handles it (walker name).
    pub handler: String,
    pub span: Span,
    /// For a route a helper registers: the file and line of the helper's own call.
    pub at: Option<(String, u32)>,
    pub auth: Auth,
    pub kind: &'static str,
}

/// A route registered from a function's parameters, instantiated at each call (in this file or,
/// through imports, in others).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTemplate {
    /// The router: a variable of the defining file, or the index of the parameter holding it.
    pub receiver: Result<Option<String>, usize>,
    /// The file that declares the receiver variable, once the template leaves it.
    pub receiver_file: Option<String>,
    /// The method, or the index of the parameter holding it.
    pub method: Result<String, usize>,
    pub path: Vec<PathPart>,
    pub auth: Auth,
    /// The handler written in the template's function, by its name in the defining file: inline
    /// (`mstream.post('/x', (req, res) => ...)`, the name its walk gave it) or named
    /// (`router.post(`/api/${name}/logo`, mw, controllers.uploadLogo)`).
    pub handler: Option<String>,
    /// Else the parameter holding the handler (`router.get(name, middlewares, controller)`):
    /// each caller passes its own.
    pub handler_param: Option<usize>,
    /// For a mount helper (`function mount(prefix, spec) { router.use(prefix, require(spec)) }`):
    /// which module the `use` mounts, in terms of the helper's parameters. `None` for a route.
    pub mount_module: Option<MountModule>,
    /// The file and line of the `router.get(...)` call the template was made from.
    pub at: Option<(String, u32)>,
}

/// The module a mount helper's `router.use(prefix, child)` mounts, in terms of its parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountModule {
    /// `require('./sites.routes')` resolved to a file.
    Spec(String),
    /// `require(<the helper's Nth parameter>)` — the caller's Nth argument names the module.
    RequireParam(usize),
    /// The helper's Nth parameter itself (the caller passes a router or sub-app).
    Param(usize),
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
    /// The export of `target_file` mounted (`require('./api').router`); the default when `None`.
    pub target_export: Option<String>,
    /// Authentication middleware on the mount (`app.use('/admin', requireAdmin, router)`).
    pub auth: Auth,
    /// The registration call's span, so a middleware-factory mount turned into an entry points at
    /// the `app.use(...)` site (where the route — and any config gate enabling it — is written).
    pub span: Span,
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
    /// The sink's rule needs the attacker to choose the start of the value (see
    /// [`RawFinding::start`]).
    pub start: bool,
    /// The parameter is a rest parameter (`...paths`): every argument from `param` on.
    pub rest: bool,
    /// [`INSTANCE`] summaries only: the class the function returns an instance of.
    pub instance_of: Option<ClassRef>,
    /// For a [`PREDICATE`] that checks containment (`c.startsWith(p + path.sep)`): the parameter
    /// holding the base; the check confines only when the caller's base is not the attacker's.
    pub base_param: Option<usize>,
    /// Sink summaries only: another parameter the sink also needs from the caller's attacker
    /// (`target[k1][k2] = v` pollutes only when both keys are chosen): the caller's argument at this
    /// index must carry attacker data too, or the call reaches nothing.
    pub with_param: Option<usize>,
    /// The function a nested function is declared in (by the start of its parameter list;
    /// `None` at the top level and for functions no declaration names): a call by name takes
    /// the summaries of the closest declaration it can see, not of every function so named.
    pub scope: Option<u32>,
}

/// A function of a table (`const _mounts = { admin: require('./admin') }`, `_mounts.main = fn`):
/// one of this file's, by the name its walk gave it, or a module's default export.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TableEntry {
    Local(String),
    Module(String),
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
    /// Locals holding a record loaded from a store (`const user = await Model.findByPk(id)`).
    records: BTreeSet<String>,
    /// Names bound to a connected client socket (`io.on('connection', (s) => ...)`).
    sockets: BTreeSet<String>,
    /// Names whose `.input` field is client data (tRPC procedure options).
    inputs: BTreeMap<String, &'static str>,
    /// Authentication recognized for this function's entry point.
    auth: Auth,
    /// This function's parameter names, in order.
    params: Vec<String>,
    /// Arrays of object literals (route tables): name -> rows of field -> text.
    /// Shared: a table never changes once declared, and every function entered copies the
    /// environment.
    tables: std::rc::Rc<BTreeMap<String, Vec<BTreeMap<String, String>>>>,
    /// The row a table loop variable stands for in this walk: `r` -> fields.
    rows: BTreeMap<String, BTreeMap<String, String>>,
    /// A route table row destructured in the loop head (`table.forEach(({ path, route }) => ...)`):
    /// each destructured local bound to its field's literal text for this walk.
    row_fields: BTreeMap<String, String>,
    /// Locals bound to `require(<a parameter>)`, directly or through a require wrapper
    /// (`const m = require(spec)`, `const m = load(spec)`): local -> that parameter's index. Used to
    /// name the module a mount helper's `router.use(prefix, m)` mounts.
    require_params: BTreeMap<String, usize>,
    /// Variables bound to an object literal: the taint of each field.
    fields: BTreeMap<String, BTreeMap<String, Origin>>,
    /// Access paths a guard validated: no longer tainted.
    clean: BTreeSet<String>,
    /// Access paths a guard proved scalar: never an object.
    scalars: BTreeSet<String>,
    /// Access paths a guard validated for some classes only (bits of [`class_bit`]).
    partial: BTreeMap<String, u8>,
    /// Names bound to `new C()` of a class whose objects hold no HTML (`URLSearchParams`):
    /// method sinks such as `.append()` do not apply to them.
    plain: BTreeSet<String>,
    /// Client-source parameters whose listed fields the server chose (`file.path` of an upload).
    server_fields: BTreeMap<String, &'static [String]>,
    /// Variables holding an instance of an imported class (`const shell = new ShellService()`):
    /// the imported binding of the class.
    instances: BTreeMap<String, String>,
    /// Variables holding an instance of a class of this file: the class.
    local_instances: BTreeMap<String, String>,
    /// Variables holding an instance of a class known only by where it is declared: what a
    /// function returns (`const db = getDBClient(cfg)`, a factory of several classes).
    remote: BTreeMap<String, Vec<ClassRef>>,
    /// Variables bound to a DOM node created here (`document.createElement('iframe')`).
    nodes: BTreeSet<String>,
    /// Variables built, unchanged, from one tainted variable and clean parts
    /// (`const file = join(root, dir, name)`): variable -> that one. A later check that the
    /// variable is clean cleans what was built from it.
    derived: BTreeMap<String, String>,
    /// Variables naming the same file as another (`const resolved = path.resolve(file)`):
    /// variable -> that one. Confining one confines the other (paths only).
    same_file: BTreeMap<String, String>,
    /// Paths built by joining a segment onto a base (`const full = path.join(base, seg)`):
    /// name -> (the base's access paths, the segment). When the joined path is confined to the
    /// base, the segment does not climb, so joining it onto any base stays confined.
    joined: BTreeMap<String, (Vec<String>, String)>,
    /// Relative paths (`const rel = path.relative(base, file)`): rel -> (the base's access
    /// paths, `file`). `rel.startsWith('..')` false puts `file` inside the base.
    relative_of: BTreeMap<String, (Vec<String>, String)>,
    /// Copies of a URL's host (`const host = url.hostname`): name -> that field's access path.
    host_alias: BTreeMap<String, String>,
    /// URLs parsed from a string alone (`const url = new URL(s)`): url -> `s`.
    url_parsed: BTreeMap<String, String>,
    /// Those nodes' tags, when the factory named one (`document.createElement('a')`).
    node_tags: BTreeMap<String, String>,
    /// Argument arrays that already hold `"--"`: what is pushed after it is positional.
    options_ended: BTreeSet<String>,
    /// Variables bound to an object whose text form is percent-encoded (`const u = new
    /// URLSearchParams(q)`): what is stored in it (`u.set(k, v)`) is encoded in that text too.
    encoded: BTreeSet<String>,
    /// Results of a lookup by equality in a list the server holds (`const doc =
    /// docs.find((d) => d.filename === name)`): result -> the value looked up (`name`).
    found_by: BTreeMap<String, String>,
    /// For a function a declaration names inside another function (`function send() {}`,
    /// `const send = () => {}`): that function ([`Summary::scope`]).
    def_scope: Option<u32>,
    /// Summary pass: where this function's own parameters' values start (not an enclosing
    /// function's, which a closure sees too).
    own_params: BTreeSet<u32>,
    /// Archives opened by a library that checks every entry's name (yauzl's `zipfile`).
    validated_archives: BTreeSet<String>,
    /// Names this function declares (parameters, `var`/`let`/`const`, loop and catch
    /// bindings, inner functions): writes to any other name are writes to its parent's.
    locals: BTreeSet<String>,
    /// Collections of tuples: the taint at each position of their elements
    /// (`extras.push(['topic', topic])`, `Object.entries(o)` gives `[key, value]`).
    tuples: BTreeMap<String, Vec<Option<Origin>>>,
    /// Variables holding what an auth call returned (`const user = verifyToken(token)`): a
    /// falsy one means the caller is not logged in (or not an admin).
    auth_vars: BTreeMap<String, Auth>,
    /// Variables initialized by a call (routers, apps), by name: where they were declared, so
    /// same-named variables of different functions are told apart.
    declared: BTreeMap<String, u32>,
    /// Inside a branch or loop: assignments only add taint.
    branch: u32,
    function: String,
    /// The nearest named function: this one, or for an anonymous callback the function it
    /// is written in (`app.get('/x', (req, res) => list.forEach((i) => exec(i)))`: `GET /x`).
    /// Its calls and findings belong to that function, for the call graph and entry points.
    owner: String,
}

/// What a statement can change about the facts and taint of an [`Env`], saved before a branch
/// to join both paths after it.
#[derive(Debug, Clone)]
struct PathState {
    vars: BTreeMap<String, Origin>,
    clean: BTreeSet<String>,
    scalars: BTreeSet<String>,
    partial: BTreeMap<String, u8>,
    fields: BTreeMap<String, BTreeMap<String, Origin>>,
    nodes: BTreeSet<String>,
    node_tags: BTreeMap<String, String>,
}

/// The value after two paths meet: tainted if either path left it tainted, with the weaker
/// state (attacker-controlled start, possibly an object, built) and escaped only if both are.
fn join(a: &mut Origin, b: &Origin) {
    a.absorb(b);
    a.upload &= b.upload;
    a.dash_free &= b.dash_free;
    a.object |= b.object;
    a.prefix |= b.prefix;
    a.built |= b.built;
    a.sqlish |= b.sqlish;
    a.htmlish |= b.htmlish;
    a.escaped &= b.escaped;
}

impl Env {
    fn save(&self) -> PathState {
        PathState {
            vars: self.vars.clone(),
            clean: self.clean.clone(),
            scalars: self.scalars.clone(),
            partial: self.partial.clone(),
            fields: self.fields.clone(),
            nodes: self.nodes.clone(),
            node_tags: self.node_tags.clone(),
        }
    }

    fn restore(&mut self, state: PathState) {
        self.vars = state.vars;
        self.clean = state.clean;
        self.scalars = state.scalars;
        self.partial = state.partial;
        self.fields = state.fields;
        self.nodes = state.nodes;
        self.node_tags = state.node_tags;
    }

    /// Joins another path's state into this one: taint from either, facts from both.
    fn join_with(&mut self, other: &PathState) {
        for (name, origin) in &other.vars {
            match self.vars.get_mut(name) {
                Some(current) => join(current, origin),
                None => {
                    self.vars.insert(name.clone(), origin.clone());
                }
            }
        }
        self.clean.retain(|k| other.clean.contains(k));
        self.scalars.retain(|k| other.scalars.contains(k));
        // A node on both paths only: `let x = markup; if (c) { x = doc.createElement('b') }`.
        self.nodes.retain(|k| other.nodes.contains(k));
        self.node_tags
            .retain(|k, tag| other.node_tags.get(k) == Some(tag));
        self.partial
            .retain(|k, classes| match other.partial.get(k) {
                Some(theirs) => {
                    *classes &= *theirs;
                    *classes != 0
                }
                None => false,
            });
        for (name, fields) in &other.fields {
            let entry = self.fields.entry(name.clone()).or_default();
            for (field, origin) in fields {
                match entry.get_mut(field) {
                    Some(current) => join(current, origin),
                    None => {
                        entry.insert(field.clone(), origin.clone());
                    }
                }
            }
        }
    }

    /// Drops every fact about `key` and the paths under it: it was written.
    fn forget(&mut self, key: &str) {
        let prefix = format!("{key}.");
        self.clean
            .retain(|k| k != key && !k.starts_with(prefix.as_str()));
        self.scalars
            .retain(|k| k != key && !k.starts_with(prefix.as_str()));
        self.partial
            .retain(|k, _| k != key && !k.starts_with(prefix.as_str()));
    }

    /// A request object or one of its object-valued parts (`req`, `req.body`, `ctx.request`):
    /// a check that names it (`hasValidSession(req)`) says nothing about every value under it.
    fn is_request_object(&self, key: &str) -> bool {
        let mut parts = key.split('.');
        let root = parts.next().unwrap_or("");
        if !self.requests.contains_key(root) {
            return false;
        }
        let rest: Vec<&str> = parts.collect();
        rest.len() <= 2
            && rest
                .iter()
                .all(|p| has(&m().request_props, p) || has(&m().sub_objects, p))
    }

    /// Whether `key` holds attacker data here: a request object, or a value tainted by a
    /// source (a parameter's value in a summary is the caller's business).
    fn attacker_data(&self, key: &str) -> bool {
        let root = key.split('.').next().unwrap_or(key);
        self.requests.contains_key(root)
            || [key, root]
                .into_iter()
                .filter_map(|k| self.vars.get(k))
                .any(|origin| origin.param.is_none())
    }

    /// The parameters' values among a base's access paths, merged: a summary's base that the
    /// caller passes (`readInside(base, file)`).
    fn param_base(&self, bases: &[String]) -> Option<Origin> {
        bases
            .iter()
            .filter_map(|base| {
                let root = base.split('.').next().unwrap_or(base);
                [base.as_str(), root]
                    .into_iter()
                    .find_map(|k| self.vars.get(k))
                    .filter(|origin| {
                        origin.param.is_some() && self.own_params.contains(&origin.span.start)
                    })
                    .cloned()
            })
            .fold(None, |merged, origin| union(merged, Some(origin)))
    }

    /// Records what a guard established.
    fn learn(&mut self, facts: Vec<(String, guards::Fact)>) {
        // Values confined to a base that is a parameter: as much the attacker's as the base the
        // caller passes, for what the base confines.
        let mut rebased: Vec<(String, Origin, u8)> = Vec::new();
        let mut facts: Vec<(String, guards::Fact)> = facts
            .into_iter()
            .filter_map(|(key, fact)| match fact {
                // `rel.startsWith('..')` was false, `rel = path.relative(base, file)`: `file`
                // is inside the base.
                guards::Fact::NoUpward => {
                    let (bases, file) = self.relative_of.get(&key)?;
                    if bases.iter().any(|b| self.attacker_data(b)) {
                        return None;
                    }
                    let path_bit = class_bit(VulnClass::PathTraversal);
                    if let Some(base) = self.param_base(bases) {
                        rebased.push((file.clone(), base, path_bit));
                    }
                    Some((file.clone(), guards::Fact::Clean(path_bit)))
                }
                // A base the attacker chose confines nothing.
                guards::Fact::Contained(_, bases)
                    if bases.iter().any(|b| self.attacker_data(b)) =>
                {
                    None
                }
                guards::Fact::Contained(classes, bases) => {
                    if let Some(base) = self.param_base(&bases) {
                        rebased.push((key.clone(), base, classes));
                    }
                    Some((key, guards::Fact::Clean(classes)))
                }
                other => Some((key, other)),
            })
            .collect();
        // What a clean value says about others: `file = join(root, name)` is as clean as `name`
        // (built from it unchanged); `resolved = path.resolve(file)` inside the root puts `file`
        // there too (the same file, for paths only).
        let path_bit = class_bit(VulnClass::PathTraversal);
        let mut next = 0;
        while facts.len() < 256 {
            let Some((key, fact)) = facts.get(next).cloned() else {
                break;
            };
            next += 1;
            let (classes, exact) = match fact {
                guards::Fact::Clean(classes) => (classes, false),
                guards::Fact::Allowed => (guards::ALL, true),
                _ => continue,
            };
            let mut more: Vec<(String, guards::Fact)> = self
                .derived
                .iter()
                .filter(|(_, from)| **from == key)
                .map(|(built, _)| (built.clone(), guards::Fact::Clean(classes)))
                .collect();
            if classes & path_bit != 0
                && let Some(file) = self.same_file.get(&key)
            {
                more.push((file.clone(), guards::Fact::Clean(path_bit)));
            }
            // `full = path.join(base, seg)` confined to `base`: `seg` does not climb, so joining
            // it onto any base stays confined. Only when the base is not the attacker's.
            if classes & path_bit != 0
                && let Some((bases, seg)) = self.joined.get(&key)
                && !bases.iter().any(|b| self.attacker_data(b))
            {
                more.push((seg.clone(), guards::Fact::Clean(path_bit)));
            }
            // `HOSTS.has(url.hostname)` on `url = new URL(x)`, the host equal to a value the
            // server holds: the URL goes there. Not a prefix, a pattern or a denylist
            // (`url.origin.startsWith(API)`, `isBlockedHost(h)`), which other hosts pass.
            let ssrf_bit = class_bit(VulnClass::Ssrf);
            if exact {
                // `host = url.hostname; HOSTS.has(host)`: a check of that URL's host.
                if let Some(field) = self.host_alias.get(&key) {
                    more.push((field.clone(), guards::Fact::Allowed));
                }
                if let Some((object, field)) = key.rsplit_once('.')
                    && has(&m().url_host_fields, field)
                    && self
                        .local_instances
                        .get(object)
                        .or_else(|| self.instances.get(object))
                        .is_some_and(|class| has(&m().url_classes, class))
                {
                    more.push((object.to_owned(), guards::Fact::Clean(ssrf_bit)));
                    // `url = new URL(s)`: `s`, parsed the same way, goes there too.
                    if let Some(from) = self.url_parsed.get(object) {
                        more.push((from.clone(), guards::Fact::Clean(ssrf_bit)));
                    }
                }
            }
            // What a value confined to a parameter base says about others (`file` past a check
            // of `resolved = path.resolve(file)`) holds as far as that base does.
            if let Some(base) = rebased
                .iter()
                .find(|(k, _, _)| *k == key)
                .map(|(_, base, _)| base.clone())
            {
                for (other, fact) in &more {
                    if let guards::Fact::Clean(classes) = fact
                        && !rebased.iter().any(|(k, _, _)| k == other)
                    {
                        rebased.push((other.clone(), base.clone(), *classes));
                    }
                }
            }
            for fact in more {
                if !facts.contains(&fact) {
                    facts.push(fact);
                }
            }
        }
        for (key, fact) in facts {
            match fact {
                guards::Fact::Clean(_) | guards::Fact::Allowed if self.is_request_object(&key) => {}
                guards::Fact::Clean(guards::ALL) | guards::Fact::Allowed => {
                    self.vars.remove(&key);
                    self.clean.insert(key);
                }
                // Safe for some classes only: still tainted, escaped for those.
                guards::Fact::Clean(classes) => {
                    if let Some(origin) = self.vars.get_mut(&key) {
                        origin.escaped |= classes;
                    }
                    *self.partial.entry(key).or_insert(0) |= classes;
                }
                guards::Fact::Scalar => {
                    if let Some(origin) = self.vars.get_mut(&key) {
                        origin.object = false;
                    }
                    self.scalars.insert(key);
                }
                // Translated above when `key` is a relative path; nothing to keep otherwise.
                guards::Fact::NoUpward => {}
                guards::Fact::NoLeadingDash => {
                    if let Some(origin) = self.vars.get_mut(&key) {
                        origin.dash_free = true;
                    }
                }
                guards::Fact::Contained(..) => {}
            }
        }
        for (key, mut base, classes) in rebased {
            // Only a value that carries data of its own is confined by the check; one that never
            // held attacker data (a directory entry, a constant) stays untainted whatever base it is
            // compared against: `file.startsWith(key)` filters `file`, it does not make `key` flow
            // into it.
            let Some(own) = self.vars.remove(&key) else {
                continue;
            };
            // The base's parameter stands for what the base confines only.
            base.escaped = guards::ALL & !classes;
            base.primary_escaped = base.escaped;
            self.clean.remove(&key);
            if let Some(merged) = union(Some(own), Some(base)) {
                self.vars.insert(key, merged);
            }
        }
    }

    fn new(function: String) -> Self {
        Self {
            vars: BTreeMap::new(),
            requests: BTreeMap::new(),
            records: BTreeSet::new(),
            sockets: BTreeSet::new(),
            inputs: BTreeMap::new(),
            fields: BTreeMap::new(),
            auth: Auth::NoneDetected,
            params: Vec::new(),
            tables: std::rc::Rc::new(BTreeMap::new()),
            rows: BTreeMap::new(),
            row_fields: BTreeMap::new(),
            require_params: BTreeMap::new(),
            clean: BTreeSet::new(),
            scalars: BTreeSet::new(),
            partial: BTreeMap::new(),
            plain: BTreeSet::new(),
            server_fields: BTreeMap::new(),
            declared: BTreeMap::new(),
            auth_vars: BTreeMap::new(),
            instances: BTreeMap::new(),
            local_instances: BTreeMap::new(),
            remote: BTreeMap::new(),
            tuples: BTreeMap::new(),
            nodes: BTreeSet::new(),
            node_tags: BTreeMap::new(),
            derived: BTreeMap::new(),
            same_file: BTreeMap::new(),
            joined: BTreeMap::new(),
            relative_of: BTreeMap::new(),
            host_alias: BTreeMap::new(),
            url_parsed: BTreeMap::new(),
            options_ended: BTreeSet::new(),
            encoded: BTreeSet::new(),
            found_by: BTreeMap::new(),
            def_scope: None,
            own_params: BTreeSet::new(),
            validated_archives: BTreeSet::new(),
            locals: BTreeSet::new(),
            branch: 0,
            owner: function.clone(),
            function,
        }
    }

    fn closure(&self, function: String) -> Self {
        Self {
            vars: self.vars.clone(),
            requests: self.requests.clone(),
            records: self.records.clone(),
            sockets: self.sockets.clone(),
            inputs: self.inputs.clone(),
            fields: self.fields.clone(),
            auth: self.auth,
            params: Vec::new(),
            tables: self.tables.clone(),
            rows: self.rows.clone(),
            row_fields: self.row_fields.clone(),
            // A nested function has its own parameters: require-of-parameter bindings do not carry in.
            require_params: BTreeMap::new(),
            clean: self.clean.clone(),
            scalars: self.scalars.clone(),
            partial: self.partial.clone(),
            plain: self.plain.clone(),
            server_fields: self.server_fields.clone(),
            declared: self.declared.clone(),
            auth_vars: self.auth_vars.clone(),
            instances: self.instances.clone(),
            local_instances: self.local_instances.clone(),
            remote: self.remote.clone(),
            tuples: self.tuples.clone(),
            nodes: self.nodes.clone(),
            node_tags: self.node_tags.clone(),
            derived: self.derived.clone(),
            same_file: self.same_file.clone(),
            joined: self.joined.clone(),
            relative_of: self.relative_of.clone(),
            host_alias: self.host_alias.clone(),
            url_parsed: self.url_parsed.clone(),
            options_ended: self.options_ended.clone(),
            encoded: self.encoded.clone(),
            found_by: self.found_by.clone(),
            def_scope: self.def_scope,
            own_params: BTreeSet::new(),
            validated_archives: self.validated_archives.clone(),
            locals: BTreeSet::new(),
            branch: 0,
            owner: if function == "<anonymous>" {
                self.owner.clone()
            } else {
                function.clone()
            },
            function,
        }
    }

    /// A strong update, in a branch too: every branch saves the state before it and joins it
    /// after (`if (!p) { p = '/usr/bin/chromium'; install(p); }` installs the constant, and past
    /// the `if` `p` is the caller's again).
    fn bind(&mut self, name: &str, taint: Option<Origin>) {
        self.forget(name);
        // What was built from the value `name` had before this write is not built from it now.
        self.derived.retain(|_, from| from != name);
        self.same_file.retain(|_, file| file != name);
        self.joined
            .retain(|_, (bases, seg)| seg != name && !bases.iter().any(|b| b == name));
        self.relative_of
            .retain(|_, (bases, file)| file != name && !bases.iter().any(|b| b == name));
        self.host_alias
            .retain(|_, field| field.split('.').next() != Some(name));
        self.url_parsed.retain(|_, from| from != name);
        match taint {
            Some(origin) => {
                self.vars.insert(name.to_owned(), origin);
            }
            None => {
                self.vars.remove(name);
            }
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
    /// The file's text, for the lines of route templates.
    source: &'e str,
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
    /// Import specifiers resolved so far (resolving tries many candidate paths).
    resolved: std::cell::RefCell<BTreeMap<String, Option<String>>>,
    /// Routers with authentication middleware applied to every later route: `router.use(auth)`.
    /// Middleware added with `use(...)` (or a verb) on each router (by [`router_key`]), in
    /// registration order.
    router_auth: BTreeMap<String, Vec<RouterGuard>>,
    /// Names given to inline route handlers (`GET /items`), with the registration that took
    /// each: kept across passes so every pass names a handler the same way.
    inline_names: BTreeMap<String, u32>,
    /// Variables bound to a router or app from a factory: `const router = express.Router()`.
    routers: BTreeSet<String>,
    /// Variables bound to a server from a server factory: `const server = http.createServer()`.
    /// Its `server.on('request', (req, res) => ...)` handles every request.
    servers: BTreeSet<String>,
    /// Top-level functions that return a function they define (see [`closure_factories`]).
    closure_factories: BTreeSet<String>,
    /// `http.createServer(handle)` with a named handler: kept as entries only if `handle` turns
    /// out to be a function of this file (known once the file is walked).
    named_server_handlers: Vec<RouteFact>,
    /// A router's own path prefix: `new Router({ prefix: '/api' })`, `router.prefix('/api')`,
    /// `new Hono().basePath('/api')`.
    router_prefixes: BTreeMap<String, String>,
    /// The variable a declaration being walked binds: the router of a chained registration on
    /// a factory (`const r = Router().get('/a', h)`).
    chain_receiver: Option<String>,
    /// Constructor-injected fields of the class being walked: `this.users` -> `UsersService`.
    injected: BTreeMap<String, String>,
    /// Names bound to `module.exports` (`const helpers = module.exports`).
    export_aliases: BTreeSet<String>,
    /// Constants of this file: `Enum.Member`, `NAME`, `OBJ.key` -> text.
    constants: BTreeMap<String, String>,
    /// Fields this file stores from request data (see [`StoredWrite`]).
    stored_writes: StoredFields,
    /// The per-field taint of the object the last helper call returned (for `const x = f()`).
    last_returned_fields: Option<BTreeMap<String, Origin>>,
    /// Functions that register a route from their parameters: `add(path, handler)`.
    route_templates: BTreeMap<String, Vec<RouteTemplate>>,
    /// Functions that return `require(<their Nth parameter>)` (a module-loading wrapper, often with
    /// caching and a fallback): name -> that parameter's index. So `const m = load(spec)` names the
    /// module `require(spec)`, the way a mount helper's `router.use(prefix, load(spec))` does.
    require_wrappers: BTreeMap<String, usize>,
    /// Re-walking a route-table loop for one row: record routes, emit no findings.
    record_only: bool,
    /// The named class whose methods are being walked.
    current_class: Option<String>,
    /// Taint stored in instance fields (`this.url = url`), per class.
    class_fields: BTreeMap<String, BTreeMap<String, Origin>>,
    /// Summary pass: constructor parameter spans, so what reaches a sink through a field is
    /// summarized under `Class.constructor`.
    ctor_params: BTreeMap<u32, String>,
    /// Summary pass: the function each parameter origin (by span start) belongs to, so a sink
    /// reached inside a callback or a nested function is summarized for the function whose
    /// parameter it is, with the function that one is declared in ([`Summary::scope`]).
    param_owner: BTreeMap<u32, (String, Option<u32>)>,
    /// Summary pass: span starts of rest parameters' origins (`...paths`): their summaries take
    /// every argument from their index on.
    rest_params: BTreeSet<u32>,
    /// The elements the next function entered is called back with (`list.map((x) => ...)`).
    pending_element: Option<PendingElement>,
    /// What the function being walked returns, so far.
    fn_returns: Option<Origin>,
    /// What the function walked last returned (read by the call that passed it as a callback).
    callback_returns: Option<Origin>,
    /// What the function walked last wrote to its parent's names: (name, field, taint).
    closure_writes: Vec<(String, Option<String>, Origin)>,
    /// Instance fields known to hold one of our classes: (class, field) -> class
    /// (`this.svc = new Svc()`, `private svc: Svc`).
    field_types: BTreeMap<(String, String), String>,
    /// Instance (and static) fields holding what an instance-returning function returned
    /// (`this.registry = getRegistry()`): (class, field) -> classes.
    field_refs: BTreeMap<(String, String), Vec<ClassRef>>,
    /// The classes each call walked returns an instance of, from its [`INSTANCE`] summaries:
    /// (call span, returned field) -> classes. Kept across passes (calls do not move).
    call_classes: BTreeMap<(u32, u32, Option<String>), Vec<ClassRef>>,
    /// Classes and interfaces declared in this file (and ES5 constructors with prototype
    /// methods): `new C()` of one of them is an instance worth typing.
    declared_classes: BTreeSet<String>,
    /// Objects whose values are functions, called by a computed key (`_mounts[name](app)`):
    /// table -> its functions.
    fn_tables: BTreeMap<String, Vec<TableEntry>>,
    /// Calls whose result is a promise (`api.get(url).then(...)`, `await api.put(url, data)`),
    /// by span: requests a client sends, never route registrations.
    promised: BTreeSet<(u32, u32)>,
    /// Registrations listed under an object key (`{ list: publicProcedure.query(fn) }`), by
    /// call span: the entry they are, which also names their callback.
    keyed_entries: BTreeMap<(u32, u32), String>,
    /// The states at `break` / `continue` in the loops, switches and labeled statements being
    /// walked (innermost last): each joins the state where its jump lands.
    jumps: Vec<Vec<PathState>>,
    /// The fields each call that returns an object literal gave this walk: (call span) ->
    /// field -> taint (a field it does not list is clean).
    call_fields: BTreeMap<(u32, u32), BTreeMap<String, Origin>>,
    /// The first read of each field of a parameter while summarizing: (parameter position,
    /// field) -> that read's position, which every later read of it shares.
    field_reads: BTreeMap<(u32, String), u32>,
    /// Positions that name a field a call returns when the call's own start already names
    /// another (see [`Self::field_slot`]): (call start, field) -> position.
    field_slots: BTreeMap<(u32, String), u32>,
    /// While summarizing a call that hands the function's own parameter on whole to a helper
    /// whose summary needs one field of it (`new this(basic)` reaching `basic.serverConfig`):
    /// (that parameter's origin offset, the field), for the summary [`Self::emit`] derives.
    emit_field: Option<(u32, String)>,
    /// While summarizing a sink that also needs another parameter from the caller (a nested
    /// write's second key): that parameter's index, for the summary [`Self::emit`] derives.
    emit_with_param: Option<usize>,
    /// The request kind this file's calls pass to a function as its first argument
    /// (`handleToolCall(request)` from an MCP handler): its conventionally named request
    /// parameter is that kind, not an HTTP request. `http` wins over any other.
    caller_kinds: BTreeMap<String, &'static str>,
    /// TypeScript parameter properties of the constructor about to be entered
    /// (`constructor(private readonly cfg: Config)`): (class, parameter names), stored as
    /// instance fields at entry.
    pending_param_props: Option<(String, Vec<String>)>,
    /// The file is a service worker (`self.addEventListener('fetch', ...)`): a `request` there is
    /// the page's own request, not a server's (kept across passes).
    service_worker: bool,
    /// Variables bound to a regular expression (`const re = /a(.*)/`): `re.exec(s)` returns
    /// parts of `s`; with the classes its captures are safe for (an anchored allowlist).
    regexes: BTreeMap<String, u8>,
    modules: BTreeMap<String, Imported>,
    /// Local names bound to relative modules: name -> (specifier, export or None).
    relative: BTreeMap<String, (String, Option<String>)>,
    /// Local names bound to a dynamic `import()` of a template specifier with one interpolation:
    /// `const { default: router } = await import(`./apis/v${v}/router.js`)` -> `router` ->
    /// (`./apis/v`, `v`, `/router.js`, `default`). Lets a `use(`/api/v${v}`, router)` mount resolve
    /// to every matching file with its own concrete prefix.
    dyn_imports: BTreeMap<String, DynImport>,
    /// Variables bound to the result of calling an imported factory
    /// (`const authorization = authorizationController(options)`): name -> factory.
    factory_bindings: BTreeMap<String, String>,
    result: ScanResult,
    depth: u32,
    /// Summary pass: parameters of named functions are tainted, and findings become summaries.
    summarize: bool,
    summaries: BTreeMap<String, Vec<Summary>>,
    /// The functions being walked, outermost first, each by the start of its parameter list.
    scope_stack: Vec<u32>,
    /// Functions declared inside another function: name -> the functions declaring one.
    nested_fns: BTreeMap<String, BTreeSet<u32>>,
    /// Set right before walking a function a declaration names in the current function.
    declaring: bool,
    /// Set while walking the arguments of a call that opens a checked archive: the index of
    /// the callback parameter that receives it.
    pending_archive: Option<usize>,
}

fn union(a: Option<Origin>, b: Option<Origin>) -> Option<Origin> {
    match (a, b) {
        (Some(mut a), Some(b)) => {
            a.absorb(&b);
            Some(Origin {
                built: a.built || b.built,
                sqlish: a.sqlish || b.sqlish,
                htmlish: a.htmlish || b.htmlish,
                // Escaped only if every part is.
                escaped: a.escaped & b.escaped,
                upload: a.upload && b.upload,
                dash_free: a.dash_free && b.dash_free,
                response: a.response || b.response,
                ..a
            })
        }
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

/// The literal text in a `+` chain or a template: `'SELECT *' + ' WHERE n = '` gives both
/// parts (other operands are skipped).
/// The object a chain of receiver-returning calls starts from: `res` for `res.status(404).type('html')`
/// (see [`Pack::receiver_methods`]); any other expression is its own receiver.
fn receiver_of_chain<'a, 'b>(mut expr: &'a Expression<'b>) -> &'a Expression<'b> {
    while let Expression::CallExpression(call) = expr.get_inner_expression() {
        let Some(member) = call.callee.get_inner_expression().as_member_expression() else {
            break;
        };
        if !member
            .static_property_name()
            .is_some_and(|name| has(&m().receiver_methods, name.as_str().unwrap_or("")))
        {
            break;
        }
        expr = member.object();
    }
    expr
}

/// Literal text that holds HTML markup: a tag opening or closing (`<h1`, `</p`, `<!--`).
fn looks_like_markup(text: &str) -> bool {
    text.as_bytes().windows(2).any(|pair| {
        matches!(pair, [b'<', next] if next.is_ascii_alphabetic() || matches!(next, b'/' | b'!'))
    })
}

fn literal_parts<'a>(expr: &'a Expression<'_>, out: &mut Vec<&'a str>) {
    match expr.get_inner_expression() {
        Expression::StringLiteral(lit) => {
            if let Some(text) = lit.value.as_str() {
                out.push(text);
            }
        }
        Expression::TemplateLiteral(template) => {
            out.extend(template.quasis.iter().map(|q| q.value.raw.as_str()));
        }
        Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
            literal_parts(&b.left, out);
            literal_parts(&b.right, out);
        }
        _ => {}
    }
}

/// `{ $eq: x }`, `{ $in: [...] }`: an object of literal-comparison operators only.
fn literal_comparison(value: &Expression<'_>) -> bool {
    let Expression::ObjectExpression(object) = value.get_inner_expression() else {
        return false;
    };
    !object.properties.is_empty()
        && object.properties.iter().all(|p| match p {
            ObjectPropertyKind::ObjectProperty(p) => {
                prop_name(&p.key).is_some_and(|k| has(&m().literal_operators, &k))
            }
            ObjectPropertyKind::SpreadProperty(_) => false,
        })
}

/// The check a predicate returns: a body that is one `return`, maybe after declarations of
/// values it compares (`const c = path.resolve(child); return c.startsWith(...)`).
fn predicate_return<'b, 'a>(statements: &'b [Statement<'a>]) -> Option<&'b Expression<'a>> {
    let (last, before) = statements.split_last()?;
    let Statement::ReturnStatement(r) = last else {
        return None;
    };
    before
        .iter()
        .all(|s| matches!(s, Statement::VariableDeclaration(_)))
        .then_some(r.argument.as_ref()?)
}

/// Whether a function body has a `return` somewhere, with a value or not (not counting nested
/// functions): a void check that `return`s on bad input lets its caller go on with it.
fn returns_at_all(statements: &[Statement<'_>]) -> bool {
    statements.iter().any(|s| statement_returns(s, true))
}

/// A `return` in `statement` (with a value, unless `bare` counts a plain `return;` too).
fn statement_returns(statement: &Statement<'_>, bare: bool) -> bool {
    let any = |list: &[Statement<'_>]| list.iter().any(|s| statement_returns(s, bare));
    match statement {
        Statement::ReturnStatement(r) => bare || r.argument.is_some(),
        Statement::BlockStatement(b) => any(&b.body),
        Statement::IfStatement(i) => {
            statement_returns(&i.consequent, bare)
                || i.alternate
                    .as_ref()
                    .is_some_and(|a| statement_returns(a, bare))
        }
        Statement::TryStatement(t) => {
            any(&t.block.body)
                || t.handler.as_ref().is_some_and(|h| any(&h.body.body))
                || t.finalizer.as_ref().is_some_and(|f| any(&f.body))
        }
        Statement::SwitchStatement(sw) => sw.cases.iter().any(|c| any(&c.consequent)),
        Statement::ForStatement(f) => statement_returns(&f.body, bare),
        Statement::ForInStatement(f) => statement_returns(&f.body, bare),
        Statement::ForOfStatement(f) => statement_returns(&f.body, bare),
        Statement::WhileStatement(w) => statement_returns(&w.body, bare),
        Statement::DoWhileStatement(d) => statement_returns(&d.body, bare),
        Statement::LabeledStatement(l) => statement_returns(&l.body, bare),
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
/// The classes the captures of a regular expression literal are safe for: an anchored allowlist
/// (`/^(\d{15,25})\.(png|gif)$/`) admits only its characters; anything else, none.
fn capture_mask(expr: &Expression<'_>) -> u8 {
    match expr.get_inner_expression() {
        Expression::RegExpLiteral(regex) => guards::match_charset(
            regex.regex.pattern.text.as_str(),
            &regex.regex.flags.to_string(),
        )
        .map_or(0, |set| guards::mask(&set)),
        _ => 0,
    }
}

/// `function RestWrite(config, data) { this.data = data; }`: a PascalCase function that sets
/// fields of `this` is an ES5 class's constructor.
fn is_es5_constructor(name: &str, f: &Function<'_>) -> bool {
    name.chars().next().is_some_and(char::is_uppercase)
        && f.body.as_ref().is_some_and(|body| {
            body.statements.iter().any(|statement| {
                let Statement::ExpressionStatement(e) = statement else {
                    return false;
                };
                let Expression::AssignmentExpression(assign) = e.expression.get_inner_expression()
                else {
                    return false;
                };
                assign
                    .left
                    .as_simple_assignment_target()
                    .and_then(SimpleAssignmentTarget::as_member_expression)
                    .is_some_and(|m| matches!(m.object(), Expression::ThisExpression(_)))
            })
        })
}

/// `C.prototype.run` -> (`C`, Some(`run`)); `C.prototype` -> (`C`, None).
fn prototype_owner(
    member: &oxc_ast::ast::MemberExpression<'_>,
) -> Option<(String, Option<String>)> {
    let key = guards::member_key(member)?;
    let mut parts = key.split('.');
    let class = parts.next()?;
    if !class.chars().next().is_some_and(char::is_uppercase) || parts.next()? != "prototype" {
        return None;
    }
    let method = parts.next().map(str::to_owned);
    if parts.next().is_some() {
        return None;
    }
    Some((class.to_owned(), method))
}

/// What a helper that returns a response gives for the caller's URL `o`: the body, all of it
/// the attacker's (and an object, for JSON). Other return summaries leave `o` as it is.
fn response_of_value(mut o: Origin, s: &Summary) -> Origin {
    if s.start {
        o.object = true;
        o.built = false;
        o.sqlish = false;
        o.htmlish = false;
        o.prefix = true;
        o.escaped = 0;
        o.primary_escaped = 0;
        o.response = true;
    }
    o
}

/// A callee as a trace names it: `fetch`, `http-client.get`, `client.send`.
fn callee_label(callee: &Callee) -> String {
    match callee {
        Callee::Global(name) => name.clone(),
        Callee::Module { family, export } => match export.as_deref() {
            Some(export) if !export.is_empty() => format!("{family}.{export}"),
            _ => (*family).to_owned(),
        },
        Callee::Method { object, method } => match object {
            Some(object) => format!("{object}.{method}"),
            None => method.clone(),
        },
    }
}

/// The access path a lookup by equality checks, when the list it searches is not the
/// attacker's: `docs.find((d) => d.filename === name)` and `docs.some(...)` give `name`.
fn lookup_value(call: &CallExpression<'_>, env: &Env) -> Option<String> {
    let member = call.callee.get_inner_expression().as_member_expression()?;
    let method = member.static_property_name()?.as_str()?;
    if !has(&m().lookup_methods, method) {
        return None;
    }
    // A list of the server's: not a value the attacker sent.
    let list = guards::path_key(member.object())?;
    let root = list.split('.').next().unwrap_or(&list);
    if env.vars.contains_key(root) || env.requests.contains_key(root) {
        return None;
    }
    let Expression::ArrowFunctionExpression(arrow) = call
        .arguments
        .first()
        .and_then(Argument::as_expression)?
        .get_inner_expression()
    else {
        return None;
    };
    let item = match &arrow.params.items.first()?.pattern {
        BindingPattern::BindingIdentifier(id) => id.name.as_str(),
        _ => return None,
    };
    let body = match &arrow.body {
        ArrowFunctionBody::FunctionBody(body) => match body.statements.as_slice() {
            [Statement::ReturnStatement(r)] => r.argument.as_ref()?,
            _ => return None,
        },
        other => other.as_expression()?,
    };
    let Expression::BinaryExpression(test) = body.get_inner_expression() else {
        return None;
    };
    if !matches!(
        test.operator,
        BinaryOperator::StrictEquality | BinaryOperator::Equality
    ) {
        return None;
    }
    let of_item = |e: &Expression<'_>| {
        guards::path_key(e).is_some_and(|k| k == item || k.starts_with(&format!("{item}.")))
    };
    let value = match (of_item(&test.left), of_item(&test.right)) {
        (true, false) => &test.right,
        (false, true) => &test.left,
        _ => return None,
    };
    guards::path_key(value)
}

/// The object literal a return gives, also behind a condition whose other outcome is no value
/// (`dir ? { url, path } : null`, `ok && { url }`).
fn returned_object<'a, 'b>(expr: &'b Expression<'a>) -> Option<&'b ObjectExpression<'a>> {
    let nothing = |e: &Expression<'_>| match e.get_inner_expression() {
        Expression::NullLiteral(_) | Expression::BooleanLiteral(_) => true,
        Expression::Identifier(id) => id.name == "undefined",
        _ => false,
    };
    match expr.get_inner_expression() {
        Expression::ObjectExpression(object) => Some(object),
        Expression::ConditionalExpression(c) if nothing(&c.alternate) => {
            returned_object(&c.consequent)
        }
        Expression::ConditionalExpression(c) if nothing(&c.consequent) => {
            returned_object(&c.alternate)
        }
        Expression::LogicalExpression(l) if l.operator == LogicalOperator::And => {
            returned_object(&l.right)
        }
        _ => None,
    }
}

/// A table's value that is a function: `require('./admin')`, an inline function (walked by its
/// key) or one named elsewhere in the file.
fn table_entry(key: String, value: &Expression<'_>) -> Option<TableEntry> {
    if let Some(spec) = require_spec(value) {
        return Some(TableEntry::Module(spec));
    }
    match value.get_inner_expression() {
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {
            Some(TableEntry::Local(key))
        }
        Expression::Identifier(id) => Some(TableEntry::Local(id.name.as_str().to_owned())),
        _ => None,
    }
}

/// A registration's last argument can be its handler: not data (`api.get(url, {})`,
/// `api.del(url, undefined)`), which a client sends.
fn handler_like(call: &CallExpression<'_>) -> bool {
    call.arguments
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
                    | Expression::BooleanLiteral(_)
            ) && !e.is_null()
                && !e.is_undefined()
        })
}

/// Middleware guarding the routes registered after it on a router.
#[derive(Debug, Clone)]
struct RouterGuard {
    /// The path prefix it guards (`""` for all); the one path it guards when `exact`.
    prefix: String,
    /// Registered with a verb (`app.get('/admin/{*path}', guard)`): routes of that method only.
    method: Option<String>,
    /// A verb's path without a wildcard (`app.all('/admin', guard)`): that path only.
    exact: bool,
    auth: Auth,
}

impl RouterGuard {
    /// Whether it runs for a route of `method` at `path` (`None`: unknown).
    fn guards(&self, method: Option<&str>, path: Option<&str>) -> bool {
        if self.method.is_some() && self.method.as_deref() != method {
            return false;
        }
        if self.exact {
            let prefix = self.prefix.trim_end_matches('/');
            return path.is_some_and(|p| p.trim_end_matches('/') == prefix);
        }
        covers(&self.prefix, path)
    }
}

/// One of `names` (a receiver's name, class or chain) contains one of `needles` (lower case).
fn any_contains<'n>(mut names: impl Iterator<Item = &'n str>, needles: &[String]) -> bool {
    names.any(|name| {
        let lower = name.to_ascii_lowercase();
        needles.iter().any(|n| lower.contains(n.as_str()))
    })
}

/// The identifiers and property names an expression reads (not inside nested functions).
fn names_in(expr: &Expression<'_>, out: &mut Vec<String>) {
    fn walk(expr: &Expression<'_>, out: &mut Vec<String>, depth: usize) {
        if depth > 32 {
            return;
        }
        let deeper = |e: &Expression<'_>, out: &mut Vec<String>| walk(e, out, depth + 1);
        match expr.get_inner_expression() {
            Expression::Identifier(id) => out.push(id.name.as_str().to_owned()),
            Expression::BinaryExpression(b) => {
                deeper(&b.left, out);
                deeper(&b.right, out);
            }
            Expression::LogicalExpression(l) => {
                deeper(&l.left, out);
                deeper(&l.right, out);
            }
            Expression::UnaryExpression(u) => deeper(&u.argument, out),
            Expression::ConditionalExpression(c) => {
                deeper(&c.test, out);
                deeper(&c.consequent, out);
                deeper(&c.alternate, out);
            }
            Expression::CallExpression(c) => {
                deeper(&c.callee, out);
                for a in &c.arguments {
                    if let Some(e) = a.as_expression() {
                        deeper(e, out);
                    }
                }
            }
            other => {
                if let Some(member) = other.as_member_expression() {
                    if let Some(name) = member.static_property_name().and_then(|n| n.as_str()) {
                        out.push(name.to_owned());
                    }
                    deeper(member.object(), out);
                }
            }
        }
    }
    walk(expr, out, 0);
}

/// The authentication an inline middleware enforces before `next()`: an `if` that answers 401
/// or 403 and returns, on a credential or an identity of the request. Admin when the check
/// names an admin word (`req.user.admin !== true`) or compares a credential of the request with
/// a value of the server (`req.header('Authorization') !== SECRET`, a shared secret); a user
/// otherwise (`!req.session.user`). Nothing when a request can get past it: a `next()` before
/// it (`if (req.method === 'GET') return next()`) or in its answer, or a check that holds only
/// with another condition (`req.user && !req.user.admin` lets anonymous requests through).
fn inline_guard_auth(expr: &Expression<'_>) -> Option<Auth> {
    let (params, statements) = match expr.get_inner_expression() {
        Expression::ArrowFunctionExpression(f) => match &f.body {
            ArrowFunctionBody::FunctionBody(body) => (&f.params, &body.statements),
            _ => return None,
        },
        Expression::FunctionExpression(f) => (&f.params, &f.body.as_ref()?.statements),
        _ => return None,
    };
    // `(err, req, res, next)` handles errors: it guards nothing.
    if params.items.len() != 3 {
        return None;
    }
    let request = params
        .items
        .first()?
        .pattern
        .get_identifier_name()?
        .to_string();
    let next = params
        .items
        .get(2)
        .and_then(|p| p.pattern.get_identifier_name())
        .map(|n| n.to_string());
    let calls_next = |statement: &Statement<'_>| {
        next.as_deref()
            .is_some_and(|next| statement_calls(statement, next))
    };
    // `const authorization = req.header('Authorization')`: read from the request; a credential
    // when its name or what it reads says so.
    let mut from_request: BTreeSet<String> = BTreeSet::from([request]);
    let mut credentials: BTreeSet<String> = BTreeSet::new();
    let mut level: Option<Auth> = None;
    for statement in statements {
        match statement {
            Statement::VariableDeclaration(d) => {
                for declarator in &d.declarations {
                    let (Some(name), Some(init)) =
                        (declarator.id.get_identifier_name(), &declarator.init)
                    else {
                        continue;
                    };
                    let mut names = Vec::new();
                    names_in(init, &mut names);
                    if names.iter().any(|n| from_request.contains(n)) {
                        from_request.insert(name.to_string());
                        let mut words = names.clone();
                        words.push(name.to_string());
                        literals_in(init, &mut words);
                        if words.iter().any(|w| credential_word(w)) {
                            credentials.insert(name.to_string());
                        }
                    }
                }
            }
            Statement::IfStatement(i)
                if guards::exits(&i.consequent) && answers_denied(&i.consequent) =>
            {
                // `res.status(401); return next()`: it answers and goes on anyway.
                if calls_next(&i.consequent) {
                    return None;
                }
                // `req.user && !req.user.admin`, `req.path.startsWith('/admin') && ...`: denied
                // only when the other condition holds too.
                if matches!(i.test.get_inner_expression(),
                    Expression::LogicalExpression(l) if l.operator == LogicalOperator::And)
                {
                    continue;
                }
                let mut names = Vec::new();
                names_in(&i.test, &mut names);
                if !names.iter().any(|n| from_request.contains(n)) {
                    continue;
                }
                // `req.get('origin') !== ALLOWED_ORIGIN`, `req.protocol !== 'https'`: no
                // credential, no identity.
                let mut words = names.clone();
                literals_in(&i.test, &mut words);
                if !words
                    .iter()
                    .any(|w| credentials.contains(w) || credential_word(w))
                {
                    continue;
                }
                let admin = names.iter().any(|n| {
                    let lower = n.to_ascii_lowercase();
                    m().auth_admin.iter().any(|a| lower.contains(a.as_str()))
                });
                let this = if admin || compares_to_server(&i.test, &from_request, &credentials) {
                    Auth::Admin
                } else {
                    Auth::User
                };
                level = level.max(Some(this));
            }
            // `if (req.method === 'GET') return next()` before the check: not every request
            // meets it.
            other if level.is_none() && calls_next(other) => return None,
            _ => {}
        }
    }
    level
}

/// `x !== SECRET` with `x` a credential read from the request (`req.header('Authorization')`)
/// and `SECRET` not read from it: a shared secret.
fn compares_to_server(
    test: &Expression<'_>,
    from_request: &BTreeSet<String>,
    credentials: &BTreeSet<String>,
) -> bool {
    match test.get_inner_expression() {
        Expression::LogicalExpression(l) => {
            compares_to_server(&l.left, from_request, credentials)
                || compares_to_server(&l.right, from_request, credentials)
        }
        Expression::UnaryExpression(u) => {
            compares_to_server(&u.argument, from_request, credentials)
        }
        Expression::BinaryExpression(b)
            if matches!(
                b.operator,
                BinaryOperator::StrictInequality | BinaryOperator::Inequality
            ) =>
        {
            let reads = |e: &Expression<'_>| {
                let mut names = Vec::new();
                names_in(e, &mut names);
                names.iter().any(|n| from_request.contains(n))
            };
            // The request's side names a credential: `authorization`, `req.get('x-api-key')`.
            let credential = |e: &Expression<'_>| {
                let mut words = Vec::new();
                names_in(e, &mut words);
                literals_in(e, &mut words);
                words
                    .iter()
                    .any(|w| credentials.contains(w) || credential_word(w))
            };
            let server = |e: &Expression<'_>| {
                matches!(e.get_inner_expression(), Expression::Identifier(_))
                    || e.get_inner_expression().as_member_expression().is_some()
            };
            (reads(&b.left) && credential(&b.left) && !reads(&b.right) && server(&b.right))
                || (reads(&b.right) && credential(&b.right) && !reads(&b.left) && server(&b.left))
        }
        _ => false,
    }
}

/// A name or string that names a credential or an identity (`authorization`, `x-api-key`,
/// `req.session`, `isAuthenticated`), word by word per the auth pack: `user-agent` and
/// `author` do not.
fn credential_word(text: &str) -> bool {
    let words = split_words(text);
    let model = m();
    // A pack phrase (`api-key`, one word or more) starting at word `i`.
    let at = |phrase: &String, i: usize| {
        let phrase = split_words(phrase);
        !phrase.is_empty() && words.get(i..i + phrase.len()) == Some(&phrase[..])
    };
    (0..words.len()).any(|i| {
        !model.auth_not_credentials.iter().any(|p| at(p, i))
            && model
                .auth_credentials
                .iter()
                .chain(&model.auth_admin)
                .any(|p| at(p, i))
    })
}

/// The lower-case words of a name or string: `x-api-key`, `apiKey` and `API_KEY` are `api`,
/// `key`.
fn split_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for c in text.chars() {
        if !c.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            previous_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && previous_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        previous_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        current.push(c.to_ascii_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// The string literals an expression reads (`req.get('Authorization')`, `h['x-api-key']`).
fn literals_in(expr: &Expression<'_>, out: &mut Vec<String>) {
    fn walk(expr: &Expression<'_>, out: &mut Vec<String>, depth: usize) {
        if depth > 32 {
            return;
        }
        let deeper = |e: &Expression<'_>, out: &mut Vec<String>| walk(e, out, depth + 1);
        match expr.get_inner_expression() {
            Expression::StringLiteral(s) => {
                if let Some(text) = s.value.as_str() {
                    out.push(text.to_owned());
                }
            }
            Expression::BinaryExpression(b) => {
                deeper(&b.left, out);
                deeper(&b.right, out);
            }
            Expression::LogicalExpression(l) => {
                deeper(&l.left, out);
                deeper(&l.right, out);
            }
            Expression::UnaryExpression(u) => deeper(&u.argument, out),
            Expression::CallExpression(c) => {
                deeper(&c.callee, out);
                for a in &c.arguments {
                    if let Some(e) = a.as_expression() {
                        deeper(e, out);
                    }
                }
            }
            Expression::ComputedMemberExpression(m) => {
                deeper(&m.expression, out);
                deeper(&m.object, out);
            }
            other => {
                if let Some(member) = other.as_member_expression() {
                    deeper(member.object(), out);
                }
            }
        }
    }
    walk(expr, out, 0);
}

/// Whether a statement calls `name` (not in a nested function): `return next()`. Too deep to
/// tell counts as a call.
fn statement_calls(statement: &Statement<'_>, name: &str) -> bool {
    fn expr(e: &Expression<'_>, name: &str, depth: usize) -> bool {
        if depth > 64 {
            return true;
        }
        let deeper = |e: &Expression<'_>| expr(e, name, depth + 1);
        let arg = |a: &Argument<'_>| a.as_expression().is_some_and(|e| expr(e, name, depth + 1));
        match e.get_inner_expression() {
            Expression::CallExpression(c) => {
                matches!(c.callee.get_inner_expression(),
                    Expression::Identifier(id) if id.name.as_str() == name)
                    || deeper(&c.callee)
                    || c.arguments.iter().any(arg)
            }
            Expression::SequenceExpression(seq) => seq.expressions.iter().any(deeper),
            Expression::LogicalExpression(l) => deeper(&l.left) || deeper(&l.right),
            Expression::BinaryExpression(b) => deeper(&b.left) || deeper(&b.right),
            Expression::ConditionalExpression(c) => {
                deeper(&c.test) || deeper(&c.consequent) || deeper(&c.alternate)
            }
            Expression::AssignmentExpression(a) => deeper(&a.right),
            Expression::UnaryExpression(u) => deeper(&u.argument),
            Expression::AwaitExpression(a) => deeper(&a.argument),
            Expression::NewExpression(n) => deeper(&n.callee) || n.arguments.iter().any(arg),
            Expression::ArrayExpression(a) => a
                .elements
                .iter()
                .any(|e| e.as_expression().is_some_and(|e| expr(e, name, depth + 1))),
            Expression::TemplateLiteral(t) => t.expressions.iter().any(deeper),
            other => other
                .as_member_expression()
                .is_some_and(|m| deeper(m.object())),
        }
    }
    fn stmt(s: &Statement<'_>, name: &str, depth: usize) -> bool {
        if depth > 64 {
            return true;
        }
        let deeper = |s: &Statement<'_>| stmt(s, name, depth + 1);
        let body = |b: &[Statement<'_>]| b.iter().any(|s| stmt(s, name, depth + 1));
        let e = |x: &Expression<'_>| expr(x, name, depth + 1);
        match s {
            Statement::ExpressionStatement(x) => e(&x.expression),
            Statement::ReturnStatement(r) => r.argument.as_ref().is_some_and(e),
            Statement::ThrowStatement(t) => e(&t.argument),
            Statement::BlockStatement(b) => body(&b.body),
            Statement::IfStatement(i) => {
                e(&i.test) || deeper(&i.consequent) || i.alternate.as_ref().is_some_and(deeper)
            }
            Statement::VariableDeclaration(d) => d
                .declarations
                .iter()
                .any(|d| d.init.as_ref().is_some_and(e)),
            Statement::TryStatement(t) => {
                body(&t.block.body)
                    || t.handler.as_ref().is_some_and(|h| body(&h.body.body))
                    || t.finalizer.as_ref().is_some_and(|f| body(&f.body))
            }
            Statement::SwitchStatement(sw) => {
                e(&sw.discriminant) || sw.cases.iter().any(|c| body(&c.consequent))
            }
            Statement::ForStatement(f) => deeper(&f.body),
            Statement::ForInStatement(f) => deeper(&f.body),
            Statement::ForOfStatement(f) => deeper(&f.body),
            Statement::WhileStatement(w) => e(&w.test) || deeper(&w.body),
            Statement::DoWhileStatement(d) => e(&d.test) || deeper(&d.body),
            Statement::LabeledStatement(l) => deeper(&l.body),
            _ => false,
        }
    }
    stmt(statement, name, 0)
}

/// A mount path written as something other than a string the walker reads: a regex, a list,
/// a configured value (`config.panelPath`, `ADMIN_PREFIX`).
fn looks_like_path(expr: &Expression<'_>) -> bool {
    match expr.get_inner_expression() {
        Expression::RegExpLiteral(_)
        | Expression::ArrayExpression(_)
        | Expression::StringLiteral(_)
        | Expression::TemplateLiteral(_)
        | Expression::BinaryExpression(_) => true,
        other => guards::path_key(other).is_some_and(|key| {
            let last = key.rsplit('.').next().unwrap_or(&key).to_ascii_lowercase();
            m().mount_path_words
                .iter()
                .any(|w| last.contains(w.as_str()))
        }),
    }
}

/// Whether a statement answers 401 or 403 (`return res.status(403).send(..)`).
fn answers_denied(statement: &Statement<'_>) -> bool {
    fn denied(expr: &Expression<'_>, depth: usize) -> bool {
        if depth > 16 {
            return false;
        }
        let Expression::CallExpression(c) = expr.get_inner_expression() else {
            return false;
        };
        let here = c
            .callee
            .get_inner_expression()
            .as_member_expression()
            .and_then(|m| m.static_property_name())
            .and_then(|n| n.as_str())
            .is_some_and(|n| has(&m().auth_denial_methods, n))
            && matches!(
                c.arguments.first(),
                Some(Argument::NumericLiteral(n)) if n.value == 401.0 || n.value == 403.0
            );
        here || c
            .callee
            .get_inner_expression()
            .as_member_expression()
            .is_some_and(|m| denied(m.object(), depth + 1))
    }
    match statement {
        Statement::BlockStatement(b) => b.body.iter().any(answers_denied),
        Statement::ReturnStatement(r) => r.argument.as_ref().is_some_and(|e| denied(e, 0)),
        Statement::ExpressionStatement(e) => denied(&e.expression, 0),
        _ => false,
    }
}

/// The receivers of methods only strings have along a call chain (`email.toLowerCase()`,
/// `name.trim().split(',')`): past the call they were strings, never objects.
fn string_receivers(expr: &Expression<'_>) -> Vec<(String, guards::Fact)> {
    let mut out = Vec::new();
    let mut current = expr.get_inner_expression();
    for _ in 0..16 {
        let Expression::CallExpression(call) = current else {
            break;
        };
        let Some(member) = call.callee.get_inner_expression().as_member_expression() else {
            break;
        };
        if member
            .static_property_name()
            .and_then(|n| n.as_str())
            .is_some_and(|n| has(&m().string_only_methods, n))
            && let Some(key) = guards::path_key(member.object())
        {
            out.push((key, guards::Fact::Scalar));
        }
        current = member.object().get_inner_expression();
    }
    out
}

/// A constant written out: a string, number, boolean, `null`, or a template without
/// substitutions.
fn constant_literal(expr: &Expression<'_>) -> bool {
    match expr.get_inner_expression() {
        Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_) => true,
        Expression::TemplateLiteral(t) => t.expressions.is_empty(),
        Expression::UnaryExpression(u) => {
            u.operator == UnaryOperator::UnaryNegation
                && matches!(
                    u.argument.get_inner_expression(),
                    Expression::NumericLiteral(_)
                )
        }
        _ => false,
    }
}

/// Whether `expr` gives the same value each time it is read in one expression: access paths,
/// constants, and the value-returning methods the packs list as passing their receiver through
/// (`u.split('.').slice(-1)[0].toLowerCase()`), none of which mutates or depends on anything else.
fn deterministic_value(expr: &Expression<'_>) -> bool {
    fn walk(expr: &Expression<'_>, depth: usize) -> bool {
        if depth > 32 {
            return false;
        }
        match expr.get_inner_expression() {
            Expression::Identifier(_) | Expression::ThisExpression(_) => true,
            e if constant_literal(e) => true,
            Expression::StaticMemberExpression(m) => walk(&m.object, depth + 1),
            Expression::ComputedMemberExpression(m) => {
                walk(&m.object, depth + 1) && walk(&m.expression, depth + 1)
            }
            Expression::ChainExpression(chain) => chain
                .expression
                .as_member_expression()
                .is_some_and(|m| walk(m.object(), depth + 1)),
            Expression::CallExpression(call) => {
                let Some(member) = call.callee.get_inner_expression().as_member_expression() else {
                    return false;
                };
                member
                    .static_property_name()
                    .is_some_and(|name| name.as_str().is_some_and(|n| has(&m().pass_methods, n)))
                    && walk(member.object(), depth + 1)
                    && call
                        .arguments
                        .iter()
                        .all(|a| a.as_expression().is_some_and(|e| walk(e, depth + 1)))
            }
            _ => false,
        }
    }
    walk(expr, 0)
}

/// Whether evaluating `expr` calls something (`remember && rememberEmail(res, email)`), whose
/// summary may prove a fact about its arguments; not counting nested functions.
fn has_call(expr: &Expression<'_>) -> bool {
    fn walk(expr: &Expression<'_>, depth: usize) -> bool {
        if depth > 64 {
            return true;
        }
        let deeper = |e: &Expression<'_>| walk(e, depth + 1);
        match expr.get_inner_expression() {
            Expression::CallExpression(_) | Expression::ChainExpression(_) => true,
            Expression::SequenceExpression(seq) => seq.expressions.iter().any(deeper),
            Expression::LogicalExpression(l) => deeper(&l.left) || deeper(&l.right),
            Expression::BinaryExpression(b) => deeper(&b.left) || deeper(&b.right),
            Expression::ConditionalExpression(c) => {
                deeper(&c.test) || deeper(&c.consequent) || deeper(&c.alternate)
            }
            Expression::UnaryExpression(u) => deeper(&u.argument),
            Expression::AwaitExpression(a) => deeper(&a.argument),
            Expression::AssignmentExpression(a) => deeper(&a.right),
            Expression::ArrayExpression(a) => a
                .elements
                .iter()
                .any(|e| e.as_expression().is_some_and(|e| walk(e, depth + 1))),
            Expression::TemplateLiteral(t) => t.expressions.iter().any(deeper),
            other => other
                .as_member_expression()
                .is_some_and(|m| deeper(m.object())),
        }
    }
    walk(expr, 0)
}

/// Whether evaluating `expr` can assign a variable or field (`flag && (x = 'ls')`), not counting
/// nested functions.
fn may_assign(expr: &Expression<'_>) -> bool {
    fn walk(expr: &Expression<'_>, depth: usize) -> bool {
        if depth > 64 {
            return true;
        }
        let deeper = |e: &Expression<'_>| walk(e, depth + 1);
        let arg = |a: &Argument<'_>| a.as_expression().is_some_and(|e| walk(e, depth + 1));
        match expr.get_inner_expression() {
            Expression::AssignmentExpression(_) | Expression::UpdateExpression(_) => true,
            Expression::SequenceExpression(seq) => seq.expressions.iter().any(deeper),
            Expression::LogicalExpression(l) => deeper(&l.left) || deeper(&l.right),
            Expression::BinaryExpression(b) => deeper(&b.left) || deeper(&b.right),
            Expression::ConditionalExpression(c) => {
                deeper(&c.test) || deeper(&c.consequent) || deeper(&c.alternate)
            }
            Expression::UnaryExpression(u) => deeper(&u.argument),
            Expression::AwaitExpression(a) => deeper(&a.argument),
            Expression::CallExpression(c) => deeper(&c.callee) || c.arguments.iter().any(arg),
            Expression::NewExpression(n) => deeper(&n.callee) || n.arguments.iter().any(arg),
            Expression::ArrayExpression(a) => a
                .elements
                .iter()
                .any(|e| e.as_expression().is_some_and(|e| walk(e, depth + 1))),
            Expression::TemplateLiteral(t) => t.expressions.iter().any(deeper),
            other => other
                .as_member_expression()
                .is_some_and(|m| deeper(m.object())),
        }
    }
    walk(expr, 0)
}

/// The names a callee's receiver is built from, outermost first: `input`, `procedure`, `t` for
/// `t.procedure.input(schema).query`; `server`, `this` for `this.server.tool`.
fn receiver_chain(callee: &Expression<'_>) -> Vec<String> {
    let mut names = Vec::new();
    let Some(member) = callee.get_inner_expression().as_member_expression() else {
        return names;
    };
    let mut current = member.object().get_inner_expression();
    for _ in 0..32 {
        match current {
            Expression::Identifier(id) => {
                names.push(id.name.as_str().to_owned());
                break;
            }
            Expression::CallExpression(call) => current = call.callee.get_inner_expression(),
            other => match other.as_member_expression() {
                Some(inner) => {
                    if let Some(name) = inner.static_property_name().and_then(|n| n.as_str()) {
                        names.push(name.to_owned());
                    }
                    current = inner.object().get_inner_expression();
                }
                None => break,
            },
        }
    }
    names
}

/// A call that creates a DOM node (`document.createElement('iframe')`,
/// `host.ownerDocument.createElement('video')`, `template.content.cloneNode(true)`): appending it
/// inserts that node, not markup. Pack names starting with `.` are methods on any receiver.
fn creates_node(expr: &Expression<'_>) -> bool {
    let Expression::CallExpression(c) = expr.get_inner_expression() else {
        return false;
    };
    guards::path_key(&c.callee).is_some_and(|callee| {
        m().node_factories
            .iter()
            .any(|f| *f == callee || (f.starts_with('.') && callee.ends_with(f.as_str())))
    })
}

/// The name of a path part known only at run time: `mount` for `mounts[mount]`, `base` for
/// `config.base`, a variable's own name.
fn runtime_part_name(expr: &Expression<'_>) -> Option<String> {
    match expr.get_inner_expression() {
        Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
        Expression::StaticMemberExpression(member) => {
            Some(member.property.name.as_str().to_owned())
        }
        Expression::ComputedMemberExpression(member) => runtime_part_name(&member.expression),
        _ => None,
    }
}

/// A member chain as written: `FastifyWorker.fastify`, `this.app`, `server.api.router`.
fn member_path(expr: &Expression<'_>) -> Option<String> {
    match expr.get_inner_expression() {
        Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
        Expression::ThisExpression(_) => Some("this".to_owned()),
        Expression::StaticMemberExpression(member) => Some(format!(
            "{}.{}",
            member_path(&member.object)?,
            member.property.name.as_str()
        )),
        _ => None,
    }
}

/// `"--"`: the end of a command's options; what follows is positional.
fn ends_options(expr: Option<&Expression<'_>>) -> bool {
    matches!(
        expr.map(Expression::get_inner_expression),
        Some(Expression::StringLiteral(l)) if l.value.as_str() == Some("--")
    )
}

/// `v.replace(/'/g, "''")` (or `replaceAll("'", "''")`): every single quote doubled.
fn doubles_quotes(arguments: &[Argument<'_>]) -> bool {
    let doubled = matches!(arguments.get(1), Some(Argument::StringLiteral(with)) if with.value.as_str() == Some("''"));
    doubled
        && match arguments.first() {
            Some(Argument::RegExpLiteral(regex)) => {
                regex.regex.pattern.text.as_str() == "'"
                    && regex.regex.flags.contains(oxc_ast::ast::RegExpFlags::G)
            }
            Some(Argument::StringLiteral(quote)) => quote.value.as_str() == Some("'"),
            _ => false,
        }
}

/// `s.replace(/[&<>"']/g, (c) => ESC[c])` or `s.replace(/[<>]/g, lookup)`: a global regex that
/// is one character class holding both `<` and `>`, replaced by what a function or a table
/// gives, never by a literal that brings markup back.
fn escapes_markup(arguments: &[Argument<'_>]) -> bool {
    let Some(Argument::RegExpLiteral(regex)) = arguments.first() else {
        return false;
    };
    if !regex.regex.flags.contains(oxc_ast::ast::RegExpFlags::G) {
        return false;
    }
    let pattern = regex.regex.pattern.text.as_str();
    let Some(inner) = pattern.strip_prefix('[').and_then(|p| p.strip_suffix(']')) else {
        return false;
    };
    if inner.starts_with('^') || !inner.contains('<') || !inner.contains('>') {
        return false;
    }
    match arguments.get(1).and_then(Argument::as_expression) {
        Some(Expression::StringLiteral(with)) => {
            with.value.as_str().is_some_and(|w| !w.contains(['<', '>']))
        }
        Some(
            Expression::ArrowFunctionExpression(_)
            | Expression::FunctionExpression(_)
            | Expression::Identifier(_)
            | Expression::StaticMemberExpression(_),
        ) => true,
        _ => false,
    }
}

/// The class a `: C` type annotation names (a PascalCase type reference).
fn annotated_class(annotation: Option<&oxc_ast::ast::TSTypeAnnotation<'_>>) -> Option<String> {
    let oxc_ast::ast::TSType::TSTypeReference(reference) = &annotation?.type_annotation else {
        return None;
    };
    let oxc_ast::ast::TSTypeName::IdentifierReference(name) = &reference.type_name else {
        return None;
    };
    let name = name.name.as_str();
    name.chars()
        .next()
        .is_some_and(char::is_uppercase)
        .then(|| name.to_owned())
}

/// The handler key and source kind of an object literal that defines an LLM tool: a schema under
/// one of the pack's schema keys (not an array) and a function under a handler key, and none of
/// the keys of a route configuration.
fn tool_object(
    object: &ObjectExpression<'_>,
) -> Option<(&'static str, &'static models::ToolObjectSpec)> {
    m().tool_objects.iter().find_map(|spec| {
        let mut schema = false;
        let mut handler: Option<&'static str> = None;
        for property in &object.properties {
            let ObjectPropertyKind::ObjectProperty(p) = property else {
                continue;
            };
            let Some(key) = prop_name(&p.key) else {
                continue;
            };
            if has(&spec.not_keys, &key) {
                return None;
            }
            let value = p.value.get_inner_expression();
            if has(&spec.schema_keys, &key)
                && matches!(
                    value,
                    Expression::ObjectExpression(_)
                        | Expression::CallExpression(_)
                        | Expression::Identifier(_)
                        | Expression::StaticMemberExpression(_)
                )
            {
                schema = true;
            }
            if matches!(
                value,
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
            ) && let Some(found) = spec.handler_keys.iter().find(|k| **k == key)
            {
                handler = Some(found.as_str());
            }
        }
        handler.filter(|_| schema).map(|h| (h, spec))
    })
}

/// A regular expression: `/a(.*)/` or `new RegExp(...)`.
fn is_regex(expr: &Expression<'_>) -> bool {
    match expr.get_inner_expression() {
        Expression::RegExpLiteral(_) => true,
        Expression::NewExpression(n) => n.callee.is_specific_id("RegExp"),
        Expression::CallExpression(c) => c.callee.is_specific_id("RegExp"),
        _ => false,
    }
}

/// The names a binding pattern declares.
fn pattern_names(pattern: &BindingPattern<'_>, out: &mut BTreeSet<String>) {
    match pattern {
        BindingPattern::BindingIdentifier(id) => {
            out.insert(id.name.as_str().to_owned());
        }
        BindingPattern::ObjectPattern(object) => {
            for property in &object.properties {
                pattern_names(&property.value, out);
            }
            if let Some(rest) = &object.rest {
                pattern_names(&rest.argument, out);
            }
        }
        BindingPattern::ArrayPattern(array) => {
            for element in array.elements.iter().flatten() {
                pattern_names(element, out);
            }
            if let Some(rest) = &array.rest {
                pattern_names(&rest.argument, out);
            }
        }
        BindingPattern::AssignmentPattern(assignment) => pattern_names(&assignment.left, out),
    }
}

/// What a function's walk wrote to names it did not declare: its parent's variables, and
/// fields of its parent's tracked objects (at most 32).
fn closure_writes(inner: &Env, parent: &Env) -> Vec<(String, Option<String>, Origin)> {
    let changed = |before: Option<&Origin>, after: &Origin| {
        before.is_none_or(|b| b.span != after.span || b.steps.len() != after.steps.len())
    };
    let mut writes = Vec::new();
    for (name, origin) in &inner.vars {
        if !inner.locals.contains(name) && changed(parent.vars.get(name), origin) {
            writes.push((name.clone(), None, origin.clone()));
        }
    }
    for (name, fields) in &inner.fields {
        let Some(before) = parent.fields.get(name) else {
            continue;
        };
        if inner.locals.contains(name) {
            continue;
        }
        for (field, origin) in fields {
            if changed(before.get(field), origin) {
                writes.push((name.clone(), Some(field.clone()), origin.clone()));
            }
        }
    }
    writes.truncate(32);
    writes
}

/// What a function returns when called with `arguments`, by its return summaries.
fn summary_returns(
    name: &str,
    summaries: &[Summary],
    arguments: &[Option<Origin>],
    span: Span,
) -> Option<Origin> {
    let mut returned = None;
    for s in summaries.iter().filter(|s| s.api == RETURNS) {
        let origin = if s.param == RETURNS_SOURCE {
            let mut origin = Origin::source(s.at_sink.kind, span);
            origin.object = s.at_sink.object;
            origin.upload = s.at_sink.upload;
            Some(origin)
        } else {
            argument_taint(arguments, s.param, s.rest)
        };
        // A response: only of a URL whose start the caller let the attacker choose.
        let origin = origin
            .filter(|o| !s.start || o.prefix)
            .map(|o| response_of_value(o, s));
        let at = &s.at_sink;
        returned = union(
            returned,
            origin.map(|mut o| {
                o.built |= at.built;
                o.sqlish |= at.sqlish;
                o.htmlish |= at.htmlish;
                o.prefix &= at.prefix;
                o.object &= at.object;
                o.escaped |= at.escaped;
                o.step(span.start, format!("returned by `{name}()`"))
            }),
        );
    }
    returned
}

/// Merges a tuple's position taints into the positions seen so far.
fn merge_positions(merged: &mut Vec<Option<Origin>>, tuple: Vec<Option<Origin>>) {
    for (index, taint) in tuple.into_iter().enumerate() {
        if index >= merged.len() {
            merged.push(taint);
        } else if let Some(slot) = merged.get_mut(index) {
            *slot = union(slot.take(), taint);
        }
    }
}

/// The taint of argument `param`, or for a rest parameter, of every argument from it on.
fn argument_taint(taints: &[Option<Origin>], param: usize, rest: bool) -> Option<Origin> {
    if rest {
        taints
            .iter()
            .skip(param)
            .fold(None, |acc, t| union(acc, t.clone()))
    } else {
        taints.get(param).cloned().flatten()
    }
}

/// Whether `origin` is safe for a sink of `class`: escaped or checked for that class, or for a
/// class the sink lists in `cleared_by`.
fn cleared(origin: &Origin, class: VulnClass, sink: &models::Sink) -> bool {
    origin.escaped & class_bit(class) != 0
        || sink
            .cleared_by
            .iter()
            .any(|other| origin.escaped & class_bit(*other) != 0)
}

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

/// `s.replace(/[^a-z0-9_-]/g, '')`: the classes a value is safe for once only the characters of
/// the negated class remain (`None` if the arguments are no such strip).
fn allowlist_strip(arguments: &[Argument<'_>]) -> Option<u8> {
    let (Some(Argument::RegExpLiteral(regex)), Some(Argument::StringLiteral(replacement))) =
        (arguments.first(), arguments.get(1))
    else {
        return None;
    };
    if replacement.value.as_str() != Some("")
        || !regex.regex.flags.contains(oxc_ast::ast::RegExpFlags::G)
    {
        return None;
    }
    let mut kept = guards::negated_class(regex.regex.pattern.text.as_str())?;
    if regex.regex.flags.contains(oxc_ast::ast::RegExpFlags::I) {
        kept = guards::with_both_cases(kept);
    }
    Some(guards::mask(&kept))
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
        // `path.join('/api', 'users')`; never `require('./users')`, a module.
        Expression::CallExpression(call) if require_spec(expr).is_none() => {
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
/// `name = url.hostname` (a copy of a URL's host) and `name = new URL(s)` (a URL parsed from
/// `s` alone): what a check of the URL's host says about the names it came from.
fn note_url_parts(name: &str, init: &Expression<'_>, env: &mut Env) {
    env.host_alias.remove(name);
    env.url_parsed.remove(name);
    match init.get_inner_expression() {
        Expression::StaticMemberExpression(member)
            if has(&m().url_host_fields, member.property.name.as_str()) =>
        {
            if let Some(object) = guards::path_key(&member.object) {
                env.host_alias.insert(
                    name.to_owned(),
                    format!("{object}.{}", member.property.name.as_str()),
                );
            }
        }
        Expression::NewExpression(n)
            if n.arguments.len() == 1
                && callee_name(&n.callee).is_some_and(|c| has(&m().url_classes, &c)) =>
        {
            if let Some(Expression::Identifier(from)) = n
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .map(Expression::get_inner_expression)
                && from.name.as_str() != name
            {
                env.url_parsed
                    .insert(name.to_owned(), from.name.as_str().to_owned());
            }
        }
        _ => {}
    }
}

/// The names a destructuring assignment writes: `({ file, dir: d } = body)`, `[a, ...b] = xs`.
fn assignment_target_names(target: &AssignmentTarget<'_>, out: &mut Vec<String>) {
    use oxc_ast::ast::{AssignmentTargetMaybeDefault as D, AssignmentTargetProperty as P};
    fn maybe_default(target: &D<'_>, out: &mut Vec<String>) {
        match target {
            D::AssignmentTargetWithDefault(d) => assignment_target_names(&d.binding, out),
            other => {
                if let Some(target) = other.as_assignment_target() {
                    assignment_target_names(target, out);
                }
            }
        }
    }
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(id) => out.push(id.name.as_str().to_owned()),
        AssignmentTarget::ObjectAssignmentTarget(o) => {
            for property in &o.properties {
                match property {
                    P::AssignmentTargetPropertyIdentifier(i) => {
                        out.push(i.binding.name.as_str().to_owned());
                    }
                    P::AssignmentTargetPropertyProperty(p) => maybe_default(&p.binding, out),
                }
            }
            if let Some(rest) = &o.rest {
                assignment_target_names(&rest.target, out);
            }
        }
        AssignmentTarget::ArrayAssignmentTarget(a) => {
            for element in a.elements.iter().flatten() {
                maybe_default(element, out);
            }
            if let Some(rest) = &a.rest {
                assignment_target_names(&rest.target, out);
            }
        }
        _ => {}
    }
}

/// For a call that opens an archive whose library checks every entry's name (yauzl's
/// `open(path, { lazyEntries: true }, (err, zipfile) => ...)`), the callback parameter that
/// receives it; not when the check is turned off (`decodeStrings: false`) or the options are
/// not written out.
fn checked_archive(callee: &Callee, arguments: &[Argument<'_>]) -> Option<usize> {
    let Callee::Module {
        family,
        export: Some(export),
    } = callee
    else {
        return None;
    };
    let spec = m()
        .validated_archives
        .iter()
        .find(|v| v.module == *family && has(&v.exports, export))?;
    let last = arguments.len().checked_sub(1)?;
    for argument in arguments.iter().take(last).skip(1) {
        match argument
            .as_expression()
            .map(Expression::get_inner_expression)
        {
            Some(Expression::ObjectExpression(options)) => {
                let off = options.properties.iter().any(|property| match property {
                    ObjectPropertyKind::ObjectProperty(p) => {
                        prop_name(&p.key).as_deref() == spec.unless_false.as_deref()
                            && !matches!(p.value.get_inner_expression(),
                                Expression::BooleanLiteral(b) if b.value)
                    }
                    ObjectPropertyKind::SpreadProperty(_) => true,
                });
                if off {
                    return None;
                }
            }
            // `open(p, opts, cb)`: options it cannot read.
            _ => return None,
        }
    }
    Some(spec.param)
}

/// An arrow function or a function expression (in parentheses or under a cast too).
fn is_function_value(expr: &Expression<'_>) -> bool {
    matches!(
        expr.get_inner_expression(),
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
    )
}

/// `controller.get`, `authorization.post`: a member named after an HTTP verb, which is a route
/// action of a controller object rather than middleware.
fn is_controller_action(expr: &Expression<'_>) -> bool {
    expr.get_inner_expression()
        .as_member_expression()
        .and_then(|m| m.static_property_name())
        .is_some_and(|p| {
            matches!(
                p.as_str().unwrap_or(""),
                "get" | "post" | "put" | "patch" | "delete"
            )
        })
}

/// A member of a validation namespace whose name only *mentions* an authentication word as part of
/// the operation it validates: `userValidations.completeEmailLogin`. Authentication middleware is
/// named for the guard it performs (`requireLogin`, `verifyToken`, `authRequest`, ...); a validator
/// namespace's ordinary operation callbacks are not guards merely because the operation is a login.
/// Keep explicit guard-shaped leaves eligible for the normal auth model so a project that stores a
/// real `requireLogin` guard under `authValidators` is not downgraded.
fn is_non_guard_validation_member(expr: &Expression<'_>) -> bool {
    let Some(name) = callee_name(expr) else {
        return false;
    };
    let Some((owner, leaf)) = name.rsplit_once('.') else {
        return false;
    };
    let validation_owner = owner.split('.').any(|segment| {
        let lower = segment.to_ascii_lowercase();
        ["validator", "validators", "validation", "validations"]
            .iter()
            .any(|suffix| lower == *suffix || lower.ends_with(suffix))
    });
    if !validation_owner {
        return false;
    }
    let leaf = leaf.to_ascii_lowercase();
    let explicit_guard = [
        "auth",
        "authenticate",
        "authorize",
        "authorise",
        "ensureauth",
        "ensurelogin",
        "haspermission",
        "isadmin",
        "isauthenticated",
        "islogged",
        "loginrequired",
        "protect",
        "require",
        "verifyauth",
        "verifyjwt",
        "verifytoken",
    ]
    .iter()
    .any(|prefix| leaf.starts_with(prefix));
    !explicit_guard
}

/// The top-level functions of a file that return a function they define: `function
/// makeHandler(rt) { return (req, res) => ... }`, `const make = (rt) => (req, res) => ...`
/// (exported or not). The returned closure is walked as part of the factory, so its calls are the
/// factory's own: a server handler made by calling one is reached through the factory.
fn closure_factories(body: &[Statement<'_>]) -> BTreeSet<String> {
    fn is_function(e: &Expression<'_>) -> bool {
        matches!(
            e.get_inner_expression(),
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
        )
    }
    fn returns_function(statements: &[Statement<'_>]) -> bool {
        statements.iter().any(|s| {
            matches!(s, Statement::ReturnStatement(r) if r.argument.as_ref().is_some_and(is_function))
        })
    }
    fn declared(f: &Function<'_>) -> Option<String> {
        let name = f.id.as_ref()?.name.as_str().to_owned();
        returns_function(&f.body.as_ref()?.statements).then_some(name)
    }
    fn bound(d: &VariableDeclaration<'_>, out: &mut BTreeSet<String>) {
        for declarator in &d.declarations {
            let BindingPattern::BindingIdentifier(id) = &declarator.id else {
                continue;
            };
            let factory = match declarator
                .init
                .as_ref()
                .map(Expression::get_inner_expression)
            {
                Some(Expression::ArrowFunctionExpression(f)) => match &f.body {
                    ArrowFunctionBody::FunctionBody(body) => returns_function(&body.statements),
                    other => other.as_expression().is_some_and(is_function),
                },
                Some(Expression::FunctionExpression(f)) => f
                    .body
                    .as_ref()
                    .is_some_and(|b| returns_function(&b.statements)),
                _ => false,
            };
            if factory {
                out.insert(id.name.as_str().to_owned());
            }
        }
    }
    let mut out = BTreeSet::new();
    for statement in body {
        match statement {
            Statement::FunctionDeclaration(f) => out.extend(declared(f)),
            Statement::VariableDeclaration(d) => bound(d, &mut out),
            Statement::ExportDeclaration(e) => match &e.declaration {
                Declaration::FunctionDeclaration(f) => out.extend(declared(f)),
                Declaration::VariableDeclaration(d) => bound(d, &mut out),
                _ => {}
            },
            Statement::ExportDefaultDeclaration(e) => {
                if let ExportDefaultDeclarationKind::FunctionDeclaration(f) = &e.declaration {
                    out.extend(declared(f));
                }
            }
            _ => {}
        }
    }
    out
}

fn callee_name(expr: &Expression<'_>) -> Option<String> {
    callee_name_within(expr, 32)
}

/// [`callee_name`], for at most `budget` segments (a longer chain has no useful name).
fn callee_name_within(expr: &Expression<'_>, budget: usize) -> Option<String> {
    let budget = budget.checked_sub(1)?;
    match expr.get_inner_expression() {
        Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
        Expression::CallExpression(call) => {
            let inner = callee_name_within(&call.callee, budget)?;
            // `passport.authenticate('jwt')`, `requireRole('admin')`: the arguments count too.
            let args: Vec<String> = call
                .arguments
                .iter()
                .filter_map(|a| match a {
                    Argument::StringLiteral(l) => l.value.as_str().map(str::to_owned),
                    _ => None,
                })
                .collect();
            Some(if args.is_empty() {
                inner
            } else {
                format!("{inner} {}", args.join(" "))
            })
        }
        other => other.as_member_expression().and_then(|m| {
            let object = callee_name_within(m.object(), budget).unwrap_or_default();
            let property = m
                .static_property_name()
                .and_then(|p| p.as_str().map(str::to_owned))?;
            Some(format!("{object}.{property}"))
        }),
    }
}

/// The authentication a wrapper call gives the handler it wraps: `withAuth(handler)`,
/// `requireAdmin(async (req) => ...)`. Not a wrapper: none detected.
fn wrapper_auth(expr: &Expression<'_>) -> Auth {
    match expr.get_inner_expression() {
        Expression::CallExpression(call) => callee_name(&call.callee)
            .and_then(|name| m().auth_of(&name))
            .unwrap_or(Auth::NoneDetected),
        _ => Auth::NoneDetected,
    }
}

/// Authentication required by a route's middleware argument. Besides Express-style positional
/// middleware, Fastify accepts lifecycle hooks in an options object:
/// `{ onRequest: [fastify.authenticate] }`.
fn route_middleware_auth(expr: &Expression<'_>) -> Option<Auth> {
    match expr.get_inner_expression() {
        Expression::ArrayExpression(list) => list
            .elements
            .iter()
            .filter_map(ArrayExpressionElement::as_expression)
            .filter_map(route_middleware_auth)
            .max(),
        Expression::ObjectExpression(object) => object
            .properties
            .iter()
            .filter_map(|property| {
                let ObjectPropertyKind::ObjectProperty(property) = property else {
                    return None;
                };
                matches!(
                    prop_name(&property.key).as_deref(),
                    Some("onRequest" | "preValidation" | "preHandler")
                )
                .then(|| route_middleware_auth(&property.value))
                .flatten()
            })
            .max(),
        // Node-RED's `RED.auth.needsPermission(...)` guard is a no-op passthrough unless the
        // operator has configured `adminAuth` in settings.js, which is not the default: the admin
        // HTTP API ships open. Treating it as unconditional authentication would overstate the
        // default deployment's posture, so it adds no requirement of its own.
        _ if is_conditional_permission_guard(expr) => None,
        _ if !is_controller_action(expr) => callee_name(expr)
            .filter(|_| !is_non_guard_validation_member(expr))
            .and_then(|name| m().auth_of(&name))
            .or_else(|| inline_guard_auth(expr)),
        _ => None,
    }
}

/// Whether `expr` is a framework permission guard that is disabled by default: Node-RED's
/// `RED.auth.needsPermission(...)` returns an empty `(req, res, next) => next()` middleware unless
/// `adminAuth` is configured in settings.js (off by default), so by itself it enforces nothing.
fn is_conditional_permission_guard(expr: &Expression<'_>) -> bool {
    let Expression::CallExpression(call) = expr.get_inner_expression() else {
        return false;
    };
    callee_name(&call.callee)
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(".auth.needspermission"))
}

/// Authentication named in a convention-router middleware declaration. Unlike positional route
/// arguments, these declarations may use strings (`["withAuthentication"]`), so string values are
/// middleware names rather than paths.
fn declared_middleware_auth(expr: &Expression<'_>) -> Option<Auth> {
    match expr.get_inner_expression() {
        Expression::StringLiteral(literal) => {
            literal.value.as_str().and_then(|name| m().auth_of(name))
        }
        Expression::ArrayExpression(list) => list
            .elements
            .iter()
            .filter_map(ArrayExpressionElement::as_expression)
            .filter_map(declared_middleware_auth)
            .max(),
        _ => route_middleware_auth(expr),
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

/// `require(name)` with a bare identifier argument (not a string literal) → that identifier.
fn require_arg_ident(expr: &Expression<'_>) -> Option<String> {
    let Expression::CallExpression(call) = expr.get_inner_expression() else {
        return None;
    };
    if !call.callee.is_specific_id("require") {
        return None;
    }
    match call
        .arguments
        .first()?
        .as_expression()?
        .get_inner_expression()
    {
        Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
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

/// The HTTP handler of a module-worker default export (`export default { async fetch(request, env,
/// ctx) {...} }`), as the walker name its `fetch` method is analyzed under (`fetch`), or `None` when
/// the object has no such method. Cloudflare Workers, Deno (`Deno.serve`-style default export) and Bun
/// all serve an HTTP origin by invoking the default export's `fetch(request)` method once per request;
/// the runtime reads nothing else to dispatch, so that one method handles every method and path of the
/// origin. Recognised structurally — a function-valued `fetch` property that takes at least the request
/// parameter — so no runtime package identifier or global is assumed, and a plain data object with a
/// `fetch: url` field is not mistaken for one.
fn module_worker_fetch_handler(object: &ObjectExpression<'_>) -> Option<String> {
    object.properties.iter().find_map(|property| {
        let ObjectPropertyKind::ObjectProperty(p) = property else {
            return None;
        };
        let key = prop_name(&p.key)?;
        if key != "fetch" {
            return None;
        }
        let takes_request = match p.value.get_inner_expression() {
            Expression::FunctionExpression(f) => !f.params.items.is_empty(),
            Expression::ArrowFunctionExpression(f) => !f.params.items.is_empty(),
            _ => return None,
        };
        takes_request.then_some(key)
    })
}

/// The route an Azure Functions v4 HTTP registration serves, as a `"METHOD /path"` entry, or `None`
/// when the call is not such a registration. `app.http('name', { route, methods, handler })` serves
/// the function under the `/api/<route>` prefix the Functions host applies by default, defaulting the
/// route template to the function name and the method to `GET`. A catch-all `{*seg}` slot and a
/// constrained `{seg:int}` slot collapse to a plain `{seg}` the request planner can fill. Recognised
/// structurally — an `http` registration method, a string-literal function name and an options object
/// carrying a `handler` function — so no `@azure/*` package identifier is assumed.
fn azure_http_route(callee: &Callee, arguments: &[Argument<'_>]) -> Option<String> {
    let Callee::Method { method, .. } = callee else {
        return None;
    };
    if method != "http" {
        return None;
    }
    let string_of = |e: &Expression<'_>| match e.get_inner_expression() {
        Expression::StringLiteral(l) => l.value.as_str().map(str::to_owned),
        _ => None,
    };
    let name = arguments
        .first()
        .and_then(Argument::as_expression)
        .and_then(string_of)?;
    let object = arguments.iter().find_map(|a| {
        let expr = a.as_expression()?;
        matches!(expr.get_inner_expression(), Expression::ObjectExpression(_)).then_some(expr)
    })?;
    let has_handler = object_prop(object, &["handler"]).is_some_and(|v| {
        matches!(
            v.get_inner_expression(),
            Expression::ArrowFunctionExpression(_)
                | Expression::FunctionExpression(_)
                | Expression::Identifier(_)
        )
    });
    if !has_handler {
        return None;
    }
    let template = object_prop(object, &["route"])
        .and_then(string_of)
        .unwrap_or(name);
    let verb = object_prop(object, &["methods"])
        .and_then(|v| match v.get_inner_expression() {
            Expression::ArrayExpression(a) => a
                .elements
                .iter()
                .find_map(|e| e.as_expression().and_then(string_of)),
            _ => string_of(v),
        })
        .map(|v| v.to_ascii_uppercase())
        .unwrap_or_else(|| "GET".to_owned());
    Some(format!("{verb} {}", azure_normalize_route(&template)))
}

/// An Azure Functions route template as the HTTP path it is served under: the default `/api` prefix,
/// then the template with each `{*seg}` catch-all and `{seg:constraint}` slot reduced to a plain
/// `{seg}` the planner fills. `chunks/{*filePath}` becomes `/api/chunks/{filePath}`.
fn azure_normalize_route(template: &str) -> String {
    let mut out = String::from("/api/");
    let mut chars = template.trim_start_matches('/').chars().peekable();
    while let Some(c) = chars.next() {
        if c != '{' {
            out.push(c);
            continue;
        }
        out.push('{');
        if chars.peek() == Some(&'*') {
            chars.next();
        }
        while let Some(&n) = chars.peek() {
            if n == '}' {
                break;
            }
            if n == ':' {
                while chars.peek().is_some_and(|&m| m != '}') {
                    chars.next();
                }
                break;
            }
            out.push(n);
            chars.next();
        }
    }
    out
}

/// `GET`, `post`, `Delete`: an HTTP method name, as `router.route('POST', path, h)` takes it.
fn is_http_verb(text: &str) -> bool {
    has(&m().route_verbs, &text.to_ascii_lowercase())
}

/// `prefix` and `path` joined with one `/` between them (`path` alone without a prefix).
fn join_path(prefix: &str, path: &str) -> String {
    if prefix.is_empty() {
        return path.to_owned();
    }
    let joined = format!(
        "{}/{}",
        prefix.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    match joined.trim_end_matches('/') {
        "" => "/".to_owned(),
        trimmed => trimmed.to_owned(),
    }
}

/// A router factory's name: `express.Router`, `Router`, `Hono`.
fn is_router_factory(name: &str) -> bool {
    let last = name.rsplit('.').next().unwrap_or(name);
    has(&m().router_factories, last) || has(&m().router_factories, name)
}

/// Whether an expression is a method chain rooted in a router factory with no variable to name it:
/// `express.Router().use('/x', child).get('/y', h)` or `new Hono().basePath('/api')`. Such a value
/// is typically the module's default export (`export default express.Router()...`); it owns the
/// routes and mounts chained onto it, but has no identifier, so registrations on it would otherwise
/// have no receiver and their mount prefixes could never be joined across files.
fn is_anonymous_router_chain(expr: &Expression<'_>) -> bool {
    let mut current = expr.get_inner_expression();
    for _ in 0..64 {
        match current {
            Expression::CallExpression(call) => {
                if callee_name(&call.callee)
                    .as_deref()
                    .is_some_and(is_router_factory)
                {
                    return true;
                }
                let Some(member) = call.callee.get_inner_expression().as_member_expression() else {
                    return false;
                };
                current = member.object().get_inner_expression();
            }
            Expression::NewExpression(new) => {
                return callee_name(&new.callee)
                    .as_deref()
                    .is_some_and(is_router_factory);
            }
            _ => return false,
        }
    }
    false
}

/// A local name bound to a dynamic `import()` of a one-interpolation template specifier.
#[derive(Debug, Clone)]
struct DynImport {
    /// Literal text before the interpolation (`./apis/v`).
    pre: String,
    /// The single interpolated variable's name (`v`).
    var: String,
    /// Literal text after the interpolation (`/router.js`).
    suf: String,
    /// The export of the loaded module this name binds (`default`, or `*` for the namespace).
    export: String,
}

/// A template literal with exactly one interpolation that is a bare identifier, returned as the
/// text before it, the identifier's name, and the text after it: `` `/api/v${v}` `` ->
/// `("/api/v", "v", "")`. `None` for any other template (no interpolation, several, or a
/// non-identifier like `${v}.${x}`).
fn single_interpolation(expr: &Expression<'_>) -> Option<(String, String, String)> {
    let Expression::TemplateLiteral(t) = expr.get_inner_expression() else {
        return None;
    };
    if t.expressions.len() != 1 || t.quasis.len() != 2 {
        return None;
    }
    let Expression::Identifier(id) = t.expressions.first()?.get_inner_expression() else {
        return None;
    };
    let cooked = |i: usize| -> Option<String> {
        t.quasis
            .get(i)
            .and_then(|q| q.value.cooked)
            .and_then(|c| c.as_str())
            .map(str::to_owned)
    };
    Some((cooked(0)?, id.name.as_str().to_owned(), cooked(1)?))
}

/// The template specifier of a dynamic `import()` (or `await import()`), when it has one
/// interpolation: `await import(`./apis/v${v}/router.js`)` -> `("./apis/v", "v", "/router.js")`.
fn dynamic_import_template(expr: &Expression<'_>) -> Option<(String, String, String)> {
    let inner = match expr.get_inner_expression() {
        Expression::AwaitExpression(a) => a.argument.get_inner_expression(),
        other => other,
    };
    let Expression::ImportExpression(import) = inner else {
        return None;
    };
    single_interpolation(&import.source)
}

/// Root-relative files matching a relative template specifier split around its interpolation, each
/// with the interpolation's concrete value: for `./apis/v` + `/router.js` from `apps/x/routes.js`,
/// `apps/x/apis/v2/router.js` -> `("apps/x/apis/v2/router.js", "2")`. The value never spans a path
/// separator, so `v${v}` matches one directory level, not a deeper tree.
fn interpolated_files(
    file: &str,
    pre: &str,
    suf: &str,
    files: &std::collections::BTreeSet<String>,
) -> Vec<(String, String)> {
    let dir = file.rsplit_once('/').map_or("", |(d, _)| d);
    // Resolve `./` and `../` segments of the pre-part against the importing file's directory.
    let mut segments: Vec<&str> = if dir.is_empty() {
        Vec::new()
    } else {
        dir.split('/').collect()
    };
    let (head, tail) = pre.rsplit_once('/').unwrap_or(("", pre));
    for part in head.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let mut base = segments.join("/");
    if !base.is_empty() {
        base.push('/');
    }
    base.push_str(tail); // The literal start of the interpolated segment (often empty).
    let mut out = Vec::new();
    for candidate in files {
        let Some(rest) = candidate.strip_prefix(&base) else {
            continue;
        };
        let Some(value) = rest.strip_suffix(suf) else {
            continue;
        };
        if value.is_empty() || value.contains('/') {
            continue;
        }
        out.push((candidate.clone(), value.to_owned()));
    }
    out
}

/// What a chain of registrations starts from: `Router()` in `Router().get('/a', h).post(..)`,
/// `app` in `app.route('/book').get(h)`, `new Hono()` in `new Hono().basePath('/api')`.
fn chain_root<'e, 'a>(expr: &'e Expression<'a>) -> &'e Expression<'a> {
    let model = m();
    let mut current = expr.get_inner_expression();
    for _ in 0..32 {
        let Expression::CallExpression(call) = current else {
            break;
        };
        let Some(member) = call.callee.get_inner_expression().as_member_expression() else {
            break;
        };
        let Some(method) = member.static_property_name().and_then(|n| n.as_str()) else {
            break;
        };
        if !(has(&model.route_methods, method)
            || has(&model.route_chain_methods, method)
            || has(&model.route_prefix_methods, method))
        {
            break;
        }
        current = member.object().get_inner_expression();
    }
    current
}

/// The arguments of the prefix-setting links of a chain, innermost first:
/// `'/api'` in `new Hono().basePath('/api')`.
fn chain_prefixes<'e, 'a>(expr: &'e Expression<'a>) -> Vec<&'e Expression<'a>> {
    let model = m();
    let mut found = Vec::new();
    let mut current = expr.get_inner_expression();
    for _ in 0..32 {
        let Expression::CallExpression(call) = current else {
            break;
        };
        let Some(member) = call.callee.get_inner_expression().as_member_expression() else {
            break;
        };
        let Some(method) = member.static_property_name().and_then(|n| n.as_str()) else {
            break;
        };
        if has(&model.route_prefix_methods, method)
            && let [
                Argument::StringLiteral(_)
                | Argument::TemplateLiteral(_)
                | Argument::Identifier(_)
                | Argument::StaticMemberExpression(_),
            ] = call.arguments.as_slice()
            && let Some(argument) = call.arguments.first().and_then(Argument::as_expression)
        {
            found.push(argument);
        } else if !(has(&model.route_methods, method) || has(&model.route_chain_methods, method)) {
            break;
        }
        current = member.object().get_inner_expression();
    }
    found.reverse();
    found
}

/// The values a callback is about to be called with: an element of the receiver, the initial
/// value of an accumulator (see [`models::CallbackSpec`]).
struct PendingElement {
    element: Option<Origin>,
    initial: Option<Origin>,
    spec: models::CallbackSpec,
    /// The element is a tuple with these taints by position (`([key, value]) => ...`).
    positions: Option<Vec<Option<Origin>>>,
}

/// A route registration in one of the shapes beyond `router.get(path, handler)`.
struct Registration {
    receiver: Option<String>,
    method: String,
    paths: Vec<String>,
}

// The AST walk is implemented in `taint/walker.rs`; this module owns its shared IR.
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
mod tests;
