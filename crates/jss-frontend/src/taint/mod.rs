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

use jss_core::{Severity, VulnClass};
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, ArrowFunctionBody, AssignmentTarget, BindingPattern,
    CallExpression, Class, ClassElement, Declaration, ExportDefaultDeclarationKind, Expression,
    ForStatementInit, ForStatementLeft, FormalParameters, Function, ModuleDeclaration,
    ObjectPropertyKind, Program, PropertyKey, Statement, VariableDeclaration,
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
}

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
}

/// A sink in another file, already resolved to a location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtSink {
    pub file: String,
    pub line: u32,
    pub col: u32,
    pub arg: String,
    /// The helper's own steps, as text.
    pub steps: Vec<String>,
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
}

/// Scans a parsed program on its own.
#[cfg(test)]
fn scan_program(program: &Program<'_>, _text: &str) -> ScanResult {
    scan_program_with(program, &Summaries::new())
}

/// Scans a parsed program, with summaries of the repository's other files.
pub fn scan_program_with(program: &Program<'_>, external: &Summaries) -> ScanResult {
    let mut walker = Walker {
        external,
        field_of: BTreeMap::new(),
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
        let mut env = Env::new("<module>".to_owned());
        walker.statements(&program.body, &mut env);
    }
    walker.summarize = false;
    walker.modules.clear();
    walker.result = ScanResult {
        findings: Vec::new(),
        truncated: walker.result.truncated,
        summaries: Summaries::new(),
    };
    let mut env = Env::new("<module>".to_owned());
    walker.statements(&program.body, &mut env);
    let mut result = walker.result;
    result.summaries = walker.summaries;
    result
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
    /// Variables bound to an object literal: the taint of each field.
    fields: BTreeMap<String, BTreeMap<String, Origin>>,
    /// Access paths a guard validated: no longer tainted.
    clean: BTreeSet<String>,
    /// Access paths a guard proved scalar: never an object.
    scalars: BTreeSet<String>,
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
            clean: BTreeSet::new(),
            scalars: BTreeSet::new(),
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
            clean: self.clean.clone(),
            scalars: self.scalars.clone(),
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
    /// Summary pass: the field each destructured parameter source stands for, by span start.
    field_of: BTreeMap<u32, String>,
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
            ..a
        }),
        (a, b) => a.or(b),
    }
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
                    self.expr(argument, env);
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
                if spec.starts_with('.') {
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
            ModuleDeclaration::ExportDeclaration(export) => match &export.declaration {
                Declaration::FunctionDeclaration(f) => {
                    let name = f.id.as_ref().map(|id| id.name.as_str().to_owned());
                    let role = if name.as_deref().is_some_and(|n| has(&m().route_exports, n)) {
                        Role::Route
                    } else {
                        Role::Plain
                    };
                    self.function(f, env, name, role);
                }
                Declaration::VariableDeclaration(d) => self.var_decl(d, env),
                Declaration::ClassDeclaration(c) => self.class(c, env),
                _ => {}
            },
            ModuleDeclaration::ExportDefaultDeclaration(export) => match &export.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
                    let name = f.id.as_ref().map(|id| id.name.as_str().to_owned());
                    self.function(f, env, name, Role::Plain);
                }
                ExportDefaultDeclarationKind::ClassDeclaration(c) => self.class(c, env),
                other => {
                    if let Some(expr) = other.as_expression() {
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
            let taint = self.expr_named(init, env, name_hint.clone());
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
        if spec.starts_with('.') {
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
                                param: None,
                                object: true,
                            })
                        }
                        (Some(_), _) => None,
                        (None, _) => taint.clone(),
                    };
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
        for element in &class.body.body {
            match element {
                ClassElement::MethodDefinition(method) => {
                    let name = prop_name(&method.key).map(|key| match &class_name {
                        Some(class) => format!("{class}.{key}"),
                        None => key,
                    });
                    self.function(&method.value, env, name, Role::Plain);
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
    }

    // ----- functions --------------------------------------------------------------------

    fn function(&mut self, f: &Function<'_>, parent: &Env, name: Option<String>, role: Role) {
        let Some(body) = &f.body else {
            return;
        };
        let mut env = self.enter_function(&f.params, parent, name, role);
        if self.enter() {
            self.statements(&body.statements, &mut env);
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
                    param: Some(index),
                    object: true,
                };
                self.bind_pattern(&param.pattern, Some(origin), None, &mut env);
            }
        }
        match role {
            Role::Client(kind, selected) => {
                for (index, (param, name)) in params.items.iter().zip(&names).enumerate() {
                    if !selected.wants(index) {
                        continue;
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
                let conventional = first.is_some_and(|n| has(&model.request_names, n))
                    && (names.len() >= 2 || role == Role::Route);
                if let Some(first) = first {
                    if has(&model.context_names, first) && (role == Role::Route || names.len() <= 2)
                    {
                        // Koa: the context is the request too.
                        env.requests.insert(first.to_owned(), "http");
                    } else if role == Role::Route
                        && names.len() == 1
                        && has(&model.hono_context_names, first)
                    {
                        // Hono: request data is under `c.req`; `c` itself is context.
                        env.requests.insert(first.to_owned(), CONTEXT);
                    } else if conventional || (role == Role::Route && names.len() >= 2) {
                        env.requests.insert(first.to_owned(), "http");
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
            ArrowFunctionBody::FunctionBody(body) => self.statements(&body.statements, &mut env),
            other => {
                if let Some(expr) = other.as_expression() {
                    self.expr(expr, &mut env);
                }
            }
        }
        self.leave();
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
                let a = self.expr(&c.consequent, env);
                let b = self.expr(&c.alternate, env);
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
                let name = match &assign.left {
                    AssignmentTarget::AssignmentTargetIdentifier(id) => {
                        Some(id.name.as_str().to_owned())
                    }
                    target => target
                        .as_simple_assignment_target()
                        .and_then(|t| t.as_member_expression())
                        .and_then(|m| m.static_property_name())
                        .and_then(|n| n.as_str().map(str::to_owned)),
                };
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
                                            self.maybe_function(&f.value, env, field_name, role);
                                        }
                                    }
                                    None
                                }
                                _ => self.expr_named(&p.value, env, name),
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
                let mut taints = Vec::new();
                for argument in &new.arguments {
                    taints.push(self.argument(argument, env, Role::Plain));
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
                None
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
            _ => None,
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
                            },
                            env,
                        );
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
                param: None,
                object: property
                    .as_deref()
                    .is_some_and(|p| has(&m().object_props, p)),
            });
        }
        // tRPC: `opts.input`
        if let (Expression::Identifier(id), Some(field)) = (object, property.as_deref())
            && has(&m().input_fields, field)
            && let Some(kind) = env.inputs.get(id.name.as_str())
        {
            return Some(Origin::source(kind, member.span()));
        }
        // Pack member sources: `process.argv`.
        if let (Expression::Identifier(id), Some(property)) = (object, property.as_deref())
            && let Some(source) = m()
                .member_sources
                .iter()
                .find(|s| s.object == id.name.as_str() && s.property == property)
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
        // A field of an object literal we tracked: only that field's taint.
        if let (Expression::Identifier(id), Some(property)) = (object, property.as_deref())
            && let Some(fields) = env.fields.get(id.name.as_str())
        {
            return fields.get(property).cloned();
        }
        // Any property of a tainted object is tainted.
        self.expr(member.object(), env)
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
        let (role, shape) = self.client_role(&callee, call, env);
        let route_name = match (&callee, call.arguments.first()) {
            (Callee::Method { method, .. }, Some(Argument::StringLiteral(path)))
                if role == Role::Route =>
            {
                Some(format!(
                    "{} {}",
                    method.to_ascii_uppercase(),
                    path.value.as_str().unwrap_or("?")
                ))
            }
            _ => None,
        };
        let last = call.arguments.len().saturating_sub(1);
        let mut taints = Vec::with_capacity(call.arguments.len());
        for (index, argument) in call.arguments.iter().enumerate() {
            let arg_role = match shape {
                Shape::LastCallback if index != last => Role::Plain,
                Shape::ObjectOfFunctions => Role::Plain,
                _ => role,
            };
            let callbacks_object = matches!(shape, Shape::ObjectOfFunctions | Shape::RouteObject)
                && matches!(
                    argument
                        .as_expression()
                        .map(Expression::get_inner_expression),
                    Some(Expression::ObjectExpression(_))
                );
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

        // Sinks.
        let sink = match &callee {
            Callee::Module { family, export } => {
                m().module_sink(family, export.as_deref().unwrap_or(""))
            }
            Callee::Global(name) => m().global_sink(name),
            Callee::Method { method, .. } => m().method_sink(method),
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

        // Same-file helpers whose parameters reach a sink.
        let helper = match &callee {
            Callee::Global(name) => self.summaries.get(name).map(|s| (name.clone(), s.clone())),
            Callee::Method { method, .. } if !method.is_empty() => {
                let suffix = format!(".{method}");
                let mut matching = self.summaries.iter().filter(|(k, _)| k.ends_with(&suffix));
                match (matching.next(), matching.next()) {
                    (Some((k, s)), None) => Some((k.clone(), s.clone())),
                    _ => None,
                }
            }
            _ => None,
        };
        // Then other files of the repository, by unique name.
        // Only through a relative import, and only to the file that import names.
        let linked = match &callee {
            Callee::Global(name) => self
                .relative
                .get(name)
                .and_then(|(spec, export)| export.clone().map(|e| (spec.clone(), e))),
            Callee::Method {
                object: Some(object),
                method,
            } if !method.is_empty() => self
                .relative
                .get(object)
                .filter(|(_, export)| export.is_none())
                .map(|(spec, _)| (spec.clone(), method.clone())),
            _ => None,
        };
        let helper = helper.or_else(|| {
            let (spec, name) = linked?;
            let suffix = format!(".{name}");
            let mut matching = self.external.iter().filter(|(k, list)| {
                (**k == name || k.ends_with(&suffix))
                    && list.iter().any(|s| {
                        s.ext
                            .as_ref()
                            .is_some_and(|e| spec_names_file(&spec, &e.file))
                    })
            });
            match (matching.next(), matching.next()) {
                (Some((k, list)), None) => Some((
                    k.clone(),
                    list.iter()
                        .filter(|s| {
                            s.ext
                                .as_ref()
                                .is_some_and(|e| spec_names_file(&spec, &e.file))
                        })
                        .cloned()
                        .collect::<Vec<_>>(),
                )),
                _ => None,
            }
        });
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
                            param: None,
                            object: true,
                        })
                    })
                    .collect();
                self.apply_summaries(&name, &summaries, &synthetic, None, call.span, env);
            }
        }

        // Result taint.
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
                        param: None,
                        object: true,
                    });
                }
                // Pack result sources: `zip.getEntries()`.
                if let Some(source) = m().result_sources.iter().find(|s| has(&s.methods, method)) {
                    return Some(Origin::source(source.kind.as_str(), call.span));
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
                        o.step(call.span.start, format!("through {name}()"))
                    });
                }
                None
            }
        }
    }

    /// How a call's function arguments are entered, from the packs' route, socket and
    /// client-source conventions.
    fn client_role(&self, callee: &Callee, call: &CallExpression<'_>, env: &Env) -> (Role, Shape) {
        let model = m();
        let event = match call.arguments.first() {
            Some(Argument::StringLiteral(lit)) => lit.value.as_str(),
            _ => None,
        };
        let (object, method) = match callee {
            Callee::Method { object, method } => (object.as_deref(), method.as_str()),
            Callee::Global(name) => (None, name.as_str()),
            Callee::Module { export, .. } => (None, export.as_deref().unwrap_or("")),
        };
        // The property the receiver was read from: `chrome.runtime.onMessage.addListener`.
        let via = call
            .callee
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
            {
                continue;
            }
            let params = Params::parse(&source.params);
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
        if let Callee::Method { .. } = callee {
            if has(&model.route_object_methods, method)
                && matches!(
                    call.arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .map(Expression::get_inner_expression),
                    Some(Expression::ObjectExpression(_))
                )
            {
                return (Role::Plain, Shape::RouteObject);
            }
            if has(&model.route_methods, method) && call.arguments.len() >= 2 {
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
        for summary in summaries {
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
                },
                env,
            );
        }
    }

    /// Records a finding, or in the summary pass, a summary of a parameter that reaches a sink.
    fn emit(&mut self, mut finding: RawFinding, env: &Env) {
        // The CLI is the user's own machine: never above low.
        finding.severity = m().cap(finding.origin.kind, finding.severity);
        match (self.summarize, finding.origin.param) {
            (true, Some(param)) => {
                let list = self.summaries.entry(env.function.clone()).or_default();
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
        for rule in rules {
            let (index, origin) = match rule {
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
                    taints
                        .get(index)
                        .cloned()
                        .flatten()
                        .filter(|o| o.built && o.sqlish),
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
            // The CLI is the user's own machine: never above low.
            let severity = m().cap(origin.kind, severity);
            let Some(arg) = arguments.get(index) else {
                continue;
            };
            self.emit(
                RawFinding {
                    class: sink.class,
                    severity,
                    api: api.clone(),
                    arg: arg.span(),
                    call: span,
                    function: env.function.clone(),
                    origin,
                    ext: None,
                },
                env,
            );
            break;
        }
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
