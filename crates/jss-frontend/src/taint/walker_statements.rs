use super::*;

impl Walker<'_> {
    /// Enters one recursion level; false when the cap is reached.
    pub(super) fn enter(&mut self) -> bool {
        if self.depth >= MAX_DEPTH {
            self.result.truncated = true;
            return false;
        }
        self.depth += 1;
        true
    }

    pub(super) fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    // ----- statements -------------------------------------------------------------------

    pub(super) fn statements(&mut self, statements: &[Statement<'_>], env: &mut Env) {
        for statement in statements {
            self.statement(statement, env);
        }
    }

    pub(super) fn branch(&mut self, statement: &Statement<'_>, env: &mut Env) {
        env.branch += 1;
        self.statement(statement, env);
        env.branch -= 1;
    }

    pub(super) fn statement(&mut self, statement: &Statement<'_>, env: &mut Env) {
        if !self.enter() {
            return;
        }
        self.statement_inner(statement, env);
        self.leave();
    }

    pub(super) fn statement_inner(&mut self, statement: &Statement<'_>, env: &mut Env) {
        match statement {
            Statement::ExpressionStatement(s) => {
                self.expr(&s.expression, env);
                // `email = email.trim()`, `name.toLowerCase();`: those receivers were strings.
                // Not `name ||= email.trim()`, which runs only when `name` is falsy.
                let value = match s.expression.get_inner_expression() {
                    Expression::AssignmentExpression(a)
                        if matches!(
                            a.operator,
                            AssignmentOperator::LogicalOr
                                | AssignmentOperator::LogicalAnd
                                | AssignmentOperator::LogicalNullish
                        ) =>
                    {
                        None
                    }
                    Expression::AssignmentExpression(a) => Some(&a.right),
                    other => Some(other),
                };
                if let Some(value) = value {
                    env.learn(string_receivers(value));
                }
                // `check(x, String)`, `assertSafe(x)`: past this line, the assertion held.
                let mut asserted = Vec::new();
                guards::assertion(statement, &mut asserted);
                env.learn(asserted);
            }
            Statement::VariableDeclaration(d) => {
                self.var_decl(d, env);
                // `const emailLowerCase = email.toLowerCase()`: `email` was a string.
                for declarator in &d.declarations {
                    if let Some(init) = &declarator.init {
                        env.learn(string_receivers(init));
                    }
                }
            }
            Statement::FunctionDeclaration(f) => {
                let name = f.id.as_ref().map(|id| id.name.as_str().to_owned());
                if let Some(name) = &name {
                    env.locals.insert(name.clone());
                }
                match name.as_deref().filter(|n| is_es5_constructor(n, f)) {
                    Some(class) => {
                        let class = class.to_owned();
                        self.es5_constructor(f, env, &class);
                    }
                    None => {
                        if let Some(name) = &name {
                            self.declare_function(name, None);
                        }
                        self.declaring = name.is_some();
                        self.function(f, env, name, Role::Plain);
                        self.declaring = false;
                    }
                }
            }
            Statement::ClassDeclaration(c) => self.class(c, env),
            // `interface Store { get(id) }`: a type receivers are annotated with, dispatched to
            // the classes implementing it.
            Statement::TSInterfaceDeclaration(i) => {
                self.declared_classes.insert(i.id.name.as_str().to_owned());
            }
            Statement::BlockStatement(b) => self.statements(&b.body, env),
            Statement::IfStatement(s) => {
                self.expr(&s.test, env);
                // Inside the consequent, the test held; inside the alternate, it failed.
                let mut held = Vec::new();
                guards::facts(&s.test, true, &mut held);
                self.predicate_facts(&s.test, true, &mut held);
                let mut failed = Vec::new();
                guards::facts(&s.test, false, &mut failed);
                self.predicate_facts(&s.test, false, &mut failed);
                let before = env.save();
                env.learn(held);
                self.branch(&s.consequent, env);
                let consequent_exits = guards::exits(&s.consequent);
                // `if (!req.user) return res.status(401)...`: past here, the caller is logged in.
                if consequent_exits && let Some(level) = self.requires_login(&s.test, env) {
                    env.auth = env.auth.max(level);
                }
                let then_path = env.save();
                // The other path starts where the test was evaluated, not where the
                // consequent ended.
                env.restore(before);
                env.learn(failed);
                if let Some(alternate) = &s.alternate {
                    self.branch(alternate, env);
                }
                let alternate_exits = s.alternate.as_ref().is_some_and(guards::exits);
                match (consequent_exits, alternate_exits) {
                    // `if (!valid(x)) return;`: only the other path goes on.
                    (true, _) => {}
                    (false, true) => env.restore(then_path),
                    (false, false) => env.join_with(&then_path),
                }
                // `if (!doc) return` after `const doc = docs.find((d) => d.name === name)`, or
                // `if (!docs.some((d) => d.name === name)) return`: `name` is the server's.
                if consequent_exits
                    && let Expression::UnaryExpression(u) = s.test.get_inner_expression()
                    && u.operator == UnaryOperator::LogicalNot
                {
                    let value = match u.argument.get_inner_expression() {
                        Expression::Identifier(id) => env.found_by.get(id.name.as_str()).cloned(),
                        Expression::CallExpression(c) => lookup_value(c, env),
                        _ => None,
                    };
                    if let Some(value) = value {
                        env.learn(vec![(value, guards::Fact::Clean(guards::ALL))]);
                    }
                }
            }
            Statement::ReturnStatement(s) => {
                if let Some(argument) = &s.argument {
                    let taint = self.expr(argument, env);
                    self.fn_returns = union(self.fn_returns.take(), taint.clone());
                    self.record_returned(argument, taint, env);
                    // `return router`: a factory's product (for mounts of `require('./x')()`).
                    if let Expression::Identifier(id) = argument.get_inner_expression() {
                        self.facts
                            .returned_locals
                            .entry(env.function.clone())
                            .or_insert_with(|| id.name.as_str().to_owned());
                    }
                    // `return function mcpProxy(req, res) { ... }`: a middleware factory's
                    // product — the request handler it returns, named so it is its own function.
                    // Recorded like a returned router so a `app.use(path, factory())` registration
                    // can be linked to the handler the factory returns (not a sub-router).
                    if let Expression::FunctionExpression(f) = argument.get_inner_expression()
                        && let Some(id) = &f.id
                    {
                        self.facts
                            .returned_locals
                            .entry(env.function.clone())
                            .or_insert_with(|| id.name.as_str().to_owned());
                    }
                    // `return require(spec)` / `return routeModule` where `routeModule =
                    // require(spec)`: a module-loading wrapper, keyed by the parameter it loads.
                    if let Some(index) = self.require_of_param(argument, env).or_else(|| {
                        match argument.get_inner_expression() {
                            Expression::Identifier(id) => {
                                env.require_params.get(id.name.as_str()).copied()
                            }
                            _ => None,
                        }
                    }) {
                        self.require_wrappers.insert(env.function.clone(), index);
                    }
                }
            }
            Statement::ThrowStatement(s) => {
                self.expr(&s.argument, env);
            }
            Statement::TryStatement(s) => {
                let before = env.save();
                env.branch += 1;
                self.statements(&s.block.body, env);
                if let Some(handler) = &s.handler {
                    if let Some(param) = &handler.param {
                        pattern_names(&param.pattern, &mut env.locals);
                    }
                    let after_try = env.save();
                    // The handler runs when the block threw: what the block established (a
                    // throwing check) does not hold there.
                    env.clean.retain(|k| before.clean.contains(k));
                    env.scalars.retain(|k| before.scalars.contains(k));
                    env.partial.retain(|k, _| before.partial.contains_key(k));
                    // Nor what it did to a value (`email.toLowerCase()` proved a string): each is
                    // at the weaker of its states before and after the block.
                    for (name, origin) in &before.vars {
                        match env.vars.get_mut(name) {
                            Some(current) => join(current, origin),
                            None => {
                                env.vars.insert(name.clone(), origin.clone());
                            }
                        }
                    }
                    self.statements(&handler.body.body, env);
                    let handler_exits = handler.body.body.last().is_some_and(guards::exits);
                    if handler_exits {
                        // `try { assertSafe(x) } catch { return 400 }`: only the block's path
                        // goes on.
                        env.restore(after_try);
                    } else {
                        env.join_with(&after_try);
                    }
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
                let before = env.save();
                self.jumps.push(Vec::new());
                self.statement(&s.body, env);
                self.land_jumps(env);
                env.join_with(&before);
                env.branch -= 1;
            }
            Statement::ForOfStatement(s) => {
                let positions = self.tuple_positions(&s.right, env);
                let taint = self.expr(&s.right, env);
                env.branch += 1;
                let before = env.save();
                // `for (const [key, value] of Object.entries(o))`: each position its own taint.
                let tuple_pattern = match &s.left {
                    ForStatementLeft::VariableDeclaration(d) if d.declarations.len() == 1 => {
                        match d.declarations.first().map(|declarator| &declarator.id) {
                            Some(BindingPattern::ArrayPattern(array)) => Some(array),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                match (tuple_pattern, positions) {
                    (Some(array), Some(positions)) => self.bind_positions(array, &positions, env),
                    _ => self.for_left(&s.left, taint, env),
                }
                self.jumps.push(Vec::new());
                self.statement(&s.body, env);
                self.land_jumps(env);
                env.join_with(&before);
                env.branch -= 1;
                // `for (const r of routes) router[r.method](r.path, r.handler)`: one record-only
                // walk per known row.
                // Not inside another row walk: nested table loops would multiply the walks.
                if !self.summarize
                    && !self.record_only
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
                        // A row walk's jumps land in its own copy, which is dropped.
                        self.jumps.push(Vec::new());
                        self.statement(&s.body, &mut inner);
                        self.jumps.pop();
                        self.record_only = saved;
                    }
                }
            }
            Statement::ForInStatement(s) => {
                // Keys of a tainted object are attacker-chosen too (not an object literal's).
                let taint = self.expr(&s.right, env);
                let taint = self.keys_taint(&s.right, taint.as_ref(), env);
                env.branch += 1;
                let before = env.save();
                self.for_left(&s.left, taint, env);
                self.jumps.push(Vec::new());
                self.statement(&s.body, env);
                self.land_jumps(env);
                env.join_with(&before);
                env.branch -= 1;
            }
            Statement::WhileStatement(s) => {
                self.expr(&s.test, env);
                let before = env.save();
                self.jumps.push(Vec::new());
                self.branch(&s.body, env);
                self.land_jumps(env);
                env.join_with(&before);
            }
            Statement::DoWhileStatement(s) => {
                let before = env.save();
                self.jumps.push(Vec::new());
                self.branch(&s.body, env);
                self.land_jumps(env);
                env.join_with(&before);
                self.expr(&s.test, env);
            }
            Statement::SwitchStatement(s) => {
                self.expr(&s.discriminant, env);
                env.branch += 1;
                // Each case starts from the state after the discriminant; what one case
                // established does not hold in another, nor after the switch.
                let before = env.save();
                let mut paths: Vec<PathState> = Vec::new();
                self.jumps.push(Vec::new());
                for case in &s.cases {
                    env.restore(before.clone());
                    if let Some(test) = &case.test {
                        self.expr(test, env);
                    }
                    self.statements(&case.consequent, env);
                    paths.push(env.save());
                }
                env.restore(before.clone());
                for path in &paths {
                    env.join_with(path);
                }
                self.land_jumps(env);
                env.branch -= 1;
            }
            // `if (k) { x = req.query.c; break; }`: this path goes on where the jump lands.
            Statement::BreakStatement(_) | Statement::ContinueStatement(_) => {
                let state = env.save();
                if let Some(frame) = self.jumps.last_mut() {
                    frame.push(state);
                }
            }
            Statement::LabeledStatement(s) => {
                let before = env.save();
                self.jumps.push(Vec::new());
                self.statement(&s.body, env);
                self.land_jumps(env);
                env.join_with(&before);
            }
            // TypeScript `import shell = require('./shell')`: as `const shell = require(...)`.
            Statement::TSImportEqualsDeclaration(decl) => {
                if let oxc_ast::ast::TSModuleReference::ExternalModuleReference(external) =
                    &decl.module_reference
                    && let Some(spec) = external.expression.value.as_str()
                    && self.linking.is_own(spec)
                {
                    self.relative
                        .insert(decl.id.name.as_str().to_owned(), (spec.to_owned(), None));
                }
            }
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

    pub(super) fn module_decl(&mut self, module: &ModuleDeclaration<'_>, env: &mut Env) {
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
                    match &export.exported {
                        // `export * as users from './users'`: a namespace.
                        Some(name) => {
                            self.facts.exports.insert(
                                name.name().as_str().to_owned(),
                                format!("{NAMESPACE}{target}"),
                            );
                        }
                        None => self.facts.reexports.push(target),
                    }
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
                    let exported = specifier.exported.name().as_str().to_owned();
                    let local = specifier.local.name().as_str().to_owned();
                    // `export { handler as GET, handler as POST }` (NextAuth, tRPC adapters).
                    if has(&m().route_exports, &exported) {
                        self.facts.routes.push(RouteFact {
                            at: None,
                            receiver: None,
                            receiver_file: None,
                            method: exported.clone(),
                            path: String::new(),
                            handler: local.clone(),
                            span: specifier.span,
                            auth: Auth::NoneDetected,
                            kind: "file-route",
                        });
                    }
                    self.facts.exports.insert(exported, local);
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
                            at: None,
                            receiver: None,
                            receiver_file: None,
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
                                    at: None,
                                    receiver: None,
                                    receiver_file: None,
                                    method: name.clone(),
                                    path: String::new(),
                                    handler: name.clone(),
                                    span: declarator.span,
                                    // `export const GET = withAuth(async (req) => ...)`
                                    auth: declarator
                                        .init
                                        .as_ref()
                                        .map_or(Auth::NoneDetected, wrapper_auth),
                                    kind: "file-route",
                                });
                            }
                            // `export const getRegistry = Registry.getInstance`
                            let local = declarator
                                .init
                                .as_ref()
                                .and_then(|init| self.member_export(init))
                                .unwrap_or_else(|| name.clone());
                            self.facts.exports.insert(name.clone(), local);
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
                Declaration::TSInterfaceDeclaration(i) => {
                    self.declared_classes.insert(i.id.name.as_str().to_owned());
                }
                _ => {}
            },
            ModuleDeclaration::ExportDefaultDeclaration(export) => match &export.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
                    let name = f.id.as_ref().map(|id| id.name.as_str().to_owned());
                    self.facts.exports.insert(
                        "default".to_owned(),
                        name.clone().unwrap_or_else(|| "<default>".to_owned()),
                    );
                    // A default-exported `(req, res)` handler (Next.js `pages/api`), or a
                    // single-argument web handler (`export default function handler(request)`) of a
                    // filesystem-routed function — a Vercel/Netlify edge function or a `pages/api`
                    // edge route — where the file's location gives the path.
                    if f.params.items.len() >= 2
                        || (f.params.items.len() == 1
                            && crate::routes::file_route_path(self.linking.file, "default-export")
                                .is_some())
                    {
                        self.facts.routes.push(RouteFact {
                            at: None,
                            receiver: None,
                            receiver_file: None,
                            method: "ANY".to_owned(),
                            path: String::new(),
                            handler: name.clone().unwrap_or_else(|| "<default>".to_owned()),
                            span: f.span,
                            auth: Auth::NoneDetected,
                            kind: "default-export",
                        });
                    }
                    // An anonymous one goes by `<default>`, the name its export points at.
                    let walked = name.or_else(|| Some("<default>".to_owned()));
                    self.function(f, env, walked, Role::Plain);
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
                        // Cloudflare/Deno/Bun module worker: `export default { fetch(request, env,
                        // ctx) {...} }`. The runtime serves the whole HTTP origin by invoking the
                        // default export's `fetch` method per request, so that method is the entry
                        // point for every path and method.
                        if let Expression::ObjectExpression(object) = expr.get_inner_expression()
                            && let Some(handler) = module_worker_fetch_handler(object)
                            && !self.summarize
                            && !self.record_only
                        {
                            self.facts.routes.push(RouteFact {
                                at: None,
                                receiver: None,
                                receiver_file: None,
                                method: "ANY".to_owned(),
                                path: "/".to_owned(),
                                handler,
                                span: expr.span(),
                                auth: Auth::NoneDetected,
                                kind: "http",
                            });
                        }
                        match expr.get_inner_expression() {
                            Expression::Identifier(id) => {
                                self.facts
                                    .exports
                                    .insert("default".to_owned(), id.name.as_str().to_owned());
                            }
                            // `export default async (req, res) => {}`, imported elsewhere as
                            // `import deleteRoute from './routes/delete.js'`.
                            Expression::ArrowFunctionExpression(_)
                            | Expression::FunctionExpression(_) => {
                                self.facts
                                    .exports
                                    .insert("default".to_owned(), "<default>".to_owned());
                            }
                            // `export default new Controller()`: the default export is an instance
                            // of the class, so a handler registered as `controller.list` is the
                            // class method `Controller.list`. Name the default by the class so the
                            // member reference resolves to the method.
                            Expression::NewExpression(new) => {
                                if let Expression::Identifier(id) =
                                    new.callee.get_inner_expression()
                                {
                                    self.facts
                                        .exports
                                        .insert("default".to_owned(), id.name.as_str().to_owned());
                                }
                            }
                            _ => {}
                        }
                        // `export default async (req, res) => {}`, `export default handler`,
                        // `export default withAuth(handler)`: a pages/api route's handler.
                        let handler = match expr.get_inner_expression() {
                            Expression::ArrowFunctionExpression(f)
                                if f.params.items.len() >= 2
                                    || (f.params.items.len() == 1
                                        && crate::routes::file_route_path(
                                            self.linking.file,
                                            "default-export",
                                        )
                                        .is_some()) =>
                            {
                                Some("<default>".to_owned())
                            }
                            Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
                            Expression::CallExpression(call) => {
                                call.arguments.iter().find_map(|a| {
                                    match a.as_expression().map(Expression::get_inner_expression) {
                                        Some(Expression::Identifier(id)) => {
                                            Some(id.name.as_str().to_owned())
                                        }
                                        _ => None,
                                    }
                                })
                            }
                            _ => None,
                        };
                        if let Some(handler) = handler {
                            self.facts.routes.push(RouteFact {
                                at: None,
                                receiver: None,
                                receiver_file: None,
                                method: "ANY".to_owned(),
                                path: String::new(),
                                handler: handler.clone(),
                                span: expr.span(),
                                auth: wrapper_auth(expr),
                                kind: "default-export",
                            });
                            if handler == "<default>" {
                                self.maybe_function(expr, env, Some(handler), Role::Route);
                                return;
                            }
                        }
                        // Any other anonymous function: walked by its export's name.
                        if matches!(
                            expr.get_inner_expression(),
                            Expression::ArrowFunctionExpression(_)
                                | Expression::FunctionExpression(_)
                        ) && self.maybe_function(
                            expr,
                            env,
                            Some("<default>".to_owned()),
                            Role::Plain,
                        ) {
                            return;
                        }
                        // `export default express.Router().use('/x', child).get('/y', h)`: an
                        // anonymous router is the default export. Name it `<default>` so its routes
                        // and mounts carry that receiver, and record it as the default export, so a
                        // parent file mounting this module under a prefix links to it.
                        if is_anonymous_router_chain(expr) {
                            self.facts
                                .exports
                                .insert("default".to_owned(), "<default>".to_owned());
                            let saved = self.chain_receiver.replace("<default>".to_owned());
                            self.expr(expr, env);
                            self.chain_receiver = saved;
                            return;
                        }
                        self.expr(expr, env);
                    }
                }
            },
            _ => {}
        }
    }

    pub(super) fn for_left(
        &mut self,
        left: &ForStatementLeft<'_>,
        taint: Option<Origin>,
        env: &mut Env,
    ) {
        match left {
            ForStatementLeft::VariableDeclaration(d) => {
                for declarator in &d.declarations {
                    pattern_names(&declarator.id, &mut env.locals);
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

    /// Whether the project's store methods (a pack's `stored` section) apply: it uses one of the
    /// packages the pack names, or the scan saw no manifest.
    pub(super) fn stored_enabled(&self) -> bool {
        let stored = &m().stored;
        match self.linking.packages {
            Some(packages) if !stored.requires.is_empty() => {
                stored.requires.iter().any(|p| packages.contains(p))
            }
            _ => true,
        }
    }

    /// Remembers whether `name` now holds a record loaded from a store (`await Model.findByPk(id)`),
    /// whose fields a request may have stored.
    pub(super) fn note_record(&mut self, name: &str, init: &Expression<'_>, env: &mut Env) {
        let mut expr = init.get_inner_expression();
        while let Expression::AwaitExpression(a) = expr {
            expr = a.argument.get_inner_expression();
        }
        let loads = self.stored_enabled()
            && matches!(expr, Expression::CallExpression(call)
                if matches!(self.callee(&call.callee), Callee::Method { ref method, .. }
                    if has(&m().stored.read_methods, method)));
        if loads {
            env.records.insert(name.to_owned());
        } else {
            env.records.remove(name);
        }
    }

    /// `user.update({ name: req.body.name })`, `Model.create({ data: { name } })`: the fields a
    /// store method saves from request data. Only plain values (names and member accesses) are read,
    /// so this adds no walk of its own.
    pub(super) fn note_stored_writes(
        &mut self,
        callee: &Callee,
        call: &CallExpression<'_>,
        env: &mut Env,
    ) {
        let Callee::Method { method, .. } = callee else {
            return;
        };
        if !has(&m().stored.write_methods, method) || !self.stored_enabled() {
            return;
        }
        for argument in call.arguments.iter().filter_map(Argument::as_expression) {
            if let Expression::ObjectExpression(object) = argument.get_inner_expression() {
                self.stored_fields_of(object, env, 0);
            }
        }
    }

    pub(super) fn stored_fields_of(
        &mut self,
        object: &oxc_ast::ast::ObjectExpression<'_>,
        env: &mut Env,
        depth: u8,
    ) {
        for property in &object.properties {
            let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) = property else {
                continue;
            };
            let Some(key) = prop_name(&property.key) else {
                continue;
            };
            let value = property.value.get_inner_expression();
            if let Expression::ObjectExpression(inner) = value {
                if depth < 2 && has(&m().stored.wrappers, &key) {
                    self.stored_fields_of(inner, env, depth + 1);
                }
                continue;
            }
            if !matches!(
                value,
                Expression::Identifier(_)
                    | Expression::StaticMemberExpression(_)
                    | Expression::ComputedMemberExpression(_)
            ) {
                continue;
            }
            let Some(origin) = self.expr(value, env) else {
                continue;
            };
            if origin.kind == STORED || origin.param.is_some() || origin.upload {
                continue;
            }
            let span = value.span();
            let text = self
                .source
                .get(span.start as usize..span.end as usize)
                .unwrap_or("")
                .to_owned();
            let line = self.line_at(span.start);
            self.stored_writes
                .entry(key)
                .or_insert_with(|| StoredWrite {
                    file: self.linking.file.to_owned(),
                    line,
                    expr: text,
                    object: origin.object,
                });
        }
    }

    pub(super) fn var_decl(&mut self, declaration: &VariableDeclaration<'_>, env: &mut Env) {
        for declarator in &declaration.declarations {
            pattern_names(&declarator.id, &mut env.locals);
            let Some(init) = &declarator.init else {
                continue;
            };
            if let BindingPattern::BindingIdentifier(id) = &declarator.id {
                self.note_record(id.name.as_str(), init, env);
            }
            if let Some(spec) = require_spec(init) {
                self.bind_require(&declarator.id, &spec, None);
                continue;
            }
            // `const { default: router } = await import(`./apis/v${v}/router.js`)`: a dynamic import
            // of a per-version module. Remember what each bound name loads so a later versioned mount
            // (`app.use(`/api/v${v}`, router)`) resolves to every matching file.
            if let Some((pre, var, suf)) = dynamic_import_template(init) {
                match &declarator.id {
                    BindingPattern::BindingIdentifier(id) => {
                        self.dyn_imports.insert(
                            id.name.as_str().to_owned(),
                            DynImport {
                                pre,
                                var,
                                suf,
                                export: "*".to_owned(),
                            },
                        );
                    }
                    BindingPattern::ObjectPattern(object) => {
                        for property in &object.properties {
                            if let (Some(key), BindingPattern::BindingIdentifier(local)) =
                                (prop_name(&property.key), &property.value)
                            {
                                self.dyn_imports.insert(
                                    local.name.as_str().to_owned(),
                                    DynImport {
                                        pre: pre.clone(),
                                        var: var.clone(),
                                        suf: suf.clone(),
                                        export: key,
                                    },
                                );
                            }
                        }
                    }
                    _ => {}
                }
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
            // `const m = require(spec)` / `const m = load(spec)` where `spec` is one of this
            // function's parameters: `m` names the module `require(<that parameter>)`, so a later
            // `router.use(prefix, m)` mounts the module the caller passes for that parameter.
            if let Some(name) = &name_hint {
                match self.require_of_param(init, env) {
                    Some(index) => {
                        env.require_params.insert(name.clone(), index);
                    }
                    None => {
                        env.require_params.remove(name);
                    }
                }
            }
            // `const api = axios.create()`, `const git = simpleGit().env(..)`, `new NodeSSH()`:
            // the family's client, whose methods are its sinks.
            if let Some(name) = &name_hint
                && let Some(family) = self.instance_family(init)
            {
                self.modules.insert(
                    name.clone(),
                    Imported {
                        family,
                        export: None,
                    },
                );
            }
            // `const fsApi = options.fs || fs`: an injected module (tests pass a stand-in) is
            // that module, not data: `fsApi.readFileSync(p)` is `fs.readFileSync(p)`.
            if let Some(name) = &name_hint
                && let Some(imported) = self.module_fallback(init)
            {
                self.walk_only(init, env);
                self.modules.insert(name.clone(), imported);
                env.vars.remove(name);
                continue;
            }
            if let Some(name) = &name_hint {
                match self.tuple_positions(init, env) {
                    Some(positions) => {
                        env.tuples.insert(name.clone(), positions);
                    }
                    None => {
                        env.tuples.remove(name);
                    }
                }
                if is_regex(init) {
                    self.regexes.insert(name.clone(), capture_mask(init));
                } else {
                    self.regexes.remove(name);
                }
            }
            // `const PREFIX = '/api'`, `const ROUTES = { users: '/users' }`: constants.
            if let (Some(name), VariableDeclarationKind::Const) = (&name_hint, declaration.kind) {
                if let Some(text) = literal_path(init).filter(|_| {
                    matches!(
                        init.get_inner_expression(),
                        Expression::StringLiteral(_) | Expression::TemplateLiteral(_)
                    )
                }) {
                    self.constants.insert(name.clone(), text);
                } else if is_regex(init) {
                    self.constants.insert(
                        format!("{REGEX_CONSTANT}{name}"),
                        capture_mask(init).to_string(),
                    );
                } else if let Expression::ObjectExpression(object) = init.get_inner_expression() {
                    for property in &object.properties {
                        let ObjectPropertyKind::ObjectProperty(p) = property else {
                            continue;
                        };
                        let Some(key) = prop_name(&p.key) else {
                            continue;
                        };
                        if let Expression::StringLiteral(value) = p.value.get_inner_expression()
                            && let Some(text) = value.value.as_str()
                        {
                            self.constants
                                .insert(format!("{name}.{key}"), text.to_owned());
                        }
                        // `const regexes = { profile: /^\/user\/([\w\-]+)/i }`
                        if is_regex(&p.value) {
                            let mask = capture_mask(&p.value);
                            self.regexes.insert(format!("{name}.{key}"), mask);
                            self.constants
                                .insert(format!("{REGEX_CONSTANT}{name}.{key}"), mask.to_string());
                        }
                    }
                }
            }
            // `const {prefix = '/gritty'} = options`: an option destructured with a literal default.
            // The default is the value in force when the caller passes nothing (which is how the app
            // is mounted by default), so a route template built from it
            // (`router.route(`${prefix}/*name`)`) resolves to its default-mounted path rather than
            // silently dropping the segment.
            if let (BindingPattern::ObjectPattern(object), VariableDeclarationKind::Const) =
                (&declarator.id, declaration.kind)
            {
                for property in &object.properties {
                    if let BindingPattern::AssignmentPattern(assign) = &property.value
                        && let BindingPattern::BindingIdentifier(local) = &assign.left
                        && let Expression::StringLiteral(lit) = assign.right.get_inner_expression()
                        && let Some(text) = lit.value.as_str()
                    {
                        self.constants
                            .insert(local.name.as_str().to_owned(), text.to_owned());
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
            // `const _mounts = { user: require('./user'), admin: require('./admin') }`: a table of
            // functions.
            if let Some(name) = &name_hint {
                match init.get_inner_expression() {
                    Expression::CallExpression(c)
                        if matches!(c.callee.get_inner_expression(),
                            Expression::Identifier(f)
                                if self.relative.contains_key(f.name.as_str())) =>
                    {
                        if let Expression::Identifier(f) = c.callee.get_inner_expression() {
                            self.factory_bindings
                                .insert(name.clone(), f.name.as_str().to_owned());
                        }
                    }
                    _ => {
                        self.factory_bindings.remove(name);
                    }
                }
            }
            if let (Some(name), Expression::ObjectExpression(object)) =
                (&name_hint, init.get_inner_expression())
            {
                let entries: Vec<TableEntry> = object
                    .properties
                    .iter()
                    .filter_map(|property| {
                        let ObjectPropertyKind::ObjectProperty(p) = property else {
                            return None;
                        };
                        table_entry(prop_name(&p.key)?, &p.value)
                    })
                    .collect();
                if entries.is_empty() {
                    self.fn_tables.remove(name);
                } else {
                    self.fn_tables.insert(name.clone(), entries);
                }
            }
            // `const routes = [{ method: 'get', path: '/x', handler: list }]`
            if let (Some(name), Expression::ArrayExpression(array)) =
                (&name_hint, init.get_inner_expression())
            {
                let rows = table_rows(array);
                if !rows.is_empty() {
                    std::rc::Rc::make_mut(&mut env.tables).insert(name.clone(), rows);
                }
            }
            // `const sortedRoutes = routes.sort(...)`: an array method that reorders or narrows the
            // same element objects (never `.map`, which reshapes them) keeps the table's rows, so a
            // loop over the result stands for the same rows.
            if let (Some(name), Expression::CallExpression(c)) =
                (&name_hint, init.get_inner_expression())
                && let Expression::StaticMemberExpression(member) = c.callee.get_inner_expression()
                && let Expression::Identifier(src) = member.object.get_inner_expression()
                && matches!(
                    member.property.name.as_str(),
                    "sort" | "reverse" | "filter" | "slice" | "concat"
                )
                && let Some(rows) = env.tables.get(src.name.as_str()).cloned()
            {
                std::rc::Rc::make_mut(&mut env.tables).insert(name.clone(), rows);
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
            // `const shell = new ShellService()`, with `ShellService` imported from our files; an
            // alias of a typed variable or field; a `: ShellService` annotation.
            if let Some(name) = &name_hint {
                let typed = self.instance_class(init, declarator.type_annotation.as_deref(), env);
                let class = typed
                    .clone()
                    .filter(|class| self.relative.contains_key(class.as_str()));
                match class {
                    Some(class) => {
                        env.instances.insert(name.clone(), class);
                    }
                    None => {
                        env.instances.remove(name);
                    }
                }
                // `const store = new SnapshotStore()` with the class in this file.
                let local = typed.filter(|class| !self.relative.contains_key(class.as_str()));
                match local {
                    Some(class) => {
                        env.local_instances.insert(name.clone(), class);
                    }
                    None => {
                        env.local_instances.remove(name);
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
                // Also through chains: `Router().get('/a', h)`, `new Hono().basePath('/api')`.
                let root = chain_root(init);
                let (factory, options) = match root {
                    Expression::CallExpression(c) => (callee_name(&c.callee), Some(&c.arguments)),
                    Expression::NewExpression(n) => (callee_name(&n.callee), Some(&n.arguments)),
                    _ => (None, None),
                };
                let from_router = match root {
                    Expression::Identifier(id)
                        if !std::ptr::eq(root, init.get_inner_expression()) =>
                    {
                        self.is_router(id.name.as_str())
                            .then(|| id.name.as_str().to_owned())
                    }
                    _ => None,
                };
                // `const server = http.createServer(opts)`: the server itself, not a chain on it.
                if std::ptr::eq(root, init.get_inner_expression())
                    && factory.as_deref().is_some_and(|f| {
                        has(&m().server_factories, f.rsplit('.').next().unwrap_or(f))
                    })
                {
                    self.servers.insert(name.clone());
                }
                if factory.as_deref().is_some_and(is_router_factory) || from_router.is_some() {
                    self.routers.insert(name.clone());
                    // Its own prefix: `new Router({ prefix: '/api' })`, `.basePath('/api')`.
                    let mut prefix = match (&from_router, options) {
                        (Some(parent), _) => self.own_prefix(Some(parent)),
                        (None, Some(arguments)) => {
                            self.options_prefix(arguments, env).unwrap_or_default()
                        }
                        (None, None) => String::new(),
                    };
                    for link in chain_prefixes(init) {
                        if let Some(text) = self.resolve_text(link, env) {
                            prefix = join_path(&prefix, &text);
                        }
                    }
                    if prefix.is_empty() {
                        self.router_prefixes.remove(name);
                    } else {
                        self.router_prefixes.insert(name.clone(), prefix);
                    }
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
                // `const u = new URLSearchParams(q)`: its text form is percent-encoded.
                let encoded = match init.get_inner_expression() {
                    Expression::NewExpression(n) => {
                        callee_name(&n.callee).is_some_and(|c| has(&m().encoding_constructors, &c))
                    }
                    _ => false,
                };
                if encoded {
                    env.encoded.insert(name.clone());
                } else {
                    env.encoded.remove(name);
                }
                // `const file = join(root, dir, name)`: built from one tainted variable, unchanged.
                let mut parts = Vec::new();
                let tainted: BTreeSet<String> = if self.built_from(init, &mut parts) {
                    parts
                        .into_iter()
                        .filter(|part| env.vars.contains_key(part))
                        .collect()
                } else {
                    BTreeSet::new()
                };
                match tainted.iter().next() {
                    Some(from) if tainted.len() == 1 && from != name => {
                        env.derived.insert(name.clone(), from.clone());
                    }
                    _ => {
                        env.derived.remove(name);
                    }
                }
                // `const rel = path.relative(base, file)`.
                match init.get_inner_expression() {
                    Expression::CallExpression(c) if guards::is_relative_call(c) => {
                        let bases = c
                            .arguments
                            .first()
                            .and_then(Argument::as_expression)
                            .map(guards::relative_base_keys)
                            .unwrap_or_default();
                        match c
                            .arguments
                            .get(1)
                            .and_then(Argument::as_expression)
                            .and_then(guards::path_key)
                        {
                            Some(file) if !bases.is_empty() => {
                                env.relative_of.insert(name.clone(), (bases, file));
                            }
                            _ => {
                                env.relative_of.remove(name);
                            }
                        }
                    }
                    _ => {
                        env.relative_of.remove(name);
                    }
                }
                // `const full = path.join(base, seg)`: a segment joined onto a base.
                match self.joined_base_segment(init) {
                    Some((bases, seg)) if seg != *name => {
                        env.joined.insert(name.clone(), (bases, seg));
                    }
                    _ => {
                        env.joined.remove(name);
                    }
                }
                // `const resolved = path.resolve(file)`: the same file as `file`.
                match self.same_file_of(init) {
                    Some(file) if file != *name => {
                        env.same_file.insert(name.clone(), file);
                    }
                    _ => {
                        env.same_file.remove(name);
                    }
                }
                note_url_parts(name, init, env);
                // `const iframe = document.createElement('iframe')`: a node, not markup.
                if creates_node(init) {
                    env.nodes.insert(name.clone());
                } else {
                    env.nodes.remove(name);
                }
                // `const doc = docs.find((d) => d.filename === name)`: found, `name` is the
                // server's.
                let looked_up = match init.get_inner_expression() {
                    Expression::AwaitExpression(a) => match a.argument.get_inner_expression() {
                        Expression::CallExpression(c) => lookup_value(c, env),
                        _ => None,
                    },
                    Expression::CallExpression(c) => lookup_value(c, env),
                    _ => None,
                };
                match looked_up {
                    Some(value) => {
                        env.found_by.insert(name.clone(), value);
                    }
                    None => {
                        env.found_by.remove(name);
                    }
                }
                // `const args = ['--json', '--']`: pushes after it are positional.
                let ended = matches!(
                    init.get_inner_expression(),
                    Expression::ArrayExpression(array)
                        if array.elements.iter().any(|e| ends_options(e.as_expression()))
                );
                if ended {
                    env.options_ended.insert(name.clone());
                } else {
                    env.options_ended.remove(name);
                }
                // `document.createElement('a')`: an anchor, whose `href` is a URL sink.
                let tag = match init.get_inner_expression() {
                    Expression::CallExpression(c) if creates_node(init) => c
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .and_then(|a| match a.get_inner_expression() {
                            Expression::StringLiteral(l) => l.value.as_str().map(str::to_owned),
                            _ => None,
                        }),
                    _ => None,
                };
                match tag {
                    Some(tag) => {
                        env.node_tags.insert(name.clone(), tag.to_ascii_lowercase());
                    }
                    None => {
                        env.node_tags.remove(name);
                    }
                }
            }
            self.last_returned_fields = None;
            // `const r = Router().get('/a', h)`: routes registered on `r`.
            let chained =
                name_hint.is_some() && !std::ptr::eq(chain_root(init), init.get_inner_expression());
            let saved_receiver = if chained {
                std::mem::replace(&mut self.chain_receiver, name_hint.clone())
            } else {
                self.chain_receiver.take()
            };
            // `const send = (m) => ...`: a function this one declares.
            if let Some(name) = name_hint.as_deref().filter(|_| is_function_value(init)) {
                self.declare_function(name, None);
                self.declaring = true;
            }
            let taint = self.expr_named(init, env, name_hint.clone());
            self.declaring = false;
            self.chain_receiver = saved_receiver;
            // `const db = getDBClient(cfg)`, `const reg = await Registry.getInstance()`: an
            // instance of what the function returns, when nothing above typed it by name.
            if let Some(name) = &name_hint {
                let refs =
                    if env.instances.contains_key(name) || env.local_instances.contains_key(name) {
                        Vec::new()
                    } else {
                        self.value_refs(init, env)
                    };
                if refs.is_empty() {
                    env.remote.remove(name);
                } else {
                    env.remote.insert(name.clone(), refs);
                }
            }
            // `const { store } = makeServices()`, returning `{ store: new Store(db) }`.
            if let BindingPattern::ObjectPattern(object) = &declarator.id {
                let call = match init.get_inner_expression() {
                    Expression::AwaitExpression(a) => match a.argument.get_inner_expression() {
                        Expression::CallExpression(c) => Some(c.span),
                        _ => None,
                    },
                    Expression::CallExpression(c) => Some(c.span),
                    _ => None,
                };
                for property in &object.properties {
                    let BindingPattern::BindingIdentifier(local) = &property.value else {
                        continue;
                    };
                    let local = local.name.as_str();
                    let classes = call.zip(prop_name(&property.key)).and_then(|(span, key)| {
                        self.call_classes.get(&(span.start, span.end, Some(key)))
                    });
                    match classes {
                        Some(classes) => {
                            env.remote.insert(local.to_owned(), classes.clone());
                        }
                        None => {
                            env.remote.remove(local);
                        }
                    }
                }
            }
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
            // `const opts = { table: 'x', ids: req.body.ids }`: remember each field's taint
            // (with spreads: their known fields, and the rest under `REST_FIELD`).
            if let (Some(name), Expression::ObjectExpression(object)) =
                (&name_hint, init.get_inner_expression())
            {
                let fields = self.literal_fields(object, env);
                env.fields.insert(name.clone(), fields);
            } else if let (Some(name), Expression::ConditionalExpression(c)) =
                (&name_hint, init.get_inner_expression())
                && let (Expression::ObjectExpression(a), Expression::ObjectExpression(b)) = (
                    c.consequent.get_inner_expression(),
                    c.alternate.get_inner_expression(),
                )
            {
                // `const scope = ids ? { where: '..', params: [..ids] } : { where, params }`: each
                // field what either literal gives it.
                let mut fields = self.literal_fields(a, env);
                for (field, origin) in self.literal_fields(b, env) {
                    match fields.get_mut(&field) {
                        Some(current) => join(current, &origin),
                        None => {
                            fields.insert(field, origin);
                        }
                    }
                }
                env.fields.insert(name.clone(), fields);
            } else if let Some(name) = &name_hint {
                env.fields.remove(name);
            }
            // `const [base, rest] = film ? [filmDir, u.slice(n)] : [root, u]`: each name what its
            // position holds, in either literal.
            if let BindingPattern::ArrayPattern(array) = &declarator.id
                && let Some(positions) = self.literal_positions(init, env)
            {
                self.bind_positions(array, &positions, env);
                continue;
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

    /// The taint at each position of an array literal, or of either of two (`c ? [a, b] :
    /// [d, e]`), without spreads; what the walk of the initializer recorded stays as it was.
    pub(super) fn literal_positions(
        &mut self,
        expr: &Expression<'_>,
        env: &Env,
    ) -> Option<Vec<Option<Origin>>> {
        let elements = |this: &mut Self,
                        array: &oxc_ast::ast::ArrayExpression<'_>|
         -> Option<Vec<Option<Origin>>> {
            let mut probe = env.clone();
            let mut positions = Vec::new();
            for element in &array.elements {
                let expr = element.as_expression()?;
                positions.push(this.expr(expr, &mut probe));
            }
            Some(positions)
        };
        let saved = std::mem::replace(&mut self.record_only, true);
        let positions = match expr.get_inner_expression() {
            Expression::ArrayExpression(array) => elements(self, array),
            Expression::ConditionalExpression(c) => match (
                c.consequent.get_inner_expression(),
                c.alternate.get_inner_expression(),
            ) {
                (Expression::ArrayExpression(a), Expression::ArrayExpression(b)) => {
                    match (elements(self, a), elements(self, b)) {
                        (Some(a), Some(b)) => Some(
                            (0..a.len().max(b.len()))
                                .map(|i| {
                                    union(a.get(i).cloned().flatten(), b.get(i).cloned().flatten())
                                })
                                .collect(),
                        ),
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        };
        self.record_only = saved;
        positions
    }

    /// Binds `const x = require(spec)` and `const { a, b: c } = require(spec)`.
    pub(super) fn bind_require(
        &mut self,
        pattern: &BindingPattern<'_>,
        spec: &str,
        export: Option<String>,
    ) {
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
    pub(super) fn bind_pattern(
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
                // `const request = req`: the whole request object aliased under a new name is still
                // the request, so its members stay sources and passing it on forwards the request.
                if let Some((kind, _)) = request {
                    env.requests.insert(id.name.as_str().to_owned(), kind);
                }
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
                                htmlish: false,
                                escaped: 0,
                                param: None,
                                // As for `req.body`: only a parsed body or query can hold objects.
                                object: has(&m().object_props, key)
                                    && !has(self.linking.scalar_props, key),
                                also: Vec::new(),
                                upload: false,
                                dash_free: false,
                                response: false,
                                primary_escaped: 0,
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

    pub(super) fn class(&mut self, class: &Class<'_>, env: &mut Env) {
        let class_name = class.id.as_ref().map(|id| id.name.as_str().to_owned());
        if let Some(name) = &class_name {
            self.declared_classes.insert(name.clone());
        }
        // `class MongoMem extends Mem implements Store`: its bases, for dispatch on a `Mem`.
        if let Some(name) = &class_name {
            let mut bases = Vec::new();
            if let Some(Expression::Identifier(base)) = class
                .heritage
                .as_ref()
                .map(|heritage| heritage.expression.get_inner_expression())
                && let Some(resolved) = self.class_ref(base.name.as_str())
            {
                bases.push(resolved);
            }
            for implemented in &class.implements {
                if let oxc_ast::ast::TSTypeName::IdentifierReference(id) = &implemented.expression
                    && let Some(resolved) = self.class_ref(id.name.as_str())
                {
                    bases.push(resolved);
                }
            }
            if !bases.is_empty() {
                self.facts.classes.push(jss_core::ir::ClassDecl {
                    name: name.clone(),
                    bases,
                });
            }
        }
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
        let controller_prefix: Option<Vec<String>> = class.decorators.iter().find_map(|d| {
            let Expression::CallExpression(call) = &d.expression else {
                return None;
            };
            let name = callee_name(&call.callee)?;
            has(&m().controller_decorators, &name).then(|| {
                // `@Controller('users')`, `@Controller(RouteKey.User)`,
                // `@Controller({ path: 'users' })` or `@Controller(['v1/users', 'users'])`.
                let keys: Vec<&str> = m().route_path_keys.iter().map(String::as_str).collect();
                let argument = call.arguments.first().and_then(Argument::as_expression);
                let paths = match argument {
                    Some(e) => match object_prop(e, &keys) {
                        Some(path) => self.text_list(path, env),
                        None => self.text_list(e, env),
                    },
                    None => Vec::new(),
                };
                if paths.is_empty() {
                    vec![String::new()]
                } else {
                    paths
                }
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
                    let mut subs = call
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .map(|e| self.text_list(e, env))
                        .unwrap_or_default();
                    if subs.is_empty() {
                        subs.push(String::new());
                    }
                    let key = prop_name(&method.key).unwrap_or_default();
                    for (prefix, sub) in prefix
                        .iter()
                        .flat_map(|p| subs.iter().map(move |s| (p, s)))
                        .take(64)
                    {
                        self.facts.routes.push(RouteFact {
                            at: None,
                        receiver: None,
                        receiver_file: None,
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
                    // `constructor(private readonly cfg: Config) {}`: `this.cfg = cfg`.
                    if method.kind == oxc_ast::ast::MethodDefinitionKind::Constructor
                        && let Some(class) = &class_name
                    {
                        let props: Vec<String> = method
                            .value
                            .params
                            .items
                            .iter()
                            .filter(|p| p.accessibility.is_some() || p.readonly || p.r#override)
                            .filter_map(|p| match &p.pattern {
                                BindingPattern::BindingIdentifier(id) => {
                                    Some(id.name.as_str().to_owned())
                                }
                                BindingPattern::AssignmentPattern(a) => match &a.left {
                                    BindingPattern::BindingIdentifier(id) => {
                                        Some(id.name.as_str().to_owned())
                                    }
                                    _ => None,
                                },
                                _ => None,
                            })
                            .collect();
                        if !props.is_empty() {
                            self.pending_param_props = Some((class.clone(), props));
                        }
                    }
                    let saved_class =
                        std::mem::replace(&mut self.current_class, class_name.clone());
                    self.function(&method.value, env, name, Role::Plain);
                    self.current_class = saved_class;
                    self.pending_param_props = None;
                }
                ClassElement::PropertyDefinition(property) => {
                    // `private svc: Svc;`, `svc = new Svc();`: the field's class.
                    if let (Some(class), Some(field)) = (&class_name, prop_name(&property.key)) {
                        let typed = match &property.value {
                            Some(value) => {
                                self.instance_class(value, property.type_annotation.as_deref(), env)
                            }
                            None => annotated_class(property.type_annotation.as_deref()),
                        };
                        if let Some(typed) = typed {
                            self.field_types.insert((class.clone(), field), typed);
                        }
                    }
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
}
