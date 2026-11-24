use super::*;

impl Walker<'_> {
    // ----- functions --------------------------------------------------------------------

    pub(super) fn function(
        &mut self,
        f: &Function<'_>,
        parent: &Env,
        name: Option<String>,
        role: Role,
    ) {
        let Some(body) = &f.body else {
            return;
        };
        let outer = self.fn_returns.take();
        let mut env = self.enter_function(&f.params, parent, name, role);
        self.declare_nested(&body.statements, f.params.span.start);
        if self.enter() {
            self.statements(&body.statements, &mut env);
            self.record_validated(&body.statements, f.params.span, &env);
            // `function pick(): Svc`, `async load(): Promise<Svc>`: returns an instance.
            if self.summarize
                && let Some(class) = self.annotated_returns(f.return_type.as_deref())
            {
                self.record_instances(vec![class], f.span, &env, None);
            }
            if let Some(argument) = predicate_return(&body.statements) {
                self.record_predicate(argument, &env);
            }
            self.leave();
        }
        self.scope_stack.pop();
        self.callback_returns = std::mem::replace(&mut self.fn_returns, outer);
        self.closure_writes = closure_writes(&env, parent);
    }

    /// A server's options object (`devServer: { before: [...] }`): the handlers its middleware
    /// keys list are entry points of `spec.kind`; the other options are walked as values.
    pub(super) fn middleware_options(
        &mut self,
        options: &ObjectExpression<'_>,
        spec: &'static models::MiddlewareOption,
        env: &mut Env,
    ) {
        for option in &options.properties {
            match option {
                ObjectPropertyKind::ObjectProperty(o) => {
                    let key = prop_name(&o.key);
                    match o.value.get_inner_expression() {
                        Expression::ArrayExpression(list)
                            if key.as_deref().is_some_and(|k| has(&spec.keys, k)) =>
                        {
                            for element in list
                                .elements
                                .iter()
                                .filter_map(ArrayExpressionElement::as_expression)
                            {
                                self.pending_request_kind.set(Some(spec.kind.as_str()));
                                if !self.maybe_function(element, env, None, Role::Route) {
                                    self.pending_request_kind.set(None);
                                    self.expr(element, env);
                                }
                            }
                        }
                        _ => {
                            self.expr_named(&o.value, env, key);
                        }
                    }
                }
                ObjectPropertyKind::SpreadProperty(spread) => {
                    self.expr(&spread.argument, env);
                }
            }
        }
    }

    /// Records the functions a function body declares by name (`function send() {}`, `const
    /// send = () => {}`) before walking it: a call above a declaration sees it too.
    pub(super) fn declare_nested(&mut self, body: &[Statement<'_>], scope: u32) {
        for statement in body {
            match statement {
                Statement::FunctionDeclaration(f) => {
                    if let Some(id) = &f.id {
                        self.declare_function(id.name.as_str(), Some(scope));
                    }
                }
                Statement::VariableDeclaration(d) => {
                    for declarator in &d.declarations {
                        if let (BindingPattern::BindingIdentifier(id), Some(init)) =
                            (&declarator.id, &declarator.init)
                            && is_function_value(init)
                        {
                            self.declare_function(id.name.as_str(), Some(scope));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// A function declaration named `name` in `scope` (the current function when `None`;
    /// nothing at the top level, where every call sees it anyway).
    pub(super) fn declare_function(&mut self, name: &str, scope: Option<u32>) {
        if let Some(scope) = scope.or_else(|| self.scope_stack.last().copied()) {
            self.nested_fns
                .entry(name.to_owned())
                .or_default()
                .insert(scope);
        }
    }

    /// The functions known to check their arguments, by name: this file's with a predicate
    /// summary, and our other files' imported here. Their calls are judged by those summaries,
    /// not by their names (`isWithin(req.query.base, f)` confines `f` to the caller's base).
    pub(super) fn predicate_names(&self) -> Vec<String> {
        let own = self
            .summaries
            .iter()
            .filter(|(_, list)| list.iter().any(|s| s.api == PREDICATE))
            .map(|(name, _)| name.clone());
        let imported = self.relative.iter().filter_map(|(local, (spec, export))| {
            let export = export.as_deref().unwrap_or("default");
            let (file, name) = self.exported_function(spec, export)?;
            self.external
                .get(&name)?
                .iter()
                .any(|s| s.api == PREDICATE && s.defined_in.as_deref() == Some(file.as_str()))
                .then(|| local.clone())
        });
        own.chain(imported).collect()
    }

    /// This file's summaries of the function a call by `name` reaches: the closest function so
    /// named declared in a function the call is in, else the top-level ones. Same-named
    /// closures of different functions (`send` in one, `send` in another) stay apart.
    pub(super) fn visible_summaries(&self, name: &str) -> Vec<Summary> {
        let Some(list) = self.summaries.get(name) else {
            return Vec::new();
        };
        let scope = self.nested_fns.get(name).and_then(|scopes| {
            self.scope_stack
                .iter()
                .rev()
                .find(|scope| scopes.contains(scope))
                .copied()
        });
        list.iter().filter(|s| s.scope == scope).cloned().collect()
    }

    pub(super) fn enter_function(
        &mut self,
        params: &FormalParameters<'_>,
        parent: &Env,
        name: Option<String>,
        role: Role,
    ) -> Env {
        let name = name.unwrap_or_else(|| "<anonymous>".to_owned());
        let declared = std::mem::take(&mut self.declaring);
        let mut env = parent.closure(name);
        // A function a declaration names inside another is that function's: a call by its name
        // sees it only from there (see `visible_summaries`).
        env.def_scope = if declared {
            self.scope_stack.last().copied()
        } else if env.function == "<anonymous>" {
            parent.def_scope
        } else {
            None
        };
        self.scope_stack.push(params.span.start);
        // `yauzl.open(p, opts, (err, zipfile) => ...)`: `zipfile` checks its entries' names.
        if let Some(index) = self.pending_archive.take()
            && let Some(name) = params
                .items
                .get(index)
                .and_then(|p| p.pattern.get_identifier_name())
        {
            env.validated_archives.insert(name.to_string());
        }
        env.auth = env.auth.max(std::mem::take(&mut self.pending_auth));
        let names: Vec<Option<&str>> = params
            .items
            .iter()
            .map(|p| match &p.pattern {
                BindingPattern::BindingIdentifier(id) => Some(id.name.as_str()),
                _ => None,
            })
            .collect();
        // Parameters shadow outer taint and facts of the same name.
        for name in names.iter().flatten() {
            env.vars.remove(*name);
            env.requests.remove(*name);
            env.forget(name);
        }
        let first = names.first().copied().flatten();
        env.params = names.iter().map(|n| n.unwrap_or("").to_owned()).collect();
        for param in &params.items {
            pattern_names(&param.pattern, &mut env.locals);
            // `function f(svc: Svc)`: an instance of `Svc` (a parameter shadows outer types).
            if let BindingPattern::BindingIdentifier(id) = &param.pattern {
                let name = id.name.as_str().to_owned();
                env.instances.remove(&name);
                env.local_instances.remove(&name);
                env.remote.remove(&name);
                if let Some(class) = annotated_class(param.type_annotation.as_deref()) {
                    if self.relative.contains_key(class.as_str()) {
                        env.instances.insert(name, class);
                    } else {
                        env.local_instances.insert(name, class);
                    }
                }
            }
        }
        if let Some(rest) = &params.rest {
            pattern_names(&rest.rest.argument, &mut env.locals);
        }
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
            let decorator = param.decorators.iter().find_map(|d| match &d.expression {
                Expression::CallExpression(call) => match call.callee.get_inner_expression() {
                    Expression::Identifier(id) if has(&m().decorators, id.name.as_str()) => {
                        Some((id.name.as_str(), call))
                    }
                    _ => None,
                },
                _ => None,
            });
            if let Some((name, call)) = decorator {
                // `@Query('limit', ParseIntPipe)`: parsed into a safe value.
                let parsed = call.arguments.iter().any(|a| {
                    a.as_expression()
                        .and_then(|e| match e.get_inner_expression() {
                            Expression::NewExpression(n) => callee_name(&n.callee),
                            other => callee_name(other),
                        })
                        .is_some_and(|pipe| {
                            let pipe = pipe.split(' ').next().unwrap_or("");
                            has(&m().sanitizing_pipes, pipe)
                        })
                });
                if parsed {
                    continue;
                }
                let origin = Origin {
                    kind: "http",
                    span: param.span,
                    steps: Vec::new(),
                    built: false,
                    prefix: true,
                    sqlish: false,
                    htmlish: false,
                    escaped: 0,
                    param: None,
                    // `@Param('id')`, `@Headers()`: strings.
                    object: !has(&m().scalar_decorators, name),
                    also: Vec::new(),
                    upload: false,
                    dash_free: false,
                    response: false,
                    primary_escaped: 0,
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
                        self.param_owner
                            .insert(property.span.start, (env.function.clone(), env.def_scope));
                        env.own_params.insert(property.span.start);
                        let mut origin = Origin::source("param", property.span);
                        origin.param = Some(index);
                        self.bind_pattern(&property.value, Some(origin), None, &mut env);
                    }
                    if let Some(rest) = &object.rest {
                        self.param_owner
                            .insert(param.span.start, (env.function.clone(), env.def_scope));
                        env.own_params.insert(param.span.start);
                        let mut origin = Origin::source("param", param.span);
                        origin.param = Some(index);
                        self.bind_pattern(&rest.argument, Some(origin), None, &mut env);
                    }
                    continue;
                }
                self.param_owner
                    .insert(param.span.start, (env.function.clone(), env.def_scope));
                env.own_params.insert(param.span.start);
                let origin = Origin {
                    kind: "param",
                    span: param.span,
                    steps: Vec::new(),
                    built: false,
                    prefix: true,
                    sqlish: false,
                    htmlish: false,
                    escaped: 0,
                    param: Some(index),
                    object: true,
                    also: Vec::new(),
                    upload: false,
                    dash_free: false,
                    response: false,
                    primary_escaped: 0,
                };
                self.bind_pattern(&param.pattern, Some(origin), None, &mut env);
            }
            // `function run(cmd, ...args)`: every argument from the rest's index on.
            if let Some(rest) = &params.rest {
                let span = rest.span;
                self.param_owner
                    .insert(span.start, (env.function.clone(), env.def_scope));
                env.own_params.insert(span.start);
                self.rest_params.insert(span.start);
                let mut origin = Origin::source("param", span);
                origin.param = Some(params.items.len());
                self.bind_pattern(&rest.rest.argument, Some(origin), None, &mut env);
            }
        }
        // `constructor(private readonly cfg: Config)`: the instance field holds the parameter.
        if let Some((class, props)) = self.pending_param_props.take() {
            let fields = self.class_fields.entry(class).or_default();
            for name in props {
                if let Some(origin) = env.vars.get(&name) {
                    fields.insert(name, origin.clone());
                }
            }
        }
        // A callback of an array, promise or string method: its parameters are the receiver's
        // elements (and a reduce's accumulator its initial value).
        if let Some(pending) = self.pending_element.take() {
            for (index, param) in params.items.iter().enumerate() {
                let value = if pending.spec.accumulator == Some(index) {
                    pending.initial.clone()
                } else if pending.spec.element_all || pending.spec.element.contains(&index) {
                    pending.element.clone()
                } else {
                    None
                };
                if value.is_none() {
                    continue;
                }
                match (&param.pattern, &pending.positions) {
                    // `([key, value]) => ...` over tuples: each position its own taint.
                    (BindingPattern::ArrayPattern(array), Some(positions))
                        if pending.spec.accumulator != Some(index) =>
                    {
                        self.bind_positions(array, positions, &mut env);
                    }
                    _ => self.bind_pattern(&param.pattern, value, None, &mut env),
                }
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
                        htmlish: false,
                        escaped: 0,
                        param: None,
                        // GraphQL arguments are typed by the schema.
                        object: !has(&m().scalar_kinds, kind),
                        also: Vec::new(),
                        upload: false,
                        dash_free: false,
                        response: false,
                        primary_escaped: 0,
                    };
                    self.bind_pattern(&param.pattern, Some(origin), None, &mut env);
                }
                // `socket.onAny((event, ...args) => ...)`: the rest holds client data too.
                if let Some(rest) = &params.rest
                    && selected.wants(params.items.len())
                    && selected != Params::Input
                {
                    let mut origin = Origin::source(kind, rest.span);
                    origin.object = !has(&m().scalar_kinds, kind);
                    self.bind_pattern(&rest.rest.argument, Some(origin), None, &mut env);
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
                            self.caller_kinds
                                .get(&env.function)
                                .copied()
                                .unwrap_or("http")
                        };
                        // In a service worker, a `request` is the page's (browser-side data).
                        let worker_kind = m().service_worker.kind.as_str();
                        let kind =
                            if self.service_worker && kind == "http" && !worker_kind.is_empty() {
                                worker_kind
                            } else {
                                kind
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

    pub(super) fn arrow(
        &mut self,
        params: &FormalParameters<'_>,
        body: &ArrowFunctionBody<'_>,
        parent: &Env,
        name: Option<String>,
        role: Role,
    ) {
        let outer = self.fn_returns.take();
        let mut env = self.enter_function(params, parent, name, role);
        if let ArrowFunctionBody::FunctionBody(body) = body {
            self.declare_nested(&body.statements, params.span.start);
        }
        if self.enter() {
            match body {
                ArrowFunctionBody::FunctionBody(body) => {
                    self.statements(&body.statements, &mut env);
                    self.record_validated(&body.statements, params.span, &env);
                    if let Some(argument) = predicate_return(&body.statements) {
                        self.record_predicate(argument, &env);
                    }
                }
                other => {
                    if let Some(expr) = other.as_expression() {
                        self.record_predicate(expr, &env);
                        let taint = self.expr(expr, &mut env);
                        self.fn_returns = union(self.fn_returns.take(), taint.clone());
                        self.record_returned(expr, taint, &env);
                    }
                }
            }
            self.leave();
        }
        self.scope_stack.pop();
        self.callback_returns = std::mem::replace(&mut self.fn_returns, outer);
        self.closure_writes = closure_writes(&env, parent);
    }

    /// Adds what the inline function walked last wrote to this function's names (`let s = '';
    /// list.forEach((x) => { s += x; })`), as weak updates: registered callbacks run later, so
    /// later reads see the write.
    pub(super) fn apply_closure_writes(&mut self, env: &mut Env) {
        for (name, field, origin) in std::mem::take(&mut self.closure_writes) {
            match field {
                None => {
                    let merged = match env.vars.get(&name) {
                        Some(existing) => {
                            let mut merged = existing.clone();
                            join(&mut merged, &origin);
                            merged
                        }
                        None => origin,
                    };
                    env.vars.insert(name, merged);
                }
                Some(field) => {
                    if let Some(fields) = env.fields.get_mut(&name) {
                        let merged = union(fields.remove(&field), Some(origin.clone()));
                        fields.insert(field, merged.unwrap_or(origin));
                    }
                }
            }
        }
    }

    /// Summary pass: a function that returns a check of its parameters (`typeof v ===
    /// 'string' && /^[\w.-]+$/.test(v)`): true, each parameter the check cleans is safe for
    /// those classes.
    pub(super) fn record_predicate(&mut self, returned: &Expression<'_>, env: &Env) {
        if !self.summarize || env.function == "<anonymous>" || env.function == "<module>" {
            return;
        }
        let mut held = Vec::new();
        guards::facts(returned, true, &mut held);
        // `return isInsideDir(ROOT, p)`: what the predicates it calls establish.
        self.predicate_facts(returned, true, &mut held);
        // A parameter, or a local naming the same file as one (`const c = path.resolve(child)`):
        // its index, and whether it was reached through such a local.
        let param_of = |key: &str| -> Option<(usize, bool)> {
            let mut key = key.to_owned();
            for hop in 0..8 {
                if let Some(index) = env.params.iter().position(|p| !p.is_empty() && *p == key) {
                    return Some((index, hop > 0));
                }
                key = env.same_file.get(&key)?.clone();
            }
            None
        };
        for (key, fact) in held {
            let (classes, bases) = match fact {
                guards::Fact::Clean(classes) => (classes, Vec::new()),
                guards::Fact::Allowed => (guards::ALL, Vec::new()),
                // `c.startsWith(p + path.sep)`: inside a base that is a parameter (the caller's
                // argument decides) or a constant of the function.
                guards::Fact::Contained(classes, bases) => (classes, bases),
                _ => continue,
            };
            let Some((index, through_file)) = param_of(&key) else {
                continue;
            };
            // `p + path.sep`: one base is a parameter (or the same file as one); the others must
            // be clean (a separator, a constant root).
            let mut base_params = BTreeSet::new();
            let mut tainted_base = false;
            for base in &bases {
                match param_of(base) {
                    Some((base, _)) => {
                        base_params.insert(base);
                    }
                    None if env.vars.contains_key(base) => tainted_base = true,
                    None => {}
                }
            }
            if tainted_base || base_params.len() > 1 {
                continue;
            }
            let base_param = base_params.into_iter().next();
            // The same file, not the same text: paths only.
            let classes = if through_file {
                classes & class_bit(VulnClass::PathTraversal)
            } else {
                classes
            };
            if classes == 0 {
                continue;
            }
            let list = self.summaries.entry(env.function.clone()).or_default();
            if list
                .iter()
                .any(|s| s.api == PREDICATE && s.param == index && s.scope == env.def_scope)
            {
                continue;
            }
            let span = returned.span();
            let mut at_sink = Origin::source("param", span);
            at_sink.escaped = classes;
            list.push(Summary {
                param: index,
                class: VulnClass::CodeInjection,
                severity: Severity::Low,
                api: PREDICATE.to_owned(),
                arg: span,
                call: span,
                steps: Vec::new(),
                at_sink,
                ext: None,
                field: None,
                out_field: None,
                defined_in: None,
                start: false,
                rest: false,
                instance_of: None,
                base_param,
                with_param: None,
                scope: env.def_scope,
            });
        }
    }

    /// For `LIST.includes(e) ? e : other` (or `!LIST.includes(e) ? other : e`, `SET.has(e) ...`):
    /// whether the consequent (`Some(true)`) or the alternate (`Some(false)`) repeats the checked
    /// expression and so evaluates to one of the values the server listed. The expression must
    /// read the same twice (only access paths and value-returning string/array methods), and a
    /// list must be written out with constant elements.
    pub(super) fn allowlisted_echo(
        &self,
        c: &oxc_ast::ast::ConditionalExpression<'_>,
    ) -> Option<bool> {
        let mut test = c.test.get_inner_expression();
        let mut holds = true;
        while let Expression::UnaryExpression(u) = test
            && u.operator == UnaryOperator::LogicalNot
        {
            holds = !holds;
            test = u.argument.get_inner_expression();
        }
        let Expression::CallExpression(call) = test else {
            return None;
        };
        let member = call.callee.get_inner_expression().as_member_expression()?;
        let name = member.static_property_name()?;
        let name = name.as_str()?;
        let model = m();
        let listed = has(&model.set_members, name)
            || (has(&model.list_members, name)
                && matches!(
                    member.object().get_inner_expression(),
                    Expression::ArrayExpression(list)
                        if list.elements.iter().all(|e| e.as_expression().is_some_and(constant_literal))
                ));
        if !listed || call.arguments.len() != 1 {
            return None;
        }
        let checked = call.arguments.first()?.as_expression()?;
        if !deterministic_value(checked) {
            return None;
        }
        let branch = if holds { &c.consequent } else { &c.alternate };
        let text = |e: &Expression<'_>| -> Option<String> {
            let span = e.get_inner_expression().span();
            self.source
                .get(span.start as usize..span.end as usize)
                .map(|t| t.chars().filter(|ch| !ch.is_whitespace()).collect())
        };
        (text(checked)? == text(branch)?).then_some(holds)
    }

    /// The facts a test establishes through calls to predicates by what they do (see
    /// [`PREDICATE`]): `!identity(id)` failed, so `id` is clean.
    pub(super) fn predicate_facts(
        &self,
        test: &Expression<'_>,
        truth: bool,
        out: &mut Vec<(String, guards::Fact)>,
    ) {
        match test.get_inner_expression() {
            Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot => {
                self.predicate_facts(&u.argument, !truth, out);
            }
            Expression::LogicalExpression(l)
                if (l.operator == LogicalOperator::And && truth)
                    || (l.operator == LogicalOperator::Or && !truth) =>
            {
                self.predicate_facts(&l.left, truth, out);
                self.predicate_facts(&l.right, truth, out);
            }
            Expression::CallExpression(call) if truth => {
                let Expression::Identifier(id) = call.callee.get_inner_expression() else {
                    return;
                };
                let name = id.name.as_str();
                let summaries: Vec<Summary> = match self.relative.get(name) {
                    Some((spec, export)) => {
                        let export = export.as_deref().unwrap_or("default");
                        self.exported_function(spec, export)
                            .and_then(|(file, local)| {
                                self.external.get(&local).map(|list| {
                                    list.iter()
                                        .filter(|s| s.defined_in.as_deref() == Some(file.as_str()))
                                        .cloned()
                                        .collect()
                                })
                            })
                            .unwrap_or_default()
                    }
                    None => self.visible_summaries(name),
                };
                for s in summaries.iter().filter(|s| s.api == PREDICATE) {
                    let Some(key) = call
                        .arguments
                        .get(s.param)
                        .and_then(Argument::as_expression)
                        .and_then(guards::path_key)
                    else {
                        continue;
                    };
                    let classes = s.at_sink.escaped;
                    match s
                        .base_param
                        .map(|b| call.arguments.get(b).and_then(Argument::as_expression))
                    {
                        None => out.push((key, guards::Fact::Clean(classes))),
                        // `isPathWithinParent(resolved, root)`: inside the caller's base, which
                        // confines only if the attacker did not choose it.
                        Some(Some(base)) => match guards::path_key(base) {
                            Some(base) => {
                                out.push((key, guards::Fact::Contained(classes, vec![base])));
                            }
                            None if literal_path(base).is_some() => {
                                out.push((key, guards::Fact::Clean(classes)));
                            }
                            // `isInsideDir(os.homedir(), p)`, `isInside(p, path.join(ROOT, d))`:
                            // inside a base built from these, none of them the attacker's.
                            None => out.push((
                                key,
                                guards::Fact::Contained(classes, guards::base_keys(base)),
                            )),
                        },
                        Some(None) => {}
                    }
                }
            }
            _ => {}
        }
    }

    /// Summary pass: a void function that throws unless its parameters are valid
    /// (`isValidRequest(req, fileName)` throwing on a bad name) validates them for its callers.
    pub(super) fn record_validated(&mut self, body: &[Statement<'_>], span: Span, env: &Env) {
        // Only a check whose every failure throws: one that `return`s lets the caller go on.
        if !self.summarize
            || env.function == "<anonymous>"
            || env.function == "<module>"
            || returns_at_all(body)
        {
            return;
        }
        for (index, param) in env.params.iter().enumerate() {
            // `if (typeof channel !== 'string') throw ...`: never an object past the call.
            if !param.is_empty()
                && env.scalars.contains(param)
                && !env.clean.contains(param)
                && !self.summaries.get(&env.function).is_some_and(|list| {
                    list.iter()
                        .any(|s| s.api == SCALARS && s.param == index && s.scope == env.def_scope)
                })
            {
                self.summaries
                    .entry(env.function.clone())
                    .or_default()
                    .push(Summary {
                        param: index,
                        class: VulnClass::NosqlInjection,
                        severity: Severity::Low,
                        api: SCALARS.to_owned(),
                        arg: span,
                        call: span,
                        steps: Vec::new(),
                        at_sink: Origin::source("param", span),
                        ext: None,
                        field: None,
                        out_field: None,
                        defined_in: None,
                        start: false,
                        rest: false,
                        instance_of: None,
                        base_param: None,
                        with_param: None,
                        scope: env.def_scope,
                    });
            }
            // The classes it validates the parameter for (`at_sink.escaped`).
            let classes = if env.clean.contains(param) {
                guards::ALL
            } else {
                env.partial.get(param).copied().unwrap_or(0)
            };
            if param.is_empty() || classes == 0 {
                continue;
            }
            let list = self.summaries.entry(env.function.clone()).or_default();
            if list
                .iter()
                .any(|s| s.api == VALIDATES && s.param == index && s.scope == env.def_scope)
            {
                continue;
            }
            let mut at_sink = Origin::source("param", span);
            at_sink.escaped = classes;
            list.push(Summary {
                param: index,
                class: VulnClass::CodeInjection,
                severity: Severity::Low,
                api: VALIDATES.to_owned(),
                arg: span,
                call: span,
                steps: Vec::new(),
                at_sink,
                ext: None,
                field: None,
                out_field: None,
                defined_in: None,
                start: false,
                rest: false,
                instance_of: None,
                base_param: None,
                with_param: None,
                scope: env.def_scope,
            });
        }
    }

    /// Summary pass: a function that returns (a value derived from) its parameter.
    pub(super) fn record_return(
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
        // `function getDir(req) { return req.query.dir }`: returns client data itself. A value
        // built from several parameters returns each of them.
        let contributors: Vec<(usize, u32, bool, u8)> = match origin.param {
            Some(_) => origin.contributors(),
            None => std::iter::once((
                RETURNS_SOURCE,
                origin.span.start,
                origin.prefix,
                origin.escaped,
            ))
            .chain(origin.also.iter().map(|&(p, a, prefix, escaped)| {
                (p, a, prefix && origin.prefix, escaped | origin.escaped)
            }))
            .collect(),
        };
        for (param, at, prefix, escaped) in contributors {
            let field = self.field_of.get(&at).cloned();
            let list = self.summaries.entry(env.function.clone()).or_default();
            if list.iter().any(|s| {
                s.api == RETURNS
                    && s.param == param
                    && s.field == field
                    && s.out_field == out_field
                    && s.scope == env.def_scope
            }) {
                continue;
            }
            list.push(Summary {
                param,
                class: VulnClass::CodeInjection,
                severity: Severity::Low,
                api: RETURNS.to_owned(),
                arg: span,
                call: span,
                steps: origin.steps.clone(),
                at_sink: Origin {
                    prefix,
                    escaped,
                    ..origin.clone()
                },
                ext: None,
                field,
                out_field: out_field.clone(),
                defined_in: None,
                // The response of a request to the parameter's URL: the attacker's only where
                // the caller let them choose that URL's start.
                start: origin.response,
                rest: false,
                instance_of: None,
                base_param: None,
                with_param: None,
                scope: env.def_scope,
            });
        }
    }

    /// Records what a returned value carries: per field for an object literal
    /// (`return { command, args }`), as a whole otherwise.
    pub(super) fn record_returned(
        &mut self,
        argument: &Expression<'_>,
        whole: Option<Origin>,
        env: &Env,
    ) {
        if !self.summarize {
            return;
        }
        if let Some(object) = returned_object(argument)
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
                    let classes = self.value_refs(&p.value, &probe);
                    self.record_instances(classes, p.span, env, Some(key.clone()));
                    self.record_return(taint, p.span, env, Some(key));
                }
            }
            return;
        }
        let classes = self.value_refs(argument, env);
        self.record_instances(classes, argument.span(), env, None);
        self.record_return(whole, argument.span(), env, None);
    }

    /// Summary pass: the function returns an instance of each of `classes`, whole or as its
    /// `out_field` (`return new PgClient(cfg)`, `return { store: new Store(db) }`).
    pub(super) fn record_instances(
        &mut self,
        classes: Vec<ClassRef>,
        span: Span,
        env: &Env,
        out_field: Option<String>,
    ) {
        if !self.summarize
            || classes.is_empty()
            || env.function == "<anonymous>"
            || env.function == "<module>"
        {
            return;
        }
        let list = self.summaries.entry(env.function.clone()).or_default();
        for class in classes {
            let mut known = list.iter().filter(|s| {
                s.api == INSTANCE && s.out_field == out_field && s.scope == env.def_scope
            });
            let count = known.clone().count();
            if count >= MAX_RETURNED_CLASSES
                || known.any(|s| s.instance_of.as_ref() == Some(&class))
            {
                continue;
            }
            list.push(Summary {
                param: 0,
                class: VulnClass::CodeInjection,
                severity: Severity::Low,
                api: INSTANCE.to_owned(),
                arg: span,
                call: span,
                steps: Vec::new(),
                at_sink: Origin::source("param", span),
                ext: None,
                field: None,
                out_field: out_field.clone(),
                defined_in: None,
                start: false,
                rest: false,
                instance_of: Some(class),
                base_param: None,
                with_param: None,
                scope: env.def_scope,
            });
        }
    }

    /// The position that names `field` of what the call at `call` returns: the call's start,
    /// unless that already names another field; then a position past the end of any file
    /// (it never names code), the same one in every pass.
    pub(super) fn field_slot(&mut self, call: u32, field: &str) -> u32 {
        match self.field_of.get(&call) {
            Some(named) if named != field => {
                let next = u32::MAX - u32::try_from(self.field_slots.len()).unwrap_or(u32::MAX / 2);
                *self
                    .field_slots
                    .entry((call, field.to_owned()))
                    .or_insert(next)
            }
            _ => call,
        }
    }

    /// The class of ours a return type names: `Svc`, or inside a generic (`Promise<Svc>`).
    pub(super) fn annotated_returns(
        &self,
        annotation: Option<&oxc_ast::ast::TSTypeAnnotation<'_>>,
    ) -> Option<ClassRef> {
        let mut annotated = &annotation?.type_annotation;
        for _ in 0..4 {
            let oxc_ast::ast::TSType::TSTypeReference(reference) = annotated else {
                return None;
            };
            let oxc_ast::ast::TSTypeName::IdentifierReference(name) = &reference.type_name else {
                return None;
            };
            if let Some(class) = self.known_class(name.name.as_str()) {
                return Some(class);
            }
            annotated = reference.type_arguments.as_ref()?.params.first()?;
        }
        None
    }

    /// `C` where it is declared, when it names a class (or interface) of ours: imported from
    /// one of our modules, declared in this file, or the class being walked.
    pub(super) fn known_class(&self, name: &str) -> Option<ClassRef> {
        (self.relative.contains_key(name)
            || self.declared_classes.contains(name)
            || self.current_class.as_deref() == Some(name))
        .then(|| self.class_ref(name))
        .flatten()
    }

    /// The export-table entry for a class member exported under another name
    /// (`getRegistry: Registry.getInstance`): `Registry.getInstance` for a class of this file,
    /// else the defining file and name behind [`ELSEWHERE`].
    pub(super) fn member_export(&self, expr: &Expression<'_>) -> Option<String> {
        let Expression::StaticMemberExpression(member) = expr.get_inner_expression() else {
            return None;
        };
        let Expression::Identifier(class) = member.object.get_inner_expression() else {
            return None;
        };
        let (file, name) = self.known_class(class.name.as_str())?;
        let method = member.property.name.as_str();
        Some(if file == self.linking.file {
            format!("{name}.{method}")
        } else {
            format!("{ELSEWHERE}{file}#{name}.{method}")
        })
    }

    /// The classes `expr` holds an instance of, where they are declared: `new C()` of one of
    /// our classes, `new this()` in a static method, a typed variable or field (static ones
    /// too: `Registry.instance`), what an instance-returning function returned, or a property
    /// the repository types by assignment (`this.config.database`). At most
    /// [`MAX_RETURNED_CLASSES`].
    pub(super) fn value_refs(&self, expr: &Expression<'_>, env: &Env) -> Vec<ClassRef> {
        let mut out = Vec::new();
        self.collect_refs(expr, env, &mut out, 0);
        out
    }

    pub(super) fn collect_refs(
        &self,
        expr: &Expression<'_>,
        env: &Env,
        out: &mut Vec<ClassRef>,
        depth: u8,
    ) {
        fn add(out: &mut Vec<ClassRef>, class: Option<ClassRef>) {
            if let Some(class) = class
                && !out.contains(&class)
                && out.len() < MAX_RETURNED_CLASSES
            {
                out.push(class);
            }
        }
        if depth > 6 {
            return;
        }
        match expr.get_inner_expression() {
            Expression::AwaitExpression(a) => self.collect_refs(&a.argument, env, out, depth + 1),
            Expression::ConditionalExpression(c) => {
                self.collect_refs(&c.consequent, env, out, depth + 1);
                self.collect_refs(&c.alternate, env, out, depth + 1);
            }
            Expression::LogicalExpression(l) => {
                self.collect_refs(&l.left, env, out, depth + 1);
                self.collect_refs(&l.right, env, out, depth + 1);
            }
            Expression::SequenceExpression(s) => {
                if let Some(last) = s.expressions.last() {
                    self.collect_refs(last, env, out, depth + 1);
                }
            }
            // `return (Registry.instance = new Registry())`
            Expression::AssignmentExpression(a) if a.operator.is_assign() => {
                self.collect_refs(&a.right, env, out, depth + 1);
            }
            Expression::CallExpression(c) => {
                for class in self
                    .call_classes
                    .get(&(c.span.start, c.span.end, None))
                    .into_iter()
                    .flatten()
                {
                    add(out, Some(class.clone()));
                }
            }
            Expression::NewExpression(n) => match n.callee.get_inner_expression() {
                Expression::Identifier(id) => add(out, self.known_class(id.name.as_str())),
                // `new this(opts)` in a static factory: the class itself.
                Expression::ThisExpression(_) => add(
                    out,
                    self.current_class
                        .clone()
                        .map(|c| (self.linking.file.to_owned(), c)),
                ),
                _ => {}
            },
            Expression::Identifier(id) => {
                let name = id.name.as_str();
                if let Some(classes) = env.remote.get(name) {
                    for class in classes {
                        add(out, Some(class.clone()));
                    }
                } else if let Some(class) = env.instances.get(name) {
                    add(out, self.class_ref(class));
                } else if let Some(class) = env.local_instances.get(name)
                    && (self.declared_classes.contains(class.as_str())
                        || self.current_class.as_deref() == Some(class.as_str()))
                {
                    add(out, Some((self.linking.file.to_owned(), class.clone())));
                }
            }
            Expression::StaticMemberExpression(member) => {
                let field = member.property.name.as_str();
                let owner = match member.object.get_inner_expression() {
                    Expression::ThisExpression(_) => {
                        if let Some(class) = self.this_field_class(field) {
                            add(out, self.known_class(&class));
                            return;
                        }
                        self.current_class.clone()
                    }
                    // `Registry.instance`
                    Expression::Identifier(id)
                        if self.declared_classes.contains(id.name.as_str())
                            || self.current_class.as_deref() == Some(id.name.as_str()) =>
                    {
                        Some(id.name.as_str().to_owned())
                    }
                    _ => None,
                };
                if let Some(owner) = &owner {
                    let key = (owner.clone(), field.to_owned());
                    if let Some(class) = self.field_types.get(&key) {
                        add(out, self.known_class(class));
                    }
                    for class in self.field_refs.get(&key).into_iter().flatten() {
                        add(out, Some(class.clone()));
                    }
                }
                if out.is_empty()
                    && let Some(class) = self.linking.properties.get(field)
                {
                    add(out, Some(class.clone()));
                }
            }
            _ => {}
        }
    }

    /// Types what an assignment stores: a variable (`db = getDBClient(cfg)`), a field of the
    /// class being walked or a static one (`this.registry = getRegistry()`,
    /// `Registry.instance = new Registry()`). In the reporting pass, also records the property
    /// for the repository-wide table (`config.database = new DatabaseController(..)`).
    pub(super) fn type_assignment(
        &mut self,
        left: &AssignmentTarget<'_>,
        right: &Expression<'_>,
        env: &mut Env,
    ) {
        let refs = self.value_refs(right, env);
        if let AssignmentTarget::AssignmentTargetIdentifier(id) = left {
            let name = id.name.as_str();
            if let Some(class) = self.instance_class(right, None, env) {
                env.remote.remove(name);
                if self.relative.contains_key(class.as_str()) {
                    env.local_instances.remove(name);
                    env.instances.insert(name.to_owned(), class);
                } else {
                    env.instances.remove(name);
                    env.local_instances.insert(name.to_owned(), class);
                }
            } else if !refs.is_empty() {
                env.instances.remove(name);
                env.local_instances.remove(name);
                env.remote.insert(name.to_owned(), refs);
            }
            return;
        }
        if refs.is_empty() {
            return;
        }
        let Some(member) = left
            .as_simple_assignment_target()
            .and_then(SimpleAssignmentTarget::as_member_expression)
        else {
            return;
        };
        let Some(field) = member.static_property_name().and_then(|n| n.as_str()) else {
            return;
        };
        let owner = match member.object().get_inner_expression() {
            Expression::ThisExpression(_) => self.current_class.clone(),
            Expression::Identifier(id)
                if self.declared_classes.contains(id.name.as_str())
                    || self.current_class.as_deref() == Some(id.name.as_str()) =>
            {
                Some(id.name.as_str().to_owned())
            }
            _ => None,
        };
        if let Some(owner) = owner {
            let key = (owner, field.to_owned());
            if !self.field_types.contains_key(&key) {
                let entry = self.field_refs.entry(key).or_default();
                for class in &refs {
                    if !entry.contains(class) && entry.len() < MAX_RETURNED_CLASSES {
                        entry.push(class.clone());
                    }
                }
            }
        }
        if let ([class], false) = (refs.as_slice(), self.summarize) {
            self.facts
                .properties
                .push((field.to_owned(), class.clone()));
        }
    }

    /// Walks a function-valued expression, if it is one. Returns whether it was.
    pub(super) fn maybe_function(
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
}
