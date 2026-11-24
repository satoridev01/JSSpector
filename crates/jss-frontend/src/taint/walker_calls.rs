use super::*;

impl Walker<'_> {
    pub(super) fn call(&mut self, call: &CallExpression<'_>, env: &mut Env) -> Option<Origin> {
        // `self.addEventListener('fetch', ...)`, `self.skipWaiting()`: a service worker.
        if !self.service_worker
            && let Some(name) = guards::path_key(&call.callee)
        {
            let worker = &m().service_worker;
            let registers = has(&worker.registrations, &name)
                && matches!(call.arguments.first(),
                    Some(Argument::StringLiteral(event))
                        if event.value.as_str().is_some_and(|e| has(&worker.events, e)));
            if registers || has(&worker.calls, &name) {
                self.service_worker = true;
            }
        }
        let callee = self.callee(&call.callee);
        self.note_stored_writes(&callee, call, env);
        // Receiver taint (for pass-through methods), walking the callee once.
        let receiver = match call.callee.get_inner_expression().as_member_expression() {
            Some(member) => {
                // `api.get(url).then(...)`: that call returns a promise.
                if let Expression::CallExpression(inner) = member.object().get_inner_expression()
                    && member
                        .static_property_name()
                        .and_then(|n| n.as_str())
                        .is_some_and(|n| has(&m().promise_methods, n))
                {
                    self.promised.insert((inner.span.start, inner.span.end));
                }
                self.expr(member.object(), env)
            }
            None => {
                self.expr(&call.callee, env);
                None
            }
        };

        // How function arguments are entered.
        let (role, shape) = self.client_role(&callee, &call.callee, &call.arguments, env);
        // A request a client sends, with its callback: no route, no request in the callback.
        let (role, shape) = if role == Role::Route && self.client_request(call) {
            (Role::Plain, Shape::Callback)
        } else {
            (role, shape)
        };
        let registration = if role == Role::Route {
            self.registration(&callee, &call.callee, &call.arguments, env)
        } else {
            None
        };
        let route_name = match (
            &callee,
            call.arguments.first().and_then(Argument::as_expression),
            &registration,
        ) {
            // The name `record_entry` gives the same registration's inline handler.
            (_, _, Some(registration)) => registration.paths.first().map(|path| {
                self.inline_route_name(
                    &registration.method,
                    path,
                    registration.receiver.as_deref(),
                    call.span.start,
                )
            }),
            (Callee::Method { method, object }, Some(first), None) if role == Role::Route => {
                self.resolve_text(first, env).map(|path| {
                    self.inline_route_name(method, &path, object.as_deref(), call.span.start)
                })
            }
            _ => None,
        };
        // `http.createServer(async (req, res) => ...)`: every request, an entry of its own.
        let route_name = route_name.or_else(|| {
            let factory = match &callee {
                Callee::Module {
                    export: Some(e), ..
                }
                | Callee::Method { method: e, .. } => has(&m().server_factories, e),
                Callee::Global(name) => has(&m().server_factories, name),
                Callee::Module { export: None, .. } => false,
            };
            let handler = call
                .arguments
                .last()
                .and_then(Argument::as_expression)
                .filter(|e| {
                    matches!(
                        e.get_inner_expression(),
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    )
                });
            // `server.middlewares.use((req, res, next) => ...)`: a dev server's every request.
            let middleware = match &callee {
                Callee::Method { method, .. } => call
                    .callee
                    .get_inner_expression()
                    .as_member_expression()
                    .and_then(|m| match m.object().get_inner_expression() {
                        Expression::StaticMemberExpression(via) => Some(via.property.name.as_str()),
                        _ => None,
                    })
                    .and_then(|via| {
                        m().middleware_registrations
                            .iter()
                            .find(|r| has(&r.methods, method) && has(&r.via, via))
                    })
                    .map(|r| r.kind.as_str()),
                _ => None,
            };
            let kind = match (factory, middleware) {
                (true, _) => Some("http"),
                (false, Some(kind)) => Some(kind),
                (false, None) => None,
            };
            (role == Role::Route && handler.is_some())
                .then_some(kind)
                .flatten()
                .map(|kind| {
                    let name = self.inline_route_name("ANY", "*", None, call.span.start);
                    if !self.summarize && !self.record_only {
                        self.facts.routes.push(RouteFact {
                            at: None,
                            receiver: None,
                            receiver_file: None,
                            method: "ANY".to_owned(),
                            path: "*".to_owned(),
                            handler: name.clone(),
                            span: call.span,
                            auth: Auth::NoneDetected,
                            kind,
                        });
                    }
                    name
                })
        });
        // `http.createServer(handle)` / `http.createServer(makeHandler(runtime))`: every request,
        // handled by a function of this file or by the closure a local factory returns (walked as
        // the factory's own, so the factory stands for it).
        if route_name.is_none()
            && role == Role::Route
            && !self.summarize
            && !self.record_only
            && match &callee {
                Callee::Module {
                    export: Some(e), ..
                }
                | Callee::Method { method: e, .. } => has(&m().server_factories, e),
                Callee::Global(name) => has(&m().server_factories, name),
                Callee::Module { export: None, .. } => false,
            }
            && let Some(last) = call.arguments.last().and_then(Argument::as_expression)
        {
            let fact = |handler: String| RouteFact {
                at: None,
                receiver: None,
                receiver_file: None,
                method: "ANY".to_owned(),
                path: "*".to_owned(),
                handler,
                span: call.span,
                auth: Auth::NoneDetected,
                kind: "http",
            };
            match last.get_inner_expression() {
                Expression::Identifier(id) if !env.params.iter().any(|p| p == id.name.as_str()) => {
                    self.named_server_handlers
                        .push(fact(id.name.as_str().to_owned()));
                }
                Expression::CallExpression(made) => {
                    if let Expression::Identifier(factory) = made.callee.get_inner_expression()
                        && self.closure_factories.contains(factory.name.as_str())
                    {
                        self.facts
                            .routes
                            .push(fact(factory.name.as_str().to_owned()));
                    }
                }
                _ => {}
            }
        }
        // `server.on('request', ...)` / `server.on('upgrade', ...)` on a server from a server
        // factory: every request (or every upgrade request), like `http.createServer(handler)`.
        // The handler may be an inline callback (walked as part of its enclosing function, so the
        // entry covers the listener's own lines), a named function, or the closure a local factory
        // returns (`createUpgradeHandler(runtime)`, walked as the factory's own). `'upgrade'` is
        // marked a distinct method so verification drives it as an HTTP upgrade, not a plain request.
        if !self.summarize
            && !self.record_only
            && let Some(event) = self.server_event_listener(&callee, &call.arguments)
            && let Some(handler) = call.arguments.last().and_then(Argument::as_expression)
        {
            let method = if event == "upgrade" { "UPGRADE" } else { "ANY" };
            let fact = |handler: String| RouteFact {
                at: None,
                receiver: None,
                receiver_file: None,
                method: method.to_owned(),
                path: "*".to_owned(),
                handler,
                span: call.span,
                auth: Auth::NoneDetected,
                kind: "http",
            };
            match handler.get_inner_expression() {
                Expression::ArrowFunctionExpression(f) => {
                    let scoped = fact(env.function.clone());
                    self.facts.scoped_routes.push((scoped, f.span));
                }
                Expression::FunctionExpression(f) => {
                    let scoped = fact(env.function.clone());
                    self.facts.scoped_routes.push((scoped, f.span));
                }
                // The named function is the handler.
                Expression::Identifier(id) => self.facts.routes.push(fact(id.name.to_string())),
                // `createUpgradeHandler(runtime)`: a local factory that returns the handler closure.
                Expression::CallExpression(made) => {
                    if let Expression::Identifier(factory) = made.callee.get_inner_expression()
                        && self.closure_factories.contains(factory.name.as_str())
                    {
                        self.facts
                            .routes
                            .push(fact(factory.name.as_str().to_owned()));
                    }
                }
                _ => {}
            }
        }
        // `socket.on('join', (data) => ...)`: the callback goes by its entry's name, so the
        // findings in it are linked to that entry.
        let client_name = match (&role, &callee) {
            (Role::Client(kind, _), Callee::Method { object, .. }) => self
                .keyed_entries
                .get(&(call.span.start, call.span.end))
                .cloned()
                .or_else(|| {
                    self.client_event(&call.arguments, object.as_deref())
                        .map(|event| format!("{} {event}", kind.to_ascii_uppercase()))
                }),
            _ => None,
        };
        let last = call.arguments.len().saturating_sub(1);
        // Authentication middleware: `app.get(path, requireLogin, handler)`, an earlier
        // `router.use(auth)`, or `router.use(auth)` itself.
        let receiver_name = match (&registration, &callee) {
            (Some(registration), _) => registration.receiver.clone(),
            (
                None,
                Callee::Method {
                    object: Some(o), ..
                },
            ) => Some(o.clone()),
            _ => None,
        };
        let middleware_auth = call
            .arguments
            .iter()
            .take(last)
            .filter_map(Argument::as_expression)
            .filter_map(route_middleware_auth)
            .max()
            .unwrap_or_default();
        // What earlier `use(...)` calls on this router require under this route's path.
        let route_path = match &registration {
            Some(registration) => registration.paths.first().cloned(),
            None => call
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .and_then(|e| self.mount_path(e, env)),
        };
        let inherited_auth = receiver_name
            .as_deref()
            .and_then(|r| self.router_auth.get(&router_key(r, env)))
            .map(|guards| {
                let route_method = match &callee {
                    Callee::Method { method, .. } if has(&m().route_verbs, method) => {
                        Some(method.to_ascii_lowercase())
                    }
                    _ => None,
                };
                guards
                    .iter()
                    .filter(|g| g.guards(route_method.as_deref(), route_path.as_deref()))
                    .map(|g| g.auth)
                    .max()
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let route_auth = inherited_auth.max(middleware_auth);
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
            // Under a path it cannot read (`app.use(config.panelPath, guard)`, a regex, a list)
            // or only on some runs (`if (TOKEN) app.use(guard)`): nothing it guards is known.
            let unknown_scope = env.branch > 0
                || (prefix.is_none() && arguments.first().is_some_and(|e| looks_like_path(e)));
            if !unknown_scope && !middleware.iter().any(|e| self.mountable(e)) {
                // `app.use((req, res, next) => { if (..) return res.status(403)..; next(); })`
                let used = middleware
                    .iter()
                    .filter_map(|e| {
                        callee_name(e)
                            .and_then(|name| m().auth_of(&name))
                            .or_else(|| inline_guard_auth(e))
                    })
                    .max();
                if let Some(level) = used {
                    self.router_auth
                        .entry(router_key(object, env))
                        .or_default()
                        .push(RouterGuard {
                            prefix: prefix.unwrap_or_default(),
                            method: None,
                            exact: false,
                            auth: level,
                        });
                }
            }
        }
        // `mstream.all('/api/v1/admin/{*path}', (req, res, next) => { if (!req.user.admin) return
        // res.status(403)..; next(); })`: guards the routes registered after it under that path.
        if let Callee::Method {
            object: Some(object),
            method,
        } = &callee
            && !has(&m().mount_methods, method)
            && has(&m().route_methods, method)
            && call.arguments.len() == 2
            && env.branch == 0
            && let Some(level) = call
                .arguments
                .last()
                .and_then(Argument::as_expression)
                .and_then(inline_guard_auth)
            && let Some(prefix) = call
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .and_then(|e| self.mount_path(e, env))
        {
            // Up to the first wildcard: `/api/v1/admin/{*path}` guards `/api/v1/admin/...`;
            // without one, that path only. `all` is every method; a verb, its own.
            let cut = ["{*", "*", "("].iter().filter_map(|w| prefix.find(w)).min();
            let exact = cut.is_none();
            let prefix = prefix
                .get(..cut.unwrap_or(prefix.len()))
                .unwrap_or(&prefix)
                .to_owned();
            let method = method.to_ascii_lowercase();
            self.router_auth
                .entry(router_key(object, env))
                .or_default()
                .push(RouterGuard {
                    prefix,
                    method: (method != "all").then_some(method),
                    exact,
                    auth: level,
                });
        }
        // Routes are kept from the final pass only (facts reset before it); templates from any.
        {
            if role == Role::Route && !self.summarize && !self.record_only {
                let expressions: Vec<&Expression<'_>> = call
                    .arguments
                    .iter()
                    .filter_map(Argument::as_expression)
                    .collect();
                let mut positional_auth = Auth::NoneDetected;
                let mut handlers = Vec::new();
                for expression in expressions
                    .get(1..expressions.len().saturating_sub(1))
                    .unwrap_or(&[])
                {
                    if let Some(handler) = self.route_handler_name(expression) {
                        handlers.push((handler, inherited_auth.max(positional_auth)));
                    }
                    if let Some(auth) = route_middleware_auth(expression) {
                        positional_auth = positional_auth.max(auth);
                    }
                }
                if !handlers.is_empty() {
                    self.facts
                        .route_handlers
                        .insert((call.span.start, call.span.end), handlers);
                }
            }
            self.record_entry(&callee, call, role, route_auth, env);
            // `routes.forEach((r) => router[r.method](r.path, r.handler))`: one record-only
            // walk of the callback per known row.
            if let Callee::Method {
                object: Some(table),
                method,
            } = &callee
                && !self.summarize
                && !self.record_only
                && has(&m().iteration_methods, method)
                && let Some(rows) = env.tables.get(table).cloned()
                && let Some(callback) = call.arguments.first().and_then(Argument::as_expression)
            {
                let params = match callback.get_inner_expression() {
                    Expression::ArrowFunctionExpression(f) => Some(&f.params),
                    Expression::FunctionExpression(f) => Some(&f.params),
                    _ => None,
                };
                let pattern = params.and_then(|p| p.items.first()).map(|p| &p.pattern);
                // `(r) => ...`: the row stands for `r`, fields read as `r.field`.
                let var = pattern.and_then(|p| match p {
                    BindingPattern::BindingIdentifier(id) => Some(id.name.as_str().to_owned()),
                    _ => None,
                });
                // `({ path, route }) => ...`: the row's fields are destructured into bare locals.
                let destructured: Vec<(String, String)> = match pattern {
                    Some(BindingPattern::ObjectPattern(object)) => object
                        .properties
                        .iter()
                        .filter_map(|p| {
                            let field = prop_name(&p.key)?;
                            let local = match &p.value {
                                BindingPattern::BindingIdentifier(id) => {
                                    id.name.as_str().to_owned()
                                }
                                _ => return None,
                            };
                            Some((field, local))
                        })
                        .collect(),
                    _ => Vec::new(),
                };
                if var.is_some() || !destructured.is_empty() {
                    for row in rows.into_iter().take(100) {
                        let mut inner = env.clone();
                        if let Some(var) = &var {
                            inner.rows.insert(var.clone(), row.clone());
                        }
                        for (field, local) in &destructured {
                            if let Some(value) = row.get(field) {
                                inner.row_fields.insert(local.clone(), value.clone());
                            }
                        }
                        let saved = std::mem::replace(&mut self.record_only, true);
                        self.maybe_function(callback, &inner, None, Role::Plain);
                        self.record_only = saved;
                    }
                }
            }
        }
        // `list.map((x) => ...)`, `p.then((v) => ...)`, `s.replace(re, (m) => ...)`: what the
        // callback is called with, and what it returns.
        let (callback_spec, method_name) = match &callee {
            Callee::Method { method, .. } if !method.is_empty() => {
                (m().callbacks.get(method).cloned(), method.clone())
            }
            _ => (None, String::new()),
        };
        // `reduce((acc, x) => ..., initial)`: the accumulator starts as the initial value
        // (walked ahead for its taint only: no findings from this walk).
        let initial = match &callback_spec {
            Some(spec) if spec.accumulator.is_some() => call
                .arguments
                .get(spec.callback + 1)
                .and_then(Argument::as_expression)
                .and_then(|e| {
                    let saved = std::mem::replace(&mut self.record_only, true);
                    let mut probe = env.clone();
                    let taint = self.expr(e, &mut probe);
                    self.record_only = saved;
                    taint
                }),
            _ => None,
        };
        let element = receiver
            .clone()
            .map(|o| o.step(call.span.start, format!("element of .{method_name}()")));
        let mut callback_result: Option<Origin> = None;
        let mut taints = Vec::with_capacity(call.arguments.len());
        self.pending_archive = checked_archive(&callee, &call.arguments);
        for (index, argument) in call.arguments.iter().enumerate() {
            let arg_role = match shape {
                Shape::LastCallback if index != last => Role::Plain,
                Shape::ObjectOfFunctions => Role::Plain,
                _ => role,
            };
            let callback = callback_spec
                .as_ref()
                .filter(|spec| spec.callback == index && arg_role == Role::Plain);
            if let Some(spec) = callback
                && (element.is_some() || initial.is_some())
            {
                let positions = call
                    .callee
                    .get_inner_expression()
                    .as_member_expression()
                    .and_then(|member| self.tuple_positions(member.object(), env));
                self.pending_element = Some(PendingElement {
                    element: element.clone(),
                    initial: initial.clone(),
                    spec: spec.clone(),
                    positions,
                });
            }
            self.callback_returns = None;
            let callbacks_object = matches!(shape, Shape::ObjectOfFunctions | Shape::RouteObject)
                && matches!(
                    argument
                        .as_expression()
                        .map(Expression::get_inner_expression),
                    Some(Expression::ObjectExpression(_))
                );
            if arg_role == Role::Route {
                let preceding_auth = call
                    .arguments
                    .iter()
                    .skip(1)
                    .take(index.saturating_sub(1))
                    .filter_map(Argument::as_expression)
                    .filter_map(route_middleware_auth)
                    .max()
                    .unwrap_or_default();
                let inline = argument.as_expression().is_some_and(|expression| {
                    matches!(
                        expression.get_inner_expression(),
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    )
                });
                self.pending_auth = if inline {
                    inherited_auth.max(preceding_auth)
                } else {
                    // Named handlers are attributed after the cross-file call graph is linked.
                    // Keeping positional auth in this global pending slot would leak the last
                    // handler's guard into an earlier handler that is walked later.
                    Auth::NoneDetected
                };
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
                (Some(expr), _)
                    if matches!(arg_role, Role::Client(..))
                        && index == last
                        && client_name.is_some() =>
                {
                    if self.maybe_function(expr, env, client_name.clone(), arg_role) {
                        self.apply_closure_writes(env);
                        None
                    } else {
                        self.expr(expr, env)
                    }
                }
                _ => self.argument(argument, env, arg_role),
            };
            if let Some(spec) = callback {
                self.pending_element = None;
                let is_function = argument.as_expression().is_some_and(|e| {
                    matches!(
                        e.get_inner_expression(),
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    )
                });
                callback_result = if is_function {
                    self.callback_returns.take()
                } else {
                    // `ids.map(Number)`, `items.forEach(save)`: the function by what it does.
                    let spec = spec.clone();
                    argument.as_expression().and_then(|e| {
                        self.callback_by_reference(
                            e,
                            &spec,
                            element.clone(),
                            initial.clone(),
                            call.span,
                            env,
                        )
                    })
                };
            }
            taints.push(taint);
        }
        // A callback passed by name, or none: no parameter of a later function is the archive.
        self.pending_archive = None;
        self.call_tail(
            call,
            env,
            callee,
            receiver,
            role,
            shape,
            taints,
            callback_spec,
            callback_result,
            initial,
        )
    }

    /// The part of [`Self::call`] after its arguments are walked: object callbacks, stores,
    /// lowering, sinks, summaries and the result. Kept out of `call`'s stack frame, which
    /// every level of nested calls holds while their arguments are walked.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn call_tail(
        &mut self,
        call: &CallExpression<'_>,
        env: &mut Env,
        callee: Callee,
        receiver: Option<Origin>,
        role: Role,
        shape: Shape,
        taints: Vec<Option<Origin>>,
        callback_spec: Option<models::CallbackSpec>,
        callback_result: Option<Origin>,
        initial: Option<Origin>,
    ) -> Option<Origin> {
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
                    if let Some(azure) = azure_http_route(&callee, &call.arguments) {
                        return azure;
                    }
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
                            .filter(|v| !v.is_empty())
                            .unwrap_or_else(|| "ANY".to_owned())
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
                        at: None,
                        receiver,
                        receiver_file: None,
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

        // `args.push(x)`, `map.set(k, v)`, `Object.assign(target, src)`: the value is stored in
        // the receiver (a weak update: it never clears).
        let stored = match &callee {
            Callee::Method { method, .. } => m().store_methods.get(method).and_then(|&from| {
                let member = call.callee.get_inner_expression().as_member_expression()?;
                Some((member.object(), from))
            }),
            Callee::Global(name) if has(&m().store_globals, name) => call
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .map(|target| (target, 1)),
            _ => None,
        };
        if let Some((target, from)) = stored {
            // `extras.push(['topic', topic])`: tuples, position by position.
            if let Expression::Identifier(id) = target.get_inner_expression() {
                let name = id.name.as_str().to_owned();
                let stored: Vec<&Expression<'_>> = call
                    .arguments
                    .iter()
                    .skip(from)
                    .filter_map(Argument::as_expression)
                    .collect();
                let tuples: Option<Vec<Vec<Option<Origin>>>> = stored
                    .iter()
                    .map(|e| match e.get_inner_expression() {
                        Expression::ArrayExpression(array) => {
                            Some(self.array_positions(array, env))
                        }
                        _ => None,
                    })
                    .collect();
                match tuples {
                    Some(tuples) if !tuples.is_empty() => {
                        let mut merged = env.tuples.remove(&name).unwrap_or_default();
                        for tuple in tuples {
                            merge_positions(&mut merged, tuple);
                        }
                        env.tuples.insert(name, merged);
                    }
                    _ => {
                        env.tuples.remove(&name);
                    }
                }
            }
            // `args.push('--', pattern)`: what follows the end of options (in this call or an
            // earlier one) is positional, never an option.
            let target_name = match target.get_inner_expression() {
                Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
                _ => None,
            };
            let mut ended = target_name
                .as_ref()
                .is_some_and(|n| env.options_ended.contains(n));
            let mut value = None;
            for (argument, taint) in call.arguments.iter().zip(&taints).skip(from) {
                if ends_options(argument.as_expression()) {
                    ended = true;
                    continue;
                }
                let taint = taint.clone().map(|mut o| {
                    o.dash_free |= ended;
                    o
                });
                value = union(value, taint);
            }
            // `u.set(k, v)` on a `new URLSearchParams()`: percent-encoded in its text form.
            if target_name
                .as_ref()
                .is_some_and(|n| env.encoded.contains(n))
            {
                value = value.map(|mut o| {
                    o.escaped |= ENCODED;
                    o
                });
            }
            if let (true, Some(name)) = (ended, target_name) {
                env.options_ended.insert(name);
            }
            if let Some(value) = value {
                self.store_into(target, value, call.span.start, env);
            }
        }

        // Lowering: the call, its callee and what each argument is. A method of a typed
        // receiver is recorded by its class (`c.h()` on a `Ctl` is `Ctl.h`), so the call graph
        // links it.
        if !self.summarize
            && !self.record_only
            && let Some(callee_text) = self.typed_callee(&callee, call, env)
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
                        // The request/context object itself passed on (`handler(req)`, or an alias
                        // `const request = req; util(request)`): the callee receives the live request,
                        // so this call forwards it. A bare request identifier carries no member taint,
                        // so it would otherwise read as `Other` and hide a genuine forward.
                        (Some(expr), _) if self.request_kind(expr, env).is_some() => {
                            jss_core::ir::Value::Source(
                                self.request_kind(expr, env).unwrap_or("http").to_owned(),
                            )
                        }
                        (_, Some(origin)) => jss_core::ir::Value::Source(origin.kind.to_owned()),
                        _ => jss_core::ir::Value::Other,
                    }
                })
                .collect();
            self.facts
                .calls
                .entry(env.owner.clone())
                .or_default()
                .push((callee_text, call.span.start, args));
        }

        // `a.setAttribute('href', v)` on `document.createElement('a')`.
        if let Callee::Method {
            object: Some(object),
            method,
        } = &callee
            && let Some(tag) = env.node_tags.get(object)
            && m()
                .url_attributes
                .as_ref()
                .is_some_and(|u| has(&u.setters, method))
            && let Some(Expression::StringLiteral(attribute)) = call
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .map(Expression::get_inner_expression)
            && let Some(attribute) = attribute.value.as_str()
            && let Some(sink) = m().url_attribute(tag, attribute)
            && let Some(Some(origin)) = taints.get(1)
            && let Some(value) = call.arguments.get(1)
        {
            let api = format!("{object}.{method}('{attribute}')");
            self.url_sink(sink, api, value.span(), call.span, origin.clone(), env);
        }
        // `handleToolCall(request)` in an MCP handler: the kind of request the first argument is.
        if let Callee::Global(name) = &callee {
            let passed = match call
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .map(Expression::get_inner_expression)
            {
                Some(Expression::Identifier(id)) => env.requests.get(id.name.as_str()).copied(),
                _ => None,
            }
            .or_else(|| {
                taints
                    .first()
                    .and_then(Option::as_ref)
                    .filter(|o| o.param.is_none())
                    .map(|o| o.kind)
            });
            if let Some(kind) = passed {
                let entry = self.caller_kinds.entry(name.clone()).or_insert(kind);
                if kind == "http" {
                    *entry = kind;
                }
            }
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
                // `document.write(...)` before any `write(...)`; `res.status(404).send(...)` is
                // `res.send(...)` when `status` returns its receiver.
                let qualified = call
                    .callee
                    .get_inner_expression()
                    .as_member_expression()
                    .and_then(|mem| guards::path_key(receiver_of_chain(mem.object())))
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
            Callee::Global(name) => {
                let list = self.visible_summaries(name);
                (!list.is_empty()).then(|| (name.clone(), list))
            }
            Callee::Method {
                object: Some(object),
                ..
            } if self.relative.contains_key(object)
                || self.modules.contains_key(object)
                || env.instances.contains_key(object) =>
            {
                None
            }
            // Only for a receiver we know is this file's: `Class.m()`, `this.m()` in the class,
            // a `new LocalClass()` instance, or an object literal declared here (whose methods
            // go by their own names). Not `this.cache.read()` matched to any `*.read`.
            Callee::Method {
                object: Some(object),
                method,
            } if !method.is_empty() => {
                let class = if object == "this" {
                    self.current_class.clone()
                } else {
                    env.local_instances.get(object).cloned()
                };
                [
                    Some(format!("{object}.{method}")),
                    class.map(|c| format!("{c}.{method}")),
                    env.fields.contains_key(object).then(|| method.clone()),
                ]
                .into_iter()
                .flatten()
                .find_map(|key| self.summaries.get(&key).map(|s| (key, s.clone())))
            }
            // `this._rebuild(path)`: a method of the class being walked.
            Callee::Method {
                object: None,
                method,
            } if !method.is_empty()
                && call
                    .callee
                    .get_inner_expression()
                    .as_member_expression()
                    .is_some_and(|m| {
                        matches!(
                            m.object().get_inner_expression(),
                            Expression::ThisExpression(_)
                        )
                    }) =>
            {
                self.current_class
                    .as_ref()
                    .map(|c| format!("{c}.{method}"))
                    .and_then(|key| self.summaries.get(&key).map(|s| (key, s.clone())))
            }
            // `new Svc(cfg).run(x)` with `Svc` a class of this file.
            Callee::Method {
                object: None,
                method,
            } if !method.is_empty() => call
                .callee
                .get_inner_expression()
                .as_member_expression()
                .and_then(|m| match m.object().get_inner_expression() {
                    Expression::NewExpression(n) => match n.callee.get_inner_expression() {
                        Expression::Identifier(id)
                            if !self.relative.contains_key(id.name.as_str()) =>
                        {
                            Some(format!("{}.{method}", id.name.as_str()))
                        }
                        _ => None,
                    },
                    _ => None,
                })
                .and_then(|key| self.summaries.get(&key).map(|s| (key, s.clone()))),
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
            // `require('./shell').run(x)`: that module's `run`; `api.users.gen(x)`: the `gen` of
            // the module `api` exports as its `users` namespace; `new Svc().run(x)` with `Svc`
            // imported: its method.
            Callee::Method {
                object: None,
                method,
            } if !method.is_empty() => {
                let member = call.callee.get_inner_expression().as_member_expression();
                let constructed = member.and_then(|m| match m.object().get_inner_expression() {
                    Expression::NewExpression(n) => match n.callee.get_inner_expression() {
                        Expression::Identifier(id) => self
                            .relative
                            .get(id.name.as_str())
                            .map(|r| (id.name.as_str().to_owned(), r.clone())),
                        _ => None,
                    },
                    _ => None,
                });
                match (constructed, member.and_then(|m| require_spec(m.object()))) {
                    (Some((class, (spec, export))), _) => {
                        Some(class_target(self, &spec, export.as_deref(), &class, method))
                    }
                    (None, Some(spec)) if self.linking.is_own(&spec) => Some(Target {
                        exact: self.exported_function(&spec, method),
                        names: vec![method.clone()],
                        spec,
                    }),
                    (None, Some(_)) => None,
                    (None, None) => member
                        .and_then(|m| self.namespace_file(m.object()))
                        .and_then(|file| self.exported_function_in(&file, method))
                        .map(|exact| Target {
                            spec: String::new(),
                            names: vec![method.clone()],
                            exact: Some(exact),
                        }),
                }
            }
            // `shell.run()` on `const shell = new ShellService()`: the imported class's method.
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
            let last = name.rsplit('.').next().unwrap_or(&name);
            let mut matching = self
                .linking
                .external_names
                .get(last)
                .into_iter()
                .flatten()
                .filter(|k| k.ends_with(&suffix))
                .filter_map(|k| self.external.get(k).map(|list| (k, list)))
                .filter(|(_, list)| list.iter().any(&defined_there));
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
        // `m.get(id)` on an `m: Mem` with no `Mem.get` of its own (an abstract class or an
        // interface): the `get` of every class that extends or implements `Mem`. A receiver
        // known only by what a function returned (`getDBClient(cfg).runQuery(sql)`): the
        // method of each class it returns.
        let dispatched: Vec<(String, Vec<Summary>)> = match (&helper, &callee) {
            (None, Callee::Method { method, .. }) => {
                match self.receiver_class(&callee, call, env) {
                    Some(class) => self.dispatch_candidates(&class, method),
                    None => {
                        let classes = self.receiver_refs(&callee, call, env);
                        self.class_method_summaries(&classes, method)
                    }
                }
            }
            _ => Vec::new(),
        };
        // `getDBClient(cfg)` returning `new PgClient(cfg)`: the classes the call returns, for
        // `.m()` on it and the names it is bound to.
        let mut returned_classes: BTreeMap<Option<String>, Vec<ClassRef>> = BTreeMap::new();
        for (_, summaries) in helper.iter().chain(&dispatched) {
            for s in summaries.iter().filter(|s| s.api == INSTANCE) {
                if let Some(class) = &s.instance_of {
                    let entry = returned_classes.entry(s.out_field.clone()).or_default();
                    if !entry.contains(class) && entry.len() < MAX_RETURNED_CLASSES {
                        entry.push(class.clone());
                    }
                }
            }
        }
        for (field, classes) in returned_classes {
            self.call_classes
                .insert((call.span.start, call.span.end, field), classes);
        }
        let returned = helper.as_ref().and_then(|(name, summaries)| {
            let mut whole = None;
            for s in summaries.iter().filter(|s| s.api == RETURNS) {
                let origin = if s.param == RETURNS_SOURCE {
                    let mut origin = Origin::source(s.at_sink.kind, call.span);
                    origin.object = s.at_sink.object;
                    origin.upload = s.at_sink.upload;
                    Some(origin)
                } else {
                    let arg = argument_taint(&taints, s.param, s.rest);
                    match &s.field {
                        Some(field) => {
                            let value =
                                self.field_taint(call.arguments.get(s.param), field, env, arg);
                            // Summarizing a function that passes its own parameter on: what it
                            // returns is that parameter's `field` too (`resolveTarget(options)`
                            // returning `options.path`).
                            match value {
                                Some(mut origin)
                                    if self.summarize
                                        && origin.param.is_some()
                                        && !self.field_of.contains_key(&origin.span.start) =>
                                {
                                    // Each field it returns gets its own position, so a value
                                    // built from several of them (`${o.a} ${o.b}`) names each.
                                    let slot = self.field_slot(call.span.start, field);
                                    if let Some(class) =
                                        self.ctor_params.get(&origin.span.start).cloned()
                                    {
                                        self.ctor_params.insert(slot, class);
                                    }
                                    if let Some(owner) =
                                        self.param_owner.get(&origin.span.start).cloned()
                                    {
                                        self.param_owner.insert(slot, owner);
                                    }
                                    origin.span = if slot == call.span.start {
                                        call.span
                                    } else {
                                        Span::new(slot, slot)
                                    };
                                    self.field_of.insert(slot, field.clone());
                                    Some(origin)
                                }
                                other => other,
                            }
                        }
                        None => arg,
                    }
                };
                // What the helper did to the value on its way out: built into a string,
                // put after a prefix, converted to a string, escaped.
                // A response: only of a URL whose start the caller let the attacker choose.
                let origin = origin
                    .filter(|o| !s.start || o.prefix)
                    .map(|o| response_of_value(o, s));
                let at = &s.at_sink;
                let Some(origin) = origin.map(|mut o| {
                    o.built |= at.built;
                    o.sqlish |= at.sqlish;
                    o.htmlish |= at.htmlish;
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
        // `remoteImagePlace(tab)` returning `{ note, workspace, data }`: a helper whose return
        // summaries are all per field returns an object literal, whose other fields are clean.
        let fields_only = helper.as_ref().is_some_and(|(_, summaries)| {
            summaries
                .iter()
                .filter(|s| s.api == RETURNS)
                .all(|s| s.out_field.is_some())
        });
        if fields_only && !returned_fields.is_empty() {
            self.call_fields
                .insert((call.span.start, call.span.end), returned_fields.clone());
        } else {
            self.call_fields.remove(&(call.span.start, call.span.end));
        }
        self.last_returned_fields = (!returned_fields.is_empty()).then_some(returned_fields);
        // `isValidRequest(req, fileName)`: past the call, what it validates is clean.
        if let Some((_, summaries)) = &helper {
            let validated: Vec<(String, guards::Fact)> = summaries
                .iter()
                .filter(|s| s.api == VALIDATES || s.api == SCALARS)
                .filter_map(|s| {
                    call.arguments
                        .get(s.param)
                        .and_then(Argument::as_expression)
                        .and_then(guards::path_key)
                        .map(|key| {
                            let fact = if s.api == SCALARS {
                                guards::Fact::Scalar
                            } else {
                                guards::Fact::Clean(s.at_sink.escaped)
                            };
                            (key, fact)
                        })
                })
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
        let mut returned = returned;
        for (name, summaries) in &dispatched {
            self.apply_summaries(
                name,
                summaries,
                &taints,
                Some(&call.arguments),
                call.span,
                env,
            );
            returned = union(
                returned,
                summary_returns(name, summaries, &taints, call.span),
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
                            htmlish: false,
                            escaped: 0,
                            param: None,
                            object: true,
                            also: Vec::new(),
                            upload: false,
                            dash_free: false,
                            response: false,
                            primary_escaped: 0,
                        })
                    })
                    .collect();
                self.apply_summaries(&name, &summaries, &synthetic, None, call.span, env);
            }
        }

        // `run.call(null, x)`, `run.apply(null, [x])`, `setImmediate(run, x)`.
        if let Some(returned) = self.indirect_call(call, &taints, env) {
            return returned;
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
            && (returned.is_none()
                || m()
                    .signed_words
                    .iter()
                    .any(|w| last_segment.contains(w.as_str())))
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
        // `sanitizeUrl(u)` (a helper of ours by that name too): a URL with a harmless scheme.
        if let Some(mut origin) = returned.clone()
            && m()
                .url_checks
                .iter()
                .any(|c| c.eq_ignore_ascii_case(&last_segment))
        {
            origin.prefix = false;
            return Some(origin.step(call.span.start, format!("URL checked by `{callee_text}()`")));
        }
        if returned.is_some() {
            return returned;
        }
        // `await fetch(url)` where the attacker chose the URL's start: the response is theirs.
        if let Some(response) = self.response_of(&callee, &taints, call.span) {
            return Some(response);
        }
        let any_arg = || taints.iter().flatten().next().cloned();
        match &callee {
            Callee::Method { method, .. }
                if callback_spec
                    .as_ref()
                    .is_some_and(|s| s.returns || s.keeps_receiver) =>
            {
                let spec = callback_spec.as_ref()?;
                let mut result = if spec.keeps_receiver {
                    receiver.clone()
                } else {
                    None
                };
                if spec.returns {
                    result = union(result, callback_result);
                    if spec.accumulator.is_some() {
                        result = union(result, initial);
                    }
                }
                result.map(|o| o.step(call.span.start, format!("returned through .{method}()")))
            }
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
                        htmlish: false,
                        escaped: 0,
                        param: None,
                        object: true,
                        also: Vec::new(),
                        upload: false,
                        dash_free: false,
                        response: false,
                        primary_escaped: 0,
                    });
                }
                // Pack result sources: `zip.getEntries()`, or a qualified library API such as
                // `unzipper.Open.buffer()`. Resolve the root identifier through the import map
                // so aliases do not weaken the module constraint.
                let chain = receiver_chain(&call.callee);
                let family = match &callee {
                    Callee::Module { family, .. } => Some(*family),
                    _ => chain
                        .iter()
                        .rev()
                        .find_map(|name| self.modules.get(name).map(|imported| imported.family)),
                };
                if let Some(source) = m().result_sources.iter().find(|source| {
                    has(&source.methods, method)
                        && source
                            .family
                            .as_deref()
                            .is_none_or(|expected| family == Some(expected))
                        && source.via.iter().all(|expected| has(&chain, expected))
                }) {
                    return Some(Origin::source(source.kind.as_str(), call.span));
                }
                // `schema.safeParse(req.body)`: the input, typed by the schema (no operator objects).
                if has(&m().validating_methods, method) {
                    return any_arg().map(|mut o| {
                        o.object = false;
                        o.step(call.span.start, format!("validated by .{method}()"))
                    });
                }
                // `String(v).replace(/[&<>"']/g, (c) => ESC[c])`: every markup character
                // replaced by what a function or table gives (an entity): an HTML escaper.
                if has(&m().strip_methods, method) && escapes_markup(&call.arguments) {
                    return receiver.map(|mut o| {
                        o.escaped |= class_bit(VulnClass::Xss);
                        o.step(call.span.start, "markup characters replaced".to_owned())
                    });
                }
                // `v.replace(/'/g, "''")`: quotes doubled, safe inside a quoted SQL string.
                if has(&m().strip_methods, method) && doubles_quotes(&call.arguments) {
                    return receiver.map(|mut o| {
                        o.escaped |= class_bit(VulnClass::SqlInjection);
                        o.step(call.span.start, "quotes doubled".to_owned())
                    });
                }
                // `/a(.*)/.exec(s)`: the match and its groups are parts of `s` (only characters
                // an anchored allowlist admits: `/^(\d+)\.png$/` leaves nothing to attack).
                if has(&m().regex_methods, method)
                    && let Some(member) = call.callee.get_inner_expression().as_member_expression()
                    && let Some(classes) = self.regex_mask(member.object(), env)
                {
                    if classes == guards::ALL {
                        return None;
                    }
                    return taints.first().cloned().flatten().map(|mut o| {
                        o.object = false;
                        o.escaped |= classes;
                        o.step(
                            call.span.start,
                            "matched by a regular expression".to_owned(),
                        )
                    });
                }
                // `s.match(/^(\d+)$/)`: likewise.
                if has(&m().match_methods, method)
                    && let Some(classes) = call
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .and_then(|regex| self.regex_mask(regex, env))
                {
                    if classes == guards::ALL {
                        return None;
                    }
                    return receiver.map(|mut o| {
                        o.object = false;
                        o.escaped |= classes;
                        o.step(call.span.start, format!("matched by .{method}()"))
                    });
                }
                // `items.find(..)`, `list.filter(..)`, `args.pop()`: elements of the receiver,
                // never the arguments (`User.find({ name })` is a query, not its result).
                if has(&m().element_methods, method) {
                    return receiver
                        .map(|o| o.step(call.span.start, format!("element of .{method}()")));
                }
                // `s.replace(/[^a-z0-9_-]/gi, '')`: an allowlist strip leaves only the characters
                // it keeps, safe for the classes they cannot attack.
                if has(&m().strip_methods, method)
                    && let Some(classes) = allowlist_strip(&call.arguments)
                {
                    if classes == guards::ALL {
                        return None;
                    }
                    return receiver.map(|mut o| {
                        o.escaped |= classes;
                        o.step(call.span.start, format!("stripped by .{method}()"))
                    });
                }
                // `url.replace(/^https?:\/\/[^/]+/, 'https://proxy.example')`: the start of the
                // value is now that literal origin.
                let rewrites_start = has(&m().strip_methods, method)
                    && matches!(
                        (call.arguments.first(), call.arguments.get(1)),
                        (Some(Argument::RegExpLiteral(regex)), Some(Argument::StringLiteral(with)))
                            if regex.regex.pattern.text.as_str().starts_with('^')
                                && with.value.as_str().is_some_and(guards::fixed_origin)
                    );
                // `new URLSearchParams(location.search).get('next')`: a value of the receiver,
                // never of the argument (`ALLOWED.get(req.query.k)` stays clean).
                if has(&m().receiver_reads, method) {
                    return receiver.map(|mut o| {
                        o.prefix = true;
                        o.built = false;
                        // A value read back is decoded: whatever encoding the receiver's text
                        // form had does not apply to it.
                        o.escaped = 0;
                        o.primary_escaped = 0;
                        o.step(call.span.start, format!("read by .{method}()"))
                    });
                }
                if has(&m().pass_methods, method) {
                    let built = has(&m().build_methods, method);
                    let taint = union(receiver, any_arg()).map(|mut o| {
                        if rewrites_start {
                            o.prefix = false;
                        }
                        o
                    });
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
                // `deepcopy(x)`: the module's own (default) function goes by the module's name.
                let qualified = if export.is_empty() {
                    (*family).to_owned()
                } else {
                    format!("{family}.{export}")
                };
                // `_.cloneDeep(o)`, `_.get(o, path)`: the first argument, objects included (the
                // path picks a part of it; a clean object gives a clean part).
                if has(&m().object_module_pass, &qualified) {
                    return taints
                        .first()
                        .cloned()
                        .flatten()
                        .map(|o| o.step(call.span.start, format!("through {qualified}()")));
                }
                if has(&m().clearing, &qualified) {
                    // `path.basename(p)`: safe as a file name, not in a shell or a query.
                    let classes = guards::named_mask(export, Some(&qualified));
                    if classes == guards::ALL {
                        return None;
                    }
                    return any_arg().map(|mut o| {
                        o.escaped |= classes;
                        o.object = false;
                        o.step(call.span.start, format!("through {qualified}()"))
                    });
                }
                if has(&m().module_pass, &qualified) {
                    let built = has(&m().build_methods, export);
                    // `path.join(root, x)` starts with a clean `root` (unlike `path.resolve`,
                    // where an absolute `x` wins): the attacker no longer chooses the start.
                    let fixed_start = has(&m().root_joins, &qualified)
                        && call.arguments.len() > 1
                        && taints.first().is_some_and(Option::is_none);
                    return any_arg().map(|mut o| {
                        o.built |= built;
                        // `path.join(...)`, `util.format(...)`: a string.
                        o.object = false;
                        if fixed_start {
                            o.prefix = false;
                        }
                        o.step(call.span.start, format!("through {qualified}()"))
                    });
                }
                None
            }
            Callee::Global(name) => {
                // `Object.keys(req.body)`: attacker-chosen keys; `Object.entries` adds the values.
                if has(&m().key_globals, name) {
                    let keys = call
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .and_then(|e| {
                            self.keys_taint(e, taints.first().and_then(Option::as_ref), env)
                        });
                    let values = if has(&m().pass_globals, name) {
                        taints.first().cloned().flatten()
                    } else {
                        None
                    };
                    return union(keys, values).map(|mut o| {
                        o.object = has(&m().object_globals, name);
                        o.step(call.span.start, format!("through {name}()"))
                    });
                }
                if has(&m().clearing, name) {
                    // `encodeURIComponent(x)`: safe in a URL, not in a quoted SQL string.
                    let classes = guards::named_mask(name, None);
                    if classes == guards::ALL {
                        return None;
                    }
                    return any_arg().map(|mut o| {
                        o.escaped |= classes;
                        o.object = false;
                        o.step(call.span.start, format!("through {name}()"))
                    });
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
    pub(super) fn client_role(
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
        let family = match callee {
            Callee::Module { family, .. } => Some(*family),
            _ => None,
        };
        // `zipfile.on('entry', ...)` on an archive whose library checks entry names.
        let checked = object.is_some_and(|o| env.validated_archives.contains(o));
        for source in &model.client_sources {
            if !has(&source.methods, method)
                || checked
                || source.object.as_deref().is_some_and(|o| object != Some(o))
                // The receiver's name, class or chain: `emailQueue`, `q = new Queue('emails')`,
                // `t.procedure.input(schema).query(..)`.
                || (!source.object_contains.is_empty() && {
                    let class = object
                        .and_then(|o| env.local_instances.get(o).or_else(|| env.instances.get(o)));
                    let chain = receiver_chain(callee_expr);
                    !any_contains(
                        object
                            .into_iter()
                            .chain(class.map(String::as_str))
                            .chain(chain.iter().map(String::as_str)),
                        &source.object_contains,
                    )
                })
                || source.family.as_deref().is_some_and(|f| family != Some(f))
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
        // By the receiver's name only an inline `(req, res, ...)` handler: a Redux store's
        // `middlewares.push(thunk)` is no server.
        let handler = |e: &Expression<'_>| match e.get_inner_expression() {
            Expression::ArrowFunctionExpression(f) => f.params.items.len() >= 2,
            Expression::FunctionExpression(f) => f.params.items.len() >= 2,
            _ => false,
        };
        // webpack-dev-server: `middlewares.unshift({ name, path, middleware: (req, res) => ... })`.
        let handler_object = arguments.iter().any(|a| {
            matches!(a.as_expression().map(Expression::get_inner_expression),
                Some(Expression::ObjectExpression(o)) if o.properties.iter().any(|p| matches!(p,
                    ObjectPropertyKind::ObjectProperty(p) if handler(&p.value))))
        });
        let inline_handler = handler_object
            || arguments
                .iter()
                .any(|a| a.as_expression().is_some_and(handler));
        if let Some(registration) = model.middleware_registrations.iter().find(|r| {
            has(&r.methods, method)
                && (via.as_deref().is_some_and(|v| has(&r.via, v))
                    || (inline_handler && object.is_some_and(|o| has(&r.objects, o))))
        }) {
            self.pending_request_kind
                .set(Some(registration.kind.as_str()));
            let shape = if handler_object {
                Shape::ObjectOfFunctions
            } else {
                Shape::Callback
            };
            return (Role::Route, shape);
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
            // Azure Functions v4: `app.http('name', { route, methods, handler })` — the options
            // object (with the handler) follows the function-name argument, so it is driven as a
            // route object whose path/method come from the Azure route template.
            if azure_http_route(callee, arguments).is_some() {
                return (Role::Plain, Shape::RouteObject);
            }
            // `app.get(path, handler)` on a router: a factory's product, a router-like name or a
            // helper's parameter, never `$.get(url, cb)` or `schema.post('save', fn)`.
            if has(&model.route_methods, method)
                && arguments.len() >= 2
                && object.is_some_and(|o| self.is_router(o) || env.params.iter().any(|p| p == o))
            {
                return (Role::Route, Shape::Callback);
            }
            // `router.route('POST', '/x', h)`, `app.route('/x').get(h)`, `Router().get('/a', h)`.
            if self
                .registration(callee, callee_expr, arguments, env)
                .is_some()
            {
                return (Role::Route, Shape::Callback);
            }
        }
        (Role::Plain, Shape::Callback)
    }

    /// The taint of `argument.field`: from an object literal's property, a variable's tracked
    /// fields, or (when neither is known) the whole argument.
    pub(super) fn field_taint(
        &mut self,
        argument: Option<&Argument<'_>>,
        field: &str,
        env: &Env,
        whole: Option<Origin>,
    ) -> Option<Origin> {
        let expr = argument?.as_expression()?.get_inner_expression();
        // The server chose this field: an upload's `path` (`move(req.file)`, or of an upload
        // that went through an array or a loop: `for (const file of req.files) move(file)`), or
        // a field a client source lists as the server's.
        if has(&m().upload_server_fields, field)
            && (whole.as_ref().is_some_and(|o| o.upload) || self.is_upload_object(expr, env))
        {
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
        // `if (!isSafe(opts.path)) return; helper(opts)`, `opts.type = 'note'; helper(opts)`:
        // that field is clean here.
        if let Expression::Identifier(id) = expr
            && env.clean.contains(&format!("{}.{field}", id.name.as_str()))
        {
            return None;
        }
        self.field_taint_expr(expr, field, env, whole)
    }

    /// [`Self::field_taint`] of an expression whose own taint is `whole`.
    pub(super) fn field_taint_expr(
        &mut self,
        expr: &Expression<'_>,
        field: &str,
        env: &Env,
        whole: Option<Origin>,
    ) -> Option<Origin> {
        // A helper that uses its parameter's keys: this argument's keys.
        if field == KEYS_FIELD {
            return self.keys_taint(expr, whole.as_ref(), env);
        }
        match expr.get_inner_expression() {
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
                        // `{ ...opts }` may carry the field: what `opts` has under it.
                        ObjectPropertyKind::SpreadProperty(spread) => {
                            let mut probe = env.clone();
                            let spread_whole = self.expr(&spread.argument, &mut probe);
                            taint = union(
                                taint,
                                self.field_taint_expr(&spread.argument, field, env, spread_whole),
                            );
                        }
                        ObjectPropertyKind::ObjectProperty(_) => {}
                    }
                }
                taint
            }
            // `...(cond ? { a } : {})`, `...(cond && { a })`
            Expression::ConditionalExpression(c) => {
                let mut probe = env.clone();
                let consequent = self.expr(&c.consequent, &mut probe);
                let alternate = self.expr(&c.alternate, &mut probe);
                let a = self.field_taint_expr(&c.consequent, field, env, consequent);
                let b = self.field_taint_expr(&c.alternate, field, env, alternate);
                union(a, b)
            }
            Expression::LogicalExpression(l) => {
                let mut probe = env.clone();
                let right = self.expr(&l.right, &mut probe);
                let right = self.field_taint_expr(&l.right, field, env, right);
                if l.operator == LogicalOperator::And {
                    right
                } else {
                    let left = self.expr(&l.left, &mut probe);
                    union(self.field_taint_expr(&l.left, field, env, left), right)
                }
            }
            Expression::Identifier(id) => match env.fields.get(id.name.as_str()) {
                Some(fields) => fields
                    .get(field)
                    .cloned()
                    .or_else(|| unnamed_fields(fields)),
                None => whole,
            },
            // `remoteImageResponse(src, remoteImagePlace(tab))`: that field of what the inner
            // call returned.
            Expression::CallExpression(c) => {
                match self.call_fields.get(&(c.span.start, c.span.end)) {
                    Some(fields) => fields.get(field).cloned(),
                    None => whole,
                }
            }
            Expression::AwaitExpression(a) => match a.argument.get_inner_expression() {
                Expression::CallExpression(c) => {
                    match self.call_fields.get(&(c.span.start, c.span.end)) {
                        Some(fields) => fields.get(field).cloned(),
                        None => whole,
                    }
                }
                _ => whole,
            },
            _ => whole,
        }
    }

    /// The 1-based line of a byte offset of this file.
    pub(super) fn line_at(&self, offset: u32) -> u32 {
        let bytes = self.source.as_bytes();
        let before = bytes.get(..offset as usize).unwrap_or(bytes);
        let newlines = before.iter().filter(|b| **b == b'\n').count();
        u32::try_from(newlines + 1).unwrap_or(u32::MAX)
    }

    /// The name of an inline route handler: `GET /items`, or, when another registration in
    /// this file already took that name, with its receiver (`GET / [settings]`).
    pub(super) fn inline_route_name(
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

    /// The module family an initializer makes an instance of: a factory of the family
    /// (`axios.create()`, `simpleGit()`), `new` of one of its classes, possibly followed by
    /// fluent calls (`.env(..).cwd(..)`).
    pub(super) fn instance_family(&self, init: &Expression<'_>) -> Option<&'static str> {
        let model = m();
        let mut current = init.get_inner_expression();
        for _ in 0..16 {
            if let Expression::AwaitExpression(a) = current {
                current = a.argument.get_inner_expression();
                continue;
            }
            let Expression::CallExpression(call) = current else {
                break;
            };
            let Some(member) = call.callee.get_inner_expression().as_member_expression() else {
                break;
            };
            let Some(method) = member.static_property_name().and_then(|n| n.as_str()) else {
                break;
            };
            if !model
                .instances
                .values()
                .any(|spec| has(&spec.fluent, method))
            {
                break;
            }
            current = member.object().get_inner_expression();
        }
        let (callee, made_by_new) = match current {
            Expression::CallExpression(call) => (self.callee(&call.callee), false),
            Expression::NewExpression(new) => (self.callee(&new.callee), true),
            _ => return None,
        };
        let Callee::Module { family, export } = callee else {
            return None;
        };
        let spec = model.instances.get(family)?;
        let export = export.as_deref().unwrap_or("");
        let made = if made_by_new {
            has(&spec.classes, export)
        } else {
            has(&spec.factories, export)
        };
        made.then_some(family)
    }

    /// The module a `x || module` / `x ?? module` fallback stands for (`options.fs || fs`), whole
    /// modules only (not `opts.join || join`).
    pub(super) fn module_fallback(&self, expr: &Expression<'_>) -> Option<Imported> {
        let module = |side: &Expression<'_>| match side.get_inner_expression() {
            Expression::Identifier(id) => self
                .modules
                .get(id.name.as_str())
                .filter(|imported| imported.export.is_none())
                .cloned(),
            other => require_spec(other)
                .and_then(|spec| m().module_family(&spec))
                .map(|family| Imported {
                    family,
                    export: None,
                }),
        };
        match expr.get_inner_expression() {
            Expression::LogicalExpression(logical) if logical.operator != LogicalOperator::And => {
                [&logical.right, &logical.left]
                    .into_iter()
                    .find_map(|side| match side.get_inner_expression() {
                        Expression::Identifier(_) => module(side),
                        _ => None,
                    })
            }
            // `const mod = url.startsWith('https') ? https : http`: that module either way.
            Expression::ConditionalExpression(c) => {
                match (module(&c.consequent), module(&c.alternate)) {
                    (Some(a), Some(b)) if a.family == b.family => Some(a),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Walks an expression for what it records, discarding its taint.
    pub(super) fn walk_only(&mut self, expr: &Expression<'_>, env: &mut Env) {
        self.expr(expr, env);
    }

    /// The taint at each position of the tuples a collection holds: a tracked collection of
    /// tuples, `Object.entries(o)` (`[key, value]`), or an array of array literals.
    pub(super) fn tuple_positions(
        &mut self,
        expr: &Expression<'_>,
        env: &Env,
    ) -> Option<Vec<Option<Origin>>> {
        match expr.get_inner_expression() {
            Expression::Identifier(id) => env.tuples.get(id.name.as_str()).cloned(),
            Expression::CallExpression(call)
                if guards::path_key(&call.callee)
                    .is_some_and(|callee| has(&m().entry_globals, &callee)) =>
            {
                let object = call.arguments.first().and_then(Argument::as_expression)?;
                let saved = std::mem::replace(&mut self.record_only, true);
                let mut probe = env.clone();
                let whole = self.expr(object, &mut probe);
                let keys = self.keys_taint(object, whole.as_ref(), env);
                self.record_only = saved;
                Some(vec![keys, whole])
            }
            Expression::ArrayExpression(array)
                if !array.elements.is_empty()
                    && array.elements.iter().all(|e| {
                        matches!(
                            e.as_expression().map(Expression::get_inner_expression),
                            Some(Expression::ArrayExpression(_))
                        )
                    }) =>
            {
                let mut merged = Vec::new();
                for element in &array.elements {
                    if let Some(Expression::ArrayExpression(inner)) = element
                        .as_expression()
                        .map(Expression::get_inner_expression)
                    {
                        let positions = self.array_positions(inner, env);
                        merge_positions(&mut merged, positions);
                    }
                }
                Some(merged)
            }
            _ => None,
        }
    }

    /// The taint of each element of an array literal (walked for its taint only).
    pub(super) fn array_positions(
        &mut self,
        array: &oxc_ast::ast::ArrayExpression<'_>,
        env: &Env,
    ) -> Vec<Option<Origin>> {
        let saved = std::mem::replace(&mut self.record_only, true);
        let mut probe = env.clone();
        let positions = array
            .elements
            .iter()
            .take(16)
            .map(|element| match element {
                ArrayExpressionElement::SpreadElement(spread) => {
                    self.expr(&spread.argument, &mut probe)
                }
                other => other.as_expression().and_then(|e| self.expr(e, &mut probe)),
            })
            .collect();
        self.record_only = saved;
        positions
    }

    /// Binds `[a, b]` to a tuple's positions.
    pub(super) fn bind_positions(
        &mut self,
        array: &oxc_ast::ast::ArrayPattern<'_>,
        positions: &[Option<Origin>],
        env: &mut Env,
    ) {
        for (index, element) in array.elements.iter().enumerate() {
            if let Some(pattern) = element {
                let value = positions.get(index).cloned().flatten();
                self.bind_pattern(pattern, value, None, env);
            }
        }
        if let Some(rest) = &array.rest {
            let value = positions
                .iter()
                .skip(array.elements.len())
                .fold(None, |acc, t| union(acc, t.clone()));
            self.bind_pattern(&rest.argument, value, None, env);
        }
    }

    /// What a function passed by reference as a callback does with the elements it is called
    /// with: a global by its rule (`Number` clears, `String` passes), a function of ours by its
    /// summaries (sinks reached, values returned). Returns what the callback returns.
    pub(super) fn callback_by_reference(
        &mut self,
        expr: &Expression<'_>,
        spec: &models::CallbackSpec,
        element: Option<Origin>,
        initial: Option<Origin>,
        span: Span,
        env: &Env,
    ) -> Option<Origin> {
        if let Expression::Identifier(id) = expr.get_inner_expression()
            && !self.relative.contains_key(id.name.as_str())
            && !self.summaries.contains_key(id.name.as_str())
        {
            let name = id.name.as_str();
            if has(&m().clearing, name) {
                let classes = guards::named_mask(name, None);
                return (classes != guards::ALL)
                    .then(|| {
                        element.map(|mut o| {
                            o.escaped |= classes;
                            o.object = false;
                            o
                        })
                    })
                    .flatten();
            }
            if has(&m().pass_globals, name) {
                return element.map(|mut o| {
                    o.object = has(&m().object_globals, name);
                    o.step(span.start, format!("through {name}()"))
                });
            }
            return None;
        }
        let (name, summaries) = self.referenced_summaries(expr)?;
        let most = summaries
            .iter()
            .map(|s| s.param.saturating_add(1))
            .filter(|n| *n < 64)
            .max()
            .unwrap_or(0)
            .max(spec.element.iter().map(|i| i + 1).max().unwrap_or(1));
        let arguments: Vec<Option<Origin>> = (0..most)
            .map(|index| {
                if spec.accumulator == Some(index) {
                    initial.clone()
                } else if spec.element_all || spec.element.contains(&index) {
                    element.clone()
                } else {
                    None
                }
            })
            .collect();
        self.apply_summaries(&name, &summaries, &arguments, None, span, env);
        summary_returns(&name, &summaries, &arguments, span)
    }

    /// `run.call(null, x)`, `run.apply(null, [x])`, `setImmediate(run, x)`: calls of a
    /// function referenced by name, with the arguments it really receives. Applies its
    /// summaries and returns what it returns (`None` when this is no such call).
    pub(super) fn indirect_call(
        &mut self,
        call: &CallExpression<'_>,
        taints: &[Option<Origin>],
        env: &Env,
    ) -> Option<Option<Origin>> {
        let callee = call.callee.get_inner_expression();
        let (target, forwarded): (&Expression<'_>, Vec<Option<Origin>>) = match callee
            .as_member_expression()
            .and_then(|m| {
                m.static_property_name()
                    .and_then(|n| n.as_str())
                    .map(|n| (m, n))
            }) {
            Some((member, method)) if has(&m().call_methods, method) => {
                (member.object(), taints.iter().skip(1).cloned().collect())
            }
            Some((member, method)) if has(&m().apply_methods, method) => {
                let forwarded = match call
                    .arguments
                    .get(1)
                    .and_then(Argument::as_expression)
                    .map(Expression::get_inner_expression)
                {
                    Some(Expression::ArrayExpression(array)) => self.array_positions(array, env),
                    _ => {
                        let all = taints.get(1).cloned().flatten();
                        (0..8).map(|_| all.clone()).collect()
                    }
                };
                (member.object(), forwarded)
            }
            _ => {
                let name = guards::path_key(callee)?;
                let spec = m().forwarders.iter().find(|f| has(&f.functions, &name))?;
                let target = call
                    .arguments
                    .get(spec.callback)
                    .and_then(Argument::as_expression)?;
                (target, taints.iter().skip(spec.from).cloned().collect())
            }
        };
        let (name, summaries) = self.referenced_summaries(target)?;
        self.apply_summaries(&name, &summaries, &forwarded, None, call.span, env);
        Some(summary_returns(&name, &summaries, &forwarded, call.span))
    }

    /// The summaries of a function referenced by name (`save`, `this.save`, `helpers.save`):
    /// this file's, or an imported function's.
    pub(super) fn referenced_summaries(
        &self,
        expr: &Expression<'_>,
    ) -> Option<(String, Vec<Summary>)> {
        let referenced = match expr.get_inner_expression() {
            Expression::Identifier(id) => id.name.as_str().to_owned(),
            other => other
                .as_member_expression()
                .and_then(|m| m.static_property_name())
                .and_then(|n| n.as_str().map(str::to_owned))?,
        };
        if let Expression::Identifier(id) = expr.get_inner_expression()
            && let Some((spec, export)) = self.relative.get(id.name.as_str())
        {
            let export = export.as_deref().unwrap_or("default");
            let (file, name) = self.exported_function(spec, export)?;
            let list: Vec<Summary> = self
                .external
                .get(&name)?
                .iter()
                .filter(|s| s.defined_in.as_deref() == Some(file.as_str()))
                .cloned()
                .collect();
            return (!list.is_empty()).then_some((name, list));
        }
        let suffix = format!(".{referenced}");
        self.summaries
            .iter()
            .find(|(k, _)| **k == referenced || k.ends_with(&suffix))
            .map(|(k, list)| (k.clone(), list.clone()))
    }

    /// Walks `function C(x) { this.x = x; }` as the constructor of the ES5 class `C`: its
    /// parameters' flows into instance fields are summarized under `C.constructor`, which
    /// `new C(..)` applies.
    pub(super) fn es5_constructor(&mut self, f: &Function<'_>, env: &Env, class: &str) {
        if self.summarize {
            for param in &f.params.items {
                self.ctor_params.insert(param.span.start, class.to_owned());
                if let BindingPattern::ObjectPattern(object) = &param.pattern {
                    for property in &object.properties {
                        self.ctor_params
                            .insert(property.span.start, class.to_owned());
                    }
                }
            }
        }
        let saved_class = self.current_class.replace(class.to_owned());
        self.function(f, env, Some(format!("{class}.constructor")), Role::Plain);
        self.current_class = saved_class;
    }

    /// The file a namespace of an imported module names: `api.users` with `api` from
    /// `require('./api')`, whose `users` is `require('./users')` or `export * as users`.
    pub(super) fn namespace_file(&self, expr: &Expression<'_>) -> Option<String> {
        let Expression::StaticMemberExpression(member) = expr.get_inner_expression() else {
            return None;
        };
        let Expression::Identifier(root) = member.object.get_inner_expression() else {
            return None;
        };
        let (spec, export) = self.relative.get(root.name.as_str())?;
        let file = self.linking.resolve(spec)?;
        // `import { users } from './api'` then `users.gen()` is handled as a plain import.
        if export.as_deref().is_some_and(|e| e != "default") {
            return None;
        }
        let local = self
            .linking
            .exports
            .get(&file)?
            .get(member.property.name.as_str())?;
        local.strip_prefix(NAMESPACE).map(str::to_owned)
    }

    /// The class of ours a value is an instance of: `new C(..)`, an alias of a typed variable,
    /// a typed field (`this.svc`), or what a `: C` annotation says.
    pub(super) fn instance_class(
        &self,
        init: &Expression<'_>,
        annotation: Option<&oxc_ast::ast::TSTypeAnnotation<'_>>,
        env: &Env,
    ) -> Option<String> {
        let from_value = match init.get_inner_expression() {
            Expression::NewExpression(n) => match n.callee.get_inner_expression() {
                Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
                _ => None,
            },
            Expression::AwaitExpression(a) => {
                return self.instance_class(&a.argument, annotation, env);
            }
            Expression::Identifier(id) => {
                let name = id.name.as_str();
                env.instances
                    .get(name)
                    .or_else(|| env.local_instances.get(name))
                    .cloned()
            }
            Expression::StaticMemberExpression(field)
                if matches!(field.object, Expression::ThisExpression(_)) =>
            {
                self.this_field_class(field.property.name.as_str())
            }
            _ => None,
        };
        from_value.or_else(|| annotated_class(annotation))
    }

    /// A call's callee as the call graph should see it: `Class.method` for a typed receiver
    /// (a variable, `this.field`, `new Class()`), else as written.
    pub(super) fn typed_callee(
        &self,
        callee: &Callee,
        call: &CallExpression<'_>,
        env: &Env,
    ) -> Option<String> {
        if let Callee::Method { object, method } = callee
            && !method.is_empty()
        {
            let receiver = call
                .callee
                .get_inner_expression()
                .as_member_expression()
                .map(|m| m.object().get_inner_expression());
            let class = match (object, receiver) {
                (Some(object), Some(Expression::Identifier(_))) => env
                    .local_instances
                    .get(object)
                    .or_else(|| env.instances.get(object))
                    .cloned(),
                // `this.svc.run()`: `object` is already the field's class.
                (Some(object), Some(Expression::StaticMemberExpression(field)))
                    if matches!(field.object, Expression::ThisExpression(_)) =>
                {
                    Some(object.clone())
                }
                (None, Some(Expression::NewExpression(n))) => match n.callee.get_inner_expression()
                {
                    Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
                    _ => None,
                },
                _ => None,
            };
            if let Some(class) = class {
                return Some(format!("{class}.{method}"));
            }
            // `getRegistry().addServer(..)`, `db.runQuery(..)` on what a factory returned.
            if let Some((_, class)) = self.receiver_refs(callee, call, env).first() {
                return Some(format!("{class}.{method}"));
            }
        }
        callee_name(&call.callee)
    }

    /// The class `this.<field>` holds: constructor injection, or a typed field.
    pub(super) fn this_field_class(&self, field: &str) -> Option<String> {
        self.injected.get(field).cloned().or_else(|| {
            let class = self.current_class.clone()?;
            self.field_types.get(&(class, field.to_owned())).cloned()
        })
    }

    /// Where a class or interface named here is defined: (file, its name there).
    pub(super) fn class_ref(&self, name: &str) -> Option<(String, String)> {
        match self.relative.get(name) {
            Some((spec, export)) => {
                let file = self.linking.resolve(spec)?;
                let export = export.as_deref().unwrap_or("default");
                Some(
                    self.exported_function_in(&file, export)
                        .unwrap_or((file, export.to_owned())),
                )
            }
            None => Some((self.linking.file.to_owned(), name.to_owned())),
        }
    }

    /// `m.get(id)` on an `m: Mem` with no `Mem.get` of its own: the `get` of every class that
    /// extends or implements `Mem` (at most 16), as (name, summaries).
    pub(super) fn dispatch_candidates(
        &self,
        class: &str,
        method: &str,
    ) -> Vec<(String, Vec<Summary>)> {
        let Some(base) = self.class_ref(class) else {
            return Vec::new();
        };
        self.dispatch_from(&base, method)
    }

    /// [`Self::dispatch_candidates`] of a class known by where it is declared.
    pub(super) fn dispatch_from(
        &self,
        base: &ClassRef,
        method: &str,
    ) -> Vec<(String, Vec<Summary>)> {
        let Some(classes) = self.linking.subclasses.get(base) else {
            return Vec::new();
        };
        if classes.len() > 16 {
            return Vec::new();
        }
        classes
            .iter()
            .filter_map(|(file, name)| {
                let key = format!("{name}.{method}");
                let list: Vec<Summary> = if file == self.linking.file {
                    self.summaries.get(&key)?.clone()
                } else {
                    self.external
                        .get(&key)?
                        .iter()
                        .filter(|s| s.defined_in.as_deref() == Some(file.as_str()))
                        .cloned()
                        .collect()
                };
                (!list.is_empty()).then_some((key, list))
            })
            .collect()
    }

    /// The summaries of `method` on each of `classes`: this file's own for a class declared
    /// here, else the defining file's; for a class without its own `method` (an interface, an
    /// abstract base), that of every class extending or implementing it.
    pub(super) fn class_method_summaries(
        &self,
        classes: &[ClassRef],
        method: &str,
    ) -> Vec<(String, Vec<Summary>)> {
        let mut found = Vec::new();
        for (file, class) in classes {
            let key = format!("{class}.{method}");
            let list: Vec<Summary> = if file == self.linking.file {
                self.summaries.get(&key).cloned().unwrap_or_default()
            } else {
                self.external
                    .get(&key)
                    .into_iter()
                    .flatten()
                    .filter(|s| s.defined_in.as_deref() == Some(file.as_str()))
                    .cloned()
                    .collect()
            };
            if list.is_empty() {
                found.extend(self.dispatch_from(&(file.clone(), class.clone()), method));
            } else {
                found.push((key, list));
            }
        }
        found
    }

    /// The classes a method call's receiver holds when only where they are declared is known:
    /// a variable bound to what an instance-returning function returned, the call itself
    /// (`getRegistry().addServer(..)`), `new this()`, a field typed that way, or a property the
    /// repository types by assignment (`this.config.database.find(..)`).
    pub(super) fn receiver_refs(
        &self,
        callee: &Callee,
        call: &CallExpression<'_>,
        env: &Env,
    ) -> Vec<ClassRef> {
        let Callee::Method { object, method } = callee else {
            return Vec::new();
        };
        if method.is_empty() {
            return Vec::new();
        }
        let Some(receiver) = call
            .callee
            .get_inner_expression()
            .as_member_expression()
            .map(|m| m.object().get_inner_expression())
        else {
            return Vec::new();
        };
        match (object, receiver) {
            (Some(name), Expression::Identifier(_)) => {
                env.remote.get(name).cloned().unwrap_or_default()
            }
            (Some(_), _) => Vec::new(),
            // `new C().m()` is typed by name; `new this().m()` here.
            (None, Expression::NewExpression(n))
                if !matches!(
                    n.callee.get_inner_expression(),
                    Expression::ThisExpression(_)
                ) =>
            {
                Vec::new()
            }
            (None, receiver) => self.value_refs(receiver, env),
        }
    }

    /// The class a method call's receiver is typed with: a typed variable, `this.field`, or
    /// `new C()`.
    pub(super) fn receiver_class(
        &self,
        callee: &Callee,
        call: &CallExpression<'_>,
        env: &Env,
    ) -> Option<String> {
        let Callee::Method { object, method } = callee else {
            return None;
        };
        if method.is_empty() {
            return None;
        }
        let receiver = call
            .callee
            .get_inner_expression()
            .as_member_expression()
            .map(|m| m.object().get_inner_expression());
        match (object, receiver) {
            (Some(object), Some(Expression::Identifier(_))) => env
                .local_instances
                .get(object)
                .or_else(|| env.instances.get(object))
                .cloned(),
            (Some(object), Some(Expression::StaticMemberExpression(field)))
                if matches!(field.object, Expression::ThisExpression(_)) =>
            {
                Some(object.clone())
            }
            (None, Some(Expression::NewExpression(n))) => match n.callee.get_inner_expression() {
                Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
                _ => None,
            },
            _ => None,
        }
    }
}
