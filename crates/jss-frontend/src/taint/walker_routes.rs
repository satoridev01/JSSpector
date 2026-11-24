use super::*;

impl Walker<'_> {
    /// A router's own path prefix (`""` without one).
    pub(super) fn own_prefix(&self, router: Option<&str>) -> String {
        router
            .and_then(|r| self.router_prefixes.get(r))
            .cloned()
            .unwrap_or_default()
    }

    /// The path prefix an options argument sets: `{ prefix: '/users' }`.
    pub(super) fn options_prefix(&self, arguments: &[Argument<'_>], env: &Env) -> Option<String> {
        let keys: Vec<&str> = m().route_prefix_keys.iter().map(String::as_str).collect();
        arguments
            .iter()
            .filter_map(Argument::as_expression)
            .find_map(|e| object_prop(e, &keys))
            .and_then(|value| self.resolve_text(value, env))
    }

    /// The literal paths of a path argument: one, or each of `['/', '/:name']`.
    pub(super) fn route_paths(&self, argument: Option<&Argument<'_>>, env: &Env) -> Vec<String> {
        argument
            .and_then(Argument::as_expression)
            .map(|e| self.text_list(e, env))
            .unwrap_or_default()
    }

    /// The texts an expression stands for: its own, or each element's of an array literal
    /// (at most 16).
    pub(super) fn text_list(&self, expr: &Expression<'_>, env: &Env) -> Vec<String> {
        match expr.get_inner_expression() {
            Expression::ArrayExpression(list) => list
                .elements
                .iter()
                .filter_map(ArrayExpressionElement::as_expression)
                .filter_map(|e| self.resolve_text(e, env))
                .take(16)
                .collect(),
            other => self.resolve_text(other, env).into_iter().collect(),
        }
    }

    /// Where a chained registration registers, when the callee's object is a chain: the
    /// router (`app` in `app.route('/book').get(h)`; the declared variable for a chain on a
    /// factory, `Router().get('/a', h)`), the path a `route(path)` link gives, and the prefix
    /// `basePath(...)` links give.
    pub(super) fn chain_base(
        &self,
        callee: &Expression<'_>,
        env: &Env,
    ) -> Option<(Option<String>, Option<String>, String)> {
        let model = m();
        let member = callee.get_inner_expression().as_member_expression()?;
        let mut object = member.object().get_inner_expression();
        if !matches!(
            object,
            Expression::CallExpression(_) | Expression::NewExpression(_)
        ) {
            return None;
        }
        let mut path: Option<String> = None;
        let mut prefixes: Vec<String> = Vec::new();
        for _ in 0..32 {
            match object {
                Expression::Identifier(id) => {
                    let name = id.name.as_str();
                    if !self.is_router(name) {
                        return None;
                    }
                    prefixes.push(self.own_prefix(Some(name)));
                    prefixes.reverse();
                    let prefix = prefixes.iter().fold(String::new(), |a, p| join_path(&a, p));
                    return Some((Some(name.to_owned()), path, prefix));
                }
                Expression::NewExpression(n) => {
                    if !callee_name(&n.callee)
                        .as_deref()
                        .is_some_and(is_router_factory)
                    {
                        return None;
                    }
                    if let Some(own) = self.options_prefix(&n.arguments, env) {
                        prefixes.push(own);
                    }
                    prefixes.reverse();
                    let prefix = prefixes.iter().fold(String::new(), |a, p| join_path(&a, p));
                    return Some((self.chain_receiver.clone(), path, prefix));
                }
                Expression::CallExpression(c) => {
                    let inner = c.callee.get_inner_expression();
                    let method = inner
                        .as_member_expression()
                        .and_then(|m| m.static_property_name())
                        .and_then(|n| n.as_str());
                    match (inner.as_member_expression(), method) {
                        (Some(link), Some(method))
                            if has(&model.route_chain_methods, method)
                                && path.is_none()
                                && prefixes.is_empty()
                                && c.arguments.len() == 1 =>
                        {
                            // `.route('/book')`
                            path = Some(self.resolve_text(
                                c.arguments.first().and_then(Argument::as_expression)?,
                                env,
                            )?);
                            object = link.object().get_inner_expression();
                        }
                        (Some(link), Some(method))
                            if has(&model.route_prefix_methods, method)
                                && c.arguments.len() == 1 =>
                        {
                            // `.basePath('/api')`
                            prefixes.push(self.resolve_text(
                                c.arguments.first().and_then(Argument::as_expression)?,
                                env,
                            )?);
                            object = link.object().get_inner_expression();
                        }
                        (Some(link), Some(method)) if has(&model.route_methods, method) => {
                            // An earlier registration of the chain: `.get('/a', h)`.
                            object = link.object().get_inner_expression();
                        }
                        _ => {
                            if !callee_name(inner).as_deref().is_some_and(is_router_factory) {
                                return None;
                            }
                            if let Some(own) = self.options_prefix(&c.arguments, env) {
                                prefixes.push(own);
                            }
                            prefixes.reverse();
                            let prefix =
                                prefixes.iter().fold(String::new(), |a, p| join_path(&a, p));
                            return Some((self.chain_receiver.clone(), path, prefix));
                        }
                    }
                }
                _ => return None,
            }
        }
        None
    }

    /// The router variable a registration call returns: `router.all('/cors', h)` and
    /// `router.get('/a', h).post('/b', h)` evaluate to `router`, since registration and mount
    /// methods return their receiver. `.route('/book')` returns a route, not the router.
    pub(super) fn registration_receiver(&self, expr: &Expression<'_>) -> Option<String> {
        let model = m();
        let mut object = expr.get_inner_expression();
        for _ in 0..32 {
            match object {
                Expression::Identifier(id) => {
                    let name = id.name.as_str();
                    return self.is_router(name).then(|| name.to_owned());
                }
                Expression::CallExpression(c) => {
                    let link = c.callee.get_inner_expression().as_member_expression()?;
                    let method = link.static_property_name().and_then(|n| n.as_str())?;
                    if !(has(&model.route_methods, method) || has(&model.mount_methods, method))
                        || has(&model.route_chain_methods, method)
                    {
                        return None;
                    }
                    object = link.object().get_inner_expression();
                }
                _ => return None,
            }
        }
        None
    }

    /// A route registration beyond `router.get(path, handler)`: verb-first
    /// (`router.route('POST', '/users', h)`), chained (`app.route('/book').get(h)`,
    /// `Router().get('/a', h).post('/b', h2)`) or with several paths
    /// (`router.post(['/', '/:name'], h)`). Its last argument must be a handler.
    pub(super) fn registration(
        &self,
        callee: &Callee,
        callee_expr: &Expression<'_>,
        arguments: &[Argument<'_>],
        env: &Env,
    ) -> Option<Registration> {
        let Callee::Method { object, method } = callee else {
            return None;
        };
        if method.is_empty() {
            return None;
        }
        let model = m();
        let handler_like = arguments
            .last()
            .and_then(Argument::as_expression)
            .is_some_and(|e| {
                matches!(
                    e.get_inner_expression(),
                    Expression::ArrowFunctionExpression(_)
                        | Expression::FunctionExpression(_)
                        | Expression::Identifier(_)
                        | Expression::StaticMemberExpression(_)
                        | Expression::CallExpression(_)
                )
            });
        if !handler_like {
            return None;
        }
        let first = arguments.first().and_then(Argument::as_expression);
        // `router.route('POST', '/users', ...handlers)`
        if has(&model.route_verb_first_methods, method)
            && arguments.len() >= 3
            && let Some(verb) = first
                .and_then(|e| self.resolve_text(e, env))
                .filter(|v| is_http_verb(v))
        {
            let paths = self.route_paths(arguments.get(1), env);
            let prefix = self.own_prefix(object.as_deref());
            return (!paths.is_empty()).then(|| Registration {
                receiver: object.clone(),
                method: verb.to_ascii_lowercase(),
                paths: paths.iter().map(|p| join_path(&prefix, p)).collect(),
            });
        }
        if !has(&model.route_methods, method) || has(&model.route_chain_methods, method) {
            return None;
        }
        if object.is_none()
            && let Some((receiver, path, prefix)) = self.chain_base(callee_expr, env)
        {
            let paths = match path {
                // `app.route('/book').get(h)`: every argument is a handler.
                Some(path) => vec![path],
                None if arguments.len() >= 2 => self.route_paths(arguments.first(), env),
                None => Vec::new(),
            };
            return (!paths.is_empty()).then(|| Registration {
                receiver,
                method: method.clone(),
                paths: paths.iter().map(|p| join_path(&prefix, p)).collect(),
            });
        }
        // `router.post(['/', '/:name'], h)`
        if arguments.len() >= 2
            && matches!(
                first.map(Expression::get_inner_expression),
                Some(Expression::ArrayExpression(_))
            )
            && object.as_deref().is_some_and(|o| self.is_router(o))
        {
            let paths = self.route_paths(arguments.first(), env);
            let prefix = self.own_prefix(object.as_deref());
            return (!paths.is_empty()).then(|| Registration {
                receiver: object.clone(),
                method: method.clone(),
                paths: paths.iter().map(|p| join_path(&prefix, p)).collect(),
            });
        }
        None
    }

    /// Records the routes (or, for `use`, the mounts) of a [`Registration`].
    pub(super) fn record_registration(
        &mut self,
        registration: Registration,
        call: &CallExpression<'_>,
        auth: Auth,
        env: &Env,
    ) {
        let last = call.arguments.last().and_then(Argument::as_expression);
        let is_function = last.is_some_and(|e| {
            matches!(
                e.get_inner_expression(),
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
            )
        });
        let first_path = registration.paths.first().cloned().unwrap_or_default();
        let handler = last
            .and_then(|e| match e.get_inner_expression() {
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => None,
                other => self.route_handler_name(other),
            })
            .unwrap_or_else(|| {
                self.inline_route_name(
                    &registration.method,
                    &first_path,
                    registration.receiver.as_deref(),
                    call.span.start,
                )
            });
        for path in registration.paths {
            if has(&m().mount_methods, &registration.method) && !is_function {
                let (target, target_file, target_export) = match last {
                    Some(e) => self.mount_target(e),
                    None => (None, None, None),
                };
                self.facts.mounts.push(MountFact {
                    receiver: registration.receiver.clone(),
                    prefix: path,
                    target,
                    target_file,
                    target_export,
                    auth,
                    span: call.span,
                });
                continue;
            }
            // On the router our caller hands in (`module.exports = (router) => {
            // router.route('/download').post(h) }`): also a template, as for `router.post(path, h)`,
            // so a caller's mounted router gives it its prefix.
            if let Some(index) = registration
                .receiver
                .as_deref()
                .and_then(|r| env.params.iter().position(|p| p == r))
                .filter(|_| env.function != "<anonymous>" && env.function != "<module>")
            {
                let template = RouteTemplate {
                    receiver: Err(index),
                    receiver_file: None,
                    method: Ok(registration.method.clone()),
                    path: vec![PathPart::Lit(path.clone())],
                    auth,
                    handler: Some(handler.clone()),
                    handler_param: None,
                    mount_module: None,
                    at: Some((self.linking.file.to_owned(), self.line_at(call.span.start))),
                };
                let list = self
                    .route_templates
                    .entry(env.function.clone())
                    .or_default();
                if list.len() < MAX_TEMPLATES && !list.contains(&template) {
                    list.push(template);
                }
            }
            self.facts.routes.push(RouteFact {
                at: None,
                receiver: registration.receiver.clone(),
                receiver_file: None,
                method: registration.method.to_ascii_uppercase(),
                path,
                handler: handler.clone(),
                span: call.span,
                auth,
                kind: "http",
            });
        }
    }

    /// Records the entry point or mount a registration call makes.
    /// The event, channel, schema or queue name a client callback is registered for:
    /// `socket.on('join', ..)`, `ipcMain.handle(CHANNEL, ..)`, `new Worker(this.queue.name, ..)`
    /// (`{this.queue.name}`), or `queue.process(..)` with the callback alone (`{queue}`).
    pub(super) fn client_event(
        &self,
        arguments: &[Argument<'_>],
        object: Option<&str>,
    ) -> Option<String> {
        let event = match arguments.first() {
            _ if arguments.len() < 2 => object.map(|o| format!("{{{o}}}")),
            Some(Argument::StringLiteral(name)) => name.value.as_str().map(str::to_owned),
            Some(Argument::Identifier(id)) => Some(
                self.constant(id.name.as_str())
                    .unwrap_or_else(|| id.name.as_str().to_owned()),
            ),
            Some(other) => other
                .as_expression()
                .and_then(|e| guards::path_key(e).or_else(|| callee_name(e)))
                .map(|key| match key.strip_prefix('.') {
                    // `this.queue.name`
                    Some(rest) => format!("{{this.{rest}}}"),
                    None => format!("{{{key}}}"),
                }),
            None => None,
        };
        event.filter(|n| !n.is_empty() && !n.contains(char::is_whitespace) && n.len() < 120)
    }

    pub(super) fn record_entry(
        &mut self,
        callee: &Callee,
        call: &CallExpression<'_>,
        role: Role,
        auth: Auth,
        env: &Env,
    ) {
        // `_mounts[original](router, mount, ...)`: the routes of every function of the table.
        if let Expression::ComputedMemberExpression(computed) = call.callee.get_inner_expression()
            && let Expression::Identifier(table) = computed.object.get_inner_expression()
            && let Some(entries) = self.fn_tables.get(table.name.as_str()).cloned()
        {
            for entry in entries {
                let found = match &entry {
                    TableEntry::Local(name) => self
                        .route_templates
                        .get(name)
                        .map(|list| (name.clone(), list.clone(), None)),
                    TableEntry::Module(spec) => self.module_templates(spec),
                };
                if let Some((name, templates, defining_file)) = found
                    && name != env.function
                {
                    for template in templates {
                        self.instantiate(
                            &name,
                            &template,
                            defining_file.as_deref(),
                            call,
                            auth,
                            env,
                        );
                    }
                }
            }
            return;
        }
        // A helper that registers routes from its parameters: `add('/x', handler)` here or in
        // another file instantiates its routes (or, called with this function's own parameters,
        // makes this function a template too).
        if let Some((name, templates, defining_file)) = self.templates_for(callee) {
            // A helper calling itself (`add(p + '/x')` inside `add`) would derive its templates
            // from its own, without end. Only a function of this file can be the caller itself: two
            // files' `module.exports = (router) => ...` share a name but are different functions.
            let elsewhere = defining_file
                .as_deref()
                .is_some_and(|file| file != self.linking.file);
            if elsewhere || name != env.function {
                for template in templates {
                    self.instantiate(&name, &template, defining_file.as_deref(), call, auth, env);
                }
            }
            return;
        }
        // `router.prefix('/api')` (Koa): the prefix of this router's later routes.
        if let Callee::Method {
            object: Some(object),
            method,
        } = callee
            && has(&m().route_prefix_methods, method)
            && call.arguments.len() == 1
            && self.is_router(object)
        {
            if let Some(prefix) = call
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .and_then(|e| self.resolve_text(e, env))
            {
                self.router_prefixes.insert(object.clone(), prefix);
            }
            return;
        }
        if role == Role::Route
            && let Some(registration) =
                self.registration(callee, &call.callee, &call.arguments, env)
        {
            self.record_registration(registration, call, auth, env);
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
            && !self.client_request(call)
        {
            Role::Route
        } else {
            role
        };
        let first = call.arguments.first().and_then(Argument::as_expression);
        // A client source: an event, channel or schema name (`socket.on('join', ...)`,
        // `server.setRequestHandler(CallToolRequestSchema, ...)`), never the callback itself.
        if let Role::Client(kind, _) = role {
            // Listed under its object key already (`{ list: publicProcedure.query(fn) }`).
            if self
                .keyed_entries
                .contains_key(&(call.span.start, call.span.end))
            {
                return;
            }
            if let Some(event) = self.client_event(&call.arguments, object.as_deref()) {
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
                    at: None,
                    receiver: object.clone(),
                    receiver_file: None,
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
        // `export function setup(mstream) { mstream.post('/api/x', h) }`: a literal path on a
        // parameter not named like a router is still the caller's router's route.
        // Also through a factory declared here and called with constants
        // (`mstream.all('/dlna/event/cds', genaRoute('cds'))`).
        let param_router = receiver_param.is_some()
            && !object.as_deref().is_some_and(|o| self.is_router(o))
            && call
                .arguments
                .last()
                .and_then(Argument::as_expression)
                .is_some_and(|e| match e.get_inner_expression() {
                    Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {
                        true
                    }
                    Expression::CallExpression(c) => {
                        matches!(c.callee.get_inner_expression(),
                            Expression::Identifier(f) if env.locals.contains(f.name.as_str()))
                            && c.arguments.iter().all(|a| {
                                matches!(
                                    a,
                                    Argument::StringLiteral(_) | Argument::NumericLiteral(_)
                                )
                            })
                    }
                    _ => false,
                });
        // `module.exports = (router) => { router.post('/download', h) }`: a literal path on a
        // parameter named like a router. The route is recorded on that parameter as before (its
        // prefix unknown here), and also as a template, so a caller that hands in its own mounted
        // router (`files(router)` under `app.use('/api', router)`) instantiates it with the prefix.
        // The inventory keeps the unprefixed copy only while no caller resolves the registration.
        let router_param = receiver_param.is_some()
            && !depends_on_params
            && object.as_deref().is_some_and(|o| self.is_router(o));
        if role == Role::Route
            && (depends_on_params || param_router || router_param)
            && router_receiver
            && handler_like(call)
            && env.function != "<anonymous>"
            && env.function != "<module>"
            && let Some(parts) = parts
        {
            let inline_handler = call
                .arguments
                .last()
                .and_then(Argument::as_expression)
                .filter(|e| {
                    matches!(
                        e.get_inner_expression(),
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    )
                })
                .and(first)
                .and_then(|first| self.resolve_text(first, env))
                .map(|path| {
                    self.inline_route_name(&method, &path, object.as_deref(), call.span.start)
                });
            let last = call
                .arguments
                .last()
                .filter(|_| call.arguments.len() >= 2)
                .and_then(Argument::as_expression);
            let param_index =
                |expr: Option<&Expression<'_>>| match expr.map(Expression::get_inner_expression) {
                    Some(Expression::Identifier(id)) => {
                        env.params.iter().position(|p| p == id.name.as_str())
                    }
                    _ => None,
                };
            // `router.get(name, middlewares, controller)`, or wrapped:
            // `helpers.tryRoute(controller)`.
            let handler_param =
                param_index(last).or_else(|| match last.map(Expression::get_inner_expression) {
                    Some(Expression::CallExpression(wrapper)) if wrapper.arguments.len() == 1 => {
                        param_index(wrapper.arguments.first().and_then(Argument::as_expression))
                    }
                    _ => None,
                });
            let template = RouteTemplate {
                receiver_file: None,
                receiver: match receiver_param {
                    Some(index) => Err(index),
                    None => Ok(object.clone()),
                },
                method: match method_param {
                    Some(index) => Err(index),
                    None => Ok(method.clone()),
                },
                path: parts,
                // `(req, res) => ...` written here (the name `call` gave it), or a handler named
                // here that is none of the parameters.
                handler: inline_handler.or_else(|| {
                    last.filter(|_| handler_param.is_none())
                        .and_then(|e| self.route_handler_name(e))
                }),
                handler_param,
                // A mount helper (`function mount(prefix, spec) { router.use(prefix, require(spec)) }`):
                // which module the `use` mounts, in terms of this helper's parameters.
                mount_module: has(&m().mount_methods, &method)
                    .then(|| self.mount_module_source(last, env))
                    .flatten(),
                auth,
                at: Some((self.linking.file.to_owned(), self.line_at(call.span.start))),
            };
            let list = self
                .route_templates
                .entry(env.function.clone())
                .or_default();
            if !list.contains(&template) {
                list.push(template);
            }
            if !router_param || param_router {
                return;
            }
        }
        if method_param.is_some() {
            return;
        }
        // `app.use((req, res, next) => { ... })`: a global middleware registered with no mount path
        // runs on every request, so it is an anonymous HTTP entry just like `http.createServer(handler)`
        // or `server.on('request', ...)`. An inline function argument is unambiguously a handler (never a
        // mountable router), so recording it as an entry cannot shadow a real mount. Findings inside it
        // (a handler that reads `req.path`/`req.url` into a sink) then link to this entry instead of being
        // left unreachable. A `use` that mounts a child, or lists named middleware before one, has no
        // inline function as its sole argument and falls through to the path-less mount handling below.
        if has(&m().mount_methods, &method)
            && object.as_deref().is_some_and(|o| self.is_router(o))
            && env.branch == 0
            && !self.summarize
            && !self.record_only
            && call.arguments.len() == 1
            && let Some(handler) = first
        {
            let span = match handler.get_inner_expression() {
                Expression::ArrowFunctionExpression(f) => Some(f.span),
                Expression::FunctionExpression(f) => Some(f.span),
                _ => None,
            };
            // A pure authentication/authorization guard (`if (!req.user) return res.status(403)`) is
            // already modeled as a router guard above and only gates the routes after it; it is not
            // itself a useful request handler, so it is not recorded as an entry.
            if let Some(span) = span.filter(|_| inline_guard_auth(handler).is_none()) {
                self.facts.scoped_routes.push((
                    RouteFact {
                        at: None,
                        receiver: None,
                        receiver_file: None,
                        method: "ANY".to_owned(),
                        path: "*".to_owned(),
                        handler: env.function.clone(),
                        span: call.span,
                        auth,
                        kind: "http",
                    },
                    span,
                ));
                return;
            }
        }
        // `router.use(child)`, `app.use(requireAuth, api)`: path-less mounts.
        if has(&m().mount_methods, &method)
            && object.as_deref().is_some_and(|o| self.is_router(o))
            && first.is_some_and(|e| self.mount_path(e, env).is_none())
        {
            // `fastify.register(users, { prefix: '/users' })`, under the router's own prefix.
            let prefix = join_path(
                &self.own_prefix(object.as_deref()),
                &self
                    .options_prefix(&call.arguments, env)
                    .unwrap_or_default(),
            );
            for argument in call.arguments.iter().filter_map(Argument::as_expression) {
                if !self.mountable(argument) {
                    continue;
                }
                let (target, target_file, target_export) = self.mount_target(argument);
                self.facts.mounts.push(MountFact {
                    receiver: object.clone(),
                    prefix: prefix.clone(),
                    target,
                    target_file,
                    target_export,
                    auth,
                    span: call.span,
                });
            }
            return;
        }
        let Some(own_path) = first.and_then(|e| self.resolve_text(e, env)) else {
            return;
        };
        let path = join_path(&self.own_prefix(object.as_deref()), &own_path);
        let object = &object;
        let method = &method;
        // Only registrations on a router or app: not `$http.get('/x', config)` in a client.
        let is_router = object.as_deref().is_some_and(|o| self.is_router(o));
        if role == Role::Route && !(is_router && handler_like(call)) {
            return;
        }
        let last = call.arguments.last().and_then(Argument::as_expression);
        let handler = last
            .and_then(|e| match e.get_inner_expression() {
                Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => None,
                other => self.route_handler_name(other),
            })
            .unwrap_or_else(|| {
                // Named from the path as written, before the router's own prefix
                // (`new Hono().basePath('/api')`, `new Router({ prefix })`): the walk names the
                // same inline handler that way, and the route must resolve to that function.
                self.inline_route_name(method, &own_path, object.as_deref(), call.span.start)
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
                    // `app.use(`/api/v${v}`, router)` where `router` is a dynamic import of
                    // `./apis/v${v}/router.js`: one mount per matching file, each under its own
                    // concrete version prefix. Resolves the versioned-API loop a single string
                    // prefix cannot express.
                    if self.record_versioned_mount(first, last, object.as_deref(), auth, call.span)
                    {
                        return;
                    }
                    let (target, target_file, target_export) = match last {
                        Some(e) => self.mount_target(e),
                        None => (None, None, None),
                    };
                    for router in last.map(|e| self.handed_routers(e)).unwrap_or_default() {
                        self.facts.mounts.push(MountFact {
                            receiver: object.clone(),
                            prefix: path.clone(),
                            target: Some(router),
                            target_file: None,
                            target_export: None,
                            auth,
                            span: call.span,
                        });
                    }
                    self.facts.mounts.push(MountFact {
                        receiver: object.clone(),
                        prefix: path,
                        target,
                        target_file,
                        target_export,
                        auth,
                        span: call.span,
                    });
                    return;
                }
                self.facts.routes.push(RouteFact {
                    at: None,
                    receiver: object.clone(),
                    receiver_file: None,
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
    pub(super) fn constructor_summaries(&self, class: &str) -> Option<(String, Vec<Summary>)> {
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
    pub(super) fn own_function_followed(&self, object: &str, method: &str) -> bool {
        let Some((spec, _)) = self.relative.get(object) else {
            return false;
        };
        // A function the module exports (`exports.find = function find`): our code, not a
        // library call named like a sink.
        if self.exported_function(spec, method).is_some() {
            return true;
        }
        self.linking
            .external_names
            .get(method)
            .into_iter()
            .flatten()
            .filter_map(|name| self.external.get(name))
            .any(|list| {
                list.iter().any(|s| {
                    s.defined_in
                        .as_deref()
                        .or(s.ext.as_ref().map(|e| e.file.as_str()))
                        .is_some_and(|file| self.names_file(spec, file))
                })
            })
    }

    /// Whether `expr` is an upload object of the request: `req.file`, `req.files[0]`,
    /// `req.files.avatar[0]`.
    pub(super) fn is_upload_object(&self, expr: &Expression<'_>, env: &Env) -> bool {
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
    pub(super) fn mount_path(&self, expr: &Expression<'_>, env: &Env) -> Option<String> {
        if matches!(expr.get_inner_expression(), Expression::CallExpression(_))
            && callee_name(expr).is_some_and(|name| m().auth_of(&name).is_some())
        {
            return None;
        }
        self.resolve_text(expr, env)
    }

    /// Whether a `use(...)` argument mounts routes rather than adding middleware: a router, a
    /// router imported from our own files, or `require('./routes')` (or a factory call of it).
    pub(super) fn mountable(&self, expr: &Expression<'_>) -> bool {
        match expr.get_inner_expression() {
            Expression::Identifier(id) => {
                let name = id.name.as_str();
                self.is_router(name)
                    || (self.relative.contains_key(name) && m().auth_of(name).is_none())
            }
            e @ Expression::CallExpression(c) => {
                require_spec(e).is_some()
                    || require_spec(&c.callee).is_some()
                    // `users()` or `routes.users()` from our files: a router factory.
                    || match c.callee.get_inner_expression() {
                        Expression::Identifier(id) => {
                            self.relative.contains_key(id.name.as_str())
                                && m().auth_of(id.name.as_str()).is_none()
                        }
                        Expression::StaticMemberExpression(member) => {
                            matches!(member.object.get_inner_expression(),
                                Expression::Identifier(id)
                                    if self.relative.contains_key(id.name.as_str()))
                                && callee_name(&c.callee)
                                    .is_some_and(|name| m().auth_of(&name).is_none())
                        }
                        _ => false,
                    }
            }
            // `api.router` of an import, `require('./api').router`.
            Expression::StaticMemberExpression(member) => {
                match member.object.get_inner_expression() {
                    Expression::Identifier(id) => {
                        self.relative.contains_key(id.name.as_str())
                            && self.is_router(member.property.name.as_str())
                    }
                    object => require_spec(object).is_some(),
                }
            }
            _ => false,
        }
    }

    /// If `expr` is `require(<p>)` or a require wrapper `load(<p>)` where `p` is one of the current
    /// function's parameters, that parameter's index. So the module it loads is whichever module
    /// specifier the caller passes for that parameter.
    pub(super) fn require_of_param(&self, expr: &Expression<'_>, env: &Env) -> Option<usize> {
        if let Some(ident) = require_arg_ident(expr) {
            return env.params.iter().position(|p| *p == ident);
        }
        if let Expression::CallExpression(call) = expr.get_inner_expression()
            && let Expression::Identifier(f) = call.callee.get_inner_expression()
            && let Some(&k) = self.require_wrappers.get(f.name.as_str())
            && let Some(Expression::Identifier(arg)) = call
                .arguments
                .get(k)
                .and_then(Argument::as_expression)
                .map(Expression::get_inner_expression)
        {
            return env.params.iter().position(|p| *p == arg.name.as_str());
        }
        None
    }

    /// The module a mount helper's `router.use(prefix, child)` mounts, named in terms of the
    /// helper's parameters: a `require('./literal')` file, `require(<param>)`/`wrapper(<param>)`
    /// (the caller's argument names the module), or a parameter that holds a router.
    pub(super) fn mount_module_source(
        &self,
        expr: Option<&Expression<'_>>,
        env: &Env,
    ) -> Option<MountModule> {
        let expr = expr?;
        if let Some(spec) = require_spec(expr).or_else(|| {
            // `require('./x')()` or `require('./x').router`.
            match expr.get_inner_expression() {
                Expression::CallExpression(c) => require_spec(&c.callee),
                e => e
                    .as_member_expression()
                    .and_then(|m| require_spec(m.object())),
            }
        }) {
            return self.linking.resolve(&spec).map(MountModule::Spec);
        }
        if let Some(index) = self.require_of_param(expr, env) {
            return Some(MountModule::RequireParam(index));
        }
        if let Expression::Identifier(id) = expr.get_inner_expression() {
            if let Some(&index) = env.require_params.get(id.name.as_str()) {
                return Some(MountModule::RequireParam(index));
            }
            if let Some(index) = env.params.iter().position(|p| p == id.name.as_str()) {
                return Some(MountModule::Param(index));
            }
        }
        None
    }

    /// The router a mount helper's `mount_module` names, resolved at one call: `(target,
    /// target_file, target_export)`, the way [`Self::mount_target`] names a direct mount argument.
    /// `RequireParam(i)`/`Param(i)` read the caller's `i`th argument — a module specifier the loop
    /// row supplies (`route: '@routes/v2/sites.routes'`), a `require('./x')`, or a router value.
    pub(super) fn resolve_mount(
        &self,
        mount: &MountModule,
        call: &CallExpression<'_>,
        env: &Env,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let arg = |index: usize| call.arguments.get(index).and_then(Argument::as_expression);
        match mount {
            MountModule::Spec(file) => (None, Some(file.clone()), None),
            MountModule::RequireParam(index) => {
                let Some(expr) = arg(*index) else {
                    return (None, None, None);
                };
                // The argument is a module specifier (a string literal, or a loop-row field such as
                // `route: '@routes/v2/sites.routes'`): resolve it to the mounted file.
                if let Some(file) = self
                    .resolve_text(expr, env)
                    .and_then(|spec| self.linking.resolve(&spec))
                {
                    return (None, Some(file), None);
                }
                // Else the caller passes `require('./x')` (or a router value) directly.
                self.mount_target(expr)
            }
            MountModule::Param(index) => match arg(*index) {
                Some(expr) => self.mount_target(expr),
                None => (None, None, None),
            },
        }
    }

    /// What a mount argument names: a local router or an import's member (`api.router`, as
    /// `api.router`), or the file of `require('./users')` (or of a factory
    /// `require('./users')()`, or its export `require('./users').router`).
    /// Records the mounts of a versioned-API loop and reports whether it did: `app.use(
    /// `/api/v${v}`, router)` where `router` was bound by `import(`./apis/v${v}/router.js`)` mounts
    /// `apis/v1/router.js` under `/api/v1`, `apis/v2/router.js` under `/api/v2`, and so on — one
    /// `MountFact` per version found on disk, each with its own concrete prefix. Both templates must
    /// interpolate the same loop variable, so each file is mounted under the matching version.
    pub(super) fn record_versioned_mount(
        &mut self,
        prefix_expr: Option<&Expression<'_>>,
        router_expr: Option<&Expression<'_>>,
        receiver: Option<&str>,
        auth: Auth,
        span: Span,
    ) -> bool {
        let Some((pfx_pre, pfx_var, pfx_suf)) = prefix_expr.and_then(single_interpolation) else {
            return false;
        };
        let Some(Expression::Identifier(id)) = router_expr.map(Expression::get_inner_expression)
        else {
            return false;
        };
        let Some(import) = self.dyn_imports.get(id.name.as_str()) else {
            return false;
        };
        if import.var != pfx_var {
            return false;
        }
        let export = (import.export != "*").then(|| import.export.clone());
        let matches = interpolated_files(
            self.linking.file,
            &import.pre,
            &import.suf,
            self.linking.files,
        );
        let mut recorded = false;
        for (file, value) in matches {
            self.facts.mounts.push(MountFact {
                receiver: receiver.map(str::to_owned),
                prefix: format!("{pfx_pre}{value}{pfx_suf}"),
                target: None,
                target_file: Some(file),
                target_export: export.clone(),
                auth,
                span,
            });
            recorded = true;
        }
        recorded
    }

    /// The routers of this file a mounted factory call is handed (`app.use('/api', routes(router))`):
    /// a registrar fills the router it is given and returns it, so that router is mounted too.
    pub(super) fn handed_routers(&self, expr: &Expression<'_>) -> Vec<String> {
        let Expression::CallExpression(call) = expr.get_inner_expression() else {
            return Vec::new();
        };
        call.arguments
            .iter()
            .filter_map(
                |argument| match argument.as_expression()?.get_inner_expression() {
                    Expression::Identifier(id) if self.is_router(id.name.as_str()) => {
                        Some(id.name.as_str().to_owned())
                    }
                    _ => None,
                },
            )
            .collect()
    }

    pub(super) fn mount_target(
        &self,
        expr: &Expression<'_>,
    ) -> (Option<String>, Option<String>, Option<String>) {
        match expr.get_inner_expression() {
            Expression::Identifier(id) => (Some(id.name.as_str().to_owned()), None, None),
            Expression::StaticMemberExpression(member) => {
                let property = member.property.name.as_str().to_owned();
                match member.object.get_inner_expression() {
                    Expression::Identifier(id) => {
                        (Some(format!("{}.{property}", id.name.as_str())), None, None)
                    }
                    object => (
                        None,
                        require_spec(object).and_then(|spec| self.linking.resolve(&spec)),
                        Some(property),
                    ),
                }
            }
            // `users()` or `routes.users()`: a factory, whose product is the router.
            Expression::CallExpression(c)
                if require_spec(expr).is_none() && require_spec(&c.callee).is_none() =>
            {
                (callee_name(&c.callee), None, None)
            }
            e => {
                let required = match e {
                    Expression::CallExpression(c) if require_spec(e).is_none() => {
                        require_spec(&c.callee)
                    }
                    _ => require_spec(e),
                };
                (
                    None,
                    required.and_then(|spec| self.linking.resolve(&spec)),
                    None,
                )
            }
        }
    }

    /// A server-request listener on a server from a server factory, and which event it is: Node's
    /// `'request'` event is the same handler `http.createServer(handler)` installs, and `'upgrade'`
    /// is the entry for HTTP upgrade (WebSocket) requests. Returns the event name, or `None` when
    /// this is not such a listener.
    pub(super) fn server_event_listener(
        &self,
        callee: &Callee,
        arguments: &[Argument<'_>],
    ) -> Option<&'static str> {
        const LISTENERS: [&str; 4] = ["on", "once", "addListener", "prependListener"];
        let Callee::Method {
            object: Some(object),
            method,
        } = callee
        else {
            return None;
        };
        if !LISTENERS.contains(&method.as_str())
            || !self.servers.contains(object)
            || arguments.len() != 2
        {
            return None;
        }
        match arguments.first() {
            Some(Argument::StringLiteral(lit)) if lit.value == "request" => Some("request"),
            Some(Argument::StringLiteral(lit)) if lit.value == "upgrade" => Some("upgrade"),
            _ => None,
        }
    }

    pub(super) fn is_router(&self, name: &str) -> bool {
        self.routers.contains(name) || {
            let lower = name.to_ascii_lowercase();
            m().router_names
                .iter()
                .any(|n| lower == *n || lower.ends_with(n.as_str()))
        }
    }

    /// `api.get('/users', params).then(...)`, `await api.put(url, data)`,
    /// `api.get(url, params, function (err, result) { ... })`: a request a client sends.
    pub(super) fn client_request(&self, call: &CallExpression<'_>) -> bool {
        // An HTTP verb's call (`await fastify.register(plugin)` mounts, whatever it returns).
        let verb = call
            .callee
            .get_inner_expression()
            .as_member_expression()
            .and_then(|member| member.static_property_name())
            .and_then(|n| n.as_str())
            .is_some_and(|n| is_http_verb(n) && !has(&m().mount_methods, n));
        if !verb {
            return false;
        }
        if self.promised.contains(&(call.span.start, call.span.end)) {
            return true;
        }
        let params = match call
            .arguments
            .last()
            .and_then(Argument::as_expression)
            .map(Expression::get_inner_expression)
        {
            Some(Expression::ArrowFunctionExpression(f)) => &f.params,
            Some(Expression::FunctionExpression(f)) => &f.params,
            _ => return false,
        };
        params.items.len() < 4
            && params.items.first().is_some_and(|p| {
                p.pattern
                    .get_identifier_name()
                    .is_some_and(|n| has(&m().callback_error_params, n.as_str()))
            })
    }

    /// The route templates of a module's default export (`require('./admin')` in a table).
    pub(super) fn module_templates(
        &self,
        spec: &str,
    ) -> Option<(String, Vec<RouteTemplate>, Option<String>)> {
        let file = self.linking.resolve(spec)?;
        let key = self
            .exported_function(spec, "default")
            .map(|(_, local)| local)
            .unwrap_or_else(|| "default".to_owned());
        let mut files = vec![file.clone()];
        if let Some(more) = self.linking.reexports.get(&file) {
            files.extend(more.iter().cloned());
        }
        files.iter().find_map(|f| {
            self.linking
                .templates
                .get(f)
                .and_then(|by_name| by_name.get(&key))
                .map(|list| (key.clone(), list.clone(), Some(f.clone())))
        })
    }

    /// The route templates a callee has: this file's, or (through an import) another file's.
    pub(super) fn templates_for(
        &self,
        callee: &Callee,
    ) -> Option<(String, Vec<RouteTemplate>, Option<String>)> {
        let (local, linked) = match callee {
            Callee::Global(name) => (
                Some(name.clone()),
                self.relative.get(name).map(|(spec, export)| {
                    // `const registerPage = require('./helpers')`: the default export's own name.
                    let export = export.as_deref().unwrap_or("default");
                    let key = self
                        .exported_function(spec, export)
                        .map(|(_, local)| local)
                        .unwrap_or_else(|| {
                            if export == "default" {
                                name.clone()
                            } else {
                                export.to_owned()
                            }
                        });
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
            return Some((name, list.clone(), None));
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
                .map(|list| (key.clone(), list.clone(), Some(f.clone())))
        })
    }

    /// Instantiates a route template at a call: a route when every part is known, otherwise a
    /// template of the calling function (when it passes its own parameters along).
    pub(super) fn instantiate(
        &mut self,
        name: &str,
        template: &RouteTemplate,
        defining_file: Option<&str>,
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
                    let Some(expr) = arg(*index) else { return };
                    match self.path_parts(expr, env) {
                        Some(parts) => path.extend(parts),
                        // A value known only at run time (`mounts[mount]`, `config.base`): a
                        // path parameter named after it.
                        None => match runtime_part_name(expr) {
                            Some(name) => path.push(PathPart::Lit(format!("{{{name}}}"))),
                            None => return,
                        },
                    }
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
        // What this call passes for the template's handler parameter.
        let passed_handler = template.handler_param.and_then(arg);
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
        // A router variable of another file stays that file's.
        let receiver_file = match &template.receiver {
            Ok(Some(_)) => template
                .receiver_file
                .clone()
                .or_else(|| defining_file.map(str::to_owned)),
            _ => None,
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
        // Bounded: a path of at most `MAX_TEMPLATE_PARTS` parts, at most `MAX_TEMPLATES` templates
        // per function.
        if path.len() > MAX_TEMPLATE_PARTS {
            return;
        }
        // Called from a callback, whose parameters no caller of ours fills in
        // (`Object.keys(mounts).map((mount) => _mounts[mount](router, mount))`): the part is a
        // path parameter of the route (`/{mount}/dashboard`).
        if env.function == "<anonymous>" || env.function == "<module>" {
            for part in &mut path {
                if let PathPart::Param(index) = part {
                    let name = env.params.get(*index).cloned().unwrap_or_default();
                    *part = PathPart::Lit(format!("{{{name}}}"));
                }
            }
        }
        let named = env.function != "<anonymous>" && env.function != "<module>";
        let open = path.iter().any(|p| matches!(p, PathPart::Param(_))) || method.is_err();
        // Registered on the router our own caller hands us (`module.exports = (router) => {
        // files(router); }`): the route is on whatever router our callers pass, and only they know
        // where it is mounted. Hand the template up to them too; the route is still recorded here
        // without a receiver for a registrar no caller of ours reaches, and the inventory drops that
        // copy once a caller resolves the registration onto a router.
        let handed_on = named && receiver.is_err();
        if open || handed_on {
            if named {
                let derived = RouteTemplate {
                    receiver: receiver.clone(),
                    receiver_file: receiver_file.clone(),
                    method: method.clone(),
                    path: path.clone(),
                    auth: template.auth.max(auth),
                    handler: template
                        .handler
                        .as_ref()
                        .map(|h| match defining_file {
                            Some(file) if !h.starts_with(ELSEWHERE) => {
                                format!("{ELSEWHERE}{file}#{h}")
                            }
                            _ => h.clone(),
                        })
                        .or_else(|| {
                            passed_handler
                                .filter(|e| param_of(Some(e)).is_none())
                                .and_then(|e| self.route_handler_name(e))
                        }),
                    // Handed on by one of our parameters: our callers pass it.
                    handler_param: passed_handler.and_then(|e| param_of(Some(e))),
                    // A mount is named in terms of this helper's own parameters, which the
                    // derived template shares, so carry it through unchanged.
                    mount_module: template.mount_module.clone(),
                    at: template.at.clone(),
                };
                let list = self
                    .route_templates
                    .entry(env.function.clone())
                    .or_default();
                if list.len() < MAX_TEMPLATES && !list.contains(&derived) {
                    list.push(derived);
                }
            }
            if open {
                return;
            }
        }
        let text: String = path
            .iter()
            .map(|p| match p {
                PathPart::Lit(text) => text.as_str(),
                PathPart::Param(_) => "",
            })
            .collect();
        let Ok(method) = method else { return };
        // A mount helper instantiated here (`safeMountRoute('/sites', '@routes/v2/sites.routes')`
        // whose body is `router.use(prefix, require(route))`): record the child module mounted under
        // the resolved prefix, so its routes inherit it, rather than a bare `USE` route.
        if let Some(mount) = &template.mount_module {
            let (target, target_file, target_export) = self.resolve_mount(mount, call, env);
            if target.is_some() || target_file.is_some() {
                self.facts.mounts.push(MountFact {
                    receiver: receiver.ok().flatten(),
                    prefix: text,
                    target,
                    target_file,
                    target_export,
                    auth: template.auth.max(auth),
                    span: call.span,
                });
            }
            return;
        }
        // Registered on a variable of the caller that is not a router: not a route.
        if let Ok(Some(receiver)) = &receiver
            && receiver_file.is_none()
            && !self.is_router(receiver)
        {
            return;
        }
        self.facts.routes.push(RouteFact {
            receiver: receiver.ok().flatten(),
            receiver_file,
            method: method.to_ascii_uppercase(),
            path: text,
            // The handler written in the template's function (in its file), else the one this
            // call passes.
            handler: match (&template.handler, defining_file) {
                (Some(h), Some(file)) if !h.starts_with(ELSEWHERE) => {
                    format!("{ELSEWHERE}{file}#{h}")
                }
                (Some(h), _) => h.clone(),
                // The one this call passes for the template's handler parameter, else its last
                // argument.
                (None, _) => passed_handler
                    .or_else(|| call.arguments.last().and_then(Argument::as_expression))
                    .and_then(|e| self.route_handler_name(e))
                    .unwrap_or_else(|| format!("{name}()")),
            },
            span: call.span,
            at: template.at.clone(),
            auth: template.auth.max(auth),
            kind: "http",
        });
    }

    /// A path expression in terms of this function's parameters: `` `/api${name}` `` is
    /// `["/api", Param(name)]`. Unknown pieces fall back to the literal text around them.
    pub(super) fn path_parts(&self, expr: &Expression<'_>, env: &Env) -> Option<Vec<PathPart>> {
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
    pub(super) fn resolve_text(&self, expr: &Expression<'_>, env: &Env) -> Option<String> {
        // A template literal with interpolations (`` `${prefix}/*name` ``): resolve each `${..}`
        // part and interleave it with the literal quasis, so a configurable prefix with a resolvable
        // value (a constant, or an option destructured with a literal default) contributes its path
        // segment instead of being dropped. Fall through to the quasis-only reading when any part is
        // unresolvable, preserving the previous behavior.
        if let Expression::TemplateLiteral(template) = expr.get_inner_expression()
            && !template.expressions.is_empty()
        {
            let mut out = String::new();
            let mut resolved = true;
            for (index, quasi) in template.quasis.iter().enumerate() {
                if let Some(cooked) = quasi.value.cooked.and_then(|c| c.as_str()) {
                    out.push_str(cooked);
                }
                if let Some(part) = template.expressions.get(index) {
                    match self.resolve_text(part, env) {
                        Some(value) => out.push_str(&value),
                        None => {
                            resolved = false;
                            break;
                        }
                    }
                }
            }
            if resolved && !out.is_empty() {
                return Some(out);
            }
        }
        literal_path(expr).or_else(|| {
            let key = guards::path_key(expr)?;
            // A loop row destructured in the loop head (`forEach(({ path }) => ...)`): the bare local.
            if let Some(value) = env.row_fields.get(&key) {
                return Some(value.clone());
            }
            if let Some((var, field)) = key.split_once('.')
                && let Some(value) = env.rows.get(var).and_then(|row| row.get(field))
            {
                return Some(value.clone());
            }
            self.constant(&key)
        })
    }

    /// A constant by access path: this file's, or an imported module's (`RouteKey.Asset`).
    pub(super) fn constant(&self, key: &str) -> Option<String> {
        self.linked_constant(key, "")
    }

    /// [`Self::constant`] under a prefix of the constants map ([`REGEX_CONSTANT`]).
    pub(super) fn linked_constant(&self, key: &str, prefix: &str) -> Option<String> {
        if let Some(value) = self.constants.get(&format!("{prefix}{key}")) {
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
        let name = format!("{prefix}{name}");
        files.iter().find_map(|f| {
            self.linking
                .constants
                .get(f)
                .and_then(|c| c.get(&name))
                .cloned()
        })
    }

    /// Whether `expr` is built from variables passed through unchanged (`+`, template literals,
    /// a pack's path joins like `path.join(root, dir, name)`), with literals; `parts` gets those
    /// variables. Anything else taking part (`decodeURIComponent(name)`, a member read) may
    /// change the value: `false`.
    pub(super) fn built_from(&self, expr: &Expression<'_>, parts: &mut Vec<String>) -> bool {
        match expr.get_inner_expression() {
            Expression::Identifier(id) => {
                parts.push(id.name.as_str().to_owned());
                true
            }
            Expression::StringLiteral(_) | Expression::NumericLiteral(_) => true,
            Expression::TemplateLiteral(t) => {
                t.expressions.iter().all(|e| self.built_from(e, parts))
            }
            Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
                self.built_from(&b.left, parts) && self.built_from(&b.right, parts)
            }
            Expression::CallExpression(c) => {
                let joins = match self.callee(&c.callee) {
                    Callee::Module {
                        family,
                        export: Some(export),
                    } => has(&m().root_joins, &format!("{family}.{export}")),
                    _ => false,
                };
                joins
                    && c.arguments
                        .iter()
                        .all(|a| a.as_expression().is_some_and(|e| self.built_from(e, parts)))
            }
            _ => false,
        }
    }

    /// The name a route's handler goes by (`listUsers`, `users.list`); through a one-argument
    /// wrapper around a function of ours (`asyncHandler(deleteRoute)`, `catchAsync(list)`), the
    /// wrapped one, which is what runs for the route (`serveStatic(dir)` keeps its name); for a
    /// factory called with constants (`genaRoute('cds')`), the factory.
    pub(super) fn route_handler_name(&self, expr: &Expression<'_>) -> Option<String> {
        if let Expression::CallExpression(c) = expr.get_inner_expression()
            && c.arguments.len() == 1
            && let Some(inner) = c
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .map(Expression::get_inner_expression)
        {
            if let Expression::Identifier(inner) = inner
                && (self.relative.contains_key(inner.name.as_str())
                    || self.summaries.contains_key(inner.name.as_str()))
            {
                return Some(inner.name.as_str().to_owned());
            }
            // A route wrapper can receive a handler factory invocation rather than the handler
            // itself (`asyncHandler(profileImageUrlUpload())`). The function created by that
            // zero/constant-argument factory is what the route reaches, just as when the factory is
            // passed directly. Keep requiring a function known to this module so an arbitrary
            // middleware call is never mistaken for the route handler.
            if let Expression::CallExpression(factory_call) = inner
                && let Expression::Identifier(factory) = factory_call.callee.get_inner_expression()
                && (self.relative.contains_key(factory.name.as_str())
                    || self.summaries.contains_key(factory.name.as_str()))
                && factory_call.arguments.iter().all(|argument| {
                    matches!(
                        argument,
                        Argument::StringLiteral(_) | Argument::NumericLiteral(_)
                    )
                })
            {
                return Some(factory.name.as_str().to_owned());
            }
        }
        // `genaRoute('cds')`: a factory whose returned handler is a closure of it (its calls
        // and findings are the factory's own).
        if let Expression::CallExpression(c) = expr.get_inner_expression()
            && let Expression::Identifier(factory) = c.callee.get_inner_expression()
            && c.arguments
                .iter()
                .all(|a| matches!(a, Argument::StringLiteral(_) | Argument::NumericLiteral(_)))
        {
            return Some(factory.name.as_str().to_owned());
        }
        // `authorization.get` with `const authorization = authorizationController(options)`:
        // the action of the object the imported factory returns.
        if let Some(member) = expr.get_inner_expression().as_member_expression()
            && let Expression::Identifier(object) = member.object().get_inner_expression()
            && let Some(factory) = self.factory_bindings.get(object.name.as_str())
            && let Some(property) = member.static_property_name()
        {
            return Some(format!("{factory}.{}", property.as_str().unwrap_or("")));
        }
        callee_name(expr)
    }

    /// The variable a call names the same file as: `path.resolve(file)`, `path.normalize(file)`
    /// (a pack's `same_file` calls, with that one argument).
    /// `path.join(base, seg)` / `path.resolve(base, seg)` (and `join(base, 'mid', seg)` with
    /// literal middle parts): the base's access paths and the single joined segment, when exactly
    /// one argument is a path the rest is not. The segment is the last argument.
    pub(super) fn joined_base_segment(
        &self,
        expr: &Expression<'_>,
    ) -> Option<(Vec<String>, String)> {
        let Expression::CallExpression(c) = expr.get_inner_expression() else {
            return None;
        };
        let Callee::Module {
            family,
            export: Some(export),
        } = self.callee(&c.callee)
        else {
            return None;
        };
        let qualified = format!("{family}.{export}");
        if !(has(&m().root_joins, &qualified) || has(&m().same_file_calls, &qualified))
            || c.arguments.len() < 2
        {
            return None;
        }
        let args: Vec<&Expression<'_>> = c
            .arguments
            .iter()
            .map(|a| a.as_expression())
            .collect::<Option<_>>()?;
        let (base, rest) = args.split_first()?;
        let bases = guards::relative_base_keys(base);
        if bases.is_empty() {
            return None;
        }
        // Every middle argument must be a constant; the last is the segment.
        let (segment, middle) = rest.split_last()?;
        if !middle.iter().all(|e| literal_path(e).is_some()) {
            return None;
        }
        guards::path_key(segment).map(|seg| (bases, seg))
    }

    pub(super) fn same_file_of(&self, expr: &Expression<'_>) -> Option<String> {
        let Expression::CallExpression(c) = expr.get_inner_expression() else {
            return None;
        };
        let Callee::Module {
            family,
            export: Some(export),
        } = self.callee(&c.callee)
        else {
            return None;
        };
        if !has(&m().same_file_calls, &format!("{family}.{export}")) || c.arguments.len() != 1 {
            return None;
        }
        match c
            .arguments
            .first()
            .and_then(Argument::as_expression)?
            .get_inner_expression()
        {
            Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
            _ => None,
        }
    }

    /// Joins the states of the `break` / `continue` jumps that land here (see [`Walker::jumps`]).
    pub(super) fn land_jumps(&mut self, env: &mut Env) {
        for state in self.jumps.pop().unwrap_or_default() {
            env.join_with(&state);
        }
    }

    /// The classes a regular expression's captures are safe for: a literal, a local
    /// `const re = /.../`, or a property of a local or imported object of them
    /// (`regexes.profile` from `lib/utils/location.js`).
    pub(super) fn regex_mask(&self, expr: &Expression<'_>, env: &Env) -> Option<u8> {
        if is_regex(expr) {
            return Some(capture_mask(expr));
        }
        let key = guards::path_key(expr)?;
        // A parameter is whatever the caller passes, not a regex of this file of that name.
        let head = key.split('.').next().unwrap_or(&key);
        if env.params.iter().any(|p| p == head) {
            return None;
        }
        if let Some(mask) = self.regexes.get(&key) {
            return Some(*mask);
        }
        self.linked_constant(&key, REGEX_CONSTANT)
            .and_then(|mask| mask.parse().ok())
    }

    /// Records a TypeScript enum's members with literal values.
    pub(super) fn record_enum(&mut self, declaration: &oxc_ast::ast::TSEnumDeclaration<'_>) {
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
    pub(super) fn exported_function(&self, spec: &str, export: &str) -> Option<(String, String)> {
        let file = self.linking.resolve(spec)?;
        self.exported_function_in(&file, export)
    }

    /// [`Self::exported_function`] of a resolved file.
    pub(super) fn exported_function_in(
        &self,
        file: &str,
        export: &str,
    ) -> Option<(String, String)> {
        let file = file.to_owned();
        let table = |f: &str| self.linking.exports.get(f);
        let reexported: Vec<&String> = self
            .linking
            .reexports
            .get(&file)
            .map(|set| set.iter().collect())
            .unwrap_or_default();
        match table(&file).and_then(|t| t.get(export)) {
            // `{ getRegistry: Registry.getInstance }` with `Registry` declared elsewhere.
            Some(local) if local.starts_with(ELSEWHERE) => {
                let (file, name) = local.strip_prefix(ELSEWHERE)?.split_once('#')?;
                Some((file.to_owned(), name.to_owned()))
            }
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

    pub(super) fn names_file(&self, spec: &str, file: &str) -> bool {
        if self.linking.files.is_empty() {
            return spec_names_file(spec, file);
        }
        let resolved = self
            .resolved
            .borrow_mut()
            .entry(spec.to_owned())
            .or_insert_with(|| self.linking.resolve(spec))
            .clone();
        match resolved {
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
    pub(super) fn apply_summaries(
        &mut self,
        name: &str,
        summaries: &[Summary],
        taints: &[Option<Origin>],
        arguments: Option<&[Argument<'_>]>,
        call_span: Span,
        env: &Env,
    ) {
        for summary in summaries.iter().filter(|s| {
            s.api != RETURNS
                && s.api != VALIDATES
                && s.api != SCALARS
                && s.api != INSTANCE
                && s.api != PREDICATE
        }) {
            let whole = argument_taint(taints, summary.param, summary.rest);
            let origin = match (&summary.field, arguments) {
                (Some(field), Some(arguments)) => {
                    self.field_taint(arguments.get(summary.param), field, env, whole)
                }
                _ => whole,
            };
            let Some(origin) = origin else {
                continue;
            };
            // A sink that also needs another argument from the attacker (a nested write's second
            // key): a caller passing a constant there reaches nothing.
            if let Some(other) = summary.with_param
                && argument_taint(taints, other, false).is_none()
            {
                continue;
            }
            // Summarizing a function that hands its own parameter on whole (`new this(basic)`,
            // `create(options)`): what reaches the sink is that parameter's `field`, not all of
            // it (so a caller's other fields, `{ serverName, serverConfig }`, stay out).
            let handed_on = match (&summary.field, arguments) {
                (Some(field), Some(arguments))
                    if self.summarize
                        && origin.param.is_some()
                        && !self.field_of.contains_key(&origin.span.start)
                        && matches!(
                            arguments
                                .get(summary.param)
                                .and_then(Argument::as_expression)
                                .map(Expression::get_inner_expression),
                            Some(Expression::Identifier(id))
                                if env.params.iter().any(|p| p == id.name.as_str())
                        ) =>
                {
                    Some((origin.span.start, field.clone()))
                }
                _ => None,
            };
            let at_sink = &summary.at_sink;
            // A URL sink (or an argument that must start with `-`) is reached only when the
            // parameter is the value's start in the helper (not `${base}?key=${param}`) and the
            // caller controls the start of its value.
            if (summary.start || url_rule(summary.class, &summary.api))
                && !(at_sink.prefix && origin.prefix)
            {
                continue;
            }
            let built = at_sink.built || origin.built;
            let sqlish = at_sink.sqlish || origin.sqlish;
            let htmlish = at_sink.htmlish || origin.htmlish;
            // A raw SQL fragment (`orderByRaw`) is SQL whatever the text looks like.
            let fragment = sink_for_api(&summary.api)
                .is_some_and(|s| s.args.iter().any(|r| matches!(r, ArgRule::Fragment(_))));
            if summary.class == VulnClass::SqlInjection && !fragment && !(built && sqlish) {
                continue;
            }
            if summary.class == VulnClass::Xss && !built {
                continue;
            }
            // A response body is HTML only with markup in it, unless the sink also takes plain
            // built text (Express answers a string as HTML).
            if sink_for_api(&summary.api).is_some_and(|s| {
                s.args.iter().any(|r| matches!(r, ArgRule::Markup(_))) && s.also.is_empty()
            }) && !htmlish
            {
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
            // Preserve the sink-side shape while this finding is turned into another summary.
            // Without this, a first helper can establish that text is built HTML/SQL, but a
            // second helper loses that fact: the current call is accepted, then its transitive
            // summary records only the caller-side origin. A later caller therefore never sees
            // the same sink. This is especially important for DOM flows such as
            // `callback -> updateDisplay -> renderCard -> innerHTML`.
            let mut origin = origin;
            origin.built = built;
            origin.sqlish = sqlish;
            origin.htmlish = htmlish;
            let mut origin = origin.step(call_span.start, format!("passed to `{name}()`"));
            for step in summary.steps.iter().filter(|_| summary.ext.is_none()) {
                if origin.steps.len() < MAX_STEPS {
                    origin.steps.push(step.clone());
                }
            }
            self.emit_field = handed_on;
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
                    function: env.owner.clone(),
                    origin,
                    ext: summary.ext.clone(),
                    auth: Auth::NoneDetected,
                    start: summary.start,
                },
                env,
            );
            self.emit_field = None;
        }
    }

    /// Records a finding, or in the summary pass, a summary of a parameter that reaches a sink.
    pub(super) fn emit(&mut self, mut finding: RawFinding, env: &Env) {
        // Escaped for this class on the way (every sink kind ends here), or checked for a class
        // the sink is safe with (`shell.openPath` on a path confined to a directory).
        if self.record_only
            || finding.origin.escaped & class_bit(finding.class) != 0
            || sink_for_api(&finding.api)
                .is_some_and(|sink| cleared(&finding.origin, finding.class, sink))
        {
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
        if self.summarize {
            // One summary per parameter the value carries (`exec(b + a)`: both).
            let url_sink = finding.start || url_rule(finding.class, &finding.api);
            for (param, at, prefix, escaped) in finding.origin.contributors() {
                // A parameter after the start of a URL does not choose where it goes.
                if url_sink && !prefix {
                    continue;
                }
                // Escaped for this class on its own way in, before it met the rest.
                if escaped & class_bit(finding.class) != 0 {
                    continue;
                }
                // Reached through an instance field set from a constructor parameter; else the
                // function whose parameter it is (a sink inside a callback or a nested function).
                let (owner, scope) = match self.ctor_params.get(&at) {
                    Some(class) => (format!("{class}.constructor"), None),
                    None => self
                        .param_owner
                        .get(&at)
                        .cloned()
                        .unwrap_or_else(|| (env.function.clone(), env.def_scope)),
                };
                let field = self.field_of.get(&at).cloned().or_else(|| {
                    self.emit_field
                        .as_ref()
                        .filter(|(offset, _)| *offset == at)
                        .map(|(_, field)| field.clone())
                });
                let list = self.summaries.entry(owner).or_default();
                let duplicate = list.iter().any(|s| {
                    s.param == param
                        && s.call == finding.call
                        && s.api == finding.api
                        && s.field == field
                        && s.scope == scope
                });
                if !duplicate {
                    list.push(Summary {
                        param,
                        class: finding.class,
                        severity: finding.severity,
                        api: finding.api.clone(),
                        arg: finding.arg,
                        call: finding.call,
                        steps: finding.origin.steps.clone(),
                        field,
                        at_sink: Origin {
                            prefix,
                            ..finding.origin.clone()
                        },
                        ext: finding.ext.clone(),
                        out_field: None,
                        defined_in: None,
                        start: finding.start || url_sink,
                        rest: self.rest_params.contains(&at),
                        instance_of: None,
                        base_param: None,
                        with_param: self.emit_with_param.filter(|&other| other != param),
                        scope,
                    });
                }
            }
        } else if finding.origin.param.is_none() {
            self.result.findings.push(finding);
        }
    }

    pub(super) fn check_sink(
        &mut self,
        sink: models::Sink,
        callee: &Callee,
        arguments: &[Argument<'_>],
        taints: &[Option<Origin>],
        span: Span,
        env: &Env,
    ) {
        // A MongoDB query where the project has no MongoDB driver is another `.find()`.
        if !sink.requires.is_empty()
            && let Some(packages) = self.linking.packages
            && !sink.requires.iter().any(|p| packages.contains(p))
        {
            return;
        }
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
    pub(super) fn check_rules(
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
            let (index, origin) = match rule {
                ArgRule::Any(index) => (index, taints.get(index).cloned().flatten()),
                // `spawn('git', ['clone', x])`: `x` can start with `-` only if the attacker
                // chooses its start, nothing checked it, and no `--` ends the options before it.
                ArgRule::Start(index) => {
                    let argument = arguments.get(index).and_then(Argument::as_expression);
                    let origin = match argument.map(Expression::get_inner_expression) {
                        Some(Expression::ArrayExpression(array)) => {
                            let positions = self.array_positions(array, env);
                            let end_of_options = array.elements.iter().position(|e| {
                                matches!(e.as_expression().map(Expression::get_inner_expression),
                                    Some(Expression::StringLiteral(l)) if l.value.as_str() == Some("--"))
                            });
                            positions
                                .into_iter()
                                .enumerate()
                                .filter(|(i, _)| end_of_options.is_none_or(|end| *i < end))
                                .filter_map(|(_, t)| t)
                                .filter(|o| o.prefix && !o.dash_free)
                                .fold(None, |acc, o| union(acc, Some(o)))
                        }
                        _ => taints
                            .get(index)
                            .cloned()
                            .flatten()
                            .filter(|o| o.prefix && !o.dash_free),
                    };
                    (index, origin)
                }
                // A helper's parameter passed straight to the sink (`function query(sql) {
                // return pool.query(sql) }`): a summary, whose callers must build the text.
                ArgRule::Html(index) => (
                    index,
                    taints
                        .get(index)
                        .cloned()
                        .flatten()
                        .filter(|o| o.built || (self.summarize && o.param.is_some())),
                ),
                // A response body built with HTML markup in its literal text.
                ArgRule::Markup(index) => (
                    index,
                    taints.get(index).cloned().flatten().filter(|o| {
                        (o.built && o.htmlish) || (self.summarize && o.param.is_some())
                    }),
                ),
                ArgRule::Object(index) => (index, self.object_query(index, arguments, taints, env)),
                // `knex('t').orderByRaw('"t"."' + field + '"')`: text that is SQL by contract.
                ArgRule::Fragment(index) => (index, taints.get(index).cloned().flatten()),
                // `database.find('_User', { token })`: a data-access wrapper that takes the
                // collection's name first.
                ArgRule::ObjectAfterName(index) => {
                    let named = index
                        .checked_sub(1)
                        .and_then(|i| arguments.get(i))
                        .and_then(Argument::as_expression)
                        .is_some_and(|name| {
                            matches!(name.get_inner_expression(), Expression::StringLiteral(_))
                                || self.resolve_text(name, env).is_some()
                        });
                    let origin = if named {
                        self.object_query(index, arguments, taints, env)
                    } else {
                        None
                    };
                    (index, origin)
                }
                ArgRule::Built(index) => (
                    index,
                    taints.get(index).cloned().flatten().filter(|o| {
                        o.built && (o.sqlish || sink.class != VulnClass::SqlInjection)
                            || (self.summarize && o.param.is_some())
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
            // `shadowRoot.append(iframe)`: a node created here is inserted as a node.
            if sink.class == VulnClass::Xss
                && matches!(
                    arguments.get(index).and_then(Argument::as_expression).map(Expression::get_inner_expression),
                    Some(Expression::Identifier(id)) if env.nodes.contains(id.name.as_str())
                )
            {
                continue;
            }
            if has(&sink.ignore_kinds, origin.kind) || cleared(&origin, sink.class, sink) {
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
                    function: env.owner.clone(),
                    origin,
                    ext: None,
                    auth: Auth::NoneDetected,
                    start: matches!(rule, ArgRule::UrlPrefix(_) | ArgRule::Start(_)),
                },
                env,
            );
            return true;
        }
        false
    }
}
