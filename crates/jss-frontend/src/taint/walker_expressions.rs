use super::*;

impl Walker<'_> {
    // ----- expressions ------------------------------------------------------------------

    pub(super) fn expr_named(
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
        // `const Card = memo((props) => ...)`, `forwardRef(...)`, `observer(...)`: the wrapped
        // function is the component `Card`.
        if let (Some(name), Expression::CallExpression(call)) = (&name, expr.get_inner_expression())
            && callee_name(&call.callee).is_some_and(|c| has(&m().component_wrappers, &c))
            && let Some(wrapped) = call.arguments.first().and_then(Argument::as_expression)
        {
            for argument in call.arguments.iter().skip(1) {
                self.argument(argument, env, Role::Plain);
            }
            return self.expr_named(wrapped, env, Some(name.clone()));
        }
        if self.maybe_function(expr, env, name, role) {
            return None;
        }
        self.expr(expr, env)
    }

    pub(super) fn expr(&mut self, expr: &Expression<'_>, env: &mut Env) -> Option<Origin> {
        if !self.enter() {
            return None;
        }
        let taint = self.expr_inner(expr, env);
        self.leave();
        taint
    }

    pub(super) fn expr_inner(&mut self, expr: &Expression<'_>, env: &mut Env) -> Option<Origin> {
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
                        origin.htmlish |= template
                            .quasis
                            .iter()
                            .any(|q| looks_like_markup(q.value.raw.as_str()));
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
                    // Any literal text on either side: `'SELECT ...' + ' WHERE n = ' + x`.
                    let mut parts = Vec::new();
                    literal_parts(&binary.left, &mut parts);
                    literal_parts(&binary.right, &mut parts);
                    let sqlish = parts.iter().any(|t| m().looks_like_sql(t));
                    let htmlish = parts.iter().any(|t| looks_like_markup(t));
                    let left = left.map(|mut o| {
                        o.built = true;
                        o.sqlish |= sqlish;
                        o.htmlish |= htmlish;
                        o
                    });
                    let right = right.map(|mut o| {
                        o.built = true;
                        o.sqlish |= sqlish;
                        o.htmlish |= htmlish;
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
                // `flag && (x = 'ls')`, `remember && rememberEmail(res, email)`: the right side
                // runs on one path only; what it assigns or proves joins the path that skipped it.
                let skipped =
                    (may_assign(&logical.right) || has_call(&logical.right)).then(|| env.save());
                let right = self.expr(&logical.right, env);
                if let Some(skipped) = skipped {
                    env.join_with(&skipped);
                }
                // `options.path || path`: a module object, not data.
                if self.module_fallback(expr).is_some() {
                    return None;
                }
                // `match && table[match[1]]`: the left side is the value only when it is falsy
                // (`null`, `''`, `0`, `false`), which carries nothing an attacker chose.
                if logical.operator == LogicalOperator::And {
                    return right;
                }
                union(left, right)
            }
            Expression::ConditionalExpression(c) => {
                self.expr(&c.test, env);
                // `['jpg', 'png'].includes(ext(u)) ? ext(u) : 'jpg'`: the branch that repeats the
                // checked expression is one of the listed values, even when that expression has
                // no access path for a fact to hold on.
                let echoed = self.allowlisted_echo(c);
                let mask = |a: Option<Origin>, b: Option<Origin>| {
                    union(
                        a.filter(|_| echoed != Some(true)),
                        b.filter(|_| echoed != Some(false)),
                    )
                };
                // `ALLOWED.includes(x) ? x : 'id'`, `isInsideDir(home, p) ? p : null`: what the
                // test establishes holds in its branch.
                let mut held = Vec::new();
                guards::facts(&c.test, true, &mut held);
                self.predicate_facts(&c.test, true, &mut held);
                let mut failed = Vec::new();
                guards::facts(&c.test, false, &mut failed);
                self.predicate_facts(&c.test, false, &mut failed);
                // `flag ? (x = 'ls') : 0`, `flag ? check(x) : 0`: each branch on its own path,
                // joined after.
                if may_assign(&c.consequent)
                    || may_assign(&c.alternate)
                    || has_call(&c.consequent)
                    || has_call(&c.alternate)
                {
                    let before = env.save();
                    env.learn(held);
                    let a = self.expr(&c.consequent, env);
                    let then_path = env.save();
                    env.restore(before);
                    env.learn(failed);
                    let b = self.expr(&c.alternate, env);
                    env.join_with(&then_path);
                    return mask(a, b);
                }
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
                mask(a, b)
            }
            Expression::AwaitExpression(a) => {
                if let Expression::CallExpression(awaited) = a.argument.get_inner_expression() {
                    self.promised.insert((awaited.span.start, awaited.span.end));
                }
                self.expr(&a.argument, env)
            }
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
                if assign.operator == AssignmentOperator::Assign
                    && let AssignmentTarget::AssignmentTargetIdentifier(id) = &assign.left
                {
                    note_url_parts(id.name.as_str(), &assign.right, env);
                    self.note_record(id.name.as_str(), &assign.right, env);
                }
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
                // `exports.r = Router().get('/a', h)`: the routes of the chain are on `r`.
                let mut chain_local: Option<String> = None;
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
                        // `exports.getRegistry = Registry.getInstance`
                        value @ Expression::StaticMemberExpression(_) => self.member_export(value),
                        Expression::FunctionExpression(f) => {
                            f.id.as_ref()
                                .map(|id| id.name.as_str().to_owned())
                                .or_else(|| property.clone())
                        }
                        Expression::ArrowFunctionExpression(_) => property.clone(),
                        // `module.exports = router.all('/cors', h)`: exports `router`.
                        right @ Expression::CallExpression(_) => self.registration_receiver(right),
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
                    if export.is_some()
                        && local.is_none()
                        && let Expression::CallExpression(c) = assign.right.get_inner_expression()
                        && self.chain_base(&c.callee, env).is_some()
                    {
                        chain_local = property.clone();
                    }
                    // `module.exports = require('./impl')`: a re-export; `exports.users =
                    // require('./users')`: a namespace.
                    if let Some(file) =
                        require_spec(&assign.right).and_then(|spec| self.linking.resolve(&spec))
                    {
                        match export.as_deref() {
                            Some("default") => self.facts.reexports.push(file),
                            Some(name) => {
                                self.facts
                                    .exports
                                    .insert(name.to_owned(), format!("{NAMESPACE}{file}"));
                            }
                            None => {}
                        }
                    }
                    let local = local.or_else(|| chain_local.clone());
                    if let (Some(export), Some(local)) = (export, local) {
                        self.facts.exports.insert(export, local);
                    }
                    // `module.exports = { list, create, users: require('./users') }`
                    if key == "module.exports"
                        && let Expression::ObjectExpression(object) =
                            assign.right.get_inner_expression()
                    {
                        for property in &object.properties {
                            let ObjectPropertyKind::ObjectProperty(p) = property else {
                                continue;
                            };
                            let Some(k) = prop_name(&p.key) else {
                                continue;
                            };
                            match p.value.get_inner_expression() {
                                Expression::Identifier(v) => {
                                    self.facts.exports.insert(k, v.name.as_str().to_owned());
                                }
                                // `getRegistry: Registry.getInstance`
                                value if self.member_export(value).is_some() => {
                                    if let Some(local) = self.member_export(value) {
                                        self.facts.exports.insert(k, local);
                                    }
                                }
                                value => {
                                    if let Some(file) = require_spec(value)
                                        .and_then(|spec| self.linking.resolve(&spec))
                                    {
                                        self.facts.exports.insert(k, format!("{NAMESPACE}{file}"));
                                    }
                                }
                            }
                        }
                        // A self-describing HTTP route-definition module:
                        // `module.exports = { method: 'post', path: '/api/x', handler: (req, res) => {...} }`.
                        // An index file collects these and registers each in a loop
                        // (`app[def.method](def.path, def.handler)`), so the exported handler is an
                        // anonymous HTTP entry reached at that method and path. The handler function is
                        // walked (and named) by its property key, so the route resolves to it.
                        if !self.summarize && !self.record_only {
                            let model = m();
                            let field = |keys: &[String]| {
                                object.properties.iter().find_map(|property| {
                                    let ObjectPropertyKind::ObjectProperty(p) = property else {
                                        return None;
                                    };
                                    let name = prop_name(&p.key)?;
                                    has(keys, &name).then_some((name, &p.value))
                                })
                            };
                            if let Some((handler_key, handler_value)) =
                                field(&model.route_handler_keys)
                                && matches!(
                                    handler_value.get_inner_expression(),
                                    Expression::ArrowFunctionExpression(_)
                                        | Expression::FunctionExpression(_)
                                )
                                && let Some(method) = field(&model.route_method_keys)
                                    .and_then(|(_, value)| self.resolve_text(value, env))
                                    .filter(|verb| is_http_verb(verb))
                                && let Some(path) = field(&model.route_path_keys)
                                    .and_then(|(_, value)| self.resolve_text(value, env))
                                    .filter(|path| path.starts_with('/'))
                            {
                                self.facts.routes.push(RouteFact {
                                    at: None,
                                    receiver: None,
                                    receiver_file: None,
                                    method: method.to_ascii_uppercase(),
                                    path,
                                    handler: handler_key,
                                    span: object.span,
                                    auth: Auth::NoneDetected,
                                    kind: "http",
                                });
                            }
                        }
                    }
                }
                // `this.svc = new Svc()`: the field holds a `Svc` in every method.
                if let Some(member) = assign
                    .left
                    .as_simple_assignment_target()
                    .and_then(SimpleAssignmentTarget::as_member_expression)
                    && matches!(member.object(), Expression::ThisExpression(_))
                    && let Some(field) = member.static_property_name().and_then(|n| n.as_str())
                    && let Some(class) = self.current_class.clone()
                    && let Some(typed) = self.instance_class(&assign.right, None, env)
                {
                    self.field_types.insert((class, field.to_owned()), typed);
                }
                // `C.prototype.run = function () {}` and `C.prototype = { run() {} }`: methods
                // of the ES5 class `C`, walked as `C.run` with `this` an instance of `C`.
                if let Some(class) = assign
                    .left
                    .as_simple_assignment_target()
                    .and_then(SimpleAssignmentTarget::as_member_expression)
                    .and_then(prototype_owner)
                {
                    self.declared_classes.insert(class.0.clone());
                    let saved_class = self.current_class.replace(class.0.clone());
                    match (&class.1, assign.right.get_inner_expression()) {
                        (Some(method), right) => {
                            let name = Some(format!("{}.{method}", class.0));
                            if !self.maybe_function(right, env, name, Role::Plain) {
                                self.expr(right, env);
                            }
                        }
                        (None, Expression::ObjectExpression(object)) => {
                            for property in &object.properties {
                                let ObjectPropertyKind::ObjectProperty(p) = property else {
                                    continue;
                                };
                                let name = prop_name(&p.key).map(|k| format!("{}.{k}", class.0));
                                if !self.maybe_function(&p.value, env, name, Role::Plain) {
                                    self.expr(&p.value, env);
                                }
                            }
                        }
                        (None, right) => {
                            self.expr(right, env);
                        }
                    }
                    self.current_class = saved_class;
                    return None;
                }
                let saved_receiver = match chain_local {
                    Some(local) => {
                        self.routers.insert(local.clone());
                        self.chain_receiver.replace(local)
                    }
                    None => self.chain_receiver.take(),
                };
                let taint = self.expr_named(&assign.right, env, name);
                self.chain_receiver = saved_receiver;
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
                // `a.href = value` on `document.createElement('a')`
                if let Some(origin) = &taint
                    && let Some(member) = assign
                        .left
                        .as_simple_assignment_target()
                        .and_then(SimpleAssignmentTarget::as_member_expression)
                    && let Expression::Identifier(object) = member.object().get_inner_expression()
                    && let Some(tag) = env.node_tags.get(object.name.as_str())
                    && let Some(property) = member.static_property_name().and_then(|n| n.as_str())
                    && let Some(sink) = m().url_attribute(tag, property)
                {
                    let api = format!("{}.{property} =", object.name.as_str());
                    self.url_sink(
                        sink,
                        api,
                        assign.right.span(),
                        assign.span,
                        origin.clone(),
                        env,
                    );
                }
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
                    // A local `let location` is not the page's `location`.
                    && !env
                        .locals
                        .contains(target.split('.').next().unwrap_or(&target))
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
                                function: env.owner.clone(),
                                origin: origin.clone(),
                                ext: None,
                                auth: Auth::NoneDetected,
                                start: url_rule,
                            },
                            env,
                        );
                    }
                }
                // `db = getDBClient(cfg)`, `this.registry = getRegistry()`, `Registry.instance =
                // new Registry()`: what the target now holds an instance of.
                if assign.operator.is_assign() {
                    self.type_assignment(&assign.left, &assign.right, env);
                }
                // `video = doc.createElement('video')` on a `let video` declared earlier: a node;
                // `re = new RegExp(input)`: no longer the regex it was declared with.
                if assign.operator.is_assign()
                    && let Some(SimpleAssignmentTarget::AssignmentTargetIdentifier(id)) =
                        assign.left.as_simple_assignment_target()
                {
                    let name = id.name.as_str().to_owned();
                    if creates_node(&assign.right) {
                        env.nodes.insert(name.clone());
                    } else {
                        env.nodes.remove(&name);
                    }
                    if is_regex(&assign.right) {
                        self.regexes.insert(name, capture_mask(&assign.right));
                    } else {
                        self.regexes.remove(&name);
                    }
                }
                // `_mounts.main = (app) => { ... }`: one more function of the table.
                if assign.operator.is_assign()
                    && let Some(member) = assign
                        .left
                        .as_simple_assignment_target()
                        .and_then(SimpleAssignmentTarget::as_member_expression)
                    && let Expression::Identifier(table) = member.object().get_inner_expression()
                    && let Some(key) = member.static_property_name().and_then(|n| n.as_str())
                    && let Some(entry) = table_entry(key.to_owned(), &assign.right)
                    && let Some(entries) = self.fn_tables.get_mut(table.name.as_str())
                    && !entries.contains(&entry)
                {
                    entries.push(entry);
                }
                // `mstream = express()` on a `let mstream;` declared earlier: a router, for the
                // routes registered on it here and in the helpers it is handed to.
                if assign.operator.is_assign() {
                    let factory = match chain_root(&assign.right) {
                        Expression::CallExpression(c) => callee_name(&c.callee),
                        Expression::NewExpression(n) => callee_name(&n.callee),
                        _ => None,
                    };
                    // ... or a field: `FastifyWorker.fastify = Fastify()`, `this.app = express()`.
                    let target = match &assign.left {
                        AssignmentTarget::AssignmentTargetIdentifier(id) => {
                            Some(id.name.as_str().to_owned())
                        }
                        other => other
                            .as_simple_assignment_target()
                            .and_then(SimpleAssignmentTarget::as_member_expression)
                            .and_then(|m| match m {
                                oxc_ast::ast::MemberExpression::StaticMemberExpression(s) => {
                                    Some(format!(
                                        "{}.{}",
                                        member_path(&s.object)?,
                                        s.property.name.as_str()
                                    ))
                                }
                                _ => None,
                            }),
                    };
                    if factory.as_deref().is_some_and(is_router_factory)
                        && let Some(target) = target
                    {
                        self.routers.insert(target);
                    }
                }
                self.assign_target(&assign.left, taint.clone(), env);
                taint
            }
            Expression::ArrayExpression(array) => {
                let mut taint = None;
                // `['--json', '--', pattern]`: after `--`, arguments are positional.
                let mut ended = false;
                for element in &array.elements {
                    if ends_options(element.as_expression()) {
                        ended = true;
                        continue;
                    }
                    let t = match element {
                        ArrayExpressionElement::SpreadElement(s) => self.expr(&s.argument, env),
                        ArrayExpressionElement::Elision(_) => None,
                        other => other.as_expression().and_then(|e| self.expr(e, env)),
                    };
                    let t = t.map(|mut o| {
                        o.dash_free |= ended;
                        o
                    });
                    taint = union(taint, t);
                }
                taint
            }
            Expression::ObjectExpression(object) => {
                let mut taint = None;
                // Convention routers can declare middleware beside their handler rather than pass
                // it positionally: `{ useMiddlewares: ["withAuthentication"], fn(req) { ... } }`.
                // Ground the handler's auth in those declared names just as route arguments are.
                let configured_auth = object
                    .properties
                    .iter()
                    .filter_map(|property| {
                        let ObjectPropertyKind::ObjectProperty(property) = property else {
                            return None;
                        };
                        matches!(
                            prop_name(&property.key).as_deref(),
                            Some("middleware" | "middlewares" | "useMiddlewares")
                        )
                        .then(|| declared_middleware_auth(&property.value))
                        .flatten()
                    })
                    .max()
                    .unwrap_or_default();
                // `{ parameters, handler: async (args) => ... }`: an LLM tool.
                let tool = tool_object(object);
                // `{ name: 'run-sql', parameters, handler }`: an entry named by the tool, and its
                // handler by the entry.
                let tool_entry = tool.and_then(|(_, spec)| {
                    let tool_name = object.properties.iter().find_map(|property| {
                        let ObjectPropertyKind::ObjectProperty(p) = property else {
                            return None;
                        };
                        prop_name(&p.key)
                            .is_some_and(|k| has(&spec.name_keys, &k))
                            .then(|| match p.value.get_inner_expression() {
                                Expression::StringLiteral(l) => l.value.as_str().map(str::to_owned),
                                _ => None,
                            })
                            .flatten()
                    })?;
                    let entry = format!("{} {tool_name}", spec.kind.to_ascii_uppercase());
                    if !self.summarize && !self.record_only {
                        self.facts.routes.push(RouteFact {
                            at: None,
                            receiver: None,
                            receiver_file: None,
                            method: spec.kind.to_ascii_uppercase(),
                            path: tool_name,
                            handler: entry.clone(),
                            span: object.span,
                            auth: Auth::NoneDetected,
                            kind: spec.kind.as_str(),
                        });
                    }
                    Some(entry)
                });
                for property in &object.properties {
                    let t = match property {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            if let Some(key) = p.key.as_expression()
                                && p.computed
                            {
                                self.expr(key, env);
                            }
                            let name = prop_name(&p.key);
                            if let (Some((handler, spec)), Some(key)) = (tool, name.as_deref())
                                && key == handler
                                && self.maybe_function(
                                    &p.value,
                                    env,
                                    tool_entry.clone().or_else(|| name.clone()),
                                    Role::Client(
                                        spec.kind.as_str(),
                                        spec.params.as_deref().map_or(Params::First, Params::parse),
                                    ),
                                )
                            {
                                continue;
                            }
                            // `devServer: { before: [(req, res, next) => ...] }`: middleware a
                            // server runs, listed in its options.
                            if let Some(spec) = name.as_deref().and_then(|key| {
                                m().middleware_options.iter().find(|o| o.object == key)
                            }) && let Expression::ObjectExpression(options) =
                                p.value.get_inner_expression()
                            {
                                self.middleware_options(options, spec, env);
                                continue;
                            }
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
                                                    at: None,
                                                    receiver: None,
                                                    receiver_file: None,
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
                                    // tRPC: `{ getUser: t.procedure.input(...).query(fn) }`: listed (and its
                                    // callback named) by its key.
                                    if let (Some(key), Expression::CallExpression(c)) =
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
                                                // On a procedure, not RTK Query's
                                                // `builder.mutation({ query })`.
                                                && (s.object_contains.is_empty()
                                                    || any_contains(
                                                        receiver_chain(&c.callee)
                                                            .iter()
                                                            .map(String::as_str),
                                                        &s.object_contains,
                                                    ))
                                        })
                                    {
                                        let verb = format!(
                                            "{}.{}",
                                            source.kind.to_ascii_uppercase(),
                                            method.to_ascii_uppercase()
                                        );
                                        let entry = format!("{verb} {key}");
                                        self.keyed_entries
                                            .insert((c.span.start, c.span.end), entry.clone());
                                        if !self.summarize {
                                            self.facts.routes.push(RouteFact {
                                                at: None,
                                                receiver: None,
                                                receiver_file: None,
                                                method: verb,
                                                path: key.clone(),
                                                handler: entry,
                                                span: p.span,
                                                auth: env.auth,
                                                kind: source.kind.as_str(),
                                            });
                                        }
                                    }
                                    if configured_auth != Auth::NoneDetected
                                        && name
                                            .as_deref()
                                            .is_some_and(|key| matches!(key, "fn" | "handler"))
                                    {
                                        let pending = self.pending_auth;
                                        self.pending_auth = pending.max(configured_auth);
                                        let value = self.expr_named(&p.value, env, name);
                                        self.pending_auth = pending;
                                        value
                                    } else {
                                        self.expr_named(&p.value, env, name)
                                    }
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
                // `new StreamableHTTPServerTransport(..)`: lifts a pack's local cap repo-wide.
                if !self.summarize
                    && let Some(name) = callee_name(&new.callee)
                    && m().local_caps.iter().any(|c| has(&c.unless_new, &name))
                {
                    self.facts.constructed.insert(name);
                }
                // `new Worker('jobs', async (job) => ...)`: client callbacks as with calls, an
                // entry named by the queue, and the callback by its entry.
                let (role, shape) = self.client_role(&callee, &new.callee, &new.arguments, env);
                let last = new.arguments.len().saturating_sub(1);
                let client_name = match role {
                    Role::Client(kind, _) => self.client_event(&new.arguments, None).map(|event| {
                        let name = format!("{} {event}", kind.to_ascii_uppercase());
                        if !self.summarize && !self.record_only {
                            self.facts.routes.push(RouteFact {
                                at: None,
                                receiver: None,
                                receiver_file: None,
                                method: kind.to_ascii_uppercase(),
                                path: event,
                                handler: name.clone(),
                                span: new.span,
                                auth: Auth::NoneDetected,
                                kind,
                            });
                        }
                        name
                    }),
                    _ => None,
                };
                let mut taints = Vec::new();
                for (index, argument) in new.arguments.iter().enumerate() {
                    let role = match shape {
                        Shape::LastCallback if index != last => Role::Plain,
                        _ => role,
                    };
                    let named = match argument.as_expression() {
                        Some(expr) if index == last && client_name.is_some() => {
                            self.maybe_function(expr, env, client_name.clone(), role)
                        }
                        _ => false,
                    };
                    if named {
                        self.apply_closure_writes(env);
                        taints.push(None);
                    } else {
                        taints.push(self.argument(argument, env, role));
                    }
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
                // `new Executor(config)`: what the constructor's fields reach in any method;
                // `new this(basic)` in a static factory: the class's own constructor.
                let class = match (&callee, new.callee.get_inner_expression()) {
                    (Callee::Global(class), _) => Some(class.clone()),
                    (_, Expression::ThisExpression(_)) => self.current_class.clone(),
                    _ => None,
                };
                if let Some(class) = class
                    && let Some((name, summaries)) = self.constructor_summaries(&class)
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
                // `new URL(input)` keeps the input; `new URLSearchParams(q)` too, though its
                // text form is percent-encoded (what `.get()` reads back is not).
                match &callee {
                    Callee::Global(name) if has(&m().pass_globals, name) => {
                        taints.iter().flatten().next().cloned().map(|mut o| {
                            if has(&m().encoding_constructors, name) {
                                o.escaped |= ENCODED;
                            }
                            o.step(new.span.start, format!("through new {name}()"))
                        })
                    }
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
                self.apply_closure_writes(env);
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
                let taint = self.expr(&import.source, env);
                // `import(x)`: the module a computed specifier names runs.
                if let Some(origin) = taint
                    && let Some(sink) = m().global_sink("import")
                    && !has(&sink.ignore_kinds, origin.kind)
                    && !cleared(&origin, sink.class, sink)
                {
                    let severity = m().cap(origin.kind, sink.severity);
                    self.emit(
                        RawFinding {
                            class: sink.class,
                            severity,
                            api: "import".to_owned(),
                            arg: import.source.span(),
                            call: import.span,
                            function: env.owner.clone(),
                            origin,
                            ext: None,
                            auth: Auth::NoneDetected,
                            start: false,
                        },
                        env,
                    );
                }
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
    pub(super) fn jsx_element(&mut self, element: &oxc_ast::ast::JSXElement<'_>, env: &mut Env) {
        use oxc_ast::ast::{JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXElementName};
        if !self.enter() {
            return;
        }
        // An intrinsic element (`<a>`, `<embed>`), never a component (`<Link>`).
        let tag = match &element.opening_element.name {
            JSXElementName::Identifier(id) => Some(id.name.as_str()),
            _ => None,
        };
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
                            if let Some((tag, sink)) =
                                tag.and_then(|t| m().url_attribute(t, name).map(|s| (t, s)))
                            {
                                // `<a href={url}>`, `<embed src={href}>`
                                if let Some(origin) = self.expr(expr, env) {
                                    self.url_sink(
                                        sink,
                                        format!("<{tag} {name}>"),
                                        expr.span(),
                                        attribute.span,
                                        origin,
                                        env,
                                    );
                                }
                            } else if has(&m().jsx_html_props, name) {
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
                                            function: env.owner.clone(),
                                            origin,
                                            ext: None,
                                            auth: Auth::NoneDetected,
                                            start: false,
                                        },
                                        env,
                                    );
                                }
                            } else if self.maybe_function(expr, env, None, Role::Plain) {
                                self.apply_closure_writes(env);
                            } else {
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

    /// What a request to an attacker-chosen URL returns (`fetch(url)`, `axios.get(url)`): the
    /// attacker's server answers, so its body is attacker data (an object, for JSON). Nothing for
    /// a URL whose start the code fixed.
    pub(super) fn response_of(
        &self,
        callee: &Callee,
        taints: &[Option<Origin>],
        span: Span,
    ) -> Option<Origin> {
        let sink = match callee {
            Callee::Module { family, export } => {
                m().module_sink(family, export.as_deref().unwrap_or(""))
            }
            Callee::Global(name) => m().global_sink(name),
            Callee::Method { .. } => None,
        }?;
        if !sink.response {
            return None;
        }
        let index = sink.args.iter().find_map(|rule| match rule {
            ArgRule::UrlPrefix(index) => Some(*index),
            _ => None,
        })?;
        let origin = taints.get(index)?.clone()?;
        if !origin.prefix {
            return None;
        }
        let api = callee_label(callee);
        Some(
            Origin {
                object: true,
                built: false,
                sqlish: false,
                htmlish: false,
                escaped: 0,
                primary_escaped: 0,
                response: true,
                ..origin
            }
            .step(span.start, format!("response of `{api}()`")),
        )
    }

    /// A NoSQL query argument that JSON or qs can turn into `{ "$ne": null }`: the value itself
    /// (`find(req.body.filter)`), or a value written in a literal query
    /// (`find({ email: req.body.email })`).
    pub(super) fn object_query(
        &mut self,
        index: usize,
        arguments: &[Argument<'_>],
        taints: &[Option<Origin>],
        env: &Env,
    ) -> Option<Origin> {
        let arg = arguments.get(index).and_then(Argument::as_expression);
        let literal = matches!(
            arg.map(Expression::get_inner_expression),
            Some(Expression::ObjectExpression(_) | Expression::ArrayExpression(_))
        );
        let from_fields = arg
            .filter(|_| literal)
            .and_then(|arg| self.query_values(arg, env, 0));
        let direct = taints
            .get(index)
            .cloned()
            .flatten()
            .filter(|o| !o.built && o.object && !literal);
        from_fields.or(direct)
    }

    /// The first value of a query written as a literal (`{ email: x }`, an aggregation
    /// pipeline `[{ $match: { type: t } }]`) that JSON or qs could turn into an operator
    /// object. Not an ORM's options (`{ where: { email } }`: its operators cannot come from
    /// JSON), nor the operand of a comparison (`{ url: { $ne: x } }`: compared as a value).
    pub(super) fn query_values(
        &mut self,
        expr: &Expression<'_>,
        env: &Env,
        depth: u8,
    ) -> Option<Origin> {
        if depth > 6 {
            return None;
        }
        match expr.get_inner_expression() {
            Expression::ObjectExpression(object) => {
                object
                    .properties
                    .iter()
                    .find_map(|property| match property {
                        ObjectPropertyKind::ObjectProperty(p)
                            if prop_name(&p.key).is_some_and(|k| has(&m().orm_options, &k))
                                || literal_comparison(&p.value) =>
                        {
                            None
                        }
                        ObjectPropertyKind::ObjectProperty(p) => {
                            match p.value.get_inner_expression() {
                                nested @ (Expression::ObjectExpression(_)
                                | Expression::ArrayExpression(_)) => {
                                    self.query_values(nested, env, depth + 1)
                                }
                                value => {
                                    let mut probe = env.clone();
                                    self.expr(value, &mut probe)
                                        .filter(|o| !o.built && o.object)
                                }
                            }
                        }
                        ObjectPropertyKind::SpreadProperty(_) => None,
                    })
            }
            Expression::ArrayExpression(array) => array.elements.iter().find_map(|element| {
                let element = element.as_expression()?;
                match element.get_inner_expression() {
                    nested @ (Expression::ObjectExpression(_) | Expression::ArrayExpression(_)) => {
                        self.query_values(nested, env, depth + 1)
                    }
                    value => {
                        let mut probe = env.clone();
                        self.expr(value, &mut probe)
                            .filter(|o| !o.built && o.object)
                    }
                }
            }),
            _ => None,
        }
    }

    /// A URL sink (`<a href={v}>`, `a.href = v` on an anchor): reported when the attacker
    /// chooses the start of the URL, and so its scheme (`javascript:`).
    pub(super) fn url_sink(
        &mut self,
        sink: &models::Sink,
        api: String,
        arg: Span,
        call: Span,
        origin: Origin,
        env: &Env,
    ) {
        if !origin.prefix {
            return;
        }
        self.emit(
            RawFinding {
                class: sink.class,
                severity: m().cap(origin.kind, sink.severity),
                api,
                arg,
                call,
                function: env.owner.clone(),
                origin,
                ext: None,
                auth: Auth::NoneDetected,
                start: true,
            },
            env,
        );
    }

    pub(super) fn jsx_children(&mut self, children: &[oxc_ast::ast::JSXChild<'_>], env: &mut Env) {
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

    /// The fields of an object literal with their taint: written ones, those of spread object
    /// literals (`...(c ? { a } : {})`) and of tracked locals, and under [`REST_FIELD`] what
    /// spreads of unknown shape (`...req.body`) or computed keys may hold.
    pub(super) fn literal_fields(
        &mut self,
        object: &ObjectExpression<'_>,
        env: &Env,
    ) -> BTreeMap<String, Origin> {
        let mut fields: BTreeMap<String, Origin> = BTreeMap::new();
        let add = |fields: &mut BTreeMap<String, Origin>, key: String, origin: Origin| {
            let merged = union(fields.remove(&key), Some(origin.clone())).unwrap_or(origin);
            fields.insert(key, merged);
        };
        for property in &object.properties {
            match property {
                ObjectPropertyKind::ObjectProperty(p) => {
                    // A method value (`{ list: async (req) => {...} }`) carries no data taint,
                    // and the object's own walk already analyzes it under its property name;
                    // re-walking it here as an anonymous function would only duplicate its
                    // findings under the enclosing scope's owner.
                    if is_function_value(&p.value) {
                        continue;
                    }
                    let mut probe = env.clone();
                    let Some(origin) = self.expr(&p.value, &mut probe) else {
                        continue;
                    };
                    let key = prop_name(&p.key).unwrap_or_else(|| REST_FIELD.to_owned());
                    add(&mut fields, key, origin);
                }
                ObjectPropertyKind::SpreadProperty(spread) => {
                    for (key, origin) in self.spread_fields(&spread.argument, env) {
                        add(&mut fields, key, origin);
                    }
                }
            }
        }
        fields
    }

    /// The fields a spread brings into an object literal (see [`Self::literal_fields`]).
    pub(super) fn spread_fields(
        &mut self,
        expr: &Expression<'_>,
        env: &Env,
    ) -> BTreeMap<String, Origin> {
        match expr.get_inner_expression() {
            Expression::ObjectExpression(object) => self.literal_fields(object, env),
            Expression::ConditionalExpression(c) => {
                let mut fields = self.spread_fields(&c.consequent, env);
                for (key, origin) in self.spread_fields(&c.alternate, env) {
                    let merged = union(fields.remove(&key), Some(origin.clone())).unwrap_or(origin);
                    fields.insert(key, merged);
                }
                fields
            }
            Expression::LogicalExpression(l) if l.operator == LogicalOperator::And => {
                self.spread_fields(&l.right, env)
            }
            Expression::Identifier(id) if env.fields.contains_key(id.name.as_str()) => env
                .fields
                .get(id.name.as_str())
                .cloned()
                .unwrap_or_default(),
            other => {
                let mut probe = env.clone();
                self.expr(other, &mut probe)
                    .map(|origin| BTreeMap::from([(REST_FIELD.to_owned(), origin)]))
                    .unwrap_or_default()
            }
        }
    }

    /// The taint of an object's keys, given the object's own taint: attacker-chosen when the
    /// object can be an attacker's (a parsed body or query, a parameter), never for an object
    /// or array literal or a tracked local, whose keys are written in the code.
    pub(super) fn keys_taint(
        &mut self,
        expr: &Expression<'_>,
        taint: Option<&Origin>,
        env: &Env,
    ) -> Option<Origin> {
        // A tracked local: the keys its unknown spreads bring and those an attacker-chosen
        // computed write added; its written keys are the code's.
        if let Expression::Identifier(id) = expr.get_inner_expression()
            && let Some(fields) = env.fields.get(id.name.as_str())
        {
            return union(
                fields.get(REST_FIELD).filter(|o| o.object).cloned(),
                fields.get(KEYED_FIELD).cloned(),
            );
        }
        let taint = taint.filter(|o| o.object)?;
        let keys = match expr.get_inner_expression() {
            // `{ ...req.body }` brings the body's keys; `{ a: req.query.x }` has only `a`.
            Expression::ObjectExpression(object) => object
                .properties
                .iter()
                .any(|p| matches!(p, ObjectPropertyKind::SpreadProperty(_)))
                .then(|| taint.clone()),
            Expression::ArrayExpression(_) => None,
            _ => Some(taint.clone()),
        }?;
        // Summary pass: a parameter's keys are a pseudo-field of it, which each call site
        // resolves to its argument's keys (not its values).
        if self.summarize && keys.param.is_some() && !self.field_of.contains_key(&keys.span.start) {
            let at = expr.span().start;
            if let Some(owner) = self.param_owner.get(&keys.span.start).cloned() {
                self.param_owner.insert(at, owner);
            }
            if let Some(class) = self.ctor_params.get(&keys.span.start).cloned() {
                self.ctor_params.insert(at, class);
            }
            self.field_of.insert(at, KEYS_FIELD.to_owned());
            let mut keyed = keys;
            keyed.span = expr.span();
            return Some(keyed);
        }
        Some(keys)
    }

    /// Stores `value` in what `target` names, as a weak update (`args.push(x)`,
    /// `Object.assign(o, src)`): a variable, a field of `this`, or a field of a tracked object.
    pub(super) fn store_into(
        &mut self,
        target: &Expression<'_>,
        value: Origin,
        at: u32,
        env: &mut Env,
    ) {
        match target.get_inner_expression() {
            Expression::Identifier(id) => {
                let name = id.name.as_str();
                if env.requests.contains_key(name) {
                    return;
                }
                let value = value.step(at, format!("stored in `{name}`"));
                // Its fields are no longer the ones written in the code.
                env.fields.remove(name);
                env.forget(name);
                let merged = union(env.vars.get(name).cloned(), Some(value));
                if let Some(merged) = merged {
                    env.vars.insert(name.to_owned(), merged);
                }
            }
            Expression::StaticMemberExpression(member) => {
                let field = member.property.name.as_str().to_owned();
                match member.object.get_inner_expression() {
                    Expression::ThisExpression(_) => {
                        let Some(class) = self.current_class.clone() else {
                            return;
                        };
                        let value = value.step(at, format!("stored in `this.{field}`"));
                        let fields = self.class_fields.entry(class).or_default();
                        let merged = union(fields.get(&field).cloned(), Some(value));
                        if let Some(merged) = merged {
                            fields.insert(field, merged);
                        }
                    }
                    Expression::Identifier(root) if env.fields.contains_key(root.name.as_str()) => {
                        let root = root.name.as_str().to_owned();
                        env.forget(&format!("{root}.{field}"));
                        if let Some(fields) = env.fields.get_mut(&root) {
                            let merged = union(fields.get(&field).cloned(), Some(value));
                            if let Some(merged) = merged {
                                fields.insert(field, merged);
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    pub(super) fn assign_target(
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
                // `file = other`: no longer built from what it was.
                env.derived.remove(id.name.as_str());
                env.same_file.remove(id.name.as_str());
                env.joined.remove(id.name.as_str());
                env.relative_of.remove(id.name.as_str());
            }
            // `({ file } = req.body)`, `[a, b] = list`: each name gets the value (as a whole), and
            // what it was built from or checked against before is gone.
            AssignmentTarget::ObjectAssignmentTarget(_)
            | AssignmentTarget::ArrayAssignmentTarget(_) => {
                let mut names = Vec::new();
                assignment_target_names(target, &mut names);
                for name in names {
                    let taint = taint
                        .clone()
                        .map(|o| o.step(target.span().start, format!("assigned to `{name}`")));
                    env.fields.remove(&name);
                    env.bind(&name, taint);
                    env.derived.remove(&name);
                    env.same_file.remove(&name);
                    env.joined.remove(&name);
                    env.relative_of.remove(&name);
                }
            }
            other => {
                if let Some(member) = other
                    .as_simple_assignment_target()
                    .and_then(SimpleAssignmentTarget::as_member_expression)
                {
                    // `job.name = req.body.name`: what a guard said about `job.name` is gone.
                    // `properties["post-type"] = type` (server data, on every path): that field
                    // of the object is clean now, whatever the rest of it holds.
                    if let Some(key) = guards::member_key(member) {
                        env.forget(&key);
                        if taint.is_none()
                            && env.branch == 0
                            && let Some((root, _)) = key.split_once('.')
                            && env.vars.contains_key(root)
                            && !env.requests.contains_key(root)
                        {
                            env.clean.insert(key);
                        }
                    }
                    // `target[key][key2] = value` with attacker-chosen keys.
                    if let oxc_ast::ast::MemberExpression::ComputedMemberExpression(outer) = member
                        && let Expression::ComputedMemberExpression(inner) =
                            outer.object.get_inner_expression()
                    {
                        let mut probe = env.clone();
                        let outer_key = self.expr(&outer.expression, &mut probe);
                        let inner_key = self.expr(&inner.expression, &mut probe);
                        // In a helper, a second key that is only a parameter pollutes only when the
                        // caller's argument for it is the attacker's too (`store(key, 'fix', v)`
                        // writes a constant second key).
                        let with_param = outer_key
                            .as_ref()
                            .filter(|o| self.summarize && o.also.is_empty())
                            .and_then(|o| o.param);
                        if let (Some(origin), Some(_)) = (inner_key, outer_key)
                            && origin.param.is_none() == !self.summarize
                        {
                            self.emit_with_param = with_param;
                            self.emit(
                                RawFinding {
                                    class: VulnClass::PrototypePollution,
                                    severity: Severity::High,
                                    api: "obj[key][key] =".to_owned(),
                                    arg: outer.span,
                                    call: outer.span,
                                    function: env.owner.clone(),
                                    origin,
                                    ext: None,
                                    auth: Auth::NoneDetected,
                                    start: false,
                                },
                                env,
                            );
                            self.emit_with_param = None;
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
                                function: env.owner.clone(),
                                origin: origin.clone(),
                                ext: None,
                                auth: Auth::NoneDetected,
                                start: false,
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
                    // `properties["post-type"] = type` on an object we do not track field by
                    // field: track it from here, the rest of it as it was.
                    let mut newly_tracked = false;
                    if env.branch == 0
                        && let (Expression::Identifier(root), Some(_)) = (
                            member.object().get_inner_expression(),
                            member.static_property_name(),
                        )
                        && !env.fields.contains_key(root.name.as_str())
                        && !env.requests.contains_key(root.name.as_str())
                        && let Some(whole) = env.vars.get(root.name.as_str()).cloned()
                    {
                        env.fields.insert(
                            root.name.as_str().to_owned(),
                            BTreeMap::from([(REST_FIELD.to_owned(), whole)]),
                        );
                        newly_tracked = true;
                    }
                    // `settings.map = fromUrl` on a clean object we do not track: track it from
                    // here, its other fields as clean as it was (`settings.wpnMode` is not
                    // `fromUrl`); the object as a whole carries what is written to it.
                    if let (Some(origin), Expression::Identifier(root), Some(_)) = (
                        &taint,
                        member.object().get_inner_expression(),
                        member.static_property_name(),
                    ) && !env.fields.contains_key(root.name.as_str())
                        && !env.requests.contains_key(root.name.as_str())
                        && !env.vars.contains_key(root.name.as_str())
                    {
                        let name = root.name.as_str().to_owned();
                        env.fields.insert(name.clone(), BTreeMap::new());
                        env.vars.insert(
                            name,
                            origin.clone().step(
                                member.span().start,
                                format!("stored in a field of `{}`", root.name),
                            ),
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
                        let strong = env.branch == 0;
                        env.forget(&format!("{}.{property}", root.name.as_str()));
                        // An object with parts we do not know (tracked from a write on, or with
                        // spreads) still carries what is written to it, as a whole
                        // (`object.extra = additions; return object`).
                        if let Some(origin) = &taint
                            && (newly_tracked
                                || env
                                    .fields
                                    .get(root.name.as_str())
                                    .is_some_and(|f| f.contains_key(REST_FIELD)))
                        {
                            let origin = origin.clone().step(
                                member.span().start,
                                format!("stored in a field of `{}`", root.name),
                            );
                            if let Some(existing) = env.vars.get_mut(root.name.as_str()) {
                                join(existing, &origin);
                            }
                        }
                        let clean = format!("{}.{property}", root.name.as_str());
                        let cleared = taint.is_none() && strong;
                        if let Some(fields) = env.fields.get_mut(root.name.as_str()) {
                            match taint {
                                Some(origin) => {
                                    fields.insert(property, origin);
                                }
                                None if strong => {
                                    fields.remove(&property);
                                }
                                None => {}
                            }
                        }
                        // A clean value written on every path: the field is clean, not what the
                        // rest of the object may hold.
                        if cleared {
                            env.clean.insert(clean);
                        }
                        return;
                    }
                    // `fields[key] = value` on a tracked object: an unnamed field; the key, if the
                    // attacker chose it, a key of the object.
                    if let oxc_ast::ast::MemberExpression::ComputedMemberExpression(c) = member
                        && let Expression::Identifier(root) = c.object.get_inner_expression()
                        && env.fields.contains_key(root.name.as_str())
                        && guards::member_key(member).is_none()
                    {
                        let mut probe = env.clone();
                        let key = self.expr(&c.expression, &mut probe);
                        let root = root.name.as_str().to_owned();
                        if let Some(fields) = env.fields.get_mut(&root) {
                            if let Some(key) = key {
                                let merged = union(fields.remove(KEYED_FIELD), Some(key));
                                if let Some(merged) = merged {
                                    fields.insert(KEYED_FIELD.to_owned(), merged);
                                }
                            }
                            if let Some(value) = taint {
                                let merged = union(fields.remove(VALUES_FIELD), Some(value));
                                if let Some(merged) = merged {
                                    fields.insert(VALUES_FIELD.to_owned(), merged);
                                }
                            }
                        }
                        return;
                    }
                    // `obj.x = tainted` taints `obj` (coarse: other objects' fields are not tracked).
                    // A weak update: an `obj` that already carried data keeps its own origin
                    // (`properties.x = fromConfig` leaves `properties` the caller's argument).
                    if let (Some(origin), Expression::Identifier(root)) =
                        (taint, member.object().get_inner_expression())
                    {
                        let origin = origin.step(
                            member.span().start,
                            format!("stored in a field of `{}`", root.name),
                        );
                        let merged = match env.vars.get(root.name.as_str()) {
                            Some(existing) => {
                                let mut merged = existing.clone();
                                join(&mut merged, &origin);
                                merged
                            }
                            None => origin,
                        };
                        env.vars.insert(root.name.as_str().to_owned(), merged);
                    }
                }
            }
        }
    }

    pub(super) fn member(&mut self, expr: &Expression<'_>, env: &mut Env) -> Option<Origin> {
        let member = expr.as_member_expression()?;
        self.member_of(member, env)
    }

    pub(super) fn member_of(
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
        let escaped = prefixes()
            .filter_map(|p| env.partial.get(p))
            .fold(0, |classes, c| classes | c);
        self.member_of_inner(member, env).map(|mut o| {
            if scalar {
                o.object = false;
            }
            o.escaped |= escaped;
            o
        })
    }

    pub(super) fn member_of_inner(
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
                htmlish: false,
                escaped: 0,
                param: None,
                object: property.as_deref().is_some_and(|p| {
                    has(&m().object_props, p) && !has(self.linking.scalar_props, p)
                }),
                also: Vec::new(),
                upload: property
                    .as_deref()
                    .is_some_and(|p| has(&m().upload_objects, p)),
                dash_free: false,
                response: false,
                primary_escaped: 0,
            });
        }
        // `user.name` of a record loaded from a store, where a request stored that field.
        if let (Expression::Identifier(id), Some(field)) = (object, property.as_deref())
            && !self.summarize
            && env.records.contains(id.name.as_str())
            && let Some(write) = self.linking.stored.get(field)
        {
            let at = member.span();
            let mut origin = Origin::source(STORED, at);
            // A value the write site already proved scalar (`check(x, String)`, a validator) can
            // never carry an operator object here either; only a write whose value could still be
            // an object keeps that possibility open on the read side.
            origin.object = write.object;
            return Some(origin.step(
                at.start,
                format!(
                    "stored by {}:{} from `{}`, read back from the store",
                    write.file, write.line, write.expr
                ),
            ));
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
            let mut origin = Origin::source(source.kind.as_str(), member.span());
            origin.prefix = !source.fixed_start;
            return Some(origin);
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
        // A field of an object literal we tracked: only that field's taint, or what its unknown
        // spreads may hold (read below as a field of that value).
        let mut rest = None;
        if let (Expression::Identifier(id), Some(property)) = (object, property.as_deref())
            && let Some(fields) = env.fields.get(id.name.as_str())
        {
            match (fields.get(property), unnamed_fields(fields)) {
                (Some(origin), _) => return Some(origin.clone()),
                (None, None) => return None,
                (None, Some(origin)) => rest = Some(origin),
            }
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
        let whole = match rest {
            Some(rest) => Some(rest),
            None => self.expr(member.object(), env),
        };
        // `r.success` of a validation result: a boolean, no input.
        if property
            .as_deref()
            .is_some_and(|p| has(&m().validation_clean_fields, p))
            && whole.as_ref().is_some_and(|o| {
                o.steps
                    .last()
                    .is_some_and(|(_, note)| note.starts_with("validated by"))
            })
        {
            return None;
        }
        // `file.path` of an upload that went through a helper, an array or a callback.
        if whole.as_ref().is_some_and(|o| o.upload)
            && property
                .as_deref()
                .is_some_and(|p| has(&m().upload_server_fields, p))
        {
            return None;
        }
        if self.summarize
            && let (Expression::Identifier(_), Some(property)) = (object, property.as_deref())
            && let Some(origin) = &whole
            && origin.param.is_some()
            && !self.field_of.contains_key(&origin.span.start)
        {
            // Every read of the same field of the same parameter is one contributor (the first
            // read's position), so a value built from many reads of one field still has room
            // for the other fields it carries.
            let start = *self
                .field_reads
                .entry((origin.span.start, property.to_owned()))
                .or_insert(member.span().start);
            let mut field = origin.clone();
            field.span = if start == member.span().start {
                member.span()
            } else {
                Span::new(start, start)
            };
            self.field_of.insert(start, property.to_owned());
            if let Some(class) = self.ctor_params.get(&origin.span.start).cloned() {
                self.ctor_params.insert(start, class);
            }
            if let Some(owner) = self.param_owner.get(&origin.span.start).cloned() {
                self.param_owner.insert(start, owner);
            }
            if self.rest_params.contains(&origin.span.start) {
                self.rest_params.insert(start);
            }
            return Some(field);
        }
        whole
    }

    /// `!req.user`, `!req.session.userId`, `!req.isAuthenticated()`, `!isAdmin(req)`, or `!user`
    /// after `const user = verifyToken(token)`: a test that is true when the caller is not
    /// logged in (or not an admin). The level it establishes once it failed.
    pub(super) fn requires_login(&self, test: &Expression<'_>, env: &Env) -> Option<Auth> {
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
    pub(super) fn request_kind(&self, expr: &Expression<'_>, env: &Env) -> Option<&'static str> {
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

    pub(super) fn argument(
        &mut self,
        argument: &Argument<'_>,
        env: &mut Env,
        role: Role,
    ) -> Option<Origin> {
        match argument {
            Argument::SpreadElement(spread) => self.expr(&spread.argument, env),
            other => {
                let expr = other.as_expression()?;
                if self.maybe_function(expr, env, None, role) {
                    // `list.forEach((x) => { total += x; })`: the callback's writes.
                    self.apply_closure_writes(env);
                    None
                } else {
                    self.expr(expr, env)
                }
            }
        }
    }

    pub(super) fn callee(&self, callee: &Expression<'_>) -> Callee {
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
                                if matches!(field.object, Expression::ThisExpression(_))
                                    && self
                                        .this_field_class(field.property.name.as_str())
                                        .is_some() =>
                            {
                                self.this_field_class(field.property.name.as_str())
                            }
                            // `FastifyWorker.fastify.all('/x', h)`, `this.app.get(..)` on a router
                            // held in a field, or a framework router read off a host object
                            // (`RED.httpAdmin.post(...)`): keep the member path when it names a
                            // router so the registration is attributed to it.
                            // `res.status(404).send(...)`: named after the response the chain of
                            // receiver-returning calls starts from.
                            Expression::CallExpression(_) => match receiver_of_chain(object) {
                                Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
                                _ => None,
                            },
                            other => member_path(other)
                                .filter(|path| self.routers.contains(path) || self.is_router(path)),
                        };
                        // `Buffer.from`, `JSON.parse`, `Object.keys`, `Object.assign` as globals.
                        if let Some(object) = &object_name {
                            let qualified = format!("{object}.{method}");
                            let model = m();
                            if has(&model.pass_globals, &qualified)
                                || has(&model.key_globals, &qualified)
                                || has(&model.store_globals, &qualified)
                            {
                                return Callee::Global(qualified);
                            }
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
}
