use super::Method;

#[test]
fn in_handler_session_cookie_gate_is_detected_as_an_auth_precondition() {
    // A handler that reaches its sink only inside a branch guarded by a session it looks up from a
    // request cookie it reads itself is an authenticated-user sink: the cookie name must be mined
    // so the verifier can carry a minted token back under it. The sink is on line 4.
    let handler = "function h(req, res) {\n\
             const url = req.body.imageUrl\n\
             const loggedInUser = sessions.get(req.cookies.token)\n\
             if (loggedInUser) { fetch(url) }\n\
           }";
    assert_eq!(
        super::session_cookie_gate(handler, 4).as_deref(),
        Some("token")
    );
    // No in-handler session guard: an ordinary unauthenticated handler is left untouched so the
    // verifier drives it anonymously, never fabricating an auth step it does not need.
    let anon = "function h(req, res) {\n\
             const url = req.body.imageUrl\n\
             fetch(url)\n\
           }";
    assert_eq!(super::session_cookie_gate(anon, 3), None);
    // A cookie read that does not gate the sink (no branch on the bound local before it) is not an
    // auth precondition either.
    let ungated = "function h(req, res) {\n\
             const t = req.cookies.token\n\
             fetch(req.body.url)\n\
           }";
    assert_eq!(super::session_cookie_gate(ungated, 3), None);
}

#[test]
fn auth_endpoints_rank_exact_login_first_and_skip_parameterized() {
    // Route registrations carrying a mix of auth-vocabulary paths: the exact-segment login
    // (`/rest/user/login`) must lead the loose lookalikes (`/rest/passkey/login-options`,
    // `/rest/saveLoginIp`) so the real session login is reached before a weaker token endpoint can
    // short-circuit the bootstrap, a user/account collection is mined for registration, and a
    // parameterized path is dropped (it cannot be driven with a real value).
    let source = "app.post('/rest/passkey/login-options', a)\n\
             app.post('/rest/saveLoginIp', b)\n\
             app.get('/api/Users', c)\n\
             app.route('/api/Users/:id')\n\
             app.post('/rest/user/login', login())\n\
             app.post('/api/Products', d)";
    let (login, register) = super::auth_endpoints(source);
    assert_eq!(login.first().map(String::as_str), Some("/rest/user/login"));
    assert!(login.contains(&"/rest/passkey/login-options".to_owned()));
    assert!(login.contains(&"/rest/saveLoginIp".to_owned()));
    assert_eq!(register, vec!["/api/Users".to_owned()]);
    assert!(!login.iter().any(|p| p.contains(":id")));
    assert!(!register.iter().any(|p| p.contains(":id")));
}

#[test]
fn sibling_value_satisfies_a_startswith_prefix_guard() {
    // The sink runs only when a required sibling begins with a fixed prefix, checked on a renamed,
    // trimmed local. The generated filler must lead with that prefix so the guarded branch runs.
    let handler = "export async function POST(request) {\n\
             const { apiKey, baseUrl } = await request.json();\n\
             const key = typeof apiKey === \"string\" ? apiKey.trim() : \"\";\n\
             if (key && !key.startsWith(\"sk-\")) return bad();\n\
             if (key) { fetch(`${baseUrl}/models`); }\n\
           }";
    let siblings = super::required_siblings(handler, "body", "baseUrl");
    let api_key = siblings
        .iter()
        .find(|(name, _)| name == "apiKey")
        .map(|(_, value)| value.as_str());
    assert!(
        api_key.is_some_and(|value| value.starts_with("sk-")),
        "apiKey filler should satisfy startsWith(\"sk-\"), got {api_key:?}"
    );
}

#[test]
fn matcher_entry_covers_catch_all_and_prefix_forms() {
    // A negative-lookahead catch-all covers an API route but not the excluded static assets.
    let catch_all = "/((?!_next/static|_next/image|favicon\\.ico).*)";
    assert!(super::matcher_entry_covers(
        catch_all,
        "/api/oauth/x/api-key"
    ));
    assert!(!super::matcher_entry_covers(
        catch_all,
        "/_next/static/app.js"
    ));
    // A path-prefix matcher covers its subtree only.
    assert!(super::matcher_entry_covers("/api/:path*", "/api/oauth/x"));
    assert!(!super::matcher_entry_covers(
        "/dashboard/:path*",
        "/api/oauth/x"
    ));
    // A bare catch-all covers everything.
    assert!(super::matcher_entry_covers("/:path*", "/api/anything"));
}

#[test]
fn source_enforces_auth_requires_both_a_denial_and_a_check() {
    assert!(super::source_enforces_auth(
        "if (!isAuthenticated(req)) return json({error:'Unauthorized'},{status:401})"
    ));
    assert!(super::source_enforces_auth(
        "if (settings.requireLogin) return new Response('Unauthorized', {status: 401})"
    ));
    // A denial without any auth check, or a check without a denial, is not an auth gate.
    assert!(!super::source_enforces_auth(
        "return json({error:'Bad input'},{status:400})"
    ));
    assert!(!super::source_enforces_auth("const user = getToken(req)"));
}

#[test]
fn app_router_login_path_derives_url_and_skips_dynamic_segments() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let write = |rel: &str, body: &str| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    };
    // A conventional Next.js App Router login route, under a route group that drops from the URL.
    write(
        "src/app/(auth)/api/auth/login/route.js",
        "export async function POST(){}",
    );
    // A non-login route is ignored; a dynamic segment yields no concrete URL.
    write(
        "src/app/api/models/route.js",
        "export async function GET(){}",
    );
    write(
        "src/app/api/session/[id]/route.js",
        "export async function GET(){}",
    );
    let logins = super::next_app_router_login_paths(root);
    assert_eq!(logins, vec!["/api/auth/login".to_owned()]);
}

#[test]
fn framework_auth_login_paths_needs_a_covering_auth_middleware() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let write = |rel: &str, body: &str| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    };
    write(
        "src/app/api/auth/login/route.js",
        "export async function POST(){}",
    );
    // No middleware yet: a route behind no gate needs no bootstrap.
    assert!(super::framework_auth_login_paths(root, "/api/oauth/x/api-key").is_none());
    // A Next.js middleware that denies the route unless authenticated: the login route is offered.
    write(
        "src/proxy.js",
        "export default async function proxy(request){\n\
               if (!(await isAuthenticated(request))) return json({error:'Unauthorized'},{status:401});\n\
             }\n\
             export const config = { matcher: ['/((?!_next/static|favicon\\\\.ico).*)'] };",
    );
    assert_eq!(
        super::framework_auth_login_paths(root, "/api/oauth/x/api-key"),
        Some(vec!["/api/auth/login".to_owned()])
    );
    // A path the matcher excludes is not treated as gated.
    assert!(super::framework_auth_login_paths(root, "/_next/static/app.js").is_none());
}

#[test]
fn parse_entry_treats_express_all_as_any_method() {
    // `app.all('/files', ...)` registers one handler for every HTTP method; the engine uppercases
    // the `all` verb to `ALL`, which the planner must drive like `Any` (a routable HTTP path),
    // not reject as unroutable.
    let (method, path) = super::parse_entry("ALL /files").expect("ALL route is routable");
    assert_eq!(method, Method::Any);
    assert_eq!(path, "/files");
    // The existing catch-all spelling still parses.
    assert_eq!(
        super::parse_entry("ANY /x").map(|(m, _)| m),
        Some(Method::Any)
    );
    // A non-method verb (an event kind) is still not a routable HTTP path.
    assert!(super::parse_entry("SOCKET /x").is_none());
}

#[test]
fn body_field_reaches_sink_as_element_detects_per_element_query() {
    // `for (const d of device_names) ... findOne({ name: d })`: the body field is iterated and
    // each element is queried, so the operator must ride inside an array.
    let src = "const { device_names } = request.body;\n\
            for (const deviceName of device_names) {\n\
              const device = await DeviceModel(tenant).findOne({ name: deviceName });\n\
            }\n";
    assert!(super::body_field_reaches_sink_as_element(
        src,
        "device_names",
        "{ name: deviceName }"
    ));
    // `.forEach` with the element in the sink argument is the same shape.
    let fe = "ids.forEach((id) => Model.findOne({ _id: id }));\n";
    assert!(super::body_field_reaches_sink_as_element(
        fe,
        "ids",
        "{ _id: id }"
    ));
    // The field reaching the sink directly (not via an element) is not array-wrapped.
    let direct = "const { id } = request.body;\nModel.findOne({ _id: id });\n";
    assert!(!super::body_field_reaches_sink_as_element(
        direct,
        "id",
        "{ _id: id }"
    ));
    // A loop over a different field does not trigger wrapping of this field.
    assert!(!super::body_field_reaches_sink_as_element(
        src,
        "site_ids",
        "{ name: deviceName }"
    ));
}

#[test]
fn validator_middleware_resolves_multiline_destructured_requires() {
    let src = "const express = require(\"express\");\n\
const {\n  headers, pagination, validate } = require(\"@validators/common\");\n\
const {\n  validateTenant,\n  validateCreateShippingBatch,\n  validate2,\n} = require(\"@validators/device.validators\");\n";
    assert_eq!(
        super::require_source_path(src, "validate"),
        Some("@validators/common".to_owned())
    );
    assert_eq!(
        super::require_source_path(src, "validateCreateShippingBatch"),
        Some("@validators/device.validators".to_owned())
    );
    let arr = "const validateCreateShippingBatch = [\n  body(\"device_names\").exists().bail().isArray({min:1}).custom(x=>true),\n  body(\"token_type\").optional().isIn([\"hex\",\"readable\"]),\n  body(\"batch_name\").exists().notEmpty(),\n];\n";
    assert!(super::defines_const_array(
        arr,
        "validateCreateShippingBatch"
    ));
    let got = super::validator_required_body_fields(
        "router.post(\n  \"/x\",\n  validateCreateShippingBatch,\n  validate,\n  c.h\n);\n",
        1,
        "batch_name",
        &|name| {
            if name == "validateCreateShippingBatch" {
                Some(arr.to_owned())
            } else {
                None
            }
        },
    );
    assert_eq!(
        got,
        vec![("device_names".to_owned(), "[\"jsspector\"]".to_owned())]
    );
}

#[test]
fn validator_middleware_reports_optional_body_fields_with_their_own_chain_window() {
    let route = "router.post(\"/refresh\", validators.refresh, validate, controller.run);\n";
    let module = "const common = {\n  tenant: [body(\"tenant\").exists().notEmpty()],\n  unrelated: [body(\"noise\").exists(), body(\"wrong_shape\").optional().isArray()],\n};\nconst refresh = [\n  ...common.tenant,\n  body(\"device_names\").optional().isArray(),\n  body(\"site_ids\").optional().isArray(),\n  body(\"refresh_all\").optional().isBoolean(),\n];\n";
    let optional = super::validator_optional_body_fields(route, 1, &|name| {
        (name == "validators").then(|| module.to_owned())
    });
    assert_eq!(
        optional,
        vec![
            "device_names".to_owned(),
            "site_ids".to_owned(),
            "refresh_all".to_owned(),
        ]
    );
    let required = super::validator_required_body_fields(route, 1, "device_names", &|name| {
        (name == "validators").then(|| module.to_owned())
    });
    assert_eq!(
        required,
        vec![("tenant".to_owned(), "jsspector".to_owned())]
    );
}

#[test]
fn member_expression_validator_supplies_a_oneof_sibling_for_a_body_payload() {
    // The middleware is a member expression (`userValidations.syncAnalyticsAndMobile`), not a
    // bare identifier, and the payload field (`email`) is one branch of a `oneOf`. The other
    // branch's field (`firebase_uid`) must be carried as a sibling so the group is satisfied
    // without the payload field needing to be a valid scalar — letting the operator object reach
    // the sink.
    let route = "router.post(\n  \"/syncAnalyticsAndMobile\",\n  userValidations.syncAnalyticsAndMobile,\n  controller.sync\n);\n";
    let module = "const syncAnalyticsAndMobile = [\n  oneOf([\n    body(\"firebase_uid\").exists().notEmpty().trim(),\n    body(\"email\").exists().notEmpty().isEmail(),\n  ]),\n  body(\"phoneNumber\").optional().isMobilePhone(),\n];\nmodule.exports = { syncAnalyticsAndMobile };\n";
    let got = super::validator_required_body_fields(route, 1, "email", &|name| {
        (name == "userValidations").then(|| module.to_owned())
    });
    assert_eq!(
        got,
        vec![("firebase_uid".to_owned(), "jsspector".to_owned())]
    );
}

#[test]
fn a_later_query_spread_can_override_a_validated_body_field() {
    let handler = r#"
          async function unsubscribe(request) {
            const { email, tenant } = {
              ...request.body,
              ...request.query,
              ...request.params,
            };
            return Users.findOneAndUpdate({ email }, { tenant });
          }
        "#;
    assert!(super::query_overrides_body_field(handler, "email"));
    assert!(!super::query_overrides_body_field(handler, "missing"));
    let safe_order = handler
        .replace("...request.body,", "...request.query,")
        .replace(
            "...request.query,\n              ...request.params",
            "...request.body,\n              ...request.params",
        );
    assert!(!super::query_overrides_body_field(&safe_order, "email"));

    let route =
        "router.post('/unsubscribe/:type', validators.validateUnsubscribe, controller.run);";
    let validators = r#"
          const validateUnsubscribe = [
            oneOf([
              body("email").exists().isEmail(),
              body("user_id").exists().isMongoId(),
            ]),
          ];
        "#;
    assert_eq!(
        super::validator_body_field_filler(route, 1, "email", &|name| {
            (name == "validators").then(|| validators.to_owned())
        }),
        Some("jss@jsspector.test".to_owned())
    );
}

#[test]
fn namespace_validator_supplies_a_typed_non_payload_path_slot() {
    let route = "router.get(\n  \"/:email/health-score\",\n  analyticsValidations.healthScoreValidators.getHealthScore,\n  controller.getEngagementHealth\n);\n";
    let validator = "const validateUserEmail = param(\"email\").isEmail();\n\
const healthScoreValidators = {\n  getHealthScore: [validateUserEmail, query(\"includeFactors\").optional().isBoolean()]\n};\n\
module.exports = { healthScoreValidators };\n";
    let got = super::validator_path_fillers(
        route,
        1,
        "/api/v2/users/analytics/{email}/health-score",
        None,
        &|name| (name == "analyticsValidations").then(|| validator.to_owned()),
    );
    assert_eq!(
        got,
        vec![("email".to_owned(), "jss@jsspector.test".to_owned())]
    );
    assert!(
        super::validator_path_fillers(
            route,
            1,
            "/api/v2/users/analytics/{email}/health-score",
            Some("email"),
            &|name| (name == "analyticsValidations").then(|| validator.to_owned()),
        )
        .is_empty()
    );
}

#[test]
fn a_field_only_named_inside_a_conditional_is_not_mined_as_required() {
    // `timeframe` is optional in its own chain and otherwise appears only as the condition of
    // another field's `.if(query("timeframe").equals("custom"))`. Neither occurrence makes it an
    // unconditionally required query parameter, so mining must not emit a (junk) filler for it —
    // doing so would send `timeframe=jsspector`, fail the `.isIn([...])` validator, and mask the
    // injection behind an identical validation error for every payload.
    let route = "router.get(\n  \"/:email/activity-report\",\n  analyticsValidations.activityValidators.getReport,\n  controller.getActivityReport\n);\n";
    let validator = "const validateTenant = query(\"tenant\").optional().notEmpty();\n\
const validateTimeframe = query(\"timeframe\").optional().isIn([\"last7days\", \"custom\"]).withMessage(\"Invalid timeframe\");\n\
const validateDateRange = [\n  query(\"startDate\").if(query(\"timeframe\").equals(\"custom\")).isISO8601(),\n  query(\"endDate\").if(query(\"timeframe\").equals(\"custom\")).isISO8601(),\n];\n\
const validateUserEmail = param(\"email\").isEmail();\n\
const activityValidators = {\n  getReport: [validateUserEmail, validateTenant, validateTimeframe, ...validateDateRange],\n};\n\
module.exports = { activityValidators };\n";
    let mined = super::validator_query_fillers(route, 1, "email", &|name| {
        (name == "analyticsValidations").then(|| validator.to_owned())
    });
    assert!(
        mined.is_empty(),
        "no query field is unconditionally required here, got {mined:?}"
    );
    let optional = super::validator_optional_query_fields(route, 1, &|name| {
        (name == "analyticsValidations").then(|| validator.to_owned())
    });
    assert_eq!(
        optional,
        vec![
            "tenant".to_owned(),
            "timeframe".to_owned(),
            "startDate".to_owned(),
            "endDate".to_owned(),
        ]
    );

    let parenthesized = "const validators = [(query(\"tenant\").notEmpty())];";
    let chains = super::chain_starts(parenthesized);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].1.as_deref(), Some("tenant"));
    assert_eq!(chains[0].2, "query");
}

#[test]
fn removal_sinks_are_recognized_by_their_api_name() {
    use super::sink_removes;
    assert!(sink_removes("fs.unlinkSync"));
    assert!(sink_removes("fs.unlink"));
    assert!(sink_removes("fs.promises.unlink"));
    assert!(sink_removes("fs.rmSync"));
    assert!(sink_removes("fs.rmdir"));
    assert!(sink_removes("rimraf"));
    // A read or write sink is not a removal, and a method whose name merely contains `rm` is not
    // mistaken for one.
    assert!(!sink_removes("fs.readFileSync"));
    assert!(!sink_removes("fs.writeFileSync"));
    assert!(!sink_removes("db.confirmSync"));
}

#[test]
fn create_sinks_are_recognized_by_their_api_name() {
    use super::sink_creates;
    assert!(sink_creates("fs.mkdirSync"));
    assert!(sink_creates("fs.mkdir"));
    assert!(sink_creates("fs.promises.mkdir"));
    assert!(sink_creates("fs.writeFileSync"));
    assert!(sink_creates("fs.appendFile"));
    assert!(sink_creates("fs.createWriteStream"));
    assert!(sink_creates("myFile.mv"));
    // A read or removal sink is not a create, and an unrelated method is not mistaken for one.
    assert!(!sink_creates("fs.readFileSync"));
    assert!(!sink_creates("fs.unlinkSync"));
    assert!(!sink_creates("fs.readdirSync"));
}

#[test]
fn a_copy_that_reads_an_enumerated_tainted_dir_is_a_listing_read_not_a_create() {
    // `var tempFiles = fs.readdirSync('./public/temp/' + tempId)` then
    // `fs.copyFileSync('./public/temp/' + tempId + '/' + tempFiles[i], folder + '/' + tempFiles[i])`:
    // the tainted `tempId` names the directory the copy reads *out of* (its enumerated children are
    // copied into a confined base), so the traversal is a directory-enumerating read, not a create.
    use super::copy_reads_enumerated_dir;
    let src = "app.post('/save', function(req, res) {\n\
            var tempId = req.body.tempId\n\
            var tempFiles = fs.readdirSync('./public/temp/' + tempId)\n\
            for (var i=0;i<tempFiles.length;i++) {\n\
                fs.copyFileSync('./public/temp/' + tempId + '/' + tempFiles[i], folder + '/' + tempFiles[i])\n\
            }\n\
        })\n";
    let tainted = vec!["tempId".to_owned()];
    assert!(copy_reads_enumerated_dir(
        "fs.copyFileSync",
        "'./public/temp/' + tempId + '/' + tempFiles[i]",
        src,
        &tainted,
    ));
    // A copy whose source is the tainted value itself (not an enumerated child) is a direct read,
    // handled by the ordinary read oracle, not this directory-enumeration case.
    assert!(!copy_reads_enumerated_dir(
        "fs.copyFileSync",
        "'./base/' + tempId",
        src,
        &tainted,
    ));
    // A create sink (no copy) never qualifies as a copy-read.
    assert!(!copy_reads_enumerated_dir(
        "fs.writeFileSync",
        "'./public/temp/' + tempId + '/' + tempFiles[i]",
        src,
        &tainted,
    ));
}

#[test]
fn copy_sinks_are_recognized_by_their_api_name() {
    use super::sink_copies;
    assert!(sink_copies("fs.copyFileSync"));
    assert!(sink_copies("fs.copyFile"));
    assert!(sink_copies("fs.promises.copyFile"));
    assert!(sink_copies("fse.copy"));
    // A read, write, or removal sink is not a copy.
    assert!(!sink_copies("fs.readFileSync"));
    assert!(!sink_copies("fs.writeFileSync"));
    assert!(!sink_copies("fs.unlinkSync"));
}

#[test]
fn url_substring_query_gate_is_mined_from_a_raw_url_dispatch() {
    // A handler that binds the request URL to a local and reaches the sink only when the URL
    // carries a `key=value` fragment (`if (url.indexOf("action=createdir") != -1) fs.mkdirSync`)
    // must be driven with that query pair, or the branch the sink sits on is never taken.
    let src = "app.all(\"/sdfiles\", function (req, res) {\n\
            let url = req.originalUrl\n\
            if (url.indexOf(\"action=createdir\") != -1) {\n\
                fs.mkdirSync(filepath)\n\
            }\n\
        })\n";
    let gates = super::url_substring_query_gates(src, &[4]);
    assert_eq!(gates, vec![("action".to_owned(), "createdir".to_owned())]);
    // A receiver that is not derived from the request URL is not treated as a URL dispatch.
    let unrelated = "if (name.indexOf(\"action=createdir\") != -1) {\n\
            fs.mkdirSync(p)\n\
        }\n";
    assert!(super::url_substring_query_gates(unrelated, &[2]).is_empty());
    // A substring guard that does not enclose any anchor is ignored.
    assert!(super::url_substring_query_gates(src, &[1]).is_empty());
}

#[test]
fn nested_write_prototype_pollution_resolves_both_keys() {
    // `obj[req.params.bid][key]` with `const key = req.params.id`: the outer key is driven with
    // `__proto__`, the inner (resolved through the local binding) with the marker property.
    let mut f = finding(
        VulnClass::PrototypePollution,
        Auth::NoneDetected,
        Some("USE /request-bank/{bid}/withdraw/{id}"),
        "req.params",
    );
    f.sink.arg = "bank[req.params.bid][key]".to_owned();
    let source = "app.use('/request-bank/:bid/withdraw/:id/', (req, res) => {\n\
            const key = req.params.id;\n\
            bank[req.params.bid][key] = callback;\n\
        });";
    let probe = match plan_with_source(&f, Some(source)) {
        Ok(Plan::Http(probe)) => probe,
        other => panic!("expected an HTTP probe, got {other:?}"),
    };
    let pp = probe
        .proto_pollution
        .expect("prototype-pollution probe carries a read-back descriptor");
    assert_eq!(pp.outer, Entry::PathParam("bid".to_owned()));
    assert_eq!(pp.inner, Entry::PathParam("id".to_owned()));
}

#[test]
fn nested_index_exprs_reads_the_two_keys() {
    assert_eq!(
        super::nested_index_exprs("bank[req.params.bid][key]"),
        Some(("req.params.bid".to_owned(), "key".to_owned()))
    );
    // A single index is not a nested write.
    assert_eq!(super::nested_index_exprs("bank[req.params.bid]"), None);
}

#[test]
fn convention_based_http_entries_are_conservative() {
    let mut body = finding(
        VulnClass::NosqlInjection,
        Auth::NoneDetected,
        None,
        "request.body",
    );
    body.file = "app/controllers/api/user.js".to_owned();
    assert_eq!(derive_http_entry(&body).as_deref(), Some("POST /api/user"));
    body.entry = derive_http_entry(&body);
    let probe = Probe::from_finding(&body).unwrap();
    assert_eq!(probe.class, VulnClass::NosqlInjection);
    assert_eq!(probe.path, "/api/user");

    let mut query = finding(
        VulnClass::NosqlInjection,
        Auth::NoneDetected,
        None,
        "req.query.id",
    );
    query.file = "src/routes/users/index.js".to_owned();
    assert_eq!(derive_http_entry(&query).as_deref(), Some("GET /users"));
    query.file = "lib/helpers/db.js".to_owned();
    assert_eq!(derive_http_entry(&query), None);
}

#[test]
fn a_registered_route_and_its_url_search_params_are_mined() {
    // A plug-in that mounts a prefix handler on a host web-server service and dispatches
    // sub-paths itself, choosing the outbound host from a query parameter of the parsed URL.
    let source = r#"
          ctx.inject(['webServer'], (ctx) => {
            const webServer = ctx.webServer;
            ctx.effect(() => webServer.register({
              kind: 'prefix',
              path: '/dsh-wallpaper-bg',
              handler: async (req, res) => {
                const url = new URL(req.url, 'http://localhost');
                const p = url.pathname;
                if (p === '/dsh-wallpaper-bg/we') {
                  const query = Object.fromEntries(url.searchParams);
                  return weApi(query);
                }
              },
            }));
          });
          async function weApi(query) {
            const base = query.base || DEFAULT;
            const action = query.action;
            await fetch(base + '/api/wallpapers');
          }
        "#;
    assert_eq!(
        super::registered_route_entry(source).as_deref(),
        Some("GET /dsh-wallpaper-bg")
    );
    let params = super::url_search_params(source);
    assert!(params.contains(&"base".to_owned()), "mined {params:?}");
    assert!(params.contains(&"action".to_owned()), "mined {params:?}");
    // The dispatched sub-path is recovered as a gate path.
    assert!(super::gate_paths(source).contains(&"/dsh-wallpaper-bg/we".to_owned()));
    // A registration without a request handler is not mistaken for a route.
    assert_eq!(
        super::registered_route_entry("thing.register({ path: '/x' })"),
        None
    );
}

#[test]
fn url_search_params_mines_an_inline_member_off_from_entries() {
    // The handler reads the query parameter directly on the `Object.fromEntries` call, with no
    // intermediate variable, so the variable-binding shape misses it. Both the dot and bracket
    // member forms are mined.
    let dot = "const requestUrl = new URL(req.url);\n\
             const _url = Object.fromEntries(requestUrl.searchParams).url;\n";
    assert_eq!(super::url_search_params(dot), vec!["url".to_owned()]);
    let bracket = "const _url = Object.fromEntries(new URL(req.url).searchParams)[\"target\"];\n";
    assert_eq!(super::url_search_params(bracket), vec!["target".to_owned()]);
}

#[test]
fn relative_import_specifiers_follow_only_the_app_tree() {
    let source = "import fs from 'fs';\n\
            import { sendJson } from '../http.js';\n\
            import { createGithubAuthEnv } from '../../github-token.js';\n\
            const log = require('./log');\n\
            const dyn = await import('./lazy.js');\n";
    let specs = super::relative_import_specifiers(source);
    assert_eq!(
        specs,
        [
            "../http.js".to_owned(),
            "../../github-token.js".to_owned(),
            "./log".to_owned(),
            "./lazy.js".to_owned(),
        ]
    );
    // Bare package specifiers (`fs`) are never followed.
    assert!(!specs.iter().any(|s| s == "fs"));
}

#[test]
fn forwarded_search_params_follow_a_call_into_another_module() {
    // A semicolon-free (ASI) handler that parses the URL here but forwards the whole
    // search-parameters object into a render function in another module, which reads its
    // fields. The query name the sink consumes (`coinIcon`) lives only in the callee.
    let server = "import { renderStoryPng } from \"./story-render.js\"\n\
             const url = new URL(req.url, `http://localhost:${PORT}`)\n\
             const params = Object.fromEntries(url.searchParams)\n\
             const png = await renderStoryPng(params, assets)\n";
    // Without a semicolon, the URL-binding statement must not bleed into the next and make
    // `url` look bound from the search parameters; only `params` is.
    assert_eq!(
        super::vars_bound_from(server, "searchParams"),
        vec!["params".to_owned()]
    );
    // The import specifier is recovered even without a terminating semicolon.
    assert_eq!(
        super::import_source_path(server, "renderStoryPng").as_deref(),
        Some("./story-render.js")
    );
    let render = "export async function renderStoryPng(params, assets) {\n\
             const icon = await loadCoinIcon(params.coinIcon)\n\
             return params.coinName\n\
             }\n";
    let mined = super::forwarded_search_params(
        server,
        &|name| (name == "renderStoryPng").then(|| render.to_owned()),
        &[],
    );
    assert!(mined.contains(&"coinIcon".to_owned()), "mined {mined:?}");
    assert!(mined.contains(&"coinName".to_owned()), "mined {mined:?}");
    // An object that is not forwarded anywhere yields nothing to resolve.
    assert!(super::forwarded_search_params(server, &|_| None, &[]).is_empty());
}

#[test]
fn node_querystring_params_are_mined_locally_and_when_forwarded() {
    let server = "const parsed = url.parse(request.url);\n\
                  const options = querystring.parse(parsed.query);\n\
                  const direct = options.format;\n\
                  return listFolders(options);\n";
    assert_eq!(super::url_search_params(server), vec!["format".to_owned()]);

    let helper = "function listFolders(input) {\n\
                  return fs.readdirSync(input.q);\n\
                  }\n";
    assert_eq!(
        super::forwarded_search_params(
            server,
            &|name| (name == "listFolders").then(|| helper.to_owned()),
            &[],
        ),
        vec!["q".to_owned()]
    );
}

#[test]
fn node_querystring_params_can_be_consumed_before_the_handler_binding() {
    let source = "function runTask(options) {\n\
                  return spawn(options.fn);\n\
                  }\n\
                  function listFolders(options) {\n\
                  return fs.readdirSync(options.q);\n\
                  }\n\
                  function handleRequest(request) {\n\
                  const parsed = url.parse(request.url);\n\
                  const options = querystring.parse(parsed.query);\n\
                  runTask(options);\n\
                  return ok(response, listFolders(options));\n\
                  }\n";
    assert_eq!(
        super::url_search_params(source),
        vec!["fn".to_owned(), "q".to_owned()]
    );
    let forwarded = super::forwarded_search_params(
        source,
        &|name| matches!(name, "runTask" | "listFolders").then(|| source.to_owned()),
        &[12],
    );
    assert_eq!(forwarded.first().map(String::as_str), Some("q"));
    assert!(forwarded.contains(&"fn".to_owned()));
}

#[test]
fn inline_search_parameter_objects_are_followed_into_helpers() {
    let source = "function serveSongAudio(query, res) {\n\
                    const raw = String(query.file ?? '');\n\
                    return fs.readFile(path.resolve(raw));\n\
                  }\n\
                  function route(req, res) {\n\
                    const url = new URL(req.url, 'http://localhost');\n\
                    return serveSongAudio(Object.fromEntries(url.searchParams), res);\n\
                  }\n";
    assert_eq!(
        super::forwarded_search_params(
            source,
            &|name| (name == "serveSongAudio").then(|| source.to_owned()),
            &[7],
        ),
        vec!["file".to_owned()]
    );
}

#[test]
fn import_source_path_bounds_its_window_on_utf8() {
    let prefix = "import { target } from './target.js';";
    let source = format!("{}{}─\n", prefix, "x".repeat(399 - prefix.len()));
    assert_eq!(source.as_bytes()[399], 0xe2);
    assert_eq!(
        super::import_source_path(&source, "target").as_deref(),
        Some("./target.js")
    );
}

#[test]
fn import_source_path_rejects_an_unnamed_sink_receiver() {
    let source = "import { User } from './user.js';\n";
    assert_eq!(super::import_source_path(source, ""), None);
    assert!(!super::contains_word(source, ""));
}

#[test]
fn a_registration_lookup_keeps_unique_probe_identities_and_observes_later_mutation() {
    let source = "async function register(req) {\n\
            await User.create({ username: req.body.username });\n\
            const referrer = await User.findOne({ referralCode: req.body.referralCode });\n\
            if (referrer) await User.findOneAndUpdate({ _id: referrer._id }, { $inc: { coin: 1 } });\n\
            }\n";
    assert_eq!(
        super::nosql_handler_effects(source, 3, Some(1)),
        (true, true)
    );
}

#[test]
fn url_query_fillers_satisfy_presence_and_object_key_guards() {
    // A URL-sourced SSRF handler reads two query parameters and reaches `fetch(url)` only when
    // both are present and `type` indexes an imported allow-list object. The payload rides `url`;
    // the sibling `type` must carry a real key of that object, resolved from its own module.
    let handler = "\
            export async function GET(request) {\n\
              const { searchParams } = new URL(request.url);\n\
              const url = searchParams.get(\"url\");\n\
              const type = searchParams.get(\"type\");\n\
              if (!url || !type) return bad();\n\
              const filter = FILTERS[type];\n\
              if (!filter) return bad();\n\
              const res = await fetch(url);\n\
            }\n";
    let module = "\
            // free-model filters\n\
            export const FILTERS = {\n\
              \"openrouter-free\": (m) => m,\n\
              \"opencode-free\": (m) => m,\n\
            };\n";
    let fillers =
        super::url_query_fillers(handler, &["url".to_owned(), "type".to_owned()], &|name| {
            (name == "FILTERS").then(|| module.to_owned())
        });
    assert_eq!(
        fillers,
        vec![
            ("url".to_owned(), "http://jss-filler.test/".to_owned()),
            ("type".to_owned(), "openrouter-free".to_owned()),
        ]
    );
}

#[test]
fn declared_mount_prefix_reads_a_literal_default() {
    use super::declared_mount_prefix as p;
    assert_eq!(
        p("const defaults = {\n  mountPath: \"/auth\",\n};").as_deref(),
        Some("/auth")
    );
    assert_eq!(p("this.mountPath = '/files/'").as_deref(), Some("/files"));
    assert_eq!(p("this.mountPath = this.options.mountPath;"), None);
    assert_eq!(p("mountPath: \"/\""), None);
    assert_eq!(
        p("// REST surface for cells, mounted at /api/cells.\nimport express from 'express';")
            .as_deref(),
        Some("/api/cells")
    );
    assert_eq!(
        p("/** Router mounted under `/internal/files` by the host. */"),
        None,
        "quoted prose is intentionally not treated as an executable path hint"
    );
}

#[test]
fn required_siblings_fill_a_handlers_other_guards() {
    // A handler that reaches its sink only after a cluster of query parameters checks out: one
    // pinned to a literal by a regex guard (via an aliased variable), one that wants a URL,
    // and one merely required present.
    let source = r#"
          const responseType =
            request.query.response_type ?? (deprecated ? "id" : undefined);
          const required = {
            client_id: request.query.client_id,
            redirect_uri: request.query.redirect_uri,
            response_type: responseType,
            state: request.query.state,
          };
          if (!/^(code|id)$/.test(String(responseType))) throw new Error("bad");
        "#;
    let siblings = required_siblings(source, "query", "client_id");
    assert_eq!(
        siblings,
        vec![
            (
                "redirect_uri".to_owned(),
                "http://jss-filler.test/".to_owned()
            ),
            ("response_type".to_owned(), "code".to_owned()),
            ("state".to_owned(), "jsspector".to_owned()),
        ]
    );
}

#[test]
fn a_header_entry_takes_its_other_forwarded_headers_as_siblings() {
    // A handler that forwards a second request header into the outbound request: the tainted
    // header chooses the host, the sibling must still be sent so the request is constructed.
    let source = r#"
          axios({
            method: 'get',
            url: `${req.headers.backendurl}/jsonapi/${model}/${req.params.objectId}`,
            headers: { Authorization: req.headers.authorization },
          });
        "#;
    let entry = Entry::Header("backendurl".to_owned());
    let probe = Probe {
        method: Method::Get,
        path: "/jsonapi/stagedAssets/{objectId}".to_owned(),
        entry,
        class: VulnClass::Ssrf,
        siblings: Vec::new(),
        gate_paths: Vec::new(),
        url_query_params: Vec::new(),
        read_suffix: None,
        read_filename_suffix: None,
        envelope: None,
        doc_envelope: None,
        lists_dir: false,
        removes: false,
        removes_dir: false,
        creates: false,
        archive_upload: false,
        appended_param: None,
        path_fillers: Vec::new(),
        body_requires: Vec::new(),
        body_object: false,
        body_query_override: None,
        sql: None,
        sql_value: None,
        array_element: false,
        appended_fields: Vec::new(),
        removed_child_marker: None,
        proto_pollution: None,
        alt_paths: Vec::new(),
        auth: None,
        multipart: None,
        cmd_quote: None,
        cmd_dir_segment: false,
        nosql_lookup: false,
        nosql_inserts_before_sink: false,
        nosql_mutates: false,
        decode_base64: None,
        allow_tokens: Vec::new(),
        stored_write: None,
        query_dispatch: Vec::new(),
        text_wrap: None,
        mcp: None,
        element_body: None,
    };
    let (part, target) = probe.entry_part().expect("a header entry takes siblings");
    assert_eq!((part, target), ("headers", "backendurl"));
    let siblings = required_siblings(source, part, target);
    assert_eq!(
        siblings,
        vec![("authorization".to_owned(), "jsspector".to_owned())]
    );
}

#[test]
fn a_substring_url_allowlist_is_mined_as_bypassable_host_tokens() {
    // The image-proxy shape: the handler decodes the URL, then rejects it unless it *contains* one
    // of two Google hosts, and otherwise fetches it. Both host substrings are must-contain tokens a
    // substring allowlist cannot actually bind the request host with, so both are mined.
    let source = r#"
          const imageUrl = req.query.url;
          const decodedUrl = decodeURIComponent(imageUrl);
          if (!decodedUrl.includes('googleusercontent.com') && !decodedUrl.includes('google.com')) {
            return res.status(403).json({ error: 'nope' });
          }
          const response = await fetch(decodedUrl, { method: 'GET' });
        "#;
    let names = vec![
        "decodedUrl".to_owned(),
        "imageUrl".to_owned(),
        "url".to_owned(),
    ];
    assert_eq!(
        ssrf_allowlist_host_tokens(source, &names),
        vec!["googleusercontent.com".to_owned(), "google.com".to_owned()]
    );
}

#[test]
fn a_blocklist_and_a_parsed_host_allowlist_mine_no_bypass_tokens() {
    // A non-negated `.includes` is a blocklist (the request is rejected *for* containing the token),
    // so embedding it would defeat the request — not mined. An allow-array membership and a parsed
    // `new URL(url).hostname` equality constrain the real host and are not substring-bypassable, so
    // their receivers (`allowed`, `host`) are not the tainted URL and are also left out.
    let names = vec!["url".to_owned(), "host".to_owned()];
    assert!(
        ssrf_allowlist_host_tokens(
            "if (url.includes('169.254.169.254')) return res.status(403).end();",
            &names,
        )
        .is_empty()
    );
    assert!(
            ssrf_allowlist_host_tokens(
                "const host = new URL(url).hostname; if (!allowed.includes(host)) throw new Error('x');",
                &names,
            )
            .is_empty()
        );
}

#[test]
fn a_negated_prefix_and_indexof_url_allowlist_are_mined() {
    // `startsWith`/`endsWith` prefix-or-suffix allowlists, and the `indexOf(...) === -1` spelling of
    // "does not contain", are all must-contain gates reduced to their host substring.
    let names = vec!["url".to_owned()];
    assert_eq!(
        ssrf_allowlist_host_tokens(
            "if (!url.startsWith('https://api.example.com/')) return bad();",
            &names,
        ),
        vec!["api.example.com".to_owned()]
    );
    assert_eq!(
        ssrf_allowlist_host_tokens(
            "if (url.indexOf('cdn.example.net') === -1) return bad();",
            &names
        ),
        vec!["cdn.example.net".to_owned()]
    );
}

#[test]
fn required_siblings_include_used_body_fields_destructured_from_request_json() {
    // A Next.js App Router handler destructures its body from `request.json()`; the sibling fields
    // the handler also consumes (passed to `User.create`) must be supplied, or the insert that
    // precedes the sink rejects the request. The payload field itself is excluded.
    let source = "const { username, password, referralCode } = await request.json();\n\
                      await User.create({ username, password });\n\
                      const r = await User.findOne({ referralCode });";
    let siblings = required_siblings(source, "body", "referralCode");
    let names: Vec<&str> = siblings.iter().map(|(name, _)| name.as_str()).collect();
    assert!(names.contains(&"username"), "{names:?}");
    assert!(names.contains(&"password"), "{names:?}");
    assert!(!names.contains(&"referralCode"), "{names:?}");
}

#[test]
fn handler_scoping_and_joi_defaults_keep_only_real_body_preconditions() {
    let source = r#"
          router.post('/search', (req, res) => {
            use(req.body.artist, req.body.album, req.body.image);
          });
          router.post('/set-from-url', async (req, res) => {
            const schema = Joi.object({
              filepath: Joi.string().required(),
              url: Joi.string().uri().required(),
              writeToFolder: Joi.boolean().default(false),
              writeToFile: Joi.boolean().default(false)
            });
            joiValidate(schema, req.body);
            try {
              const image = await httpGet(req.body.url);
              await apply(req.body.filepath, image, req.body.writeToFolder, req.body.writeToFile);
            } catch (error) {}
          });
        "#;
    let route_line = source
        .lines()
        .position(|line| line.contains("router.post('/set-from-url'"))
        .map(|line| line as u32 + 1)
        .unwrap();
    let line = source
        .lines()
        .position(|line| line.contains("httpGet(req.body.url)"))
        .map(|line| line as u32 + 1)
        .unwrap();
    let handler = super::route_handler_source(source, route_line, line);
    assert!(!handler.contains("req.body.artist"));
    assert_eq!(
        super::required_siblings(handler, "body", "url"),
        vec![("filepath".to_owned(), "jsspector".to_owned())]
    );
}

#[test]
fn required_siblings_read_an_equality_guard_and_skip_destructured_only_names() {
    // `mode` is pinned by `===`; `token` is only destructured (optional), so it is not sent.
    let source = r#"
          const { token } = req.query;
          if (req.query.mode === 'strict') { use(req.query.name); }
        "#;
    let siblings = required_siblings(source, "query", "name");
    assert_eq!(siblings, vec![("mode".to_owned(), "strict".to_owned())]);
}

#[test]
fn required_siblings_do_not_borrow_a_later_fields_literal_without_semicolons() {
    // Semicolon-free code (ASI): the `shortHandVal` binding must end at its own newline and resolve
    // to a neutral filler, not the `"true"` literal that `makenew == "true"` pins two lines down.
    // Over-spanning the right-hand side (the original bug) pinned every field to `"true"`, so the
    // handler crashed writing a boolean where it expected a string.
    let source = r#"
          var id = req.body.id
          var makenew = req.body.makenew == "true" ? true : false
          var shortHandVal = req.body.shortHandVal
          fs.writeFileSync(folder + '/x', shortHandVal)
          use(id, makenew)
        "#;
    let siblings = required_siblings(source, "body", "id");
    let short = siblings
        .iter()
        .find(|(k, _)| k == "shortHandVal")
        .expect("shortHandVal is a required sibling");
    assert_eq!(short.1, "jsspector");
    let makenew = siblings
        .iter()
        .find(|(k, _)| k == "makenew")
        .expect("makenew is a required sibling");
    assert_eq!(makenew.1, "true");
}

#[test]
fn provisioning_branch_field_is_sent_so_the_create_branch_reaches_the_sink() {
    // A "create new vs. reuse existing" selector: the `makenew` branch provisions `folder`
    // (`fs.mkdirSync`) that the post-join sink flow writes into and reads from, while the `else`
    // branch reads attacker-absent state (`fs.readdirSync(base + '/' + id)`) and throws before the
    // sink. The selector's positive block does not enclose the sink, so the diverting heuristics
    // would drop it; `provisioning_branch_fields` keeps it and pins it to the literal that enters
    // the provisioning branch (`"true"`), so the request takes the branch that reaches the sink.
    let source = r#"
          app.post('/save', function (req, res) {
            var id = req.body.id
            var makenew = req.body.makenew == "true" ? true : false
            var tempId = req.body.tempId
            var folder, version
            if (makenew) {
              id = makeid(7)
              version = 1
              folder = base + '/' + id + '/' + version
              fs.mkdirSync(folder, { recursive: true })
            } else {
              var versions = fs.readdirSync(base + '/' + id)
              version = versions.length + 1
              folder = base + '/' + id + '/' + version
            }
            fs.writeFileSync(folder + '/music.gq', req.body.shortHandVal)
            var tempFiles = fs.readdirSync('./public/temp/' + tempId)
          });
        "#;
    let source_line = source
        .lines()
        .position(|line| line.contains("var tempId = req.body.tempId"))
        .map(|line| line as u32 + 1)
        .unwrap();
    let sink_line = source
        .lines()
        .position(|line| line.contains("readdirSync('./public/temp/'"))
        .map(|line| line as u32 + 1)
        .unwrap();
    assert_eq!(
        provisioning_branch_fields(source, "body", &[source_line, sink_line]),
        vec![("makenew".to_owned(), "true".to_owned())]
    );
    // The ordinary `fs.mkdirSync('./public/temp')` setup call sits under no branch selector, so no
    // field is invented when the handler has no create-vs-reuse gate on the path to the sink.
    let no_gate = r#"
          app.post('/x', function (req, res) {
            var tempId = req.body.tempId
            fs.mkdirSync('./public/temp', { recursive: true })
            var tempFiles = fs.readdirSync('./public/temp/' + tempId)
          });
        "#;
    let s2 = no_gate
        .lines()
        .position(|line| line.contains("var tempId"))
        .map(|line| line as u32 + 1)
        .unwrap();
    let k2 = no_gate
        .lines()
        .position(|line| line.contains("readdirSync('./public/temp/'"))
        .map(|line| line as u32 + 1)
        .unwrap();
    assert!(provisioning_branch_fields(no_gate, "body", &[s2, k2]).is_empty());
}

#[test]
fn removed_dir_child_marker_reads_an_enumerated_removals_filter() {
    // `fs.unlinkSync(dir + '/' + f)` where `f` iterates `fs.readdirSync(dir)` and is filtered by
    // `.indexOf('.png')`: the removed leaf is a child enumerated from the tainted directory, so the
    // oracle must plant a `.png` child inside the climbed directory.
    let source = r#"
          var currFiles = fs.readdirSync(folder + '/')
          for (var i=0;i<currFiles.length;i++) {
            if (currFiles[i].indexOf('.png') > -1)
              fs.unlinkSync(folder + '/' + currFiles[i])
          }
        "#;
    let tainted = vec!["folder".to_owned(), "id".to_owned()];
    assert_eq!(
        removed_dir_child_marker(source, "folder + '/' + currFiles[i]", &tainted),
        Some(".png".to_owned())
    );
}

#[test]
fn removed_dir_child_marker_is_none_for_a_direct_name_removal() {
    // The tainted value itself names the removed entry: not an enumeration, so the ordinary delete
    // oracle (which plants the named file directly) applies and this returns `None`.
    let source = "fs.unlinkSync(path.join(base, name))";
    let tainted = vec!["name".to_owned()];
    assert_eq!(
        removed_dir_child_marker(source, "path.join(base, name)", &tainted),
        None
    );
}

#[test]
fn guards_enclosing_the_sink_pin_a_path_segment_and_require_a_branch_field() {
    // A handler routes on a path segment, reaches the sink only on one segment value and only on
    // a truthiness branch over a sibling body field. The branch over `note`, which closes before
    // the sink, and the branch over `token`, which opens after it, are not enclosing and excluded.
    let source = r#"
          router.post('/svc/:kind', async (req, res) => {
            const valid = ['go', 'stop'];
            if (!valid.includes(kind)) return;
            if (kind === 'go') {
              const { token, agent, base, note } = req.body;
              if (note) {
                handleNote(note);
              } else if (agent) {
                const url = base || 'https://default';
                const r = await fetch(`${url}/profile`);
              } else if (token) {
                handleToken(token);
              }
            }
          });
        "#;
    let sink_line = source
        .lines()
        .position(|l| l.contains("fetch("))
        .map(|i| i as u32 + 1)
        .unwrap();

    let guards = enclosing_guards(source, sink_line);
    assert!(guards.contains(&("kind".to_owned(), Some("go".to_owned()))));
    assert!(guards.contains(&("agent".to_owned(), None)));
    assert!(guards.iter().all(|(id, _)| id != "note" && id != "token"));

    let fillers = path_slot_fillers(
        source,
        "/svc/{kind}",
        &Entry::Body(Some("base".to_owned())),
        &[sink_line],
    );
    assert_eq!(fillers, vec![("kind".to_owned(), "go".to_owned())]);

    let required = guard_required_fields(source, "body", "base", &[sink_line]);
    assert_eq!(required, vec![("agent".to_owned(), "jsspector".to_owned())]);
}

#[test]
fn shell_quote_context_reads_the_interpolated_quote() {
    // The tainted value sits inside a double quote, a single quote, or unquoted; the payload must
    // close the quote it is interpolated within before its separator.
    assert_eq!(shell_quote_context(r#"'open "' + folder + '"'"#), Some('"'));
    assert_eq!(shell_quote_context(r#"'ping -c1 ' + host"#), None);
    assert_eq!(shell_quote_context("\"echo '\" + name + \"'\""), Some('\''));
    assert_eq!(shell_quote_context("`open \"${folder}\"`"), Some('"'));
    assert_eq!(shell_quote_context("`xdg-open ${folder}`"), None);
    // The tainted value is not the first interpolation: a helper call (`${fnFile("ids.js")}`)
    // precedes it, and the quote state is read at the tainted `${query}` — inside the single quote
    // the template opens just before it.
    assert_eq!(
        shell_quote_context("`node ${fnFile(\"ids.js\")} '${query}'`"),
        Some('\'')
    );
    // A bare variable argument (no literal prefix) is unquoted.
    assert_eq!(shell_quote_context("folder"), None);
}

#[test]
fn json_stringify_trace_is_a_double_quoted_shell_context() {
    let mut f = finding(
        VulnClass::CommandInjection,
        Auth::NoneDetected,
        Some("GET /run"),
        "req.url",
    );
    f.sink.api = "child_process.exec".to_owned();
    f.sink.arg = "cmd".to_owned();
    f.trace.push(TraceStep {
        file: None,
        line: 12,
        col: 8,
        note: "through JSON.stringify()".to_owned(),
    });
    assert_eq!(command_quote_context(&f), Some('"'));
}

#[test]
fn diverting_guard_fields_drops_an_alternative_branch_selector() {
    // `openFolderOnly` selects a branch that does not contain the tainted flow (the sink is reached
    // only when it is absent); it must be dropped. `file` is read on the flow path, and `id` is a
    // negated presence requirement — neither is diverting.
    let source = r#"
          router.get('/openFileFolder/', async (req, res) => {
            let folder = null;
            if (req.query.openFolderOnly) {
              folder = path.join(root, 'ASSETS', req.query.openFolderOnly);
            } else {
              let relpath = req.query.file || '';
              if (!req.query.id) return res.status(400).send('no');
              folder = path.dirname(path.join(root, 'ASSETS', 'templates', relpath));
            }
            require('child_process').exec('open "' + folder + '"');
          });
        "#;
    let flow_line = source
        .lines()
        .position(|l| l.contains("let relpath ="))
        .map(|i| i as u32 + 1)
        .unwrap();
    let diverting = diverting_guard_fields(source, "query", &[flow_line]);
    assert_eq!(diverting, vec!["openFolderOnly".to_owned()]);
}

#[test]
fn diverting_local_guard_fields_drops_fields_branched_on_through_a_local() {
    // The sink sits in the `else` of `if (keepVersion == 'yes')` and before the `if (tempId !=
    // undefined)` / `else if (hasFiles ...)` branches, each gated on a LOCAL the handler copied the
    // request field into (`var keepVersion = req.body.keepVersion`). Sending those fields routes
    // control away from the sink (or into a branch that crashes past it); each must be dropped so a
    // body-delivered `id` reaches `fs.readdirSync`. The payload field `id` itself is not diverting.
    let source = r#"
          app.post('/save', function(req, res) {
            var id = req.body.id
            var makenew = req.body.makenew == "true" ? true : false
            var shortHandVal = req.body.shortHandVal
            var hasFiles = req.body.hasFiles == "true" ? true : false
            var tempId = req.body.tempId
            var keepVersion = req.body.keepVersion == undefined ? 'no' : req.body.keepVersion
            if (makenew) {
              id = makeid(7)
            }
            else {
              if (keepVersion == 'yes') {
                version = oldVersion
              }
              else {
                var versions = fs.readdirSync(MUSIC_DIR + '/' + id)
              }
            }
            if (tempId != undefined) {
              var tempFiles = fs.readdirSync('./public/temp/' + tempId)
            }
            else if (hasFiles && keepVersion == 'no') {
              var oldFiles = fs.readdirSync(MUSIC_DIR + '/' + id)
            }
            res.send({ id: id })
          });
        "#;
    let line_of = |needle: &str| {
        source
            .lines()
            .position(|l| l.contains(needle))
            .map(|i| i as u32 + 1)
            .unwrap()
    };
    let source_line = line_of("var id = req.body.id");
    let sink_line = line_of("fs.readdirSync(MUSIC_DIR + '/' + id)");
    let mut diverting = diverting_local_guard_fields(source, "body", &[source_line, sink_line]);
    diverting.sort();
    assert_eq!(
        diverting,
        vec![
            "hasFiles".to_owned(),
            "keepVersion".to_owned(),
            "makenew".to_owned(),
            "tempId".to_owned(),
        ]
    );
}

#[test]
fn diverting_local_guard_fields_keeps_a_local_gate_that_encloses_the_sink() {
    // `if (mode === 'raw')` copied into a local still ENCLOSES the sink: dropping `mode` would make
    // the sink unreachable, so it must not be reported as diverting.
    let source = r#"
          app.post('/run', function(req, res) {
            var mode = req.body.mode
            if (mode === 'raw') {
              var out = fs.readFileSync(req.body.path)
            }
            res.send(out)
          });
        "#;
    let line_of = |needle: &str| {
        source
            .lines()
            .position(|l| l.contains(needle))
            .map(|i| i as u32 + 1)
            .unwrap()
    };
    let sink_line = line_of("fs.readFileSync(req.body.path)");
    let diverting = diverting_local_guard_fields(source, "body", &[sink_line]);
    assert!(diverting.is_empty(), "{diverting:?}");
}

#[test]
fn a_cross_function_sink_picks_up_guards_enclosing_the_in_handler_flow() {
    // The tainted URL is forwarded into a helper, so the sink `fetch` sits in the callee with no
    // enclosing guard of its own. The guards that gate reaching it — a non-payload path segment
    // (`kind === 'go'`) and the branch field (`token`) — enclose the handler-side flow positions:
    // the source read and the call site. Anchoring the guard search on every same-file flow line,
    // not the callee's sink line alone, recovers both. (With the sink line alone, neither is seen.)
    let source = r#"
          async function upload(base) {
            const r = await fetch(`${base}/account/agent/profile/`);
            return r;
          }
          router.post('/svc/:kind', async (req, res) => {
            const valid = ['go', 'stop'];
            if (!valid.includes(kind)) return;
            if (kind === 'go') {
              const { token, base } = req.body;
              if (token) {
                await upload(base);
              }
            }
          });
        "#;
    let line_of = |needle: &str| {
        source
            .lines()
            .position(|l| l.contains(needle))
            .map(|i| i as u32 + 1)
            .unwrap()
    };
    let sink_line = line_of("fetch(");
    let source_line = line_of("const { token, base }");
    let call_line = line_of("await upload(base)");

    // The finding's own locations: source in the handler, sink in the callee, a trace step at the
    // call site. All share the finding's file, so each contributes an anchor line.
    let mut f = finding(
        VulnClass::Ssrf,
        Auth::NoneDetected,
        Some("POST /svc/{kind}"),
        "req.body",
    );
    f.source.line = source_line;
    f.sink.line = sink_line;
    f.trace = vec![TraceStep {
        file: None,
        line: call_line,
        col: 1,
        note: "passed to upload()".to_owned(),
    }];
    let anchors = guard_anchor_lines(&f);

    // The sink line alone finds nothing; the full flow recovers both guards.
    assert!(
        path_slot_fillers(
            source,
            "/svc/{kind}",
            &Entry::Body(Some("base".to_owned())),
            &[sink_line]
        )
        .is_empty()
    );
    let fillers = path_slot_fillers(
        source,
        "/svc/{kind}",
        &Entry::Body(Some("base".to_owned())),
        &anchors,
    );
    assert_eq!(fillers, vec![("kind".to_owned(), "go".to_owned())]);

    assert!(guard_required_fields(source, "body", "base", &[sink_line]).is_empty());
    let required = guard_required_fields(source, "body", "base", &anchors);
    assert_eq!(required, vec![("token".to_owned(), "jsspector".to_owned())]);
}

#[test]
fn an_early_return_presence_guard_supplies_required_body_siblings() {
    let source = r#"
          async function signup(req, res, next) {
            const { email, name, firstName, lastName, password } = req.body;
            if (!email || !name || !firstName || !lastName || !password) {
              return next(new Error('missing'));
            }
            const user = await User.findOne({ $or: [{ email }, { name }] });
          }
        "#;
    let line = |needle: &str| {
        source
            .lines()
            .position(|text| text.contains(needle))
            .map(|index| index as u32 + 1)
            .unwrap()
    };
    assert_eq!(
        guard_required_fields(
            source,
            "body",
            "email",
            &[line("const { email"), line("User.findOne")],
        ),
        vec![
            ("name".to_owned(), "jsspector".to_owned()),
            ("firstName".to_owned(), "jsspector".to_owned()),
            ("lastName".to_owned(), "jsspector".to_owned()),
            ("password".to_owned(), "jsspector".to_owned()),
        ]
    );

    let mixed = source.replace(
        "!email || !name || !firstName || !lastName || !password",
        "!email && !name",
    );
    assert!(
        guard_required_fields(
            &mixed,
            "body",
            "email",
            &[line("const { email"), line("User.findOne")],
        )
        .is_empty()
    );
}

#[test]
fn a_multiline_destructure_anchor_still_finds_the_handlers_presence_guards() {
    // A query SSRF where the handler destructures its query over several lines and the payload
    // field (`umamiUrl`) is one of the inner lines, so a flow anchor falls *inside* the `{ ... } =
    // req.query` braces. The sink `fetch` sits in a helper the handler calls. The two other query
    // fields (`website`, `token`) are required by early-return presence guards (`if (!website)
    // return ...`). The guard scan must scope to the whole handler body — not the destructuring
    // braces the lowest anchor lands in — or neither required sibling is supplied and the handler
    // redirects before the sink.
    let source = r#"
          app.get("/api/:metric", async (req, res) => {
            const {
              website,
              token,
              style = "for-the-badge",
              umamiUrl,
            } = req.query;
            if (!website) {
              return res.redirect("https://img.shields.io/badge/Error-red");
            }
            if (!token) {
              return res.redirect("https://img.shields.io/badge/Error-red");
            }
            const data = await fetchUmamiData(umamiUrl, website, token, metric);
            res.send(data);
          });
          async function fetchUmamiData(umamiUrl, websiteId, token, metric) {
            const baseUrl = umamiUrl.replace(/\/$/, "");
            const url = `${baseUrl}/realtime/${websiteId}`;
            const response = await fetch(url, { headers: { "x-api-key": token } });
            return await response.json();
          }
        "#;
    let line = |needle: &str| {
        source
            .lines()
            .position(|text| text.contains(needle))
            .map(|index| index as u32 + 1)
            .unwrap()
    };
    // Anchors mirror a real finding: the source read sits on `umamiUrl,` inside the destructure,
    // the call site, and the sink in the helper.
    let anchors = [
        line("umamiUrl,"),
        line("} = req.query;"),
        line("await fetchUmamiData("),
        line("const url = `${baseUrl}"),
        line("const response = await fetch"),
    ];
    let required = guard_required_fields(source, "query", "umamiUrl", &anchors);
    assert!(
        required.contains(&("website".to_owned(), "jsspector".to_owned())),
        "{required:?}"
    );
    assert!(
        required.contains(&("token".to_owned(), "jsspector".to_owned())),
        "{required:?}"
    );
}

use super::*;

#[test]
fn a_forwarded_whole_query_targets_the_sink_bound_destructured_field() {
    let route = r#"
async function checkCredentialProvider(provider, query) {
  if (provider === 'jira') {
    const { domain, email, project_key: projectKey,
      token_store_type: tokenStoreType, token_secret_name: tokenSecretName } = query;
    if (!domain || !email || !projectKey) return { status: 'missing' };
    return resolveJiraToken(null, null, tokenSecretName, tokenStoreType);
  }
}
async function handle(req) {
  const provider = req.query.provider;
  return checkCredentialProvider(provider, req.query);
}
"#;
    let sink = r#"
export function resolveJiraToken(tokenEnv, token, tokenSecret, tokenStore) {
  if (tokenStore === 'gcp-secret' && tokenSecret) {
    return execSync(`gcloud --secret="${tokenSecret}"`);
  }
}
"#;
    let line = sink[..sink.find("execSync").unwrap()]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count() as u32
        + 1;
    let (field, siblings) =
        forwarded_query_context(route, sink, line, "`gcloud --secret=\"${tokenSecret}\"`")
            .expect("the forwarded field should resolve");
    assert_eq!(field, "token_secret_name");
    assert!(siblings.contains(&("provider".to_owned(), "jira".to_owned())));
    assert!(siblings.contains(&("token_store_type".to_owned(), "gcp-secret".to_owned())));
    assert!(siblings.contains(&("domain".to_owned(), "jsspector".to_owned())));
    assert!(siblings.contains(&("email".to_owned(), "jsspector".to_owned())));
    assert!(siblings.contains(&("project_key".to_owned(), "jsspector".to_owned())));
}
use jss_core::{SinkLoc, SourceLoc, TraceStep};

#[test]
fn a_destructuring_default_is_not_read_as_an_assignment_to_the_bound_field() {
    // A later handler binds the same field with a default from the request part
    // (`{ id, type = "x" } = req.body`). The payload field must still resolve to the specific
    // body field, not be dragged back to the whole body by the trailing `req.body` of the default
    // destructuring.
    let source = r#"
            router.post("/remove", async (req, res) => {
              const { id, type } = req.body;
              let typeDir = path.join(baseDir, type, id);
              if (fs.existsSync(typeDir)) await fs.promises.rm(typeDir);
            });
            router.post("/other", async (req, res) => {
              const { id, type = "Anime", numbers } = req.body;
              doThing(type, id, numbers);
            });
        "#;
    let mut f = finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("POST /remove"),
        "req.body",
    );
    f.sink.api = "fs.rm".to_owned();
    f.sink.arg = "typeDir".to_owned();
    f.trace = vec![TraceStep {
        file: None,
        line: 3,
        col: 17,
        note: "assigned to `type`".to_owned(),
    }];
    assert_eq!(
        best_entry(&f, "/remove", Some(source)),
        Some(Entry::Body(Some("type".to_owned())))
    );
    // The default binding is a destructuring default, not an assignment to `type`.
    assert!(assignment_rhs(source, "type").is_empty());
}

#[test]
fn a_path_join_names_an_appended_request_field_after_the_tainted_segment() {
    // `path.join(base, type, id)`: `id` is another member of the same body destructuring, so it is
    // attacker-controlled and recorded as an appended field. A server-computed local is not.
    let source = r#"
            const { id, type } = req.body;
            let typeDir = path.join(baseDir, type, id);
            let other = path.join(baseDir, type, folderName);
        "#;
    assert_eq!(
        appended_path_fields(
            source,
            &["type".to_owned()],
            &Entry::Body(Some("type".to_owned())),
        ),
        vec!["id".to_owned()]
    );
    // A query-derived field is picked up for a query entry; nothing for a path-param entry.
    assert!(
        appended_path_fields(
            source,
            &["type".to_owned()],
            &Entry::PathParam("type".to_owned()),
        )
        .is_empty()
    );
}

#[test]
fn string_concatenation_names_an_appended_request_field_after_the_tainted_segment() {
    // `serverpath + "Flash" + mypath + "/" + req.query.filename`: the tainted `mypath` is only a
    // directory prefix; the handler appends `filename` (another query member) after a `"/"`
    // separator, so `filename` is the attacker-controlled terminal segment. The fixed string
    // literals are skipped, and the tainted value itself is not recorded.
    let source = r#"
            let mypath = req.query.path
            let filepath = path.normalize(
                serverpath + "Flash" + mypath + "/" + req.query.filename
            )
            deleteFolderRecursive(filepath)
        "#;
    assert_eq!(
        appended_path_fields(
            source,
            &["mypath".to_owned(), "path".to_owned()],
            &Entry::Query("path".to_owned()),
        ),
        vec!["filename".to_owned()]
    );
    // A server-computed local appended after the tainted value is not attacker-controlled: nothing
    // is recorded past it.
    let computed = r#"
            let mypath = req.query.path
            let filepath = serverpath + mypath + "/" + folderName
        "#;
    assert!(
        appended_path_fields(
            computed,
            &["mypath".to_owned(), "path".to_owned()],
            &Entry::Query("path".to_owned()),
        )
        .is_empty()
    );
}

#[test]
fn concatenated_read_through_a_listing_selected_segment_yields_a_planted_leaf_suffix() {
    // `base + '/' + id + '/' + version + '/music.gq'`: `id` is the tainted directory, `version` is
    // a server-selected segment chosen from a numeric listing of that directory, and `music.gq` is a
    // fixed leaf. The traversal proof must plant `<dir>/0/music.gq`, so the suffix is `0/music.gq`.
    let source = r#"
            var id = req.query.id
            if (fs.existsSync(MUSIC_DIR + '/' + id)) {
              var versions = fs.readdirSync(MUSIC_DIR + '/' + id)
              var version = 0
              for (var i=0;i<versions.length;i++) {
                if (!isNaN(versions[i]))
                  version = Math.max(version, Number(versions[i]))
              }
              gq = fs.readFileSync(MUSIC_DIR + '/' + id + '/' + version + '/music.gq', 'utf-8')
            }
        "#;
    assert_eq!(
        appended_listing_suffix(
            source,
            "MUSIC_DIR + '/' + id + '/' + version + '/music.gq'",
            &["id".to_owned()],
        ),
        Some("0/music.gq".to_owned())
    );
    // No enumeration of the tainted directory: the middle segment is not a selectable listing child,
    // so nothing is planted (the generic read oracle handles a direct read instead).
    let no_listing = r#"
            var id = req.query.id
            var version = Number(req.query.v)
            gq = fs.readFileSync(MUSIC_DIR + '/' + id + '/' + version + '/music.gq', 'utf-8')
        "#;
    assert_eq!(
        appended_listing_suffix(
            no_listing,
            "MUSIC_DIR + '/' + id + '/' + version + '/music.gq'",
            &["id".to_owned()],
        ),
        None
    );
    // A `path.join(...)` sink is handled by `appended_path_suffix`, not here.
    assert_eq!(
        appended_listing_suffix(
            source,
            "path.join(MUSIC_DIR, id, 'music.gq')",
            &["id".to_owned()]
        ),
        None
    );
}

#[test]
fn an_appended_suffix_is_not_borrowed_from_a_sibling_route_in_the_same_module() {
    // Two routes share a same-named `saveDir`. The delete route removes it directly (no appended
    // leaf); a sibling load route reads `path.join(saveDir, 'chatHistory.json')`. Scanning the whole
    // enclosing module would borrow that sibling leaf as the delete sink's suffix, making the oracle
    // name the whole directory and have a recursive removal wipe its own control. Scoping to the
    // sink's handler block keeps the delete route suffix-less, so its tainted value names the removed
    // entry itself.
    let source = "\
app.get('/api/save/:saveName/load', (req, res) => {\n\
    const { saveName } = req.params;\n\
    const saveDir = path.join(__dirname, 'saves', saveName);\n\
    const history = fs.readFileSync(path.join(saveDir, 'chatHistory.json'));\n\
    res.json(history);\n\
});\n\
app.delete('/api/save/:saveName', (req, res) => {\n\
    const { saveName } = req.params;\n\
    const saveDir = path.join(__dirname, 'saves', saveName);\n\
    fs.rmSync(saveDir, { recursive: true, force: true });\n\
});\n";
    let tainted = ["saveName".to_owned(), "saveDir".to_owned()];
    // Unscoped, the sibling route's leaf is wrongly borrowed.
    assert_eq!(
        appended_path_suffix(source, &tainted),
        Some("chatHistory.json".to_owned())
    );
    // Scoped to the delete handler (its source line), no suffix is appended to the sink path.
    let delete_handler = handler_source(source, 8);
    assert_eq!(appended_path_suffix(delete_handler, &tainted), None);
}

#[test]
fn a_literal_filename_suffix_is_mined_from_templates_and_concatenation() {
    let tainted = ["userId".to_owned()];
    assert_eq!(
        appended_filename_suffix("const file = path.join(root, `${userId}.json`);", &tainted,),
        Some(".json".to_owned())
    );
    assert_eq!(
        appended_filename_suffix("const file = root + '/' + userId + '.yaml';", &tainted),
        Some(".yaml".to_owned())
    );
    assert_eq!(
        appended_filename_suffix("const file = path.join(root, userId);", &tainted),
        None
    );
}

#[test]
fn rmdir_sink_marks_the_delete_oracle_to_plant_a_directory() {
    // `fs.rmdirSync` only removes a directory, so the destructive differential must plant a
    // directory target, not a file. `fs.unlink`/`fs.rm` remove a file and stay file-based.
    assert!(sink_removes_dir("fs.rmdirSync"));
    assert!(sink_removes_dir("rmdir"));
    assert!(!sink_removes_dir("fs.unlinkSync"));
    assert!(!sink_removes_dir("fs.rm"));
}

fn finding(class: VulnClass, auth: Auth, entry: Option<&str>, expr: &str) -> Finding {
    Finding {
        file: "server.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "fs.readFile".to_owned(),
            arg: "p".to_owned(),
            line: 1,
            col: 1,
        },
        class,
        severity: jss_core::Severity::High,
        confidence: "heuristic",
        auth,
        function: "GET /x".to_owned(),
        entry: entry.map(str::to_owned),
        entry_at: None,
        source: SourceLoc {
            kind: "http",
            expr: expr.to_owned(),
            line: 1,
            col: 1,
        },
        stored_by: None,
        trace: Vec::<TraceStep>::new(),
        key: "k".to_owned(),
        fingerprint: "f".to_owned(),
    }
}

/// A socket-sourced finding: `finding()`, with the source kind and expression a socket.io
/// `socket.on(event, (param, cb) => ...)` registration carries, and `entry` set to `"SOCKET
/// <event>"` instead of an HTTP route.
fn socket_finding(class: VulnClass, event: &str, param: &str) -> Finding {
    let mut f = finding(
        class,
        Auth::NoneDetected,
        Some(&format!("SOCKET {event}")),
        param,
    );
    f.source.kind = "socket";
    f
}

#[test]
fn element_body_shapes_an_array_of_objects_body_field() {
    use jss_core::TraceStep;
    // The tainted body field `tasks` is an array of objects the handler iterates; the sink reads
    // `task.downloadUrl` on the `task.action === 'video'` branch. The payload must ride under
    // `downloadUrl` inside a one-element array, with `action` pinned to the branch value.
    let handler = "async function h(req, res) {\n\
         \x20 const { tasks } = req.body;\n\
         \x20 for (let i = 0; i < tasks.length; i += 1) {\n\
         \x20   const task = tasks[i];\n\
         \x20   if (task.action === 'video') {\n\
         \x20     await fetchVideoStream(task.downloadUrl);\n\
         \x20   }\n\
         \x20 }\n\
         }";
    let mut f = finding(
        VulnClass::Ssrf,
        Auth::NoneDetected,
        Some("POST /api/x"),
        "req.body",
    );
    f.source.line = 2;
    f.trace = vec![
        TraceStep {
            file: None,
            line: 4,
            col: 1,
            note: "assigned to `task`".to_owned(),
        },
        TraceStep {
            file: None,
            line: 6,
            col: 1,
            note: "passed to `fetchVideoStream()`".to_owned(),
        },
    ];
    let shape = super::element_body(handler, "tasks", &f).expect("element body");
    assert_eq!(shape.sink_key, "downloadUrl");
    assert_eq!(
        shape.required,
        vec![("action".to_owned(), "video".to_owned())]
    );
    // A scalar body field (no iteration binding) stays a plain field.
    assert!(super::element_body(handler, "other", &f).is_none());
}

#[test]
fn parse_socket_entry_reads_the_event_name() {
    assert_eq!(parse_socket_entry("SOCKET run"), Some("run".to_owned()));
    assert_eq!(parse_socket_entry("SOCKET "), None);
    assert_eq!(parse_socket_entry("GET /run"), None);
}

#[test]
fn socket_field_resolves_a_direct_member_access_at_the_sink() {
    let mut f = socket_finding(VulnClass::CommandInjection, "run", "data");
    f.sink.arg = "data.cmd".to_owned();
    f.trace = vec![TraceStep {
        file: None,
        line: 1,
        col: 1,
        note: "assigned to `data`".to_owned(),
    }];
    assert_eq!(
        socket_field(&f, None),
        Some(Entry::Body(Some("cmd".to_owned())))
    );
}

#[test]
fn socket_field_follows_one_hop_through_a_built_local() {
    // `const filepath = path.join(base, data.name); fs.readFileSync(filepath)`: the sink argument
    // names only the built local; the member access is in that local's own binding, in the
    // handler's source, not in the sink argument.
    let mut f = socket_finding(VulnClass::PathTraversal, "read", "data");
    f.sink.arg = "filepath".to_owned();
    f.trace = vec![
        TraceStep {
            file: None,
            line: 1,
            col: 1,
            note: "assigned to `data`".to_owned(),
        },
        TraceStep {
            file: None,
            line: 2,
            col: 1,
            note: "assigned to `filepath`".to_owned(),
        },
    ];
    let source = "socket.on('read', (data, cb) => {\n\
             const filepath = path.join(base, data.name);\n\
             cb(fs.readFileSync(filepath, 'utf8'));\n\
           });";
    assert_eq!(
        socket_field(&f, Some(source)),
        Some(Entry::Body(Some("name".to_owned())))
    );
    // With no source to search, the one-hop hop cannot be followed; the field is not resolved
    // (never the wrong field: `filepath` itself is not the tainted name on the wire).
    assert_eq!(socket_field(&f, None), None);
}

#[test]
fn socket_field_resolves_the_whole_payload_when_nothing_reads_a_member() {
    let mut f = socket_finding(VulnClass::CommandInjection, "run", "cmd");
    f.sink.arg = "cmd".to_owned();
    f.trace = vec![TraceStep {
        file: None,
        line: 1,
        col: 1,
        note: "assigned to `cmd`".to_owned(),
    }];
    assert_eq!(socket_field(&f, None), Some(Entry::Body(None)));
}

#[test]
fn socket_field_does_not_guess_a_renamed_destructured_field() {
    // `const { cmd: command } = data; exec(command)`: the wire field is `cmd`, but only the
    // renamed local `command` appears anywhere the resolver looks; guessing would send the
    // payload under the wrong key.
    let mut f = socket_finding(VulnClass::CommandInjection, "run", "data");
    f.sink.arg = "command".to_owned();
    f.trace = vec![
        TraceStep {
            file: None,
            line: 1,
            col: 1,
            note: "assigned to `data`".to_owned(),
        },
        TraceStep {
            file: None,
            line: 2,
            col: 1,
            note: "assigned to `command`".to_owned(),
        },
    ];
    let source = "socket.on('run', (data, cb) => {\n\
             const { cmd: command } = data;\n\
             exec(command);\n\
           });";
    assert_eq!(socket_field(&f, Some(source)), None);
}

#[test]
fn a_socket_finding_plans_as_plan_socket_with_the_event_as_its_path() {
    let mut f = socket_finding(VulnClass::CommandInjection, "run", "data");
    f.sink.arg = "data.cmd".to_owned();
    f.trace = vec![TraceStep {
        file: None,
        line: 1,
        col: 1,
        note: "assigned to `data`".to_owned(),
    }];
    match plan_with_source(&f, None).expect("a socket command-injection finding should plan") {
        Plan::Socket(probe) => {
            assert_eq!(probe.path, "run");
            assert_eq!(probe.entry, Entry::Body(Some("cmd".to_owned())));
            assert_eq!(probe.class, VulnClass::CommandInjection);
        }
        other => panic!("expected Plan::Socket, got {other:?}"),
    }
}

#[test]
fn a_socket_finding_of_an_unsupported_class_is_skipped_with_a_reason() {
    let f = socket_finding(VulnClass::NosqlInjection, "query", "data");
    let Err(skip) = plan_with_source(&f, None) else {
        panic!("NoSQL injection over a socket.io event should not plan yet");
    };
    assert!(skip.0.contains("not driven yet"), "{}", skip.0);
}

#[test]
fn a_socket_finding_behind_authentication_is_skipped_with_a_reason() {
    let mut f = socket_finding(VulnClass::CommandInjection, "run", "data");
    f.auth = Auth::User;
    let Err(skip) = plan_with_source(&f, None) else {
        panic!("an authenticated socket.io finding should not plan yet");
    };
    assert!(skip.0.contains("authentication"), "{}", skip.0);
}

/// An MCP finding: the engine's own naming for `entry`, the source expression and the sink
/// argument, with the trace locals that carry the value.
fn mcp_finding(
    class: VulnClass,
    entry: Option<&str>,
    expr: &str,
    arg: &str,
    locals: &[&str],
) -> Finding {
    let mut f = finding(class, Auth::NoneDetected, entry, expr);
    f.source.kind = "mcp";
    f.sink.arg = arg.to_owned();
    f.trace = locals
        .iter()
        .map(|local| TraceStep {
            file: None,
            line: 1,
            col: 1,
            note: format!("assigned to `{local}`"),
        })
        .collect();
    f
}

fn mcp_plan(f: &Finding, source: Option<&str>) -> Probe {
    match plan_with_source(f, source).expect("an MCP finding should plan") {
        Plan::Mcp(probe) => *probe,
        other => panic!("expected Plan::Mcp, got {other:?}"),
    }
}

#[test]
fn mcp_entries_name_a_tool_unless_they_name_a_protocol_schema() {
    assert_eq!(parse_mcp_entry("MCP run"), Some("run".to_owned()));
    assert_eq!(
        parse_mcp_entry("MCP read_note"),
        Some("read_note".to_owned())
    );
    // A low-level server dispatches on the request schema, not on a tool.
    assert_eq!(parse_mcp_entry("MCP CallToolRequestSchema"), None);
    assert_eq!(parse_mcp_entry("MCP "), None);
    assert_eq!(parse_mcp_entry("GET /run"), None);
}

#[test]
fn a_destructured_parameter_names_the_argument_that_reaches_the_sink() {
    // `server.registerTool('shell', ..., async ({ command }) => exec(command))`
    let f = mcp_finding(
        VulnClass::CommandInjection,
        Some("MCP shell"),
        "{ command }",
        "command",
        &["command"],
    );
    let probe = mcp_plan(&f, None);
    assert_eq!(probe.method, Method::Mcp);
    assert_eq!(probe.path, "shell");
    assert_eq!(probe.entry, Entry::Body(Some("command".to_owned())));
    // A renamed binding names the argument, not the local (`{ path: p }` -> `path`).
    let renamed = mcp_finding(
        VulnClass::PathTraversal,
        Some("MCP read"),
        "{ path: p, mode }",
        "p",
        &["p"],
    );
    assert_eq!(
        mcp_plan(&renamed, None).entry,
        Entry::Body(Some("path".to_owned()))
    );
}

#[test]
fn a_member_of_the_arguments_object_names_the_argument() {
    // `server.tool('read_note', schema, async (args) => handleRead(args))` and `args.name` at the sink.
    let whole = mcp_finding(
        VulnClass::PathTraversal,
        Some("MCP read_note"),
        "args",
        "path.join('/data', args.name)",
        &["args"],
    );
    assert_eq!(
        mcp_plan(&whole, None).entry,
        Entry::Body(Some("name".to_owned()))
    );
    // A low-level handler: `request.params.arguments.path`, under a protocol-schema entry.
    let low = mcp_finding(
        VulnClass::PathTraversal,
        Some("MCP CallToolRequestSchema"),
        "request",
        "request.params.arguments.path",
        &[],
    );
    let probe = mcp_plan(&low, None);
    assert_eq!(probe.path, "", "the tool is the server's to say");
    assert_eq!(probe.entry, Entry::Body(Some("path".to_owned())));
    // FastMCP's `addTool` gets no entry from the engine at all.
    let fast = mcp_finding(
        VulnClass::CommandInjection,
        None,
        "args",
        "args.cmd",
        &["args"],
    );
    let probe = mcp_plan(&fast, None);
    assert_eq!(probe.path, "");
    assert_eq!(probe.entry, Entry::Body(Some("cmd".to_owned())));
}

#[test]
fn an_argument_the_source_does_not_name_is_left_to_the_servers_schema() {
    // The whole arguments object reaches a helper in another file: the sink names a local only.
    let f = mcp_finding(
        VulnClass::PathTraversal,
        Some("MCP verify_answer"),
        "args",
        "dir",
        &["args", "params", "baseDir", "dir"],
    );
    let probe = mcp_plan(&f, None);
    assert_eq!(probe.path, "verify_answer");
    assert_eq!(probe.entry, Entry::Body(None));
    let hints = probe.mcp.expect("hints");
    // The names the source used are what ranks the schema's arguments.
    assert!(hints.fields.contains(&"baseDir".to_owned()), "{hints:?}");
}

#[test]
fn an_mcp_finding_that_cannot_be_driven_is_skipped_with_a_reason() {
    let mut authed = mcp_finding(
        VulnClass::CommandInjection,
        Some("MCP run"),
        "{ cmd }",
        "cmd",
        &["cmd"],
    );
    authed.auth = Auth::User;
    let Err(skip) = plan_with_source(&authed, None) else {
        panic!("an authenticated MCP tool should not plan yet");
    };
    assert!(skip.0.contains("authentication"), "{}", skip.0);
    let nosql = mcp_finding(
        VulnClass::NosqlInjection,
        Some("MCP q"),
        "args",
        "args.q",
        &["args"],
    );
    let Err(skip) = plan_with_source(&nosql, None) else {
        panic!("NoSQL injection through an MCP tool should not plan yet");
    };
    assert!(skip.0.contains("not driven yet"), "{}", skip.0);
}

#[test]
fn mcp_endpoints_are_mined_from_the_routes_the_source_registers() {
    let source = "app.get('/health', h);\n\
             app.post('/api/mcp', handler);\n\
             app.get('/sse', async (req, res) => {\n\
               const t = new SSEServerTransport('/messages', res);\n\
             });\n\
             app.get('/users/:id', u);\n\
             server.start({ httpStream: { endpoint: '/rpc' } });";
    let paths = mcp_endpoint_paths(source);
    // The ones that look like MCP (`mcp`, `sse`, `message`) come first; a parametrized route
    // is no endpoint.
    assert_eq!(&paths[..3], ["/api/mcp", "/sse", "/messages"], "{paths:?}");
    assert!(paths.contains(&"/rpc".to_owned()) && paths.contains(&"/health".to_owned()));
    assert!(!paths.iter().any(|p| p.contains(':')));
}

#[test]
fn a_socket_finding_with_no_entry_point_is_skipped() {
    let mut f = socket_finding(VulnClass::CommandInjection, "run", "data");
    f.entry = None;
    assert!(plan_with_source(&f, None).is_err());
}

#[test]
fn a_reflected_xss_over_http_plans_a_browser_driven_reflected_probe() {
    // A Hono handler reflects a query parameter into the HTML response (`c.html(unsubscribePage(
    // token))`). The source is an HTTP request, so it is neither a DOM XSS (the static-page browser
    // phase) nor a server-side HTTP oracle; it must be driven as a reflected XSS.
    let mut xss = finding(
        VulnClass::Xss,
        Auth::NoneDetected,
        Some("GET /unsubscribe"),
        "c.req.query(\"t\")",
    );
    xss.sink.api = "c.html".to_owned();
    xss.sink.arg = "unsubscribePage(token)".to_owned();
    match plan_with_source(&xss, None).expect("reflected XSS should plan") {
        Plan::ReflectedXss(probe) => {
            assert_eq!(probe.method, Method::Get);
            assert_eq!(probe.path, "/unsubscribe");
            assert_eq!(probe.entry, Entry::Query("t".to_owned()));
        }
        other => panic!("expected a reflected-XSS plan, got {other:?}"),
    }
}

#[test]
fn a_reflected_xss_with_a_body_only_source_is_skipped_with_a_reason() {
    // A browser navigation can only place the payload in the URL; a body-only reflection is not
    // driven, and the skip explains why rather than guessing at a request.
    let mut xss = finding(
        VulnClass::Xss,
        Auth::NoneDetected,
        Some("POST /comment"),
        "req.body.text",
    );
    xss.sink.api = "res.send".to_owned();
    xss.sink.arg = "render(text)".to_owned();
    let skip = plan_with_source(&xss, None).expect_err("a body-only reflected XSS is not driven");
    assert!(
        skip.0.contains("URL-placed input"),
        "reason was: {}",
        skip.0
    );
}

#[test]
fn a_dom_sourced_xss_still_uses_the_static_browser_phase() {
    // Routing reflected (HTTP-source) XSS to its own plan must not divert a DOM-source XSS away
    // from the existing static-page browser phase.
    let dom = dom_finding("location.search", "el.innerHTML", "web/app.js");
    assert!(matches!(plan_with_source(&dom, None), Ok(Plan::Browser(_))));
}

#[test]
fn an_archive_entry_reaching_a_create_sink_builds_an_upload_probe() {
    let mut archive = finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("POST /file-upload"),
        "unzipper.Open.buffer(buffer)",
    );
    archive.source.kind = "archive";
    archive.sink.api = "fs.createWriteStream".to_owned();

    let probe = Probe::from_finding(&archive).unwrap();
    assert!(probe.archive_upload);
    assert!(probe.creates);
    assert_eq!(probe.method, Method::Post);
    assert_eq!(probe.path, "/file-upload");
    assert_eq!(probe.entry, Entry::Body(None));
}

#[test]
fn a_coarse_body_ssrf_resolves_the_field_its_own_handler_destructures() {
    // The handler under test destructures `const { repostId } = req.body`; an unrelated sibling
    // route reads `req.body.csrfToken`. Resolution must pin the destructured field of the handler
    // that reaches the sink, not the only `req.body.<field>` member read elsewhere in the module.
    let source = "\n\
            app.post('/delete', async (req, res) => {\n\
            \x20 if (typeof req.body.csrfToken !== 'string') return;\n\
            \x20 await doDelete();\n\
            });\n\
            app.post('/repost', async (req, res) => {\n\
            \x20 const { repostId } = req.body;\n\
            \x20 const repostThreadsUrl = buildGraphAPIURL(`${repostId}/repost`);\n\
            \x20 await axios.post(repostThreadsUrl, {});\n\
            });\n";
    let mut finding = finding(
        VulnClass::Ssrf,
        Auth::NoneDetected,
        Some("POST /repost"),
        "req.body",
    );
    finding.sink.api = "http-client.post".to_owned();
    finding.sink.arg = "repostThreadsUrl".to_owned();
    finding.sink.line = 9;
    finding.source.line = 7;
    finding.trace.push(TraceStep {
        file: None,
        line: 7,
        col: 9,
        note: "assigned to `repostId`".to_owned(),
    });

    let probe = Probe::from_finding_with_source(&finding, Some(source)).unwrap();
    assert_eq!(probe.entry, Entry::Body(Some("repostId".to_owned())));
}

#[test]
fn request_form_data_resolves_the_text_field_and_required_file_part() {
    let source = r#"
          export async function POST(request) {
            const form = await request.formData();
            const upload = form.get("document");
            const destination = form.get('destination');
            const bytes = Buffer.from(await upload.arrayBuffer());
            const name = `copy_${destination}_${Date.now()}.bin`;
            await fs.writeFile(path.join(process.cwd(), "uploads", name), bytes);
          }
        "#;
    let mut finding = finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("POST /upload"),
        "request.formData()",
    );
    finding.sink.api = "fs.writeFile".to_owned();
    finding.sink.arg = "path.join(process.cwd(), \"uploads\", name)".to_owned();
    finding.trace.push(TraceStep {
        file: None,
        line: 5,
        col: 1,
        note: "assigned to `destination`".to_owned(),
    });

    let probe = Probe::from_finding_with_source(&finding, Some(source)).unwrap();
    assert_eq!(probe.entry, Entry::Body(Some("destination".to_owned())));
    assert!(probe.creates);
    assert_eq!(
        multipart_form(source, "destination"),
        Some(MultipartForm {
            fields: vec!["document".to_owned()],
            file_fields: vec!["document".to_owned()],
        })
    );
    // A File-valued field needs a filename payload, which the text-field multipart driver does
    // not guess at. It must remain unsupported rather than silently sending the wrong shape.
    assert_eq!(multipart_form(source, "document"), None);
}

#[test]
fn form_data_file_detection_does_not_promote_plain_text_fields_by_name() {
    let source = r#"
          async function POST(req) {
            const formData = await req.formData();
            const filename = formData.get("filename");
            const note = formData.get("note");
            return fs.writeFile(filename, note);
          }
        "#;
    assert_eq!(
        multipart_form(source, "filename"),
        Some(MultipartForm {
            fields: vec!["note".to_owned()],
            file_fields: Vec::new(),
        })
    );
}

/// A DOM finding: a browser-side source and sink, in a static front-end file.
fn dom_finding(expr: &str, sink_api: &str, file: &str) -> Finding {
    let mut f = finding(VulnClass::Xss, Auth::NoneDetected, None, expr);
    f.source.kind = "dom";
    f.file = file.to_owned();
    f.sink.api = sink_api.to_owned();
    f
}

#[test]
fn a_dom_search_into_inner_html_is_a_browser_html_probe() {
    let plan = plan(&dom_finding(
        "location.search",
        ".innerHTML =",
        "web/pages.js",
    ))
    .unwrap();
    let Plan::Browser(probe) = plan else {
        panic!("expected a browser probe, got {plan:?}");
    };
    assert_eq!(probe.vector, UrlVector::Search);
    assert_eq!(probe.sink, BrowserSink::Html);
    assert_eq!(probe.file, "web/pages.js");
}

#[test]
fn a_browser_probe_mines_the_real_url_parameter_from_source() {
    let src = "const state = new URLSearchParams(window.location.search).get('state') || 'd';\n\
                   app.innerHTML = `<p>${state}</p>`;";
    let plan = plan_with_source(
        &dom_finding("window.location.search", ".innerHTML =", "app.js"),
        Some(src),
    )
    .unwrap();
    let Plan::Browser(probe) = plan else {
        panic!("expected a browser probe");
    };
    // The exact parameter the script reads off the URL is mined, so the browser phase drives it.
    assert_eq!(probe.params, vec!["state".to_owned()]);
}

#[test]
fn param_mining_is_gated_on_building_url_search_params() {
    // A plain Map `.get` in a script that never builds URL search parameters is not a URL param.
    assert!(url_param_reads("const cache = new Map(); cache.get('ignored');").is_empty());
    // Nor is it confused with a real URLSearchParams receiver elsewhere in the same file.
    assert_eq!(
        url_param_reads(
            "const params = new URLSearchParams(location.search);\n\
                 const cache = new Map(); cache.get('ignored'); params.get('state');"
        ),
        vec!["state".to_owned()]
    );
    // Chained and via `searchParams`, both forms are recovered.
    assert_eq!(
        url_param_reads("new URLSearchParams(location.search).get('q')"),
        vec!["q".to_owned()]
    );
    assert_eq!(
        url_param_reads("new URL(location.href).searchParams.get('next')"),
        vec!["next".to_owned()]
    );
}

#[test]
fn manual_split_param_reads_mines_a_hand_rolled_key_value_hash_parser() {
    // The exact ModelEarth/localsite idiom: no URLSearchParams anywhere, a bare
    // split('&')/split('=') loop writing into an object, read later by property name.
    let source = "\
            window.addEventListener('hashchange', function() {\n\
                const hashStr = window.location.hash.substring(1);\n\
                const params = {};\n\
                hashStr.split('&').forEach(pair => {\n\
                    const [k, v] = pair.split('=');\n\
                    if (k && v) params[k] = decodeURIComponent(v);\n\
                });\n\
                if (params.state && params.naics && params.naics.indexOf(',') < 0) {\n\
                    showIndustryDetail(params.naics);\n\
                }\n\
            });\n";
    assert_eq!(
        manual_split_param_reads(source),
        vec!["state".to_owned(), "naics".to_owned()]
    );
    // Mixed into mined_url_params, a real URLSearchParams read still comes first.
    let mixed = format!("new URLSearchParams(location.search).get('q');\n{source}");
    assert_eq!(
        mined_url_params(&mixed),
        vec!["q".to_owned(), "state".to_owned(), "naics".to_owned()]
    );
}

#[test]
fn manual_split_param_reads_mines_direct_key_dispatch() {
    let source = r#"
        const query = req.url.split('?')[1] || '';
        const pairs = query.split('&');
        for (const pair of pairs) {
          const eq = pair.indexOf('=');
          const k = pair.substring(0, eq);
          const v = pair.substring(eq + 1);
          if (k === 'name') selected = decodeURIComponent(v);
          if (k === "secrets" && v === '1') includeSecrets = true;
        }
    "#;
    assert_eq!(
        manual_split_param_reads(source),
        vec!["name".to_owned(), "secrets".to_owned()]
    );
    assert_eq!(
        url_search_params(source),
        vec!["name".to_owned(), "secrets".to_owned()]
    );
}

#[test]
fn manual_split_param_reads_ignores_an_unrelated_split_on_ampersand() {
    // No `=`-split and no bracket-assigned object nearby: not the idiom, no false candidates.
    assert!(
        manual_split_param_reads("const parts = 'a&b&c'.split('&'); console.log(parts.length);")
            .is_empty()
    );
}

#[test]
fn a_field_read_inside_a_call_keeps_only_its_name() {
    // `path.resolve(base, req.query.name)`: the accessor as read from the source text carries the
    // call's closing paren, which is not part of the field the handler reads.
    assert_eq!(
        source_entry("req.query.name)", "/read"),
        Some(Entry::Query("name".to_owned()))
    );
    assert_eq!(
        source_entry("req.body.user,", "/login"),
        Some(Entry::Body(Some("user".to_owned())))
    );
    assert_eq!(
        source_entry("req.params.id);", "/items/{id}"),
        Some(Entry::PathParam("id".to_owned()))
    );
}

#[test]
fn a_location_assignment_is_a_navigation_probe() {
    let plan = plan(&dom_finding(
        "location.search",
        "window.location =",
        "app.js",
    ))
    .unwrap();
    let Plan::Browser(probe) = plan else {
        panic!("expected a browser probe");
    };
    assert_eq!(probe.sink, BrowserSink::Navigation);
}

#[test]
fn dom_vectors_and_sinks_are_classified() {
    assert_eq!(url_vector("location.hash.slice(1)"), Some(UrlVector::Hash));
    assert_eq!(
        url_vector("new URL(location.href).searchParams"),
        Some(UrlVector::Href)
    );
    assert_eq!(url_vector("document.referrer"), Some(UrlVector::Referrer));
    assert_eq!(url_vector("req.query.name"), None);
    assert_eq!(browser_sink("el.innerHTML ="), Some(BrowserSink::Html));
    assert_eq!(browser_sink("insertAdjacentHTML"), Some(BrowserSink::Html));
    assert_eq!(
        browser_sink("location.href ="),
        Some(BrowserSink::Navigation)
    );
    assert_eq!(browser_sink("fs.readFile"), None);
}

#[test]
fn a_non_url_dom_source_is_skipped_with_a_reason() {
    // A postMessage source is DOM but not a URL input: skipped, not driven.
    let mut f = dom_finding("event.data.html", ".innerHTML =", "w.js");
    f.source.kind = "dom";
    let err = plan(&f).unwrap_err();
    assert!(err.0.contains("not a URL input"), "{}", err.0);
}

#[test]
fn a_postmessage_eval_is_driven_from_a_cross_origin_browser_page() {
    let mut f = dom_finding("event.data", "eval", "plugins.js");
    f.class = VulnClass::CodeInjection;
    f.source.kind = "postmessage";
    let plan = plan_with_source(&f, None).expect("postMessage eval should be browser-driven");
    let Plan::Browser(probe) = plan else {
        panic!("expected a browser probe, got {plan:?}");
    };
    assert_eq!(probe.vector, UrlVector::Message);
    assert_eq!(probe.sink, BrowserSink::Eval);
    assert_eq!(probe.file, "plugins.js");
}

#[test]
fn a_dom_code_injection_into_a_dynamic_import_is_a_browser_import_probe() {
    // A harness reads an attacker-controlled URL off its own page URL and builds the module
    // specifier a dynamic `import()` loads from it (`import(`${base}/pdfjs/pdf.mjs`)`). The source
    // is a DOM URL input and the sink loads code from that URL, so the browser phase drives it by
    // repointing the URL at the marker origin.
    let src = "const BASE = new URL(new URL(window.location.href).searchParams.get('base') \
                   || './out', window.location.href).href;\n\
                   const pdfjsLib = await import(`${BASE}/pdfjs/pdf.mjs`);";
    let mut f = dom_finding("window.location.href", "import", "harness.js");
    f.class = VulnClass::CodeInjection;
    f.entry = Some("PAGE harness.js".to_owned());
    let plan = plan_with_source(&f, Some(src)).expect("a DOM import injection should plan");
    let Plan::Browser(probe) = plan else {
        panic!("expected a browser probe, got {plan:?}");
    };
    assert_eq!(probe.vector, UrlVector::Href);
    assert_eq!(probe.sink, BrowserSink::Import);
    assert_eq!(probe.file, "harness.js");
    // The exact parameter the harness reads off its URL is mined, so the real vector is driven.
    assert_eq!(probe.params, vec!["base".to_owned()]);
}

#[test]
fn code_url_sinks_are_classified_and_non_url_code_sinks_are_not() {
    assert_eq!(code_url_sink("import"), Some(BrowserSink::Import));
    assert_eq!(code_url_sink("importScripts"), Some(BrowserSink::Import));
    // A string-evaluating sink does not load code from a URL the browser phase can repoint.
    assert_eq!(code_url_sink("eval"), None);
    assert_eq!(code_url_sink("new Function"), None);
}

#[test]
fn a_dom_code_injection_into_a_string_eval_sink_is_skipped_with_a_reason() {
    // `eval` of a DOM value is a real code injection, but it is not a URL the browser phase can
    // repoint at the marker, so it is skipped with a reason rather than driven incorrectly.
    let mut f = dom_finding("location.hash.slice(1)", "eval", "app.js");
    f.class = VulnClass::CodeInjection;
    let err = plan_with_source(&f, None).unwrap_err();
    assert!(err.0.contains("does not load code from a URL"), "{}", err.0);
}

#[test]
fn query_path_traversal_is_a_get_with_a_query_param() {
    let probe = Probe::from_finding(&finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("GET /api/files"),
        "req.query.name",
    ))
    .unwrap();
    assert_eq!(probe.method, Method::Get);
    assert_eq!(probe.path, "/api/files");
    assert_eq!(probe.entry, Entry::Query("name".to_owned()));
}

#[test]
fn a_coarse_query_member_read_drives_the_accessed_parameter_not_the_local() {
    // The engine reports the coarse `req.query` as the source and the local the value is stored in
    // (`subtitlePath`) as the sink argument. The real parameter is the member actually read
    // (`req.query.file`), recovered from the handler source — not the local's own name.
    let source = "router.get('/subtitles', (req, res) => { \
            let subtitlePath = req.query.file; \
            subtitlePath = decodeURIComponent(subtitlePath); \
            return res.sendFile(subtitlePath, { dotfiles: 'allow' }); });";
    let mut f = finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("GET /subtitles"),
        "req.query",
    );
    f.sink.api = "res.sendFile".to_owned();
    f.sink.arg = "subtitlePath".to_owned();
    f.trace = vec![TraceStep {
        file: None,
        line: 1,
        col: 1,
        note: "assigned to `subtitlePath`".to_owned(),
    }];
    let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
    assert_eq!(probe.entry, Entry::Query("file".to_owned()));
}

#[test]
fn a_coarse_query_forwarded_across_a_call_resolves_the_field_by_name() {
    // The engine reports the coarse `req.query` as the source and names the sink argument by the
    // callee's parameter (`mapFile`), not a `req.query` member. The handler reads `req.query.mapFile`
    // and passes it to that callee; the flow trace records the value `assigned to \`mapFile\``, so the
    // query field whose name matches is the attacker input.
    let source = "putSettingsToMapFile(req, res) { \
            SettingsService.updateMapFile(req.query.mapFile, req.body, req.url); }";
    let mut f = finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("PUT /api/v2/settings/layermenu"),
        "req.query",
    );
    f.sink.api = "fs.writeFile".to_owned();
    f.sink.arg = "this.getFullPathToFile(mapFile)".to_owned();
    f.trace = vec![TraceStep {
        file: None,
        line: 1,
        col: 1,
        note: "assigned to `mapFile`".to_owned(),
    }];
    let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
    assert_eq!(probe.entry, Entry::Query("mapFile".to_owned()));
}

#[test]
fn sibling_routes_of_the_same_handler_are_recovered_from_the_route_source() {
    // One controller method mounted on several paths: the literals are every registered path, and
    // the siblings are the full paths of all but the live one, sharing its mount prefix.
    let router = "export default express.Router() \
            .put('/layermenu', controller.putSettingsToMapFile) \
            .put('/mapsettings', controller.putSettingsToMapFile) \
            .put('/toolsettings', controller.putSettingsToMapFile) \
            .put('/update/:map/:tool', controller.updateMapTool);";
    let literals = handler_route_literals(router, "putSettingsToMapFile");
    assert_eq!(
        literals,
        vec!["/layermenu", "/mapsettings", "/toolsettings"]
    );
    // The `:param` route of a different handler is not among them.
    assert!(!literals.iter().any(|l| l.contains(':')));
    let siblings = sibling_paths("/api/v2/settings/layermenu", &literals);
    assert_eq!(
        siblings,
        vec![
            "/api/v2/settings/mapsettings".to_owned(),
            "/api/v2/settings/toolsettings".to_owned(),
        ]
    );
    // A single-route handler has no siblings.
    assert!(sibling_paths("/api/v2/settings/layermenu", &["/layermenu".to_owned()]).is_empty());
}

#[test]
fn a_whole_request_body_is_distinguished_from_a_body_member() {
    assert!(handler_consumes_whole_body(
        "Service.update(req.params.id, req.body);"
    ));
    assert!(handler_consumes_whole_body(
        "const { value } = request.body;"
    ));
    assert!(!handler_consumes_whole_body(
        "Service.update(req.body.value);"
    ));
    assert!(!handler_consumes_whole_body(
        "const bodyText = req.bodyText;"
    ));
}

#[test]
fn a_file_based_catch_all_param_is_driven_through_the_path() {
    // `pages/api/md/[...path].ts` reads `req.query.path`: a file router merges the catch-all
    // segment into the request params, so the payload must fill the URL path slot, not a
    // `?path=` query that the real path segment would override.
    let mut f = finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("ANY /api/md/{}"),
        "req.query",
    );
    f.file = "src/pages/api/md/[...path].ts".to_owned();
    let source =
        "export default function handler(req, res){ const pathSegments = req.query.path; }";
    let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
    assert_eq!(probe.entry, Entry::PathParam(String::new()));
    assert_eq!(probe.path, "/api/md/{}");
}

#[test]
fn a_plain_query_traversal_is_not_mistaken_for_a_path_param() {
    // No dynamic route segment in the file path: the query parameter stays a query entry.
    let probe = Probe::from_finding_with_source(
        &finding(
            VulnClass::PathTraversal,
            Auth::NoneDetected,
            Some("GET /api/files"),
            "req.query.name",
        ),
        Some("const n = req.query.name;"),
    )
    .unwrap();
    assert_eq!(probe.entry, Entry::Query("name".to_owned()));
}

#[test]
fn dynamic_route_params_reads_the_framework_bracket_convention() {
    assert_eq!(
        dynamic_route_params("api/md/[...path].ts"),
        vec!["path".to_owned()]
    );
    assert_eq!(
        dynamic_route_params("routes/[id].js"),
        vec!["id".to_owned()]
    );
    assert_eq!(
        dynamic_route_params("app/[[...slug]]/route.ts"),
        vec!["slug".to_owned()]
    );
    assert!(dynamic_route_params("api/files.ts").is_empty());
}

#[test]
fn body_field_ssrf_is_a_post() {
    let probe = Probe::from_finding(&finding(
        VulnClass::Ssrf,
        Auth::NoneDetected,
        Some("POST /fetch"),
        "req.body.url",
    ))
    .unwrap();
    assert_eq!(probe.method.verb(&probe.entry), "POST");
    assert_eq!(probe.entry, Entry::Body(Some("url".to_owned())));
}

#[test]
fn a_whole_body_ssrf_resolves_the_member_behind_a_transform_step() {
    // The source is the coarse `req.body`; the tainted member is read, transformed, and stored
    // in a local (`const scrapeURL = req.body.queryURL.split("?")[0]`). The trace records the
    // transform (`through .split()`) before the assignment, so the `assigned to` step is not
    // first. The specific body field `queryURL` must still be resolved, or the payload rides a
    // generic field the handler never reads and the request throws before the sink.
    let source = r#"
          const handler = async (req, res) => {
            const scrapeURL =
              req.body.queryURL.split("?")[0];
            const response = await fetch(`${scrapeURL}`);
          };
        "#;
    let mut f = finding(
        VulnClass::Ssrf,
        Auth::NoneDetected,
        Some("POST /api/works/questions"),
        "req.body",
    );
    f.sink.arg = "`${scrapeURL}`".to_owned();
    f.trace = vec![
        TraceStep {
            file: None,
            line: 3,
            col: 23,
            note: "through .split()".to_owned(),
        },
        TraceStep {
            file: None,
            line: 3,
            col: 11,
            note: "assigned to `scrapeURL`".to_owned(),
        },
    ];
    let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
    assert_eq!(probe.entry, Entry::Body(Some("queryURL".to_owned())));
}

#[test]
fn a_whole_body_ssrf_resolves_the_member_a_callee_reads_off_an_alias() {
    // The handler binds the whole body to a local and forwards it to a callee; the sink (in that
    // callee) interpolates `config.galaxyDomain`, where `config` is the callee's parameter — an
    // alias of the whole body recorded in the flow trace. The specific body member `galaxyDomain`
    // must be resolved from the sink argument even though the handler source never shows
    // `req.body.galaxyDomain`, or the payload rides a generic field the request never reads.
    let mut f = finding(
        VulnClass::Ssrf,
        Auth::NoneDetected,
        Some("POST /api/testtrino/testtrino"),
        "req.body",
    );
    f.sink.arg = "`${config.galaxyDomain}/oauth/v2/token`".to_owned();
    f.trace = vec![
        TraceStep {
            file: None,
            line: 12,
            col: 11,
            note: "assigned to `connectionConfig`".to_owned(),
        },
        TraceStep {
            file: None,
            line: 3,
            col: 36,
            note: "assigned to `config`".to_owned(),
        },
    ];
    let probe = Probe::from_finding(&f).unwrap();
    assert_eq!(probe.entry, Entry::Body(Some("galaxyDomain".to_owned())));
}

#[test]
fn required_siblings_read_the_fields_a_guard_checks_through_a_whole_body_alias() {
    // The handler binds the whole body to a local (`const cfg = req.body`) and rejects the request
    // unless several of its fields are present (`if (!cfg.host || !cfg.port) return 400`). Those
    // fields are reads of the body part through the alias, so they are required siblings the probe
    // must carry alongside the payload field, or the request is rejected before the sink.
    let source = r#"
          router.post("/testtrino", async (req, res) => {
            const cfg = req.body;
            if (!cfg.host || !cfg.port || !cfg.user || !cfg.password) {
              return res.status(400).json({ success: false });
            }
            await testTrinoConnection(cfg);
          });
        "#;
    let siblings = required_siblings(source, "body", "galaxyDomain");
    let names: Vec<&str> = siblings.iter().map(|(name, _)| name.as_str()).collect();
    for field in ["host", "port", "user", "password"] {
        assert!(names.contains(&field), "missing {field} in {names:?}");
    }
    assert!(
        siblings.iter().all(|(_, value)| !value.is_empty()),
        "every sibling needs a presence-satisfying value: {siblings:?}"
    );
}

#[test]
fn an_upgrade_entry_is_a_get_marked_for_upgrade() {
    let probe = Probe::from_finding(&finding(
        VulnClass::Ssrf,
        Auth::NoneDetected,
        Some("UPGRADE /{wildcard}"),
        "request?.url",
    ))
    .unwrap();
    assert_eq!(probe.method, Method::Upgrade);
    assert!(probe.method.is_upgrade());
    assert_eq!(probe.method.verb(&probe.entry), "GET");
    assert_eq!(probe.entry, Entry::Url);
    assert!(!Method::Any.is_upgrade());
}

#[test]
fn a_use_mount_entry_is_a_routable_get_under_the_mount_path() {
    // `app.use('/clients', handler)` mounts a middleware at a path prefix that reads
    // `req.originalUrl`; it is driven as a GET whose payload rides under the mount.
    let probe = Probe::from_finding(&finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("USE /clients"),
        "req.originalUrl",
    ))
    .unwrap();
    assert_eq!(probe.method, Method::Use);
    assert_eq!(probe.method.verb(&probe.entry), "GET");
    assert_eq!(probe.entry, Entry::Url);
    assert_eq!(probe.path, "/clients");
}

#[test]
fn gate_paths_are_mined_from_the_handlers_own_comparisons() {
    let source = "function isIde(p) { return p === \"/ide\" || p.startsWith(\"/ide/\"); }\n\
             function isLog(p) { return p === '/logs/ws' || p === '/api/logs/ws'; }\n\
             const ok = [\"/health\"].includes(path);\n\
             const name = user.name === \"alice\";\n\
             const rel = \"./static/\" + req.url;\n";
    let paths = super::gate_paths(source);
    assert!(paths.contains(&"/ide".to_owned()), "{paths:?}");
    assert!(paths.contains(&"/logs/ws".to_owned()), "{paths:?}");
    assert!(paths.contains(&"/api/logs/ws".to_owned()), "{paths:?}");
    assert!(paths.contains(&"/health".to_owned()), "{paths:?}");
    // `startsWith("/ide/")` collapses onto `/ide`; non-path and non-compared literals are left out.
    assert!(!paths.iter().any(|p| p == "/ide/"), "{paths:?}");
    assert!(!paths.iter().any(|p| p == "./static/"), "{paths:?}");
    assert!(!paths.iter().any(|p| p == "alice"), "{paths:?}");
    // A raw catch-all dispatch gates on a substring of the URL (`req.url.indexOf('/api/ids') !==
    // -1`): the path it recognizes is mined so the payload rides a URL it accepts.
    let substring = "if (request.url.indexOf('/api/ids') !== -1) {}\n";
    assert!(super::gate_paths(substring).contains(&"/api/ids".to_owned()));
}

#[test]
fn gate_paths_ignores_an_apostrophe_inside_a_comment() {
    // An apostrophe in a comment (`Anivexa's`) must not be read as a string-literal opener, which
    // would swallow the following source and hide a real path comparison below it.
    let source = "// every lookup of that media id (Anivexa's getMedia) is answered from it\n\
             const u = typeof input === 'string' ? input : '';\n\
             if (url.pathname === '/api' || url.pathname === '/api/') return runApi(request);\n";
    assert!(
        super::gate_paths(source).contains(&"/api".to_owned()),
        "{:?}",
        super::gate_paths(source)
    );
}

#[test]
fn url_query_routes_outrank_early_noise_in_a_monolithic_router() {
    let mut source = String::from(
        "async function route(req, res, url) {\nconst { pathname: p, searchParams } = url;\n",
    );
    for index in 0..40 {
        source.push_str(&format!(
            "if (p === '/api/noise/{index}') return searchParams.get('page{index}');\n"
        ));
    }
    source.push_str("if (p === '/api/image') return fetch(searchParams.get('url'));\n}\n");

    assert_eq!(
        super::url_query_gate_paths(&source)
            .first()
            .map(String::as_str),
        Some("/api/image")
    );
    let params = super::url_search_params(&source);
    assert_eq!(params.first().map(String::as_str), Some("url"));
    assert!(params.len() <= 16, "bounded candidates: {params:?}");
}

#[test]
fn a_dispatch_path_near_the_sink_flow_outranks_earlier_routes() {
    let source = "function listFolders(options) {\n\
                    return fs.readdirSync(options.q);\n\
                  }\n\
                  function handle(request, response) {\n\
                    const parsed = url.parse(request.url);\n\
                    const options = querystring.parse(parsed.query);\n\
                    if ('/status' === parsed.pathname) return status();\n\
                    if ('/tasks' === parsed.pathname) return tasks();\n\
                    if ('/folders' === parsed.pathname) return listFolders(options);\n\
                  }\n";
    assert_eq!(
        super::gate_paths_near(source, &[9])
            .first()
            .map(String::as_str),
        Some("/folders")
    );
    assert!(super::gate_paths_near(source, &[]).is_empty());
}

#[test]
fn query_dispatch_cases_resolve_the_selector_and_forwarded_members() {
    // A handler that binds the whole query (`const q = req.query`) and dispatches on `q.action`
    // via a switch reaches the request sink only inside the matching case, where it forwards
    // another query member (`q.url`). The branch's selector, value and that member are recovered.
    let source = "async function handle(req, res) {\n\
             const q = req.query || {};\n\
             switch (q.action) {\n\
               case 'search':\n\
                 return send(res, await search(q.q));\n\
               case 'addon_check':\n\
                 return send(res, await addonInfo(q.url));\n\
               default:\n\
                 return send(res, 404);\n\
             }\n\
           }\n";
    let cases = super::query_dispatch_cases(source);
    let addon = cases
        .iter()
        .find(|d| d.selector == "action" && d.value == "addon_check")
        .expect("addon_check branch is mined");
    assert_eq!(addon.params, vec!["url".to_owned()]);
    let search = cases
        .iter()
        .find(|d| d.value == "search")
        .expect("search branch is mined");
    assert_eq!(search.params, vec!["q".to_owned()]);
    // The selector field itself is never offered as a URL-bearing member.
    assert!(
        cases
            .iter()
            .all(|d| !d.params.contains(&"action".to_owned()))
    );

    // The if/else-if equality form of the same dispatch is recovered too.
    let chained = "function h(req, res) {\n\
             const q = req.query;\n\
             if (q.action === 'addon_check') { return addonInfo(q.url); }\n\
           }\n";
    let chained_cases = super::query_dispatch_cases(chained);
    assert!(
        chained_cases
            .iter()
            .any(|d| d.selector == "action" && d.value == "addon_check" && d.params == ["url"]),
        "{chained_cases:?}"
    );

    // A handler with no query dispatch yields nothing.
    assert!(super::query_dispatch_cases("function h(req){ return req.query.q; }").is_empty());
}

#[test]
fn a_path_param_must_have_a_slot_in_the_route() {
    let ok = Probe::from_finding(&finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("GET /barcode/{key}"),
        "req.params.key",
    ))
    .unwrap();
    assert_eq!(ok.entry, Entry::PathParam("key".to_owned()));
    // No slot for `id`: skipped, not guessed.
    assert!(
        Probe::from_finding(&finding(
            VulnClass::PathTraversal,
            Auth::NoneDetected,
            Some("GET /barcode/{key}"),
            "req.params.id",
        ))
        .is_err()
    );
}

#[test]
fn a_coarse_params_base64_json_envelope_is_resolved_and_packed() {
    // The finding names only `req.params`; the handler reads `req.params.id`, base64url-decodes
    // it as a JSON envelope, and makes the outbound request to `payload.url`. The route's `{id}`
    // slot is recovered as the entry, and the envelope describes how to pack the payload.
    let source = r#"
          export async function handle(req, res) {
            const raw = req.params.id;
            const payload = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
            if (!payload.url || !payload.from || !payload.to) return res.status(400).end();
            const r = await axios.get(payload.url);
          }
        "#;
    let mut f = finding(
        VulnClass::Ssrf,
        Auth::NoneDetected,
        Some("GET /proxy/translated/{id}.srt"),
        "req.params",
    );
    f.file = "lib/translated.js".to_owned();
    f.sink.arg = "url".to_owned();
    f.trace = vec![TraceStep {
        file: None,
        line: 1,
        col: 1,
        note: "assigned to `raw`".to_owned(),
    }];
    let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
    assert_eq!(probe.entry, Entry::PathParam("id".to_owned()));
    let env = probe.envelope.expect("envelope recognized");
    assert_eq!(env.field, "url");
    assert_eq!(env.siblings, vec!["from".to_owned(), "to".to_owned()]);
    assert!(env.url_safe);
    // Without the handler source the coarse `req.params` stays unresolved, never guessed.
    assert!(Probe::from_finding(&f).is_err());
}

#[test]
fn a_base64_decoded_eval_input_is_marked_for_base64_encoding() {
    // The handler base64-decodes its tainted query parameter into a raw string and evaluates it
    // directly (not JSON.parsed into an envelope). The probe must record that the payload has to be
    // base64-encoded so the decode reconstructs it at the sink, and must *not* mistake it for the
    // JSON-envelope case.
    let source = r#"
          const requestHandler = (req, res) => {
            const url = new URL(req.url, `http://${req.headers.host}`);
            if (url.pathname === '/api') {
              const c = url.searchParams.get('c');
              const decoded = Buffer.from(c, 'base64').toString();
              const result = eval(decoded);
            }
          };
        "#;
    let mut f = finding(
        VulnClass::CodeInjection,
        Auth::NoneDetected,
        Some("GET /{wildcard}"),
        "req.url",
    );
    f.sink.api = "eval".to_owned();
    f.sink.arg = "decoded".to_owned();
    f.trace = vec![
        TraceStep {
            file: None,
            line: 1,
            col: 1,
            note: "assigned to `c`".to_owned(),
        },
        TraceStep {
            file: None,
            line: 1,
            col: 1,
            note: "assigned to `decoded`".to_owned(),
        },
    ];
    let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
    assert_eq!(probe.decode_base64, Some(false));
    assert!(probe.envelope.is_none());
    // Without the base64 decode in the source, the flag stays unset.
    let plain = "const result = eval(req.query.c);";
    let mut g = finding(
        VulnClass::CodeInjection,
        Auth::NoneDetected,
        Some("GET /x"),
        "req.query.c",
    );
    g.sink.api = "eval".to_owned();
    g.sink.arg = "c".to_owned();
    let probe = Probe::from_finding_with_source(&g, Some(plain)).unwrap();
    assert_eq!(probe.decode_base64, None);
}

#[test]
fn a_params_segment_passed_positionally_to_path_join_resolves_the_route_slot() {
    // An Azure Functions v4 handler destructures a catch-all route param and passes it as a
    // positional `path.join(base, '../client', filePath)` argument rather than interpolating it.
    // The planner must still map the tainted local back to its `{filePath}` route slot.
    let source = r#"
          app.http('getChunks', { route: 'chunks/{*filePath}', methods: ['GET'], handler: (request, context) => {
            const { filePath } = request.params;
            return { body: fs.readFileSync(path.join(__dirname, '../client', filePath)) };
          } });
        "#;
    let mut f = finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("GET /api/chunks/{filePath}"),
        "request.params",
    );
    f.sink.api = "fs.readFileSync".to_owned();
    f.sink.arg = "path.join(__dirname, '../client', filePath)".to_owned();
    f.trace = vec![TraceStep {
        file: None,
        line: 1,
        col: 1,
        note: "assigned to `filePath`".to_owned(),
    }];
    let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
    assert_eq!(probe.entry, Entry::PathParam("filePath".to_owned()));
    assert_eq!(probe.path, "/api/chunks/{filePath}");
    assert_eq!(probe.method, Method::Get);
}

#[test]
fn a_hono_param_destructuring_into_a_directory_listing_resolves_the_tainted_slot() {
    // A Hono handler destructures all path params from `c.req.param()`, uses one as a directory
    // ancestor and appends a sibling path param (enum-constrained) before listing it. The planner
    // must map the tainted local back to its route slot, recognize the listing sink, and recover
    // the sibling slot and its accepted values.
    let source = r#"
          app.get('/resources/:module/:kind', async c => {
            const { module: mod, kind } = c.req.param();
            const base = path.resolve(__dirname, '..', '..', 'mcp_resources', mod);
            if (!['info', 'docs', 'examples'].includes(kind)) {
              return c.json({ error: 'nope' }, 400);
            }
            const dirPath = path.join(base, kind);
            const files = fs.readdirSync(dirPath, { withFileTypes: true });
            return c.json({ files });
          });
        "#;
    let mut f = finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("GET /resources/{module}/{kind}"),
        "c.req.param()",
    );
    f.sink.api = "fs.readdirSync".to_owned();
    f.sink.arg = "abs".to_owned();
    f.trace = vec![
        TraceStep {
            file: None,
            line: 1,
            col: 1,
            note: "assigned to `mod`".to_owned(),
        },
        TraceStep {
            file: None,
            line: 1,
            col: 1,
            note: "assigned to `base`".to_owned(),
        },
        TraceStep {
            file: None,
            line: 1,
            col: 1,
            note: "assigned to `dirPath`".to_owned(),
        },
    ];
    let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
    assert_eq!(probe.entry, Entry::PathParam("module".to_owned()));
    assert!(probe.lists_dir);
    let ap = probe.appended_param.expect("sibling path param recovered");
    assert_eq!(ap.name, "kind");
    assert_eq!(
        ap.values,
        vec!["info".to_owned(), "docs".to_owned(), "examples".to_owned()]
    );
    // Without the handler source the coarse `c.req.param()` stays unresolved, never guessed.
    assert!(Probe::from_finding(&f).is_err());
}

#[test]
fn a_base_dir_built_from_the_tainted_param_carries_taint_to_an_appended_enum_slot() {
    // The real handler builds a base directory from the tainted param (`path.resolve(.., mod)`),
    // guards a sibling slot with an enum, then appends it (`path.join(base, kind)`) before a
    // directory read — and the taint trace runs through a *different* branch, so `base` is not in
    // the trace. Taint must still propagate through the base-building assignment so the appended
    // enum slot and its accepted values are recovered.
    let source = r#"
          app.get('/resources/:module/:kind', async c => {
            const { module: mod, kind } = c.req.param();
            const base = path.resolve(__dirname, '..', '..', 'mcp_resources', mod);
            if (!['info', 'docs', 'examples'].includes(kind)) {
              return c.json({ error: 'nope' }, 400);
            }
            const dirPath = path.join(base, kind);
            if (!fs.existsSync(dirPath)) {
              const moduleDir = path.resolve(__dirname, '..', '..', 'mcp_modules', mod);
              const fallbackDir = path.join(moduleDir, 'docs');
              const walk = dir => {
                const abs = path.join(dir, '.');
                return fs.readdirSync(abs, { withFileTypes: true });
              };
              return c.json({ files: walk(fallbackDir) });
            }
          });
        "#;
    let mut f = finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("GET /resources/{module}/{kind}"),
        "c.req.param()",
    );
    f.sink.api = "fs.readdirSync".to_owned();
    f.sink.arg = "abs".to_owned();
    // The reported trace runs through the fallback branch (moduleDir/fallbackDir), never `base`.
    f.trace = ["mod", "moduleDir", "fallbackDir", "dir", "abs"]
        .iter()
        .map(|name| TraceStep {
            file: None,
            line: 1,
            col: 1,
            note: format!("assigned to `{name}`"),
        })
        .collect();
    let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
    assert_eq!(probe.entry, Entry::PathParam("module".to_owned()));
    assert!(probe.lists_dir);
    // Taint reaching `base` through `path.resolve(.., mod)` is what lets the appended enum slot be
    // recovered: without it the sibling is appended after an untainted name and never driven.
    let ap = probe
        .appended_param
        .expect("enum slot recovered through the base-derived taint");
    assert_eq!(ap.name, "kind");
    assert_eq!(
        ap.values,
        vec!["info".to_owned(), "docs".to_owned(), "examples".to_owned()]
    );
}

#[test]
fn a_coarse_headers_source_resolves_the_host_header_from_the_handler() {
    // The finding names only `req.headers`; the handler reads `req.headers["wx-host"]` as the
    // request host (and an unrelated header in a logged field). The host one is recovered.
    let source = r#"
          const proxyRequestSettings = {
            host: req.headers["wx-host"] ?? "api.weather.gov",
            port: 443,
            headers: { pragma: req.headers.pragma },
          };
          https.request(proxyRequestSettings);
        "#;
    let mut f = finding(
        VulnClass::Ssrf,
        Auth::NoneDetected,
        Some("GET /{any}"),
        "req.headers",
    );
    f.sink.arg = "proxyRequestSettings".to_owned();
    let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
    assert_eq!(probe.entry, Entry::Header("wx-host".to_owned()));
    // Without the source it stays unresolved, not guessed.
    assert!(Probe::from_finding(&f).is_err());
}

#[test]
fn an_unrelated_coarse_header_is_not_taken() {
    // No header sits in a request-target position: nothing is resolved.
    let source = r#"
          log({ pragma: req.headers.pragma });
          fetch("https://api.example.test/fixed");
        "#;
    let f = finding(
        VulnClass::Ssrf,
        Auth::NoneDetected,
        Some("GET /{any}"),
        "req.headers",
    );
    assert!(Probe::from_finding_with_source(&f, Some(source)).is_err());
}

#[test]
fn headers_in_both_forms() {
    for expr in ["req.headers['x-forward']", "req.get('X-Forward')"] {
        let probe = Probe::from_finding(&finding(
            VulnClass::Ssrf,
            Auth::NoneDetected,
            Some("GET /proxy"),
            expr,
        ))
        .unwrap();
        assert_eq!(probe.entry, Entry::Header("x-forward".to_owned()));
    }
}

#[test]
fn a_catch_all_reads_the_url_itself() {
    let probe = Probe::from_finding(&finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("ANY /{wildcard}"),
        "req.url",
    ))
    .unwrap();
    assert_eq!(probe.entry, Entry::Url);
    assert_eq!(probe.method.verb(&probe.entry), "GET");
}

/// Optional chaining reads the same request input: `request?.url`, `req.query?.name`,
/// `req.headers?.["x"]`. A conditional before a number is not optional chaining.
#[test]
fn optional_chaining_names_the_same_input() {
    for (expr, entry) in [
        ("request?.url", Entry::Url),
        ("req?.query?.name", Entry::Query("name".to_owned())),
        (
            "req.headers?.['x-forward']",
            Entry::Header("x-forward".to_owned()),
        ),
    ] {
        let probe = Probe::from_finding(&finding(
            VulnClass::Ssrf,
            Auth::NoneDetected,
            Some("ANY /{wildcard}"),
            expr,
        ))
        .unwrap();
        assert_eq!(probe.entry, entry, "{expr}");
    }
    assert_eq!(
        super::without_optional_chaining("a?.b?.[c]?.(d) ? x :y?.5:1"),
        "a.b[c](d) ? x :y?.5:1"
    );
}

#[test]
fn a_value_position_sql_injection_is_mapped_to_a_quote_breakout() {
    // A login handler interpolates a body field into a quoted string-literal position of a SQL
    // statement. This is a value, not a table name, so the identifier plan declines it; the
    // value-position plan recovers the enclosing quote so the sandbox can drive a boolean breakout.
    let source = "models.sequelize.query(`SELECT * FROM Users WHERE email = \
            '${req.body.email || ''}' AND password = '${hash(req.body.password || '')}' \
            AND deletedAt IS NULL`, { plain: true })";
    let mut f = finding(
        VulnClass::SqlInjection,
        Auth::NoneDetected,
        Some("POST /rest/user/login"),
        "req.body.email",
    );
    f.sink.api = ".query".to_owned();
    let probe = Probe::from_finding_with_source(&f, Some(source)).unwrap();
    assert_eq!(probe.entry, Entry::Body(Some("email".to_owned())));
    assert!(
        sql_plan_for(&f, &probe.entry, source).is_none(),
        "a quoted value is not an identifier substitution"
    );
    let value =
        sql_value_plan_for(&f, &probe.entry, source).expect("value-position injection mapped");
    assert_eq!(value.quote, '\'');

    // An identifier position (`FROM ${table}`) is driven by the identifier plan, not misread as a
    // value breakout.
    let id_source = "const { table } = req.body; \
            db.query(`SELECT id FROM ${table} WHERE id = 1`)";
    let mut idf = finding(
        VulnClass::SqlInjection,
        Auth::NoneDetected,
        Some("POST /x"),
        "req.body.table",
    );
    idf.sink.api = ".query".to_owned();
    idf.sink.arg = "`SELECT id FROM ${table} WHERE id = 1`".to_owned();
    let idp = Probe::from_finding_with_source(&idf, Some(id_source)).unwrap();
    assert!(sql_value_plan_for(&idf, &idp.entry, id_source).is_none());

    // A later destructive statement in the same handler does not turn this SELECT finding into
    // a DELETE finding; the oracle is selected from the reported sink argument.
    let mixed = "const { table } = req.body; \
            db.query(`SELECT id FROM ${table} WHERE id = 1`); \
            db.query(`DELETE FROM ${table} WHERE id = ?`)";
    assert!(
        sql_plan_for(&idf, &idp.entry, mixed)
            .expect("the SELECT identifier remains driveable")
            .delete
            .is_none()
    );

    // A non-SQL template carrying the same interpolation is not treated as a SQL value position.
    let html = "res.send(`<p>${req.body.email}</p>`)";
    assert!(sql_value_plan_for(&f, &probe.entry, html).is_none());
}

#[test]
fn entry_from_request_expr_reads_body_query_and_param_accesses() {
    assert_eq!(
        entry_from_request_expr("req.body.username"),
        Some(Entry::Body(Some("username".to_owned())))
    );
    assert_eq!(
        entry_from_request_expr("req.query.q"),
        Some(Entry::Query("q".to_owned()))
    );
    assert_eq!(
        entry_from_request_expr("req.params.id"),
        Some(Entry::PathParam("id".to_owned()))
    );
    assert_eq!(entry_from_request_expr("req.body[\'name\']"), None);
    assert_eq!(entry_from_request_expr("req.headers.x"), None);
    assert_eq!(entry_from_request_expr("req.body"), None);
}

#[test]
fn text_wrap_mines_the_literal_scaffold_around_a_regex_capture_group() {
    // A common text-envelope convention: a plain `.match()` guard, then a `.substring()` unwrap.
    let source = "let username = user.username\n\
            if (username?.match(/#{(.*)}/) !== null) {\n  \
            const code = username?.substring(2, username.length - 1)\n  \
            username = eval(code)\n}";
    let tainted = vec!["code".to_owned(), "username".to_owned()];
    let wrap = text_wrap(source, &tainted).expect("the wrap convention is found");
    assert_eq!(wrap.prefix, "#{");
    assert_eq!(wrap.suffix, "}");

    // Found through whichever tainted alias the handler actually tests, not only the first.
    let tainted_code_first = vec!["code".to_owned()];
    assert!(text_wrap(source, &tainted_code_first).is_none());

    // A handler that reaches the sink unwrapped has no such convention.
    assert!(text_wrap("eval(username)", &tainted).is_none());

    // A guard with no capturing group (nothing to unwrap) is not mistaken for a wrap.
    assert!(text_wrap("if (username.match(/^[a-z]+$/)) eval(username)", &tainted).is_none());
}

#[test]
fn a_stored_source_plans_the_write_that_saves_it_and_the_read_that_reaches_the_sink() {
    // The sink's own source is the loaded record's field (`user.username`); the finding carries
    // the request that saved it (`POST /profile`, `req.body.username`).
    let mut f = finding(
        VulnClass::CodeInjection,
        Auth::User,
        Some("GET /profile"),
        "user.username",
    );
    f.source.kind = "stored";
    f.stored_by = Some(jss_core::StoredBy {
        entry: Some("POST /profile".to_owned()),
        expr: "req.body.username".to_owned(),
        file: "routes/updateUserProfile.ts".to_owned(),
        line: 38,
    });
    let probe = Probe::from_finding(&f).expect("a stored source should plan");
    assert_eq!(probe.method, Method::Get);
    assert_eq!(probe.path, "/profile");
    let write = probe.stored_write.expect("the write that saves the value");
    assert_eq!(write.method, Method::Post);
    assert_eq!(write.path, "/profile");
    assert_eq!(write.entry, Entry::Body(Some("username".to_owned())));
    // Login-gated, like any other `auth: user` finding.
    assert!(probe.auth.is_some_and(|b| b.route_gate));

    // No write side known: skipped, not silently sent anonymously.
    let mut no_write = f.clone();
    no_write.stored_by = None;
    assert_eq!(
        Probe::from_finding(&no_write).unwrap_err().0,
        "no entry point saves the value this sink reads back from the store"
    );

    // SQL/NoSQL second-order flows are not driven yet: skipped with a clear reason, not guessed.
    let mut sql = f.clone();
    sql.class = VulnClass::SqlInjection;
    assert_eq!(
        Probe::from_finding(&sql).unwrap_err().0,
        "a second-order sql-injection (one request stores the value, another reads it back) is not driven by verify v1 yet"
    );
}

#[test]
fn login_gated_findings_plan_with_a_pending_registered_session() {
    // A route behind login middleware is planned, carrying a route-level bootstrap whose
    // endpoints are mined later from the project's route sources.
    let probe = Probe::from_finding(&finding(
        VulnClass::PathTraversal,
        Auth::User,
        Some("GET /x"),
        "req.query.n",
    ))
    .unwrap();
    let boot = probe.auth.expect("a login-gated probe carries a bootstrap");
    assert!(boot.route_gate);
    assert!(!boot.default_credentials);
    assert!(boot.login_paths.is_empty() && boot.register_paths.is_empty());
    // The same route without auth carries none.
    let open = Probe::from_finding(&finding(
        VulnClass::PathTraversal,
        Auth::NoneDetected,
        Some("GET /x"),
        "req.query.n",
    ))
    .unwrap();
    assert!(open.auth.is_none());
    // Command injection behind login is planned the same way.
    let mut cmd = finding(
        VulnClass::CommandInjection,
        Auth::User,
        Some("GET /x"),
        "req.query.n",
    );
    cmd.sink.api = "child_process.exec".to_owned();
    assert!(
        Probe::from_finding(&cmd)
            .unwrap()
            .auth
            .is_some_and(|b| b.route_gate)
    );
    // File-create/delete oracles carry the same minted session as the generic request matrix.
    let mut create = finding(
        VulnClass::PathTraversal,
        Auth::User,
        Some("POST /x"),
        "req.body.n",
    );
    create.sink.api = "fs.writeFile".to_owned();
    let create = Probe::from_finding(&create).unwrap();
    assert!(create.creates);
    assert!(create.auth.is_some_and(|boot| boot.route_gate));
}

#[test]
fn registration_fields_come_from_the_module_that_reads_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("core")).unwrap();
    // A passport signup strategy in its own module requires a confirmation and a display name.
    std::fs::write(
            root.join("core/passport.js"),
            "if (req.body.email && req.body.password && req.body.username && req.body.cpassword && req.body['name']) {\n\
             db.User.create({ role: req.body.role }) }\n",
        )
        .unwrap();
    // Destructured from the body in another handler that reads a password.
    std::fs::write(
        root.join("core/account.js"),
        "const { fullName, password: pw, isAdmin } = req.body;\n",
    )
    .unwrap();
    // A module that reads no password contributes nothing.
    std::fs::write(
        root.join("core/notes.js"),
        "const title = req.body.title; req.body.nickname;\n",
    )
    .unwrap();
    let fields = registration_fields(root);
    for expected in [
        "email",
        "password",
        "username",
        "cpassword",
        "name",
        "fullName",
    ] {
        assert!(
            fields.iter().any(|f| f == expected),
            "{expected} in {fields:?}"
        );
    }
    // Never an attribute a visitor should not choose, nor a field from an unrelated module.
    for absent in ["role", "isAdmin", "title", "nickname"] {
        assert!(
            !fields.iter().any(|f| f == absent),
            "{absent} in {fields:?}"
        );
    }
}

#[test]
fn project_auth_endpoints_mines_routes_split_across_modules() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("routes")).unwrap();
    std::fs::create_dir_all(root.join("node_modules/dep")).unwrap();
    std::fs::write(
        root.join("routes/auth.js"),
        "router.post('/api/auth/login-options', o);\nrouter.post('/api/auth/login', login);\n",
    )
    .unwrap();
    std::fs::write(
        root.join("routes/users.js"),
        "router.post('/api/users', create);\nrouter.get('/api/users/:id', show);\n",
    )
    .unwrap();
    std::fs::write(
        root.join("routes/files.js"),
        "router.get('/api/files', requireAuth, read);\n",
    )
    .unwrap();
    // Dependencies are not the app's routes.
    std::fs::write(
        root.join("node_modules/dep/index.js"),
        "app.post('/dep/signin', x);\n",
    )
    .unwrap();
    let (login, register) = project_auth_endpoints(root);
    // The exact-verb login ranks before the lookalike, across files.
    assert_eq!(login, vec!["/api/auth/login", "/api/auth/login-options"]);
    assert_eq!(register, vec!["/api/users"]);
}

#[test]
fn ineligible_findings_are_skipped_with_a_reason() {
    // A role gate: a self-registered account cannot reach it.
    assert_eq!(
        Probe::from_finding(&finding(
            VulnClass::PathTraversal,
            Auth::Admin,
            Some("GET /x"),
            "req.query.n"
        ))
        .unwrap_err()
        .0,
        "reaching it needs admin authentication, which verify v1 does not perform"
    );
    // SQL/NoSQL semantic oracles now carry the same minted session on every differential leg.
    let sql = Probe::from_finding(&finding(
        VulnClass::SqlInjection,
        Auth::User,
        Some("GET /x"),
        "req.query.n",
    ))
    .unwrap();
    assert!(sql.auth.is_some_and(|boot| boot.route_gate));
    // Not an HTTP source.
    let mut dom = finding(
        VulnClass::Xss,
        Auth::NoneDetected,
        Some("GET /x"),
        "req.query.n",
    );
    dom.source.kind = "dom";
    assert!(Probe::from_finding(&dom).is_err());
    // SQL injection is HTTP-driveable, but without handler source the planner conservatively
    // leaves its semantic differential absent; the sandbox will skip rather than claiming a
    // token merely reached SQL text.
    let sql = Probe::from_finding(&finding(
        VulnClass::SqlInjection,
        Auth::NoneDetected,
        Some("GET /x"),
        "req.query.n",
    ))
    .unwrap();
    assert_eq!(sql.class, VulnClass::SqlInjection);
    assert!(sql.sql.is_none());
    // No entry point.
    assert!(
        Probe::from_finding(&finding(
            VulnClass::PathTraversal,
            Auth::NoneDetected,
            None,
            "req.query.n"
        ))
        .is_err()
    );
}

#[test]
fn a_parsed_document_body_field_is_packed_into_the_scaffold_the_parser_requires() {
    // A handler passes a tainted body field to a parse function defined in another module, then
    // chooses the outbound host from one member of the parsed result and guards on another. The
    // planner must recover, from the handler and the parser's own source, which JSON key reaches
    // the sink, which other members to fill, and the literal frontmatter scaffold the parser's
    // extraction regexes require around the embedded JSON object.
    let handler = r#"
          router.post('/connect', async (req, res) => {
            const { blob } = req.body;
            const parsed = parseDoc(blob);
            if (!parsed) return res.status(400).json({ error: 'bad' });
            const dest = parsed.endpoint || 'https://default';
            if (!parsed.ticket) return res.status(400).json({ error: 'no ticket' });
            const resp = await fetch(`${dest}/go`, { method: 'POST' });
          });
        "#;
    let module = r#"
          export function parseDoc(content) {
            if (!content) return null;
            const fm = content.match(/^===\s*\n([\s\S]*?)\n===/);
            if (!fm) return null;
            const m = fm[1].match(/meta:\s*(\{[\s\S]*?\})\s*$/m);
            if (!m) return null;
            try {
              const obj = JSON.parse(m[1]);
              return { endpoint: obj.host_url, ticket: obj.token };
            } catch { return null; }
          }
        "#;
    let mut f = finding(
        VulnClass::Ssrf,
        Auth::NoneDetected,
        Some("POST /connect"),
        "req.body",
    );
    f.sink.api = "fetch".to_owned();
    f.sink.arg = "dest".to_owned();
    f.trace = vec![TraceStep {
        file: None,
        line: 1,
        col: 1,
        note: "assigned to `dest`".to_owned(),
    }];

    let entry = Entry::Body(Some("blob".to_owned()));
    let doc = doc_envelope(&f, &entry, handler, module).expect("document envelope recognized");
    assert_eq!(doc.sink_key, "host_url");
    assert_eq!(doc.filler_keys, vec!["token".to_owned()]);
    assert_eq!(doc.prefix, "===\nmeta:");
    assert_eq!(doc.suffix, "\n===");
}

#[test]
fn sql_identifier_plan_preserves_result_column_case_and_required_body_fields() {
    let source = r#"
          router.post('/api/info/:tableName/:provider', async (req, res) => {
            const { tableName } = req.params;
            const { id } = req.body;
            const row = db.prepare(
              `SELECT DisplayValue, provider FROM ${tableName}
               WHERE MalID = ? AND LOWER(title) = LOWER(?)`
            ).get(id, id);
            res.json(row);
          });
        "#;

    let plan = sql_identifier_plan(source, &["tableName".to_owned()])
        .expect("table-identifier injection is driveable");
    assert!(
        plan.columns
            .iter()
            .any(|column| column.name == "DisplayValue" && !column.filter)
    );
    assert!(
        plan.columns
            .iter()
            .any(|column| column.name == "MalID" && column.filter)
    );
    assert!(
        plan.columns
            .iter()
            .any(|column| column.name == "title" && column.filter)
    );
    assert!(plan.body_fields.contains(&"id".to_owned()));

    let value_position = "db.prepare(`SELECT * FROM items WHERE title = '${tableName}'`)";
    assert!(sql_identifier_plan(value_position, &["tableName".to_owned()]).is_none());
}

#[test]
fn quoted_delete_identifier_is_detected_as_a_destructive_injection() {
    // A tainted identifier interpolated into a *double-quoted* table position of a DELETE is both
    // recognized (the opening quote no longer hides the preceding `FROM`) and marked destructive,
    // with the breakout parameters mined: the quote to close and the bound-placeholder count.
    let source = r#"
          router.post('/api/items/remove', async (req, res) => {
            let { bucket, accountKey } = req.body;
            const tableName = bucket;
            await db.prepare(
              `DELETE FROM "${tableName}" WHERE account_key = ? OR tenant_key = ?`
            ).run(accountKey, "public");
          });
        "#;
    let plan = sql_identifier_plan(source, &["tableName".to_owned()])
        .expect("quoted table-identifier DELETE is driveable");
    let delete = plan
        .delete
        .as_ref()
        .expect("the DELETE is marked destructive");
    assert_eq!(delete.quote, Some('"'));
    assert_eq!(delete.placeholders, 2);
    assert!(
        plan.columns
            .iter()
            .any(|c| c.name == "account_key" && c.filter)
    );
    assert!(
        plan.columns
            .iter()
            .any(|c| c.name == "tenant_key" && c.filter)
    );

    // A non-destructive SELECT in an identifier position carries no destructive plan.
    let select = "db.prepare(`SELECT * FROM ${tableName} WHERE account_key = ?`).get(key)";
    assert!(
        sql_identifier_plan(select, &["tableName".to_owned()])
            .expect("select identifier is driveable")
            .delete
            .is_none()
    );

    // A value-position quote is not an identifier quote: no destructive plan is produced.
    let value = "db.prepare(`DELETE FROM items WHERE name = '${tableName}'`).run()";
    assert!(sql_delete_identifier(value, &["tableName".to_owned()]).is_none());
}

#[test]
fn mongoose_schema_types_produce_json_safe_sibling_fillers() {
    let source = r#"
const userSchema = new mongoose.Schema({
  username: String,
  coin: Number,
  active: Boolean,
  tags: [String],
  scores: [Number],
  nested: { type: String },
  authProvider: {
    type: String,
    enum: ['local', 'google'],
    default: 'local'
  }
})
"#;
    assert_eq!(
        mongoose_schema_fillers(source),
        vec![
            ("username".to_owned(), "jsspector".to_owned()),
            ("coin".to_owned(), "1".to_owned()),
            ("active".to_owned(), "true".to_owned()),
            ("tags".to_owned(), "[\"jsspector\"]".to_owned()),
            ("scores".to_owned(), "[1]".to_owned()),
            ("authProvider".to_owned(), "local".to_owned()),
        ]
    );
}
