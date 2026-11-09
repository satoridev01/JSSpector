//! End-to-end tests of `jsspector routes` and cross-file `jsspector scan` on temporary trees.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn run(args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_jsspector"))
        .args(args)
        .env_remove("RAYON_NUM_THREADS")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn write(root: &Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

/// An Express app that mounts a router from another file, which calls a service in a third.
fn app(root: &Path) {
    write(
        root,
        "src/app.js",
        "const express = require('express');\nconst users = require('./routes/users');\n\
         const app = express();\napp.use('/api/v1', requireAuth, users);\n\
         app.use('/health', require('./routes/health'));\nmodule.exports = app;\n",
    );
    write(
        root,
        "src/routes/users.js",
        "const router = require('express').Router();\nconst svc = require('../services/users');\n\
         router.get('/users/:id', (req, res) => svc.find(req.query.name));\n\
         router.post('/users', (req, res) => res.json(req.body.email));\nmodule.exports = router;\n",
    );
    write(
        root,
        "src/routes/health.js",
        "const express = require('express');\nconst r = express.Router();\nr.get('/', (req, res) => res.end());\nmodule.exports = r;\n",
    );
    write(
        root,
        "src/services/users.js",
        "const db = require('../db');\nexports.find = function find(name) {\n  \
         return db.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\");\n};\n",
    );
    write(root, "src/db.js", "module.exports = { query() {} };\n");
    // A client-side call is not a route.
    write(
        root,
        "client/api.js",
        "export const load = () => $http.get('/api/v1/users', { params: {} });\n",
    );
}

#[test]
fn routes_follow_mounts_across_files_and_export_openapi() {
    let dir = tempfile::tempdir().unwrap();
    app(dir.path());
    let root = dir.path().to_str().unwrap();
    let routes = run(&["routes", "--json", root]);
    let list: Vec<(String, String)> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["method"].as_str().unwrap().to_owned(),
                r["path"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert!(
        list.contains(&("GET".into(), "/api/v1/users/{id}".into())),
        "{list:?}"
    );
    assert!(
        list.contains(&("POST".into(), "/api/v1/users".into())),
        "{list:?}"
    );
    assert!(list.contains(&("GET".into(), "/health".into())), "{list:?}");
    assert_eq!(list.len(), 3, "client calls are not routes: {list:?}");
    let get = routes
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["path"] == "/api/v1/users/{id}")
        .unwrap();
    assert_eq!(get["inputs"][0], "query.name");

    let openapi = run(&["routes", "--openapi", root]);
    assert_eq!(openapi["openapi"], "3.1.0");
    let op = &openapi["paths"]["/api/v1/users/{id}"]["get"];
    let params: Vec<&str> = op["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(params, ["id", "name"]);
    assert!(openapi["paths"]["/api/v1/users"]["post"]["requestBody"].is_object());
}

#[test]
fn scan_links_a_route_to_a_sink_two_files_away() {
    let dir = tempfile::tempdir().unwrap();
    app(dir.path());
    let report = run(&["scan", "--json", dir.path().to_str().unwrap()]);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["class"], "sql-injection");
    assert_eq!(findings[0]["file"], "src/routes/users.js");
    assert_eq!(findings[0]["sink"]["file"], "src/services/users.js");
    // What issue trackers show: a readable title, the sink's location, a description, the fix.
    assert_eq!(
        findings[0]["title"],
        "SQL injection in GET /api/v1/users/{id}: req.query reaches db.query"
    );
    assert_eq!(findings[0]["resource"], "src/services/users.js:3");
    let description = findings[0]["description"].as_str().unwrap();
    assert!(
        description.starts_with("Data from `req.query` (http) is concatenated into an SQL query: `db.query`. It is reachable from `GET /api/v1/users/{id}` by any logged-in user.\n\n"),
        "{description}"
    );
    // The excerpt: one bullet per file in flow order (the route, then the service it calls),
    // each line annotated with its step; the sink with the two lines above it.
    let affected = findings[0]["affected"].as_str().unwrap();
    let routes = affected.find("- `src/routes/users.js`").expect(affected);
    let service = affected.find("- `src/services/users.js`").expect(affected);
    assert!(routes < service, "{affected}");
    assert!(
        affected.contains("router.get('/users/:id', (req, res) => svc.find(req.query.name));"),
        "{affected}"
    );
    assert!(
        affected.contains("// [1] entry: GET /api/v1/users/{id}, logged-in users"),
        "{affected}"
    );
    assert!(
        affected.contains("exports.find = function find(name) {"),
        "{affected}"
    );
    assert!(
        affected.contains("// [") && affected.contains("] VULNERABLE: req.query reaches db.query"),
        "{affected}"
    );
    assert!(
        findings[0]["remediation"]
            .as_str()
            .is_some_and(|r| r.contains("placeholders") || r.contains("parameter")),
        "{}",
        findings[0]["remediation"]
    );
}

#[test]
fn versioned_dynamic_mounts_link_anonymous_default_routers_and_class_instances() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "server/routes.js",
        "export default async function routes(app) {\n\
         for (const v of app.get('apiVersions')) {\n\
           const { default: router } = await import(`./apis/v${v}/router.js`);\n\
           app.use(`/api/v${v}`, router);\n\
         }\n}\n",
    );
    write(
        root,
        "server/apis/v2/router.js",
        "import express from 'express';\n\
         import files from './files/router.js';\n\
         export default express.Router().use('/files', files);\n",
    );
    write(
        root,
        "server/apis/v2/files/router.js",
        "import express from 'express';\n\
         import controller from './controller.js';\n\
         export default express.Router().get('/:name', controller.read);\n",
    );
    write(
        root,
        "server/apis/v2/files/controller.js",
        "import fs from 'fs';\n\
         class Controller {\n\
           read(req, res) { return fs.readFile(req.params.name, () => res.end()); }\n\
         }\n\
         export default new Controller();\n",
    );

    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    assert!(
        routes
            .as_array()
            .unwrap()
            .iter()
            .any(|route| { route["method"] == "GET" && route["path"] == "/api/v2/files/{name}" }),
        "{routes}"
    );

    let report = run(&["scan", "--json", root.to_str().unwrap()]);
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["class"] == "path-traversal")
        .expect("the class-instance handler should remain linked to its full route");
    assert_eq!(finding["entry"], "GET /api/v2/files/{name}");
}

#[test]
fn provider_resource_routes_use_the_deployed_metadata_prefix() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "apps/widget/metadata.json",
        r#"{"name":"deployed-widget"}"#,
    );
    write(
        dir.path(),
        "apps/widget/server.js",
        "const axios = require('axios');\n\
         module.exports = (core, proc) => ({ init() {\n\
           const { app } = core;\n\
           app.post(proc.resource('/fetch'), async (req, res) => {\n\
             res.send(await axios.get(req.body.url));\n\
           });\n\
         }});\n",
    );
    let root = dir.path().to_str().unwrap();
    let routes = run(&["routes", "--json", root]);
    assert_eq!(routes[0]["path"], "/apps/deployed-widget/fetch", "{routes}");

    let report = run(&["scan", "--json", root]);
    let finding = &report["findings"][0];
    assert_eq!(finding["entry"], "POST /apps/deployed-widget/fetch");
}

#[test]
fn nestjs_controllers_route_and_injected_services_are_followed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/users/users.controller.ts",
        "import { Controller, Get, Query, UseGuards } from '@nestjs/common';\n\
         import { UsersService } from './users.service';\n\
         @Controller('users')\nexport class UsersController {\n  constructor(private readonly users: UsersService) {}\n\
         @Get('search')\n  search(@Query('q') q: string) { return this.users.find(q); }\n\
         @UseGuards(AuthGuard)\n  @Get(':id')\n  one(@Query('id') id: string) { return id; }\n}\n",
    );
    write(
        root,
        "src/users/users.service.ts",
        "export class UsersService {\n  constructor(private readonly db: any) {}\n\
         find(q: string) { return this.db.query(`SELECT * FROM users WHERE name = '${q}'`); }\n}\n",
    );
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let list: Vec<(String, String, String)> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["method"].as_str().unwrap().to_owned(),
                r["path"].as_str().unwrap().to_owned(),
                r["auth"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert!(
        list.contains(&("GET".into(), "/users/search".into(), "none-detected".into())),
        "{list:?}"
    );
    assert!(
        list.contains(&("GET".into(), "/users/{id}".into(), "user".into())),
        "{list:?}"
    );

    let report = run(&["scan", "--json", root.to_str().unwrap()]);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["class"], "sql-injection");
    assert_eq!(findings[0]["sink"]["file"], "src/users/users.service.ts");
}

#[test]
fn route_tables_helpers_fastify_graphql_and_trpc_are_inventoried() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "server.js",
        "const express = require('express');\nconst router = express.Router();\n\
         const routes = [\n  { method: 'get', path: '/a', handler: listA },\n  { method: 'post', path: '/b', handler: makeB },\n];\n\
         routes.forEach((r) => router[r.method](r.path, r.handler));\n\
         for (const r of [{ method: 'delete', path: '/c', handler: delC }]) { router[r.method](r.path, r.handler); }\n\
         function add(path, handler) { router.put(path, handler); }\nadd('/d', putD);\n\
         const fastify = require('fastify')();\nfastify.route({ method: 'PATCH', url: '/e', handler: async (request, reply) => 1 });\n\
         const resolvers = { Query: { user(parent, args) { return args.id; } } };\n\
         const appRouter = t.router({ getUser: t.procedure.input(z.string()).query(({ input }) => input) });\n",
    );
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let list: Vec<String> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{} {}",
                r["method"].as_str().unwrap(),
                r["path"].as_str().unwrap()
            )
        })
        .collect();
    for expected in [
        "GET /a",
        "POST /b",
        "PUT /d",
        "PATCH /e",
        "QUERY user",
        "TRPC.QUERY getUser",
    ] {
        assert!(
            list.iter().any(|r| r == expected),
            "{expected} missing from {list:?}"
        );
    }
}

#[test]
fn ir_lowers_modules_and_links_calls_across_files() {
    let dir = tempfile::tempdir().unwrap();
    app(dir.path());
    let ir = run(&["ir", dir.path().to_str().unwrap()]);
    let modules = ir["modules"].as_array().unwrap();
    let service = modules
        .iter()
        .find(|m| m["file"] == "src/services/users.js")
        .unwrap();
    let find = service["functions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "find")
        .unwrap();
    assert_eq!(find["params"][0], "name");
    assert_eq!(find["flows"][0]["to"]["kind"], "sink");
    assert_eq!(find["flows"][0]["to"]["class"], "sql-injection");
    let routes = modules
        .iter()
        .find(|m| m["file"] == "src/routes/users.js")
        .unwrap();
    let svc = routes["imports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["local"] == "svc")
        .unwrap();
    assert_eq!(svc["resolved"], "src/services/users.js");
    let edges = &ir["call_graph"]["edges"];
    let callees = edges["src/routes/users.js#GET /users/:id"]
        .as_array()
        .unwrap();
    assert!(
        callees.iter().any(|c| c == "src/services/users.js#find"),
        "{callees:?}"
    );
    assert!(ir["call_graph"]["cross_module"].as_u64().unwrap() >= 1);
}

#[test]
fn workspace_packages_and_barrels_are_followed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "packages/components/package.json",
        r#"{ "name": "acme-components", "main": "dist/index.js" }"#,
    );
    write(
        root,
        "packages/components/src/index.ts",
        "export * from './storage';\n",
    );
    write(
        root,
        "packages/components/src/storage.ts",
        "import fs from 'fs';\nimport path from 'path';\n\
         export const streamFile = (id: string, name: string) => fs.createReadStream(path.join('/data', id, name));\n",
    );
    write(
        root,
        "packages/server/package.json",
        r#"{ "name": "acme-server" }"#,
    );
    write(
        root,
        "packages/server/src/controller.ts",
        "import { streamFile } from 'acme-components';\n\
         export const download = (req: any, res: any) => streamFile(req.query.id, req.query.name).pipe(res);\n",
    );
    let report = run(&["scan", "--json", root.to_str().unwrap()]);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["class"], "path-traversal");
    assert_eq!(
        findings[0]["sink"]["file"],
        "packages/components/src/storage.ts"
    );
}

#[test]
fn route_helpers_across_files_build_paths_and_factories_mount_their_router() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // NodeBB-style helpers: the path is built from a parameter, the method can be one too.
    write(
        root,
        "src/routes/helpers.js",
        "const helpers = module.exports;\n\
         helpers.setupPageRoute = function (router, name, controller) {\n  router.get(name, controller);\n  router.get(`/api${name}`, controller);\n};\n\
         helpers.setupApiRoute = function (router, verb, name, controller) {\n  router[verb](name, controller);\n};\n",
    );
    write(
        root,
        "src/routes/write/users.js",
        "const router = require('express').Router();\nconst routeHelpers = require('../helpers');\nconst { setupApiRoute } = routeHelpers;\n\
         module.exports = function () {\n  setupApiRoute(router, 'get', '/:uid', controllers.get);\n  setupApiRoute(router, 'delete', '/:uid', controllers.del);\n  return router;\n};\n",
    );
    write(
        root,
        "src/routes/write/index.js",
        "const express = require('express');\nconst router = express.Router();\nrouter.use('/api/v3/users', require('./users')());\nmodule.exports = router;\n",
    );
    write(
        root,
        "src/routes/index.js",
        "const helpers = require('./helpers');\nconst { setupPageRoute } = helpers;\n\
         function mainRoutes(app) {\n  setupPageRoute(app, '/login', controllers.login);\n  setupPageRoute(app, '/search', controllers.search);\n}\n\
         module.exports = mainRoutes;\n",
    );
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let list: Vec<String> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{} {}",
                r["method"].as_str().unwrap(),
                r["path"].as_str().unwrap()
            )
        })
        .collect();
    for expected in [
        "GET /api/v3/users/{uid}",
        "DELETE /api/v3/users/{uid}",
        "GET /login",
        "GET /api/login",
        "GET /api/search",
    ] {
        assert!(
            list.iter().any(|r| r == expected),
            "{expected} missing from {list:?}"
        );
    }
}

#[test]
fn nest_prefixes_from_imported_enums_through_tsconfig_paths_and_controller_auth_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "server/tsconfig.json",
        "{\n  \"compilerOptions\": { \"baseUrl\": \"./\", \"paths\": { \"src/*\": [\"./src/*\"], }, },\n}\n",
    );
    write(
        root,
        "server/src/enum.ts",
        "export enum RouteKey {\n  Asset = 'assets',\n  User = 'users',\n}\n",
    );
    write(
        root,
        "server/src/controllers/asset.controller.ts",
        "import { Controller, Get } from '@nestjs/common';\nimport { RouteKey } from 'src/enum';\n\
         @Controller(RouteKey.Asset)\nexport class AssetController {\n  @Get(':id')\n  get() {}\n}\n",
    );
    write(
        root,
        "server/src/controllers/auth.controller.ts",
        "import { RestController, Get, Post } from '@n8n/decorators';\n\
         @RestController()\nexport class AuthController {\n  @Post('/login', { skipAuth: true })\n  login() {}\n  @Get('/login')\n  current() {}\n}\n",
    );
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let list: Vec<(String, String, String)> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["method"].as_str().unwrap().to_owned(),
                r["path"].as_str().unwrap().to_owned(),
                r["auth"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert!(
        list.contains(&("GET".into(), "/assets/{id}".into(), "none-detected".into())),
        "{list:?}"
    );
    assert!(
        list.contains(&("POST".into(), "/login".into(), "none-detected".into())),
        "{list:?}"
    );
    assert!(
        list.contains(&("GET".into(), "/login".into(), "user".into())),
        "{list:?}"
    );
}

#[test]
fn findings_get_their_entry_point_and_the_route_auth_from_mounts_in_other_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "app.js",
        "const express = require('express');\nconst admin = require('./admin');\nconst app = express();\n\
         app.use('/admin', requireAdmin, admin);\nmodule.exports = app;\n",
    );
    write(
        root,
        "admin.js",
        "const router = require('express').Router();\nconst { exec } = require('child_process');\n\
         const ping = (req, res) => exec('ping -c 1 ' + req.query.host);\n\
         router.get('/ping', ping);\nmodule.exports = router;\n",
    );
    let report = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["entry"], "GET /admin/ping");
    assert_eq!(findings[0]["auth"], "admin");
    // Admin-only: critical command injection reported one level lower.
    assert_eq!(findings[0]["severity"], "high");
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    assert_eq!(routes[0]["auth"], "admin");
}

/// Middleware applies to the routes registered after it, on that router only.
#[test]
fn middleware_auth_follows_registration_order_and_router() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "app.js",
        "const express = require('express');\nconst { exec } = require('child_process');\n\
         const app = express();\n\
         app.get('/run', (req, res) => { exec('ls ' + req.query.dir); });\n\
         app.use(requireAdmin);\n\
         app.get('/admin/stats', (req, res) => res.send('ok'));\n",
    );
    write(
        root,
        "routes.js",
        "const express = require('express');\nconst { exec } = require('child_process');\n\
         function adminRoutes() { const router = express.Router(); router.use(requireAdmin); \
         router.get('/stats', (req, res) => res.send('ok')); return router; }\n\
         function publicRoutes() { const router = express.Router(); \
         router.get('/open', (req, res) => { exec('ls ' + req.query.dir); }); return router; }\n\
         module.exports = { adminRoutes, publicRoutes };\n",
    );
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let auth = |path: &str| -> String {
        routes
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["path"] == path)
            .map(|r| r["auth"].as_str().unwrap().to_owned())
            .unwrap_or_default()
    };
    assert_eq!(auth("/run"), "none-detected");
    assert_eq!(auth("/admin/stats"), "admin");
    assert_eq!(auth("/open"), "none-detected");
    assert_eq!(auth("/stats"), "admin");
    let report = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    for finding in report["findings"].as_array().unwrap() {
        assert_eq!(finding["auth"], "none-detected", "{finding}");
        assert_eq!(finding["severity"], "critical", "{finding}");
    }
}

#[test]
fn dynamically_loaded_controller_namespace_links_route_and_auth_to_findings() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "routes.js",
        "const express = require('express');\nconst app = express();\n\
         const router = express.Router();\nconst ctrl = require('./controller');\n\
         app.use(checkAuth);\nrouter.post('/subscribe/delete', ctrl.Douban.delete);\n\
         app.use('/api', router);\n",
    );
    write(
        root,
        "controller/index.js",
        "const fs = require('fs');\nconst path = require('path');\n\
         for (const file of fs.readdirSync(__dirname)) {\n  if (file !== 'index.js') {\n\
         const Ctrl = require(path.join(__dirname, file));\n\
         module.exports[file.split('.')[0]] = new Ctrl();\n  }\n}\n",
    );
    write(
        root,
        "controller/Douban.js",
        "const { execSync } = require('child_process');\n\
         class Douban { delete(req, res) { execSync(req.body.command); res.end(); } }\n\
         module.exports = Douban;\n",
    );

    let report = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let finding = &report["findings"].as_array().unwrap()[0];
    assert_eq!(finding["entry"], "POST /api/subscribe/delete");
    assert_eq!(finding["auth"], "user");
}

/// A helper reached from a public and an admin route is public; same-path inline handlers on two
/// routers of one file stay apart.
#[test]
fn findings_take_the_weakest_auth_among_reaching_routes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "app.js",
        "const express = require('express');\nconst { exec } = require('child_process');\n\
         const app = express();\n\
         function runReport(req) { exec('report ' + req.query.name); }\n\
         app.post('/admin/report', requireAdmin, (req, res) => { runReport(req); });\n\
         app.get('/public/report', (req, res) => { runReport(req); });\n\
         const publicRouter = express.Router();\nconst settingsRouter = express.Router();\n\
         publicRouter.get('/', (req, res) => { exec('ls ' + req.query.d); });\n\
         settingsRouter.get('/', requireAdmin, (req, res) => res.send('ok'));\n\
         app.use('/public', publicRouter);\napp.use('/settings', settingsRouter);\n",
    );
    let report = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2, "{findings:?}");
    for finding in findings {
        assert_eq!(finding["severity"], "critical", "{finding}");
        assert_eq!(finding["auth"], "none-detected", "{finding}");
    }
    let entries: Vec<&str> = findings
        .iter()
        .map(|f| f["entry"].as_str().unwrap())
        .collect();
    assert!(entries.contains(&"GET /public/report"), "{entries:?}");
    assert!(entries.contains(&"GET /public"), "{entries:?}");
}

/// Path-less mounts keep prefixes; mounted routers, setup middleware and non-auth guards are no
/// authentication.
#[test]
fn mounts_without_paths_and_what_is_not_auth() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "users.js",
        "const router = require('express').Router();\n\
         router.get('/users', (req, res) => res.end());\nmodule.exports = router;\n",
    );
    write(
        root,
        "api.js",
        "const router = require('express').Router();\nconst users = require('./users');\n\
         router.use(users);\nrouter.get('/health', (req, res) => res.end());\nmodule.exports = router;\n",
    );
    write(
        root,
        "adminRouter.js",
        "const router = require('express').Router();\n\
         router.get('/admin/stats', (req, res) => res.end());\nmodule.exports = router;\n",
    );
    write(
        root,
        "app.js",
        "const express = require('express');\nconst session = require('express-session');\n\
         const passport = require('passport');\nconst adminRouter = require('./adminRouter');\n\
         const app = express();\napp.use(session({ secret: 'k' }));\napp.use(passport.initialize());\n\
         app.use(adminRouter);\napp.use('/api/v1', requireAuth, require('./api'));\n\
         app.get('/search', (req, res) => res.end());\n",
    );
    write(
        root,
        "auth.controller.ts",
        "@Controller('auth')\nexport class AuthController {\n\
         @UseGuards(ThrottlerGuard)\n@Post('login')\nlogin(@Body() body) {}\n\
         @UseGuards(AdminGuard)\n@Get('purge')\npurge() {}\n}\n",
    );
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let auth = |path: &str| -> String {
        routes
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["path"] == path)
            .map(|r| r["auth"].as_str().unwrap().to_owned())
            .unwrap_or_else(|| format!("missing {path}"))
    };
    assert_eq!(auth("/api/v1/users"), "user");
    assert_eq!(auth("/api/v1/health"), "user");
    assert_eq!(auth("/search"), "none-detected");
    assert_eq!(auth("/admin/stats"), "none-detected");
    assert_eq!(auth("/auth/login"), "none-detected");
    assert_eq!(auth("/auth/purge"), "admin");
}

/// `app.use('/api', jwt())` guards the routes registered after it under `/api` only.
#[test]
fn path_scoped_middleware_guards_its_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "app.js",
        "const express = require('express');\nconst app = express();\n\
         app.get('/api/early', (req, res) => res.end());\n\
         app.use(urljoin(settings.route, 'api'), expressJwt({ secret: 'x' }));\n\
         app.get(urljoin(settings.route, 'api/state'), (req, res) => res.end());\n\
         app.get('/apiary', (req, res) => res.end());\napp.get('/', (req, res) => res.end());\n",
    );
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let auth = |path: &str| -> String {
        routes
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["path"] == path)
            .map(|r| r["auth"].as_str().unwrap().to_owned())
            .unwrap_or_else(|| format!("missing {path}"))
    };
    assert_eq!(auth("/api/state"), "user");
    assert_eq!(auth("/api/early"), "none-detected");
    assert_eq!(auth("/apiary"), "none-detected");
    assert_eq!(auth("/"), "none-detected");
}

/// Calls into other files are linked through the export tables: two hops, default and aliased
/// exports, CommonJS shapes, barrels and instances of imported classes; never to a same-named
/// function that is not the one exported.
#[test]
fn calls_link_through_export_tables() {
    let shell = "import { exec } from 'child_process';\n";
    let route = |import: &str, call: &str| {
        format!(
            "import express from 'express';\n{import}\nconst app = express();\n\
             app.get('/run', (req, res) => {{ {call}; res.end(); }});\n"
        )
    };
    // (label, files, expected findings)
    type Case<'a> = (&'a str, Vec<(&'a str, String)>, usize);
    let cases: Vec<Case<'_>> = vec![
        (
            "two hops",
            vec![
                ("routes.ts", route("import { runIt } from './services';", "runIt(req.query.cmd as string)")),
                ("services.ts", "import { execute } from './shell';\nexport function runIt(cmd: string) { return execute(cmd); }\n".to_owned()),
                ("shell.ts", format!("{shell}export function execute(c: string) {{ exec('ls ' + c); }}\n")),
            ],
            1,
        ),
        (
            "default export",
            vec![
                ("app.ts", route("import run from './shell';", "run(req.query.cmd as string)")),
                ("shell.ts", format!("{shell}export default function runCommand(c: string) {{ exec('ls ' + c); }}\n")),
            ],
            1,
        ),
        (
            "commonjs function",
            vec![
                ("app.js", "const express = require('express');\nconst runCommand = require('./shell');\nconst app = express();\napp.get('/run', (req, res) => { runCommand(req.query.cmd); res.end(); });\n".to_owned()),
                ("shell.js", "const { exec } = require('child_process');\nmodule.exports = function runCommand(c) { exec('ls ' + c); };\n".to_owned()),
            ],
            1,
        ),
        (
            "barrel alias",
            vec![
                ("app.ts", route("import { run } from './lib';", "run(req.query.cmd as string)")),
                ("lib/index.ts", "export { runCommand as run } from './shell';\n".to_owned()),
                ("lib/shell.ts", format!("{shell}export function runCommand(c: string) {{ exec('ls ' + c); }}\n")),
            ],
            1,
        ),
        (
            "instance of an imported class",
            vec![
                ("app.ts", route("import { ShellService } from './shell';\nconst shell = new ShellService();", "shell.run(req.query.cmd as string)")),
                ("shell.ts", format!("{shell}export class ShellService {{ run(c: string) {{ exec('ls ' + c); }} }}\n")),
            ],
            1,
        ),
        (
            "barrel name collision",
            vec![
                ("app.ts", route("import { normalize } from './utils';", "res.json(normalize(req.query.n as string))")),
                ("utils/index.ts", "export * from './files';\nexport * from './strings';\n".to_owned()),
                ("utils/files.ts", "import * as fs from 'fs';\nfunction normalize(p: string) { return fs.readFileSync('/d/' + p, 'utf8'); }\nexport function loadAll(l: string[]) { return l.map((p) => normalize(p)); }\n".to_owned()),
                ("utils/strings.ts", "export function normalize(s: string) { return s.trim(); }\n".to_owned()),
            ],
            0,
        ),
        (
            "local function shadowing an imported method",
            vec![
                ("app.js", "const express = require('express');\nconst { exec } = require('child_process');\nconst users = require('./users');\nconst app = express();\nfunction find(p) { exec('find /var -name ' + p); }\napp.get('/u', (req, res) => { res.json(users.find(req.query.name)); });\napp.post('/m', (req, res) => { find('*.log'); res.end(); });\n".to_owned()),
                ("users.js", "const all = [];\nexports.find = function find(name) { return all.filter((u) => u.name === name); };\n".to_owned()),
            ],
            0,
        ),
    ];
    for (label, files, expected) in cases {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in &files {
            write(dir.path(), path, text);
        }
        let report = run(&[
            "scan",
            "--json",
            "--min-severity",
            "low",
            dir.path().to_str().unwrap(),
        ]);
        let findings = report["findings"].as_array().unwrap();
        assert_eq!(findings.len(), expected, "{label}: {findings:?}");
        for finding in findings {
            assert_eq!(finding["class"], "command-injection", "{label}");
        }
    }
}

/// Express 5 parses query strings with the simple parser (no objects): no NoSQL operator
/// injection through `req.query` there; a JSON body still can carry one.
#[test]
fn express_major_version_decides_whether_query_values_can_be_objects() {
    let app = "const express = require('express');\nconst app = express();\n\
               app.get('/q', async (req, res) => { res.json(await User.findOne({ email: req.query.email })); });\n\
               app.post('/b', async (req, res) => { res.json(await User.findOne({ email: req.body.email })); });\n";
    let count = |express: &str| -> usize {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            &format!(
                "{{\"name\": \"x\", \"dependencies\": {{\"express\": \"{express}\", \"mongoose\": \"^8.0.0\"}}}}"
            ),
        );
        write(dir.path(), "src/app.js", app);
        let report = run(&[
            "scan",
            "--json",
            "--min-severity",
            "low",
            dir.path().to_str().unwrap(),
        ]);
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["class"] == "nosql-injection")
            .count()
    };
    assert_eq!(count("^4.21.2"), 2);
    assert_eq!(count("^5.3.0"), 1);
    assert_eq!(count("latest"), 2);
}

/// Monorepo resolution and mounts through barrels: tsconfig `extends`, workspace packages
/// with build output on disk, `export *` barrels, `api.router` mounts, and routes added through
/// another file's helper on that file's router.
#[test]
fn monorepo_links_and_mounts_through_barrels() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Nx-style path alias declared in the base config, inherited through `extends`.
    write(
        root,
        "tsconfig.base.json",
        "{ \"compilerOptions\": { \"baseUrl\": \".\", \"paths\": { \"@acme/shell\": [\"libs/shell/src/index.ts\"] } } }",
    );
    write(
        root,
        "apps/api/tsconfig.json",
        "{ \"extends\": \"../../tsconfig.base.json\", \"compilerOptions\": { \"outDir\": \"dist\" } }",
    );
    write(
        root,
        "libs/shell/src/index.ts",
        "import { exec } from 'child_process';\nexport function run(c: string) { exec('ls ' + c); }\n",
    );
    // A workspace package whose `main` is build output: resolved to its sources.
    write(
        root,
        "packages/db/package.json",
        "{ \"name\": \"@acme/db\", \"main\": \"dist/esm/index.js\", \"types\": \"dist/types/index.d.ts\" }",
    );
    write(
        root,
        "packages/db/dist/esm/index.js",
        "exports.query = function query() {};\n",
    );
    write(
        root,
        "packages/db/src/index.ts",
        "export function query(sql: string) { return pool.query(sql); }\n",
    );
    write(
        root,
        "apps/api/src/app.ts",
        "import express from 'express';\nimport { run } from '@acme/shell';\nimport { query } from '@acme/db';\n\
         import * as routes from './routes';\nconst app = express();\n\
         app.get('/run', (req, res) => { run(req.query.c as string); });\n\
         app.get('/q', (req, res) => { query('SELECT * FROM t WHERE id = ' + req.query.id); });\n\
         app.use('/api', requireLogin, routes.router);\n",
    );
    write(
        root,
        "apps/api/src/routes/index.ts",
        "export * from './users';\n",
    );
    write(
        root,
        "apps/api/src/routes/users.ts",
        "import express from 'express';\nexport const router = express.Router();\n\
         export function addRoute(path: string, handler: any) { router.get(path, handler); }\n\
         router.get('/users/:id', (req, res) => res.end());\n",
    );
    write(
        root,
        "apps/api/src/extra.ts",
        "import express from 'express';\nimport { addRoute } from './routes/users';\n\
         const router = express.Router();\naddRoute('/reports', listReports);\n",
    );
    let report = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let mut found: Vec<String> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["class"].as_str().unwrap().to_owned())
        .collect();
    found.sort();
    assert_eq!(found, ["command-injection", "sql-injection"], "{report}");
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let auth = |path: &str| -> String {
        routes
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["path"] == path)
            .map(|r| r["auth"].as_str().unwrap().to_owned())
            .unwrap_or_else(|| format!("missing {path}"))
    };
    assert_eq!(auth("/api/users/{id}"), "user");
    assert_eq!(auth("/api/reports"), "user");
}

/// TypeScript `import x = require()` and inline `require('./m').f()` link like any import.
#[test]
fn import_equals_and_inline_requires_link() {
    for (name, app) in [
        (
            "app.ts",
            "import shell = require('./shell');\nimport express = require('express');\n\
             const app = express();\napp.get('/r', (req, res) => { shell.run(req.query.c as string); });\n",
        ),
        (
            "app.js",
            "const app = require('express')();\n\
             app.get('/r', (req, res) => { require('./shell').run(req.query.c); });\n",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), name, app);
        write(
            dir.path(),
            if name.ends_with(".ts") {
                "shell.ts"
            } else {
                "shell.js"
            },
            "const { exec } = require('child_process');\nfunction run(c) { exec('ls ' + c); }\nmodule.exports = { run };\n",
        );
        let report = run(&[
            "scan",
            "--json",
            "--min-severity",
            "low",
            dir.path().to_str().unwrap(),
        ]);
        assert_eq!(
            report["findings"].as_array().unwrap().len(),
            1,
            "{name}: {report}"
        );
    }
}

#[test]
fn router_factories_and_next_export_forms_are_routes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "server/app.ts",
        "import express from 'express';\nimport users from './users';\nimport * as routes from './routes';\n\
         const app = express();\n\
         function makeAdmin() {\n  const r = express.Router();\n  r.get('/stats', (req, res) => res.end());\n  return r;\n}\n\
         app.use('/users', users());\napp.use('/v2', routes.items());\napp.use('/admin', makeAdmin());\n",
    );
    write(
        root,
        "server/users.ts",
        "import { Router } from 'express';\nexport default function users() {\n  const router = Router();\n  \
         router.get('/:id', (req, res) => res.json(req.params.id));\n  return router;\n}\n",
    );
    write(
        root,
        "server/routes.ts",
        "import { Router } from 'express';\nexport function items() {\n  const router = Router();\n  \
         router.post('/items', (req, res) => res.end());\n  return router;\n}\n",
    );
    // NextAuth-style re-exported handlers.
    write(
        root,
        "web/app/api/auth/[...nextauth]/route.ts",
        "import NextAuth from 'next-auth';\nconst handler = NextAuth({});\nexport { handler as GET, handler as POST };\n",
    );
    // pages/api: an anonymous default export, and a wrapped one.
    write(
        root,
        "web/pages/api/items.ts",
        "import db from '../../lib/db';\nexport default async (req, res) => {\n  \
         await db.query(\"SELECT * FROM items WHERE id = '\" + req.query.id + \"'\");\n  res.end();\n};\n",
    );
    write(
        root,
        "web/pages/api/me.ts",
        "async function handler(req, res) {\n  res.json({});\n}\nexport default withAuth(handler);\n",
    );
    // Not routes: a default export in an app route file, a named GET in pages/api.
    write(
        root,
        "web/app/api/legacy/route.ts",
        "export default function handler(req, res) {}\n",
    );
    write(
        root,
        "web/pages/api/named.ts",
        "export function GET(request) { return null; }\n",
    );
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let list: Vec<String> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{} {} {}",
                r["method"].as_str().unwrap(),
                r["path"].as_str().unwrap(),
                r["auth"].as_str().unwrap()
            )
        })
        .collect();
    for expected in [
        "GET /users/{id} none-detected",
        "POST /v2/items none-detected",
        "GET /admin/stats none-detected",
        "GET /api/auth/{nextauth} none-detected",
        "POST /api/auth/{nextauth} none-detected",
        "ANY /api/items none-detected",
        "ANY /api/me user",
    ] {
        assert!(
            list.iter().any(|r| r == expected),
            "{expected} missing from {list:?}"
        );
    }
    for absent in ["/api/legacy", "/api/named"] {
        assert!(
            !list.iter().any(|r| r.contains(absent)),
            "{absent} should not be a route: {list:?}"
        );
    }
    let scan = run(&["scan", "--json", root.to_str().unwrap()]);
    let findings = scan["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["class"] == "sql-injection" && f["entry"] == "ANY /api/items"),
        "{findings:?}"
    );
}

#[test]
fn next_middleware_auth_guards_file_routes_and_honors_public_prefixes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "web/src/middleware.ts",
        "import { NextResponse } from 'next/server';\n\
         export const config = { matcher: ['/((?!api/auth|_next/static|favicon.ico).*)'] };\n\
         export function middleware(request) {\n\
           const session = request.cookies.get('session');\n\
           if (!session?.value) return NextResponse.redirect(new URL('/api/auth/login', request.url));\n\
           return NextResponse.next();\n\
         }\n",
    );
    write(
        root,
        "web/src/app/api/fetch/route.ts",
        "export async function GET(request) {\n\
           const url = new URL(request.url).searchParams.get('url');\n\
           return Response.json(await (await fetch(url)).text());\n\
         }\n",
    );
    write(
        root,
        "web/src/app/api/auth/proxy/route.ts",
        "export async function GET(request) {\n\
           const url = new URL(request.url).searchParams.get('url');\n\
           return Response.json(await (await fetch(url)).text());\n\
         }\n",
    );
    write(
        root,
        "web/src/server.ts",
        "const app = require('express')();\n\
         app.get('/express', (req, res) => res.send(req.query.value));\n",
    );
    write(
        root,
        "locale/src/middleware.ts",
        "import { NextResponse } from 'next/server';\n\
         export function middleware(request) {\n\
           const locale = request.cookies.get('locale')?.value || 'en';\n\
           return NextResponse.redirect(new URL('/' + locale + request.nextUrl.pathname, request.url));\n\
         }\n",
    );
    write(
        root,
        "locale/src/app/api/translate/route.ts",
        "export async function GET(request) {\n\
           const url = new URL(request.url).searchParams.get('url');\n\
           return Response.json(await (await fetch(url)).text());\n\
         }\n",
    );

    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let auth = |path: &str| {
        routes
            .as_array()
            .unwrap()
            .iter()
            .find(|route| route["path"] == path)
            .unwrap()["auth"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(auth("/api/fetch"), "user");
    assert_eq!(auth("/api/auth/proxy"), "none-detected");
    assert_eq!(auth("/express"), "none-detected");
    assert_eq!(auth("/api/translate"), "none-detected");

    let report = run(&["scan", "--json", root.to_str().unwrap()]);
    let findings = report["findings"].as_array().unwrap();
    let protected = findings
        .iter()
        .find(|finding| finding["entry"] == "GET /api/fetch")
        .unwrap();
    let public = findings
        .iter()
        .find(|finding| finding["entry"] == "GET /api/auth/proxy")
        .unwrap();
    assert_eq!(protected["auth"], "user");
    assert_eq!(public["auth"], "none-detected");
}

#[test]
fn route_shapes_array_paths_verb_first_chains_and_prefixes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/app.js",
        "const express = require('express');\nconst nodes = require('./nodes');\nconst { r } = require('./chained');\n\
         const app = express();\napp.use('/api/v1/node-load-method', nodes);\napp.use('/x', r);\n\
         app.route('/book').get(listBooks).post(requireAuth, createBook);\n\
         app.post('/secure', [validate, requireRole('admin')], (req, res) => res.end());\n\
         module.exports = app;\n",
    );
    write(
        root,
        "src/nodes.js",
        "const express = require('express');\nconst router = express.Router();\nconst ctl = require('./ctl');\n\
         router.post(['/', '/:name'], ctl.loadMethod);\nmodule.exports = router;\n",
    );
    write(
        root,
        "src/ctl.js",
        "const { exec } = require('child_process');\n\
         exports.loadMethod = async (req, res) => { exec('node ' + req.body.script); };\n",
    );
    write(
        root,
        "src/chained.js",
        "const { Router } = require('express');\n\
         exports.r = Router().post('/a', (req, res) => res.end()).post('/b', (req, res) => res.end());\n",
    );
    // parse-server style: verb first, on `this` in a router class.
    write(
        root,
        "src/routers/users.js",
        "class UsersRouter extends PromiseRouter {\n  mountRoutes() {\n    \
         this.route('GET', '/users', (req) => this.handleFind(req));\n    \
         this.route('POST', '/users/:objectId', (req) => this.handleUpdate(req));\n    \
         this.route('/not-a-route');\n    cache.route('GET', key);\n  }\n}\nmodule.exports = UsersRouter;\n",
    );
    write(
        root,
        "hono/index.ts",
        "import { Hono } from 'hono';\nconst app = new Hono();\nconst books = new Hono();\n\
         books.get('/', (c) => c.json([]));\napp.route('/books', books);\n\
         const api = new Hono().basePath('/api');\napi.get('/hello', (c) => c.text('hi'));\n",
    );
    write(
        root,
        "koa/index.js",
        "const Router = require('@koa/router');\nconst router = new Router({ prefix: '/v1' });\n\
         router.get('/users', (ctx) => {});\nconst other = new Router();\nother.prefix('/v2');\n\
         other.get('/items', (ctx) => {});\n",
    );
    write(
        root,
        "fastify/server.js",
        "const fastify = require('fastify')();\nfastify.register(require('./users'), { prefix: '/users' });\n",
    );
    write(
        root,
        "fastify/users.js",
        "module.exports = async function users(fastify, opts) {\n  fastify.get('/:id', async (request, reply) => ({}));\n};\n",
    );
    write(
        root,
        "nest/cats.controller.ts",
        "@Controller(['v1/cats', 'cats'])\nexport class CatsController {\n  @Get([':id', 'by-id/:id'])\n  findOne() {}\n}\n",
    );
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let list: Vec<String> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{} {} {}",
                r["method"].as_str().unwrap(),
                r["path"].as_str().unwrap(),
                r["auth"].as_str().unwrap()
            )
        })
        .collect();
    for expected in [
        "POST /api/v1/node-load-method none-detected",
        "POST /api/v1/node-load-method/{name} none-detected",
        "POST /x/a none-detected",
        "POST /x/b none-detected",
        "GET /book none-detected",
        "POST /book user",
        "POST /secure admin",
        "GET /users none-detected",
        "POST /users/{objectId} none-detected",
        "GET /books none-detected",
        "GET /api/hello none-detected",
        "GET /v1/users none-detected",
        "GET /v2/items none-detected",
        "GET /users/{id} none-detected",
        "GET /v1/cats/{id} none-detected",
        "GET /cats/by-id/{id} none-detected",
    ] {
        assert!(
            list.iter().any(|r| r == expected),
            "{expected} missing from {list:?}"
        );
    }
    for absent in ["/not-a-route", "ROUTE ", "/POST", "/GET"] {
        assert!(
            !list.iter().any(|r| r.contains(absent)),
            "{absent} should not be a route: {list:?}"
        );
    }
    let scan = run(&["scan", "--json", root.to_str().unwrap()]);
    let findings = scan["findings"].as_array().unwrap();
    assert!(
        findings.iter().any(|f| f["class"] == "command-injection"
            && f["entry"]
                .as_str()
                .is_some_and(|e| e.starts_with("POST /api/v1/node-load-method"))),
        "{findings:?}"
    );
}

#[test]
fn a_value_is_followed_across_six_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "route.js",
        "const s1 = require('./s1');\napp.get('/x', (req, res) => s1.go(req.query.x));\n\
         app.get('/y', (req, res) => s1.go(String(parseInt(req.query.y, 10))));\n",
    );
    for (i, next) in [(1, 2), (2, 3), (3, 4), (4, 5)] {
        write(
            root,
            &format!("s{i}.js"),
            &format!("const n = require('./s{next}');\nexports.go = (v) => n.go(v);\n"),
        );
    }
    write(
        root,
        "s5.js",
        "const { exec } = require('child_process');\nexports.go = (v) => exec('ls ' + v);\n",
    );
    let scan = run(&["scan", "--json", root.to_str().unwrap()]);
    let findings = scan["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["class"], "command-injection");
    assert_eq!(findings[0]["sink"]["file"], "s5.js");
    assert_eq!(findings[0]["entry"], "GET /x");
}

/// `.find()` is a MongoDB query only where the project has a MongoDB driver (or is a Meteor app);
/// elsewhere it is an ORM's or the app's own method.
#[test]
fn nosql_sinks_need_a_mongodb_project() {
    let app = "const express = require('express');\nconst app = express();\n\
               app.post('/b', async (req, res) => { res.json(await Shipment.find(req.body)); });\n";
    let count = |manifest: Option<(&str, &str)>, meteor: bool| -> usize {
        let dir = tempfile::tempdir().unwrap();
        if let Some((path, deps)) = manifest {
            write(
                dir.path(),
                path,
                &format!("{{\"name\": \"x\", \"dependencies\": {{{deps}}}}}"),
            );
        }
        if meteor {
            write(dir.path(), ".meteor/packages", "mongo\n");
        }
        write(dir.path(), "server/app.js", app);
        write(dir.path(), "server/core/db.js", "module.exports = {};\n");
        write(dir.path(), "other/keep.js", "module.exports = {};\n");
        let report = run(&["scan", "--json", dir.path().to_str().unwrap()]);
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["class"] == "nosql-injection")
            .count()
    };
    // A SQL app's own `find`.
    assert_eq!(
        count(
            Some((
                "package.json",
                "\"express\": \"^4.21.2\", \"mysql2\": \"^3.0.0\""
            )),
            false
        ),
        0
    );
    // A MongoDB driver, in the root manifest above a package without one.
    assert_eq!(
        count(Some(("package.json", "\"mongodb\": \"^6.0.0\"")), false),
        1
    );
    // A dependency in the file's package applies.
    assert_eq!(
        count(
            Some(("server/package.json", "\"mongodb\": \"^6.0.0\"")),
            false
        ),
        1
    );
    // A dependency in an unrelated monorepo sibling does not reclassify this app's method.
    assert_eq!(
        count(
            Some(("other/package.json", "\"mongodb\": \"^6.0.0\"")),
            false
        ),
        0
    );
    // A Meteor app's collections.
    assert_eq!(
        count(Some(("package.json", "\"express\": \"^4.21.2\"")), true),
        1
    );
    // No manifest at all: nothing is held back.
    assert_eq!(count(None, false), 1);
}

/// An ES5 class in another file: its constructor's fields reach a sink in a prototype method.
#[test]
fn es5_classes_link_across_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/RestWrite.js",
        "const { exec } = require('child_process');\n\
         function RestWrite(config, data) { this.config = config; this.data = data; }\n\
         RestWrite.prototype.execute = function () { return exec('ls ' + this.data.cmd); };\n\
         module.exports = RestWrite;\n",
    );
    write(
        root,
        "src/rest.js",
        "const RestWrite = require('./RestWrite');\n\
         app.post('/x', (req, res) => new RestWrite(CONFIG, req.body).execute());\n\
         app.post('/y', (req, res) => new RestWrite(CONFIG, { cmd: 'ls' }).execute());\n",
    );
    let scan = run(&["scan", "--json", root.to_str().unwrap()]);
    let findings = scan["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["class"], "command-injection");
    assert_eq!(findings[0]["entry"], "POST /x");
}

/// CommonJS namespaces (`module.exports = { users: require('./users') }`) and whole-module
/// re-exports (`module.exports = require('./impl')`) link calls through them.
#[test]
fn commonjs_namespaces_and_reexports_link() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/app.js",
        "const api = require('./api');\nconst idx = require('./idx');\n\
         app.post('/x/:type', (req, res) => api.users.gen(req, req.params));\n\
         app.post('/csv', (req, res) => api.users.gen(req, { type: 'csv' }));\n\
         app.get('/run', (req, res) => idx.run(req.query.x));\n",
    );
    write(
        root,
        "src/api/index.js",
        "module.exports = { users: require('./users') };\n",
    );
    write(
        root,
        "src/api/users.js",
        "exports.gen = async (c, { type }) => require('child_process').fork('./x-' + type + '.js');\n",
    );
    write(root, "src/idx.js", "module.exports = require('./impl');\n");
    write(
        root,
        "src/impl.js",
        "const { exec } = require('child_process');\nexports.run = (v) => exec('ls ' + v);\n",
    );
    let scan = run(&["scan", "--json", root.to_str().unwrap()]);
    let findings = scan["findings"].as_array().unwrap();
    let got: Vec<(String, String)> = findings
        .iter()
        .map(|f| {
            (
                f["class"].as_str().unwrap().to_owned(),
                f["entry"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    assert!(
        got.contains(&("path-traversal".to_owned(), "POST /x/{type}".to_owned())),
        "{got:?}"
    );
    assert!(
        got.contains(&("command-injection".to_owned(), "GET /run".to_owned())),
        "{got:?}"
    );
    assert!(!got.iter().any(|(_, e)| e == "POST /csv"), "{got:?}");
}

/// Instances of a class from another file: through a field set in the constructor, through
/// `new Svc().run()`, and through a TypeScript annotation.
#[test]
fn imported_instances_link_through_fields_new_and_annotations() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/svc.ts",
        "import { exec } from 'child_process';\nexport class Svc { run(x: string) { exec('ls ' + x); } }\n",
    );
    write(
        root,
        "src/ctl.ts",
        "import { Svc } from './svc';\n\
         class Ctl { private svc: Svc; constructor() { this.svc = new Svc(); } h(req: any) { this.svc.run(req.query.a); } }\n\
         const c = new Ctl();\n\
         app.get('/a', (req, res) => c.h(req));\n\
         app.get('/b', (req, res) => new Svc().run(req.query.b));\n\
         function go(s: Svc, v: string) { s.run(v); }\n\
         app.get('/c', (req, res) => go(make(), req.query.c));\n",
    );
    let scan = run(&["scan", "--json", root.to_str().unwrap()]);
    let found: Vec<(String, String)> = scan["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["class"] == "command-injection")
        .map(|f| {
            (
                f["function"].as_str().unwrap_or("").to_owned(),
                f["entry"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    // Through the field, in the controller's method, linked to its route through `c.h(req)`.
    assert!(
        found.iter().any(|(f, e)| f == "Ctl.h" && e == "GET /a"),
        "{found:?}"
    );
    for entry in ["GET /b", "GET /c"] {
        assert!(
            found.iter().any(|(_, e)| e == entry),
            "{entry} missing from {found:?}"
        );
    }
}

/// A call on a receiver typed with an abstract class (or interface) reaches the classes that
/// extend (or implement) it, and only those.
#[test]
fn calls_on_a_base_type_dispatch_to_its_implementations() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/base.ts",
        "export abstract class Mem { abstract get(id: string): any; }\nexport interface Store { put(k: string): void; }\n",
    );
    write(
        root,
        "src/mongo.ts",
        "import { Mem, Store } from './base';\n\
         export class MongoMem extends Mem { get(id: string) { return coll.findOne({ s: id }); } }\n\
         export class FileStore implements Store { put(k: string) { require('fs').writeFileSync('/data/' + k, ''); } }\n\
         export class Other { get(id: string) { return require('child_process').exec('ls ' + id); } }\n",
    );
    write(
        root,
        "src/svc.ts",
        "import { Mem, Store } from './base';\n\
         app.post('/m', async (req, res) => { const m: Mem = await load(); m.get(req.body.id); });\n\
         app.post('/s', async (req, res) => { const s: Store = pick(); s.put(req.body.k); });\n",
    );
    let scan = run(&["scan", "--json", root.to_str().unwrap()]);
    let found: Vec<(String, String)> = scan["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["class"].as_str().unwrap_or("").to_owned(),
                f["sink"]["file"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    assert!(
        found.contains(&("nosql-injection".to_owned(), "src/mongo.ts".to_owned())),
        "{found:?}"
    );
    assert!(
        found.contains(&("path-traversal".to_owned(), "src/mongo.ts".to_owned())),
        "{found:?}"
    );
    // `Other.get` shares the name but neither extends nor implements `Mem`.
    assert!(
        !found.iter().any(|(class, _)| class == "command-injection"),
        "{found:?}"
    );
}

/// Instances returned by functions in other files: a factory of several classes (the method
/// of each class it returns, and only those), a singleton accessor exported under another
/// name, `new this()` in a static factory, and a property every typed assignment in the
/// repository gives the same class.
#[test]
fn instances_returned_by_factories_singletons_and_typed_properties() {
    let tree = |root: &Path, conflicting: bool| {
        write(
            root,
            "src/a.js",
            "const { exec } = require('child_process');\nclass A { run(x) { exec('ls ' + x); } }\nmodule.exports = { A };\n",
        );
        write(
            root,
            "src/b.js",
            "const fs = require('fs');\nclass B { run(x) { fs.readFileSync('/data/' + x); } }\nmodule.exports = { B };\n",
        );
        write(
            root,
            "src/safe.js",
            "const { exec } = require('child_process');\nclass Safe { run(x) { exec('ls ' + parseInt(x, 10)); } }\nmodule.exports = { Safe };\n",
        );
        write(
            root,
            "src/factory.js",
            "const { A } = require('./a');\nconst { B } = require('./b');\nconst { Safe } = require('./safe');\n\
             function getClient(kind) { switch (kind) { case 'a': return new A(); default: return new B(); } }\n\
             function getSafe() { return new Safe(); }\nmodule.exports = { getClient, getSafe };\n",
        );
        write(
            root,
            "src/registry.ts",
            "import { exec } from 'child_process';\n\
             export class Registry {\n  private static instance: Registry;\n\
             static getInstance(): Registry { if (!Registry.instance) { Registry.instance = new Registry(); } return Registry.instance; }\n\
             add(cmd: string) { exec(cmd); }\n}\n\
             export class Maker { static create() { return new this(); } go(p: string) { require('fs').readFileSync(p); } }\n",
        );
        write(
            root,
            "src/config.js",
            "const { Registry, Maker } = require('./registry');\n\
             module.exports = { getRegistry: Registry.getInstance, makeOne: Maker.create };\n",
        );
        write(
            root,
            "src/db.js",
            "const { exec } = require('child_process');\nclass Database { find(w) { exec('grep ' + w); } }\nmodule.exports = { Database };\n",
        );
        write(
            root,
            "src/setup.js",
            "const { Database } = require('./db');\nfunction setup(config) { config.database = new Database(); }\nmodule.exports = { setup };\n",
        );
        if conflicting {
            write(
                root,
                "src/other.js",
                "const { Safe } = require('./safe');\nfunction init(o) { o.database = new Safe(); }\nmodule.exports = { init };\n",
            );
        }
        write(
            root,
            "src/query.js",
            "class Query { constructor(config) { this.config = config; } execute(w) { this.config.database.find(w); } }\nmodule.exports = { Query };\n",
        );
        write(
            root,
            "src/routes.js",
            "const { getClient, getSafe } = require('./factory');\n\
             const { getRegistry, makeOne } = require('./config');\nconst { Query } = require('./query');\n\
             app.get('/f', (req, res) => getClient(req.query.k).run(req.query.x));\n\
             app.get('/v', async (req, res) => { const c = await getClient('a'); c.run(req.query.v); });\n\
             app.get('/s', (req, res) => getSafe().run(req.query.s));\n\
             app.get('/r', (req, res) => getRegistry().add(req.query.r));\n\
             app.get('/n', (req, res) => makeOne().go(req.query.n));\n\
             app.get('/q', (req, res) => new Query(cfg).execute(req.query.q));\n",
        );
    };
    let found = |root: &Path| -> Vec<(String, String, String)> {
        let scan = run(&["scan", "--json", root.to_str().unwrap()]);
        scan["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["class"].as_str().unwrap_or("").to_owned(),
                    f["sink"]["file"].as_str().unwrap_or("").to_owned(),
                    f["entry"].as_str().unwrap_or("").to_owned(),
                )
            })
            .collect()
    };
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path(), false);
    let got = found(dir.path());
    let has = |class: &str, file: &str, entry: &str| {
        got.iter()
            .any(|(c, f, e)| c == class && f == file && e == entry)
    };
    for (class, file, entry) in [
        ("command-injection", "src/a.js", "GET /f"),
        ("path-traversal", "src/b.js", "GET /f"),
        ("command-injection", "src/a.js", "GET /v"),
        ("command-injection", "src/registry.ts", "GET /r"),
        ("path-traversal", "src/registry.ts", "GET /n"),
        ("command-injection", "src/db.js", "GET /q"),
    ] {
        assert!(
            has(class, file, entry),
            "{class} {file} {entry} missing from {got:?}"
        );
    }
    // The factory that returns `Safe` reaches no sink.
    assert!(!got.iter().any(|(_, f, _)| f == "src/safe.js"), "{got:?}");
    // A property assigned two different classes is typed by neither.
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path(), true);
    let got = found(dir.path());
    assert!(!got.iter().any(|(_, f, _)| f == "src/db.js"), "{got:?}");
    assert!(!got.iter().any(|(_, f, _)| f == "src/safe.js"), "{got:?}");
}

/// An MCP server reachable only over stdio answers the client that launched it: its tool
/// arguments are capped at medium. Served over HTTP too, they are not.
#[test]
fn stdio_only_mcp_servers_are_capped() {
    let server = |root: &Path, http: bool| {
        let extra = if http {
            "app.post('/mcp', async (req, res) => { const t = new StreamableHTTPServerTransport({}); await server.connect(t); });\n"
        } else {
            ""
        };
        write(
            root,
            "src/server.js",
            &format!(
                "const {{ Server }} = require('@modelcontextprotocol/sdk/server/index.js');\n\
                 const {{ StdioServerTransport }} = require('@modelcontextprotocol/sdk/server/stdio.js');\n\
                 const {{ exec }} = require('child_process');\n\
                 const server = new Server({{ name: 'x', version: '1' }}, {{ capabilities: {{}} }});\n\
                 server.setRequestHandler(CallToolRequestSchema, async (request) => {{ exec('git log ' + request.params.arguments.ref); }});\n\
                 server.connect(new StdioServerTransport());\n{extra}"
            ),
        );
    };
    for (http, expected) in [(false, "medium"), (true, "critical")] {
        let dir = tempfile::tempdir().unwrap();
        server(dir.path(), http);
        let scan = run(&[
            "scan",
            "--json",
            "--min-severity",
            "low",
            dir.path().to_str().unwrap(),
        ]);
        let severities: Vec<&str> = scan["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["source"]["kind"] == "mcp")
            .map(|f| f["severity"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(severities, vec![expected], "http: {http}");
    }
}

/// Findings inside client callbacks (socket.io events, Electron IPC channels, queue workers,
/// MCP handlers) are linked to the entry that registers them, whatever the event's name is: a
/// literal, a constant, an expression, or none (`queue.process(fn)`).
#[test]
fn client_callbacks_are_linked_to_their_entries() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/server.js",
        "const { exec } = require('child_process');\nconst fs = require('fs');\n\
         const io = require('socket.io')(3000);\n\
         io.on('connection', (socket) => { socket.on('run', (data) => { exec('ls ' + data.dir); }); });\n\
         const { ipcMain } = require('electron');\n\
         ipcMain.handle('open-file', async (event, p) => { fs.readFileSync(p); });\n\
         const { Worker, Queue } = require('bullmq');\n\
         new Worker('jobs', async (job) => { exec('run ' + job.data.cmd); });\n\
         class Base { constructor(q) { this.queue = q; } start() { new Worker(this.queue.name, async (job) => { exec('go ' + job.data.cmd); }); } }\n\
         const q = new Queue('emails');\nq.process(async (job) => { exec('mail ' + job.data.to); });\n\
         async function handleToolCall(request) { return fs.readFileSync(request.params.arguments.path); }\n\
         server.setRequestHandler(CallToolRequestSchema, async (request) => ctx.run({}, () => observe(async () => handleToolCall(request))));\n\
         app.get('/batch', (req, res) => { req.query.items.split(',').forEach((item) => { exec('process ' + item); }); });\n\
         require('http').createServer((req, res) => { const u = new URL(req.url, 'http://x'); exec('show ' + u.searchParams.get('id')); });\n",
    );
    let scan = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let entries: Vec<String> = scan["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["entry"].as_str().unwrap_or("").to_owned())
        .collect();
    for entry in [
        "SOCKET run",
        "IPC open-file",
        "QUEUE jobs",
        "QUEUE {this.queue.name}",
        "QUEUE {q}",
        // Nested callbacks belong to the named function they are written in.
        "MCP CallToolRequestSchema",
        "GET /batch",
        // A raw `node:http` server: every request.
        "ANY /{wildcard}",
    ] {
        assert!(
            entries.iter().any(|e| e == entry),
            "{entry} missing from {entries:?}"
        );
    }
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let listed: Vec<String> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{} {}",
                r["method"].as_str().unwrap(),
                r["path"].as_str().unwrap()
            )
        })
        .collect();
    for entry in ["SOCKET run", "IPC open-file", "QUEUE jobs", "QUEUE {q}"] {
        assert!(
            listed.iter().any(|e| e == entry),
            "{entry} missing from {listed:?}"
        );
    }
}

/// A helper that registers literal routes on the router it is handed, whatever the parameter
/// is called (`setup(mstream)`), called through a namespace import on an app assigned after
/// its declaration: the routes are the caller's, and the findings in their inline handlers
/// are linked to them.
#[test]
fn routes_registered_on_a_handed_router_are_linked() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/api/admin.js",
        "import fs from 'fs';\nexport function setup(mstream) {\n  \
         mstream.post('/api/v1/admin/file', (req, res) => { res.send(fs.readFileSync(req.body.path)); });\n}\n",
    );
    write(
        root,
        "src/server.js",
        "import express from 'express';\nimport * as adminApi from './api/admin.js';\nlet mstream;\n\
         export function serveIt() {\n  mstream = express();\n  adminApi.setup(mstream);\n}\n",
    );
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let listed: Vec<String> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{} {} {}",
                r["method"].as_str().unwrap(),
                r["path"].as_str().unwrap(),
                r["handler"].as_str().unwrap()
            )
        })
        .collect();
    assert!(
        listed
            .iter()
            .any(|r| r == "POST /api/v1/admin/file POST /api/v1/admin/file"),
        "{listed:?}"
    );
    let scan = run(&["scan", "--json", root.to_str().unwrap()]);
    let entries: Vec<&str> = scan["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["entry"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(entries, vec!["POST /api/v1/admin/file"]);
}

/// Routers held in fields (`FastifyWorker.fastify = Fastify()`, `this.app = express()`) register
/// routes like variables do, and `routes` honors the config's `include` (tests, examples).
#[test]
fn routers_in_fields_and_included_classes_are_inventoried() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/worker.ts",
        "import Fastify from 'fastify';\nclass FastifyWorker {\n  static fastify: any;\n  \
         static start() {\n    FastifyWorker.fastify = Fastify({ logger: true });\n    \
         FastifyWorker.fastify.all('/api/echo', (request) => request.body);\n  }\n}\n\
         class App {\n  app: any;\n  constructor() {\n    this.app = express();\n    \
         this.app.post('/api/items', (req, res) => res.json(req.body));\n  }\n}\n",
    );
    write(
        root,
        "test/server.test.js",
        "const Fastify = require('fastify');\ntest('x', async () => {\n  const fastify = Fastify();\n  \
         fastify.get('/from-test', (request) => request.query);\n});\n",
    );
    let listed = |args: &[&str]| -> Vec<String> {
        run(args)
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                format!(
                    "{} {}",
                    r["method"].as_str().unwrap(),
                    r["path"].as_str().unwrap()
                )
            })
            .collect()
    };
    let routes = listed(&["routes", "--json", root.to_str().unwrap()]);
    for route in ["ALL /api/echo", "POST /api/items"] {
        assert!(
            routes.iter().any(|r| r == route),
            "{route} missing from {routes:?}"
        );
    }
    assert!(!routes.iter().any(|r| r == "GET /from-test"), "{routes:?}");
    write(root, ".jsspector.yml", "include: [tests]\n");
    let routes = listed(&["routes", "--json", root.to_str().unwrap()]);
    assert!(routes.iter().any(|r| r == "GET /from-test"), "{routes:?}");
}

/// `server.on('request', (req, res) => ...)` on a server from `http.createServer(opts)` handles
/// every request, like a handler passed to the factory; `server.on('upgrade', ...)` handles every
/// HTTP upgrade request and is marked a distinct `UPGRADE` method. The callback is walked as
/// before, so its findings keep their function (and fingerprint); each listener's entry covers its
/// own lines only, and the same listener on an emitter that is not a server is not an entry.
#[test]
fn server_request_listeners_are_catch_all_entries() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "server.js",
        "import fs from 'fs';\nimport http from 'http';\n\
         const server = http.createServer({ keepAlive: false }, void 0);\n\
         server.on('request', (req, res) => { const p = new URL(req.url, 'http://x').pathname; fs.createReadStream('./static/' + decodeURIComponent(p)).pipe(res); });\n\
         server.on('upgrade', (req, sock) => { fs.createReadStream('./ws/' + req.url).pipe(sock); });\n\
         server.listen(8000);\n",
    );
    write(
        root,
        "inline.js",
        "import fs from 'fs';\nimport http from 'http';\n\
         http.createServer((req, res) => { fs.createReadStream('./static/' + req.url).pipe(res); }).listen(8001);\n",
    );
    write(
        root,
        "other.js",
        "import fs from 'fs';\nimport { EventEmitter } from 'events';\n\
         const bus = new EventEmitter();\n\
         bus.on('request', (req, res) => { fs.createReadStream('./static/' + req.url).pipe(res); });\n",
    );
    let scan = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let findings = scan["findings"].as_array().unwrap();
    let entry = |file: &str| -> Vec<String> {
        findings
            .iter()
            .filter(|f| f["file"].as_str() == Some(file))
            .map(|f| f["entry"].as_str().unwrap_or("").to_owned())
            .collect()
    };
    let inline = entry("inline.js");
    assert_eq!(inline.len(), 1, "{findings:?}");
    assert!(inline[0].starts_with("ANY /"), "{inline:?}");
    let server: Vec<&Value> = findings
        .iter()
        .filter(|f| f["file"].as_str() == Some("server.js"))
        .collect();
    assert_eq!(server.len(), 2, "{findings:?}");
    for f in &server {
        assert_eq!(f["function"], "<module>", "{f:?}");
        // The `'request'` listener (line 4) is a plain catch-all; the `'upgrade'` listener (line 5)
        // is the same path but marked `UPGRADE`.
        let expected = if f["sink"]["line"] == 4 {
            Some(inline[0].as_str())
        } else {
            Some("UPGRADE /{wildcard}")
        };
        assert_eq!(f["entry"].as_str(), expected, "{f:?}");
    }
    assert!(
        entry("other.js").iter().all(|e| e.is_empty()),
        "{findings:?}"
    );
}

/// `http.createServer(handle)` with a function of the file, or `http.createServer(make(rt))` with
/// a local factory returning the handler, handles every request: the findings the handler reaches
/// (here or in another file) get the catch-all entry. `http.createServer(app)` on something that
/// is no function of the file, or a call to a function that returns no closure, is not one.
#[test]
fn named_and_factory_made_server_handlers_are_catch_all_entries() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "named.js",
        "import http from 'node:http';\n\
         function handle(req, res) { http.request(new URL(req.url, 'http://x')).end(); }\n\
         http.createServer(handle).listen(1);\n",
    );
    write(
        root,
        "made.js",
        "import http from 'node:http';\nimport { forward } from './forward.js';\n\
         function makeHandler(runtime) {\n\
         \x20 return (request, response) => { if (request.url === '/health') return; forward(request, response); };\n\
         }\n\
         export async function start() { const server = http.createServer(makeHandler({})); server.listen(2); }\n",
    );
    write(
        root,
        "forward.js",
        "import http from 'node:http';\n\
         export function forward(request, response) {\n\
         \x20 const target = new URL(request?.url || '/', 'http://upstream');\n\
         \x20 http.request({ hostname: target.hostname, path: target.pathname }).end();\n\
         }\n",
    );
    write(
        root,
        "other.js",
        "import http from 'node:http';\nimport express from 'express';\n\
         const app = express();\n\
         function options() { return { keepAlive: true }; }\n\
         function unrelated(req) { http.request(new URL(req.url, 'http://x')).end(); }\n\
         http.createServer(app).listen(3);\n\
         http.createServer(options()).listen(4);\n",
    );
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let handlers: Vec<(String, String)> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["file"].as_str().unwrap_or("").to_owned(),
                r["handler"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    assert!(
        handlers.contains(&("named.js".to_owned(), "handle".to_owned())),
        "{handlers:?}"
    );
    assert!(
        handlers.contains(&("made.js".to_owned(), "makeHandler".to_owned())),
        "{handlers:?}"
    );
    assert!(
        handlers.iter().all(|(file, _)| file != "other.js"),
        "{handlers:?}"
    );
    let scan = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let findings = scan["findings"].as_array().unwrap();
    let entry = |file: &str| -> Vec<Option<String>> {
        findings
            .iter()
            .filter(|f| f["file"].as_str() == Some(file))
            .map(|f| f["entry"].as_str().map(str::to_owned))
            .collect()
    };
    for file in ["named.js", "forward.js"] {
        let entries = entry(file);
        assert!(!entries.is_empty(), "{file}: {findings:?}");
        assert!(
            entries
                .iter()
                .all(|e| e.as_deref().is_some_and(|e| e.starts_with("ANY /"))),
            "{file}: {entries:?}"
        );
    }
    assert!(
        entry("other.js").iter().all(Option::is_none),
        "{findings:?}"
    );
}

/// `server.on('upgrade', makeUpgradeHandler(rt))` with a local factory returning the handler
/// closure links the HTTP-upgrade entry to the sink the closure reaches in another file, and marks
/// it `UPGRADE` so verification drives it as an upgrade request rather than a plain one.
#[test]
fn factory_made_upgrade_handlers_link_the_upgrade_entry() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "server.js",
        "import http from 'node:http';\nimport { proxyUpgrade } from './upgrade.js';\n\
         function makeUpgradeHandler(runtime) {\n\
         \x20 return (request, socket, head) => { proxyUpgrade(request, socket, head); };\n\
         }\n\
         const server = http.createServer((req, res) => res.end('ok'));\n\
         server.on('upgrade', makeUpgradeHandler({}));\n\
         server.listen(2);\n",
    );
    write(
        root,
        "upgrade.js",
        "import http from 'node:http';\n\
         export function proxyUpgrade(request, socket, head) {\n\
         \x20 const upstream = new URL(request?.url || '/', 'http://upstream');\n\
         \x20 http.request({ hostname: upstream.hostname, path: upstream.pathname }).end();\n\
         }\n",
    );
    let scan = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let findings = scan["findings"].as_array().unwrap();
    let upgrade: Vec<&Value> = findings
        .iter()
        .filter(|f| f["file"].as_str() == Some("upgrade.js"))
        .collect();
    assert!(!upgrade.is_empty(), "{findings:?}");
    assert!(
        upgrade
            .iter()
            .all(|f| f["entry"].as_str() == Some("UPGRADE /{wildcard}")),
        "{upgrade:?}"
    );
}

/// Entry points beyond routes and events: an LLM tool (named by its `name`), a dev server's
/// middleware, and, for browser-side data no route reaches, the page or the component.
#[test]
fn tools_dev_servers_pages_and_components_are_entries() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/tools.js",
        "const { exec } = require('child_process');\n\
         aibitat.function({ name: 'run-report', parameters: { type: 'object' }, handler: async ({ dir }) => { exec('ls ' + dir); } });\n",
    );
    write(
        root,
        "vite.config.js",
        "import fs from 'fs';\nexport default { plugins: [{ configureServer(server) { server.middlewares.use((req, res, next) => { res.end(fs.readFileSync('.' + req.url)); }); } }] };\n",
    );
    write(
        root,
        "web/page.js",
        "document.getElementById('out').innerHTML = '<b>' + decodeURIComponent(location.hash.slice(1)) + '</b>';\n",
    );
    write(
        root,
        "web/Card.jsx",
        "export function Card({ html }) { return <div dangerouslySetInnerHTML={{ __html: html }} />; }\n",
    );
    let scan = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let entries: Vec<String> = scan["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["entry"].as_str().unwrap_or("").to_owned())
        .collect();
    for entry in [
        "LLM-TOOL run-report",
        "ANY *",
        "PAGE web/page.js",
        "COMPONENT Card",
    ] {
        assert!(
            entries.iter().any(|e| e == entry),
            "{entry} missing from {entries:?}"
        );
    }
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let kinds: Vec<String> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{} {}",
                r["kind"].as_str().unwrap(),
                r["path"].as_str().unwrap()
            )
        })
        .collect();
    for route in ["llm-tool run-report", "dev-server *"] {
        assert!(
            kinds.iter().any(|k| k == route),
            "{route} missing from {kinds:?}"
        );
    }
}

/// A table of route modules called by a computed key from a callback (NodeBB's
/// `_mounts[original](router, mount, ...)` over `Object.keys(mounts)`): every module's routes
/// are registered with the run-time mount as a path parameter, a module that registers more
/// than a few dozen routes through helpers keeps them all, and each route names its handler.
#[test]
fn route_tables_called_by_computed_key_are_instantiated() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/routes/helpers.js",
        "const helpers = module.exports;\n\
         helpers.setupPageRoute = function (router, name, middlewares, controller) {\n  \
         router.get(name, middlewares, controller);\n  \
         router.get(`/api${name}`, middlewares, controller);\n};\n",
    );
    let pages: String = (0..70)
        .map(|i| {
            format!(
                "  helpers.setupPageRoute(app, `/${{name}}/page{i}`, [], controllers.page{i});\n"
            )
        })
        .collect();
    write(
        root,
        "src/routes/admin.js",
        &format!(
            "const helpers = require('./helpers');\n\
             module.exports = function (app, name, middleware, controllers) {{\n{pages}  \
             apiRoutes(app, name, middleware, controllers);\n}};\n\
             function apiRoutes(router, name, middleware, controllers) {{\n  \
             router.post(`/api/${{name}}/uploadlogo`, [middleware.validateFiles], controllers.uploadLogo);\n}}\n"
        ),
    );
    write(
        root,
        "src/routes/index.js",
        "const express = require('express');\n\
         const _mounts = { admin: require('./admin') };\n\
         _mounts.topic = (app, name, middleware, controllers) => {\n  \
         app.get(`/${name}/:tid`, controllers.topics.get);\n};\n\
         function addRemountableRoutes(router, middleware, controllers, mounts) {\n  \
         Object.keys(mounts).map((mount) => {\n    \
         _mounts[mount](router, mounts[mount], middleware, controllers);\n  });\n}\n\
         exports.reloadRoutes = function (params) {\n  \
         const router = express.Router();\n  \
         addRemountableRoutes(router, params.middleware, params.controllers, { admin: 'admin', topic: 'topic' });\n  \
         params.app.use('/', router);\n};\n",
    );
    let routes: Vec<String> = run(&["routes", "--json", root.to_str().unwrap()])
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{} {} {}",
                r["method"].as_str().unwrap(),
                r["path"].as_str().unwrap(),
                r["handler"].as_str().unwrap()
            )
        })
        .collect();
    // Each route names the handler its module passed, not the table call's last argument.
    for route in [
        "GET /{mount}/page0 controllers.page0",
        "GET /api/{mount}/page69 controllers.page69",
        "POST /api/{mount}/uploadlogo controllers.uploadLogo",
        "GET /{mount}/{tid} controllers.topics.get",
    ] {
        assert!(
            routes.iter().any(|r| r == route),
            "{route} missing from {routes:?}"
        );
    }
    let pages = routes.iter().filter(|r| r.contains("}/page")).count();
    assert_eq!(pages, 140, "{routes:?}");
}

/// Queue, MCP and tRPC registrations go by their receiver: a queue's `process`, BullMQ's
/// `Worker`, a server's `tool`, a procedure's `query`. A Web Worker, `posthtml().process(..)`,
/// `bootbox.prompt(..)`, Fluent's `bundle.addResource(..)`, `connection.query(sql)` and RTK
/// Query's `builder.mutation(..)` are no entries.
#[test]
fn queue_mcp_and_trpc_registrations_need_their_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/jobs.js",
        "import { Worker } from 'bullmq';\nimport { exec } from 'child_process';\n\
         const Queue = require('bull');\nconst emailQueue = new Queue('email');\n\
         new Worker('reports', async (job) => { exec('make-report ' + job.data.name); });\n\
         emailQueue.process(async (job) => { exec('mail ' + job.data.to); });\n",
    );
    write(
        root,
        "src/mcp.js",
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n\
         import { exec } from 'child_process';\n\
         const server = new McpServer({ name: 'x', version: '1' });\n\
         server.tool('run', { cmd: {} }, async ({ cmd }) => { exec(cmd); return { content: [] }; });\n",
    );
    write(
        root,
        "public/viewer.js",
        "const worker = new Worker(workerSrc, { type: 'module' });\n\
         posthtml(plugins).process(content, posthtmlProcessOptions);\n\
         bootbox.prompt('[[name]]', (name) => { document.body.innerHTML = name; });\n\
         bundle.addResource(resource);\n",
    );
    write(
        root,
        "src/api.ts",
        "export const api = createApi({ endpoints: (builder) => ({ exchange: builder.mutation({ query: (body) => ({ url: '/x', body }) }) }) });\n\
         connection.query(rawQuery);\n\
         export const appRouter = router({ list: publicProcedure.query(() => []) });\n",
    );
    let routes: Vec<String> = run(&["routes", "--json", root.to_str().unwrap()])
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{} {} {}",
                r["method"].as_str().unwrap(),
                r["path"].as_str().unwrap(),
                r["file"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(
        routes,
        vec![
            "MCP run src/mcp.js",
            "QUEUE reports src/jobs.js",
            "QUEUE {emailQueue} src/jobs.js",
            "TRPC.QUERY list src/api.ts"
        ]
    );
}

/// A regular expression exported in an object from another module, through a barrel
/// (Reddit Enhancement Suite's `regexes.profile`): its captures keep their character set.
#[test]
fn imported_regexes_keep_their_charset() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "lib/utils/location.js",
        "export const regexes = { profile: /^\\/user\\/([\\w\\-]+)\\/?$/i, any: /^\\/user\\/(.+)$/ };\n",
    );
    write(
        root,
        "lib/utils/index.js",
        "export { regexes } from './location';\n",
    );
    write(
        root,
        "lib/modules/search.js",
        "import $ from 'jquery';\nimport { regexes } from '../utils';\n\
         export function safe() { const [, user] = location.hash.match(regexes.profile) || []; $('.main').prepend(`<b>${user}</b>`); }\n\
         export function unsafe() { const [, user] = location.hash.match(regexes.any) || []; $('.main').prepend(`<b>${user}</b>`); }\n",
    );
    let scan = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let functions: Vec<&str> = scan["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["function"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(functions, vec!["unsafe"]);
}

/// A validator in another module that throws unless a value is a string (indiekit's
/// `validateChannel`) keeps query operators out of the query its caller builds.
#[test]
fn imported_string_validators_keep_query_operators_out() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "lib/validation.js",
        "export function validateChannel(__, channel, isRequired = true) {\n  \
         if (isRequired && !channel) { throw new Error('missing'); }\n  \
         if (channel && typeof channel !== 'string') { throw new Error('invalid'); }\n}\n",
    );
    write(
        root,
        "lib/app.js",
        "import express from 'express';\nimport { validateChannel } from './validation.js';\n\
         const app = express();\n\
         app.post('/checked', async (req, res) => { const { uid } = req.body; validateChannel(null, uid); await db.collection('c').deleteOne({ uid }); });\n\
         app.post('/unchecked', async (req, res) => { const { uid } = req.body; await db.collection('c').deleteOne({ uid }); });\n",
    );
    let scan = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let entries: Vec<&str> = scan["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["entry"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(entries, vec!["POST /unchecked"]);
}

/// An internal service behind inline middleware that answers 403 unless a request header
/// equals a secret of the server (blot's iCloud macserver), whose routes wrap handlers from
/// other files (`asyncHandler(deleteRoute)`): the route names the wrapped handler, and the
/// findings in it are the route's, at admin level.
#[test]
fn wrapped_handlers_behind_a_shared_secret_guard_are_admin_routes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "routes/delete.js",
        "import fs from 'fs';\nexport default async function deleteRoute(req, res) {\n  \
         fs.unlinkSync('/data/' + req.header('blogID') + '/' + req.body.path);\n  res.end();\n}\n",
    );
    // An anonymous default export (`export default async (req, res) => {}`), as blot writes them.
    write(
        root,
        "routes/mkdir.js",
        "import fs from 'fs';\nexport default async (req, res) => {\n  \
         fs.mkdirSync('/data/' + req.header('blogID') + '/' + req.body.path);\n  res.end();\n};\n",
    );
    write(
        root,
        "index.js",
        "import express from 'express';\nimport { Authorization } from './config.js';\n\
         import deleteRoute from './routes/delete.js';\nimport mkdirRoute from './routes/mkdir.js';\n\
         const asyncHandler = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);\n\
         const app = express();\n\
         app.use((req, res, next) => { const authorization = req.header('Authorization'); \
         if (authorization !== Authorization) { return res.status(403).send('Unauthorized'); } next(); });\n\
         app.post('/delete', asyncHandler(deleteRoute));\napp.post('/mkdir', asyncHandler(mkdirRoute));\n",
    );
    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    let handlers: Vec<&str> = routes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["handler"].as_str().unwrap())
        .collect();
    assert_eq!(handlers, vec!["deleteRoute", "mkdirRoute"]);
    let scan = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let findings: Vec<(String, String, String)> = scan["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["entry"].as_str().unwrap_or("").to_owned(),
                f["auth"].as_str().unwrap_or("").to_owned(),
                f["severity"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    let mut findings = findings;
    findings.sort();
    assert_eq!(
        findings,
        vec![
            (
                "POST /delete".to_owned(),
                "admin".to_owned(),
                "medium".to_owned()
            ),
            (
                "POST /mkdir".to_owned(),
                "admin".to_owned(),
                "medium".to_owned()
            )
        ]
    );
}

#[test]
fn wrapped_handler_factories_are_linked_to_their_route() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "routes/profile.js",
        "export function profileImageUrlUpload() {\n  return async (req, res) => {\n    const url = req.body.imageUrl;\n    const response = await fetch(url);\n    res.send(await response.text());\n  };\n}\n",
    );
    write(
        root,
        "server.js",
        "import express from 'express';\nimport { profileImageUrlUpload } from './routes/profile.js';\n\
         import * as utils from './utils.js';\nconst app = express();\n\
         app.post('/profile/image/url', utils.asyncHandler(profileImageUrlUpload()));\n",
    );

    let routes = run(&["routes", "--json", root.to_str().unwrap()]);
    assert_eq!(routes[0]["handler"], "profileImageUrlUpload");
    let scan = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    assert_eq!(scan["findings"][0]["entry"], "POST /profile/image/url");
}

/// mStream's DLNA routes: `all(path, genaRoute('cds'))` registers the closure a factory
/// returns. The route goes by the factory, whose closure calls the sink's function, so that
/// public route is the finding's entry, even though an admin-only route reaches the same
/// function.
#[test]
fn a_handler_made_by_a_factory_links_the_public_route() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "dlna.js",
        "const http = require('http');\nconst express = require('express');\nconst app = express();\n\
         function handleSubscribe(req, res) { const u = new URL(req.headers['callback']); http.request({ hostname: u.hostname, path: u.pathname }).end(); res.end(); }\n\
         function genaRoute(service) { return (req, res) => { if (req.method === 'SUBSCRIBE') { return handleSubscribe(req, res); } res.status(405).end(); }; }\n\
         app.all('/dlna/event/cds', genaRoute('cds'));\n\
         app.all('/admin/{*path}', (req, res, next) => { if (req.user.admin !== true) { return res.status(403).end(); } next(); });\n\
         app.delete('/admin/directory', (req, res) => { handleSubscribe(req, res); });\n",
    );
    let scan = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let findings: Vec<(String, String, String)> = scan["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["class"].as_str().unwrap_or("").to_owned(),
                f["severity"].as_str().unwrap_or("").to_owned(),
                f["entry"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        findings,
        vec![(
            "ssrf".to_owned(),
            "high".to_owned(),
            "ALL /dlna/event/cds".to_owned()
        )]
    );
}

/// The same, registered by a helper on the router its caller hands it
/// (`export function setup(mstream) { mstream.all(path, genaRoute('cds')) }`).
#[test]
fn a_factory_handler_on_a_handed_router_is_a_route() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/api/dlna.js",
        "import http from 'http';\nexport function setup(mstream) {\n  \
         function handleSubscribe(req, res) { const u = new URL(req.headers['callback']); http.request({ hostname: u.hostname, path: u.pathname }).end(); res.end(); }\n  \
         function genaRoute(service) { return (req, res) => { if (req.method === 'SUBSCRIBE') { return handleSubscribe(req, res); } res.status(405).end(); }; }\n  \
         mstream.all('/dlna/event/cds', genaRoute('cds'));\n}\n",
    );
    write(
        root,
        "src/server.js",
        "import express from 'express';\nimport * as dlnaApi from './api/dlna.js';\n\
         const app = express();\ndlnaApi.setup(app);\n",
    );
    let scan = run(&[
        "scan",
        "--json",
        "--min-severity",
        "low",
        root.to_str().unwrap(),
    ]);
    let entries: Vec<(&str, &str)> = scan["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["severity"].as_str().unwrap_or(""),
                f["entry"].as_str().unwrap_or(""),
            )
        })
        .collect();
    assert_eq!(entries, vec![("high", "ALL /dlna/event/cds")]);
}
