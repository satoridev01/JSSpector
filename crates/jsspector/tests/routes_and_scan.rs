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
            &format!("{{\"name\": \"x\", \"dependencies\": {{\"express\": \"{express}\"}}}}"),
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
