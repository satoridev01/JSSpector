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
