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
