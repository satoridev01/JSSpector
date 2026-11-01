//! End-to-end tests of the reporting options of `jsspector scan` (SARIF, baselines, `--fail-on`,
//! `.jsspector.yml`, `jsspector-ignore` comments) and of `jsspector explain`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

fn jsspector(args: &[&str], dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_jsspector"))
        .args(args)
        .current_dir(dir)
        .env_remove("RAYON_NUM_THREADS")
        .output()
        .unwrap()
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "{err}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn write(root: &Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

/// An app with a cross-file SQL injection (high), a command injection behind an admin check
/// (lowered to high), an ignored one, and a script with a critical one.
fn app(root: &Path) {
    write(
        root,
        "src/server.js",
        "const express = require('express');\nconst { run } = require('./db');\n\
         const { exec } = require('child_process');\nconst app = express();\n\
         app.get('/items', (req, res) => res.json(run(req.query.id)));\n\
         app.post('/admin/run', mustBeAdmin, (req, res) => { exec('ls ' + req.body.dir); });\n\
         app.get('/legacy', (req, res) => {\n  // jsspector-ignore sql-injection -- checked upstream\n  \
         db.query('SELECT * FROM t WHERE id = ' + req.query.id);\n});\n\
         app.get('/gated', gatekeeper, (req, res) => runReport(req.query.name));\n",
    );
    write(
        root,
        "src/db.js",
        "const db = require('mysql').createConnection({});\nfunction run(id) {\n  \
         const sql = 'SELECT * FROM items WHERE id = ' + id;\n  return db.query(sql);\n}\n\
         module.exports = { run };\n",
    );
    write(
        root,
        "scripts/tool.js",
        "const { exec } = require('child_process');\n\
         require('express')().get('/x', (req, res) => exec(req.query.cmd));\n",
    );
}

fn classes(report: &Value) -> Vec<String> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            format!(
                "{}:{}",
                f["class"].as_str().unwrap(),
                f["severity"].as_str().unwrap()
            )
        })
        .collect()
}

#[test]
fn fail_on_and_baselines_gate_the_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    app(dir.path());
    let root = dir.path();

    let all = jsspector(
        &["scan", ".", "--format", "json", "--fail-on", "high"],
        root,
    );
    assert_eq!(all.status.code(), Some(1));
    let report = json(&all);
    let mut found = classes(&report);
    found.sort();
    assert_eq!(
        found,
        [
            "command-injection:critical",
            "command-injection:high",
            "sql-injection:high"
        ]
    );
    assert_eq!(report["ignored"], 1);
    // Fingerprints are 16 hex digits and unique.
    let fingerprints: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["fingerprint"].as_str().unwrap())
        .collect();
    assert!(fingerprints.iter().all(|f| f.len() == 16));

    // Below the threshold: exit 0.
    let critical_only = jsspector(
        &[
            "scan",
            ".",
            "--format",
            "json",
            "--fail-on",
            "critical",
            "--exclude",
            "scripts/",
        ],
        root,
    );
    assert_eq!(critical_only.status.code(), Some(0));
    assert_eq!(
        json(&critical_only)["findings"].as_array().unwrap().len(),
        2
    );

    // Accept everything, then nothing new fails the build.
    let written = jsspector(&["scan", ".", "--write-baseline", "base.json"], root);
    assert_eq!(written.status.code(), Some(0));
    let gated = jsspector(
        &[
            "scan",
            ".",
            "--format",
            "json",
            "--baseline",
            "base.json",
            "--fail-on",
            "low",
        ],
        root,
    );
    assert_eq!(gated.status.code(), Some(0));
    let gated = json(&gated);
    assert_eq!(gated["findings"].as_array().unwrap().len(), 0);
    assert_eq!(gated["baselined"], 3);

    // A new finding is reported, and only it.
    write(
        root,
        "src/new.js",
        "const fs = require('fs');\nrequire('express')().get('/f', (req, res) => \
         fs.readFile(req.query.p, () => {}));\n",
    );
    let fresh = jsspector(
        &[
            "scan",
            ".",
            "--format",
            "json",
            "--baseline",
            "base.json",
            "--fail-on",
            "high",
        ],
        root,
    );
    assert_eq!(fresh.status.code(), Some(1));
    assert_eq!(classes(&json(&fresh)), ["path-traversal:high"]);

    // A baseline named on the command line must exist.
    let missing = jsspector(&["scan", ".", "--baseline", "nope.json"], root);
    assert_eq!(missing.status.code(), Some(2));
}

#[test]
fn line_shifts_keep_fingerprints() {
    let dir = tempfile::tempdir().unwrap();
    app(dir.path());
    let fingerprints = |root: &Path| -> Vec<String> {
        let mut prints: Vec<String> =
            json(&jsspector(&["scan", ".", "--format", "json"], root))["findings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["fingerprint"].as_str().unwrap().to_owned())
                .collect();
        prints.sort();
        prints
    };
    let before = fingerprints(dir.path());
    let server = dir.path().join("src/server.js");
    let text = fs::read_to_string(&server).unwrap();
    fs::write(&server, format!("// a header\n\n{text}")).unwrap();
    let db = dir.path().join("src/db.js");
    let text = fs::read_to_string(&db).unwrap();
    fs::write(&db, format!("'use strict';\n{text}")).unwrap();
    assert_eq!(fingerprints(dir.path()), before);
}

#[test]
fn sarif_carries_rules_flows_and_fingerprints() {
    let dir = tempfile::tempdir().unwrap();
    app(dir.path());
    let output = jsspector(
        &["scan", ".", "--format", "sarif", "-o", "out.sarif"],
        dir.path(),
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    let log: Value =
        serde_json::from_slice(&fs::read(dir.path().join("out.sarif")).unwrap()).unwrap();
    assert_eq!(log["version"], "2.1.0");
    let run = &log["runs"][0];
    assert_eq!(run["columnKind"], "utf16CodeUnits");
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 8);
    for rule in rules {
        let severity: f64 = rule["properties"]["security-severity"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((0.0..=10.0).contains(&severity));
    }
    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    let sql = results
        .iter()
        .find(|r| r["ruleId"] == "jsspector.sql-injection")
        .unwrap();
    assert_eq!(
        rules[sql["ruleIndex"].as_u64().unwrap() as usize]["id"],
        sql["ruleId"]
    );
    assert_eq!(
        sql["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/db.js"
    );
    assert_eq!(
        sql["partialFingerprints"]["jsspector/v1"]
            .as_str()
            .unwrap()
            .len(),
        16
    );
    let flow = sql["codeFlows"][0]["threadFlows"][0]["locations"]
        .as_array()
        .unwrap();
    let first = &flow[0]["location"]["physicalLocation"];
    let last = &flow[flow.len() - 1]["location"]["physicalLocation"];
    assert_eq!(first["artifactLocation"]["uri"], "src/server.js");
    assert_eq!(last["artifactLocation"]["uri"], "src/db.js");
    assert!(flow.len() >= 3, "{flow:?}");

    // A SARIF log works as a baseline too.
    let gated = jsspector(
        &[
            "scan",
            ".",
            "--format",
            "json",
            "--baseline",
            "out.sarif",
            "--fail-on",
            "low",
        ],
        dir.path(),
    );
    assert_eq!(gated.status.code(), Some(0));
    assert_eq!(json(&gated)["baselined"], 3);
}

#[test]
fn the_config_file_sets_defaults_and_conventions() {
    let dir = tempfile::tempdir().unwrap();
    app(dir.path());
    let root = dir.path();
    write(
        root,
        "sec/report.yaml",
        "name: in-house\nsinks:\n  - {global: [runReport], class: command-injection, severity: \
         critical, args: [\"any:0\"]}\n",
    );
    write(
        root,
        ".jsspector.yml",
        "min_severity: high\nfail_on: critical\nexclude: [scripts/]\ndisable: [sql-injection]\n\
         packs: [sec/report.yaml]\nauth:\n  require: [gatekeeper]\n",
    );
    let output = jsspector(&["scan", ".", "--format", "json"], root);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the in-house sink is critical"
    );
    let report = json(&output);
    let mut found = classes(&report);
    found.sort();
    assert_eq!(
        found,
        ["command-injection:critical", "command-injection:high"]
    );
    let gated = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["sink"]["api"] == "runReport")
        .unwrap();
    assert_eq!(gated["auth"], "user");

    // The routes honor the excludes and the auth conventions too.
    let routes = json(&jsspector(&["routes", ".", "--json"], root));
    let routes = routes.as_array().unwrap();
    assert!(routes.iter().all(|r| r["path"] != "/x"));
    let gated = routes.iter().find(|r| r["path"] == "/gated").unwrap();
    assert_eq!(gated["auth"], "user");

    // The command line wins; --no-config ignores the file.
    let all = jsspector(&["scan", ".", "--format", "json", "--no-config"], root);
    assert_eq!(all.status.code(), Some(0));
    assert_eq!(json(&all)["findings"].as_array().unwrap().len(), 3);

    // Mistakes in the file are usage errors.
    write(
        root,
        ".jsspector.yml",
        "min_severity: high\nexclude_paths: [x]\n",
    );
    assert_eq!(jsspector(&["scan", "."], root).status.code(), Some(2));
    write(root, ".jsspector.yml", "disable: [lint]\n");
    assert_eq!(jsspector(&["scan", "."], root).status.code(), Some(2));
    write(root, ".jsspector.yml", "packs: [sec/missing.yaml]\n");
    assert_eq!(jsspector(&["scan", "."], root).status.code(), Some(2));
}

#[test]
fn explain_shows_rules_and_findings() {
    let dir = tempfile::tempdir().unwrap();
    app(dir.path());
    let root = dir.path();

    let rule = jsspector(&["explain", "path-traversal"], root);
    assert_eq!(rule.status.code(), Some(0));
    let text = String::from_utf8(rule.stdout).unwrap();
    assert!(text.contains("CWE-22"), "{text}");
    assert!(text.contains("fs.readFile"), "{text}");

    let report = json(&jsspector(&["scan", ".", "--format", "json"], root));
    let sql = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["class"] == "sql-injection")
        .unwrap();
    let fingerprint = sql["fingerprint"].as_str().unwrap();
    let explained = jsspector(&["explain", &fingerprint[..8], "."], root);
    assert_eq!(explained.status.code(), Some(0));
    let text = String::from_utf8(explained.stdout).unwrap();
    assert!(text.contains("GET /items"), "{text}");
    assert!(text.contains("src/db.js:4"), "{text}");
    assert!(text.contains("return db.query(sql);"), "{text}");
    assert!(text.contains("jsspector-ignore sql-injection"), "{text}");

    let as_json = json(&jsspector(&["explain", fingerprint, ".", "--json"], root));
    assert_eq!(as_json["finding"]["fingerprint"], fingerprint);
    assert_eq!(as_json["rule"]["cwe"], 89);

    assert_eq!(
        jsspector(&["explain", "0000000000000000", "."], root)
            .status
            .code(),
        Some(2)
    );
}
