//! SARIF 2.1.0 output for `scan --format sarif`: one run, one rule per vulnerability class, one
//! result per finding with its witness path as a `codeFlow`, its fingerprint in
//! `partialFingerprints`, and columns in UTF-16 code units.

use std::path::Path;

use jss_core::{Finding, Severity};
use serde_json::{Value, json};

use crate::rules::{self, CLASSES};

/// The `partialFingerprints` key. Bump the version if the key format ever changes.
const FINGERPRINT_KEY: &str = "jsspector/v1";

/// A file the scan could not analyze, reported as a tool notification.
pub struct Note<'a> {
    pub file: &'a str,
    pub reason: &'a str,
    /// The analysis crashed on this file (contained), rather than skipping it on purpose.
    pub error: bool,
}

/// The SARIF log of a scan of `root` (absolute) that reported `findings`. With `baseline`, every
/// result is marked `baselineState: new` (findings in the baseline are not reported at all).
pub fn document(
    root: &Path,
    findings: &[Finding],
    notes: &[Note<'_>],
    baseline: bool,
    verified: &std::collections::BTreeMap<String, &str>,
) -> Value {
    let rules: Vec<Value> = CLASSES.iter().map(|class| rule(*class)).collect();
    let results: Vec<Value> = findings
        .iter()
        .map(|f| result(f, baseline, verified.get(f.fingerprint.as_str()).copied()))
        .collect();
    let notifications: Vec<Value> = notes
        .iter()
        .map(|note| {
            json!({
                "level": if note.error { "error" } else { "note" },
                "descriptor": { "id": if note.error { "analysis-panicked" } else { "file-skipped" } },
                "message": { "text": note.reason },
                "locations": [{ "physicalLocation": { "artifactLocation": artifact(note.file) } }],
            })
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "JSSpector",
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "informationUri": env!("CARGO_PKG_REPOSITORY"),
                    "rules": rules,
                }
            },
            "originalUriBaseIds": {
                "SRCROOT": { "uri": root_uri(root) }
            },
            "invocations": [{
                "executionSuccessful": true,
                "toolExecutionNotifications": notifications,
            }],
            "columnKind": "utf16CodeUnits",
            "results": results,
        }]
    })
}

fn rule(class: jss_core::VulnClass) -> Value {
    let rule = rules::rule(class);
    let mut help = String::new();
    for paragraph in rule.fix {
        help.push_str(paragraph);
        help.push_str("\n\n");
    }
    help.push_str("Treated as safe: ");
    help.push_str(rule.safe);
    help.push('.');
    json!({
        "id": rules::id(class),
        "name": rule.name,
        "shortDescription": { "text": rule.title },
        "fullDescription": { "text": rule.summary },
        "help": { "text": help, "markdown": help },
        "helpUri": format!("{}#rules", env!("CARGO_PKG_REPOSITORY")),
        "defaultConfiguration": { "level": "error" },
        "properties": {
            "tags": ["security", format!("external/cwe/cwe-{}", rule.cwe)],
            "precision": "medium",
            "problem.severity": "error",
            "security-severity": rule.security_severity,
        }
    })
}

fn result(f: &Finding, baseline: bool, verification: Option<&str>) -> Value {
    let sink_file = f.sink.file.as_deref().unwrap_or(&f.file);
    let mut message = format!(
        "Data from `{}` ({}) {}: `{}`.",
        f.source.expr,
        f.source.kind,
        rules::describe(f.class),
        f.sink.api
    );
    if let Some(entry) = &f.entry {
        message.push_str(&format!(" Reached from {entry}"));
    } else {
        message.push_str(&format!(" In {}", f.function));
    }
    message.push_str(&format!(" (auth: {}).", f.auth.name()));

    let mut flow = vec![json!({
        "location": location(&f.file, f.source.line, f.source.col,
            &format!("source: {} ({})", f.source.expr, f.source.kind)),
    })];
    for step in &f.trace {
        let file = step.file.as_deref().unwrap_or(&f.file);
        flow.push(json!({ "location": location(file, step.line, step.col, &step.note) }));
    }
    flow.push(json!({
        "location": location(sink_file, f.sink.line, f.sink.col,
            &format!("sink: {}({})", f.sink.api, f.sink.arg)),
    }));

    let mut properties = json!({
        "severity": rules::severity_name(f.severity),
        "auth": f.auth.name(),
        "function": f.function,
        "confidence": f.confidence,
        "key": f.key,
    });
    if let (Some(entry), Some(map)) = (&f.entry, properties.as_object_mut()) {
        map.insert("entry".to_owned(), json!(entry));
    }
    // `--verify` outcome, when the run verified findings dynamically.
    if let (Some(outcome), Some(map)) = (verification, properties.as_object_mut()) {
        map.insert("verification".to_owned(), json!(outcome));
    }
    let mut result = json!({
        "ruleId": rules::id(f.class),
        "ruleIndex": rules::index(f.class),
        "level": level(f.severity),
        "message": { "text": message },
        "locations": [location(sink_file, f.sink.line, f.sink.col, "")],
        "relatedLocations": [{
            "id": 1,
            "physicalLocation": physical(&f.file, f.source.line, f.source.col),
            "message": { "text": format!("source: {}", f.source.expr) },
        }],
        "partialFingerprints": { FINGERPRINT_KEY: f.fingerprint },
        "codeFlows": [{ "threadFlows": [{ "locations": flow }] }],
        "properties": properties,
    });
    if baseline && let Some(map) = result.as_object_mut() {
        map.insert("baselineState".to_owned(), json!("new"));
    }
    result
}

/// `error` for critical and high, `warning` for medium, `note` for low.
fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn location(file: &str, line: u32, col: u32, message: &str) -> Value {
    let mut location = json!({ "physicalLocation": physical(file, line, col) });
    if !message.is_empty()
        && let Some(map) = location.as_object_mut()
    {
        map.insert("message".to_owned(), json!({ "text": message }));
    }
    location
}

fn physical(file: &str, line: u32, col: u32) -> Value {
    let mut physical = json!({ "artifactLocation": artifact(file) });
    // Line 0 means unknown: SARIF regions are 1-based, so leave the region out.
    if line > 0
        && let Some(map) = physical.as_object_mut()
    {
        map.insert(
            "region".to_owned(),
            json!({ "startLine": line, "startColumn": col.max(1) }),
        );
    }
    physical
}

fn artifact(file: &str) -> Value {
    json!({ "uri": encode(&file.replace('\\', "/"), false), "uriBaseId": "SRCROOT" })
}

/// `file:///abs/root/`.
fn root_uri(root: &Path) -> String {
    let mut path = root.to_string_lossy().replace('\\', "/");
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    format!("file://{}", encode(&path, true))
}

/// Percent-encodes what may not appear in a URI path: everything but unreserved characters,
/// sub-delimiters, `@`, `/` and (with `colon`) `:`. A `:` in a relative reference would read as a
/// scheme, so it is encoded there.
fn encode(path: &str, colon: bool) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || b"-._~!$&'()*+,;=@/".contains(&byte)
            || (colon && byte == b':');
        if keep {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use jss_core::{Auth, SinkLoc, SourceLoc, TraceStep, VulnClass};

    fn finding() -> Finding {
        Finding {
            file: "src/routes/a b.js".to_owned(),
            sink: SinkLoc {
                file: Some("src/db.js".to_owned()),
                api: "db.query".to_owned(),
                arg: "sql".to_owned(),
                line: 9,
                col: 3,
            },
            class: VulnClass::SqlInjection,
            severity: Severity::Critical,
            confidence: "heuristic",
            auth: Auth::NoneDetected,
            function: "list".to_owned(),
            entry: Some("GET /items".to_owned()),
            entry_at: None,
            source: SourceLoc {
                kind: "http",
                expr: "req.query.id".to_owned(),
                line: 4,
                col: 15,
            },
            trace: vec![
                TraceStep {
                    file: None,
                    line: 5,
                    col: 3,
                    note: "passed to find".to_owned(),
                },
                TraceStep {
                    file: Some("src/db.js".to_owned()),
                    line: 8,
                    col: 9,
                    note: "built into sql".to_owned(),
                },
            ],
            key: "k".to_owned(),
            fingerprint: "0123456789abcdef".to_owned(),
        }
    }

    #[test]
    fn a_finding_becomes_a_result_with_its_flow() {
        let log = document(
            Path::new("/repo dir"),
            &[finding()],
            &[],
            true,
            &std::collections::BTreeMap::new(),
        );
        let run = &log["runs"][0];
        assert_eq!(log["version"], "2.1.0");
        assert_eq!(run["columnKind"], "utf16CodeUnits");
        assert_eq!(
            run["originalUriBaseIds"]["SRCROOT"]["uri"],
            "file:///repo%20dir/"
        );
        assert_eq!(
            run["tool"]["driver"]["rules"].as_array().map(Vec::len),
            Some(8)
        );
        let result = &run["results"][0];
        assert_eq!(result["ruleId"], "jsspector.sql-injection");
        assert_eq!(
            run["tool"]["driver"]["rules"][result["ruleIndex"].as_u64().unwrap_or(99) as usize]["id"],
            "jsspector.sql-injection"
        );
        assert_eq!(result["level"], "error");
        assert_eq!(result["baselineState"], "new");
        assert_eq!(
            result["partialFingerprints"]["jsspector/v1"],
            "0123456789abcdef"
        );
        let sink = &result["locations"][0]["physicalLocation"];
        assert_eq!(sink["artifactLocation"]["uri"], "src/db.js");
        assert_eq!(sink["region"]["startLine"], 9);
        let flow = result["codeFlows"][0]["threadFlows"][0]["locations"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        // source, two steps, sink
        assert_eq!(flow.len(), 4);
        assert_eq!(
            flow[0]["location"]["physicalLocation"]["artifactLocation"]["uri"],
            "src/routes/a%20b.js"
        );
        assert_eq!(
            flow[2]["location"]["physicalLocation"]["artifactLocation"]["uri"],
            "src/db.js"
        );
        assert_eq!(result["properties"]["entry"], "GET /items");
        // No verification property unless a verdict was supplied.
        assert!(result["properties"].get("verification").is_none());
    }

    #[test]
    fn a_verified_finding_carries_its_outcome() {
        let mut verified = std::collections::BTreeMap::new();
        verified.insert(finding().fingerprint, "verified");
        let log = document(Path::new("/r"), &[finding()], &[], false, &verified);
        assert_eq!(
            log["runs"][0]["results"][0]["properties"]["verification"],
            "verified"
        );
    }

    #[test]
    fn uris_are_encoded() {
        assert_eq!(encode("a/@scope/b c#1.js", false), "a/@scope/b%20c%231.js");
        assert_eq!(encode("C:/x", false), "C%3A/x");
        assert_eq!(encode("/C:/x/", true), "/C:/x/");
        assert_eq!(encode("é", false), "%C3%A9");
    }
}
