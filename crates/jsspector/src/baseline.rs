//! Baselines: findings accepted earlier, by fingerprint. `scan --write-baseline FILE` records the
//! findings reported now; `scan --baseline FILE` (or `baseline:` in `.jsspector.yml`) then reports
//! only findings that are not in it.
//!
//! A baseline is read from any JSON with a `findings` array of objects with a `fingerprint` (a
//! baseline file, or a saved `scan --format json` report), or from a SARIF log written by
//! `scan --format sarif`.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

use jss_core::Finding;
use serde::Serialize;
use serde_json::Value;

/// Schema identifier of a baseline file.
pub const SCHEMA: &str = "jsspector.baseline/1";

#[derive(Serialize)]
struct File<'a> {
    schema: &'static str,
    /// One entry per finding, sorted by fingerprint. Everything but the fingerprint is there to
    /// make the file readable in review.
    findings: Vec<Entry<'a>>,
}

#[derive(Serialize)]
struct Entry<'a> {
    fingerprint: &'a str,
    class: &'static str,
    severity: &'static str,
    file: &'a str,
    function: &'a str,
    sink: &'a str,
    source: &'a str,
}

/// Writes `findings` as a baseline to `path`.
pub fn write(path: &Path, findings: &[Finding]) -> Result<(), String> {
    let mut entries: Vec<Entry<'_>> = findings
        .iter()
        .map(|f| Entry {
            fingerprint: &f.fingerprint,
            class: f.class.name(),
            severity: crate::rules::severity_name(f.severity),
            file: f.sink.file.as_deref().unwrap_or(&f.file),
            function: &f.function,
            sink: &f.sink.api,
            source: &f.source.expr,
        })
        .collect();
    entries.sort_by(|a, b| (a.fingerprint, a.file).cmp(&(b.fingerprint, b.file)));
    entries.dedup_by(|a, b| a.fingerprint == b.fingerprint);
    let file = File {
        schema: SCHEMA,
        findings: entries,
    };
    let mut text =
        serde_json::to_vec_pretty(&file).map_err(|err| format!("cannot encode baseline: {err}"))?;
    text.push(b'\n');
    std::fs::File::create(path)
        .and_then(|mut out| out.write_all(&text))
        .map_err(|err| format!("cannot write baseline {}: {err}", path.display()))
}

/// The fingerprints in the baseline at `path`.
pub fn read(path: &Path) -> Result<BTreeSet<String>, String> {
    let text = std::fs::read(path)
        .map_err(|err| format!("cannot read baseline {}: {err}", path.display()))?;
    let value: Value = serde_json::from_slice(&text)
        .map_err(|err| format!("baseline {} is not JSON: {err}", path.display()))?;
    fingerprints(&value).ok_or_else(|| {
        format!(
            "baseline {}: expected a `findings` array with fingerprints (a baseline or a JSON \
             report) or a SARIF log",
            path.display()
        )
    })
}

fn fingerprints(value: &Value) -> Option<BTreeSet<String>> {
    if let Some(findings) = value.get("findings").and_then(Value::as_array) {
        return Some(
            findings
                .iter()
                .filter_map(|f| f.get("fingerprint").and_then(Value::as_str))
                .map(str::to_owned)
                .collect(),
        );
    }
    let runs = value.get("runs").and_then(Value::as_array)?;
    Some(
        runs.iter()
            .filter_map(|run| run.get("results").and_then(Value::as_array))
            .flatten()
            .filter_map(|result| {
                result
                    .get("partialFingerprints")
                    .and_then(|p| p.get("jsspector/v1"))
                    .and_then(Value::as_str)
            })
            .map(str::to_owned)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn baselines_read_reports_and_sarif() {
        let report = json!({ "findings": [{ "fingerprint": "a" }, { "fingerprint": "b" }] });
        assert_eq!(fingerprints(&report).unwrap().len(), 2);
        let sarif = json!({ "runs": [{ "results": [
            { "partialFingerprints": { "jsspector/v1": "c" } },
            { "partialFingerprints": { "other": "d" } },
        ] }] });
        assert_eq!(
            fingerprints(&sarif)
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["c"]
        );
        assert!(fingerprints(&json!({ "x": 1 })).is_none());
    }
}
