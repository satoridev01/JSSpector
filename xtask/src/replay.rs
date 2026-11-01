//! `cargo xtask replay`: score `jsspector scan` against published advisories (CVE replay).
//!
//! For each verified pair in `corpus/research/cve-replay-seed.json` whose class the scanner
//! covers, the repository is fetched at the vulnerable commit (`fix^1`) and at the fix (blobless,
//! sparse: JavaScript/TypeScript files only; nothing in it is ever run), scanned, and scored:
//! - detected: a finding of the advisory's class has its sink in the advisory's sink file;
//! - cleared: no such finding at the fix commit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

/// Advisory classes the scanner has sinks for.
const CLASSES: &[&str] = &[
    "command-injection",
    "code-injection",
    "sql-injection",
    "nosql-injection",
    "path-traversal",
    "ssrf",
    "xss",
    "prototype-pollution",
];

/// Sparse-checkout patterns: sources and the package files that decide module types.
pub(crate) const SPARSE: &[&str] = &[
    "*.js",
    "*.jsx",
    "*.ts",
    "*.tsx",
    "*.mjs",
    "*.cjs",
    "*.mts",
    "*.cts",
    "package.json",
    "tsconfig*.json",
    "jsconfig*.json",
    "!node_modules/",
];

pub struct Options {
    pub root: PathBuf,
    pub cache: PathBuf,
    pub limit: Option<usize>,
    pub repo: Option<String>,
    pub out: Option<PathBuf>,
    /// The scanner to run (default: `target/release/jsspector`).
    pub binary: Option<PathBuf>,
}

struct Pair {
    repo: String,
    id: String,
    class: String,
    vulnerable: String,
    fix: String,
    sink_file: String,
    /// The advisory's sink line at the vulnerable commit, when it gives one.
    sink_line: Option<u64>,
}

pub fn run(options: &Options) -> Result<()> {
    let seed: Value = serde_json::from_str(
        &std::fs::read_to_string(options.root.join("corpus/research/cve-replay-seed.json"))
            .context("corpus/research/cve-replay-seed.json")?,
    )?;
    let pairs = pairs(&seed, options);
    eprintln!("replay: {} pairs in covered classes", pairs.len());
    let binary = options
        .binary
        .clone()
        .unwrap_or_else(|| options.root.join("target/release/jsspector"));
    if !binary.exists() {
        bail!("build the scanner first: cargo build --release -p jsspector");
    }
    let mut results = Vec::new();
    let (mut detected, mut cleared, mut scored) = (0usize, 0usize, 0usize);
    let mut by_class: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for pair in &pairs {
        let outcome = score(pair, &options.cache, &binary);
        let (status, hit, clear) = match &outcome {
            Ok((hit, clear)) => ("ok", *hit, *clear),
            Err(err) => {
                eprintln!("  {} {}: {err:#}", pair.repo, pair.id);
                ("error", false, false)
            }
        };
        if status == "ok" {
            scored += 1;
            detected += usize::from(hit);
            cleared += usize::from(hit && clear);
            let entry = by_class.entry(pair.class.clone()).or_default();
            entry.0 += 1;
            entry.1 += usize::from(hit);
        }
        eprintln!(
            "  {:<8} {:<7} {:<20} {:<28} {}",
            if hit { "DETECTED" } else { "missed" },
            if hit && clear { "cleared" } else { "" },
            pair.class,
            pair.repo,
            pair.id
        );
        results.push(json!({
            "repo": pair.repo, "id": pair.id, "class": pair.class, "sink_file": pair.sink_file,
            "vulnerable": pair.vulnerable, "fix": pair.fix,
            "status": status, "detected": hit, "cleared": hit && clear,
            "error": outcome.err().map(|e| format!("{e:#}")),
        }));
    }
    let recall = ratio(detected, scored);
    let clearance = ratio(cleared, detected);
    eprintln!(
        "\nreplay: detected {detected}/{scored} ({recall:.1}%), cleared at the fix {cleared}/{detected} ({clearance:.1}%)"
    );
    for (class, (total, hit)) in &by_class {
        eprintln!("  {class:<20} {hit}/{total}");
    }
    let report = json!({
        "pairs": results,
        "scored": scored, "detected": detected, "cleared": cleared,
        "recall_percent": recall, "clearance_percent": clearance,
    });
    match &options.out {
        Some(path) => std::fs::write(path, serde_json::to_string_pretty(&report)?)?,
        None => println!("{}", serde_json::to_string_pretty(&report)?),
    }
    Ok(())
}

/// `value[key]`, or null.
fn get<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

fn ratio(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        let r = part as f64 * 100.0 / whole as f64;
        r
    }
}

fn pairs(seed: &Value, options: &Options) -> Vec<Pair> {
    let mut out = Vec::new();
    let repos = get(seed, "repos").as_array().cloned().unwrap_or_default();
    for repo in &repos {
        let name = get(repo, "repo").as_str().unwrap_or_default().to_owned();
        if options.repo.as_deref().is_some_and(|r| r != name) {
            continue;
        }
        for candidate in get(repo, "replay_candidates")
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let verdict = get(get(&candidate, "verification"), "verdict")
                .as_str()
                .unwrap_or("");
            let class = get(&candidate, "vuln_class")
                .as_str()
                .unwrap_or("")
                .to_owned();
            if !matches!(verdict, "verified" | "corrected") || !CLASSES.contains(&class.as_str()) {
                continue;
            }
            let location = get(&candidate, "sink_location").as_str().unwrap_or("");
            let sink_file = location.split([':', ' ']).next().unwrap_or("").to_owned();
            // `path/file.ts:892 — ...`
            let sink_line = location
                .strip_prefix(sink_file.as_str())
                .and_then(|rest| rest.strip_prefix(':'))
                .map(|rest| {
                    rest.chars()
                        .take_while(char::is_ascii_digit)
                        .collect::<String>()
                })
                .and_then(|digits| digits.parse().ok());
            let id = get(&candidate, "cve")
                .as_str()
                .filter(|c| !c.is_empty())
                .or_else(|| get(&candidate, "ghsa").as_str())
                .unwrap_or("?")
                .to_owned();
            out.push(Pair {
                repo: name.clone(),
                id,
                class,
                vulnerable: get(&candidate, "vulnerable_commit")
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                fix: get(&candidate, "fix_commit")
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                sink_file,
                sink_line,
            });
        }
    }
    if let Some(limit) = options.limit {
        out.truncate(limit);
    }
    out
}

/// (detected at the vulnerable commit, absent at the fix).
/// (detected at the vulnerable commit, cleared at the fix). Detected: a finding of the
/// advisory's class family with its sink in the advisory's file (the nearest to the advisory's
/// line when it gives one). Cleared: none of those findings' line-independent keys remain at the
/// fix (other findings in the same file do not count against it).
fn score(pair: &Pair, cache: &Path, binary: &Path) -> Result<(bool, bool)> {
    let dir = cache.join(pair.repo.replace('/', "__"));
    let keys = matching(&scan_at(&dir, &pair.repo, &pair.vulnerable, binary)?, pair);
    if keys.is_empty() {
        return Ok((false, false));
    }
    let fixed = scan_at(&dir, &pair.repo, &pair.fix, binary)?;
    let remaining = get(&fixed, "findings").as_array().is_some_and(|findings| {
        findings.iter().any(|f| {
            get(f, "key")
                .as_str()
                .is_some_and(|k| keys.iter().any(|key| key == k))
        })
    });
    Ok((true, !remaining))
}

/// The keys of the findings that match the advisory.
fn matching(report: &Value, pair: &Pair) -> Vec<String> {
    let candidates: Vec<(u64, String)> = get(report, "findings")
        .as_array()
        .map(|findings| {
            findings
                .iter()
                .filter(|f| {
                    let file = get(get(f, "sink"), "file")
                        .as_str()
                        .or_else(|| get(f, "file").as_str())
                        .unwrap_or("");
                    family(get(f, "class").as_str().unwrap_or("")) == family(&pair.class)
                        && file == pair.sink_file
                })
                .map(|f| {
                    let line = get(get(f, "sink"), "line").as_u64().unwrap_or(0);
                    let distance = pair.sink_line.map_or(0, |at| line.abs_diff(at));
                    (distance, get(f, "key").as_str().unwrap_or("").to_owned())
                })
                .collect()
        })
        .unwrap_or_default();
    // The nearest to the advisory's line (within a window); otherwise every match in the file.
    let nearest = candidates.iter().map(|(d, _)| *d).min().unwrap_or(0);
    candidates
        .into_iter()
        .filter(|(d, _)| nearest > 40 || *d == nearest)
        .map(|(_, key)| key)
        .collect()
}

/// Classes scored as one: command and code injection are both code execution.
fn family(class: &str) -> &str {
    match class {
        "command-injection" | "code-injection" => "code-execution",
        other => other,
    }
}

pub(crate) fn git(dir: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "advice.detachedHead=false",
        ])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()
        .with_context(|| format!("git {args:?}"))?;
    if !status.success() {
        bail!("git {} failed ({status})", args.join(" "));
    }
    Ok(())
}

/// Checks `commit` out (blobless, sparse) and scans it.
fn scan_at(dir: &Path, repo: &str, commit: &str, binary: &Path) -> Result<Value> {
    if !dir.join(".git").exists() {
        std::fs::create_dir_all(dir)?;
        git(dir, &["init", "-q"])?;
        git(
            dir,
            &[
                "remote",
                "add",
                "origin",
                &format!("https://github.com/{repo}.git"),
            ],
        )?;
        let mut sparse = vec!["sparse-checkout", "set", "--no-cone"];
        sparse.extend_from_slice(SPARSE);
        git(dir, &sparse)?;
    }
    git(
        dir,
        &[
            "fetch",
            "-q",
            "--depth",
            "1",
            "--filter=blob:none",
            "origin",
            commit,
        ],
    )?;
    git(dir, &["checkout", "-q", "--force", "--detach", commit])?;
    let output = Command::new(binary)
        .args(["scan", "--json", "--min-severity", "low", "--threads", "8"])
        .arg(dir)
        .output()?;
    if !output.status.success() {
        bail!("scan failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
