//! `cargo xtask corpus`: fetch a corpus of repositories and scan all of it (the full-corpus job,
//! run locally or on Satori through `.satori.yml`).
//!
//! The list of repositories is input, never part of this repository: `owner/name@commit`,
//! `owner/name commit` or `owner/name` (the default branch's head), one per line or separated by
//! spaces; `#` starts a comment. Repositories are fetched shallow, blobless and sparse
//! (JavaScript/TypeScript sources and the package files that decide module types) at that
//! commit. Nothing in them is ever run: they are only read by the scanner.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::replay::{SPARSE, git};

/// One repository of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    /// `owner/name`.
    pub name: String,
    /// The commit to scan; the default branch's head when absent.
    pub commit: Option<String>,
}

impl Repo {
    /// Its directory under the corpus directory: `owner__name`.
    pub fn dir(&self, root: &Path) -> PathBuf {
        root.join(self.name.replace('/', "__"))
    }
}

/// Parses a list (see the module documentation).
pub fn parse_list(text: &str) -> Result<Vec<Repo>> {
    let mut repos: Vec<Repo> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        for token in line.split_whitespace() {
            let is_commit = token.len() >= 7 && token.chars().all(|c| c.is_ascii_hexdigit());
            if is_commit {
                match repos.last_mut() {
                    Some(repo) if repo.commit.is_none() => repo.commit = Some(token.to_owned()),
                    _ => bail!("commit `{token}` does not follow a repository"),
                }
                continue;
            }
            let (name, commit) = match token.split_once('@') {
                Some((name, commit)) => (name, Some(commit.to_owned())),
                None => (token, None),
            };
            let valid = |part: &str| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            };
            match name.split_once('/') {
                Some((owner, repo)) if valid(owner) && valid(repo) => {}
                _ => bail!("`{token}` is not owner/name[@commit]"),
            }
            if let Some(commit) = &commit
                && !(commit.len() >= 7 && commit.chars().all(|c| c.is_ascii_hexdigit()))
            {
                bail!("`{token}`: the commit must be a hexadecimal hash");
            }
            repos.push(Repo {
                name: name.to_owned(),
                commit,
            });
        }
    }
    Ok(repos)
}

pub struct Options {
    pub repos: Vec<Repo>,
    /// Where repositories are fetched (reused between runs).
    pub dir: PathBuf,
    /// Fetch before scanning.
    pub fetch: bool,
    /// Scan (after fetching, if asked).
    pub scan: bool,
    pub binary: PathBuf,
    /// Where each repository's JSON report and `summary.json` go.
    pub out: PathBuf,
    /// Scanner threads per repository.
    pub threads: usize,
    /// Repositories fetched at once.
    pub jobs: usize,
    /// Print the findings at or above this severity, per repository.
    pub show: Option<String>,
    /// A previous `summary.json` to compare finding counts with.
    pub compare: Option<PathBuf>,
}

/// Fetches and/or scans the corpus. Fails when a scan crashed or a file panicked; a repository
/// that cannot be fetched is reported and skipped.
pub fn run(options: &Options) -> Result<()> {
    std::fs::create_dir_all(&options.dir)
        .with_context(|| format!("create {}", options.dir.display()))?;
    let mut fetch_errors: BTreeMap<String, String> = BTreeMap::new();
    if options.fetch {
        fetch_errors = fetch_all(options);
    }
    if !options.scan {
        if !fetch_errors.is_empty() {
            bail!("{} repositories could not be fetched", fetch_errors.len());
        }
        return Ok(());
    }
    if !options.binary.exists() {
        bail!(
            "{} does not exist: build the scanner first (cargo build --release -p jsspector)",
            options.binary.display()
        );
    }
    std::fs::create_dir_all(&options.out)
        .with_context(|| format!("create {}", options.out.display()))?;
    let started = Instant::now();
    let mut rows = Vec::new();
    let mut failures = Vec::new();
    for repo in &options.repos {
        if let Some(err) = fetch_errors.get(&repo.name) {
            rows.push(json!({ "repo": repo.name, "status": "fetch-failed", "error": err }));
            continue;
        }
        let dir = repo.dir(&options.dir);
        if !dir.exists() {
            rows.push(json!({ "repo": repo.name, "status": "missing" }));
            continue;
        }
        let row = scan(repo, &dir, options)?;
        if at(&row, &["status"]) != "ok" || at(&row, &["panicked"]).as_u64().unwrap_or(0) > 0 {
            failures.push(repo.name.clone());
        }
        rows.push(row);
    }
    let summary = summarize(&rows, started.elapsed().as_secs_f64());
    std::fs::write(
        options.out.join("summary.json"),
        serde_json::to_string_pretty(&json!({ "repos": rows, "totals": summary }))?,
    )?;
    print_table(&rows, &summary);
    if let Some(previous) = &options.compare {
        compare(&rows, previous)?;
    }
    if !failures.is_empty() {
        bail!(
            "{} repositories crashed the scanner or panicked: {}",
            failures.len(),
            failures.join(", ")
        );
    }
    Ok(())
}

/// Fetches every repository, `options.jobs` at a time; returns the failures by repository.
fn fetch_all(options: &Options) -> BTreeMap<String, String> {
    let next = AtomicUsize::new(0);
    let errors = Mutex::new(BTreeMap::new());
    let done = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..options.jobs.max(1) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(repo) = options.repos.get(index) else {
                        break;
                    };
                    let result = fetch(repo, &repo.dir(&options.dir));
                    let finished = done.fetch_add(1, Ordering::Relaxed) + 1;
                    match result {
                        Ok(commit) => eprintln!(
                            "  fetched {finished}/{} {} @ {}",
                            options.repos.len(),
                            repo.name,
                            commit.get(..12).unwrap_or(&commit)
                        ),
                        Err(err) => {
                            eprintln!("  FAILED {} : {err:#}", repo.name);
                            if let Ok(mut errors) = errors.lock() {
                                errors.insert(repo.name.clone(), format!("{err:#}"));
                            }
                        }
                    }
                }
            });
        }
    });
    errors.into_inner().unwrap_or_default()
}

/// Checks out `repo` at its commit in `dir` (shallow, blobless, sparse); returns the commit.
fn fetch(repo: &Repo, dir: &Path) -> Result<String> {
    if !dir.join(".git").exists() {
        std::fs::create_dir_all(dir)?;
        git(dir, &["init", "-q"])?;
        git(
            dir,
            &[
                "remote",
                "add",
                "origin",
                &format!("https://github.com/{}.git", repo.name),
            ],
        )?;
        let mut sparse = vec!["sparse-checkout", "set", "--no-cone"];
        sparse.extend_from_slice(SPARSE);
        git(dir, &sparse)?;
    }
    let target = repo.commit.as_deref().unwrap_or("HEAD");
    git(
        dir,
        &[
            "fetch",
            "-q",
            "--depth",
            "1",
            "--filter=blob:none",
            "origin",
            target,
        ],
    )?;
    git(
        dir,
        &["checkout", "-q", "--force", "--detach", "FETCH_HEAD"],
    )?;
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Scans one checkout; the row of the summary.
fn scan(repo: &Repo, dir: &Path, options: &Options) -> Result<Value> {
    let started = Instant::now();
    let report_path = options
        .out
        .join(format!("{}.json", repo.name.replace('/', "__")));
    let output = Command::new(&options.binary)
        .args([
            "scan",
            "--format",
            "json",
            "--min-severity",
            "low",
            "--no-config",
        ])
        .args(["--threads", &options.threads.max(1).to_string()])
        .arg("--output")
        .arg(&report_path)
        .arg(dir)
        .output()
        .with_context(|| format!("run {}", options.binary.display()))?;
    let seconds = started.elapsed().as_secs_f64();
    let commit = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("  CRASHED {}: {}", repo.name, stderr.trim());
        return Ok(json!({
            "repo": repo.name, "commit": commit, "status": "crashed",
            "exit": output.status.code(), "error": stderr.trim(), "seconds": round(seconds),
        }));
    }
    let report: Value = serde_json::from_slice(
        &std::fs::read(&report_path).with_context(|| report_path.display().to_string())?,
    )
    .with_context(|| format!("{} is not JSON", report_path.display()))?;
    let findings = at(&report, &["findings"])
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut by_severity: BTreeMap<&str, usize> = ["critical", "high", "medium", "low"]
        .into_iter()
        .map(|s| (s, 0))
        .collect();
    for finding in &findings {
        if let Some(count) = at(finding, &["severity"])
            .as_str()
            .and_then(|s| by_severity.get_mut(s))
        {
            *count += 1;
        }
    }
    let skipped = at(&report, &["skipped"])
        .as_array()
        .cloned()
        .unwrap_or_default();
    let panicked = skipped
        .iter()
        .filter(|s| {
            s["reason"]
                .as_str()
                .is_some_and(|r| r.starts_with("panicked"))
        })
        .count();
    if let Some(show) = &options.show {
        print_findings(&repo.name, &findings, show);
    }
    Ok(json!({
        "repo": repo.name,
        "commit": commit,
        "status": "ok",
        "files": at(&report, &["files_scanned"]),
        "findings": by_severity,
        "skipped": skipped.len(),
        "panicked": panicked,
        "seconds": round(seconds),
    }))
}

/// Prints the findings of one repository at or above `show`, one line each.
fn print_findings(repo: &str, findings: &[Value], show: &str) {
    let rank = |s: &str| match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        _ => 3,
    };
    let threshold = rank(show);
    let shown: Vec<&Value> = findings
        .iter()
        .filter(|f| rank(at(f, &["severity"]).as_str().unwrap_or("low")) <= threshold)
        .collect();
    if shown.is_empty() {
        return;
    }
    println!("\n## {repo}");
    for f in shown {
        let file = at(f, &["sink", "file"])
            .as_str()
            .or(at(f, &["file"]).as_str())
            .unwrap_or("");
        println!(
            "  {:<8} {:<19} {}:{}  {}  from {} ({}){}  [{}] {}",
            at(f, &["severity"]).as_str().unwrap_or(""),
            at(f, &["class"]).as_str().unwrap_or(""),
            file,
            at(f, &["sink", "line"]),
            at(f, &["sink", "api"]).as_str().unwrap_or(""),
            at(f, &["source", "expr"]).as_str().unwrap_or(""),
            at(f, &["auth"]).as_str().unwrap_or(""),
            at(f, &["entry"])
                .as_str()
                .map(|e| format!(" via {e}"))
                .unwrap_or_default(),
            at(f, &["fingerprint"]).as_str().unwrap_or(""),
            at(f, &["function"]).as_str().unwrap_or(""),
        );
    }
}

fn summarize(rows: &[Value], seconds: f64) -> Value {
    let mut totals: BTreeMap<&str, u64> = BTreeMap::new();
    let mut scanned = 0;
    for row in rows {
        if at(row, &["status"]) != "ok" {
            continue;
        }
        scanned += 1;
        for key in ["files", "skipped", "panicked"] {
            *totals.entry(key).or_default() += at(row, &[key]).as_u64().unwrap_or(0);
        }
        for severity in ["critical", "high", "medium", "low"] {
            *totals.entry(severity).or_default() +=
                at(row, &["findings", severity]).as_u64().unwrap_or(0);
        }
    }
    let failed = rows.len() - scanned;
    json!({
        "repos": rows.len(), "scanned": scanned, "not_scanned": failed,
        "files": totals.get("files"), "skipped": totals.get("skipped"),
        "panicked": totals.get("panicked"),
        "findings": {
            "critical": totals.get("critical"), "high": totals.get("high"),
            "medium": totals.get("medium"), "low": totals.get("low"),
        },
        "seconds": round(seconds),
    })
}

fn print_table(rows: &[Value], totals: &Value) {
    println!(
        "\n{:<44} {:>6} {:>5} {:>5} {:>5} {:>5} {:>5} {:>8}",
        "repository", "files", "crit", "high", "med", "low", "skip", "seconds"
    );
    for row in rows {
        if at(row, &["status"]) != "ok" {
            println!(
                "{:<44} {}",
                at(row, &["repo"]).as_str().unwrap_or(""),
                at(row, &["status"])
            );
            continue;
        }
        let count = |s: &str| at(row, &["findings", s]).as_u64().unwrap_or(0);
        println!(
            "{:<44} {:>6} {:>5} {:>5} {:>5} {:>5} {:>5} {:>8.1}{}",
            at(row, &["repo"]).as_str().unwrap_or(""),
            at(row, &["files"]).as_u64().unwrap_or(0),
            count("critical"),
            count("high"),
            count("medium"),
            count("low"),
            at(row, &["skipped"]).as_u64().unwrap_or(0),
            at(row, &["seconds"]).as_f64().unwrap_or(0.0),
            if at(row, &["panicked"]).as_u64().unwrap_or(0) > 0 {
                "  PANICKED"
            } else {
                ""
            }
        );
    }
    println!(
        "\ncorpus: {} of {} repositories scanned, {} files, {} skipped, {} panicked; findings \
         critical {} high {} medium {} low {}; {:.1}s",
        at(totals, &["scanned"]),
        at(totals, &["repos"]),
        at(totals, &["files"]),
        at(totals, &["skipped"]),
        at(totals, &["panicked"]),
        at(totals, &["findings", "critical"]),
        at(totals, &["findings", "high"]),
        at(totals, &["findings", "medium"]),
        at(totals, &["findings", "low"]),
        at(totals, &["seconds"]).as_f64().unwrap_or(0.0)
    );
}

/// Prints the repositories whose finding counts changed since `previous` (a `summary.json`).
fn compare(rows: &[Value], previous: &Path) -> Result<()> {
    let old: Value = serde_json::from_slice(
        &std::fs::read(previous).with_context(|| previous.display().to_string())?,
    )?;
    let old_rows: BTreeMap<&str, &Value> = at(&old, &["repos"])
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|r| Some((r["repo"].as_str()?, r)))
                .collect()
        })
        .unwrap_or_default();
    println!("\nchanges since {}:", previous.display());
    let mut changed = 0;
    for row in rows {
        let Some(name) = at(row, &["repo"]).as_str() else {
            continue;
        };
        let Some(before) = old_rows.get(name) else {
            println!("  {name}: new");
            continue;
        };
        let deltas: Vec<String> = ["critical", "high", "medium", "low"]
            .into_iter()
            .filter_map(|s| {
                let now = at(row, &["findings", s]).as_i64().unwrap_or(0);
                let then = at(before, &["findings", s]).as_i64().unwrap_or(0);
                (now != then).then(|| format!("{s} {then}->{now}"))
            })
            .collect();
        if !deltas.is_empty() {
            changed += 1;
            println!("  {name}: {}", deltas.join(", "));
        }
    }
    if changed == 0 {
        println!("  none");
    }
    Ok(())
}

/// `value[path...]`, or null when a key is missing.
fn at<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    path.iter()
        .try_fold(value, |value, key| value.get(*key))
        .unwrap_or(&Value::Null)
}

fn round(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_take_several_spellings() {
        let repos = parse_list(
            "# corpus\nowner/a@0123abcd\nowner/b 89abcdef0123  # pinned\nowner/c\n\
             owner/d@fedcba98 owner/e\n",
        )
        .unwrap();
        let names: Vec<(&str, Option<&str>)> = repos
            .iter()
            .map(|r| (r.name.as_str(), r.commit.as_deref()))
            .collect();
        assert_eq!(
            names,
            [
                ("owner/a", Some("0123abcd")),
                ("owner/b", Some("89abcdef0123")),
                ("owner/c", None),
                ("owner/d", Some("fedcba98")),
                ("owner/e", None),
            ]
        );
        assert_eq!(repos[0].dir(Path::new("/c")), PathBuf::from("/c/owner__a"));
    }

    #[test]
    fn bad_lists_are_rejected() {
        assert!(parse_list("abcdef12").is_err());
        assert!(parse_list("owner/../x").is_err());
        assert!(parse_list("owner").is_err());
        assert!(parse_list("owner/a@main").is_err());
        assert!(parse_list("owner/a abcdef12 abcdef34").is_err());
    }
}
