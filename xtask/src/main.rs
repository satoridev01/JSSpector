//! Development tasks for JSSpector. Run with `cargo xtask <task>`.

mod replay;

use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "JSSpector development tasks")]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Run the same checks as CI: rustfmt, clippy (warnings are errors) and the test suite.
    Ci,
    /// Score `jsspector scan` against the verified CVE-replay pairs (fetches repositories).
    Replay {
        /// Where repositories are fetched (blobless, sparse; reused between runs).
        #[arg(long, default_value = "target/replay")]
        cache: std::path::PathBuf,
        /// Score at most this many pairs.
        #[arg(long)]
        limit: Option<usize>,
        /// Only this repository (`owner/name`).
        #[arg(long)]
        repo: Option<String>,
        /// Write the JSON report here instead of stdout.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().task {
        Task::Ci => ci(),
        Task::Replay {
            cache,
            limit,
            repo,
            out,
        } => {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .context("workspace root")?
                .to_path_buf();
            let cache = if cache.is_absolute() {
                cache
            } else {
                root.join(cache)
            };
            replay::run(&replay::Options {
                root,
                cache,
                limit,
                repo,
                out,
            })
        }
    }
}

fn ci() -> Result<()> {
    packs_only()?;
    cargo(&["fmt", "--all", "--check"])?;
    cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ])?;
    cargo(&["test", "--workspace", "--locked"])?;
    eprintln!("xtask ci: all checks passed");
    Ok(())
}

/// Engine files that must not hold framework or library knowledge.
const ENGINE_FILES: &[&str] = &["crates/jss-frontend/src/taint/mod.rs"];

/// Generic labels the engine may use although a pack also mentions them.
const ENGINE_LABELS: &[&str] = &[
    // Source-kind labels.
    "http",
    "socket",
    "param",
    "context",
    // JavaScript itself (CommonJS).
    "exports",
    // Pack schema vocabulary.
    "all",
    "first",
    "second",
    "after-first",
    "input",
    "callback",
    "last-callback",
    "object-of-functions",
    "resolver-map",
];

/// The plan's rule: all framework knowledge lives in the YAML packs. Fails when a string literal
/// in the engine (outside its tests) is a name some pack lists.
fn packs_only() -> Result<()> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace root")?;
    let mut names = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(root.join("packs")).context("packs/")? {
        let text = std::fs::read_to_string(entry?.path())?;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            // Values only: list items and the right side of `key: value`.
            let values = match line.split_once(':') {
                Some((_, rest)) => rest,
                None => line,
            };
            for word in values.split(|c: char| !(c.is_alphanumeric() || "_$./-".contains(c))) {
                if word.len() > 2 && !word.chars().all(|c| c.is_ascii_digit()) {
                    names.insert(word.to_owned());
                }
            }
        }
    }
    let mut offenders = Vec::new();
    for file in ENGINE_FILES {
        let text = std::fs::read_to_string(root.join(file))?;
        let engine = text.split("\nmod tests {").next().unwrap_or(&text);
        for (number, line) in engine.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for literal in line.split('"').skip(1).step_by(2) {
                if names.contains(literal) && !ENGINE_LABELS.contains(&literal) {
                    offenders.push(format!("{file}:{}: \"{literal}\"", number + 1));
                }
            }
        }
    }
    if !offenders.is_empty() {
        bail!(
            "framework names in the engine (move them to a pack):\n{}",
            offenders.join("\n")
        );
    }
    eprintln!("xtask ci: the engine holds no pack names");
    Ok(())
}

/// Runs a cargo subcommand with the same cargo binary that launched xtask.
fn cargo(args: &[&str]) -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    eprintln!("$ cargo {}", args.join(" "));
    let status = Command::new(&cargo)
        .args(args)
        .status()
        .with_context(|| format!("failed to run {cargo}"))?;
    if !status.success() {
        bail!("`cargo {}` failed ({status})", args.join(" "));
    }
    Ok(())
}
