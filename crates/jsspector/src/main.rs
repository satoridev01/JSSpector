//! `jsspector` command-line interface.

mod baseline;
mod config;
mod excerpt;
mod explain;
mod openapi;
mod report;
mod rules;
mod sarif;
mod secure_io;
mod text;
mod verify;

use std::fmt::Display;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::time::Instant;

use clap::{Args, Parser, Subcommand, ValueEnum};
use jss_core::{
    ClassSet, DiscoverError, DiscoverOptions, FileClass, Finding, PackageType, Severity,
};
use jss_frontend::{ParsePool, ScanStatus};
use serde::Serialize;

/// Exit codes, as defined in `docs/PLAN.md`: 0 = clean, 1 = findings at or above `--fail-on`
/// that are not in the baseline, 2 = usage or config error, 3 = engine error (including IO
/// errors on the root).
const EXIT_FINDINGS: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_ENGINE: u8 = 3;

#[derive(Parser)]
#[command(
    name = "jsspector",
    version,
    about = "Static analyzer for JavaScript/TypeScript: entry-point inventory and high/critical attack paths"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Discover and parse a file or directory, and print a JSON parse report (development aid).
    ///
    /// The report is deterministic: the same tree gives byte-identical output for any number
    /// of threads. Only the optional `stats` object varies. Files that fail to parse are
    /// diagnostics, not errors: the exit code is 0 unless the root itself is unusable.
    #[command(hide = true)]
    Parse(ParseArgs),
    /// Scan a file or directory for attacker-controlled data reaching dangerous sinks.
    ///
    /// Every finding is a candidate for triage, with its path from source to sink. Settings come
    /// from `--config FILE`, or with `--repo-config` from `.jsspector.yml` in the scanned directory
    /// (command-line options win). Output is deterministic: the same tree gives the same report for
    /// any number of threads.
    Scan(Box<ScanArgs>),
    /// Grow JSSpector against its pinned exploitability benchmark.
    ///
    /// This is the explicit, mutating counterpart to `scan`: it may invoke the repair agent,
    /// commit validated scanner changes and push them to the configured upstream branch. A normal
    /// scan never evolves the scanner or publishes what it learns.
    Evolve(EvolveArgs),
    /// List every entry point: HTTP routes with full paths (mount prefixes followed across files),
    /// socket events, IPC channels, GraphQL fields, tRPC procedures and queue processors.
    Routes(RoutesArgs),
    /// Explain a rule (`jsspector explain sql-injection`) or a finding, by fingerprint or key
    /// (`jsspector explain 3f2a9c... ./repo`): the code at every step, why it matters, how to fix
    /// and how to silence it.
    Explain(ExplainArgs),
    /// Print the owned IR of a file or directory (modules and their cross-module call graph) as
    /// JSON (development aid).
    #[command(hide = true)]
    Ir(IrArgs),
}

#[derive(Args)]
struct IrArgs {
    /// File or directory to lower.
    path: PathBuf,
    #[arg(long, value_name = "N")]
    threads: Option<NonZeroUsize>,
}

#[derive(Args)]
struct RoutesArgs {
    /// File or directory to inventory.
    path: PathBuf,
    /// Number of threads [default: all available cores].
    #[arg(long, value_name = "N")]
    threads: Option<NonZeroUsize>,
    /// Print JSON instead of a table.
    #[arg(long, conflicts_with = "openapi")]
    json: bool,
    /// Print an OpenAPI 3.1 document of the HTTP routes.
    #[arg(long)]
    openapi: bool,
    #[command(flatten)]
    config: ConfigArgs,
}

/// Where settings come from.
#[derive(Args)]
struct ConfigArgs {
    /// Read settings from FILE.
    #[arg(long, value_name = "FILE", conflicts_with = "repo_config")]
    config: Option<PathBuf>,
    /// Read settings from `.jsspector.yml` in the scanned directory. Off by default: a scanned
    /// repository's own settings could exclude or disable exactly what would report it.
    #[arg(long)]
    repo_config: bool,
    /// Accepted for compatibility: the scanned directory's `.jsspector.yml` is ignored by default.
    #[arg(long, hide = true, conflicts_with_all = ["config", "repo_config"])]
    no_config: bool,
}

/// Report formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Findings grouped by file, with the code of every step.
    Text,
    /// The full report as JSON.
    Json,
    /// SARIF 2.1.0, for code-scanning tools.
    Sarif,
}

#[derive(Args)]
struct ScanArgs {
    /// File or directory to scan.
    #[arg(required_unless_present = "repo", conflicts_with = "repo")]
    path: Option<PathBuf>,
    /// Clone and scan a GitHub repository, optionally pinned as OWNER/REPO@REVISION.
    #[arg(long, value_name = "OWNER/REPO[@REVISION]", conflicts_with = "path")]
    repo: Option<String>,
    /// Number of threads [default: all available cores, or RAYON_NUM_THREADS].
    #[arg(long, value_name = "N")]
    threads: Option<NonZeroUsize>,
    /// Also scan these file classes (source files always are). Comma-separated.
    #[arg(long, value_name = "CLASSES", value_delimiter = ',', value_parser = parse_include)]
    include: Vec<Include>,
    /// Do not scan paths matching GLOB (relative to the root; like `.gitignore`). Repeatable.
    #[arg(long, value_name = "GLOB")]
    exclude: Vec<String>,
    /// Do not trust `jsspector-ignore` comments in scanned source. `scan --repo` always behaves
    /// this way because the remote repository is not the scanner operator's policy boundary.
    #[arg(long)]
    no_inline_ignores: bool,
    /// Report only findings at or above this severity: critical, high, medium or low
    /// [default: low].
    #[arg(long, value_name = "SEVERITY", value_parser = rules::parse_severity)]
    min_severity: Option<Severity>,
    /// Report format [default: text].
    #[arg(short = 'f', long, value_enum)]
    format: Option<Format>,
    /// Same as `--format json`.
    #[arg(long, hide = true, conflicts_with = "format")]
    json: bool,
    /// Write the report to FILE instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Exit with code 1 when a reported finding (not in the baseline) is at or above SEVERITY.
    #[arg(long, value_name = "SEVERITY", value_parser = rules::parse_severity)]
    fail_on: Option<Severity>,
    /// Permit a successful exit when selected files were skipped, panicked or hit an analysis
    /// depth cap. Reports still carry `complete: false` and the affected files.
    #[arg(long)]
    allow_incomplete: bool,
    /// Do not report findings recorded in FILE (see --write-baseline).
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Record the findings reported now in FILE, to accept them as a baseline.
    #[arg(long, value_name = "FILE")]
    write_baseline: Option<PathBuf>,
    /// Confirm each reported finding by running the app in a throwaway Docker container and
    /// sending the request it implies (or in this environment with `--local`). `--verify=strict`
    /// fails instead of skipping when the selected runtime is unavailable.
    #[arg(long, value_name = "MODE", num_args = 0..=1, default_missing_value = "best-effort")]
    verify: Option<VerifyMode>,
    /// Run each verified app in this environment instead of a Docker container: for an
    /// already-disposable sandbox such as a CI or Satori job, where Docker is not available. The
    /// services an app needs (MongoDB, Redis) are provisioned on demand.
    #[arg(long, requires = "verify")]
    local: bool,
    /// Dynamically verify only this exact finding fingerprint. Repeatable; the report still
    /// includes every static finding. Intended for targeted reproduction and repair checks.
    #[arg(long, value_name = "FINGERPRINT", requires = "verify")]
    verify_fingerprint: Vec<String>,
    /// Stop dynamic verification after the first selected finding is reproduced. When combined
    /// with repeated --verify-fingerprint options, their order is the verification priority.
    #[arg(long, requires = "verify")]
    verify_until_first: bool,
    /// Do not look for a proven fix for verified findings. By default, each verified finding gets
    /// a `fix`: a minimal change shown to stop the exploit in the same sandbox while a benign
    /// request to the route keeps its behavior.
    #[arg(long, requires = "verify")]
    no_fix: bool,
    /// Do not ask an LLM (the `claude` CLI) for fix candidates: only replay fixes recorded for the
    /// same finding on the same file content.
    #[arg(long, requires = "verify")]
    no_fix_llm: bool,
    /// LLM fix candidates per verified finding [default: 3].
    #[arg(long, value_name = "N", requires = "verify")]
    fix_attempts: Option<usize>,
    /// Time budget in seconds to prove a fix for one finding [default: 600].
    #[arg(long, value_name = "SECONDS", requires = "verify")]
    fix_timeout: Option<u64>,
    /// Model for the LLM fix fallback [default: the `claude` CLI's own].
    #[arg(long, value_name = "MODEL", requires = "verify")]
    fix_model: Option<String>,
    /// Record what a proven LLM fix taught JSSpector in its local recipe store. Off by default:
    /// verification and fix generation otherwise leave the JSSpector checkout unchanged.
    #[arg(long, requires = "verify")]
    learn_fixes: bool,
    /// Record, commit and push what a proven LLM fix taught JSSpector. This is an explicit
    /// cross-run publication action; without it no recipe commit or push is attempted.
    #[arg(long, requires = "verify")]
    publish_fixes: bool,
    #[command(flatten)]
    config: ConfigArgs,
}

#[derive(Args)]
struct EvolveArgs {
    /// Repair scanner support for unresolved benchmark cases in one GitHub repository.
    #[arg(
        long,
        value_name = "OWNER/REPO[@REVISION]",
        conflicts_with = "repos",
        required_unless_present = "repos"
    )]
    repo: Option<String>,
    /// Repair scanner support for repositories listed in FILE, one per line.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with = "repo",
        required_unless_present = "repo",
        requires = "push"
    )]
    repos: Option<PathBuf>,
    /// Independent repair workers used with --repos.
    #[arg(long, value_name = "N", requires = "repos", conflicts_with = "repo")]
    parallel: Option<NonZeroUsize>,
    /// Push validated evolution commits to the configured upstream. Without this option a
    /// single-repository evolution leaves its commits local for review. Batch evolution requires
    /// it because independent workers exchange generations through the upstream branch.
    #[arg(long)]
    push: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum VerifyMode {
    /// Skip verification when Docker is unreachable.
    BestEffort,
    /// Fail when Docker is unreachable.
    Strict,
}

#[derive(Args)]
struct ExplainArgs {
    /// A finding's fingerprint (or a unique prefix of it, or its key), or a vulnerability class
    /// (`sql-injection`, `jsspector.xss`).
    what: String,
    /// The file or directory a finding is in (scanned to find it).
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Number of threads [default: all available cores].
    #[arg(long, value_name = "N")]
    threads: Option<NonZeroUsize>,
    /// Also scan these file classes (source files always are). Comma-separated.
    #[arg(long, value_name = "CLASSES", value_delimiter = ',', value_parser = parse_include)]
    include: Vec<Include>,
    /// Print JSON (the rule, and the finding).
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    config: ConfigArgs,
}

/// The `scan` report.
#[derive(Serialize)]
struct ScanOutput<'a> {
    root: String,
    /// The git checkout the scan ran on, so the report's fix diffs can be applied to the right
    /// repository and commit; absent outside a git checkout.
    #[serde(skip_serializing_if = "Option::is_none")]
    git: Option<GitInfo>,
    files_scanned: usize,
    /// False when any selected file could not be fully analyzed.
    complete: bool,
    findings: Vec<ReportedFinding<'a>>,
    /// Findings left out because they are in the baseline.
    baselined: usize,
    /// Findings left out by `jsspector-ignore` comments.
    ignored: usize,
    /// Files not analyzed, with the reason; sorted by path.
    skipped: &'a [FileNote],
    /// Files where the walker hit its depth cap.
    truncated: &'a [String],
}

/// A finding as `scan --json` prints it: a title first, the finding, then the fields issue
/// trackers read (Satori's `title`, `resource`, `description`, `remediation`).
#[derive(Serialize)]
struct ReportedFinding<'a> {
    title: String,
    cwe: String,
    /// Versioned semantic identity for deduplication across scanner versions. The legacy
    /// `fingerprint` remains the exact baseline and verification selector.
    identity: String,
    #[serde(flatten)]
    finding: &'a Finding,
    resource: String,
    description: String,
    /// The lines the value passes through, entry point to sink, as annotated Markdown code
    /// blocks (one per file).
    affected: String,
    /// The same source-to-sink flow in the concise form used by the terminal renderer.
    flow: String,
    remediation: String,
    /// The exact dynamic-verification result, when this finding was selected for verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    exploitation: Option<Exploitation<'a>>,
    /// The request and evidence, present only when dynamic exploitation was verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    poc: Option<verify::Reproduction>,
    /// A change proven to stop the verified exploit (or why there is none), present only when the
    /// finding verified and fixes were not turned off.
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<&'a verify::FixOutcome>,
}

impl<'a> ReportedFinding<'a> {
    fn new(
        finding: &'a Finding,
        sources: &mut text::Sources,
        verdict: Option<&'a verify::Verdict>,
    ) -> Self {
        let (exploitation, poc) = verdict
            .map(Exploitation::from_verdict)
            .map_or((None, None), |(exploitation, poc)| {
                (Some(exploitation), poc)
            });
        Self {
            title: rules::title(finding),
            cwe: format!("CWE-{}", rules::rule(finding.class).cwe),
            identity: jss_core::finding::semantic_identity(finding),
            finding,
            resource: rules::resource(finding),
            description: rules::description(finding),
            affected: excerpt::affected(finding, sources),
            flow: text::flow(finding, sources),
            remediation: rules::remediation(finding.class),
            exploitation,
            poc,
            fix: verdict.and_then(|verdict| verdict.fix.as_ref()),
        }
    }
}

/// A finding-local view of dynamic verification. The verifier's distinctions are preserved:
/// failure to reproduce is not reported as proof that the finding is not exploitable.
#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
enum Exploitation<'a> {
    Verified { how: &'a str },
    NotReproduced { tried: usize },
    Skipped { reason: &'a str },
}

impl<'a> Exploitation<'a> {
    fn from_verdict(verdict: &'a verify::Verdict) -> (Self, Option<verify::Reproduction>) {
        match &verdict.outcome {
            verify::Outcome::Verified { how, poc } => {
                (Self::Verified { how }, Some(poc.report_safe()))
            }
            verify::Outcome::NotReproduced { tried } => {
                (Self::NotReproduced { tried: *tried }, None)
            }
            verify::Outcome::Skipped { reason } => (Self::Skipped { reason }, None),
        }
    }
}

fn verdicts_by_fingerprint(
    verdicts: &[verify::Verdict],
) -> std::collections::BTreeMap<&str, &verify::Verdict> {
    verdicts
        .iter()
        .map(|verdict| (verdict.fingerprint.as_str(), verdict))
        .collect()
}

#[cfg(test)]
mod exploitation_output_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use jss_core::{Auth, SinkLoc, SourceLoc, VulnClass};
    use serde_json::json;

    fn reproduction() -> verify::Reproduction {
        verify::Reproduction {
            command: "curl http://TARGET/items?id=proof".to_owned(),
            command_redacted: false,
            method: "GET".to_owned(),
            target: "/items?id=proof".to_owned(),
            headers: Vec::new(),
            body: None,
            evidence: "the response contained proof".to_owned(),
            response: "proof".to_owned(),
            stdout: None,
            stderr: None,
            exit_code: None,
            output_safety: None,
            controls: Vec::new(),
        }
    }

    fn verdict(fingerprint: &str, outcome: verify::Outcome) -> verify::Verdict {
        verify::Verdict {
            fingerprint: fingerprint.to_owned(),
            entry: Some("GET /items".to_owned()),
            class: "sql-injection".to_owned(),
            outcome,
            fix: None,
        }
    }

    fn finding() -> Finding {
        Finding {
            file: "server.js".to_owned(),
            sink: SinkLoc {
                file: None,
                api: "db.query".to_owned(),
                arg: "req.query.id".to_owned(),
                line: 1,
                col: 1,
            },
            class: VulnClass::SqlInjection,
            severity: Severity::High,
            confidence: "heuristic",
            auth: Auth::NoneDetected,
            function: "handler".to_owned(),
            entry: Some("GET /items".to_owned()),
            entry_at: None,
            source: SourceLoc {
                kind: "http",
                expr: "req.query.id".to_owned(),
                line: 1,
                col: 1,
            },
            stored_by: None,
            trace: Vec::new(),
            key: "sql|server.js|handler|db.query|req.query.id|0".to_owned(),
            fingerprint: "0123456789abcdef".to_owned(),
        }
    }

    #[test]
    fn verified_exploitation_carries_the_structured_poc() {
        let verdict = verdict(
            "0123456789abcdef",
            verify::Outcome::Verified {
                how: "GET /items?id=proof".to_owned(),
                poc: reproduction(),
            },
        );
        let (exploitation, poc) = Exploitation::from_verdict(&verdict);

        assert_eq!(
            serde_json::to_value(exploitation).unwrap(),
            json!({"outcome": "verified", "how": "GET /items?id=proof"})
        );
        let poc = serde_json::to_value(poc.unwrap()).unwrap();
        assert_eq!(poc["command"], "curl http://TARGET/items?id=proof");
        assert_eq!(poc["evidence"], "the response contained proof");
    }

    #[test]
    fn non_verified_outcomes_never_carry_a_poc() {
        let not_reproduced = verdict(
            "0123456789abcdef",
            verify::Outcome::NotReproduced { tried: 3 },
        );
        let (exploitation, poc) = Exploitation::from_verdict(&not_reproduced);
        assert_eq!(
            serde_json::to_value(exploitation).unwrap(),
            json!({"outcome": "not-reproduced", "tried": 3})
        );
        assert!(poc.is_none());

        let skipped = verdict(
            "fedcba9876543210",
            verify::Outcome::Skipped {
                reason: "no runnable entry point".to_owned(),
            },
        );
        let (exploitation, poc) = Exploitation::from_verdict(&skipped);
        assert_eq!(
            serde_json::to_value(exploitation).unwrap(),
            json!({"outcome": "skipped", "reason": "no runnable entry point"})
        );
        assert!(poc.is_none());
    }

    #[test]
    fn verdict_lookup_contains_only_selected_fingerprints() {
        let verdicts = vec![verdict(
            "0123456789abcdef",
            verify::Outcome::NotReproduced { tried: 1 },
        )];
        let by_fingerprint = verdicts_by_fingerprint(&verdicts);

        assert!(by_fingerprint.contains_key("0123456789abcdef"));
        assert!(!by_fingerprint.contains_key("fedcba9876543210"));
    }

    #[test]
    fn selected_skipped_finding_embeds_exploitation_without_a_poc() {
        let finding = finding();
        let verdict = verdict(
            &finding.fingerprint,
            verify::Outcome::Skipped {
                reason: "no runnable entry point".to_owned(),
            },
        );
        let mut sources = text::Sources::new(Path::new("."));
        let reported = ReportedFinding::new(&finding, &mut sources, Some(&verdict));
        let value = serde_json::to_value(reported).unwrap();

        assert_eq!(
            value["exploitation"],
            json!({"outcome": "skipped", "reason": "no runnable entry point"})
        );
        assert!(value.get("poc").is_none());
    }

    #[test]
    fn authenticated_proof_is_redacted_before_report_serialization() {
        let finding = finding();
        let token = "eyJheader.payload.signature";
        let poc = verify::Reproduction {
            command: format!(
                "curl --header 'Authorization: Bearer opaque' --header 'Cookie: sid={token}' /items"
            ),
            command_redacted: false,
            method: "POST".to_owned(),
            target: "/items".to_owned(),
            headers: vec![
                "Content-Type: application/json".to_owned(),
                "Authorization: Bearer opaque".to_owned(),
                format!("Cookie: sid={token}"),
            ],
            body: Some(format!(r#"{{"proof":"{token}"}}"#)),
            evidence: format!("callback {token}"),
            response: "private account record".to_owned(),
            stdout: None,
            stderr: None,
            exit_code: None,
            output_safety: None,
            controls: vec![verify::ControlObservation {
                label: "negative".to_owned(),
                method: "POST".to_owned(),
                target: "/items".to_owned(),
                body: None,
                response: "another private record".to_owned(),
            }],
        };
        let verdict = verdict(
            &finding.fingerprint,
            verify::Outcome::Verified {
                how: "POST /items".to_owned(),
                poc,
            },
        );
        let mut sources = text::Sources::new(Path::new("."));
        let value =
            serde_json::to_value(ReportedFinding::new(&finding, &mut sources, Some(&verdict)))
                .unwrap();
        let serialized = value["poc"].to_string();

        assert!(!serialized.contains("opaque"), "{serialized}");
        assert!(!serialized.contains(token), "{serialized}");
        assert!(!serialized.contains("private account"), "{serialized}");
        assert!(!serialized.contains("another private"), "{serialized}");
        assert_eq!(value["poc"]["headers"][1], "Authorization: REDACTED");
        assert_eq!(value["poc"]["headers"][2], "Cookie: REDACTED");
        assert!(
            value["poc"]["response"]
                .as_str()
                .is_some_and(|response| response.starts_with("[redacted authenticated response:"))
        );
    }
}

#[derive(Serialize)]
struct FileNote {
    file: String,
    reason: String,
    /// The analysis panicked on this file (contained).
    #[serde(skip)]
    panicked: bool,
}

#[derive(Args)]
struct ParseArgs {
    /// File or directory to parse.
    path: PathBuf,
    /// Number of parser threads [default: all available cores, or RAYON_NUM_THREADS].
    #[arg(long, value_name = "N")]
    threads: Option<NonZeroUsize>,
    /// Also parse these file classes (source files always are): tests, examples, docs,
    /// generated, vendor, or all. Comma-separated. A single FILE is always parsed.
    #[arg(long, value_name = "CLASSES", value_delimiter = ',', value_parser = parse_include)]
    include: Vec<Include>,
    /// Add one record per discovered file to the report.
    #[arg(long)]
    list: bool,
    /// Add a `stats` object: wall time per phase, threads, peak memory, throughput.
    #[arg(long)]
    stats: bool,
    /// Parse a single FILE as an ES module, as if its package.json had "type": "module". (By
    /// default a single FILE follows the nearest package.json, searched up to the enclosing git
    /// work tree.)
    #[arg(long)]
    esm: bool,
}

/// One `--include` value.
#[derive(Debug, Clone, Copy)]
enum Include {
    All,
    Class(FileClass),
}

fn parse_include(value: &str) -> Result<Include, String> {
    if value.trim().eq_ignore_ascii_case("all") {
        return Ok(Include::All);
    }
    FileClass::from_name(value)
        .map(Include::Class)
        .ok_or_else(|| {
            format!(
                "unknown file class `{value}` (expected tests, examples, docs, generated, vendor, \
             source or all)"
            )
        })
}

/// The classes to parse: source, plus every `--include`.
fn include_set(includes: &[Include]) -> ClassSet {
    let mut set = ClassSet::default();
    for include in includes {
        match include {
            Include::All => set = ClassSet::ALL,
            Include::Class(class) => set.insert(*class),
        }
    }
    set
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Parse(args) => parse(&args),
        Command::Scan(args) => scan(&args),
        Command::Evolve(args) => evolve(&args),
        Command::Routes(args) => routes(&args),
        Command::Explain(args) => explain(&args),
        Command::Ir(args) => ir(&args),
    }
}

/// Reads the settings for scanning `path` and installs their packs (before any analysis).
fn setup(path: &Path, args: &ConfigArgs) -> Result<config::Loaded, ExitCode> {
    let loaded = config::Loaded::load(path, args.config.as_deref(), !args.repo_config)
        .map_err(|err| fail(EXIT_USAGE, err))?;
    let packs = loaded.packs().map_err(|err| fail(EXIT_USAGE, err))?;
    if !packs.is_empty() {
        jss_frontend::taint::models::install(&packs)
            .map_err(|errors| fail(EXIT_USAGE, errors.join("\n")))?;
    }
    Ok(loaded)
}

/// The file classes to scan: `--include` if given, else the config's `include`.
fn classes(cli: &[Include], loaded: &config::Loaded) -> Result<ClassSet, ExitCode> {
    if !cli.is_empty() {
        return Ok(include_set(cli));
    }
    let parsed: Result<Vec<Include>, String> = loaded
        .config
        .include
        .iter()
        .map(|name| parse_include(name))
        .collect();
    parsed
        .map(|includes| include_set(&includes))
        .map_err(|err| fail(EXIT_USAGE, err))
}

/// Everything one analysis found, before any filtering.
struct Analysis {
    /// Canonical root directory.
    root: PathBuf,
    files_scanned: usize,
    /// Every finding, with its key and fingerprint, sorted for output.
    findings: Vec<Finding>,
    skipped: Vec<FileNote>,
    truncated: Vec<String>,
}

impl Analysis {
    fn complete(&self) -> bool {
        self.skipped.is_empty() && self.truncated.is_empty()
    }

    fn incomplete_summary(&self) -> String {
        format!(
            "{} file(s) skipped or panicked, {} file(s) truncated",
            self.skipped.len(),
            self.truncated.len()
        )
    }
}

/// Discovers, parses and analyzes `path`, minus the excluded paths.
fn analyze(
    path: &Path,
    threads: Option<NonZeroUsize>,
    include: ClassSet,
    excludes: &config::Excludes,
) -> Result<Analysis, ExitCode> {
    let pool = ParsePool::new(threads).map_err(|err| fail(EXIT_ENGINE, err))?;
    let mut discovery = match pool.install(|| jss_core::discover(path, &DiscoverOptions::default()))
    {
        Ok(discovery) => discovery,
        Err(err @ DiscoverError::Io { .. }) => return Err(fail(EXIT_ENGINE, err)),
        Err(err) => return Err(fail(EXIT_USAGE, err)),
    };
    discovery
        .files
        .retain(|file| !excludes.matches(&file.rel_path));
    let selection = discovery.selection(include);
    let mut reports = pool.scan(&discovery.files, selection);
    jss_frontend::attach_entries(&discovery.root, &mut reports);
    let mut analysis = Analysis {
        root: discovery.root.clone(),
        files_scanned: 0,
        findings: Vec::new(),
        skipped: Vec::new(),
        truncated: Vec::new(),
    };
    for report in reports {
        match report.status {
            ScanStatus::Scanned => analysis.files_scanned += 1,
            ScanStatus::Skipped(reason) => analysis.skipped.push(FileNote {
                file: report.rel_path.clone(),
                reason,
                panicked: false,
            }),
            ScanStatus::Panicked(panic) => analysis.skipped.push(FileNote {
                file: report.rel_path.clone(),
                reason: format!("panicked: {panic}"),
                panicked: true,
            }),
        }
        if report.truncated {
            analysis.truncated.push(report.rel_path.clone());
        }
        analysis.findings.extend(report.findings);
    }
    // Keys first, over every finding, so they never depend on the filters applied later.
    jss_frontend::finalize(&mut analysis.findings);
    Ok(analysis)
}

struct RemoteCheckout {
    _directory: tempfile::TempDir,
    path: PathBuf,
    label: String,
}

fn repository_spec(value: &str) -> Result<(&str, Option<&str>), String> {
    let (repository, revision) = value
        .rsplit_once('@')
        .map_or((value, None), |(repository, revision)| {
            (repository, Some(revision))
        });
    let Some((owner, name)) = repository.split_once('/') else {
        return Err("repository must be OWNER/REPO or OWNER/REPO@REVISION".to_owned());
    };
    let safe_name = |part: &str| {
        !part.is_empty()
            && !part.starts_with('.')
            && part
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
    };
    if !safe_name(owner) || !safe_name(name) || name.contains('/') {
        return Err("repository must be a safe GitHub OWNER/REPO name".to_owned());
    }
    if revision.is_some_and(|revision| {
        revision.is_empty()
            || revision.starts_with('-')
            || !revision
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_./".contains(character))
    }) {
        return Err("repository revision contains unsupported characters".to_owned());
    }
    Ok((repository, revision))
}

#[cfg(test)]
mod repository_input_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn repository_input_accepts_head_and_pinned_scans() {
        assert_eq!(
            repository_spec("owner/project").unwrap(),
            ("owner/project", None)
        );
        assert_eq!(
            repository_spec("owner/project@ace6a5fbc409").unwrap(),
            ("owner/project", Some("ace6a5fbc409"))
        );
        assert_eq!(
            repository_spec("owner/project@release/v1").unwrap(),
            ("owner/project", Some("release/v1"))
        );
    }

    #[test]
    fn repository_input_rejects_urls_options_and_incomplete_names() {
        for invalid in [
            "project",
            "owner/",
            "/project",
            "https://github.com/owner/project",
            "owner/project@",
            "owner/project@--upload-pack=bad",
            "owner/project@main:refs/heads/x",
        ] {
            assert!(repository_spec(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn scan_cli_accepts_exactly_one_repository_source() {
        assert!(Cli::try_parse_from(["jsspector", "scan", "--repo", "owner/project"]).is_ok());
        assert!(Cli::try_parse_from(["jsspector", "scan", "."]).is_ok());
        assert!(
            Cli::try_parse_from(["jsspector", "scan", ".", "--repo", "owner/project"]).is_err()
        );
        assert!(Cli::try_parse_from(["jsspector", "scan"]).is_err());
    }

    #[test]
    fn only_a_main_checkout_keeps_a_recipe_store() {
        let main = tempfile::tempdir().unwrap();
        std::fs::create_dir(main.path().join(".git")).unwrap();
        assert_eq!(
            recipe_store_of(main.path()),
            Some(main.path().join(".satori").join("fix-recipes"))
        );
        // A linked worktree's `.git` is a file pointing at the main repository.
        let linked = tempfile::tempdir().unwrap();
        std::fs::write(
            linked.path().join(".git"),
            "gitdir: /elsewhere/.git/worktrees/x\n",
        )
        .unwrap();
        assert_eq!(recipe_store_of(linked.path()), None);
        assert_eq!(recipe_store_of(tempfile::tempdir().unwrap().path()), None);
    }

    #[test]
    fn repository_scan_does_not_implicitly_verify_or_evolve() {
        assert!(
            Cli::try_parse_from(["jsspector", "scan", "--repo", "owner/project"]).is_ok_and(
                |cli| matches!(cli.command, Command::Scan(ref scan) if scan.verify.is_none())
            )
        );
        assert!(
            Cli::try_parse_from([
                "jsspector",
                "scan",
                "--repo",
                "owner/project",
                "--no-self-heal"
            ])
            .is_err()
        );
    }

    #[test]
    fn scanner_evolution_is_an_explicit_command() {
        assert!(Cli::try_parse_from(["jsspector", "scan", ".", "--parallel", "2"]).is_err());
        assert!(Cli::try_parse_from(["jsspector", "scan", "--repos", "list.txt"]).is_err());
        assert!(
            Cli::try_parse_from([
                "jsspector",
                "evolve",
                "--repo",
                "owner/project",
                "--parallel",
                "2"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "jsspector",
                "evolve",
                "--repos",
                "list.txt",
                "--parallel",
                "2",
                "--push"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["jsspector", "evolve", "--repos", "list.txt"]).is_err());
        assert!(Cli::try_parse_from(["jsspector", "evolve", "--repo", "owner/project"]).is_ok());
        assert!(
            Cli::try_parse_from(["jsspector", "evolve", "--repo", "owner/project", "--push"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["jsspector", "evolve"]).is_err());
    }

    #[test]
    fn evolution_requires_a_clean_published_checkout() {
        let checkout = tempfile::tempdir().unwrap();
        // Evolution is unavailable away from a source checkout.
        assert!(self_heal_unavailable(None).is_some());
        let missing = self_heal_unavailable(Some(checkout.path())).unwrap();
        assert!(missing.contains("JSSPECTOR_SOURCE_ROOT"), "{missing}");
        std::fs::create_dir_all(checkout.path().join(".satori")).unwrap();
        std::fs::write(checkout.path().join(".satori/self-heal.sh"), "").unwrap();
        let reason = || self_heal_unavailable(Some(checkout.path()));
        assert!(reason().unwrap().contains("not a git checkout"));

        // A published, clean checkout self-heals; one self-heal.sh would refuse does not.
        let git = |dir: &Path, args: &[&str]| {
            let status = ProcessCommand::new("git")
                .arg("-C")
                .arg(dir)
                .args([
                    "-c",
                    "user.name=test",
                    "-c",
                    "user.email=test@localhost.invalid",
                ])
                .args(args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?}");
        };
        let remote = tempfile::tempdir().unwrap();
        git(remote.path(), &["init", "-q", "--bare"]);
        git(checkout.path(), &["init", "-q"]);
        git(checkout.path(), &["add", "-A"]);
        git(checkout.path(), &["commit", "-qm", "base"]);
        assert!(reason().unwrap().contains("no upstream"));
        git(
            checkout.path(),
            &["remote", "add", "origin", remote.path().to_str().unwrap()],
        );
        git(checkout.path(), &["push", "-q", "-u", "origin", "HEAD"]);
        assert_eq!(reason(), None);
        std::fs::write(checkout.path().join("NOTES"), "draft\n").unwrap();
        assert!(reason().unwrap().contains("uncommitted changes"));
        git(checkout.path(), &["add", "-A"]);
        git(checkout.path(), &["commit", "-qm", "local"]);
        assert!(reason().unwrap().contains("unpublished commits"));
    }

    #[test]
    fn local_runtime_is_a_verify_option() {
        assert!(
            Cli::try_parse_from(["jsspector", "scan", ".", "--verify"])
                .is_ok_and(|cli| matches!(cli.command, Command::Scan(ref scan) if !scan.local))
        );
        assert!(
            Cli::try_parse_from(["jsspector", "scan", ".", "--verify", "--local"])
                .is_ok_and(|cli| matches!(cli.command, Command::Scan(ref scan) if scan.local))
        );
        // Without `--verify` there is no app to run, so `--local` is a usage error.
        assert!(Cli::try_parse_from(["jsspector", "scan", ".", "--local"]).is_err());
    }

    #[test]
    fn verify_until_first_is_an_explicit_verify_option() {
        assert!(
            Cli::try_parse_from([
                "jsspector",
                "scan",
                ".",
                "--verify=strict",
                "--verify-until-first",
                "--verify-fingerprint",
                "0123456789abcdef",
            ])
            .is_ok_and(|cli| matches!(
                cli.command,
                Command::Scan(ref scan) if scan.verify_until_first
            ))
        );
        assert!(Cli::try_parse_from(["jsspector", "scan", ".", "--verify-until-first"]).is_err());
    }

    #[test]
    fn fix_learning_and_publication_are_explicit_verify_options() {
        assert!(Cli::try_parse_from(["jsspector", "scan", ".", "--learn-fixes"]).is_err());
        assert!(Cli::try_parse_from(["jsspector", "scan", ".", "--publish-fixes"]).is_err());
        assert!(
            Cli::try_parse_from(["jsspector", "scan", ".", "--verify", "--learn-fixes"]).is_ok_and(
                |cli| matches!(
                    cli.command,
                    Command::Scan(ref scan) if scan.learn_fixes && !scan.publish_fixes
                )
            )
        );
        assert!(
            Cli::try_parse_from(["jsspector", "scan", ".", "--verify", "--publish-fixes"])
                .is_ok_and(|cli| matches!(
                    cli.command,
                    Command::Scan(ref scan) if scan.publish_fixes
                ))
        );
    }

    #[test]
    fn a_clone_url_loses_its_credentials() {
        assert_eq!(
            without_credentials("https://x-access-token:secret@github.com/o/r.git"),
            "https://github.com/o/r.git"
        );
        assert_eq!(
            without_credentials("https://github.com/o/r.git"),
            "https://github.com/o/r.git"
        );
        assert_eq!(
            without_credentials("git@github.com:o/r.git"),
            "git@github.com:o/r.git"
        );
    }

    #[test]
    fn the_report_names_the_checkout_a_scan_ran_on() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let git = |args: &[&str]| {
            ProcessCommand::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@t"])
                .args(args)
                .current_dir(root)
                .output()
                .is_ok_and(|output| output.status.success())
        };
        if !git(&["init", "-q"]) {
            eprintln!("git not available: skipped");
            return;
        }
        std::fs::create_dir(root.join("app")).unwrap();
        std::fs::write(root.join("app/index.js"), "x\n").unwrap();
        assert!(git(&["add", "-A"]));
        assert!(git(&["commit", "-qm", "base"]));
        assert!(git(&[
            "remote",
            "add",
            "origin",
            "https://user:token@github.com/o/r.git"
        ]));
        let info = git_info(&root.join("app")).unwrap();
        assert_eq!(
            info.repository.as_deref(),
            Some("https://github.com/o/r.git")
        );
        assert_eq!(info.revision.len(), 40);
        assert_eq!(info.path, "app");
        assert!(!info.dirty);
        std::fs::write(root.join("app/index.js"), "y\n").unwrap();
        assert!(git_info(root).unwrap().dirty);
        assert_eq!(git_info(root).unwrap().path, "");
        // Outside a checkout there is nothing to report.
        assert_eq!(git_info(tempfile::tempdir().unwrap().path()), None);
    }
}

fn checkout_repository(value: &str) -> Result<RemoteCheckout, String> {
    let (repository, revision) = repository_spec(value)?;
    let directory = tempfile::Builder::new()
        .prefix("jsspector-repo-")
        .tempdir()
        .map_err(|error| format!("create temporary repository checkout: {error}"))?;
    let path = directory.path().join("repository");
    let url = format!("https://github.com/{repository}.git");
    let mut clone = ProcessCommand::new("git");
    clone.args(["clone", "--filter=blob:none"]);
    if revision.is_some() {
        clone.arg("--no-checkout");
    } else {
        clone.args(["--depth", "1"]);
    }
    let status = clone
        .arg(&url)
        .arg(&path)
        .status()
        .map_err(|error| format!("start git clone for {repository}: {error}"))?;
    if !status.success() {
        return Err(format!("git clone failed for {repository} with {status}"));
    }
    if let Some(revision) = revision {
        let expression = format!("{revision}^{{commit}}");
        let local = ProcessCommand::new("git")
            .arg("-C")
            .arg(&path)
            .args(["rev-parse", "--verify", "--quiet", &expression])
            .output()
            .map_err(|error| format!("resolve local git revision for {value}: {error}"))?;
        let checkout = if local.status.success() {
            String::from_utf8(local.stdout)
                .map_err(|error| format!("git revision for {value} is not UTF-8: {error}"))?
                .trim()
                .to_owned()
        } else {
            let status = ProcessCommand::new("git")
                .arg("-C")
                .arg(&path)
                .args(["fetch", "--depth", "1", "origin", revision])
                .status()
                .map_err(|error| format!("start git fetch for {value}: {error}"))?;
            if !status.success() {
                return Err(format!("git fetch failed for {value} with {status}"));
            }
            "FETCH_HEAD".to_owned()
        };
        let status = ProcessCommand::new("git")
            .arg("-C")
            .arg(&path)
            .args(["checkout", "--quiet", "--detach", &checkout])
            .status()
            .map_err(|error| format!("start git checkout for {value}: {error}"))?;
        if !status.success() {
            return Err(format!("git checkout failed for {value} with {status}"));
        }
    }
    Ok(RemoteCheckout {
        _directory: directory,
        path,
        label: value.to_owned(),
    })
}

/// The JSSpector checkout self-heal runs from: `JSSPECTOR_SOURCE_ROOT`, or the one this binary was
/// compiled from.
fn self_heal_source_root() -> Option<PathBuf> {
    std::env::var_os("JSSPECTOR_SOURCE_ROOT")
        .map(PathBuf::from)
        .or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .map(Path::to_path_buf)
        })
}

/// Why explicit scanner evolution cannot run here: a binary away from its JSSpector checkout, or
/// a checkout the controller would refuse to synchronize (uncommitted changes, unpublished
/// commits or no upstream).
fn self_heal_unavailable(source_root: Option<&Path>) -> Option<String> {
    let Some(source_root) = source_root else {
        return Some(
            "the JSSpector source checkout is unknown; set JSSPECTOR_SOURCE_ROOT".to_owned(),
        );
    };
    let workflow = source_root.join(".satori/self-heal.sh");
    if !workflow.is_file() {
        return Some(format!(
            "no JSSpector source checkout at {}; set JSSPECTOR_SOURCE_ROOT",
            source_root.display()
        ));
    }
    let git = |args: &[&str]| {
        ProcessCommand::new("git")
            .arg("-C")
            .arg(source_root)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    match git(&["status", "--porcelain"]) {
        None => {
            return Some(format!("{} is not a git checkout", source_root.display()));
        }
        Some(changes) if !changes.is_empty() => {
            return Some(format!(
                "the JSSpector checkout at {} has uncommitted changes",
                source_root.display()
            ));
        }
        Some(_) => {}
    }
    match git(&["rev-list", "--count", "@{upstream}..HEAD"]).as_deref() {
        Some("0") => None,
        Some(_) => Some(format!(
            "the JSSpector checkout at {} has unpublished commits",
            source_root.display()
        )),
        None => Some(format!(
            "the JSSpector checkout at {} has no upstream branch",
            source_root.display()
        )),
    }
}

fn evolve_repository(source_root: &Path, repository: &str, push: bool) -> Result<ExitCode, String> {
    let workflow = source_root.join(".satori/self-heal.sh");
    eprintln!("jsspector: validating and repairing scanner support for {repository}");
    let mut command = ProcessCommand::new(&workflow);
    command
        .current_dir(source_root)
        .args(["--repo", repository]);
    if push {
        command.arg("--push");
    }
    let status = command
        .status()
        .map_err(|error| format!("start automatic scanner repair: {error}"))?;
    Ok(ExitCode::from(
        status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(EXIT_ENGINE),
    ))
}

fn evolve_repository_batch(
    repositories: &Path,
    parallel: NonZeroUsize,
) -> Result<ExitCode, String> {
    let compiled_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "the compiled JSSpector source root is unavailable".to_owned())?;
    let source_root = std::env::var_os("JSSPECTOR_SOURCE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| compiled_root.to_path_buf());
    let workflow = source_root.join(".satori/self-heal-batch.py");
    if !workflow.is_file() {
        return Err(format!(
            "parallel scanner repair needs a JSSpector source checkout; set \
             JSSPECTOR_SOURCE_ROOT (looked for {})",
            workflow.display()
        ));
    }
    let repositories = if repositories.is_absolute() {
        repositories.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("read current directory: {error}"))?
            .join(repositories)
    };
    eprintln!(
        "jsspector: completing repositories from {} with {} workers",
        repositories.display(),
        parallel
    );
    let status = ProcessCommand::new("python3")
        .arg(workflow)
        .args(["--repos", repositories.to_string_lossy().as_ref()])
        .args(["--parallel", &parallel.to_string()])
        .arg("--push")
        .current_dir(&source_root)
        .status()
        .map_err(|error| format!("start parallel scanner repair: {error}"))?;
    Ok(ExitCode::from(
        status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(EXIT_ENGINE),
    ))
}

fn evolve(args: &EvolveArgs) -> ExitCode {
    if let Some(repositories) = args.repos.as_deref() {
        return match evolve_repository_batch(
            repositories,
            args.parallel.unwrap_or(NonZeroUsize::MIN),
        ) {
            Ok(code) => code,
            Err(error) => fail(EXIT_ENGINE, error),
        };
    }
    let Some(repository) = args.repo.as_deref() else {
        return fail(EXIT_USAGE, "give --repo OWNER/REPO or --repos FILE");
    };
    let Some(source_root) = self_heal_source_root() else {
        return fail(
            EXIT_ENGINE,
            "the JSSpector source checkout is unknown; set JSSPECTOR_SOURCE_ROOT",
        );
    };
    if let Some(reason) = self_heal_unavailable(Some(&source_root)) {
        return fail(EXIT_ENGINE, reason);
    }
    match evolve_repository(&source_root, repository, args.push) {
        Ok(code) => code,
        Err(error) => fail(EXIT_ENGINE, error),
    }
}

fn scan(args: &ScanArgs) -> ExitCode {
    let started = Instant::now();
    let remote = match args.repo.as_deref().map(checkout_repository).transpose() {
        Ok(remote) => remote,
        Err(error) => return fail(EXIT_USAGE, error),
    };
    let Some(path) = remote
        .as_ref()
        .map(|checkout| checkout.path.as_path())
        .or(args.path.as_deref())
    else {
        return fail(EXIT_USAGE, "give a local path or --repo OWNER/REPO");
    };
    let root_label = remote.as_ref().map_or_else(
        || path.to_string_lossy().into_owned(),
        |checkout| checkout.label.clone(),
    );
    // Read before verification, which may install dependencies in the checkout.
    let git = git_info(path);
    let loaded = match setup(path, &args.config) {
        Ok(loaded) => loaded,
        Err(code) => return code,
    };
    let settings = (|| -> Result<_, String> {
        let min_severity = args
            .min_severity
            .or(loaded.min_severity()?)
            .unwrap_or(Severity::Low);
        let fail_on = args.fail_on.or(loaded.fail_on()?);
        let disabled = loaded.disabled()?;
        let mut patterns = loaded.config.exclude.clone();
        patterns.extend(args.exclude.iter().cloned());
        let excludes = config::Excludes::new(&patterns)?;
        let baseline = match &args.baseline {
            Some(path) => Some(path.clone()),
            None => loaded.config.baseline.as_deref().map(|p| loaded.resolve(p)),
        };
        Ok((min_severity, fail_on, disabled, excludes, baseline))
    })();
    let (min_severity, fail_on, disabled, excludes, baseline_path) = match settings {
        Ok(settings) => settings,
        Err(err) => return fail(EXIT_USAGE, err),
    };
    // A baseline named on the command line must exist; one named in the config may not exist
    // yet (it is written by the first --write-baseline).
    let accepted = match &baseline_path {
        Some(path) if args.baseline.is_some() || path.exists() => match baseline::read(path) {
            Ok(fingerprints) => Some(fingerprints),
            Err(err) => return fail(EXIT_USAGE, err),
        },
        _ => None,
    };
    let include = match classes(&args.include, &loaded) {
        Ok(include) => include,
        Err(code) => return code,
    };
    let analysis = match analyze(path, args.threads, include, &excludes) {
        Ok(analysis) => analysis,
        Err(code) => return code,
    };
    let analysis_complete = analysis.complete();
    let incomplete_summary = (!analysis_complete).then(|| analysis.incomplete_summary());

    let mut sources = text::Sources::new(&analysis.root);
    let honor_inline_ignores = remote.is_none() && !args.no_inline_ignores;
    let mut ignored = 0;
    let reported: Vec<Finding> = analysis
        .findings
        .into_iter()
        .filter(|f| f.severity <= min_severity && !disabled.contains(&f.class))
        .filter(|f| {
            let silenced = honor_inline_ignores && sources.ignores(f);
            ignored += usize::from(silenced);
            !silenced
        })
        .collect();
    if let Some(path) = &args.write_baseline
        && let Err(err) = baseline::write(path, &reported)
    {
        return fail(EXIT_ENGINE, err);
    }
    let (findings, baselined): (Vec<Finding>, Vec<Finding>) = match &accepted {
        Some(accepted) => reported
            .into_iter()
            .partition(|f| !accepted.contains(&f.fingerprint)),
        None => (reported, Vec::new()),
    };

    // `--verify`: run the app and confirm each finding. Only when asked; a failure to reach
    // Docker in strict mode is a usage error.
    let verification = match args.verify {
        None => Vec::new(),
        Some(_) if !analysis_complete && !args.allow_incomplete => {
            eprintln!(
                "jsspector: dynamic verification skipped because the static analysis is incomplete"
            );
            Vec::new()
        }
        Some(mode) => {
            let missing = match mode {
                VerifyMode::Strict => verify::Missing::Fail,
                VerifyMode::BestEffort => verify::Missing::Skip,
            };
            let selected: Vec<Finding> = if args.verify_fingerprint.is_empty() {
                findings.clone()
            } else if args.verify_until_first {
                args.verify_fingerprint
                    .iter()
                    .filter_map(|fingerprint| {
                        findings
                            .iter()
                            .find(|finding| finding.fingerprint == *fingerprint)
                            .cloned()
                    })
                    .fold(Vec::new(), |mut selected, finding| {
                        if selected
                            .iter()
                            .all(|item: &Finding| item.fingerprint != finding.fingerprint)
                        {
                            selected.push(finding);
                        }
                        selected
                    })
            } else {
                findings
                    .iter()
                    .filter(|finding| args.verify_fingerprint.contains(&finding.fingerprint))
                    .cloned()
                    .collect()
            };
            if args.local {
                verify::use_local_runtime();
            }
            let defaults = verify::FixOptions::default();
            let fix_options = verify::FixOptions {
                enabled: !args.no_fix,
                llm: !args.no_fix_llm,
                model: args.fix_model.clone(),
                attempts: args.fix_attempts.unwrap_or(defaults.attempts),
                timeout: args
                    .fix_timeout
                    .map_or(defaults.timeout, std::time::Duration::from_secs),
                recipes: if args.learn_fixes || args.publish_fixes {
                    mutable_fix_recipes()
                } else {
                    Some(compiled_fix_recipes())
                },
                learn: args.learn_fixes || args.publish_fixes,
                publish: args.publish_fixes,
                allow_unpublished_recipes: false,
            };
            let result = if args.verify_until_first {
                verify::run_until_first(&analysis.root, &selected, missing, &fix_options)
            } else {
                verify::run(&analysis.root, &selected, missing, &fix_options)
            };
            match result {
                Ok(verdicts) => verdicts,
                Err(err) => return fail(EXIT_USAGE, err),
            }
        }
    };

    let format = match (args.format, args.json) {
        (Some(format), _) => format,
        (None, true) => Format::Json,
        (None, false) => Format::Text,
    };
    let written = write_to(args.output.as_deref(), |out, color| match format {
        Format::Json => {
            let verdicts = verdicts_by_fingerprint(&verification);
            let output = ScanOutput {
                root: root_label,
                git,
                files_scanned: analysis.files_scanned,
                complete: analysis_complete,
                findings: findings
                    .iter()
                    .map(|finding| {
                        ReportedFinding::new(
                            finding,
                            &mut sources,
                            verdicts.get(finding.fingerprint.as_str()).copied(),
                        )
                    })
                    .collect(),
                baselined: baselined.len(),
                ignored,
                skipped: &analysis.skipped,
                truncated: &analysis.truncated,
            };
            serde_json::to_writer_pretty(&mut *out, &output)
                .map_err(io::Error::from)
                .and_then(|()| writeln!(out))
        }
        Format::Sarif => {
            let mut notes: Vec<sarif::Note<'_>> = analysis
                .skipped
                .iter()
                .map(|note| sarif::Note {
                    file: &note.file,
                    reason: &note.reason,
                    error: note.panicked,
                })
                .collect();
            notes.extend(analysis.truncated.iter().map(|file| sarif::Note {
                file,
                reason: "analysis reached its depth cap",
                error: true,
            }));
            let verified: std::collections::BTreeMap<String, &str> = verification
                .iter()
                .map(|v| (v.fingerprint.clone(), v.outcome.label()))
                .collect();
            let log = sarif::document(
                &analysis.root,
                &findings,
                &notes,
                analysis_complete,
                accepted.is_some(),
                &verified,
            );
            serde_json::to_writer_pretty(&mut *out, &log)
                .map_err(io::Error::from)
                .and_then(|()| writeln!(out))
        }
        Format::Text => text::write(
            out,
            &findings,
            &mut sources,
            &text::Summary {
                files_scanned: analysis.files_scanned,
                skipped: analysis.skipped.len(),
                baselined: baselined.len(),
                ignored,
                elapsed: started.elapsed(),
            },
            &text::Style::new(color),
        )
        .and_then(|()| verify::write_text(out, &verification, color)),
    });
    if let Err(err) = written {
        return fail(EXIT_ENGINE, format!("cannot write the report: {err}"));
    }
    if !analysis_complete && !args.allow_incomplete {
        return fail(
            EXIT_ENGINE,
            format!(
                "analysis incomplete ({}); inspect the report or pass --allow-incomplete",
                incomplete_summary
                    .as_deref()
                    .unwrap_or("unknown incompleteness")
            ),
        );
    }
    match fail_on {
        Some(level) if findings.iter().any(|f| f.severity <= level) => {
            ExitCode::from(EXIT_FINDINGS)
        }
        _ => ExitCode::SUCCESS,
    }
}

/// Runs `write` on FILE, or on stdout (with color when stdout is a terminal), and flushes.
fn write_to(
    file: Option<&Path>,
    write: impl FnOnce(&mut dyn Write, bool) -> io::Result<()>,
) -> io::Result<()> {
    match file {
        Some(path) => secure_io::atomic_write(path, |output| {
            let mut output = BufWriter::new(output);
            write(&mut output, false)?;
            output.flush()
        }),
        None => {
            let stdout = io::stdout();
            let color = stdout.is_terminal();
            let mut out = BufWriter::new(stdout.lock());
            write(&mut out, color)?;
            out.flush()
        }
    }
}

fn explain(args: &ExplainArgs) -> ExitCode {
    let loaded = match setup(&args.path, &args.config) {
        Ok(loaded) => loaded,
        Err(code) => return code,
    };
    let wanted = args.what.trim();
    if let Some(rule) = rules::by_name(wanted) {
        return match write_to(None, |out, color| {
            if args.json {
                serde_json::to_writer_pretty(
                    &mut *out,
                    &serde_json::json!({ "rule": rule_json(rule) }),
                )
                .map_err(io::Error::from)
                .and_then(|()| writeln!(out))
            } else {
                explain::write_rule(out, rule, &text::Style::new(color))
            }
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => fail(EXIT_ENGINE, format!("cannot write: {err}")),
        };
    }
    let include = match classes(&args.include, &loaded) {
        Ok(include) => include,
        Err(code) => return code,
    };
    let excludes = match config::Excludes::new(&loaded.config.exclude) {
        Ok(excludes) => excludes,
        Err(err) => return fail(EXIT_USAGE, err),
    };
    let analysis = match analyze(&args.path, args.threads, include, &excludes) {
        Ok(analysis) => analysis,
        Err(code) => return code,
    };
    // A fingerprint, a unique prefix of one (at least 4 characters), or a key.
    let exact: Vec<&Finding> = analysis
        .findings
        .iter()
        .filter(|f| f.fingerprint == wanted || f.key == wanted)
        .collect();
    let candidates: Vec<&Finding> = if exact.is_empty() && wanted.len() >= 4 {
        analysis
            .findings
            .iter()
            .filter(|f| f.fingerprint.starts_with(wanted))
            .collect()
    } else {
        exact
    };
    let finding = match candidates.as_slice() {
        [finding] => *finding,
        [] => {
            return fail(
                EXIT_USAGE,
                format!(
                    "`{wanted}` is neither a vulnerability class nor the fingerprint of a finding \
                     under {} (of any severity)",
                    args.path.display()
                ),
            );
        }
        many => {
            return fail(
                EXIT_USAGE,
                format!(
                    "`{wanted}` matches {} findings; give more of the fingerprint",
                    many.len()
                ),
            );
        }
    };
    let mut sources = text::Sources::new(&analysis.root);
    match write_to(None, |out, color| {
        if args.json {
            let document = serde_json::json!({
                "rule": rule_json(rules::rule(finding.class)),
                "finding": finding,
            });
            serde_json::to_writer_pretty(&mut *out, &document)
                .map_err(io::Error::from)
                .and_then(|()| writeln!(out))
        } else {
            explain::write_finding(out, finding, &mut sources, &text::Style::new(color))
        }
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => fail(EXIT_ENGINE, format!("cannot write: {err}")),
    }
}

/// A rule as JSON (for `explain --json`).
fn rule_json(rule: &rules::Rule) -> serde_json::Value {
    serde_json::json!({
        "id": rules::id(rule.class),
        "class": rule.class.name(),
        "title": rule.title,
        "cwe": rule.cwe,
        "security_severity": rule.security_severity,
        "summary": rule.summary,
        "fix": rule.fix,
        "safe": rule.safe,
        "sinks": explain::sinks(rule.class),
        "modules": explain::families(rule.class)
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>(),
    })
}

fn ir(args: &IrArgs) -> ExitCode {
    let pool = match ParsePool::new(args.threads) {
        Ok(pool) => pool,
        Err(err) => return fail(EXIT_ENGINE, err),
    };
    let discovered = pool.install(|| jss_core::discover(&args.path, &DiscoverOptions::default()));
    let discovery = match discovered {
        Ok(discovery) => discovery,
        Err(err @ DiscoverError::Io { .. }) => return fail(EXIT_ENGINE, err),
        Err(err) => return fail(EXIT_USAGE, err),
    };
    let selection = discovery.selection(ClassSet::default());
    let reports = pool.scan(&discovery.files, selection);
    let modules: Vec<jss_core::ir::Module> = reports.into_iter().map(|r| r.module).collect();
    let graph = jss_core::ir::link(&modules);
    let document = serde_json::json!({ "modules": modules, "call_graph": graph });
    let mut out = BufWriter::new(io::stdout().lock());
    let written = serde_json::to_writer_pretty(&mut out, &document)
        .map_err(io::Error::from)
        .and_then(|()| writeln!(out))
        .and_then(|()| out.flush());
    if let Err(err) = written {
        return fail(EXIT_ENGINE, format!("cannot write the IR: {err}"));
    }
    ExitCode::SUCCESS
}

fn routes(args: &RoutesArgs) -> ExitCode {
    let loaded = match setup(&args.path, &args.config) {
        Ok(loaded) => loaded,
        Err(code) => return code,
    };
    let excludes = match config::Excludes::new(&loaded.config.exclude) {
        Ok(excludes) => excludes,
        Err(err) => return fail(EXIT_USAGE, err),
    };
    let pool = match ParsePool::new(args.threads) {
        Ok(pool) => pool,
        Err(err) => return fail(EXIT_ENGINE, err),
    };
    let discovered = pool.install(|| jss_core::discover(&args.path, &DiscoverOptions::default()));
    let mut discovery = match discovered {
        Ok(discovery) => discovery,
        Err(err @ DiscoverError::Io { .. }) => return fail(EXIT_ENGINE, err),
        Err(err) => return fail(EXIT_USAGE, err),
    };
    discovery
        .files
        .retain(|file| !excludes.matches(&file.rel_path));
    // The config's `include` (tests, examples, ...) applies to the inventory as to `scan`.
    let include = match classes(&[], &loaded) {
        Ok(include) => include,
        Err(code) => return code,
    };
    let selection = discovery.selection(include);
    let reports = pool.scan(&discovery.files, selection);
    let routes = jss_frontend::inventory(&discovery.root, &reports);
    let mut out = BufWriter::new(io::stdout().lock());
    let written = if args.openapi {
        let title = args
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        serde_json::to_writer_pretty(&mut out, &openapi::document(&title, &routes))
            .map_err(io::Error::from)
            .and_then(|()| writeln!(out))
    } else if args.json {
        serde_json::to_writer_pretty(&mut out, &routes)
            .map_err(io::Error::from)
            .and_then(|()| writeln!(out))
    } else {
        write_routes(&mut out, &routes)
    }
    .and_then(|()| out.flush());
    if let Err(err) = written {
        return fail(EXIT_ENGINE, format!("cannot write the inventory: {err}"));
    }
    ExitCode::SUCCESS
}

/// One line per entry point: method, path, auth, handler and where it is registered.
fn write_routes(out: &mut impl Write, routes: &[jss_frontend::Route]) -> io::Result<()> {
    let width = routes
        .iter()
        .map(|r| r.path.len())
        .max()
        .unwrap_or(0)
        .min(70);
    for r in routes {
        writeln!(
            out,
            "{:<8} {:<width$}  {:<13} {}  {}:{}{}",
            r.method,
            r.path,
            r.auth.name(),
            r.handler,
            r.file,
            r.line,
            if r.inputs.is_empty() {
                String::new()
            } else {
                format!("  [{}]", r.inputs.join(", "))
            }
        )?;
    }
    writeln!(out, "\n{} entry point(s)", routes.len())
}

fn parse(args: &ParseArgs) -> ExitCode {
    let started = Instant::now();
    // One pool for everything, so --threads bounds discovery too.
    let pool = match ParsePool::new(args.threads) {
        Ok(pool) => pool,
        Err(err) => return fail(EXIT_ENGINE, err),
    };
    let discover_started = Instant::now();
    let discovered = pool.install(|| jss_core::discover(&args.path, &DiscoverOptions::default()));
    let mut discovery = match discovered {
        Ok(discovery) => discovery,
        Err(err @ DiscoverError::Io { .. }) => return fail(EXIT_ENGINE, err),
        Err(err) => return fail(EXIT_USAGE, err),
    };
    let discover_time = discover_started.elapsed();

    let selection = discovery.selection(include_set(&args.include));
    if args.esm {
        if !discovery.single_file {
            return fail(
                EXIT_USAGE,
                "--esm applies to a single file; in a directory, each file follows its nearest \
                 package.json \"type\"",
            );
        }
        for file in &mut discovery.files {
            file.package_type = PackageType::Module;
        }
    }

    // Every file gets a report: selected ones are parsed, the others classified.
    let parse_started = Instant::now();
    let reports = pool.process(&discovery.files, selection);
    let parse_time = parse_started.elapsed();

    let root = args.path.to_string_lossy().into_owned();
    let mut report = report::build(root, &discovery, selection, &reports, args.list);
    if args.stats {
        report.stats = Some(report::Stats::new(
            pool.threads(),
            started,
            discover_time,
            parse_time,
            &reports,
        ));
    }
    // Streamed, so the report is never held in memory as text.
    let mut out = BufWriter::new(io::stdout().lock());
    let written = serde_json::to_writer_pretty(&mut out, &report)
        .map_err(io::Error::from)
        .and_then(|()| writeln!(out))
        .and_then(|()| out.flush());
    if let Err(err) = written {
        return fail(EXIT_ENGINE, format!("cannot write the report: {err}"));
    }
    ExitCode::SUCCESS
}

/// Prints `jsspector: <message>` to stderr and returns `code`.
/// Where a scanned checkout came from.
#[derive(Debug, PartialEq, Eq, Serialize)]
struct GitInfo {
    /// The `origin` remote's URL, without credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    repository: Option<String>,
    /// The checked-out commit.
    revision: String,
    /// The scanned directory relative to the repository's top level (empty at the top level): fix
    /// diffs are relative to the scanned directory.
    path: String,
    /// Whether tracked files had uncommitted changes, in which case a diff may not apply to
    /// `revision` itself.
    dirty: bool,
}

/// The git checkout `path` is in, if any.
fn git_info(path: &Path) -> Option<GitInfo> {
    let dir = if path.is_file() { path.parent()? } else { path };
    let git = |args: &[&str]| -> Option<String> {
        let output = ProcessCommand::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    let revision = git(&["rev-parse", "HEAD"])?;
    Some(GitInfo {
        repository: git(&["remote", "get-url", "origin"])
            .filter(|url| !url.is_empty())
            .map(|url| without_credentials(&url)),
        revision,
        path: git(&["rev-parse", "--show-prefix"])
            .unwrap_or_default()
            .trim_end_matches('/')
            .to_owned(),
        dirty: git(&["status", "--porcelain", "--untracked-files=no"])
            .is_some_and(|status| !status.is_empty()),
    })
}

/// `url` without the user and password a clone URL may embed (`https://user:token@host/…`).
fn without_credentials(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('@') {
            Some((userinfo, host)) if !userinfo.contains('/') => format!("{scheme}://{host}"),
            _ => url.to_owned(),
        },
        None => url.to_owned(),
    }
}

/// The logical recipe-store path compiled into this binary. Read-only verification can always use
/// it because [`verify::recipes::Book`] falls back to its embedded copy when no trusted checkout is
/// available.
fn compiled_fix_recipes() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(".satori")
        .join("fix-recipes")
}

/// A store may be mutated only from JSSpector's main checkout. Linked repair worktrees must not
/// write outside their allowed branch, while installed binaries still retain read-only recipes.
fn mutable_fix_recipes() -> Option<PathBuf> {
    recipe_store_of(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

/// The recipe store of `checkout`, only when it is a repository's main checkout (its `.git` is a
/// directory). A linked worktree — where a repair agent builds and checks a candidate scanner —
/// has no store: a fix it proved would be an edit outside the repair's allowed paths, and its
/// branch is no place to learn or publish from.
fn recipe_store_of(checkout: &Path) -> Option<PathBuf> {
    checkout
        .join(".git")
        .is_dir()
        .then(|| checkout.join(".satori").join("fix-recipes"))
}

fn fail(code: u8, message: impl Display) -> ExitCode {
    let _ = writeln!(io::stderr(), "jsspector: {message}");
    ExitCode::from(code)
}
