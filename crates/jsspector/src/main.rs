//! `jsspector` command-line interface.

mod baseline;
mod config;
mod excerpt;
mod explain;
mod online_ui;
mod openapi;
mod report;
mod rules;
mod sarif;
mod secure_io;
mod text;
mod update;
mod verify;

use std::ffi::OsString;
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
    /// Research one resumable pass of recently pushed public JavaScript repositories.
    ///
    /// Static workers feed deterministic and Opus-ranked queues. Only findings reproduced by
    /// strict Docker verification become private Satori issues. A proven exploit gets one
    /// best-effort Opus fix attempt by default; failure to produce a fix never hides the issue.
    Online(Box<OnlineArgs>),
    /// Grow JSSpector against its pinned exploitability benchmark.
    ///
    /// This is the explicit, mutating counterpart to `scan`: it may invoke the repair agent,
    /// commit validated scanner changes and push them to the configured upstream branch. A normal
    /// scan never evolves the scanner or publishes what it learns.
    Evolve(EvolveArgs),
    /// Upgrade a pip- or pipx-installed JSSpector to the newest version available on PyPI.
    Update,
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
    /// Run each verified app in this environment instead of a Docker container: only for an
    /// already-disposable sandbox such as a containerized CI or Satori job, where Docker is not
    /// available. Refused on an ordinary host. Other disposable workers must set
    /// JSS_VERIFY_DISPOSABLE=1. The services an app needs are provisioned on demand.
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
    /// Record what a proven LLM fix taught JSSpector in its private user-data recipe store. Off by
    /// default; the store is never written inside the public JSSpector checkout.
    #[arg(long, requires = "verify")]
    learn_fixes: bool,
    /// Promote repository-neutral proven fix recipes through a versioned evolve release. Exact
    /// replay examples remain private and are never included in that release.
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
        required_unless_present = "repo"
    )]
    repos: Option<PathBuf>,
    /// Independent repair workers used with --repos.
    #[arg(long, value_name = "N", requires = "repos", conflicts_with = "repo")]
    parallel: Option<NonZeroUsize>,
    /// Leave a single-repository evolution local instead of publishing it. By default validated
    /// scanner repairs are pushed, patch-versioned and released to GitHub and PyPI. Batch workers
    /// always publish because they exchange generations through the upstream branch.
    #[arg(long, conflicts_with = "repos")]
    no_push: bool,
}

#[derive(Args)]
struct OnlineArgs {
    /// How far back GitHub discovery looks.
    #[arg(long, default_value = "24h")]
    since: String,
    /// Minimum repository fork count; 0 includes repositories with no forks.
    #[arg(long, default_value_t = 0)]
    min_forks: usize,
    /// Analyze at most this many repositories; 0 means every match.
    #[arg(long, default_value_t = 0)]
    limit: usize,
    /// Skip repositories larger than this GitHub-reported size in MiB.
    #[arg(long, default_value_t = 100)]
    max_repo_size_mb: usize,
    /// GitHub language selected by discovery.
    #[arg(long, default_value = "JavaScript")]
    language: String,
    /// Private-vulnerability-reporting policy.
    #[arg(long, default_value = "off", value_parser = ["on", "off", "any"])]
    pvr: String,
    /// Replay this deterministic owner/repository inventory instead of searching GitHub.
    #[arg(long, value_name = "FILE")]
    repos_file: Option<PathBuf>,
    /// Directory holding durable state and private run artifacts [default:
    /// runs/jsspector-online, or runs/jsspector-calibrate with --calibrate].
    #[arg(long, value_name = "DIR")]
    out: Option<PathBuf>,
    /// Concurrent one-thread static scans [default: auto, at least 12].
    #[arg(long)]
    static_parallel: Option<usize>,
    /// Maximum run-owned repository checkouts retained across static analysis and verification
    /// [default: auto, at least 24].
    #[arg(long)]
    max_checkouts: Option<usize>,
    /// Deterministically ordered dynamic-verification workers [default: auto, the Docker slots
    /// left after the Opus lane].
    #[arg(long)]
    parallel_no_ai: Option<usize>,
    /// Opus-ranked dynamic-verification workers.
    #[arg(long, default_value_t = 2)]
    parallel_ai: usize,
    /// Shared Docker verification cap [default: auto, sized from this host's free CPU and
    /// memory].
    #[arg(long)]
    parallel_docker: Option<usize>,
    /// Whole-host CPU and memory share that auto-sizing and the governor aim for.
    #[arg(long, default_value_t = 0.8, value_parser = parse_utilization)]
    target_utilization: f64,
    /// Keep auto-sized worker counts fixed instead of adjusting the Docker slots while the pass
    /// runs. Explicit --parallel-docker or --parallel-no-ai also keep them fixed.
    #[arg(long)]
    no_governor: bool,
    /// Print the concurrency this host supports, and why, then exit without running a pass.
    #[arg(long, conflicts_with = "calibrate")]
    estimate: bool,
    /// Measure what one verification costs on this host and save the host profile that later
    /// passes size themselves from. Runs a real, local-only pass without fixes or Opus ranking at
    /// two load levels.
    #[arg(long)]
    calibrate: bool,
    /// Measured calibration window, counted from the first verification.
    #[arg(
        long,
        value_name = "MINUTES",
        default_value_t = 30,
        requires = "calibrate"
    )]
    calibrate_minutes: usize,
    /// Stop safely if Docker GC cannot preserve this much host disk; 0 disables the guard.
    #[arg(long, default_value_t = 100)]
    min_free_gb: usize,
    /// Maximum BuildKit cache retained by online GC.
    #[arg(long, default_value_t = 20)]
    docker_cache_gb: usize,
    /// Run Docker storage GC after this many completed verifications.
    #[arg(long, default_value_t = 8)]
    docker_gc_every: usize,
    /// Maximum seconds for the one reusable shallow checkout of a repository.
    #[arg(long, default_value_t = 120)]
    clone_timeout: usize,
    /// Maximum seconds for statically scanning an already checked-out repository.
    #[arg(long, default_value_t = 600)]
    static_timeout: usize,
    /// Maximum seconds for building and starting one candidate application.
    #[arg(long, default_value_t = 180)]
    verify_startup_timeout: usize,
    /// Idle decision point for one candidate before it has made a real request.
    #[arg(long, default_value_t = 180)]
    verify_candidate_soft_timeout: usize,
    /// Maximum seconds for a candidate that has made real request progress.
    #[arg(long, default_value_t = 300)]
    verify_candidate_hard_timeout: usize,
    /// Normal seconds for strict dynamic verification of one repository.
    #[arg(long, default_value_t = 900)]
    verify_timeout: usize,
    /// Maximum repository seconds after sink or canary evidence appears (a route that merely
    /// answers does not extend the normal budget).
    #[arg(long, default_value_t = 1800)]
    verify_extended_timeout: usize,
    /// Maximum seconds spent proving a fix after exploitation succeeds.
    #[arg(long, default_value_t = 600)]
    fix_timeout: usize,
    /// Maximum seconds for one optional Opus candidate-ranking call.
    #[arg(long, default_value_t = 60)]
    ai_timeout: usize,
    /// Keep verified reports local instead of creating private Satori issues.
    #[arg(long)]
    local_only: bool,
    /// Satori credential profile used for deduplication and synchronization.
    #[arg(long, default_value = "satoridev05")]
    satori_profile: String,
    /// Do not attempt or learn a proven fix after exploitation succeeds.
    #[arg(long)]
    no_evolve: bool,
    /// Print append-only logs instead of the interactive terminal interface.
    #[arg(long)]
    no_tui: bool,
    /// Override the Python online controller embedded in the JSSpector binary.
    #[arg(long, value_name = "FILE", hide = true)]
    runner: Option<PathBuf>,
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
    Verified {
        how: &'a str,
        /// The demonstrated CIA impact, distinct from merely reaching a dangerous primitive.
        impact: &'static str,
    },
    NotReproduced {
        tried: usize,
    },
    Skipped {
        reason: &'a str,
    },
}

impl<'a> Exploitation<'a> {
    fn from_verdict(verdict: &'a verify::Verdict) -> (Self, Option<verify::Reproduction>) {
        match &verdict.outcome {
            verify::Outcome::Verified { how, poc } => {
                let impact = if poc.evidence.contains("existence oracle")
                    && poc.evidence.contains("local file content disclosure")
                {
                    "file-existence-only"
                } else {
                    "demonstrated"
                };
                (Self::Verified { how, impact }, Some(poc.report_safe()))
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
            json!({
                "outcome": "verified",
                "how": "GET /items?id=proof",
                "impact": "demonstrated"
            })
        );
        let poc = serde_json::to_value(poc.unwrap()).unwrap();
        assert_eq!(poc["command"], "curl http://TARGET/items?id=proof");
        assert_eq!(poc["evidence"], "the response contained proof");
    }

    #[test]
    fn existence_only_traversal_is_machine_readable_as_non_material_impact() {
        let mut poc = reproduction();
        poc.evidence =
            "the target produced an existence oracle, not local file content disclosure".to_owned();
        let verdict = verdict(
            "0123456789abcdef",
            verify::Outcome::Verified {
                how: "GET /../../etc/shadow".to_owned(),
                poc,
            },
        );
        let (exploitation, _) = Exploitation::from_verdict(&verdict);

        assert_eq!(
            serde_json::to_value(exploitation).unwrap()["impact"],
            "file-existence-only"
        );
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
        Command::Online(args) => online(&args),
        Command::Evolve(args) => evolve(&args),
        Command::Update => update_cli(),
        Command::Routes(args) => routes(&args),
        Command::Explain(args) => explain(&args),
        Command::Ir(args) => ir(&args),
    }
}

fn update_cli() -> ExitCode {
    match update::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(EXIT_ENGINE, format!("update: {error}")),
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
    #![allow(clippy::panic, clippy::unwrap_used)]

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
    fn recipe_store_defaults_to_private_user_data() {
        assert_eq!(
            recipe_store_path(
                None,
                Some(Path::new("/tmp/xdg")),
                Some(Path::new("/tmp/home")),
            ),
            Some(PathBuf::from("/tmp/xdg/jsspector/fix-recipes"))
        );
        assert_eq!(
            recipe_store_path(None, None, Some(Path::new("/tmp/home"))),
            Some(PathBuf::from(
                "/tmp/home/.local/share/jsspector/fix-recipes",
            ))
        );
        assert_eq!(
            recipe_store_path(Some(Path::new("/private/store")), None, None),
            Some(PathBuf::from("/private/store"))
        );
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
                "2"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["jsspector", "evolve", "--repos", "list.txt"]).is_ok());
        assert!(
            Cli::try_parse_from(["jsspector", "evolve", "--repos", "list.txt", "--no-push"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["jsspector", "evolve", "--repo", "owner/project"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "jsspector",
                "evolve",
                "--repo",
                "owner/project",
                "--no-push"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["jsspector", "evolve", "--repo", "owner/project", "--push"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["jsspector", "evolve"]).is_err());
    }

    #[test]
    fn online_defaults_are_the_tuned_verified_only_pipeline() {
        let cli = Cli::try_parse_from(["jsspector", "online"]).unwrap();
        let Command::Online(args) = cli.command else {
            panic!("online did not parse as the online command");
        };
        assert_eq!(args.since, "24h");
        assert_eq!(args.min_forks, 0);
        assert_eq!(args.limit, 0);
        assert_eq!(args.max_repo_size_mb, 100);
        assert_eq!(args.pvr, "off");
        // Worker counts are auto-sized by the controller from this host's free resources.
        assert_eq!(args.static_parallel, None);
        assert_eq!(args.max_checkouts, None);
        assert_eq!(args.parallel_no_ai, None);
        assert_eq!(args.parallel_ai, 2);
        assert_eq!(args.parallel_docker, None);
        assert!((args.target_utilization - 0.8).abs() < f64::EPSILON);
        assert!(!args.no_governor && !args.estimate && !args.calibrate);
        assert_eq!(online_out(&args), PathBuf::from("runs/jsspector-online"));
        assert_eq!(args.min_free_gb, 100);
        assert_eq!(args.docker_cache_gb, 20);
        assert_eq!(args.docker_gc_every, 8);
        assert_eq!(args.clone_timeout, 120);
        assert_eq!(args.static_timeout, 600);
        assert_eq!(args.verify_startup_timeout, 180);
        assert_eq!(args.verify_candidate_soft_timeout, 180);
        assert_eq!(args.verify_candidate_hard_timeout, 300);
        assert_eq!(args.verify_timeout, 900);
        assert_eq!(args.verify_extended_timeout, 1800);
        assert_eq!(args.fix_timeout, 600);
        assert_eq!(args.ai_timeout, 60);
        assert_eq!(args.satori_profile, "satoridev05");
        assert!(!args.local_only);
        assert!(!args.no_evolve);
        assert!(!args.no_tui);

        let arguments = online_arguments(&args, Path::new("/tmp/jsspector"))
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for expected in [
            "--satori-sync",
            "--learn-fixes",
            "--ai-model",
            "claude-opus-5-5",
            "--fix-model",
            "--parallel-ai",
            "--target-utilization",
            "--max-repo-size-mb",
            "--verify-startup-timeout",
            "--verify-candidate-soft-timeout",
            "--verify-candidate-hard-timeout",
            "--verify-extended-timeout",
            "--satori-profile",
        ] {
            assert!(
                arguments.iter().any(|value| value == expected),
                "{expected}"
            );
        }
    }

    #[test]
    fn online_local_non_evolving_mode_has_no_mutating_flags() {
        let cli = Cli::try_parse_from([
            "jsspector",
            "online",
            "--local-only",
            "--no-evolve",
            "--no-tui",
        ])
        .unwrap();
        let Command::Online(args) = cli.command else {
            panic!("online did not parse as the online command");
        };
        let arguments = online_arguments(&args, Path::new("/tmp/jsspector"));
        assert!(!arguments.iter().any(|value| value == "--satori-sync"));
        assert!(!arguments.iter().any(|value| value == "--learn-fixes"));
        assert!(!arguments.iter().any(|value| value == "--fix-attempts"));
    }

    #[test]
    fn online_auto_sizing_passes_only_explicit_counts() {
        let parse = |extra: &[&str]| {
            let cli = Cli::try_parse_from(["jsspector", "online"].iter().chain(extra)).unwrap();
            let Command::Online(args) = cli.command else {
                panic!("online did not parse as the online command");
            };
            let arguments = online_arguments(&args, Path::new("/tmp/jsspector"))
                .into_iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            (args, arguments)
        };
        let (_, automatic) = parse(&[]);
        for flag in [
            "--static-parallel",
            "--max-checkouts",
            "--parallel-no-ai",
            "--parallel-docker",
            "--no-governor",
            "--estimate",
            "--calibrate",
        ] {
            assert!(!automatic.iter().any(|value| value == flag), "{flag}");
        }
        let (_, explicit) = parse(&["--parallel-docker", "16", "--no-governor"]);
        let position = explicit
            .iter()
            .position(|value| value == "--parallel-docker")
            .unwrap();
        assert_eq!(explicit[position + 1], "16");
        assert!(explicit.iter().any(|value| value == "--no-governor"));

        let (args, estimate) = parse(&["--estimate"]);
        assert!(args.estimate);
        assert!(estimate.iter().any(|value| value == "--estimate"));

        assert!(
            Cli::try_parse_from(["jsspector", "online", "--target-utilization", "1.5"]).is_err()
        );
        assert!(Cli::try_parse_from(["jsspector", "online", "--estimate", "--calibrate"]).is_err());
        assert!(Cli::try_parse_from(["jsspector", "online", "--calibrate-minutes", "5"]).is_err());
    }

    #[test]
    fn online_calibration_measures_without_publishing_or_fixing() {
        let cli = Cli::try_parse_from([
            "jsspector",
            "online",
            "--calibrate",
            "--calibrate-minutes",
            "20",
        ])
        .unwrap();
        let Command::Online(args) = cli.command else {
            panic!("online did not parse as the online command");
        };
        assert_eq!(online_out(&args), PathBuf::from("runs/jsspector-calibrate"));
        let arguments = online_arguments(&args, Path::new("/tmp/jsspector"))
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for absent in [
            "--satori-sync",
            "--learn-fixes",
            "--fix-attempts",
            "--fix-model",
        ] {
            assert!(!arguments.iter().any(|value| value == absent), "{absent}");
        }
        let position = arguments
            .iter()
            .position(|value| value == "--calibrate-minutes")
            .unwrap();
        assert_eq!(arguments[position + 1], "20");
        assert!(
            arguments
                .iter()
                .any(|value| value == "runs/jsspector-calibrate")
        );
    }

    #[test]
    fn online_controller_is_bundled_without_the_monitor_checkout() {
        let controller = materialize_online_controller().unwrap();
        let runner = controller.runner;
        assert!(runner.is_file());
        let directory = runner.parent().unwrap();
        for module in [
            "controller.py",
            "discover.py",
            "github.py",
            "claude_limits.py",
            "resources.py",
        ] {
            assert!(directory.join(module).is_file(), "missing {module}");
        }
        let github = std::fs::read_to_string(directory.join("github.py")).unwrap();
        assert!(github.contains("jsspector-online"));
        assert!(!github.contains("jsspector-monitor"));
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

struct OnlineController {
    runner: PathBuf,
    _temporary: Option<tempfile::TempDir>,
}

fn online_runner(explicit: Option<&Path>) -> Result<OnlineController, String> {
    if let Some(path) = explicit {
        return path
            .is_file()
            .then(|| OnlineController {
                runner: path.to_path_buf(),
                _temporary: None,
            })
            .ok_or_else(|| format!("online controller not found: {}", path.display()));
    }
    if let Some(path) = std::env::var_os("JSSPECTOR_ONLINE_RUNNER").map(PathBuf::from) {
        return path
            .is_file()
            .then_some(OnlineController {
                runner: path.clone(),
                _temporary: None,
            })
            .ok_or_else(|| format!("JSSPECTOR_ONLINE_RUNNER is not a file: {}", path.display()));
    }
    materialize_online_controller()
}

const ONLINE_CONTROLLER: &[(&str, &str)] = &[
    (
        "controller.py",
        include_str!("../../../scripts/online/controller.py"),
    ),
    (
        "discover.py",
        include_str!("../../../scripts/online/discover.py"),
    ),
    (
        "github.py",
        include_str!("../../../scripts/online/github.py"),
    ),
    (
        "claude_limits.py",
        include_str!("../../../scripts/online/claude_limits.py"),
    ),
    (
        "resources.py",
        include_str!("../../../scripts/online/resources.py"),
    ),
];

fn materialize_online_controller() -> Result<OnlineController, String> {
    let temporary = tempfile::Builder::new()
        .prefix("jsspector-online-controller-")
        .tempdir()
        .map_err(|error| format!("create private online controller directory: {error}"))?;
    let directory = temporary.path();
    for (name, contents) in ONLINE_CONTROLLER {
        let path = directory.join(name);
        std::fs::write(&path, contents)
            .map_err(|error| format!("write bundled online controller: {error}"))?;
    }
    Ok(OnlineController {
        runner: directory.join("controller.py"),
        _temporary: Some(temporary),
    })
}

fn parse_utilization(value: &str) -> Result<f64, String> {
    let number: f64 = value
        .parse()
        .map_err(|_| format!("expected a fraction such as 0.8, got {value:?}"))?;
    if (0.1..=0.95).contains(&number) {
        Ok(number)
    } else {
        Err("expected a fraction between 0.1 and 0.95".to_owned())
    }
}

fn online_out(args: &OnlineArgs) -> PathBuf {
    args.out.clone().unwrap_or_else(|| {
        PathBuf::from(if args.calibrate {
            "runs/jsspector-calibrate"
        } else {
            "runs/jsspector-online"
        })
    })
}

/// Whether a pass may create Satori issues, attempt fixes or rank with Opus (a calibration never
/// does: it measures hardware).
fn online_publishes(args: &OnlineArgs) -> bool {
    !args.local_only && !args.calibrate
}

fn online_evolves(args: &OnlineArgs) -> bool {
    !args.no_evolve && !args.calibrate
}

fn online_arguments(args: &OnlineArgs, scanner: &Path) -> Vec<OsString> {
    let mut command = vec![
        OsString::from("--scanner"),
        scanner.as_os_str().to_owned(),
        OsString::from("--since"),
        OsString::from(&args.since),
        OsString::from("--min-forks"),
        OsString::from(args.min_forks.to_string()),
        OsString::from("--limit"),
        OsString::from(args.limit.to_string()),
        OsString::from("--max-repo-size-mb"),
        OsString::from(args.max_repo_size_mb.to_string()),
        OsString::from("--language"),
        OsString::from(&args.language),
        OsString::from("--pvr"),
        OsString::from(&args.pvr),
        OsString::from("--out"),
        online_out(args).into_os_string(),
        OsString::from("--parallel-ai"),
        OsString::from(args.parallel_ai.to_string()),
        OsString::from("--target-utilization"),
        OsString::from(args.target_utilization.to_string()),
        OsString::from("--min-free-gb"),
        OsString::from(args.min_free_gb.to_string()),
        OsString::from("--docker-cache-gb"),
        OsString::from(args.docker_cache_gb.to_string()),
        OsString::from("--docker-gc-every"),
        OsString::from(args.docker_gc_every.to_string()),
        OsString::from("--clone-timeout"),
        OsString::from(args.clone_timeout.to_string()),
        OsString::from("--static-timeout"),
        OsString::from(args.static_timeout.to_string()),
        OsString::from("--verify-startup-timeout"),
        OsString::from(args.verify_startup_timeout.to_string()),
        OsString::from("--verify-candidate-soft-timeout"),
        OsString::from(args.verify_candidate_soft_timeout.to_string()),
        OsString::from("--verify-candidate-hard-timeout"),
        OsString::from(args.verify_candidate_hard_timeout.to_string()),
        OsString::from("--verify-timeout"),
        OsString::from(args.verify_timeout.to_string()),
        OsString::from("--verify-extended-timeout"),
        OsString::from(args.verify_extended_timeout.to_string()),
        OsString::from("--satori-profile"),
        OsString::from(&args.satori_profile),
        OsString::from("--ai-attempts"),
        OsString::from("1"),
        OsString::from("--ai-model"),
        OsString::from("claude-opus-5-5"),
        OsString::from("--ai-timeout"),
        OsString::from(args.ai_timeout.to_string()),
    ];
    for (flag, value) in [
        ("--static-parallel", args.static_parallel),
        ("--max-checkouts", args.max_checkouts),
        ("--parallel-no-ai", args.parallel_no_ai),
        ("--parallel-docker", args.parallel_docker),
    ] {
        if let Some(value) = value {
            command.push(OsString::from(flag));
            command.push(OsString::from(value.to_string()));
        }
    }
    if args.no_governor {
        command.push(OsString::from("--no-governor"));
    }
    if args.estimate {
        command.push(OsString::from("--estimate"));
    }
    if args.calibrate {
        command.extend([
            OsString::from("--calibrate"),
            OsString::from("--calibrate-minutes"),
            OsString::from(args.calibrate_minutes.to_string()),
        ]);
    }
    if let Some(repositories) = &args.repos_file {
        command.push(OsString::from("--repos-file"));
        command.push(repositories.as_os_str().to_owned());
    }
    if online_publishes(args) {
        command.push(OsString::from("--satori-sync"));
    }
    if online_evolves(args) {
        command.extend([
            OsString::from("--fix-attempts"),
            OsString::from("1"),
            OsString::from("--fix-timeout"),
            OsString::from(args.fix_timeout.to_string()),
            OsString::from("--fix-model"),
            OsString::from("claude-opus-5-5"),
            OsString::from("--learn-fixes"),
        ]);
    }
    command
}

fn online(args: &OnlineArgs) -> ExitCode {
    let explicit_counts = [
        args.static_parallel,
        args.max_checkouts,
        args.parallel_no_ai,
        args.parallel_docker,
    ];
    if [args.parallel_ai, args.docker_cache_gb, args.docker_gc_every].contains(&0)
        || explicit_counts.contains(&Some(0))
        || args.calibrate_minutes == 0
    {
        return fail(EXIT_USAGE, "online worker counts must be positive");
    }
    let controller = match online_runner(args.runner.as_deref()) {
        Ok(controller) => controller,
        Err(error) => return fail(EXIT_ENGINE, error),
    };
    let scanner = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => return fail(EXIT_ENGINE, format!("locate jsspector binary: {error}")),
    };
    let mut command = ProcessCommand::new("python3");
    command
        .arg(&controller.runner)
        .args(online_arguments(args, &scanner));
    if online_evolves(args)
        && let Some(source_root) = self_heal_source_root()
        && self_heal_unavailable(Some(&source_root)).is_none()
    {
        command
            .env(
                "JSSPECTOR_FIX_RECIPES",
                source_root.join(".satori/fix-recipes"),
            )
            .env("JSSPECTOR_PUBLISH_FIXES", "1");
    }
    // An estimate is a short report, not a pass: print it plainly.
    let use_tui =
        !args.no_tui && !args.estimate && io::stdout().is_terminal() && io::stderr().is_terminal();
    if !use_tui && !args.estimate {
        let auto =
            |value: Option<usize>| value.map_or_else(|| "auto".to_owned(), |n| n.to_string());
        eprintln!(
            "jsspector: online {} since={} deterministic={} ai={} docker={} target={} satori={} evolve={}",
            if args.calibrate {
                "calibration"
            } else {
                "research"
            },
            args.since,
            auto(args.parallel_no_ai),
            if args.calibrate {
                "off".to_owned()
            } else {
                args.parallel_ai.to_string()
            },
            auto(args.parallel_docker),
            args.target_utilization,
            online_publishes(args),
            online_evolves(args),
        );
    }
    let status = if use_tui {
        online_ui::run(command)
    } else {
        online_ui::run_plain(command)
    };
    match status {
        Ok(status) => ExitCode::from(
            status
                .code()
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(EXIT_ENGINE),
        ),
        Err(error) => fail(EXIT_ENGINE, format!("start online controller: {error}")),
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
    match evolve_repository(&source_root, repository, !args.no_push) {
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
                recipes: private_fix_recipes(),
                learn: args.learn_fixes,
                publish: args.publish_fixes,
                allow_unpublished_recipes: true,
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

/// Exact exploit/fix examples are sensitive until disclosure. Keep them outside the public source
/// checkout, with an explicit override for isolated automation accounts.
fn private_fix_recipes() -> Option<PathBuf> {
    recipe_store_path(
        std::env::var_os("JSSPECTOR_FIX_RECIPES")
            .as_deref()
            .map(Path::new),
        std::env::var_os("XDG_DATA_HOME").as_deref().map(Path::new),
        std::env::var_os("HOME").as_deref().map(Path::new),
    )
}

fn recipe_store_path(
    explicit: Option<&Path>,
    data_home: Option<&Path>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    explicit
        .filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .or_else(|| data_home.map(|path| path.join("jsspector/fix-recipes")))
        .or_else(|| home.map(|path| path.join(".local/share/jsspector/fix-recipes")))
}

fn fail(code: u8, message: impl Display) -> ExitCode {
    let _ = writeln!(io::stderr(), "jsspector: {message}");
    ExitCode::from(code)
}
