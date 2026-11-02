//! `jsspector` command-line interface.

mod baseline;
mod config;
mod excerpt;
mod explain;
mod openapi;
mod report;
mod rules;
mod sarif;
mod text;
mod verify;

use std::fmt::Display;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
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
    /// from `.jsspector.yml` in the scanned directory (command-line options win). Output is
    /// deterministic: the same tree gives the same report for any number of threads.
    Scan(ScanArgs),
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
    /// Read settings from FILE instead of `.jsspector.yml` in the scanned directory.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Ignore `.jsspector.yml`.
    #[arg(long, conflicts_with = "config")]
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
    path: PathBuf,
    /// Number of threads [default: all available cores, or RAYON_NUM_THREADS].
    #[arg(long, value_name = "N")]
    threads: Option<NonZeroUsize>,
    /// Also scan these file classes (source files always are). Comma-separated.
    #[arg(long, value_name = "CLASSES", value_delimiter = ',', value_parser = parse_include)]
    include: Vec<Include>,
    /// Do not scan paths matching GLOB (relative to the root; like `.gitignore`). Repeatable.
    #[arg(long, value_name = "GLOB")]
    exclude: Vec<String>,
    /// Report only findings at or above this severity: critical, high, medium or low
    /// [default: high].
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
    /// Do not report findings recorded in FILE (see --write-baseline).
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Record the findings reported now in FILE, to accept them as a baseline.
    #[arg(long, value_name = "FILE")]
    write_baseline: Option<PathBuf>,
    /// Confirm each reported finding by running the app in a throwaway Docker container and
    /// sending the request it implies (opt-in; needs a running Docker daemon). `--verify=strict`
    /// fails the command when Docker is unreachable instead of skipping.
    #[arg(long, value_name = "MODE", num_args = 0..=1, default_missing_value = "best-effort")]
    verify: Option<VerifyMode>,
    #[command(flatten)]
    config: ConfigArgs,
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
    files_scanned: usize,
    findings: Vec<ReportedFinding<'a>>,
    /// Findings left out because they are in the baseline.
    baselined: usize,
    /// Findings left out by `jsspector-ignore` comments.
    ignored: usize,
    /// Files not analyzed, with the reason; sorted by path.
    skipped: &'a [FileNote],
    /// Files where the walker hit its depth cap.
    truncated: &'a [String],
    /// `--verify` verdicts, one per reported finding; empty when `--verify` was not given.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    verification: &'a [verify::Verdict],
}

/// A finding as `scan --json` prints it: a title first, the finding, then the fields issue
/// trackers read (Satori's `title`, `resource`, `description`, `remediation`).
#[derive(Serialize)]
struct ReportedFinding<'a> {
    title: String,
    cwe: String,
    #[serde(flatten)]
    finding: &'a Finding,
    resource: String,
    description: String,
    /// The lines the value passes through, entry point to sink, as annotated Markdown code
    /// blocks (one per file).
    affected: String,
    remediation: String,
}

impl<'a> ReportedFinding<'a> {
    fn new(finding: &'a Finding, sources: &mut text::Sources) -> Self {
        Self {
            title: rules::title(finding),
            cwe: format!("CWE-{}", rules::rule(finding.class).cwe),
            finding,
            resource: rules::resource(finding),
            description: rules::description(finding),
            affected: excerpt::affected(finding, sources),
            remediation: rules::remediation(finding.class),
        }
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
        Command::Routes(args) => routes(&args),
        Command::Explain(args) => explain(&args),
        Command::Ir(args) => ir(&args),
    }
}

/// Reads the settings for scanning `path` and installs their packs (before any analysis).
fn setup(path: &Path, args: &ConfigArgs) -> Result<config::Loaded, ExitCode> {
    let loaded = config::Loaded::load(path, args.config.as_deref(), args.no_config)
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
    jss_frontend::attach_entries(&mut reports);
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

fn scan(args: &ScanArgs) -> ExitCode {
    let started = Instant::now();
    let loaded = match setup(&args.path, &args.config) {
        Ok(loaded) => loaded,
        Err(code) => return code,
    };
    let settings = (|| -> Result<_, String> {
        let min_severity = args
            .min_severity
            .or(loaded.min_severity()?)
            .unwrap_or(Severity::High);
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
    let analysis = match analyze(&args.path, args.threads, include, &excludes) {
        Ok(analysis) => analysis,
        Err(code) => return code,
    };

    let mut sources = text::Sources::new(&analysis.root);
    let mut ignored = 0;
    let reported: Vec<Finding> = analysis
        .findings
        .into_iter()
        .filter(|f| f.severity <= min_severity && !disabled.contains(&f.class))
        .filter(|f| {
            let silenced = sources.ignores(f);
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
        Some(mode) => {
            let missing = match mode {
                VerifyMode::Strict => verify::Missing::Fail,
                VerifyMode::BestEffort => verify::Missing::Skip,
            };
            match verify::run(&analysis.root, &findings, missing) {
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
            let output = ScanOutput {
                root: args.path.to_string_lossy().into_owned(),
                files_scanned: analysis.files_scanned,
                findings: findings
                    .iter()
                    .map(|f| ReportedFinding::new(f, &mut sources))
                    .collect(),
                baselined: baselined.len(),
                ignored,
                skipped: &analysis.skipped,
                truncated: &analysis.truncated,
                verification: &verification,
            };
            serde_json::to_writer_pretty(&mut *out, &output)
                .map_err(io::Error::from)
                .and_then(|()| writeln!(out))
        }
        Format::Sarif => {
            let notes: Vec<sarif::Note<'_>> = analysis
                .skipped
                .iter()
                .map(|note| sarif::Note {
                    file: &note.file,
                    reason: &note.reason,
                    error: note.panicked,
                })
                .collect();
            let verified: std::collections::BTreeMap<String, &str> = verification
                .iter()
                .map(|v| (v.fingerprint.clone(), v.outcome.label()))
                .collect();
            let log = sarif::document(
                &analysis.root,
                &findings,
                &notes,
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
        Some(path) => {
            let mut out = BufWriter::new(std::fs::File::create(path)?);
            write(&mut out, false)?;
            out.flush()
        }
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
    let routes = jss_frontend::inventory(&reports);
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
fn fail(code: u8, message: impl Display) -> ExitCode {
    let _ = writeln!(io::stderr(), "jsspector: {message}");
    ExitCode::from(code)
}
