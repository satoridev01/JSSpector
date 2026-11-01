//! `jsspector` command-line interface.

mod report;

use std::fmt::Display;
use std::io::{self, BufWriter, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Args, Parser, Subcommand};
use jss_core::{
    ClassSet, DiscoverError, DiscoverOptions, FileClass, Finding, PackageType, Severity,
};
use jss_frontend::{ParsePool, ScanStatus};
use serde::Serialize;

/// Exit codes, as defined in `docs/PLAN.md`: 0 = clean, 1 = findings at or above `--fail-on`
/// (once scanning exists), 2 = usage error, 3 = engine error (including IO errors on the root).
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
    /// Scan a file or directory for tainted data reaching dangerous sinks (v0 spike).
    ///
    /// Single-file, intra-procedural, heuristic: every finding is a candidate for hand triage.
    /// Prints deterministic JSON (byte-identical for any number of threads).
    Scan(ScanArgs),
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
    /// Report only findings at or above this severity: critical, high, medium or low.
    #[arg(long, value_name = "SEVERITY", default_value = "high", value_parser = parse_severity)]
    min_severity: Severity,
    /// Print the full JSON report instead of the readable list.
    #[arg(long)]
    json: bool,
}

fn parse_severity(value: &str) -> Result<Severity, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        _ => Err(format!("unknown severity `{value}`")),
    }
}

/// The `scan` report.
#[derive(Serialize)]
struct ScanOutput {
    root: String,
    files_scanned: usize,
    findings: Vec<Finding>,
    /// Files not analyzed, with the reason; sorted by path.
    skipped: Vec<FileNote>,
    /// Files where the walker hit its depth cap.
    truncated: Vec<String>,
}

#[derive(Serialize)]
struct FileNote {
    file: String,
    reason: String,
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
    }
}

fn scan(args: &ScanArgs) -> ExitCode {
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
    let selection = discovery.selection(include_set(&args.include));
    let reports = pool.scan(&discovery.files, selection);
    let mut output = ScanOutput {
        root: args.path.to_string_lossy().into_owned(),
        files_scanned: 0,
        findings: Vec::new(),
        skipped: Vec::new(),
        truncated: Vec::new(),
    };
    for report in reports {
        match report.status {
            ScanStatus::Scanned => output.files_scanned += 1,
            ScanStatus::Skipped(reason) => output.skipped.push(FileNote {
                file: report.rel_path.clone(),
                reason,
            }),
            ScanStatus::Panicked(panic) => output.skipped.push(FileNote {
                file: report.rel_path.clone(),
                reason: format!("panicked: {panic}"),
            }),
        }
        if report.truncated {
            output.truncated.push(report.rel_path.clone());
        }
        output.findings.extend(
            report
                .findings
                .into_iter()
                .filter(|f| f.severity <= args.min_severity),
        );
    }
    jss_frontend::finalize(&mut output.findings);
    let mut out = BufWriter::new(io::stdout().lock());
    let written = if args.json {
        serde_json::to_writer_pretty(&mut out, &output)
            .map_err(io::Error::from)
            .and_then(|()| writeln!(out))
    } else {
        write_text(&mut out, &output, &discovery.root)
    }
    .and_then(|()| out.flush());
    if let Err(err) = written {
        return fail(EXIT_ENGINE, format!("cannot write the report: {err}"));
    }
    ExitCode::SUCCESS
}

/// ANSI styles, empty when stdout is not a terminal.
struct Style {
    bold: &'static str,
    dim: &'static str,
    red: &'static str,
    yellow: &'static str,
    reset: &'static str,
}

impl Style {
    fn new(color: bool) -> Self {
        if color {
            Style {
                bold: "\x1b[1m",
                dim: "\x1b[2m",
                red: "\x1b[31m",
                yellow: "\x1b[33m",
                reset: "\x1b[0m",
            }
        } else {
            Style {
                bold: "",
                dim: "",
                red: "",
                yellow: "",
                reset: "",
            }
        }
    }
}

/// One line of a file under `root` (1-based), trimmed; empty when unreadable.
fn source_line(root: &std::path::Path, file: &str, line: u32) -> String {
    std::fs::read_to_string(root.join(file))
        .ok()
        .and_then(|text| {
            text.lines()
                .nth(usize::try_from(line).unwrap_or(1).saturating_sub(1))
                .map(|l| {
                    let l = l.trim();
                    if l.chars().count() > 140 {
                        let mut cut: String = l.chars().take(137).collect();
                        cut.push_str("...");
                        cut
                    } else {
                        l.to_owned()
                    }
                })
        })
        .unwrap_or_default()
}

/// A plain-language description of a vulnerability class.
fn describe(class: jss_core::VulnClass) -> &'static str {
    use jss_core::VulnClass as C;
    match class {
        C::CommandInjection => "reaches a shell command or program execution",
        C::CodeInjection => "is evaluated as code",
        C::SqlInjection => "is concatenated into an SQL query",
        C::PathTraversal => "is used as a file path without confinement",
        C::Ssrf => "controls the URL of a server-side request",
        C::Xss => "is written into the page as HTML",
        C::PrototypePollution => "chooses both keys of a nested object write",
    }
}

/// Semgrep-style output: findings grouped by the file of their sink, with the code lines.
fn write_text(out: &mut impl Write, output: &ScanOutput, root: &std::path::Path) -> io::Result<()> {
    use std::io::IsTerminal;
    let st = Style::new(io::stdout().is_terminal());
    let mut by_file: std::collections::BTreeMap<&str, Vec<&Finding>> = Default::default();
    for f in &output.findings {
        by_file
            .entry(f.sink.file.as_deref().unwrap_or(&f.file))
            .or_default()
            .push(f);
    }
    for (file, findings) in &by_file {
        writeln!(out, "\n  {}{file}{}", st.bold, st.reset)?;
        for f in findings {
            let severity = serde_json::to_value(f.severity)
                .ok()
                .and_then(|v| v.as_str().map(str::to_uppercase))
                .unwrap_or_default();
            let color = if severity == "CRITICAL" {
                st.red
            } else {
                st.yellow
            };
            writeln!(
                out,
                "  {color}{}❯❯❱ jsspector.{}{} {}[{severity}]{}",
                st.bold,
                f.class.name(),
                st.reset,
                color,
                st.reset
            )?;
            writeln!(
                out,
                "          Data from `{}` ({}) {}.",
                f.source.expr,
                f.source.kind,
                describe(f.class)
            )?;
            writeln!(
                out,
                "          {}in {}, auth: {}{}",
                st.dim, f.function, f.auth, st.reset
            )?;
            writeln!(out)?;
            let sink_code = source_line(root, file, f.sink.line);
            writeln!(out, "  {:>8}┆ {}", f.sink.line, sink_code)?;
            if f.sink.file.is_some() || f.source.line != f.sink.line {
                let source_code = source_line(root, &f.file, f.source.line);
                writeln!(
                    out,
                    "          {}↳ source: {}:{}{}",
                    st.dim, f.file, f.source.line, st.reset
                )?;
                writeln!(out, "  {:>8}┆ {}", f.source.line, source_code)?;
                // Each step from the source to the sink, with its code line.
                let mut last = (f.file.clone(), f.source.line);
                for step in &f.trace {
                    // Steps in another file come as `file:line: note`.
                    let (file, line, note) = if step.line == 0 {
                        let mut parts = step.note.splitn(3, ':');
                        match (
                            parts.next(),
                            parts.next().and_then(|l| l.parse().ok()),
                            parts.next(),
                        ) {
                            (Some(file), Some(line), Some(note)) => {
                                (file.to_owned(), line, note.trim().to_owned())
                            }
                            _ => continue,
                        }
                    } else {
                        (f.file.clone(), step.line, step.note.clone())
                    };
                    if (file.clone(), line) == last {
                        continue;
                    }
                    writeln!(
                        out,
                        "          {}↳ {note}: {file}:{line}{}",
                        st.dim, st.reset
                    )?;
                    writeln!(out, "  {:>8}┆ {}", line, source_line(root, &file, line))?;
                    last = (file, line);
                }
            }
            writeln!(out, "          ⋮┆----------------------------------------")?;
        }
    }
    writeln!(
        out,
        "\n{}{} finding(s){} in {} file(s) scanned ({} skipped)",
        st.bold,
        output.findings.len(),
        st.reset,
        output.files_scanned,
        output.skipped.len()
    )
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
