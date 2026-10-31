//! The `jsspector parse` report: one deterministic JSON document (schema
//! [`SCHEMA`]). Only the optional `stats` object varies from run to run.

use std::collections::BTreeMap;
use std::time::Duration;

use jss_core::{ClassSet, Diagnostic, Discovery, FileClass, PackageType, SkipReason, diag};
use jss_frontend::{FileReport, FileStatus};
use serde::Serialize;

/// Schema identifier of the parse report. Bump the version on any breaking change.
pub const SCHEMA: &str = "jsspector.parse-report/1";

#[derive(Debug, Serialize)]
pub struct ParseReport<'a> {
    pub schema: &'static str,
    /// The root exactly as given on the command line.
    pub root: String,
    pub totals: Totals,
    /// Every diagnostic, sorted by path, code, message.
    pub diagnostics: Vec<Diagnostic>,
    /// One record per discovered file (with `--list`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<FileRecord<'a>>>,
    /// Timing and resource use (with `--stats`): the only non-deterministic part.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<Stats>,
}

#[derive(Debug, Default, Serialize)]
pub struct Totals {
    /// Discovered JS/TS files, whatever their class.
    pub files: usize,
    /// Discovered files per class (every class is present).
    pub by_class: BTreeMap<&'static str, usize>,
    /// Files whose class was selected for parsing. The rest were excluded by class.
    pub selected: usize,
    /// Parsed without syntax errors.
    pub parsed_ok: usize,
    /// Parsed, with syntax errors the parser recovered from.
    pub recovered: usize,
    /// The parser gave up.
    pub fatal: usize,
    /// The parser panicked (contained).
    pub panicked: usize,
    /// `skip/*` diagnostics per reason (every reason is present), from discovery and parsing.
    pub skipped_by_reason: BTreeMap<&'static str, usize>,
}

#[derive(Debug, Serialize)]
pub struct FileRecord<'a> {
    pub path: &'a str,
    pub class: FileClass,
    pub package_type: PackageType,
    pub size: u64,
    /// `parsed`, `recovered`, `fatal`, `panicked`, `skipped` or `excluded` (class not selected).
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<SkipReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statements: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syntax_errors: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct Stats {
    pub threads: usize,
    pub wall_ms: WallMs,
    /// Peak resident set size of the process; `null` where unavailable.
    pub peak_rss_bytes: Option<u64>,
    /// Selected files per second of the parse phase.
    pub files_per_sec: f64,
    /// Bytes of selected files per second of the parse phase.
    pub bytes_per_sec: f64,
}

#[derive(Debug, Serialize)]
pub struct WallMs {
    pub discover: f64,
    pub parse: f64,
    pub total: f64,
}

/// Builds the deterministic part of the report. `reports` holds one report per file of
/// `discovery.files` whose class is in `include`, in order.
pub fn build<'a>(
    root: String,
    discovery: &'a Discovery,
    include: ClassSet,
    reports: &'a [FileReport],
    list: bool,
) -> ParseReport<'a> {
    let mut remaining = reports.iter();
    let outcomes: Vec<Option<&FileReport>> = discovery
        .files
        .iter()
        .map(|file| {
            if include.contains(file.class) {
                remaining.next()
            } else {
                None
            }
        })
        .collect();

    let mut diagnostics: Vec<Diagnostic> = discovery
        .diagnostics
        .iter()
        .chain(reports.iter().flat_map(|report| &report.diagnostics))
        .cloned()
        .collect();
    diag::sort(&mut diagnostics);

    let mut totals = Totals {
        files: discovery.files.len(),
        by_class: FileClass::ALL
            .iter()
            .map(|class| (class.as_str(), 0))
            .collect(),
        selected: reports.len(),
        skipped_by_reason: SkipReason::ALL
            .iter()
            .map(|reason| (reason.as_str(), 0))
            .collect(),
        ..Totals::default()
    };
    for file in &discovery.files {
        *totals.by_class.entry(file.class.as_str()).or_insert(0) += 1;
    }
    for diagnostic in &diagnostics {
        if let Some(reason) = diagnostic.code.skip_reason() {
            *totals.skipped_by_reason.entry(reason.as_str()).or_insert(0) += 1;
        }
    }
    for report in reports {
        match report.status {
            FileStatus::Parsed {
                recovered: false, ..
            } => totals.parsed_ok += 1,
            FileStatus::Parsed {
                recovered: true, ..
            } => totals.recovered += 1,
            FileStatus::Fatal => totals.fatal += 1,
            FileStatus::Panicked => totals.panicked += 1,
            FileStatus::Skipped(_) => {}
        }
    }

    let files = list.then(|| {
        discovery
            .files
            .iter()
            .zip(&outcomes)
            .map(|(file, outcome)| {
                let mut record = FileRecord {
                    path: &file.rel_path,
                    class: file.class,
                    package_type: file.package_type,
                    size: file.size,
                    status: "excluded",
                    reason: None,
                    statements: None,
                    syntax_errors: None,
                };
                if let Some(report) = outcome {
                    match report.status {
                        FileStatus::Parsed {
                            statements,
                            syntax_errors,
                            recovered,
                        } => {
                            record.status = if recovered { "recovered" } else { "parsed" };
                            record.statements = Some(statements);
                            record.syntax_errors = Some(syntax_errors);
                        }
                        FileStatus::Fatal => record.status = "fatal",
                        FileStatus::Panicked => record.status = "panicked",
                        FileStatus::Skipped(reason) => {
                            record.status = "skipped";
                            record.reason = Some(reason);
                        }
                    }
                }
                record
            })
            .collect()
    });

    ParseReport {
        schema: SCHEMA,
        root,
        totals,
        diagnostics,
        files,
        stats: None,
    }
}

/// Builds the `stats` object.
pub fn stats(
    threads: usize,
    discover: Duration,
    parse: Duration,
    total: Duration,
    files: usize,
    bytes: u64,
) -> Stats {
    let parse_secs = parse.as_secs_f64();
    let per_sec = |count: f64| {
        if parse_secs > 0.0 {
            round3(count / parse_secs)
        } else {
            0.0
        }
    };
    Stats {
        threads,
        wall_ms: WallMs {
            discover: millis(discover),
            parse: millis(parse),
            total: millis(total),
        },
        peak_rss_bytes: peak_rss_bytes(),
        // Counts far beyond 2^53 lose precision, which is fine for a rate.
        files_per_sec: per_sec(files as f64),
        bytes_per_sec: per_sec(bytes as f64),
    }
}

fn millis(duration: Duration) -> f64 {
    round3(duration.as_secs_f64() * 1000.0)
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

/// Peak resident set size, from `getrusage(RUSAGE_SELF)`. `ru_maxrss` is in bytes on Apple
/// platforms and in KiB on Linux and the BSDs.
#[cfg(unix)]
fn peak_rss_bytes() -> Option<u64> {
    use nix::sys::resource::{UsageWho, getrusage};

    let max_rss = u64::try_from(getrusage(UsageWho::RUSAGE_SELF).ok()?.max_rss()).ok()?;
    if cfg!(target_vendor = "apple") {
        Some(max_rss)
    } else {
        max_rss.checked_mul(1024)
    }
}

#[cfg(not(unix))]
fn peak_rss_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_handle_a_zero_duration() {
        let stats = stats(2, Duration::ZERO, Duration::ZERO, Duration::ZERO, 10, 100);
        assert_eq!(stats.files_per_sec, 0.0);
        assert_eq!(stats.bytes_per_sec, 0.0);
        let stats = stats_for(Duration::from_millis(500));
        assert_eq!(stats.files_per_sec, 20.0);
        assert_eq!(stats.bytes_per_sec, 200.0);
        assert_eq!(stats.wall_ms.parse, 500.0);
    }

    fn stats_for(parse: Duration) -> Stats {
        stats(1, Duration::from_micros(1500), parse, parse, 10, 100)
    }

    #[cfg(unix)]
    #[test]
    fn peak_rss_is_plausible() {
        let rss = peak_rss_bytes().unwrap();
        assert!(rss > 1024 * 1024, "{rss}");
        assert!(rss < 64 * 1024 * 1024 * 1024, "{rss}");
    }
}
