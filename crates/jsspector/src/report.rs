//! The `jsspector parse` report: one deterministic JSON document (schema
//! [`SCHEMA`]). Only the optional `stats` object varies from run to run.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use jss_core::{ClassSet, Diagnostic, Discovery, FileClass, PackageType, SkipReason, diag};
use jss_frontend::{FileReport, FileStatus};
use serde::ser::{Serialize, SerializeStruct, Serializer};

/// Schema identifier of the parse report. Bump the version on any breaking change.
pub const SCHEMA: &str = "jsspector.parse-report/1";

#[derive(Debug, serde::Serialize)]
pub struct ParseReport<'a> {
    pub schema: &'static str,
    /// The root exactly as given on the command line.
    pub root: String,
    /// The classes selected for parsing.
    pub selection: Vec<FileClass>,
    pub totals: Totals,
    /// Every diagnostic, sorted by path, code, message.
    pub diagnostics: Vec<Diagnostic>,
    /// One record per discovered file (with `--list`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<FileRecord<'a>>>,
    /// Timing and resource use (with `--stats`): the only non-deterministic part, and always
    /// the last field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<Stats>,
}

/// Counts over the run. For the selected files,
/// `selected == parsed_ok + recovered + fatal + panicked + skipped`.
#[derive(Debug, Default, serde::Serialize)]
pub struct Totals {
    /// Discovered JS/TS files, whatever their class.
    pub files: usize,
    /// Discovered files per final class (every class is present). Independent of the selection.
    pub by_class: BTreeMap<&'static str, usize>,
    /// TypeScript declaration files seen and not listed (they hold no executable code).
    pub declaration_files: usize,
    /// Files whose class is selected. The others were excluded by class.
    pub selected: usize,
    /// Parsed without syntax errors.
    pub parsed_ok: usize,
    /// Parsed, with syntax errors the parser recovered from.
    pub recovered: usize,
    /// The parser gave up.
    pub fatal: usize,
    /// The parser panicked (contained).
    pub panicked: usize,
    /// Selected files that were not parsed.
    pub skipped: usize,
    /// `skipped` per reason (every reason is present).
    pub skipped_by_reason: BTreeMap<&'static str, usize>,
    /// Selected files that are Flow-typed JavaScript, parsed with TypeScript syntax or fatal.
    pub flow: usize,
    /// `skip/*` diagnostics for everything else (every reason is present): entries discovery
    /// could not list (symlinks leaving the root, unreadable entries) and unselected files
    /// that could not be read to classify them.
    pub discovery_skips_by_reason: BTreeMap<&'static str, usize>,
}

#[derive(Debug, serde::Serialize)]
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
    /// Flow-typed JavaScript (see `totals.flow`).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub flow: bool,
}

/// Builds the deterministic part of the report. `reports` holds one report per file of
/// `discovery.files`, in order, processed with `selection`.
pub fn build<'a>(
    root: String,
    discovery: &'a Discovery,
    selection: ClassSet,
    reports: &'a [FileReport],
    list: bool,
) -> ParseReport<'a> {
    let mut diagnostics: Vec<Diagnostic> = discovery
        .diagnostics
        .iter()
        .chain(reports.iter().flat_map(|report| &report.diagnostics))
        .cloned()
        .collect();
    diag::sort(&mut diagnostics);

    let per_reason = || {
        SkipReason::ALL
            .iter()
            .map(|reason| (reason.as_str(), 0))
            .collect::<BTreeMap<_, _>>()
    };
    let mut totals = Totals {
        files: discovery.files.len(),
        by_class: FileClass::ALL
            .iter()
            .map(|class| (class.as_str(), 0))
            .collect(),
        declaration_files: discovery.declaration_files,
        skipped_by_reason: per_reason(),
        discovery_skips_by_reason: per_reason(),
        ..Totals::default()
    };
    let count = |map: &mut BTreeMap<&'static str, usize>, reason: SkipReason| {
        *map.entry(reason.as_str()).or_insert(0) += 1;
    };
    for diagnostic in &discovery.diagnostics {
        if let Some(reason) = diagnostic.code.skip_reason() {
            count(&mut totals.discovery_skips_by_reason, reason);
        }
    }
    for report in reports {
        *totals.by_class.entry(report.class.as_str()).or_insert(0) += 1;
        // An exclusion never has a selected class; were it to, it would still not count as one.
        if !selection.contains(report.class) || report.status == FileStatus::Excluded {
            if let FileStatus::Skipped(reason) = report.status {
                count(&mut totals.discovery_skips_by_reason, reason);
            }
            continue;
        }
        totals.selected += 1;
        totals.flow += usize::from(report.flow);
        match report.status {
            FileStatus::Parsed {
                recovered: false, ..
            } => totals.parsed_ok += 1,
            FileStatus::Parsed {
                recovered: true, ..
            } => totals.recovered += 1,
            FileStatus::Fatal => totals.fatal += 1,
            FileStatus::Panicked => totals.panicked += 1,
            FileStatus::Skipped(reason) => {
                totals.skipped += 1;
                count(&mut totals.skipped_by_reason, reason);
            }
            FileStatus::Excluded => {}
        }
    }

    let files = list.then(|| {
        discovery
            .files
            .iter()
            .zip(reports)
            .map(|(file, report)| {
                let mut record = FileRecord {
                    path: &file.rel_path,
                    class: report.class,
                    package_type: file.package_type,
                    size: file.size,
                    status: "excluded",
                    reason: None,
                    statements: None,
                    syntax_errors: None,
                    flow: report.flow,
                };
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
                    FileStatus::Excluded => {}
                }
                record
            })
            .collect()
    });

    ParseReport {
        schema: SCHEMA,
        root,
        selection: selection.iter().collect(),
        totals,
        diagnostics,
        files,
        stats: None,
    }
}

/// The `stats` object. Total wall time and peak memory are sampled when it is serialized, which
/// happens last, so they cover the whole run, writing the report included.
#[derive(Debug)]
pub struct Stats {
    pub threads: usize,
    pub started: Instant,
    pub discover: Duration,
    pub parse: Duration,
    /// Files that reached the parser.
    pub parsed_files: usize,
    /// Bytes handed to the parser.
    pub parsed_bytes: u64,
}

impl Stats {
    /// Builds the stats for a run, counting what reached the parser in `reports`.
    pub fn new(
        threads: usize,
        started: Instant,
        discover: Duration,
        parse: Duration,
        reports: &[FileReport],
    ) -> Self {
        let reached_parser = |report: &&FileReport| {
            matches!(
                report.status,
                FileStatus::Parsed { .. }
                    | FileStatus::Fatal
                    | FileStatus::Panicked
                    | FileStatus::Skipped(SkipReason::Template)
            )
        };
        Stats {
            threads,
            started,
            discover,
            parse,
            parsed_files: reports.iter().filter(reached_parser).count(),
            parsed_bytes: reports
                .iter()
                .map(|report| report.parsed_bytes)
                .fold(0, u64::saturating_add),
        }
    }
}

impl Serialize for Stats {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (files_per_sec, bytes_per_sec) =
            rates(self.parse, self.parsed_files, self.parsed_bytes);
        let mut stats = serializer.serialize_struct("Stats", 5)?;
        stats.serialize_field("threads", &self.threads)?;
        stats.serialize_field(
            "wall_ms",
            &WallMs {
                discover: millis(self.discover),
                parse: millis(self.parse),
                total: millis(self.started.elapsed()),
            },
        )?;
        // Peak resident set size of the process; `null` where unavailable.
        stats.serialize_field("peak_rss_bytes", &peak_rss_bytes())?;
        // Files and bytes that reached the parser, per second of the parse phase (which also
        // reads and classifies the files that are not parsed).
        stats.serialize_field("files_per_sec", &files_per_sec)?;
        stats.serialize_field("bytes_per_sec", &bytes_per_sec)?;
        stats.end()
    }
}

#[derive(Debug, serde::Serialize)]
struct WallMs {
    discover: f64,
    parse: f64,
    total: f64,
}

/// Files and bytes per second of `parse`; 0 for an empty duration.
fn rates(parse: Duration, files: usize, bytes: u64) -> (f64, f64) {
    let secs = parse.as_secs_f64();
    let per_sec = |count: f64| {
        if secs > 0.0 {
            round3(count / secs)
        } else {
            0.0
        }
    };
    // Counts far beyond 2^53 lose precision, which is fine for a rate.
    (per_sec(files as f64), per_sec(bytes as f64))
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
    use jss_core::{DiagCode, SourceFile, SourceKind};

    #[test]
    fn rates_handle_a_zero_duration() {
        assert_eq!(rates(Duration::ZERO, 10, 100), (0.0, 0.0));
        assert_eq!(rates(Duration::from_millis(500), 10, 100), (20.0, 200.0));
    }

    fn file(rel: &str, path_class: FileClass) -> SourceFile {
        SourceFile {
            rel_path: rel.to_owned(),
            rel_path_os: rel.into(),
            abs_path: format!("/r/{rel}").into(),
            kind: SourceKind::Js,
            path_class,
            package_type: PackageType::CommonJs,
            size: 10,
        }
    }

    fn report(rel: &str, class: FileClass, status: FileStatus, flow: bool) -> FileReport {
        let diagnostics = match status {
            FileStatus::Skipped(reason) => vec![Diagnostic::at(reason.code(), rel, "x")],
            FileStatus::Panicked => vec![Diagnostic::at(DiagCode::ParsePanicked, rel, "boom")],
            FileStatus::Fatal => vec![Diagnostic::at(DiagCode::ParseFatal, rel, "bad")],
            _ => Vec::new(),
        };
        let parsed_bytes = if matches!(
            status,
            FileStatus::Parsed { .. } | FileStatus::Fatal | FileStatus::Panicked
        ) {
            10
        } else {
            0
        };
        FileReport {
            rel_path: rel.to_owned(),
            class,
            status,
            flow,
            parsed_bytes,
            diagnostics,
        }
    }

    const OK: FileStatus = FileStatus::Parsed {
        statements: 1,
        syntax_errors: 0,
        recovered: false,
    };

    #[test]
    fn totals_add_up_and_split_skips_by_phase() {
        let files = [
            file("a.js", FileClass::Source),
            file("boom.js", FileClass::Source),
            file("flow.js", FileClass::Source),
            file("gen.js", FileClass::Source),
            file("huge.js", FileClass::Source),
            file("t.test.js", FileClass::Test),
            file("v.js", FileClass::Vendor),
        ];
        let reports = vec![
            report("a.js", FileClass::Source, OK, false),
            report("boom.js", FileClass::Source, FileStatus::Panicked, false),
            report("flow.js", FileClass::Source, FileStatus::Fatal, true),
            report("gen.js", FileClass::Generated, FileStatus::Excluded, false),
            report(
                "huge.js",
                FileClass::Source,
                FileStatus::Skipped(SkipReason::TooLarge),
                false,
            ),
            // Unselected and unreadable: a discovery-phase skip, not a skipped selected file.
            report(
                "t.test.js",
                FileClass::Test,
                FileStatus::Skipped(SkipReason::IoError),
                false,
            ),
            report("v.js", FileClass::Vendor, FileStatus::Excluded, false),
        ];
        let discovery = Discovery {
            root: "/r".into(),
            single_file: false,
            files: files.to_vec(),
            diagnostics: vec![Diagnostic::at(
                DiagCode::SkipSymlinkOutsideRoot,
                "escape.js",
                "out",
            )],
            declaration_files: 2,
        };
        let parse_report = build(
            "r".to_owned(),
            &discovery,
            ClassSet::default(),
            &reports,
            true,
        );
        let totals = &parse_report.totals;
        assert_eq!(totals.files, 7);
        assert_eq!(totals.declaration_files, 2);
        assert_eq!(totals.by_class["source"], 4);
        assert_eq!(totals.by_class["generated"], 1);
        assert_eq!(totals.selected, 4);
        assert_eq!(
            totals.selected,
            totals.parsed_ok + totals.recovered + totals.fatal + totals.panicked + totals.skipped
        );
        assert_eq!(
            (
                totals.parsed_ok,
                totals.fatal,
                totals.panicked,
                totals.skipped
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(totals.flow, 1);
        assert_eq!(totals.skipped_by_reason["too-large"], 1);
        assert_eq!(totals.skipped_by_reason.values().sum::<usize>(), 1);
        assert_eq!(totals.discovery_skips_by_reason["io-error"], 1);
        assert_eq!(totals.discovery_skips_by_reason["symlink-outside-root"], 1);
        assert_eq!(parse_report.diagnostics.len(), 5);

        let records = parse_report.files.as_ref().unwrap();
        let status = |path: &str| {
            let record = records.iter().find(|r| r.path == path).unwrap();
            (record.status, record.class, record.flow)
        };
        assert_eq!(status("boom.js"), ("panicked", FileClass::Source, false));
        assert_eq!(status("flow.js"), ("fatal", FileClass::Source, true));
        assert_eq!(status("gen.js"), ("excluded", FileClass::Generated, false));
        assert_eq!(status("t.test.js"), ("skipped", FileClass::Test, false));

        let stats = Stats::new(
            1,
            Instant::now(),
            Duration::ZERO,
            Duration::from_secs(1),
            &reports,
        );
        // Only the three files that reached the parser count, not the oversized one.
        assert_eq!((stats.parsed_files, stats.parsed_bytes), (3, 30));
        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["files_per_sec"], 3.0);
        assert_eq!(json["bytes_per_sec"], 30.0);
    }

    #[cfg(unix)]
    #[test]
    fn peak_rss_is_plausible() {
        let rss = peak_rss_bytes().unwrap();
        assert!(rss > 1024 * 1024, "{rss}");
        assert!(rss < 64 * 1024 * 1024 * 1024, "{rss}");
    }
}
