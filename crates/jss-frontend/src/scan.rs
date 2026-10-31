//! `scan` v0 driver: parse each selected file and run the taint spike on it, under the same
//! stack and panic discipline as parsing (see `process`).

use jss_core::content;
use jss_core::{
    ClassSet, Finding, LineIndex, SinkLoc, SourceFile, SourceLoc, TraceStep, Work, classify,
};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::Span;
use rayon::prelude::*;

use crate::parse::{parse_options, source_type, typed_fallbacks};
use crate::process::{
    ParseFailure, ParsePool, guarded, on_parser_stack, read_capped, template_tag,
};
use crate::taint::{self, RawFinding};

/// What happened to one scanned file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus {
    Scanned,
    /// Not analyzed: the reason (too large, not UTF-8, template, fatal syntax error, ...).
    Skipped(String),
    /// The parser or the walker panicked (contained).
    Panicked(String),
}

/// The scan of one file.
#[derive(Debug, Clone)]
pub struct ScanReport {
    pub rel_path: String,
    pub status: ScanStatus,
    /// The walker hit its depth cap somewhere in the file.
    pub truncated: bool,
    pub findings: Vec<Finding>,
}

impl ParsePool {
    /// Scans every file of a class in `selection`, in parallel. Reports come back in input
    /// order; files that are not scanned have no report.
    pub fn scan(&self, files: &[SourceFile], selection: ClassSet) -> Vec<ScanReport> {
        self.install(|| {
            files
                .par_iter()
                .filter_map(|file| match guarded(|| scan_file(file, selection)) {
                    Ok(report) => report,
                    Err(panic) => Some(report(file, ScanStatus::Panicked(panic))),
                })
                .collect()
        })
    }
}

fn report(file: &SourceFile, status: ScanStatus) -> ScanReport {
    ScanReport {
        rel_path: file.rel_path.clone(),
        status,
        truncated: false,
        findings: Vec::new(),
    }
}

fn scan_file(file: &SourceFile, selection: ClassSet) -> Option<ScanReport> {
    if !matches!(file.work(selection), Work::Parse) {
        return None;
    }
    if let Err(skip) = content::check_size(file.size) {
        return Some(report(file, ScanStatus::Skipped(skip.message)));
    }
    let bytes = match read_capped(&file.abs_path, file.size) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Some(report(
                file,
                ScanStatus::Skipped(format!("unreadable: {err}")),
            ));
        }
    };
    if !selection.contains(classify::with_header(file.path_class, &bytes)) {
        return None;
    }
    let text = match content::check(&bytes) {
        Ok(text) => text,
        Err(skip) => return Some(report(file, ScanStatus::Skipped(skip.message))),
    };
    let outcome = on_parser_stack(text, |allocator| scan_text(allocator, file, text));
    Some(match outcome {
        Ok(Ok((findings, truncated))) => ScanReport {
            rel_path: file.rel_path.clone(),
            status: ScanStatus::Scanned,
            truncated,
            findings,
        },
        Ok(Err(reason)) => report(file, ScanStatus::Skipped(reason)),
        Err(ParseFailure::Panicked(panic)) => report(file, ScanStatus::Panicked(panic)),
        Err(ParseFailure::NoStack { bytes, error }) => report(
            file,
            ScanStatus::Skipped(format!("no {bytes}-byte parser stack: {error}")),
        ),
    })
}

/// Parses `text` (as its kind, then as TypeScript for Flow-ish JavaScript; the Flow eraser is
/// not used in v0) and walks the first program that parsed.
fn scan_text(
    allocator: &Allocator,
    file: &SourceFile,
    text: &str,
) -> Result<(Vec<Finding>, bool), String> {
    let primary = source_type(file.kind, file.package_type);
    let mut candidates = vec![primary];
    if let Some(fallbacks) = typed_fallbacks(file.kind, file.package_type) {
        candidates.extend(fallbacks);
    }
    let mut first_error = None;
    for (attempt, source_type) in candidates.into_iter().enumerate() {
        let ret = Parser::new(allocator, text, source_type)
            .with_options(parse_options())
            .parse();
        if ret.fatal_error {
            if attempt == 0 {
                let outcome = crate::parse::ParseOutcome {
                    statements: 0,
                    syntax_errors: ret.diagnostics.len(),
                    fatal: true,
                    flow: ret.is_flow_language,
                    first_error: ret.diagnostics.first().map(|e| crate::parse::SyntaxError {
                        message: e.message.to_string(),
                        offset: e
                            .labels
                            .iter()
                            .find(|l| l.primary())
                            .or_else(|| e.labels.first())
                            .map(|l| l.offset()),
                    }),
                };
                if let Some(message) = template_tag(text, &outcome) {
                    return Err(format!("template: {message}"));
                }
                first_error = outcome.first_error.map(|e| e.message);
            }
            continue;
        }
        let result = taint::scan_program(&ret.program, text);
        let index = LineIndex::new(text);
        let findings = result
            .findings
            .iter()
            .map(|raw| to_finding(raw, &file.rel_path, text, &index))
            .collect();
        return Ok((findings, result.truncated));
    }
    Err(format!(
        "fatal syntax error: {}",
        first_error.unwrap_or_else(|| "unknown".to_owned())
    ))
}

fn snippet(text: &str, span: Span) -> String {
    let raw = text
        .get(span.start as usize..span.end as usize)
        .unwrap_or("");
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > 120 {
        let mut cut: String = collapsed.chars().take(117).collect();
        cut.push_str("...");
        cut
    } else {
        collapsed
    }
}

fn to_finding(raw: &RawFinding, file: &str, text: &str, index: &LineIndex) -> Finding {
    let at = |offset: u32| index.line_col(offset);
    let source_at = at(raw.origin.span.start);
    let sink_at = at(raw.call.start);
    let source_expr = snippet(text, raw.origin.span);
    Finding {
        file: file.to_owned(),
        sink: SinkLoc {
            api: raw.api.clone(),
            arg: snippet(text, raw.arg),
            line: sink_at.line,
            col: sink_at.column,
        },
        class: raw.class,
        severity: raw.severity,
        confidence: "heuristic",
        auth: "unknown",
        function: raw.function.clone(),
        source: SourceLoc {
            kind: raw.origin.kind,
            expr: source_expr,
            line: source_at.line,
            col: source_at.column,
        },
        trace: raw
            .origin
            .steps
            .iter()
            .map(|(offset, note)| {
                let step = at(*offset);
                TraceStep {
                    line: step.line,
                    col: step.column,
                    note: note.clone(),
                }
            })
            .collect(),
        key: String::new(),
    }
}

/// Sorts findings deterministically and fills in each line-independent key.
pub fn finalize(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        (
            a.severity,
            a.class,
            &a.file,
            a.sink.line,
            a.sink.col,
            &a.source.expr,
        )
            .cmp(&(
                b.severity,
                b.class,
                &b.file,
                b.sink.line,
                b.sink.col,
                &b.source.expr,
            ))
    });
    let mut seen: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for finding in findings.iter_mut() {
        let base = format!(
            "{}|{}|{}|{}|{}",
            finding.class.name(),
            finding.file,
            finding.function,
            finding.sink.api,
            finding.source.expr
        );
        let ordinal = seen.entry(base.clone()).or_insert(0);
        finding.key = format!("{base}|{ordinal}");
        *ordinal += 1;
    }
}
