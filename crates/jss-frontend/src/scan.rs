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
use crate::taint::{self, ExtSink, Linking, RawFinding, Summaries};
use jss_core::ir;
use std::collections::{BTreeMap, BTreeSet};

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
    /// This file's functions whose parameters reach a sink, located for other files.
    summaries: Summaries,
    /// The file lowered to the owned IR: imports, exports, functions (calls and flows), entry
    /// points and mounts.
    pub module: ir::Module,
}

/// What every file's scan needs to know about the scan root.
struct Context<'a> {
    all: &'a BTreeSet<String>,
    workspace: &'a jss_core::resolve::Workspace,
    reexports: BTreeMap<String, BTreeSet<String>>,
}

impl ParsePool {
    /// Scans every file of a class in `selection`, in parallel. Reports come back in input
    /// order; files that are not scanned have no report.
    ///
    /// Two passes: the first collects every file's helper summaries, the second scans with
    /// them, so a call into another file's function reaches its sinks. Functions are linked by
    /// name, and only names that are unique in the scan root are used.
    pub fn scan(&self, files: &[SourceFile], selection: ClassSet) -> Vec<ScanReport> {
        let all: BTreeSet<String> = files.iter().map(|f| f.rel_path.clone()).collect();
        // The scan root, from any file: its absolute path minus its root-relative one.
        let root = files.first().and_then(|f| {
            let abs = f.abs_path.to_string_lossy().replace('\\', "/");
            abs.strip_suffix(&f.rel_path).map(std::path::PathBuf::from)
        });
        let workspace = root
            .map(|r| jss_core::resolve::Workspace::load(&r))
            .unwrap_or_default();
        let run = |external: &Summaries,
                   reexports: BTreeMap<String, BTreeSet<String>>|
         -> Vec<ScanReport> {
            let context = Context {
                all: &all,
                workspace: &workspace,
                reexports,
            };
            self.install(|| {
                files
                    .par_iter()
                    .filter_map(|file| {
                        match guarded(|| scan_file(file, selection, external, &context)) {
                            Ok(report) => report,
                            Err(panic) => Some(report(file, ScanStatus::Panicked(panic))),
                        }
                    })
                    .collect()
            })
        };
        // Each round lets a summary cross one more file: a route, its controller, a service,
        // a helper. Stop when nothing new is learned (at most `CROSS_FILE_HOPS` rounds).
        let mut external = Summaries::new();
        let mut reports = run(&external, BTreeMap::new());
        for _ in 1..CROSS_FILE_HOPS {
            let reexports = reexport_closure(&reports);
            let merged = merge(reports);
            let grew = count(&merged) > count(&external);
            external = merged;
            reports = run(&external, reexports);
            if !grew {
                break;
            }
        }
        reports
    }
}

/// Most files a value is followed across: route -> controller -> service -> helper.
pub const CROSS_FILE_HOPS: usize = 4;

/// File -> every file it re-exports, followed through chains of barrels.
fn reexport_closure(reports: &[ScanReport]) -> BTreeMap<String, BTreeSet<String>> {
    let direct: BTreeMap<&str, &[String]> = reports
        .iter()
        .map(|r| (r.rel_path.as_str(), r.module.reexports.as_slice()))
        .collect();
    let mut closure = BTreeMap::new();
    for (file, targets) in &direct {
        if targets.is_empty() {
            continue;
        }
        let mut seen = BTreeSet::new();
        let mut stack: Vec<&str> = targets.iter().map(String::as_str).collect();
        while let Some(next) = stack.pop() {
            if seen.len() > 500 || !seen.insert(next.to_owned()) {
                continue;
            }
            if let Some(more) = direct.get(next) {
                stack.extend(more.iter().map(String::as_str));
            }
        }
        closure.insert((*file).to_owned(), seen);
    }
    closure
}

fn count(summaries: &Summaries) -> usize {
    summaries.values().map(Vec::len).sum()
}

/// Merges per-file summaries. A name defined in several files keeps every definition: callers
/// link to the one their import resolves to.
fn merge(reports: Vec<ScanReport>) -> Summaries {
    let mut merged = Summaries::new();
    for report in reports {
        for (name, list) in report.summaries {
            merged.entry(name).or_default().extend(list);
        }
    }
    merged
}

fn report(file: &SourceFile, status: ScanStatus) -> ScanReport {
    ScanReport {
        rel_path: file.rel_path.clone(),
        status,
        truncated: false,
        findings: Vec::new(),
        summaries: Summaries::new(),
        module: ir::Module::default(),
    }
}

fn scan_file(
    file: &SourceFile,
    selection: ClassSet,
    external: &Summaries,
    context: &Context<'_>,
) -> Option<ScanReport> {
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
    let outcome = on_parser_stack(text, |allocator| {
        scan_text(allocator, file, text, external, context)
    });
    Some(match outcome {
        Ok(Ok((findings, truncated, summaries, module))) => ScanReport {
            rel_path: file.rel_path.clone(),
            status: ScanStatus::Scanned,
            truncated,
            findings,
            summaries,
            module,
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
    external: &Summaries,
    context: &Context<'_>,
) -> Result<(Vec<Finding>, bool, Summaries, ir::Module), String> {
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
        return Ok(analyze(&ret.program, file, text, external, context));
    }
    // Flow-typed JavaScript: blank the Flow-only syntax (offsets kept) and read it as TypeScript.
    if let Some(fallbacks) = typed_fallbacks(file.kind, file.package_type) {
        let pragma = text.contains("@flow");
        for typed in fallbacks {
            let Some(erased) = crate::flow::erased_text(text, typed, pragma) else {
                continue;
            };
            let ret = Parser::new(allocator, &erased, typed)
                .with_options(parse_options())
                .parse();
            if !ret.fatal_error {
                return Ok(analyze(&ret.program, file, text, external, context));
            }
        }
    }
    Err(format!(
        "fatal syntax error: {}",
        first_error.unwrap_or_else(|| "unknown".to_owned())
    ))
}

/// Walks a parsed program (whose offsets are those of `text`) and packages what it found.
fn analyze(
    program: &oxc_ast::ast::Program<'_>,
    file: &SourceFile,
    text: &str,
    external: &Summaries,
    context: &Context<'_>,
) -> (Vec<Finding>, bool, Summaries, ir::Module) {
    let linking = Linking {
        file: &file.rel_path,
        files: context.all,
        workspace: context.workspace,
        reexports: &context.reexports,
    };
    let result = taint::scan_file_program(program, &linking, external);
    let index = LineIndex::new(text);
    let findings = result
        .findings
        .iter()
        .map(|raw| to_finding(raw, &file.rel_path, text, &index))
        .collect();
    let mut summaries = result.summaries;
    for summary in summaries.values_mut().flatten() {
        if summary.ext.is_none() {
            let at = index.line_col(summary.call.start);
            summary.ext = Some(ExtSink {
                file: file.rel_path.clone(),
                line: at.line,
                col: at.column,
                arg: snippet(text, summary.arg),
                steps: summary
                    .steps
                    .iter()
                    .map(|(offset, note)| {
                        let step = index.line_col(*offset);
                        format!("{}:{}: {note}", file.rel_path, step.line)
                    })
                    .collect(),
            });
        }
    }
    let facts = result.facts;
    let line = |offset: u32| index.line_col(offset).line;
    let mut functions: BTreeMap<String, ir::Function> = facts
        .functions
        .iter()
        .map(|(name, (offset, params))| {
            (
                name.clone(),
                ir::Function {
                    name: name.clone(),
                    line: line(*offset),
                    params: params.clone(),
                    calls: Vec::new(),
                    flows: Vec::new(),
                },
            )
        })
        .collect();
    for (name, calls) in &facts.calls {
        let function = functions
            .entry(name.clone())
            .or_insert_with(|| ir::Function {
                name: name.clone(),
                ..ir::Function::default()
            });
        function.calls = calls
            .iter()
            .map(|(callee, offset, args)| ir::Call {
                callee: callee.clone(),
                line: line(*offset),
                args: args.clone(),
            })
            .collect();
    }
    for (name, list) in &summaries {
        let function = functions
            .entry(name.clone())
            .or_insert_with(|| ir::Function {
                name: name.clone(),
                ..ir::Function::default()
            });
        for summary in list {
            let to = if summary.api == taint::RETURNS {
                ir::FlowTarget::Return
            } else {
                let ext = summary.ext.as_ref();
                ir::FlowTarget::Sink {
                    class: summary.class,
                    severity: summary.severity,
                    api: summary.api.clone(),
                    file: ext.map_or_else(|| file.rel_path.clone(), |e| e.file.clone()),
                    line: ext.map_or(0, |e| e.line),
                }
            };
            let flow = ir::Flow {
                param: summary.param,
                field: summary.field.clone(),
                to,
            };
            if !function.flows.contains(&flow) {
                function.flows.push(flow);
            }
        }
    }
    let module = ir::Module {
        file: file.rel_path.clone(),
        imports: facts.imports,
        exports: facts.exports,
        functions: functions.into_values().collect(),
        entries: facts
            .routes
            .iter()
            .map(|r| ir::Entry {
                receiver: r.receiver.clone(),
                method: r.method.clone(),
                path: r.path.clone(),
                handler: r.handler.clone(),
                line: line(r.span.start),
                auth: r.auth,
                kind: r.kind.to_owned(),
                inputs: facts
                    .inputs
                    .get(&r.handler)
                    .map(|set| set.iter().cloned().collect())
                    .unwrap_or_default(),
            })
            .collect(),
        reexports: facts.reexports,
        mounts: facts
            .mounts
            .into_iter()
            .map(|mount| ir::Mount {
                receiver: mount.receiver,
                prefix: mount.prefix,
                target: mount.target,
                target_file: mount.target_file,
            })
            .collect(),
    };
    (findings, result.truncated, summaries, module)
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
    let sink = match &raw.ext {
        Some(ext) => SinkLoc {
            file: Some(ext.file.clone()),
            api: raw.api.clone(),
            arg: ext.arg.clone(),
            line: ext.line,
            col: ext.col,
        },
        None => SinkLoc {
            file: None,
            api: raw.api.clone(),
            arg: snippet(text, raw.arg),
            line: sink_at.line,
            col: sink_at.column,
        },
    };
    let mut trace: Vec<TraceStep> = raw
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
        .collect();
    if let Some(ext) = &raw.ext {
        trace.extend(ext.steps.iter().map(|note| TraceStep {
            line: 0,
            col: 0,
            note: note.clone(),
        }));
    }
    Finding {
        file: file.to_owned(),
        sink,
        class: raw.class,
        severity: raw.severity,
        confidence: "heuristic",
        auth: raw.auth,
        function: raw.function.clone(),
        source: SourceLoc {
            kind: raw.origin.kind,
            expr: source_expr,
            line: source_at.line,
            col: source_at.column,
        },
        trace,
        key: String::new(),
        fingerprint: String::new(),
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
        finding.fingerprint = jss_core::finding::fingerprint(&finding.key);
        *ordinal += 1;
    }
}
