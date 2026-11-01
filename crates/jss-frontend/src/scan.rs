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

/// One file's route templates: function -> templates.
type Templates = BTreeMap<String, Vec<taint::RouteTemplate>>;

/// What analyzing one file yields: findings, whether the walk was capped, summaries, the lowered
/// module, route templates and constants.
type Analysis = (
    Vec<Finding>,
    bool,
    Summaries,
    ir::Module,
    Templates,
    BTreeMap<String, String>,
);
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
    /// Functions of this file that register routes from their parameters.
    templates: BTreeMap<String, Vec<taint::RouteTemplate>>,
    /// Constants of this file (enum members, `const` strings).
    constants: BTreeMap<String, String>,
}

/// What every file's scan needs to know about the scan root.
struct Context<'a> {
    all: &'a BTreeSet<String>,
    workspace: &'a jss_core::resolve::Workspace,
    reexports: BTreeMap<String, BTreeSet<String>>,
    templates: taint::Templates,
    constants: BTreeMap<String, BTreeMap<String, String>>,
    exports: BTreeMap<String, BTreeMap<String, String>>,
    /// Every class extending or implementing a class or interface, transitively:
    /// (file, name) -> [(file, name)].
    subclasses: BTreeMap<(String, String), Vec<(String, String)>>,
    /// Request props that hold no objects, per directory of a scanned file.
    scalar: &'a BTreeMap<String, Vec<String>>,
    /// Packages sinks require that the scanned project depends on (`None`: no manifest).
    packages: Option<&'a BTreeSet<String>>,
    /// The round's summary names by last segment.
    external_names: BTreeMap<String, Vec<String>>,
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
            .as_ref()
            .map(|r| jss_core::resolve::Workspace::load(r))
            .unwrap_or_default();
        let scalar = scalar_props_by_dir(files, root.as_deref());
        let packages = project_packages(files, root.as_deref());
        let run = |external: &Summaries,
                   reexports: BTreeMap<String, BTreeSet<String>>,
                   templates: taint::Templates,
                   constants: BTreeMap<String, BTreeMap<String, String>>,
                   exports: BTreeMap<String, BTreeMap<String, String>>,
                   subclasses: BTreeMap<(String, String), Vec<(String, String)>>|
         -> Vec<ScanReport> {
            let context = Context {
                all: &all,
                workspace: &workspace,
                reexports,
                templates,
                constants,
                exports,
                subclasses,
                scalar: &scalar,
                packages: packages.as_ref(),
                external_names: taint::index_names(external),
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
        // What the last round ran on: summaries, templates, constants, exports and re-exports
        // (counted). A round on the same inputs would give the same reports.
        let mut known = (0usize, 0usize, 0usize, 0usize, 0usize);
        let mut reports = run(
            &external,
            BTreeMap::new(),
            taint::Templates::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        for _ in 1..CROSS_FILE_HOPS {
            let reexports = reexport_closure(&reports);
            let templates: taint::Templates = reports
                .iter()
                .filter(|r| !r.templates.is_empty())
                .map(|r| (r.rel_path.clone(), r.templates.clone()))
                .collect();
            let template_count: usize = templates
                .values()
                .flat_map(BTreeMap::values)
                .map(Vec::len)
                .sum();
            let constants: BTreeMap<String, BTreeMap<String, String>> = reports
                .iter()
                .filter(|r| !r.constants.is_empty())
                .map(|r| (r.rel_path.clone(), r.constants.clone()))
                .collect();
            let constant_count: usize = constants.values().map(BTreeMap::len).sum();
            let exports: BTreeMap<String, BTreeMap<String, String>> = reports
                .iter()
                .filter(|r| !r.module.exports.is_empty())
                .map(|r| (r.rel_path.clone(), r.module.exports.clone()))
                .collect();
            let merged = merge(&reports);
            let now = (
                count(&merged),
                template_count,
                constant_count,
                exports.values().map(BTreeMap::len).sum(),
                reexports.values().map(BTreeSet::len).sum(),
            );
            if now == known {
                break;
            }
            known = now;
            external = merged;
            let subclasses = subclass_closure(&reports);
            reports = run(
                &external, reexports, templates, constants, exports, subclasses,
            );
        }
        reports
    }
}

/// The directory part of a root-relative path (`""` at the root).
fn parent_dir(rel_path: &str) -> &str {
    rel_path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// Request props that hold no objects, per directory of a scanned file: from the nearest
/// `package.json` that depends on a package a pack gates (`express` 5 parses query strings
/// with the simple parser). Unknown versions (`*`, `latest`, a git URL) gate nothing.
fn scalar_props_by_dir(
    files: &[SourceFile],
    root: Option<&std::path::Path>,
) -> BTreeMap<String, Vec<String>> {
    let gates = &taint::models::model().scalar_props_from;
    let mut by_dir: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let Some(root) = root else { return by_dir };
    if gates.is_empty() {
        return by_dir;
    }
    let mut manifests: BTreeMap<std::path::PathBuf, Option<serde_json::Value>> = BTreeMap::new();
    for file in files {
        let dir = parent_dir(&file.rel_path);
        if by_dir.contains_key(dir) {
            continue;
        }
        let mut props = Vec::new();
        for gate in gates {
            let mut cursor = root.join(dir);
            let major = loop {
                let manifest = manifests
                    .entry(cursor.join("package.json"))
                    .or_insert_with_key(|path| {
                        std::fs::read(path)
                            .ok()
                            .filter(|bytes| bytes.len() < 1 << 20)
                            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                    });
                let spec = manifest.as_ref().and_then(|m| {
                    ["dependencies", "devDependencies", "peerDependencies"]
                        .iter()
                        .find_map(|section| m.get(section)?.get(&gate.package)?.as_str())
                });
                if let Some(spec) = spec {
                    break major_version(spec);
                }
                if cursor.as_path() == root {
                    break None;
                }
                match cursor.parent() {
                    Some(parent) if parent.starts_with(root) => cursor = parent.to_path_buf(),
                    _ => break None,
                }
            };
            if major.is_some_and(|m| m >= gate.major) {
                props.extend(gate.props.iter().cloned());
            }
        }
        by_dir.insert(dir.to_owned(), props);
    }
    by_dir
}

/// The packages some sink `requires` that the scanned project depends on: from every
/// `package.json` between a scanned file and the scan root (a monorepo's packages share their
/// drivers: the core package often holds the database client the others are handed), plus
/// `meteor` for a Meteor app. `None` when the scan has no manifest at all (nothing is held
/// back then).
fn project_packages(
    files: &[SourceFile],
    root: Option<&std::path::Path>,
) -> Option<BTreeSet<String>> {
    let wanted = &taint::models::model().sink_packages;
    let root = root?;
    if wanted.is_empty() {
        return None;
    }
    let mut found: BTreeSet<String> = BTreeSet::new();
    if root.join(".meteor").is_dir() {
        found.insert("meteor".to_owned());
    }
    let mut manifests: BTreeMap<std::path::PathBuf, Option<BTreeSet<String>>> = BTreeMap::new();
    let mut dirs_done: BTreeSet<&str> = BTreeSet::new();
    let mut seen_manifest = false;
    for file in files {
        let dir = parent_dir(&file.rel_path);
        if !dirs_done.insert(dir) {
            continue;
        }
        let mut cursor = root.join(dir);
        loop {
            let deps = manifests
                .entry(cursor.join("package.json"))
                .or_insert_with_key(|path| {
                    let bytes = std::fs::read(path).ok().filter(|b| b.len() < 1 << 20)?;
                    let manifest: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
                    let mut deps = BTreeSet::new();
                    for section in [
                        "dependencies",
                        "devDependencies",
                        "peerDependencies",
                        "optionalDependencies",
                    ] {
                        if let Some(map) = manifest.get(section).and_then(|s| s.as_object()) {
                            deps.extend(map.keys().filter(|k| wanted.contains(*k)).cloned());
                        }
                    }
                    Some(deps)
                });
            if let Some(deps) = deps {
                seen_manifest = true;
                found.extend(deps.iter().cloned());
            }
            if cursor.as_path() == root {
                break;
            }
            match cursor.parent() {
                Some(parent) if parent.starts_with(root) => cursor = parent.to_path_buf(),
                _ => break,
            }
        }
    }
    seen_manifest.then_some(found)
}

/// The major version a dependency spec starts from: `^5.3.0` -> 5, `~4.18` -> 4, `5.x` -> 5.
fn major_version(spec: &str) -> Option<u64> {
    let digits: String = spec
        .trim_start_matches(|c: char| !c.is_ascii_digit() && "^~=<> v".contains(c))
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Most files a value is followed across: route -> controller -> registry -> service ->
/// storage -> adapter -> helper. Rounds stop earlier once a round learns nothing new.
pub const CROSS_FILE_HOPS: usize = 8;

/// Every class that extends or implements each class or interface, transitively (at most 64
/// per base), from every module's class declarations.
fn subclass_closure(reports: &[ScanReport]) -> BTreeMap<(String, String), Vec<(String, String)>> {
    let mut direct: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    for report in reports {
        for class in &report.module.classes {
            for base in &class.bases {
                direct
                    .entry(base.clone())
                    .or_default()
                    .push((report.rel_path.clone(), class.name.clone()));
            }
        }
    }
    let mut closure = BTreeMap::new();
    for base in direct.keys() {
        let mut found: Vec<(String, String)> = Vec::new();
        let mut queue: Vec<(String, String)> = direct.get(base).cloned().unwrap_or_default();
        while let Some(class) = queue.pop() {
            if found.contains(&class) || found.len() >= 64 {
                continue;
            }
            if let Some(more) = direct.get(&class) {
                queue.extend(more.iter().cloned());
            }
            found.push(class);
        }
        found.sort();
        closure.insert(base.clone(), found);
    }
    closure
}

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
fn merge(reports: &[ScanReport]) -> Summaries {
    let mut merged = Summaries::new();
    for report in reports {
        for (name, list) in &report.summaries {
            merged
                .entry(name.clone())
                .or_default()
                .extend(list.iter().cloned());
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
        templates: BTreeMap::new(),
        constants: BTreeMap::new(),
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
        Ok(Ok((findings, truncated, summaries, module, templates, constants))) => ScanReport {
            rel_path: file.rel_path.clone(),
            status: ScanStatus::Scanned,
            truncated,
            findings,
            summaries,
            module,
            templates,
            constants,
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
) -> Result<Analysis, String> {
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
) -> Analysis {
    let linking = Linking {
        file: &file.rel_path,
        files: context.all,
        workspace: context.workspace,
        reexports: &context.reexports,
        templates: &context.templates,
        constants: &context.constants,
        exports: &context.exports,
        subclasses: &context.subclasses,
        scalar_props: context
            .scalar
            .get(parent_dir(&file.rel_path))
            .map_or(&[], Vec::as_slice),
        packages: context.packages,
        external_names: &context.external_names,
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
        summary.defined_in = Some(file.rel_path.clone());
        // Derived from another file's summary: this file's own steps come first in the trace.
        if let Some(ext) = &mut summary.ext {
            let ours: Vec<TraceStep> = summary
                .steps
                .iter()
                .map(|(offset, note)| {
                    let step = index.line_col(*offset);
                    TraceStep {
                        file: Some(file.rel_path.clone()),
                        line: step.line,
                        col: step.column,
                        note: note.clone(),
                    }
                })
                .collect();
            ext.steps.splice(0..0, ours);
        }
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
                        TraceStep {
                            file: Some(file.rel_path.clone()),
                            line: step.line,
                            col: step.column,
                            note: note.clone(),
                        }
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
                    returns_local: facts.returned_locals.get(name).cloned(),
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
        for summary in list.iter().filter(|s| s.api != taint::VALIDATES) {
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
                receiver_file: r.receiver_file.clone(),
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
        classes: facts.classes,
        mounts: facts
            .mounts
            .into_iter()
            .map(|mount| ir::Mount {
                receiver: mount.receiver,
                prefix: mount.prefix,
                target: mount.target,
                target_file: mount.target_file,
                target_export: mount.target_export,
                auth: mount.auth,
            })
            .collect(),
    };
    (
        findings,
        result.truncated,
        summaries,
        module,
        result.templates,
        result.constants,
    )
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
                file: None,
                line: step.line,
                col: step.column,
                note: note.clone(),
            }
        })
        .collect();
    if let Some(ext) = &raw.ext {
        trace.extend(ext.steps.iter().cloned());
    }
    Finding {
        file: file.to_owned(),
        sink,
        class: raw.class,
        severity: raw.severity,
        confidence: "heuristic",
        auth: raw.auth,
        function: raw.function.clone(),
        entry: None,
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

/// Fills in each finding's line-independent key and fingerprint, then sorts the findings for
/// output (severity first).
///
/// The key is `class|file|function|sink api|source expr|ordinal`; the ordinal tells apart
/// findings that share the rest, counted in source order (sink position, then source position).
/// Severity plays no part, so call this on every finding before filtering by severity: a key
/// then never depends on the filters or on how a finding was rated.
pub fn finalize(findings: &mut [Finding]) {
    fn identity(f: &Finding) -> (jss_core::VulnClass, &str, &str, &str, &str) {
        (f.class, &f.file, &f.function, &f.sink.api, &f.source.expr)
    }
    fn position(f: &Finding) -> (Option<&str>, u32, u32, u32, u32) {
        (
            f.sink.file.as_deref(),
            f.sink.line,
            f.sink.col,
            f.source.line,
            f.source.col,
        )
    }
    findings.sort_by(|a, b| {
        identity(a)
            .cmp(&identity(b))
            .then_with(|| position(a).cmp(&position(b)))
            .then_with(|| a.cmp(b))
    });
    let mut previous: Option<String> = None;
    let mut ordinal = 0u32;
    for finding in findings.iter_mut() {
        let base = format!(
            "{}|{}|{}|{}|{}",
            finding.class.name(),
            finding.file,
            finding.function,
            finding.sink.api,
            finding.source.expr
        );
        ordinal = if previous.as_deref() == Some(base.as_str()) {
            ordinal + 1
        } else {
            0
        };
        finding.key = format!("{base}|{ordinal}");
        finding.fingerprint = jss_core::finding::fingerprint(&finding.key);
        previous = Some(base);
    }
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
            .then_with(|| a.key.cmp(&b.key))
    });
}
