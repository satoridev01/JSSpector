//! Parallel per-file processing: read, classify, check and parse every file, each isolated from
//! the others.
//!
//! - Files run on a dedicated rayon pool whose workers have [`WORKER_STACK_BYTES`] stacks.
//! - Each file is opened at most once. Its header decides its final class (the `@generated`
//!   marker; see [`jss_core::Work`]), and only files of a selected class are parsed.
//! - The parser recurses once per nesting level and a stack overflow aborts the whole process
//!   (it cannot be caught; oxc#21953). So the parser always runs on a stack at least
//!   [`parser_stack_bound`] large for the file: on the worker when that fits, otherwise on a
//!   thread spawned with that much stack. The bound follows from the file's size alone, so no
//!   input can overflow it, whatever the nesting prescan concluded. Files that need more than a
//!   worker's stack are parsed one at a time (see [`DEEP_PARSE`]).
//! - Each worker keeps one oxc [`Allocator`] and resets it between files. After a panic the
//!   allocator is dropped and the next file gets a fresh one.
//! - Each file runs inside `catch_unwind`: a panic becomes a `parse/panicked` diagnostic for
//!   that file only. While a file is being processed, a panic hook records the panic location
//!   instead of printing it, so expected panics keep stderr quiet; every other panic still goes
//!   to the previously installed hook.
//! - Results come back in input order (indexed `collect`), so output is identical for any number
//!   of threads.

use std::any::Any;
use std::cell::Cell;
use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::sync::{Mutex, Once, PoisonError};

use jss_core::content::{self, Skip};
use jss_core::{
    ClassSet, DiagCode, Diagnostic, FileClass, LineIndex, PackageType, SkipReason, SourceFile,
    SourceKind, Work, classify,
};
use oxc_allocator::Allocator;
use rayon::prelude::*;

use crate::flow;
use crate::parse::{ParseFn, ParseOutcome, parse_with, source_type, typed_fallbacks};

/// Stack size of each worker thread. Files whose [`parser_stack_bound`] exceeds it are parsed
/// on a thread of their own with a large enough stack.
pub const WORKER_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Parser stack allowed per input byte that can open a nesting level: `(`, `[`, `{` or `<`.
///
/// Measured on oxc_parser 0.156 (aarch64, release and test builds), the costliest one-byte
/// level is `[` in a type (about 1.74 KiB), then `(` (about 1.52 KiB); this leaves room for
/// other targets and compiler versions.
pub const STACK_PER_BRACKET_BYTE: usize = 4 * 1024;

/// Parser stack allowed per other input byte. Recursion without brackets costs at most about
/// 370 bytes per input byte (`a ? a ? ...`; also `a => a => ...`, `a = a = ...`, labels, unary
/// chains), measured like [`STACK_PER_BRACKET_BYTE`].
pub const STACK_PER_BYTE: usize = 768;

/// Stack allowed for everything below and around the parser's recursion.
pub const STACK_BASE: usize = 4 * 1024 * 1024;

/// Held while a file whose [`parser_stack_bound`] exceeds [`WORKER_STACK_BYTES`] is parsed, so
/// such files are parsed one at a time. They are rare in real code (one file in about 15,000 on
/// the day-2 corpus), but pathological input really uses that stack, hundreds of MiB per file:
/// one per worker at once could multiply the peak memory past the budget.
static DEEP_PARSE: Mutex<()> = Mutex::new(());

/// An upper bound of the stack the parser can use on `bytes`. Every level of recursion consumes
/// at least one input byte, so a per-byte cost bounds every construct, nested or chained,
/// without parsing.
pub fn parser_stack_bound(bytes: &[u8]) -> usize {
    let brackets = bytes
        .iter()
        .filter(|&&byte| matches!(byte, b'(' | b'[' | b'{' | b'<'))
        .count();
    let others = bytes.len().saturating_sub(brackets);
    STACK_BASE
        .saturating_add(brackets.saturating_mul(STACK_PER_BRACKET_BYTE))
        .saturating_add(others.saturating_mul(STACK_PER_BYTE))
}

/// What happened to one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    /// The file parsed. `recovered` is true when the parser reported syntax errors but still
    /// built an AST.
    Parsed {
        statements: usize,
        syntax_errors: usize,
        recovered: bool,
    },
    /// The parser gave up: there is no AST.
    Fatal,
    /// The parser panicked; the panic was contained to this file.
    Panicked,
    /// The file was selected but not parsed.
    Skipped(SkipReason),
    /// The file's class is not selected: it was not parsed.
    Excluded,
}

/// The outcome of processing one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReport {
    pub rel_path: String,
    /// The final class: the path class, or Generated when the header carries the marker.
    pub class: FileClass,
    pub status: FileStatus,
    /// Flow-typed JavaScript: the file has an `@flow` pragma, or it parses only with type
    /// syntax (read as TypeScript, which covers most Flow annotations).
    pub flow: bool,
    /// Flow-only syntax erased before the file was read as TypeScript: how many ranges were
    /// blanked (see the `flow` module). 0 for a file that needed none. The blanks keep every
    /// offset, so locations in this file's results refer to the original text.
    pub flow_edits: u32,
    /// Bytes handed to the parser: the file's size if it reached the parser, otherwise 0.
    pub parsed_bytes: u64,
    /// This file's diagnostics: one for every status except a clean parse and an exclusion.
    pub diagnostics: Vec<Diagnostic>,
}

/// The worker pool could not be started.
#[derive(Debug)]
pub struct PoolError(rayon::ThreadPoolBuildError);

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot start the parser thread pool: {}", self.0)
    }
}

impl std::error::Error for PoolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// A dedicated pool of parser workers: the frontend's entry point. Build it once and reuse it.
#[derive(Debug)]
pub struct ParsePool {
    pool: rayon::ThreadPool,
}

impl ParsePool {
    /// Starts `threads` workers. `None` uses rayon's default: `RAYON_NUM_THREADS` when set,
    /// otherwise the available parallelism.
    pub fn new(threads: Option<NonZeroUsize>) -> Result<Self, PoolError> {
        install_panic_hook();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads.map_or(0, NonZeroUsize::get))
            .stack_size(WORKER_STACK_BYTES)
            .thread_name(|index| format!("jss-parse-{index}"))
            .start_handler(|_| {
                let _ = STACK_BUDGET.try_with(|budget| budget.set(WORKER_STACK_BYTES));
            })
            .build()
            .map_err(PoolError)?;
        Ok(Self { pool })
    }

    /// Number of worker threads.
    pub fn threads(&self) -> usize {
        self.pool.current_num_threads()
    }

    /// Runs `work` inside the pool, so rayon parallelism in it (such as
    /// [`jss_core::discover()`]) uses these workers rather than the global pool.
    pub fn install<R: Send>(&self, work: impl FnOnce() -> R + Send) -> R {
        self.pool.install(work)
    }

    /// Processes every file in parallel: those of a class in `selection` are parsed, the others
    /// are only classified. Returns one report per file, in input order.
    pub fn process(&self, files: &[SourceFile], selection: ClassSet) -> Vec<FileReport> {
        self.pool.install(|| {
            files
                .par_iter()
                .map(|file| process_file(file, selection))
                .collect()
        })
    }
}

/// Processes one file. Safe on any thread: the parser gets a large enough stack either way.
fn process_file(file: &SourceFile, selection: ClassSet) -> FileReport {
    process_file_with(file, selection, parse_with)
}

/// [`process_file`] with the parser as a parameter (a seam for tests). Never panics: a panic
/// anywhere becomes a `parse/panicked` report.
fn process_file_with(file: &SourceFile, selection: ClassSet, parse: ParseFn) -> FileReport {
    match guarded(|| run(file, selection, parse)) {
        Ok(report) => report,
        Err(panic) => panicked(file, file.path_class, &panic),
    }
}

fn run(file: &SourceFile, selection: ClassSet, parse: ParseFn) -> FileReport {
    match file.work(selection) {
        Work::Exclude => report(file, file.path_class, FileStatus::Excluded),
        Work::Classify => match read_head(&file.abs_path) {
            Ok(head) => report(
                file,
                classify::with_header(file.path_class, &head),
                FileStatus::Excluded,
            ),
            Err(err) => unreadable(file, file.path_class, &err),
        },
        Work::Parse => parse_candidate(file, selection, parse),
    }
}

/// A file that is parsed unless its header makes it a class that is not selected.
fn parse_candidate(file: &SourceFile, selection: ClassSet, parse: ParseFn) -> FileReport {
    if let Err(skip) = content::check_size(file.size) {
        // Too large to parse: read just the header to classify it.
        return match read_head(&file.abs_path) {
            Ok(head) => {
                let class = classify::with_header(file.path_class, &head);
                if selection.contains(class) {
                    skipped(file, class, skip)
                } else {
                    report(file, class, FileStatus::Excluded)
                }
            }
            Err(err) => unreadable(file, file.path_class, &err),
        };
    }
    let bytes = match read_capped(&file.abs_path, file.size) {
        Ok(bytes) => bytes,
        Err(err) => return unreadable(file, file.path_class, &err),
    };
    let class = classify::with_header(file.path_class, &bytes);
    if !selection.contains(class) {
        return report(file, class, FileStatus::Excluded);
    }
    let text = match content::check(&bytes) {
        Ok(text) => text,
        Err(skip) => return skipped(file, class, skip),
    };
    let mut report = match parse_text(text, file.kind, file.package_type, parse) {
        Ok(Parse::Done {
            outcome,
            flow,
            flow_edits,
        }) => parsed(file, class, text, &outcome, flow, flow_edits),
        Ok(Parse::Template { message }) => {
            skipped(file, class, Skip::new(SkipReason::Template, message))
        }
        Err(ParseFailure::Panicked(panic)) => panicked(file, class, &panic),
        Err(ParseFailure::NoStack { bytes, error }) => {
            // The parser never ran.
            return skipped(
                file,
                class,
                Skip::new(
                    SkipReason::TooDeep,
                    format!(
                        "cannot start a parser thread with the {bytes}-byte stack this file \
                         may need: {error}"
                    ),
                ),
            );
        }
    };
    report.parsed_bytes = u64::try_from(text.len()).unwrap_or(u64::MAX);
    report
}

/// Reads at most one byte more than [`content::MAX_FILE_BYTES`], so a file that grew after
/// discovery is still caught by the size check without reading all of it.
pub(crate) fn read_capped(path: &Path, size_hint: u64) -> io::Result<Vec<u8>> {
    let limit = content::MAX_FILE_BYTES.saturating_add(1);
    let mut bytes = Vec::with_capacity(usize::try_from(size_hint.min(limit)).unwrap_or(0));
    File::open(path)?.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Reads the first [`classify::GENERATED_SCAN_BYTES`] bytes of a file.
pub(crate) fn read_head(path: &Path) -> io::Result<Vec<u8>> {
    let limit = u64::try_from(classify::GENERATED_SCAN_BYTES).unwrap_or(u64::MAX);
    let mut head = Vec::with_capacity(classify::GENERATED_SCAN_BYTES);
    File::open(path)?.take(limit).read_to_end(&mut head)?;
    Ok(head)
}

fn report(file: &SourceFile, class: FileClass, status: FileStatus) -> FileReport {
    FileReport {
        rel_path: file.rel_path.clone(),
        class,
        status,
        flow: false,
        flow_edits: 0,
        parsed_bytes: 0,
        diagnostics: Vec::new(),
    }
}

fn skipped(file: &SourceFile, class: FileClass, skip: Skip) -> FileReport {
    FileReport {
        diagnostics: vec![skip.clone().into_diagnostic(file.rel_path.clone())],
        ..report(file, class, FileStatus::Skipped(skip.reason))
    }
}

/// A file that could not be read. If its class is not known to be selected, it is still
/// reported (nothing is dropped silently), as a skip.
fn unreadable(file: &SourceFile, class: FileClass, err: &io::Error) -> FileReport {
    skipped(
        file,
        class,
        Skip::new(SkipReason::IoError, format!("cannot read file: {err}")),
    )
}

fn panicked(file: &SourceFile, class: FileClass, panic: &str) -> FileReport {
    FileReport {
        diagnostics: vec![Diagnostic::at(
            DiagCode::ParsePanicked,
            file.rel_path.clone(),
            format!("parser panicked: {panic}"),
        )],
        ..report(file, class, FileStatus::Panicked)
    }
}

fn parsed(
    file: &SourceFile,
    class: FileClass,
    text: &str,
    outcome: &ParseOutcome,
    flow: bool,
    flow_edits: u32,
) -> FileReport {
    let (status, code) = if outcome.fatal {
        (FileStatus::Fatal, Some(DiagCode::ParseFatal))
    } else {
        let recovered = outcome.syntax_errors > 0;
        let status = FileStatus::Parsed {
            statements: outcome.statements,
            syntax_errors: outcome.syntax_errors,
            recovered,
        };
        (status, recovered.then_some(DiagCode::ParseRecovered))
    };
    let diagnostics = code
        .map(|code| {
            let mut message = error_message(text, outcome);
            if flow && outcome.fatal {
                message.insert_str(0, "Flow syntax that TypeScript syntax does not cover: ");
            }
            Diagnostic::at(code, file.rel_path.clone(), message)
        })
        .into_iter()
        .collect();
    FileReport {
        flow,
        flow_edits,
        diagnostics,
        ..report(file, class, status)
    }
}

/// `line:column: message`, plus how many more errors there are. Columns are UTF-16 code units,
/// as in every report.
fn error_message(text: &str, outcome: &ParseOutcome) -> String {
    let Some(first) = &outcome.first_error else {
        return format!("{} syntax errors", outcome.syntax_errors);
    };
    let mut message = match first.offset {
        Some(offset) => {
            let at = LineIndex::new(text).line_col(offset);
            format!("{}:{}: {}", at.line, at.column, first.message)
        }
        None => first.message.clone(),
    };
    if outcome.syntax_errors > 1 {
        let _ = write!(message, " (+{} more)", outcome.syntax_errors - 1);
    }
    message
}

/// The result of parsing a file's text, all attempts included.
enum Parse {
    /// The final outcome; `flow` when the file is Flow-typed (see [`FileReport::flow`]) and
    /// `flow_edits` the ranges of Flow-only syntax blanked to get it (see [`FileReport::flow_edits`]).
    Done {
        outcome: ParseOutcome,
        flow: bool,
        flow_edits: u32,
    },
    /// The file is a server-side template, not JavaScript.
    Template { message: String },
}

/// Why a file has no [`Parse`].
pub(crate) enum ParseFailure {
    Panicked(String),
    /// A thread with a large enough stack could not be started.
    NoStack {
        bytes: usize,
        error: io::Error,
    },
}

/// Parses `text` on a stack of at least [`parser_stack_bound`]: this thread's when it is a pool
/// worker with room enough, otherwise a thread spawned for this file.
fn parse_text(
    text: &str,
    kind: SourceKind,
    package_type: PackageType,
    parse: ParseFn,
) -> Result<Parse, ParseFailure> {
    on_parser_stack(text, |allocator| {
        parse_all(allocator, text, kind, package_type, parse)
    })
}

/// Runs `work` (which parses `text`, and may walk the result) with this thread's allocator on a
/// stack of at least [`parser_stack_bound`] for `text`, catching any panic. Anything that parses
/// must go through here: a stack overflow cannot be caught.
pub(crate) fn on_parser_stack<T: Send>(
    text: &str,
    work: impl Fn(&Allocator) -> T + Sync,
) -> Result<T, ParseFailure> {
    let needed = parser_stack_bound(text.as_bytes());
    let budget = STACK_BUDGET.try_with(Cell::get).unwrap_or(0);
    let attempt = || isolated(&work);
    if needed <= budget {
        return attempt().map_err(ParseFailure::Panicked);
    }
    // Waits for any other oversized parse to finish; released once this file's thread is joined.
    let _one_at_a_time = (needed > WORKER_STACK_BYTES)
        .then(|| DEEP_PARSE.lock().unwrap_or_else(PoisonError::into_inner));
    std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .name("jss-parse-deep".to_owned())
            .stack_size(needed)
            .spawn_scoped(scope, attempt)
            .map_err(|error| ParseFailure::NoStack {
                bytes: needed,
                error,
            })?;
        match handle.join() {
            Ok(result) => result.map_err(ParseFailure::Panicked),
            Err(payload) => Err(ParseFailure::Panicked(describe_panic(payload.as_ref()))),
        }
    })
}

/// Parses `text` as its kind says; a JavaScript file that fails is checked for template tags,
/// then retried as Flow: read as TypeScript, with the syntax only Flow has erased (see
/// [`typed_fallbacks`] and the `flow` module).
fn parse_all(
    allocator: &Allocator,
    text: &str,
    kind: SourceKind,
    package_type: PackageType,
    parse: ParseFn,
) -> Parse {
    let primary = parse(allocator, text, source_type(kind, package_type));
    if primary.fatal
        && let Some(message) = template_tag(text, &primary)
    {
        return Parse::Template { message };
    }
    let fallbacks = match typed_fallbacks(kind, package_type) {
        Some(fallbacks) if primary.fatal || primary.flow => fallbacks,
        _ => {
            return Parse::Done {
                flow: primary.flow,
                flow_edits: 0,
                outcome: primary,
            };
        }
    };
    let mut furthest: Option<flow::Repair> = None;
    for typed in fallbacks {
        // Only a file JavaScript could not parse has Flow-only syntax to erase. One that parsed
        // is never edited: TypeScript's opinion of valid JavaScript is no reason to change it.
        let repair = if primary.fatal {
            flow::parse_repaired(allocator, text, typed, parse, primary.flow)
        } else {
            flow::Repair::unrepaired(parse(allocator, text, typed))
        };
        let outcome = &repair.outcome;
        if !outcome.fatal && (primary.fatal || outcome.syntax_errors == 0) {
            return Parse::Done {
                outcome: repair.outcome,
                flow: true,
                flow_edits: repair.edits,
            };
        }
        if outcome.fatal
            && error_offset(outcome) > furthest.as_ref().map_or(0, |r| error_offset(&r.outcome))
        {
            furthest = Some(repair);
        }
    }
    // Neither syntax works. For a declared Flow file, the attempt that got furthest shows the
    // first construct no rule could erase; for anything else, the JavaScript error stands.
    match furthest {
        Some(repair) if primary.flow => Parse::Done {
            outcome: repair.outcome,
            flow: true,
            flow_edits: repair.edits,
        },
        _ => Parse::Done {
            flow: primary.flow,
            flow_edits: 0,
            outcome: primary,
        },
    }
}

fn error_offset(outcome: &ParseOutcome) -> u32 {
    outcome
        .first_error
        .as_ref()
        .and_then(|error| error.offset)
        .unwrap_or(0)
}

/// The opening delimiter of server-side templates (EJS, ERB, Underscore/lodash templates).
const TEMPLATE_TAG: &str = "<%";

/// A skip message when the line of the first syntax error holds a template tag: a template
/// with a `.js` extension, which no JavaScript parser should accept. Only consulted after a
/// fatal parse.
pub(crate) fn template_tag(text: &str, outcome: &ParseOutcome) -> Option<String> {
    let offset = usize::try_from(outcome.first_error.as_ref()?.offset?).ok()?;
    let bytes = text.as_bytes();
    let line_start = bytes
        .get(..offset.min(bytes.len()))?
        .iter()
        .rposition(|&byte| byte == b'\n' || byte == b'\r')
        .map_or(0, |newline| newline + 1);
    let line_end = bytes
        .get(offset.min(bytes.len())..)?
        .iter()
        .position(|&byte| byte == b'\n' || byte == b'\r')
        .map_or(bytes.len(), |newline| offset + newline);
    let line = text.get(line_start..line_end)?;
    let tag = line_start + line.find(TEMPLATE_TAG)?;
    let at = LineIndex::new(text).line_col(u32::try_from(tag).ok()?);
    Some(format!(
        "{}:{}: template tag `{TEMPLATE_TAG}` (a server-side template such as EJS, not \
         JavaScript)",
        at.line, at.column
    ))
}

thread_local! {
    /// This worker's allocator, reused (after `reset`) from one file to the next.
    static ALLOCATOR: Cell<Option<Allocator>> = const { Cell::new(None) };
    /// Stack this thread can give the parser: [`WORKER_STACK_BYTES`] on pool workers, 0
    /// elsewhere (the parser then always runs on a thread of its own).
    static STACK_BUDGET: Cell<usize> = const { Cell::new(0) };
    /// True while this thread processes a file: the panic hook records instead of printing.
    static CAPTURING: Cell<bool> = const { Cell::new(false) };
    /// Location of the last panic recorded on this thread.
    static PANIC_LOCATION: Cell<Option<String>> = const { Cell::new(None) };
}

/// Runs `work` with this thread's allocator, catching any panic. On a panic the allocator is
/// dropped (the next call starts with a fresh one) and the panic is described as a string.
fn isolated<T>(work: impl FnOnce(&Allocator) -> T) -> Result<T, String> {
    let mut allocator = ALLOCATOR
        .try_with(Cell::take)
        .ok()
        .flatten()
        .unwrap_or_default();
    allocator.reset();
    match guarded(|| work(&allocator)) {
        Ok(value) => {
            let _ = ALLOCATOR.try_with(|cell| cell.set(Some(allocator)));
            Ok(value)
        }
        Err(panic) => {
            // The arena may be in any state after a panic: never reuse it.
            drop(allocator);
            Err(panic)
        }
    }
}

/// Runs `work`, catching any panic and describing it as a string; the panic hook records the
/// panic's location instead of printing it.
pub(crate) fn guarded<T>(work: impl FnOnce() -> T) -> Result<T, String> {
    install_panic_hook();
    let result = {
        let _capture = Capture::start();
        panic::catch_unwind(AssertUnwindSafe(work))
    };
    result.map_err(|payload| describe_panic(payload.as_ref()))
}

/// Marks this thread as processing a file for as long as it lives (nesting restores the outer
/// state).
struct Capture {
    previous: bool,
}

impl Capture {
    fn start() -> Self {
        let previous = CAPTURING.try_with(|capturing| capturing.replace(true));
        let _ = PANIC_LOCATION.try_with(Cell::take);
        Capture {
            previous: previous.unwrap_or(false),
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let _ = CAPTURING.try_with(|capturing| capturing.set(self.previous));
    }
}

fn describe_panic(payload: &(dyn Any + Send)) -> String {
    let message = payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned());
    match PANIC_LOCATION.try_with(Cell::take).ok().flatten() {
        Some(location) => format!("{message} (at {location})"),
        None => message,
    }
}

/// Installs, once per process, a panic hook that records (instead of printing) panics raised
/// while a thread processes a file, and passes every other panic to the previous hook. Because
/// it only intercepts panics inside [`guarded`], it never needs to be uninstalled, and
/// concurrent pools cannot race to install and restore hooks.
fn install_panic_hook() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if CAPTURING.try_with(Cell::get).unwrap_or(false) {
                let location = info.location().map(|location| {
                    format!(
                        "{}:{}:{}",
                        stable_source_path(location.file()),
                        location.line(),
                        location.column()
                    )
                });
                let _ = PANIC_LOCATION.try_with(|cell| cell.set(location));
            } else {
                previous(info);
            }
        }));
    });
}

/// Strips the machine-specific prefix of a dependency's source path
/// (`$CARGO_HOME/registry/src/<index>/oxc_parser-0.156.0/src/lib.rs` becomes
/// `oxc_parser-0.156.0/src/lib.rs`), so panic diagnostics are the same on every machine.
fn stable_source_path(file: &str) -> String {
    let file = file.replace('\\', "/");
    match file.split_once("/registry/src/") {
        Some((_, rest)) => rest
            .split_once('/')
            .map_or(rest, |(_, path)| path)
            .to_owned(),
        None => file,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc_span::SourceType;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn source_file_as(dir: &Path, rel: &str, contents: &[u8], class: FileClass) -> SourceFile {
        let abs_path = dir.join(rel);
        std::fs::create_dir_all(abs_path.parent().unwrap()).unwrap();
        std::fs::write(&abs_path, contents).unwrap();
        SourceFile {
            rel_path: rel.to_owned(),
            rel_path_os: rel.into(),
            abs_path,
            kind: SourceKind::from_path(Path::new(rel)).unwrap(),
            path_class: class,
            package_type: PackageType::CommonJs,
            size: u64::try_from(contents.len()).unwrap(),
        }
    }

    fn source_file(dir: &Path, rel: &str, contents: &[u8]) -> SourceFile {
        source_file_as(dir, rel, contents, FileClass::Source)
    }

    /// Processes with the default selection (source only).
    fn process(file: &SourceFile) -> FileReport {
        process_file(file, ClassSet::default())
    }

    fn one_diag(report: &FileReport) -> (&str, &str) {
        assert_eq!(report.diagnostics.len(), 1, "{report:?}");
        let diag = &report.diagnostics[0];
        assert_eq!(diag.path.as_deref(), Some(report.rel_path.as_str()));
        (diag.code.as_str(), diag.message.as_str())
    }

    const CLEAN: FileStatus = FileStatus::Parsed {
        statements: 1,
        syntax_errors: 0,
        recovered: false,
    };

    #[test]
    fn clean_files_parse_without_diagnostics() {
        let dir = tempfile::tempdir().unwrap();
        let src = b"const a = <b/>;\nmodule.exports = a;\n";
        let file = source_file(dir.path(), "a.js", src);
        let report = process(&file);
        assert_eq!(
            report.status,
            FileStatus::Parsed {
                statements: 2,
                syntax_errors: 0,
                recovered: false
            }
        );
        assert!(report.diagnostics.is_empty());
        assert!(!report.flow);
        assert_eq!(report.class, FileClass::Source);
        assert_eq!(report.parsed_bytes, u64::try_from(src.len()).unwrap());
    }

    #[test]
    fn recovered_errors_report_the_first_error_with_its_position() {
        let dir = tempfile::tempdir().unwrap();
        // Line-leading HTML-like comments are a recoverable error in modules (.mjs).
        let src = "const é = \"😀\";\n<!-- one\n<!-- two\n";
        let file = source_file(dir.path(), "a.mjs", src.as_bytes());
        let report = process(&file);
        assert_eq!(
            report.status,
            FileStatus::Parsed {
                statements: 1,
                syntax_errors: 2,
                recovered: true
            }
        );
        let (code, message) = one_diag(&report);
        assert_eq!(code, "parse/recovered");
        assert_eq!(
            message,
            "2:1: HTML comments are not allowed in modules (+1 more)"
        );
    }

    #[test]
    fn fatal_errors_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let file = source_file(dir.path(), "a.ts", b"class {{{ ]]] <<<");
        let report = process(&file);
        assert_eq!(report.status, FileStatus::Fatal, "{report:?}");
        let (code, message) = one_diag(&report);
        assert_eq!(code, "parse/fatal");
        assert!(message.starts_with("1:"), "{message}");
        assert!(!report.flow);
        assert_eq!(report.parsed_bytes, 17, "the file reached the parser");
    }

    #[test]
    fn content_checks_skip_files_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let cases: [(&str, Vec<u8>, &str); 3] = [
            ("latin1.js", b"var s = '\xe9';\n".to_vec(), "skip/not-utf8"),
            (
                "packed.js",
                format!("var a=[{}];", "1,".repeat(15_000)).into_bytes(),
                "skip/minified",
            ),
            (
                "deep.js",
                format!("x =\n{}1{};\n", "(\n".repeat(2_001), "\n)".repeat(2_001)).into_bytes(),
                "skip/too-deep",
            ),
        ];
        for (rel, contents, expected) in cases {
            let report = process(&source_file(dir.path(), rel, &contents));
            assert!(matches!(report.status, FileStatus::Skipped(_)), "{rel}");
            assert_eq!(one_diag(&report).0, expected, "{rel}");
            assert_eq!(report.parsed_bytes, 0, "{rel} never reached the parser");
        }
    }

    #[test]
    fn oversized_and_unreadable_files_are_skipped_without_parsing() {
        let dir = tempfile::tempdir().unwrap();
        // The size recorded at discovery decides; only the header is read.
        let mut big = source_file(dir.path(), "big.js", b"1;");
        big.size = content::MAX_FILE_BYTES + 1;
        let report = process(&big);
        assert_eq!(report.status, FileStatus::Skipped(SkipReason::TooLarge));
        assert_eq!(one_diag(&report).0, "skip/too-large");
        assert_eq!(report.parsed_bytes, 0);
        // A file that grew past the limit after discovery is caught after reading.
        let grown = source_file(
            dir.path(),
            "grown.js",
            &vec![b' '; usize::try_from(content::MAX_FILE_BYTES).unwrap() + 10],
        );
        let grown = SourceFile { size: 10, ..grown };
        assert_eq!(
            process(&grown).status,
            FileStatus::Skipped(SkipReason::TooLarge)
        );
        let gone = source_file_as(dir.path(), "gone.js", b"1;", FileClass::Test);
        std::fs::remove_file(&gone.abs_path).unwrap();
        for selection in [ClassSet::ALL, ClassSet::default()] {
            // Selected (parse) or not (classify only), an unreadable file is reported.
            let report = process_file(&gone, selection);
            assert_eq!(report.status, FileStatus::Skipped(SkipReason::IoError));
            assert_eq!(report.class, FileClass::Test);
            let (code, message) = one_diag(&report);
            assert_eq!(code, "skip/io-error");
            assert!(message.starts_with("cannot read file: "), "{message}");
        }
    }

    #[test]
    fn the_generated_marker_decides_the_final_class_from_the_one_read() {
        let dir = tempfile::tempdir().unwrap();
        let marked = b"// @generated by protoc\nexport const a = 1;\n";
        let schema = source_file(dir.path(), "src/schema.ts", marked);
        // Source by path, Generated by header: excluded by default...
        let report = process(&schema);
        assert_eq!(report.class, FileClass::Generated);
        assert_eq!(report.status, FileStatus::Excluded);
        assert!(report.diagnostics.is_empty());
        assert_eq!(report.parsed_bytes, 0);
        // ...and parsed when Generated is selected.
        let generated = ClassSet::default().with(FileClass::Generated);
        let report = process_file(&schema, generated);
        assert_eq!((report.class, report.status), (FileClass::Generated, CLEAN));
        // A test file is only classified: its header is read, but it is not parsed.
        let test = source_file_as(dir.path(), "test/gen.js", marked, FileClass::Test);
        let report = process(&test);
        assert_eq!(
            (report.class, report.status),
            (FileClass::Generated, FileStatus::Excluded)
        );
        let test = source_file_as(dir.path(), "test/a.js", b"x;\n", FileClass::Test);
        assert_eq!(process(&test).class, FileClass::Test);
        // Vendor is final: the file is not even opened.
        let mut vendor = source_file_as(dir.path(), "vendor/v.js", marked, FileClass::Vendor);
        std::fs::remove_file(&vendor.abs_path).unwrap();
        vendor.size = 0;
        let report = process(&vendor);
        assert_eq!(
            (report.class, report.status),
            (FileClass::Vendor, FileStatus::Excluded)
        );
        assert!(report.diagnostics.is_empty());
        // An oversized file is classified from its header, never read in full.
        let mut big = source_file(dir.path(), "src/big.ts", marked);
        big.size = content::MAX_FILE_BYTES + 1;
        let report = process(&big);
        assert_eq!(
            (report.class, report.status),
            (FileClass::Generated, FileStatus::Excluded)
        );
    }

    #[test]
    fn flow_files_parse_with_typescript_syntax() {
        let dir = tempfile::tempdir().unwrap();
        let cases: [(&str, &str); 3] = [
            (
                "pragma.js",
                "// @flow\nimport type { Config } from './Config';\n\
                 export function load<T>(name: string, config: Config): T {\n  return null;\n}\n",
            ),
            // No pragma, but type syntax: still Flow (parse-server style).
            (
                "types.js",
                "export type Options = { mount: string };\nclass Id { className: string; }\n",
            ),
            // Flow in React code needs JSX too.
            (
                "view.jsx",
                "// @flow\nconst View = (props: Props) => <div>{props.title}</div>;\n",
            ),
        ];
        for (rel, src) in cases {
            let report = process(&source_file(dir.path(), rel, src.as_bytes()));
            assert!(
                matches!(
                    report.status,
                    FileStatus::Parsed {
                        syntax_errors: 0,
                        ..
                    }
                ),
                "{rel}: {report:?}"
            );
            assert!(report.flow, "{rel}");
            assert!(report.diagnostics.is_empty(), "{rel}");
        }
        // Flow-only syntax (a type cast) is erased and the file then parses as TypeScript. The
        // blanks are reported, and keep every offset.
        let cast = "// @flow\nimport type { A } from './a';\nconst sorts = (where.sorts: any);\n";
        let report = process(&source_file(dir.path(), "cast.js", cast.as_bytes()));
        assert_eq!(
            report.status,
            FileStatus::Parsed {
                statements: 2,
                syntax_errors: 0,
                recovered: false
            }
        );
        assert!(report.flow);
        assert_eq!(report.flow_edits, 1);
        assert!(report.diagnostics.is_empty());
        // Files that needed no erasing report none.
        let plain = process(&source_file(
            dir.path(),
            "plain.js",
            b"// @flow\nconst x: number = 1;\n",
        ));
        assert!(plain.flow);
        assert_eq!(plain.flow_edits, 0);
        // Syntax no rule erases (component syntax runs, so it cannot be blanked): reported,
        // with where the parser stopped.
        let component = "// @flow\nimport type { A } from './a';\ncomponent Foo() {}\n";
        let report = process(&source_file(
            dir.path(),
            "component.js",
            component.as_bytes(),
        ));
        assert_eq!(report.status, FileStatus::Fatal);
        assert!(report.flow);
        assert_eq!(report.flow_edits, 0);
        let (code, message) = one_diag(&report);
        assert_eq!(code, "parse/fatal");
        assert!(
            message.starts_with("Flow syntax that TypeScript syntax does not cover: 3:"),
            "{message}"
        );
        // TypeScript files are never retried, and plain broken JavaScript stays a JS error.
        let report = process(&source_file(dir.path(), "broken.js", b"const x = ;\n"));
        assert_eq!(report.status, FileStatus::Fatal);
        assert!(!report.flow);
        assert_eq!(one_diag(&report).1, "1:11: Unexpected token");
    }

    /// JavaScript parses it; TypeScript syntax rejects it and says so at the start, where the
    /// repair rules would find a Flow shape if they were looking.
    fn js_ok_ts_broken(_: &Allocator, text: &str, kind: SourceType) -> ParseOutcome {
        PARSE_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let broken = kind.is_typescript();
        ParseOutcome {
            statements: usize::from(!broken && !text.is_empty()),
            syntax_errors: usize::from(broken),
            fatal: broken,
            flow: true,
            first_error: broken.then(|| crate::parse::SyntaxError {
                message: "Unexpected token".to_owned(),
                offset: Some(0),
            }),
        }
    }

    static PARSE_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    #[test]
    fn a_file_that_javascript_parses_is_never_repaired() {
        let dir = tempfile::tempdir().unwrap();
        // `...}` is the inexact-object marker: the repair would blank it if it ran.
        let src = "// @flow\ntype A = {a: number, ...};\n";
        let file = source_file(dir.path(), "valid.js", src.as_bytes());
        let before = PARSE_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        let report = process_file_with(&file, ClassSet::ALL, js_ok_ts_broken);
        let calls = PARSE_CALLS.load(std::sync::atomic::Ordering::SeqCst) - before;
        assert_eq!(
            report.status,
            FileStatus::Parsed {
                statements: 1,
                syntax_errors: 0,
                recovered: false
            }
        );
        assert_eq!(report.flow_edits, 0);
        // One JavaScript parse and one attempt per TypeScript flavor: no repair rounds.
        assert_eq!(calls, 3);
    }

    #[test]
    fn templates_with_a_js_extension_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let ejs =
            "\n(async () => {\n  window.clientVars = { prefix: <%-JSON.stringify(p)%> };\n})()\n";
        let report = process(&source_file(
            dir.path(),
            "indexBootstrap.js",
            ejs.as_bytes(),
        ));
        assert_eq!(report.status, FileStatus::Skipped(SkipReason::Template));
        let (code, message) = one_diag(&report);
        assert_eq!(code, "skip/template");
        assert_eq!(
            message,
            "3:33: template tag `<%` (a server-side template such as EJS, not JavaScript)"
        );
        // `<%` in a string elsewhere does not make a broken file a template.
        let broken = "const tag = '<%';\nconst x = ;\n";
        let report = process(&source_file(dir.path(), "broken.js", broken.as_bytes()));
        assert_eq!(report.status, FileStatus::Fatal);
        // Nor in a file that parses.
        let fine = "const tag = '<% x %>';\n";
        let report = process(&source_file(dir.path(), "fine.js", fine.as_bytes()));
        assert_eq!(report.status, CLEAN);
    }

    fn panicking_parser(_: &Allocator, _: &str, _: SourceType) -> ParseOutcome {
        panic!("injected parser failure")
    }

    #[test]
    fn a_parser_panic_becomes_a_panicked_report_for_that_file_only() {
        let dir = tempfile::tempdir().unwrap();
        let file = source_file(dir.path(), "boom.js", b"x;\n");
        let report = process_file_with(&file, ClassSet::default(), panicking_parser);
        assert_eq!(report.status, FileStatus::Panicked);
        assert_eq!(report.class, FileClass::Source);
        assert_eq!(report.parsed_bytes, 3);
        let (code, message) = one_diag(&report);
        assert_eq!(code, "parse/panicked");
        assert!(
            message.starts_with("parser panicked: injected parser failure (at "),
            "{message}"
        );
        assert!(
            message.contains("crates/jss-frontend/src/process.rs:"),
            "{message}"
        );
        assert!(!CAPTURING.with(Cell::get), "capture mode is switched off");
        // The next file on this thread parses normally.
        let next = source_file(dir.path(), "next.js", b"y;\n");
        assert_eq!(process(&next).status, CLEAN);
        // Same on a pool worker, where the parser runs on the worker itself.
        let pool = ParsePool::new(NonZeroUsize::new(1)).unwrap();
        let reports = pool.install(|| {
            [&file, &next].map(|file| {
                let parse: ParseFn = if file.rel_path == "boom.js" {
                    panicking_parser
                } else {
                    parse_with
                };
                process_file_with(file, ClassSet::default(), parse)
            })
        });
        assert_eq!(reports[0].status, FileStatus::Panicked);
        assert_eq!(reports[1].status, CLEAN);
    }

    #[test]
    fn panics_are_contained_and_the_allocator_is_replaced() {
        // Leave a used allocator behind on this thread.
        assert_eq!(isolated(|allocator| *allocator.alloc(7u64)), Ok(7));
        assert!(ALLOCATOR.with(|cell| {
            let allocator = cell.take();
            let present = allocator.is_some();
            cell.set(allocator);
            present
        }));
        let err = isolated(|_| -> u8 { panic!("boom in the parser") }).unwrap_err();
        assert!(err.starts_with("boom in the parser"), "{err}");
        assert!(err.contains("(at "), "the hook records the location: {err}");
        assert!(err.contains("process.rs:"), "{err}");
        // The panicked allocator was dropped, not put back...
        assert!(ALLOCATOR.with(|cell| {
            let allocator = cell.take();
            allocator.is_none()
        }));
        // ...and the next file gets a working one.
        assert_eq!(isolated(|allocator| *allocator.alloc(9u32)), Ok(9));
        assert!(!CAPTURING.with(Cell::get), "capture mode is switched off");
    }

    #[test]
    fn non_string_panic_payloads_are_described() {
        let err = isolated(|_| -> u8 { std::panic::panic_any(42u32) }).unwrap_err();
        assert!(err.starts_with("non-string panic payload"), "{err}");
    }

    #[test]
    fn registry_paths_are_made_machine_independent() {
        assert_eq!(
            stable_source_path(
                "/home/ci/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/oxc_parser-0.156.0/src/lexer/mod.rs"
            ),
            "oxc_parser-0.156.0/src/lexer/mod.rs"
        );
        assert_eq!(
            stable_source_path(r"C:\Users\x\.cargo\registry\src\idx\oxc_ast-0.156.0\src\a.rs"),
            "oxc_ast-0.156.0/src/a.rs"
        );
        assert_eq!(
            stable_source_path("crates/jss-frontend/src/process.rs"),
            "crates/jss-frontend/src/process.rs"
        );
    }

    #[test]
    fn reports_come_back_in_input_order_for_any_thread_count() {
        let dir = tempfile::tempdir().unwrap();
        let files: Vec<SourceFile> = (0..64)
            .map(|i| {
                let contents = match i % 4 {
                    0 => format!("export const v{i} = {i};\n").into_bytes(),
                    1 => format!("let = {i};\n").into_bytes(),
                    2 => [b"var s = '\xe9", i.to_string().as_bytes(), b"';\n"].concat(),
                    _ => format!("function f{i}() {{ return [{i}]; }}\n").into_bytes(),
                };
                let class = if i % 5 == 0 {
                    FileClass::Test
                } else {
                    FileClass::Source
                };
                source_file_as(dir.path(), &format!("f{i:02}.js"), &contents, class)
            })
            .collect();
        let one = ParsePool::new(NonZeroUsize::new(1))
            .unwrap()
            .process(&files, ClassSet::default());
        let four = ParsePool::new(NonZeroUsize::new(4)).unwrap();
        assert_eq!(four.threads(), 4);
        let parallel = four.process(&files, ClassSet::default());
        assert_eq!(one, parallel);
        let names: Vec<&str> = parallel.iter().map(|r| r.rel_path.as_str()).collect();
        let expected: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(names, expected);
        assert_eq!(parallel[0].status, FileStatus::Excluded, "a test file");
    }

    /// `[{a:` nesting `depth` levels deep (the prescan counts two levels per line).
    fn nested_literals(depth: usize) -> String {
        let mut nested = String::from("x =\n");
        for _ in 0..depth / 2 {
            nested.push_str("[{a:\n");
        }
        nested.push('1');
        for _ in 0..depth / 2 {
            nested.push_str("\n}]");
        }
        nested.push_str(";\n");
        nested
    }

    #[test]
    fn nesting_at_the_limit_parses_on_workers_and_on_small_stacks() {
        let dir = tempfile::tempdir().unwrap();
        let src = nested_literals(content::MAX_NESTING_DEPTH);
        let file = source_file(dir.path(), "deep.js", src.as_bytes());
        let pool = ParsePool::new(NonZeroUsize::new(1)).unwrap();
        let report = pool.process(std::slice::from_ref(&file), ClassSet::default());
        assert_eq!(report[0].status, CLEAN);
        // On an ordinary thread with a small stack (D2-PLAN-03), the parser gets a thread of
        // its own instead of overflowing this one.
        let report = std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || process(&file))
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(report.status, CLEAN);
    }

    #[test]
    fn deep_recursion_without_brackets_gets_a_large_enough_stack() {
        // Shapes the bracket prescan cannot see, which overflow any fixed stack once long
        // enough (D2-PLAN-02). Here they need a few MiB of parser stack, run from a thread
        // whose own budget is far smaller, so only the stack bound keeps them alive.
        let dir = tempfile::tempdir().unwrap();
        let cases: [(&str, String); 4] = [
            ("arrows.js", format!("f =\n{}1;\n", "a =>\n".repeat(20_000))),
            (
                "assign.js",
                format!("var a;\n{}1;\n", "a =\n".repeat(20_000)),
            ),
            ("labels.js", format!("{}x;\n", "a:\n".repeat(20_000))),
            (
                "generic.ts",
                format!(
                    "type T =\n{}B{};\n",
                    "A<\n".repeat(3_000),
                    "\n>".repeat(3_000)
                ),
            ),
        ];
        for (rel, src) in cases {
            let file = source_file(dir.path(), rel, src.as_bytes());
            let report = std::thread::Builder::new()
                .stack_size(256 * 1024)
                .spawn(move || {
                    let _ = STACK_BUDGET.try_with(|budget| budget.set(128 * 1024));
                    process(&file)
                })
                .unwrap()
                .join()
                .unwrap();
            assert!(
                matches!(report.status, FileStatus::Parsed { .. }),
                "{rel}: {report:?}"
            );
        }
    }

    #[test]
    fn the_stack_bound_covers_every_byte() {
        assert_eq!(parser_stack_bound(b""), STACK_BASE);
        assert_eq!(
            parser_stack_bound(b"a(b"),
            STACK_BASE + STACK_PER_BRACKET_BYTE + 2 * STACK_PER_BYTE
        );
        assert_eq!(
            parser_stack_bound(b"([{<"),
            STACK_BASE + 4 * STACK_PER_BRACKET_BYTE
        );
        // A typical file stays on the worker; the largest possible one needs its own thread.
        let typical = "function f(a) { return g(a, [1, 2]); }\n".repeat(2_000);
        assert!(parser_stack_bound(typical.as_bytes()) <= WORKER_STACK_BYTES);
        let max = vec![b'('; usize::try_from(content::MAX_FILE_BYTES).unwrap()];
        assert!(parser_stack_bound(&max) > WORKER_STACK_BYTES);
    }

    static ACTIVE_PARSES: AtomicUsize = AtomicUsize::new(0);
    static MOST_ACTIVE_PARSES: AtomicUsize = AtomicUsize::new(0);

    /// Parses for real, but slowly, and records how many such parses ever overlapped.
    fn slow_counting_parser(allocator: &Allocator, text: &str, kind: SourceType) -> ParseOutcome {
        let active = ACTIVE_PARSES.fetch_add(1, Ordering::SeqCst) + 1;
        MOST_ACTIVE_PARSES.fetch_max(active, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let outcome = parse_with(allocator, text, kind);
        ACTIVE_PARSES.fetch_sub(1, Ordering::SeqCst);
        outcome
    }

    #[test]
    fn files_that_need_more_than_a_worker_stack_are_parsed_one_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let src = "a;\n".repeat(140_000);
        assert!(parser_stack_bound(src.as_bytes()) > WORKER_STACK_BYTES);
        let files: Vec<SourceFile> = (0..4)
            .map(|i| source_file(dir.path(), &format!("big{i}.js"), src.as_bytes()))
            .collect();
        let reports: Vec<FileReport> = std::thread::scope(|scope| {
            let handles: Vec<_> = files
                .iter()
                .map(|file| {
                    scope.spawn(move || {
                        process_file_with(file, ClassSet::default(), slow_counting_parser)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for report in &reports {
            assert!(
                matches!(report.status, FileStatus::Parsed { .. }),
                "{report:?}"
            );
        }
        assert_eq!(MOST_ACTIVE_PARSES.load(Ordering::SeqCst), 1);
    }
}
