//! Parallel per-file processing: read, check and parse every file, each isolated from the others.
//!
//! - Files run on a dedicated rayon pool whose workers have [`WORKER_STACK_BYTES`] stacks.
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
use std::sync::Once;

use jss_core::content::{self, Skip};
use jss_core::{DiagCode, Diagnostic, FileClass, LineIndex, SkipReason, SourceFile};
use oxc_allocator::Allocator;
use rayon::prelude::*;

use crate::parse::{ParseOutcome, parse_with, source_type};

/// Stack size of each worker thread.
///
/// The parser recurses once per nesting level, and a stack overflow aborts the whole process
/// (it cannot be caught; oxc#21953). Workers therefore get a large stack, and
/// [`content::MAX_NESTING_DEPTH`] keeps the deepest files away from the parser altogether.
pub const WORKER_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Options for [`process_files`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessOptions {
    /// Worker threads. `None` uses rayon's default: `RAYON_NUM_THREADS` when set, otherwise the
    /// available parallelism.
    pub threads: Option<NonZeroUsize>,
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
    /// The file was not parsed.
    Skipped(SkipReason),
}

/// The outcome of processing one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReport {
    pub rel_path: String,
    pub class: FileClass,
    pub status: FileStatus,
    /// This file's diagnostics: one for every status except a clean parse.
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

/// A dedicated pool of parser workers. Build it once and reuse it for many batches.
#[derive(Debug)]
pub struct ParsePool {
    pool: rayon::ThreadPool,
}

impl ParsePool {
    /// Starts `threads` workers (see [`ProcessOptions::threads`] for the default).
    pub fn new(threads: Option<NonZeroUsize>) -> Result<Self, PoolError> {
        install_panic_hook();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads.map_or(0, NonZeroUsize::get))
            .stack_size(WORKER_STACK_BYTES)
            .thread_name(|index| format!("jss-parse-{index}"))
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

    /// Processes `files` in parallel; the reports are in input order.
    pub fn process(&self, files: &[SourceFile]) -> Vec<FileReport> {
        self.pool
            .install(|| files.par_iter().map(process_file).collect())
    }
}

/// Processes `files` on a new [`ParsePool`]; the reports are in input order.
pub fn process_files(
    files: &[SourceFile],
    options: &ProcessOptions,
) -> Result<Vec<FileReport>, PoolError> {
    Ok(ParsePool::new(options.threads)?.process(files))
}

/// Processes one file on the current thread: size check, read, content checks, parse. Never
/// panics: a panic anywhere in the pipeline becomes a `parse/panicked` report.
///
/// Prefer [`ParsePool`], whose workers have the large stacks deep files need.
pub fn process_file(file: &SourceFile) -> FileReport {
    match isolated(|allocator| analyze(file, allocator)) {
        Ok(report) => report,
        Err(panic) => FileReport {
            rel_path: file.rel_path.clone(),
            class: file.class,
            status: FileStatus::Panicked,
            diagnostics: vec![Diagnostic::at(
                DiagCode::ParsePanicked,
                file.rel_path.clone(),
                format!("parser panicked: {panic}"),
            )],
        },
    }
}

fn analyze(file: &SourceFile, allocator: &Allocator) -> FileReport {
    if let Err(skip) = content::check_size(file.size) {
        return skipped(file, skip);
    }
    let bytes = match read_capped(&file.abs_path, file.size) {
        Ok(bytes) => bytes,
        Err(err) => {
            return skipped(
                file,
                Skip::new(SkipReason::IoError, format!("cannot read file: {err}")),
            );
        }
    };
    let text = match content::check(&bytes) {
        Ok(text) => text,
        Err(skip) => return skipped(file, skip),
    };
    let outcome = parse_with(allocator, text, source_type(file.kind, file.package_type));
    parsed(file, text, &outcome)
}

/// Reads at most one byte more than [`content::MAX_FILE_BYTES`], so a file that grew after
/// discovery is still caught by the size check without reading all of it.
fn read_capped(path: &Path, size_hint: u64) -> io::Result<Vec<u8>> {
    let limit = content::MAX_FILE_BYTES.saturating_add(1);
    let mut bytes = Vec::with_capacity(usize::try_from(size_hint.min(limit)).unwrap_or(0));
    File::open(path)?.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn skipped(file: &SourceFile, skip: Skip) -> FileReport {
    FileReport {
        rel_path: file.rel_path.clone(),
        class: file.class,
        status: FileStatus::Skipped(skip.reason),
        diagnostics: vec![skip.into_diagnostic(file.rel_path.clone())],
    }
}

fn parsed(file: &SourceFile, text: &str, outcome: &ParseOutcome) -> FileReport {
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
        .map(|code| Diagnostic::at(code, file.rel_path.clone(), error_message(text, outcome)))
        .into_iter()
        .collect();
    FileReport {
        rel_path: file.rel_path.clone(),
        class: file.class,
        status,
        diagnostics,
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

thread_local! {
    /// This worker's allocator, reused (after `reset`) from one file to the next.
    static ALLOCATOR: Cell<Option<Allocator>> = const { Cell::new(None) };
    /// True while this thread processes a file: the panic hook records instead of printing.
    static CAPTURING: Cell<bool> = const { Cell::new(false) };
    /// Location of the last panic recorded on this thread.
    static PANIC_LOCATION: Cell<Option<String>> = const { Cell::new(None) };
}

/// Runs `work` with this thread's allocator, catching any panic. On a panic the allocator is
/// dropped (the next call starts with a fresh one) and the panic is described as a string.
fn isolated<T>(work: impl FnOnce(&Allocator) -> T) -> Result<T, String> {
    install_panic_hook();
    let mut allocator = ALLOCATOR
        .try_with(Cell::take)
        .ok()
        .flatten()
        .unwrap_or_default();
    allocator.reset();
    let result = {
        let _capture = Capture::start();
        panic::catch_unwind(AssertUnwindSafe(|| work(&allocator)))
    };
    match result {
        Ok(value) => {
            let _ = ALLOCATOR.try_with(|cell| cell.set(Some(allocator)));
            Ok(value)
        }
        Err(payload) => {
            // The arena may be in any state after a panic: never reuse it.
            drop(allocator);
            Err(describe_panic(payload.as_ref()))
        }
    }
}

/// Marks this thread as processing a file for as long as it lives.
struct Capture;

impl Capture {
    fn start() -> Self {
        let _ = CAPTURING.try_with(|capturing| capturing.set(true));
        let _ = PANIC_LOCATION.try_with(Cell::take);
        Capture
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let _ = CAPTURING.try_with(|capturing| capturing.set(false));
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
/// it only intercepts panics inside [`isolated`], it never needs to be uninstalled, and
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
    use jss_core::{PackageType, SourceKind};

    fn source_file(dir: &Path, rel: &str, contents: &[u8]) -> SourceFile {
        let abs_path = dir.join(rel);
        std::fs::create_dir_all(abs_path.parent().unwrap()).unwrap();
        std::fs::write(&abs_path, contents).unwrap();
        SourceFile {
            rel_path: rel.to_owned(),
            rel_path_os: rel.into(),
            abs_path,
            kind: SourceKind::from_path(Path::new(rel)).unwrap(),
            class: FileClass::Source,
            package_type: PackageType::CommonJs,
            size: u64::try_from(contents.len()).unwrap(),
        }
    }

    fn one_diag(report: &FileReport) -> (&str, &str) {
        assert_eq!(report.diagnostics.len(), 1, "{report:?}");
        let diag = &report.diagnostics[0];
        assert_eq!(diag.path.as_deref(), Some(report.rel_path.as_str()));
        (diag.code.as_str(), diag.message.as_str())
    }

    #[test]
    fn clean_files_parse_without_diagnostics() {
        let dir = tempfile::tempdir().unwrap();
        let file = source_file(
            dir.path(),
            "a.js",
            b"const a = <b/>;\nmodule.exports = a;\n",
        );
        let report = process_file(&file);
        assert_eq!(
            report.status,
            FileStatus::Parsed {
                statements: 2,
                syntax_errors: 0,
                recovered: false
            }
        );
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn recovered_errors_report_the_first_error_with_its_position() {
        let dir = tempfile::tempdir().unwrap();
        // Line-leading HTML-like comments are a recoverable error in modules (.mjs).
        let src = "const é = \"😀\";\n<!-- one\n<!-- two\n";
        let file = source_file(dir.path(), "a.mjs", src.as_bytes());
        let report = process_file(&file);
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
        let report = process_file(&file);
        assert_eq!(report.status, FileStatus::Fatal, "{report:?}");
        let (code, message) = one_diag(&report);
        assert_eq!(code, "parse/fatal");
        assert!(message.starts_with("1:"), "{message}");
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
            let report = process_file(&source_file(dir.path(), rel, &contents));
            assert!(matches!(report.status, FileStatus::Skipped(_)), "{rel}");
            assert_eq!(one_diag(&report).0, expected, "{rel}");
        }
    }

    #[test]
    fn oversized_and_unreadable_files_are_skipped_without_parsing() {
        let dir = tempfile::tempdir().unwrap();
        // The size recorded at discovery decides; the file is not even opened.
        let mut big = source_file(dir.path(), "big.js", b"1;");
        big.size = content::MAX_FILE_BYTES + 1;
        let report = process_file(&big);
        assert_eq!(report.status, FileStatus::Skipped(SkipReason::TooLarge));
        assert_eq!(one_diag(&report).0, "skip/too-large");
        // A file that grew past the limit after discovery is caught after reading.
        let grown = source_file(
            dir.path(),
            "grown.js",
            &vec![b' '; usize::try_from(content::MAX_FILE_BYTES).unwrap() + 10],
        );
        let grown = SourceFile { size: 10, ..grown };
        assert_eq!(
            process_file(&grown).status,
            FileStatus::Skipped(SkipReason::TooLarge)
        );
        let mut gone = source_file(dir.path(), "gone.js", b"1;");
        std::fs::remove_file(&gone.abs_path).unwrap();
        gone.class = FileClass::Test;
        let report = process_file(&gone);
        assert_eq!(report.status, FileStatus::Skipped(SkipReason::IoError));
        assert_eq!(report.class, FileClass::Test);
        let (code, message) = one_diag(&report);
        assert_eq!(code, "skip/io-error");
        assert!(message.starts_with("cannot read file: "), "{message}");
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
                source_file(dir.path(), &format!("f{i:02}.js"), &contents)
            })
            .collect();
        let one = process_files(
            &files,
            &ProcessOptions {
                threads: NonZeroUsize::new(1),
            },
        )
        .unwrap();
        let four = ParsePool::new(NonZeroUsize::new(4)).unwrap();
        assert_eq!(four.threads(), 4);
        let parallel = four.process(&files);
        assert_eq!(one, parallel);
        let names: Vec<&str> = parallel.iter().map(|r| r.rel_path.as_str()).collect();
        let expected: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(names, expected);
    }

    #[test]
    fn workers_parse_nesting_just_under_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let depth = content::MAX_NESTING_DEPTH;
        let mut nested = String::from("x =\n");
        for _ in 0..depth / 2 {
            nested.push_str("[{a:\n");
        }
        nested.push('1');
        for _ in 0..depth / 2 {
            nested.push_str("\n}]");
        }
        nested.push_str(";\n");
        let file = source_file(dir.path(), "deep.js", nested.as_bytes());
        let pool = ParsePool::new(NonZeroUsize::new(1)).unwrap();
        let report = pool.process(std::slice::from_ref(&file));
        assert_eq!(
            report[0].status,
            FileStatus::Parsed {
                statements: 1,
                syntax_errors: 0,
                recovered: false
            }
        );
    }
}
