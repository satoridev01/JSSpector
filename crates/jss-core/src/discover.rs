//! File discovery: lists the JS/TS files under a scan root, contained to the root, deduplicated,
//! classified by path and sorted.
//!
//! - The walk uses the `ignore` crate's parallel walker on as many threads as the current rayon
//!   pool has (run [`discover`] inside a dedicated pool's `install` to bound them). `.gitignore`
//!   files inside the root are honored (whether or not the tree is a git checkout), hidden files
//!   and directories are skipped, and symlinks are never followed by the walker.
//! - Ignore files outside the root (parent directories, the user's global gitignore,
//!   `.git/info/exclude`) are deliberately NOT consulted, so the result depends only on the
//!   tree under the root.
//! - A symlinked file is accepted only when its canonical target is inside the root; otherwise
//!   it is reported as `skip/symlink-outside-root`. A file reachable through several paths is
//!   kept once: under its real path when the walk reaches it, otherwise under the smallest
//!   relative path of the links to it. Either way it is classified by where it really lives,
//!   so symlinks cannot change what is analyzed.
//! - Discovery never opens source files: it only reads directory entries, file metadata and
//!   `package.json` files. The one check that needs a file's content (the `@generated` marker,
//!   see [`SourceFile::work`]) happens when the frontend reads the file anyway.
//! - Output is sorted by relative path bytes, so it does not depend on directory order or on the
//!   number of threads.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use ignore::{ParallelVisitor, ParallelVisitorBuilder, WalkBuilder, WalkState};

use crate::classify::{self, ClassSet, FileClass};
use crate::diag::{self, DiagCode, Diagnostic};
use crate::package_type::{PackageType, PackageTypes};

/// The kind of JS/TS file, from its extension (case-insensitive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SourceKind {
    Js,
    Jsx,
    Mjs,
    Cjs,
    Ts,
    Tsx,
    Mts,
    Cts,
}

/// Suffixes of TypeScript declaration files, which contain no executable code.
const DECLARATION_SUFFIXES: [&str; 3] = [".d.ts", ".d.mts", ".d.cts"];

impl SourceKind {
    /// Every kind, in declaration order.
    pub const ALL: [SourceKind; 8] = [
        SourceKind::Js,
        SourceKind::Jsx,
        SourceKind::Mjs,
        SourceKind::Cjs,
        SourceKind::Ts,
        SourceKind::Tsx,
        SourceKind::Mts,
        SourceKind::Cts,
    ];

    /// The kind of a file, from its name. `None` for anything else, including TypeScript
    /// declaration files (`.d.ts`, `.d.mts`, `.d.cts`), which contain no executable code.
    pub fn from_file_name(name: &OsStr) -> Option<SourceKind> {
        let name = name.to_string_lossy().to_ascii_lowercase();
        if DECLARATION_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
        {
            return None;
        }
        let (_, ext) = name.rsplit_once('.')?;
        SourceKind::ALL
            .into_iter()
            .find(|kind| kind.extension() == ext)
    }

    /// The kind of the file at `path`, from its file name.
    pub fn from_path(path: &Path) -> Option<SourceKind> {
        path.file_name().and_then(SourceKind::from_file_name)
    }

    /// The lowercase extension, without the dot.
    pub const fn extension(self) -> &'static str {
        match self {
            SourceKind::Js => "js",
            SourceKind::Jsx => "jsx",
            SourceKind::Mjs => "mjs",
            SourceKind::Cjs => "cjs",
            SourceKind::Ts => "ts",
            SourceKind::Tsx => "tsx",
            SourceKind::Mts => "mts",
            SourceKind::Cts => "cts",
        }
    }

    /// Whether this is a JavaScript kind (`.js`, `.jsx`, `.mjs`, `.cjs`).
    pub const fn is_javascript(self) -> bool {
        matches!(
            self,
            SourceKind::Js | SourceKind::Jsx | SourceKind::Mjs | SourceKind::Cjs
        )
    }
}

/// Whether `name` is a TypeScript declaration file name (`.d.ts`, `.d.mts`, `.d.cts`).
pub fn is_declaration_file(name: &OsStr) -> bool {
    let name = name.to_string_lossy().to_ascii_lowercase();
    DECLARATION_SUFFIXES
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

/// One discovered file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    /// Root-relative, `/`-separated path. Lossy for non-UTF-8 names, but stable. This is the
    /// file's name in every report and the sort key.
    pub rel_path: String,
    /// The exact root-relative path.
    pub rel_path_os: PathBuf,
    /// Canonical absolute path (the target, for a symlink), used for all IO.
    pub abs_path: PathBuf,
    pub kind: SourceKind,
    /// The class from the file's real location alone ([`classify::classify_path`]). Unless it is
    /// Generated or Vendor, the file's header may still make it Generated: see
    /// [`SourceFile::work`].
    pub path_class: FileClass,
    pub package_type: PackageType,
    /// Size in bytes at discovery time.
    pub size: u64,
}

/// What processing a discovered file takes, given the classes selected for analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    /// Read the file and parse it, unless its header makes it a class that is not selected.
    Parse,
    /// Read only the file's header, to classify it ([`classify::classify`]); never parse it.
    Classify,
    /// Nothing: the path class is final and not selected.
    Exclude,
}

impl SourceFile {
    /// The work this file needs when `selection` holds the classes to analyze. Every file whose
    /// header can change its class is read (in full or just the header), so final classes, and
    /// counts of them, do not depend on the selection.
    pub fn work(&self, selection: ClassSet) -> Work {
        let header_matters = classify::header_can_change(self.path_class);
        if selection.contains(self.path_class)
            || (header_matters && selection.contains(FileClass::Generated))
        {
            Work::Parse
        } else if header_matters {
            Work::Classify
        } else {
            Work::Exclude
        }
    }
}

/// Discovery options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverOptions {
    /// Honor `.gitignore` files inside the root. Default: true.
    pub respect_gitignore: bool,
}

impl Default for DiscoverOptions {
    fn default() -> Self {
        Self {
            respect_gitignore: true,
        }
    }
}

/// The result of [`discover`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// Canonical root directory. For a single-file root, its parent directory.
    pub root: PathBuf,
    /// Whether the root given was a single file.
    pub single_file: bool,
    /// Every candidate file, whatever its class, sorted by `rel_path` bytes.
    pub files: Vec<SourceFile>,
    /// One diagnostic per entry that could not be considered, sorted: symlinks leaving the
    /// root, unresolvable links, non-regular files with source names, unreadable directories.
    pub diagnostics: Vec<Diagnostic>,
    /// TypeScript declaration files seen and not listed (they contain no executable code).
    pub declaration_files: usize,
}

impl Discovery {
    /// The classes to analyze when `include` was requested: a single-file root is analyzed
    /// whatever its class, since it was named explicitly.
    pub fn selection(&self, include: ClassSet) -> ClassSet {
        if self.single_file {
            ClassSet::ALL
        } else {
            include
        }
    }
}

/// A problem with the root itself. Problems below the root are diagnostics instead.
#[derive(Debug)]
pub enum DiscoverError {
    /// The root does not exist or cannot be read.
    Io { path: PathBuf, source: io::Error },
    /// The root is a file but not a JS/TS source file (or is a declaration file).
    UnsupportedFile(PathBuf),
    /// The root is neither a regular file nor a directory.
    NotFileOrDirectory(PathBuf),
}

impl fmt::Display for DiscoverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoverError::Io { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            DiscoverError::UnsupportedFile(path) => write!(
                f,
                "unsupported file type: {} (expected .js, .jsx, .mjs, .cjs, .ts, .tsx, .mts or \
                 .cts, and not a .d.ts declaration file)",
                path.display()
            ),
            DiscoverError::NotFileOrDirectory(path) => {
                write!(f, "not a file or directory: {}", path.display())
            }
        }
    }
}

impl std::error::Error for DiscoverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DiscoverError::Io { source, .. } => Some(source),
            DiscoverError::UnsupportedFile(_) | DiscoverError::NotFileOrDirectory(_) => None,
        }
    }
}

/// Discovers the JS/TS files under `root`, a directory or a single file. For a single file, the
/// root becomes its parent directory and the result holds that one file; its package type comes
/// from the nearest `package.json` up to the enclosing git work tree (see
/// [`package_type_search_root`]), as a directory scan of that work tree would find it.
pub fn discover(root: &Path, options: &DiscoverOptions) -> Result<Discovery, DiscoverError> {
    let meta = fs::metadata(root).map_err(io_error(root))?;
    if meta.is_dir() {
        discover_dir(root, options)
    } else if meta.is_file() {
        discover_file(root)
    } else {
        Err(DiscoverError::NotFileOrDirectory(root.to_path_buf()))
    }
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> DiscoverError + '_ {
    move |source| DiscoverError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn discover_dir(root: &Path, options: &DiscoverOptions) -> Result<Discovery, DiscoverError> {
    let canonical = fs::canonicalize(root).map_err(io_error(root))?;
    // An unreadable root is an error on the root itself, not a diagnostic.
    fs::read_dir(&canonical).map_err(io_error(root))?;

    let mut walker = WalkBuilder::new(&canonical);
    walker
        // Start from no filters, then enable exactly what we want.
        .standard_filters(false)
        .hidden(true)
        .git_ignore(options.respect_gitignore)
        .require_git(false)
        .follow_links(false)
        .threads(rayon::current_num_threads());
    let found = Mutex::new(Found::default());
    walker.build_parallel().visit(&mut VisitorBuilder {
        root: &canonical,
        sink: &found,
    });
    let found = found.into_inner().unwrap_or_else(PoisonError::into_inner);
    Ok(finish(canonical.clone(), &canonical, false, found))
}

fn discover_file(root: &Path) -> Result<Discovery, DiscoverError> {
    let name = root
        .file_name()
        .ok_or_else(|| DiscoverError::NotFileOrDirectory(root.to_path_buf()))?;
    let kind = SourceKind::from_file_name(name)
        .ok_or_else(|| DiscoverError::UnsupportedFile(root.to_path_buf()))?;
    // Unreadable is an error on the root itself.
    fs::File::open(root).map_err(io_error(root))?;
    let parent = root
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let canonical = fs::canonicalize(parent).map_err(io_error(root))?;

    let path = canonical.join(name);
    let rel = PathBuf::from(name);
    let meta = fs::symlink_metadata(&path).map_err(io_error(root))?;
    let mut found = Found::default();
    if meta.file_type().is_symlink() {
        found.symlink(&canonical, &path, &rel, Some(kind));
    } else {
        found.files.push(FoundFile {
            canonical: path,
            rel,
            kind,
            direct: true,
            size: meta.len(),
        });
    }
    let search_root = package_type_search_root(&canonical);
    Ok(finish(canonical, &search_root, true, found))
}

/// Where the `package.json` search of a single-file root may go: the top of the enclosing git
/// work tree (the nearest ancestor holding `.git`), or the filesystem root outside one.
pub fn package_type_search_root(dir: &Path) -> PathBuf {
    dir.ancestors()
        .find(|ancestor| ancestor.join(".git").exists())
        .or_else(|| dir.ancestors().last())
        .unwrap_or(dir)
        .to_path_buf()
}

/// What the walk found, merged from every walker thread.
#[derive(Debug, Default)]
struct Found {
    files: Vec<FoundFile>,
    diagnostics: Vec<Diagnostic>,
    declaration_files: usize,
}

/// A file reached by the walk, directly or through a symlink.
#[derive(Debug)]
struct FoundFile {
    /// Canonical absolute path: the identity used to deduplicate.
    canonical: PathBuf,
    /// Root-relative path it was reached by.
    rel: PathBuf,
    kind: SourceKind,
    /// Reached by its real path rather than through a symlink.
    direct: bool,
    size: u64,
}

impl Found {
    fn append(&mut self, other: &mut Found) {
        self.files.append(&mut other.files);
        self.diagnostics.append(&mut other.diagnostics);
        self.declaration_files += std::mem::take(&mut other.declaration_files);
    }

    fn report(&mut self, code: DiagCode, rel: &Path, message: impl Into<String>) {
        self.diagnostics
            .push(Diagnostic::at(code, rel_path_string(rel), message));
    }

    /// One walker entry under `root`.
    fn entry(&mut self, root: &Path, entry: &ignore::DirEntry) {
        if entry.depth() == 0 {
            return;
        }
        let Some(file_type) = entry.file_type() else {
            return;
        };
        if file_type.is_dir() {
            return;
        }
        let path = entry.path();
        let Ok(rel) = path.strip_prefix(root) else {
            return;
        };
        let kind = SourceKind::from_file_name(entry.file_name());
        if file_type.is_symlink() {
            self.symlink(root, path, rel, kind);
            return;
        }
        let Some(kind) = kind else {
            if file_type.is_file() && is_declaration_file(entry.file_name()) {
                self.declaration_files += 1;
            }
            return;
        };
        if !file_type.is_file() {
            // A FIFO, socket or device named like a source file: never opened.
            self.report(DiagCode::SkipIoError, rel, "not a regular file");
            return;
        }
        match entry.metadata() {
            Ok(meta) => self.files.push(FoundFile {
                canonical: path.to_path_buf(),
                rel: rel.to_path_buf(),
                kind,
                direct: true,
                size: meta.len(),
            }),
            Err(err) => self.report(
                DiagCode::SkipIoError,
                rel,
                format!("cannot read file metadata: {}", error_message(&err)),
            ),
        }
    }

    /// Handles a symlink at `path` (`rel` relative to `root`). `kind` is set when the link's own
    /// name is a JS/TS file name.
    fn symlink(&mut self, root: &Path, path: &Path, rel: &Path, kind: Option<SourceKind>) {
        let target = match fs::canonicalize(path) {
            Ok(target) => target,
            Err(err) => {
                if kind.is_some() {
                    self.report(
                        DiagCode::SkipIoError,
                        rel,
                        format!("cannot resolve symlink: {err}"),
                    );
                }
                return;
            }
        };
        if !target.starts_with(root) {
            // Report links that stand for source files, and directory links whose contents
            // are therefore not scanned. The target is not named: it may be outside anything
            // the report should reveal, and it would make output machine-dependent.
            if kind.is_some() || target.is_dir() {
                self.report(
                    DiagCode::SkipSymlinkOutsideRoot,
                    rel,
                    "symlink resolves outside the scan root; not followed",
                );
            }
            return;
        }
        // Links to directories inside the root need nothing: the walker visits their targets
        // directly.
        let Some(kind) = kind else {
            return;
        };
        match fs::metadata(&target) {
            Ok(meta) if meta.is_file() => self.files.push(FoundFile {
                canonical: target,
                rel: rel.to_path_buf(),
                kind,
                direct: false,
                size: meta.len(),
            }),
            Ok(meta) if meta.is_dir() => {}
            // A FIFO, socket or device behind a source-named link: never opened.
            Ok(_) => self.report(
                DiagCode::SkipIoError,
                rel,
                "symlink target is not a regular file",
            ),
            Err(err) => self.report(
                DiagCode::SkipIoError,
                rel,
                format!("cannot read symlink target: {err}"),
            ),
        }
    }

    fn walk_error(&mut self, root: &Path, err: &ignore::Error) {
        let path = error_path(err)
            .and_then(|path| path.strip_prefix(root).ok())
            .map(rel_path_string)
            .filter(|rel| !rel.is_empty());
        self.diagnostics.push(Diagnostic::new(
            DiagCode::SkipIoError,
            path,
            error_message(err),
        ));
    }
}

/// Creates one [`Visitor`] per walker thread.
struct VisitorBuilder<'s> {
    root: &'s Path,
    sink: &'s Mutex<Found>,
}

impl<'s> ParallelVisitorBuilder<'s> for VisitorBuilder<'s> {
    fn build(&mut self) -> Box<dyn ParallelVisitor + 's> {
        Box::new(Visitor {
            root: self.root,
            sink: self.sink,
            found: Found::default(),
        })
    }
}

/// Collects one walker thread's findings, and hands them over when the thread is done.
struct Visitor<'s> {
    root: &'s Path,
    sink: &'s Mutex<Found>,
    found: Found,
}

impl ParallelVisitor for Visitor<'_> {
    fn visit(&mut self, entry: Result<ignore::DirEntry, ignore::Error>) -> WalkState {
        match entry {
            Ok(entry) => self.found.entry(self.root, &entry),
            Err(err) => self.found.walk_error(self.root, &err),
        }
        WalkState::Continue
    }
}

impl Drop for Visitor<'_> {
    fn drop(&mut self) {
        self.sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .append(&mut self.found);
    }
}

/// A file reachable under one canonical path, with the path that names it.
struct Candidate {
    rel_path: String,
    rel_path_os: PathBuf,
    kind: SourceKind,
    direct: bool,
    size: u64,
}

impl Candidate {
    /// The name a file keeps when it is reached several times: its real path if the walk
    /// reached it, otherwise the smallest link path. Independent of the order of discovery.
    fn wins_over(&self, other: &Candidate) -> bool {
        (!self.direct, &self.rel_path, &self.rel_path_os)
            < (!other.direct, &other.rel_path, &other.rel_path_os)
    }
}

/// Deduplicates, classifies, resolves package types and sorts what the walk found.
/// `package_root` bounds the `package.json` search.
fn finish(root: PathBuf, package_root: &Path, single_file: bool, found: Found) -> Discovery {
    let Found {
        files: found_files,
        mut diagnostics,
        declaration_files,
    } = found;
    // Keyed by canonical path, which deduplicates files reachable through symlinks.
    let mut candidates: BTreeMap<PathBuf, Candidate> = BTreeMap::new();
    for file in found_files {
        let candidate = Candidate {
            rel_path: rel_path_string(&file.rel),
            rel_path_os: file.rel,
            kind: file.kind,
            direct: file.direct,
            size: file.size,
        };
        match candidates.get_mut(&file.canonical) {
            Some(existing) => {
                if candidate.wins_over(existing) {
                    *existing = candidate;
                }
            }
            None => {
                candidates.insert(file.canonical, candidate);
            }
        }
    }

    let package_dir = |canonical: &Path| {
        canonical
            .parent()
            .and_then(|dir| dir.strip_prefix(package_root).ok())
            .map(Path::to_path_buf)
    };
    let mut package_types = PackageTypes::new(package_root);
    let dirs: Vec<PathBuf> = candidates.keys().filter_map(|c| package_dir(c)).collect();
    package_types.resolve_all(dirs.iter().map(PathBuf::as_path));

    let mut files: Vec<SourceFile> = candidates
        .into_iter()
        .map(|(canonical, candidate)| {
            // Classify by where the file really lives, whatever link named it.
            let real_rel = canonical
                .strip_prefix(&root)
                .map(rel_path_string)
                .unwrap_or_else(|_| candidate.rel_path.clone());
            let package_type = package_dir(&canonical)
                .map(|dir| package_types.for_dir(&dir))
                .unwrap_or_default();
            SourceFile {
                path_class: classify::classify_path(&real_rel),
                rel_path: candidate.rel_path,
                rel_path_os: candidate.rel_path_os,
                abs_path: canonical,
                kind: candidate.kind,
                package_type,
                size: candidate.size,
            }
        })
        .collect();
    files.sort_by(|a, b| {
        a.rel_path
            .cmp(&b.rel_path)
            .then_with(|| a.rel_path_os.cmp(&b.rel_path_os))
    });
    diag::sort(&mut diagnostics);
    Discovery {
        root,
        single_file,
        files,
        diagnostics,
        declaration_files,
    }
}

/// The path a walker error is about, if any.
fn error_path(err: &ignore::Error) -> Option<&Path> {
    match err {
        ignore::Error::WithPath { path, .. } => Some(path),
        ignore::Error::WithDepth { err, .. } | ignore::Error::WithLineNumber { err, .. } => {
            error_path(err)
        }
        ignore::Error::Partial(errs) => errs.iter().find_map(error_path),
        ignore::Error::Loop { child, .. } => Some(child),
        _ => None,
    }
}

/// A walker error message without absolute paths (the diagnostic carries the relative path).
fn error_message(err: &ignore::Error) -> String {
    match err {
        ignore::Error::Partial(errs) => errs
            .iter()
            .map(error_message)
            .collect::<Vec<_>>()
            .join("; "),
        ignore::Error::WithLineNumber { line, err } => {
            format!("line {line}: {}", error_message(err))
        }
        ignore::Error::WithPath { err, .. } | ignore::Error::WithDepth { err, .. } => {
            error_message(err)
        }
        ignore::Error::Loop { .. } => "symlink loop".to_owned(),
        ignore::Error::Io(err) => innermost_message(err),
        other => other.to_string(),
    }
}

/// The message of the innermost error in `err`'s source chain. The walker wraps OS errors in
/// errors whose message repeats the absolute path; the OS error alone does not.
fn innermost_message(err: &io::Error) -> String {
    let mut innermost: &dyn std::error::Error = err;
    while let Some(source) = innermost.source() {
        innermost = source;
    }
    innermost.to_string()
}

/// A relative path as a `/`-separated string, lossy for non-UTF-8 components.
pub fn rel_path_string(rel: &Path) -> String {
    let mut out = String::new();
    for component in rel.components() {
        let part = match component {
            Component::Normal(part) => part.to_string_lossy(),
            Component::ParentDir => "..".into(),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => continue,
        };
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, contents: &[u8]) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn rel_paths(discovery: &Discovery) -> Vec<&str> {
        discovery
            .files
            .iter()
            .map(|file| file.rel_path.as_str())
            .collect()
    }

    fn file<'a>(discovery: &'a Discovery, rel: &str) -> &'a SourceFile {
        discovery
            .files
            .iter()
            .find(|file| file.rel_path == rel)
            .unwrap_or_else(|| panic!("{rel} not discovered: {:?}", rel_paths(discovery)))
    }

    fn diags(discovery: &Discovery) -> Vec<(&str, &str, &str)> {
        discovery
            .diagnostics
            .iter()
            .map(|d| {
                (
                    d.path.as_deref().unwrap(),
                    d.code.as_str(),
                    d.message.as_str(),
                )
            })
            .collect()
    }

    #[test]
    fn source_kinds_come_from_extensions() {
        let kind = |name: &str| SourceKind::from_file_name(OsStr::new(name));
        assert_eq!(kind("a.js"), Some(SourceKind::Js));
        assert_eq!(kind("a.JSX"), Some(SourceKind::Jsx));
        assert_eq!(kind("a.mjs"), Some(SourceKind::Mjs));
        assert_eq!(kind("a.cjs"), Some(SourceKind::Cjs));
        assert_eq!(kind("a.Ts"), Some(SourceKind::Ts));
        assert_eq!(kind("a.tsx"), Some(SourceKind::Tsx));
        assert_eq!(kind("a.mts"), Some(SourceKind::Mts));
        assert_eq!(kind("a.cts"), Some(SourceKind::Cts));
        assert_eq!(kind("a.d.ts"), None);
        assert_eq!(kind("a.D.MTS"), None);
        assert_eq!(kind("a.d.cts"), None);
        assert_eq!(kind("a.json"), None);
        assert_eq!(kind("Makefile"), None);
        assert_eq!(kind("a.vue"), None);
        assert!(is_declaration_file(OsStr::new("index.D.ts")));
        assert!(!is_declaration_file(OsStr::new("index.ts")));
        let js: Vec<SourceKind> = SourceKind::ALL
            .into_iter()
            .filter(|kind| kind.is_javascript())
            .collect();
        assert_eq!(
            js,
            [
                SourceKind::Js,
                SourceKind::Jsx,
                SourceKind::Mjs,
                SourceKind::Cjs
            ]
        );
    }

    #[test]
    fn walks_classifies_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for rel in [
            "src/b.js",
            "src/a.ts",
            "src/App.jsx",
            "src/a.test.js",
            "test/helper.js",
            "node_modules/m/index.js",
            "dist/out.js",
            "docs/site.js",
            "examples/e.mjs",
            "src/types.d.ts",
            "lib/index.d.mts",
            "src/style.css",
            "README.md",
            ".hidden/h.js",
            "src/.eslintrc.js",
            "ignored/i.js",
            "src/also-ignored.log.js",
        ] {
            write(root, rel, b"export {};\n");
        }
        write(root, "src/gen.ts", b"// @generated by a tool\nexport {};\n");
        write(root, ".gitignore", b"ignored/\n*.log.js\n");

        let discovery = discover(root, &DiscoverOptions::default()).unwrap();
        assert!(!discovery.single_file);
        assert_eq!(discovery.root, fs::canonicalize(root).unwrap());
        assert_eq!(
            rel_paths(&discovery),
            [
                "dist/out.js",
                "docs/site.js",
                "examples/e.mjs",
                "node_modules/m/index.js",
                "src/App.jsx",
                "src/a.test.js",
                "src/a.ts",
                "src/b.js",
                "src/gen.ts",
                "test/helper.js",
            ]
        );
        assert!(
            discovery.diagnostics.is_empty(),
            "{:?}",
            discovery.diagnostics
        );
        assert_eq!(discovery.declaration_files, 2);
        let class = |rel: &str| file(&discovery, rel).path_class;
        assert_eq!(class("dist/out.js"), FileClass::Generated);
        assert_eq!(class("docs/site.js"), FileClass::Docs);
        assert_eq!(class("examples/e.mjs"), FileClass::Example);
        assert_eq!(class("node_modules/m/index.js"), FileClass::Vendor);
        assert_eq!(class("src/App.jsx"), FileClass::Source);
        assert_eq!(class("src/a.test.js"), FileClass::Test);
        // Discovery classifies by path only; the marker is checked when the file is read.
        assert_eq!(class("src/gen.ts"), FileClass::Source);
        assert_eq!(class("test/helper.js"), FileClass::Test);

        let app = file(&discovery, "src/App.jsx");
        assert_eq!(app.kind, SourceKind::Jsx);
        assert_eq!(app.size, 11);
        assert_eq!(app.rel_path_os, Path::new("src").join("App.jsx"));
        assert_eq!(app.abs_path, discovery.root.join("src").join("App.jsx"));
    }

    #[test]
    fn work_depends_on_the_selection() {
        let file = |path_class| SourceFile {
            rel_path: "a.js".to_owned(),
            rel_path_os: "a.js".into(),
            abs_path: "/a.js".into(),
            kind: SourceKind::Js,
            path_class,
            package_type: PackageType::CommonJs,
            size: 1,
        };
        let default = ClassSet::default();
        assert_eq!(file(FileClass::Source).work(default), Work::Parse);
        // The header can still make a test file Generated: read it, but do not parse it.
        assert_eq!(file(FileClass::Test).work(default), Work::Classify);
        // Generated and Vendor are final.
        assert_eq!(file(FileClass::Vendor).work(default), Work::Exclude);
        assert_eq!(file(FileClass::Generated).work(default), Work::Exclude);
        // Selecting Generated means any file that may turn out Generated is a parse candidate.
        let generated = ClassSet::only(FileClass::Generated);
        assert_eq!(file(FileClass::Test).work(generated), Work::Parse);
        assert_eq!(file(FileClass::Generated).work(generated), Work::Parse);
        assert_eq!(file(FileClass::Vendor).work(generated), Work::Exclude);
        assert_eq!(file(FileClass::Vendor).work(ClassSet::ALL), Work::Parse);
    }

    #[test]
    fn output_is_identical_for_any_thread_count() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..200 {
            write(
                dir.path(),
                &format!("d{}/e{}/f{i}.js", i % 7, i % 3),
                b"1;\n",
            );
        }
        let run = |threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| discover(dir.path(), &DiscoverOptions::default()).unwrap())
        };
        let one = run(1);
        assert_eq!(one.files.len(), 200);
        assert_eq!(one, run(8));
    }

    #[test]
    fn gitignore_can_be_disabled() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".gitignore", b"ignored/\n");
        write(dir.path(), "ignored/i.js", b"1");
        let options = DiscoverOptions {
            respect_gitignore: false,
        };
        let discovery = discover(dir.path(), &options).unwrap();
        assert_eq!(rel_paths(&discovery), ["ignored/i.js"]);
    }

    #[test]
    fn package_types_come_from_the_nearest_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "package.json", br#"{"name": "app"}"#);
        write(root, "server/index.js", b"1");
        write(root, "web/package.json", br#"{"type": "module"}"#);
        write(root, "web/src/main.js", b"1");
        write(root, "web/legacy/package.json", br#"{"type": "commonjs"}"#);
        write(root, "web/legacy/old.js", b"1");
        let discovery = discover(root, &DiscoverOptions::default()).unwrap();
        let package_type = |rel: &str| file(&discovery, rel).package_type;
        assert_eq!(package_type("server/index.js"), PackageType::CommonJs);
        assert_eq!(package_type("web/src/main.js"), PackageType::Module);
        assert_eq!(package_type("web/legacy/old.js"), PackageType::CommonJs);
    }

    #[test]
    fn a_single_file_root_yields_that_file() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "pkg/package.json", br#"{"type": "module"}"#);
        write(dir.path(), "pkg/lib/a.test.ts", b"export const a = 1;\n");
        write(dir.path(), "pkg/lib/b.ts", b"1");
        let discovery = discover(
            &dir.path().join("pkg/lib/a.test.ts"),
            &DiscoverOptions::default(),
        )
        .unwrap();
        assert!(discovery.single_file);
        assert_eq!(
            discovery.root,
            fs::canonicalize(dir.path().join("pkg/lib")).unwrap()
        );
        assert_eq!(rel_paths(&discovery), ["a.test.ts"]);
        assert_eq!(
            discovery.selection(ClassSet::default()),
            ClassSet::ALL,
            "a named file is analyzed whatever its class"
        );
        let only = file(&discovery, "a.test.ts");
        assert_eq!(only.path_class, FileClass::Test);
        assert_eq!(only.kind, SourceKind::Ts);
        // Like a directory scan of the project, the package.json above the file's directory
        // decides (D2-PLAN-09).
        assert_eq!(only.package_type, PackageType::Module);
    }

    #[test]
    fn a_single_file_package_search_stops_at_the_git_work_tree() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "package.json", br#"{"type": "module"}"#);
        write(dir.path(), "repo/.git/HEAD", b"ref: refs/heads/main\n");
        write(dir.path(), "repo/src/a.js", b"1");
        let discovery = discover(
            &dir.path().join("repo/src/a.js"),
            &DiscoverOptions::default(),
        )
        .unwrap();
        assert_eq!(discovery.files[0].package_type, PackageType::CommonJs);
        let repo = fs::canonicalize(dir.path().join("repo")).unwrap();
        assert_eq!(package_type_search_root(&repo.join("src")), repo);
    }

    #[test]
    fn root_problems_are_errors_not_diagnostics() {
        let dir = tempfile::tempdir().unwrap();
        let missing = discover(&dir.path().join("nope"), &DiscoverOptions::default());
        assert!(matches!(missing, Err(DiscoverError::Io { .. })));
        write(dir.path(), "notes.md", b"#");
        write(dir.path(), "types.d.ts", b"export {};");
        for unsupported in ["notes.md", "types.d.ts"] {
            let result = discover(&dir.path().join(unsupported), &DiscoverOptions::default());
            assert!(
                matches!(result, Err(DiscoverError::UnsupportedFile(_))),
                "{unsupported}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_contained_and_deduplicated() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        write(dir.path(), "outside/secret.js", b"steal();\n");
        write(&root, "src/app.js", b"run();\n");
        symlink(
            dir.path().join("outside/secret.js"),
            root.join("src/escape.js"),
        )
        .unwrap();
        symlink(dir.path().join("outside"), root.join("src/outside-dir")).unwrap();
        symlink("app.js", root.join("src/zlink.js")).unwrap();
        symlink("src/app.js", root.join("lib-link.js")).unwrap();
        symlink("missing.js", root.join("src/dangling.js")).unwrap();
        symlink("../src", root.join("src-alias")).unwrap();

        let discovery = discover(&root, &DiscoverOptions::default()).unwrap();
        // src/app.js is reachable as lib-link.js, src/app.js and src/zlink.js: it is listed
        // once, under its real path, even though a link path sorts first.
        assert_eq!(rel_paths(&discovery), ["src/app.js"]);
        let kept = file(&discovery, "src/app.js");
        assert_eq!(kept.abs_path, discovery.root.join("src/app.js"));
        assert_eq!(kept.size, 7);
        let codes: Vec<(&str, &str)> = diags(&discovery)
            .into_iter()
            .map(|(path, code, _)| (path, code))
            .collect();
        assert_eq!(
            codes,
            [
                ("src/dangling.js", "skip/io-error"),
                ("src/escape.js", "skip/symlink-outside-root"),
                ("src/outside-dir", "skip/symlink-outside-root"),
            ]
        );
        assert!(
            discovery
                .diagnostics
                .iter()
                .all(|d| !d.message.contains(dir.path().to_str().unwrap())),
            "messages must not leak absolute paths"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_aliases_cannot_change_a_files_class() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A real source file linked from docs/ (which sorts first): still source (DP-1).
        write(root, "src/server.js", b"listen();\n");
        fs::create_dir_all(root.join("docs/snippets")).unwrap();
        symlink("../../src/server.js", root.join("docs/snippets/server.js")).unwrap();
        // A vendored file linked into src/: still vendor.
        write(root, "vendor/jquery.js", b"jq();\n");
        fs::create_dir_all(root.join("src/lib")).unwrap();
        symlink("../../vendor/jquery.js", root.join("src/lib/jquery.js")).unwrap();
        // The real path is ignored, so only the link reaches the file: it keeps the link's
        // name but the class of its real location.
        write(root, ".gitignore", b"/third_party/\n");
        write(root, "third_party/lib.js", b"lib();\n");
        symlink("../../third_party/lib.js", root.join("src/lib/tp.js")).unwrap();

        let discovery = discover(root, &DiscoverOptions::default()).unwrap();
        let summary: Vec<(&str, FileClass)> = discovery
            .files
            .iter()
            .map(|file| (file.rel_path.as_str(), file.path_class))
            .collect();
        assert_eq!(
            summary,
            [
                ("src/lib/tp.js", FileClass::Vendor),
                ("src/server.js", FileClass::Source),
                ("vendor/jquery.js", FileClass::Vendor),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_regular_files_are_reported_never_dropped() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "src/a.js", b"1");
        let fifo = |path: &Path| {
            let status = std::process::Command::new("mkfifo")
                .arg(path)
                .status()
                .unwrap();
            assert!(status.success());
        };
        fifo(&root.join("src/raw-fifo.js"));
        fifo(&root.join("src/pipe-target"));
        symlink("pipe-target", root.join("src/fifo-link.js")).unwrap();
        // A link with a source name to a directory inside the root is not a file: the walker
        // lists the directory's contents under their own paths.
        fs::create_dir_all(root.join("src/dir")).unwrap();
        symlink("dir", root.join("src/dir-link.js")).unwrap();

        let discovery = discover(root, &DiscoverOptions::default()).unwrap();
        assert_eq!(rel_paths(&discovery), ["src/a.js"]);
        assert_eq!(
            diags(&discovery),
            [
                (
                    "src/fifo-link.js",
                    "skip/io-error",
                    "symlink target is not a regular file"
                ),
                ("src/raw-fifo.js", "skip/io-error", "not a regular file"),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_directories_are_reported_without_absolute_paths() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "locked/a.js", b"1");
        write(dir.path(), "secret.js", b"1");
        write(dir.path(), "ok.js", b"1");
        let set_mode = |rel: &str, mode: u32| {
            fs::set_permissions(dir.path().join(rel), fs::Permissions::from_mode(mode)).unwrap();
        };
        set_mode("locked", 0o000);
        set_mode("secret.js", 0o000);
        let readable_anyway = fs::read_dir(dir.path().join("locked")).is_ok();
        let discovery = discover(dir.path(), &DiscoverOptions::default());
        set_mode("locked", 0o755);
        set_mode("secret.js", 0o644);
        if readable_anyway {
            return; // running as root: permissions are not enforced
        }
        let discovery = discovery.unwrap();
        // Discovery never opens files: the unreadable file is listed, and reading it fails
        // later, when the frontend gets to it.
        assert_eq!(rel_paths(&discovery), ["ok.js", "secret.js"]);
        let diags = diags(&discovery);
        let denied = io::Error::from(io::ErrorKind::PermissionDenied).kind();
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].0, "locked");
        assert_eq!(diags[0].1, "skip/io-error");
        assert!(!diags[0].2.contains('/'), "absolute path leaked: {diags:?}");
        assert!(
            diags[0].2.to_lowercase().contains(&denied.to_string()),
            "{diags:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_single_file_symlink_leaving_its_directory_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "outside/real.js", b"1");
        fs::create_dir_all(dir.path().join("repo")).unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("outside/real.js"),
            dir.path().join("repo/link.js"),
        )
        .unwrap();
        let discovery = discover(
            &dir.path().join("repo/link.js"),
            &DiscoverOptions::default(),
        )
        .unwrap();
        assert!(discovery.files.is_empty());
        assert_eq!(discovery.diagnostics.len(), 1);
        assert_eq!(
            discovery.diagnostics[0].code,
            DiagCode::SkipSymlinkOutsideRoot
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_names_are_lossy_but_readable() {
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let name = OsStr::from_bytes(b"caf\xe9.js");
        if fs::write(dir.path().join(name), b"1;\n").is_err() {
            return; // the filesystem rejects non-UTF-8 names
        }
        let discovery = discover(dir.path(), &DiscoverOptions::default()).unwrap();
        assert_eq!(rel_paths(&discovery), ["caf\u{FFFD}.js"]);
        let only = &discovery.files[0];
        assert_eq!(only.rel_path_os, Path::new(name));
        assert_eq!(fs::read(&only.abs_path).unwrap(), b"1;\n");
    }

    #[test]
    fn rel_paths_use_forward_slashes() {
        let rel: PathBuf = ["a", "b", "c.js"].iter().collect();
        assert_eq!(rel_path_string(&rel), "a/b/c.js");
        assert_eq!(rel_path_string(Path::new("")), "");
        assert_eq!(rel_path_string(Path::new("./x/../y.js")), "x/../y.js");
    }
}
