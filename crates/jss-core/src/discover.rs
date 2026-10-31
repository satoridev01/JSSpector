//! File discovery: lists the JS/TS files under a scan root, contained to the root, deduplicated,
//! classified and sorted.
//!
//! - The walk uses the `ignore` crate: `.gitignore` files inside the root are honored (whether or
//!   not the tree is a git checkout), hidden files and directories are skipped, and symlinks are
//!   never followed by the walker.
//! - Ignore files outside the root (parent directories, the user's global gitignore,
//!   `.git/info/exclude`) are deliberately NOT consulted, so the result depends only on the
//!   tree under the root.
//! - A symlinked file is accepted only when its canonical target is inside the root; otherwise
//!   it is reported as `skip/symlink-outside-root`. Files reachable through several paths are
//!   kept once, under the lexicographically smallest relative path.
//! - Output is sorted by relative path bytes, so it does not depend on directory order.
//! - File headers (for the `@generated` check) are read in parallel on the current rayon pool;
//!   run [`discover`] inside a dedicated pool's `install` to bound its threads.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use ignore::WalkBuilder;
use rayon::prelude::*;

use crate::classify::{self, FileClass};
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
        if [".d.ts", ".d.mts", ".d.cts"]
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
    pub class: FileClass,
    pub package_type: PackageType,
    /// Size in bytes at discovery time.
    pub size: u64,
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
    /// One diagnostic per file or directory that could not be considered, sorted.
    pub diagnostics: Vec<Diagnostic>,
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
/// root becomes its parent directory and the result holds that one file.
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

    let mut collector = Collector::new(canonical.clone());
    let mut walker = WalkBuilder::new(&canonical);
    walker
        // Start from no filters, then enable exactly what we want.
        .standard_filters(false)
        .hidden(true)
        .git_ignore(options.respect_gitignore)
        .require_git(false)
        .follow_links(false);
    for result in walker.build() {
        match result {
            Ok(entry) => collector.visit(&entry),
            Err(err) => collector.walk_error(&err),
        }
    }
    let (files, diagnostics) = collector.finish();
    Ok(Discovery {
        root: canonical,
        single_file: false,
        files,
        diagnostics,
    })
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

    let mut collector = Collector::new(canonical.clone());
    let path = canonical.join(name);
    let rel = PathBuf::from(name);
    let meta = fs::symlink_metadata(&path).map_err(io_error(root))?;
    if meta.file_type().is_symlink() {
        collector.visit_symlink(&path, &rel, Some(kind));
    } else {
        collector.add(path, rel, kind);
    }
    let (files, diagnostics) = collector.finish();
    Ok(Discovery {
        root: canonical,
        single_file: true,
        files,
        diagnostics,
    })
}

/// A file reachable under one canonical path, with the smallest relative path seen so far.
struct Candidate {
    rel_path: String,
    rel_path_os: PathBuf,
    kind: SourceKind,
}

struct Collector {
    root: PathBuf,
    package_types: PackageTypes,
    /// Keyed by canonical path, which deduplicates files reachable through symlinks.
    candidates: BTreeMap<PathBuf, Candidate>,
    diagnostics: Vec<Diagnostic>,
}

impl Collector {
    fn new(root: PathBuf) -> Self {
        Self {
            package_types: PackageTypes::new(root.clone()),
            root,
            candidates: BTreeMap::new(),
            diagnostics: Vec::new(),
        }
    }

    fn visit(&mut self, entry: &ignore::DirEntry) {
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
        let Ok(rel) = path.strip_prefix(&self.root) else {
            return;
        };
        let kind = SourceKind::from_file_name(entry.file_name());
        if file_type.is_symlink() {
            self.visit_symlink(path, rel, kind);
            return;
        }
        let Some(kind) = kind else {
            return;
        };
        if !file_type.is_file() {
            // A FIFO, socket or device named like a source file: never opened.
            self.report(DiagCode::SkipIoError, rel, "not a regular file");
            return;
        }
        self.add(path.to_path_buf(), rel.to_path_buf(), kind);
    }

    /// Handles a symlink at `path` (`rel` relative to the root). `kind` is set when the link's
    /// own name is a JS/TS file name.
    fn visit_symlink(&mut self, path: &Path, rel: &Path, kind: Option<SourceKind>) {
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
        if !target.starts_with(&self.root) {
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
            Ok(meta) if meta.is_file() => self.add(target, rel.to_path_buf(), kind),
            Ok(_) => {}
            Err(err) => self.report(
                DiagCode::SkipIoError,
                rel,
                format!("cannot read symlink target: {err}"),
            ),
        }
    }

    /// Records a candidate, keeping the smallest relative path per canonical path.
    fn add(&mut self, canonical: PathBuf, rel_path_os: PathBuf, kind: SourceKind) {
        let candidate = Candidate {
            rel_path: rel_path_string(&rel_path_os),
            rel_path_os,
            kind,
        };
        match self.candidates.get_mut(&canonical) {
            Some(existing) => {
                let smaller = (&candidate.rel_path, &candidate.rel_path_os)
                    < (&existing.rel_path, &existing.rel_path_os);
                if smaller {
                    *existing = candidate;
                }
            }
            None => {
                self.candidates.insert(canonical, candidate);
            }
        }
    }

    fn walk_error(&mut self, err: &ignore::Error) {
        let path = error_path(err)
            .and_then(|path| path.strip_prefix(&self.root).ok())
            .map(rel_path_string)
            .filter(|rel| !rel.is_empty());
        self.diagnostics.push(Diagnostic::new(
            DiagCode::SkipIoError,
            path,
            error_message(err),
        ));
    }

    fn report(&mut self, code: DiagCode, rel: &Path, message: impl Into<String>) {
        self.diagnostics
            .push(Diagnostic::at(code, rel_path_string(rel), message));
    }

    /// Classifies every candidate, looks up its package type and sorts the output.
    fn finish(mut self) -> (Vec<SourceFile>, Vec<Diagnostic>) {
        let candidates: Vec<(PathBuf, Candidate)> =
            std::mem::take(&mut self.candidates).into_iter().collect();
        // Opening every file to read its header dominates discovery time, so probe in
        // parallel (on the caller's rayon pool, if any). The indexed collect keeps the order.
        let probed: Vec<_> = candidates
            .into_par_iter()
            .map(|(canonical, candidate)| {
                let probed = probe(&canonical, &candidate.rel_path);
                (canonical, candidate, probed)
            })
            .collect();
        let mut files = Vec::with_capacity(probed.len());
        for (canonical, candidate, probed) in probed {
            let (size, class) = match probed {
                Ok(probed) => probed,
                Err(err) => {
                    self.diagnostics.push(Diagnostic::at(
                        DiagCode::SkipIoError,
                        candidate.rel_path,
                        format!("cannot read file: {err}"),
                    ));
                    continue;
                }
            };
            let package_type = canonical
                .parent()
                .and_then(|dir| dir.strip_prefix(&self.root).ok())
                .map(|dir| self.package_types.for_dir(dir))
                .unwrap_or_default();
            files.push(SourceFile {
                rel_path: candidate.rel_path,
                rel_path_os: candidate.rel_path_os,
                abs_path: canonical,
                kind: candidate.kind,
                class,
                package_type,
                size,
            });
        }
        files.sort_by(|a, b| {
            a.rel_path
                .cmp(&b.rel_path)
                .then_with(|| a.rel_path_os.cmp(&b.rel_path_os))
        });
        diag::sort(&mut self.diagnostics);
        (files, self.diagnostics)
    }
}

/// Size and final class of a candidate. The file header is read only when it can still change
/// the class (see [`classify::header_can_change`]).
fn probe(canonical: &Path, rel_path: &str) -> io::Result<(u64, FileClass)> {
    let path_class = classify::classify_path(rel_path);
    if classify::header_can_change(path_class) {
        let (size, head) = read_head(canonical)?;
        Ok((size, classify::classify(rel_path, Some(&head))))
    } else {
        Ok((fs::metadata(canonical)?.len(), path_class))
    }
}

/// Opens a file and returns its size and first [`classify::GENERATED_SCAN_BYTES`] bytes.
fn read_head(path: &Path) -> io::Result<(u64, Vec<u8>)> {
    let file = fs::File::open(path)?;
    let size = file.metadata()?.len();
    let limit = u64::try_from(classify::GENERATED_SCAN_BYTES).unwrap_or(u64::MAX);
    let mut head = Vec::with_capacity(classify::GENERATED_SCAN_BYTES);
    file.take(limit).read_to_end(&mut head)?;
    Ok((size, head))
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
        let class = |rel: &str| file(&discovery, rel).class;
        assert_eq!(class("dist/out.js"), FileClass::Generated);
        assert_eq!(class("docs/site.js"), FileClass::Docs);
        assert_eq!(class("examples/e.mjs"), FileClass::Example);
        assert_eq!(class("node_modules/m/index.js"), FileClass::Vendor);
        assert_eq!(class("src/App.jsx"), FileClass::Source);
        assert_eq!(class("src/a.test.js"), FileClass::Test);
        assert_eq!(class("src/gen.ts"), FileClass::Generated);
        assert_eq!(class("test/helper.js"), FileClass::Test);

        let app = file(&discovery, "src/App.jsx");
        assert_eq!(app.kind, SourceKind::Jsx);
        assert_eq!(app.size, 11);
        assert_eq!(app.rel_path_os, Path::new("src").join("App.jsx"));
        assert_eq!(app.abs_path, discovery.root.join("src").join("App.jsx"));
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
        let only = file(&discovery, "a.test.ts");
        assert_eq!(only.class, FileClass::Test);
        assert_eq!(only.kind, SourceKind::Ts);
        // The package.json lookup stays within the root (the file's directory).
        assert_eq!(only.package_type, PackageType::CommonJs);
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
        // src/app.js is reachable as lib-link.js, src/app.js and src/zlink.js: the smallest
        // relative path wins, and the file is listed once.
        assert_eq!(rel_paths(&discovery), ["lib-link.js"]);
        let kept = file(&discovery, "lib-link.js");
        assert_eq!(kept.abs_path, discovery.root.join("src/app.js"));
        assert_eq!(kept.size, 7);
        let diags: Vec<(&str, &str)> = discovery
            .diagnostics
            .iter()
            .map(|d| (d.path.as_deref().unwrap(), d.code.as_str()))
            .collect();
        assert_eq!(
            diags,
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
    fn unreadable_entries_are_reported_without_absolute_paths() {
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
        assert_eq!(rel_paths(&discovery), ["ok.js"]);
        let diags: Vec<(&str, &str, &str)> = discovery
            .diagnostics
            .iter()
            .map(|d| {
                (
                    d.path.as_deref().unwrap(),
                    d.code.as_str(),
                    d.message.as_str(),
                )
            })
            .collect();
        let denied = io::Error::from(io::ErrorKind::PermissionDenied).kind();
        assert_eq!(diags.len(), 2, "{diags:?}");
        assert_eq!(diags[0].0, "locked");
        assert_eq!(diags[0].1, "skip/io-error");
        assert_eq!(diags[1].0, "secret.js");
        assert_eq!(diags[1].1, "skip/io-error");
        assert!(diags[1].2.starts_with("cannot read file: "), "{diags:?}");
        for (_, _, message) in diags {
            assert!(!message.contains('/'), "absolute path leaked: {message}");
            assert!(
                message.to_lowercase().contains(&denied.to_string()),
                "{message}"
            );
        }
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
