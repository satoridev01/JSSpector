//! The package.json `"type"` field, which decides whether `.js` and `.ts` files are ES modules.
//!
//! Like Node.js, the NEAREST ancestor `package.json` decides, even when it has no `"type"` field
//! (then the files are CommonJS). The search never leaves the scan root, and results are
//! memoized per directory.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The `"type"` field of the nearest `package.json`, which decides how `.js` and `.ts` files parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageType {
    /// No `"type"` field, or `"type": "commonjs"`. Files may be scripts or modules
    /// (the parser decides from the presence of `import`/`export`).
    #[default]
    CommonJs,
    /// `"type": "module"`: `.js` and `.ts` files are ES modules.
    Module,
}

impl PackageType {
    /// The output name: `commonjs` or `module`.
    pub const fn as_str(self) -> &'static str {
        match self {
            PackageType::CommonJs => "commonjs",
            PackageType::Module => "module",
        }
    }
}

/// `package.json` files larger than this are not read (they count as having no `"type"`).
pub const MAX_PACKAGE_JSON_BYTES: u64 = 1024 * 1024;

/// Finds the [`PackageType`] for directories under a root, memoizing every directory visited.
#[derive(Debug)]
pub struct PackageTypes {
    root: PathBuf,
    /// Resolved type per root-relative directory (`""` is the root itself).
    memo: BTreeMap<PathBuf, PackageType>,
}

impl PackageTypes {
    /// A resolver for `root`, which should be canonical (see [`crate::discover()`]).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            memo: BTreeMap::new(),
        }
    }

    /// The package type for files in `rel_dir`, a directory relative to the root. Searches
    /// `rel_dir` and its ancestors up to and including the root; outside the root nothing is
    /// read and the default ([`PackageType::CommonJs`]) applies.
    pub fn for_dir(&mut self, rel_dir: &Path) -> PackageType {
        let mut visited = Vec::new();
        let mut current = Some(rel_dir);
        let resolved = loop {
            let Some(dir) = current else {
                break PackageType::default();
            };
            if let Some(&known) = self.memo.get(dir) {
                break known;
            }
            visited.push(dir.to_path_buf());
            if let Some(found) = self.read(dir) {
                break found;
            }
            current = dir.parent();
        };
        for dir in visited {
            self.memo.insert(dir, resolved);
        }
        resolved
    }

    /// Reads `<root>/<rel_dir>/package.json`. `None` when there is no such file (keep looking
    /// upward); otherwise its type, defaulting to CommonJS when the file has no usable
    /// `"type"`, cannot be read, is too large, is not JSON, or is a symlink leaving the root.
    fn read(&self, rel_dir: &Path) -> Option<PackageType> {
        let path = self.root.join(rel_dir).join("package.json");
        let meta = fs::symlink_metadata(&path).ok()?;
        if meta.file_type().is_symlink() {
            let inside = fs::canonicalize(&path)
                .is_ok_and(|target| target.starts_with(&self.root) && target.is_file());
            if !inside {
                return Some(PackageType::default());
            }
        } else if !meta.is_file() {
            return None;
        }
        Some(read_type(&path).unwrap_or_default())
    }
}

#[derive(Deserialize)]
struct PackageJson {
    #[serde(rename = "type")]
    kind: Option<serde_json::Value>,
}

fn read_type(path: &Path) -> Option<PackageType> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_PACKAGE_JSON_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PACKAGE_JSON_BYTES {
        return None;
    }
    let package: PackageJson = serde_json::from_slice(&bytes).ok()?;
    match package.kind {
        Some(serde_json::Value::String(kind)) if kind == "module" => Some(PackageType::Module),
        _ => Some(PackageType::CommonJs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        (dir, root)
    }

    #[test]
    fn no_package_json_means_commonjs() {
        let (_dir, root) = canonical_tempdir();
        fs::create_dir_all(root.join("src/a")).unwrap();
        let mut types = PackageTypes::new(&root);
        assert_eq!(types.for_dir(Path::new("src/a")), PackageType::CommonJs);
        assert_eq!(types.for_dir(Path::new("")), PackageType::CommonJs);
    }

    #[test]
    fn nearest_package_json_wins_even_without_a_type() {
        let (_dir, root) = canonical_tempdir();
        write(&root, "package.json", r#"{"type": "module"}"#);
        write(&root, "legacy/package.json", r#"{"name": "legacy"}"#);
        write(&root, "esm/deep/package.json", r#"{"type": "module"}"#);
        write(&root, "cjs/package.json", r#"{"type": "commonjs"}"#);
        fs::create_dir_all(root.join("src/x")).unwrap();
        fs::create_dir_all(root.join("legacy/lib")).unwrap();
        let mut types = PackageTypes::new(&root);
        assert_eq!(types.for_dir(Path::new("")), PackageType::Module);
        assert_eq!(types.for_dir(Path::new("src/x")), PackageType::Module);
        assert_eq!(
            types.for_dir(Path::new("legacy/lib")),
            PackageType::CommonJs
        );
        assert_eq!(types.for_dir(Path::new("esm/deep")), PackageType::Module);
        assert_eq!(types.for_dir(Path::new("cjs")), PackageType::CommonJs);
    }

    #[test]
    fn results_are_memoized_per_directory() {
        let (_dir, root) = canonical_tempdir();
        write(&root, "pkg/package.json", r#"{"type": "module"}"#);
        fs::create_dir_all(root.join("pkg/a/b")).unwrap();
        let mut types = PackageTypes::new(&root);
        assert_eq!(types.for_dir(Path::new("pkg/a/b")), PackageType::Module);
        // Every directory on the way up was memoized...
        for dir in ["pkg/a/b", "pkg/a", "pkg"] {
            assert_eq!(types.memo.get(Path::new(dir)), Some(&PackageType::Module));
        }
        assert_eq!(types.memo.get(Path::new("")), None, "search stopped at pkg");
        // ...so later changes on disk are not seen again.
        write(&root, "pkg/a/package.json", r#"{"type": "commonjs"}"#);
        assert_eq!(types.for_dir(Path::new("pkg/a/b")), PackageType::Module);
    }

    #[test]
    fn unusable_package_json_counts_as_commonjs() {
        let (_dir, root) = canonical_tempdir();
        write(&root, "package.json", r#"{"type": "module"}"#);
        write(&root, "broken/package.json", "{ not json");
        write(&root, "weird/package.json", r#"{"type": 42}"#);
        write(&root, "array/package.json", "[1, 2]");
        let mut types = PackageTypes::new(&root);
        assert_eq!(types.for_dir(Path::new("broken")), PackageType::CommonJs);
        assert_eq!(types.for_dir(Path::new("weird")), PackageType::CommonJs);
        assert_eq!(types.for_dir(Path::new("array")), PackageType::CommonJs);
    }

    #[test]
    fn oversized_package_json_is_not_read() {
        let (_dir, root) = canonical_tempdir();
        let padding = " ".repeat(usize::try_from(MAX_PACKAGE_JSON_BYTES).unwrap());
        write(
            &root,
            "big/package.json",
            &format!("{{\"type\": \"module\"{padding}}}"),
        );
        let mut types = PackageTypes::new(&root);
        assert_eq!(types.for_dir(Path::new("big")), PackageType::CommonJs);
    }

    #[test]
    fn the_search_never_leaves_the_root() {
        let (_dir, outer) = canonical_tempdir();
        write(&outer, "package.json", r#"{"type": "module"}"#);
        fs::create_dir_all(outer.join("repo/src")).unwrap();
        let mut types = PackageTypes::new(outer.join("repo"));
        assert_eq!(types.for_dir(Path::new("src")), PackageType::CommonJs);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_package_json_outside_the_root_is_ignored() {
        let (_dir, outer) = canonical_tempdir();
        write(&outer, "elsewhere/package.json", r#"{"type": "module"}"#);
        write(&outer, "repo/package.json", r#"{"type": "module"}"#);
        fs::create_dir_all(outer.join("repo/linked")).unwrap();
        fs::create_dir_all(outer.join("repo/inside")).unwrap();
        std::os::unix::fs::symlink(
            outer.join("elsewhere/package.json"),
            outer.join("repo/linked/package.json"),
        )
        .unwrap();
        std::os::unix::fs::symlink("../package.json", outer.join("repo/inside/package.json"))
            .unwrap();
        let mut types = PackageTypes::new(outer.join("repo"));
        // Present but leaving the root: it stops the search and counts as CommonJS.
        assert_eq!(types.for_dir(Path::new("linked")), PackageType::CommonJs);
        // Symlinks that stay inside the root are followed.
        assert_eq!(types.for_dir(Path::new("inside")), PackageType::Module);
    }

    #[test]
    fn serializes_as_lowercase() {
        assert_eq!(
            serde_json::to_string(&PackageType::Module).unwrap(),
            "\"module\""
        );
        assert_eq!(
            serde_json::to_string(&PackageType::CommonJs).unwrap(),
            "\"commonjs\""
        );
        assert_eq!(PackageType::CommonJs.as_str(), "commonjs");
    }
}
