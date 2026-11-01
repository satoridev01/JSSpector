//! Resolving module specifiers between the files of one scan root (the linker's file step).
//!
//! Relative specifiers (`./db`, `../routes/index.js`) resolve against the importing file's
//! directory, trying the specifier as written, then with each JavaScript/TypeScript extension,
//! then as a directory with an `index` file. TypeScript's ESM convention of importing `./x.js`
//! for a `./x.ts` source is honored. Bare specifiers (packages) are not files of the root and do
//! not resolve here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Extensions tried, in order, when a specifier has none (or names a compiled `.js`).
pub const EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"];

/// The root-relative path `spec` names when imported from `from` (root-relative, `/`-separated),
/// if it is one of `files`.
pub fn resolve(from: &str, spec: &str, files: &BTreeSet<String>) -> Option<String> {
    if !(spec.starts_with("./") || spec.starts_with("../") || spec == "." || spec == "..") {
        return None;
    }
    let dir = match from.rfind('/') {
        Some(at) => from.get(..at).unwrap_or(""),
        None => "",
    };
    let joined = normalize(&format!("{dir}/{spec}"))?;
    candidates(&joined).into_iter().find(|c| files.contains(c))
}

/// The packages of a workspace (monorepo): package name -> (directory, entry points), from the
/// `package.json` files under the scan root (outside `node_modules`).
#[derive(Debug, Clone, Default)]
pub struct Workspace {
    packages: BTreeMap<String, (String, Vec<String>)>,
}

impl Workspace {
    /// Reads every `package.json` under `root`.
    pub fn load(root: &Path) -> Self {
        let mut packages = BTreeMap::new();
        let walker = ignore::WalkBuilder::new(root)
            .standard_filters(false)
            .hidden(true)
            .filter_entry(|e| e.file_name() != "node_modules" && e.file_name() != ".git")
            .build();
        for entry in walker.flatten() {
            if entry.file_name() != "package.json" {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            let Some(name) = json.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let Some(dir) = entry
                .path()
                .parent()
                .and_then(|d| d.strip_prefix(root).ok())
                .map(|d| d.to_string_lossy().replace('\\', "/"))
            else {
                continue;
            };
            let mut entries = Vec::new();
            for field in ["source", "module", "main", "types", "typings"] {
                if let Some(value) = json.get(field).and_then(|v| v.as_str()) {
                    entries.push(value.trim_start_matches("./").to_owned());
                }
            }
            packages.insert(name.to_owned(), (dir, entries));
        }
        Self { packages }
    }

    /// The file a bare specifier names when it is a package of this workspace.
    pub fn resolve(&self, spec: &str, files: &BTreeSet<String>) -> Option<String> {
        let (name, (dir, entries)) = self
            .packages
            .iter()
            .filter(|(name, _)| spec == name.as_str() || spec.starts_with(&format!("{name}/")))
            .max_by_key(|(name, _)| name.len())?;
        let join = |rest: &str| {
            if dir.is_empty() {
                rest.to_owned()
            } else {
                format!("{dir}/{rest}")
            }
        };
        let subpath = spec.get(name.len()..).unwrap_or("").trim_start_matches('/');
        let mut bases = Vec::new();
        if subpath.is_empty() {
            for entry in entries {
                let entry = entry.trim_end_matches(".d.ts");
                bases.push(join(entry));
                // Built output points back at the sources: dist/index.js -> src/index.ts.
                for built in ["dist/", "lib/", "build/", "out/"] {
                    if let Some(rest) = entry.strip_prefix(built) {
                        bases.push(join(&format!("src/{rest}")));
                    }
                }
            }
            bases.push(join("src/index"));
            bases.push(join("index"));
        } else {
            bases.push(join(subpath));
            bases.push(join(&format!("src/{subpath}")));
        }
        bases.iter().find_map(|base| {
            let stem = base
                .strip_suffix(".js")
                .or_else(|| base.strip_suffix(".mjs"))
                .or_else(|| base.strip_suffix(".cjs"))
                .unwrap_or(base);
            candidates(base)
                .into_iter()
                .chain(candidates(stem))
                .find(|c| files.contains(c))
        })
    }

    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

/// Every path `base` may name, in resolution order.
fn candidates(base: &str) -> Vec<String> {
    let mut out = vec![base.to_owned()];
    // `./x.js` written for `./x.ts` (TypeScript ESM).
    if let Some((stem, ext)) = base.rsplit_once('.')
        && matches!(ext, "js" | "jsx" | "mjs" | "cjs")
        && !stem.ends_with('/')
    {
        let typed = match ext {
            "mjs" => "mts",
            "cjs" => "cts",
            "jsx" => "tsx",
            _ => "ts",
        };
        out.push(format!("{stem}.{typed}"));
        if ext == "js" {
            out.push(format!("{stem}.tsx"));
        }
    }
    for ext in EXTENSIONS {
        out.push(format!("{base}.{ext}"));
    }
    for ext in EXTENSIONS {
        out.push(format!("{base}/index.{ext}"));
    }
    out
}

/// Resolves `.` and `..` segments; `None` when the path climbs above the root.
fn normalize(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn relative_specifiers_resolve_with_extensions_and_index_files() {
        let set = files(&[
            "src/app.js",
            "src/routes/users.js",
            "src/db/index.ts",
            "lib/x.ts",
        ]);
        assert_eq!(
            resolve("src/app.js", "./routes/users", &set).as_deref(),
            Some("src/routes/users.js")
        );
        assert_eq!(
            resolve("src/app.js", "./routes/users.js", &set).as_deref(),
            Some("src/routes/users.js")
        );
        assert_eq!(
            resolve("src/routes/users.js", "../db", &set).as_deref(),
            Some("src/db/index.ts")
        );
        assert_eq!(
            resolve("src/app.js", "../lib/x.js", &set).as_deref(),
            Some("lib/x.ts")
        );
        assert_eq!(resolve("app.js", "./missing", &set), None);
        assert_eq!(resolve("src/app.js", "express", &set), None);
        assert_eq!(resolve("a.js", "../../outside", &set), None);
    }
}
