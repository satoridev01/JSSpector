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
    /// TypeScript configs: directory -> (base directory, `paths` patterns -> targets).
    tsconfigs: BTreeMap<String, TsConfig>,
}

/// The module-resolution part of a `tsconfig.json` / `jsconfig.json`.
#[derive(Debug, Clone, Default)]
struct TsConfig {
    /// `baseUrl`, root-relative (`None`: not set).
    base: Option<String>,
    /// `paths`, with targets root-relative.
    paths: Vec<(String, Vec<String>)>,
}

impl Workspace {
    /// Reads every `package.json` under `root`.
    pub fn load(root: &Path) -> Self {
        let mut packages: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
        let mut tsconfigs = BTreeMap::new();
        // Sorted, so the result never depends on the file system's directory order.
        let walker = ignore::WalkBuilder::new(root)
            .standard_filters(false)
            .hidden(true)
            .filter_entry(|e| e.file_name() != "node_modules" && e.file_name() != ".git")
            .sort_by_file_path(|a, b| a.cmp(b))
            .build();
        for entry in walker.flatten() {
            let name = entry.file_name().to_string_lossy();
            if name == "tsconfig.json" || name == "jsconfig.json" {
                if let Some((dir, config)) = read_tsconfig(root, entry.path()) {
                    // tsconfig.json wins over jsconfig.json in the same directory.
                    if name == "tsconfig.json" {
                        tsconfigs.insert(dir, config);
                    } else {
                        tsconfigs.entry(dir).or_insert(config);
                    }
                }
                continue;
            }
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
            // A name declared twice (fixtures, examples): the shallowest directory, then the
            // first by name, whatever order the walk found them in.
            let depth = |d: &str| d.matches('/').count() + usize::from(!d.is_empty());
            match packages.get(name) {
                Some((existing, _))
                    if (depth(existing), existing.as_str()) <= (depth(&dir), dir.as_str()) => {}
                _ => {
                    packages.insert(name.to_owned(), (dir, entries));
                }
            }
        }
        Self {
            packages,
            tsconfigs,
        }
    }

    /// The file a bare specifier names through the nearest tsconfig's `paths` or `baseUrl`.
    pub fn resolve_typescript(
        &self,
        from: &str,
        spec: &str,
        files: &BTreeSet<String>,
    ) -> Option<String> {
        // The nearest config whose directory contains `from`.
        let mut dir = from.rsplit_once('/').map_or("", |(d, _)| d).to_owned();
        let config = loop {
            if let Some(config) = self.tsconfigs.get(&dir) {
                break config;
            }
            if dir.is_empty() {
                return None;
            }
            dir = dir
                .rsplit_once('/')
                .map_or(String::new(), |(d, _)| d.to_owned());
        };
        let join = |base: &str, rest: &str| {
            if base.is_empty() {
                rest.to_owned()
            } else {
                format!("{base}/{rest}")
            }
        };
        for (pattern, targets) in &config.paths {
            let wildcard = match pattern.split_once('*') {
                Some((prefix, suffix)) => spec
                    .strip_prefix(prefix)
                    .and_then(|rest| rest.strip_suffix(suffix)),
                None => (spec == pattern).then_some(""),
            };
            let Some(wildcard) = wildcard else { continue };
            for target in targets {
                let path = normalize(&target.replace('*', wildcard))?;
                if let Some(found) = candidates(&path).into_iter().find(|c| files.contains(c)) {
                    return Some(found);
                }
            }
        }
        let base = config.base.as_deref()?;
        let path = normalize(&join(base, spec))?;
        candidates(&path).into_iter().find(|c| files.contains(c))
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
        self.packages.is_empty() && self.tsconfigs.is_empty()
    }
}

/// Reads a tsconfig (JSON with comments and trailing commas): its directory and settings, both
/// root-relative.
fn read_tsconfig(root: &Path, path: &Path) -> Option<(String, TsConfig)> {
    let text = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&strip_jsonc(&text)).ok()?;
    let dir = path
        .parent()?
        .strip_prefix(root)
        .ok()?
        .to_string_lossy()
        .replace('\\', "/");
    let options = json.get("compilerOptions")?;
    let in_dir = |relative: &str| {
        let joined = if dir.is_empty() {
            relative.to_owned()
        } else {
            format!("{dir}/{relative}")
        };
        normalize(&joined)
    };
    let base = options
        .get("baseUrl")
        .and_then(|b| b.as_str())
        .and_then(in_dir);
    let paths_base = base.clone().or_else(|| Some(dir.clone()))?;
    let paths = options
        .get("paths")
        .and_then(|p| p.as_object())
        .map(|object| {
            object
                .iter()
                .map(|(pattern, targets)| {
                    let targets = targets
                        .as_array()
                        .map(|list| {
                            list.iter()
                                .filter_map(|t| t.as_str())
                                .filter_map(|t| {
                                    let joined = if paths_base.is_empty() {
                                        t.to_owned()
                                    } else {
                                        format!("{paths_base}/{t}")
                                    };
                                    normalize(&joined)
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    (pattern.clone(), targets)
                })
                .collect()
        })
        .unwrap_or_default();
    Some((dir, TsConfig { base, paths }))
}

/// JSON with comments (`//`, `/* */`) and trailing commas, made plain JSON.
fn strip_jsonc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if c == '\\' {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut previous = ' ';
                for next in chars.by_ref() {
                    if previous == '*' && next == '/' {
                        break;
                    }
                    previous = next;
                }
            }
            _ => out.push(c),
        }
    }
    // Trailing commas: `,` followed (after whitespace) by `}` or `]`.
    let mut cleaned = String::with_capacity(out.len());
    let bytes: Vec<char> = out.chars().collect();
    let mut in_string = false;
    let mut index = 0;
    while let Some(&c) = bytes.get(index) {
        if in_string {
            cleaned.push(c);
            if c == '\\' {
                if let Some(&next) = bytes.get(index + 1) {
                    cleaned.push(next);
                    index += 1;
                }
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            cleaned.push(c);
        } else if c == ',' {
            let rest = bytes.get(index + 1..).unwrap_or(&[]);
            let next = rest.iter().find(|ch| !ch.is_whitespace());
            if !matches!(next, Some('}' | ']')) {
                cleaned.push(c);
            }
        } else {
            cleaned.push(c);
        }
        index += 1;
    }
    cleaned
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

    #[test]
    fn tsconfig_paths_and_base_url_resolve_bare_specifiers() {
        let dir = std::env::temp_dir().join(format!("jss-tsconfig-{}", std::process::id()));
        let server = dir.join("server");
        std::fs::create_dir_all(server.join("src")).unwrap();
        std::fs::write(
            server.join("tsconfig.json"),
            "{\n  // comment\n  \"compilerOptions\": { \"baseUrl\": \"./\", \"paths\": { \"@app/*\": [\"./src/*\"], }, },\n}\n",
        )
        .unwrap();
        let workspace = Workspace::load(&dir);
        let set = files(&["server/src/enum.ts", "server/src/controllers/a.ts"]);
        assert_eq!(
            workspace
                .resolve_typescript("server/src/controllers/a.ts", "src/enum", &set)
                .as_deref(),
            Some("server/src/enum.ts")
        );
        assert_eq!(
            workspace
                .resolve_typescript("server/src/controllers/a.ts", "@app/enum", &set)
                .as_deref(),
            Some("server/src/enum.ts")
        );
        assert_eq!(
            workspace.resolve_typescript("server/src/controllers/a.ts", "lodash", &set),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
