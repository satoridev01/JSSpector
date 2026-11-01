//! Resolving module specifiers between the files of one scan root (the linker's file step).
//!
//! Relative specifiers (`./db`, `../routes/index.js`) resolve against the importing file's
//! directory, trying the specifier as written, then with each JavaScript/TypeScript extension,
//! then as a directory with an `index` file. TypeScript's ESM convention of importing `./x.js`
//! for a `./x.ts` source is honored. Bare specifiers (packages) are not files of the root and do
//! not resolve here.

use std::collections::BTreeSet;

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
