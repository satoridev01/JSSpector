//! jss-frontend: the only JSSpector crate that depends on oxc.
//!
//! Everything oxc-specific (parsing, semantic analysis, lowering to JSSpector's owned IR) lives
//! here, so oxc's frequent breaking releases stay contained in one crate. The rest of the
//! workspace only ever sees owned, lifetime-free data.

use std::path::Path;

use oxc_allocator::Allocator;
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;
use serde::Serialize;

/// The `"type"` field of the nearest `package.json`, which decides how `.js` and `.ts` files parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PackageType {
    /// No `"type"` field, or `"type": "commonjs"`. Files may be scripts or modules
    /// (oxc decides from the presence of `import`/`export`).
    #[default]
    CommonJs,
    /// `"type": "module"`: `.js` and `.ts` files are ES modules.
    Module,
}

/// Picks the oxc [`SourceType`] for a file from its extension.
///
/// `SourceType::from_path` is deliberately not used. It does not enable JSX for `.js`, although
/// React code commonly puts JSX in `.js` files, and it fails on non-UTF-8 file names.
///
/// Returns `None` for unsupported files. That includes type declaration files (`.d.ts`, `.d.mts`,
/// `.d.cts`), which contain no executable code.
pub fn source_type_for(path: &Path, package_type: PackageType) -> Option<SourceType> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if [".d.ts", ".d.mts", ".d.cts"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
    {
        return None;
    }
    let (_, ext) = name.rsplit_once('.')?;
    let (js, ts) = match package_type {
        PackageType::Module => (SourceType::mjs(), SourceType::ts().with_module(true)),
        PackageType::CommonJs => (
            SourceType::unambiguous(),
            SourceType::ts().with_unambiguous(true),
        ),
    };
    Some(match ext {
        "js" | "jsx" => js.with_jsx(true),
        "mjs" => SourceType::mjs().with_jsx(true),
        "cjs" => SourceType::cjs().with_jsx(true),
        "ts" => ts,
        "tsx" => ts.with_jsx(true),
        "mts" => SourceType::ts().with_module(true),
        "cts" => SourceType::ts().with_commonjs(true),
        _ => return None,
    })
}

/// Parser statistics for one file. This is a development aid until IR lowering lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ParseStats {
    /// Top-level statements in the program (0 when parsing failed fatally).
    pub statements: usize,
    /// Syntax errors reported by the parser, whether it recovered or not.
    pub syntax_errors: usize,
    /// The parser gave up: the AST is empty and the file cannot be analyzed.
    pub fatal: bool,
    /// The file uses Flow type annotations.
    pub flow: bool,
}

/// Parse options shared by every JSSpector parse.
fn parse_options() -> ParseOptions {
    ParseOptions {
        // CommonJS modules and scripts may `return` at the top level.
        allow_return_outside_function: true,
        // Parentheses carry no meaning for data flow; keep the AST minimal.
        preserve_parens: false,
        ..ParseOptions::default()
    }
}

/// Parses `source` and reports [`ParseStats`]. Never panics on malformed input: syntax errors
/// are counted, and a fatal error is reported in [`ParseStats::fatal`].
pub fn parse_stats(source: &str, source_type: SourceType) -> ParseStats {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, source_type)
        .with_options(parse_options())
        .parse();
    ParseStats {
        statements: ret.program.body.len(),
        syntax_errors: ret.diagnostics.len(),
        fatal: ret.fatal_error,
        flow: ret.is_flow_language,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(name: &str) -> Option<SourceType> {
        source_type_for(Path::new(name), PackageType::CommonJs)
    }

    #[test]
    fn source_type_comes_from_the_extension() {
        assert!(st("app.js").unwrap().is_jsx(), ".js must accept JSX");
        assert!(st("app.jsx").unwrap().is_jsx());
        assert!(st("users.ts").unwrap().is_typescript());
        assert!(
            !st("users.ts").unwrap().is_jsx(),
            ".ts must not enable JSX (`<T>x` casts)"
        );
        assert!(st("page.tsx").unwrap().is_jsx());
        assert!(
            st("APP.JS").is_some(),
            "extension matching is case-insensitive"
        );
        assert!(
            st("index.d.ts").is_none(),
            "declaration files have no executable code"
        );
        assert!(st("index.d.mts").is_none());
        assert!(st("style.css").is_none());
        assert!(st("Makefile").is_none());
    }

    #[test]
    fn package_type_module_makes_js_an_es_module() {
        let esm = source_type_for(Path::new("a.js"), PackageType::Module).unwrap();
        assert!(esm.is_module());
        assert!(esm.is_jsx());
    }

    #[test]
    fn jsx_in_a_dot_js_file_parses_cleanly() {
        let src = "const App = () => <div onClick={go}>hi</div>;\nexport default App;\n";
        let stats = parse_stats(src, st("app.js").unwrap());
        assert_eq!(
            stats,
            ParseStats {
                statements: 2,
                syntax_errors: 0,
                fatal: false,
                flow: false
            }
        );
    }

    #[test]
    fn typescript_decorators_parse_cleanly() {
        let src = "@Controller('users')\nexport class UsersController {\n  @Get(':id')\n  find(@Param('id') id: string): string { return id; }\n}\n";
        let stats = parse_stats(src, st("users.controller.ts").unwrap());
        assert_eq!(stats.syntax_errors, 0);
        assert!(!stats.fatal);
    }

    #[test]
    fn commonjs_top_level_return_is_allowed() {
        let src = "if (!module.parent) return;\nmodule.exports = function routes(app) {};\n";
        let stats = parse_stats(src, st("routes.cjs").unwrap());
        assert_eq!(stats.syntax_errors, 0);
    }

    #[test]
    fn syntax_errors_are_counted_not_panicked() {
        let stats = parse_stats("function (", st("broken.js").unwrap());
        assert!(stats.syntax_errors > 0);
    }
}
