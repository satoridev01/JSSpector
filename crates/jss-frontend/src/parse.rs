//! Parsing one file with oxc and summarizing the result as owned data.

use std::path::Path;

use jss_core::{PackageType, SourceKind};
use oxc_allocator::Allocator;
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;
use serde::Serialize;

/// The oxc [`SourceType`] for a file kind and package type.
///
/// `.js` and `.ts` follow the nearest package.json `"type"`; `.mjs`/`.mts` are always modules and
/// `.cjs`/`.cts` always CommonJS. JSX is enabled for every JavaScript kind, because React code
/// commonly puts JSX in `.js` files, but not for `.ts`, where `<T>x` is a type assertion.
pub fn source_type(kind: SourceKind, package_type: PackageType) -> SourceType {
    let (js, ts) = match package_type {
        PackageType::Module => (SourceType::mjs(), SourceType::ts().with_module(true)),
        PackageType::CommonJs => (
            SourceType::unambiguous(),
            SourceType::ts().with_unambiguous(true),
        ),
    };
    match kind {
        SourceKind::Js | SourceKind::Jsx => js.with_jsx(true),
        SourceKind::Mjs => SourceType::mjs().with_jsx(true),
        SourceKind::Cjs => SourceType::cjs().with_jsx(true),
        SourceKind::Ts => ts,
        SourceKind::Tsx => ts.with_jsx(true),
        SourceKind::Mts => SourceType::ts().with_module(true),
        SourceKind::Cts => SourceType::ts().with_commonjs(true),
    }
}

/// Picks the oxc [`SourceType`] for a file from its extension.
///
/// `SourceType::from_path` is deliberately not used. It does not enable JSX for `.js`, although
/// React code commonly puts JSX in `.js` files, and it fails on non-UTF-8 file names.
///
/// Returns `None` for unsupported files. That includes type declaration files (`.d.ts`, `.d.mts`,
/// `.d.cts`), which contain no executable code.
pub fn source_type_for(path: &Path, package_type: PackageType) -> Option<SourceType> {
    SourceKind::from_path(path).map(|kind| source_type(kind, package_type))
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

/// The first syntax error of a parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxError {
    pub message: String,
    /// Byte offset of the error's primary label, when it has one.
    pub offset: Option<u32>,
}

/// Owned summary of one parse: nothing borrows from the allocator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOutcome {
    /// Top-level statements in the program (0 when parsing failed fatally).
    pub statements: usize,
    /// Syntax errors reported by the parser, whether it recovered or not.
    pub syntax_errors: usize,
    /// The parser gave up: the AST is empty and the file cannot be analyzed.
    pub fatal: bool,
    /// The file uses Flow type annotations.
    pub flow: bool,
    /// The first error, in oxc's order.
    pub first_error: Option<SyntaxError>,
}

/// Parses `source` in `allocator`. Never panics on malformed input by itself (oxc bugs aside,
/// which callers contain with `catch_unwind`).
pub fn parse_with(allocator: &Allocator, source: &str, source_type: SourceType) -> ParseOutcome {
    let ret = Parser::new(allocator, source, source_type)
        .with_options(parse_options())
        .parse();
    let first_error = ret.diagnostics.first().map(|error| SyntaxError {
        message: error.message.to_string(),
        offset: error
            .labels
            .iter()
            .find(|label| label.primary())
            .or_else(|| error.labels.first())
            .map(|label| label.offset()),
    });
    ParseOutcome {
        statements: ret.program.body.len(),
        syntax_errors: ret.diagnostics.len(),
        fatal: ret.fatal_error,
        flow: ret.is_flow_language,
        first_error,
    }
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

/// Parses `source` with a fresh allocator and reports [`ParseStats`]. Never panics on malformed
/// input: syntax errors are counted, and a fatal error is reported in [`ParseStats::fatal`].
pub fn parse_stats(source: &str, source_type: SourceType) -> ParseStats {
    let allocator = Allocator::default();
    let outcome = parse_with(&allocator, source, source_type);
    ParseStats {
        statements: outcome.statements,
        syntax_errors: outcome.syntax_errors,
        fatal: outcome.fatal,
        flow: outcome.flow,
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
    fn every_kind_has_a_source_type() {
        for kind in SourceKind::ALL {
            for package_type in [PackageType::CommonJs, PackageType::Module] {
                let source_type = source_type(kind, package_type);
                let ts = matches!(
                    kind,
                    SourceKind::Ts | SourceKind::Tsx | SourceKind::Mts | SourceKind::Cts
                );
                assert_eq!(source_type.is_typescript(), ts, "{kind:?}");
            }
        }
        assert!(source_type(SourceKind::Mjs, PackageType::CommonJs).is_module());
        assert!(source_type(SourceKind::Mts, PackageType::CommonJs).is_module());
        assert!(!source_type(SourceKind::Cjs, PackageType::Module).is_module());
        assert!(!source_type(SourceKind::Cts, PackageType::Module).is_module());
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

    #[test]
    fn the_first_error_carries_its_offset() {
        let allocator = Allocator::default();
        let outcome = parse_with(&allocator, "let a = 1;\nlet = ;\n", st("a.js").unwrap());
        assert!(outcome.syntax_errors > 0);
        let first = outcome.first_error.unwrap();
        assert!(!first.message.is_empty());
        assert!(first.offset.is_some_and(|offset| offset >= 11), "{first:?}");
    }

    #[test]
    fn package_type_decides_whether_html_comments_are_allowed() {
        // Annex B HTML-like comments are legal in scripts but not in modules, and oxc reports
        // them as a recoverable error.
        let src = "<!-- legacy comment\nx();\n";
        let cjs = parse_stats(src, source_type(SourceKind::Js, PackageType::CommonJs));
        assert_eq!(cjs.syntax_errors, 0);
        let esm = parse_stats(src, source_type(SourceKind::Js, PackageType::Module));
        assert_eq!(esm.syntax_errors, 1);
        assert!(!esm.fatal);
        assert_eq!(esm.statements, 1);
    }

    #[test]
    fn unambiguous_mode_accepts_top_level_await() {
        // Like TypeScript, oxc's unambiguous mode parses top-level `await` as an expression.
        let src = "const data = await load();\n";
        let cjs = parse_stats(src, source_type(SourceKind::Js, PackageType::CommonJs));
        assert_eq!(cjs.syntax_errors, 0);
    }
}
