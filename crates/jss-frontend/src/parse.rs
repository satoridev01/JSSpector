//! Parsing one file with oxc and summarizing the result as owned data.

use jss_core::{PackageType, SourceKind};
use oxc_allocator::Allocator;
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;

/// The oxc [`SourceType`] for a file kind and package type.
///
/// `.js` and `.ts` follow the nearest package.json `"type"`; `.mjs`/`.mts` are always modules and
/// `.cjs`/`.cts` always CommonJS. JSX is enabled for every JavaScript kind, because React code
/// commonly puts JSX in `.js` files, but not for `.ts`, where `<T>x` is a type assertion.
///
/// `SourceType::from_path` is deliberately not used. It does not enable JSX for `.js`, and it
/// fails on non-UTF-8 file names.
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

/// TypeScript source types to try on a JavaScript file that does not parse as JavaScript, in
/// order; `None` for TypeScript kinds.
///
/// Flow-typed JavaScript (oxc does not parse Flow) is mostly valid TypeScript: annotations,
/// generics, `import type`, `export type`, interfaces. The module kind stays the same. JSX comes
/// first (Flow is common in React code), then plain TypeScript, where `<T>(x) => x` is a generic
/// arrow function rather than a JSX element.
pub fn typed_fallbacks(kind: SourceKind, package_type: PackageType) -> Option<[SourceType; 2]> {
    let typed = match kind {
        SourceKind::Js | SourceKind::Jsx => SourceKind::Ts,
        SourceKind::Mjs => SourceKind::Mts,
        SourceKind::Cjs => SourceKind::Cts,
        SourceKind::Ts | SourceKind::Tsx | SourceKind::Mts | SourceKind::Cts => return None,
    };
    let base = source_type(typed, package_type);
    Some([base.with_jsx(true), base.with_jsx(false)])
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
    /// oxc found an `@flow` pragma in a file that failed to parse.
    pub flow: bool,
    /// The first error, in oxc's order.
    pub first_error: Option<SyntaxError>,
}

/// The signature of [`parse_with`], so tests can substitute a parser.
pub type ParseFn = fn(&Allocator, &str, SourceType) -> ParseOutcome;

/// Parses `source` in `allocator`. Never panics on malformed input by itself (oxc bugs aside,
/// which callers contain with `catch_unwind`). It recurses once per nesting level: callers run
/// it on a stack sized for the input (see `process::parser_stack_bound`).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn st(kind: SourceKind) -> SourceType {
        source_type(kind, PackageType::CommonJs)
    }

    fn parse(source: &str, source_type: SourceType) -> ParseOutcome {
        let allocator = Allocator::default();
        parse_with(&allocator, source, source_type)
    }

    #[test]
    fn source_type_comes_from_the_kind() {
        assert!(st(SourceKind::Js).is_jsx(), ".js must accept JSX");
        assert!(st(SourceKind::Jsx).is_jsx());
        assert!(st(SourceKind::Ts).is_typescript());
        assert!(
            !st(SourceKind::Ts).is_jsx(),
            ".ts must not enable JSX (`<T>x` casts)"
        );
        assert!(st(SourceKind::Tsx).is_jsx());
    }

    #[test]
    fn package_type_module_makes_js_an_es_module() {
        let esm = source_type(SourceKind::Js, PackageType::Module);
        assert!(esm.is_module());
        assert!(esm.is_jsx());
    }

    #[test]
    fn every_kind_has_a_source_type() {
        for kind in SourceKind::ALL {
            for package_type in [PackageType::CommonJs, PackageType::Module] {
                let source_type = source_type(kind, package_type);
                assert_eq!(
                    source_type.is_typescript(),
                    !kind.is_javascript(),
                    "{kind:?}"
                );
            }
        }
        assert!(source_type(SourceKind::Mjs, PackageType::CommonJs).is_module());
        assert!(source_type(SourceKind::Mts, PackageType::CommonJs).is_module());
        assert!(!source_type(SourceKind::Cjs, PackageType::Module).is_module());
        assert!(!source_type(SourceKind::Cts, PackageType::Module).is_module());
    }

    #[test]
    fn typed_fallbacks_keep_the_module_kind_and_try_jsx_first() {
        for kind in SourceKind::ALL {
            for package_type in [PackageType::CommonJs, PackageType::Module] {
                let fallbacks = typed_fallbacks(kind, package_type);
                assert_eq!(fallbacks.is_some(), kind.is_javascript(), "{kind:?}");
                let Some([jsx, plain]) = fallbacks else {
                    continue;
                };
                let original = source_type(kind, package_type);
                for typed in [jsx, plain] {
                    assert!(typed.is_typescript());
                    assert_eq!(typed.is_module(), original.is_module(), "{kind:?}");
                    assert_eq!(
                        typed.is_unambiguous(),
                        original.is_unambiguous(),
                        "{kind:?}"
                    );
                }
                assert!(jsx.is_jsx());
                assert!(!plain.is_jsx());
            }
        }
    }

    #[test]
    fn jsx_in_a_dot_js_file_parses_cleanly() {
        let src = "const App = () => <div onClick={go}>hi</div>;\nexport default App;\n";
        let outcome = parse(src, st(SourceKind::Js));
        assert_eq!(
            outcome,
            ParseOutcome {
                statements: 2,
                syntax_errors: 0,
                fatal: false,
                flow: false,
                first_error: None
            }
        );
    }

    #[test]
    fn typescript_decorators_parse_cleanly() {
        let src = "@Controller('users')\nexport class UsersController {\n  @Get(':id')\n  find(@Param('id') id: string): string { return id; }\n}\n";
        let outcome = parse(src, st(SourceKind::Ts));
        assert_eq!(outcome.syntax_errors, 0);
        assert!(!outcome.fatal);
    }

    #[test]
    fn commonjs_top_level_return_is_allowed() {
        let src = "if (!module.parent) return;\nmodule.exports = function routes(app) {};\n";
        assert_eq!(parse(src, st(SourceKind::Cjs)).syntax_errors, 0);
    }

    #[test]
    fn syntax_errors_are_counted_not_panicked() {
        assert!(parse("function (", st(SourceKind::Js)).syntax_errors > 0);
    }

    #[test]
    fn the_first_error_carries_its_offset() {
        let outcome = parse("let a = 1;\nlet = ;\n", st(SourceKind::Js));
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
        let cjs = parse(src, source_type(SourceKind::Js, PackageType::CommonJs));
        assert_eq!(cjs.syntax_errors, 0);
        let esm = parse(src, source_type(SourceKind::Js, PackageType::Module));
        assert_eq!(esm.syntax_errors, 1);
        assert!(!esm.fatal);
        assert_eq!(esm.statements, 1);
    }

    #[test]
    fn unambiguous_mode_accepts_top_level_await() {
        // Like TypeScript, oxc's unambiguous mode parses top-level `await` as an expression.
        let src = "const data = await load();\n";
        let cjs = parse(src, source_type(SourceKind::Js, PackageType::CommonJs));
        assert_eq!(cjs.syntax_errors, 0);
    }

    #[test]
    fn flow_files_fail_as_javascript_and_parse_as_typescript() {
        let src = "// @flow\nimport type { Config } from './Config';\n\
                   export function load<T>(name: string, config: Config): T {\n  return null;\n}\n";
        let js = parse(src, st(SourceKind::Js));
        assert!(js.fatal);
        assert!(js.flow, "oxc reports the pragma");
        let [jsx, plain] = typed_fallbacks(SourceKind::Js, PackageType::CommonJs).unwrap();
        for typed in [jsx, plain] {
            let outcome = parse(src, typed);
            assert!(!outcome.fatal, "{outcome:?}");
            assert_eq!(outcome.syntax_errors, 0, "{outcome:?}");
            assert_eq!(outcome.statements, 2);
        }
    }
}
