//! Parsing Flow-typed JavaScript.
//!
//! oxc parses TypeScript but not Flow. The two share most type syntax (annotations, generics,
//! `import type`, `export type`, interfaces, `readonly`, `unknown`, `extends` bounds), so a Flow
//! file is first read as TypeScript, which covers most of them (see
//! [`crate::typed_fallbacks`]). What is left is a short list of Flow-only spellings: `...` in
//! object types, `string => void` without parentheses, `import typeof`, `declare export`,
//! `opaque type`, `Foo<>`, `(x: T)` casts, `interface { }` types, and a few more (see [`rules`]).
//!
//! [`parse_repaired`] erases them one at a time: parse as TypeScript, take the first syntax
//! error, let the rule that knows the construct blank it, parse again. TypeScript is the
//! oracle for what is a type, so nothing here has to understand JavaScript's grammar, and a
//! construct no rule knows leaves the file exactly as unparseable as it was.
//!
//! The repaired text only feeds the parser. It has the same length as the file, with line
//! breaks in the same places, so offsets, lines and columns mean the same thing in both. Rules
//! blank only types and type-only declarations, never code that runs.

mod rules;
mod scan;

use oxc_allocator::Allocator;
use oxc_span::SourceType;

use crate::parse::{ParseFn, ParseOutcome};

/// The result of parsing one file as TypeScript after repairing its Flow-only syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Repair {
    /// The last parse: clean when every Flow-only construct had a rule, otherwise it shows the
    /// first one that did not.
    pub(crate) outcome: ParseOutcome,
    /// How many ranges were blanked.
    pub(crate) edits: u32,
}

impl Repair {
    /// A parse that was not repaired: for a file that JavaScript already parses, where there is
    /// no Flow-only syntax to erase and nothing may be changed.
    pub(crate) fn unrepaired(outcome: ParseOutcome) -> Self {
        Self { outcome, edits: 0 }
    }
}

/// Most repair rounds for a file of `len` bytes. Every round parses the file again, so this keeps
/// the work for one file under about 32 MiB of parsing, however many constructs it has: a
/// small file may take thousands of rounds, a 2 MiB one a handful.
fn max_rounds(len: usize) -> usize {
    const BYTES_PARSED_AT_MOST: usize = 32 * 1024 * 1024;
    (BYTES_PARSED_AT_MOST / len.max(1)).clamp(8, 4096)
}

/// Parses `source` as `source_type` (TypeScript), repairing Flow-only syntax. `pragma` is whether
/// the file declares itself Flow (`@flow`): without it only the rules whose shapes are Flow's
/// alone apply, until one of them fires and proves it (see `rules::Evidence`). `allocator` is
/// used for the first parse; every later round uses a fresh arena, so a file that needs many
/// rounds does not pile their ASTs up in the worker's allocator.
pub(crate) fn parse_repaired(
    allocator: &Allocator,
    source: &str,
    source_type: SourceType,
    parse: ParseFn,
    pragma: bool,
) -> Repair {
    let first = parse(allocator, source, source_type);
    if first.syntax_errors == 0 {
        return Repair {
            outcome: first,
            edits: 0,
        };
    }
    let (_, repair, _) = repair_rounds(source, source_type, parse, first, pragma);
    repair
}

/// Prints each repair as it is made when `JSS_FLOW_TRACE` is set: which rule fixed which error.
/// For working out why a file is repaired the way it is; off in normal runs.
fn trace(rule: &str, text: &str, offset: usize, message: &str) {
    if std::env::var_os("JSS_FLOW_TRACE").is_some() {
        let around = text
            .get(offset..)
            .unwrap_or("")
            .chars()
            .take(40)
            .collect::<String>();
        eprintln!("flow: {rule} at {offset} ({message}): {around:?}");
    }
}

/// One range blanked by one rule, in offsets of the original text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Applied {
    rule: &'static str,
    start: usize,
    end: usize,
}

/// The repair loop; also returns the repaired text and what was applied.
fn repair_rounds(
    source: &str,
    source_type: SourceType,
    parse: ParseFn,
    first: ParseOutcome,
    pragma: bool,
) -> (String, Repair, Vec<Applied>) {
    let mut text = source.to_owned();
    let mut outcome = first;
    let mut edits = 0u32;
    let mut applied = Vec::new();
    let mut flow = pragma;
    for _ in 0..max_rounds(source.len()) {
        let Some(error) = outcome.first_error.as_ref() else {
            break;
        };
        let Some(offset) = error.offset.and_then(|offset| usize::try_from(offset).ok()) else {
            break;
        };
        let Some(fix) = rules::step(&text, offset, &error.message, flow) else {
            break;
        };
        trace(fix.rule, &text, offset, &error.message);
        let Some(repaired) = rules::apply(&text, &fix.edits) else {
            break;
        };
        flow |= fix.proves_flow;
        edits = edits.saturating_add(u32::try_from(fix.edits.len()).unwrap_or(u32::MAX));
        applied.extend(fix.edits.iter().map(|edit| Applied {
            rule: fix.rule,
            start: edit.start,
            end: edit.end,
        }));
        text = repaired;
        outcome = parse(&Allocator::default(), &text, source_type);
        if outcome.syntax_errors == 0 {
            break;
        }
    }
    (text, Repair { outcome, edits }, applied)
}

#[cfg(test)]
mod tests {
    use jss_core::{PackageType, SourceKind};

    use super::*;
    use crate::parse::{parse_with, typed_fallbacks};

    /// The TypeScript syntax Flow files are read as: JSX on, or off.
    fn flavor(jsx: bool) -> SourceType {
        let [with_jsx, plain] = typed_fallbacks(SourceKind::Js, PackageType::CommonJs).unwrap();
        if jsx { with_jsx } else { plain }
    }

    fn run(src: &str, jsx: bool) -> (String, Repair) {
        run_with(src, jsx, true)
    }

    fn run_with(src: &str, jsx: bool, pragma: bool) -> (String, Repair) {
        let source_type = flavor(jsx);
        let first = parse_with(&Allocator::default(), src, source_type);
        if first.syntax_errors == 0 {
            return (
                src.to_owned(),
                Repair {
                    outcome: first,
                    edits: 0,
                },
            );
        }
        let (text, repair, _) = repair_rounds(src, source_type, parse_with, first, pragma);
        (text, repair)
    }

    /// `src` with each part replaced by blanks of its length (the first occurrence of each).
    fn blanked(src: &str, parts: &[&str]) -> String {
        let mut out = src.to_owned();
        for part in parts {
            let at = out
                .find(part)
                .unwrap_or_else(|| panic!("{part:?} not in {src:?}"));
            let blanks = part
                .chars()
                .map(|c| if c == '\n' { '\n' } else { ' ' })
                .collect::<String>();
            out.replace_range(at..at + part.len(), &blanks);
        }
        out
    }

    /// `src` with `from` replaced by `fill` followed by blanks.
    fn swapped(src: &str, from: &str, fill: &str) -> String {
        let at = src.find(from).unwrap();
        let mut out = src.to_owned();
        let mut text = fill.to_owned();
        while text.len() < from.len() {
            text.push(' ');
        }
        out.replace_range(at..at + from.len(), &text);
        out
    }

    /// Repairing `src` gives `expected`, which parses cleanly, keeps the length and every
    /// line break, and is itself left alone by a second repair.
    fn assert_repairs(src: &str, expected: &str) {
        let (text, repair) = run(src, true);
        assert_eq!(text, expected, "repaired text of {src:?}");
        assert_eq!(text.len(), src.len());
        let breaks = |s: &str| s.match_indices('\n').map(|(at, _)| at).collect::<Vec<_>>();
        assert_eq!(breaks(&text), breaks(src), "line breaks of {src:?}");
        assert_eq!(repair.outcome.syntax_errors, 0, "{src:?}: {repair:?}");
        assert!(!repair.outcome.fatal);
        assert!(repair.edits > 0);
        let (again, second) = run(&text, true);
        assert_eq!(again, text, "a repaired text needs no further repair");
        assert_eq!(second.edits, 0);
    }

    #[test]
    fn object_type_spread_and_inexact_markers() {
        let src = "type A = {...B, c: number};\ntype D = {e: string, ...};\n";
        assert_repairs(src, &blanked(src, &["...B,", "..."]));
        let src = "type A = {a: number, ...$ReadOnly<{b: Array<C>}>};\n";
        assert_repairs(src, &blanked(src, &["...$ReadOnly<{b: Array<C>}>"]));
        let src = "type A = {\n  ...B,\n  ...C,\n  d: D,\n  ...\n};\n";
        assert_repairs(src, &blanked(src, &["...B,", "...C,", "..."]));
        let src = "function f(opts: {shallow: boolean, ...}): void {}\n";
        assert_repairs(src, &blanked(src, &["..."]));
    }

    #[test]
    fn import_typeof_is_spelled_type() {
        let src =
            "import typeof Yargs from 'yargs';\nimport typeof * as Types from '@babel/types';\n";
        let expected = swapped(&swapped(src, "typeof Yargs", "type"), "typeof * as", "type");
        // `swapped` replaced only the keyword's own bytes.
        assert_eq!(expected.len(), src.len());
        let (text, repair) = run(src, true);
        assert_eq!(repair.outcome.syntax_errors, 0, "{repair:?}");
        assert_eq!(text.len(), src.len());
        assert!(text.starts_with("import type   Yargs"), "{text}");
        assert!(text.contains("import type   * as Types"), "{text}");
        let src = "import {typeof SourceMapConsumer, other} from 'source-map';\n";
        let (text, repair) = run(src, true);
        assert_eq!(repair.outcome.syntax_errors, 0, "{repair:?}");
        assert!(
            text.starts_with("import {type   SourceMapConsumer"),
            "{text}"
        );
    }

    #[test]
    fn declare_statements_typescript_rejects_are_erased_whole() {
        for src in [
            "declare export type AST = any;\n",
            "declare export var CHILD_MESSAGE_INITIALIZE: 0;\n",
            "declare export function f(x: number): string;\n",
            "declare export default class A { m(): void }\n",
            "declare export default (x: number) => string;\n",
            "declare export { a, b } from 'x';\n",
            "declare export * from 'x';\n",
            "declare opaque type Wrapper;\n",
            "declare function f(x: mixed): boolean %checks(!!x);\n",
            "declare class A<T> extends B<{a: T}> mixins C { static m(): void; x: T }\n",
            "declare module.exports: (req: Request) => {a: number};\n",
        ] {
            assert_repairs(src, &blanked(src, &[src.trim_end_matches('\n')]));
        }
    }

    #[test]
    fn declare_statements_typescript_reads_are_left_alone() {
        for src in [
            "declare type T = {a: number};\n",
            "declare interface Formatters { x: string }\n",
            "declare var x: number;\n",
            "declare function f(x: number): string;\n",
            "declare class A { m(): void }\n",
        ] {
            let (text, repair) = run(src, true);
            assert_eq!(text, src);
            assert_eq!(repair.edits, 0);
            assert_eq!(repair.outcome.syntax_errors, 0, "{src:?}");
        }
    }

    #[test]
    fn a_declare_module_is_erased_with_everything_inside() {
        let src = "// flow-typed\ndeclare module 'yargs' {\n  declare export type A = number;\n  declare module.exports: A;\n}\nconst x = 1;\n";
        let expected = blanked(
            src,
            &[
                "declare module 'yargs' {\n  declare export type A = number;\n  declare module.exports: A;\n}",
            ],
        );
        assert_repairs(src, &expected);
        // One round, not one per inner declaration.
        let (_, repair) = run(src, true);
        assert_eq!(repair.edits, 1);
    }

    #[test]
    fn opaque_types_are_erased() {
        let src = "export opaque type RevisionId: string = string;\nopaque type Id = number;\n";
        assert_repairs(
            src,
            &blanked(
                src,
                &[
                    "export opaque type RevisionId: string = string;",
                    "opaque type Id = number;",
                ],
            ),
        );
    }

    #[test]
    fn type_casts_lose_their_annotation() {
        let src = "const a = (b: any);\nconst c = ((d: any): E);\nf((g.h: I).j, k);\nconst l = ({ ...m || {} }: N.O);\n";
        assert_repairs(
            src,
            &blanked(src, &[": any", ": any", ": E", ": I", ": N.O"]),
        );
    }

    #[test]
    fn function_types_without_parentheses_become_any() {
        let src = "type F = string => void;\nconst g: Error => number = h;\ntype I = {cb: Array<string> => void, n: number};\n";
        assert_repairs(
            src,
            &swapped(
                &swapped(
                    &swapped(src, "string => void", "any"),
                    "Error => number",
                    "any",
                ),
                "Array<string> => void",
                "any",
            ),
        );
        let src = "let b: ?(HTMLElement => (('down' | 'up', Event) => void));\n";
        assert_repairs(
            src,
            &swapped(
                src,
                "HTMLElement => (('down' | 'up', Event) => void)",
                "any",
            ),
        );
        let src =
            "x.forEach((c: T => void) => c(res));\nfunction f(cb: A => B => C, n: number) {}\n";
        assert_repairs(
            src,
            &swapped(&swapped(src, "T => void", "any"), "A => B => C", "any"),
        );
    }

    #[test]
    fn function_types_in_unions_become_any() {
        let src =
            "type P = RegExp | string | (cmd: string, val: string) => false | void | null | T;\n";
        assert_repairs(
            src,
            &swapped(
                src,
                "(cmd: string, val: string) => false | void | null | T",
                "any",
            ),
        );
    }

    #[test]
    fn small_flow_only_spellings() {
        let src = "let a: Foo<> = b;\nlet c: Array<Module<>> = d;\n";
        assert_repairs(src, &blanked(src, &["<>", "<>"]));
        let src = "function f(): ?Promise<*> {}\n";
        assert_repairs(src, &swapped(src, "*", "_"));
        let src = "async function f(card: interface { getTarget(): HTMLElement }) {}\n";
        assert_repairs(src, &blanked(src, &["interface"]));
        let src = "function f(a?: number = 1, {b}?: C = {}) {}\n";
        assert_repairs(src, &blanked(src, &["?", "?"]));
        let src = "function f(a?: string, b: number) {}\n";
        assert_repairs(src, &blanked(src, &["?"]));
        let src = "type A = {+a: number, -b: string};\nclass B { +c: number; static -d: string }\n";
        assert_repairs(src, &blanked(src, &["+", "-", "+", "-"]));
        let src = "type A = {|a: number|};\ntype B = {||};\n";
        assert_repairs(src, &blanked(src, &["|", "|", "|", "|"]));
        let src = "function f(x: mixed): boolean %checks { return !!x; }\n";
        assert_repairs(src, &blanked(src, &["%checks"]));
    }

    #[test]
    fn a_flow_file_with_many_constructs_is_repaired_in_one_pass_per_construct() {
        let src = "\
// @flow
import typeof Foo from './foo';
import type { Config } from './config';

opaque type Id = string;
export type Options = {| ...Config, mount?: string, +id: Id |};
type Handler = (req: Request) => void;
type Callback = Error => void;

export function load<T>(name: string, cb: Callback, opts?: Options = {}): ?Promise<*> {
  const c = (opts: any);
  return c;
}
";
        let (text, repair) = run(src, true);
        assert_eq!(repair.outcome.syntax_errors, 0, "{repair:?}\n{text}");
        assert!(repair.edits >= 7, "{repair:?}");
        assert_eq!(text.len(), src.len());
        // Code that runs is untouched.
        for kept in [
            "export function load<T>(name: string",
            "const c = (opts",
            "return c;",
        ] {
            assert!(text.contains(kept), "{kept:?} missing from\n{text}");
        }
    }

    #[test]
    fn text_without_flow_only_syntax_is_never_changed() {
        for src in [
            "const a = (b, c) => b ? c : (d) => e;\n",
            "type A = { a: number };\nfunction f<T>(x: T): T { return x; }\n",
            "const o = {...a, b, ...c};\nconst [x, ...rest] = list;\nf(...args);\n",
            "import type { A } from './a';\nexport type { A };\nexport interface I { m(): void }\n",
            "const x = a < b && c > d;\nlet y = a<b>(c);\n",
        ] {
            let (text, repair) = run(src, true);
            assert_eq!(text, src);
            assert_eq!(repair.edits, 0, "{src:?}");
        }
    }

    #[test]
    fn what_no_rule_knows_is_left_failing_untouched() {
        // Flow's component syntax is runtime code: no rule erases it, so the file stays
        // unparseable and the error says where.
        let src = "component Foo() {}\nconst x = 1;\n";
        let (text, repair) = run(src, true);
        assert_eq!(text, src);
        assert_eq!(repair.edits, 0);
        assert!(repair.outcome.syntax_errors > 0);
        // A broken file that is not Flow at all.
        let src = "const x = {{ y }};\n";
        let (text, repair) = run(src, true);
        assert_eq!(text, src);
        assert!(repair.outcome.syntax_errors > 0);
    }

    #[test]
    fn partial_repairs_report_the_error_that_remains() {
        let src = "import typeof A from 'a';\ncomponent E() {}\n";
        let (text, repair) = run(src, true);
        assert!(text.starts_with("import type   A"), "{text}");
        assert_eq!(repair.edits, 1);
        let error = repair.outcome.first_error.unwrap();
        // The remaining error is on the second line, in original coordinates.
        assert!(error.offset.unwrap() >= 26, "{error:?}");
    }

    #[test]
    fn generic_arrow_functions_need_the_plain_flavor() {
        let src = "const id = <T>(x: T): T => x;\ntype A = {...B, c: C};\n";
        let (_, with_jsx) = run(src, true);
        assert!(with_jsx.outcome.syntax_errors > 0, "{with_jsx:?}");
        let (text, plain) = run(src, false);
        assert_eq!(plain.outcome.syntax_errors, 0, "{plain:?}");
        assert!(text.starts_with("const id = <T>(x: T): T => x;"));
    }

    #[test]
    fn multibyte_text_around_edits_keeps_every_offset() {
        let src = "const ñ = 'é';\ntype A = {...B, ü: string}; // ü\nconst z = (ñ: any);\n";
        let (text, repair) = run(src, true);
        assert_eq!(repair.outcome.syntax_errors, 0, "{repair:?}");
        assert_eq!(text.len(), src.len());
        assert!(text.starts_with("const ñ = 'é';\n"));
        assert!(text.contains("// ü\n"));
    }

    #[test]
    fn apply_refuses_edits_it_cannot_keep_the_same_length() {
        let src = "type A = string => void;";
        let edit = |start: usize, end: usize, fill: &'static str| rules::Edit { start, end, fill };
        // Overlap, empty range, out of range, a fill longer than its range.
        assert!(rules::apply(src, &[edit(0, 4, ""), edit(2, 6, "")]).is_none());
        assert!(rules::apply(src, &[edit(3, 3, "")]).is_none());
        assert!(rules::apply(src, &[edit(0, 999, "")]).is_none());
        assert!(rules::apply(src, &[edit(0, 2, "any")]).is_none());
        // A fill that a line break would cut in two.
        assert!(rules::apply("a\nb", &[edit(0, 3, "any")]).is_none());
        // Not on a character boundary.
        assert!(rules::apply("é", &[edit(1, 2, "")]).is_none());
        let ok = rules::apply(src, &[edit(9, 23, "any")]).unwrap();
        assert_eq!(ok, "type A = any           ;");
    }

    #[test]
    fn function_types_with_unnamed_parameters_lose_their_parameters() {
        for (src, params) in [
            ("type F = (string, ?Error) => void;\n", "string, ?Error"),
            ("type G = ('data', Handler) => R;\n", "'data', Handler"),
            (
                "type H = (Iterable<T>, (T) => S) => X<S>;\n",
                "Iterable<T>, (T) => S",
            ),
            ("type I = ([A, Array<B>]) => boolean;\n", "[A, Array<B>]"),
            (
                "type J = (ReadonlyArray<ReturnType<typeof f>>) => void;\n",
                "ReadonlyArray<ReturnType<typeof f>>",
            ),
            (
                "type K = (Thing, Filter | null) => void;\n",
                "Thing, Filter | null",
            ),
            (
                "type L = {reconcile: ?((Array<any>) => any)};\n",
                "Array<any>",
            ),
            (
                "type M = {callback: (?Error, ?number) => unknown};\n",
                "?Error, ?number",
            ),
            // Named and unnamed parameters mix, and an unnamed one may be an object type.
            (
                "type N = (line: string, ((err: ?Error, data: [Array<string>, string]) => void)) => void;\n",
                "line: string, ((err: ?Error, data: [Array<string>, string]) => void)",
            ),
            (
                "type S = (string, {readonly sourceRoot?: ?string, ...}) => string;\n",
                "string, {readonly sourceRoot?: ?string, ...}",
            ),
        ] {
            assert_repairs(src, &blanked(src, &[params]));
        }
        // The same in a method signature.
        let src = "interface I { processFile(WorkerMessage, Readonly<{getContent: () => Buffer}>): V8; }\n";
        assert_repairs(
            src,
            &blanked(
                src,
                &["WorkerMessage, Readonly<{getContent: () => Buffer}>"],
            ),
        );
        let src = "type T = { addParams(string, ...Array<unknown>): string, other: number };\n";
        assert_repairs(src, &blanked(src, &["string, ...Array<unknown>"]));
    }

    #[test]
    fn code_that_runs_next_to_unnamed_parameter_types_is_untouched() {
        let src = "type F = (?Error) => void;\nconst g = (a, b) => a + b;\nconst h = x => x;\n";
        let (text, repair) = run(src, true);
        assert_eq!(text, blanked(src, &["?Error"]), "{repair:?}");
        // Named parameters are what TypeScript reads as they are: never blanked.
        let src = "type F = (a: string, b?: number, ...rest: Array<T>) => void;\n";
        assert_eq!(run(src, true).0, src);
    }

    #[test]
    fn function_types_as_union_members_become_any() {
        let src = "type U = string | () => string;\nfunction f(key: string | () => string /* pure */, d: T) {}\n";
        assert_repairs(
            src,
            &swapped(&swapped(src, "() => string", "any"), "() => string", "any"),
        );
    }

    #[test]
    fn type_parameter_bounds_and_variance_go() {
        let src = "function f<T: Object, U: {a: number} = V>(x: T) {}\nclass A { m<T: {[key: string]: any}>(a: T, b: T) {} }\n";
        assert_repairs(
            src,
            &blanked(
                src,
                &[": Object", ": {a: number}", ": {[key: string]: any}"],
            ),
        );
        let src =
            "type T<+A, -B> = A;\nclass C<+T, -U: Object> { static +x: number; -y: string; }\n";
        assert_repairs(
            src,
            &blanked(src, &["+", "-", "+", "-", ": Object", "+", "-"]),
        );
    }

    #[test]
    fn small_guards_predicates_and_mapped_types() {
        let src = "function f(x: unknown): implies x is string { return true; }\n";
        assert_repairs(src, &blanked(src, &["implies"]));
        let src = "type M<T> = {[K in keyof T]: T[K],};\ntype N<T> = {\n  [K in keyof T]: T[K] extends void ? void | T[K] : T[K],\n};\n";
        assert_repairs(src, &blanked(src, &[",", ","]));
        let src = "const x: interface {} = y;\n";
        assert_repairs(src, &blanked(src, &["interface"]));
        let src = "type T = [A, B, ...];\ntype U = [\n  C,\n  ...\n];\n";
        assert_repairs(src, &blanked(src, &["...", "..."]));
        let src = "const f = (x): %checks => !!x;\n";
        assert_repairs(src, &blanked(src, &[": %checks"]));
        let src = "type O = {get c(): number, set c(v: number): void};\n";
        assert_repairs(src, &blanked(src, &[": void"]));
    }

    #[test]
    fn a_cast_in_the_consequent_of_a_conditional_loses_its_annotation() {
        let src = "const a = b ? (c: any) : d;\nconst e = f ? (g: H).i : j;\n";
        assert_repairs(src, &blanked(src, &[": any", ": H"]));
        // Code that is only a conditional is left alone.
        let src = "const a = b ? (c) : d;\nconst e = f ? (g) : h => i;\n";
        assert_eq!(run(src, true).0, src);
    }

    #[test]
    fn code_that_runs_is_never_blanked_when_a_parameter_annotation_has_flow_syntax() {
        // oxc gives up on the parameters of these arrow functions at the colon of an annotation,
        // before it reaches the Flow syntax inside: the parameters and the body must survive, and
        // only the Flow-only token goes.
        for (src, flow_only) in [
            (
                "const f = ({ id }: { id: string, ... }) => {\n  return id;\n};\n",
                vec!["..."],
            ),
            (
                "const f = ({ id, depth = 0 }: { id: string, depth?: number, ... }) => {\n  return id + depth;\n};\n",
                vec!["..."],
            ),
            (
                "const f = ({ id }: Props<>) => {\n  return id;\n};\n",
                vec!["<>"],
            ),
            (
                "const f = async ({ id }: {| id: string |}) => {\n  await id;\n};\n",
                vec!["|", "|"],
            ),
            (
                "function g({ a }: { a: ?T, ... }): void {\n  run(a);\n}\n",
                vec!["..."],
            ),
            (
                "class A {\n  m({ a }: { a: T, ... }): void {\n    run(a);\n  }\n}\n",
                vec!["..."],
            ),
            ("const f = ([a, b]: [A, B, ...]) => a + b;\n", vec!["..."]),
        ] {
            assert_repairs(src, &blanked(src, &flow_only));
        }
    }

    #[test]
    fn runtime_code_that_looks_like_flow_survives_next_to_flow() {
        // Every line marked `// RT` is code that runs and has the shape of something a rule
        // blanks: a curried arrow (`type => type` looks like a bare function type), a conditional
        // in parentheses (like a cast), a JSX fragment (`<>`), object spread and rest (`...`), an
        // arrow's own parameters (like an unnamed-parameter list), a default value after an
        // annotation. Lines marked `// FLOW` have Flow-only syntax. The repair must leave every
        // RT line byte for byte and change every FLOW line.
        let src = "\
// @flow
const curried = () => type => type; // RT
const pick = (a ? b : c); // RT
const merged = {...base, extra: 1, ...more}; // RT
const [first, ...rest] = list; // RT
const sum = (a, b) => a + b; // RT
const view = <><div className=\"x\">{label}</div></>; // RT
const apply = (fn, ...args) => fn(...args); // RT
const slice = (n = (a ? 1 : 2)) => n; // RT
type Props = {a: number, ...Base}; // FLOW
type Cb = string => void; // FLOW
export const f = (x: Props = {a: 1}): string => (x.a ? 'y' : 'n'); // RT-AFTER-TYPES
const c = (list: any); // FLOW
const label2 = cond ? (a) : b => b; // RT
";
        let (text, repair) = run(src, true);
        assert_eq!(repair.outcome.syntax_errors, 0, "{repair:?}\n{text}");
        let original: Vec<&str> = src.lines().collect();
        let repaired: Vec<&str> = text.lines().collect();
        assert_eq!(original.len(), repaired.len());
        for (before, after) in original.iter().zip(&repaired) {
            if before.ends_with("// RT") || before.ends_with("// RT-AFTER-TYPES") {
                assert_eq!(before, after, "runtime line changed");
            }
            if before.ends_with("// FLOW") {
                assert_ne!(before, after, "Flow-only line left alone: {before}");
            }
        }
    }

    #[test]
    fn only_rules_that_cannot_be_broken_code_run_without_the_pragma() {
        // These shapes could be a broken file rather than Flow: not repaired without `@flow`.
        for src in [
            "type A = {...B, c: number};\n",
            "const a = (b: any);\n",
            "type F = string => void;\n",
            "type F = (?Error) => void;\n",
            "function f<T: Object>(x: T) {}\n",
        ] {
            let (text, repair) = run_with(src, true, false);
            assert_eq!(text, src, "{src:?}");
            assert_eq!(repair.edits, 0);
            assert!(repair.outcome.syntax_errors > 0, "{src:?}");
        }
        // These only exist in Flow, pragma or not.
        let src =
            "declare export type A = number;\nopaque type B = string;\nimport typeof C from 'c';\n";
        let (text, repair) = run_with(src, true, false);
        assert_eq!(repair.outcome.syntax_errors, 0, "{repair:?}\n{text}");
        assert_eq!(repair.edits, 3);
        let src = "type A = {a: number, ...};\ntype B = {|a: number|};\nlet c: Foo<> = d;\n";
        let (_, repair) = run_with(src, true, false);
        assert_eq!(repair.outcome.syntax_errors, 0, "{repair:?}");
        assert_eq!(repair.edits, 4);
    }

    #[test]
    fn a_file_that_showed_flow_for_certain_gets_the_ambiguous_rules_too() {
        // No pragma, but the inexact marker can only be Flow; after it the rest is read as Flow.
        let src = "type A = {a: number, ...};\ntype F = string => void;\nconst c = (d: any);\n";
        let (text, repair) = run_with(src, true, false);
        assert_eq!(repair.outcome.syntax_errors, 0, "{repair:?}\n{text}");
        assert_eq!(repair.edits, 3);
        // Without the marker, the same two lines stay broken.
        let src = "type F = string => void;\nconst c = (d: any);\n";
        let (text, repair) = run_with(src, true, false);
        assert_eq!(text, src);
        assert!(repair.outcome.syntax_errors > 0);
    }

    #[test]
    fn a_parameter_with_a_default_is_never_taken_for_a_cast() {
        // oxc reads the arrow's parameters as a cast and stops at what follows them; the
        // annotation of `platform` ends before its default, which is code that runs.
        let src = "export const f = (\n  platform: 'win32' | 'posix' = process.platform === 'win32'\n    ? 'win32'\n    : 'posix',\n): (string => string) =>\n  platform === 'win32'\n    ? p => p.replace('/', '\\\\')\n    : p => p;\n";
        let (text, repair) = run(src, true);
        assert_eq!(repair.outcome.syntax_errors, 0, "{repair:?}\n{text}");
        // The parameter, its default and the body are untouched; only the return type's inner
        // function type went, with the parentheses that grouped it.
        for kept in [
            "platform: 'win32' | 'posix' = process.platform === 'win32'",
            "? p => p.replace('/'",
            ": p => p;",
        ] {
            assert!(text.contains(kept), "{kept:?} missing from\n{text}");
        }
        assert!(text.contains("): any"), "{text}");
    }

    #[test]
    fn constructor_return_types_go() {
        let src = "class A {\n  constructor(x: T): Self {\n    return x;\n  }\n}\n";
        assert_repairs(src, &blanked(src, &[": Self"]));
    }

    #[test]
    fn jsx_misreading_of_generic_arrow_functions_is_never_repaired() {
        // Read as JSX, `<T>(x: T): T => x;` is an element with text; the error lands inside the
        // `=>` token. No rule may take that for a function type: the plain flavor is the answer.
        let src = "export const f = <T>(x: T): T => x;\n";
        let (text, repair) = run(src, true);
        assert_eq!(text, src);
        assert_eq!(repair.edits, 0);
        assert!(repair.outcome.syntax_errors > 0);
        let (text, repair) = run(src, false);
        assert_eq!(text, src);
        assert_eq!(repair.outcome.syntax_errors, 0);
    }

    /// Audits real files, not part of the normal run:
    ///
    /// `JSS_FLOW_AUDIT_DIRS=/path/a:/path/b cargo test -p jss-frontend audit_corpus -- --ignored --nocapture`
    ///
    /// For every JavaScript file under those directories that needs repair, it checks each blanked
    /// range for tokens that exist in code that runs and never in a type (`return`, `await`,
    /// `new`, `&&`, `++`, templates, regexes, ...). A range with one is printed: a rule took
    /// code with it. Files are only read, never executed.
    #[test]
    #[ignore = "audits the directories named by JSS_FLOW_AUDIT_DIRS"]
    fn audit_corpus() {
        let Some(dirs) = std::env::var_os("JSS_FLOW_AUDIT_DIRS") else {
            return;
        };
        let dirs: Vec<std::path::PathBuf> = std::env::split_paths(&dirs).collect();
        // The pipeline's stack discipline: the parser recurses, so give it room.
        let worker = std::thread::Builder::new()
            .stack_size(512 * 1024 * 1024)
            .spawn(move || audit(&dirs))
            .unwrap();
        worker.join().unwrap();
    }

    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            let name = entry.file_name();
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                if name != ".git" && name != "node_modules" {
                    walk(&path, out);
                }
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("js" | "jsx" | "mjs" | "cjs")
            ) {
                out.push(path);
            }
        }
    }

    /// A token that runs: it cannot be part of a type.
    fn runs(toks: &scan::Toks<'_>) -> Option<String> {
        use scan::Kind;
        for i in 0..toks.len() {
            let text = toks.text(i);
            let kind = toks.kind(i);
            if kind == Some(Kind::Template) || kind == Some(Kind::Regex) {
                return Some(text.to_owned());
            }
            if kind == Some(Kind::Ident)
                && matches!(
                    text,
                    "return"
                        | "if"
                        | "else"
                        | "for"
                        | "while"
                        | "do"
                        | "switch"
                        | "case"
                        | "break"
                        | "continue"
                        | "throw"
                        | "try"
                        | "catch"
                        | "finally"
                        | "new"
                        | "delete"
                        | "await"
                        | "yield"
                )
            {
                return Some(text.to_owned());
            }
            let pair = |a: &str| toks.is(i, a) && toks.is(i + 1, a) && toks.adjacent(i, i + 1);
            // `{||}` is the empty exact object type; `&&`, `++`, `--` are not types.
            if pair("&") || pair("+") || pair("-") || (pair("|") && !toks.prev_adjacent_brace(i)) {
                return Some(format!("{text}{text}"));
            }
            if toks.is(i, "!") || toks.is(i, "~") || toks.is(i, "^") || toks.is(i, "/") {
                return Some(text.to_owned());
            }
            if toks.is(i, "=") && toks.is(i + 1, "=") && toks.adjacent(i, i + 1) {
                return Some("==".to_owned());
            }
        }
        None
    }

    /// One line for a human or an agent to read: tabs and line breaks made visible.
    fn visible(text: &str) -> String {
        text.replace('\t', "→").replace('\n', "⏎").replace('\r', "")
    }

    fn audit(dirs: &[std::path::PathBuf]) {
        use std::collections::BTreeMap;
        use std::io::Write as _;
        // JSS_FLOW_AUDIT_DUMP=file: one line per blanked range, with its surroundings.
        // JSS_FLOW_AUDIT_OUT=dir: the repaired text of every repaired file.
        let mut dump = std::env::var_os("JSS_FLOW_AUDIT_DUMP")
            .and_then(|path| std::fs::File::create(path).ok());
        let out_dir = std::env::var_os("JSS_FLOW_AUDIT_OUT").map(std::path::PathBuf::from);
        let mut files = Vec::new();
        for dir in dirs {
            walk(dir, &mut files);
        }
        let mut stats: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();
        let (mut candidates, mut repaired, mut still_failing, mut flagged) = (0, 0, 0, 0);
        let mut largest: Vec<(usize, String)> = Vec::new();
        for path in &files {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            if text.len() > 2 * 1024 * 1024
                || crate::parser_stack_bound(text.as_bytes()) > crate::WORKER_STACK_BYTES
            {
                continue;
            }
            let kind = match path.extension().and_then(|e| e.to_str()) {
                Some("jsx") => SourceKind::Jsx,
                Some("mjs") => SourceKind::Mjs,
                Some("cjs") => SourceKind::Cjs,
                _ => SourceKind::Js,
            };
            let primary = parse_with(
                &Allocator::default(),
                &text,
                crate::parse::source_type(kind, PackageType::CommonJs),
            );
            if primary.syntax_errors == 0 && !primary.flow {
                continue;
            }
            let Some(flavors) = typed_fallbacks(kind, PackageType::CommonJs) else {
                continue;
            };
            candidates += 1;
            let pragma = text
                .chars()
                .take(4096)
                .collect::<String>()
                .contains("@flow");
            let mut result = None;
            for flavor in flavors {
                let first = parse_with(&Allocator::default(), &text, flavor);
                let done = repair_rounds(&text, flavor, parse_with, first, pragma);
                let clean = done.1.outcome.syntax_errors == 0;
                result = Some(done);
                if clean {
                    break;
                }
            }
            let Some((fixed, repair, applied)) = result else {
                continue;
            };
            if repair.outcome.syntax_errors > 0 {
                still_failing += 1;
                println!(
                    "STILL FAILING {}: {:?}",
                    path.display(),
                    repair.outcome.first_error
                );
                continue;
            }
            if applied.is_empty() {
                continue;
            }
            repaired += 1;
            assert_eq!(fixed.len(), text.len(), "{}", path.display());
            if let Some(dir) = &out_dir {
                let flat = path.display().to_string().replace(['/', '\\'], "__");
                let _ = std::fs::create_dir_all(dir);
                let _ = std::fs::write(dir.join(flat), &fixed);
            }
            for range in &applied {
                let entry = stats.entry(range.rule).or_default();
                entry.0 += 1;
                entry.1 += range.end - range.start;
                let original = text.get(range.start..range.end).unwrap_or("");
                if let Some(dump) = dump.as_mut() {
                    let before = text
                        .get(..range.start)
                        .unwrap_or("")
                        .chars()
                        .rev()
                        .take(80)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<String>();
                    let after = text
                        .get(range.end..)
                        .unwrap_or("")
                        .chars()
                        .take(80)
                        .collect::<String>();
                    let _ = writeln!(
                        dump,
                        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                        range.rule,
                        path.display(),
                        range.start,
                        range.end,
                        visible(&before),
                        visible(&original.chars().take(400).collect::<String>()),
                        visible(&after)
                    );
                }
                largest.push((
                    range.end - range.start,
                    format!(
                        "{} [{}] {}",
                        path.display(),
                        range.rule,
                        original
                            .chars()
                            .take(70)
                            .collect::<String>()
                            .replace('\n', "⏎")
                    ),
                ));
                // A declaration is types all the way down, and its members may be named `new`
                // or `delete`; what could go wrong there is where it ends, not what is in it.
                let code = if range.rule == "declare" {
                    let toks = scan::Toks::new(original);
                    let last = toks.len().checked_sub(1).map_or("", |i| toks.text(i));
                    (last != ";" && last != "}").then(|| format!("ends with `{last}`"))
                } else {
                    runs(&scan::Toks::new(original))
                };
                if let Some(token) = code {
                    flagged += 1;
                    println!(
                        "RUNS `{token}` in a blanked range: {} [{}] {:?}",
                        path.display(),
                        range.rule,
                        original.chars().take(160).collect::<String>()
                    );
                }
            }
        }
        println!(
            "\nfiles scanned {}, candidates {candidates}, repaired {repaired}, still failing {still_failing}, ranges with code-like tokens {flagged}",
            files.len()
        );
        for (rule, (count, bytes)) in &stats {
            println!("  {rule:24} {count:6} ranges {bytes:8} bytes");
        }
        largest.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        println!("largest blanked ranges:");
        for (len, what) in largest.iter().take(12) {
            println!("  {len:6} {what}");
        }
        assert_eq!(flagged, 0, "some rule blanked code that runs");
    }

    /// The repair with everything it did, for the invariants below.
    fn run_full(src: &str, jsx: bool) -> (String, Repair, Vec<Applied>) {
        let source_type = flavor(jsx);
        let first = parse_with(&Allocator::default(), src, source_type);
        repair_rounds(src, source_type, parse_with, first, true)
    }

    /// Text that is almost Flow, mutated at random (a fixed seed, so every run is the same): the
    /// repair always finishes, never changes a length or a line break, and changes nothing
    /// outside the ranges it reports. The ranges themselves only ever hold blanks, the fill text,
    /// and the line breaks that were there.
    #[test]
    fn mutated_text_never_breaks_the_repair() {
        let seeds = [
            "// @flow\nimport typeof A from 'a';\nexport type O = {|a: number, ...B, +c?: ?string|};\nconst f = (x: Error => void, {y}: {y: T, ...} = {}): %checks => (x: any);\n",
            "declare module 'm' {\n  declare export type T = {a: number};\n  declare function f(?string, ...Array<T>): void;\n}\nopaque type Id: string = string;\n",
            "class A<+T: Object = {}> extends B<*> implements C {\n  +x: T; static -y: ?() => void = () => {};\n  constructor(a: T): this { return a ? (b: any) : c; }\n}\n",
            "type U = string | () => string | (cmd: string, v: Foo<>) => void;\nfunction g<T>(cb: (?Error, ?number) => unknown, é: 'ü'): ñ => void {}\n",
        ];
        let alphabet: Vec<char> = "(){}[]<>:,;?|&=.*+-!/'\"`\\ \n\tabxyz_é→...=>"
            .chars()
            .collect();
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state >> 8).unwrap_or(0)
        };
        let mut repaired_somehow = 0usize;
        for seed in seeds {
            for _ in 0..250 {
                let mut chars: Vec<char> = seed.chars().collect();
                for _ in 0..=(next() % 4) {
                    let at = next() % (chars.len() + 1);
                    let pick = alphabet
                        .get(next() % alphabet.len())
                        .copied()
                        .unwrap_or(' ');
                    match next() % 3 {
                        0 if at < chars.len() => {
                            chars.remove(at);
                        }
                        1 => chars.insert(at, pick),
                        _ => {
                            if let Some(slot) = chars.get_mut(at) {
                                *slot = pick;
                            }
                        }
                    }
                }
                let mutated: String = chars.into_iter().collect();
                for jsx in [true, false] {
                    let (text, repair, applied) = run_full(&mutated, jsx);
                    assert_eq!(text.len(), mutated.len(), "{mutated:?}");
                    repaired_somehow += usize::from(repair.edits > 0);
                    for (at, (new, old)) in text.bytes().zip(mutated.bytes()).enumerate() {
                        let inside = applied.iter().any(|a| a.start <= at && at < a.end);
                        if !inside {
                            assert_eq!(
                                new, old,
                                "byte {at} changed outside any applied range of {mutated:?}"
                            );
                        } else if new != old {
                            // Inside a range: blanks and the fill's own letters, never a line break.
                            assert!(
                                new == b' ' || new.is_ascii_alphabetic() || new == b'_',
                                "{mutated:?}"
                            );
                            assert!(old != b'\n' && old != b'\r', "{mutated:?}");
                        }
                    }
                }
            }
        }
        // The mutations still leave a lot of real Flow to repair; otherwise this tested nothing.
        assert!(repaired_somehow > 500, "{repaired_somehow}");
    }
}
