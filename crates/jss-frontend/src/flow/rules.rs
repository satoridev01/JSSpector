//! The repair rules: each recognizes one Flow-only construct next to the syntax error that
//! TypeScript syntax reports on it, and says which bytes to blank.
//!
//! A rule fires on an error anchor: the first token that starts at or after the error's offset.
//! (oxc reports "expected a semicolon" at the end of the previous token, so the offending token
//! is the one that follows; every other error points at the token itself.) Rules look at the
//! tokens around the anchor and refuse anything that is not exactly their shape, so a file that
//! is not Flow is not changed by chance.
//!
//! A rule never changes what runs: it blanks types, type-only declarations and type-only
//! modifiers, or swaps a Flow-only spelling for the TypeScript one of the same length.

use super::scan::{Kind, Toks};

/// Replaces the bytes `start..end` with `fill`, then blanks. The length never changes, and line
/// breaks inside the range stay where they are, so every offset and line number is the same
/// in the repaired text as in the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Edit {
    pub(crate) start: usize,
    pub(crate) end: usize,
    /// ASCII text written at the start of the range; the rest becomes blanks.
    pub(crate) fill: &'static str,
}

type Rule = fn(&Toks<'_>, usize, &str) -> Option<Vec<Edit>>;

/// When a rule may fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    /// Its shape cannot occur in valid JavaScript or TypeScript, and what it blanks is a token
    /// or a type-only declaration, so a broken file is not changed in any way that matters. When
    /// it fires, the file is Flow.
    Anywhere,
    /// Its shape could come from a file that is merely broken, or it blanks enough to matter: it
    /// fires in a file that declares itself Flow with an `@flow` pragma, or that already showed
    /// Flow-only syntax. A broken file is then reported rather than "repaired" into one that
    /// parses but means something else.
    Flow,
}

/// In the order tried: statements that are Flow's alone; then rules for one token or a few, found
/// by shape; then the ones that take a whole type; and last the one that takes a whole parameter
/// list, so it only gets what nothing smaller took. Each has a name, for tracing.
const RULES: &[(&str, Rule, Evidence)] = &[
    ("declare", declare, Evidence::Anywhere),
    ("opaque", opaque, Evidence::Anywhere),
    ("import_typeof", import_typeof, Evidence::Anywhere),
    ("inexact_marker", inexact_marker, Evidence::Anywhere),
    ("empty_type_args", empty_type_args, Evidence::Anywhere),
    ("existential", existential, Evidence::Anywhere),
    ("exact_object", exact_object, Evidence::Anywhere),
    ("inline_interface", inline_interface, Evidence::Anywhere),
    ("type_spread", type_spread, Evidence::Flow),
    ("variance", variance, Evidence::Flow),
    ("checks", checks, Evidence::Flow),
    ("implies_guard", implies_guard, Evidence::Flow),
    ("setter_return_type", setter_return_type, Evidence::Flow),
    (
        "constructor_return_type",
        constructor_return_type,
        Evidence::Flow,
    ),
    (
        "optional_with_default",
        optional_with_default,
        Evidence::Flow,
    ),
    (
        "required_after_optional",
        required_after_optional,
        Evidence::Flow,
    ),
    ("mapped_type_comma", mapped_type_comma, Evidence::Flow),
    ("type_param_bound", type_param_bound, Evidence::Flow),
    ("cast_read_as_arrow", cast_read_as_arrow, Evidence::Flow),
    ("colon_in_parens", colon_in_parens, Evidence::Flow),
    ("function_type_member", function_type_member, Evidence::Flow),
    ("bare_function_type", bare_function_type, Evidence::Flow),
    ("const_annotation", const_annotation, Evidence::Flow),
    ("unnamed_params", unnamed_params, Evidence::Flow),
];

/// A repair: which rule, what to blank, and whether that shows the file is Flow.
pub(crate) struct Fix {
    pub(crate) rule: &'static str,
    pub(crate) edits: Vec<Edit>,
    pub(crate) proves_flow: bool,
}

/// The fix for the error `message` at `offset` in `src`, if one of the rules knows it. `flow` is
/// whether the file is known to be Flow: it declares itself with `@flow`, or an earlier fix in it
/// proved it (see [`Evidence`]).
pub(crate) fn step(src: &str, offset: usize, message: &str, flow: bool) -> Option<Fix> {
    // JSX text is not code: the file is being read in the wrong flavor, not misspelled.
    if message.contains("JSX") || message.contains("&gt;") {
        return None;
    }
    let toks = Toks::new(src);
    let anchor = toks.at_offset(offset);
    // An error is at a token's start, or right after a token (where a `;` is missing). Inside
    // one, this tokenizer and the parser disagree about what the text is, and nothing here is safe.
    if toks.start(anchor).is_some_and(|start| start < offset) {
        return None;
    }
    let attempt = |anchor: usize, message: &str| {
        RULES
            .iter()
            .filter(|(_, _, evidence)| flow || *evidence == Evidence::Anywhere)
            .find_map(|(rule, run, evidence)| {
                run(&toks, anchor, message)
                    .filter(|edits| !edits.is_empty())
                    .map(|edits| Fix {
                        rule,
                        edits,
                        proves_flow: *evidence == Evidence::Anywhere,
                    })
            })
    };
    if let Some(fix) = attempt(anchor, message) {
        return Some(fix);
    }
    // oxc fails at the `:` of a parameter's annotation when something later in the annotation is
    // Flow's (`({ a }: { a: T, ... }) => ...`): it gives up on the parentheses as arrow
    // parameters before it reaches the construct. The construct is inside the annotation, so look
    // there. The message belongs to the colon, not to these tokens.
    if toks.is(anchor, ":")
        && let Some(open) = enclosing_open(&toks, anchor).filter(|&open| toks.is(open, "("))
        && let Some(close) = toks.close_of(open)
        && let Some(end) = toks.type_end(anchor + 1)
    {
        for inner in anchor + 1..end.min(close) {
            if let Some(fix) = attempt(inner, "") {
                return Some(fix);
            }
        }
    }
    None
}

/// Applies `edits` to `src`; `None` when they overlap, are out of range, do not change the text
/// or cannot keep it the same length.
pub(crate) fn apply(src: &str, edits: &[Edit]) -> Option<String> {
    let mut sorted: Vec<&Edit> = edits.iter().collect();
    sorted.sort_by_key(|edit| edit.start);
    let mut out = String::with_capacity(src.len());
    let mut at = 0usize;
    for edit in sorted {
        if edit.start < at || edit.end <= edit.start || edit.end > src.len() {
            return None;
        }
        out.push_str(src.get(at..edit.start)?);
        blank_into(&mut out, src.get(edit.start..edit.end)?, edit.fill)?;
        at = edit.end;
    }
    out.push_str(src.get(at..)?);
    (out.len() == src.len() && out != src).then_some(out)
}

/// Writes `fill`, then blanks, in place of `original`: one byte out for every byte in, line
/// breaks kept. `None` when the fill does not fit before the first line break.
fn blank_into(out: &mut String, original: &str, fill: &str) -> Option<()> {
    let mut fill_bytes = fill.bytes();
    let mut unwritten = fill.len();
    for ch in original.chars() {
        if matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
            if unwritten > 0 {
                return None;
            }
            out.push(ch);
            continue;
        }
        for _ in 0..ch.len_utf8() {
            match fill_bytes.next() {
                Some(byte) => {
                    out.push(char::from(byte));
                    unwritten -= 1;
                }
                None => out.push(' '),
            }
        }
    }
    (unwritten == 0).then_some(())
}

/// Blank the tokens `from..to` (`to` exclusive).
fn blank(toks: &Toks<'_>, from: usize, to: usize) -> Option<Edit> {
    let start = toks.start(from)?;
    let end = toks.end(to.checked_sub(1)?)?;
    (end > start).then_some(Edit {
        start,
        end,
        fill: "",
    })
}

fn blank_one(toks: &Toks<'_>, i: usize) -> Option<Vec<Edit>> {
    Some(vec![blank(toks, i, i + 1)?])
}

/// Swap the tokens `from..to` for `fill`.
fn replace(toks: &Toks<'_>, from: usize, to: usize, fill: &'static str) -> Option<Vec<Edit>> {
    let mut edit = blank(toks, from, to)?;
    edit.fill = fill;
    Some(vec![edit])
}

/// The innermost bracket that is open at token `i`.
fn enclosing_open(toks: &Toks<'_>, i: usize) -> Option<usize> {
    let mut k = i;
    loop {
        k = k.checked_sub(1)?;
        if toks.is_closer(k) {
            k = toks.open_of(k)?;
        } else if toks.is_opener(k) {
            return Some(k);
        }
    }
}

/// Token `i` begins a statement.
fn statement_start(toks: &Toks<'_>, i: usize) -> bool {
    match toks.back(i, 1) {
        None => true,
        Some(prev) => {
            toks.newline_before(i) || toks.is(prev, ";") || toks.is(prev, "}") || toks.is(prev, "{")
        }
    }
}

/// `;` after a statement, if there is one: the index after it.
fn semi(toks: &Toks<'_>, i: usize) -> usize {
    if toks.is(i, ";") { i + 1 } else { i }
}

// --- declarations -------------------------------------------------------------------------

/// `declare ...`: Flow's ambient declarations (`declare export type`, `declare module.exports: T`,
/// `declare opaque type`, `declare class ... mixins`, `%checks`). TypeScript reads some declares
/// (`declare var`, `declare type`, `declare function`, `declare class`) and fails on the others,
/// wherever inside the statement. They only describe types, so the whole statement goes. A
/// `declare module` that holds the failing declaration goes whole, since library definitions
/// are made of nothing else.
fn declare(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    // The nearest `declare` before the error whose declaration reaches the error.
    let mut d = (0..=anchor).rev().take(MAX_DECLARE_LOOKBACK).find(|&k| {
        declare_statement(toks, k) && declare_end(toks, k).is_some_and(|end| end > anchor)
    })?;
    // Climb out of `declare module 'x' { ... }` bodies.
    while let Some(open) = enclosing_open(toks, d)
        && toks.is(open, "{")
        && let Some(module) = open.checked_sub(2)
        && toks.is(module, "module")
        && let Some(outer) = module.checked_sub(1)
        && toks.is(outer, "declare")
        && declare_statement(toks, outer)
    {
        d = outer;
    }
    let end = declare_end(toks, d)?;
    Some(vec![blank(toks, d, end)?])
}

/// How many tokens back from an error [`declare`] looks for the statement it belongs to.
const MAX_DECLARE_LOOKBACK: usize = 512;

/// `declare` at token `d` starts a Flow declaration (rather than being an identifier).
fn declare_statement(toks: &Toks<'_>, d: usize) -> bool {
    toks.is(d, "declare")
        && statement_start(toks, d)
        && !toks.newline_before(d + 1)
        && matches!(
            toks.text(d + 1),
            "export"
                | "module"
                | "type"
                | "opaque"
                | "interface"
                | "var"
                | "let"
                | "const"
                | "function"
                | "class"
                | "enum"
                | "namespace"
        )
}

/// The token index after the declaration that starts with the `declare` at `d`.
fn declare_end(toks: &Toks<'_>, d: usize) -> Option<usize> {
    let mut j = d + 1;
    if toks.is(j, "export") {
        j += 1;
        if toks.is(j, "default") {
            j += 1;
            return if toks.is(j, "function") || toks.is(j, "class") {
                declare_form(toks, j)
            } else {
                Some(semi(toks, toks.type_end(j)?))
            };
        }
        if toks.is(j, "{") {
            j = toks.close_of(j)? + 1;
            if toks.is(j, "from") {
                j += 2;
            }
            return Some(semi(toks, j));
        }
        if toks.is(j, "*") {
            j += 1;
            if toks.is(j, "as") {
                j += 2;
            }
            return toks.is(j, "from").then(|| semi(toks, j + 2));
        }
    }
    declare_form(toks, j)
}

fn declare_form(toks: &Toks<'_>, j: usize) -> Option<usize> {
    match toks.text(j) {
        "type" => alias_end(toks, j),
        "opaque" if toks.is(j + 1, "type") => opaque_end(toks, j + 1),
        "var" | "let" | "const" => {
            if !toks.is_ident(j + 1) {
                return None;
            }
            let mut k = j + 2;
            if toks.is(k, ":") {
                k = toks.type_end(k + 1)?;
            }
            Some(semi(toks, k))
        }
        "function" => {
            if !toks.is_ident(j + 1) {
                return None;
            }
            let mut k = j + 2;
            if toks.is(k, "<") {
                k = toks.angle_close(k)? + 1;
            }
            if !toks.is(k, "(") {
                return None;
            }
            k = toks.close_of(k)? + 1;
            if toks.is(k, ":") {
                k = toks.type_end(k + 1)?;
            }
            // `%checks` or `%checks(expr)`.
            if toks.is(k, "%") && toks.is(k + 1, "checks") {
                k += 2;
                if toks.is(k, "(") {
                    k = toks.close_of(k)? + 1;
                }
            }
            Some(semi(toks, k))
        }
        "class" | "interface" | "enum" | "namespace" => body_end(toks, j + 1),
        "module" => {
            if toks.is(j + 1, ".") && toks.is(j + 2, "exports") && toks.is(j + 3, ":") {
                Some(semi(toks, toks.type_end(j + 4)?))
            } else {
                body_end(toks, j + 1)
            }
        }
        _ => None,
    }
}

/// `type Name<T> = Type;` with `j` at `type`.
fn alias_end(toks: &Toks<'_>, j: usize) -> Option<usize> {
    if !toks.is_ident(j + 1) {
        return None;
    }
    let mut k = j + 2;
    if toks.is(k, "<") {
        k = toks.angle_close(k)? + 1;
    }
    if !toks.is(k, "=") {
        return None;
    }
    Some(semi(toks, toks.type_end(k + 1)?))
}

/// `type Name<T>: Super = Type;` (both parts optional) with `j` at `type`.
fn opaque_end(toks: &Toks<'_>, j: usize) -> Option<usize> {
    if !toks.is_ident(j + 1) {
        return None;
    }
    let mut k = j + 2;
    if toks.is(k, "<") {
        k = toks.angle_close(k)? + 1;
    }
    if toks.is(k, ":") {
        k = toks.type_end(k + 1)?;
    }
    if toks.is(k, "=") {
        k = toks.type_end(k + 1)?;
    }
    Some(semi(toks, k))
}

/// From a declaration's header to the end of its `{ ... }` body.
fn body_end(toks: &Toks<'_>, from: usize) -> Option<usize> {
    let mut k = from;
    while k < toks.len() {
        if toks.is(k, "{") {
            return Some(toks.close_of(k)? + 1);
        }
        if toks.is(k, "<") {
            k = toks.angle_close(k)? + 1;
        } else if toks.is(k, "(") {
            k = toks.close_of(k)? + 1;
        } else if toks.is(k, ";") || toks.is_closer(k) {
            return None;
        } else {
            k += 1;
        }
    }
    None
}

/// `opaque type Id: string = string;` and its `export` form: a type-only declaration. The
/// error is at `opaque` after `export`, and at the `type` that follows it otherwise.
fn opaque(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    let keyword = if toks.is(anchor, "opaque") {
        anchor
    } else {
        let prev = toks.back(anchor, 1)?;
        (toks.is(anchor, "type") && toks.is(prev, "opaque")).then_some(prev)?
    };
    if !toks.is(keyword + 1, "type") {
        return None;
    }
    let first = match toks.back(keyword, 1) {
        Some(prev) if toks.is(prev, "export") => prev,
        _ => keyword,
    };
    if !statement_start(toks, first) {
        return None;
    }
    let end = opaque_end(toks, keyword + 1)?;
    Some(vec![blank(toks, first, end)?])
}

/// `import typeof X from 'm'` and `import { typeof X }`: TypeScript spells it `type`. `typeof`
/// has two letters more, which become blanks.
fn import_typeof(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    if !toks.is(anchor, "typeof") {
        return None;
    }
    let prev = toks.back(anchor, 1)?;
    let in_import = toks.is(prev, "import")
        || ((toks.is(prev, "{") || toks.is(prev, ",")) && in_import_braces(toks, anchor));
    if !in_import {
        return None;
    }
    replace(toks, anchor, anchor + 1, "type")
}

/// Token `i` sits directly inside the braces of an `import { ... }`.
fn in_import_braces(toks: &Toks<'_>, i: usize) -> bool {
    let Some(open) = enclosing_open(toks, i).filter(|&open| toks.is(open, "{")) else {
        return false;
    };
    let Some(before) = toks.back(open, 1) else {
        return false;
    };
    // `import {` or `import Default, {`.
    toks.is(before, "import")
        || (toks.is(before, ",")
            && toks
                .back(before, 2)
                .is_some_and(|import| toks.is(import, "import")))
}

// --- types ----------------------------------------------------------------------------------

/// `...` with nothing after it in an object type or a tuple: the inexact marker, `{ a: T, ... }`
/// or `[A, B, ...]`. JavaScript spreads always have an operand, so this can only be Flow. The
/// error is at the `...`, or at the closer after it when the parser took it for a tuple rest.
fn inexact_marker(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    let dots = if toks.is(anchor, "...") {
        anchor
    } else {
        toks.back(anchor, 1).filter(|&dots| toks.is(dots, "..."))?
    };
    matches!(toks.text(dots + 1), "}" | "," | ";" | ")" | "]").then(|| blank_one(toks, dots))?
}

/// `{ ...A, b: T }`: a spread in an object type. JavaScript spreads exist too, so the error
/// being at one means TypeScript expected a type member there. The spread and its separator
/// go; the closing brace stays.
fn type_spread(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    if !toks.is(anchor, "...") {
        return None;
    }
    let mut k = anchor + 1;
    while k < toks.len() {
        if toks.is(k, ",") || toks.is(k, ";") {
            return Some(vec![blank(toks, anchor, k + 1)?]);
        }
        if toks.is(k, "}") {
            return Some(vec![blank(toks, anchor, k)?]);
        }
        if toks.is(k, "<") {
            k = toks.angle_close(k).map_or(k + 1, |close| close + 1);
        } else if toks.is_opener(k) {
            k = toks.close_of(k)? + 1;
        } else if toks.is_closer(k) {
            return None;
        } else {
            k += 1;
        }
    }
    None
}

/// `(expr: Type)`, a Flow type cast: the `: Type` goes. A `:` in parentheses that are followed
/// by `=>` belongs to the parameters of an arrow function, which are code that runs and are never
/// touched here; what is wrong in them is found inside their annotations (see [`step`]).
fn colon_in_parens(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    if !toks.is(anchor, ":") {
        return None;
    }
    let open = enclosing_open(toks, anchor).filter(|&open| toks.is(open, "("))?;
    let close = toks.close_of(open)?;
    if toks.is(close + 1, "=>") {
        return None;
    }
    cast_annotation(toks, anchor, close)
}

/// Blank the annotation of a cast whose colon is at `colon` and whose parenthesis closes at
/// `close`, if the annotation is a type that ends exactly there. Anything after the type (a
/// default value: `(x: T = 1)`) means these are parameters, not a cast, and are code that runs.
fn cast_annotation(toks: &Toks<'_>, colon: usize, close: usize) -> Option<Vec<Edit>> {
    if toks.type_end(colon + 1)? != close {
        return None;
    }
    let start = toks.start(colon)?;
    let end = toks.start(close)?;
    (end > start).then(|| {
        vec![Edit {
            start,
            end,
            fill: "",
        }]
    })
}

/// `string => void`: a function type with no parentheses around its one parameter, which
/// TypeScript syntax does not have. The whole type becomes `any`.
fn bare_function_type(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    toks.is(anchor, "=>").then(|| bare_arrow(toks, anchor))?
}

/// `const f: A => B = v;` and `const x: interface {} = v;`: oxc reports the missing
/// initializer at the binding, so the Flow-only syntax is looked for in its annotation.
fn const_annotation(toks: &Toks<'_>, anchor: usize, message: &str) -> Option<Vec<Edit>> {
    if !message.contains("Missing initializer") {
        return None;
    }
    let after = if toks.is(anchor, "{") || toks.is(anchor, "[") {
        toks.close_of(anchor)? + 1
    } else {
        anchor + 1
    };
    if !toks.is(after, ":") {
        return None;
    }
    let end = toks.type_end(after + 1)?;
    let bare_arrow_at = (after + 1..end)
        .find(|&k| toks.is(k, "=>") && toks.back(k, 1).is_some_and(|left| !toks.is(left, ")")));
    if let Some(arrow) = bare_arrow_at {
        return bare_arrow(toks, arrow);
    }
    let inline_interface =
        (after + 1..end).find(|&k| toks.is(k, "interface") && toks.is(k + 1, "{"))?;
    blank_one(toks, inline_interface)
}

/// Replaces the function type whose unparenthesized parameter sits right before the `=>` at
/// `arrow`. `(params) =>` is a function type or an arrow function, both fine as they are.
///
/// In `(x): (A => B) => body` the parentheses only group the return type. Left in place around
/// `any`, `(any) => body` would read as a function type and orphan the arrow's own `=>`, so they
/// go with it.
fn bare_arrow(toks: &Toks<'_>, arrow: usize) -> Option<Vec<Edit>> {
    let left = toks.back(arrow, 1)?;
    if toks.is(left, ")") {
        return None;
    }
    let from = toks.atom_start_before(arrow)?;
    let end = toks.type_end(arrow + 1)?;
    if let Some(open) = toks.back(from, 1).filter(|&open| toks.is(open, "("))
        && toks.close_of(open) == Some(end)
        && toks.is(end + 1, "=>")
        && toks
            .back(open, 1)
            .is_some_and(|colon| toks.is(colon, ":") && toks.prev_is(colon, ")"))
    {
        return replace(toks, open, end + 1, "any");
    }
    replace(toks, from, end, "any")
}

/// `(expr: Type)` cast that oxc read as the parameters of an arrow function: it reports the
/// missing `=>` at the token after the parenthesis (or, for `((a: A): B)`, at the closing one,
/// and for `c ? (a: A) : b`, after the `b` it took for a return type). The annotation goes;
/// what is left is the parenthesized expression.
fn cast_read_as_arrow(toks: &Toks<'_>, anchor: usize, message: &str) -> Option<Vec<Edit>> {
    if !message.contains("`=>`") {
        return None;
    }
    let close = match toks.back(anchor, 1) {
        Some(prev) if toks.is(prev, ")") => prev,
        _ if toks.is(anchor, ")") => anchor,
        _ => return_colon_paren(toks, anchor)?,
    };
    let open = toks.open_of(close)?;
    let colon = annotation_colon(toks, open, close)?;
    cast_annotation(toks, colon, close)
}

/// The `)` of the nearest `) : Type` before `anchor`: the parenthesis oxc took for the
/// parameters of an arrow function with a return type.
fn return_colon_paren(toks: &Toks<'_>, anchor: usize) -> Option<usize> {
    let mut k = anchor;
    for _ in 0..MAX_RETURN_TYPE_LOOKBACK {
        k = k.checked_sub(1)?;
        if toks.is_closer(k) {
            k = toks.open_of(k)?;
        } else if toks.is(k, ":") {
            return toks.back(k, 1).filter(|&paren| toks.is(paren, ")"));
        } else if toks.is_opener(k) || toks.is(k, ";") {
            return None;
        }
    }
    None
}

/// How far back from the missing `=>` to look for the `) :` that starts a return type.
const MAX_RETURN_TYPE_LOOKBACK: usize = 96;

/// The `:` that annotates the expression in `( expr : Type )`: the first one directly inside the
/// parentheses that is not the other half of a `?` (a conditional expression).
fn annotation_colon(toks: &Toks<'_>, open: usize, close: usize) -> Option<usize> {
    let mut pending = 0usize;
    let mut k = open + 1;
    while k < close {
        if toks.is_opener(k) {
            k = toks.close_of(k)? + 1;
            continue;
        }
        if toks.is(k, "?") {
            // `?.` and `??` are not conditionals.
            let chained = toks.is(k + 1, ".") && toks.adjacent(k, k + 1);
            let nullish = toks.is(k + 1, "?") && toks.adjacent(k, k + 1);
            if nullish {
                k += 1;
            } else if !chained {
                pending += 1;
            }
        } else if toks.is(k, ":") {
            if pending == 0 {
                return Some(k);
            }
            pending -= 1;
        }
        k += 1;
    }
    None
}

/// A function type with an unnamed parameter: `(string, ?Error) => void`, or a method
/// signature `m(?string, ...Array<T>): R` in an object type. TypeScript wants every parameter
/// named, which only works when an unnamed one happens to be a plain identifier, so it fails on
/// `?Error`, `Array<T>`, `'lit'`, `A | B`, `[A, B]`, `{ a: T, ... }`, `T[]`, `(A) => B` and
/// `...Array<T>`. Parameter types say nothing about what runs, so the parameters go and the
/// type keeps its shape: `() => void`.
///
/// What makes this safe is where it fires: the failing item must be unnamed, and a failure
/// inside an unnamed item means it is not a valid binding pattern, so the group is a type.
/// (The parameters of code that runs are names and patterns, which TypeScript accepts as they
/// are.) The item may be nested in an object or tuple type.
fn unnamed_params(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    let (open, child) = if toks.is(anchor, "=>") {
        // The parser read `(Type)` as a parenthesized type and stopped at the arrow.
        let left = toks.back(anchor, 1).filter(|&left| toks.is(left, ")"))?;
        (toks.open_of(left)?, None)
    } else {
        let mut child = anchor;
        let mut group = enclosing_open(toks, anchor)?;
        for _ in 0..MAX_PARAM_CLIMB {
            if toks.is(group, "(") {
                break;
            }
            if !(toks.is(group, "{") || toks.is(group, "[")) {
                return None;
            }
            child = group;
            group = enclosing_open(toks, group)?;
        }
        if !toks.is(group, "(") {
            return None;
        }
        (group, Some(child))
    };
    let close = toks.close_of(open)?;
    let function_type = toks.is(close + 1, "=>");
    let method_signature = toks.is(close + 1, ":")
        && toks
            .back(open, 1)
            .is_some_and(|name| toks.is_ident(name) || toks.is(name, ">"))
        && toks.type_end(close + 2).is_some_and(|end| {
            toks.is(end, ",") || toks.is(end, ";") || toks.is(end, "}") || end >= toks.len()
        });
    if !(function_type || method_signature) || close == open + 1 {
        return None;
    }
    let items = param_items(toks, open, close);
    let named = match child {
        // The item the failure is in. An error at a comma is about the item before it.
        Some(child) => items
            .iter()
            .find(|item| item.contains(&child) || item.end == child)
            .is_none_or(|item| is_named(toks, item.clone())),
        None => items.iter().any(|item| is_named(toks, item.clone())),
    };
    if named {
        return None;
    }
    Some(vec![blank(toks, open + 1, close)?])
}

/// How many object or tuple types [`unnamed_params`] climbs out of to find the parameter list.
const MAX_PARAM_CLIMB: usize = 4;

/// The token ranges of the items of the list `( a, b, c )`.
fn param_items(toks: &Toks<'_>, open: usize, close: usize) -> Vec<std::ops::Range<usize>> {
    let mut items = Vec::new();
    let mut start = open + 1;
    let mut k = open + 1;
    while k < close {
        if toks.is(k, ",") {
            items.push(start..k);
            start = k + 1;
        } else if toks.is_opener(k) {
            k = toks.close_of(k).unwrap_or(k);
        }
        k += 1;
    }
    if start < close {
        items.push(start..close);
    }
    items
}

/// The item is a named parameter: `name: T`, `name?: T`, `...name: T`, `{ a, b }: T` or
/// `[a, b]: T`; that is, it has a `:` directly inside it that is not half of a conditional type
/// (`A extends B ? C : D`). Everything else is a type with no name: `?Error`, `Array<T>`,
/// `{ a: T }`, `(A) => B`.
///
/// Mistaking a named parameter for a type would let a rule blank code that runs, so this errs
/// toward "named".
fn is_named(toks: &Toks<'_>, item: std::ops::Range<usize>) -> bool {
    let mut conditionals = 0usize;
    let mut k = item.start;
    while k < item.end {
        if toks.is_opener(k) {
            k = toks.close_of(k).unwrap_or(k) + 1;
            continue;
        }
        if toks.is(k, "?") {
            if toks.is(k + 1, ":") {
                // `name?: T`: the colon that follows annotates the name.
                return true;
            }
            // A `?` after a complete type opens a conditional type; one that starts a type is
            // the prefix of a maybe type (`?T`).
            let after_a_type = k
                .checked_sub(1)
                .filter(|&prev| prev >= item.start)
                .is_some_and(|prev| {
                    toks.is_ident(prev)
                        || toks.is(prev, ">")
                        || toks.is(prev, "]")
                        || toks.is(prev, ")")
                        || toks.is(prev, "}")
                });
            if after_a_type {
                conditionals += 1;
            }
        } else if toks.is(k, ":") {
            if conditionals == 0 {
                return true;
            }
            conditionals -= 1;
        }
        k += 1;
    }
    false
}

/// `A | () => B` and `A & (x: X) => B`: a function type as a union or intersection member, which
/// TypeScript wants parenthesized. The whole function type becomes `any`. The error is at the
/// `(`, at the `)` of `()`, or inside the parameters. What makes it safe is the `|` or `&` before
/// the parenthesis: an arrow function cannot be an operand of either.
fn function_type_member(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    let open = if toks.is(anchor, "(") {
        anchor
    } else if toks.is(anchor, ")") && toks.prev_is(anchor, "(") {
        anchor - 1
    } else {
        enclosing_open(toks, anchor).filter(|&open| toks.is(open, "("))?
    };
    let before = toks.back(open, 1)?;
    if !(toks.is(before, "|") || toks.is(before, "&")) {
        return None;
    }
    let close = toks.close_of(open)?;
    if !toks.is(close + 1, "=>") {
        return None;
    }
    let end = toks.type_end(close + 2)?;
    replace(toks, open, end, "any")
}

/// `<T: Bound>`: Flow's type parameter bound, which TypeScript spells `extends`. The bound goes
/// (the default after it, `= D`, stays).
fn type_param_bound(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    if !toks.is(anchor, ":") {
        return None;
    }
    let name = toks.back(anchor, 1).filter(|&name| toks.is_ident(name))?;
    let before = toks.back(name, 1)?;
    // After `<`, `,`, or a variance sign.
    let starts_param = toks.is(before, "<")
        || ((toks.is(before, ",") || toks.is(before, "+") || toks.is(before, "-"))
            && in_type_params(toks, name));
    if !starts_param {
        return None;
    }
    let end = toks.type_end(anchor + 1)?;
    Some(vec![blank(toks, anchor, end)?])
}

/// Token `i` sits directly inside the `<...>` of a type parameter list.
fn in_type_params(toks: &Toks<'_>, i: usize) -> bool {
    let mut k = i;
    for _ in 0..MAX_ANGLE_LOOKBACK {
        let Some(prev) = k.checked_sub(1) else {
            return false;
        };
        k = prev;
        if toks.is(k, "<") {
            return true;
        }
        if toks.is(k, ">") {
            let Some(open) = toks.angle_open(k) else {
                return false;
            };
            k = open;
        } else if toks.is_closer(k) {
            let Some(open) = toks.open_of(k) else {
                return false;
            };
            k = open;
        } else if toks.is_opener(k) || toks.is(k, ";") {
            return false;
        }
    }
    false
}

const MAX_ANGLE_LOOKBACK: usize = 256;

/// `): implies x is T`: Flow's type guard that also implies, which TypeScript does not have.
fn implies_guard(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    let implies = toks
        .back(anchor, 1)
        .filter(|&prev| toks.is(prev, "implies"))?;
    let colon = toks.back(implies, 1)?;
    (toks.is(colon, ":") && toks.is_ident(anchor)).then(|| blank_one(toks, implies))?
}

/// A mapped type with a trailing comma, `{ [K in keyof T]: V, }`: Flow allows it, TypeScript
/// does not.
fn mapped_type_comma(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    if !toks.is(anchor, ",") {
        return None;
    }
    let open = enclosing_open(toks, anchor).filter(|&open| toks.is(open, "{"))?;
    let mapped = toks.is(open + 1, "[") && toks.is_ident(open + 2) && toks.is(open + 3, "in");
    mapped.then(|| blank_one(toks, anchor))?
}

/// `Foo<>`: Flow allows an empty type argument list.
fn empty_type_args(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    let after_a_type = toks
        .back(anchor, 1)
        .is_some_and(|prev| toks.is_ident(prev) || toks.is(prev, ">") || toks.is(prev, "]"));
    (toks.is(anchor, "<")
        && toks.is(anchor + 1, ">")
        && toks.adjacent(anchor, anchor + 1)
        && after_a_type)
        .then(|| blank(toks, anchor, anchor + 2))
        .flatten()
        .map(|edit| vec![edit])
}

/// `*`: Flow's existential type, which TypeScript spells nothing like. `_` is a valid type name.
fn existential(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    if !toks.is(anchor, "*") {
        return None;
    }
    let prev = toks.back(anchor, 1)?;
    let in_type_position = toks.kind(prev) == Some(Kind::Punct)
        && matches!(
            toks.text(prev),
            "<" | "," | ":" | "=" | "|" | "&" | "(" | "?"
        );
    in_type_position.then(|| replace(toks, anchor, anchor + 1, "_"))?
}

/// `interface { ... }` as a type: the object type is what matters, so `interface` goes.
fn inline_interface(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    let keyword = if toks.is(anchor, "interface") && toks.is(anchor + 1, "{") {
        anchor
    } else if toks.is(anchor, "{") {
        let prev = toks.back(anchor, 1)?;
        toks.is(prev, "interface").then_some(prev)?
    } else {
        return None;
    };
    blank_one(toks, keyword)
}

/// `(x?: T = d)`: Flow allows a default on an optional parameter, TypeScript does not.
fn optional_with_default(toks: &Toks<'_>, anchor: usize, message: &str) -> Option<Vec<Edit>> {
    if !message.contains("question mark and an initializer") {
        return None;
    }
    // The error is at the parameter; the `?` follows its name or pattern.
    let after = if toks.is(anchor, "{") || toks.is(anchor, "[") {
        toks.close_of(anchor)? + 1
    } else {
        anchor + 1
    };
    toks.is(after, "?").then(|| blank_one(toks, after))?
}

/// `(a?: T, b: U)`: Flow allows a required parameter after an optional one. The earliest `?`
/// in the parameter list goes (one per round; the error repeats for the next).
fn required_after_optional(toks: &Toks<'_>, anchor: usize, message: &str) -> Option<Vec<Edit>> {
    if !message.contains("required parameter cannot follow an optional parameter") {
        return None;
    }
    let open = enclosing_open(toks, anchor).filter(|&open| toks.is(open, "("))?;
    let close = toks.close_of(open)?;
    let mut k = open + 1;
    while k < close {
        if toks.is(k, "?")
            && (toks.is(k + 1, ":")
                || toks.is(k + 1, ",")
                || toks.is(k + 1, ")")
                || toks.is(k + 1, "="))
        {
            return blank_one(toks, k);
        }
        k = if toks.is_opener(k) {
            toks.close_of(k)? + 1
        } else {
            k + 1
        };
    }
    None
}

/// `+x: T` and `-x: T` on properties, and `<+T, -U>` on type parameters: Flow's variance, which
/// TypeScript does not have.
fn variance(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    if !(toks.is(anchor, "+") || toks.is(anchor, "-")) {
        return None;
    }
    let name = anchor + 1;
    let names_a_property = match toks.kind(name) {
        Some(Kind::Ident | Kind::Str) => toks.is(name + 1, ":") || toks.is(name + 1, "?"),
        Some(Kind::Punct) => toks.is(name, "["),
        _ => false,
    };
    let starts_type_param = toks.is_ident(name)
        && toks.adjacent(anchor, name)
        && toks.back(anchor, 1).is_some_and(|before| {
            toks.is(before, "<") || (toks.is(before, ",") && in_type_params(toks, anchor))
        });
    (names_a_property || starts_type_param).then(|| blank_one(toks, anchor))?
}

/// `{| a: T |}`: Flow's exact object type. The bars go.
fn exact_object(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    if toks.is(anchor, "|") {
        let opens = toks
            .back(anchor, 1)
            .is_some_and(|prev| toks.is(prev, "{") && toks.adjacent(prev, anchor));
        let closes = toks.is(anchor + 1, "}") && toks.adjacent(anchor, anchor + 1);
        return (opens || closes).then(|| blank_one(toks, anchor))?;
    }
    if toks.is(anchor, "}") {
        let bar = toks.back(anchor, 1).filter(|&bar| toks.is(bar, "|"))?;
        return toks.adjacent(bar, anchor).then(|| blank_one(toks, bar))?;
    }
    None
}

/// `: boolean %checks`, a predicate function: the `%checks` (and its argument) go. For
/// `(x): %checks => ...` the predicate is the whole return type, so the colon goes too.
fn checks(toks: &Toks<'_>, anchor: usize, _message: &str) -> Option<Vec<Edit>> {
    let marker = if toks.is(anchor, ":") {
        anchor + 1
    } else {
        anchor
    };
    if !(toks.is(marker, "%") && toks.is(marker + 1, "checks") && toks.adjacent(marker, marker + 1))
    {
        return None;
    }
    let mut end = marker + 2;
    if toks.is(end, "(") {
        end = toks.close_of(end)? + 1;
    }
    Some(vec![blank(toks, anchor, end)?])
}

/// `set c(v: T): void` in an object type: Flow allows a return type on a setter, TypeScript does
/// not. The error is at the `:` after the parameters; `: void` goes.
fn setter_return_type(toks: &Toks<'_>, anchor: usize, message: &str) -> Option<Vec<Edit>> {
    if !message.contains("accessor cannot have a return type annotation") || !toks.is(anchor, ":") {
        return None;
    }
    let end = toks.type_end(anchor + 1)?;
    Some(vec![blank(toks, anchor, end)?])
}

/// `constructor(x: T): Self { ... }`: Flow allows a return type on a constructor, TypeScript does
/// not. The error is at the type; the colon before it and the type go.
fn constructor_return_type(toks: &Toks<'_>, anchor: usize, message: &str) -> Option<Vec<Edit>> {
    if !message.contains("cannot appear on a constructor declaration") {
        return None;
    }
    let colon = toks.back(anchor, 1).filter(|&colon| toks.is(colon, ":"))?;
    let end = toks.type_end(anchor)?;
    Some(vec![blank(toks, colon, end)?])
}
