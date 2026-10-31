//! Pure checks on a file's bytes, run before parsing.
//!
//! They keep the parser away from files it cannot or should not handle: oversized files,
//! non-UTF-8 text, minified bundles, and nesting deep enough to overflow the parser's stack
//! (oxc#21953; a stack overflow aborts the process and cannot be caught).

use std::str::Utf8Error;

use crate::diag::{Diagnostic, SkipReason};

/// Files larger than this are skipped (`skip/too-large`).
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// A file with any line longer than this many characters is minified (`skip/minified`).
pub const MAX_LINE_CHARS: usize = 20_000;

/// A file larger than this many bytes...
pub const AVG_LINE_MIN_FILE_BYTES: usize = 1024;

/// ...whose average line is longer than this many characters is minified (`skip/minified`).
pub const MAX_AVG_LINE_CHARS: usize = 300;

/// Approximate bracket nesting deeper than this is skipped (`skip/too-deep`).
pub const MAX_NESTING_DEPTH: usize = 2_000;

/// A failed check: the reason and a human-readable, deterministic message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skip {
    pub reason: SkipReason,
    pub message: String,
}

impl Skip {
    pub fn new(reason: SkipReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }

    /// The diagnostic reporting this skip for the file at `rel_path`.
    pub fn into_diagnostic(self, rel_path: impl Into<String>) -> Diagnostic {
        Diagnostic::at(self.reason.code(), rel_path, self.message)
    }
}

/// Size check, usable before reading the file.
pub fn check_size(size: u64) -> Result<(), Skip> {
    if size > MAX_FILE_BYTES {
        return Err(Skip::new(
            SkipReason::TooLarge,
            format!("file is {size} bytes, over the {MAX_FILE_BYTES}-byte limit"),
        ));
    }
    Ok(())
}

/// Runs every check in order (size, UTF-8, minified, nesting depth) and returns the text when
/// the file may be parsed.
pub fn check(bytes: &[u8]) -> Result<&str, Skip> {
    check_size(u64::try_from(bytes.len()).unwrap_or(u64::MAX))?;
    let text = std::str::from_utf8(bytes).map_err(not_utf8)?;
    check_minified(text)?;
    let depth = nesting_depth(bytes);
    if depth > MAX_NESTING_DEPTH {
        return Err(Skip::new(
            SkipReason::TooDeep,
            format!("bracket nesting depth {depth} exceeds the limit of {MAX_NESTING_DEPTH}"),
        ));
    }
    Ok(text)
}

fn not_utf8(err: Utf8Error) -> Skip {
    Skip::new(
        SkipReason::NotUtf8,
        format!("invalid UTF-8 at byte offset {}", err.valid_up_to()),
    )
}

fn check_minified(text: &str) -> Result<(), Skip> {
    let shape = LineShape::of(text);
    if shape.max_line_chars > MAX_LINE_CHARS {
        return Err(Skip::new(
            SkipReason::Minified,
            format!(
                "line {} is {} characters long (limit {MAX_LINE_CHARS})",
                shape.longest_line, shape.max_line_chars
            ),
        ));
    }
    if text.len() > AVG_LINE_MIN_FILE_BYTES
        && shape.total_chars > MAX_AVG_LINE_CHARS.saturating_mul(shape.lines)
    {
        return Err(Skip::new(
            SkipReason::Minified,
            format!(
                "average line length is over {MAX_AVG_LINE_CHARS} characters \
                 ({} characters on {} lines)",
                shape.total_chars, shape.lines
            ),
        ));
    }
    Ok(())
}

/// Line statistics, counted in characters (Unicode scalar values) without line terminators.
/// `\n`, `\r\n` and a lone `\r` each end a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LineShape {
    /// Number of lines. A trailing line terminator does not start another line; empty text has
    /// no lines.
    pub lines: usize,
    /// Characters on the longest line.
    pub max_line_chars: usize,
    /// 1-based number of the (first) longest line.
    pub longest_line: usize,
    /// Characters on all lines together.
    pub total_chars: usize,
}

impl LineShape {
    pub fn of(text: &str) -> Self {
        let mut shape = LineShape::default();
        let mut current = 0usize;
        let mut bytes = text.bytes().peekable();
        while let Some(byte) = bytes.next() {
            match byte {
                b'\n' | b'\r' => {
                    if byte == b'\r' && bytes.peek() == Some(&b'\n') {
                        bytes.next();
                    }
                    shape.end_line(current);
                    current = 0;
                }
                // Count characters, not bytes: skip UTF-8 continuation bytes.
                _ if byte & 0xC0 != 0x80 => current += 1,
                _ => {}
            }
        }
        if current > 0 {
            shape.end_line(current);
        }
        shape
    }

    fn end_line(&mut self, chars: usize) {
        self.lines += 1;
        self.total_chars += chars;
        if chars > self.max_line_chars {
            self.max_line_chars = chars;
            self.longest_line = self.lines;
        }
    }
}

/// Lexer state of the [`nesting_depth`] scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Code,
    LineComment,
    BlockComment,
    /// A `'` or `"` string. Strings end at an unescaped newline (error recovery for stray
    /// quotes, e.g. apostrophes in JSX text).
    Str(u8),
    /// The literal text of a template, outside `${...}`.
    Template,
    /// A regular expression literal; `in_class` is true inside `[...]`.
    Regex {
        in_class: bool,
    },
}

/// Approximate maximum nesting depth of `(`, `[`, `{` (and template `${`) in JS/TS source.
///
/// A cheap single pass that ignores brackets inside strings, template text, comments and regular
/// expression literals as well as a lexer can without parsing. It only has to be good enough to
/// keep pathological nesting away from the parser.
pub fn nesting_depth(bytes: &[u8]) -> usize {
    let mut mode = Mode::Code;
    let mut depth = 0usize;
    let mut max_depth = 0usize;
    // For each open template `${`, the depth right after its `{`.
    let mut templates: Vec<usize> = Vec::new();
    // Index of the last significant byte seen in code (decides whether `/` starts a regex).
    let mut last_significant: Option<usize> = None;
    // Set after a string, template or regex literal ends: a following `/` is a division.
    let mut after_literal = false;
    let mut i = 0usize;
    while let Some(&byte) = bytes.get(i) {
        match mode {
            Mode::Code => {
                let mut significant = true;
                match byte {
                    b'(' | b'[' | b'{' => {
                        depth += 1;
                        max_depth = max_depth.max(depth);
                    }
                    b')' | b']' => depth = depth.saturating_sub(1),
                    b'}' => {
                        if templates.last().is_some_and(|&open| depth <= open) {
                            templates.pop();
                            mode = Mode::Template;
                        }
                        depth = depth.saturating_sub(1);
                    }
                    b'\'' | b'"' => mode = Mode::Str(byte),
                    b'`' => mode = Mode::Template,
                    b'/' => match bytes.get(i + 1) {
                        Some(b'/') => {
                            mode = Mode::LineComment;
                            significant = false;
                            i += 1;
                        }
                        Some(b'*') => {
                            mode = Mode::BlockComment;
                            significant = false;
                            i += 1;
                        }
                        _ if !after_literal && regex_allowed(bytes, last_significant) => {
                            mode = Mode::Regex { in_class: false };
                        }
                        _ => {}
                    },
                    b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C => significant = false,
                    _ => {}
                }
                if significant {
                    last_significant = Some(i);
                    after_literal = false;
                }
            }
            Mode::LineComment => {
                if byte == b'\n' || byte == b'\r' {
                    mode = Mode::Code;
                }
            }
            Mode::BlockComment => {
                if byte == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    mode = Mode::Code;
                    i += 1;
                }
            }
            Mode::Str(quote) => match byte {
                b'\\' => i += 1,
                b'\n' | b'\r' => mode = Mode::Code,
                _ if byte == quote => {
                    mode = Mode::Code;
                    after_literal = true;
                }
                _ => {}
            },
            Mode::Template => match byte {
                b'\\' => i += 1,
                b'`' => {
                    mode = Mode::Code;
                    after_literal = true;
                }
                b'$' if bytes.get(i + 1) == Some(&b'{') => {
                    i += 1;
                    depth += 1;
                    max_depth = max_depth.max(depth);
                    templates.push(depth);
                    mode = Mode::Code;
                    last_significant = Some(i);
                    after_literal = false;
                }
                _ => {}
            },
            Mode::Regex { in_class } => match byte {
                b'\\' => i += 1,
                b'\n' | b'\r' => mode = Mode::Code,
                b'[' => mode = Mode::Regex { in_class: true },
                b']' => mode = Mode::Regex { in_class: false },
                b'/' if !in_class => {
                    mode = Mode::Code;
                    after_literal = true;
                }
                _ => {}
            },
        }
        i += 1;
    }
    max_depth
}

/// Keywords after which `/` starts a regular expression rather than a division.
const REGEX_KEYWORDS: &[&[u8]] = &[
    b"return",
    b"typeof",
    b"instanceof",
    b"in",
    b"of",
    b"new",
    b"delete",
    b"void",
    b"throw",
    b"case",
    b"do",
    b"else",
    b"yield",
    b"await",
];

/// Whether a `/` following the significant byte at `last` starts a regular expression.
fn regex_allowed(bytes: &[u8], last: Option<usize>) -> bool {
    let Some(last) = last else {
        return true; // start of file
    };
    let Some(&prev) = bytes.get(last) else {
        return true;
    };
    if prev == b')' || prev == b']' || prev == b'}' {
        return false;
    }
    if !is_ident_byte(prev) {
        return true; // after an operator or punctuator
    }
    // After an identifier or number: a regex only if the word is a keyword like `return`.
    let mut start = last;
    while let Some(before) = start.checked_sub(1) {
        match bytes.get(before) {
            Some(&b) if is_ident_byte(b) => start = before,
            _ => break,
        }
    }
    bytes
        .get(start..=last)
        .is_some_and(|word| REGEX_KEYWORDS.contains(&word))
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(bytes: &[u8]) -> Option<SkipReason> {
        check(bytes).err().map(|skip| skip.reason)
    }

    #[test]
    fn ordinary_code_passes_every_check() {
        let src = "const a = [1, 2, { b: (3) }];\nfunction f(x) {\n  return x;\n}\n";
        assert_eq!(check(src.as_bytes()), Ok(src));
        assert_eq!(check(b""), Ok(""));
    }

    #[test]
    fn size_limit_is_inclusive() {
        assert!(check_size(MAX_FILE_BYTES).is_ok());
        let skip = check_size(MAX_FILE_BYTES + 1).unwrap_err();
        assert_eq!(skip.reason, SkipReason::TooLarge);
        assert_eq!(
            skip.message,
            "file is 2097153 bytes, over the 2097152-byte limit"
        );
        let mut big = "a;\n".repeat(700_000).into_bytes();
        big.truncate(usize::try_from(MAX_FILE_BYTES).unwrap() + 1);
        assert_eq!(reason(&big), Some(SkipReason::TooLarge));
    }

    #[test]
    fn invalid_utf8_is_reported_with_its_offset() {
        let skip = check(b"var s = '\xff';").unwrap_err();
        assert_eq!(skip.reason, SkipReason::NotUtf8);
        assert_eq!(skip.message, "invalid UTF-8 at byte offset 9");
        // Truncated multi-byte sequence at the end.
        assert_eq!(reason(b"var s = '\xe2\x82"), Some(SkipReason::NotUtf8));
    }

    #[test]
    fn one_long_line_is_minified() {
        // A line of exactly the limit does not trip the long-line rule; plenty of short lines
        // keep the average down.
        let at_limit = format!("{}\n{}", "x".repeat(MAX_LINE_CHARS), "a;\n".repeat(100));
        assert_eq!(LineShape::of(&at_limit).max_line_chars, MAX_LINE_CHARS);
        assert!(check(at_limit.as_bytes()).is_ok());
        let long = format!("\n\nvar a = '{}';\n", "x".repeat(MAX_LINE_CHARS));
        let skip = check(long.as_bytes()).unwrap_err();
        assert_eq!(skip.reason, SkipReason::Minified);
        assert_eq!(
            skip.message,
            "line 3 is 20011 characters long (limit 20000)"
        );
    }

    #[test]
    fn line_length_counts_characters_not_bytes() {
        // 15,000 three-byte characters: 45,000 bytes but only 15,000 characters.
        let line = "€".repeat(15_000);
        assert_eq!(LineShape::of(&line).max_line_chars, 15_000);
        let text = format!("{line}\n{}", "a;\n".repeat(60));
        assert_eq!(LineShape::of(&text).lines, 61);
        // 15,120 characters over 61 lines is under 300 per line, whatever the byte count.
        assert!(check(text.as_bytes()).is_ok());
    }

    #[test]
    fn long_average_lines_are_minified_only_above_one_kib() {
        // 4 lines of 400 characters: 1.6 KiB, average 400.
        let dense = format!("{}\n", "y".repeat(400)).repeat(4);
        let skip = check(dense.as_bytes()).unwrap_err();
        assert_eq!(skip.reason, SkipReason::Minified);
        assert_eq!(
            skip.message,
            "average line length is over 300 characters (1600 characters on 4 lines)"
        );
        // Same average, but under 1 KiB.
        let small = format!("{}\n", "y".repeat(400)).repeat(2);
        assert!(check(small.as_bytes()).is_ok());
        // Average exactly 300 is allowed.
        let edge = format!("{}\n", "y".repeat(300)).repeat(5);
        assert!(check(edge.as_bytes()).is_ok());
    }

    #[test]
    fn line_shape_handles_every_line_terminator() {
        let shape = LineShape::of("ab\ncd\r\nef\rgh");
        assert_eq!(shape.lines, 4);
        assert_eq!(shape.total_chars, 8);
        assert_eq!(LineShape::of("a\n").lines, 1);
        assert_eq!(LineShape::of("a\n\n").lines, 2);
        assert_eq!(LineShape::of("").lines, 0);
        assert_eq!(LineShape::of("\r\n\r\n").lines, 2);
    }

    #[test]
    fn nesting_depth_counts_all_bracket_kinds() {
        assert_eq!(nesting_depth(b""), 0);
        assert_eq!(nesting_depth(b"a; b;"), 0);
        assert_eq!(nesting_depth(b"f(a[b{c}])"), 3);
        assert_eq!(nesting_depth(b"(())(((())))"), 4);
        // Stray closers never go negative.
        assert_eq!(nesting_depth(b")))((("), 3);
    }

    #[test]
    fn nesting_depth_ignores_strings_and_comments() {
        assert_eq!(nesting_depth(b"a = '((((' + \"[[[[\";"), 0);
        assert_eq!(nesting_depth(b"a = '\\'(((';"), 0);
        assert_eq!(nesting_depth(b"// ((((\nx"), 0);
        assert_eq!(nesting_depth(b"/* ((((\n (((( */ f()"), 1);
        // An apostrophe in JSX text only swallows the rest of its line.
        assert_eq!(nesting_depth(b"<p>Don't</p>\nf(g())"), 2);
    }

    #[test]
    fn nesting_depth_follows_template_literals() {
        assert_eq!(nesting_depth(b"`((((`"), 0);
        assert_eq!(nesting_depth(b"`a ${ f(x) } b`"), 2);
        assert_eq!(nesting_depth(b"`a ${ {k: 1}.k } ((( `"), 2);
        // Nested templates.
        assert_eq!(nesting_depth(b"`${ `${ g() }` }`"), 3);
        // Escaped `${` is template text.
        assert_eq!(nesting_depth(b"`\\${ ((( `"), 0);
    }

    #[test]
    fn nesting_depth_skips_regex_literals() {
        assert_eq!(nesting_depth(b"x = /[(]+/.test(s);"), 1);
        assert_eq!(nesting_depth(b"if (/\\(/.test(s)) {}"), 2);
        assert_eq!(nesting_depth(b"return /((/g;"), 0);
        assert_eq!(nesting_depth(b"x = typeof /(/"), 0);
        // Divisions are not regexes.
        assert_eq!(nesting_depth(b"a = b / c / (d);"), 1);
        assert_eq!(nesting_depth(b"a = f(x) / (y) / 2;"), 1);
        assert_eq!(nesting_depth(b"a = 'x' / ('y')"), 1);
    }

    /// `depth` nested brackets, one per line so the file does not look minified.
    fn nested(open: &str, close: &str, depth: usize) -> String {
        format!(
            "x =\n{}1{};\n",
            format!("{open}\n").repeat(depth),
            format!("\n{close}").repeat(depth)
        )
    }

    #[test]
    fn deep_nesting_is_skipped() {
        let deep = nested("(", ")", MAX_NESTING_DEPTH + 1);
        let skip = check(deep.as_bytes()).unwrap_err();
        assert_eq!(skip.reason, SkipReason::TooDeep);
        assert_eq!(
            skip.message,
            "bracket nesting depth 2001 exceeds the limit of 2000"
        );
        assert!(check(nested("[", "]", MAX_NESTING_DEPTH).as_bytes()).is_ok());
        assert_eq!(
            reason(nested("{", "}", MAX_NESTING_DEPTH + 5).as_bytes()),
            Some(SkipReason::TooDeep)
        );
    }

    #[test]
    fn skips_become_diagnostics() {
        let diag = Skip::new(SkipReason::Minified, "m").into_diagnostic("a.js");
        assert_eq!(diag.code, crate::diag::DiagCode::SkipMinified);
        assert_eq!(diag.path.as_deref(), Some("a.js"));
        assert_eq!(diag.message, "m");
    }
}
