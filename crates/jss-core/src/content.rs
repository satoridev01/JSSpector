//! Pure checks on a file's bytes, run before parsing.
//!
//! They keep the parser away from files it cannot or should not handle: oversized files,
//! non-UTF-8 text, minified bundles, and nesting deep enough to overflow the parser's stack
//! (oxc#21953; a stack overflow aborts the process and cannot be caught).
//!
//! The minified and nesting checks start from cheap upper bounds: raw line lengths, and the raw
//! number of opening brackets (nesting can never be deeper than that). Only a file that fails a
//! bound is lexed ([`scan`]), so that string literals do not count towards line length and
//! brackets inside strings, comments and regular expressions do not count towards depth.
//!
//! The depth estimate is a heuristic: a lexer that does not parse can be fooled. It is the
//! first line of defense only; the frontend also sizes the parser's stack from the file's size,
//! which bounds the recursion of every construct whatever this scan concludes.

use std::str::Utf8Error;

use crate::diag::{Diagnostic, SkipReason};

/// Files larger than this are skipped (`skip/too-large`).
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// A file with any line longer than this many characters is minified (`skip/minified`).
/// Characters inside string literals and template literal text do not count.
pub const MAX_LINE_CHARS: usize = 20_000;

/// A file larger than this many bytes...
pub const AVG_LINE_MIN_FILE_BYTES: usize = 1024;

/// ...whose average line is longer than this many characters is minified (`skip/minified`).
/// Characters inside string literals and template literal text do not count.
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
    // Raw line lengths bound the code-only ones, and the opening brackets bound the depth: when
    // neither bound fails, the file passes without being lexed (the common case).
    let maybe_minified = minified(&LineShape::of(text), text.len()).is_some();
    let maybe_deep = opening_brackets(bytes) > MAX_NESTING_DEPTH;
    if !maybe_minified && !maybe_deep {
        return Ok(text);
    }
    let scan = scan(bytes);
    if let Some(skip) = minified(&scan.code_shape, text.len()) {
        return Err(skip);
    }
    if scan.max_depth > MAX_NESTING_DEPTH {
        return Err(Skip::new(
            SkipReason::TooDeep,
            format!(
                "bracket nesting depth {} exceeds the limit of {MAX_NESTING_DEPTH}",
                scan.max_depth
            ),
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

/// The minified verdict for a line shape, if it is one.
fn minified(shape: &LineShape, text_bytes: usize) -> Option<Skip> {
    if shape.max_line_chars > MAX_LINE_CHARS {
        return Some(Skip::new(
            SkipReason::Minified,
            format!(
                "line {} is {} characters long, not counting string literals (limit \
                 {MAX_LINE_CHARS})",
                shape.longest_line, shape.max_line_chars
            ),
        ));
    }
    if text_bytes > AVG_LINE_MIN_FILE_BYTES
        && shape.total_chars > MAX_AVG_LINE_CHARS.saturating_mul(shape.lines)
    {
        return Some(Skip::new(
            SkipReason::Minified,
            format!(
                "average line length is over {MAX_AVG_LINE_CHARS} characters, not counting \
                 string literals ({} characters on {} lines)",
                shape.total_chars, shape.lines
            ),
        ));
    }
    None
}

/// The number of `(`, `[` and `{` bytes: an upper bound of [`nesting_depth`], since every level
/// (template `${` included) is opened by one of them.
pub fn opening_brackets(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .filter(|&&byte| matches!(byte, b'(' | b'[' | b'{'))
        .count()
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
    /// The raw shape of `text`: every character counts.
    pub fn of(text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut shape = LineShape::default();
        let mut terminator_bytes = 0usize;
        let mut rest = bytes;
        while !rest.is_empty() {
            let (line, terminator) =
                match rest.iter().position(|&byte| byte == b'\n' || byte == b'\r') {
                    Some(end) => {
                        let crlf =
                            rest.get(end) == Some(&b'\r') && rest.get(end + 1) == Some(&b'\n');
                        (
                            rest.get(..end).unwrap_or_default(),
                            if crlf { 2 } else { 1 },
                        )
                    }
                    None => (rest, 0),
                };
            shape.lines += 1;
            // A line has at most as many characters as bytes: count them only when this line
            // could be the longest so far.
            if line.len() > shape.max_line_chars {
                let chars = char_count(line);
                if chars > shape.max_line_chars {
                    shape.max_line_chars = chars;
                    shape.longest_line = shape.lines;
                }
            }
            terminator_bytes += terminator;
            rest = rest.get(line.len() + terminator..).unwrap_or_default();
        }
        // Line terminators are ASCII, so every non-continuation byte outside them is a
        // character.
        shape.total_chars = bytes
            .len()
            .saturating_sub(terminator_bytes)
            .saturating_sub(continuation_bytes(bytes));
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

fn continuation_bytes(bytes: &[u8]) -> usize {
    bytes.iter().filter(|&&byte| byte & 0xC0 == 0x80).count()
}

fn char_count(bytes: &[u8]) -> usize {
    bytes.len().saturating_sub(continuation_bytes(bytes))
}

/// What [`scan`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Scan {
    /// Approximate maximum nesting depth of `(`, `[`, `{` and template `${`.
    pub max_depth: usize,
    /// Line statistics without the characters inside string literals and template literal text
    /// (delimiters, comments and regular expressions count).
    pub code_shape: LineShape,
}

/// Approximate maximum nesting depth of `(`, `[`, `{` (and template `${`) in JS/TS source.
pub fn nesting_depth(bytes: &[u8]) -> usize {
    scan(bytes).max_depth
}

/// Lexes `bytes` once, well enough to skip strings, template text, comments and regular
/// expression literals without parsing, and measures nesting depth and code-only line lengths.
///
/// Where the lexer has to guess, it prefers the guess that counts more brackets:
/// - `/` starts a regular expression only after an operator, punctuator or keyword; after
///   `)`, `]`, `}`, an identifier, a number, a postfix `++`/`--` or a member name such as
///   `x.in` it is a division.
/// - A string or regular expression cut off by a line break (impossible in valid code, so a
///   mis-lex, e.g. an apostrophe in JSX text) is lexed again as code: its brackets count.
pub fn scan(bytes: &[u8]) -> Scan {
    let mut scanner = Scanner::new(bytes);
    scanner.run();
    Scan {
        max_depth: scanner.max_depth,
        code_shape: scanner.shape,
    }
}

/// Lexer state of the [`scan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Code,
    LineComment,
    BlockComment,
    /// A `'` or `"` string.
    Str(u8),
    /// The literal text of a template, outside `${...}`.
    Template,
    /// A regular expression literal; `in_class` is true inside `[...]`.
    Regex {
        in_class: bool,
    },
}

struct Scanner<'a> {
    bytes: &'a [u8],
    mode: Mode,
    depth: usize,
    max_depth: usize,
    /// For each open template `${`, the depth right after its `{`.
    templates: Vec<usize>,
    /// Index of the last significant byte seen in code (decides whether `/` starts a regex).
    last_significant: Option<usize>,
    /// Set after a string, template or regex literal ends: a following `/` is a division.
    after_literal: bool,
    /// The previous byte was a backslash inside a string, template or regex.
    escaped: bool,
    /// Index of the opening delimiter of the current string or regex literal.
    literal_start: usize,
    /// Characters inside the current string literal: code after all if it is cut off.
    literal_chars: usize,
    /// Code characters on the current line.
    line_chars: usize,
    /// Whether the current line has any byte (a final line without one does not count).
    line_open: bool,
    shape: LineShape,
}

impl<'a> Scanner<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            mode: Mode::Code,
            depth: 0,
            max_depth: 0,
            templates: Vec::new(),
            last_significant: None,
            after_literal: false,
            escaped: false,
            literal_start: 0,
            literal_chars: 0,
            line_chars: 0,
            line_open: false,
            shape: LineShape::default(),
        }
    }

    fn run(&mut self) {
        let mut i = 0usize;
        while let Some(&byte) = self.bytes.get(i) {
            if byte == b'\n' || byte == b'\r' {
                let crlf = byte == b'\r' && self.bytes.get(i + 1) == Some(&b'\n');
                self.line_break(i);
                i += if crlf { 2 } else { 1 };
                continue;
            }
            self.line_open = true;
            let is_char = byte & 0xC0 != 0x80;
            i = match self.mode {
                Mode::Code => {
                    self.line_chars += usize::from(is_char);
                    self.code(i, byte)
                }
                Mode::LineComment => {
                    self.line_chars += usize::from(is_char);
                    i + 1
                }
                Mode::BlockComment => {
                    self.line_chars += usize::from(is_char);
                    if byte == b'*' && self.bytes.get(i + 1) == Some(&b'/') {
                        self.line_chars += 1;
                        self.mode = Mode::Code;
                        i + 2
                    } else {
                        i + 1
                    }
                }
                Mode::Str(quote) => {
                    if self.escaped {
                        self.escaped = false;
                        self.literal_chars += usize::from(is_char);
                    } else if byte == b'\\' {
                        self.escaped = true;
                        self.literal_chars += 1;
                    } else if byte == quote {
                        self.line_chars += 1;
                        self.literal_chars = 0;
                        self.mode = Mode::Code;
                        self.after_literal = true;
                    } else {
                        self.literal_chars += usize::from(is_char);
                    }
                    i + 1
                }
                Mode::Template => self.template(i, byte),
                Mode::Regex { in_class } => {
                    self.line_chars += usize::from(is_char);
                    if self.escaped {
                        self.escaped = false;
                    } else {
                        match byte {
                            b'\\' => self.escaped = true,
                            b'[' => self.mode = Mode::Regex { in_class: true },
                            b']' => self.mode = Mode::Regex { in_class: false },
                            b'/' if !in_class => {
                                self.mode = Mode::Code;
                                self.after_literal = true;
                            }
                            _ => {}
                        }
                    }
                    i + 1
                }
            };
        }
        if self.line_open {
            self.shape.end_line(self.line_chars);
        }
    }

    /// One byte of code (never a line terminator); returns the index of the next byte.
    fn code(&mut self, i: usize, byte: u8) -> usize {
        let mut significant = true;
        let mut next = i + 1;
        match byte {
            b'(' | b'[' | b'{' => self.open(),
            b')' | b']' => self.close(),
            b'}' => self.close_brace(),
            b'\'' | b'"' => {
                self.mode = Mode::Str(byte);
                self.literal_start = i;
                self.literal_chars = 0;
            }
            b'`' => self.mode = Mode::Template,
            b'/' => match self.bytes.get(i + 1) {
                Some(b'/') => {
                    self.mode = Mode::LineComment;
                    significant = false;
                }
                Some(b'*') => {
                    self.mode = Mode::BlockComment;
                    significant = false;
                    // The `*` belongs to the opener: `/*/` does not close the comment.
                    self.line_chars += 1;
                    next = i + 2;
                }
                _ if !self.after_literal && regex_allowed(self.bytes, self.last_significant) => {
                    self.mode = Mode::Regex { in_class: false };
                    self.literal_start = i;
                }
                _ => {}
            },
            b' ' | b'\t' | 0x0B | 0x0C => significant = false,
            _ => {}
        }
        if significant {
            self.last_significant = Some(i);
            self.after_literal = false;
        }
        next
    }

    /// One byte of template text (never a line terminator); returns the index of the next byte.
    fn template(&mut self, i: usize, byte: u8) -> usize {
        if self.escaped {
            self.escaped = false;
            return i + 1;
        }
        match byte {
            b'\\' => self.escaped = true,
            b'`' => {
                self.line_chars += 1;
                self.mode = Mode::Code;
                self.after_literal = true;
            }
            b'$' if self.bytes.get(i + 1) == Some(&b'{') => {
                self.line_chars += 2;
                self.open();
                self.templates.push(self.depth);
                self.mode = Mode::Code;
                self.last_significant = Some(i + 1);
                self.after_literal = false;
                return i + 2;
            }
            _ => {}
        }
        i + 1
    }

    fn open(&mut self) {
        self.depth += 1;
        self.max_depth = self.max_depth.max(self.depth);
    }

    fn close(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// A `}` in code: closes a template `${` (back to template text) or a bracket.
    fn close_brace(&mut self) {
        if self
            .templates
            .last()
            .is_some_and(|&open| self.depth <= open)
        {
            self.templates.pop();
            self.mode = Mode::Template;
        }
        self.close();
    }

    /// A line terminator at `i`, in any mode.
    fn line_break(&mut self, i: usize) {
        match self.mode {
            Mode::LineComment => self.mode = Mode::Code,
            // A backslash before the line break continues the string onto the next line.
            Mode::Str(_) if self.escaped => {
                self.escaped = false;
                // The content on the finished line was string content; start counting afresh.
                self.literal_chars = 0;
            }
            Mode::Str(_) | Mode::Regex { .. } => self.relex_as_code(i),
            Mode::Template => self.escaped = false,
            Mode::Code | Mode::BlockComment => {}
        }
        self.shape.end_line(self.line_chars);
        self.line_chars = 0;
        self.line_open = false;
    }

    /// The string or regex literal that started at `literal_start` was cut off by the line
    /// break at `end`, which valid code never does: it was a mis-lex. Count its characters and
    /// brackets as code instead.
    fn relex_as_code(&mut self, end: usize) {
        if let Mode::Str(_) = self.mode {
            self.line_chars += self.literal_chars;
        }
        self.literal_chars = 0;
        self.escaped = false;
        self.mode = Mode::Code;
        self.after_literal = false;
        let start = self.literal_start;
        self.last_significant = Some(start);
        for index in start.saturating_add(1)..end {
            let Some(&byte) = self.bytes.get(index) else {
                break;
            };
            match byte {
                b'(' | b'[' | b'{' => self.open(),
                b')' | b']' => self.close(),
                // Only depth is tracked here: the line ends right after, in code.
                b'}' => {
                    if self
                        .templates
                        .last()
                        .is_some_and(|&open| self.depth <= open)
                    {
                        self.templates.pop();
                    }
                    self.close();
                }
                _ => {}
            }
            if !matches!(byte, b' ' | b'\t' | 0x0B | 0x0C) {
                self.last_significant = Some(index);
            }
        }
    }
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
    if (prev == b'+' || prev == b'-')
        && last.checked_sub(1).and_then(|i| bytes.get(i)) == Some(&prev)
    {
        // A postfix `x++ / y` or `x-- / y` (a regex can never follow a postfix update; a
        // prefix update cannot apply to one).
        return false;
    }
    if !is_ident_byte(prev) {
        return true; // after an operator or punctuator
    }
    // After an identifier or number: a regex only if the word is a keyword like `return`, and
    // not a member name like `x.in` or `this.#return`.
    let mut start = last;
    while let Some(before) = start.checked_sub(1) {
        match bytes.get(before) {
            Some(&b) if is_ident_byte(b) => start = before,
            _ => break,
        }
    }
    let member = start
        .checked_sub(1)
        .and_then(|before| bytes.get(before))
        .is_some_and(|&b| b == b'.' || b == b'#');
    !member
        && bytes
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
        let long = format!("\n\nvar a = [{}];\n", "1,".repeat(MAX_LINE_CHARS / 2));
        let skip = check(long.as_bytes()).unwrap_err();
        assert_eq!(skip.reason, SkipReason::Minified);
        assert_eq!(
            skip.message,
            "line 3 is 20011 characters long, not counting string literals (limit 20000)"
        );
    }

    #[test]
    fn string_literals_do_not_make_a_line_minified() {
        // A hand-written file with one huge data URI: the line is long, the code on it is not.
        let data = format!(
            "export const logo = {{\n  src: 'data:image/png;base64,{}',\n}};\n",
            "A".repeat(35_000)
        );
        assert!(LineShape::of(&data).max_line_chars > MAX_LINE_CHARS);
        assert_eq!(check(data.as_bytes()), Ok(data.as_str()));
        let shape = scan(data.as_bytes()).code_shape;
        assert_eq!(shape.lines, 3);
        assert_eq!(shape.max_line_chars, "export const logo = {".len());
        // The same goes for template literal text, but not for code inside `${}`.
        let template = format!("const t = `{}`;\n", "<p>".repeat(10_000));
        assert!(check(template.as_bytes()).is_ok());
        let code = format!("const t = `${{[{}]}}`;\n", "1,".repeat(10_001));
        assert_eq!(reason(code.as_bytes()), Some(SkipReason::Minified));
        // Comments and regular expressions count: inline source maps still look minified.
        let map = format!("f();\n//# sourceMappingURL=data:,{}\n", "x".repeat(25_000));
        assert_eq!(reason(map.as_bytes()), Some(SkipReason::Minified));
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
        assert_eq!(scan(text.as_bytes()).code_shape, LineShape::of(&text));
    }

    #[test]
    fn long_average_lines_are_minified_only_above_one_kib() {
        // 4 lines of 400 characters: 1.6 KiB, average 400.
        let dense = format!("{}\n", "y".repeat(400)).repeat(4);
        let skip = check(dense.as_bytes()).unwrap_err();
        assert_eq!(skip.reason, SkipReason::Minified);
        assert_eq!(
            skip.message,
            "average line length is over 300 characters, not counting string literals \
             (1600 characters on 4 lines)"
        );
        // Same average, but under 1 KiB.
        let small = format!("{}\n", "y".repeat(400)).repeat(2);
        assert!(check(small.as_bytes()).is_ok());
        // Average exactly 300 is allowed.
        let edge = format!("{}\n", "y".repeat(300)).repeat(5);
        assert!(check(edge.as_bytes()).is_ok());
        // Long string literals do not count towards the average either.
        let strings = format!("x = '{}';\n", "s".repeat(400)).repeat(4);
        assert!(check(strings.as_bytes()).is_ok());
    }

    #[test]
    fn line_shape_handles_every_line_terminator() {
        for text in [
            "ab\ncd\r\nef\rgh",
            "a\n",
            "a\n\n",
            "",
            "\r\n\r\n",
            "x\r",
            "é\n\r\nü",
        ] {
            // The scan's code-only shape agrees with the raw shape on code without literals.
            assert_eq!(
                scan(text.as_bytes()).code_shape,
                LineShape::of(text),
                "{text:?}"
            );
        }
        let shape = LineShape::of("ab\ncd\r\nef\rgh");
        assert_eq!(shape.lines, 4);
        assert_eq!(shape.total_chars, 8);
        assert_eq!(LineShape::of("a\n").lines, 1);
        assert_eq!(LineShape::of("a\n\n").lines, 2);
        assert_eq!(LineShape::of("").lines, 0);
        assert_eq!(LineShape::of("\r\n\r\n").lines, 2);
        let shape = LineShape::of("ab\nlonger line\nx");
        assert_eq!((shape.max_line_chars, shape.longest_line), (11, 2));
    }

    #[test]
    fn line_shapes_follow_multi_line_literals() {
        // A string continued with a backslash, a multi-line template and a block comment still
        // count their lines.
        let text = "a = 'x\\\ny';\nb = `\n\n`;\n/*\n*/\n";
        let shape = scan(text.as_bytes()).code_shape;
        assert_eq!(shape.lines, LineShape::of(text).lines);
        assert_eq!(shape.lines, 7);
        // Same with CRLF line ends, including the backslash continuation.
        let crlf = text.replace('\n', "\r\n");
        assert_eq!(scan(crlf.as_bytes()).code_shape.lines, 7);
        assert_eq!(nesting_depth(b"a = 'x\\\n(((';"), 0);
        assert_eq!(nesting_depth(b"a = 'x\\\r\n(((';"), 0);
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
        assert_eq!(nesting_depth(b"/*/ ((( */ f()"), 1);
    }

    #[test]
    fn literals_cut_off_by_a_line_break_are_lexed_as_code() {
        // An apostrophe in JSX text is not a string: its brackets count.
        assert_eq!(nesting_depth(b"<p>Don't (stop) f(((\n</p>"), 3);
        assert_eq!(nesting_depth(b"<p>Don't</p>\nf(g())"), 2);
        // `</` looks like the start of a regex to the lexer; the line break proves it was not.
        assert_eq!(nesting_depth(b"x = <a></a> ((((\ny"), 4);
        // A closed string on the same line still hides its brackets.
        assert_eq!(nesting_depth(b"x = '((((' + f(\n)"), 1);
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
        // Templates span lines.
        assert_eq!(nesting_depth(b"`\n((\n${ f() }\n((`"), 2);
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

    #[test]
    fn divisions_after_postfix_updates_and_member_names_are_not_regexes() {
        assert_eq!(nesting_depth(b"a++ / ((b)) / 2"), 2);
        assert_eq!(nesting_depth(b"a-- / ((b)) / 2"), 2);
        assert_eq!(nesting_depth(b"obj.in / ((b)) / 2"), 2);
        assert_eq!(nesting_depth(b"a?.return / ((b)) / 2"), 2);
        assert_eq!(nesting_depth(b"this.#of / ((b)) / 2"), 2);
        // Operators and real keywords still start regexes.
        assert_eq!(nesting_depth(b"a + /((/.source"), 0);
        assert_eq!(nesting_depth(b"a+ +/((/.source"), 0);
        assert_eq!(nesting_depth(b"x in /((/"), 0);
    }

    /// `depth` nested brackets, one per line so the file does not look minified.
    fn nested(open: &str, close: &str, depth: usize) -> String {
        format!(
            "x =\n{}1{};\n",
            format!("{open}\n").repeat(depth),
            format!("\n{close}").repeat(depth)
        )
    }

    /// Nesting hidden behind `a++ / (((...`, which a lexer that treats `/` after `+` as the
    /// start of a regex would skip line by line (D2-PLAN-01).
    fn hidden_parens(depth: usize) -> String {
        let lines = depth / 200;
        format!(
            "var a = 1;\nx =\n{}1{};\n",
            format!("a++ / {}\n", "(".repeat(200)).repeat(lines),
            format!("\n{}", ")".repeat(200)).repeat(lines)
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
        let hidden = hidden_parens(3_000);
        assert_eq!(nesting_depth(hidden.as_bytes()), 3_000);
        assert_eq!(reason(hidden.as_bytes()), Some(SkipReason::TooDeep));
    }

    #[test]
    fn brackets_in_literals_beyond_the_bound_are_lexed_away() {
        // More opening brackets than the depth limit, all inside strings and comments: the
        // cheap bound fails, the lexer clears the file.
        let src = format!(
            "const a = '{}';\n// {}\n{}",
            "(".repeat(MAX_NESTING_DEPTH),
            "[".repeat(MAX_NESTING_DEPTH),
            "f(a);\n".repeat(20)
        );
        assert!(opening_brackets(src.as_bytes()) > MAX_NESTING_DEPTH);
        assert_eq!(check(src.as_bytes()), Ok(src.as_str()));
    }

    #[test]
    fn opening_brackets_bound_the_depth() {
        for src in [
            "f(a[b{c}])",
            "`${ `${ g() }` }`",
            "<p>Don't (stop) f(((\n</p>",
            "x = '((((' + f(\n)",
        ] {
            assert!(
                nesting_depth(src.as_bytes()) <= opening_brackets(src.as_bytes()),
                "{src}"
            );
        }
    }

    #[test]
    fn skips_become_diagnostics() {
        let diag = Skip::new(SkipReason::Minified, "m").into_diagnostic("a.js");
        assert_eq!(diag.code, crate::diag::DiagCode::SkipMinified);
        assert_eq!(diag.path.as_deref(), Some("a.js"));
        assert_eq!(diag.message, "m");
    }
}
