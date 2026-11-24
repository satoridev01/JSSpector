//! A forgiving tokenizer and token-level helpers for the Flow repair rules.
//!
//! This is not a JavaScript lexer. The rules only need token boundaries good enough to match
//! brackets and to recognize a few Flow shapes next to a syntax error, so it never fails and
//! never allocates per token. Punctuation is one token per character, except `=>` and `...`:
//! that keeps `Array<Array<T>>` and `{| a |}` unambiguous.
//!
//! Types never contain regular expressions or statements, so everything here that walks a type
//! (see [`Toks::type_end`]) is exact for valid Flow; the regex guess in the tokenizer only has to
//! be right often enough that bracket matching near a Flow construct is not thrown off.

/// How deep the type scanners recurse before giving up: bounds the stack on hostile input.
const MAX_DEPTH: u8 = 96;

/// Most tokens an angle-bracket scan walks, so a stray `<` cannot make a rule quadratic.
const MAX_ANGLE_SCAN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Ident,
    Number,
    Str,
    Template,
    Regex,
    Punct,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Tok {
    pub(crate) kind: Kind,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

/// The tokens of one source text, with bracket partners.
pub(crate) struct Toks<'a> {
    src: &'a str,
    toks: Vec<Tok>,
    /// For each `(`, `[`, `{` and its closer, the index of the other one.
    partner: Vec<Option<usize>>,
}

impl<'a> Toks<'a> {
    pub(crate) fn new(src: &'a str) -> Self {
        let toks = tokenize(src);
        let partner = pair_brackets(src, &toks);
        Self { src, toks, partner }
    }

    pub(crate) fn len(&self) -> usize {
        self.toks.len()
    }

    pub(crate) fn tok(&self, i: usize) -> Option<Tok> {
        self.toks.get(i).copied()
    }

    pub(crate) fn start(&self, i: usize) -> Option<usize> {
        self.tok(i).map(|tok| tok.start)
    }

    pub(crate) fn end(&self, i: usize) -> Option<usize> {
        self.tok(i).map(|tok| tok.end)
    }

    pub(crate) fn kind(&self, i: usize) -> Option<Kind> {
        self.tok(i).map(|tok| tok.kind)
    }

    /// The token's text; empty past the end.
    pub(crate) fn text(&self, i: usize) -> &'a str {
        self.tok(i)
            .and_then(|tok| self.src.get(tok.start..tok.end))
            .unwrap_or("")
    }

    /// The token is this identifier, keyword or punctuation.
    pub(crate) fn is(&self, i: usize, text: &str) -> bool {
        matches!(self.kind(i), Some(Kind::Ident | Kind::Punct)) && self.text(i) == text
    }

    pub(crate) fn is_ident(&self, i: usize) -> bool {
        self.kind(i) == Some(Kind::Ident)
    }

    /// The token `n` places before `i`, if there is one.
    pub(crate) fn back(&self, i: usize, n: usize) -> Option<usize> {
        i.checked_sub(n)
    }

    /// The token before `i` is this text.
    pub(crate) fn prev_is(&self, i: usize, text: &str) -> bool {
        self.back(i, 1).is_some_and(|prev| self.is(prev, text))
    }

    /// Token `i - 1` is a `{` that token `i` follows directly (`{||}` is an empty exact object
    /// type, the one place two bars in a row are a type).
    #[cfg(test)]
    pub(crate) fn prev_adjacent_brace(&self, i: usize) -> bool {
        self.back(i, 1)
            .is_some_and(|prev| self.is(prev, "{") && self.adjacent(prev, i))
    }

    /// Index of the first token that ends after `offset`: the token containing it, or else the
    /// next one. A syntax error "after" a token therefore anchors at the token that follows.
    pub(crate) fn at_offset(&self, offset: usize) -> usize {
        self.toks.partition_point(|tok| tok.end <= offset)
    }

    /// The closer of the bracket at `open`.
    pub(crate) fn close_of(&self, open: usize) -> Option<usize> {
        self.partner
            .get(open)
            .copied()
            .flatten()
            .filter(|&close| close > open)
    }

    /// The opener of the bracket at `close`.
    pub(crate) fn open_of(&self, close: usize) -> Option<usize> {
        self.partner
            .get(close)
            .copied()
            .flatten()
            .filter(|&open| open < close)
    }

    pub(crate) fn is_opener(&self, i: usize) -> bool {
        self.is(i, "(") || self.is(i, "[") || self.is(i, "{")
    }

    pub(crate) fn is_closer(&self, i: usize) -> bool {
        self.is(i, ")") || self.is(i, "]") || self.is(i, "}")
    }

    /// A line break lies between token `i - 1` and token `i`.
    pub(crate) fn newline_before(&self, i: usize) -> bool {
        let Some(tok) = self.tok(i) else {
            return false;
        };
        let from = self
            .back(i, 1)
            .and_then(|p| self.end(p))
            .unwrap_or_default();
        self.src
            .as_bytes()
            .get(from..tok.start)
            .is_some_and(|gap| gap.iter().any(|&byte| byte == b'\n' || byte == b'\r'))
    }

    /// Token `j` starts exactly where token `i` ends.
    pub(crate) fn adjacent(&self, i: usize, j: usize) -> bool {
        matches!((self.end(i), self.start(j)), (Some(end), Some(start)) if end == start)
    }

    /// The `>` closing the `<` at `open`, skipping bracket groups. `None` when the `<` is an
    /// operator (a `;` or a stray closer comes first).
    pub(crate) fn angle_close(&self, open: usize) -> Option<usize> {
        let mut depth = 0usize;
        let mut i = open;
        let limit = open.saturating_add(MAX_ANGLE_SCAN);
        while i < self.len() && i < limit {
            if self.is(i, "<") {
                depth += 1;
            } else if self.is(i, ">") {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            } else if self.is_opener(i) {
                i = self.close_of(i)?;
            } else if self.is_closer(i) || self.is(i, ";") {
                return None;
            }
            i += 1;
        }
        None
    }

    /// The `<` opening the `>` at `close`, skipping bracket groups backwards.
    pub(crate) fn angle_open(&self, close: usize) -> Option<usize> {
        let mut depth = 0usize;
        let mut i = close;
        let floor = close.saturating_sub(MAX_ANGLE_SCAN);
        loop {
            if self.is(i, ">") {
                depth += 1;
            } else if self.is(i, "<") {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            } else if self.is_closer(i) {
                i = self.open_of(i)?;
            } else if self.is_opener(i) || self.is(i, ";") {
                return None;
            }
            if i <= floor {
                return None;
            }
            i -= 1;
        }
    }

    /// `a.b.c` starting at `i`: the index after it.
    pub(crate) fn path_end(&self, i: usize) -> Option<usize> {
        if !self.is_ident(i) {
            return None;
        }
        let mut end = i + 1;
        while self.is(end, ".") && self.is_ident(end + 1) {
            end += 2;
        }
        Some(end)
    }

    /// The index after the Flow (or TypeScript) type that starts at token `i`; `None` when
    /// what starts there is not a type this scanner knows.
    ///
    /// It follows the type grammar just far enough to find where a type stops: unions and
    /// intersections, prefix `?`, postfix `[]` and `[K]`, function types with or without
    /// parentheses around their parameter, generics, object types, tuples, `typeof`, `keyof`,
    /// `interface { }`, conditional types and `*`. Object types, tuples and parenthesized
    /// groups are skipped as bracket groups, which is exact because types hold no regexes.
    pub(crate) fn type_end(&self, i: usize) -> Option<usize> {
        self.ty(i, 0)
    }

    fn ty(&self, mut i: usize, depth: u8) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        if self.is(i, "|") || self.is(i, "&") {
            i += 1;
        }
        loop {
            i = self.anon(i, depth + 1)?;
            // `|}` closes an exact object type; it is never a union member.
            if (self.is(i, "|") && !self.is(i + 1, "}")) || self.is(i, "&") {
                i += 1;
                continue;
            }
            break;
        }
        if self.is(i, "extends") && !self.newline_before(i) {
            // `T extends U ? X : Y`; anything else leaves `extends` for the caller.
            if let Some(check_end) = self.ty(i + 1, depth + 1)
                && self.is(check_end, "?")
                && let Some(then_end) = self.ty(check_end + 1, depth + 1)
                && self.is(then_end, ":")
            {
                return self.ty(then_end + 1, depth + 1);
            }
        }
        Some(i)
    }

    /// A type without unions: prefixes, an atom, postfixes, and a function arrow.
    fn anon(&self, mut i: usize, depth: u8) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        while self.is(i, "?") {
            i += 1;
        }
        i = self.atom(i, depth + 1)?;
        loop {
            if self.is(i, "[") && !self.newline_before(i) {
                if self.is(i + 1, "]") {
                    i += 2;
                } else {
                    i = self.ty(i + 1, depth + 1)?;
                    if !self.is(i, "]") {
                        return None;
                    }
                    i += 1;
                }
            } else if self.is(i, "?")
                && self.is(i + 1, ".")
                && self.is(i + 2, "[")
                && self.adjacent(i, i + 1)
                && self.adjacent(i + 1, i + 2)
            {
                // Optional indexed access: `T?.[K]`.
                i += 2;
            } else {
                break;
            }
        }
        // A type guard in a return type: `x is T`.
        if self.is(i, "is")
            && !self.newline_before(i)
            && self.back(i, 1).is_some_and(|p| self.is_ident(p))
        {
            return self.ty(i + 1, depth + 1);
        }
        // A function type whose single parameter has no parentheses: `string => void`.
        if self.is(i, "=>") {
            return self.ty(i + 1, depth + 1);
        }
        Some(i)
    }

    fn atom(&self, i: usize, depth: u8) -> Option<usize> {
        match self.kind(i)? {
            Kind::Ident => self.ident_atom(i, depth),
            Kind::Str | Kind::Number | Kind::Template => Some(i + 1),
            Kind::Regex => None,
            Kind::Punct => match self.text(i) {
                "{" | "[" => self.close_of(i).map(|close| close + 1),
                "(" => {
                    let close = self.close_of(i)?;
                    if self.is(close + 1, "=>") {
                        self.ty(close + 2, depth + 1)
                    } else {
                        Some(close + 1)
                    }
                }
                "<" => {
                    // A generic function type: `<T>(x: T) => T`.
                    let close = self.angle_close(i)?;
                    if !self.is(close + 1, "(") {
                        return None;
                    }
                    let params = self.close_of(close + 1)?;
                    if !self.is(params + 1, "=>") {
                        return None;
                    }
                    self.ty(params + 2, depth + 1)
                }
                "*" => Some(i + 1),
                "-" | "+" if self.kind(i + 1) == Some(Kind::Number) => Some(i + 2),
                _ => None,
            },
        }
    }

    fn ident_atom(&self, i: usize, depth: u8) -> Option<usize> {
        match self.text(i) {
            "typeof" => self.path_end(i + 1),
            // Prefix operators, when a type follows on the same line.
            "keyof" | "readonly" if !self.newline_before(i + 1) && self.starts_type(i + 1) => {
                self.anon(i + 1, depth + 1)
            }
            "infer" => {
                let end = self.path_end(i + 1)?;
                if self.is(end, "extends")
                    && let Some(bound) = self.anon(end + 1, depth + 1)
                {
                    return Some(bound);
                }
                Some(end)
            }
            "interface" if self.is(i + 1, "{") || self.is(i + 1, "extends") => {
                // An inline interface type: `interface { m(): void }`.
                let mut j = i + 1;
                while j < self.len() && !self.is(j, "{") {
                    if self.is(j, ";") || self.is_closer(j) {
                        return None;
                    }
                    j += 1;
                }
                self.close_of(j).map(|close| close + 1)
            }
            _ => {
                let path = self.path_end(i)?;
                // Type arguments: `Array<T>`, and `Foo<>` (Flow allows an empty list).
                if self.is(path, "<")
                    && let Some(close) = self.angle_close(path)
                {
                    return Some(close + 1);
                }
                Some(path)
            }
        }
    }

    /// Token `i` can start a type that follows a prefix operator.
    fn starts_type(&self, i: usize) -> bool {
        match self.kind(i) {
            Some(Kind::Ident | Kind::Str | Kind::Number) => true,
            Some(Kind::Punct) => matches!(self.text(i), "[" | "{" | "(" | "?"),
            _ => false,
        }
    }

    /// The start of the postfix type that ends right before token `end`: the left operand of
    /// an unparenthesized function type (`T` in `T => U`, `Array<T>` in `Array<T> => U`,
    /// `?T`, `T[]`, `{ a: T }`, `typeof x`). Unions stop it: `A | B => C` is `A | (B => C)`.
    pub(crate) fn atom_start_before(&self, end: usize) -> Option<usize> {
        let mut j = end;
        // Postfix chain, read backwards.
        loop {
            let last = self.back(j, 1)?;
            match self.kind(last)? {
                Kind::Ident => {
                    j = last;
                    while let Some(dot) = self.back(j, 1)
                        && self.is(dot, ".")
                        && let Some(head) = self.back(dot, 1)
                        && self.is_ident(head)
                    {
                        j = head;
                    }
                    if let Some(word) = self.back(j, 1)
                        && (self.is(word, "typeof") || self.is(word, "keyof"))
                    {
                        j = word;
                    }
                    break;
                }
                Kind::Str | Kind::Number => {
                    j = last;
                    break;
                }
                Kind::Punct => match self.text(last) {
                    ">" => {
                        j = self.angle_open(last)?;
                        // The generic's name comes right before it: keep reading.
                        if self.back(j, 1).is_some_and(|p| self.is_ident(p)) {
                            continue;
                        }
                        break;
                    }
                    "]" => {
                        j = self.open_of(last)?;
                        // `T[]` and `T[K]` continue to the left; a tuple stops here.
                        if self
                            .back(j, 1)
                            .is_some_and(|p| self.is_ident(p) || self.is(p, ">") || self.is(p, "]"))
                        {
                            continue;
                        }
                        break;
                    }
                    "}" | ")" => {
                        j = self.open_of(last)?;
                        break;
                    }
                    "*" => {
                        j = last;
                        break;
                    }
                    _ => return None,
                },
                Kind::Template | Kind::Regex => return None,
            }
        }
        // Prefix maybe-types: `?T`.
        while let Some(question) = self.back(j, 1)
            && self.is(question, "?")
            && self.adjacent(question, j)
        {
            j = question;
        }
        Some(j)
    }
}

fn tokenize(src: &str) -> Vec<Tok> {
    let bytes = src.as_bytes();
    let mut toks: Vec<Tok> = Vec::new();
    let mut i = 0usize;
    if bytes.starts_with(b"#!") {
        i = skip_line(bytes, 0);
    }
    while let Some(&byte) = bytes.get(i) {
        let start = i;
        let next = bytes.get(i + 1).copied();
        match byte {
            b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c => i += 1,
            b'/' => match next {
                Some(b'/') => i = skip_line(bytes, i),
                Some(b'*') => i = skip_block_comment(bytes, i),
                _ => {
                    let regex = regex_allowed(src, toks.last())
                        .then(|| scan_regex(bytes, i))
                        .flatten();
                    if let Some(end) = regex {
                        i = end;
                        toks.push(Tok {
                            kind: Kind::Regex,
                            start,
                            end,
                        });
                    } else {
                        i += 1;
                        toks.push(punct(start, i));
                    }
                }
            },
            b'\'' | b'"' => {
                i = scan_string(bytes, i);
                toks.push(Tok {
                    kind: Kind::Str,
                    start,
                    end: i,
                });
            }
            b'`' => {
                i = scan_template(bytes, i + 1);
                toks.push(Tok {
                    kind: Kind::Template,
                    start,
                    end: i,
                });
            }
            b'0'..=b'9' => {
                i = scan_number(bytes, i);
                toks.push(Tok {
                    kind: Kind::Number,
                    start,
                    end: i,
                });
            }
            b'.' if next.is_some_and(|n| n.is_ascii_digit()) => {
                i = scan_number(bytes, i);
                toks.push(Tok {
                    kind: Kind::Number,
                    start,
                    end: i,
                });
            }
            b'.' if next == Some(b'.') && bytes.get(i + 2) == Some(&b'.') => {
                i += 3;
                toks.push(punct(start, i));
            }
            b'=' if next == Some(b'>') => {
                i += 2;
                toks.push(punct(start, i));
            }
            b'#' if next.is_some_and(is_ident_start) => {
                i = scan_ident(src, i + 1);
                toks.push(Tok {
                    kind: Kind::Ident,
                    start,
                    end: i,
                });
            }
            _ if is_ident_start(byte) => {
                i = scan_ident(src, i);
                toks.push(Tok {
                    kind: Kind::Ident,
                    start,
                    end: i,
                });
            }
            _ if byte < 0x80 => {
                i += 1;
                toks.push(punct(start, i));
            }
            _ => match src.get(i..).and_then(|rest| rest.chars().next()) {
                Some(ch) if ch.is_whitespace() => i += ch.len_utf8(),
                Some(ch) if is_ident_char(ch) => {
                    i = scan_ident(src, i);
                    toks.push(Tok {
                        kind: Kind::Ident,
                        start,
                        end: i,
                    });
                }
                Some(ch) => {
                    i += ch.len_utf8();
                    toks.push(punct(start, i));
                }
                // Not on a character boundary: cannot happen, but never loop on it.
                None => i += 1,
            },
        }
    }
    toks
}

fn punct(start: usize, end: usize) -> Tok {
    Tok {
        kind: Kind::Punct,
        start,
        end,
    }
}

fn pair_brackets(src: &str, toks: &[Tok]) -> Vec<Option<usize>> {
    let mut partner = vec![None; toks.len()];
    let mut stack: Vec<(usize, u8)> = Vec::new();
    for (i, tok) in toks.iter().enumerate() {
        if tok.kind != Kind::Punct {
            continue;
        }
        let byte = src.as_bytes().get(tok.start).copied().unwrap_or(0);
        let want = match byte {
            b'(' => Some(b')'),
            b'[' => Some(b']'),
            b'{' => Some(b'}'),
            _ => None,
        };
        if let Some(want) = want {
            stack.push((i, want));
        } else if matches!(byte, b')' | b']' | b'}')
            && let Some(&(open, expected)) = stack.last()
            && expected == byte
        {
            stack.pop();
            if let Some(slot) = partner.get_mut(open) {
                *slot = Some(i);
            }
            if let Some(slot) = partner.get_mut(i) {
                *slot = Some(open);
            }
        }
    }
    partner
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$'
}

fn is_ident_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_' || ch == '$' || ch == '\u{200c}' || ch == '\u{200d}'
}

fn scan_ident(src: &str, from: usize) -> usize {
    let rest = src.get(from..).unwrap_or("");
    let len = rest
        .char_indices()
        .find(|&(_, ch)| !is_ident_char(ch))
        .map_or(rest.len(), |(at, _)| at);
    from + len.max(1)
}

fn skip_line(bytes: &[u8], from: usize) -> usize {
    bytes
        .get(from..)
        .and_then(|rest| rest.iter().position(|&b| b == b'\n' || b == b'\r'))
        .map_or(bytes.len(), |at| from + at)
}

fn skip_block_comment(bytes: &[u8], from: usize) -> usize {
    bytes
        .get(from + 2..)
        .and_then(|rest| rest.windows(2).position(|pair| pair == b"*/"))
        .map_or(bytes.len(), |at| from + 2 + at + 2)
}

fn scan_string(bytes: &[u8], from: usize) -> usize {
    let quote = bytes.get(from).copied().unwrap_or(b'"');
    let mut i = from + 1;
    loop {
        match bytes.get(i) {
            None => return bytes.len(),
            Some(b'\\') => i += 2,
            Some(&byte) if byte == quote => return i + 1,
            // An unterminated string stops at the end of its line.
            Some(b'\n' | b'\r') => return i,
            Some(_) => i += 1,
        }
    }
}

/// `from` is right after the opening backtick.
fn scan_template(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    loop {
        match bytes.get(i) {
            None => return bytes.len(),
            Some(b'\\') => i += 2,
            Some(b'`') => return i + 1,
            Some(b'$') if bytes.get(i + 1) == Some(&b'{') => i = skip_template_expr(bytes, i + 2),
            Some(_) => i += 1,
        }
    }
}

/// `from` is right after `${`; returns the index after the matching `}`.
fn skip_template_expr(bytes: &[u8], from: usize) -> usize {
    let mut depth = 1usize;
    let mut i = from;
    loop {
        match bytes.get(i) {
            None => return bytes.len(),
            Some(b'{') => {
                depth += 1;
                i += 1;
            }
            Some(b'}') => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return i;
                }
            }
            Some(b'\'' | b'"') => i = scan_string(bytes, i),
            Some(b'`') => i = scan_template(bytes, i + 1),
            Some(b'/') if bytes.get(i + 1) == Some(&b'/') => i = skip_line(bytes, i),
            Some(b'/') if bytes.get(i + 1) == Some(&b'*') => i = skip_block_comment(bytes, i),
            Some(_) => i += 1,
        }
    }
}

fn scan_number(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while let Some(&byte) = bytes.get(i) {
        let exponent_sign = (byte == b'+' || byte == b'-')
            && i > from
            && matches!(bytes.get(i - 1), Some(b'e' | b'E'))
            && !matches!(bytes.get(from + 1), Some(b'x' | b'X'));
        if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.' || exponent_sign {
            i += 1;
        } else {
            break;
        }
    }
    i.max(from + 1)
}

/// The end of the regex literal that starts at `from`, if it is one.
fn scan_regex(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i = from + 1;
    let mut in_class = false;
    loop {
        match bytes.get(i)? {
            b'\n' | b'\r' => return None,
            b'\\' => i += 2,
            b'[' => {
                in_class = true;
                i += 1;
            }
            b']' => {
                in_class = false;
                i += 1;
            }
            b'/' if !in_class => {
                i += 1;
                while bytes.get(i).is_some_and(u8::is_ascii_alphabetic) {
                    i += 1;
                }
                return Some(i);
            }
            _ => i += 1,
        }
    }
}

/// Whether a `/` after `prev` starts a regex (rather than being a division).
fn regex_allowed(src: &str, prev: Option<&Tok>) -> bool {
    let Some(prev) = prev else {
        return true;
    };
    let text = src.get(prev.start..prev.end).unwrap_or("");
    match prev.kind {
        Kind::Number | Kind::Str | Kind::Template | Kind::Regex => false,
        Kind::Ident => matches!(
            text,
            "return"
                | "typeof"
                | "instanceof"
                | "in"
                | "of"
                | "new"
                | "delete"
                | "void"
                | "throw"
                | "case"
                | "do"
                | "else"
                | "yield"
                | "await"
        ),
        Kind::Punct => !matches!(text, ")" | "]" | "}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(src: &str) -> Vec<&str> {
        let toks = Toks::new(src);
        (0..toks.len()).map(|i| toks.text(i)).collect()
    }

    /// Token index of the first token with this text.
    fn find(toks: &Toks, text: &str) -> usize {
        (0..toks.len())
            .find(|&i| toks.is(i, text))
            .unwrap_or(usize::MAX)
    }

    #[test]
    fn punctuation_is_one_token_per_character_except_arrow_and_spread() {
        assert_eq!(
            texts("a: Array<Array<T>> => {| ...B |}"),
            [
                "a", ":", "Array", "<", "Array", "<", "T", ">", ">", "=>", "{", "|", "...", "B",
                "|", "}"
            ]
        );
        // `>=` is two tokens, so it can never be mistaken for `=>`.
        assert_eq!(texts("a >= b"), ["a", ">", "=", "b"]);
    }

    #[test]
    fn comments_strings_templates_and_regexes_are_single_tokens() {
        let src =
            "x = 'a\\'b' + \"c\" + `t${ {a: `n`} }u` // trailing ) (\n/* ( */ y = /[)/]+/g.test(z)";
        assert_eq!(
            texts(src),
            [
                "x",
                "=",
                "'a\\'b'",
                "+",
                "\"c\"",
                "+",
                "`t${ {a: `n`} }u`",
                "y",
                "=",
                "/[)/]+/g",
                ".",
                "test",
                "(",
                "z",
                ")"
            ]
        );
    }

    #[test]
    fn division_is_not_a_regex() {
        assert_eq!(texts("a / b / c"), ["a", "/", "b", "/", "c"]);
        assert_eq!(texts("(a) / 2 / 3"), ["(", "a", ")", "/", "2", "/", "3"]);
        assert_eq!(texts("x = /re/"), ["x", "=", "/re/"]);
    }

    #[test]
    fn unterminated_input_never_panics_or_loops() {
        for src in [
            "'abc",
            "\"abc\n",
            "`abc",
            "`a${",
            "/* x",
            "// x",
            "/re",
            "a = /[",
            "0x",
            "1e+",
            "\\",
            "é",
            "#!/bin/sh",
            "#",
            "a\u{2028}b",
            "\u{feff}x",
        ] {
            let _ = Toks::new(src);
        }
    }

    #[test]
    fn non_ascii_text_keeps_offsets_on_char_boundaries() {
        let src = "const ñandú: ?Тип = 'é'; // ü";
        let toks = Toks::new(src);
        assert_eq!(toks.text(1), "ñandú");
        assert_eq!(toks.text(4), "Тип");
        for i in 0..toks.len() {
            assert!(src.is_char_boundary(toks.start(i).unwrap_or(0)));
            assert!(src.is_char_boundary(toks.end(i).unwrap_or(0)));
        }
    }

    #[test]
    fn brackets_pair_up_and_ignore_those_inside_strings() {
        let toks = Toks::new("f(a, [b, '('], {c: 1})");
        let open = find(&toks, "(");
        assert_eq!(toks.close_of(open), Some(toks.len() - 1));
        assert_eq!(toks.open_of(toks.len() - 1), Some(open));
        let unbalanced = Toks::new("f(a, [b)");
        assert_eq!(unbalanced.close_of(1), None);
    }

    #[test]
    fn at_offset_finds_the_token_at_or_after_the_offset() {
        let toks = Toks::new("ab  cd");
        assert_eq!(toks.at_offset(0), 0);
        assert_eq!(toks.at_offset(1), 0);
        // Offset 2 is the end of `ab`: the error is "after" it, at the next token.
        assert_eq!(toks.at_offset(2), 1);
        assert_eq!(toks.at_offset(4), 1);
        assert_eq!(toks.at_offset(6), 2);
    }

    #[test]
    fn angle_brackets_match_across_nesting_and_refuse_operators() {
        let toks = Toks::new("Array<Map<K, {a: Array<T>}>> x");
        let open = find(&toks, "<");
        let close = toks.angle_close(open).unwrap_or(0);
        // The outermost `<` closes at the last `>`, right before `x`.
        assert_eq!(toks.text(close), ">");
        assert_eq!(toks.text(close + 1), "x");
        assert_eq!(toks.angle_open(close), Some(open));
        // `a < b; c > d` is comparison, not generics.
        let cmp = Toks::new("a < b; c > d");
        assert_eq!(cmp.angle_close(1), None);
    }

    fn type_text(src: &str) -> String {
        // The type starts after the first `=`.
        let toks = Toks::new(src);
        let from = find(&toks, "=") + 1;
        match toks.type_end(from) {
            Some(end) => {
                let a = toks.start(from).unwrap_or(0);
                let b = toks.end(end - 1).unwrap_or(0);
                src.get(a..b).unwrap_or("").to_owned()
            }
            None => "<none>".to_owned(),
        }
    }

    #[test]
    fn type_end_finds_where_flow_types_stop() {
        for ty in [
            "string",
            "?string",
            "Array<?string>",
            "A | B | C",
            "| A | B",
            "A & B",
            "{ a: number, ... }",
            "{| a: number |}",
            "{ [string]: number }",
            "[A, B]",
            "(A, B) => C",
            "(x: A, y?: B, ...rest: C[]) => D",
            "string => void",
            "A => B => C",
            "Array<string> => void",
            "typeof x.y",
            "keyof T",
            "T[]",
            "T[K]",
            "?(A | B)",
            "<T>(x: T) => T",
            "interface { m(): void }",
            "T extends U ? X : Y",
            "Promise<*>",
            "Foo<>",
            "'a' | 'b'",
            "-1 | 0 | 1",
            "$ReadOnly<{| a: A |}>",
            "A.B.C<D>",
            "x is string",
        ] {
            assert_eq!(type_text(&format!("type X = {ty};")), ty, "{ty}");
        }
    }

    #[test]
    fn type_end_stops_at_what_cannot_continue_a_type() {
        // A newline then an identifier ends a type (no semicolon needed).
        assert_eq!(type_text("type A = B\nconst c = 1"), "B");
        // So does a closing bracket, a comma, an equals sign or a brace.
        assert_eq!(type_text("f = (x: A => B) => 1"), "(x: A => B) => 1");
        assert_eq!(type_text("type A<T = B, C> = D"), "B");
        // `[` on the next line is a new statement, not an indexed access.
        assert_eq!(type_text("type A = B\n[x] = 1"), "B");
    }

    #[test]
    fn type_end_gives_up_on_things_that_are_not_types() {
        assert_eq!(type_text("x = + y"), "<none>");
        assert_eq!(type_text("x = ("), "<none>");
        let deep = format!("x = {}A{}", "(".repeat(300), ")".repeat(300));
        assert_eq!(type_text(&deep), deep.get(4..).unwrap_or(""));
    }

    #[test]
    fn hostile_nesting_cannot_overflow_the_type_scanner() {
        // Chains the scanner follows recursively stop at its depth limit...
        let arrows = format!("type A = {}x;", "a => ".repeat(20_000));
        assert_eq!(type_text(&arrows), "<none>");
        let indexes = format!("type A = A{}{};", "[A".repeat(20_000), "]".repeat(20_000));
        assert_eq!(type_text(&indexes), "<none>");
        let unions = format!("type A = {};", "A | ".repeat(50_000) + "B");
        assert!(type_text(&unions).ends_with("| B"));
        // ...and bracket groups are skipped without recursion at any depth.
        // (Angle scans give up after 4096 tokens and read the name alone: a shorter extent, no panic.)
        let generics = format!(
            "type A = {}x{};",
            "Array<".repeat(20_000),
            ">".repeat(20_000)
        );
        assert!(type_text(&generics).starts_with("Array"));
        let braces = format!("type A = {}{};", "{a: ".repeat(20_000), "}".repeat(20_000));
        assert_eq!(type_text(&braces).len(), braces.len() - "type A = ;".len());
    }

    #[test]
    fn atom_start_before_finds_the_left_operand() {
        let start = |src: &str| {
            let toks = Toks::new(src);
            let arrow = find(&toks, "=>");
            toks.atom_start_before(arrow)
                .and_then(|i| toks.start(i))
                .and_then(|at| src.get(at..))
                .map(|rest| rest.split(" =>").next().unwrap_or("").to_owned())
        };
        let cases = [
            ("x: Error => void", "Error"),
            ("x: ?Error => void", "?Error"),
            ("x: Array<string> => void", "Array<string>"),
            ("x: Map<K, Array<V>> => void", "Map<K, Array<V>>"),
            ("x: A.B.C => void", "A.B.C"),
            ("x: T[] => void", "T[]"),
            ("x: {a: number} => void", "{a: number}"),
            ("x: [A, B] => void", "[A, B]"),
            ("x: typeof y => void", "typeof y"),
            ("x: A | B => void", "B"),
            ("x: A & B => void", "B"),
            ("x: 'lit' => void", "'lit'"),
        ];
        for (src, expected) in cases {
            assert_eq!(start(src).as_deref(), Some(expected), "{src}");
        }
    }
}
