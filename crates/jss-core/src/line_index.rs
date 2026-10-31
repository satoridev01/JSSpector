//! Byte offset → (line, column) conversion for reports.
//!
//! oxc has no line/column API, and SARIF wants columns in UTF-16 code units
//! (`columnKind: utf16CodeUnits`), so JSSpector keeps its own index. It lives in the core (not
//! the frontend) because reports, which are built in the core, need it too.

/// A 1-based line and a 1-based column counted in UTF-16 code units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LineCol {
    pub line: u32,
    pub column: u32,
}

/// A non-ASCII character: where it starts and how many UTF-8 bytes it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WideChar {
    start: u32,
    utf8_len: u32,
}

impl WideChar {
    /// UTF-8 bytes minus UTF-16 code units: 2-byte and 3-byte characters are one code unit,
    /// 4-byte (astral) characters are a surrogate pair.
    fn extra_bytes(self) -> u32 {
        let utf16_len = if self.utf8_len == 4 { 2 } else { 1 };
        self.utf8_len.saturating_sub(utf16_len)
    }
}

/// Precomputed line starts and non-ASCII characters of one source text. Owns its data, so it can
/// be kept after the source is dropped.
///
/// `\n`, `\r\n` and a lone `\r` end lines. Offsets are `u32` like oxc spans; offsets past the end
/// clamp to the end, and offsets inside a multi-byte character clamp to its start. Lookups never
/// panic and cost O(log n).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineIndex {
    /// Byte offset at which each line starts; the first entry is always 0.
    line_starts: Vec<u32>,
    /// Every non-ASCII character, in source order.
    wide_chars: Vec<WideChar>,
    /// `extra_prefix[i]` is the sum of [`WideChar::extra_bytes`] over `wide_chars[..i]`.
    extra_prefix: Vec<u32>,
    /// Length of the indexed text in bytes.
    len: u32,
}

impl LineIndex {
    /// Indexes `text`. Text beyond `u32::MAX` bytes cannot be addressed by a `u32` offset and is
    /// not indexed.
    pub fn new(text: &str) -> Self {
        let mut line_starts = vec![0];
        let mut wide_chars = Vec::new();
        let mut chars = text.char_indices().peekable();
        while let Some((offset, ch)) = chars.next() {
            let Ok(start) = u32::try_from(offset) else {
                break;
            };
            match ch {
                '\n' => line_starts.push(start.saturating_add(1)),
                '\r' => {
                    // In `\r\n`, the line ends after the `\n`.
                    if chars.peek().map(|&(_, next)| next) != Some('\n') {
                        line_starts.push(start.saturating_add(1));
                    }
                }
                _ if !ch.is_ascii() => wide_chars.push(WideChar {
                    start,
                    utf8_len: u32::try_from(ch.len_utf8()).unwrap_or(1),
                }),
                _ => {}
            }
        }
        let mut extra_prefix = Vec::with_capacity(wide_chars.len() + 1);
        let mut total = 0u32;
        extra_prefix.push(total);
        for wide in &wide_chars {
            total = total.saturating_add(wide.extra_bytes());
            extra_prefix.push(total);
        }
        Self {
            line_starts,
            wide_chars,
            extra_prefix,
            len: u32::try_from(text.len()).unwrap_or(u32::MAX),
        }
    }

    /// Number of lines. Text ending in a line terminator has a final empty line.
    pub fn line_count(&self) -> usize {
        self.line_starts.len()
    }

    /// Length of the indexed text in bytes.
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Whether the indexed text is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The 1-based line and UTF-16 column of a byte offset.
    pub fn line_col(&self, offset: u32) -> LineCol {
        let offset = self.clamp(offset);
        let line = self
            .line_starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        let line_start = self.line_starts.get(line).copied().unwrap_or(0);
        let first_wide = self
            .wide_chars
            .partition_point(|wide| wide.start < line_start);
        let end_wide = self.wide_chars.partition_point(|wide| wide.start < offset);
        let extra = self
            .prefix(end_wide)
            .saturating_sub(self.prefix(first_wide));
        let column = offset.saturating_sub(line_start).saturating_sub(extra);
        LineCol {
            line: u32::try_from(line).unwrap_or(u32::MAX).saturating_add(1),
            column: column.saturating_add(1),
        }
    }

    /// Clamps to the text and to the start of the character containing `offset`.
    fn clamp(&self, offset: u32) -> u32 {
        let offset = offset.min(self.len);
        let before = self.wide_chars.partition_point(|wide| wide.start < offset);
        match before
            .checked_sub(1)
            .and_then(|index| self.wide_chars.get(index))
        {
            Some(wide) if offset < wide.start.saturating_add(wide.utf8_len) => wide.start,
            _ => offset,
        }
    }

    fn prefix(&self, index: usize) -> u32 {
        self.extra_prefix.get(index).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lc(index: &LineIndex, offset: u32) -> (u32, u32) {
        let pos = index.line_col(offset);
        (pos.line, pos.column)
    }

    /// Reference implementation: walk the text char by char.
    fn naive(text: &str, offset: usize) -> (u32, u32) {
        let (mut line, mut col) = (1u32, 1u32);
        let mut chars = text.char_indices().peekable();
        while let Some((i, ch)) = chars.next() {
            if i >= offset {
                break;
            }
            match ch {
                '\n' => (line, col) = (line + 1, 1),
                '\r' if chars.peek().map(|&(_, c)| c) == Some('\n') => col += 1,
                '\r' => (line, col) = (line + 1, 1),
                _ => col += u32::try_from(ch.len_utf16()).unwrap(),
            }
        }
        (line, col)
    }

    #[test]
    fn empty_text() {
        let index = LineIndex::new("");
        assert!(index.is_empty());
        assert_eq!(index.line_count(), 1);
        assert_eq!(lc(&index, 0), (1, 1));
        assert_eq!(lc(&index, 10), (1, 1));
    }

    #[test]
    fn ascii_lines_with_lf() {
        let index = LineIndex::new("ab\ncd\n");
        assert_eq!(index.line_count(), 3);
        assert_eq!(lc(&index, 0), (1, 1));
        assert_eq!(lc(&index, 1), (1, 2));
        assert_eq!(lc(&index, 2), (1, 3)); // the `\n` itself
        assert_eq!(lc(&index, 3), (2, 1));
        assert_eq!(lc(&index, 5), (2, 3));
        assert_eq!(lc(&index, 6), (3, 1)); // end of text, after the final newline
    }

    #[test]
    fn crlf_is_one_line_break() {
        let index = LineIndex::new("ab\r\ncd");
        assert_eq!(index.line_count(), 2);
        assert_eq!(lc(&index, 2), (1, 3)); // `\r`
        assert_eq!(lc(&index, 3), (1, 4)); // `\n` of the pair stays on line 1
        assert_eq!(lc(&index, 4), (2, 1));
        assert_eq!(lc(&index, 5), (2, 2));
    }

    #[test]
    fn lone_cr_is_a_line_break() {
        let index = LineIndex::new("ab\rcd\r\rx");
        assert_eq!(index.line_count(), 4);
        assert_eq!(lc(&index, 3), (2, 1));
        assert_eq!(lc(&index, 6), (3, 1));
        assert_eq!(lc(&index, 7), (4, 1));
    }

    #[test]
    fn columns_count_utf16_code_units() {
        // é: 2 bytes, 1 unit. €: 3 bytes, 1 unit. 😀: 4 bytes, 2 units (surrogate pair).
        let text = "é€😀x";
        let index = LineIndex::new(text);
        assert_eq!(lc(&index, 0), (1, 1)); // é
        assert_eq!(lc(&index, 2), (1, 2)); // €
        assert_eq!(lc(&index, 5), (1, 3)); // 😀
        assert_eq!(lc(&index, 9), (1, 5)); // x comes after the surrogate pair
        assert_eq!(lc(&index, 10), (1, 6)); // end
    }

    #[test]
    fn wide_chars_on_earlier_lines_do_not_shift_columns() {
        let text = "😀😀\nab😀c\r\n€";
        let index = LineIndex::new(text);
        assert_eq!(lc(&index, 9), (2, 1)); // a
        assert_eq!(lc(&index, 11), (2, 3)); // 😀
        assert_eq!(lc(&index, 15), (2, 5)); // c
        assert_eq!(lc(&index, 18), (3, 1)); // €
    }

    #[test]
    fn offsets_inside_a_code_point_clamp_to_its_start() {
        let text = "a😀b";
        let index = LineIndex::new(text);
        for inside in 2..=4 {
            assert_eq!(lc(&index, inside), (1, 2), "offset {inside}");
        }
        assert_eq!(lc(&index, 5), (1, 4)); // b
        let index = LineIndex::new("x\n€");
        assert_eq!(lc(&index, 3), (2, 1));
        assert_eq!(lc(&index, 4), (2, 1));
    }

    #[test]
    fn offsets_past_the_end_clamp_to_the_end() {
        let index = LineIndex::new("ab\ncd😀");
        assert_eq!(index.len(), 9);
        assert_eq!(lc(&index, 9), (2, 5));
        assert_eq!(lc(&index, 100), (2, 5));
        assert_eq!(lc(&index, u32::MAX), (2, 5));
    }

    #[test]
    fn matches_a_naive_walk_at_every_offset() {
        let text = "const s = 'é€😀';\r\n// 漢字 🎉\rlet x = `${a}`;\n\n\u{2028}y😀\r\n";
        let index = LineIndex::new(text);
        for offset in 0..=text.len() + 2 {
            let mut boundary = offset.min(text.len());
            while !text.is_char_boundary(boundary) {
                boundary -= 1;
            }
            assert_eq!(
                lc(&index, u32::try_from(offset).unwrap()),
                naive(text, boundary),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn unicode_line_separators_are_not_line_breaks() {
        // Only \n, \r\n and \r end lines (SARIF and editors agree; U+2028 is one column).
        let index = LineIndex::new("a\u{2028}b");
        assert_eq!(index.line_count(), 1);
        assert_eq!(lc(&index, 4), (1, 3));
    }
}
