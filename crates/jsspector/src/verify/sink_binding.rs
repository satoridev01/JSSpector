//! Runtime binding between a static finding and the exact sink expression it names.
//!
//! Dynamic effects alone are not enough: a route can contain two file reads, outbound requests or
//! database calls, and a payload can accidentally exercise the other one.  The verifier therefore
//! wraps the source expression at the finding's file/line/column with a controller-owned marker and
//! requires that marker during the same driven request as the exploit signal.

use jss_core::Finding;

/// Shared by the preload and the controller.  The file lives only in the disposable verifier
/// runtime (`/tmp` is a container tmpfs, and local verification owns it under its fixture lock).
pub const HIT_FILE: &str = "/tmp/jsspector-sink-hits";

/// A deliberately tiny preload.  Unlike the launch compatibility shim, this changes no module
/// resolution and patches no application API; it only exposes a non-enumerable synchronous marker
/// used by the expression inserted below.
pub const PRELOAD_JS: &str = r#"
'use strict';
const fs = require('fs');
try {
  Object.defineProperty(globalThis, '__jsspectorRecordSink', {
    configurable: true,
    enumerable: false,
    value: function (token) {
      if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{8,160}$/.test(token)) return;
      try { fs.appendFileSync('/tmp/jsspector-sink-hits', token + '\n'); } catch (e) {}
    },
  });
} catch (e) {}
"#;

#[derive(Debug, Clone)]
pub struct Binding {
    pub file: String,
    pub api: String,
    pub arg: String,
    pub line: u32,
    pub col: u32,
    pub token: String,
    callback_url: String,
}

impl Binding {
    pub fn for_finding(finding: &Finding, token: String, callback_url: String) -> Self {
        Self {
            file: finding
                .sink
                .file
                .clone()
                .unwrap_or_else(|| finding.file.clone()),
            api: finding.sink.api.clone(),
            arg: finding.sink.arg.clone(),
            line: finding.sink.line,
            col: finding.sink.col,
            token,
            callback_url,
        }
    }

    /// Instruments this binding's exact expression in `source`.  A fix candidate is passed through
    /// this same function before it is relaunched; inability to bind the changed source is an
    /// inconclusive fix proof, never evidence that the exploit disappeared.
    pub fn instrument_original(&mut self, source: &str) -> Result<String, String> {
        let (start, end) = self.locate(source)?;
        if let Some((line, col)) = offset_line_col(source, start) {
            self.line = line;
            self.col = col;
        }
        instrument_range(
            source,
            start,
            end,
            &marker_expression(&self.token, &self.callback_url),
        )
        .ok_or_else(|| self.failure("the selected sink could not be instrumented"))
    }

    pub fn instrument(&self, source: &str) -> Result<String, String> {
        if source.contains("__jsspectorRecordSink") && source.contains(&self.token) {
            return Ok(source.to_owned());
        }
        let marker = marker_expression(&self.token, &self.callback_url);
        let (start, end) = self.locate(source)?;
        instrument_range(source, start, end, &marker)
            .ok_or_else(|| self.failure("the selected sink could not be instrumented"))
    }

    /// Whether the exact statically selected sink can still be located after a source change.
    /// Fix proof uses this only after a strong functional control authorizes replacing the sink;
    /// an ambiguous or merely shifted sink therefore remains instrumented or fails closed.
    pub fn is_present(&self, source: &str) -> bool {
        self.locate(source).is_ok()
    }

    fn locate(&self, source: &str) -> Result<(usize, usize), String> {
        if let Some(exact) = line_col_offset(source, self.line, self.col)
            && let Some(range) = expression_range(source, exact, &self.api)
        {
            return Ok(range);
        }

        // A candidate can insert a few lines before the sink. Search the local neighborhood first,
        // but never choose the first textual API match: two calls to the same API are common. The
        // scanner's recorded argument disambiguates them. If it cannot, binding fails closed.
        let leaf = api_leaf(&self.api);
        let (from, to) = line_window(source, self.line, 16);
        if !leaf.is_empty() {
            let local = expression_candidates(source, &self.api, &leaf, from, to);
            if let Some(range) = select_candidate(source, &local, &self.arg) {
                return Ok(range);
            }

            // Generated/cross-file summaries can retain a stale line after a build rewrites the
            // module. A whole-file fallback is safe only when the argument identifies one call or
            // there is exactly one compatible expression in the file.
            let all = expression_candidates(source, &self.api, &leaf, 0, source.len());
            if let Some(range) = select_candidate(source, &all, &self.arg) {
                return Ok(range);
            }
        }
        Err(self.failure("the exact sink expression could not be located after the source changed"))
    }

    pub fn evidence(&self) -> String {
        format!(
            "the same request executed the planned sink `{}:{}:{}` (`{}`), observed by a controller-injected runtime marker",
            self.file, self.line, self.col, self.api
        )
    }

    fn failure(&self, why: &str) -> String {
        format!(
            "exact runtime binding for `{}:{}:{}` (`{}`) failed: {why}",
            self.file, self.line, self.col, self.api
        )
    }
}

fn marker_expression(token: &str, callback_url: &str) -> String {
    let token = js(token);
    let callback = js(callback_url);
    // `Function('return this')()` is valid in both old CommonJS and strict TypeScript source and
    // avoids introducing DOM globals into a server project's type-check.  A browser CSP can reject
    // it; that is caught and makes binding absent (hence inconclusive), not falsely verified.
    format!(
        "(function(){{try{{var g=Function('return this')();var f=g['__jsspectorRecordSink'];if(typeof f==='function'){{f({token})}}else{{var I=g['Image'];if(typeof I==='function'){{var i=new I();i.src={callback}}}else{{var q=g['fetch'];if(typeof q==='function'){{var p=q({callback});if(p&&typeof p.catch==='function')p.catch(function(){{}})}}}}}}}}catch(e){{}}}})()"
    )
}

fn js(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

/// Converts the scanner's 1-based line and UTF-16 column back to a UTF-8 byte offset.
fn line_col_offset(source: &str, line: u32, col: u32) -> Option<usize> {
    let line = usize::try_from(line.checked_sub(1)?).ok()?;
    let column = col.checked_sub(1)?;
    let start = source
        .split_inclusive('\n')
        .take(line)
        .map(str::len)
        .sum::<usize>();
    let text = source
        .get(start..)?
        .split_once('\n')
        .map_or_else(|| source.get(start..).unwrap_or_default(), |(head, _)| head);
    let mut units = 0u32;
    for (byte, ch) in text.char_indices() {
        if units == column {
            return Some(start + byte);
        }
        units = units.saturating_add(ch.len_utf16() as u32);
        if units > column {
            return None;
        }
    }
    (units == column).then_some(start + text.len())
}

fn offset_line_col(source: &str, offset: usize) -> Option<(u32, u32)> {
    let before = source.get(..offset)?;
    let line_start = before.rfind('\n').map_or(0, |at| at + 1);
    let line = u32::try_from(before.bytes().filter(|byte| *byte == b'\n').count() + 1).ok()?;
    let col = u32::try_from(source.get(line_start..offset)?.encode_utf16().count() + 1).ok()?;
    Some((line, col))
}

fn line_window(source: &str, line: u32, radius: usize) -> (usize, usize) {
    let starts: Vec<usize> = std::iter::once(0)
        .chain(source.match_indices('\n').map(|(at, _)| at + 1))
        .collect();
    let center = usize::try_from(line.saturating_sub(1)).unwrap_or(0);
    let from_line = center
        .saturating_sub(radius)
        .min(starts.len().saturating_sub(1));
    let to_line = center.saturating_add(radius + 1).min(starts.len());
    (
        starts.get(from_line).copied().unwrap_or(0),
        starts.get(to_line).copied().unwrap_or(source.len()),
    )
}

fn api_leaf(api: &str) -> String {
    let trimmed = api.trim().trim_end_matches('=').trim();
    trimmed
        .rsplit('.')
        .next()
        .unwrap_or(trimmed)
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '$')
        .to_owned()
}

fn expression_range(source: &str, start: usize, api: &str) -> Option<(usize, usize)> {
    if api.trim_end().ends_with('=') {
        let equals = find_assignment(source, start)?;
        if !api_matches_at(source, start, equals, api) {
            return None;
        }
        let end = expression_end(source, equals + 1)?;
        return Some((start, end));
    }
    let open = find_call_open(source, start)?;
    if !api_matches_at(source, start, open, api) {
        return None;
    }
    let close = matching_delimiter(source, open, b'(', b')')?;
    Some((start, close + 1))
}

fn instrument_range(source: &str, start: usize, end: usize, marker: &str) -> Option<String> {
    wrap(source, start, end, marker)
}

fn expression_candidates(
    source: &str,
    api: &str,
    leaf: &str,
    from: usize,
    to: usize,
) -> Vec<(usize, usize)> {
    let mut candidates = Vec::new();
    let mut cursor = from.min(source.len());
    let to = to.min(source.len());
    while cursor < to {
        let Some(found) = source[cursor..to].find(leaf) else {
            break;
        };
        let leaf_at = cursor + found;
        let at = member_expression_start(source, leaf_at);
        if let Some(range) = expression_range(source, at, api)
            && !candidates.contains(&range)
        {
            candidates.push(range);
        }
        cursor = leaf_at.saturating_add(leaf.len().max(1));
    }
    candidates
}

fn member_expression_start(source: &str, leaf_at: usize) -> usize {
    let bytes = source.as_bytes();
    let mut at = leaf_at.min(bytes.len());
    while at > 0 {
        let Some(&byte) = bytes.get(at - 1) else {
            break;
        };
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'.' | b'?') {
            at -= 1;
        } else {
            break;
        }
    }
    at
}

fn select_candidate(
    source: &str,
    candidates: &[(usize, usize)],
    recorded_arg: &str,
) -> Option<(usize, usize)> {
    let needle = normalized_argument(recorded_arg);
    if !needle.is_empty() {
        let matching: Vec<(usize, usize)> = candidates
            .iter()
            .copied()
            .filter(|(start, end)| {
                source
                    .get(*start..*end)
                    .is_some_and(|expression| normalize(expression).contains(&needle))
            })
            .collect();
        if matching.len() == 1 {
            return matching.first().copied();
        }
        if matching.len() > 1 {
            return None;
        }
    }
    match candidates {
        [candidate] => Some(*candidate),
        _ => None,
    }
}

fn normalized_argument(argument: &str) -> String {
    let argument = argument
        .split_once('…')
        .map_or(argument, |(prefix, _)| prefix)
        .split_once("...")
        .map_or(argument, |(prefix, _)| prefix);
    normalize(argument)
}

fn normalize(value: &str) -> String {
    value.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn api_matches_at(source: &str, start: usize, end: usize, api: &str) -> bool {
    let leaf = api_leaf(api);
    leaf.is_empty()
        || source
            .get(start..end)
            .is_some_and(|written| written.contains(&leaf))
}

fn wrap(source: &str, start: usize, end: usize, marker: &str) -> Option<String> {
    if start >= end
        || end > source.len()
        || !source.is_char_boundary(start)
        || !source.is_char_boundary(end)
    {
        return None;
    }
    let mut out = String::with_capacity(source.len() + marker.len() + 4);
    out.push_str(source.get(..start)?);
    // Wrapping a statement-leading call makes its first byte `(`. In semicolon-free source that can
    // be parsed as a continuation of the previous line (`value\n((marker(), sink()))`), changing the
    // program before the marker ever runs. Terminate only that ASI-sensitive shape; a call used as a
    // multiline array element/argument follows `[`, `(`, `,`, etc. and must remain an expression.
    if needs_asi_guard(source, start) {
        out.push(';');
    }
    out.push('(');
    out.push_str(marker);
    out.push(',');
    out.push_str(source.get(start..end)?);
    out.push(')');
    out.push_str(source.get(end..)?);
    Some(out)
}

fn needs_asi_guard(source: &str, start: usize) -> bool {
    let line_start = source[..start].rfind('\n').map_or(0, |at| at + 1);
    if !source[line_start..start].trim().is_empty() {
        return false;
    }
    source[..line_start]
        .chars()
        .rev()
        .find(|ch| !ch.is_whitespace())
        .is_some_and(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(ch, '_' | '$' | ')' | ']' | '}' | '\'' | '"' | '`')
        })
}

fn find_call_open(source: &str, start: usize) -> Option<usize> {
    let limit = start.saturating_add(768).min(source.len());
    let bytes = source.as_bytes();
    let mut i = start;
    while i < limit {
        match *bytes.get(i)? {
            b'(' => return Some(i),
            b';' | b'{' | b'}' | b'\n' => return None,
            b'\'' | b'"' | b'`' => i = skip_quoted(bytes, i)?,
            b'/' if bytes.get(i + 1) == Some(&b'/') => return None,
            b'/' if bytes.get(i + 1) == Some(&b'*') => i = skip_block_comment(bytes, i)?,
            _ => i += 1,
        }
    }
    None
}

fn find_assignment(source: &str, start: usize) -> Option<usize> {
    let limit = start.saturating_add(1024).min(source.len());
    let bytes = source.as_bytes();
    let mut i = start;
    while i < limit {
        match *bytes.get(i)? {
            b'=' if bytes.get(i + 1) != Some(&b'=') && bytes.get(i + 1) != Some(&b'>') => {
                return Some(i);
            }
            b';' | b'\n' => return None,
            b'\'' | b'"' | b'`' => i = skip_quoted(bytes, i)?,
            b'/' if bytes.get(i + 1) == Some(&b'/') => return None,
            b'/' if bytes.get(i + 1) == Some(&b'*') => i = skip_block_comment(bytes, i)?,
            _ => i += 1,
        }
    }
    None
}

fn matching_delimiter(source: &str, open: usize, left: u8, right: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match *bytes.get(i)? {
            b if b == left => {
                depth += 1;
                i += 1;
            }
            b if b == right => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
                i += 1;
            }
            b'\'' | b'"' | b'`' => i = skip_quoted(bytes, i)?,
            b'/' if bytes.get(i + 1) == Some(&b'/') => i = skip_line_comment(bytes, i),
            b'/' if bytes.get(i + 1) == Some(&b'*') => i = skip_block_comment(bytes, i)?,
            _ => i += 1,
        }
    }
    None
}

fn expression_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut i = start;
    let mut round = 0usize;
    let mut square = 0usize;
    let mut curly = 0usize;
    while i < bytes.len() {
        match *bytes.get(i)? {
            b'(' => {
                round += 1;
                i += 1;
            }
            b'[' => {
                square += 1;
                i += 1;
            }
            b'{' => {
                curly += 1;
                i += 1;
            }
            b')' if round == 0 && square == 0 && curly == 0 => {
                return Some(trim_end(source, start, i));
            }
            b']' if round == 0 && square == 0 && curly == 0 => {
                return Some(trim_end(source, start, i));
            }
            b'}' if round == 0 && square == 0 && curly == 0 => {
                return Some(trim_end(source, start, i));
            }
            b')' => {
                round = round.checked_sub(1)?;
                i += 1;
            }
            b']' => {
                square = square.checked_sub(1)?;
                i += 1;
            }
            b'}' => {
                curly = curly.checked_sub(1)?;
                i += 1;
            }
            b';' | b',' if round == 0 && square == 0 && curly == 0 => {
                return Some(trim_end(source, start, i));
            }
            b'\n' if round == 0 && square == 0 && curly == 0 => {
                return Some(trim_end(source, start, i));
            }
            b'\'' | b'"' | b'`' => i = skip_quoted(bytes, i)?,
            b'/' if bytes.get(i + 1) == Some(&b'/') => return Some(trim_end(source, start, i)),
            b'/' if bytes.get(i + 1) == Some(&b'*') => i = skip_block_comment(bytes, i)?,
            _ => i += 1,
        }
    }
    Some(trim_end(source, start, i))
}

fn trim_end(source: &str, start: usize, mut end: usize) -> usize {
    while end > start
        && source
            .as_bytes()
            .get(end - 1)
            .is_some_and(u8::is_ascii_whitespace)
    {
        end -= 1;
    }
    end
}

fn skip_quoted(bytes: &[u8], at: usize) -> Option<usize> {
    let quote = *bytes.get(at)?;
    let mut i = at + 1;
    while i < bytes.len() {
        match *bytes.get(i)? {
            b'\\' => i = i.saturating_add(2),
            b if b == quote => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

fn skip_line_comment(bytes: &[u8], at: usize) -> usize {
    bytes
        .get(at..)
        .unwrap_or_default()
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |offset| at + offset + 1)
}

fn skip_block_comment(bytes: &[u8], at: usize) -> Option<usize> {
    bytes
        .get(at + 2..)?
        .windows(2)
        .position(|pair| pair == b"*/")
        .map(|offset| at + 2 + offset + 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(api: &str, line: u32, col: u32) -> Binding {
        Binding {
            file: "src/app.js".to_owned(),
            api: api.to_owned(),
            arg: String::new(),
            line,
            col,
            token: "jss12345678-sink-a".to_owned(),
            callback_url: "http://jss-marker/jss12345678-sink-a".to_owned(),
        }
    }

    #[test]
    fn wraps_the_exact_multiline_call_without_touching_its_arguments() {
        let source = "app.get('/x', (req, res) => {\n  return fs.readFileSync(\n    req.query.file\n  );\n});\n";
        let out = binding("fs.readFileSync", 2, 10)
            .instrument(source)
            .unwrap();
        assert!(out.contains(",fs.readFileSync(\n    req.query.file\n  ))"));
        assert_eq!(out.matches("__jsspectorRecordSink").count(), 1);
    }

    #[test]
    fn wraps_an_assignment_expression_not_the_surrounding_statement() {
        let source = "if (ready) el.innerHTML = `<b>${location.hash}</b>`;\n";
        let out = binding(".innerHTML =", 1, 12).instrument(source).unwrap();
        assert!(out.contains(",el.innerHTML = `<b>${location.hash}</b>`);"));
        assert!(out.starts_with("if (ready) ("));
    }

    #[test]
    fn statement_leading_sink_is_guarded_from_semicolon_free_previous_line() {
        let source = "let criteria = req.query.q ?? ''\nmodels.sequelize.query(`SELECT ${criteria}`)\n  .then(send)\n";
        let out = binding(".query", 2, 1).instrument(source).unwrap();
        assert!(out.contains("?? ''\n;((function()"), "{out}");
        assert!(out.contains(",models.sequelize.query(`SELECT ${criteria}`))"));
    }

    #[test]
    fn multiline_expression_sink_does_not_get_a_statement_semicolon() {
        let source = "const calls = [\n  fetch(req.query.url),\n]\n";
        let out = binding("fetch", 2, 3).instrument(source).unwrap();
        assert!(out.contains("[\n  ((function()"), "{out}");
        assert!(!out.contains("[\n  ;("), "{out}");
    }

    #[test]
    fn utf16_columns_map_back_to_utf8() {
        let source = "const face = '😀'; fetch(req.url);\n";
        // JavaScript columns count the emoji as two UTF-16 code units.
        let byte = source.find("fetch").unwrap();
        let units = source[..byte].encode_utf16().count() as u32 + 1;
        let out = binding("fetch", 1, units).instrument(source).unwrap();
        assert!(out.contains(",fetch(req.url))"));
    }

    #[test]
    fn fails_closed_when_the_recorded_expression_is_gone() {
        let error = binding("fs.readFileSync", 1, 1)
            .instrument("safeRead(req.query.file);\n")
            .unwrap_err();
        assert!(error.contains("exact sink expression could not be located"));
    }

    #[test]
    fn a_stale_line_uses_the_recorded_argument_instead_of_the_first_matching_api() {
        let source = "const safe = fs.readFileSync(path.join(ROOT, path.basename(req.query.file)));\nconst vulnerable = fs.readFileSync(path.join(ROOT, req.query.file));\nconst later = true;\n";
        let mut binding = binding("fs.readFileSync", 3, 1);
        binding.arg = "path.join(ROOT, req.query.file)".to_owned();
        let out = binding.instrument(source).unwrap();
        let marker = out.find("__jsspectorRecordSink").unwrap();
        let vulnerable = out.find("const vulnerable").unwrap();
        let vulnerable_arg = out[vulnerable..].find("req.query.file").unwrap() + vulnerable;
        assert!(marker > vulnerable);
        assert!(marker < vulnerable_arg);
        assert!(!out[..vulnerable].contains("__jsspectorRecordSink"));
    }

    #[test]
    fn ambiguous_fallbacks_fail_closed() {
        let source =
            "fs.readFileSync(req.query.a);\nfs.readFileSync(req.query.b);\nconst later = true;\n";
        let error = binding("fs.readFileSync", 3, 1)
            .instrument(source)
            .unwrap_err();
        assert!(error.contains("exact sink expression could not be located"));
    }
}
