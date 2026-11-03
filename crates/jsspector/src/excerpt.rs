//! The annotated code excerpt of a finding, as Markdown: every line its value passes through,
//! from the entry point to the sink, one block per file. Inside a block the lines are in code
//! order with `...` over the gaps, so it reads like the file; a `// [n]` comment at the end of
//! each line numbers the flow, so it can also be followed across files. The sink also shows the
//! two lines above it.

use std::collections::BTreeMap;

use jss_core::{Auth, Finding};

use crate::rules;
use crate::text::Sources;

/// Longest code shown on one line; minified lines are cut.
const MAX_CODE: usize = 100;
/// The column the comments align to, unless the code is wider.
const MAX_ALIGN: usize = 72;
/// Lines shown above the sink.
const CONTEXT: u32 = 2;
/// Most lines shown below the sink to finish its call.
const MAX_CONTINUATION: u32 = 8;

/// One line of the flow, numbered by its first appearance.
#[derive(Debug, PartialEq)]
struct Mark {
    file: String,
    line: u32,
    number: usize,
    notes: Vec<String>,
}

/// The finding's flow as numbered lines: entry point, source, trace steps, sink. A line the
/// value passes twice keeps its first number and gathers the notes.
fn marks(f: &Finding) -> Vec<Mark> {
    let mut steps: Vec<(String, u32, String)> = Vec::new();
    if let (Some(at), Some(entry)) = (&f.entry_at, &f.entry) {
        steps.push((at.file.clone(), at.line, entry_note(entry, f.auth)));
    }
    steps.push((
        f.file.clone(),
        f.source.line,
        format!("origin: {} ({})", f.source.expr, f.source.kind),
    ));
    for step in &f.trace {
        steps.push((
            step.file.clone().unwrap_or_else(|| f.file.clone()),
            step.line,
            step.note.replace('`', ""),
        ));
    }
    steps.push((
        f.sink.file.clone().unwrap_or_else(|| f.file.clone()),
        f.sink.line,
        format!("VULNERABLE: {} reaches {}", f.source.expr, f.sink.api),
    ));

    let mut marks: Vec<Mark> = Vec::new();
    for (file, line, note) in steps {
        match marks.iter_mut().find(|m| m.file == file && m.line == line) {
            Some(mark) if !mark.notes.contains(&note) => mark.notes.push(note),
            Some(_) => {}
            None => {
                let number = marks.len() + 1;
                marks.push(Mark {
                    file,
                    line,
                    number,
                    notes: vec![note],
                });
            }
        }
    }
    marks
}

fn entry_note(entry: &str, auth: Auth) -> String {
    let who = match auth {
        Auth::NoneDetected => "no authentication check detected",
        Auth::User => "logged-in users",
        Auth::Admin => "administrators only",
    };
    format!("entry: {}, {who}", rules::entry_label(entry))
}

/// The comment of a line: `[n]` and its notes, the sink first. Where a line has more to say,
/// plain `assigned to x` steps are left out.
fn comment(mark: &Mark) -> String {
    let mut notes: Vec<&str> = mark.notes.iter().map(String::as_str).collect();
    if notes.len() > 1 {
        let telling: Vec<&str> = notes
            .iter()
            .copied()
            .filter(|n| !n.starts_with("assigned to "))
            .collect();
        if !telling.is_empty() {
            notes = telling;
        }
    }
    notes.sort_by_key(|n| !n.starts_with("VULNERABLE"));
    format!("[{}] {}", mark.number, notes.join("; "))
}

/// A source line as shown: tabs expanded, trailing space dropped, cut when too long.
fn code(line: Option<&str>) -> String {
    let line = line.unwrap_or("").replace('\t', "    ");
    let line = line.trim_end();
    if line.chars().count() <= MAX_CODE {
        return line.to_owned();
    }
    let cut: String = line.chars().take(MAX_CODE - 1).collect();
    format!("{cut}…")
}

/// How many brackets a line leaves open: `(`, `[` and `{` minus their closers, outside string
/// literals and before a `//` comment.
fn open_brackets(line: &str) -> i32 {
    let mut depth = 0;
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == '\\' {
                    chars.next();
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '\'' | '"' | '`' => quote = Some(c),
                '/' if chars.peek() == Some(&'/') => break,
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                _ => {}
            },
        }
    }
    depth
}

/// The lines below the sink that finish its call (`client.get(url, {` then its options), and
/// whether the rest was left out: the call goes on past a callback's opening line
/// (`}, res => {`) or past `MAX_CONTINUATION` lines.
fn continuation(sources: &mut Sources, file: &str, line: u32) -> (Vec<u32>, bool) {
    let Some(first) = sources.line(file, line) else {
        return (Vec::new(), false);
    };
    let mut depth = open_brackets(first);
    let mut lines = Vec::new();
    let mut next = line;
    if depth == 0 {
        let chained = line + 1;
        if sources
            .line(file, chained)
            .is_some_and(|text| text.trim_start().starts_with('.'))
        {
            next = chained;
            let text = sources.line(file, next).unwrap_or_default();
            depth = open_brackets(text);
            lines.push(next);
            if depth > 0
                && text.trim_end().ends_with('{')
                && (text.contains("=>") || text.contains("function"))
            {
                return (lines, true);
            }
        }
    }
    while depth > 0 {
        if lines.len() >= MAX_CONTINUATION as usize {
            return (lines, true);
        }
        next += 1;
        let Some(text) = sources.line(file, next) else {
            break;
        };
        depth += open_brackets(text);
        let text = text.trim_end();
        let callback = text.ends_with('{') && (text.contains("=>") || text.contains("function"));
        lines.push(next);
        if depth > 0 && callback {
            return (lines, true);
        }
    }
    (lines, false)
}

/// The excerpt of `f`: per file, in order of first appearance, a bullet with the file name and
/// a code block of its lines.
pub fn affected(f: &Finding, sources: &mut Sources) -> String {
    let marks = marks(f);
    let sink_file = f.sink.file.as_deref().unwrap_or(&f.file);
    let mut files: Vec<&str> = Vec::new();
    for mark in &marks {
        if !files.contains(&mark.file.as_str()) {
            files.push(&mark.file);
        }
    }

    let mut out = String::new();
    for file in files {
        // Line -> comment; context lines have none.
        let mut shown: BTreeMap<u32, Option<String>> = marks
            .iter()
            .filter(|m| m.file == file)
            .map(|m| (m.line, Some(comment(m))))
            .collect();
        let mut cut_after = None;
        if file == sink_file {
            for line in f.sink.line.saturating_sub(CONTEXT).max(1)..f.sink.line {
                shown.entry(line).or_insert(None);
            }
            let (more, cut) = continuation(sources, file, f.sink.line);
            if cut {
                cut_after = Some(more.last().copied().unwrap_or(f.sink.line));
            }
            for line in more {
                shown.entry(line).or_insert(None);
            }
        }
        let rows: Vec<(u32, String, Option<String>)> = shown
            .into_iter()
            .map(|(line, note)| (line, code(sources.line(file, line)), note))
            .collect();
        out.push_str(&block(file, &rows, cut_after));
    }
    out.trim_end().to_owned()
}

/// One file's bullet and code block. Common indentation is removed, comments are aligned, and
/// `...` marks the lines left out between two shown ones, and after `cut_after` (a call shown
/// only in part) when nothing follows it.
fn block(file: &str, rows: &[(u32, String, Option<String>)], cut_after: Option<u32>) -> String {
    let indent = rows
        .iter()
        .filter(|(_, code, _)| !code.trim().is_empty())
        .map(|(_, code, _)| code.len() - code.trim_start().len())
        .min()
        .unwrap_or(0);
    let rows: Vec<(u32, String, &Option<String>)> = rows
        .iter()
        .map(|(line, code, note)| {
            let code = if code.len() >= indent {
                code[indent..].to_owned()
            } else {
                code.trim_start().to_owned()
            };
            (*line, code, note)
        })
        .collect();
    let number_width = rows
        .iter()
        .map(|(line, _, _)| line.to_string().len())
        .max()
        .unwrap_or(1);
    let align = rows
        .iter()
        .map(|(_, code, _)| code.chars().count())
        .max()
        .unwrap_or(0)
        .min(MAX_ALIGN);

    let mut lines: Vec<String> = Vec::new();
    let mut previous: Option<u32> = None;
    for (line, code, note) in &rows {
        if previous.is_some_and(|p| *line > p + 1) {
            lines.push("...".to_owned());
        }
        previous = Some(*line);
        let mut text = format!("{line:>number_width$}  {code}");
        if let Some(note) = note {
            let pad = align.saturating_sub(code.chars().count());
            text.push_str(&" ".repeat(pad));
            text.push_str("  // ");
            text.push_str(note);
        }
        lines.push(text.trim_end().to_owned());
    }
    if cut_after.is_some() && cut_after == previous {
        lines.push("...".to_owned());
    }

    let longest_ticks = lines
        .iter()
        .map(|l| l.split(|c| c != '`').map(str::len).max().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(longest_ticks.max(2) + 1);
    let mut out = format!("- `{file}`\n\n  {fence}\n");
    for line in lines {
        out.push_str("  ");
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str(&format!("  {fence}\n\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use jss_core::{EntryLoc, Severity, SinkLoc, SourceLoc, TraceStep, VulnClass};

    fn finding() -> Finding {
        Finding {
            file: "src/api/hooks.js".to_owned(),
            sink: SinkLoc {
                file: None,
                api: "http.request".to_owned(),
                arg: "0".to_owned(),
                line: 9,
                col: 5,
            },
            class: VulnClass::Ssrf,
            severity: Severity::High,
            confidence: "heuristic",
            auth: Auth::NoneDetected,
            function: "send".to_owned(),
            entry: Some("ALL /hooks/event".to_owned()),
            entry_at: Some(EntryLoc {
                file: "src/routes.js".to_owned(),
                line: 3,
            }),
            source: SourceLoc {
                kind: "http",
                expr: "req.headers".to_owned(),
                line: 20,
                col: 3,
            },
            trace: vec![
                TraceStep {
                    file: None,
                    line: 20,
                    col: 3,
                    note: "returned by `parse()`".to_owned(),
                },
                TraceStep {
                    file: None,
                    line: 20,
                    col: 3,
                    note: "assigned to `targets`".to_owned(),
                },
                TraceStep {
                    file: None,
                    line: 4,
                    col: 3,
                    note: "assigned to `url`".to_owned(),
                },
            ],
            key: String::new(),
            fingerprint: String::new(),
        }
    }

    fn sources(dir: &std::path::Path) -> Sources {
        std::fs::create_dir_all(dir.join("src/api")).unwrap();
        let hooks: Vec<String> = (1..=22).map(|n| format!("    line{n}();")).collect();
        std::fs::write(dir.join("src/api/hooks.js"), hooks.join("\n")).unwrap();
        std::fs::write(
            dir.join("src/routes.js"),
            "a\nb\napp.all('/hooks/event', handler);\n",
        )
        .unwrap();
        Sources::new(dir)
    }

    #[test]
    fn numbers_the_flow_and_merges_lines_reached_twice() {
        let marks = marks(&finding());
        let summary: Vec<(&str, u32, usize)> = marks
            .iter()
            .map(|m| (m.file.as_str(), m.line, m.number))
            .collect();
        assert_eq!(
            summary,
            [
                ("src/routes.js", 3, 1),
                ("src/api/hooks.js", 20, 2),
                ("src/api/hooks.js", 4, 3),
                ("src/api/hooks.js", 9, 4),
            ]
        );
        // `assigned to targets` is dropped where the line says more.
        assert_eq!(
            comment(&marks[1]),
            "[2] origin: req.headers (http); returned by parse()"
        );
        assert_eq!(
            comment(&marks[0]),
            "[1] entry: /hooks/event, no authentication check detected"
        );
    }

    #[test]
    fn one_block_per_file_with_gaps_and_sink_context() {
        let dir = std::env::temp_dir().join(format!("jss-excerpt-{}", std::process::id()));
        let mut sources = sources(&dir);
        let text = affected(&finding(), &mut sources);
        std::fs::remove_dir_all(&dir).ok();

        // Files in order of first appearance, each a bullet.
        let routes = text.find("- `src/routes.js`").unwrap();
        let hooks = text.find("- `src/api/hooks.js`").unwrap();
        assert!(routes < hooks, "{text}");
        // The sink and the two lines above it, in code order; a gap before line 20.
        assert!(text.contains(" 7  line7();\n"), "{text}");
        assert!(text.contains(" 8  line8();\n"), "{text}");
        assert!(
            text.contains("// [4] VULNERABLE: req.headers reaches http.request"),
            "{text}"
        );
        let sink = text.find("line9();").unwrap();
        let gap = text[sink..].find("...").map(|i| i + sink).unwrap();
        let origin = text.find("line20();").unwrap();
        assert!(sink < gap && gap < origin, "{text}");
        // Common indentation removed.
        assert!(text.contains("  20  line20();"), "{text}");
    }

    #[test]
    fn a_call_over_several_lines_is_shown_up_to_its_callback() {
        let dir = std::env::temp_dir().join(format!("jss-excerpt-call-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/a.js"),
            "x();\ny();\nres = client.get(url, {\n  headers: { 'UA': 'm (x)' },\n  timeout: 1\n}, res => {\n  res.resume();\n});\n",
        )
        .unwrap();
        let mut sources = Sources::new(&dir);
        let (lines, cut) = continuation(&mut sources, "src/a.js", 3);
        assert_eq!((lines, cut), (vec![4, 5, 6], true));
        // A call that closes on its own line needs nothing more.
        std::fs::write(
            dir.join("src/b.js"),
            "fetch(url, { method: 'POST' });\nz();\n",
        )
        .unwrap();
        assert_eq!(
            continuation(&mut sources, "src/b.js", 1),
            (Vec::new(), false)
        );
        std::fs::write(
            dir.join("src/c.js"),
            "const proxy = https\n  .request(options, response => {\n  response.resume();\n});\n",
        )
        .unwrap();
        assert_eq!(continuation(&mut sources, "src/c.js", 1), (vec![2], true));
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(open_brackets("f('(', \"[\", `{`) // ("), 0);
    }

    #[test]
    fn long_lines_are_cut() {
        let long = "x".repeat(300);
        assert_eq!(code(Some(&long)).chars().count(), MAX_CODE);
        assert_eq!(code(Some("\tfoo();  ")), "    foo();");
    }
}
