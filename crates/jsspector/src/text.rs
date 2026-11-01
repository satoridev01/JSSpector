//! Readable output: findings grouped by the file of their sink, with the code of every step, and
//! inline suppressions (`// jsspector-ignore`).

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use jss_core::{Finding, VulnClass};

use crate::rules;

/// ANSI styles, empty when the output is not a terminal.
pub struct Style {
    pub bold: &'static str,
    pub dim: &'static str,
    pub red: &'static str,
    pub yellow: &'static str,
    pub reset: &'static str,
}

impl Style {
    pub fn new(color: bool) -> Self {
        if color {
            Style {
                bold: "\x1b[1m",
                dim: "\x1b[2m",
                red: "\x1b[31m",
                yellow: "\x1b[33m",
                reset: "\x1b[0m",
            }
        } else {
            Style {
                bold: "",
                dim: "",
                red: "",
                yellow: "",
                reset: "",
            }
        }
    }
}

/// The files under a root, read once each, as lines.
pub struct Sources {
    root: PathBuf,
    files: BTreeMap<String, Option<Vec<String>>>,
}

impl Sources {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            files: BTreeMap::new(),
        }
    }

    /// Line `line` (1-based) of `file`, untrimmed; `None` when unreadable or out of range.
    pub fn line(&mut self, file: &str, line: u32) -> Option<&str> {
        let index = usize::try_from(line).ok()?.checked_sub(1)?;
        let root = &self.root;
        self.files
            .entry(file.to_owned())
            .or_insert_with(|| {
                std::fs::read(root.join(file)).ok().map(|bytes| {
                    String::from_utf8_lossy(&bytes)
                        .lines()
                        .map(str::to_owned)
                        .collect()
                })
            })
            .as_ref()?
            .get(index)
            .map(String::as_str)
    }

    /// Line `line` of `file`, trimmed and cut to 140 characters; empty when unreadable.
    pub fn snippet(&mut self, file: &str, line: u32) -> String {
        let Some(text) = self.line(file, line) else {
            return String::new();
        };
        let text = text.trim();
        if text.chars().count() > 140 {
            let mut cut: String = text.chars().take(137).collect();
            cut.push_str("...");
            cut
        } else {
            text.to_owned()
        }
    }

    /// Whether a `jsspector-ignore` comment on the sink's line or the line above silences `f`.
    /// `// jsspector-ignore` silences every class; `// jsspector-ignore sql-injection, xss` only
    /// those (anything after the class names, such as a reason, is ignored).
    pub fn ignores(&mut self, f: &Finding) -> bool {
        let file = f.sink.file.as_deref().unwrap_or(&f.file).to_owned();
        let line = f.sink.line;
        [line, line.saturating_sub(1)].into_iter().any(|at| {
            self.line(&file, at)
                .is_some_and(|text| comment_ignores(text, f.class))
        })
    }
}

/// Whether `line` holds a `jsspector-ignore` comment that covers `class`.
fn comment_ignores(line: &str, class: VulnClass) -> bool {
    const MARKER: &str = "jsspector-ignore";
    let Some(at) = line.find(MARKER) else {
        return false;
    };
    let rest = line.get(at + MARKER.len()..).unwrap_or("");
    // `jsspector-ignore-next-line` or another word that merely starts with the marker.
    if rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return false;
    }
    let mut classes = Vec::new();
    for token in rest
        .trim_start_matches(':')
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
    {
        match rules::by_name(token) {
            Some(rule) => classes.push(rule.class),
            None => break,
        }
    }
    classes.is_empty() || classes.contains(&class)
}

/// Counts shown after the findings.
pub struct Summary {
    pub files_scanned: usize,
    pub skipped: usize,
    pub baselined: usize,
    pub ignored: usize,
    pub elapsed: std::time::Duration,
}

/// Writes `findings`, grouped by the file of their sink, then the summary line.
pub fn write(
    out: &mut dyn Write,
    findings: &[Finding],
    sources: &mut Sources,
    summary: &Summary,
    st: &Style,
) -> io::Result<()> {
    let mut by_file: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_file
            .entry(f.sink.file.as_deref().unwrap_or(&f.file))
            .or_default()
            .push(f);
    }
    for (file, findings) in &by_file {
        writeln!(out, "\n  {}{file}{}", st.bold, st.reset)?;
        for f in findings {
            let severity = rules::severity_name(f.severity).to_uppercase();
            let color = if severity == "CRITICAL" {
                st.red
            } else {
                st.yellow
            };
            writeln!(
                out,
                "  {color}{}❯❯❱ {}{} {}[{severity}]{} {}{}{}",
                st.bold,
                rules::id(f.class),
                st.reset,
                color,
                st.reset,
                st.dim,
                f.fingerprint,
                st.reset
            )?;
            writeln!(
                out,
                "          Data from `{}` ({}) {}.",
                f.source.expr,
                f.source.kind,
                rules::describe(f.class)
            )?;
            let via = f
                .entry
                .as_deref()
                .map(|e| format!(" via {e}"))
                .unwrap_or_default();
            writeln!(
                out,
                "          {}in {}{via}, auth: {}{}",
                st.dim,
                f.function,
                f.auth.name(),
                st.reset
            )?;
            writeln!(out)?;
            writeln!(
                out,
                "  {:>8}┆ {}",
                f.sink.line,
                sources.snippet(file, f.sink.line)
            )?;
            if f.sink.file.is_some() || f.source.line != f.sink.line {
                writeln!(
                    out,
                    "          {}↳ source: {}:{}{}",
                    st.dim, f.file, f.source.line, st.reset
                )?;
                writeln!(
                    out,
                    "  {:>8}┆ {}",
                    f.source.line,
                    sources.snippet(&f.file, f.source.line)
                )?;
                // Each step from the source to the sink, with its code line.
                let mut last = (f.file.as_str(), f.source.line);
                for step in &f.trace {
                    let step_file = step.file.as_deref().unwrap_or(&f.file);
                    if step.line == 0 || (step_file, step.line) == last {
                        continue;
                    }
                    writeln!(
                        out,
                        "          {}↳ {}: {step_file}:{}{}",
                        st.dim, step.note, step.line, st.reset
                    )?;
                    writeln!(
                        out,
                        "  {:>8}┆ {}",
                        step.line,
                        sources.snippet(step_file, step.line)
                    )?;
                    last = (step_file, step.line);
                }
            }
            writeln!(out, "          ⋮┆----------------------------------------")?;
        }
    }
    let mut extra = String::new();
    if summary.baselined > 0 {
        extra.push_str(&format!(", {} in the baseline", summary.baselined));
    }
    if summary.ignored > 0 {
        extra.push_str(&format!(", {} ignored by comments", summary.ignored));
    }
    writeln!(
        out,
        "\n{}{} finding(s){}{extra} in {} file(s) scanned ({} skipped) in {:.2}s",
        st.bold,
        findings.len(),
        st.reset,
        summary.files_scanned,
        summary.skipped,
        summary.elapsed.as_secs_f64()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_comments_name_classes() {
        let sql = VulnClass::SqlInjection;
        assert!(comment_ignores("db.query(q); // jsspector-ignore", sql));
        assert!(comment_ignores("// jsspector-ignore: sql-injection", sql));
        assert!(comment_ignores(
            "/* jsspector-ignore xss, sql-injection -- ids are numeric */",
            sql
        ));
        assert!(!comment_ignores("// jsspector-ignore xss", sql));
        assert!(!comment_ignores("// jsspector-ignore-all", sql));
        assert!(!comment_ignores("db.query(q);", sql));
        // A reason that is not a class name does not narrow the comment.
        assert!(comment_ignores(
            "// jsspector-ignore because the id is checked",
            sql
        ));
    }
}
