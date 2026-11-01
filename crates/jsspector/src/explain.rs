//! `jsspector explain`: a rule's documentation, or one finding in full (the code at every step of
//! its path, why it matters, how to fix it, how to silence it).

use std::io::{self, Write};

use jss_core::{Finding, VulnClass};
use jss_frontend::taint::models::model;

use crate::rules::{self, Rule};
use crate::text::{Sources, Style};

/// Writes the documentation of `rule`, with the sink APIs the packs define for it.
pub fn write_rule(out: &mut dyn Write, rule: &Rule, st: &Style) -> io::Result<()> {
    writeln!(
        out,
        "{}{}{}  {} (CWE-{}, security severity {})",
        st.bold,
        rules::id(rule.class),
        st.reset,
        rule.title,
        rule.cwe,
        rule.security_severity
    )?;
    section(out, "What it means", st)?;
    paragraph(out, rule.summary)?;
    section(out, "How to fix it", st)?;
    for fix in rule.fix {
        paragraph(out, &format!("- {fix}"))?;
    }
    section(out, "Treated as safe", st)?;
    paragraph(out, &format!("{}.", capitalize(rule.safe)))?;
    section(out, "Sinks (from the packs)", st)?;
    paragraph(out, &sinks(rule.class).join(", "))?;
    for (family, modules) in families(rule.class) {
        paragraph(out, &format!("{family}: {}", modules.join(", ")))?;
    }
    section(out, "Silencing a finding", st)?;
    paragraph(
        out,
        &format!(
            "Accept the current findings with `jsspector scan --write-baseline FILE` and scan with \
             `--baseline FILE`, or put `// jsspector-ignore {}` on the sink's line or the line \
             above it.",
            rule.class.name()
        ),
    )
}

/// The sink APIs of `class`, as the packs name them: a module family and export
/// (`http-client.get`), a function (`eval`), a method on any receiver (`.query`) or an
/// assignment target (`innerHTML =`).
pub fn sinks(class: VulnClass) -> Vec<String> {
    model().sink_names(class)
}

/// The module families the sinks of `class` use, with the modules that belong to each:
/// `http-client` is `axios`, `got`, ...
pub fn families(class: VulnClass) -> Vec<(String, Vec<String>)> {
    let model = model();
    let mut families: Vec<String> = sinks(class)
        .iter()
        .filter(|name| !name.starts_with('.'))
        .filter_map(|name| {
            name.split_once(['.', '('])
                .map(|(family, _)| family.to_owned())
        })
        .collect();
    families.sort();
    families.dedup();
    families
        .into_iter()
        .filter_map(|family| {
            let modules: Vec<String> = model
                .modules
                .iter()
                .filter(|(spec, fam)| **fam == family && **spec != family)
                .map(|(spec, _)| spec.clone())
                .collect();
            (!modules.is_empty()).then_some((family, modules))
        })
        .collect()
}

/// Writes one finding in full.
pub fn write_finding(
    out: &mut dyn Write,
    f: &Finding,
    sources: &mut Sources,
    st: &Style,
) -> io::Result<()> {
    let rule = rules::rule(f.class);
    let severity = rules::severity_name(f.severity).to_uppercase();
    writeln!(
        out,
        "{}{}{} [{severity}]  {} (CWE-{})",
        st.bold,
        rules::id(f.class),
        st.reset,
        rule.title,
        rule.cwe
    )?;
    writeln!(out, "{}fingerprint {}{}", st.dim, f.fingerprint, st.reset)?;
    writeln!(out)?;
    paragraph(
        out,
        &format!(
            "Data from `{}` ({}) {}: `{}({})`.",
            f.source.expr,
            f.source.kind,
            rules::describe(f.class),
            f.sink.api,
            f.sink.arg
        ),
    )?;
    match &f.entry {
        Some(entry) => paragraph(
            out,
            &format!(
                "Entry point: {entry} (authentication: {}), in `{}`.",
                f.auth.name(),
                f.function
            ),
        )?,
        None => paragraph(
            out,
            &format!(
                "In `{}` (authentication: {}); no entry point was linked to it.",
                f.function,
                f.auth.name()
            ),
        )?,
    }

    section(out, "Path", st)?;
    let sink_file = f.sink.file.as_deref().unwrap_or(&f.file);
    let mut steps: Vec<(&str, u32, u32, String)> = vec![(
        &f.file,
        f.source.line,
        f.source.col,
        format!("source: `{}` ({})", f.source.expr, f.source.kind),
    )];
    for step in &f.trace {
        let file = step.file.as_deref().unwrap_or(&f.file);
        if step.line > 0 {
            steps.push((file, step.line, step.col, step.note.clone()));
        }
    }
    steps.push((
        sink_file,
        f.sink.line,
        f.sink.col,
        format!("sink: `{}`", f.sink.api),
    ));
    steps.dedup_by(|b, a| a.0 == b.0 && a.1 == b.1 && a.3 == b.3);
    let mut shown: Option<(&str, u32)> = None;
    for (number, (file, line, col, note)) in steps.iter().enumerate() {
        writeln!(
            out,
            "  {}{}. {note}{}  {}{file}:{line}:{col}{}",
            st.bold,
            number + 1,
            st.reset,
            st.dim,
            st.reset
        )?;
        // The code around each line once: a step on the line just shown points back to it.
        if shown == Some((*file, *line)) {
            continue;
        }
        shown = Some((*file, *line));
        for at in line.saturating_sub(2).max(1)..=line.saturating_add(1) {
            let Some(code) = sources.line(file, at) else {
                continue;
            };
            let code: String = code.chars().take(160).collect();
            let marker = if at == *line { "→" } else { " " };
            writeln!(out, "     {marker} {at:>6} │ {}", code.trim_end())?;
        }
    }

    section(out, "Why it matters", st)?;
    paragraph(out, rule.summary)?;
    section(out, "How to fix it", st)?;
    for fix in rule.fix {
        paragraph(out, &format!("- {fix}"))?;
    }
    section(out, "Treated as safe", st)?;
    paragraph(out, &format!("{}.", capitalize(rule.safe)))?;
    section(out, "Silencing it", st)?;
    paragraph(
        out,
        &format!(
            "Put `// jsspector-ignore {}` on line {} of {sink_file} (or the line above it), or \
             accept it in a baseline (`jsspector scan --write-baseline FILE`, then \
             `--baseline FILE`).",
            f.class.name(),
            f.sink.line
        ),
    )?;
    writeln!(out, "\n{}key: {}{}", st.dim, f.key, st.reset)
}

fn section(out: &mut dyn Write, title: &str, st: &Style) -> io::Result<()> {
    writeln!(out, "\n{}{title}{}", st.bold, st.reset)
}

/// Writes `text` wrapped at 96 columns, indented by two spaces.
fn paragraph(out: &mut dyn Write, text: &str) -> io::Result<()> {
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > 96 {
            writeln!(out, "  {line}")?;
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        writeln!(out, "  {line}")?;
    }
    Ok(())
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_lists_its_sinks() {
        let mut out = Vec::new();
        write_rule(
            &mut out,
            rules::rule(VulnClass::CommandInjection),
            &Style::new(false),
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("CWE-78"), "{text}");
        assert!(text.contains("child_process.exec"), "{text}");
        assert!(
            text.contains("jsspector-ignore command-injection"),
            "{text}"
        );
    }

    #[test]
    fn paragraphs_wrap() {
        let mut out = Vec::new();
        paragraph(&mut out, &"word ".repeat(40)).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.lines().count() > 1);
        assert!(text.lines().all(|l| l.chars().count() <= 98));
    }
}
