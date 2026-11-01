//! One rule per vulnerability class: what it means, how to fix it, and its metadata (CWE, SARIF
//! security severity). Shared by `scan --format sarif` and `explain`.

use jss_core::{Finding, Severity, VulnClass};

/// Every class, in rule-index order (the SARIF `ruleIndex`).
pub const CLASSES: [VulnClass; 8] = [
    VulnClass::CommandInjection,
    VulnClass::CodeInjection,
    VulnClass::SqlInjection,
    VulnClass::NosqlInjection,
    VulnClass::PathTraversal,
    VulnClass::Ssrf,
    VulnClass::Xss,
    VulnClass::PrototypePollution,
];

/// The documentation of one rule.
pub struct Rule {
    pub class: VulnClass,
    /// `SqlInjection`.
    pub name: &'static str,
    /// `SQL injection`.
    pub title: &'static str,
    pub cwe: u32,
    /// SARIF `security-severity` (CVSS-like, 0.0-10.0): how bad the class typically is.
    pub security_severity: &'static str,
    /// What reaching the sink lets an attacker do.
    pub summary: &'static str,
    /// How to fix it, as short paragraphs.
    pub fix: &'static [&'static str],
    /// What the engine accepts as making the value safe.
    pub safe: &'static str,
}

/// The rule of `class`.
pub fn rule(class: VulnClass) -> &'static Rule {
    match class {
        VulnClass::CommandInjection => &COMMAND_INJECTION,
        VulnClass::CodeInjection => &CODE_INJECTION,
        VulnClass::SqlInjection => &SQL_INJECTION,
        VulnClass::NosqlInjection => &NOSQL_INJECTION,
        VulnClass::PathTraversal => &PATH_TRAVERSAL,
        VulnClass::Ssrf => &SSRF,
        VulnClass::Xss => &XSS,
        VulnClass::PrototypePollution => &PROTOTYPE_POLLUTION,
    }
}

/// The rule of a class named `name` (`sql-injection`, or the rule id `jsspector.sql-injection`).
pub fn by_name(name: &str) -> Option<&'static Rule> {
    let name = name.strip_prefix("jsspector.").unwrap_or(name);
    CLASSES
        .iter()
        .find(|class| class.name().eq_ignore_ascii_case(name))
        .map(|class| rule(*class))
}

/// The rule id used in every output: `jsspector.sql-injection`.
pub fn id(class: VulnClass) -> String {
    format!("jsspector.{}", class.name())
}

/// The index of `class` in [`CLASSES`].
pub fn index(class: VulnClass) -> usize {
    CLASSES.iter().position(|c| *c == class).unwrap_or(0)
}

/// The lowercase name of a severity.
pub fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

/// Parses a severity name.
pub fn parse_severity(value: &str) -> Result<Severity, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        _ => Err(format!(
            "unknown severity `{value}` (expected critical, high, medium or low)"
        )),
    }
}

/// A plain-language description of what happens to the data at the sink.
/// A finding's title, one line: its class, the entry point (or function, or file) where it is
/// reached, and what flows into what. `Path traversal in POST /api/watch/file: req.body reaches
/// fs.readFile`.
pub fn title(f: &Finding) -> String {
    let place = match &f.entry {
        Some(entry) => entry.clone(),
        None if !f.function.starts_with('<') => format!("{}()", f.function),
        None => f.file.clone(),
    };
    format!(
        "{} in {}: {} reaches {}",
        rule(f.class).title,
        clip(&place, 60),
        clip(&f.source.expr, 48),
        clip(&f.sink.api, 40)
    )
}

/// Where the sink is: `file:line`.
pub fn resource(f: &Finding) -> String {
    format!(
        "{}:{}",
        f.sink.file.as_deref().unwrap_or(&f.file),
        f.sink.line
    )
}

/// A finding in a few sentences: what flows where, from which entry point and with what
/// authentication, the path the value takes, and what the class lets an attacker do.
pub fn description(f: &Finding) -> String {
    let mut text = format!(
        "Data from `{}` ({}) {}: `{}`.",
        f.source.expr,
        f.source.kind,
        describe(f.class),
        f.sink.api
    );
    match &f.entry {
        Some(entry) => text.push_str(&format!(" Reached from {entry}")),
        None => text.push_str(&format!(" In {}", f.function)),
    }
    text.push_str(&format!(
        " (authentication: {}). Source at {}:{}, sink at {}.",
        f.auth.name(),
        f.file,
        f.source.line,
        resource(f)
    ));
    if !f.trace.is_empty() {
        let steps: Vec<String> = f
            .trace
            .iter()
            .take(8)
            .map(|step| {
                format!(
                    "{} ({}:{})",
                    step.note,
                    step.file.as_deref().unwrap_or(&f.file),
                    step.line
                )
            })
            .collect();
        text.push_str(&format!(" Path: {}", steps.join(" -> ")));
        if f.trace.len() > 8 {
            text.push_str(" -> ...");
        }
        text.push('.');
    }
    text.push(' ');
    text.push_str(rule(f.class).summary);
    text
}

/// How to fix a finding of `class`, as one paragraph.
pub fn remediation(class: VulnClass) -> String {
    rule(class).fix.join(" ")
}

/// `text` on one line, cut to `max` characters (ending in `…` when cut).
fn clip(text: &str, max: usize) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() <= max {
        return text;
    }
    let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

pub fn describe(class: VulnClass) -> &'static str {
    match class {
        VulnClass::CommandInjection => "reaches a shell command or program execution",
        VulnClass::CodeInjection => "is evaluated as code",
        VulnClass::SqlInjection => "is concatenated into an SQL query",
        VulnClass::NosqlInjection => {
            "is used in a database query, where an object changes its meaning"
        }
        VulnClass::PathTraversal => "is used as a file path without confinement",
        VulnClass::Ssrf => "controls the URL of a server-side request",
        VulnClass::Xss => "is written into the page as HTML",
        VulnClass::PrototypePollution => "chooses both keys of a nested object write",
    }
}

static COMMAND_INJECTION: Rule = Rule {
    class: VulnClass::CommandInjection,
    name: "CommandInjection",
    title: "OS command injection",
    cwe: 78,
    security_severity: "9.8",
    summary: "Attacker-controlled data reaches a shell command or the program and arguments of a \
              new process. With a shell (`exec`, `execSync`, `spawn(..., { shell: true })`), \
              metacharacters such as `;`, `|`, `$( )` run arbitrary commands on the server.",
    fix: &[
        "Do not build shell command strings from input. Call the program directly with an \
         argument array (`execFile`/`spawn` without `shell`), so input can only ever be an \
         argument.",
        "When input chooses an argument, validate it against an allowlist or a strict pattern, \
         and put `--` before positional arguments so a value starting with `-` is not read as \
         an option.",
    ],
    safe: "an allowlist or strict-pattern check that returns or throws before the call \
           (`if (!/^[\\w.-]+$/.test(name)) return`), a comparison with a constant, numeric \
           conversion, or a shell escaper (`quote`, `shellescape`)",
};

static CODE_INJECTION: Rule = Rule {
    class: VulnClass::CodeInjection,
    name: "CodeInjection",
    title: "Code injection",
    cwe: 94,
    security_severity: "9.3",
    summary: "Attacker-controlled data is evaluated as JavaScript (`eval`, `new Function`, \
              `vm.runIn*`, a string passed to `setTimeout`, a renderer's \
              `executeJavaScript`), which runs arbitrary code with the privileges of the \
              process.",
    fix: &[
        "Never evaluate input. Parse data with `JSON.parse`, look values up in a map, or \
         dispatch through a fixed table of functions.",
        "`vm` is not a security boundary: do not use it to run untrusted code.",
    ],
    safe: "an allowlist check that returns or throws before the call, a comparison with a \
           constant, or numeric conversion",
};

static SQL_INJECTION: Rule = Rule {
    class: VulnClass::SqlInjection,
    name: "SqlInjection",
    title: "SQL injection",
    cwe: 89,
    security_severity: "8.8",
    summary: "Attacker-controlled data is concatenated or interpolated into the text of an SQL \
              statement, so it can change the statement: read or modify other rows and tables, \
              bypass checks, and sometimes run commands through the database.",
    fix: &[
        "Pass values as bound parameters (`db.query('... WHERE id = ?', [id])`, `$1`, named \
         parameters) or through the query builder's value methods, never by building the SQL \
         text.",
        "Identifiers (table, column, sort order) cannot be parameters: map them from an \
         allowlist.",
    ],
    safe: "bound parameters (values passed apart from the SQL text), an SQL escaper \
           (`escape`, `escapeId`, `escapeLiteral`), an allowlist check, a comparison with a \
           constant, or numeric conversion (`parseInt`, `Number`)",
};

static NOSQL_INJECTION: Rule = Rule {
    class: VulnClass::NosqlInjection,
    name: "NosqlInjection",
    title: "NoSQL injection",
    cwe: 943,
    security_severity: "8.8",
    summary: "A request value that can be an object (a JSON body, or `?id[$ne]=x` with the \
              default query parser) is used as a query or filter value, so operators such as \
              `$ne`, `$gt` or `$where` change what the query matches: login bypass, reading \
              other users' data.",
    fix: &[
        "Make sure the value is a scalar before it reaches the query: `String(id)`, \
         `typeof id === 'string'` checks, a schema validator, or `mongo-sanitize`.",
        "Turn on the driver's sanitizing options where they exist (`sanitizeFilter` in \
         Mongoose), and never pass input to `$where`.",
    ],
    safe: "a `typeof x === 'string'` (or number, boolean) check, a type assertion such as \
           `check(x, String)`, or numeric conversion",
};

static PATH_TRAVERSAL: Rule = Rule {
    class: VulnClass::PathTraversal,
    name: "PathTraversal",
    title: "Path traversal",
    cwe: 22,
    security_severity: "7.5",
    summary: "Attacker-controlled data is used as a file path (`fs.readFile`, `res.sendFile`, \
              `createReadStream`, archive extraction) without being confined to a directory, so \
              `../` sequences or absolute paths read or write files elsewhere on the server.",
    fix: &[
        "Resolve the path against a base directory and check the result stays inside it: \
         `const p = path.resolve(base, input); if (!p.startsWith(base + path.sep)) throw ...`.",
        "Prefer looking files up by an identifier (a database row, a map) over taking paths \
         from the request; with `res.sendFile`, pass the `root` option.",
    ],
    safe: "`path.basename`, a `startsWith(base)` check, rejecting `..` (`if \
           (p.includes('..')) return`), the `root` option of `sendFile`/`download`, an \
           allowlist check, or numeric conversion",
};

static SSRF: Rule = Rule {
    class: VulnClass::Ssrf,
    name: "Ssrf",
    title: "Server-side request forgery",
    cwe: 918,
    security_severity: "9.1",
    summary: "Attacker-controlled data chooses the scheme or host of a request the server makes \
              (`fetch`, `axios`, `http.request`), so the server can be made to call internal \
              services, cloud metadata endpoints (`169.254.169.254`) or other hosts on the \
              attacker's behalf.",
    fix: &[
        "Do not let input choose the host: build URLs from a fixed base and only let input fill \
         a path segment or query value (encoded).",
        "When users must give URLs (webhooks, imports), resolve the host and reject private, \
         loopback and link-local addresses, check again after redirects, and use an \
         allowlist where possible.",
    ],
    safe: "a fixed scheme and host before the input (`https://api.example.com/${id}`), \
           `encodeURIComponent`, or an allowlist or URL-validation check before the call",
};

static XSS: Rule = Rule {
    class: VulnClass::Xss,
    name: "Xss",
    title: "Cross-site scripting",
    cwe: 79,
    security_severity: "7.8",
    summary: "Attacker-controlled data is written into a page as HTML (`innerHTML`, \
              `outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html`, React \
              `dangerouslySetInnerHTML`), so it can run script in other users' browsers: \
              session theft, actions as the victim.",
    fix: &[
        "Write text, not HTML: `textContent`, template engines with auto-escaping, React \
         children instead of `dangerouslySetInnerHTML`.",
        "When HTML is really needed, sanitize it with a maintained sanitizer (DOMPurify) right \
         before writing it, and set a Content-Security-Policy.",
    ],
    safe: "an HTML escaper or sanitizer (`escapeHtml`, `DOMPurify.sanitize`, `sanitizeHtml`, \
           `he.encode`), numeric conversion, or an allowlist check",
};

static PROTOTYPE_POLLUTION: Rule = Rule {
    class: VulnClass::PrototypePollution,
    name: "PrototypePollution",
    title: "Prototype pollution",
    cwe: 1321,
    security_severity: "7.3",
    summary: "Attacker-controlled data chooses the keys of a nested write (`obj[a][b] = v`, \
              `_.set(obj, path, v)`, deep merges), so a key of `__proto__` or \
              `constructor.prototype` changes `Object.prototype` for the whole process: \
              authorization bypass, denial of service, and code execution through gadgets.",
    fix: &[
        "Reject `__proto__`, `constructor` and `prototype` as keys before nested writes, or \
         check `Object.hasOwn` before walking into a key.",
        "Use `Map` or objects made with `Object.create(null)` for attacker-keyed data, and keep \
         merge and set libraries up to date (most now refuse these keys).",
    ],
    safe: "an allowlist check on the keys (`ALLOWED.includes(key)`), a comparison with a \
           constant, or keys that are not attacker-controlled",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_has_its_own_rule() {
        for (index, class) in CLASSES.iter().enumerate() {
            let rule = rule(*class);
            assert_eq!(rule.class, *class);
            assert_eq!(super::index(*class), index);
            assert!(rule.security_severity.parse::<f64>().is_ok());
        }
        assert_eq!(by_name("jsspector.sql-injection").map(|r| r.cwe), Some(89));
        assert_eq!(by_name("XSS").map(|r| r.cwe), Some(79));
        assert!(by_name("lint").is_none());
    }
}
