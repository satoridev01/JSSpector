//! Owned, serializable taint findings (the `scan` command's output).
//!
//! v0 findings come from a single-file, intra-procedural heuristic spike (see `jss-frontend`'s
//! `taint` module). Every finding is a candidate for hand triage, never a verdict.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// The vulnerability class of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VulnClass {
    CommandInjection,
    CodeInjection,
    SqlInjection,
    NosqlInjection,
    PathTraversal,
    Ssrf,
    Xss,
    PrototypePollution,
}

impl VulnClass {
    pub fn name(self) -> &'static str {
        match self {
            Self::CommandInjection => "command-injection",
            Self::CodeInjection => "code-injection",
            Self::SqlInjection => "sql-injection",
            Self::NosqlInjection => "nosql-injection",
            Self::PathTraversal => "path-traversal",
            Self::Ssrf => "ssrf",
            Self::Xss => "xss",
            Self::PrototypePollution => "prototype-pollution",
        }
    }
}

/// Severity, highest first in sort order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// Authentication found on the path to a sink.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Auth {
    /// No middleware or check was recognized (it may still exist, e.g. app-wide).
    #[default]
    NoneDetected,
    /// A login check (middleware, guard, or `if (!req.user) return`).
    User,
    /// An admin or role check.
    Admin,
}

impl Auth {
    pub fn name(self) -> &'static str {
        match self {
            Self::NoneDetected => "none-detected",
            Self::User => "user",
            Self::Admin => "admin",
        }
    }
}

/// Where a finding's tainted value came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SourceLoc {
    /// `http` (Express/Fastify/Hapi-style request), `koa`, `socket` (socket.io event data) or
    /// `cli` (process.argv).
    pub kind: &'static str,
    pub expr: String,
    pub line: u32,
    pub col: u32,
}

/// The dangerous call.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SinkLoc {
    /// Set when the sink is in another file than the finding's source (repo-wide link).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub api: String,
    /// Source text of the tainted argument (truncated).
    pub arg: String,
    pub line: u32,
    pub col: u32,
}

/// One step of the value's path from source to sink.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct TraceStep {
    /// Set when the step is in another file than the finding's source (inside a helper reached
    /// through a repo-wide summary).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub line: u32,
    pub col: u32,
    pub note: String,
}

/// Where an entry point is registered: the `app.post('/x', handler)` call.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct EntryLoc {
    pub file: String,
    pub line: u32,
}

/// How a stored value reached a finding whose source is `stored`: the request that saves it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct StoredBy {
    /// The entry point that saves it (`POST /profile`), when the inventory finds one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    /// The request data it saves (`req.body.username`).
    pub expr: String,
    /// Where it is saved.
    pub file: String,
    pub line: u32,
}

/// One candidate: a tainted value reaching a sink.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Finding {
    pub file: String,
    pub sink: SinkLoc,
    pub class: VulnClass,
    pub severity: Severity,
    /// Always `heuristic` in v0.
    pub confidence: &'static str,
    /// Authentication recognized on the path from the entry point.
    pub auth: Auth,
    /// Nearest enclosing named function, or `<anonymous>`.
    pub function: String,
    /// The entry point that reaches this function (`GET /api/files`), when the inventory finds
    /// one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    /// Where `entry` is registered, when it is a route the inventory located.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_at: Option<EntryLoc>,
    pub source: SourceLoc,
    /// For a `stored` source: the request that saves the value read here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_by: Option<StoredBy>,
    pub trace: Vec<TraceStep>,
    /// Line-independent identity: `class|file|function|sink api|source expr|ordinal`.
    pub key: String,
    /// A short stable hash of `key` (16 hex digits), for baselines and deduplication.
    pub fingerprint: String,
}

/// FNV-1a (64-bit) of `text`, as 16 hex digits: stable across runs, platforms and versions.
pub fn fingerprint(text: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Versioned semantic identity for cross-run/cross-version deduplication. Unlike `fingerprint`,
/// this intentionally excludes severity, authentication, line/column positions and scanner trace
/// wording. The legacy fingerprint remains the exact baseline and per-scan selector.
pub fn semantic_identity(finding: &Finding) -> String {
    fn normalized(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
    fn field(key: &mut String, value: &str) {
        use std::fmt::Write;
        let _ = write!(key, "{}:", value.len());
        key.push_str(value);
    }

    let mut key = String::from("jsspector.finding/1|");
    for value in [
        finding.class.name().to_owned(),
        finding.file.replace('\\', "/"),
        finding
            .entry
            .as_deref()
            .map(normalized)
            .unwrap_or_else(|| normalized(&finding.function)),
        finding.source.kind.to_owned(),
        normalized(&finding.source.expr),
        finding
            .sink
            .file
            .as_deref()
            .unwrap_or(&finding.file)
            .replace('\\', "/"),
        normalized(&finding.sink.api),
        normalized(&finding.sink.arg),
        finding
            .stored_by
            .as_ref()
            .and_then(|stored| stored.entry.as_deref())
            .map(normalized)
            .unwrap_or_default(),
        finding
            .stored_by
            .as_ref()
            .map(|stored| stored.file.replace('\\', "/"))
            .unwrap_or_default(),
        finding
            .stored_by
            .as_ref()
            .map(|stored| normalized(&stored.expr))
            .unwrap_or_default(),
    ] {
        field(&mut key, &value);
    }
    let digest = Sha256::digest(key.as_bytes());
    let mut encoded = String::with_capacity(5 + digest.len() * 2);
    encoded.push_str("jss1-");
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_stable() {
        assert_eq!(fingerprint(""), "cbf29ce484222325");
        assert_eq!(fingerprint("a"), "af63dc4c8601ec8c");
        assert_ne!(
            fingerprint("sql|a.js|f|db.query|req.query|0"),
            fingerprint("sql|a.js|f|db.query|req.query|1")
        );
    }

    fn finding() -> Finding {
        Finding {
            file: "routes/files.js".to_owned(),
            sink: SinkLoc {
                file: Some("lib/read.js".to_owned()),
                api: "fs.readFile".to_owned(),
                arg: "path.join(ROOT, req.params.name)".to_owned(),
                line: 40,
                col: 8,
            },
            class: VulnClass::PathTraversal,
            severity: Severity::High,
            confidence: "heuristic",
            auth: Auth::NoneDetected,
            function: "download".to_owned(),
            entry: Some("GET /files/{name}".to_owned()),
            entry_at: None,
            source: SourceLoc {
                kind: "http",
                expr: "req.params.name".to_owned(),
                line: 12,
                col: 4,
            },
            stored_by: None,
            trace: Vec::new(),
            key: String::new(),
            fingerprint: String::new(),
        }
    }

    #[test]
    fn semantic_identities_ignore_positions_risk_and_formatting() {
        let original = finding();
        let identity = semantic_identity(&original);
        assert_eq!(identity.len(), 69);
        assert!(identity.starts_with("jss1-"));

        let mut shifted = original.clone();
        shifted.source.line += 100;
        shifted.sink.line += 100;
        shifted.severity = Severity::Medium;
        shifted.auth = Auth::Admin;
        shifted.source.expr = "  req.params.name  ".to_owned();
        shifted.sink.arg = "path.join(ROOT,   req.params.name)".to_owned();
        assert_eq!(semantic_identity(&shifted), identity);

        shifted.sink.api = "fs.unlink".to_owned();
        assert_ne!(semantic_identity(&shifted), identity);

        let mut stored = original;
        stored.source.kind = "stored";
        stored.stored_by = Some(StoredBy {
            entry: Some("POST /profile".to_owned()),
            expr: "req.body.avatar".to_owned(),
            file: "routes/profile.js".to_owned(),
            line: 8,
        });
        let stored_identity = semantic_identity(&stored);
        stored.stored_by.as_mut().unwrap().file = "routes/admin.js".to_owned();
        assert_ne!(semantic_identity(&stored), stored_identity);
    }
}
