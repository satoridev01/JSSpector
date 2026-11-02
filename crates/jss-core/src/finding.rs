//! Owned, serializable taint findings (the `scan` command's output).
//!
//! v0 findings come from a single-file, intra-procedural heuristic spike (see `jss-frontend`'s
//! `taint` module). Every finding is a candidate for hand triage, never a verdict.

use serde::Serialize;

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
}
