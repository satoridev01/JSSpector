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
    pub line: u32,
    pub col: u32,
    pub note: String,
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
    /// Always `unknown` in v0: entry points and middleware are not modeled yet.
    pub auth: &'static str,
    /// Nearest enclosing named function, or `<anonymous>`.
    pub function: String,
    pub source: SourceLoc,
    pub trace: Vec<TraceStep>,
    /// Line-independent identity: `class|file|function|sink api|source expr|ordinal`.
    pub key: String,
}
