//! JSSpector analysis core.
//!
//! Will host the owned IR, module linking, value flow, symbolic summaries, taint, entry points,
//! attack-path chaining and reports (see `docs/PLAN.md`). It must never depend on oxc directly:
//! everything oxc-specific lives in `jss-frontend`.
//!
//! Today it holds the pipeline's first step and the pieces every later step shares:
//! - [`mod@discover`]: file discovery, contained to the scan root, sorted, plus what each file
//!   needs for a given selection of classes ([`Work`]);
//! - [`classify`]: the single classifier (source, test, docs, example, generated, vendor);
//! - [`content`]: pre-parse checks on file bytes (size, UTF-8, minified, nesting depth);
//! - [`package_type`]: the nearest `package.json` `"type"`;
//! - [`line_index`]: byte offset to line and UTF-16 column;
//! - [`diag`]: structured diagnostics with stable codes.

pub mod classify;
pub mod content;
pub mod diag;
pub mod discover;
pub mod finding;
pub mod line_index;
pub mod package_type;

pub use classify::{ClassSet, FileClass};
pub use diag::{DiagCode, Diagnostic, SkipReason};
pub use discover::{
    DiscoverError, DiscoverOptions, Discovery, SourceFile, SourceKind, Work, discover,
    rel_path_string,
};
pub use finding::{Auth, Finding, Severity, SinkLoc, SourceLoc, TraceStep, VulnClass};
pub use line_index::{LineCol, LineIndex};
pub use package_type::PackageType;
