//! jss-frontend: the only JSSpector crate that depends on oxc.
//!
//! Everything oxc-specific (parsing, semantic analysis, lowering to JSSpector's owned IR) lives
//! here, so oxc's frequent breaking releases stay contained in one crate. The rest of the
//! workspace only ever sees owned, lifetime-free data.
//!
//! - [`source_type`] / [`source_type_for`] / [`parse_stats`]: oxc source types and parsing.
//! - [`process_files`] / [`ParsePool`]: parallel, panic-isolated processing of discovered files.

mod parse;
mod process;

pub use jss_core::PackageType;
pub use parse::{ParseStats, parse_stats, source_type, source_type_for};
pub use process::{
    FileReport, FileStatus, ParsePool, PoolError, ProcessOptions, WORKER_STACK_BYTES, process_file,
    process_files,
};
