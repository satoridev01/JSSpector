//! jss-frontend: the only JSSpector crate that depends on oxc.
//!
//! Everything oxc-specific (parsing, semantic analysis, lowering to JSSpector's owned IR) lives
//! here, so oxc's frequent breaking releases stay contained in one crate. The rest of the
//! workspace only ever sees owned, lifetime-free data.
//!
//! - [`ParsePool`]: the entry point. Parallel, panic-isolated processing of discovered files on
//!   workers whose parser always has a large enough stack.
//! - [`source_type`] / [`typed_fallbacks`]: how each kind of file is parsed.

mod parse;
mod process;

pub use jss_core::PackageType;
pub use parse::{source_type, typed_fallbacks};
pub use process::{
    FileReport, FileStatus, ParsePool, PoolError, STACK_BASE, STACK_PER_BRACKET_BYTE,
    STACK_PER_BYTE, WORKER_STACK_BYTES, parser_stack_bound,
};
