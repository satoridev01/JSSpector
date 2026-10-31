//! JSSpector analysis core.
//!
//! Will host the owned IR, module linking, value flow, symbolic summaries, taint, entry points,
//! attack-path chaining and reports (see `docs/PLAN.md`). It must never depend on oxc directly:
//! everything oxc-specific lives in `jss-frontend`.
