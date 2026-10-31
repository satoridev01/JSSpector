//! `jsspector` command-line interface.

mod report;

use std::fmt::Display;
use std::io::{self, BufWriter, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Args, Parser, Subcommand};
use jss_core::{ClassSet, DiscoverError, DiscoverOptions, FileClass, PackageType};
use jss_frontend::ParsePool;

/// Exit codes, as defined in `docs/PLAN.md`: 0 = clean, 1 = findings at or above `--fail-on`
/// (once scanning exists), 2 = usage error, 3 = engine error (including IO errors on the root).
const EXIT_USAGE: u8 = 2;
const EXIT_ENGINE: u8 = 3;

#[derive(Parser)]
#[command(
    name = "jsspector",
    version,
    about = "Static analyzer for JavaScript/TypeScript: entry-point inventory and high/critical attack paths"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Discover and parse a file or directory, and print a JSON parse report (development aid).
    ///
    /// The report is deterministic: the same tree gives byte-identical output for any number
    /// of threads. Only the optional `stats` object varies. Files that fail to parse are
    /// diagnostics, not errors: the exit code is 0 unless the root itself is unusable.
    #[command(hide = true)]
    Parse(ParseArgs),
}

#[derive(Args)]
struct ParseArgs {
    /// File or directory to parse.
    path: PathBuf,
    /// Number of parser threads [default: all available cores, or RAYON_NUM_THREADS].
    #[arg(long, value_name = "N")]
    threads: Option<NonZeroUsize>,
    /// Also parse these file classes (source files always are): tests, examples, docs,
    /// generated, vendor, or all. Comma-separated. A single FILE is always parsed.
    #[arg(long, value_name = "CLASSES", value_delimiter = ',', value_parser = parse_include)]
    include: Vec<Include>,
    /// Add one record per discovered file to the report.
    #[arg(long)]
    list: bool,
    /// Add a `stats` object: wall time per phase, threads, peak memory, throughput.
    #[arg(long)]
    stats: bool,
    /// Parse a single FILE as an ES module, as if its package.json had "type": "module". (By
    /// default a single FILE follows the nearest package.json, searched up to the enclosing git
    /// work tree.)
    #[arg(long)]
    esm: bool,
}

/// One `--include` value.
#[derive(Debug, Clone, Copy)]
enum Include {
    All,
    Class(FileClass),
}

fn parse_include(value: &str) -> Result<Include, String> {
    if value.trim().eq_ignore_ascii_case("all") {
        return Ok(Include::All);
    }
    FileClass::from_name(value)
        .map(Include::Class)
        .ok_or_else(|| {
            format!(
                "unknown file class `{value}` (expected tests, examples, docs, generated, vendor, \
             source or all)"
            )
        })
}

/// The classes to parse: source, plus every `--include`.
fn include_set(includes: &[Include]) -> ClassSet {
    let mut set = ClassSet::default();
    for include in includes {
        match include {
            Include::All => set = ClassSet::ALL,
            Include::Class(class) => set.insert(*class),
        }
    }
    set
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Parse(args) => parse(&args),
    }
}

fn parse(args: &ParseArgs) -> ExitCode {
    let started = Instant::now();
    // One pool for everything, so --threads bounds discovery too.
    let pool = match ParsePool::new(args.threads) {
        Ok(pool) => pool,
        Err(err) => return fail(EXIT_ENGINE, err),
    };
    let discover_started = Instant::now();
    let discovered = pool.install(|| jss_core::discover(&args.path, &DiscoverOptions::default()));
    let mut discovery = match discovered {
        Ok(discovery) => discovery,
        Err(err @ DiscoverError::Io { .. }) => return fail(EXIT_ENGINE, err),
        Err(err) => return fail(EXIT_USAGE, err),
    };
    let discover_time = discover_started.elapsed();

    let selection = discovery.selection(include_set(&args.include));
    if args.esm {
        if !discovery.single_file {
            return fail(
                EXIT_USAGE,
                "--esm applies to a single file; in a directory, each file follows its nearest \
                 package.json \"type\"",
            );
        }
        for file in &mut discovery.files {
            file.package_type = PackageType::Module;
        }
    }

    // Every file gets a report: selected ones are parsed, the others classified.
    let parse_started = Instant::now();
    let reports = pool.process(&discovery.files, selection);
    let parse_time = parse_started.elapsed();

    let root = args.path.to_string_lossy().into_owned();
    let mut report = report::build(root, &discovery, selection, &reports, args.list);
    if args.stats {
        report.stats = Some(report::Stats::new(
            pool.threads(),
            started,
            discover_time,
            parse_time,
            &reports,
        ));
    }
    // Streamed, so the report is never held in memory as text.
    let mut out = BufWriter::new(io::stdout().lock());
    let written = serde_json::to_writer_pretty(&mut out, &report)
        .map_err(io::Error::from)
        .and_then(|()| writeln!(out))
        .and_then(|()| out.flush());
    if let Err(err) = written {
        return fail(EXIT_ENGINE, format!("cannot write the report: {err}"));
    }
    ExitCode::SUCCESS
}

/// Prints `jsspector: <message>` to stderr and returns `code`.
fn fail(code: u8, message: impl Display) -> ExitCode {
    let _ = writeln!(io::stderr(), "jsspector: {message}");
    ExitCode::from(code)
}
