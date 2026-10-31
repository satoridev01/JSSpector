//! `jsspector` command-line interface.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use jss_frontend::{PackageType, parse_stats, source_type_for};

/// Exit codes, as defined in `docs/PLAN.md`: 0 = clean, 1 = findings at or above `--fail-on`
/// (once scanning exists), 2 = usage error, 3 = engine error.
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
    /// Parse a single file and print parser statistics as JSON (development aid).
    #[command(hide = true)]
    Parse {
        /// File to parse.
        path: PathBuf,
        /// Parse `.js`/`.ts` as ES modules, as if package.json had `"type": "module"`.
        #[arg(long)]
        esm: bool,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Parse { path, esm } => parse_one(&path, esm),
    }
}

fn parse_one(path: &Path, esm: bool) -> ExitCode {
    let package_type = if esm {
        PackageType::Module
    } else {
        PackageType::CommonJs
    };
    let Some(source_type) = source_type_for(path, package_type) else {
        eprintln!("jsspector: unsupported file type: {}", path.display());
        return ExitCode::from(EXIT_USAGE);
    };
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("jsspector: cannot read {}: {err}", path.display());
            return ExitCode::from(EXIT_ENGINE);
        }
    };
    let Ok(source) = String::from_utf8(bytes) else {
        eprintln!("jsspector: {} is not valid UTF-8", path.display());
        return ExitCode::from(EXIT_ENGINE);
    };
    match serde_json::to_string(&parse_stats(&source, source_type)) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("jsspector: cannot serialize statistics: {err}");
            ExitCode::from(EXIT_ENGINE)
        }
    }
}
