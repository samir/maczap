//! maczap — uninstall macOS apps completely and safely. See docs/DESIGN.md.

mod batches;
mod commands;
mod doctor;
mod env;
mod homebrew;
mod lock;
mod output;
mod privileged;
mod tui;

use std::fmt::Display;
use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Exit codes (DESIGN §2).
pub const ERROR: u8 = 1;
pub const PARTIAL: u8 = 2;
pub const ABORTED: u8 = 3;

pub fn fail(code: u8, message: impl Display) -> ExitCode {
    eprintln!("maczap: {message}");
    ExitCode::from(code)
}

/// Asks a yes/no question on the terminal. Anything but "y"/"yes" is a no, and so is
/// the absence of a terminal.
pub fn confirm(question: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[derive(Debug, Parser)]
#[command(
    name = "maczap",
    version,
    about = "Uninstall macOS apps completely and safely"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show everything an app left on this Mac. Read-only.
    Scan {
        /// App name, path to the .app, or bundle id.
        app: String,
        /// Print JSON.
        #[arg(long)]
        json: bool,
        /// Also select name-only (low-confidence) matches.
        #[arg(long)]
        include_low: bool,
        /// Also read login and background items (takes a few seconds).
        #[arg(long)]
        background_items: bool,
        /// Also use the Homebrew cask list from the internet (cached for a week).
        #[arg(long)]
        online: bool,
    },
    /// Quit an app and move it and its traces to the quarantine.
    Uninstall {
        /// App name, path to the .app, or bundle id.
        app: String,
        /// Show what would be removed, change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Do not ask for confirmation (several matching apps still abort).
        #[arg(long, short)]
        yes: bool,
        /// Print JSON.
        #[arg(long)]
        json: bool,
        /// Move user items to the Trash instead of the quarantine (no restore).
        #[arg(long, conflicts_with = "permanent")]
        trash: bool,
        /// Delete instead of quarantining (no restore).
        #[arg(long)]
        permanent: bool,
        /// Also remove name-only (low-confidence) matches.
        #[arg(long)]
        include_low: bool,
        /// Also use the Homebrew cask list from the internet (cached for a week).
        #[arg(long)]
        online: bool,
    },
    /// List quarantine batches.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Put the items of a batch back where they were.
    Restore {
        batch: String,
        /// Move whatever now occupies an original path aside first.
        #[arg(long)]
        overwrite: bool,
    },
    /// Delete quarantine batches permanently.
    Purge {
        batches: Vec<String>,
        /// Batches older than this (e.g. 30d, 12h, 2w).
        #[arg(long)]
        older_than: Option<String>,
        /// Every batch.
        #[arg(long)]
        all: bool,
        #[arg(long, short)]
        yes: bool,
    },
    /// Check permissions and environment.
    Doctor,
    #[command(name = "__apply-system", hide = true)]
    ApplySystem,
    #[command(name = "__restore-system", hide = true)]
    RestoreSystem {
        batch: String,
        #[arg(long)]
        overwrite: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Command::ApplySystem = cli.command {
        return match privileged::run_apply_system() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(ERROR, e),
        };
    }
    let env = match env::Env::detect() {
        Ok(env) => env,
        Err(e) => return fail(ERROR, e),
    };
    match cli.command {
        Command::Scan {
            app,
            json,
            include_low,
            background_items,
            online,
        } => commands::scan(&env, &app, json, include_low, background_items, online),
        Command::Uninstall {
            app,
            dry_run,
            yes,
            json,
            trash,
            permanent,
            include_low,
            online,
        } => {
            let args = commands::UninstallArgs {
                app,
                dry_run,
                yes,
                json,
                trash,
                permanent,
                include_low,
                online,
            };
            commands::uninstall(&env, &args)
        }
        Command::List { json } => batches::list(&env, json),
        Command::Restore { batch, overwrite } => batches::restore(&env, &batch, overwrite),
        Command::Purge {
            batches: ids,
            older_than,
            all,
            yes,
        } => batches::purge(&env, &ids, older_than.as_deref(), all, yes),
        Command::Doctor => doctor::run(&env),
        Command::RestoreSystem { batch, overwrite } => {
            match privileged::restore_system(&env, &batch, overwrite) {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::from(PARTIAL),
                Err(e) => fail(ERROR, e),
            }
        }
        Command::ApplySystem => unreachable!("handled above"),
    }
}
