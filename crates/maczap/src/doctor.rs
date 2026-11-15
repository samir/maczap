//! `maczap doctor`: the preflight of DESIGN §2.

use std::path::Path;
use std::process::ExitCode;

use maczap_core::command::{self, DEFAULT_TIMEOUT};
use maczap_core::quarantine::Quarantine;

use crate::env::Env;
use crate::output::size;

const SW_VERS: &str = "/usr/bin/sw_vers";
const MDUTIL: &str = "/usr/bin/mdutil";

pub fn run(env: &Env) -> ExitCode {
    let mut problems = 0;
    let mut check = |ok: bool, label: &str, detail: String| {
        println!("{} {label}: {detail}", if ok { "ok  " } else { "WARN" });
        if !ok {
            problems += 1;
        }
    };

    let version = command::run(Path::new(SW_VERS), &["-productVersion"], DEFAULT_TIMEOUT)
        .map(|o| o.stdout.trim().to_string())
        .unwrap_or_default();
    let major: u32 = version
        .split('.')
        .next()
        .and_then(|m| m.parse().ok())
        .unwrap_or(0);
    check(
        major >= 13,
        "macOS",
        format!("{version} (13 or later is supported)"),
    );

    let terminal = std::env::var("TERM_PROGRAM").unwrap_or_else(|_| "your terminal".into());
    let fda = full_disk_access(env);
    check(
        fda,
        "Full Disk Access",
        if fda {
            format!("granted to {terminal}")
        } else {
            format!(
                "not granted to {terminal}: containers of other apps cannot be read. \
                 System Settings › Privacy & Security › Full Disk Access"
            )
        },
    );

    let spotlight = command::run(Path::new(MDUTIL), &["-s", "/"], DEFAULT_TIMEOUT)
        .map(|o| o.stdout.contains("Indexing enabled"))
        .unwrap_or(false);
    check(
        spotlight,
        "Spotlight",
        if spotlight {
            "indexing enabled".into()
        } else {
            "indexing disabled: app search falls back to folder walks".into()
        },
    );

    let brew = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        .into_iter()
        .find(|b| Path::new(b).exists());
    println!("info Homebrew: {}", brew.unwrap_or("not installed"));

    let quarantine_size = Quarantine::open_existing(&env.user_quarantine, false)
        .ok()
        .flatten()
        .and_then(|q| q.list().ok())
        .map(|l| l.batches.iter().map(|b| b.size_bytes).sum::<u64>())
        .unwrap_or(0);
    println!(
        "info quarantine: {} in {}",
        size(quarantine_size),
        crate::output::tilde(&env.user_quarantine, &env.home)
    );

    if problems == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(crate::ERROR)
    }
}

/// The system TCC database is only readable with Full Disk Access (spike 0001).
fn full_disk_access(env: &Env) -> bool {
    let db = env
        .system_root
        .join("Library/Application Support/com.apple.TCC/TCC.db");
    std::fs::File::open(db).is_ok()
}
