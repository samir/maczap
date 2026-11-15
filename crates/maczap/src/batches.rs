//! `list`, `restore` and `purge`.

use std::path::Path;
use std::process::ExitCode;

use maczap_core::manifest::BatchState;
use maczap_core::quarantine::{
    BatchSummary, PurgeSelector, Quarantine, RestoreOptions, RestoreReport,
};
use serde::Serialize;

use crate::env::Env;
use crate::output::{size, tilde};
use crate::{ABORTED, ERROR, PARTIAL, fail};

#[derive(Serialize)]
struct ListedBatch<'a> {
    scope: &'static str,
    #[serde(flatten)]
    batch: &'a BatchSummary,
}

/// The user quarantine, if it exists. These commands never create it.
fn open_user(env: &Env) -> Result<Option<Quarantine>, ExitCode> {
    Quarantine::open_existing(&env.user_quarantine, false).map_err(|e| fail(ERROR, e))
}

/// The system quarantine, if it exists (never created from a user process).
fn system(env: &Env) -> Option<Quarantine> {
    Quarantine::open_existing(&env.system_quarantine, true)
        .ok()
        .flatten()
}

pub fn list(env: &Env, json: bool) -> ExitCode {
    let user = match open_user(env) {
        Ok(q) => q,
        Err(code) => return code,
    };
    let user_listing = match user.map(|q| q.list()).transpose() {
        Ok(l) => l.unwrap_or_default(),
        Err(e) => return fail(ERROR, e),
    };
    let system_listing = system(env).and_then(|q| q.list().ok()).unwrap_or_default();
    let mut all: Vec<ListedBatch> = user_listing
        .batches
        .iter()
        .map(|b| ListedBatch {
            scope: "user",
            batch: b,
        })
        .chain(system_listing.batches.iter().map(|b| ListedBatch {
            scope: "system",
            batch: b,
        }))
        .collect();
    all.sort_by_key(|a| a.batch.created_at);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&all).expect("serializable")
        );
        return ExitCode::SUCCESS;
    }
    if all.is_empty() {
        println!("The quarantine is empty.");
        return ExitCode::SUCCESS;
    }
    let now = jiff::Timestamp::now();
    let mut total = 0;
    println!(
        "{:<34} {:<7} {:<10} {:>6} {:>9}  APP",
        "BATCH", "SCOPE", "STATE", "ITEMS", "SIZE"
    );
    for entry in &all {
        let b = entry.batch;
        total += b.size_bytes;
        let age_days = (now.as_duration() - b.created_at.as_duration()).as_hours() / 24;
        println!(
            "{:<34} {:<7} {:<10} {:>6} {:>9}  {} ({}){}",
            b.id,
            entry.scope,
            state(b.state),
            b.moved,
            size(b.size_bytes),
            b.app.name,
            b.app.bundle_id,
            if age_days >= 30 {
                format!(" — {age_days} days old")
            } else {
                String::new()
            }
        );
    }
    println!("\nTotal in quarantine: {}.", size(total));
    for bad in user_listing
        .unreadable
        .iter()
        .chain(&system_listing.unreadable)
    {
        println!("unreadable batch: {}", tilde(bad, &env.home));
    }
    ExitCode::SUCCESS
}

fn state(s: BatchState) -> &'static str {
    match s {
        BatchState::Open => "open",
        BatchState::Closed => "closed",
        BatchState::Restored => "restored",
        BatchState::PartiallyRestored => "partial",
    }
}

pub fn print_restore_report(report: &RestoreReport, home: &Path) {
    for p in &report.restored {
        println!("restored  {}", tilde(p, home));
    }
    for (p, to) in &report.displaced {
        println!("displaced {} → {}", tilde(p, home), tilde(to, home));
    }
    for p in &report.conflicts {
        println!(
            "conflict  {} already exists (use --overwrite)",
            tilde(p, home)
        );
    }
    for (p, why) in &report.failures {
        println!("failed    {}: {why}", tilde(p, home));
    }
    for a in &report.irreversible {
        println!("not undone: {:?} {}", a.kind, a.target);
    }
}

pub fn restore(env: &Env, id: &str, overwrite: bool) -> ExitCode {
    let user = match open_user(env) {
        Ok(q) => q,
        Err(code) => return code,
    };
    let system_quarantine = system(env);
    // The id may name the user batch or the system batch of an uninstall.
    let (user_id, system_id) = match user
        .as_ref()
        .map_or_else(|| Err(()), |q| q.load(id).map_err(|_| ()))
    {
        Ok(m) => (Some(id.to_string()), m.linked_batch),
        Err(_) => match system_quarantine.as_ref().and_then(|q| q.load(id).ok()) {
            Some(m) => (m.linked_batch, Some(id.to_string())),
            None => return fail(ERROR, format!("no quarantine batch named `{id}`")),
        },
    };
    let mut complete = true;
    if let Some(system_id) = &system_id
        && system_quarantine
            .as_ref()
            .is_some_and(|q| q.load(system_id).is_ok())
    {
        println!("Restoring system items (batch {system_id}); administrator privileges needed.");
        match crate::privileged::restore_system(env, system_id, overwrite) {
            Ok(ok) => complete &= ok,
            Err(e) => {
                eprintln!("maczap: {e}");
                complete = false;
            }
        }
    }
    if let Some((user, user_id)) = user
        .as_ref()
        .zip(user_id)
        .filter(|(q, u)| q.load(u).is_ok())
    {
        match user.restore(&user_id, RestoreOptions { overwrite }) {
            Ok(report) => {
                print_restore_report(&report, &env.home);
                complete &= report.conflicts.is_empty() && report.failures.is_empty();
            }
            Err(e) => return fail(ERROR, e),
        }
    }
    if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(PARTIAL)
    }
}

pub fn parse_age(text: &str) -> Result<jiff::SignedDuration, String> {
    let (number, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len()),
    );
    let n: i64 = number
        .parse()
        .map_err(|_| format!("`{text}`: expected a number followed by d, h or w"))?;
    let hours = match unit {
        "h" => n,
        "d" | "" => n * 24,
        "w" => n * 24 * 7,
        _ => return Err(format!("`{text}`: unknown unit `{unit}` (use h, d or w)")),
    };
    Ok(jiff::SignedDuration::from_hours(hours))
}

pub fn purge(
    env: &Env,
    ids: &[String],
    older_than: Option<&str>,
    all: bool,
    yes: bool,
) -> ExitCode {
    let user = match open_user(env) {
        Ok(q) => q,
        Err(code) => return code,
    };
    // System batches are root-owned: only a root run can delete them.
    let system = rustix::process::geteuid()
        .is_root()
        .then(|| system(env))
        .flatten();
    let quarantines: Vec<&Quarantine> = user.iter().chain(system.iter()).collect();

    let selectors: Vec<PurgeSelector> = match (ids.is_empty(), older_than, all) {
        (false, None, false) => {
            // Every id must exist somewhere before anything is deleted.
            let mut per = vec![Vec::new(); quarantines.len()];
            for id in ids {
                match quarantines.iter().position(|q| q.load(id).is_ok()) {
                    Some(n) => per[n].push(id.clone()),
                    None => return fail(ERROR, format!("no quarantine batch named `{id}`")),
                }
            }
            per.into_iter().map(PurgeSelector::Ids).collect()
        }
        (true, Some(age), false) => match parse_age(age) {
            Ok(age) => vec![PurgeSelector::OlderThan(age); quarantines.len()],
            Err(e) => return fail(ERROR, e),
        },
        (true, None, true) => vec![PurgeSelector::All; quarantines.len()],
        _ => {
            return fail(
                ERROR,
                "give batch ids, or --older-than, or --all (exactly one)",
            );
        }
    };
    if quarantines.is_empty() {
        println!("The quarantine is empty.");
        return ExitCode::SUCCESS;
    }
    if !yes && !crate::confirm("Delete these batches permanently? This cannot be undone.") {
        return ExitCode::from(ABORTED);
    }
    let mut freed = 0;
    for (quarantine, selector) in quarantines.iter().zip(&selectors) {
        if matches!(selector, PurgeSelector::Ids(ids) if ids.is_empty()) {
            continue;
        }
        match quarantine.purge(selector, jiff::Timestamp::now()) {
            Ok(report) => {
                for id in &report.removed {
                    println!("deleted {id}");
                }
                freed += report.freed_bytes;
            }
            Err(e) => return fail(ERROR, e),
        }
    }
    println!("Freed {}.", size(freed));
    if system.is_none()
        && self::system(env).is_some_and(|q| q.list().is_ok_and(|l| !l.batches.is_empty()))
    {
        println!("System batches are kept; run `sudo maczap purge` to delete them.");
    }
    ExitCode::SUCCESS
}
