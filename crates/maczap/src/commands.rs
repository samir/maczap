//! `scan` and `uninstall`.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use maczap_core::btm::BtmRecord;
use maczap_core::discovery::{self, Scan};
use maczap_core::identity::AppIdentity;
use maczap_core::mac::{MacControl, MacPlatform};
use maczap_core::plan::{Plan, PlanOptions};
use maczap_core::platform::Platform;
use maczap_core::quarantine::{Quarantine, measure};
use maczap_core::resolve::{Resolution, protection, resolve};
use maczap_core::uninstall::{Abort, Mode, Request, execute};
use serde::Serialize;

use crate::env::Env;
use crate::lock::Lock;
use crate::output::{plan_json, print_plan, size, tilde};
use crate::{ABORTED, ERROR, PARTIAL, fail};

#[derive(Debug, Clone, Default)]
pub struct UninstallArgs {
    pub app: String,
    pub dry_run: bool,
    pub yes: bool,
    pub json: bool,
    pub trash: bool,
    pub permanent: bool,
    pub include_low: bool,
    pub online: bool,
}

fn print_cask(cask: Option<&maczap_core::zap::Cask>) {
    if let Some(cask) = cask {
        let source = if cask.installed {
            "installed with Homebrew"
        } else {
            "known to the Homebrew API"
        };
        println!(
            "Homebrew cask: `{}` ({source}); its zap list is a curated source.",
            cask.token
        );
    }
}

/// Resolves the query to one app. Several matches are offered for a choice only when
/// a person is at the terminal; otherwise maczap aborts rather than guess.
fn resolve_app(
    query: &str,
    platform: &MacPlatform,
    interactive: bool,
) -> Result<PathBuf, ExitCode> {
    match resolve(query, platform) {
        Err(e) => Err(fail(ERROR, e)),
        Ok(Resolution::None) => Err(fail(ERROR, format!("no installed app matches `{query}`"))),
        Ok(Resolution::One(path)) => Ok(path),
        Ok(Resolution::Many(paths)) => {
            eprintln!("Several apps match `{query}`:");
            for (n, p) in paths.iter().enumerate() {
                eprintln!("  {}. {}", n + 1, p.display());
            }
            if !interactive {
                return Err(fail(
                    ABORTED,
                    "ambiguous app; pass the full path of the one to use",
                ));
            }
            eprint!("Which one? [1-{}] ", paths.len());
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            let _ = std::io::stdin().lock().read_line(&mut line);
            match line.trim().parse::<usize>() {
                Ok(n) if (1..=paths.len()).contains(&n) => Ok(paths[n - 1].clone()),
                _ => Err(fail(ABORTED, "no app chosen")),
            }
        }
    }
}

struct Prepared {
    scan: Scan,
    plan: Plan,
    sizes: Vec<u64>,
    /// The Homebrew cask of the app, if any.
    cask: Option<maczap_core::zap::Cask>,
}

struct Options {
    include_low: bool,
    interactive: bool,
    online: bool,
}

fn prepare(
    env: &Env,
    platform: &MacPlatform,
    query: &str,
    options: Options,
) -> Result<Prepared, ExitCode> {
    let casks = crate::homebrew::read(env, options.online);
    let path = resolve_app(query, platform, options.interactive)?;
    let identity = AppIdentity::read(&path, platform).map_err(|e| fail(ERROR, e))?;
    protection(&identity, &env.system_root).map_err(|e| fail(ABORTED, e))?;
    let catalog = env.catalog();
    let mut scan = discovery::scan(&identity, &catalog, platform);
    let mut cask = None;
    if let Some(casks) = casks.and_then(|h| h.join().ok()) {
        for w in &casks.warnings {
            eprintln!("maczap: {w}");
        }
        if let Some(found) = casks.lookup(&identity) {
            scan.merge(maczap_core::zap::candidates(found, &catalog));
            cask = Some(found.clone());
        }
    }
    let include_low = options.include_low;
    let guard = env.guard().map_err(|e| fail(ERROR, e))?;
    let plan = Plan::new(&scan, &guard, PlanOptions { include_low }, env.uid);
    let sizes = plan
        .items
        .iter()
        .map(|i| measure(&i.candidate.path).0)
        .collect();
    Ok(Prepared {
        scan,
        plan,
        sizes,
        cask,
    })
}

/// Reading Background Task Management takes several seconds (`sfltool dumpbtm`), so
/// it runs on its own thread while the rest of the work goes on.
fn read_background_items(env: &Env) -> std::thread::JoinHandle<Vec<BtmRecord>> {
    let hermetic = env.hermetic;
    std::thread::spawn(move || {
        if hermetic {
            Vec::new()
        } else {
            MacPlatform::default().btm_records()
        }
    })
}

fn merge_background_items(scan: &mut Scan, records: &[BtmRecord]) {
    let found = discovery::background_items(&scan.identity, records);
    scan.report_only.extend(found.report);
    scan.legacy_login_items = found.legacy_login_items;
}

pub fn scan(
    env: &Env,
    query: &str,
    json: bool,
    include_low: bool,
    background_items: bool,
    online: bool,
) -> ExitCode {
    let platform = env.platform();
    let interactive = !json && std::io::stdin().is_terminal();
    let btm = background_items.then(|| read_background_items(env));
    let mut p = match prepare(
        env,
        &platform,
        query,
        Options {
            include_low,
            interactive,
            online,
        },
    ) {
        Ok(p) => p,
        Err(code) => return code,
    };
    if let Some(btm) = btm {
        merge_background_items(&mut p.scan, &btm.join().unwrap_or_default());
    } else if !json {
        println!(
            "(background items not checked; add --background-items, it takes a few seconds)\n"
        );
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&plan_json(
                &p.scan,
                &p.plan,
                &p.sizes,
                p.cask.as_ref().map(|c| c.token.as_str())
            ))
            .expect("serializable")
        );
    } else {
        print_plan(&p.scan, &p.plan, &p.sizes, &env.home);
        print_cask(p.cask.as_ref());
    }
    ExitCode::SUCCESS
}

#[derive(Serialize)]
struct UninstallJson {
    batch: String,
    system_batch: Option<String>,
    moved: usize,
    failures: Vec<(PathBuf, String)>,
    skipped: Vec<PathBuf>,
    warnings: Vec<String>,
    complete: bool,
}

pub fn uninstall(env: &Env, args: &UninstallArgs) -> ExitCode {
    let _lock = match Lock::acquire(&env.state_dir) {
        Ok(lock) => lock,
        Err(e) => return fail(ERROR, e),
    };
    let platform = env.platform();
    let interactive = !args.yes && !args.json && std::io::stdin().is_terminal();
    let btm = read_background_items(env);
    let options = Options {
        include_low: args.include_low,
        interactive,
        online: args.online,
    };
    let mut p = match prepare(env, &platform, &args.app, options) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let mut btm = Some(btm);
    let mut join_btm = |p: &mut Prepared| {
        if let Some(handle) = btm.take() {
            merge_background_items(&mut p.scan, &handle.join().unwrap_or_default());
        }
    };

    if args.dry_run {
        join_btm(&mut p);
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&plan_json(
                    &p.scan,
                    &p.plan,
                    &p.sizes,
                    p.cask.as_ref().map(|c| c.token.as_str())
                ))
                .expect("serializable")
            );
        } else {
            print_plan(&p.scan, &p.plan, &p.sizes, &env.home);
            println!("\nDry run: nothing was changed.");
        }
        return ExitCode::SUCCESS;
    }
    if p.plan.selected().next().is_none() {
        return fail(ABORTED, "nothing is selected");
    }
    let mode = if args.permanent {
        Mode::Permanent
    } else if args.trash {
        Mode::Trash(env.trash.clone())
    } else {
        Mode::Quarantine
    };
    if let Some(cask) = p.cask.as_ref().filter(|c| c.installed)
        && interactive
        && let Some(brew) = crate::homebrew::brew()
    {
        let question = format!(
            "{} was installed with Homebrew (cask `{}`). Let Homebrew remove it with \
             `brew uninstall --zap --cask {}` instead?",
            p.scan.identity.name, cask.token, cask.token
        );
        if crate::confirm(&question) {
            let status = std::process::Command::new(brew)
                .args(["uninstall", "--zap", "--cask", &cask.token])
                .status();
            return match status {
                Ok(s) if s.success() => ExitCode::SUCCESS,
                Ok(s) => fail(ERROR, format!("brew exited with {s}")),
                Err(e) => fail(ERROR, format!("cannot run brew: {e}")),
            };
        }
    }

    if !args.yes {
        if !interactive {
            return fail(
                ABORTED,
                "not running in a terminal: review with --dry-run, then pass --yes",
            );
        }
        let id = &p.scan.identity;
        let title = format!(
            "{} {} ({}){}",
            id.name,
            id.version.as_deref().unwrap_or(""),
            id.bundle_id,
            id.team_id
                .as_deref()
                .map(|t| format!(", Team ID {t}"))
                .unwrap_or_default()
        );
        let action = match mode {
            Mode::Quarantine => "quit the app and move the selection to the quarantine",
            Mode::Trash(_) => "quit the app and move the selection to the Trash",
            Mode::Permanent => "quit the app and DELETE the selection permanently",
        };
        let notes = p
            .scan
            .not_checked
            .iter()
            .map(|n| {
                format!(
                    "not checked: {} (grant Full Disk Access)",
                    tilde(&n.path, &env.home)
                )
            })
            .chain(
                p.scan
                    .report_only
                    .iter()
                    .map(|r| format!("not removed: {}", tilde(&r.path, &env.home))),
            )
            .collect();
        let selector = crate::tui::Selector::from_plan(
            title,
            action.into(),
            &p.plan,
            &p.sizes,
            &env.home,
            notes,
        );
        match crate::tui::run(selector) {
            Ok(Some(selection)) => {
                for (index, selected) in selection.into_iter().enumerate() {
                    p.plan.set_selected(index, selected);
                }
            }
            Ok(None) => return ExitCode::from(ABORTED),
            Err(e) => return fail(ERROR, format!("cannot open the selection screen: {e}")),
        }
        for r in &p.scan.report_only {
            println!("not removed: {} — {}", tilde(&r.path, &env.home), r.detail);
        }
    }

    join_btm(&mut p);
    for item in &p.scan.legacy_login_items {
        println!("Login item `{item}` will be removed.");
    }
    let quarantine = match Quarantine::open(&env.user_quarantine) {
        Ok(q) => q,
        Err(e) => return fail(ERROR, e),
    };
    let request = Request {
        identity: &p.scan.identity,
        plan: &p.plan,
        quarantine: &quarantine,
        now: jiff::Timestamp::now(),
        mode: mode.clone(),
        quit_timeout: Duration::from_secs(10),
        legacy_login_items: p.scan.legacy_login_items.clone(),
        receipts: p.scan.receipts.clone(),
    };
    let privileged = crate::privileged::Sudo { interactive };
    let outcome = match execute(&request, &MacControl, &privileged) {
        Ok(outcome) => outcome,
        Err(
            abort @ (Abort::StillRunning(_) | Abort::NotAuthorized(_) | Abort::BundleNotMovable(_)),
        ) => {
            return fail(ABORTED, format!("{abort}. Nothing was changed."));
        }
        Err(e) => return fail(ERROR, e),
    };

    let complete = outcome.is_complete();
    let system_batch = outcome.system.as_ref().and_then(|s| s.batch_id.clone());
    if args.json {
        let body = UninstallJson {
            batch: outcome.manifest.id.clone(),
            system_batch,
            moved: outcome.manifest.moved_count()
                + outcome.system.as_ref().map_or(0, |s| s.moved.len()),
            failures: outcome.failures.clone(),
            skipped: outcome.skipped.clone(),
            warnings: outcome.warnings.clone(),
            complete,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&body).expect("serializable")
        );
    } else {
        let moved =
            outcome.manifest.moved_count() + outcome.system.as_ref().map_or(0, |s| s.moved.len());
        println!(
            "\nRemoved {moved} item(s), {}.",
            size(outcome.manifest.total_size())
        );
        for (path, why) in &outcome.failures {
            println!("failed:  {} — {why}", tilde(path, &env.home));
        }
        for path in &outcome.skipped {
            println!("skipped: {}", tilde(path, &env.home));
        }
        for w in &outcome.warnings {
            println!("warning: {w}");
        }
        if let Some(cask) = p.cask.as_ref().filter(|c| c.installed) {
            println!(
                "Homebrew still lists cask `{}`; run `brew uninstall --cask --force {}` to update its records.",
                cask.token, cask.token
            );
        }
        match mode {
            Mode::Quarantine => println!("Undo with: maczap restore {}", outcome.manifest.id),
            Mode::Trash(_) => println!("User items are in the Trash."),
            Mode::Permanent => println!("Items were deleted permanently."),
        }
    }
    if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(PARTIAL)
    }
}
