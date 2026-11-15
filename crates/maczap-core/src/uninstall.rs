//! Executes a plan in the order of DESIGN §4:
//!
//! 1. quit the app (abort if it keeps running) — nothing has changed yet;
//! 2. check that the bundle can be moved, and obtain root if needed — still nothing;
//! 3. reset TCC while LaunchServices still knows the ids, remove legacy login items,
//!    boot out user launch agents;
//! 4. the privileged step (root-owned items, daemons, receipts), with the bundle still
//!    in place so it can recompute its own plan;
//! 5. move user items, bundle first; a failed bundle move stops the run.

use std::path::{Path, PathBuf};
use std::time::Duration;

use jiff::Timestamp;
use plist::Value;
use rustix::fs::Access;

use crate::candidate::Category;
use crate::control::{Bootout, Control, PrivilegedStep, SystemRequest, SystemResult, TccReset};
use crate::identity::AppIdentity;
use crate::manifest::{ActionKind, AppInfo, IrreversibleAction, ItemStatus, Manifest};
use crate::plan::{Plan, PlanItem};
use crate::quarantine::{PurgeSelector, Quarantine, QuarantineError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Keep everything in the quarantine (restorable).
    Quarantine,
    /// Move user items to this Trash directory afterwards (not restorable by maczap).
    Trash(PathBuf),
    /// Delete the batch right after moving.
    Permanent,
}

#[derive(Debug)]
pub struct Request<'a> {
    pub identity: &'a AppIdentity,
    pub plan: &'a Plan,
    pub quarantine: &'a Quarantine,
    pub now: Timestamp,
    pub mode: Mode,
    pub quit_timeout: Duration,
    /// Names of legacy login items that belong to the app.
    pub legacy_login_items: Vec<String>,
    pub receipts: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum Abort {
    #[error("the app is still running (pid {0:?}); quit it and try again")]
    StillRunning(Vec<i32>),
    #[error("cannot obtain administrator privileges: {0}")]
    NotAuthorized(String),
    #[error("the application bundle cannot be moved: {0}")]
    BundleNotMovable(String),
    #[error(transparent)]
    Quarantine(#[from] QuarantineError),
}

#[derive(Debug)]
pub struct Outcome {
    pub manifest: Manifest,
    pub system: Option<SystemResult>,
    /// Items that could not be moved, with the reason.
    pub failures: Vec<(PathBuf, String)>,
    /// Items that were not attempted because the bundle could not be moved.
    pub skipped: Vec<PathBuf>,
    /// Problems after the move (trash/permanent post-processing).
    pub warnings: Vec<String>,
}

impl Outcome {
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty() && self.skipped.is_empty()
    }
}

const POLL: Duration = Duration::from_millis(200);

pub fn execute(
    req: &Request,
    control: &dyn Control,
    privileged: &dyn PrivilegedStep,
) -> Result<Outcome, Abort> {
    let identity = req.identity;
    let ids: Vec<&str> = std::iter::once(identity.bundle_id.as_str())
        .chain(identity.nested_ids.iter().map(String::as_str))
        .collect();

    // 1. Quit.
    quit(&ids, control, req.quit_timeout)?;

    // 2. Preconditions; nothing has changed before this point.
    let selected: Vec<&PlanItem> = req.plan.selected().filter(|i| i.verdict.is_ok()).collect();
    let (root_items, user_items): (Vec<&PlanItem>, Vec<&PlanItem>) =
        selected.iter().partition(|i| i.needs_root);
    if let Some(bundle) = user_items
        .iter()
        .find(|i| i.candidate.category == Category::AppBundle)
    {
        check_movable(&bundle.candidate.path).map_err(Abort::BundleNotMovable)?;
    }
    let needs_root = !root_items.is_empty() || !req.receipts.is_empty();
    if needs_root {
        privileged.authorize().map_err(Abort::NotAuthorized)?;
    }

    let mut batch = req.quarantine.begin(app_info(identity), req.now)?;

    // 3. System state that must change while the bundle is still in place.
    for id in &ids {
        match control.tcc_reset(id) {
            Ok(TccReset::Reset) => batch.record_action(action(ActionKind::TccReset, id, Ok(())))?,
            Ok(TccReset::NothingToReset) => {}
            Err(e) => batch.record_action(action(ActionKind::TccReset, id, Err(e)))?,
        }
    }
    for name in &req.legacy_login_items {
        let result = control.remove_legacy_login_item(name);
        batch.record_action(action(ActionKind::LoginItemRemoval, name, result))?;
    }
    for item in user_items
        .iter()
        .filter(|i| i.candidate.category == Category::LaunchAgent)
    {
        let label = launchd_label(&item.candidate.path);
        match control.bootout_user_agent(&label, &item.candidate.path) {
            Ok(Bootout::Unloaded) => {
                batch.record_action(action(ActionKind::LaunchctlBootout, &label, Ok(())))?
            }
            Ok(Bootout::NotLoaded) => {}
            Err(e) => batch.record_action(action(ActionKind::LaunchctlBootout, &label, Err(e)))?,
        }
    }

    let mut failures = Vec::new();
    let mut skipped = Vec::new();

    // 4. Privileged step.
    let mut system = None;
    let mut bundle_failed = false;
    if needs_root {
        let request = SystemRequest {
            bundle_id: identity.bundle_id.clone(),
            app_path: identity.path.clone(),
            paths: root_items
                .iter()
                .map(|i| i.candidate.path.clone())
                .collect(),
            forget_receipts: req.receipts.clone(),
            permanent: req.mode == Mode::Permanent,
            user_batch: batch.id().to_string(),
        };
        match privileged.apply(&request) {
            Ok(result) => {
                for (path, why) in result.failed.iter().chain(result.refused.iter()) {
                    failures.push((path.clone(), why.clone()));
                }
                for a in &result.actions {
                    batch.record_action(a.clone())?;
                }
                if let Some(id) = &result.batch_id {
                    batch.link(id)?;
                }
                system = Some(result);
            }
            Err(e) => {
                for path in &request.paths {
                    failures.push((path.clone(), format!("privileged step failed: {e}")));
                }
            }
        }
        bundle_failed = root_items.iter().any(|i| {
            i.candidate.category == Category::AppBundle
                && failures.iter().any(|(p, _)| p == &i.candidate.path)
        });
    }

    // 5. User items, bundle first.
    let mut ordered = user_items.clone();
    ordered.sort_by_key(|i| i.candidate.category != Category::AppBundle);
    for item in ordered {
        if bundle_failed {
            skipped.push(item.candidate.path.clone());
            continue;
        }
        let verified = item.verdict.clone().expect("filtered above");
        if let Err(e) = batch.admit(verified) {
            failures.push((item.candidate.path.clone(), e.to_string()));
            if item.candidate.category == Category::AppBundle {
                bundle_failed = true;
            }
        }
    }

    let manifest = batch.finish()?;
    let mut warnings = Vec::new();
    match &req.mode {
        Mode::Quarantine => {}
        Mode::Permanent => {
            if let Err(e) = req
                .quarantine
                .purge(&PurgeSelector::Ids(vec![manifest.id.clone()]), req.now)
            {
                warnings.push(format!("could not delete batch {}: {e}", manifest.id));
            }
        }
        Mode::Trash(trash) => warnings.extend(move_batch_to_trash(
            req.quarantine,
            &manifest,
            trash,
            req.now,
        )),
    }

    Ok(Outcome {
        manifest,
        system,
        failures,
        skipped,
        warnings,
    })
}

fn quit(ids: &[&str], control: &dyn Control, timeout: Duration) -> Result<(), Abort> {
    let mut pids = Vec::new();
    for id in ids {
        let running = control.running_pids(id);
        if !running.is_empty() {
            control.request_quit(id);
            pids.extend(running);
        }
    }
    if pids.is_empty() {
        return Ok(());
    }
    let mut waited = Duration::ZERO;
    loop {
        let alive: Vec<i32> = pids
            .iter()
            .copied()
            .filter(|p| control.is_alive(*p))
            .collect();
        if alive.is_empty() {
            return Ok(());
        }
        if waited >= timeout {
            return Err(Abort::StillRunning(alive));
        }
        control.wait(POLL);
        waited += POLL;
    }
}

/// The user process must be able to rename the bundle: write access to its parent
/// and, for a directory moving to another parent, to the bundle itself.
fn check_movable(bundle: &Path) -> Result<(), String> {
    let parent = bundle
        .parent()
        .ok_or("the bundle has no parent directory")?;
    rustix::fs::access(parent, Access::WRITE_OK)
        .map_err(|e| format!("no write access to {}: {e}", parent.display()))?;
    rustix::fs::access(bundle, Access::WRITE_OK)
        .map_err(|e| format!("no write access to {}: {e}", bundle.display()))?;
    Ok(())
}

/// The `Label` of a launchd plist, or its file stem when unreadable.
pub fn launchd_label(plist: &Path) -> String {
    Value::from_file(plist)
        .ok()
        .and_then(|v| v.into_dictionary())
        .and_then(|d| {
            d.get("Label")
                .and_then(Value::as_string)
                .map(str::to_string)
        })
        .unwrap_or_else(|| {
            plist
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
}

fn action(kind: ActionKind, target: &str, result: Result<(), String>) -> IrreversibleAction {
    IrreversibleAction {
        kind,
        target: target.to_string(),
        before: None,
        succeeded: result.is_ok(),
        error: result.err(),
    }
}

pub fn app_info(identity: &AppIdentity) -> AppInfo {
    AppInfo {
        name: identity.name.clone(),
        bundle_id: identity.bundle_id.clone(),
        team_id: identity.team_id.clone(),
        version: identity.version.clone(),
        path: identity.path.clone(),
    }
}

/// Moves every moved item of a batch into the Trash (unique names), then deletes the
/// batch. Items that cannot be moved stay in the batch, which is then kept.
fn move_batch_to_trash(
    quarantine: &Quarantine,
    manifest: &Manifest,
    trash: &Path,
    now: Timestamp,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Err(e) = std::fs::create_dir_all(trash) {
        return vec![format!(
            "cannot create {}: {e}; items stay in batch {}",
            trash.display(),
            manifest.id
        )];
    }
    for item in manifest
        .items
        .iter()
        .filter(|i| i.status == ItemStatus::Moved)
    {
        let Some(name) = item.quarantine_path.file_name() else {
            continue;
        };
        let mut target = trash.join(name);
        let mut n = 1;
        while std::fs::symlink_metadata(&target).is_ok() {
            n += 1;
            target = trash.join(format!("{} {n}", name.to_string_lossy()));
        }
        if let Err(e) = std::fs::rename(&item.quarantine_path, &target) {
            warnings.push(format!(
                "{} stays in batch {}: {e}",
                item.original_path.display(),
                manifest.id
            ));
        }
    }
    if warnings.is_empty()
        && let Err(e) = quarantine.purge(&PurgeSelector::Ids(vec![manifest.id.clone()]), now)
    {
        warnings.push(format!("could not delete batch {}: {e}", manifest.id));
    }
    warnings
}
