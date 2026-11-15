//! The privileged step (DESIGN §5.3).
//!
//! The user process runs `sudo -v` once, then `sudo -n <maczap> __apply-system` with a
//! `SystemRequest` on stdin. The root process trusts nothing in the request except as
//! a *selection*: it re-reads the app, recomputes its own plan, and acts only on
//! requested paths that are in that plan and pass the guard.

use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use maczap_core::candidate::Category;
use maczap_core::command::{self, DEFAULT_TIMEOUT};
use maczap_core::control::{PrivilegedStep, SystemRequest, SystemResult};
use maczap_core::discovery::{self, Scan};
use maczap_core::guard::Verified;
use maczap_core::identity::AppIdentity;
use maczap_core::manifest::{ActionKind, IrreversibleAction};
use maczap_core::plan::{Plan, PlanOptions};
use maczap_core::quarantine::{PurgeSelector, Quarantine, RestoreOptions};
use maczap_core::resolve::protection;
use maczap_core::uninstall::{app_info, launchd_label};

use crate::env::Env;

const SUDO: &str = "/usr/bin/sudo";
const LAUNCHCTL: &str = "/bin/launchctl";
const PKGUTIL: &str = "/usr/sbin/pkgutil";
const DSCL: &str = "/usr/bin/dscl";

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// The user side.
#[derive(Debug)]
pub struct Sudo {
    pub interactive: bool,
}

impl PrivilegedStep for Sudo {
    fn authorize(&self) -> Result<(), String> {
        if is_root() {
            return Ok(());
        }
        let mut cmd = Command::new(SUDO);
        if self.interactive && std::io::stdin().is_terminal() {
            eprintln!("maczap needs administrator privileges for items owned by the system.");
            cmd.args(["-v", "-p", "Password for %u: "]);
        } else {
            cmd.args(["-n", "-v"]);
        }
        let status = cmd.status().map_err(|e| format!("cannot run sudo: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err("sudo did not grant administrator privileges".into())
        }
    }

    fn apply(&self, request: &SystemRequest) -> Result<SystemResult, String> {
        if is_root() {
            return apply_system(request);
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut child = Command::new(SUDO)
            .arg("-n")
            .arg(&exe)
            .arg("__apply-system")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot run sudo: {e}"))?;
        let body = serde_json::to_vec(request).map_err(|e| e.to_string())?;
        child
            .stdin
            .take()
            .expect("piped")
            .write_all(&body)
            .map_err(|e| e.to_string())?;
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("piped")
            .read_to_string(&mut out)
            .map_err(|e| e.to_string())?;
        let status = child.wait().map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("the privileged step failed ({status})"));
        }
        serde_json::from_str(&out)
            .map_err(|e| format!("unreadable reply from the privileged step: {e}"))
    }
}

/// `maczap __apply-system`: the root side. Reads a `SystemRequest` from stdin and
/// writes a `SystemResult` to stdout.
pub fn run_apply_system() -> Result<(), String> {
    if !is_root() {
        return Err("__apply-system must run as root".into());
    }
    let mut body = String::new();
    std::io::stdin()
        .read_to_string(&mut body)
        .map_err(|e| e.to_string())?;
    let request: SystemRequest =
        serde_json::from_str(&body).map_err(|e| format!("bad request: {e}"))?;
    let result = apply_system(&request)?;
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn invoking_user() -> Result<(u32, PathBuf), String> {
    let uid: u32 = std::env::var("SUDO_UID")
        .ok()
        .and_then(|u| u.parse().ok())
        .unwrap_or_else(|| rustix::process::getuid().as_raw());
    let user = std::env::var("SUDO_USER").map_err(|_| "SUDO_USER is not set".to_string())?;
    if user.is_empty() || user.contains('/') {
        return Err(format!("invalid SUDO_USER `{user}`"));
    }
    let record = format!("/Users/{user}");
    let out = command::run(
        Path::new(DSCL),
        &[".", "-read", record.as_str(), "NFSHomeDirectory"],
        DEFAULT_TIMEOUT,
    )
    .map_err(|e| e.to_string())?;
    let home = out
        .stdout
        .split_whitespace()
        .last()
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| format!("cannot find the home directory of `{user}`"))?;
    Ok((uid, home))
}

/// What the root side accepts from a request.
pub(crate) struct Selection {
    pub identity: AppIdentity,
    pub scan: Scan,
    pub accepted: Vec<(Verified, Category)>,
    pub refused: Vec<(PathBuf, String)>,
}

/// The security-critical part of the root side: recompute maczap's own plan for the
/// app and split the requested paths into accepted (in that plan and approved by the
/// guard) and refused.
pub(crate) fn select_requested(env: &Env, request: &SystemRequest) -> Result<Selection, String> {
    let platform = env.platform();
    let identity = AppIdentity::read(&request.app_path, &platform).map_err(|e| e.to_string())?;
    if identity.bundle_id != request.bundle_id {
        return Err(format!(
            "{} is `{}`, not `{}`",
            request.app_path.display(),
            identity.bundle_id,
            request.bundle_id
        ));
    }
    protection(&identity, &env.system_root).map_err(|e| e.to_string())?;

    // Low-confidence items count as plannable: the user may have opted in.
    let scan = discovery::scan(&identity, &env.catalog(), &platform);
    let guard = env.guard().map_err(|e| e.to_string())?;
    let plan = Plan::new(&scan, &guard, PlanOptions { include_low: true }, 0);
    let plannable: HashMap<&Path, (Verified, Category)> = plan
        .items
        .iter()
        .filter_map(|i| {
            i.verdict.as_ref().ok().map(|v| {
                (
                    i.candidate.path.as_path(),
                    (v.clone(), i.candidate.category),
                )
            })
        })
        .collect();
    let mut accepted = Vec::new();
    let mut refused = Vec::new();
    for path in &request.paths {
        match plannable.get(path.as_path()) {
            Some(entry)
                if !accepted
                    .iter()
                    .any(|(v, _): &(Verified, Category)| v.path() == path) =>
            {
                accepted.push(entry.clone())
            }
            Some(_) => {}
            None => refused.push((
                path.clone(),
                format!("not in maczap's own plan for {}", identity.bundle_id),
            )),
        }
    }
    Ok(Selection {
        identity,
        scan,
        accepted,
        refused,
    })
}

fn apply_system(request: &SystemRequest) -> Result<SystemResult, String> {
    let (uid, home) = invoking_user()?;
    let env = Env::new(home, PathBuf::from("/"), uid, None, None);
    let Selection {
        identity,
        scan,
        mut accepted,
        refused,
    } = select_requested(&env, request)?;
    let mut result = SystemResult {
        refused,
        ..Default::default()
    };

    // Unload jobs before their plists move.
    for (verified, category) in &accepted {
        let domain = match category {
            Category::LaunchDaemon => "system".to_string(),
            Category::LaunchAgent => format!("gui/{uid}"),
            _ => continue,
        };
        let label = launchd_label(verified.path());
        let target = format!("{domain}/{label}");
        match command::run(
            Path::new(LAUNCHCTL),
            &["bootout", target.as_str()],
            DEFAULT_TIMEOUT,
        ) {
            Ok(out) if out.success() => {
                result
                    .actions
                    .push(action(ActionKind::LaunchctlBootout, &target, None, Ok(())))
            }
            Ok(out) if matches!(out.code(), Some(3) | Some(113)) => {}
            Ok(out) => result.actions.push(action(
                ActionKind::LaunchctlBootout,
                &target,
                None,
                Err(out.stderr.trim().to_string()),
            )),
            Err(e) => result.actions.push(action(
                ActionKind::LaunchctlBootout,
                &target,
                None,
                Err(e.to_string()),
            )),
        }
    }

    let quarantine = Quarantine::open_shared(&env.system_quarantine).map_err(|e| e.to_string())?;
    let mut batch = quarantine
        .begin(app_info(&identity), jiff::Timestamp::now())
        .map_err(|e| e.to_string())?;
    batch.link(&request.user_batch).map_err(|e| e.to_string())?;
    // Bundle first: if it cannot move, nothing else moves.
    accepted.sort_by_key(|(_, category)| *category != Category::AppBundle);
    let mut bundle_failed = false;
    for (verified, category) in accepted {
        let path = verified.path().to_path_buf();
        if bundle_failed {
            result.failed.push((
                path,
                "not attempted: the application bundle could not be moved".into(),
            ));
            continue;
        }
        match batch.admit(verified) {
            Ok(_) => result.moved.push(path),
            Err(e) => {
                bundle_failed |= category == Category::AppBundle;
                result.failed.push((path, e.to_string()));
            }
        }
    }

    if !bundle_failed {
        for pkg in request
            .forget_receipts
            .iter()
            .filter(|p| scan.receipts.contains(p))
        {
            let before = command::run(
                Path::new(PKGUTIL),
                &["--pkg-info", pkg.as_str()],
                DEFAULT_TIMEOUT,
            )
            .ok()
            .map(|o| o.stdout);
            let outcome = command::run(
                Path::new(PKGUTIL),
                &["--forget", pkg.as_str()],
                DEFAULT_TIMEOUT,
            )
            .map_err(|e| e.to_string())
            .and_then(|o| {
                if o.success() {
                    Ok(())
                } else {
                    Err(o.stderr.trim().to_string())
                }
            });
            let a = action(ActionKind::PkgutilForget, pkg, before, outcome);
            result.actions.push(a);
        }
    }
    for a in &result.actions {
        batch.record_action(a.clone()).map_err(|e| e.to_string())?;
    }
    let manifest = batch.finish().map_err(|e| e.to_string())?;
    result.batch_id = Some(manifest.id.clone());
    if request.permanent {
        quarantine
            .purge(
                &PurgeSelector::Ids(vec![manifest.id]),
                jiff::Timestamp::now(),
            )
            .map_err(|e| e.to_string())?;
        result.batch_id = None;
    }
    Ok(result)
}

fn action(
    kind: ActionKind,
    target: &str,
    before: Option<String>,
    result: Result<(), String>,
) -> IrreversibleAction {
    IrreversibleAction {
        kind,
        target: target.to_string(),
        before,
        succeeded: result.is_ok(),
        error: result.err(),
    }
}

/// Restores a system batch: as root directly, otherwise through `sudo`.
pub fn restore_system(env: &Env, id: &str, overwrite: bool) -> Result<bool, String> {
    if is_root() {
        let quarantine =
            Quarantine::open_shared(&env.system_quarantine).map_err(|e| e.to_string())?;
        let report = quarantine
            .restore(id, RestoreOptions { overwrite })
            .map_err(|e| e.to_string())?;
        crate::batches::print_restore_report(&report, &env.home);
        return Ok(report.conflicts.is_empty() && report.failures.is_empty());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(SUDO);
    cmd.arg(exe).arg("__restore-system").arg(id);
    if overwrite {
        cmd.arg("--overwrite");
    }
    let status = cmd.status().map_err(|e| format!("cannot run sudo: {e}"))?;
    Ok(status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(path: &Path, id: &str) {
        let mut info = plist::Dictionary::new();
        info.insert("CFBundleIdentifier".into(), plist::Value::String(id.into()));
        std::fs::create_dir_all(path.join("Contents")).unwrap();
        plist::Value::Dictionary(info)
            .to_file_xml(path.join("Contents/Info.plist"))
            .unwrap();
    }

    fn file(path: &Path) -> PathBuf {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "x").unwrap();
        path.to_path_buf()
    }

    struct Machine {
        _dir: tempfile::TempDir,
        root: PathBuf,
        env: Env,
        app: PathBuf,
    }

    fn machine() -> Machine {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let home = root.join("Users/alice");
        std::fs::create_dir_all(home.join("Library")).unwrap();
        let app = root.join("Applications/PrivTest.app");
        bundle(&app, "dev.maczap.unit.privtest");
        let env = Env::new(home, root.clone(), 501, None, None);
        Machine {
            _dir: dir,
            root,
            env,
            app,
        }
    }

    fn request(m: &Machine, paths: Vec<PathBuf>) -> SystemRequest {
        SystemRequest {
            bundle_id: "dev.maczap.unit.privtest".into(),
            app_path: m.app.clone(),
            paths,
            forget_receipts: vec![],
            permanent: false,
            user_batch: "u".into(),
        }
    }

    #[test]
    fn accepts_only_paths_in_its_own_plan() {
        let m = machine();
        let ours = file(
            &m.root
                .join("Library/LaunchDaemons/dev.maczap.unit.privtest.plist"),
        );
        let foreign = file(&m.root.join("Library/LaunchDaemons/com.other.daemon.plist"));
        let outside = file(&m.root.join("etc/passwd"));

        let Selection {
            accepted, refused, ..
        } = select_requested(
            &m.env,
            &request(
                &m,
                vec![
                    m.app.clone(),
                    ours.clone(),
                    foreign.clone(),
                    outside.clone(),
                    ours.clone(),
                ],
            ),
        )
        .unwrap();

        let accepted: Vec<&Path> = accepted.iter().map(|(v, _)| v.path()).collect();
        assert_eq!(
            accepted,
            vec![m.app.as_path(), ours.as_path()],
            "duplicates collapse"
        );
        let refused: Vec<&PathBuf> = refused.iter().map(|(p, _)| p).collect();
        assert_eq!(refused, vec![&foreign, &outside]);
    }

    #[test]
    fn refuses_a_request_whose_bundle_id_does_not_match_the_app() {
        let m = machine();
        let mut req = request(&m, vec![m.app.clone()]);
        req.bundle_id = "com.other.app".into();
        assert!(select_requested(&m.env, &req).is_err());
    }

    #[test]
    fn refuses_apple_apps_even_when_asked_by_id() {
        let m = machine();
        let apple = m.root.join("Applications/Fake.app");
        bundle(&apple, "com.apple.fake");
        let req = SystemRequest {
            bundle_id: "com.apple.fake".into(),
            app_path: apple.clone(),
            ..request(&m, vec![apple])
        };
        assert!(select_requested(&m.env, &req).is_err());
    }
}
