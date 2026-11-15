mod common;

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::Sandbox;
use common::fake::{FakeApp, FakePlatform, write_plist};
use maczap_core::catalog::Catalog;
use maczap_core::control::{
    Bootout, Control, PrivilegedStep, SystemRequest, SystemResult, TccReset,
};
use maczap_core::discovery::scan;
use maczap_core::guard::Guard;
use maczap_core::identity::AppIdentity;
use maczap_core::manifest::{ActionKind, ItemStatus};
use maczap_core::plan::{Plan, PlanOptions};
use maczap_core::quarantine::Quarantine;
use maczap_core::uninstall::{Abort, Mode, Request, execute};
use plist::Value;

/// Records every call, with whether the app bundle still existed at that moment.
#[derive(Default)]
struct FakeControl {
    log: RefCell<Vec<String>>,
    bundle: PathBuf,
    running: RefCell<Vec<i32>>,
    ignores_quit: bool,
}

impl FakeControl {
    fn note(&self, what: String) {
        let state = if self.bundle.exists() {
            "bundle present"
        } else {
            "bundle gone"
        };
        self.log.borrow_mut().push(format!("{what} [{state}]"));
    }
    fn log(&self) -> Vec<String> {
        self.log.borrow().clone()
    }
}

impl Control for FakeControl {
    fn running_pids(&self, bundle_id: &str) -> Vec<i32> {
        if bundle_id == "com.foo.Bar" {
            self.running.borrow().clone()
        } else {
            vec![]
        }
    }
    fn request_quit(&self, bundle_id: &str) {
        self.note(format!("quit {bundle_id}"));
        if !self.ignores_quit {
            self.running.borrow_mut().clear();
        }
    }
    fn is_alive(&self, pid: i32) -> bool {
        self.running.borrow().contains(&pid)
    }
    fn wait(&self, _: Duration) {}
    fn bootout_user_agent(&self, label: &str, plist: &Path) -> Result<Bootout, String> {
        self.note(format!("bootout {label} plist_exists={}", plist.exists()));
        Ok(Bootout::Unloaded)
    }
    fn tcc_reset(&self, bundle_id: &str) -> Result<TccReset, String> {
        self.note(format!("tcc {bundle_id}"));
        Ok(TccReset::Reset)
    }
    fn remove_legacy_login_item(&self, name: &str) -> Result<(), String> {
        self.note(format!("login-item {name}"));
        Ok(())
    }
}

#[derive(Default)]
struct FakePrivileged {
    log: RefCell<Vec<String>>,
    decline: bool,
    requests: RefCell<Vec<SystemRequest>>,
}

impl PrivilegedStep for FakePrivileged {
    fn authorize(&self) -> Result<(), String> {
        self.log.borrow_mut().push("authorize".into());
        if self.decline {
            Err("sudo: a password is required".into())
        } else {
            Ok(())
        }
    }
    fn apply(&self, request: &SystemRequest) -> Result<SystemResult, String> {
        self.log.borrow_mut().push("apply".into());
        self.requests.borrow_mut().push(request.clone());
        Ok(SystemResult {
            batch_id: Some("sys-1".into()),
            moved: request.paths.clone(),
            ..Default::default()
        })
    }
}

struct World {
    sb: Sandbox,
    app: PathBuf,
    catalog: Catalog,
    platform: FakePlatform,
}

impl World {
    fn new() -> Self {
        let sb = Sandbox::new();
        let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
        common::fake::nested_bundle(
            &app,
            "Contents/Library/LoginItems/L.app",
            "com.foo.Bar.Launcher",
        );
        let catalog = Catalog::standard(&sb.home, &sb.base, None, None);
        World {
            sb,
            app,
            catalog,
            platform: FakePlatform::default(),
        }
    }

    fn control(&self) -> FakeControl {
        FakeControl {
            bundle: self.app.clone(),
            ..Default::default()
        }
    }

    fn run(
        &self,
        uid: u32,
        mode: Mode,
        control: &FakeControl,
        privileged: &FakePrivileged,
    ) -> Result<maczap_core::uninstall::Outcome, Abort> {
        let identity = AppIdentity::read(&self.app, &self.platform).unwrap();
        let found = scan(&identity, &self.catalog, &self.platform);
        let guard = Guard::new(
            self.catalog
                .roots(std::slice::from_ref(&self.sb.quarantine))
                .unwrap(),
        );
        let plan = Plan::new(&found, &guard, PlanOptions::default(), uid);
        let quarantine = Quarantine::open(&self.sb.quarantine).unwrap();
        let request = Request {
            identity: &identity,
            plan: &plan,
            quarantine: &quarantine,
            now: "2026-11-14T12:00:00Z".parse().unwrap(),
            mode,
            quit_timeout: Duration::from_secs(1),
            legacy_login_items: found.legacy_login_items.clone(),
            receipts: found.receipts.clone(),
        };
        execute(&request, control, privileged)
    }
}

fn me() -> u32 {
    rustix::process::getuid().as_raw()
}

#[test]
fn quits_the_app_resets_tcc_while_the_bundle_exists_then_moves_everything() {
    let w = World::new();
    let prefs = w.sb.file(
        &w.sb.home.join("Library/Preferences/com.foo.Bar.plist"),
        "p",
    );
    let control = w.control();
    control.running.borrow_mut().push(4242);
    let privileged = FakePrivileged::default();

    let outcome = w
        .run(me(), Mode::Quarantine, &control, &privileged)
        .unwrap();

    assert_eq!(
        control.log(),
        vec![
            "quit com.foo.Bar [bundle present]",
            "tcc com.foo.Bar [bundle present]",
            "tcc com.foo.Bar.Launcher [bundle present]",
        ]
    );
    assert!(!w.app.exists() && !prefs.exists());
    assert_eq!(outcome.manifest.moved_count(), 2);
    let kinds: Vec<_> = outcome.manifest.actions.iter().map(|a| a.kind).collect();
    assert_eq!(kinds, vec![ActionKind::TccReset, ActionKind::TccReset]);
    assert!(privileged.log.borrow().is_empty(), "nothing needed root");
}

#[test]
fn aborts_without_changing_anything_when_the_app_does_not_quit() {
    let w = World::new();
    let prefs = w.sb.file(
        &w.sb.home.join("Library/Preferences/com.foo.Bar.plist"),
        "p",
    );
    let control = FakeControl {
        ignores_quit: true,
        ..w.control()
    };
    control.running.borrow_mut().push(4242);

    let result = w.run(me(), Mode::Quarantine, &control, &FakePrivileged::default());

    assert!(
        matches!(result, Err(Abort::StillRunning(ref pids)) if pids == &vec![4242]),
        "{result:?}"
    );
    assert!(w.app.exists() && prefs.exists());
    assert_eq!(control.log(), vec!["quit com.foo.Bar [bundle present]"]);
    let quarantine = Quarantine::open(&w.sb.quarantine).unwrap();
    assert!(
        quarantine.list().unwrap().batches.is_empty(),
        "no batch was started"
    );
}

#[test]
fn boots_out_user_agents_before_their_plist_moves() {
    let w = World::new();
    let agent =
        w.sb.home
            .join("Library/LaunchAgents/com.foo.Bar.agent.plist");
    write_plist(
        &agent,
        &[("Label", Value::String("com.foo.Bar.agent".into()))],
    );
    let control = w.control();

    w.run(me(), Mode::Quarantine, &control, &FakePrivileged::default())
        .unwrap();

    assert!(
        control
            .log()
            .contains(&"bootout com.foo.Bar.agent plist_exists=true [bundle present]".to_string())
    );
    assert!(!agent.exists());
}

#[test]
fn asks_for_root_first_and_hands_root_items_to_the_privileged_step() {
    let w = World::new();
    let daemon_support = w.sb.file(
        &w.sb.base.join("Library/Application Support/com.foo.Bar/d"),
        "x",
    );
    let control = w.control();
    let privileged = FakePrivileged::default();

    // Pretend we are another user: every item now "belongs to someone else".
    let outcome = w
        .run(me() + 1, Mode::Quarantine, &control, &privileged)
        .unwrap();

    assert_eq!(*privileged.log.borrow(), vec!["authorize", "apply"]);
    let request = privileged.requests.borrow()[0].clone();
    assert_eq!(request.bundle_id, "com.foo.Bar");
    assert!(request.paths.contains(&w.app));
    assert!(
        request
            .paths
            .contains(&daemon_support.parent().unwrap().to_path_buf())
    );
    assert_eq!(outcome.manifest.linked_batch.as_deref(), Some("sys-1"));
}

#[test]
fn a_declined_password_aborts_before_anything_changes() {
    let w = World::new();
    let control = w.control();
    let privileged = FakePrivileged {
        decline: true,
        ..Default::default()
    };

    let result = w.run(me() + 1, Mode::Quarantine, &control, &privileged);

    assert!(matches!(result, Err(Abort::NotAuthorized(_))), "{result:?}");
    assert!(w.app.exists());
    assert!(
        control.log().iter().all(|l| !l.starts_with("tcc")),
        "TCC untouched: {:?}",
        control.log()
    );
}

#[test]
fn aborts_before_tcc_when_the_bundle_cannot_be_moved() {
    use std::os::unix::fs::PermissionsExt;
    let w = World::new();
    let control = w.control();
    fs::set_permissions(&w.sb.applications, fs::Permissions::from_mode(0o555)).unwrap();

    let result = w.run(me(), Mode::Quarantine, &control, &FakePrivileged::default());
    fs::set_permissions(&w.sb.applications, fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        matches!(result, Err(Abort::BundleNotMovable(_))),
        "{result:?}"
    );
    assert!(w.app.exists());
    assert!(control.log().iter().all(|l| !l.starts_with("tcc")));
}

#[test]
fn permanent_mode_deletes_the_batch_after_moving() {
    let w = World::new();
    let prefs = w.sb.file(
        &w.sb.home.join("Library/Preferences/com.foo.Bar.plist"),
        "p",
    );

    let outcome = w
        .run(
            me(),
            Mode::Permanent,
            &w.control(),
            &FakePrivileged::default(),
        )
        .unwrap();

    assert!(!prefs.exists() && !w.app.exists());
    assert!(
        outcome
            .manifest
            .items
            .iter()
            .all(|i| i.status == ItemStatus::Moved)
    );
    let quarantine = Quarantine::open(&w.sb.quarantine).unwrap();
    assert!(quarantine.list().unwrap().batches.is_empty());
}

#[test]
fn trash_mode_moves_user_items_to_the_trash() {
    let w = World::new();
    let prefs = w.sb.file(
        &w.sb.home.join("Library/Preferences/com.foo.Bar.plist"),
        "p",
    );
    let trash = w.sb.home.join(".Trash");

    w.run(
        me(),
        Mode::Trash(trash.clone()),
        &w.control(),
        &FakePrivileged::default(),
    )
    .unwrap();

    assert!(!prefs.exists());
    assert_eq!(
        fs::read_to_string(trash.join("com.foo.Bar.plist")).unwrap(),
        "p"
    );
    assert!(trash.join("Bar.app").exists());
}
