//! End-to-end: the real binary against a sandboxed machine (`HOME` and the debug-only
//! `MACZAP_SYSTEM_ROOT` point into a temporary directory).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use plist::{Dictionary, Value};

struct Machine {
    _dir: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    id: String,
    app: PathBuf,
}

fn bundle(path: &Path, id: &str, name: &str) {
    let mut info = Dictionary::new();
    info.insert("CFBundleIdentifier".into(), Value::String(id.into()));
    info.insert("CFBundleName".into(), Value::String(name.into()));
    info.insert("CFBundleExecutable".into(), Value::String(name.into()));
    fs::create_dir_all(path.join("Contents/MacOS")).unwrap();
    Value::Dictionary(info)
        .to_file_xml(path.join("Contents/Info.plist"))
        .unwrap();
    fs::write(path.join("Contents/MacOS").join(name), "#!/bin/sh\n").unwrap();
}

impl Machine {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let home = root.join("Users/alice");
        fs::create_dir_all(home.join("Library")).unwrap();
        // A unique id and name, so nothing on the real Mac can ever match.
        let tag = format!(
            "{}{}",
            std::process::id(),
            root.file_name().unwrap().to_string_lossy().replace('.', "")
        );
        let id = format!("dev.maczap.e2e.app{tag}");
        let app = root.join(format!("Applications/MaczapE2E{tag}.app"));
        bundle(&app, &id, &format!("MaczapE2E{tag}"));
        Machine {
            _dir: dir,
            root,
            home,
            id,
            app,
        }
    }

    fn file(&self, path: &Path) -> PathBuf {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "data").unwrap();
        path.to_path_buf()
    }

    fn traces(&self) -> Vec<PathBuf> {
        vec![
            self.file(
                &self
                    .home
                    .join(format!("Library/Preferences/{}.plist", self.id)),
            ),
            self.file(
                &self
                    .home
                    .join(format!("Library/Caches/{}/cache.db", self.id)),
            )
            .parent()
            .unwrap()
            .to_path_buf(),
            self.file(
                &self
                    .root
                    .join(format!("Library/Application Support/{}/state", self.id)),
            )
            .parent()
            .unwrap()
            .to_path_buf(),
        ]
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_maczap"))
            .args(args)
            .env("HOME", &self.home)
            .env("MACZAP_SYSTEM_ROOT", &self.root)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn app_arg(&self) -> &str {
        self.app.to_str().unwrap()
    }
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[test]
fn scan_json_lists_the_bundle_and_its_traces_without_changing_anything() {
    let m = Machine::new();
    let traces = m.traces();

    let out = m.run(&["scan", m.app_arg(), "--json"]);

    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    let body = json(&out);
    assert_eq!(body["app"]["bundle_id"], m.id.as_str());
    let paths: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap())
        .collect();
    for p in traces.iter().chain([&m.app]) {
        assert!(
            paths.contains(&p.to_str().unwrap()),
            "{} missing from {paths:?}",
            p.display()
        );
        assert!(p.exists());
    }
    assert!(
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["selected"] == true)
    );
}

#[test]
fn uninstall_refuses_to_act_without_a_terminal_or_yes() {
    let m = Machine::new();
    let traces = m.traces();

    let dry = m.run(&["uninstall", m.app_arg(), "--dry-run"]);
    let refused = m.run(&["uninstall", m.app_arg()]);

    assert_eq!(code(&dry), 0);
    assert_eq!(
        code(&refused),
        3,
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(m.app.exists() && traces.iter().all(|t| t.exists()));
}

#[test]
fn uninstall_list_restore_purge_round_trip() {
    let m = Machine::new();
    let traces = m.traces();

    let out = m.run(&["uninstall", m.app_arg(), "--yes", "--json"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    let body = json(&out);
    assert_eq!(body["complete"], true);
    assert_eq!(body["moved"], 4);
    assert!(!m.app.exists() && traces.iter().all(|t| !t.exists()));
    let batch = body["batch"].as_str().unwrap().to_string();

    let list = json(&m.run(&["list", "--json"]));
    assert_eq!(list[0]["id"], batch.as_str());
    assert_eq!(list[0]["moved"], 4);

    let restored = m.run(&["restore", &batch]);
    assert_eq!(
        code(&restored),
        0,
        "{}",
        String::from_utf8_lossy(&restored.stdout)
    );
    assert!(m.app.exists() && traces.iter().all(|t| t.exists()));

    let purged = m.run(&["purge", "--all", "--yes"]);
    assert_eq!(code(&purged), 0);
    assert_eq!(json(&m.run(&["list", "--json"])), serde_json::json!([]));
}

#[test]
fn permanent_uninstall_leaves_no_batch_behind() {
    let m = Machine::new();
    let traces = m.traces();

    let out = m.run(&["uninstall", m.app_arg(), "--yes", "--permanent"]);

    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!m.app.exists() && traces.iter().all(|t| !t.exists()));
    assert_eq!(json(&m.run(&["list", "--json"])), serde_json::json!([]));
}

#[test]
fn ambiguous_names_abort_instead_of_guessing() {
    let m = Machine::new();
    let name = m.app.file_stem().unwrap().to_str().unwrap().to_string();
    bundle(
        &m.home.join(format!("Applications/{name}.app")),
        &format!("{}.copy", m.id),
        &name,
    );

    let out = m.run(&["uninstall", &name, "--yes"]);

    assert_eq!(code(&out), 3, "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Several apps match"));
    assert!(m.app.exists());
}

#[test]
fn apple_apps_are_refused_and_unknown_apps_are_errors() {
    let m = Machine::new();
    let apple = m.root.join("Applications/FakeApple.app");
    bundle(&apple, "com.apple.FakeApple", "FakeApple");

    let refused = m.run(&["uninstall", apple.to_str().unwrap(), "--yes"]);
    let unknown = m.run(&["scan", "dev.maczap.e2e.does-not-exist"]);

    assert_eq!(code(&refused), 3);
    assert!(apple.exists());
    assert_eq!(code(&unknown), 1);
}
