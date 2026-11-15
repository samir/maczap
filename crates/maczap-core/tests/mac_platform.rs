//! Contract tests of the real adapter against the running Mac.

use std::path::{Path, PathBuf};

use maczap_core::mac::MacPlatform;
use maczap_core::platform::Platform;

const CALCULATOR: &str = "/System/Applications/Calculator.app";

#[test]
fn reads_the_signature_of_an_apple_app() {
    let sig = MacPlatform::default()
        .code_signature(Path::new(CALCULATOR))
        .unwrap();
    assert_eq!(sig.identifier.as_deref(), Some("com.apple.calculator"));
    assert_eq!(
        sig.team_id, None,
        "Apple platform binaries carry no Team ID"
    );
}

#[test]
fn an_unsigned_or_missing_bundle_has_no_signature() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(MacPlatform::default().code_signature(dir.path()), None);
    assert_eq!(
        MacPlatform::default().code_signature(Path::new("/nonexistent.app")),
        None
    );
}

#[test]
fn lists_installed_apps_including_system_ones() {
    let apps = MacPlatform::new(vec![PathBuf::from("/System/Applications")]).installed_apps();
    assert!(
        apps.iter().any(|a| a == Path::new(CALCULATOR)),
        "{} apps",
        apps.len()
    );
}

#[test]
fn resolves_receipt_files_and_their_owners() {
    let pkgs = std::process::Command::new("/usr/sbin/pkgutil")
        .arg("--pkgs")
        .output()
        .unwrap();
    let pkgs = String::from_utf8(pkgs.stdout).unwrap();
    let platform = MacPlatform::default();
    // Find one receipt with a file that still exists, then ask who owns that file.
    let found = pkgs.lines().find_map(|pkg| {
        let files = platform.receipt_files(pkg)?;
        let file = files.into_iter().find(|f| f.is_file())?;
        Some((pkg.to_string(), file))
    });
    let (pkg, file) = found.expect("this Mac has at least one receipt with an existing file");
    assert!(file.is_absolute());
    assert!(
        platform.receipts_containing(&file).contains(&pkg),
        "{pkg} should own {}",
        file.display()
    );
    assert!(
        platform
            .receipts_containing(Path::new("/nonexistent/file"))
            .is_empty()
    );
    assert_eq!(platform.receipt_files("com.nonexistent.pkg.maczap"), None);
}

mod control {
    use std::path::Path;
    use std::time::{Duration, Instant};

    use maczap_core::control::{Bootout, Control, TccReset};
    use maczap_core::mac::MacControl;

    #[test]
    fn unknown_ids_and_labels_are_nothing_to_do() {
        let c = MacControl;
        assert_eq!(
            c.tcc_reset("dev.maczap.contract.unknown").unwrap(),
            TccReset::NothingToReset
        );
        assert_eq!(
            c.bootout_user_agent(
                "dev.maczap.contract.unknown",
                Path::new("/nonexistent.plist")
            )
            .unwrap(),
            Bootout::NotLoaded
        );
        assert!(c.running_pids("dev.maczap.contract.unknown").is_empty());
    }

    #[test]
    fn process_liveness() {
        let c = MacControl;
        assert!(c.is_alive(std::process::id() as i32));
        assert!(!c.is_alive(i32::MAX - 1));
    }

    #[test]
    #[ignore = "launches and quits Chess.app on this Mac"]
    fn quits_a_running_app_gracefully() {
        let c = MacControl;
        assert!(
            c.running_pids("com.apple.Chess").is_empty(),
            "close Chess before running this test"
        );
        std::process::Command::new("/usr/bin/open")
            .args(["-g", "-j", "-a", "Chess"])
            .status()
            .unwrap();
        let start = Instant::now();
        let pids = loop {
            let pids = c.running_pids("com.apple.Chess");
            if !pids.is_empty() || start.elapsed() > Duration::from_secs(10) {
                break pids;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        assert!(!pids.is_empty());
        c.request_quit("com.apple.Chess");
        let start = Instant::now();
        while pids.iter().any(|p| c.is_alive(*p)) && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(pids.iter().all(|p| !c.is_alive(*p)));
    }
}
