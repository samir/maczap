//! The quarantine on a different volume than the item: `rename` fails with EXDEV and
//! the copy-verify-delete fallback runs. Mounts a small APFS disk image with `hdiutil`.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{Sandbox, candidate};
use maczap_core::guard::Guard;
use maczap_core::manifest::{AppInfo, ItemStatus};
use maczap_core::quarantine::{Quarantine, RestoreOptions};

struct DiskImage {
    mount_point: PathBuf,
}

impl DiskImage {
    fn mount(dir: &Path) -> Self {
        let image = dir.join("vol.dmg");
        let mount_point = dir.join("mnt");
        fs::create_dir_all(&mount_point).unwrap();
        let created = Command::new("/usr/bin/hdiutil")
            .args([
                "create", "-quiet", "-size", "8m", "-fs", "APFS", "-volname", "mzx",
            ])
            .arg(&image)
            .status()
            .unwrap();
        assert!(created.success(), "hdiutil create failed");
        let attached = Command::new("/usr/bin/hdiutil")
            .args(["attach", "-quiet", "-nobrowse", "-mountpoint"])
            .arg(&mount_point)
            .arg(&image)
            .status()
            .unwrap();
        assert!(attached.success(), "hdiutil attach failed");
        DiskImage { mount_point }
    }
}

impl Drop for DiskImage {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/hdiutil")
            .args(["detach", "-quiet", "-force"])
            .arg(&self.mount_point)
            .status();
    }
}

#[test]
fn admit_and_restore_work_across_volumes() {
    let sb = Sandbox::new();
    let image = DiskImage::mount(&sb.base);
    let dir = sb.app_support.join("Bar");
    sb.file(&dir.join("a.txt"), "alpha");
    sb.file(&dir.join("sub/b.txt"), "beta");
    std::os::unix::fs::symlink("a.txt", dir.join("link")).unwrap();
    let verified = Guard::new(sb.roots()).verify(candidate(&dir)).unwrap();
    let quarantine = Quarantine::open(&image.mount_point.join("quarantine")).unwrap();
    let app = AppInfo {
        name: "Bar".into(),
        bundle_id: "com.foo.Bar".into(),
        team_id: None,
        version: None,
        path: "/Applications/Bar.app".into(),
    };

    let mut batch = quarantine
        .begin(app, "2026-11-14T12:00:00Z".parse().unwrap())
        .unwrap();
    let record = batch.admit(verified).unwrap().clone();
    let id = batch.finish().unwrap().id;

    assert_eq!(record.status, ItemStatus::Moved);
    assert!(!dir.exists());
    assert_eq!(
        fs::read_to_string(record.quarantine_path.join("sub/b.txt")).unwrap(),
        "beta"
    );
    assert!(
        fs::symlink_metadata(record.quarantine_path.join("link"))
            .unwrap()
            .is_symlink()
    );

    let report = quarantine.restore(&id, RestoreOptions::default()).unwrap();

    assert_eq!(report.restored, vec![dir.clone()]);
    assert_eq!(fs::read_to_string(dir.join("a.txt")).unwrap(), "alpha");
    assert_eq!(fs::read_link(dir.join("link")).unwrap(), Path::new("a.txt"));
}
