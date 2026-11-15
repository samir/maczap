mod common;

use std::fs;

use common::{Sandbox, candidate};
use jiff::Timestamp;
use maczap_core::guard::Guard;
use maczap_core::manifest::{AppInfo, BatchState, ItemStatus};
use maczap_core::quarantine::{AdmitError, PurgeSelector, Quarantine, RestoreOptions};

fn app() -> AppInfo {
    AppInfo {
        name: "Bar".into(),
        bundle_id: "com.foo.Bar".into(),
        team_id: Some("ABCDE12345".into()),
        version: Some("1.2.3".into()),
        path: "/Applications/Bar.app".into(),
    }
}

fn now() -> Timestamp {
    "2026-11-14T12:00:00Z".parse().unwrap()
}

#[test]
fn admit_moves_the_item_into_the_batch_and_records_it() {
    let sb = Sandbox::new();
    let item = sb.file(&sb.caches.join("com.foo.Bar/cache.db"), "cached");
    let dir = item.parent().unwrap().to_path_buf();
    let verified = Guard::new(sb.roots()).verify(candidate(&dir)).unwrap();
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();

    let mut batch = quarantine.begin(app(), now()).unwrap();
    let record = batch.admit(verified).unwrap().clone();
    let manifest = batch.finish().unwrap();

    assert!(!dir.exists(), "original must be gone");
    assert_eq!(
        fs::read_to_string(record.quarantine_path.join("cache.db")).unwrap(),
        "cached"
    );
    assert!(record.quarantine_path.starts_with(&sb.quarantine));
    assert_eq!(manifest.items.len(), 1);
    assert_eq!(manifest.items[0].original_path, dir);
    assert_eq!(manifest.items[0].status, ItemStatus::Moved);
    assert_eq!(quarantine.load(&manifest.id).unwrap(), manifest);
}

#[test]
fn admit_refuses_an_item_replaced_after_verification() {
    let sb = Sandbox::new();
    let item = sb.file(&sb.caches.join("com.foo.Bar.plist"), "original");
    let verified = Guard::new(sb.roots()).verify(candidate(&item)).unwrap();
    // Swap: a different file now lives at the verified path.
    fs::remove_file(&item).unwrap();
    fs::write(&item, "somebody else's file").unwrap();
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    let mut batch = quarantine.begin(app(), now()).unwrap();

    let result = batch.admit(verified);

    assert!(
        matches!(result, Err(AdmitError::Changed { .. })),
        "{result:?}"
    );
    assert_eq!(fs::read_to_string(&item).unwrap(), "somebody else's file");
    assert!(
        batch.manifest().items.is_empty(),
        "nothing was planned for a changed item"
    );
}

#[test]
fn admit_refuses_when_a_parent_became_a_symlink() {
    let sb = Sandbox::new();
    let item = sb.file(&sb.app_support.join("Bar/state.json"), "mine");
    let verified = Guard::new(sb.roots()).verify(candidate(&item)).unwrap();
    // Swap the parent directory for a link to a victim directory holding the same name.
    let victim = sb.file(&sb.base.join("victim/state.json"), "victim");
    fs::rename(sb.app_support.join("Bar"), sb.base.join("moved-away")).unwrap();
    std::os::unix::fs::symlink(sb.base.join("victim"), sb.app_support.join("Bar")).unwrap();
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    let mut batch = quarantine.begin(app(), now()).unwrap();

    let result = batch.admit(verified);

    assert!(
        matches!(result, Err(AdmitError::Changed { .. })),
        "{result:?}"
    );
    assert_eq!(fs::read_to_string(&victim).unwrap(), "victim");
}

#[test]
fn admit_moves_a_symlink_itself_and_leaves_its_target_alone() {
    let sb = Sandbox::new();
    let target = sb.file(&sb.base.join("elsewhere/data"), "precious");
    let link = sb.caches.join("com.foo.Bar");
    std::os::unix::fs::symlink(target.parent().unwrap(), &link).unwrap();
    let verified = Guard::new(sb.roots()).verify(candidate(&link)).unwrap();
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    let mut batch = quarantine.begin(app(), now()).unwrap();

    let record = batch.admit(verified).unwrap().clone();

    assert!(fs::symlink_metadata(&link).is_err(), "link must be gone");
    assert!(record.is_symlink);
    assert!(
        fs::symlink_metadata(&record.quarantine_path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "precious");
}

#[test]
fn admit_records_size_and_entry_count_of_a_directory() {
    let sb = Sandbox::new();
    let dir = sb.caches.join("com.foo.Bar");
    sb.file(&dir.join("a"), "12345");
    sb.file(&dir.join("sub/b"), "123");
    let verified = Guard::new(sb.roots()).verify(candidate(&dir)).unwrap();
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    let mut batch = quarantine.begin(app(), now()).unwrap();

    let record = batch.admit(verified).unwrap().clone();

    assert!(record.is_dir);
    assert_eq!(record.size_bytes, 8);
    assert_eq!(record.file_count, 4, "dir + a + sub + b");
}

#[test]
fn admit_does_not_traverse_a_swapped_parent_even_when_it_holds_the_same_inode() {
    let sb = Sandbox::new();
    let item = sb.file(&sb.app_support.join("Bar/state.json"), "mine");
    let verified = Guard::new(sb.roots()).verify(candidate(&item)).unwrap();
    // The victim directory holds a hard link to the very same inode, so a fingerprint
    // check alone would pass: only refusing to traverse the symlink protects it.
    fs::create_dir_all(sb.base.join("victim")).unwrap();
    let victim_link = sb.base.join("victim/state.json");
    fs::hard_link(&item, &victim_link).unwrap();
    fs::rename(sb.app_support.join("Bar"), sb.base.join("moved-away")).unwrap();
    std::os::unix::fs::symlink(sb.base.join("victim"), sb.app_support.join("Bar")).unwrap();
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    let mut batch = quarantine.begin(app(), now()).unwrap();

    let result = batch.admit(verified);

    assert!(
        matches!(result, Err(AdmitError::Changed { .. })),
        "{result:?}"
    );
    assert!(
        victim_link.exists(),
        "the victim's directory entry must stay"
    );
}

fn quarantine_all(sb: &Sandbox, paths: &[std::path::PathBuf]) -> (Quarantine, String) {
    let guard = Guard::new(sb.roots());
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    let mut batch = quarantine.begin(app(), now()).unwrap();
    for path in paths {
        batch.admit(guard.verify(candidate(path)).unwrap()).unwrap();
    }
    let id = batch.finish().unwrap().id;
    (quarantine, id)
}

#[test]
fn restore_puts_every_item_back_where_it_was() {
    let sb = Sandbox::new();
    let file = sb.file(&sb.caches.join("com.foo.Bar.plist"), "prefs");
    let dir = sb.app_support.join("Bar");
    sb.file(&dir.join("db/data.sqlite"), "rows");
    let link = sb.caches.join("com.foo.Bar.link");
    std::os::unix::fs::symlink("/nonexistent/target", &link).unwrap();
    let (quarantine, id) = quarantine_all(&sb, &[file.clone(), dir.clone(), link.clone()]);
    assert!(!file.exists() && !dir.exists());

    let report = quarantine.restore(&id, RestoreOptions::default()).unwrap();

    assert_eq!(report.restored.len(), 3);
    assert!(report.conflicts.is_empty() && report.failures.is_empty());
    assert_eq!(fs::read_to_string(&file).unwrap(), "prefs");
    assert_eq!(
        fs::read_to_string(dir.join("db/data.sqlite")).unwrap(),
        "rows"
    );
    assert_eq!(
        fs::read_link(&link).unwrap(),
        std::path::Path::new("/nonexistent/target")
    );
    let manifest = quarantine.load(&id).unwrap();
    assert_eq!(manifest.state, BatchState::Restored);
    assert!(
        manifest
            .items
            .iter()
            .all(|i| i.status == ItemStatus::Restored)
    );
}

#[test]
fn restore_skips_an_occupied_path_and_keeps_the_item_in_quarantine() {
    let sb = Sandbox::new();
    let file = sb.file(&sb.caches.join("com.foo.Bar.plist"), "old prefs");
    let (quarantine, id) = quarantine_all(&sb, std::slice::from_ref(&file));
    fs::write(&file, "reinstalled app's prefs").unwrap();

    let report = quarantine.restore(&id, RestoreOptions::default()).unwrap();

    assert_eq!(report.conflicts, vec![file.clone()]);
    assert!(report.restored.is_empty());
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "reinstalled app's prefs"
    );
    let manifest = quarantine.load(&id).unwrap();
    assert_eq!(manifest.state, BatchState::PartiallyRestored);
    assert_eq!(
        fs::read_to_string(&manifest.items[0].quarantine_path).unwrap(),
        "old prefs"
    );
}

#[test]
fn restore_with_overwrite_moves_the_occupant_aside_first() {
    let sb = Sandbox::new();
    let file = sb.file(&sb.caches.join("com.foo.Bar.plist"), "old prefs");
    let (quarantine, id) = quarantine_all(&sb, std::slice::from_ref(&file));
    fs::write(&file, "reinstalled app's prefs").unwrap();

    let report = quarantine
        .restore(&id, RestoreOptions { overwrite: true })
        .unwrap();

    assert_eq!(report.restored, vec![file.clone()]);
    assert_eq!(fs::read_to_string(&file).unwrap(), "old prefs");
    let (original, displaced) = &report.displaced[0];
    assert_eq!(original, &file);
    assert_eq!(
        fs::read_to_string(displaced).unwrap(),
        "reinstalled app's prefs"
    );
    assert!(displaced.starts_with(&sb.quarantine));
}

#[test]
fn restore_recovers_a_batch_that_was_never_finished() {
    let sb = Sandbox::new();
    let file = sb.file(&sb.caches.join("com.foo.Bar.plist"), "prefs");
    let guard = Guard::new(sb.roots());
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    let id = {
        let mut batch = quarantine.begin(app(), now()).unwrap();
        batch
            .admit(guard.verify(candidate(&file)).unwrap())
            .unwrap();
        batch.id().to_string()
        // dropped without finish(): the process "crashed"
    };
    assert_eq!(quarantine.load(&id).unwrap().state, BatchState::Open);

    let report = quarantine.restore(&id, RestoreOptions::default()).unwrap();

    assert_eq!(report.restored, vec![file.clone()]);
    assert_eq!(fs::read_to_string(&file).unwrap(), "prefs");
}

#[test]
fn restore_recreates_a_missing_parent_directory() {
    let sb = Sandbox::new();
    let file = sb.file(&sb.app_support.join("Bar/Sub/state.json"), "state");
    let (quarantine, id) = quarantine_all(&sb, std::slice::from_ref(&file));
    fs::remove_dir_all(sb.app_support.join("Bar")).unwrap();

    let report = quarantine.restore(&id, RestoreOptions::default()).unwrap();

    assert_eq!(report.restored, vec![file.clone()]);
    assert_eq!(fs::read_to_string(&file).unwrap(), "state");
}

#[test]
fn restore_rejects_crafted_batch_ids() {
    let sb = Sandbox::new();
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    for id in ["../../etc", "", "-rf", "a/b", "nope"] {
        assert!(
            quarantine.restore(id, RestoreOptions::default()).is_err(),
            "{id:?}"
        );
    }
}

fn batch_at(sb: &Sandbox, quarantine: &Quarantine, name: &str, when: &str) -> String {
    let file = sb.file(&sb.caches.join(name), "12345");
    let mut batch = quarantine.begin(app(), when.parse().unwrap()).unwrap();
    batch
        .admit(Guard::new(sb.roots()).verify(candidate(&file)).unwrap())
        .unwrap();
    batch.finish().unwrap().id
}

#[test]
fn list_shows_every_batch_oldest_first_with_its_size() {
    let sb = Sandbox::new();
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    let newer = batch_at(&sb, &quarantine, "b", "2026-11-10T00:00:00Z");
    let older = batch_at(&sb, &quarantine, "a", "2026-10-01T00:00:00Z");

    let listing = quarantine.list().unwrap();

    let ids: Vec<_> = listing.batches.iter().map(|b| b.id.clone()).collect();
    assert_eq!(ids, vec![older, newer]);
    assert_eq!(listing.batches[0].size_bytes, 5);
    assert_eq!(listing.batches[0].moved, 1);
    assert_eq!(listing.batches[0].app.bundle_id, "com.foo.Bar");
    assert!(listing.unreadable.is_empty());
}

#[test]
fn list_reports_a_corrupt_manifest_instead_of_failing() {
    let sb = Sandbox::new();
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    batch_at(&sb, &quarantine, "a", "2026-10-01T00:00:00Z");
    fs::create_dir(sb.quarantine.join("broken")).unwrap();
    fs::write(sb.quarantine.join("broken/manifest.json"), "{ not json").unwrap();

    let listing = quarantine.list().unwrap();

    assert_eq!(listing.batches.len(), 1);
    assert_eq!(listing.unreadable, vec![sb.quarantine.join("broken")]);
}

#[test]
fn purge_by_id_deletes_only_that_batch() {
    let sb = Sandbox::new();
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    let keep = batch_at(&sb, &quarantine, "a", "2026-10-01T00:00:00Z");
    let drop = batch_at(&sb, &quarantine, "b", "2026-10-02T00:00:00Z");

    let report = quarantine
        .purge(&PurgeSelector::Ids(vec![drop.clone()]), now())
        .unwrap();

    assert_eq!(report.removed, vec![drop.clone()]);
    assert_eq!(report.freed_bytes, 5);
    assert!(!sb.quarantine.join(&drop).exists());
    assert!(quarantine.load(&keep).is_ok());
}

#[test]
fn purge_older_than_uses_the_batch_creation_time() {
    let sb = Sandbox::new();
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    let old = batch_at(&sb, &quarantine, "a", "2026-10-01T00:00:00Z"); // 44 days before now()
    let recent = batch_at(&sb, &quarantine, "b", "2026-11-01T00:00:00Z"); // 13 days before

    let selector = PurgeSelector::OlderThan(jiff::SignedDuration::from_hours(30 * 24));
    let report = quarantine.purge(&selector, now()).unwrap();

    assert_eq!(report.removed, vec![old]);
    assert!(quarantine.load(&recent).is_ok());
}

#[test]
fn purge_removes_read_only_directories_from_app_bundles() {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new();
    let dir = sb.app_support.join("Bar");
    sb.file(&dir.join("locked/inner.txt"), "x");
    fs::set_permissions(
        dir.join("locked/inner.txt"),
        fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    fs::set_permissions(dir.join("locked"), fs::Permissions::from_mode(0o555)).unwrap();
    let (quarantine, id) = quarantine_all(&sb, &[dir]);

    let report = quarantine
        .purge(&PurgeSelector::Ids(vec![id.clone()]), now())
        .unwrap();

    assert_eq!(report.removed, vec![id.clone()]);
    assert!(!sb.quarantine.join(&id).exists());
}

#[test]
fn purge_refuses_unknown_or_crafted_ids_and_removes_nothing() {
    let sb = Sandbox::new();
    let quarantine = Quarantine::open(&sb.quarantine).unwrap();
    let keep = batch_at(&sb, &quarantine, "a", "2026-10-01T00:00:00Z");
    let outside = sb.file(&sb.home.join("precious.txt"), "x");

    for id in ["../../precious.txt", "..", "nope"] {
        let result = quarantine.purge(&PurgeSelector::Ids(vec![keep.clone(), id.into()]), now());
        assert!(result.is_err(), "{id:?}");
    }
    assert!(
        quarantine.load(&keep).is_ok(),
        "an invalid id aborts the whole purge"
    );
    assert!(outside.exists());
}
