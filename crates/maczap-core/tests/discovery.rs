mod common;

use std::path::{Path, PathBuf};

use common::Sandbox;
use common::fake::{FakeApp, FakePlatform};
use maczap_core::candidate::{Category, Confidence};
use maczap_core::catalog::Catalog;
use maczap_core::discovery::{Scan, scan};
use maczap_core::identity::AppIdentity;

/// A sandboxed machine plus the production catalog wired to it.
struct World {
    sb: Sandbox,
    catalog: Catalog,
    platform: FakePlatform,
}

impl World {
    fn new() -> Self {
        let sb = Sandbox::new();
        let cache = sb.base.join("var/folders/zz/abc/C");
        let temp = sb.base.join("var/folders/zz/abc/T");
        let catalog = Catalog::standard(&sb.home, &sb.base, Some(&cache), Some(&temp));
        World {
            sb,
            catalog,
            platform: FakePlatform::default(),
        }
    }

    fn user(&self, relative: &str) -> PathBuf {
        self.sb.home.join("Library").join(relative)
    }

    fn system(&self, relative: &str) -> PathBuf {
        self.sb.base.join(relative)
    }

    fn touch(&self, path: &Path) -> PathBuf {
        self.sb.file(path, "x")
    }

    fn app(&self) -> PathBuf {
        FakeApp::new(&self.sb.applications, "Bar", "com.foo.Bar").build()
    }

    fn scan(&self, app: &Path) -> Scan {
        let identity = AppIdentity::read(app, &self.platform).unwrap();
        scan(&identity, &self.catalog, &self.platform)
    }
}

fn find<'a>(scan: &'a Scan, path: &Path) -> Option<&'a maczap_core::candidate::Candidate> {
    scan.candidates.iter().find(|c| c.path == path)
}

#[test]
fn finds_items_named_exactly_after_the_bundle_id_with_high_confidence() {
    let w = World::new();
    let app = w.app();
    let expected = [
        (
            w.touch(&w.user("Caches/com.foo.Bar/db"))
                .parent()
                .unwrap()
                .to_path_buf(),
            Category::Caches,
        ),
        (
            w.touch(&w.user("Preferences/com.foo.Bar.plist")),
            Category::Preferences,
        ),
        (
            w.touch(&w.user("Containers/com.foo.Bar/Data/x"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf(),
            Category::Containers,
        ),
        (
            w.touch(&w.user("Saved Application State/com.foo.Bar.savedState/w"))
                .parent()
                .unwrap()
                .to_path_buf(),
            Category::SavedState,
        ),
        (
            w.touch(&w.user("HTTPStorages/com.foo.Bar.binarycookies")),
            Category::WebData,
        ),
        (
            w.touch(&w.user("Application Support/com.foo.Bar/s"))
                .parent()
                .unwrap()
                .to_path_buf(),
            Category::ApplicationSupport,
        ),
        (
            w.touch(&w.system("Library/Caches/com.foo.Bar/c"))
                .parent()
                .unwrap()
                .to_path_buf(),
            Category::Caches,
        ),
        (
            w.touch(&w.system("var/folders/zz/abc/C/com.foo.Bar/c"))
                .parent()
                .unwrap()
                .to_path_buf(),
            Category::TempData,
        ),
    ];
    let unrelated = w.touch(&w.user("Caches/com.other.App/db"));

    let scan = w.scan(&app);

    for (path, category) in &expected {
        let c = find(&scan, path).unwrap_or_else(|| panic!("missing {}", path.display()));
        assert_eq!(c.confidence, Confidence::High, "{}", path.display());
        assert_eq!(c.category, *category, "{}", path.display());
    }
    assert!(find(&scan, unrelated.parent().unwrap()).is_none());
    let bundle = find(&scan, &app).expect("the bundle itself is a candidate");
    assert_eq!(bundle.category, Category::AppBundle);
}

#[test]
fn matches_sub_ids_and_byhost_preferences_but_not_lookalike_ids() {
    let mut w = World::new();
    let app = w.app();
    let other = FakeApp::new(&w.sb.applications, "BarPro", "com.foo.Bar.Pro").build();
    w.platform.installed = vec![app.clone(), other];
    let shipit = w
        .touch(&w.user("Caches/com.foo.Bar.ShipIt/update"))
        .parent()
        .unwrap()
        .to_path_buf();
    let byhost = w.touch(
        &w.user("Preferences/ByHost/com.foo.Bar.0A1B2C3D-0000-1111-2222-333344445555.plist"),
    );
    let lookalike = w.touch(&w.user("Preferences/com.foo.BarPro.plist"));
    let other_apps = w.touch(&w.user("Preferences/com.foo.Bar.Pro.plist"));

    let scan = w.scan(&app);

    assert_eq!(find(&scan, &shipit).unwrap().confidence, Confidence::High);
    assert_eq!(find(&scan, &byhost).unwrap().confidence, Confidence::High);
    assert!(
        find(&scan, &lookalike).is_none(),
        "com.foo.BarPro is a different id"
    );
    assert!(
        find(&scan, &other_apps).is_none(),
        "com.foo.Bar.Pro is another installed app"
    );
}

#[test]
fn matches_traces_of_nested_bundle_ids() {
    let w = World::new();
    let app = w.app();
    common::fake::nested_bundle(
        &app,
        "Contents/Library/LoginItems/Launcher.app",
        "com.foo.BarLauncher",
    );
    let launcher_prefs = w.touch(&w.user("Preferences/com.foo.BarLauncher.plist"));

    let scan = w.scan(&app);

    let c = find(&scan, &launcher_prefs).unwrap();
    assert_eq!(c.confidence, Confidence::High);
    assert!(c.reason.contains("com.foo.BarLauncher"), "{}", c.reason);
}

#[test]
fn traces_shared_with_another_installed_copy_are_marked_shared() {
    let mut w = World::new();
    let app = w.app();
    let copy = FakeApp::new(&w.sb.home.join("Applications"), "Bar", "com.foo.Bar").build();
    w.platform.installed = vec![app.clone(), copy];
    let prefs = w.touch(&w.user("Preferences/com.foo.Bar.plist"));

    let scan = w.scan(&app);

    let c = find(&scan, &prefs).unwrap();
    assert_eq!(c.confidence, Confidence::Shared);
    assert!(
        find(&scan, &app).is_some(),
        "the selected bundle itself is still a candidate"
    );
}

#[test]
fn name_matches_are_low_confidence_and_skipped_when_another_app_has_that_name() {
    let mut w = World::new();
    let app = FakeApp::new(&w.sb.applications, "Bar", "com.foo.Bar")
        .set("CFBundleExecutable", "BarCore")
        .build();
    let by_name = w
        .touch(&w.user("Application Support/Bar/state"))
        .parent()
        .unwrap()
        .to_path_buf();
    let by_exe = w
        .touch(&w.user("Logs/barcore/log"))
        .parent()
        .unwrap()
        .to_path_buf();
    let generic = w
        .touch(&w.user("Caches/Google/x"))
        .parent()
        .unwrap()
        .to_path_buf();
    let chrome = FakeApp::new(&w.sb.applications, "Google", "com.google.Chrome").build();
    w.platform.installed = vec![app.clone(), chrome];

    let scan = w.scan(&app);

    assert_eq!(find(&scan, &by_name).unwrap().confidence, Confidence::Low);
    assert_eq!(find(&scan, &by_exe).unwrap().confidence, Confidence::Low);
    assert!(find(&scan, &generic).is_none());
}

#[test]
fn name_match_is_skipped_when_another_installed_app_shares_the_name() {
    let mut w = World::new();
    let app = w.app();
    let twin = FakeApp::new(&w.sb.home.join("Applications"), "Bar", "com.other.Bar").build();
    w.platform.installed = vec![app.clone(), twin];
    let folder = w
        .touch(&w.user("Application Support/Bar/x"))
        .parent()
        .unwrap()
        .to_path_buf();

    let scan = w.scan(&app);

    assert!(find(&scan, &folder).is_none());
}

#[test]
fn group_containers_follow_declared_groups_team_prefix_and_sharing() {
    let mut w = World::new();
    let app = w.app();
    let word = FakeApp::new(&w.sb.applications, "Word", "com.foo.Word").build();
    w.platform.sign(
        &app,
        "ABCDE12345",
        &["ABCDE12345.com.foo.bar", "ABCDE12345.com.foo.office"],
    );
    w.platform
        .sign(&word, "ABCDE12345", &["ABCDE12345.com.foo.office"]);
    w.platform.installed = vec![app.clone(), word];
    let own = w
        .touch(&w.user("Group Containers/ABCDE12345.com.foo.bar/x"))
        .parent()
        .unwrap()
        .to_path_buf();
    let shared = w
        .touch(&w.user("Group Containers/ABCDE12345.com.foo.office/x"))
        .parent()
        .unwrap()
        .to_path_buf();
    let undeclared = w
        .touch(&w.user("Group Containers/ABCDE12345.com.foo.legacy/x"))
        .parent()
        .unwrap()
        .to_path_buf();
    let foreign = w
        .touch(&w.user("Group Containers/ZZZZZ99999.com.other/x"))
        .parent()
        .unwrap()
        .to_path_buf();

    let scan = w.scan(&app);

    assert_eq!(find(&scan, &own).unwrap().confidence, Confidence::High);
    assert_eq!(find(&scan, &shared).unwrap().confidence, Confidence::Shared);
    assert_eq!(
        find(&scan, &undeclared).unwrap().confidence,
        Confidence::Low,
        "team-prefixed, but another app of the team is installed"
    );
    assert!(find(&scan, &foreign).is_none());
}

#[test]
fn team_prefixed_group_is_high_when_no_other_app_of_the_team_is_installed() {
    let mut w = World::new();
    let app = w.app();
    w.platform.sign(&app, "ABCDE12345", &[]);
    w.platform.installed = vec![app.clone()];
    let legacy = w
        .touch(&w.user("Group Containers/ABCDE12345.com.foo.legacy/x"))
        .parent()
        .unwrap()
        .to_path_buf();

    let scan = w.scan(&app);

    assert_eq!(find(&scan, &legacy).unwrap().confidence, Confidence::High);
}

#[test]
fn launchd_jobs_match_on_label_program_or_association_and_bring_their_helper() {
    use plist::Value;
    let w = World::new();
    let app = w.app();
    let by_label = w.user("LaunchAgents/whatever.plist");
    common::fake::write_plist(
        &by_label,
        &[("Label", Value::String("com.foo.Bar.agent".into()))],
    );
    let by_program = w.user("LaunchAgents/com.vendor.updater.plist");
    let exe = app
        .join("Contents/MacOS/Bar")
        .to_string_lossy()
        .into_owned();
    common::fake::write_plist(
        &by_program,
        &[
            ("Label", Value::String("com.vendor.updater".into())),
            (
                "ProgramArguments",
                Value::Array(vec![Value::String(exe), Value::String("--update".into())]),
            ),
        ],
    );
    let helper = w.touch(&w.system("Library/PrivilegedHelperTools/com.vendor.helperd"));
    let daemon = w.system("Library/LaunchDaemons/com.vendor.helperd.plist");
    common::fake::write_plist(
        &daemon,
        &[
            ("Label", Value::String("com.vendor.helperd".into())),
            (
                "Program",
                Value::String(helper.to_string_lossy().into_owned()),
            ),
            (
                "AssociatedBundleIdentifiers",
                Value::String("com.foo.Bar".into()),
            ),
        ],
    );
    let unrelated = w.user("LaunchAgents/com.other.agent.plist");
    common::fake::write_plist(
        &unrelated,
        &[("Label", Value::String("com.other.agent".into()))],
    );

    let scan = w.scan(&app);

    for path in [&by_label, &by_program, &daemon, &helper] {
        let c = find(&scan, path).unwrap_or_else(|| panic!("missing {}", path.display()));
        assert_eq!(c.confidence, Confidence::High, "{}", path.display());
    }
    assert_eq!(
        find(&scan, &daemon).unwrap().category,
        Category::LaunchDaemon
    );
    assert_eq!(
        find(&scan, &helper).unwrap().category,
        Category::PrivilegedHelper
    );
    assert!(find(&scan, &unrelated).is_none());
}

#[test]
fn plugins_match_on_their_own_bundle_id() {
    let w = World::new();
    let app = w.app();
    let ours = common::fake::nested_bundle(
        &w.sb.base,
        "Library/QuickLook/BarPreview.qlgenerator",
        "com.foo.Bar.QuickLook",
    );
    let theirs = common::fake::nested_bundle(
        &w.sb.base,
        "Library/QuickLook/Other.qlgenerator",
        "com.other.QL",
    );

    let scan = w.scan(&app);

    let c = find(&scan, &ours).unwrap();
    assert_eq!(
        (c.category, c.confidence),
        (Category::Plugin, Confidence::High)
    );
    assert!(find(&scan, &theirs).is_none());
}

#[test]
fn crash_reports_of_the_executable_are_low_confidence() {
    let w = World::new();
    let app = w.app();
    let report = w.touch(&w.user("Logs/DiagnosticReports/Bar-2026-11-14-101010.ips"));
    let other = w.touch(&w.user("Logs/DiagnosticReports/Barista-2026-11-14-101010.ips"));

    let scan = w.scan(&app);

    assert_eq!(find(&scan, &report).unwrap().confidence, Confidence::Low);
    assert!(find(&scan, &other).is_none());
}

#[test]
fn unreadable_locations_are_reported_as_not_checked() {
    use std::os::unix::fs::PermissionsExt;
    let w = World::new();
    let app = w.app();
    let containers = w.user("Containers");
    w.touch(&containers.join("com.foo.Bar/x"));
    std::fs::set_permissions(&containers, std::fs::Permissions::from_mode(0o000)).unwrap();

    let scan = w.scan(&app);
    std::fs::set_permissions(&containers, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(scan.not_checked.len(), 1);
    assert_eq!(scan.not_checked[0].path, containers);
    assert!(
        scan.candidates
            .iter()
            .all(|c| !c.path.starts_with(&containers))
    );
}

#[test]
fn daemon_containers_and_system_extensions_are_report_only() {
    use maczap_core::discovery::ReportKind;
    let w = World::new();
    let app = w.app();
    let daemon_container = w
        .touch(&w.user("Daemon Containers/com.foo.Bar/x"))
        .parent()
        .unwrap()
        .to_path_buf();
    common::fake::nested_bundle(
        &app,
        "Contents/Library/SystemExtensions/com.foo.Bar.net.systemextension",
        "com.foo.Bar.net",
    );

    let scan = w.scan(&app);

    assert!(find(&scan, &daemon_container).is_none());
    let kinds: Vec<_> = scan.report_only.iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        vec![ReportKind::DaemonContainer, ReportKind::SystemExtension]
    );
}

#[test]
fn every_high_candidate_of_a_realistic_scan_passes_the_guard() {
    use maczap_core::guard::Guard;
    let w = World::new();
    let app = w.app();
    w.touch(&w.user("Caches/com.foo.Bar/db"));
    w.touch(&w.user("Preferences/com.foo.Bar.plist"));
    w.touch(&w.system("Library/Application Support/com.foo.Bar/x"));
    let guard = Guard::new(
        w.catalog
            .roots(std::slice::from_ref(&w.sb.quarantine))
            .unwrap(),
    );

    let scan = w.scan(&app);

    assert!(scan.candidates.len() >= 4);
    for c in scan.candidates {
        let path = c.path.clone();
        guard
            .verify(c)
            .unwrap_or_else(|r| panic!("{}: {r}", path.display()));
    }
}

#[test]
fn background_items_of_the_app_are_reported_and_legacy_login_items_listed() {
    use maczap_core::btm::BtmRecord;
    use maczap_core::discovery::{ReportKind, background_items};
    let w = World::new();
    let app = w.app();
    let identity = AppIdentity::read(&app, &w.platform).unwrap();
    let records = vec![
        BtmRecord {
            name: "BarHelper".into(),
            kind: "login item (0x4)".into(),
            bundle_id: Some("com.foo.Bar.Helper".into()),
            parent_identifier: Some("2.com.foo.Bar".into()),
            url: Some("Contents/Library/LoginItems/Bar%20Helper.app".into()),
            ..Default::default()
        },
        BtmRecord {
            name: "Bar".into(),
            kind: "login item (0x4)".into(),
            flags: "[ legacy ] (0x1)".into(),
            url: Some(format!("file://{}/", app.display())),
            ..Default::default()
        },
        BtmRecord {
            name: "Bar".into(),
            kind: "app (0x2)".into(),
            bundle_id: Some("com.foo.Bar".into()),
            ..Default::default()
        },
        BtmRecord {
            name: "Other".into(),
            bundle_id: Some("com.other.App".into()),
            ..Default::default()
        },
    ];

    let found = background_items(&identity, &records);

    assert_eq!(found.report.len(), 1, "{:#?}", found.report);
    assert_eq!(found.report[0].kind, ReportKind::BackgroundItem);
    assert_eq!(
        found.report[0].path,
        app.join("Contents/Library/LoginItems/Bar Helper.app")
    );
    assert_eq!(found.legacy_login_items, vec!["Bar"]);
}

#[test]
fn locations_given_through_a_symlink_still_produce_guard_approved_candidates() {
    use maczap_core::guard::Guard;
    // getconf answers /var/folders/…, but /var is a symlink to /private/var.
    let sb = Sandbox::new();
    let real_cache = sb.base.join("private/var/folders/zz/C");
    std::fs::create_dir_all(&real_cache).unwrap();
    std::os::unix::fs::symlink(sb.base.join("private/var"), sb.base.join("var")).unwrap();
    let through_link = sb.base.join("var/folders/zz/C");
    let item = sb
        .file(&real_cache.join("com.foo.Bar/x"), "x")
        .parent()
        .unwrap()
        .to_path_buf();
    let catalog = Catalog::standard(&sb.home, &sb.base, Some(&through_link), None);
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    let platform = FakePlatform::default();
    let guard = Guard::new(catalog.roots(&[]).unwrap());

    let found = scan(
        &AppIdentity::read(&app, &platform).unwrap(),
        &catalog,
        &platform,
    );

    let c = found
        .candidates
        .iter()
        .find(|c| c.path.ends_with("com.foo.Bar") && c.category == Category::TempData);
    let c = c.expect("temp data candidate").clone();
    assert_eq!(c.path, item);
    guard.verify(c).unwrap();
}

#[test]
fn merging_another_source_keeps_the_strongest_confidence_per_path() {
    use maczap_core::candidate::Candidate;
    let w = World::new();
    let app = w.app();
    let prefs = w.touch(&w.user("Preferences/com.foo.Bar.plist"));
    let extra = w
        .touch(&w.user("Application Support/Bar Data/x"))
        .parent()
        .unwrap()
        .to_path_buf();
    let mut found = w.scan(&app);
    let curated = |path: &Path| Candidate {
        path: path.to_path_buf(),
        category: Category::Preferences,
        confidence: Confidence::Curated,
        reason: "zap".into(),
    };

    found.merge(vec![curated(&prefs), curated(&extra)]);

    assert_eq!(find(&found, &prefs).unwrap().confidence, Confidence::High);
    assert_eq!(
        find(&found, &extra).unwrap().confidence,
        Confidence::Curated
    );
    assert_eq!(
        found.candidates.iter().filter(|c| c.path == prefs).count(),
        1
    );
}

const UUID_A: &str = "E411BE18-8E0E-4A6B-82EA-7377E741432A";
const UUID_B: &str = "8BDD2EA5-581C-4864-BF0C-AD5C09FFBF77";
const UUID_C: &str = "2AEA99C8-B034-4CE2-8373-3C1EAB5395A3";
const UUID_D: &str = "1A63FC79-6CC5-4B82-97BA-8DA3DAF7EC83";

impl World {
    fn ios_app(&self) -> PathBuf {
        let (outer, inner) = common::fake::wrapped_ios_app(
            &self.sb.applications,
            "iMoney",
            "BetterSpend",
            "com.foo.BetterSpend",
            "iMoney",
        );
        common::fake::flat_nested_bundle(
            &inner,
            "PlugIns/Widget.appex",
            "com.foo.BetterSpend.Widget",
        );
        outer
    }
}

#[test]
fn ios_app_containers_named_by_uuid_match_on_their_metadata() {
    let w = World::new();
    let app = w.ios_app();
    let own = common::fake::ios_container(&w.sb.home, UUID_A, "com.foo.BetterSpend");
    let widget = common::fake::ios_container(&w.sb.home, UUID_B, "com.foo.BetterSpend.Widget");
    let other = common::fake::ios_container(&w.sb.home, UUID_C, "com.other.App");
    let no_metadata = w
        .touch(&w.user(&format!("Containers/{UUID_D}/x")))
        .parent()
        .unwrap()
        .to_path_buf();
    // Application Scripts uses the UUID of the container it belongs to.
    let scripts = w.user(&format!("Application Scripts/{UUID_A}"));
    std::fs::create_dir_all(&scripts).unwrap();
    let other_scripts = w.user(&format!("Application Scripts/{UUID_C}"));
    std::fs::create_dir_all(&other_scripts).unwrap();

    let scan = w.scan(&app);

    let bundle = find(&scan, &app).unwrap();
    assert_eq!(bundle.category, Category::AppBundle);
    for path in [&own, &widget] {
        let c = find(&scan, path).unwrap_or_else(|| panic!("{} not found", path.display()));
        assert_eq!(c.category, Category::Containers);
        assert_eq!(c.confidence, Confidence::High);
        assert!(c.reason.contains("UUID"), "{}", c.reason);
    }
    let s = find(&scan, &scripts).unwrap();
    assert_eq!(s.category, Category::ApplicationScripts);
    assert_eq!(s.confidence, Confidence::High);
    for path in [&other, &no_metadata, &other_scripts] {
        assert!(find(&scan, path).is_none(), "{} matched", path.display());
    }
    assert!(scan.not_checked.is_empty());
}

#[test]
fn uuid_containers_are_shared_when_another_installed_copy_has_the_id() {
    let mut w = World::new();
    let app = w.ios_app();
    let copy = FakeApp::new(
        &w.sb.home.join("Applications"),
        "BetterSpend",
        "com.foo.BetterSpend",
    )
    .build();
    w.platform.installed = vec![app.clone(), copy];
    let own = common::fake::ios_container(&w.sb.home, UUID_A, "com.foo.BetterSpend");

    let scan = w.scan(&app);

    assert_eq!(find(&scan, &own).unwrap().confidence, Confidence::Shared);
}

#[test]
fn uuid_containers_are_not_read_for_mac_apps() {
    let w = World::new();
    let app = w.app();
    let container = common::fake::ios_container(&w.sb.home, UUID_A, "com.foo.Bar");

    let scan = w.scan(&app);

    assert!(find(&scan, &container).is_none());
}

#[test]
fn unreadable_container_metadata_is_reported_as_not_checked() {
    use std::os::unix::fs::PermissionsExt;
    let w = World::new();
    let app = w.ios_app();
    let container = common::fake::ios_container(&w.sb.home, UUID_A, "com.foo.BetterSpend");
    let metadata = container.join(".com.apple.containermanagerd.metadata.plist");
    std::fs::set_permissions(&metadata, std::fs::Permissions::from_mode(0o000)).unwrap();

    let scan = w.scan(&app);
    std::fs::set_permissions(&metadata, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert!(find(&scan, &container).is_none());
    assert_eq!(scan.not_checked.len(), 1);
    assert_eq!(scan.not_checked[0].path, metadata);
}

#[test]
fn every_candidate_of_an_ios_app_scan_passes_the_guard() {
    use maczap_core::guard::Guard;
    let w = World::new();
    let app = w.ios_app();
    common::fake::ios_container(&w.sb.home, UUID_A, "com.foo.BetterSpend");
    std::fs::create_dir_all(w.user(&format!("Application Scripts/{UUID_A}"))).unwrap();
    let guard = Guard::new(
        w.catalog
            .roots(std::slice::from_ref(&w.sb.quarantine))
            .unwrap(),
    );

    let scan = w.scan(&app);

    assert_eq!(scan.candidates.len(), 3, "{:#?}", scan.candidates);
    for c in scan.candidates {
        let path = c.path.clone();
        guard
            .verify(c)
            .unwrap_or_else(|r| panic!("{}: {r}", path.display()));
    }
}

#[test]
fn only_uuid_named_containers_with_real_metadata_files_are_read() {
    let w = World::new();
    let app = w.ios_app();
    // Named like another app, but its metadata claims ours: the name wins.
    let misnamed = common::fake::ios_container(&w.sb.home, "com.other.App", "com.foo.BetterSpend");
    // Metadata that is a symlink to a plist naming our id is not followed.
    let elsewhere = common::fake::ios_container(&w.sb.base, UUID_D, "com.foo.BetterSpend");
    let linked = w.user(&format!("Containers/{UUID_A}"));
    std::fs::create_dir_all(&linked).unwrap();
    std::os::unix::fs::symlink(
        elsewhere.join(".com.apple.containermanagerd.metadata.plist"),
        linked.join(".com.apple.containermanagerd.metadata.plist"),
    )
    .unwrap();

    let scan = w.scan(&app);

    assert!(find(&scan, &misnamed).is_none());
    assert!(find(&scan, &linked).is_none());
    assert!(scan.not_checked.is_empty());
}
