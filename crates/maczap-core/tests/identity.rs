mod common;

use common::Sandbox;
use common::fake::{FakeApp, FakePlatform, nested_bundle};
use maczap_core::identity::{AppIdentity, IdentityError};

#[test]
fn reads_the_basic_facts_from_info_plist() {
    let sb = Sandbox::new();
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar")
        .set("CFBundleShortVersionString", "1.2.3")
        .set("CFBundleExecutable", "BarExe")
        .build();

    let id = AppIdentity::read(&app, &FakePlatform::default()).unwrap();

    assert_eq!(id.bundle_id, "com.foo.Bar");
    assert_eq!(id.name, "Bar");
    assert_eq!(id.version.as_deref(), Some("1.2.3"));
    assert_eq!(id.executable.as_deref(), Some("BarExe"));
    assert_eq!(id.path, app);
}

#[test]
fn collects_nested_bundle_ids_but_not_shared_frameworks() {
    let sb = Sandbox::new();
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    nested_bundle(
        &app,
        "Contents/Library/LoginItems/BarLauncher.app",
        "com.foo.Bar.Launcher",
    );
    nested_bundle(&app, "Contents/XPCServices/Fetch.xpc", "com.foo.Bar.Fetch");
    nested_bundle(&app, "Contents/PlugIns/Share.appex", "com.foo.BarShare");
    nested_bundle(
        &app,
        "Contents/Frameworks/Sparkle.framework",
        "org.sparkle-project.Sparkle",
    );
    nested_bundle(
        &app,
        "Contents/Frameworks/Sparkle.framework/Versions/B/Updater.app",
        "org.sparkle-project.Sparkle.Updater",
    );
    // A privileged helper tool: a plain executable named after its launchd label.
    let helper = app.join("Contents/Library/LaunchServices/com.foo.Bar.PrivilegedHelper");
    std::fs::create_dir_all(helper.parent().unwrap()).unwrap();
    std::fs::write(&helper, "bin").unwrap();

    let id = AppIdentity::read(&app, &FakePlatform::default()).unwrap();

    assert_eq!(
        id.nested_ids,
        vec![
            "com.foo.Bar.Fetch",
            "com.foo.Bar.Launcher",
            "com.foo.Bar.PrivilegedHelper",
            "com.foo.BarShare",
        ]
    );
}

#[test]
fn reads_binary_info_plists() {
    let sb = Sandbox::new();
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar")
        .binary_plist()
        .build();

    let id = AppIdentity::read(&app, &FakePlatform::default()).unwrap();

    assert_eq!(id.bundle_id, "com.foo.Bar");
}

#[test]
fn refuses_a_directory_that_is_not_a_bundle_or_has_no_bundle_id() {
    let sb = Sandbox::new();
    let not_bundle = sb.applications.join("Empty.app");
    std::fs::create_dir_all(&not_bundle).unwrap();
    let no_id = FakeApp::new(&sb.applications, "NoId", "x")
        .remove("CFBundleIdentifier")
        .build();
    let platform = FakePlatform::default();

    assert!(matches!(
        AppIdentity::read(&not_bundle, &platform),
        Err(IdentityError::NotABundle(_))
    ));
    assert!(matches!(
        AppIdentity::read(&no_id, &platform),
        Err(IdentityError::NoBundleId(_))
    ));
}

#[test]
fn takes_team_id_and_app_groups_from_the_app_and_its_nested_bundles() {
    let sb = Sandbox::new();
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    let ext = nested_bundle(&app, "Contents/PlugIns/Share.appex", "com.foo.Bar.Share");
    let mut platform = FakePlatform::default();
    platform.sign(&app, "ABCDE12345", &["ABCDE12345.com.foo.shared"]);
    platform.sign(
        &ext,
        "ABCDE12345",
        &["group.com.foo.bar", "ABCDE12345.com.foo.shared"],
    );

    let id = AppIdentity::read(&app, &platform).unwrap();

    assert_eq!(id.team_id.as_deref(), Some("ABCDE12345"));
    assert_eq!(
        id.app_groups,
        vec!["ABCDE12345.com.foo.shared", "group.com.foo.bar"]
    );
}

#[test]
fn an_unsigned_app_has_no_team_id_or_groups() {
    let sb = Sandbox::new();
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();

    let id = AppIdentity::read(&app, &FakePlatform::default()).unwrap();

    assert_eq!(id.team_id, None);
    assert!(id.app_groups.is_empty());
}
