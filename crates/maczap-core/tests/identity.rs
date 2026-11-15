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

#[test]
fn reads_a_wrapped_ios_app_from_its_inner_bundle() {
    let sb = Sandbox::new();
    let (outer, inner) = common::fake::wrapped_ios_app(
        &sb.applications,
        "iMoney",
        "BetterSpend",
        "com.foo.BetterSpend",
        "iMoney",
    );
    common::fake::flat_nested_bundle(&inner, "PlugIns/Widget.appex", "com.foo.BetterSpend.Widget");

    let id = AppIdentity::read(&outer, &FakePlatform::default()).unwrap();

    assert_eq!(id.path, outer, "the wrapper is the app: it is what moves");
    assert_eq!(id.bundle_id, "com.foo.BetterSpend");
    assert_eq!(id.name, "iMoney");
    assert_eq!(id.executable.as_deref(), Some("BetterSpend"));
    assert_eq!(id.nested_ids, vec!["com.foo.BetterSpend.Widget"]);
    assert!(id.ios_app);
}

#[test]
fn a_mac_app_is_not_an_ios_app() {
    let sb = Sandbox::new();
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();

    assert!(
        !AppIdentity::read(&app, &FakePlatform::default())
            .unwrap()
            .ios_app
    );
}

#[test]
fn a_wrapper_whose_link_leaves_the_wrapper_is_not_a_bundle() {
    let sb = Sandbox::new();
    let elsewhere = FakeApp::new(&sb.base, "Elsewhere", "com.foo.Elsewhere").build();
    let outer = sb.applications.join("Trap.app");
    std::fs::create_dir_all(outer.join("Wrapper")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, outer.join("WrappedBundle")).unwrap();
    // Nor does a wrapper whose inner "bundle" is itself a symlink out.
    let outer2 = sb.applications.join("Trap2.app");
    std::fs::create_dir_all(outer2.join("Wrapper")).unwrap();
    let flat = common::fake::flat_nested_bundle(&sb.base, "Flat.app", "com.foo.Flat");
    std::os::unix::fs::symlink(&flat, outer2.join("Wrapper/Flat.app")).unwrap();

    assert!(matches!(
        AppIdentity::read(&outer, &FakePlatform::default()),
        Err(IdentityError::NotABundle(_))
    ));
    assert!(matches!(
        AppIdentity::read(&outer2, &FakePlatform::default()),
        Err(IdentityError::NotABundle(_))
    ));
}

#[test]
fn the_inner_bundle_is_found_without_the_link_and_the_link_picks_among_several() {
    let sb = Sandbox::new();
    let (outer, _) =
        common::fake::wrapped_ios_app(&sb.applications, "Solo", "Solo", "com.foo.Solo", "Solo");
    std::fs::remove_file(outer.join("WrappedBundle")).unwrap();
    // CFBundleSupportedPlatforms is optional: the wrapper alone makes it an iOS app.
    let info = outer.join("Wrapper/Solo.app/Info.plist");
    let mut dict = plist::Value::from_file(&info)
        .unwrap()
        .into_dictionary()
        .unwrap();
    dict.remove("CFBundleSupportedPlatforms");
    plist::Value::Dictionary(dict).to_file_xml(&info).unwrap();

    let (pair, _) =
        common::fake::wrapped_ios_app(&sb.applications, "Pair", "Second", "com.foo.Second", "Pair");
    common::fake::flat_nested_bundle(&pair, "Wrapper/First.app", "com.foo.First");
    let platform = FakePlatform::default();

    let solo = AppIdentity::read(&outer, &platform).unwrap();
    assert_eq!(solo.bundle_id, "com.foo.Solo");
    assert!(solo.ios_app);
    assert_eq!(
        AppIdentity::read(&pair, &platform).unwrap().bundle_id,
        "com.foo.Second"
    );
}
