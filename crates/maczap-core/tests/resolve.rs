mod common;

use common::Sandbox;
use common::fake::{FakeApp, FakePlatform};
use maczap_core::resolve::{Resolution, protection, resolve};

#[test]
fn resolves_a_path_a_bundle_id_or_a_name() {
    let sb = Sandbox::new();
    let bar = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    let other = FakeApp::new(&sb.applications, "Other", "com.other.App").build();
    let platform = FakePlatform {
        installed: vec![bar.clone(), other],
        ..Default::default()
    };

    assert_eq!(
        resolve(bar.to_str().unwrap(), &platform).unwrap(),
        Resolution::One(bar.clone())
    );
    assert_eq!(
        resolve("com.foo.bar", &platform).unwrap(),
        Resolution::One(bar.clone())
    );
    assert_eq!(
        resolve("bar", &platform).unwrap(),
        Resolution::One(bar.clone())
    );
    assert_eq!(resolve("Nope", &platform).unwrap(), Resolution::None);
}

#[test]
fn several_matches_are_returned_for_the_user_to_choose() {
    let sb = Sandbox::new();
    let a = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    let b = FakeApp::new(&sb.home.join("Applications"), "Bar", "com.foo.Bar").build();
    let platform = FakePlatform {
        installed: vec![a.clone(), b.clone()],
        ..Default::default()
    };

    assert_eq!(
        resolve("Bar", &platform).unwrap(),
        Resolution::Many(vec![a, b])
    );
}

#[test]
fn name_search_ignores_helper_apps_nested_inside_other_bundles() {
    let sb = Sandbox::new();
    let host = FakeApp::new(&sb.applications, "Host", "com.foo.Host").build();
    let helper = FakeApp::new(
        &host.join("Contents/Library/LoginItems"),
        "Bar",
        "com.foo.Host.Bar",
    )
    .build();
    let platform = FakePlatform {
        installed: vec![host, helper],
        ..Default::default()
    };

    assert_eq!(resolve("Bar", &platform).unwrap(), Resolution::None);
}

#[test]
fn a_path_that_is_not_an_app_bundle_is_an_error() {
    let sb = Sandbox::new();
    let platform = FakePlatform::default();
    assert!(resolve(sb.home.to_str().unwrap(), &platform).is_err());
    assert!(resolve("/nonexistent/Thing.app", &platform).is_err());
}

#[test]
fn apple_and_system_apps_are_refused() {
    let sb = Sandbox::new();
    let apple = FakeApp::new(&sb.applications, "Pages", "com.apple.iWork.Pages").build();
    let ours = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    let platform = FakePlatform::default();
    let read = |p| maczap_core::identity::AppIdentity::read(p, &platform).unwrap();

    assert!(protection(&read(&apple), &sb.base).is_err());
    assert!(protection(&read(&ours), &sb.base).is_ok());
    let system_app = FakeApp::new(
        &sb.base.join("System/Applications"),
        "Tool",
        "com.vendor.Tool",
    )
    .build();
    assert!(protection(&read(&system_app), &sb.base).is_err());
}

#[test]
fn apps_with_mdm_managed_preferences_are_refused() {
    let sb = Sandbox::new();
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    sb.file(
        &sb.base
            .join("Library/Managed Preferences/com.foo.Bar.plist"),
        "x",
    );
    let platform = FakePlatform::default();
    let identity = maczap_core::identity::AppIdentity::read(&app, &platform).unwrap();

    let refusal = protection(&identity, &sb.base).unwrap_err();
    assert!(refusal.to_string().contains("managed"), "{refusal}");
}
