mod common;

use std::path::PathBuf;

use common::Sandbox;
use common::fake::{FakeApp, FakePlatform};
use maczap_core::candidate::Category;
use maczap_core::identity::AppIdentity;
use maczap_core::receipts;

#[test]
fn takes_exclusive_receipt_paths_and_collapses_fully_owned_directories() {
    let sb = Sandbox::new();
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    let support = sb.base.join("Library/Application Support/BarVendor");
    let a = sb.file(&support.join("a.dat"), "x");
    let b = sb.file(&support.join("sub/b.dat"), "x");
    let tool = sb.file(&sb.base.join("usr/local/bin/bar"), "x");
    let mut platform = FakePlatform::default();
    platform.receipt(
        "com.foo.Bar.pkg",
        &[
            app.clone(),
            support.clone(),
            a,
            support.join("sub"),
            b,
            tool.clone(),
        ],
    );

    let identity = AppIdentity::read(&app, &platform).unwrap();
    let scan = receipts::scan(&identity, &platform);

    let paths: Vec<&PathBuf> = scan.candidates.iter().map(|c| &c.path).collect();
    assert_eq!(
        paths,
        vec![&support, &tool],
        "the directory is taken whole; the bundle is skipped"
    );
    assert!(
        scan.candidates
            .iter()
            .all(|c| c.category == Category::ReceiptFile)
    );
    assert_eq!(scan.packages, vec!["com.foo.Bar.pkg"]);
}

#[test]
fn skips_paths_other_packages_also_list_and_directories_with_foreign_content() {
    let sb = Sandbox::new();
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    let shared_dir = sb.base.join("Library/Application Support/Shared");
    let ours = sb.file(&shared_dir.join("ours.dat"), "x");
    sb.file(&shared_dir.join("user-data.txt"), "not in any receipt");
    let shared_file = sb.file(&sb.base.join("usr/local/lib/libcommon.dylib"), "x");
    let mut platform = FakePlatform::default();
    platform.receipt(
        "com.foo.Bar.pkg",
        &[
            app.clone(),
            shared_dir.clone(),
            ours.clone(),
            shared_file.clone(),
        ],
    );
    platform.receipt("com.other.pkg", std::slice::from_ref(&shared_file));

    let identity = AppIdentity::read(&app, &platform).unwrap();
    let scan = receipts::scan(&identity, &platform);

    let paths: Vec<&PathBuf> = scan.candidates.iter().map(|c| &c.path).collect();
    assert_eq!(
        paths,
        vec![&ours],
        "only the exclusive file inside a mixed directory"
    );
}

#[test]
fn an_app_without_a_receipt_yields_nothing() {
    let sb = Sandbox::new();
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    let platform = FakePlatform::default();

    let identity = AppIdentity::read(&app, &platform).unwrap();
    let scan = receipts::scan(&identity, &platform);

    assert!(scan.candidates.is_empty() && scan.packages.is_empty());
}

#[test]
fn finds_receipts_named_after_the_bundle_id_even_without_a_file_index() {
    // App Store style: `pkgutil --file-info` knows nothing, but a receipt with the
    // bundle id as package id lists the bundle.
    let sb = Sandbox::new();
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    let mut platform = FakePlatform::default();
    platform.receipts.insert(
        "com.foo.Bar".into(),
        vec![app.clone(), app.join("Contents")],
    );
    // Same id but not listing this bundle: not ours.
    let other = FakeApp::new(&sb.applications, "Baz", "com.foo.Baz").build();
    platform.receipts.insert(
        "com.foo.Baz".into(),
        vec![sb.applications.join("Elsewhere.app")],
    );

    let identity = AppIdentity::read(&app, &platform).unwrap();
    assert_eq!(
        receipts::scan(&identity, &platform).packages,
        vec!["com.foo.Bar"]
    );
    let identity = AppIdentity::read(&other, &platform).unwrap();
    assert!(receipts::scan(&identity, &platform).packages.is_empty());
}
