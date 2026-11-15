mod common;

use common::Sandbox;
use common::fake::{FakeApp, FakePlatform};
use maczap_core::candidate::{Category, Confidence};
use maczap_core::catalog::Catalog;
use maczap_core::identity::AppIdentity;
use maczap_core::zap;

const BREW_JSON: &str = r#"{
  "formulae": [],
  "casks": [
    {
      "token": "bar",
      "artifacts": [
        { "uninstall": [ { "quit": "com.foo.Bar", "launchctl": ["com.foo.Bar.agent"] } ] },
        { "app": [ "Bar.app" ], "target": "/Applications/Bar.app" },
        { "zap": [ { "trash": [
            "~/Library/Application Support/Bar",
            "~/Library/Saved Application State/com.foo.Bar*.savedState",
            "~/Library/Application Support/com.apple.sharedfilelist/x/com.foo.Bar.sfl*",
            "~/Library/Caches/com.foo.Bar.missing",
            "~/Documents/Bar Projects",
            "/Library/Application Support/BarVendor"
          ], "rmdir": "~/Library/Application Support/BarVendorShared" } ] }
      ],
      "installed": "1.0"
    },
    {
      "token": "renamed",
      "artifacts": [ { "app": [ "Baz Installer.app", { "target": "Baz.app" } ] } ],
      "installed": null
    },
    {
      "token": "other-bar",
      "artifacts": [
        { "app": [ "Bar.app" ] },
        { "zap": [ { "trash": "~/Library/Preferences/com.unrelated.plist" } ] }
      ],
      "installed": null
    }
  ]
}"#;

#[test]
fn parses_apps_ids_and_trash_paths_from_brew_json() {
    let casks = zap::parse(BREW_JSON).unwrap();

    assert_eq!(casks.len(), 3);
    let bar = &casks[0];
    assert_eq!(bar.token, "bar");
    assert_eq!(bar.apps, vec!["Bar.app"]);
    assert_eq!(bar.ids, vec!["com.foo.Bar", "com.foo.Bar.agent"]);
    assert_eq!(bar.trash.len(), 6, "rmdir entries are not trash");
    assert!(bar.installed);
    assert_eq!(
        casks[1].apps,
        vec!["Baz.app"],
        "an app target renames the installed bundle"
    );
    assert_eq!(
        casks[2].trash,
        vec!["~/Library/Preferences/com.unrelated.plist"]
    );
}

#[test]
fn parses_the_api_format_too() {
    let api = r#"[ { "token": "bar", "artifacts": [ { "app": ["Bar.app"] } ] } ]"#;
    let casks = zap::parse(api).unwrap();
    assert_eq!(casks[0].apps, vec!["Bar.app"]);
    assert!(!casks[0].installed);
}

fn identity(sb: &Sandbox) -> AppIdentity {
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    AppIdentity::read(&app, &FakePlatform::default()).unwrap()
}

#[test]
fn finds_the_cask_by_app_name_only_when_it_mentions_the_bundle_id_or_is_installed() {
    let sb = Sandbox::new();
    let id = identity(&sb);
    let casks = zap::parse(BREW_JSON).unwrap();

    assert_eq!(
        zap::find_cask(&casks, &id).map(|c| c.token.as_str()),
        Some("bar")
    );

    // Same app name, no mention of the id, not installed: not trusted.
    let lookalike: Vec<_> = casks
        .iter()
        .filter(|c| c.token == "other-bar")
        .cloned()
        .collect();
    assert!(zap::find_cask(&lookalike, &id).is_none());

    // Installed with Homebrew and the same app name: trusted.
    let mut installed = lookalike.clone();
    installed[0].installed = true;
    assert_eq!(
        zap::find_cask(&installed, &id).map(|c| c.token.as_str()),
        Some("other-bar")
    );
}

#[test]
fn expands_trash_paths_into_curated_candidates_inside_the_catalog_only() {
    let sb = Sandbox::new();
    identity(&sb);
    let support = sb
        .file(&sb.app_support.join("Bar/state"), "x")
        .parent()
        .unwrap()
        .to_path_buf();
    let saved_a = sb.file(
        &sb.home
            .join("Library/Saved Application State/com.foo.Bar.savedState/w"),
        "x",
    );
    let saved_b = sb.file(
        &sb.home
            .join("Library/Saved Application State/com.foo.BarHelper.savedState/w"),
        "x",
    );
    sb.file(
        &sb.app_support
            .join("com.apple.sharedfilelist/x/com.foo.Bar.sfl3"),
        "x",
    );
    sb.file(&sb.home.join("Documents/Bar Projects/p"), "x");
    let vendor = sb
        .file(
            &sb.base.join("Library/Application Support/BarVendor/v"),
            "x",
        )
        .parent()
        .unwrap()
        .to_path_buf();
    let catalog = Catalog::standard(&sb.home, &sb.base, None, None);
    let casks = zap::parse(BREW_JSON).unwrap();

    let found = zap::candidates(&casks[0], &catalog);

    let paths: Vec<_> = found.iter().map(|c| c.path.clone()).collect();
    assert_eq!(
        paths,
        vec![
            support,
            saved_a.parent().unwrap().to_path_buf(),
            saved_b.parent().unwrap().to_path_buf(),
            vendor
        ]
    );
    assert!(found.iter().all(|c| c.confidence == Confidence::Curated));
    assert_eq!(found[0].category, Category::ApplicationSupport);
    assert_eq!(found[1].category, Category::SavedState);
    assert!(found[0].reason.contains("`bar`"));
}

#[test]
fn reads_every_installed_cask_from_the_real_brew() {
    let Some(brew) = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        .into_iter()
        .find(|b| std::path::Path::new(b).exists())
    else {
        eprintln!("Homebrew is not installed: contract not checked");
        return;
    };
    let out = std::process::Command::new(brew)
        .args(["info", "--json=v2", "--installed", "--cask"])
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let raw: serde_json::Value = serde_json::from_str(&text).unwrap();
    let casks = zap::parse(&text).unwrap();
    assert_eq!(casks.len(), raw["casks"].as_array().unwrap().len());
    assert!(casks.iter().all(|c| !c.token.is_empty() && c.installed));
}
