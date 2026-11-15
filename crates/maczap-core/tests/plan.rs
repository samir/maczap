mod common;

use common::Sandbox;
use common::fake::{FakeApp, FakePlatform};
use maczap_core::candidate::{Candidate, Category, Confidence};
use maczap_core::catalog::Catalog;
use maczap_core::discovery::Scan;
use maczap_core::guard::{Guard, Rejection};
use maczap_core::identity::AppIdentity;
use maczap_core::plan::{Plan, PlanOptions};

struct Setup {
    sb: Sandbox,
    guard: Guard,
    scan: Scan,
}

fn setup(candidates: &[(&str, Confidence)]) -> Setup {
    let sb = Sandbox::new();
    let app = FakeApp::new(&sb.applications, "Bar", "com.foo.Bar").build();
    let catalog = Catalog::standard(&sb.home, &sb.base, None, None);
    let guard = Guard::new(catalog.roots(std::slice::from_ref(&sb.quarantine)).unwrap());
    let identity = AppIdentity::read(&app, &FakePlatform::default()).unwrap();
    let mut list = vec![Candidate {
        path: app.clone(),
        category: Category::AppBundle,
        confidence: Confidence::High,
        reason: "bundle".into(),
    }];
    for (relative, confidence) in candidates {
        let path = sb.file(&sb.home.join(relative), "x");
        list.push(Candidate {
            path,
            category: Category::Caches,
            confidence: *confidence,
            reason: "t".into(),
        });
    }
    let scan = Scan {
        identity,
        candidates: list,
        not_checked: vec![],
        report_only: vec![],
        receipts: vec![],
        legacy_login_items: vec![],
    };
    Setup { sb, guard, scan }
}

fn me() -> u32 {
    rustix::process::getuid().as_raw()
}

#[test]
fn selects_high_and_curated_but_not_low_by_default() {
    let s = setup(&[
        ("Library/Caches/high", Confidence::High),
        ("Library/Caches/curated", Confidence::Curated),
        ("Library/Caches/low", Confidence::Low),
    ]);

    let plan = Plan::new(&s.scan, &s.guard, PlanOptions::default(), me());

    let selected: Vec<bool> = plan.items.iter().map(|i| i.selected).collect();
    assert_eq!(selected, vec![true, true, true, false]);
}

#[test]
fn include_low_selects_low_confidence_items_too() {
    let s = setup(&[("Library/Caches/low", Confidence::Low)]);

    let plan = Plan::new(&s.scan, &s.guard, PlanOptions { include_low: true }, me());

    assert!(plan.items.iter().all(|i| i.selected));
}

#[test]
fn rejected_items_are_never_selected_and_keep_the_reason() {
    let s = setup(&[
        ("Library/Caches/shared", Confidence::Shared),
        ("Documents/outside", Confidence::High),
    ]);

    let mut plan = Plan::new(&s.scan, &s.guard, PlanOptions { include_low: true }, me());

    assert_eq!(
        plan.items[1].verdict.as_ref().unwrap_err(),
        &Rejection::Shared
    );
    assert_eq!(
        plan.items[2].verdict.as_ref().unwrap_err(),
        &Rejection::OutsideAllowedRoots
    );
    assert!(!plan.items[1].selected && !plan.items[2].selected);
    assert!(
        !plan.set_selected(2, true),
        "a rejected item cannot be selected"
    );
    assert!(!plan.items[2].selected);
    let _ = &s.sb;
}

#[test]
fn items_owned_by_someone_else_need_root() {
    let s = setup(&[("Library/Caches/high", Confidence::High)]);

    let as_me = Plan::new(&s.scan, &s.guard, PlanOptions::default(), me());
    let as_other = Plan::new(&s.scan, &s.guard, PlanOptions::default(), me() + 1);

    assert!(as_me.items.iter().all(|i| !i.needs_root));
    assert!(as_other.items.iter().all(|i| i.needs_root));
    assert_eq!(as_me.selected().count(), 2);
}
