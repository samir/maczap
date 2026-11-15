mod common;

use common::{Sandbox, candidate};
use maczap_core::guard::{Guard, Rejection};

#[test]
fn accepts_an_item_strictly_inside_an_allowed_root() {
    let sb = Sandbox::new();
    let item = sb.file(&sb.caches.join("com.foo.Bar/cache.db"), "x");
    let item_dir = item.parent().unwrap();

    let verified = Guard::new(sb.roots()).verify(candidate(item_dir)).unwrap();

    assert_eq!(verified.path(), item_dir);
}

#[test]
fn rejects_dot_dot_components_that_escape_the_root() {
    let sb = Sandbox::new();
    let victim = sb.file(&sb.base.join("victim/important.txt"), "keep me");
    let sneaky = sb.caches.join("../../../../victim/important.txt");
    assert!(
        sneaky.exists(),
        "fixture: the sneaky path must resolve to the victim"
    );
    assert!(victim.exists());

    let result = Guard::new(sb.roots()).verify(candidate(&sneaky));

    assert_eq!(result.unwrap_err(), Rejection::NotNormalized);
}

#[test]
fn rejects_relative_paths() {
    let sb = Sandbox::new();
    let result = Guard::new(sb.roots()).verify(candidate("Library/Caches/com.foo.Bar"));
    assert_eq!(result.unwrap_err(), Rejection::NotNormalized);
}

#[test]
fn rejects_an_allowed_root_itself() {
    let sb = Sandbox::new();
    let result = Guard::new(sb.roots()).verify(candidate(&sb.caches));
    assert_eq!(result.unwrap_err(), Rejection::RootOrAncestor);
}

#[test]
fn rejects_an_ancestor_of_an_allowed_root() {
    let sb = Sandbox::new();
    let guard = Guard::new(sb.roots());
    for ancestor in [sb.home.join("Library"), sb.home.clone(), sb.base.clone()] {
        assert_eq!(
            guard.verify(candidate(&ancestor)).unwrap_err(),
            Rejection::RootOrAncestor,
            "{}",
            ancestor.display()
        );
    }
}

#[test]
fn rejects_a_path_whose_parent_is_a_symlink() {
    let sb = Sandbox::new();
    sb.file(&sb.base.join("victim/important.txt"), "keep me");
    std::os::unix::fs::symlink(sb.base.join("victim"), sb.caches.join("com.evil.App")).unwrap();
    let through_link = sb.caches.join("com.evil.App/important.txt");

    let result = Guard::new(sb.roots()).verify(candidate(&through_link));

    assert_eq!(
        result.unwrap_err(),
        Rejection::SymlinkInPath(sb.caches.join("com.evil.App"))
    );
}

#[test]
fn accepts_a_symlink_as_the_item_itself_without_following_it() {
    let sb = Sandbox::new();
    sb.file(&sb.base.join("victim/important.txt"), "keep me");
    let link = sb.caches.join("com.foo.Bar");
    std::os::unix::fs::symlink(sb.base.join("victim"), &link).unwrap();

    let verified = Guard::new(sb.roots()).verify(candidate(&link)).unwrap();

    assert!(verified.fingerprint().is_symlink());
}

#[test]
fn rejects_items_when_the_root_was_replaced_by_a_symlink() {
    let sb = Sandbox::new();
    let roots = sb.roots();
    // After the roots were resolved, something swaps ~/Library/Caches for a link.
    std::fs::remove_dir(&sb.caches).unwrap();
    sb.file(&sb.base.join("victim/com.foo.Bar"), "keep me");
    std::os::unix::fs::symlink(sb.base.join("victim"), &sb.caches).unwrap();

    let result = Guard::new(roots).verify(candidate(sb.caches.join("com.foo.Bar")));

    assert_eq!(
        result.unwrap_err(),
        Rejection::SymlinkInPath(sb.caches.clone())
    );
}

#[test]
fn rejects_anything_under_a_denied_prefix() {
    let sb = Sandbox::new();
    let item = sb.file(&sb.caches.join("Shared/Keep/data"), "x");
    let roots = sb.roots().deny(&sb.caches.join("Shared")).unwrap();

    let result = Guard::new(roots).verify(candidate(&item));

    assert_eq!(
        result.unwrap_err(),
        Rejection::Denied(sb.caches.join("Shared"))
    );
}

#[test]
fn rejects_apple_owned_names_anywhere_below_the_root() {
    let sb = Sandbox::new();
    let guard = Guard::new(sb.roots());
    for name in [
        "com.apple.Safari",
        "group.com.apple.notes",
        "com.apple.dt.Xcode.plist",
    ] {
        let item = sb.file(&sb.caches.join(name), "x");
        assert_eq!(
            guard.verify(candidate(&item)).unwrap_err(),
            Rejection::AppleOwned,
            "{name}"
        );
    }
    let nested = sb.file(&sb.app_support.join("com.apple.TCC/TCC.db"), "x");
    assert_eq!(
        guard.verify(candidate(&nested)).unwrap_err(),
        Rejection::AppleOwned
    );
}

#[test]
fn rejects_protected_paths_their_ancestors_and_descendants() {
    let sb = Sandbox::new();
    // Like the system quarantine: /Library/Application Support/maczap/quarantine.
    let own_state = sb.app_support.join("maczap/quarantine");
    sb.file(&own_state.join("batch/item"), "x");
    let roots = sb.roots().protect(&own_state).unwrap();
    let guard = Guard::new(roots);

    for path in [
        sb.app_support.join("maczap"),
        own_state.clone(),
        own_state.join("batch/item"),
    ] {
        assert_eq!(
            guard.verify(candidate(&path)).unwrap_err(),
            Rejection::Protected,
            "{}",
            path.display()
        );
    }
}

#[test]
fn rejects_shared_resources_even_inside_an_allowed_root() {
    let sb = Sandbox::new();
    let item = sb.file(&sb.app_support.join("UBF8T346G9.Office/data"), "x");
    let mut shared = candidate(item.parent().unwrap());
    shared.confidence = maczap_core::candidate::Confidence::Shared;

    let result = Guard::new(sb.roots()).verify(shared);

    assert_eq!(result.unwrap_err(), Rejection::Shared);
}

#[test]
fn rejects_missing_items() {
    let sb = Sandbox::new();
    let result = Guard::new(sb.roots()).verify(candidate(sb.caches.join("com.gone.App")));
    assert_eq!(result.unwrap_err(), Rejection::Missing);
}

#[test]
fn reports_which_root_and_scope_accepted_the_item() {
    let sb = Sandbox::new();
    let plist = sb.file(&sb.system_daemons.join("com.foo.helper.plist"), "x");

    let verified = Guard::new(sb.roots()).verify(candidate(&plist)).unwrap();

    assert_eq!(verified.root().path, sb.system_daemons);
    assert_eq!(verified.root().scope, maczap_core::roots::Scope::System);
}

#[test]
fn protection_and_apple_rules_ignore_case_like_apfs_does() {
    let sb = Sandbox::new();
    let own_state = sb.app_support.join("maczap");
    sb.file(&own_state.join("quarantine/item"), "x");
    let denied_dir = sb.caches.join("Keep");
    sb.file(&denied_dir.join("data"), "x");
    let guard = Guard::new(
        sb.roots()
            .protect(&own_state)
            .unwrap()
            .deny(&denied_dir)
            .unwrap(),
    );

    // On a case-insensitive volume these names reach the very same files.
    let protected_alias = sb.app_support.join("MACZAP");
    assert!(
        protected_alias.exists(),
        "fixture expects a case-insensitive volume"
    );
    assert_eq!(
        guard.verify(candidate(&protected_alias)).unwrap_err(),
        Rejection::Protected
    );

    let denied_alias = sb.caches.join("KEEP/data");
    assert!(matches!(
        guard.verify(candidate(&denied_alias)).unwrap_err(),
        Rejection::Denied(_)
    ));

    let apple = sb.file(&sb.caches.join("COM.APPLE.Music"), "x");
    assert_eq!(
        guard.verify(candidate(&apple)).unwrap_err(),
        Rejection::AppleOwned
    );
}
