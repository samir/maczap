//! Turns what the user typed into an application bundle (DESIGN §2), and refuses apps
//! maczap must never touch (DESIGN §3.6).

use std::path::{Path, PathBuf};

use plist::Value;

use crate::identity::{AppIdentity, read_info_plist, wrapper_of};
use crate::platform::Platform;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    One(PathBuf),
    /// Several apps match; the user must pick one (never guessed, even with `--yes`).
    Many(Vec<PathBuf>),
    None,
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("{0} is not an application bundle")]
    NotAnApp(PathBuf),
}

/// `query` is a path (contains `/` or ends with `.app`), a bundle id, or an app name.
/// Bundle ids and names are compared without case; name search skips helper apps
/// nested inside other bundles.
pub fn resolve(query: &str, platform: &dyn Platform) -> Result<Resolution, ResolveError> {
    if query.contains('/') || query.to_ascii_lowercase().ends_with(".app") {
        let path = Path::new(query)
            .canonicalize()
            .map_err(|_| ResolveError::NotAnApp(PathBuf::from(query)))?;
        if read_info_plist(&path).is_err() {
            return Err(ResolveError::NotAnApp(path));
        }
        return Ok(Resolution::One(wrapper_of(&path).unwrap_or(path)));
    }

    let apps: Vec<(PathBuf, plist::Dictionary)> = platform
        .installed_apps()
        .into_iter()
        // The inner bundle of an iOS app wrapper is the wrapper's app, not another one.
        .map(|p| wrapper_of(&p).unwrap_or(p))
        .filter_map(|p| read_info_plist(&p).ok().map(|info| (p, info)))
        .collect();
    let field = |info: &plist::Dictionary, key: &str| {
        info.get(key).and_then(Value::as_string).map(str::to_string)
    };

    let by_id: Vec<PathBuf> = apps
        .iter()
        .filter(|(_, info)| {
            field(info, "CFBundleIdentifier").is_some_and(|id| id.eq_ignore_ascii_case(query))
        })
        .map(|(p, _)| p.clone())
        .collect();
    if !by_id.is_empty() {
        return Ok(many_or_one(by_id));
    }

    let by_name: Vec<PathBuf> = apps
        .iter()
        .filter(|(path, _)| !is_nested_in_another_bundle(path))
        .filter(|(path, info)| {
            let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned());
            [
                stem,
                field(info, "CFBundleName"),
                field(info, "CFBundleDisplayName"),
            ]
            .into_iter()
            .flatten()
            .any(|n| n.eq_ignore_ascii_case(query))
        })
        .map(|(p, _)| p.clone())
        .collect();
    Ok(many_or_one(by_name))
}

fn many_or_one(mut paths: Vec<PathBuf>) -> Resolution {
    paths.sort();
    paths.dedup();
    match paths.len() {
        0 => Resolution::None,
        1 => Resolution::One(paths.remove(0)),
        _ => Resolution::Many(paths),
    }
}

fn is_nested_in_another_bundle(path: &Path) -> bool {
    path.parent().is_some_and(|parent| {
        parent
            .ancestors()
            .any(|a| a.extension().is_some_and(|e| e == "app"))
    })
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("`{0}` is an Apple app; maczap never removes Apple software")]
    Apple(String),
    #[error("{0} is on the system volume")]
    SystemVolume(PathBuf),
    #[error("`{0}` is managed by your organization (MDM managed preferences found)")]
    Managed(String),
}

/// Refuses Apple apps, apps on the sealed system volume and MDM-managed apps.
/// `system_root` is `/` in production.
pub fn protection(identity: &AppIdentity, system_root: &Path) -> Result<(), Refusal> {
    if identity
        .bundle_id
        .to_ascii_lowercase()
        .starts_with("com.apple.")
    {
        return Err(Refusal::Apple(identity.bundle_id.clone()));
    }
    if identity.path.starts_with(system_root.join("System")) {
        return Err(Refusal::SystemVolume(identity.path.clone()));
    }
    let managed = system_root.join("Library/Managed Preferences");
    let user = std::env::var("USER").unwrap_or_default();
    let plist = format!("{}.plist", identity.bundle_id);
    let candidates = [managed.join(&plist), managed.join(&user).join(&plist)];
    if candidates.iter().any(|p| p.exists()) {
        return Err(Refusal::Managed(identity.bundle_id.clone()));
    }
    Ok(())
}
