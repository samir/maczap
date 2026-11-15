//! Who the target app is: ids, names and signature facts (DESIGN §3.1).

use std::path::{Path, PathBuf};

use plist::Value;
use serde::Serialize;

use crate::platform::Platform;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppIdentity {
    pub path: PathBuf,
    pub bundle_id: String,
    pub name: String,
    pub version: Option<String>,
    pub executable: Option<String>,
    /// Bundle ids of helpers, extensions and XPC services inside the bundle.
    pub nested_ids: Vec<String>,
    pub team_id: Option<String>,
    /// App groups declared by the app or any nested bundle.
    pub app_groups: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("{0} is not an application bundle (no Contents/Info.plist)")]
    NotABundle(PathBuf),
    #[error("cannot read {path}: {source}")]
    Plist { path: PathBuf, source: plist::Error },
    #[error("{0} has no CFBundleIdentifier")]
    NoBundleId(PathBuf),
}

impl AppIdentity {
    pub fn read(bundle: &Path, platform: &dyn Platform) -> Result<Self, IdentityError> {
        let info = read_info_plist(bundle)?;
        let bundle_id = string(&info, "CFBundleIdentifier")
            .ok_or_else(|| IdentityError::NoBundleId(bundle.to_path_buf()))?;
        let name = string(&info, "CFBundleDisplayName")
            .or_else(|| string(&info, "CFBundleName"))
            .or_else(|| bundle.file_stem().map(|s| s.to_string_lossy().into_owned()))
            .unwrap_or_else(|| bundle_id.clone());
        let nested = nested_bundles(bundle);
        let main_signature = platform.code_signature(bundle);
        let team_id = main_signature.as_ref().and_then(|s| s.team_id.clone());
        let app_groups = std::iter::once(main_signature)
            .chain(nested.iter().map(|(path, _)| platform.code_signature(path)))
            .flatten()
            .flat_map(|s| s.app_groups)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let nested_ids = nested
            .into_iter()
            .map(|(_, id)| id)
            .chain(launch_services_helpers(bundle))
            .filter(|id| id != &bundle_id && !id.starts_with("com.apple."))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(AppIdentity {
            path: bundle.to_path_buf(),
            bundle_id,
            name,
            version: string(&info, "CFBundleShortVersionString")
                .or_else(|| string(&info, "CFBundleVersion")),
            executable: string(&info, "CFBundleExecutable"),
            nested_ids,
            team_id,
            app_groups,
        })
    }
}

/// Extensions of nested bundles whose ids identify parts of this app. Frameworks,
/// `.bundle` and `.plugin` are skipped: they are often third-party SDKs whose ids are
/// shared with every other app embedding them.
const NESTED_EXTENSIONS: &[&str] = &["app", "appex", "xpc", "systemextension"];
const MAX_DEPTH: usize = 8;

/// (path, bundle id) of every nested app, extension, XPC service and system extension.
pub fn nested_bundles(bundle: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    walk(&bundle.join("Contents"), 0, &mut found);
    found.sort();
    found
}

fn walk(dir: &Path, depth: usize, found: &mut Vec<(PathBuf, String)>) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if !kind.is_dir() {
            continue;
        }
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if ext == "framework" {
            continue;
        }
        if NESTED_EXTENSIONS.contains(&ext)
            && let Ok(info) = read_info_plist(&path)
            && let Some(id) = string(&info, "CFBundleIdentifier")
        {
            found.push((path.clone(), id));
        }
        walk(&path, depth + 1, found);
    }
}

/// Privileged helper tools shipped for `SMJobBless` are plain executables in
/// `Contents/Library/LaunchServices`, named after their launchd label.
fn launch_services_helpers(bundle: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(bundle.join("Contents/Library/LaunchServices")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains('.') && !name.starts_with('.'))
        .collect()
}

/// Reads `<bundle>/Contents/Info.plist` (XML or binary).
pub fn read_info_plist(bundle: &Path) -> Result<plist::Dictionary, IdentityError> {
    let path = bundle.join("Contents/Info.plist");
    if !path.is_file() {
        return Err(IdentityError::NotABundle(bundle.to_path_buf()));
    }
    let value = Value::from_file(&path).map_err(|source| IdentityError::Plist {
        path: path.clone(),
        source,
    })?;
    match value {
        Value::Dictionary(dict) => Ok(dict),
        _ => Err(IdentityError::NotABundle(bundle.to_path_buf())),
    }
}

fn string(dict: &plist::Dictionary, key: &str) -> Option<String> {
    dict.get(key)
        .and_then(Value::as_string)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
