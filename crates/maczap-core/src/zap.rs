//! Homebrew cask `zap` stanzas as a curated source (DESIGN §3.2, Q21).
//!
//! Parses `brew info --json=v2 --cask` output (or the API's cask list), finds the cask
//! of the target app, and expands its `zap trash:` paths into `Curated` candidates.
//! Paths outside the catalog, and Apple-owned names, are dropped: the guard would
//! keep them anyway, and listing them would only add noise.

use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::candidate::{Candidate, Confidence};
use crate::catalog::Catalog;
use crate::identity::AppIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cask {
    pub token: String,
    /// Bundle names as installed (`Foo.app`), after any `target:` rename.
    pub apps: Vec<String>,
    /// Bundle ids and launchd labels the cask's `uninstall` stanza names.
    pub ids: Vec<String>,
    /// `zap trash:` paths, as written in the cask (`~`, globs).
    pub trash: Vec<String>,
    /// Installed with Homebrew on this Mac.
    pub installed: bool,
}

/// Accepts `{"casks": [...]}` (`brew info --json=v2`) or a bare array (the API).
pub fn parse(json: &str) -> Result<Vec<Cask>, serde_json::Error> {
    let value: Value = serde_json::from_str(json)?;
    let list = match &value {
        Value::Array(list) => list.clone(),
        Value::Object(map) => map
            .get("casks")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    Ok(list.iter().filter_map(parse_cask).collect())
}

fn strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_cask(cask: &Value) -> Option<Cask> {
    let token = cask.get("token")?.as_str()?.to_string();
    let mut parsed = Cask {
        token,
        apps: Vec::new(),
        ids: Vec::new(),
        trash: Vec::new(),
        installed: cask.get("installed").is_some_and(|v| !v.is_null()),
    };
    for artifact in cask
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(apps) = artifact.get("app").and_then(Value::as_array) {
            // ["Foo.app"] or ["Foo Installer.app", {"target": "Foo.app"}]
            let target = apps
                .iter()
                .find_map(|a| a.get("target").and_then(Value::as_str));
            match target {
                Some(t) => parsed.apps.push(file_name(t)),
                None => parsed
                    .apps
                    .extend(apps.iter().filter_map(Value::as_str).map(file_name)),
            }
        }
        for stanza in artifact
            .get("uninstall")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for key in ["quit", "launchctl", "signal"] {
                if let Some(v) = stanza.get(key) {
                    parsed
                        .ids
                        .extend(strings(v).into_iter().filter(|s| s.contains('.')));
                }
            }
        }
        for stanza in artifact
            .get("zap")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(v) = stanza.get("trash") {
                parsed.trash.extend(strings(v));
            }
        }
    }
    Some(parsed)
}

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

/// The cask that installs this app: same bundle name, and either the cask names one
/// of the app's ids or it is installed with Homebrew here. Ambiguity means no cask.
pub fn find_cask<'a>(casks: &'a [Cask], identity: &AppIdentity) -> Option<&'a Cask> {
    let bundle_name = identity.path.file_name()?.to_string_lossy().into_owned();
    let ids: Vec<&str> = std::iter::once(identity.bundle_id.as_str())
        .chain(identity.nested_ids.iter().map(String::as_str))
        .collect();
    let mentions = |cask: &Cask| {
        cask.ids
            .iter()
            .any(|i| ids.iter().any(|id| i.eq_ignore_ascii_case(id)))
            || cask
                .trash
                .iter()
                .any(|t| ids.iter().any(|id| t.contains(id)))
    };
    let same_name: Vec<&Cask> = casks
        .iter()
        .filter(|c| c.apps.iter().any(|a| a.eq_ignore_ascii_case(&bundle_name)))
        .collect();
    let trusted: Vec<&Cask> = same_name.iter().copied().filter(|c| mentions(c)).collect();
    let pick = if trusted.is_empty() {
        same_name
            .into_iter()
            .filter(|c| c.installed)
            .collect::<Vec<_>>()
    } else {
        trusted
    };
    match pick.as_slice() {
        [one] => Some(one),
        _ => None,
    }
}

/// Existing paths of the cask's `zap trash:` list that fall inside a catalog
/// location, as `Curated` candidates, in the cask's order.
pub fn candidates(cask: &Cask, catalog: &Catalog) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    for entry in &cask.trash {
        let path = if let Some(rest) = entry.strip_prefix("~/") {
            catalog.home.join(rest)
        } else if let Some(rest) = entry.strip_prefix('/') {
            catalog.system_root.join(rest)
        } else {
            continue;
        };
        for found in expand(&path) {
            let apple = found.components().any(|c| {
                matches!(c, Component::Normal(n) if n.to_string_lossy().to_lowercase().starts_with("com.apple."))
            });
            if apple || out.iter().any(|c| c.path == found) {
                continue;
            }
            let Some(location) = catalog
                .locations
                .iter()
                .filter(|l| found.starts_with(&l.path) && found != l.path)
                .max_by_key(|l| l.path.components().count())
            else {
                continue;
            };
            out.push(Candidate {
                path: found,
                category: location.category,
                confidence: Confidence::Curated,
                reason: format!("listed in the zap stanza of Homebrew cask `{}`", cask.token),
            });
        }
    }
    out
}

/// Existing paths matching `path`, whose last component may hold `*` / `?`.
fn expand(path: &Path) -> Vec<PathBuf> {
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return Vec::new();
    };
    let Some(parent) = path.parent() else {
        return Vec::new();
    };
    if parent.to_string_lossy().contains(['*', '?']) {
        return Vec::new();
    }
    if !name.contains(['*', '?']) {
        return if std::fs::symlink_metadata(path).is_ok() {
            vec![path.to_path_buf()]
        } else {
            Vec::new()
        };
    }
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut matches: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| wildcard(&name, &e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .collect();
    matches.sort();
    matches
}

/// `*` matches any run of characters, `?` one character.
fn wildcard(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::wildcard;

    #[test]
    fn wildcards() {
        assert!(wildcard(
            "com.foo.Bar*.savedState",
            "com.foo.Bar.savedState"
        ));
        assert!(wildcard(
            "com.foo.Bar*.savedState",
            "com.foo.BarHelper.savedState"
        ));
        assert!(!wildcard(
            "com.foo.Bar*.savedState",
            "com.foo.Baz.savedState"
        ));
        assert!(wildcard("a?c", "abc"));
        assert!(!wildcard("a?c", "ac"));
        assert!(wildcard("*", ""));
    }
}
