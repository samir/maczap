//! Discovery: walks the catalog and lists every trace of the target app, each with a
//! confidence level and a reason (DESIGN §3). Read-only.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use plist::Value;
use serde::Serialize;

use crate::candidate::{Candidate, Category, Confidence};
use crate::catalog::{Catalog, Location, Rule};
use crate::identity::{AppIdentity, nested_bundles, read_info_plist};
use crate::platform::Platform;
use crate::receipts;

#[derive(Debug, Clone, Serialize)]
pub struct Scan {
    pub identity: AppIdentity,
    pub candidates: Vec<Candidate>,
    /// Locations that exist but could not be read (usually TCC): not known to be clean.
    pub not_checked: Vec<NotChecked>,
    /// Traces maczap shows but never removes (DESIGN §3.5).
    pub report_only: Vec<ReportItem>,
    /// Package receipts that installed the app (`pkgutil --forget` candidates).
    pub receipts: Vec<String>,
    /// Names of legacy login items that open the app (removed via System Events).
    /// Filled from `background_items`, which is separate because reading BTM is slow.
    pub legacy_login_items: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotChecked {
    pub path: PathBuf,
    pub error: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    DaemonContainer,
    SystemExtension,
    BackgroundItem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReportItem {
    pub kind: ReportKind,
    pub path: PathBuf,
    pub detail: String,
}

/// File-name suffixes that still mean "exactly this bundle id".
const EXACT_SUFFIXES: &[&str] = &[
    "plist",
    "savedState",
    "binarycookies",
    "db",
    "log",
    "sfl2",
    "sfl3",
    "sfl4",
];

const CRASH_SUFFIXES: &[&str] = &[".ips", ".crash", ".diag", ".spin", ".hang"];

pub fn scan(identity: &AppIdentity, catalog: &Catalog, platform: &dyn Platform) -> Scan {
    let ctx = Context::new(identity, platform);
    let mut found = Found::default();

    if identity.path.extension().is_some_and(|e| e == "app") {
        found.add(Candidate {
            path: identity.path.clone(),
            category: Category::AppBundle,
            confidence: Confidence::High,
            reason: "the application bundle".into(),
        });
    }

    let mut not_checked = Vec::new();
    let mut report_only = Vec::new();
    let mut helper_programs = Vec::new();
    for location in &catalog.locations {
        let entries = match list_dir(&location.path) {
            Ok(Some(entries)) => entries,
            Ok(None) => continue,
            Err(e) => {
                not_checked.push(NotChecked {
                    path: location.path.clone(),
                    error: e.to_string(),
                });
                continue;
            }
        };
        for (name, path) in entries {
            match location.rule {
                Rule::ById => {
                    ctx.by_id(location, &name, &path, &mut found);
                }
                Rule::ByIdOrName => {
                    if !ctx.by_id(location, &name, &path, &mut found) {
                        ctx.by_name(location, &name, &path, &mut found);
                    }
                }
                Rule::GroupContainers => ctx.group_container(location, &name, &path, &mut found),
                Rule::Launchd => {
                    if let Some(program) = ctx.launchd(location, &name, &path, &mut found) {
                        helper_programs.push(program);
                    }
                }
                Rule::Helpers => {
                    ctx.by_id(location, &name, &path, &mut found);
                }
                Rule::Plugins => ctx.plugin(location, &name, &path, &mut found),
                Rule::CrashReports => ctx.crash_report(location, &name, &path, &mut found),
                Rule::ReportOnly => {
                    if let Some((_, reason)) = ctx.classify(&name) {
                        report_only.push(ReportItem {
                            kind: ReportKind::DaemonContainer,
                            path,
                            detail: format!("{reason}; owned by a system service, not removed"),
                        });
                    }
                }
            }
        }
    }

    // Privileged helpers referenced by a matched launchd job.
    for program in helper_programs {
        let in_helpers = catalog
            .locations
            .iter()
            .any(|l| l.rule == Rule::Helpers && program.parent() == Some(l.path.as_path()));
        if in_helpers && fs::symlink_metadata(&program).is_ok() {
            found.add(Candidate {
                path: program.clone(),
                category: Category::PrivilegedHelper,
                confidence: Confidence::High,
                reason: "program of a launchd job of this app".into(),
            });
        }
    }

    for (path, id) in nested_bundles(&identity.path) {
        if path.extension().is_some_and(|e| e == "systemextension") {
            report_only.push(ReportItem {
                kind: ReportKind::SystemExtension,
                detail: format!(
                    "system extension `{id}`: the app must deactivate it, or remove it with \
                     `systemextensionsctl` (needs SIP disabled)"
                ),
                path,
            });
        }
    }

    let receipt_scan = receipts::scan(identity, platform);
    for candidate in receipt_scan.candidates {
        found.add(candidate);
    }

    Scan {
        identity: identity.clone(),
        candidates: found.into_sorted(),
        not_checked,
        report_only,
        receipts: receipt_scan.packages,
        legacy_login_items: Vec::new(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct BackgroundItems {
    pub report: Vec<ReportItem>,
    pub legacy_login_items: Vec<String>,
}

/// The app's Background Task Management records: legacy login items (which maczap
/// removes) and everything else (reported). `app` and `developer` records describe
/// the app itself and are skipped.
pub fn background_items(
    identity: &AppIdentity,
    records: &[crate::btm::BtmRecord],
) -> BackgroundItems {
    let ids: Vec<&str> = std::iter::once(identity.bundle_id.as_str())
        .chain(identity.nested_ids.iter().map(String::as_str))
        .collect();
    let is_ours = |id: &str| ids.iter().any(|i| i.eq_ignore_ascii_case(id));
    let mut found = BackgroundItems::default();
    for record in records {
        if record.kind.starts_with("app") || record.kind.starts_with("developer") {
            continue;
        }
        // Relative URLs (SMAppService login items) are relative to the app bundle.
        let path = record.url_path().or_else(|| {
            record
                .url
                .as_deref()
                .filter(|u| !u.contains("://"))
                .map(|u| identity.path.join(crate::btm::percent_decode(u)))
        });
        let parent_is_ours = record
            .parent_identifier
            .as_deref()
            .and_then(|p| p.split_once('.').map(|(_, id)| id))
            .is_some_and(is_ours);
        let inside_bundle = [record.url_path(), record.executable.clone()]
            .into_iter()
            .flatten()
            .any(|p| p.starts_with(&identity.path));
        let ours = record.bundle_id.as_deref().is_some_and(is_ours)
            || record.associated_bundle_ids.iter().any(|a| is_ours(a))
            || parent_is_ours
            || inside_bundle;
        if !ours {
            continue;
        }
        if record.is_legacy_login_item() {
            found.legacy_login_items.push(record.name.clone());
            continue;
        }
        found.report.push(ReportItem {
            kind: ReportKind::BackgroundItem,
            detail: format!(
                "background item `{}` ({}); it goes away with its plist or the app — otherwise \
                 remove it in System Settings › General › Login Items",
                record.name, record.kind
            ),
            path: path
                .or_else(|| record.executable.clone())
                .unwrap_or_else(|| identity.path.clone()),
        });
    }
    found.legacy_login_items.sort();
    found.legacy_login_items.dedup();
    found
}

impl Scan {
    /// Adds candidates from another source (e.g. Homebrew `zap`). A path already found
    /// keeps its strongest confidence.
    pub fn merge(&mut self, extra: Vec<Candidate>) {
        let mut found = Found::default();
        for c in self.candidates.drain(..).chain(extra) {
            found.add(c);
        }
        self.candidates = found.into_sorted();
    }
}

/// Entries of a directory as (name, path). `Ok(None)` when it does not exist.
fn list_dir(dir: &Path) -> io::Result<Option<Vec<(String, PathBuf)>>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        out.push((
            entry.file_name().to_string_lossy().into_owned(),
            entry.path(),
        ));
    }
    out.sort();
    Ok(Some(out))
}

/// Candidates by path; a path found by several rules keeps the strongest confidence.
#[derive(Default)]
struct Found(BTreeMap<PathBuf, Candidate>);

impl Found {
    fn add(&mut self, candidate: Candidate) {
        match self.0.get(&candidate.path) {
            Some(existing) if existing.confidence <= candidate.confidence => {}
            _ => {
                self.0.insert(candidate.path.clone(), candidate);
            }
        }
    }

    fn into_sorted(self) -> Vec<Candidate> {
        let mut all: Vec<_> = self.0.into_values().collect();
        all.sort_by(|a, b| (a.category, &a.path).cmp(&(b.category, &b.path)));
        all
    }
}

struct Context<'a> {
    identity: &'a AppIdentity,
    /// The app's own ids, longest first so the most specific one explains a match.
    ids: Vec<String>,
    /// Bundle id → path of every *other* installed app.
    others: HashMap<String, PathBuf>,
    other_names: Vec<String>,
    platform: &'a dyn Platform,
}

impl<'a> Context<'a> {
    fn new(identity: &'a AppIdentity, platform: &'a dyn Platform) -> Self {
        let mut ids: Vec<String> = std::iter::once(identity.bundle_id.clone())
            .chain(identity.nested_ids.iter().cloned())
            .collect();
        ids.sort_by_key(|id| std::cmp::Reverse(id.len()));
        let mut others = HashMap::new();
        let mut other_names = Vec::new();
        for app in platform.installed_apps() {
            if app == identity.path || app.starts_with(&identity.path) {
                continue;
            }
            if let Ok(info) = read_info_plist(&app) {
                if let Some(id) = info.get("CFBundleIdentifier").and_then(Value::as_string) {
                    others.insert(id.to_string(), app.clone());
                }
                for key in ["CFBundleName", "CFBundleExecutable"] {
                    if let Some(name) = info.get(key).and_then(Value::as_string) {
                        other_names.push(name.to_lowercase());
                    }
                }
            }
            if let Some(stem) = app.file_stem() {
                other_names.push(stem.to_string_lossy().to_lowercase());
            }
        }
        Context {
            identity,
            ids,
            others,
            other_names,
            platform,
        }
    }

    /// Does `name` belong to one of the app's ids? Returns the confidence and reason.
    fn classify(&self, name: &str) -> Option<(Confidence, String)> {
        for id in &self.ids {
            if name.eq_ignore_ascii_case(id) || is_exact_with_suffix(name, id) {
                if let Some(other) = self.others.get(id) {
                    return Some((
                        Confidence::Shared,
                        format!(
                            "named `{id}`, which another installed copy uses ({})",
                            other.display()
                        ),
                    ));
                }
                return Some((Confidence::High, format!("named after bundle id `{id}`")));
            }
            if let Some(sub) = child_id(name, id) {
                if self.others.contains_key(&sub) {
                    return None; // another installed app's own id
                }
                return Some((Confidence::High, format!("prefixed by bundle id `{id}`")));
            }
        }
        None
    }

    fn by_id(&self, location: &Location, name: &str, path: &Path, found: &mut Found) -> bool {
        let Some((confidence, reason)) = self.classify(name) else {
            return false;
        };
        found.add(Candidate {
            path: path.to_path_buf(),
            category: location.category,
            confidence,
            reason,
        });
        true
    }

    fn by_name(&self, location: &Location, name: &str, path: &Path, found: &mut Found) {
        let lower = name.to_lowercase();
        let names = [Some(&self.identity.name), self.identity.executable.as_ref()];
        let Some(matched) = names
            .into_iter()
            .flatten()
            .find(|n| n.len() >= 3 && n.to_lowercase() == lower)
        else {
            return;
        };
        if self.other_names.contains(&lower) {
            return; // another installed app has the same name: not ours to guess
        }
        found.add(Candidate {
            path: path.to_path_buf(),
            category: location.category,
            confidence: Confidence::Low,
            reason: format!("named like the app (`{matched}`); name match only"),
        });
    }

    fn group_container(&self, location: &Location, name: &str, path: &Path, found: &mut Found) {
        let declared = self
            .identity
            .app_groups
            .iter()
            .any(|g| g.eq_ignore_ascii_case(name));
        let team_prefixed = self.identity.team_id.as_ref().is_some_and(|t| {
            name.len() > t.len() + 1
                && name.starts_with(t.as_str())
                && name.as_bytes()[t.len()] == b'.'
        });
        if !declared && !team_prefixed {
            return;
        }
        let users = self.other_apps_using_group(name);
        let (confidence, reason) = if let Some(other) = users.first() {
            (
                Confidence::Shared,
                format!("app group also used by {}", other.display()),
            )
        } else if declared {
            (
                Confidence::High,
                format!("app group `{name}` declared by the app"),
            )
        } else if self.other_apps_of_team().is_empty() {
            (
                Confidence::High,
                "prefixed by the app's Team ID; no other app of this developer is installed".into(),
            )
        } else {
            (
                Confidence::Low,
                "prefixed by the app's Team ID, but other apps of this developer are installed"
                    .into(),
            )
        };
        found.add(Candidate {
            path: path.to_path_buf(),
            category: location.category,
            confidence,
            reason,
        });
    }

    fn other_apps_using_group(&self, group: &str) -> Vec<PathBuf> {
        let mut users: Vec<PathBuf> = self
            .others
            .values()
            .filter(|app| {
                std::iter::once((*app).clone())
                    .chain(nested_bundles(app).into_iter().map(|(p, _)| p))
                    .filter_map(|p| self.platform.code_signature(&p))
                    .any(|s| s.app_groups.iter().any(|g| g.eq_ignore_ascii_case(group)))
            })
            .cloned()
            .collect();
        users.sort();
        users
    }

    fn other_apps_of_team(&self) -> Vec<PathBuf> {
        let Some(team) = &self.identity.team_id else {
            return Vec::new();
        };
        self.others
            .values()
            .filter(|app| {
                self.platform
                    .code_signature(app)
                    .and_then(|s| s.team_id)
                    .as_ref()
                    == Some(team)
            })
            .cloned()
            .collect()
    }

    /// Matches a launchd job plist. Returns the job's program when it matched, so a
    /// privileged helper it runs can be added too.
    fn launchd(
        &self,
        location: &Location,
        name: &str,
        path: &Path,
        found: &mut Found,
    ) -> Option<PathBuf> {
        let job = Value::from_file(path)
            .ok()
            .and_then(|v| v.into_dictionary());
        let Some(job) = job else {
            self.by_id(location, name, path, found);
            return None;
        };
        let label = job
            .get("Label")
            .and_then(Value::as_string)
            .unwrap_or_default();
        let program = job
            .get("Program")
            .and_then(Value::as_string)
            .or_else(|| {
                job.get("ProgramArguments")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(Value::as_string)
            })
            .map(PathBuf::from);
        let associated: Vec<String> = match job.get("AssociatedBundleIdentifiers") {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(Value::as_string)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };

        let by_label = self
            .classify(label)
            .filter(|(c, _)| *c != Confidence::Shared);
        let reason = if let Some((_, reason)) = by_label {
            Some(format!("launchd job label: {reason}"))
        } else if let Some(p) = program
            .as_ref()
            .filter(|p| p.starts_with(&self.identity.path))
        {
            Some(format!(
                "launchd job runs {} from the app bundle",
                p.display()
            ))
        } else {
            associated
                .iter()
                .find(|a| self.ids.iter().any(|i| i.eq_ignore_ascii_case(a)))
                .map(|id| format!("launchd job associated with bundle id `{id}`"))
        };
        let reason = reason?;
        found.add(Candidate {
            path: path.to_path_buf(),
            category: location.category,
            confidence: Confidence::High,
            reason,
        });
        program
    }

    fn plugin(&self, location: &Location, name: &str, path: &Path, found: &mut Found) {
        let plugin_id = read_info_plist(path).ok().and_then(|info| {
            info.get("CFBundleIdentifier")
                .and_then(Value::as_string)
                .map(str::to_string)
        });
        match plugin_id {
            Some(id) => {
                if let Some((confidence, reason)) = self.classify(&id) {
                    found.add(Candidate {
                        path: path.to_path_buf(),
                        category: location.category,
                        confidence,
                        reason: format!("plug-in {reason}"),
                    });
                }
            }
            None => {
                self.by_id(location, name, path, found);
            }
        }
    }

    fn crash_report(&self, location: &Location, name: &str, path: &Path, found: &mut Found) {
        let Some(exe) = self.identity.executable.as_ref().filter(|e| e.len() >= 3) else {
            return;
        };
        let starts = name.len() > exe.len()
            && name[..exe.len()].eq_ignore_ascii_case(exe)
            && matches!(name.as_bytes()[exe.len()], b'-' | b'_' | b'.');
        if starts && CRASH_SUFFIXES.iter().any(|s| name.ends_with(s)) {
            found.add(Candidate {
                path: path.to_path_buf(),
                category: location.category,
                confidence: Confidence::Low,
                reason: format!("crash report of executable `{exe}`"),
            });
        }
    }
}

/// `<id>.<suffix>` with a known suffix, or a ByHost preference `<id>.<UUID>.plist`.
fn is_exact_with_suffix(name: &str, id: &str) -> bool {
    let Some(rest) = strip_prefix_ci(name, id).and_then(|r| r.strip_prefix('.')) else {
        return false;
    };
    if EXACT_SUFFIXES.iter().any(|s| rest.eq_ignore_ascii_case(s)) {
        return true;
    }
    rest.strip_suffix(".plist").is_some_and(is_hardware_uuid)
}

/// For `<id>.<more>` (not a known suffix), the sub-id `<id>.<more>` without a known
/// trailing suffix.
fn child_id(name: &str, id: &str) -> Option<String> {
    let rest = strip_prefix_ci(name, id)?.strip_prefix('.')?;
    if rest.is_empty() {
        return None;
    }
    let mut sub = format!("{id}.{rest}");
    for suffix in EXACT_SUFFIXES {
        if let Some(stripped) = sub.strip_suffix(&format!(".{suffix}")) {
            sub = stripped.to_string();
            break;
        }
    }
    Some(sub)
}

fn strip_prefix_ci<'n>(name: &'n str, prefix: &str) -> Option<&'n str> {
    (name.len() >= prefix.len()
        && name.is_char_boundary(prefix.len())
        && name[..prefix.len()].eq_ignore_ascii_case(prefix))
    .then(|| &name[prefix.len()..])
}

/// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (the hardware UUID in ByHost file names).
fn is_hardware_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.chars().all(|c| c.is_ascii_hexdigit()))
}
