//! Human and JSON rendering shared by the commands.

use std::path::{Path, PathBuf};

use maczap_core::candidate::{Category, Confidence};
use maczap_core::discovery::{NotChecked, ReportItem, Scan};
use maczap_core::plan::Plan;
use serde::Serialize;

pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn confidence(c: Confidence) -> &'static str {
    match c {
        Confidence::High => "high",
        Confidence::Curated => "curated",
        Confidence::Low => "low",
        Confidence::Shared => "shared",
    }
}

pub fn category(c: Category) -> &'static str {
    match c {
        Category::AppBundle => "Application",
        Category::ApplicationSupport => "Application Support",
        Category::ApplicationScripts => "Application Scripts",
        Category::Caches => "Caches",
        Category::Containers => "Containers",
        Category::GroupContainers => "Group Containers",
        Category::Preferences => "Preferences",
        Category::SavedState => "Saved State",
        Category::WebData => "Web data",
        Category::Logs => "Logs",
        Category::CrashReports => "Crash reports",
        Category::LaunchAgent => "Launch agents",
        Category::LaunchDaemon => "Launch daemons",
        Category::PrivilegedHelper => "Privileged helpers",
        Category::Plugin => "Plug-ins",
        Category::TempData => "Temporary data",
        Category::ReceiptFile => "Installed by package",
    }
}

/// Replaces the home directory with `~` for display.
pub fn tilde(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

#[derive(Debug, Serialize)]
pub struct PlanItemJson {
    pub path: PathBuf,
    pub category: Category,
    pub confidence: Confidence,
    pub reason: String,
    pub selected: bool,
    pub needs_root: bool,
    pub rejected: Option<String>,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct ScanJson<'a> {
    pub schema_version: u32,
    pub app: &'a maczap_core::identity::AppIdentity,
    pub items: Vec<PlanItemJson>,
    pub not_checked: &'a [NotChecked],
    pub report_only: &'a [ReportItem],
    pub receipts: &'a [String],
    pub legacy_login_items: &'a [String],
    pub homebrew_cask: Option<&'a str>,
}

pub fn plan_json<'a>(
    scan: &'a Scan,
    plan: &Plan,
    sizes: &[u64],
    cask: Option<&'a str>,
) -> ScanJson<'a> {
    ScanJson {
        schema_version: 1,
        app: &scan.identity,
        items: plan
            .items
            .iter()
            .zip(sizes)
            .map(|(item, size)| PlanItemJson {
                path: item.candidate.path.clone(),
                category: item.candidate.category,
                confidence: item.candidate.confidence,
                reason: item.candidate.reason.clone(),
                selected: item.selected,
                needs_root: item.needs_root,
                rejected: item.verdict.as_ref().err().map(|r| r.to_string()),
                size_bytes: *size,
            })
            .collect(),
        not_checked: &scan.not_checked,
        report_only: &scan.report_only,
        receipts: &scan.receipts,
        legacy_login_items: &scan.legacy_login_items,
        homebrew_cask: cask,
    }
}

/// Prints the plan grouped by category.
pub fn print_plan(scan: &Scan, plan: &Plan, sizes: &[u64], home: &Path) {
    let id = &scan.identity;
    println!(
        "{} {} ({}){}",
        id.name,
        id.version.as_deref().unwrap_or(""),
        id.bundle_id,
        id.team_id
            .as_deref()
            .map(|t| format!(", Team ID {t}"))
            .unwrap_or_default()
    );
    println!("{}\n", tilde(&id.path, home));
    let mut last = None;
    let mut total = 0;
    for (item, bytes) in plan.items.iter().zip(sizes) {
        let c = &item.candidate;
        if last != Some(c.category) {
            println!("{}", category(c.category));
            last = Some(c.category);
        }
        let mark = match (&item.verdict, item.selected) {
            (Err(_), _) => "  -",
            (Ok(_), true) => "  [x]",
            (Ok(_), false) => "  [ ]",
        };
        let root = if item.needs_root { " (admin)" } else { "" };
        println!(
            "{mark} {:<8} {:>9}  {}{root}",
            confidence(c.confidence),
            size(*bytes),
            tilde(&c.path, home)
        );
        match &item.verdict {
            Err(rejection) => println!("              kept: {rejection}"),
            Ok(_) => println!("              {}", c.reason),
        }
        if item.selected {
            total += bytes;
        }
    }
    let selected = plan.selected().count();
    println!("\n{selected} item(s) selected, {}.", size(total));
    for nc in &scan.not_checked {
        println!(
            "not checked: {} ({}) — grant Full Disk Access to your terminal",
            tilde(&nc.path, home),
            nc.error
        );
    }
    for r in &scan.report_only {
        println!("not removed: {} — {}", tilde(&r.path, home), r.detail);
    }
    for item in &scan.legacy_login_items {
        println!("login item to remove: {item}");
    }
    if !scan.receipts.is_empty() {
        println!("package receipts to forget: {}", scan.receipts.join(", "));
    }
}
