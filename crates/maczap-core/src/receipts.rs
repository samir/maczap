//! Package receipts as a high-confidence source (DESIGN §3.4).
//!
//! A receipt path is a candidate only when no other package lists it. A directory is a
//! candidate only when, on top of that, everything inside it on disk is listed by the
//! app's own receipts; otherwise its listed children are considered one by one. Paths
//! inside the app bundle are skipped: the bundle is its own candidate.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::candidate::{Candidate, Category, Confidence};
use crate::identity::AppIdentity;
use crate::platform::Platform;

#[derive(Debug, Clone, Default)]
pub struct ReceiptScan {
    pub packages: Vec<String>,
    pub candidates: Vec<Candidate>,
}

pub fn scan(identity: &AppIdentity, platform: &dyn Platform) -> ReceiptScan {
    let mut packages: BTreeSet<String> = platform
        .receipts_containing(&identity.path)
        .into_iter()
        .collect();
    // App Store receipts are not in the file index: they are named after the bundle
    // id instead. Such a receipt counts only if it really lists this bundle.
    let ids: Vec<&str> = std::iter::once(identity.bundle_id.as_str())
        .chain(identity.nested_ids.iter().map(String::as_str))
        .collect();
    let mut files_by_pkg: Vec<(String, Vec<PathBuf>)> = Vec::new();
    for pkg in platform.all_receipts() {
        if packages.contains(&pkg) || !ids.iter().any(|id| id.eq_ignore_ascii_case(&pkg)) {
            continue;
        }
        if let Some(files) = platform.receipt_files(&pkg)
            && files.iter().any(|f| f == &identity.path)
        {
            packages.insert(pkg.clone());
            files_by_pkg.push((pkg, files));
        }
    }
    if packages.is_empty() {
        return ReceiptScan::default();
    }
    let listed: BTreeSet<PathBuf> = packages
        .iter()
        .filter_map(|pkg| match files_by_pkg.iter().find(|(p, _)| p == pkg) {
            Some((_, files)) => Some(files.clone()),
            None => platform.receipt_files(pkg),
        })
        .flatten()
        .filter(|p| p.is_absolute())
        .collect();

    let mut candidates = Vec::new();
    let mut taken: Vec<PathBuf> = Vec::new();
    // BTreeSet order puts every directory before its contents.
    for path in &listed {
        if path.starts_with(&identity.path) || identity.path.starts_with(path) {
            continue;
        }
        if taken.iter().any(|t| path.starts_with(t)) {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(path) else {
            continue;
        };
        let owners: BTreeSet<String> = platform.receipts_containing(path).into_iter().collect();
        if owners.is_empty() || !owners.is_subset(&packages) {
            continue;
        }
        if meta.is_dir() && !everything_inside_is_listed(path, &listed) {
            continue;
        }
        let pkg_list = owners.iter().cloned().collect::<Vec<_>>().join(", ");
        candidates.push(Candidate {
            path: path.clone(),
            category: Category::ReceiptFile,
            confidence: Confidence::High,
            reason: format!("installed by package {pkg_list} and listed by no other package"),
        });
        taken.push(path.clone());
    }
    ReceiptScan {
        packages: packages.into_iter().collect(),
        candidates,
    }
}

fn everything_inside_is_listed(dir: &Path, listed: &BTreeSet<PathBuf>) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries {
        let Ok(entry) = entry else { return false };
        let path = entry.path();
        if !listed.contains(&path) {
            return false;
        }
        if entry.file_type().is_ok_and(|t| t.is_dir())
            && !everything_inside_is_listed(&path, listed)
        {
            return false;
        }
    }
    true
}
