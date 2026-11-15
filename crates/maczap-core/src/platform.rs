//! Read-only facts maczap needs from macOS. Discovery depends only on this trait, so
//! tests use a fake and production uses `MacPlatform` (see `mac.rs`).

use std::path::{Path, PathBuf};

/// What the code signature of a bundle says about it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeSignature {
    pub identifier: Option<String>,
    pub team_id: Option<String>,
    /// `com.apple.security.application-groups` entitlement.
    pub app_groups: Vec<String>,
}

pub trait Platform {
    /// The code signature of a bundle, or `None` when it is unsigned or unreadable.
    fn code_signature(&self, bundle: &Path) -> Option<CodeSignature>;

    /// Paths of every application bundle installed on the machine.
    fn installed_apps(&self) -> Vec<PathBuf>;

    /// Package ids whose receipt lists `path` (`pkgutil --file-info`).
    fn receipts_containing(&self, path: &Path) -> Vec<String>;

    /// Absolute paths installed by a package (`pkgutil --files` resolved against the
    /// receipt's volume and install location). `None` when the receipt is unknown.
    fn receipt_files(&self, pkg_id: &str) -> Option<Vec<PathBuf>>;

    /// Every package id with a receipt (`pkgutil --pkgs`).
    fn all_receipts(&self) -> Vec<String> {
        Vec::new()
    }

    /// Background Task Management records (`sfltool dumpbtm`).
    fn btm_records(&self) -> Vec<crate::btm::BtmRecord> {
        Vec::new()
    }
}
