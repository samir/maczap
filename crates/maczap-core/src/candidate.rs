//! A path that discovery believes belongs to the target app.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// How sure maczap is that a path belongs to the target app (DESIGN §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Exact bundle id, nested bundle id, app group, launchd label or exclusive receipt.
    High,
    /// Listed in the Homebrew cask `zap` stanza for this bundle id.
    Curated,
    /// Name heuristics only. Never selected without an explicit opt-in.
    Low,
    /// Also used by another installed app. Never removed.
    Shared,
}

/// What kind of trace a path is. Drives grouping in the UI and some guard rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    AppBundle,
    ApplicationSupport,
    ApplicationScripts,
    Caches,
    Containers,
    GroupContainers,
    Preferences,
    SavedState,
    WebData,
    Logs,
    CrashReports,
    LaunchAgent,
    LaunchDaemon,
    PrivilegedHelper,
    Plugin,
    TempData,
    ReceiptFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub path: PathBuf,
    pub category: Category,
    pub confidence: Confidence,
    /// Human-readable explanation of why this path matched.
    pub reason: String,
}
