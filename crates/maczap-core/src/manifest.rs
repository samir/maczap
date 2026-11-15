//! The batch manifest: the durable record that makes `restore` possible
//! (DESIGN §6.3).

use std::path::PathBuf;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::candidate::{Category, Confidence};
use crate::roots::Scope;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub bundle_id: String,
    pub team_id: Option<String>,
    pub version: Option<String>,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchState {
    /// Items are being admitted (or the run was interrupted).
    Open,
    /// The uninstall finished; the batch holds what it removed.
    Closed,
    /// Every moved item went back to its original path.
    Restored,
    /// `restore` ran but some items could not go back.
    PartiallyRestored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "detail")]
pub enum ItemStatus {
    /// Recorded before the move (write-ahead); not known to have moved yet.
    Planned,
    Moved,
    /// The move did not happen; the original was left in place.
    Failed(String),
    Restored,
    /// The original was never moved (interrupted before the move).
    NotMoved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRecord {
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub scope: Scope,
    pub category: Category,
    pub confidence: Confidence,
    pub reason: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub uid: u32,
    pub dev: u64,
    pub ino: u64,
    pub size_bytes: u64,
    pub file_count: u64,
    pub status: ItemStatus,
    /// Where `restore --overwrite` put the item that was in the way, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub displaced_to: Option<PathBuf>,
}

/// Something maczap did that `restore` cannot undo (DESIGN §6.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrreversibleAction {
    pub kind: ActionKind,
    pub target: String,
    /// State before the action, when it can be captured (e.g. `pkgutil --pkg-info`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    pub succeeded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    LaunchctlBootout,
    TccReset,
    PkgutilForget,
    LoginItemRemoval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub id: String,
    pub created_at: Timestamp,
    pub maczap_version: String,
    pub user: String,
    pub app: AppInfo,
    pub state: BatchState,
    pub items: Vec<ItemRecord>,
    pub actions: Vec<IrreversibleAction>,
    /// The batch on the other side (user ↔ system quarantine) of the same uninstall.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_batch: Option<String>,
}

impl Manifest {
    pub fn total_size(&self) -> u64 {
        self.items
            .iter()
            .filter(|i| i.status == ItemStatus::Moved)
            .map(|i| i.size_bytes)
            .sum()
    }

    pub fn moved_count(&self) -> usize {
        self.items
            .iter()
            .filter(|i| i.status == ItemStatus::Moved)
            .count()
    }
}
