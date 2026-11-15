//! Actions on the running system (quit, launchd, TCC, login items), and the
//! privileged step. Separate from `Platform` so that `scan` can never act.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::manifest::IrreversibleAction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bootout {
    Unloaded,
    /// The job was not loaded (`launchctl` rc 3; spike 0001 #6).
    NotLoaded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TccReset {
    Reset,
    /// LaunchServices does not know the id (OSStatus -10814; spike 0001 #9).
    NothingToReset,
}

pub trait Control {
    /// PIDs of running instances of a bundle id.
    fn running_pids(&self, bundle_id: &str) -> Vec<i32>;
    /// Asks every instance of a bundle id to quit normally (never forced).
    fn request_quit(&self, bundle_id: &str);
    fn is_alive(&self, pid: i32) -> bool;
    fn wait(&self, duration: Duration);
    /// `launchctl bootout gui/<uid>/<label>`.
    fn bootout_user_agent(&self, label: &str, plist: &Path) -> Result<Bootout, String>;
    /// `tccutil reset All <bundle_id>`.
    fn tcc_reset(&self, bundle_id: &str) -> Result<TccReset, String>;
    /// Removes a legacy login item through System Events.
    fn remove_legacy_login_item(&self, name: &str) -> Result<(), String>;
}

/// What the user process asks the privileged step to do (sent as JSON on stdin).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemRequest {
    pub bundle_id: String,
    pub app_path: PathBuf,
    /// Selected paths the user process cannot move itself.
    pub paths: Vec<PathBuf>,
    /// Receipts to `pkgutil --forget` after the moves.
    pub forget_receipts: Vec<String>,
    /// Delete the system batch right after moving (`--permanent`).
    pub permanent: bool,
    /// The user batch this one belongs to.
    pub user_batch: String,
}

/// What the privileged step did (sent back as JSON on stdout).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemResult {
    pub batch_id: Option<String>,
    pub moved: Vec<PathBuf>,
    pub failed: Vec<(PathBuf, String)>,
    /// Requested paths the privileged step refused (not in its own recomputed plan).
    pub refused: Vec<(PathBuf, String)>,
    pub actions: Vec<IrreversibleAction>,
}

pub trait PrivilegedStep {
    /// Obtains root credentials up front (e.g. `sudo -v`). An error means the user
    /// declined or cannot authenticate.
    fn authorize(&self) -> Result<(), String>;
    fn apply(&self, request: &SystemRequest) -> Result<SystemResult, String>;
}
