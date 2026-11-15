//! Homebrew cask data (DESIGN §3.2, §3.6): the casks installed here (always, from the
//! local `brew`), and the full cask list from the Homebrew API (only with `--online`,
//! cached for a week).

use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use maczap_core::command;
use maczap_core::identity::AppIdentity;
use maczap_core::zap::{self, Cask};

use crate::env::Env;

const BREWS: [&str; 2] = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"];
const CURL: &str = "/usr/bin/curl";
const API: &str = "https://formulae.brew.sh/api/cask.json";
const API_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

#[derive(Debug, Default)]
pub struct Casks {
    pub installed: Vec<Cask>,
    pub api: Vec<Cask>,
    pub warnings: Vec<String>,
}

impl Casks {
    /// The cask of an app: one installed here first, then the API list.
    pub fn lookup(&self, identity: &AppIdentity) -> Option<&Cask> {
        zap::find_cask(&self.installed, identity).or_else(|| zap::find_cask(&self.api, identity))
    }
}

pub fn brew() -> Option<&'static str> {
    BREWS.into_iter().find(|b| Path::new(b).exists())
}

/// Reads cask data on a thread. `None` in hermetic (test) mode.
pub fn read(env: &Env, online: bool) -> Option<JoinHandle<Casks>> {
    if env.hermetic {
        return None;
    }
    let cache = env.state_dir.join("homebrew-casks.json");
    Some(std::thread::spawn(move || {
        let mut casks = Casks::default();
        if let Some(brew) = brew() {
            match installed(brew) {
                Ok(list) => casks.installed = list,
                Err(e) => casks
                    .warnings
                    .push(format!("cannot read installed Homebrew casks: {e}")),
            }
        }
        if online {
            match api(&cache) {
                Ok(list) => casks.api = list,
                Err(e) => casks
                    .warnings
                    .push(format!("cannot use the Homebrew cask list: {e}")),
            }
        }
        casks
    }))
}

fn installed(brew: &str) -> Result<Vec<Cask>, String> {
    // command::run sets HOMEBREW_NO_AUTO_UPDATE and HOMEBREW_NO_ANALYTICS.
    let out = command::run(
        Path::new(brew),
        &["info", "--json=v2", "--installed", "--cask"],
        Duration::from_secs(60),
    )
    .map_err(|e| e.to_string())?;
    if !out.success() {
        return Err(out.stderr.trim().to_string());
    }
    zap::parse(&out.stdout).map_err(|e| e.to_string())
}

fn api(cache: &PathBuf) -> Result<Vec<Cask>, String> {
    let fresh = std::fs::metadata(cache)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age < API_MAX_AGE);
    if !fresh {
        if let Some(dir) = cache.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let tmp = cache.with_extension("json.tmp");
        let out = command::run(
            Path::new(CURL),
            &[
                std::ffi::OsStr::new("-fsSL"),
                std::ffi::OsStr::new("--max-time"),
                std::ffi::OsStr::new("120"),
                std::ffi::OsStr::new("-o"),
                tmp.as_os_str(),
                std::ffi::OsStr::new(API),
            ],
            Duration::from_secs(150),
        )
        .map_err(|e| e.to_string())?;
        if !out.success() {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("download failed: {}", out.stderr.trim()));
        }
        std::fs::rename(&tmp, cache).map_err(|e| e.to_string())?;
    }
    let text = std::fs::read_to_string(cache).map_err(|e| e.to_string())?;
    zap::parse(&text).map_err(|e| e.to_string())
}
