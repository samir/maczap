//! Where things are on this machine, for this user.

use std::io;
use std::path::{Path, PathBuf};

use maczap_core::catalog::Catalog;
use maczap_core::command::{self, DEFAULT_TIMEOUT};
use maczap_core::guard::Guard;
use maczap_core::mac::MacPlatform;

#[derive(Debug, Clone)]
pub struct Env {
    pub home: PathBuf,
    pub system_root: PathBuf,
    pub uid: u32,
    pub user_quarantine: PathBuf,
    pub system_quarantine: PathBuf,
    pub state_dir: PathBuf,
    pub trash: PathBuf,
    /// Pointed at a sandbox by tests: machine-wide state (BTM) is not consulted.
    pub hermetic: bool,
    user_cache_dir: Option<PathBuf>,
    user_temp_dir: Option<PathBuf>,
}

impl Env {
    /// The environment of the invoking user. Debug builds honour
    /// `MACZAP_SYSTEM_ROOT`, so end-to-end tests can point `/` into a sandbox; release
    /// builds always use the real root.
    pub fn detect() -> io::Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|h| h.is_absolute())
            .ok_or_else(|| io::Error::other("HOME is not set to an absolute path"))?;
        let uid = rustix::process::getuid().as_raw();
        let test_root = test_system_root();
        let system_root = test_root.clone().unwrap_or_else(|| PathBuf::from("/"));
        let (user_cache_dir, user_temp_dir) = if test_root.is_some() {
            (None, None)
        } else {
            (
                getconf("DARWIN_USER_CACHE_DIR"),
                getconf("DARWIN_USER_TEMP_DIR"),
            )
        };
        let mut env = Self::new(home, system_root, uid, user_cache_dir, user_temp_dir);
        env.hermetic = test_root.is_some();
        Ok(env)
    }

    pub fn new(
        home: PathBuf,
        system_root: PathBuf,
        uid: u32,
        user_cache_dir: Option<PathBuf>,
        user_temp_dir: Option<PathBuf>,
    ) -> Self {
        let state_dir = home.join(".local/share/maczap");
        Env {
            user_quarantine: state_dir.join("quarantine"),
            system_quarantine: system_root.join("Library/Application Support/maczap/quarantine"),
            trash: home.join(".Trash"),
            hermetic: false,
            state_dir,
            home,
            system_root,
            uid,
            user_cache_dir,
            user_temp_dir,
        }
    }

    pub fn catalog(&self) -> Catalog {
        Catalog::standard(
            &self.home,
            &self.system_root,
            self.user_cache_dir.as_deref(),
            self.user_temp_dir.as_deref(),
        )
    }

    pub fn guard(&self) -> io::Result<Guard> {
        let protected = [
            self.state_dir.clone(),
            self.system_root.join("Library/Application Support/maczap"),
        ];
        Ok(Guard::new(self.catalog().roots(&protected)?))
    }

    pub fn platform(&self) -> MacPlatform {
        MacPlatform::new(vec![
            self.system_root.join("Applications"),
            self.home.join("Applications"),
        ])
    }
}

#[cfg(debug_assertions)]
fn test_system_root() -> Option<PathBuf> {
    std::env::var_os("MACZAP_SYSTEM_ROOT")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

#[cfg(not(debug_assertions))]
fn test_system_root() -> Option<PathBuf> {
    None
}

fn getconf(name: &str) -> Option<PathBuf> {
    let out = command::run(Path::new("/usr/bin/getconf"), &[name], DEFAULT_TIMEOUT).ok()?;
    let path = PathBuf::from(out.stdout.trim());
    (out.success() && path.is_absolute()).then_some(path)
}
