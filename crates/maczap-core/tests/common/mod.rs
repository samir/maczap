#![allow(dead_code)]

pub mod fake;

use std::fs;
use std::path::{Path, PathBuf};

use maczap_core::candidate::{Candidate, Category, Confidence};
use maczap_core::roots::{Roots, Scope};
use tempfile::TempDir;

/// A throw-away "machine": a temporary home with a user Library and a fake system
/// Library, wired into a `Roots` exactly like production would wire the real ones.
pub struct Sandbox {
    _dir: TempDir,
    pub base: PathBuf,
    pub home: PathBuf,
    pub caches: PathBuf,
    pub app_support: PathBuf,
    pub system_daemons: PathBuf,
    pub quarantine: PathBuf,
    pub applications: PathBuf,
}

impl Sandbox {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        // tempdir lives under /var/folders, and /var is a symlink: use the real path.
        let base = dir.path().canonicalize().unwrap();
        let home = base.join("Users/alice");
        let caches = home.join("Library/Caches");
        let app_support = home.join("Library/Application Support");
        let system_daemons = base.join("Library/LaunchDaemons");
        let quarantine = home.join(".local/share/maczap/quarantine");
        let applications = base.join("Applications");
        for d in [
            &caches,
            &app_support,
            &system_daemons,
            &quarantine,
            &applications,
        ] {
            fs::create_dir_all(d).unwrap();
        }
        Sandbox {
            _dir: dir,
            base,
            home,
            caches,
            app_support,
            system_daemons,
            quarantine,
            applications,
        }
    }

    pub fn roots(&self) -> Roots {
        Roots::new(&self.home)
            .unwrap()
            .allow(&self.caches, Scope::User)
            .unwrap()
            .allow(&self.app_support, Scope::User)
            .unwrap()
            .allow(&self.system_daemons, Scope::System)
            .unwrap()
            .protect(&self.quarantine)
            .unwrap()
    }

    pub fn file(&self, path: &Path, contents: &str) -> PathBuf {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
        path.to_path_buf()
    }
}

pub fn candidate(path: impl Into<PathBuf>) -> Candidate {
    Candidate {
        path: path.into(),
        category: Category::Caches,
        confidence: Confidence::High,
        reason: "test".into(),
    }
}
