//! The fixed set of directories maczap may remove things from (DESIGN §5.1).

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Who owns the items under a root, and therefore who may move them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    User,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedRoot {
    pub path: PathBuf,
    pub scope: Scope,
}

/// Allowlist, deny-list and protected paths. All stored paths are canonical, so a
/// candidate must be expressed below the canonical form of its root.
#[derive(Debug, Clone)]
pub struct Roots {
    home: PathBuf,
    allowed: Vec<AllowedRoot>,
    denied: Vec<PathBuf>,
    protected: Vec<PathBuf>,
}

impl Roots {
    pub fn new(home: &Path) -> io::Result<Self> {
        Ok(Roots {
            home: home.canonicalize()?,
            allowed: Vec::new(),
            denied: Vec::new(),
            protected: Vec::new(),
        })
    }

    /// Adds an allowed root. Roots that do not exist on this machine are skipped:
    /// nothing can be removed from a directory that is not there.
    pub fn allow(mut self, path: &Path, scope: Scope) -> io::Result<Self> {
        match path.canonicalize() {
            Ok(path) => self.allowed.push(AllowedRoot { path, scope }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(self)
    }

    /// Adds a deny-list prefix: nothing at or below it is ever accepted.
    pub fn deny(mut self, path: &Path) -> io::Result<Self> {
        self.denied.push(canonical_or_literal(path)?);
        Ok(self)
    }

    /// Adds a protected path (maczap's own state, e.g. the quarantine): it, its
    /// ancestors and everything below it are never accepted.
    pub fn protect(mut self, path: &Path) -> io::Result<Self> {
        self.protected.push(canonical_or_literal(path)?);
        Ok(self)
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn allowed(&self) -> &[AllowedRoot] {
        &self.allowed
    }

    pub fn denied(&self) -> &[PathBuf] {
        &self.denied
    }

    pub fn protected(&self) -> &[PathBuf] {
        &self.protected
    }
}

fn canonical_or_literal(path: &Path) -> io::Result<PathBuf> {
    match path.canonicalize() {
        Ok(p) => Ok(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(e) => Err(e),
    }
}
