//! The guard: the only code that can turn a `Candidate` into a `Verified` one
//! (DESIGN §5.1).

use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use crate::candidate::{Candidate, Confidence};
use crate::roots::{AllowedRoot, Roots};

/// What the guard saw when it accepted a candidate. The quarantine compares it with
/// the item right before moving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    pub dev: u64,
    pub ino: u64,
    pub mode_type: u32,
    pub uid: u32,
}

impl Fingerprint {
    pub fn is_symlink(&self) -> bool {
        self.mode_type == S_IFLNK
    }

    pub fn is_dir(&self) -> bool {
        self.mode_type == S_IFDIR
    }
}

/// A candidate that passed every guard rule. It cannot be built outside this module.
#[derive(Debug, Clone)]
pub struct Verified {
    candidate: Candidate,
    root: AllowedRoot,
    fingerprint: Fingerprint,
}

impl Verified {
    pub fn path(&self) -> &Path {
        &self.candidate.path
    }

    pub fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    pub fn root(&self) -> &AllowedRoot {
        &self.root
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    #[error("path is not absolute and normalized (no `.` or `..` components)")]
    NotNormalized,
    #[error("is an allowed root, the home directory, or an ancestor of one")]
    RootOrAncestor,
    #[error("not inside any allowed root")]
    OutsideAllowedRoots,
    #[error("matches the deny-list entry `{0}`")]
    Denied(PathBuf),
    #[error("is an Apple-owned name (com.apple.*)")]
    AppleOwned,
    #[error("is shared with another installed app")]
    Shared,
    #[error("is maczap's own state, or contains it")]
    Protected,
    #[error("`{0}` is a symlink or not a directory; refusing to traverse it")]
    SymlinkInPath(PathBuf),
    #[error("does not exist")]
    Missing,
    #[error("cannot inspect the path: {0}")]
    Io(String),
}

#[derive(Debug, Clone)]
pub struct Guard {
    roots: Roots,
}

impl Guard {
    pub fn new(roots: Roots) -> Self {
        Guard { roots }
    }

    pub fn roots(&self) -> &Roots {
        &self.roots
    }

    pub fn verify(&self, candidate: Candidate) -> Result<Verified, Rejection> {
        if candidate.confidence == Confidence::Shared {
            return Err(Rejection::Shared);
        }
        if !is_normalized_absolute(&candidate.path) {
            return Err(Rejection::NotNormalized);
        }
        let path = &candidate.path;
        let is_root_or_ancestor = starts_with_ci(self.roots.home(), path)
            || self
                .roots
                .allowed()
                .iter()
                .any(|r| starts_with_ci(&r.path, path));
        if is_root_or_ancestor {
            return Err(Rejection::RootOrAncestor);
        }
        if let Some(denied) = self.roots.denied().iter().find(|d| starts_with_ci(path, d)) {
            return Err(Rejection::Denied(denied.clone()));
        }
        let touches_protected = self
            .roots
            .protected()
            .iter()
            .any(|p| starts_with_ci(path, p) || starts_with_ci(p, path));
        if touches_protected {
            return Err(Rejection::Protected);
        }
        let root = self
            .roots
            .allowed()
            .iter()
            .find(|r| candidate.path.starts_with(&r.path) && candidate.path != r.path)
            .cloned()
            .ok_or(Rejection::OutsideAllowedRoots)?;
        if has_apple_owned_component(path.strip_prefix(&root.path).expect("prefix checked")) {
            return Err(Rejection::AppleOwned);
        }
        check_real_directories(&root.path, path)?;
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Rejection::Missing),
            Err(e) => return Err(Rejection::Io(e.to_string())),
        };
        let fingerprint = fingerprint_of(&meta);
        Ok(Verified {
            candidate,
            root,
            fingerprint,
        })
    }
}

/// Every directory from `root` (inclusive) down to the parent of `path` must be a real
/// directory, never a symlink: otherwise a move would act outside the root.
fn check_real_directories(root: &Path, path: &Path) -> Result<(), Rejection> {
    let mut dir = root.to_path_buf();
    let relative = path.strip_prefix(root).expect("caller checked the prefix");
    let mut parents: Vec<_> = relative.components().collect();
    parents.pop();
    for step in std::iter::once(None).chain(parents.into_iter().map(Some)) {
        if let Some(component) = step {
            dir.push(component);
        }
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => return Err(Rejection::SymlinkInPath(dir)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Rejection::Missing),
            Err(e) => return Err(Rejection::Io(e.to_string())),
        }
    }
    Ok(())
}

fn has_apple_owned_component(relative: &Path) -> bool {
    relative.components().any(|c| {
        let name = c.as_os_str().to_string_lossy().to_lowercase();
        name.starts_with("com.apple.") || name.starts_with("group.com.apple.")
    })
}

/// Component-wise `starts_with` that ignores case, like the default APFS volume does.
/// Used for every rule that must not be bypassed by spelling a name differently.
fn starts_with_ci(path: &Path, prefix: &Path) -> bool {
    let mut path = path.components();
    prefix.components().all(|p| {
        path.next().is_some_and(|c| {
            c.as_os_str().to_string_lossy().to_lowercase()
                == p.as_os_str().to_string_lossy().to_lowercase()
        })
    })
}

fn is_normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

pub(crate) fn fingerprint_of(meta: &std::fs::Metadata) -> Fingerprint {
    Fingerprint {
        dev: meta.dev(),
        ino: meta.ino(),
        mode_type: meta.mode() & S_IFMT,
        uid: meta.uid(),
    }
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
