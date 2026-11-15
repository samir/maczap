//! Quarantine: moves verified items aside with a write-ahead manifest, and puts them
//! back on `restore` (DESIGN §6).
//!
//! Moves go through directory file descriptors opened with `O_NOFOLLOW` from the
//! allowed root down to the item's parent, and the item is re-checked with `fstatat`
//! against the guard's fingerprint right before `renameat`. A symlink swapped into
//! the path, or a different file put in place of the verified one, makes the move fail
//! instead of acting outside the root.

use std::fs;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use jiff::Timestamp;
use rustix::fs::{AtFlags, CWD, Mode, OFlags, RenameFlags};

use crate::guard::Verified;
use crate::manifest::{
    AppInfo, BatchState, IrreversibleAction, ItemRecord, ItemStatus, Manifest, SCHEMA_VERSION,
};

const MANIFEST: &str = "manifest.json";
const ITEMS: &str = "items";

#[derive(Debug, thiserror::Error)]
pub enum QuarantineError {
    #[error("quarantine I/O error at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("manifest {path} is unreadable: {source}")]
    Manifest {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("no quarantine batch named `{0}`")]
    UnknownBatch(String),
    #[error("`{0}` is not a valid batch id")]
    InvalidBatchId(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    #[error("{path} changed since it was verified; left in place")]
    Changed { path: PathBuf },
    #[error("cannot move {path}: {source}")]
    Move { path: PathBuf, source: io::Error },
    #[error(transparent)]
    Quarantine(#[from] QuarantineError),
}

fn io_at(path: &Path) -> impl FnOnce(io::Error) -> QuarantineError + '_ {
    move |source| QuarantineError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The quarantine directory of one scope (user or system).
#[derive(Debug, Clone)]
pub struct Quarantine {
    dir: PathBuf,
    /// Manifests readable by every user (the system quarantine, so that `maczap list`
    /// works without root). Item contents stay in a 0700 directory either way.
    shared: bool,
}

impl Quarantine {
    /// Opens (and creates, mode 0700) a private quarantine directory.
    pub fn open(dir: &Path) -> Result<Self, QuarantineError> {
        Self::open_with(dir, false)
    }

    /// Opens an existing quarantine without creating anything; `None` if there is none.
    pub fn open_existing(dir: &Path, shared: bool) -> Result<Option<Self>, QuarantineError> {
        match fs::symlink_metadata(dir) {
            Ok(meta) if meta.is_dir() => {
                let dir = dir.canonicalize().map_err(io_at(dir))?;
                Ok(Some(Quarantine { dir, shared }))
            }
            Ok(_) => Err(QuarantineError::Io {
                path: dir.to_path_buf(),
                source: io::Error::other("not a directory"),
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_at(dir)(e)),
        }
    }

    /// Opens (and creates) a quarantine whose manifests every user can read.
    pub fn open_shared(dir: &Path) -> Result<Self, QuarantineError> {
        Self::open_with(dir, true)
    }

    fn open_with(dir: &Path, shared: bool) -> Result<Self, QuarantineError> {
        fs::create_dir_all(dir).map_err(io_at(dir))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(dir_mode(shared)))
            .map_err(io_at(dir))?;
        let dir = dir.canonicalize().map_err(io_at(dir))?;
        Ok(Quarantine { dir, shared })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Starts a new batch. The manifest is on disk before this returns.
    pub fn begin(&self, app: AppInfo, now: Timestamp) -> Result<Batch, QuarantineError> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let stamp = now.strftime("%Y%m%dT%H%M%SZ").to_string();
        let (id, dir) = loop {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let id = format!("{stamp}-{:x}-{n}", std::process::id());
            let dir = self.dir.join(&id);
            match fs::create_dir(&dir) {
                Ok(()) => break (id, dir),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(io_at(&dir)(e)),
            }
        };
        fs::set_permissions(&dir, fs::Permissions::from_mode(dir_mode(self.shared)))
            .map_err(io_at(&dir))?;
        let items = dir.join(ITEMS);
        fs::create_dir(&items).map_err(io_at(&items))?;
        fs::set_permissions(&items, fs::Permissions::from_mode(0o700)).map_err(io_at(&items))?;
        let manifest = Manifest {
            schema_version: SCHEMA_VERSION,
            id,
            created_at: now,
            maczap_version: env!("CARGO_PKG_VERSION").to_string(),
            user: current_user(),
            app,
            state: BatchState::Open,
            items: Vec::new(),
            actions: Vec::new(),
            linked_batch: None,
        };
        let batch = Batch { dir, manifest };
        batch.save()?;
        Ok(batch)
    }

    /// Reads the manifest of a batch.
    pub fn load(&self, id: &str) -> Result<Manifest, QuarantineError> {
        let dir = self.batch_dir(id)?;
        read_manifest(&dir.join(MANIFEST))
    }

    /// Moves every quarantined item of a batch back to its original path.
    ///
    /// Items whose original path is occupied are skipped (reported as conflicts)
    /// unless `overwrite` is set, in which case the occupant is first moved into the
    /// batch's `displaced/` area. Items of an interrupted batch (`Planned`) are
    /// restored if they reached the quarantine, and marked `NotMoved` otherwise.
    pub fn restore(
        &self,
        id: &str,
        options: RestoreOptions,
    ) -> Result<RestoreReport, QuarantineError> {
        let dir = self.batch_dir(id)?;
        let mut manifest = read_manifest(&dir.join(MANIFEST))?;
        let mut report = RestoreReport {
            irreversible: manifest.actions.clone(),
            ..Default::default()
        };

        for index in (0..manifest.items.len()).rev() {
            let item = &mut manifest.items[index];
            if !matches!(item.status, ItemStatus::Moved | ItemStatus::Planned) {
                continue;
            }
            if fs::symlink_metadata(&item.quarantine_path).is_err() {
                if item.status == ItemStatus::Planned {
                    item.status = ItemStatus::NotMoved;
                } else {
                    report.failures.push((
                        item.original_path.clone(),
                        "missing from the quarantine".into(),
                    ));
                }
                continue;
            }
            if fs::symlink_metadata(&item.original_path).is_ok() {
                if !options.overwrite {
                    report.conflicts.push(item.original_path.clone());
                    continue;
                }
                let name = item.original_path.file_name().expect("items are never `/`");
                let slot = dir.join("displaced").join(format!("{index:04}"));
                let displaced = slot.join(name);
                let moved = fs::create_dir_all(&slot)
                    .and_then(|()| rename_noreplace(&item.original_path, &displaced));
                if let Err(e) = moved {
                    report.failures.push((
                        item.original_path.clone(),
                        format!("cannot displace the current item: {e}"),
                    ));
                    continue;
                }
                item.displaced_to = Some(displaced.clone());
                report
                    .displaced
                    .push((item.original_path.clone(), displaced));
            }
            if let Err(e) = ensure_real_parent(&item.original_path) {
                report
                    .failures
                    .push((item.original_path.clone(), e.to_string()));
                continue;
            }
            let back = match rename_noreplace(&item.quarantine_path, &item.original_path) {
                Err(e) if e.raw_os_error() == Some(rustix::io::Errno::XDEV.raw_os_error()) => {
                    move_across_volumes(
                        &item.quarantine_path,
                        &item.original_path,
                        item.is_dir,
                        item.file_count,
                        item.size_bytes,
                    )
                }
                other => other,
            };
            match back {
                Ok(()) => {
                    item.status = ItemStatus::Restored;
                    report.restored.push(item.original_path.clone());
                }
                Err(e) => report
                    .failures
                    .push((item.original_path.clone(), e.to_string())),
            }
        }

        let all_back = manifest.items.iter().all(|i| {
            matches!(
                i.status,
                ItemStatus::Restored | ItemStatus::NotMoved | ItemStatus::Failed(_)
            )
        });
        manifest.state = if all_back {
            BatchState::Restored
        } else {
            BatchState::PartiallyRestored
        };
        write_manifest(&dir, &manifest)?;
        Ok(report)
    }

    /// Every batch in the quarantine, oldest first. Unreadable manifests are reported
    /// separately instead of failing the listing.
    pub fn list(&self) -> Result<Listing, QuarantineError> {
        let mut listing = Listing::default();
        for entry in fs::read_dir(&self.dir).map_err(io_at(&self.dir))? {
            let entry = entry.map_err(io_at(&self.dir))?;
            if !entry.file_type().map_err(io_at(&entry.path()))?.is_dir() {
                continue;
            }
            let manifest_path = entry.path().join(MANIFEST);
            if fs::symlink_metadata(&manifest_path).is_err() {
                continue;
            }
            match read_manifest(&manifest_path) {
                Ok(m) => listing.batches.push(BatchSummary {
                    size_bytes: m.total_size(),
                    moved: m.moved_count(),
                    items: m.items.len(),
                    id: m.id,
                    created_at: m.created_at,
                    app: m.app,
                    state: m.state,
                }),
                Err(_) => listing.unreadable.push(entry.path()),
            }
        }
        listing
            .batches
            .sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        listing.unreadable.sort();
        Ok(listing)
    }

    /// Deletes batches for good. Every id is validated before anything is removed, so
    /// one bad id aborts the whole purge.
    pub fn purge(
        &self,
        selector: &PurgeSelector,
        now: Timestamp,
    ) -> Result<PurgeReport, QuarantineError> {
        let targets: Vec<(String, PathBuf)> = match selector {
            PurgeSelector::Ids(ids) => ids
                .iter()
                .map(|id| self.batch_dir(id).map(|dir| (id.clone(), dir)))
                .collect::<Result<_, _>>()?,
            PurgeSelector::OlderThan(age) => self
                .list()?
                .batches
                .into_iter()
                .filter(|b| now.as_duration() - b.created_at.as_duration() > *age)
                .map(|b| (b.id.clone(), self.dir.join(&b.id)))
                .collect(),
            PurgeSelector::All => self
                .list()?
                .batches
                .into_iter()
                .map(|b| (b.id.clone(), self.dir.join(&b.id)))
                .collect(),
        };
        let mut report = PurgeReport::default();
        for (id, dir) in targets {
            let freed = read_manifest(&dir.join(MANIFEST))
                .map(|m| m.total_size())
                .unwrap_or(0);
            remove_tree(&dir).map_err(io_at(&dir))?;
            report.freed_bytes += freed;
            report.removed.push(id);
        }
        Ok(report)
    }

    /// The directory of an existing batch. Ids are validated so that a crafted id can
    /// never point outside the quarantine.
    pub(crate) fn batch_dir(&self, id: &str) -> Result<PathBuf, QuarantineError> {
        let valid = !id.is_empty()
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !id.starts_with('-');
        if !valid {
            return Err(QuarantineError::InvalidBatchId(id.to_string()));
        }
        let dir = self.dir.join(id);
        match fs::symlink_metadata(dir.join(MANIFEST)) {
            Ok(meta) if meta.is_file() => Ok(dir),
            _ => Err(QuarantineError::UnknownBatch(id.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BatchSummary {
    pub id: String,
    pub created_at: Timestamp,
    pub app: AppInfo,
    pub state: BatchState,
    pub items: usize,
    pub moved: usize,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Listing {
    pub batches: Vec<BatchSummary>,
    /// Batch directories whose manifest cannot be read.
    pub unreadable: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurgeSelector {
    Ids(Vec<String>),
    OlderThan(jiff::SignedDuration),
    All,
}

#[derive(Debug, Clone, Default)]
pub struct PurgeReport {
    pub removed: Vec<String>,
    pub freed_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RestoreOptions {
    /// Move whatever occupies an original path into the batch, then restore.
    pub overwrite: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RestoreReport {
    pub restored: Vec<PathBuf>,
    /// Original paths that are occupied; skipped because `overwrite` was not set.
    pub conflicts: Vec<PathBuf>,
    /// (original path, where the occupant was moved) for `overwrite`.
    pub displaced: Vec<(PathBuf, PathBuf)>,
    pub failures: Vec<(PathBuf, String)>,
    /// What the uninstall did that cannot be undone.
    pub irreversible: Vec<IrreversibleAction>,
}

fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE).map_err(io::Error::from)
}

/// The parent of a restore target must be a real directory. It is re-created when an
/// app or the user removed it in the meantime; a symlink there is refused.
fn ensure_real_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().expect("items are never `/`");
    match fs::symlink_metadata(parent) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(io::Error::other(format!(
            "{} is not a real directory",
            parent.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir_all(parent),
        Err(e) => Err(e),
    }
}

fn dir_mode(shared: bool) -> u32 {
    if shared { 0o755 } else { 0o700 }
}

pub(crate) fn read_manifest(path: &Path) -> Result<Manifest, QuarantineError> {
    let bytes = fs::read(path).map_err(io_at(path))?;
    serde_json::from_slice(&bytes).map_err(|source| QuarantineError::Manifest {
        path: path.to_path_buf(),
        source,
    })
}

/// Writes the manifest atomically: temp file, fsync, rename.
pub(crate) fn write_manifest(dir: &Path, manifest: &Manifest) -> Result<(), QuarantineError> {
    let tmp = dir.join(format!("{MANIFEST}.tmp"));
    let target = dir.join(MANIFEST);
    let bytes = serde_json::to_vec_pretty(manifest).expect("manifest is always serializable");
    let mut file = fs::File::create(&tmp).map_err(io_at(&tmp))?;
    file.write_all(&bytes).map_err(io_at(&tmp))?;
    file.sync_all().map_err(io_at(&tmp))?;
    fs::rename(&tmp, &target).map_err(io_at(&target))?;
    Ok(())
}

/// An open batch. Every state change is written to disk before the call returns, so
/// dropping a batch without `finish` (a crash) still leaves a restorable manifest.
#[derive(Debug)]
pub struct Batch {
    dir: PathBuf,
    manifest: Manifest,
}

impl Batch {
    pub fn id(&self) -> &str {
        &self.manifest.id
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn save(&self) -> Result<(), QuarantineError> {
        write_manifest(&self.dir, &self.manifest)
    }

    /// Moves a verified item into the batch.
    pub fn admit(&mut self, item: Verified) -> Result<&ItemRecord, AdmitError> {
        let path = item.path().to_path_buf();
        let root = item.root().path.clone();
        let relative = path.strip_prefix(&root).expect("guard checked the prefix");
        let mut components: Vec<&Path> = relative
            .components()
            .map(|c| match c {
                Component::Normal(n) => Path::new(n),
                _ => unreachable!("guard only accepts normalized paths"),
            })
            .collect();
        let name = components.pop().expect("guard rejects the root itself");

        let changed = || AdmitError::Changed { path: path.clone() };
        let parent = open_dir_chain(&root, &components).map_err(|_| changed())?;
        let stat =
            rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| changed())?;
        let expected = item.fingerprint();
        let same = stat.st_dev as u64 == expected.dev
            && stat.st_ino == expected.ino
            && (stat.st_mode as u32 & 0o170000) == expected.mode_type
            && stat.st_uid == expected.uid;
        if !same {
            return Err(changed());
        }

        let (size_bytes, file_count) = measure(&path);
        let slot = self
            .dir
            .join(ITEMS)
            .join(format!("{:04}", self.manifest.items.len()));
        fs::create_dir(&slot).map_err(io_at(&slot))?;
        let quarantine_path = slot.join(name);
        let candidate = item.candidate();
        self.manifest.items.push(ItemRecord {
            original_path: path.clone(),
            quarantine_path: quarantine_path.clone(),
            scope: item.root().scope,
            category: candidate.category,
            confidence: candidate.confidence,
            reason: candidate.reason.clone(),
            is_dir: expected.is_dir(),
            is_symlink: expected.is_symlink(),
            uid: expected.uid,
            dev: expected.dev,
            ino: expected.ino,
            size_bytes,
            file_count,
            status: ItemStatus::Planned,
            displaced_to: None,
        });
        self.save()?;

        let outcome = open_dir(CWD, &slot).and_then(|slot_fd| {
            rustix::fs::renameat_with(&parent, name, &slot_fd, name, RenameFlags::NOREPLACE)
                .map_err(io::Error::from)
        });
        let outcome = match outcome {
            Err(e) if e.raw_os_error() == Some(rustix::io::Errno::XDEV.raw_os_error()) => {
                move_across_volumes(
                    &path,
                    &quarantine_path,
                    expected.is_dir(),
                    file_count,
                    size_bytes,
                )
            }
            other => other,
        };
        let index = self.manifest.items.len() - 1;
        self.manifest.items[index].status = match &outcome {
            Ok(()) => ItemStatus::Moved,
            Err(e) => ItemStatus::Failed(e.to_string()),
        };
        self.save()?;
        match outcome {
            Ok(()) => Ok(&self.manifest.items[index]),
            Err(source) => Err(AdmitError::Move { path, source }),
        }
    }

    /// Records an irreversible action (DESIGN §6.3).
    pub fn record_action(&mut self, action: IrreversibleAction) -> Result<(), QuarantineError> {
        self.manifest.actions.push(action);
        self.save()
    }

    /// Links this batch to the batch on the other side of the same uninstall.
    pub fn link(&mut self, other: &str) -> Result<(), QuarantineError> {
        self.manifest.linked_batch = Some(other.to_string());
        self.save()
    }

    /// Closes the batch and returns its final manifest.
    pub fn finish(mut self) -> Result<Manifest, QuarantineError> {
        self.manifest.state = BatchState::Closed;
        self.save()?;
        Ok(self.manifest)
    }
}

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn open_dir<Fd: std::os::fd::AsFd>(at: Fd, path: &Path) -> io::Result<OwnedFd> {
    rustix::fs::openat(at, path, dir_flags(), Mode::empty()).map_err(io::Error::from)
}

/// Opens `root`, then each component below it, refusing symlinks at every step.
fn open_dir_chain(root: &Path, components: &[&Path]) -> io::Result<OwnedFd> {
    let mut fd = open_dir(CWD, root)?;
    for component in components {
        fd = open_dir(&fd, component)?;
    }
    Ok(fd)
}

/// Fallback when the quarantine is on another volume: copy with `ditto`, check the
/// copy, then remove the source. The source is kept if anything does not match.
fn move_across_volumes(
    source: &Path,
    target: &Path,
    is_dir: bool,
    file_count: u64,
    size_bytes: u64,
) -> io::Result<()> {
    let status = std::process::Command::new("/usr/bin/ditto")
        .arg(source)
        .arg(target)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("ditto failed with {status}")));
    }
    if measure(target) != (size_bytes, file_count) {
        let _ = remove_tree(target);
        return Err(io::Error::other("copy verification failed; source kept"));
    }
    if is_dir {
        remove_tree(source)
    } else {
        fs::remove_file(source)
    }
}

/// Removes a tree without following symlinks, making read-only directories writable
/// first (app bundles often contain them).
pub(crate) fn remove_tree(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() {
        return fs::remove_file(path);
    }
    let mode = meta.permissions().mode();
    if mode & 0o700 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700))?;
    }
    for entry in fs::read_dir(path)? {
        remove_tree(&entry?.path())?;
    }
    fs::remove_dir(path)
}

/// Total size in bytes and number of entries (files, links, directories) of an item,
/// without following symlinks. Unreadable parts are skipped.
pub fn measure(path: &Path) -> (u64, u64) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return (0, 0);
    };
    if !meta.is_dir() {
        return (meta.len(), 1);
    }
    let mut total = (0, 1);
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let (size, count) = measure(&entry.path());
            total.0 += size;
            total.1 += count;
        }
    }
    total
}

fn current_user() -> String {
    std::env::var("USER").unwrap_or_else(|_| rustix::process::getuid().as_raw().to_string())
}
