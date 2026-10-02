// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! The confined staging root: derivation, resolution, and bounded reads.
//!
//! # Path confinement is derivation, not joining
//!
//! No database string is ever treated as a path here. A staged epoch is
//! identified by a typed `(hash: &[u8; 32], epoch: i64)` pair, and this module
//! *computes* the key and the path from it:
//!
//! ```text
//! key  = "<64 lowercase hex>.s<epoch>"
//! path = <root>/staged/<key[0..2]>/<key[2..4]>/<key>
//! ```
//!
//! `hex` emits only `[0-9a-f]` and `epoch` is a non-negative decimal `i64`, so
//! no component can contain a separator, a `..`, a NUL, a drive letter or a UNC
//! prefix. Traversal is not filtered out; it is unrepresentable, because there
//! is no caller-supplied string in the path to traverse with.
//!
//! The stored key is then required to be **byte-equal** to the derived key
//! ([`ConfinedRoot::resolve`]). That is strictly stronger than checking that a
//! joined path stays under the root, and it is necessary: the coordinator
//! persists whatever `object_key` the manifest carries without revalidating it
//! (`domain/fragments/coordinator.rs`'s `commit_staged` path, in contrast to
//! `begin_direct_write`, which does check its key against the hash).
//!
//! # The derived key is a twin, and the twin is pinned by a live test
//!
//! `staged_epoch_key` in `domain/fragments/coordinator.rs` is private to that
//! module, so [`derived_staged_key`] re-derives the same string rather than
//! calling it. The two must not drift. `staged_key_matches_the_coordinator` in
//! the live tier asserts that a real `begin_stage` intent's `object_key` equals
//! this function's output; a `pub(crate)` export from the coordinator would let
//! the compiler hold this instead, and is worth taking if that lane offers one.
//!
//! # Cleanup confinement and the remaining writer/read boundary
//!
//! Cleanup walks from a pinned root descriptor with `openat(O_NOFOLLOW)` for
//! every directory, then uses `unlinkat` and fsync on that same descriptor.
//! Root inode and device identity are rechecked before each operation. Reads
//! and finalization still use path-based intermediate components.
//! [`ConfinedRoot::ensure_parent`] accepts
//! `AlreadyExists` from `create_dir`, which does not prove the existing entry
//! is a directory rather than a symlink. A party able to modify the root can
//! still substitute an intermediate component on those two paths. They must
//! not be treated as offering cleanup's descriptor-relative confinement.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use opentelemetry::KeyValue;
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::Semaphore;

use super::WriteBehindError;
use super::admission::AdmissionSample;

/// Subdirectory holding finalized, readable staged files.
// Everything below that only the `cfg(unix)` platform module reads is dead on a
// platform that cannot stage. That is the point of the split, not an oversight,
// so the allow is conditional rather than blanket: on Unix these must stay live
// and a real dead-code warning must still be a warning.
#[cfg_attr(not(unix), expect(dead_code, reason = "staging is Unix-only"))]
pub(crate) const STAGED_DIR: &str = "staged";
/// Subdirectory holding temporary files that are never readable as fragments.
///
/// A sibling of `staged/`, not a child: a rename must stay within one
/// filesystem, and a half-written temp file must be unable to resolve through
/// the read path. Its name has no valid `<hash>.s<epoch>` shape and it is not
/// under `staged/`, so both hold.
#[cfg_attr(not(unix), expect(dead_code, reason = "staging is Unix-only"))]
pub(crate) const INCOMING_DIR: &str = "incoming";

/// A staged path this process derived and may act on.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedStagedPath {
    path: PathBuf,
    parent: PathBuf,
}

impl ResolvedStagedPath {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg_attr(not(unix), expect(dead_code, reason = "staging is Unix-only"))]
    pub(crate) fn parent(&self) -> &Path {
        &self.parent
    }
}

/// The fan-out leaf directory step 1 made durable, held open for steps 4 and 5.
///
/// Purge removes empty fan-out directories, and another finalizer can then
/// recreate one at the same path before syncing it. Renaming into this held
/// directory, rather than into a path, means a removed leaf fails the rename
/// with `NotFound` instead of publishing into a directory whose entry is not
/// durable.
pub(crate) struct StagedLeaf {
    #[cfg(unix)]
    handle: std::fs::File,
}

#[cfg_attr(not(unix), expect(dead_code, reason = "staging is Unix-only"))]
struct RootInner {
    canonical: PathBuf,
    staged: PathBuf,
    incoming: PathBuf,
    /// `st_dev` of the root at open time. Every later act revalidates against
    /// it, which is what stops a bind-mount or unmount from silently relocating
    /// the staged set, and also what keeps `rename` atomic.
    device: u64,
    /// Inode identity plus a live descriptor prevents a replaced directory on
    /// the same device, or reuse of the old inode, from passing root validation.
    inode: u64,
    #[cfg(unix)]
    directory: std::fs::File,
    /// Shared by all clones. Each blocking closure owns its permit until its
    /// final syscall completes, even if the async caller stops waiting.
    /// Reads, purge and the physical inventory use this pool.
    io_capacity: Arc<Semaphore>,
    /// The put path's own pool, the same size. A put may wait for a slot (see
    /// [`ConfinedRoot::io_permit_within`]), and a tokio semaphore hands a
    /// released permit to its queued waiters before any `try_acquire`. One
    /// shared pool would let a queue of puts starve drain reads, which then
    /// age into `drain_backpressure_sustained`.
    put_capacity: Arc<Semaphore>,
}

/// A proven staging root.
#[derive(Clone)]
pub(crate) struct ConfinedRoot {
    inner: Arc<RootInner>,
}

/// Derive the staged key for one epoch.
///
/// Twin of the coordinator's private `staged_epoch_key`; see this module's
/// header for how the two are held together.
///
/// # Errors
///
/// Returns [`WriteBehindError::HashWidth`] unless the hash is exactly 32 bytes
/// — it arrives as `Vec<u8>` from the domain layer, not `[u8; 32]`, so the width
/// is a runtime fact — and [`WriteBehindError::EpochNegative`] for a negative
/// epoch, which would put a `-` in a path component.
pub(crate) fn derived_staged_key(hash: &[u8], epoch: i64) -> Result<String, WriteBehindError> {
    if hash.len() != 32 {
        return Err(WriteBehindError::HashWidth);
    }
    if epoch < 0 {
        return Err(WriteBehindError::EpochNegative);
    }
    Ok(format!("{}.s{epoch}", hex::encode(hash)))
}

/// The staging path that asked for an I/O slot.
///
/// Reads, purge and the physical inventory share one bounded slot pool; puts
/// have their own. A put holds its slot across `begin_stage`, so a slow
/// coordinator slows other puts. The refusal counter carries this label so
/// that shows up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageIoPath {
    Put,
    #[cfg_attr(
        not(any(unix, test)),
        expect(dead_code, reason = "staging is Unix-only")
    )]
    Read,
    #[cfg_attr(
        not(any(unix, test)),
        expect(dead_code, reason = "staging is Unix-only")
    )]
    Remove,
    Inventory,
}

impl StageIoPath {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Put => "put",
            Self::Read => "read",
            Self::Remove => "remove",
            Self::Inventory => "inventory",
        }
    }

    fn refusal_labels(self) -> [KeyValue; 1] {
        [KeyValue::new("path", self.label())]
    }
}

/// The refusal both permit calls return, counted under `path`.
fn io_refusal(path: StageIoPath) -> WriteBehindError {
    crate::metrics::record_stage_io_refusal(&path.refusal_labels());
    WriteBehindError::Io {
        operation: "staging I/O capacity",
        kind: std::io::ErrorKind::WouldBlock,
    }
}

impl ConfinedRoot {
    fn capacity(&self, path: StageIoPath) -> &Arc<Semaphore> {
        match path {
            StageIoPath::Put => &self.inner.put_capacity,
            StageIoPath::Read | StageIoPath::Remove | StageIoPath::Inventory => {
                &self.inner.io_capacity
            }
        }
    }

    /// Refuse excess work before queueing it on Tokio's blocking pool.
    ///
    /// Move this permit into the blocking closure. Keeping it on the awaiting
    /// future would release capacity on cancellation while I/O still runs.
    pub(crate) fn try_io_permit(
        &self,
        path: StageIoPath,
    ) -> Result<OwnedSemaphorePermit, WriteBehindError> {
        match self.capacity(path).clone().try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(_) => Err(io_refusal(path)),
        }
    }

    /// [`Self::try_io_permit`], but wait up to `wait` for a slot to free.
    ///
    /// Row 76: a burst of puts larger than the pool used to refuse the excess
    /// at once. The client backs off up to 10 s per retry, so a commit then
    /// landed in waves 10 s apart even though slots freed within milliseconds.
    /// Waiters queue in arrival order. Dropping the returned future leaves the
    /// queue and holds no permit. A zero `wait` is [`Self::try_io_permit`].
    pub(crate) async fn io_permit_within(
        &self,
        path: StageIoPath,
        wait: std::time::Duration,
    ) -> Result<OwnedSemaphorePermit, WriteBehindError> {
        if wait.is_zero() {
            return self.try_io_permit(path);
        }
        match tokio::time::timeout(wait, self.capacity(path).clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            // `Err` inside is a closed semaphore, which nothing here does; treat
            // it as the refusal it would otherwise be.
            Ok(Err(_)) | Err(_) => Err(io_refusal(path)),
        }
    }

    #[cfg(unix)]
    pub(crate) fn inventory_root(&self) -> &Path {
        &self.inner.canonical
    }
    pub(crate) fn incoming(&self) -> &Path {
        &self.inner.incoming
    }

    /// Resolve one staged epoch to a path this process may act on.
    ///
    /// Pure: no syscall, no I/O. The device revalidation that makes an `ENOENT`
    /// trustworthy belongs to the acting methods, not to resolution.
    ///
    /// # Errors
    ///
    /// Returns [`WriteBehindError::KeyMismatch`] when the stored key is not the
    /// derived key, plus the width and range errors from
    /// [`derived_staged_key`].
    pub(crate) fn resolve(
        &self,
        hash: &[u8],
        epoch: i64,
        stored_key: &str,
    ) -> Result<ResolvedStagedPath, WriteBehindError> {
        let derived = derived_staged_key(hash, epoch)?;
        if stored_key != derived {
            return Err(WriteBehindError::KeyMismatch);
        }
        // Indexing is safe without a bounds check only because `derived` is this
        // function's own output: 64 hex characters then `.s<digits>`, so it is
        // always at least 4 ASCII bytes. Slicing the stored key instead would
        // reintroduce exactly the caller-controlled path this design removes.
        let parent = self.inner.staged.join(&derived[0..2]).join(&derived[2..4]);
        let path = parent.join(&derived);
        Ok(ResolvedStagedPath { path, parent })
    }
}

#[cfg(unix)]
mod platform {
    use std::ffi::CString;
    use std::fs;
    use std::io::Read as _;
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::path::Path;
    use std::sync::Arc;

    use bytes::Bytes;
    use lore_base::lore_spawn_blocking;
    use lore_base::types::FRAGMENT_SIZE_THRESHOLD;

    use super::AdmissionSample;
    use super::ConfinedRoot;
    use super::INCOMING_DIR;
    use super::ResolvedStagedPath;
    use super::RootInner;
    use super::STAGED_DIR;
    use super::StageIoPath;
    use super::StagedLeaf;
    use super::WriteBehindError;

    impl ConfinedRoot {
        /// Prove the configured root, then record its device.
        ///
        /// Step 3 is a real durability probe, not an existence check: it writes,
        /// fsyncs, renames and fsyncs a directory through the same calls a real
        /// stage makes, so a mount that cannot fsync a directory fails at boot
        /// rather than at the first acknowledged PUT.
        pub(crate) fn open(configured: &Path) -> Result<Self, WriteBehindError> {
            // Not a discard worth preserving: `RootUnresolvable` is a *closed*
            // classification of operator configuration, deliberately distinct from
            // `Io`, which `to_store_error` treats as a retryable environmental
            // failure. A root path that cannot be canonicalized is a refusal to
            // start whatever the underlying `ErrorKind` says, and `WriteBehindError`
            // is `Copy + PartialEq` by design (see its doc comment) so it cannot
            // carry the `io::Error` as a source either way.
            #[expect(
                clippy::map_err_ignore,
                reason = "the ErrorKind must not reclassify a configuration refusal as retryable Io"
            )]
            let canonical =
                fs::canonicalize(configured).map_err(|_| WriteBehindError::RootUnresolvable)?;
            match fs::symlink_metadata(&canonical) {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => return Err(WriteBehindError::RootNotADirectory),
                Err(_) => return Err(WriteBehindError::RootUnresolvable),
            }
            let directory = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&canonical)
                .map_err(|error| WriteBehindError::io("root directory open", &error))?;
            let metadata = directory
                .metadata()
                .map_err(|error| WriteBehindError::io("root directory stat", &error))?;
            if !metadata.is_dir() {
                return Err(WriteBehindError::RootNotADirectory);
            }
            let device = metadata.dev();
            let inode = metadata.ino();
            let staged = canonical.join(STAGED_DIR);
            let incoming = canonical.join(INCOMING_DIR);
            for directory in [&staged, &incoming] {
                if let Err(error) = fs::create_dir(directory)
                    && error.kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(WriteBehindError::io("root directory create", &error));
                }
            }
            // Both entry points must survive a crash before any stage can be
            // acknowledged. AlreadyExists is not durability evidence: another
            // process may have created the directory without syncing this root.
            sync_directory(&canonical)?;
            let root = Self {
                inner: Arc::new(RootInner {
                    canonical,
                    staged,
                    incoming,
                    device,
                    inode,
                    directory,
                    // Bounds unfinished reads and exact removals, and
                    // separately finalizers, including cancelled callers, to
                    // sixteen each per root handle.
                    io_capacity: Arc::new(tokio::sync::Semaphore::new(16)),
                    put_capacity: Arc::new(tokio::sync::Semaphore::new(16)),
                }),
            };
            root.probe()?;
            root.verify_device()?;
            Ok(root)
        }

        /// Exercise write, fsync, rename-within-filesystem and directory fsync.
        fn probe(&self) -> Result<(), WriteBehindError> {
            let token = uuid::Uuid::now_v7().simple().to_string();
            let temporary = self.inner.incoming.join(format!("probe-{token}.tmp"));
            let finalized = self.inner.staged.join(format!("probe-{token}"));
            let outcome = (|| -> Result<(), WriteBehindError> {
                let mut file = fs::File::create(&temporary)
                    .map_err(|error| WriteBehindError::io("probe create", &error))?;
                file.write_all(b"lore-write-behind-probe")
                    .map_err(|error| WriteBehindError::io("probe write", &error))?;
                file.sync_all()
                    .map_err(|error| WriteBehindError::io("probe fsync", &error))?;
                drop(file);
                fs::rename(&temporary, &finalized)
                    .map_err(|error| WriteBehindError::io("probe rename", &error))?;
                sync_directory(&self.inner.staged)?;
                fs::remove_file(&finalized)
                    .map_err(|error| WriteBehindError::io("probe unlink", &error))?;
                sync_directory(&self.inner.staged)
            })();
            // Leave nothing behind on either arm. A failed probe is a refusal to
            // start, and a refusal should not also litter the operator's mount.
            let _ = fs::remove_file(&temporary);
            let _ = fs::remove_file(&finalized);
            outcome.map_err(|error| match error {
                WriteBehindError::Io { .. } => WriteBehindError::RootProbeFailed,
                other => other,
            })
        }

        /// Confirm the pathname still names the directory recorded at open.
        ///
        /// This is what makes an `ENOENT` from [`Self::read_regular`] mean "this
        /// fragment is gone" rather than "the mount went away", which is the
        /// distinction that keeps a healthy fragment from being demoted to
        /// `Missing`.
        pub(crate) fn verify_device(&self) -> Result<(), WriteBehindError> {
            self.verified_root_directory().map(|_| ())
        }

        pub(crate) fn verified_root_directory(&self) -> Result<fs::File, WriteBehindError> {
            let current = match fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&self.inner.canonical)
            {
                Ok(current) => current,
                Err(_) => return Err(WriteBehindError::RootDeviceChanged),
            };
            let metadata = match current.metadata() {
                Ok(metadata) => metadata,
                Err(_) => return Err(WriteBehindError::RootDeviceChanged),
            };
            if metadata.dev() != self.inner.device || metadata.ino() != self.inner.inode {
                return Err(WriteBehindError::RootDeviceChanged);
            }
            self.inner
                .directory
                .try_clone()
                .map_err(|error| WriteBehindError::io("root descriptor clone", &error))
        }

        /// Create the fan-out directories for one staged path and make them
        /// durable.
        ///
        /// **Ordering matters and is the reason this is a separate step.** The
        /// directory entries must be durable *before* the rename that publishes
        /// the file into them, or a crash can leave the leaf entry
        /// non-durable after `commit_staged` has already made the row
        /// authoritative — a `Staged` row with no readable file, which
        /// ADR-00027 classifies as corruption.
        ///
        /// Each level is created separately so its parent can be synced before
        /// proceeding. `AlreadyExists` does not establish the entry's type or
        /// durability. See the module header for the intermediate-symlink
        /// residual this path does not close.
        ///
        /// Each level is opened before its parent is synced, and the leaf is
        /// created relative to the held upper level. Purge removes empty fan-out
        /// directories, so a name can be removed and recreated by another
        /// finalizer; opening first means every sync covers a directory this
        /// finalizer holds. If a held directory is removed afterwards, the next
        /// act in it is `NotFound` and the caller starts over.
        pub(crate) fn ensure_parent(
            &self,
            resolved: &ResolvedStagedPath,
        ) -> Result<StagedLeaf, WriteBehindError> {
            let parent = resolved.parent();
            let (Some(grandparent), Some(leaf_name)) = (parent.parent(), parent.file_name()) else {
                return Err(WriteBehindError::RootUnresolvable);
            };
            match fs::create_dir(grandparent) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(WriteBehindError::io("fanout create", &error)),
            }
            let upper = open_directory_at(None, grandparent)?;
            // Every finalizer establishes its own durability barrier. A peer
            // can pause after mkdir, so observing its entry is not proof that
            // the peer has synced the parent before this writer acknowledges.
            sync_directory(&self.inner.staged)?;
            let mode = rustix::fs::Mode::RWXU | rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO;
            match rustix::fs::mkdirat(&upper, leaf_name, mode) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(WriteBehindError::io("fanout create", &error.into())),
            }
            let handle = open_directory_at(Some(&upper), Path::new(leaf_name))?;
            sync_directory_handle(&upper, grandparent)?;
            Ok(StagedLeaf { handle })
        }

        /// Step 4: rename the synced temporary file into the held leaf.
        /// `NotFound` when the leaf has been removed since `ensure_parent`.
        pub(crate) fn rename_into(
            temporary: &Path,
            resolved: &ResolvedStagedPath,
            leaf: &StagedLeaf,
        ) -> Result<(), WriteBehindError> {
            let name = resolved
                .path()
                .file_name()
                .ok_or(WriteBehindError::KeyMismatch)?;
            // Only the target side is descriptor-relative. The source is still
            // the absolute path under `incoming/`, a fixed directory no purge
            // removes, so resolving it by path (from CWD) cannot redirect it.
            rustix::fs::renameat(rustix::fs::CWD, temporary, &leaf.handle, name)
                .map_err(|error| WriteBehindError::io("staging rename", &error.into()))
        }

        /// Step 5: make the renamed entry durable in the held leaf.
        pub(crate) fn sync_leaf(
            leaf: &StagedLeaf,
            resolved: &ResolvedStagedPath,
        ) -> Result<(), WriteBehindError> {
            sync_directory_handle(&leaf.handle, resolved.parent())
        }

        /// Read one staged file, bounded, refusing anything that is not a
        /// regular file on the recorded device.
        ///
        /// `Ok(None)` is a real `ENOENT` and nothing else.
        pub(crate) async fn read_regular(
            &self,
            resolved: &ResolvedStagedPath,
        ) -> Result<Option<Bytes>, WriteBehindError> {
            let permit = self.try_io_permit(StageIoPath::Read)?;
            let root = self.clone();
            let path = resolved.path().to_path_buf();
            let device = self.inner.device;
            join(lore_spawn_blocking!(move || {
                let _permit = permit;
                root.verify_device()?;
                #[cfg(test)]
                super::durability_tests::before_read(&path);
                read_regular_blocking(&path, device)
            }))
            .await
        }

        /// Remove one exact staged file and make the removal durable.
        ///
        /// `Ok(())` for an already-absent file: cleanup is idempotent, and a
        /// retried purge after a crash must not fail.
        pub(crate) async fn remove_regular(
            &self,
            resolved: &ResolvedStagedPath,
        ) -> Result<(), WriteBehindError> {
            let permit = self.try_io_permit(StageIoPath::Remove)?;
            let root = self.clone();
            let resolved = resolved.clone();
            join(lore_spawn_blocking!(move || {
                let _permit = permit;
                root.remove_placement_blocking(&resolved, false)
            }))
            .await
        }

        /// Unlink only the derived final or deterministic temporary placement.
        /// The caller must already own a bounded blocking-I/O slot.
        pub(crate) fn remove_placement_blocking(
            &self,
            resolved: &ResolvedStagedPath,
            temporary: bool,
        ) -> Result<(), WriteBehindError> {
            let relative = if temporary {
                let name = resolved
                    .path()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(WriteBehindError::KeyMismatch)?;
                std::path::PathBuf::from(INCOMING_DIR).join(format!("{name}.tmp"))
            } else {
                match resolved.path().strip_prefix(&self.inner.canonical) {
                    Ok(relative) => relative.to_owned(),
                    Err(_) => return Err(WriteBehindError::KeyMismatch),
                }
            };
            let mut components = relative.components().peekable();
            let mut directory = self.verified_root_directory()?;
            let mut directory_path = self.inner.canonical.clone();
            // Each opened level with the descriptor of the directory holding it.
            let mut chain = Vec::new();
            while let Some(component) = components.next() {
                let std::path::Component::Normal(name) = component else {
                    return Err(WriteBehindError::KeyMismatch);
                };
                let name = match CString::new(name.as_bytes()) {
                    Ok(name) => name,
                    Err(_) => return Err(WriteBehindError::KeyMismatch),
                };
                if components.peek().is_none() {
                    // SAFETY: directory owns a live directory fd and name is
                    // one NUL-terminated normal component. flags=0 unlinks the
                    // entry itself and never follows a final symlink.
                    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
                    if result != 0 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() != std::io::ErrorKind::NotFound {
                            return Err(WriteBehindError::io("confined unlink", &error));
                        }
                    }
                    // Even ENOENT needs this barrier: the prior unlink may
                    // have succeeded without its caller completing fsync.
                    sync_directory_handle(&directory, &directory_path)?;
                    if !temporary {
                        remove_empty_fanout(&chain);
                    }
                    return Ok(());
                }
                // SAFETY: the parent fd remains live through the call; name
                // contains exactly one path component. NOFOLLOW rejects
                // symlink substitution and DIRECTORY rejects non-directories.
                let fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::NotFound {
                        // A missing shard does not block temp-only cleanup.
                        // Persist the nearest verified existing ancestor.
                        return sync_directory_handle(&directory, &directory_path);
                    }
                    return Err(WriteBehindError::io("confined directory open", &error));
                }
                // SAFETY: openat returned a new owned fd, transferred exactly
                // once to File so every error path closes it.
                let child = unsafe { fs::File::from_raw_fd(fd) };
                let metadata = child
                    .metadata()
                    .map_err(|error| WriteBehindError::io("confined directory stat", &error))?;
                if metadata.dev() != self.inner.device {
                    return Err(WriteBehindError::RootDeviceChanged);
                }
                directory_path.push(std::ffi::OsStr::from_bytes(name.as_bytes()));
                chain.push((std::mem::replace(&mut directory, child), name));
            }
            Err(WriteBehindError::KeyMismatch)
        }

        /// Sample free space and root reachability for the admission snapshot.
        pub(crate) fn sample(&self) -> AdmissionSample {
            if self.verify_device().is_err() {
                return AdmissionSample::RootUnavailable;
            }
            match free_bytes(&self.inner.canonical) {
                Ok(free) => AdmissionSample::Reachable { free_bytes: free },
                Err(_) => AdmissionSample::RootUnavailable,
            }
        }
    }

    /// Open one directory without following a final symlink, by path or as one
    /// component relative to `parent`.
    fn open_directory_at(
        parent: Option<&fs::File>,
        path: &Path,
    ) -> Result<fs::File, WriteBehindError> {
        let flags = rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC;
        let opened = match parent {
            Some(parent) => rustix::fs::openat(parent, path, flags, rustix::fs::Mode::empty()),
            None => rustix::fs::open(path, flags, rustix::fs::Mode::empty()),
        };
        opened
            .map(fs::File::from)
            .map_err(|error| WriteBehindError::io("fanout open", &error.into()))
    }

    /// How many fan-out levels above a purged staged file may be removed once
    /// empty: `staged/<aa>/<bb>` loses `<bb>` then `<aa>`, never `staged`.
    const REMOVABLE_FANOUT_LEVELS: usize = 2;

    /// Remove the purged file's fan-out directories if they are now empty,
    /// deepest first (INV-FT F2: empty directories made every physical walk
    /// slower as the cell aged).
    ///
    /// `unlinkat(AT_REMOVEDIR)` removes only an empty directory, so a file a
    /// concurrent finalizer has already renamed in keeps its directory
    /// (`ENOTEMPTY`), and a directory a peer already removed is `ENOENT`. Either
    /// stops the walk. Any other error also stops it without failing the purge,
    /// because the file's removal is already durable and an empty directory is
    /// only a cost. Each removal is relative to a descriptor this purge opened
    /// with `O_NOFOLLOW` under the verified root and names one normal component.
    /// A finalizer that loses its freshly made directory to this retries; see
    /// `finalize_blocking`.
    ///
    /// The removal is not fsynced. A crash can bring back an empty directory,
    /// which a later purge in it removes again.
    fn remove_empty_fanout(chain: &[(fs::File, CString)]) {
        if chain.len() <= REMOVABLE_FANOUT_LEVELS {
            return;
        }
        for (parent, name) in chain.iter().rev().take(REMOVABLE_FANOUT_LEVELS) {
            // SAFETY: `parent` owns a live directory fd for the call, and `name`
            // is one NUL-terminated normal component. AT_REMOVEDIR removes only
            // an empty directory and never follows a symlink.
            let result =
                unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
            if result != 0 {
                return;
            }
        }
    }

    fn read_regular_blocking(path: &Path, device: u64) -> Result<Option<Bytes>, WriteBehindError> {
        // O_NOFOLLOW covers the final component: a symlink planted where the
        // staged file belongs is ELOOP here rather than a read of whatever it
        // names.
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(WriteBehindError::io("staged open", &error)),
        };
        let metadata = file
            .metadata()
            .map_err(|error| WriteBehindError::io("staged stat", &error))?;
        if !metadata.is_file() {
            return Err(WriteBehindError::NotARegularFile);
        }
        if metadata.dev() != device {
            return Err(WriteBehindError::RootDeviceChanged);
        }
        // Refuse before allocating. `tokio::fs::read`, which this replaced,
        // sizes its buffer from the file length and would happily allocate an
        // oversized one first.
        let length = metadata.len();
        if length > FRAGMENT_SIZE_THRESHOLD as u64 {
            return Err(WriteBehindError::PayloadOversized);
        }
        let mut buffer = Vec::with_capacity(length as usize);
        let mut handle = file.take(FRAGMENT_SIZE_THRESHOLD as u64 + 1);
        handle
            .read_to_end(&mut buffer)
            .map_err(|error| WriteBehindError::io("staged read", &error))?;
        if buffer.len() > FRAGMENT_SIZE_THRESHOLD {
            return Err(WriteBehindError::PayloadOversized);
        }
        Ok(Some(Bytes::from(buffer)))
    }

    /// fsync one directory so its entries survive a crash.
    pub(crate) fn sync_directory(directory: &Path) -> Result<(), WriteBehindError> {
        let handle = fs::File::open(directory)
            .map_err(|error| WriteBehindError::io("directory open", &error))?;
        sync_directory_handle(&handle, directory)
    }

    fn sync_directory_handle(handle: &fs::File, directory: &Path) -> Result<(), WriteBehindError> {
        #[cfg(test)]
        super::durability_tests::observe_sync(directory, false)?;
        #[cfg(not(test))]
        let _ = directory;
        handle
            .sync_all()
            .map_err(|error| WriteBehindError::io("directory fsync", &error))?;
        #[cfg(test)]
        super::durability_tests::observe_sync(directory, true)?;
        Ok(())
    }

    // `f_bavail` and `f_frsize` are `fsblkcnt_t`/`fsfilcnt_t`, whose width is
    // target-dependent: 64-bit on glibc x86_64, 32-bit on several musl and 32-bit
    // targets. The conversions are identity only on the target clippy happens to be
    // linting, and dropping them makes this function stop compiling everywhere else.
    // The lint cannot see the other targets; the `saturating_mul` below is already
    // written for the widened type.
    #[expect(
        clippy::useless_conversion,
        reason = "statvfs field widths are target-dependent; the widening is identity only on this target"
    )]
    fn free_bytes(path: &Path) -> Result<u64, WriteBehindError> {
        // A `NulError` carries only the byte offset of an interior NUL in a path this
        // process was configured with. There is nothing here worth preserving, and
        // `WriteBehindError` is `Copy + PartialEq` by design and cannot carry a source.
        #[expect(
            clippy::map_err_ignore,
            reason = "a NulError in the configured root path adds nothing to the configuration refusal"
        )]
        let raw = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| WriteBehindError::RootUnresolvable)?;
        // SAFETY: `statvfs` writes into a fully owned, correctly sized value and
        // reads `raw`, a NUL-terminated C string that outlives the call. The
        // return code is checked before the value is read.
        let stats = unsafe {
            let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            if libc::statvfs(raw.as_ptr(), stats.as_mut_ptr()) != 0 {
                return Err(WriteBehindError::RootUnresolvable);
            }
            stats.assume_init()
        };
        Ok(u64::from(stats.f_bavail).saturating_mul(u64::from(stats.f_frsize)))
    }

    /// Unwrap a blocking join, mapping a panicked or cancelled task to an I/O
    /// failure rather than propagating a panic into the store.
    async fn join<T>(
        handle: tokio::task::JoinHandle<Result<T, WriteBehindError>>,
    ) -> Result<T, WriteBehindError> {
        match handle.await {
            Ok(result) => result,
            Err(_) => Err(WriteBehindError::Io {
                operation: "blocking join",
                kind: std::io::ErrorKind::Interrupted,
            }),
        }
    }
}

#[cfg(not(unix))]
mod platform {
    use std::path::Path;

    use bytes::Bytes;

    use super::AdmissionSample;
    use super::ConfinedRoot;
    use super::ResolvedStagedPath;
    use super::StagedLeaf;
    use super::WriteBehindError;

    // Staging is Unix-only (owner ruling, 2026-09-16): directory fsync and
    // rename-over semantics differ enough that a Windows implementation would be
    // a weaker durability guarantee wearing the same name.
    //
    // The module still COMPILES here on purpose. Cfg-ing the whole staging
    // module out would leave the staged read arm in `immutable_store.rs` on its
    // old `tokio::fs::read`, which reintroduces exactly the fail-open that
    // demotes a healthy fragment to `Missing`. A platform that cannot stage must
    // still be unable to answer "absent" wrongly.
    impl ConfinedRoot {
        pub(crate) fn open(_configured: &Path) -> Result<Self, WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) fn verify_device(&self) -> Result<(), WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) fn ensure_parent(
            &self,
            _resolved: &ResolvedStagedPath,
        ) -> Result<StagedLeaf, WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) fn rename_into(
            _temporary: &Path,
            _resolved: &ResolvedStagedPath,
            _leaf: &StagedLeaf,
        ) -> Result<(), WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) fn sync_leaf(
            _leaf: &StagedLeaf,
            _resolved: &ResolvedStagedPath,
        ) -> Result<(), WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) async fn read_regular(
            &self,
            _resolved: &ResolvedStagedPath,
        ) -> Result<Option<Bytes>, WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) async fn remove_regular(
            &self,
            _resolved: &ResolvedStagedPath,
        ) -> Result<(), WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) fn remove_placement_blocking(
            &self,
            _resolved: &ResolvedStagedPath,
            _temporary: bool,
        ) -> Result<(), WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) fn sample(&self) -> AdmissionSample {
            AdmissionSample::RootUnavailable
        }
    }
}

#[cfg(all(test, unix))]
#[path = "durability_tests.rs"]
mod durability_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: [u8; 32] = [0xAB; 32];

    #[test]
    fn derived_key_is_lowercase_hex_with_the_epoch_suffix() {
        let key = derived_staged_key(&HASH, 7).expect("derive");
        assert_eq!(key, format!("{}.s7", "ab".repeat(32)));
    }

    #[test]
    fn derived_key_refuses_a_hash_that_is_not_thirty_two_bytes() {
        assert_eq!(
            derived_staged_key(&[0u8; 31], 1),
            Err(WriteBehindError::HashWidth)
        );
        assert_eq!(
            derived_staged_key(&[0u8; 33], 1),
            Err(WriteBehindError::HashWidth)
        );
        assert_eq!(derived_staged_key(&[], 1), Err(WriteBehindError::HashWidth));
    }

    #[test]
    fn io_refusals_are_labelled_by_the_refused_path() {
        let cases = [
            (StageIoPath::Put, "put"),
            (StageIoPath::Read, "read"),
            (StageIoPath::Remove, "remove"),
            (StageIoPath::Inventory, "inventory"),
        ];
        for (path, expected) in cases {
            assert_eq!(
                path.refusal_labels(),
                [KeyValue::new("path", expected)],
                "{path:?}"
            );
        }
    }

    #[test]
    fn derived_key_refuses_a_negative_epoch() {
        assert_eq!(
            derived_staged_key(&HASH, -1),
            Err(WriteBehindError::EpochNegative)
        );
    }
}
