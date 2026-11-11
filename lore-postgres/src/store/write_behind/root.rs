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
//! # What goes through the pinned tree, and what does not
//!
//! At open the root is pinned (device, inode and a held descriptor), and so
//! is its `staged/` subdirectory; `liveness/` is pinned on first use
//! (FORK-LOCAL, WP-115 drain guard). Each subdirectory is opened relative to
//! the held root descriptor with `openat2(RESOLVE_BENEATH | RESOLVE_NO_XDEV |
//! RESOLVE_NO_SYMLINKS)` on Linux, so a symlink or a mount point (a bind
//! mount included) there refuses the open: at `staged` the stage refuses to
//! start, at `liveness` every liveness file call fails. Every later root
//! check (`verify_device`) also checks that `<root path>/staged` still names
//! the pinned `staged/`, with the same confined open; the liveness root
//! check (`liveness_tree_intact`) checks `liveness` the same way.
//!
//! Through the pinned descriptors, confined the same way:
//!
//! - staged reads: the file is opened relative to the held `staged/`
//!   descriptor, so an `ENOENT` is a miss in the pinned directory and in no
//!   other one; the root check runs before the read and again after a miss;
//! - the fan-out directories a finalizer creates and the rename target;
//! - cleanup's walk and exact unlinks (each level confined, `staged/` itself
//!   checked against the pinned inode);
//! - every stage liveness file (`liveness/`), see [`StageLivenessDir`].
//!
//! Not through them: the finalizer's temporary file under `incoming/` is
//! created and renamed from by path. A rename out of another directory than
//! the pinned root's `incoming/` either fails (`EXDEV` across a mount) or
//! still lands in the pinned leaf. The boot probe and the free-space sample
//! also use paths.
//!
//! [`StageLivenessDir`]: super::StageLivenessDir

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
/// FORK-LOCAL (Tideshift), WP-115 K11: subdirectory of the stage root where
/// each `role = "stage"` replica writes its liveness probe file.
///
/// The inventory walk counts every file under the root, and a file no ledger
/// charges fails the capacity predicate (`stage_unknown_entries`). So the walk
/// skips this one directory at the top level, and nothing else reads it.
///
/// No older pattern could hold the probe instead: the walk before K11 skips
/// no name at all. It counts every regular file, and every non-file entry is
/// unknown. A `<hash>.s<epoch>.tmp` name would be a cleanup candidate.
///
/// **Deploy note: the release that adds this needs a full-cell roll.** While
/// a pre-K11 binary still runs, its walk can catch a peer's probe file. The
/// file exists for a few milliseconds every 2 s per stage replica, and the walk
/// must list it and stat it inside that window. Each hit has this effect on
/// that older host:
///
/// - The walk reports `stage_unknown_entries`. That predicate is not
///   reconciling, so staging admission refuses at once: `StagingMode::Refuse`,
///   and PUTs answer `SlowDown`. It is not `DirectFallback`.
/// - The refusal lasts until that host's next completed walk. That is one
///   observer tick (1 s) for a stage under 4096 entries, and one more tick for
///   each further 4096 entries.
/// - Only if the run outlives `drain_stale_after` does `/health_check` on that
///   host answer `capacity_unavailable`.
/// - `/lb_health` on an older `stage` replica does not change, because it
///   ignores capacity. An older `drain` replica answers `drain_role` in every
///   case.
pub const LIVENESS_DIR: &str = "liveness";

/// A staged path this process derived and may act on.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedStagedPath {
    path: PathBuf,
    parent: PathBuf,
    /// `<aa>/<bb>/<key>`, relative to `staged/`: what reads open beneath the
    /// pinned `staged/` descriptor.
    relative: PathBuf,
}

impl ResolvedStagedPath {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg_attr(not(unix), expect(dead_code, reason = "staging is Unix-only"))]
    pub(crate) fn relative(&self) -> &Path {
        &self.relative
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
    /// FORK-LOCAL (Tideshift), WP-115 drain guard: `<root>/staged`, opened
    /// confined beneath the root descriptor at open. Reads, fan-out creation
    /// and the rename target go through it.
    #[cfg(unix)]
    staged_dir: PinnedDir,
    /// FORK-LOCAL (Tideshift), WP-115 drain guard: `<root>/liveness`, opened
    /// confined beneath the held root descriptor on first use (created if
    /// absent, as the K11 probe always did). Every stage liveness file goes
    /// through it.
    #[cfg(unix)]
    liveness_dir: std::sync::OnceLock<PinnedDir>,
    /// Shared by all clones. Each blocking closure owns its permit until its
    /// final syscall completes, even if the async caller stops waiting.
    /// Drain and cleanup reads, purge and the physical inventory use this
    /// pool. None of them waits for a slot.
    io_capacity: Arc<Semaphore>,
    /// Foreground GET reads' own pool, the same size. A GET may wait for a
    /// slot (row 80), and, as with puts below, a queue of waiting GETs on the
    /// shared pool would take every freed permit ahead of the drain's
    /// `try_acquire` and starve promotion and purge.
    read_capacity: Arc<Semaphore>,
    /// The put path's own pool, the same size. A put may wait for a slot (see
    /// [`ConfinedRoot::io_permit_within`]), and a tokio semaphore hands a
    /// released permit to its queued waiters before any `try_acquire`. One
    /// shared pool would let a queue of puts starve drain reads, which then
    /// age into `drain_backpressure_sustained`.
    put_capacity: Arc<Semaphore>,
}

/// One subdirectory of the root, opened confined beneath it at open: its held
/// descriptor and the identity it had then.
#[cfg(unix)]
struct PinnedDir {
    file: std::fs::File,
    device: u64,
    inode: u64,
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

/// Slots in each of a root's three I/O pools.
#[cfg_attr(not(unix), expect(dead_code, reason = "staging is Unix-only"))]
pub(crate) const STAGE_IO_SLOTS: usize = 16;

/// The staging path that asked for an I/O slot.
///
/// Three bounded pools. Puts and foreground GET reads each have their own,
/// because each may wait; drain and cleanup reads, purge and the physical
/// inventory share the third and never wait. A put holds its slot across
/// `begin_stage`, so a slow coordinator slows other puts. The refusal counter
/// carries this label so that shows up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageIoPath {
    Put,
    /// A foreground GET's staged read. Waits up to the configured read wait.
    #[cfg_attr(
        not(any(unix, test)),
        expect(dead_code, reason = "staging is Unix-only")
    )]
    Read,
    /// A drain promotion or cleanup read. Refused at once when its pool is full.
    #[cfg_attr(
        not(any(unix, test)),
        expect(dead_code, reason = "staging is Unix-only")
    )]
    DrainRead,
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
            Self::DrainRead => "drain_read",
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
            StageIoPath::Read => &self.inner.read_capacity,
            StageIoPath::DrainRead | StageIoPath::Remove | StageIoPath::Inventory => {
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
    ///
    /// The wait is hard-bounded by `wait`, and each nonzero-wait call records
    /// how long it waited in the `stage_io_wait` histogram, labelled `path`
    /// and `outcome` (`granted` or `refused`). A refusal is also counted in
    /// `stage_io_refusals`, as before.
    pub(crate) async fn io_permit_within(
        &self,
        path: StageIoPath,
        wait: std::time::Duration,
    ) -> Result<OwnedSemaphorePermit, WriteBehindError> {
        if wait.is_zero() {
            return self.try_io_permit(path);
        }
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(wait, self.capacity(path).clone().acquire_owned()).await;
        let waited = started.elapsed();
        // An inner `Err` is a closed semaphore, which nothing here does; treat
        // it as the refusal it would otherwise be.
        if let Ok(Ok(permit)) = outcome {
            crate::metrics::record_stage_io_wait(path.label(), "granted", waited);
            Ok(permit)
        } else {
            crate::metrics::record_stage_io_wait(path.label(), "refused", waited);
            Err(io_refusal(path))
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
        let relative = Path::new(&derived[0..2])
            .join(&derived[2..4])
            .join(&derived);
        Ok(ResolvedStagedPath {
            path,
            parent,
            relative,
        })
    }
}

#[cfg(unix)]
mod platform {
    use std::ffi::CString;
    use std::fs;
    use std::io::Read as _;
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
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
    use super::LIVENESS_DIR;
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
            for name in [STAGED_DIR, INCOMING_DIR] {
                match rustix::fs::mkdirat(&directory, name, directory_mode()) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => {
                        return Err(WriteBehindError::io("root directory create", &error.into()));
                    }
                }
            }
            // Both entry points must survive a crash before any stage can be
            // acknowledged. AlreadyExists is not durability evidence: another
            // process may have created the directory without syncing this root.
            sync_directory(&canonical)?;
            // WP-115 drain guard: a symlink or a mount point at `staged`
            // refuses the open, so it refuses to start. `liveness/` is
            // pinned on first use (`pinned_liveness`).
            let staged_dir = pin_child(&directory, STAGED_DIR)?;
            let root = Self {
                inner: Arc::new(RootInner {
                    canonical,
                    staged,
                    incoming,
                    device,
                    inode,
                    directory,
                    staged_dir,
                    liveness_dir: std::sync::OnceLock::new(),
                    // Bounds unfinished drain reads and exact removals, and
                    // separately GET reads and finalizers, including
                    // cancelled callers, to sixteen each per root handle.
                    io_capacity: Arc::new(tokio::sync::Semaphore::new(super::STAGE_IO_SLOTS)),
                    read_capacity: Arc::new(tokio::sync::Semaphore::new(super::STAGE_IO_SLOTS)),
                    put_capacity: Arc::new(tokio::sync::Semaphore::new(super::STAGE_IO_SLOTS)),
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

        /// FORK-LOCAL (Tideshift), WP-115 drain guard: whether the configured
        /// root path, as it resolves now, still names the pinned root, AND
        /// its `staged/` and `liveness/` entries, opened confined beneath it
        /// (no symlink, no mount point), are the directories pinned at open.
        /// Blocking. Any error is `false`, and so is every platform but
        /// Linux: without `openat2` a mount point at either name cannot be
        /// told apart, so nothing there counts as proven.
        ///
        /// Stage liveness checks this before and after each proof I/O
        /// (challenge write, echo write, echo or challenge read). The I/O
        /// itself goes through the pinned `liveness/` descriptor.
        pub(crate) fn liveness_tree_intact(&self) -> bool {
            if !cfg!(target_os = "linux") {
                return false;
            }
            self.current_root().is_ok_and(|current| {
                self.pinned_liveness()
                    .is_ok_and(|pinned| child_is(&current, LIVENESS_DIR, pinned))
            })
        }

        /// WP-115 drain guard: `<root>/liveness`, pinned on first use: created
        /// beneath the HELD root descriptor if absent, then opened confined
        /// beneath it (no symlink, no mount point), never by path. A symlink
        /// or a mount point there fails every liveness file call and every
        /// liveness root check, so nothing is proven through it.
        fn pinned_liveness(&self) -> std::io::Result<&super::PinnedDir> {
            if let Some(pinned) = self.inner.liveness_dir.get() {
                return Ok(pinned);
            }
            match rustix::fs::mkdirat(&self.inner.directory, LIVENESS_DIR, directory_mode()) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            let pinned =
                pin_child(&self.inner.directory, LIVENESS_DIR).map_err(std::io::Error::other)?;
            // A racing first use pinned the same directory, or failed; either
            // way the stored one is the pin.
            let _ = self.inner.liveness_dir.set(pinned);
            self.inner
                .liveness_dir
                .get()
                .ok_or_else(|| std::io::Error::other("stage liveness directory not pinned"))
        }

        /// The root path's directory as it resolves now, if it is the pinned
        /// root and its `staged/` entry is the pinned `staged/`.
        fn current_root(&self) -> Result<fs::File, WriteBehindError> {
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
            // WP-115 drain guard: a symlink, a mount point (a bind mount
            // included) or another directory now at `staged` would send a
            // path-based writer elsewhere. Stage I/O goes through the pinned
            // `staged/`, but the root check refuses the tree anyway.
            if !child_is(&current, STAGED_DIR, &self.inner.staged_dir) {
                return Err(WriteBehindError::RootDeviceChanged);
            }
            Ok(current)
        }

        pub(crate) fn verified_root_directory(&self) -> Result<fs::File, WriteBehindError> {
            self.current_root()?;
            self.inner
                .directory
                .try_clone()
                .map_err(|error| WriteBehindError::io("root descriptor clone", &error))
        }

        /// WP-115 drain guard: read one stage liveness file, at most `limit`
        /// bytes, through the pinned `liveness/` descriptor. `None` when there
        /// is no such file. `name` must be one plain file name.
        pub(crate) fn liveness_read(
            &self,
            name: &str,
            limit: u64,
        ) -> std::io::Result<Option<Vec<u8>>> {
            let name = liveness_name(name)?;
            let file = match open_beneath(
                &self.pinned_liveness()?.file,
                name,
                rustix::fs::OFlags::RDONLY,
                rustix::fs::Mode::empty(),
            ) {
                Ok(file) => fs::File::from(file),
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let mut content = Vec::new();
            file.take(limit).read_to_end(&mut content)?;
            Ok(Some(content))
        }

        /// WP-115 drain guard: replace one stage liveness file through the
        /// pinned `liveness/` descriptor: write `temporary`, fsync, then
        /// rename it over `name`, so a reader never sees a partial file.
        pub(crate) fn liveness_replace(
            &self,
            name: &str,
            temporary: &str,
            content: &[u8],
        ) -> std::io::Result<()> {
            let name = liveness_name(name)?;
            let temporary = liveness_name(temporary)?;
            let directory = &self.pinned_liveness()?.file;
            {
                let mut handle = fs::File::from(open_beneath(
                    directory,
                    temporary,
                    rustix::fs::OFlags::WRONLY
                        | rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::TRUNC,
                    rustix::fs::Mode::RUSR
                        | rustix::fs::Mode::WUSR
                        | rustix::fs::Mode::RGRP
                        | rustix::fs::Mode::ROTH,
                )?);
                handle.write_all(content)?;
                handle.sync_all()?;
            }
            rustix::fs::renameat(directory, temporary, directory, name)?;
            Ok(())
        }

        /// WP-115 drain guard: remove one stage liveness file through the
        /// pinned `liveness/` descriptor. An absent file is a success.
        pub(crate) fn liveness_remove(&self, name: &str) -> std::io::Result<()> {
            let name = liveness_name(name)?;
            match rustix::fs::unlinkat(
                &self.pinned_liveness()?.file,
                name,
                rustix::fs::AtFlags::empty(),
            ) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
                Err(error) => Err(error.into()),
            }
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
            let Some(upper_name) = grandparent.file_name() else {
                return Err(WriteBehindError::RootUnresolvable);
            };
            // WP-115 drain guard: created and opened beneath the pinned
            // `staged/` descriptor, never by path, so a symlink or a mount
            // later placed at `<root>/staged` cannot redirect a stage.
            let staged = &self.inner.staged_dir.file;
            match rustix::fs::mkdirat(staged, upper_name, directory_mode()) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(WriteBehindError::io("fanout create", &error.into())),
            }
            let upper = open_directory_at(staged, Path::new(upper_name))?;
            // Every finalizer establishes its own durability barrier. A peer
            // can pause after mkdir, so observing its entry is not proof that
            // the peer has synced the parent before this writer acknowledges.
            sync_directory_handle(staged, &self.inner.staged)?;
            match rustix::fs::mkdirat(&upper, leaf_name, directory_mode()) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(WriteBehindError::io("fanout create", &error.into())),
            }
            let handle = open_directory_at(&upper, Path::new(leaf_name))?;
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
        ///
        /// A drain or cleanup read: it takes a slot from the shared pool or is
        /// refused at once.
        pub(crate) async fn read_regular(
            &self,
            resolved: &ResolvedStagedPath,
        ) -> Result<Option<Bytes>, WriteBehindError> {
            let permit = self.try_io_permit(StageIoPath::DrainRead)?;
            self.read_regular_permitted(permit, resolved).await
        }

        /// [`Self::read_regular`] for a foreground GET: it takes a slot from
        /// the GET pool and waits up to `wait` for one. A zero `wait` refuses
        /// at once.
        pub(crate) async fn read_regular_within(
            &self,
            resolved: &ResolvedStagedPath,
            wait: std::time::Duration,
        ) -> Result<Option<Bytes>, WriteBehindError> {
            let permit = self.io_permit_within(StageIoPath::Read, wait).await?;
            self.read_regular_permitted(permit, resolved).await
        }

        async fn read_regular_permitted(
            &self,
            permit: tokio::sync::OwnedSemaphorePermit,
            resolved: &ResolvedStagedPath,
        ) -> Result<Option<Bytes>, WriteBehindError> {
            let root = self.clone();
            #[cfg(test)]
            let path = resolved.path().to_path_buf();
            let relative = resolved.relative().to_path_buf();
            join(lore_spawn_blocking!(move || {
                let _permit = permit;
                root.verify_device()?;
                #[cfg(test)]
                super::durability_tests::before_read(&path);
                #[cfg(all(test, target_os = "linux"))]
                super::pinned_tree_tests::before_read(&path);
                let read = read_regular_blocking(
                    &root.inner.staged_dir.file,
                    &relative,
                    root.inner.device,
                )?;
                // WP-115 drain guard: a miss counts only while the root path
                // still names the pinned root and its pinned `staged/`. The
                // open itself was beneath the pinned `staged/`, so the miss is
                // in that directory and in no other one.
                if read.is_none() {
                    root.verify_device()?;
                }
                Ok(read)
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
                // One component, confined beneath the parent (no symlink, no
                // mount point; see `open_beneath`); DIRECTORY rejects
                // non-directories.
                let child = match open_beneath(
                    &directory,
                    Path::new(std::ffi::OsStr::from_bytes(name.as_bytes())),
                    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                    rustix::fs::Mode::empty(),
                ) {
                    Ok(child) => fs::File::from(child),
                    Err(rustix::io::Errno::NOENT) => {
                        // A missing shard does not block temp-only cleanup.
                        // Persist the nearest verified existing ancestor.
                        return sync_directory_handle(&directory, &directory_path);
                    }
                    Err(error) => {
                        return Err(WriteBehindError::io(
                            "confined directory open",
                            &error.into(),
                        ));
                    }
                };
                let metadata = child
                    .metadata()
                    .map_err(|error| WriteBehindError::io("confined directory stat", &error))?;
                if metadata.dev() != self.inner.device {
                    return Err(WriteBehindError::RootDeviceChanged);
                }
                // WP-115 drain guard: the top-level `staged` must still be
                // the directory pinned at open.
                if chain.is_empty()
                    && name.as_bytes() == STAGED_DIR.as_bytes()
                    && metadata.ino() != self.inner.staged_dir.inode
                {
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

    /// Open one directory as one component confined beneath `parent` (see
    /// [`open_beneath`]).
    fn open_directory_at(parent: &fs::File, path: &Path) -> Result<fs::File, WriteBehindError> {
        open_beneath(
            parent,
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map(fs::File::from)
        .map_err(|error| WriteBehindError::io("fanout open", &error.into()))
    }

    /// `rwxrwxrwx` before the umask: the mode staging has always created its
    /// directories with.
    fn directory_mode() -> rustix::fs::Mode {
        rustix::fs::Mode::RWXU | rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO
    }

    /// FORK-LOCAL (Tideshift), WP-115 drain guard: open `relative` beneath
    /// `parent` without following a symlink anywhere and without crossing a
    /// mount point. On Linux this is `openat2` with `RESOLVE_BENEATH |
    /// RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, as
    /// cleanup's inventory walk and the spool writer already use, always
    /// with `O_NOFOLLOW` added. A symlink at the last component is refused
    /// by `O_NOFOLLOW` (`ELOOP`, or `ENOTDIR` with `O_DIRECTORY`, as for a
    /// symlink at `staged`); `RESOLVE_BENEATH` keeps every middle component
    /// inside `parent`, and `RESOLVE_NO_SYMLINKS` also refuses a symlink
    /// there (`ELOOP`). So for the drain guard `RESOLVE_NO_SYMLINKS` is
    /// defence in depth: without it a read still stays in the pinned
    /// directory. A mount point (a bind mount included) is `EXDEV`, and `..`
    /// is refused. `openat2` needs Linux 5.6 or later: an `ENOSYS` or
    /// `EPERM` (an older kernel, or a seccomp filter that blocks it) fails
    /// the stage open, so the server does not boot. Elsewhere it is
    /// `openat(O_NOFOLLOW)`, which covers only a final symlink: there,
    /// nothing it reads is proof for the drain guard
    /// ([`ConfinedRoot::liveness_tree_intact`] is `false` and the absence
    /// guard never proves a miss).
    fn open_beneath(
        parent: &fs::File,
        relative: &Path,
        flags: rustix::fs::OFlags,
        mode: rustix::fs::Mode,
    ) -> rustix::io::Result<std::os::fd::OwnedFd> {
        let flags = flags | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
        #[cfg(target_os = "linux")]
        {
            rustix::fs::openat2(
                parent,
                relative,
                flags,
                mode,
                rustix::fs::ResolveFlags::BENEATH
                    | rustix::fs::ResolveFlags::NO_XDEV
                    | rustix::fs::ResolveFlags::NO_SYMLINKS
                    | rustix::fs::ResolveFlags::NO_MAGICLINKS,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            rustix::fs::openat(parent, relative, flags, mode)
        }
    }

    /// WP-115 drain guard: open `name` confined beneath the root descriptor
    /// and record its identity. A symlink, a mount point or a non-directory
    /// there refuses to start.
    fn pin_child(root: &fs::File, name: &str) -> Result<super::PinnedDir, WriteBehindError> {
        let file = open_beneath(
            root,
            Path::new(name),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map(fs::File::from)
        .map_err(|error| match error {
            // A symlink at the name (`ENOTDIR`: `O_NOFOLLOW` with
            // `O_DIRECTORY`, measured), a mount point (`EXDEV`) or a
            // non-directory (`ENOTDIR`). `ELOOP` stays mapped for a kernel
            // that reports the symlink that way. Any other error, `ENOSYS`
            // or `EPERM` from a kernel before 5.6 or a seccomp filter
            // included, is an I/O error that fails boot.
            rustix::io::Errno::LOOP | rustix::io::Errno::XDEV | rustix::io::Errno::NOTDIR => {
                WriteBehindError::StageTreeUnconfined
            }
            other => WriteBehindError::io("stage subdirectory open", &other.into()),
        })?;
        let metadata = file
            .metadata()
            .map_err(|error| WriteBehindError::io("stage subdirectory stat", &error))?;
        if !metadata.is_dir() {
            return Err(WriteBehindError::StageTreeUnconfined);
        }
        Ok(super::PinnedDir {
            device: metadata.dev(),
            inode: metadata.ino(),
            file,
        })
    }

    /// WP-115 drain guard: whether `name`, opened confined beneath `root` now,
    /// is the directory `pinned` (same device and inode). Any error is
    /// `false`.
    fn child_is(root: &fs::File, name: &str, pinned: &super::PinnedDir) -> bool {
        open_beneath(
            root,
            Path::new(name),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .ok()
        .and_then(|child| fs::File::from(child).metadata().ok())
        .is_some_and(|metadata| metadata.dev() == pinned.device && metadata.ino() == pinned.inode)
    }

    /// WP-115 drain guard: `name` as one plain file name, or `InvalidInput`.
    fn liveness_name(name: &str) -> std::io::Result<&Path> {
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\0')
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a stage liveness file name must be one plain file name",
            ));
        }
        Ok(Path::new(name))
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

    fn read_regular_blocking(
        staged: &fs::File,
        relative: &Path,
        device: u64,
    ) -> Result<Option<Bytes>, WriteBehindError> {
        // WP-115 drain guard: opened beneath the pinned `staged/` descriptor,
        // confined (see `open_beneath`): a symlink at any component (the
        // final one by `O_NOFOLLOW`, a middle one by `RESOLVE_NO_SYMLINKS`)
        // or a mount point on the way is a refusal (ELOOP, EXDEV), never a
        // read of whatever it names and never an `ENOENT` from another
        // directory.
        let file = match open_beneath(
            staged,
            relative,
            rustix::fs::OFlags::RDONLY,
            rustix::fs::Mode::empty(),
        ) {
            Ok(file) => fs::File::from(file),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(WriteBehindError::io("staged open", &error.into())),
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
    // The stubs keep the unix signatures, so they take `self` and stay `async` unused.
    #[allow(clippy::unused_self, clippy::unused_async)]
    impl ConfinedRoot {
        pub(crate) fn open(_configured: &Path) -> Result<Self, WriteBehindError> {
            Err(WriteBehindError::UnsupportedPlatform)
        }

        pub(crate) fn liveness_tree_intact(&self) -> bool {
            false
        }

        pub(crate) fn liveness_read(
            &self,
            _name: &str,
            _limit: u64,
        ) -> std::io::Result<Option<Vec<u8>>> {
            Err(std::io::ErrorKind::Unsupported.into())
        }

        pub(crate) fn liveness_replace(
            &self,
            _name: &str,
            _temporary: &str,
            _content: &[u8],
        ) -> std::io::Result<()> {
            Err(std::io::ErrorKind::Unsupported.into())
        }

        pub(crate) fn liveness_remove(&self, _name: &str) -> std::io::Result<()> {
            Err(std::io::ErrorKind::Unsupported.into())
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

        pub(crate) async fn read_regular_within(
            &self,
            _resolved: &ResolvedStagedPath,
            _wait: std::time::Duration,
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

#[cfg(all(test, target_os = "linux"))]
#[path = "pinned_tree_tests.rs"]
mod pinned_tree_tests;

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
            (StageIoPath::DrainRead, "drain_read"),
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
