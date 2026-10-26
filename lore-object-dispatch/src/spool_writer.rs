// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Descriptor-relative durable spool body writer.
//!
//! WP-122 L5. Before this module nothing in the tree wrote into the shared spool
//! root: [`crate::spool`] only derives paths and [`crate::spool_verifier`] only
//! reads them. A drain worker has to put the body there before
//! `put_spool_ready` can assert it is durable, and the assertion is only true if
//! the placement was durable in the first place.
//!
//! # The ordering is the contract
//!
//! Copied, deliberately, from `lore-postgres`'s
//! `store/write_behind/finalize.rs` rather than invented here. In exactly this
//! order:
//!
//! 1. create each directory level below the root, and fsync **its parent**
//!    before descending;
//! 2. write the body to the derived `.part` file;
//! 3. fsync the `.part` file — `sync_all`, because the rename publishes metadata
//!    as well as contents;
//! 4. rename it onto the derived `.blob` path;
//! 5. fsync the leaf directory that now holds the entry.
//!
//! Step 1 precedes step 4 and that is not cosmetic. Directory entries fsynced
//! only after the rename can be lost by a crash, leaving a reserved spool object
//! whose body cannot be found — and `put_spool_ready` would then record as
//! durable a handle that resolves to nothing. `AlreadyExists` from `mkdirat` is
//! not durability evidence: a peer may have created the directory without
//! syncing this root, so every writer establishes its own barrier.
//!
//! # What a crash leaves at each point
//!
//! - before step 4: a `.part` file. `SpoolRecoveryDecision` already classifies
//!   that state, and this module never publishes a handle for it.
//! - between step 4 and the caller's `put_spool_ready`: a complete, valid
//!   `.blob` with no ready row. That is the spool's own orphan class, and it is
//!   **not** this module's to reclaim — the same rule `write_behind/cleanup.rs`
//!   follows, for the same reason: a body with no row is indistinguishable from
//!   one whose ready call is in flight.
//!
//! # Confinement is stronger here than under the staging root, on purpose
//!
//! `ConfinedRoot` resolves absolute paths and covers only the final component
//! with `O_NOFOLLOW`, documenting an intermediate-symlink residual it does not
//! close. This module writes into the root that [`crate::spool_verifier`]
//! reads under `openat2` with `RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS |
//! NO_XDEV`, so it uses the same resolution. A writer weaker than the reader
//! could place bytes the reader is then obliged to refuse, which is a failure
//! mode with no useful diagnosis.
//!
//! # Authority this module does NOT grant
//!
//! It writes bytes and reports what it wrote. It grants no reservation, ledger,
//! quota, publication or cleanup authority, and its receipt is the **writer's
//! own observation** — the value `mark_spool_ready` documents as "as the writer
//! observed it". It is not an independent anchor and must not be used as one.

use std::fmt;

use thiserror::Error;

use crate::spool::SpoolLayout;
use crate::spool::SpoolObjectKey;

/// Largest body this writer accepts, matching the provider seam's ingress cap.
///
/// A drain body is one fragment, and a fragment is bounded at 256 KiB, so a
/// larger body is a defect rather than a large object. The bound is restated
/// here rather than imported so this crate keeps no dependency on the seam.
pub const MAX_SPOOL_BODY_BYTES: u64 = 256 * 1024;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SpoolWriteError {
    #[error("shared spool writing is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("shared spool root is invalid")]
    InvalidRoot,
    #[error("shared spool root is unavailable")]
    RootUnavailable,
    #[error("shared spool root changed after writer initialization")]
    RootChanged,
    #[error("shared spool body writer accepts only PUT spool objects")]
    InvalidSpoolKind,
    #[error("shared spool key is invalid")]
    InvalidSpoolKey,
    #[error("derived spool path does not belong to the writer root")]
    PathBindingMismatch,
    #[error("shared spool body size is invalid")]
    InvalidBodySize,
    #[error("shared spool part file already exists")]
    PartAlreadyPresent,
    #[error("shared spool body is already durable at its final path")]
    BodyAlreadyPresent,
    #[error("shared spool path resolves to an unsafe or non-regular entry")]
    UnsafeOrNonRegular,
    /// The spool filesystem refused `RENAME_NOREPLACE` (`EINVAL`, `ENOSYS` or `EXDEV`), as NFS
    /// does. The retired-floor walk can only quarantine with it, so the spool root must be a
    /// local POSIX filesystem.
    #[error(
        "shared spool filesystem does not support RENAME_NOREPLACE; the spool root must be a local POSIX filesystem"
    )]
    RenameNoReplaceUnsupported,
    #[error("shared spool write failed at {operation}")]
    Io {
        operation: &'static str,
        os: SpoolOsError,
    },
}

impl SpoolWriteError {
    /// The operating-system error behind an [`SpoolWriteError::Io`], if this is one.
    pub fn os_error(&self) -> Option<SpoolOsError> {
        match self {
            Self::Io { os, .. } => Some(*os),
            _ => None,
        }
    }
}

/// The operating-system error behind a spool I/O failure, small enough to keep
/// [`SpoolWriteError`] and `SpoolVerificationError` `Copy` and `Eq`.
///
/// The variants carrying it used to drop the `std::io::Error` or `Errno` they
/// were mapped from, leaving an operator "write failed at part fsync" and no
/// errno. `std::io::Error` is neither `Copy` nor `Eq`; its kind and raw code
/// are, and they are what a diagnosis needs. The carrying variants' `Display`
/// text is unchanged, so a caller that logs the failure appends this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpoolOsError {
    kind: std::io::ErrorKind,
    raw_os_error: Option<i32>,
}

impl SpoolOsError {
    /// Keeps `error`'s kind and its raw code, which is platform-native (see
    /// [`Self::raw_os_error`]).
    pub fn from_io(error: &std::io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn from_errno(errno: rustix::io::Errno) -> Self {
        Self::from_io(&std::io::Error::from_raw_os_error(errno.raw_os_error()))
    }

    pub fn kind(&self) -> std::io::ErrorKind {
        self.kind
    }

    /// The platform-native code: an errno on Linux, a Win32 error code on Windows. Compare it only
    /// with codes from the same platform.
    pub fn raw_os_error(&self) -> Option<i32> {
        self.raw_os_error
    }
}

impl fmt::Display for SpoolOsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.raw_os_error {
            Some(code) => write!(formatter, "{} (os error {code})", self.kind),
            None => write!(formatter, "{}", self.kind),
        }
    }
}

/// What one durable spool placement produced.
///
/// The handle is [`crate::spool::SpoolPaths::opaque_handle`] for the same key,
/// so it satisfies `bind_durable_put_body_from_ready`'s derived-handle equality
/// by construction rather than by a caller remembering to pass the right string.
#[derive(Clone, PartialEq, Eq)]
pub struct SpoolWriteReceipt {
    opaque_handle: String,
    size: u64,
    blake3: [u8; 32],
}

impl SpoolWriteReceipt {
    pub fn opaque_handle(&self) -> &str {
        &self.opaque_handle
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn blake3(&self) -> &[u8; 32] {
        &self.blake3
    }
}

/// A completed physical walk of the spool root, and when it completed. The walk
/// lags the ledger by at least its age, so readiness reports that age beside the
/// capacity verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpoolPhysicalInventory {
    pub completed_at: std::time::Instant,
    pub bytes: u64,
    pub files: u64,
}

/// One bounded step of the physical walk.
///
/// `started` is true when this step began a new traversal, and `completed` is
/// the traversal this step finished, if any. A caller that compares a walk with
/// a ledger needs both edges: a body counted by the walk was reserved before it
/// was placed and released only after it was unlinked, so the ledger read before
/// the walk started and the ledger read after it completed bound what the walk
/// can legitimately count between them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpoolInventoryStep {
    pub started: bool,
    pub completed: Option<SpoolPhysicalInventory>,
}

/// The root-level directory the retired-floor walk moves residue into. The physical walk skips it,
/// so quarantined bytes never count against the spool ledger.
pub const SPOOL_QUARANTINE_DIRECTORY: &str = "quarantine";

/// One bounded step of the retired-floor walk (WP-115 f2, migration 0032).
///
/// A PUT body whose `UUIDv7` attempt is older than the cell's retired floor has no custody row and
/// can never get one, so no cleanup will ever unlink it: it is a late write after its row was
/// deleted, or a body whose row a database restore lost. The walk cannot tell those apart, so it
/// moves such a body into [`SPOOL_QUARANTINE_DIRECTORY`] and never unlinks it. `retained_unknown`
/// counts entries in the boundary's PUT tree that do not re-derive as a spool path; they are kept.
/// `skipped_entries` counts entries the walk could not stat, open or move this time; it passes
/// them by rather than stalling on them, and a later traversal tries them again.
///
/// The walk relies on one cell per spool root: the boundary token names the provider boundary,
/// not the cell, so two cells sharing a root and a boundary would see each other's bodies, and a
/// body below one cell's floor could belong to the other. Deployment gives each cell its own root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpoolReclaimStep {
    pub completed: bool,
    pub quarantined_files: u64,
    pub quarantined_bytes: u64,
    pub retained_unknown: u64,
    pub skipped_entries: u64,
}

impl fmt::Debug for SpoolWriteReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpoolWriteReceipt")
            .field("opaque_handle", &"[REDACTED]")
            .field("size", &self.size)
            .field("blake3", &"[REDACTED]")
            .finish()
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs::File;
    use std::io::Read as _;
    use std::io::Write as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Component;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::Duration;
    use std::time::Instant;

    use rustix::fd::OwnedFd;
    use rustix::fs::AtFlags;
    use rustix::fs::FileType;
    use rustix::fs::Mode;
    use rustix::fs::OFlags;
    use rustix::fs::ResolveFlags;
    use rustix::io::Errno;

    use super::MAX_SPOOL_BODY_BYTES;
    use super::SPOOL_QUARANTINE_DIRECTORY;
    use super::SpoolInventoryStep;
    use super::SpoolLayout;
    use super::SpoolObjectKey;
    use super::SpoolOsError;
    use super::SpoolPhysicalInventory;
    use super::SpoolReclaimStep;
    use super::SpoolWriteError;
    use super::SpoolWriteReceipt;
    use crate::contract::decode_canonical_uuid_v7;
    use crate::spool::SPOOL_LAYOUT_REVISION_V1;
    use crate::spool::SpoolObjectKind;

    /// How many directory levels above a purged body may be removed once empty:
    /// the per-request directory and its fan-out directory. The layout revision,
    /// boundary and kind directories stay.
    const REMOVABLE_PARENT_LEVELS: usize = 2;
    /// Bounded retries for a placement whose directory a concurrent purge removed.
    const PLACEMENT_ATTEMPTS: usize = 3;
    /// A directory in the placement chain was removed between creation and use.
    /// Only a concurrent purge of the same directory does that, and the next
    /// attempt recreates it.
    const DIRECTORY_REMOVED: SpoolWriteError = SpoolWriteError::Io {
        operation: "placement directory removed",
        os: SpoolOsError {
            kind: std::io::ErrorKind::NotFound,
            raw_os_error: Some(Errno::NOENT.raw_os_error()),
        },
    };

    impl SpoolWriteError {
        fn errno(operation: &'static str, errno: Errno) -> Self {
            Self::Io {
                operation,
                os: SpoolOsError::from_errno(errno),
            }
        }

        fn std_io(operation: &'static str, error: &std::io::Error) -> Self {
            Self::Io {
                operation,
                os: SpoolOsError::from_io(error),
            }
        }
    }

    const ROOT_RESOLVE: ResolveFlags = ResolveFlags::NO_MAGICLINKS
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::BENEATH);
    const ARTIFACT_RESOLVE: ResolveFlags = ROOT_RESOLVE.union(ResolveFlags::NO_XDEV);
    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW);
    const PART_FLAGS: OFlags = OFlags::WRONLY
        .union(OFlags::CREATE)
        .union(OFlags::EXCL)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW);
    /// Owner-only. A spool body is server-private and no peer process reads it
    /// through the filesystem.
    const DIRECTORY_MODE: Mode = Mode::RWXU;
    const FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);

    #[derive(Default)]
    struct PhysicalInventory {
        stack: Vec<(OwnedFd, rustix::fs::Dir)>,
        bytes: u64,
        files: u64,
        completed: Option<SpoolPhysicalInventory>,
    }

    /// The retired-floor walk's position: the boundary's `put` directory, then one fan-out
    /// directory, then one request directory. Each level keeps its name, and a request directory
    /// records whether this walk moved anything out of it.
    #[derive(Default)]
    struct ReclaimCursor {
        stack: Vec<(OwnedFd, rustix::fs::Dir, std::ffi::OsString, bool)>,
    }

    /// Levels of the retired-floor walk: `put`, fan-out, request directory.
    const RECLAIM_LEVELS: usize = 3;

    /// Names one quarantine move may try: the target, then the target with `.1` to `.8`.
    const QUARANTINE_NAME_ATTEMPTS: usize = 9;

    /// What one quarantine move did.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum QuarantineMove {
        Moved,
        /// The entry was gone already: a peer moved it first.
        Gone,
        /// The rename failed or every name was taken. The entry stays in place.
        Skipped,
    }

    /// `renameat2(RENAME_NOREPLACE)`, behind the test fault seam.
    fn rename_noreplace(
        old_directory: &OwnedFd,
        old_name: &std::ffi::OsStr,
        new_directory: &OwnedFd,
        new_name: &std::ffi::OsStr,
        attempt: usize,
    ) -> Result<(), Errno> {
        #[cfg(test)]
        if let Some(errno) = rename_fault::check(attempt) {
            return Err(errno);
        }
        #[cfg(not(test))]
        let _ = attempt;
        rustix::fs::renameat_with(
            old_directory,
            old_name,
            new_directory,
            new_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
    }

    pub struct LinuxSpoolWriter {
        root_path: PathBuf,
        relative_root: PathBuf,
        filesystem_root_fd: OwnedFd,
        root_fd: OwnedFd,
        root_device: u64,
        root_inode: u64,
        maximum_body_bytes: u64,
        physical_inventory: Mutex<PhysicalInventory>,
        reclaim_cursor: Mutex<ReclaimCursor>,
    }

    impl LinuxSpoolWriter {
        /// Advance a bounded inventory, retaining the cursor across observations.
        /// Only a completed, recent inventory is reported. Every descent is
        /// relative to the pinned descriptor; this grants no cleanup authority.
        pub fn physical_usage(
            &self,
            maximum_entries: u32,
        ) -> Result<Option<(u64, u64)>, SpoolWriteError> {
            Ok(self
                .physical_usage_completed(maximum_entries)?
                .map(|inventory| (inventory.bytes, inventory.files)))
        }

        /// `physical_usage`, plus when the reported inventory completed.
        pub fn physical_usage_completed(
            &self,
            maximum_entries: u32,
        ) -> Result<Option<SpoolPhysicalInventory>, SpoolWriteError> {
            let mut inventory = self
                .physical_inventory
                .lock()
                .map_err(|_error| SpoolWriteError::RootUnavailable)?;
            if let Err(error) = self.advance_physical_inventory(&mut inventory, maximum_entries) {
                *inventory = PhysicalInventory::default();
                return Err(error);
            }
            Ok(inventory
                .completed
                .filter(|completed| completed.completed_at.elapsed() <= Duration::from_secs(300)))
        }

        /// Advance the same bounded inventory, reporting whether this step began
        /// a traversal and which traversal it finished. A failed step resets the
        /// inventory, so the next step starts a new traversal.
        pub fn physical_usage_step(
            &self,
            maximum_entries: u32,
        ) -> Result<SpoolInventoryStep, SpoolWriteError> {
            let mut inventory = self
                .physical_inventory
                .lock()
                .map_err(|_error| SpoolWriteError::RootUnavailable)?;
            let started = inventory.stack.is_empty();
            match self.advance_physical_inventory(&mut inventory, maximum_entries) {
                Ok(completed) => Ok(SpoolInventoryStep {
                    started,
                    completed: completed.then_some(inventory.completed).flatten(),
                }),
                Err(error) => {
                    *inventory = PhysicalInventory::default();
                    Err(error)
                }
            }
        }

        /// Returns whether this call completed a traversal.
        fn advance_physical_inventory(
            &self,
            inventory: &mut PhysicalInventory,
            maximum_entries: u32,
        ) -> Result<bool, SpoolWriteError> {
            self.assert_configured_root_stable()?;
            if inventory.stack.is_empty() {
                let root = self
                    .root_fd
                    .try_clone()
                    .map_err(|_error| SpoolWriteError::RootUnavailable)?;
                let entries = rustix::fs::Dir::read_from(&root)
                    .map_err(|_error| SpoolWriteError::RootUnavailable)?;
                inventory.stack.push((root, entries));
                inventory.bytes = 0;
                inventory.files = 0;
            }
            let mut visited = 0_u32;
            while visited < maximum_entries {
                let depth = inventory.stack.len();
                let Some((directory, entries)) = inventory.stack.last_mut() else {
                    break;
                };
                let Some(entry) = entries.next() else {
                    inventory.stack.pop();
                    continue;
                };
                visited += 1;
                let entry = match entry {
                    Ok(entry) => entry,
                    // Purge removes empty directories, and reading a removed
                    // directory is ENOENT. That ends this directory; the root
                    // itself is revalidated below.
                    Err(Errno::NOENT) => {
                        inventory.stack.pop();
                        continue;
                    }
                    Err(_) => return Err(SpoolWriteError::RootUnavailable),
                };
                let name = entry.file_name();
                if name.to_bytes() == b"." || name.to_bytes() == b".." {
                    continue;
                }
                // Quarantined residue is not spool usage; see `SpoolReclaimStep`.
                if depth == 1 && name.to_bytes() == SPOOL_QUARANTINE_DIRECTORY.as_bytes() {
                    continue;
                }
                let stat = match rustix::fs::statat(&*directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(stat) => stat,
                    Err(Errno::NOENT) => continue,
                    Err(_) => return Err(SpoolWriteError::UnsafeOrNonRegular),
                };
                let kind = FileType::from_raw_mode(stat.st_mode);
                if kind.is_dir() {
                    // A directory purged between the stat and the open is absent,
                    // exactly like an entry purged before the stat.
                    let child = match rustix::fs::openat2(
                        &*directory,
                        name,
                        DIRECTORY_FLAGS,
                        Mode::empty(),
                        ARTIFACT_RESOLVE,
                    ) {
                        Ok(child) => child,
                        Err(Errno::NOENT) => continue,
                        Err(_) => return Err(SpoolWriteError::UnsafeOrNonRegular),
                    };
                    let entries = match rustix::fs::Dir::read_from(&child) {
                        Ok(entries) => entries,
                        Err(Errno::NOENT) => continue,
                        Err(_) => return Err(SpoolWriteError::RootUnavailable),
                    };
                    if inventory.stack.len() >= 32 {
                        return Err(SpoolWriteError::UnsafeOrNonRegular);
                    }
                    inventory.stack.push((child, entries));
                } else if kind.is_file() && stat.st_size >= 0 && stat.st_dev == self.root_device {
                    inventory.bytes = inventory
                        .bytes
                        .checked_add(stat.st_size as u64)
                        .ok_or(SpoolWriteError::InvalidBodySize)?;
                    inventory.files = inventory
                        .files
                        .checked_add(1)
                        .ok_or(SpoolWriteError::InvalidBodySize)?;
                } else {
                    return Err(SpoolWriteError::UnsafeOrNonRegular);
                }
            }
            self.assert_configured_root_stable()?;
            if !inventory.stack.is_empty() {
                return Ok(false);
            }
            inventory.completed = Some(SpoolPhysicalInventory {
                completed_at: Instant::now(),
                bytes: inventory.bytes,
                files: inventory.files,
            });
            Ok(true)
        }

        /// Sample the pinned root, refusing mount/root replacement since construction.
        pub fn available_bytes(&self) -> Result<u64, SpoolWriteError> {
            self.assert_configured_root_stable()?;
            let stats = rustix::fs::fstatvfs(&self.root_fd)
                .map_err(|_error| SpoolWriteError::RootUnavailable)?;
            stats
                .f_bavail
                .checked_mul(stats.f_frsize)
                .ok_or(SpoolWriteError::RootUnavailable)
        }
        /// Recover a completed placement after a lost writer response. It can
        /// only mint a receipt after re-reading, comparing and syncing exact bytes.
        pub fn reconcile_put_body(
            &self,
            layout: &SpoolLayout,
            key: &SpoolObjectKey,
            body: &[u8],
        ) -> Result<SpoolWriteReceipt, SpoolWriteError> {
            if body.is_empty() || body.len() as u64 > self.maximum_body_bytes {
                return Err(SpoolWriteError::InvalidBodySize);
            }
            self.assert_configured_root_stable()?;
            let paths = layout
                .derive_paths(key)
                .map_err(|_error| SpoolWriteError::InvalidSpoolKey)?;
            let relative = self.relative_artifact_path(paths.final_path())?;
            let fd = rustix::fs::openat2(
                &self.root_fd,
                &relative,
                DIRECTORY_FLAGS
                    .difference(OFlags::DIRECTORY)
                    .union(OFlags::NONBLOCK),
                Mode::empty(),
                ARTIFACT_RESOLVE,
            )
            .map_err(|_error| SpoolWriteError::UnsafeOrNonRegular)?;
            let stat =
                rustix::fs::fstat(&fd).map_err(|_error| SpoolWriteError::UnsafeOrNonRegular)?;
            if !FileType::from_raw_mode(stat.st_mode).is_file() || stat.st_size != body.len() as i64
            {
                return Err(SpoolWriteError::UnsafeOrNonRegular);
            }
            let mut file = File::from(fd);
            let mut found = Vec::with_capacity(body.len());
            (&mut file)
                .take(self.maximum_body_bytes + 1)
                .read_to_end(&mut found)
                .map_err(|error| SpoolWriteError::std_io("reconcile read", &error))?;
            if found != body {
                return Err(SpoolWriteError::InvalidBodySize);
            }
            file.sync_all()
                .map_err(|error| SpoolWriteError::std_io("reconcile fsync", &error))?;
            let parent = relative
                .parent()
                .ok_or(SpoolWriteError::PathBindingMismatch)?;
            let directory = self.ensure_directory_chain(parent)?;
            rustix::fs::fsync(&directory)
                .map_err(|errno| SpoolWriteError::errno("reconcile directory fsync", errno))?;
            self.assert_configured_root_stable()?;
            Ok(SpoolWriteReceipt {
                opaque_handle: paths.opaque_handle().to_owned(),
                size: body.len() as u64,
                blake3: *blake3::hash(body).as_bytes(),
            })
        }

        /// Remove only a database-authorized PUT identity. The pinned root and
        /// descriptor-relative parent open make missing files distinct from a lost root.
        pub(crate) fn purge_put_body(
            &self,
            layout: &SpoolLayout,
            key: &SpoolObjectKey,
        ) -> Result<bool, SpoolWriteError> {
            self.assert_configured_root_stable()?;
            let paths = layout
                .derive_paths(key)
                .map_err(|_error| SpoolWriteError::InvalidSpoolKey)?;
            let relative = self.relative_artifact_path(paths.final_path())?;
            let parent = relative
                .parent()
                .ok_or(SpoolWriteError::PathBindingMismatch)?;
            let mut directory = self
                .root_fd
                .try_clone()
                .map_err(|_error| SpoolWriteError::RootUnavailable)?;
            // Each opened level with the descriptor of the directory holding it.
            let mut chain = Vec::new();
            for component in parent.components() {
                let Component::Normal(name) = component else {
                    return Err(SpoolWriteError::PathBindingMismatch);
                };
                match rustix::fs::openat2(
                    &directory,
                    name,
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                    ARTIFACT_RESOLVE,
                ) {
                    Ok(fd) => chain.push((std::mem::replace(&mut directory, fd), name)),
                    Err(Errno::NOENT) => {
                        // Absence is durable only after the nearest surviving
                        // parent is synced, including a peer's uncommitted unlink.
                        rustix::fs::fsync(&directory).map_err(|errno| {
                            SpoolWriteError::errno("purge missing directory fsync", errno)
                        })?;
                        self.assert_configured_root_stable()?;
                        return Ok(false);
                    }
                    Err(_) => return Err(SpoolWriteError::UnsafeOrNonRegular),
                }
            }
            let mut removed = false;
            for path in [paths.part_path(), paths.final_path()] {
                let name = path
                    .file_name()
                    .ok_or(SpoolWriteError::PathBindingMismatch)?;
                match rustix::fs::unlinkat(&directory, name, rustix::fs::AtFlags::empty()) {
                    Ok(()) => removed = true,
                    Err(Errno::NOENT) => {}
                    Err(errno) => return Err(SpoolWriteError::errno("purge unlink", errno)),
                }
            }
            rustix::fs::fsync(&directory)
                .map_err(|errno| SpoolWriteError::errno("purge directory fsync", errno))?;
            remove_empty_parents(&chain);
            self.assert_configured_root_stable()?;
            Ok(removed)
        }

        /// Advance the retired-floor walk over this boundary's PUT tree by at most
        /// `maximum_entries` entries, keeping its cursor across calls, and move every body whose
        /// attempt is older than `floor_ms` into [`SPOOL_QUARANTINE_DIRECTORY`].
        ///
        /// `floor_ms` must be a value the cell database returned as its retired floor (migration
        /// 0032). No custody row is older than that floor and no first-seen reservation below it
        /// is accepted, so a body below it has no row and never will; that is this call's whole
        /// authority. Only a file whose path re-derives exactly from its directory names is
        /// moved, and only by `RENAME_NOREPLACE`, so nothing is unlinked or overwritten. A body a
        /// peer moved first is skipped.
        ///
        /// # Errors
        ///
        /// [`SpoolWriteError::PathBindingMismatch`] for a layout over another root,
        /// [`SpoolWriteError::InvalidSpoolKey`] for an invalid boundary, and any I/O failure. A
        /// failed step resets the walk.
        pub fn reclaim_step(
            &self,
            layout: &SpoolLayout,
            provider_boundary_id: &str,
            floor_ms: i64,
            maximum_entries: u32,
        ) -> Result<SpoolReclaimStep, SpoolWriteError> {
            if layout.shared_spool_root() != self.root_path {
                return Err(SpoolWriteError::PathBindingMismatch);
            }
            let binding = layout
                .derive_boundary_binding(provider_boundary_id)
                .map_err(|_error| SpoolWriteError::InvalidSpoolKey)?;
            // A panic while a step held the cursor leaves it at an unknown point. Start the
            // traversal over rather than refuse every later step.
            let mut cursor = self.reclaim_cursor.lock().unwrap_or_else(|poisoned| {
                let mut cursor = poisoned.into_inner();
                *cursor = ReclaimCursor::default();
                self.reclaim_cursor.clear_poison();
                cursor
            });
            let mut step = SpoolReclaimStep::default();
            match self.advance_reclaim(
                &mut cursor,
                layout,
                binding.provider_boundary_id(),
                binding.boundary_token(),
                floor_ms,
                maximum_entries,
                &mut step,
            ) {
                Ok(completed) => {
                    step.completed = completed;
                    Ok(step)
                }
                Err(error) => {
                    *cursor = ReclaimCursor::default();
                    Err(error)
                }
            }
        }

        /// Returns whether this call completed a traversal.
        #[allow(clippy::too_many_arguments)]
        fn advance_reclaim(
            &self,
            cursor: &mut ReclaimCursor,
            layout: &SpoolLayout,
            provider_boundary_id: &str,
            boundary_token: &str,
            floor_ms: i64,
            maximum_entries: u32,
            step: &mut SpoolReclaimStep,
        ) -> Result<bool, SpoolWriteError> {
            self.assert_configured_root_stable()?;
            if cursor.stack.is_empty() {
                let mut directory = self
                    .root_fd
                    .try_clone()
                    .map_err(|_error| SpoolWriteError::RootUnavailable)?;
                for name in [SPOOL_LAYOUT_REVISION_V1, boundary_token, "put"] {
                    directory = match rustix::fs::openat2(
                        &directory,
                        name,
                        DIRECTORY_FLAGS,
                        Mode::empty(),
                        ARTIFACT_RESOLVE,
                    ) {
                        Ok(fd) => fd,
                        // Nothing was ever placed for this boundary.
                        Err(Errno::NOENT) => return Ok(true),
                        Err(_) => return Err(SpoolWriteError::UnsafeOrNonRegular),
                    };
                }
                let entries = rustix::fs::Dir::read_from(&directory)
                    .map_err(|_error| SpoolWriteError::RootUnavailable)?;
                cursor
                    .stack
                    .push((directory, entries, std::ffi::OsString::from("put"), false));
            }
            let mut visited = 0_u32;
            while visited < maximum_entries {
                let depth = cursor.stack.len();
                let Some((directory, entries, _, _)) = cursor.stack.last_mut() else {
                    break;
                };
                let Some(entry) = entries.next() else {
                    if let Some((_, _, name, true)) = cursor.stack.pop() {
                        // Best effort, like `remove_empty_parents`: a request directory this
                        // walk emptied is only a cost.
                        if let Some((parent, _, _, _)) = cursor.stack.last() {
                            let _ =
                                rustix::fs::unlinkat(parent, name.as_os_str(), AtFlags::REMOVEDIR);
                        }
                    }
                    continue;
                };
                visited += 1;
                #[cfg(test)]
                let entry = match reclaim_read_fault::check(depth) {
                    Some(errno) => Err(errno),
                    None => entry,
                };
                let entry = match entry {
                    Ok(entry) => entry,
                    // A purge removed this directory; that ends it.
                    Err(Errno::NOENT) => {
                        cursor.stack.pop();
                        continue;
                    }
                    // An unreadable `put` directory is the whole tree: fail the step rather
                    // than report a traversal that never ran.
                    Err(_) if depth == 1 => return Err(SpoolWriteError::RootUnavailable),
                    // An unreadable fan-out or request directory: pass the rest of it by rather
                    // than fail on it on every traversal.
                    Err(_) => {
                        cursor.stack.pop();
                        step.skipped_entries += 1;
                        continue;
                    }
                };
                let name = entry.file_name();
                if name.to_bytes() == b"." || name.to_bytes() == b".." {
                    continue;
                }
                let name = std::ffi::OsStr::from_bytes(name.to_bytes()).to_os_string();
                let stat = match rustix::fs::statat(&*directory, &name, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(stat) => stat,
                    Err(Errno::NOENT) => continue,
                    Err(_) => {
                        step.skipped_entries += 1;
                        continue;
                    }
                };
                let kind = FileType::from_raw_mode(stat.st_mode);
                if depth < RECLAIM_LEVELS {
                    if !kind.is_dir() {
                        step.retained_unknown += 1;
                        continue;
                    }
                    let child = match rustix::fs::openat2(
                        &*directory,
                        &name,
                        DIRECTORY_FLAGS,
                        Mode::empty(),
                        ARTIFACT_RESOLVE,
                    ) {
                        Ok(child) => child,
                        Err(Errno::NOENT) => continue,
                        Err(_) => {
                            step.skipped_entries += 1;
                            continue;
                        }
                    };
                    let entries = match rustix::fs::Dir::read_from(&child) {
                        Ok(entries) => entries,
                        Err(Errno::NOENT) => continue,
                        Err(_) => {
                            step.skipped_entries += 1;
                            continue;
                        }
                    };
                    cursor.stack.push((child, entries, name, false));
                    continue;
                }
                let (Some(fanout), Some(logical)) = (
                    cursor.stack.get(1).map(|level| level.2.clone()),
                    cursor.stack.get(2).map(|level| level.2.clone()),
                ) else {
                    return Err(SpoolWriteError::PathBindingMismatch);
                };
                if !kind.is_file() || stat.st_dev != self.root_device {
                    step.retained_unknown += 1;
                    continue;
                }
                let Some(attempt_ms) = self.retired_attempt_ms(
                    layout,
                    provider_boundary_id,
                    boundary_token,
                    &fanout,
                    &logical,
                    &name,
                ) else {
                    step.retained_unknown += 1;
                    continue;
                };
                match i64::try_from(attempt_ms) {
                    Ok(attempt_ms) if attempt_ms < floor_ms => {}
                    _ => continue,
                }
                let mut target = logical.clone();
                target.push(".");
                target.push(&name);
                let Some((directory, _, _, moved)) = cursor.stack.last_mut() else {
                    return Err(SpoolWriteError::PathBindingMismatch);
                };
                match self.quarantine_entry(directory, &name, &target)? {
                    QuarantineMove::Moved => {
                        *moved = true;
                        step.quarantined_files += 1;
                        step.quarantined_bytes += u64::try_from(stat.st_size).unwrap_or(0);
                    }
                    QuarantineMove::Gone => {}
                    QuarantineMove::Skipped => step.skipped_entries += 1,
                }
            }
            self.assert_configured_root_stable()?;
            Ok(cursor.stack.is_empty())
        }

        /// The attempt time of a file in a request directory, when its whole path re-derives
        /// exactly as this boundary's PUT `.blob` or `.part` for that request and attempt.
        fn retired_attempt_ms(
            &self,
            layout: &SpoolLayout,
            provider_boundary_id: &str,
            boundary_token: &str,
            fanout: &std::ffi::OsStr,
            logical: &std::ffi::OsStr,
            name: &std::ffi::OsStr,
        ) -> Option<u64> {
            let file = name.to_str()?;
            let (attempt, part) = match (file.strip_suffix(".blob"), file.strip_suffix(".part")) {
                (Some(attempt), None) => (attempt, false),
                (None, Some(attempt)) => (attempt, true),
                _ => return None,
            };
            let key = SpoolObjectKey {
                provider_boundary_id: provider_boundary_id.to_owned(),
                logical_request_id: logical.to_str()?.to_owned(),
                attempt_id: attempt.to_owned(),
                kind: SpoolObjectKind::Put,
            };
            let paths = layout.derive_paths(&key).ok()?;
            let actual = self
                .root_path
                .join(SPOOL_LAYOUT_REVISION_V1)
                .join(boundary_token)
                .join("put")
                .join(fanout)
                .join(logical)
                .join(name);
            let derived = if part {
                paths.part_path()
            } else {
                paths.final_path()
            };
            if derived != actual {
                return None;
            }
            let bytes = decode_canonical_uuid_v7(attempt).ok()?;
            let mut ms = [0_u8; 8];
            ms[2..].copy_from_slice(&bytes[..6]);
            Some(u64::from_be_bytes(ms))
        }

        /// Create, open and sync the quarantine directory under the pinned root.
        fn quarantine_directory(&self) -> Result<OwnedFd, SpoolWriteError> {
            match rustix::fs::mkdirat(&self.root_fd, SPOOL_QUARANTINE_DIRECTORY, DIRECTORY_MODE) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(errno) => return Err(SpoolWriteError::errno("quarantine create", errno)),
            }
            let quarantine = rustix::fs::openat2(
                &self.root_fd,
                SPOOL_QUARANTINE_DIRECTORY,
                DIRECTORY_FLAGS,
                Mode::empty(),
                ARTIFACT_RESOLVE,
            )
            .map_err(|errno| SpoolWriteError::errno("quarantine open", errno))?;
            rustix::fs::fsync(&self.root_fd)
                .map_err(|errno| SpoolWriteError::errno("quarantine parent fsync", errno))?;
            Ok(quarantine)
        }

        /// Move one entry of `directory` into the quarantine directory as `target`, or as
        /// `target.1` to `target.8` when earlier moves of the same identity hold those names.
        /// Nothing already in quarantine is replaced. A rename the filesystem refuses, or a tenth
        /// name collision, leaves the entry in place as [`QuarantineMove::Skipped`].
        fn quarantine_entry(
            &self,
            directory: &OwnedFd,
            name: &std::ffi::OsStr,
            target: &std::ffi::OsStr,
        ) -> Result<QuarantineMove, SpoolWriteError> {
            let quarantine = self.quarantine_directory()?;
            for attempt in 0..QUARANTINE_NAME_ATTEMPTS {
                let mut candidate = target.to_os_string();
                if attempt > 0 {
                    candidate.push(format!(".{attempt}"));
                }
                match rename_noreplace(directory, name, &quarantine, &candidate, attempt) {
                    Ok(()) => {
                        // The move has happened whether or not it is durable yet, so it is
                        // reported as a move. A failed sync is logged, not turned into an
                        // error that would hide the move; a crash may still undo it, and a
                        // later traversal then finds the body again.
                        for (directory, which) in [
                            (&quarantine, "quarantine"),
                            (directory, "quarantine source"),
                        ] {
                            #[cfg(test)]
                            let synced = match fsync_fault::check(which) {
                                Some(errno) => Err(errno),
                                None => rustix::fs::fsync(directory),
                            };
                            #[cfg(not(test))]
                            let synced = rustix::fs::fsync(directory);
                            if let Err(errno) = synced {
                                tracing::warn!(
                                    "drain spool quarantine moved a body but its {which} directory \
                                     fsync failed: {}",
                                    SpoolOsError::from_errno(errno)
                                );
                            }
                        }
                        return Ok(QuarantineMove::Moved);
                    }
                    // A peer moved it first.
                    Err(Errno::NOENT) => return Ok(QuarantineMove::Gone),
                    // The same identity was quarantined before: keep both.
                    Err(Errno::EXIST) => {}
                    Err(_) => return Ok(QuarantineMove::Skipped),
                }
            }
            Ok(QuarantineMove::Skipped)
        }

        /// Prove once, before the retired-floor walk can need it, that the spool filesystem
        /// supports `RENAME_NOREPLACE`, by renaming a probe file inside the quarantine directory.
        /// NFS and some FUSE filesystems refuse it, and the walk would then skip every body it
        /// should quarantine, forever.
        ///
        /// # Errors
        ///
        /// [`SpoolWriteError::RenameNoReplaceUnsupported`] for `EINVAL`, `ENOSYS` or `EXDEV`; any
        /// other failure as an I/O error.
        pub fn probe_quarantine_rename(&self) -> Result<(), SpoolWriteError> {
            self.assert_configured_root_stable()?;
            let quarantine = self.quarantine_directory()?;
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let probe = format!(".rename-probe-{}-{nonce}", std::process::id());
            let renamed = format!("{probe}.renamed");
            rustix::fs::openat2(&quarantine, &probe, PART_FLAGS, FILE_MODE, ARTIFACT_RESOLVE)
                .map_err(|errno| SpoolWriteError::errno("quarantine probe create", errno))?;
            #[cfg(feature = "test_seams")]
            let injected = probe_fault::check(&self.root_path);
            #[cfg(not(feature = "test_seams"))]
            let injected: Option<Errno> = None;
            let result = match injected {
                Some(errno) => Err(errno),
                None => rename_noreplace(
                    &quarantine,
                    std::ffi::OsStr::new(&probe),
                    &quarantine,
                    std::ffi::OsStr::new(&renamed),
                    0,
                ),
            };
            let left = if result.is_ok() { &renamed } else { &probe };
            let _ = rustix::fs::unlinkat(&quarantine, left.as_str(), AtFlags::empty());
            match result {
                Ok(()) => Ok(()),
                Err(Errno::INVAL | Errno::NOSYS | Errno::XDEV) => {
                    Err(SpoolWriteError::RenameNoReplaceUnsupported)
                }
                Err(errno) => Err(SpoolWriteError::errno("quarantine probe rename", errno)),
            }
        }

        /// Test seam: a reclaim cursor whose mutex a panic poisoned.
        #[cfg(test)]
        pub(crate) fn poison_reclaim_cursor_for_test(&self) {
            let _guard = self.reclaim_cursor.lock();
            panic!("poisoning the reclaim cursor for a test");
        }
        /// Open and pin the configured spool root.
        ///
        /// Mirrors `LinuxSpoolVerifier::open`: the same `openat2` resolution, the
        /// same retained filesystem-root descriptor, and the same recorded
        /// `(st_dev, st_ino)` that later calls revalidate against. It does not
        /// create the root — a root the operator has not provisioned is a
        /// configuration refusal, not something a writer invents.
        ///
        /// # Errors
        ///
        /// [`SpoolWriteError::InvalidBodySize`] for a zero or out-of-range
        /// bound, [`SpoolWriteError::InvalidRoot`] for a root that is not an
        /// absolute path of normal components, and
        /// [`SpoolWriteError::RootUnavailable`] when it cannot be opened.
        ///
        /// **The `is_dir` check below is defence in depth, not a reachable
        /// arm**, and the pins measured that rather than assuming it. `O_DIRECTORY`
        /// makes the kernel fail the `openat2` itself — `ENOENT` for an absent
        /// root, `ENOTDIR` for a regular file — so both arrive as
        /// `RootUnavailable` and this check never sees a non-directory. It is
        /// kept because `LinuxSpoolVerifier::open` keeps the identical one, and
        /// a reader comparing the two should not have to work out why they
        /// differ.
        pub fn open(
            layout: &SpoolLayout,
            maximum_body_bytes: u64,
        ) -> Result<Self, SpoolWriteError> {
            if maximum_body_bytes == 0 || maximum_body_bytes > MAX_SPOOL_BODY_BYTES {
                return Err(SpoolWriteError::InvalidBodySize);
            }
            let root_path = layout.shared_spool_root();
            let relative_root = root_path
                .strip_prefix(Path::new("/"))
                .map_err(|_err| SpoolWriteError::InvalidRoot)?;
            if relative_root.as_os_str().is_empty()
                || relative_root
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(SpoolWriteError::InvalidRoot);
            }
            let filesystem_root = rustix::fs::open("/", DIRECTORY_FLAGS, Mode::empty())
                .map_err(|_err| SpoolWriteError::RootUnavailable)?;
            let root_fd = rustix::fs::openat2(
                &filesystem_root,
                relative_root,
                DIRECTORY_FLAGS,
                Mode::empty(),
                ROOT_RESOLVE,
            )
            .map_err(|_err| SpoolWriteError::RootUnavailable)?;
            let root_stat =
                rustix::fs::fstat(&root_fd).map_err(|_err| SpoolWriteError::RootUnavailable)?;
            if !FileType::from_raw_mode(root_stat.st_mode).is_dir() {
                return Err(SpoolWriteError::InvalidRoot);
            }
            Ok(Self {
                root_path: root_path.to_path_buf(),
                relative_root: relative_root.to_path_buf(),
                filesystem_root_fd: filesystem_root,
                root_fd,
                root_device: root_stat.st_dev,
                root_inode: root_stat.st_ino,
                maximum_body_bytes,
                physical_inventory: Mutex::new(PhysicalInventory::default()),
                reclaim_cursor: Mutex::new(ReclaimCursor::default()),
            })
        }

        /// Durably place one PUT body and report what was written.
        ///
        /// The returned handle equals
        /// `layout.derive_paths(key)?.opaque_handle()`, which is the equality
        /// `bind_durable_put_body_from_ready` requires.
        ///
        /// # Errors
        ///
        /// Refuses before touching the filesystem for a non-PUT kind, an empty
        /// or oversized body, and an invalid key. Refuses
        /// [`SpoolWriteError::BodyAlreadyPresent`] rather than overwriting:
        /// `(logical_request_id, attempt_id)` names one attempt's body, an
        /// attempt identity is used once, and a second write under the same name
        /// would replace bytes another call may already have reported ready.
        pub fn write_put_body(
            &self,
            layout: &SpoolLayout,
            key: &SpoolObjectKey,
            body: &[u8],
        ) -> Result<SpoolWriteReceipt, SpoolWriteError> {
            if key.kind != SpoolObjectKind::Put {
                return Err(SpoolWriteError::InvalidSpoolKind);
            }
            let size =
                u64::try_from(body.len()).map_err(|_err| SpoolWriteError::InvalidBodySize)?;
            if size == 0 || size > self.maximum_body_bytes {
                return Err(SpoolWriteError::InvalidBodySize);
            }
            let paths = layout
                .derive_paths(key)
                .map_err(|_err| SpoolWriteError::InvalidSpoolKey)?;
            let blob_relative = self.relative_artifact_path(paths.final_path())?;
            let part_relative = self.relative_artifact_path(paths.part_path())?;
            let (Some(blob_name), Some(part_name)) =
                (blob_relative.file_name(), part_relative.file_name())
            else {
                return Err(SpoolWriteError::PathBindingMismatch);
            };

            self.assert_configured_root_stable()?;

            // Step 1. Every level below the root, each one made durable in its
            // parent before the walk descends into it.
            let Some(directory_relative) = blob_relative.parent() else {
                return Err(SpoolWriteError::PathBindingMismatch);
            };
            // Steps 2 to 5 act on the leaf descriptor step 1 synced, never on a
            // path. A purge may empty-remove that leaf before the part create,
            // and another writer may recreate a directory at the same path
            // without having synced it yet. Creating in the removed leaf is then
            // ENOENT, so this attempt redoes step 1 instead of placing the body
            // somewhere whose entry is not durable.
            let mut attempt = 1;
            let outcome = loop {
                let directory_fd = match self.ensure_directory_chain(directory_relative) {
                    Err(DIRECTORY_REMOVED) if attempt < PLACEMENT_ATTEMPTS => {
                        attempt += 1;
                        continue;
                    }
                    result => result?,
                };
                #[cfg(test)]
                before_place::run();
                let outcome = Self::place_body(part_name, blob_name, &directory_fd, body);
                if outcome == Err(DIRECTORY_REMOVED) && attempt < PLACEMENT_ATTEMPTS {
                    attempt += 1;
                    continue;
                }
                if outcome.is_err() {
                    // Best effort, and exactly `finalize_blocking`'s reasoning:
                    // the rename either happened or it did not. If it did this
                    // removes nothing; if it did not this removes the part file
                    // that would otherwise wait for recovery.
                    let _ = rustix::fs::unlinkat(&directory_fd, part_name, AtFlags::empty());
                }
                break outcome;
            };
            outcome?;

            self.assert_configured_root_stable()?;
            Ok(SpoolWriteReceipt {
                opaque_handle: paths.opaque_handle().to_string(),
                size,
                blake3: *blake3::hash(body).as_bytes(),
            })
        }

        /// Steps 2 through 5, each relative to the leaf descriptor step 1 synced.
        fn place_body(
            part_name: &std::ffi::OsStr,
            blob_name: &std::ffi::OsStr,
            directory_fd: &OwnedFd,
            body: &[u8],
        ) -> Result<(), SpoolWriteError> {
            // Refuse an existing final body before creating anything. This is
            // the check that makes `O_EXCL` on the part file a diagnosis rather
            // than the only guard: a crash between rename and the ready call
            // leaves a `.blob` and no `.part`, and silently rewriting it is the
            // one outcome that could change bytes another party already trusts.
            match rustix::fs::openat2(
                directory_fd,
                blob_name,
                DIRECTORY_FLAGS.difference(OFlags::DIRECTORY),
                Mode::empty(),
                ARTIFACT_RESOLVE,
            ) {
                Ok(_) => return Err(SpoolWriteError::BodyAlreadyPresent),
                Err(Errno::NOENT) => {}
                Err(Errno::LOOP | Errno::XDEV | Errno::NOTDIR) => {
                    return Err(SpoolWriteError::UnsafeOrNonRegular);
                }
                Err(errno) => return Err(SpoolWriteError::errno("blob probe", errno)),
            }

            // Step 2. `O_EXCL`: an attempt identity is used once, so an existing
            // part file is a concurrent or abandoned writer, never something to
            // truncate.
            let part_fd = match rustix::fs::openat2(
                directory_fd,
                part_name,
                PART_FLAGS,
                FILE_MODE,
                ARTIFACT_RESOLVE,
            ) {
                Ok(fd) => fd,
                Err(Errno::EXIST) => return Err(SpoolWriteError::PartAlreadyPresent),
                // One component under a live descriptor: ENOENT means the leaf
                // step 1 synced has been removed.
                Err(Errno::NOENT) => return Err(DIRECTORY_REMOVED),
                Err(Errno::LOOP | Errno::XDEV | Errno::NOTDIR) => {
                    return Err(SpoolWriteError::UnsafeOrNonRegular);
                }
                Err(errno) => return Err(SpoolWriteError::errno("part create", errno)),
            };
            let mut part = File::from(part_fd);
            part.write_all(body)
                .map_err(|error| SpoolWriteError::std_io("part write", &error))?;
            // Step 3. Contents and metadata, because the rename publishes both.
            part.sync_all()
                .map_err(|error| SpoolWriteError::std_io("part fsync", &error))?;
            drop(part);

            // Step 4. Both sides are one component in the leaf descriptor, so
            // the rename cannot leave it and is atomic within the one filesystem
            // `NO_XDEV` has already held every open to. The leaf holds the part
            // file now, so no purge can remove it.
            rustix::fs::renameat(directory_fd, part_name, directory_fd, blob_name)
                .map_err(|errno| SpoolWriteError::errno("part rename", errno))?;

            // Step 5.
            rustix::fs::fsync(directory_fd)
                .map_err(|errno| SpoolWriteError::errno("leaf directory fsync", errno))
        }

        /// Create every level of `relative` below the root, fsyncing each
        /// parent before descending, and return the leaf directory descriptor.
        ///
        /// Each level is opened before its parent is synced. Purge removes
        /// empty directories, so the entry at a name can be removed and
        /// recreated by another writer. Opening first means the sync covers the
        /// directory this writer holds: if that one is removed later, creating
        /// in it is ENOENT and the caller starts over.
        fn ensure_directory_chain(&self, relative: &Path) -> Result<OwnedFd, SpoolWriteError> {
            let mut parent = self
                .root_fd
                .try_clone()
                .map_err(|error| SpoolWriteError::std_io("root descriptor clone", &error))?;
            for component in relative.components() {
                let Component::Normal(name) = component else {
                    return Err(SpoolWriteError::PathBindingMismatch);
                };
                match rustix::fs::mkdirat(&parent, name, DIRECTORY_MODE) {
                    // Not durability evidence. A peer may have created this
                    // entry without syncing, which is why the fsync below is
                    // unconditional rather than inside the `Ok` arm.
                    Ok(()) | Err(Errno::EXIST) => {}
                    // The parent opened on the previous level has been purged.
                    Err(Errno::NOENT) => return Err(DIRECTORY_REMOVED),
                    Err(errno) => return Err(SpoolWriteError::errno("fanout create", errno)),
                }
                let child = match rustix::fs::openat2(
                    &parent,
                    name,
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                    ARTIFACT_RESOLVE,
                ) {
                    Ok(fd) => fd,
                    Err(Errno::LOOP | Errno::XDEV | Errno::NOTDIR) => {
                        return Err(SpoolWriteError::UnsafeOrNonRegular);
                    }
                    // Created or found by the mkdirat above, then purged.
                    Err(Errno::NOENT) => return Err(DIRECTORY_REMOVED),
                    Err(errno) => return Err(SpoolWriteError::errno("fanout open", errno)),
                };
                rustix::fs::fsync(&parent)
                    .map_err(|errno| SpoolWriteError::errno("fanout parent fsync", errno))?;
                let stat = rustix::fs::fstat(&child)
                    .map_err(|errno| SpoolWriteError::errno("fanout stat", errno))?;
                if stat.st_dev != self.root_device {
                    return Err(SpoolWriteError::UnsafeOrNonRegular);
                }
                parent = child;
            }
            Ok(parent)
        }

        fn relative_artifact_path(&self, artifact_path: &Path) -> Result<PathBuf, SpoolWriteError> {
            let relative = artifact_path
                .strip_prefix(&self.root_path)
                .map_err(|_err| SpoolWriteError::PathBindingMismatch)?;
            if relative.as_os_str().is_empty()
                || relative
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(SpoolWriteError::PathBindingMismatch);
            }
            Ok(relative.to_path_buf())
        }

        fn assert_configured_root_stable(&self) -> Result<(), SpoolWriteError> {
            let reopened = rustix::fs::openat2(
                &self.filesystem_root_fd,
                &self.relative_root,
                DIRECTORY_FLAGS,
                Mode::empty(),
                ROOT_RESOLVE,
            )
            .map_err(|_err| SpoolWriteError::RootChanged)?;
            let current =
                rustix::fs::fstat(&reopened).map_err(|_err| SpoolWriteError::RootChanged)?;
            if current.st_dev != self.root_device || current.st_ino != self.root_inode {
                return Err(SpoolWriteError::RootChanged);
            }
            Ok(())
        }
    }

    /// Remove the purged body's per-request and fan-out directories if they are
    /// now empty, deepest first.
    ///
    /// Without this every reservation leaves two directories behind forever,
    /// and the physical walk, which readiness compares with the ledger, grows
    /// with every reservation the cell ever took (INV-FT F2).
    ///
    /// `unlinkat(AT_REMOVEDIR)` removes only an empty directory, so a body a
    /// concurrent writer has already created keeps its directory: that is
    /// `ENOTEMPTY`, and the walk stops. A peer that already removed the directory
    /// is `ENOENT`, and the walk stops. Any other error also stops the walk
    /// without failing the purge, because the body's removal is already durable
    /// and an empty directory is only a cost. Each removal is relative to a
    /// descriptor opened under the pinned root with `openat2`'s confinement, and
    /// names one normal component, so nothing outside the spool root is reachable.
    /// A writer that loses its freshly created directory to this retries the
    /// placement; see `write_put_body`.
    ///
    /// The removal is not fsynced. A crash can bring back an empty directory,
    /// which a later purge in it removes again.
    fn remove_empty_parents(chain: &[(OwnedFd, &std::ffi::OsStr)]) {
        // The derived layout always has fixed levels above the removable ones.
        if chain.len() <= REMOVABLE_PARENT_LEVELS {
            return;
        }
        for (parent, name) in chain.iter().rev().take(REMOVABLE_PARENT_LEVELS) {
            if rustix::fs::unlinkat(parent, *name, AtFlags::REMOVEDIR).is_err() {
                return;
            }
        }
    }

    impl std::fmt::Debug for LinuxSpoolWriter {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("LinuxSpoolWriter")
                .field("root_path", &"[REDACTED]")
                .field("root_fd", &"[REDACTED]")
                .field("filesystem_root_fd", &"[REDACTED]")
                .field("root_device", &"[REDACTED]")
                .field("root_inode", &"[REDACTED]")
                .field("maximum_body_bytes", &self.maximum_body_bytes)
                .finish()
        }
    }

    pub use LinuxSpoolWriter as ExportedLinuxSpoolWriter;

    /// Test seam: runs once per placement attempt, after step 1 and before the
    /// part create, which is the window a concurrent purge can empty-remove the
    /// directory in. Thread-local, so parallel tests cannot see each other's hook.
    #[cfg(test)]
    pub(super) mod before_place {
        use std::cell::RefCell;

        type Hook = Box<dyn FnMut()>;
        thread_local! {
            static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
        }

        pub(crate) fn run() {
            HOOK.with_borrow_mut(|hook| {
                if let Some(hook) = hook {
                    hook();
                }
            });
        }

        pub(crate) fn install(hook: impl FnMut() + 'static) {
            HOOK.with_borrow_mut(|slot| *slot = Some(Box::new(hook)));
        }

        pub(crate) fn clear() {
            HOOK.with_borrow_mut(|slot| *slot = None);
        }
    }

    /// Test seam for another crate's boot path (`test_seams` feature): make
    /// [`LinuxSpoolWriter::probe_quarantine_rename`] see `raw_errno` for writers over exactly
    /// `root`. Keyed by root, not thread-local, because the probe runs on a blocking thread, and
    /// so that tests over other roots running at the same time are unaffected.
    #[cfg(feature = "test_seams")]
    pub mod probe_fault {
        use std::path::Path;
        use std::path::PathBuf;
        use std::sync::Mutex;

        use rustix::io::Errno;

        static FAULTS: Mutex<Vec<(PathBuf, i32)>> = Mutex::new(Vec::new());

        pub fn fail_probe_under(root: &Path, raw_errno: i32) {
            let mut faults = FAULTS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            faults.retain(|(path, _)| path != root);
            faults.push((root.to_path_buf(), raw_errno));
        }

        pub fn clear(root: &Path) {
            FAULTS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|(path, _)| path != root);
        }

        pub(super) fn check(root: &Path) -> Option<Errno> {
            FAULTS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .find(|(path, _)| path == root)
                .map(|(_, raw)| Errno::from_raw_os_error(*raw))
        }
    }

    /// Test seam: makes a directory fsync after a successful quarantine rename fail. `which` is
    /// `"quarantine"` or `"quarantine source"`. Thread-local, like `before_place`.
    #[cfg(test)]
    pub(super) mod fsync_fault {
        use std::cell::RefCell;

        use rustix::io::Errno;

        type Hook = Box<dyn FnMut(&str) -> Option<Errno>>;
        thread_local! {
            static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
        }

        pub(crate) fn check(which: &str) -> Option<Errno> {
            HOOK.with_borrow_mut(|hook| hook.as_mut().and_then(|hook| hook(which)))
        }

        pub(crate) fn install(hook: impl FnMut(&str) -> Option<Errno> + 'static) {
            HOOK.with_borrow_mut(|slot| *slot = Some(Box::new(hook)));
        }

        pub(crate) fn clear() {
            HOOK.with_borrow_mut(|slot| *slot = None);
        }
    }

    /// Test seam: makes the reclaim walk's next directory read at `depth` (1 is the boundary's
    /// `put` directory) fail with the returned errno. Thread-local, like `before_place`.
    #[cfg(test)]
    pub(super) mod reclaim_read_fault {
        use std::cell::RefCell;

        use rustix::io::Errno;

        type Hook = Box<dyn FnMut(usize) -> Option<Errno>>;
        thread_local! {
            static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
        }

        pub(crate) fn check(depth: usize) -> Option<Errno> {
            HOOK.with_borrow_mut(|hook| hook.as_mut().and_then(|hook| hook(depth)))
        }

        pub(crate) fn install(hook: impl FnMut(usize) -> Option<Errno> + 'static) {
            HOOK.with_borrow_mut(|slot| *slot = Some(Box::new(hook)));
        }

        pub(crate) fn clear() {
            HOOK.with_borrow_mut(|slot| *slot = None);
        }
    }

    /// Test seam: decides the result of each `RENAME_NOREPLACE` call, in the probe and in
    /// quarantine moves. `attempt` is the name index within one move (0 for the first name).
    /// Returning `Some(errno)` fails that call. Thread-local, like `before_place`.
    #[cfg(test)]
    pub(super) mod rename_fault {
        use std::cell::RefCell;

        use rustix::io::Errno;

        type Hook = Box<dyn FnMut(usize) -> Option<Errno>>;
        thread_local! {
            static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
        }

        pub(crate) fn check(attempt: usize) -> Option<Errno> {
            HOOK.with_borrow_mut(|hook| hook.as_mut().and_then(|hook| hook(attempt)))
        }

        pub(crate) fn install(hook: impl FnMut(usize) -> Option<Errno> + 'static) {
            HOOK.with_borrow_mut(|slot| *slot = Some(Box::new(hook)));
        }

        pub(crate) fn clear() {
            HOOK.with_borrow_mut(|slot| *slot = None);
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::SpoolInventoryStep;
    use super::SpoolLayout;
    use super::SpoolObjectKey;
    use super::SpoolPhysicalInventory;
    use super::SpoolReclaimStep;
    use super::SpoolWriteError;
    use super::SpoolWriteReceipt;

    // Durable placement needs `renameat` and directory fsync semantics this
    // module can only assert on Linux, and the reader it feeds
    // (`LinuxSpoolVerifier`) is Linux-only for `openat2`. A weaker writer
    // wearing the same name is exactly what D13 refused for the staging root.
    pub struct LinuxSpoolWriter;

    impl LinuxSpoolWriter {
        pub fn physical_usage(
            &self,
            _maximum_entries: u32,
        ) -> Result<Option<(u64, u64)>, SpoolWriteError> {
            Err(SpoolWriteError::UnsupportedPlatform)
        }
        pub fn physical_usage_completed(
            &self,
            _maximum_entries: u32,
        ) -> Result<Option<SpoolPhysicalInventory>, SpoolWriteError> {
            Err(SpoolWriteError::UnsupportedPlatform)
        }
        pub fn physical_usage_step(
            &self,
            _maximum_entries: u32,
        ) -> Result<SpoolInventoryStep, SpoolWriteError> {
            Err(SpoolWriteError::UnsupportedPlatform)
        }
        pub fn available_bytes(&self) -> Result<u64, SpoolWriteError> {
            Err(SpoolWriteError::UnsupportedPlatform)
        }
        pub fn reconcile_put_body(
            &self,
            _layout: &SpoolLayout,
            _key: &SpoolObjectKey,
            _body: &[u8],
        ) -> Result<SpoolWriteReceipt, SpoolWriteError> {
            Err(SpoolWriteError::UnsupportedPlatform)
        }
        // Keeps the Linux writer's signature, which uses self.
        #[allow(clippy::unused_self)]
        pub(crate) fn purge_put_body(
            &self,
            _layout: &SpoolLayout,
            _key: &SpoolObjectKey,
        ) -> Result<bool, SpoolWriteError> {
            Err(SpoolWriteError::UnsupportedPlatform)
        }

        pub fn reclaim_step(
            &self,
            _layout: &SpoolLayout,
            _provider_boundary_id: &str,
            _floor_ms: i64,
            _maximum_entries: u32,
        ) -> Result<SpoolReclaimStep, SpoolWriteError> {
            Err(SpoolWriteError::UnsupportedPlatform)
        }

        pub fn probe_quarantine_rename(&self) -> Result<(), SpoolWriteError> {
            Err(SpoolWriteError::UnsupportedPlatform)
        }
        pub fn open(
            _layout: &SpoolLayout,
            _maximum_body_bytes: u64,
        ) -> Result<Self, SpoolWriteError> {
            Err(SpoolWriteError::UnsupportedPlatform)
        }

        pub fn write_put_body(
            &self,
            _layout: &SpoolLayout,
            _key: &SpoolObjectKey,
            _body: &[u8],
        ) -> Result<SpoolWriteReceipt, SpoolWriteError> {
            Err(SpoolWriteError::UnsupportedPlatform)
        }
    }

    impl std::fmt::Debug for LinuxSpoolWriter {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.debug_struct("LinuxSpoolWriter").finish()
        }
    }

    pub use LinuxSpoolWriter as ExportedLinuxSpoolWriter;
}

pub use platform::ExportedLinuxSpoolWriter as LinuxSpoolWriter;
#[cfg(all(target_os = "linux", feature = "test_seams"))]
pub use platform::probe_fault;

#[cfg(test)]
mod os_error_tests {
    use super::SpoolOsError;

    #[test]
    fn an_os_error_keeps_its_kind_and_code() {
        let source = std::io::Error::from_raw_os_error(2);
        let os = SpoolOsError::from_io(&source);
        assert_eq!(os.kind(), source.kind());
        assert_eq!(os.raw_os_error(), Some(2));
        assert_eq!(os.to_string(), format!("{} (os error 2)", source.kind()));
    }

    #[test]
    fn an_error_without_a_code_reports_only_its_kind() {
        let os = SpoolOsError::from_io(&std::io::Error::other("synthetic"));
        assert_eq!(os.raw_os_error(), None);
        assert_eq!(os.to_string(), std::io::ErrorKind::Other.to_string());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod purge_tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    use rustix::io::Errno;

    use super::LinuxSpoolWriter;
    use super::MAX_SPOOL_BODY_BYTES;
    use super::SpoolWriteError;
    use crate::spool::SpoolLayout;
    use crate::spool::SpoolObjectKey;
    use crate::spool::SpoolObjectKind;

    struct TestRoot(PathBuf);

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_root(label: &str) -> TestRoot {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = PathBuf::from(format!(
            "/tmp/lore-spool-purge-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated absolute spool root");
        TestRoot(path)
    }

    fn key(logical: u32, attempt: u32) -> SpoolObjectKey {
        SpoolObjectKey {
            provider_boundary_id: "boundary".into(),
            logical_request_id: format!("018f3e12-a456-7abc-8def-{logical:012x}"),
            attempt_id: format!("018f3e12-a457-7abc-8def-{attempt:012x}"),
            kind: SpoolObjectKind::Put,
        }
    }

    /// INV-FT F2: every purge used to leave its request and fan-out directories.
    #[test]
    fn purge_removes_the_empty_request_and_fanout_directories_only() {
        let root = test_root("empty-parents");
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap();
        let key = key(1, 1);
        let paths = layout.derive_paths(&key).unwrap();
        writer.write_put_body(&layout, &key, b"body").unwrap();
        let request = paths.final_path().parent().unwrap().to_path_buf();
        let fanout = request.parent().unwrap().to_path_buf();
        let kind = fanout.parent().unwrap().to_path_buf();

        assert!(writer.purge_put_body(&layout, &key).unwrap());

        assert!(!request.exists(), "the empty request directory is removed");
        assert!(!fanout.exists(), "the empty fan-out directory is removed");
        assert!(kind.is_dir(), "the fixed kind directory stays");
        assert_eq!(
            writer.physical_usage(4096).unwrap(),
            Some((0, 0)),
            "an empty spool walks as empty"
        );
    }

    #[test]
    fn purge_keeps_a_directory_that_still_holds_another_body() {
        let root = test_root("shared-parent");
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap();
        let (first, second) = (key(1, 1), key(1, 2));
        writer.write_put_body(&layout, &first, b"first").unwrap();
        writer.write_put_body(&layout, &second, b"second").unwrap();

        assert!(writer.purge_put_body(&layout, &first).unwrap());

        let survivor = layout.derive_paths(&second).unwrap();
        assert_eq!(fs::read(survivor.final_path()).unwrap(), b"second");
        assert!(
            !writer.purge_put_body(&layout, &first).unwrap(),
            "idempotent"
        );
        assert!(writer.purge_put_body(&layout, &second).unwrap());
        assert!(!survivor.final_path().parent().unwrap().exists());
    }

    /// A purge in the same directory can empty-remove the request and fan-out
    /// directories after step 1 made them and before the part create. The
    /// writer must redo step 1 rather than fail the write.
    #[test]
    fn directories_purged_between_creation_and_placement_are_recreated() {
        let root = test_root("purged-before-place");
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap();
        let key = key(1, 1);
        let paths = layout.derive_paths(&key).unwrap();
        let request = paths.final_path().parent().unwrap().to_path_buf();
        let fanout = request.parent().unwrap().to_path_buf();
        let mut fired = false;
        super::platform::before_place::install(move || {
            if !fired {
                fired = true;
                fs::remove_dir(&request).unwrap();
                fs::remove_dir(&fanout).unwrap();
            }
        });
        let result = writer.write_put_body(&layout, &key, b"body");
        super::platform::before_place::clear();
        result.expect("the write redoes step 1 and places the body");
        assert_eq!(fs::read(paths.final_path()).unwrap(), b"body");
    }

    /// A purge removes the leaf step 1 synced, then another writer recreates a
    /// directory at the same path without syncing it. The writer must not place
    /// its body there through the path; it redoes step 1, which syncs the new
    /// directory itself.
    #[test]
    fn a_removed_and_recreated_leaf_makes_the_writer_redo_step_one() {
        let root = test_root("recreated-before-place");
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap();
        let key = key(1, 1);
        let paths = layout.derive_paths(&key).unwrap();
        let request = paths.final_path().parent().unwrap().to_path_buf();
        let attempts = std::rc::Rc::new(std::cell::Cell::new(0));
        let counted = attempts.clone();
        super::platform::before_place::install(move || {
            counted.set(counted.get() + 1);
            if counted.get() == 1 {
                fs::remove_dir(&request).unwrap();
                fs::create_dir(&request).unwrap();
            }
        });
        let result = writer.write_put_body(&layout, &key, b"body");
        super::platform::before_place::clear();
        result.expect("the write redoes step 1 and places the body");
        assert_eq!(attempts.get(), 2, "the first attempt's leaf was removed");
        assert_eq!(fs::read(paths.final_path()).unwrap(), b"body");
    }

    /// A failed syscall keeps its OS error for the operator, while the
    /// `Display` text stays what it was. A directory where the body belongs
    /// makes the purge's `unlinkat` fail with `EISDIR`, even as root.
    #[test]
    fn a_failed_unlink_keeps_its_os_error() {
        let root = test_root("unlink-errno");
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap();
        let key = key(1, 1);
        let paths = layout.derive_paths(&key).unwrap();
        fs::create_dir_all(paths.final_path()).unwrap();

        let error = writer
            .purge_put_body(&layout, &key)
            .expect_err("unlinking a directory must fail");

        assert!(matches!(
            error,
            SpoolWriteError::Io {
                operation: "purge unlink",
                ..
            }
        ));
        let os = error.os_error().expect("the OS error is kept");
        assert_eq!(os.kind(), std::io::ErrorKind::IsADirectory);
        assert_eq!(os.raw_os_error(), Some(Errno::ISDIR.raw_os_error()));
        assert_eq!(
            error.to_string(),
            "shared spool write failed at purge unlink"
        );
        assert_eq!(
            os.to_string(),
            format!("is a directory (os error {})", Errno::ISDIR.raw_os_error())
        );
    }

    /// The retried placement failure keeps its `ENOENT` once retries run out.
    #[test]
    fn a_placement_directory_removed_on_every_attempt_reports_enoent() {
        let root = test_root("removed-every-attempt");
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap();
        let key = key(1, 1);
        let paths = layout.derive_paths(&key).unwrap();
        let request = paths.final_path().parent().unwrap().to_path_buf();
        super::platform::before_place::install(move || fs::remove_dir(&request).unwrap());
        let result = writer.write_put_body(&layout, &key, b"body");
        super::platform::before_place::clear();

        let error = result.expect_err("every attempt lost its leaf");
        assert!(matches!(
            error,
            SpoolWriteError::Io {
                operation: "placement directory removed",
                ..
            }
        ));
        let os = error.os_error().expect("the OS error is kept");
        assert_eq!(os.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(os.raw_os_error(), Some(Errno::NOENT.raw_os_error()));
    }

    /// Smoke only: a purger racing a writer in the same directory. The window is
    /// too narrow for this to discriminate; the seam case above does.
    #[test]
    fn concurrent_purges_in_the_same_directory_do_not_fail_a_write() {
        let root = test_root("concurrent");
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = Arc::new(LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap());
        let purger = {
            let layout = layout.clone();
            let writer = writer.clone();
            std::thread::spawn(move || {
                for attempt in 0..200 {
                    let _ = writer.purge_put_body(&layout, &key(1, attempt));
                }
            })
        };
        for attempt in 0..200 {
            writer
                .write_put_body(&layout, &key(1, 10_000 + attempt), b"x")
                .unwrap_or_else(|error| panic!("write {attempt} failed: {error}"));
            assert!(
                writer
                    .purge_put_body(&layout, &key(1, 10_000 + attempt))
                    .unwrap()
            );
        }
        purger.join().unwrap();
    }
}

/// WP-115 f2 round 3: reclaim survives per-entry failures, and the quarantine rename is probed.
/// In-crate because the fault seam (`platform::rename_fault`) is `cfg(test)`.
#[cfg(all(test, target_os = "linux"))]
mod reclaim_fault_tests {
    use std::fs;
    use std::path::PathBuf;

    use rustix::io::Errno;

    use super::LinuxSpoolWriter;
    use super::MAX_SPOOL_BODY_BYTES;
    use super::SpoolWriteError;
    use crate::spool::SpoolLayout;
    use crate::spool::SpoolObjectKey;
    use crate::spool::SpoolObjectKind;

    const BOUNDARY: &str = "boundary";

    struct TestRoot(PathBuf);

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Clears the thread-local rename fault on drop, so a failed assertion cannot leak it.
    struct Fault;

    impl Fault {
        fn install(hook: impl FnMut(usize) -> Option<Errno> + 'static) -> Self {
            super::platform::rename_fault::install(hook);
            Self
        }
    }

    impl Drop for Fault {
        fn drop(&mut self) {
            super::platform::rename_fault::clear();
        }
    }

    fn test_root(label: &str) -> TestRoot {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = PathBuf::from(format!(
            "/tmp/lore-spool-fault-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated absolute spool root");
        TestRoot(path)
    }

    fn key(attempt: u32) -> SpoolObjectKey {
        SpoolObjectKey {
            provider_boundary_id: BOUNDARY.into(),
            logical_request_id: "018f3e12-a456-7abc-8def-000000000001".into(),
            attempt_id: format!("018f3e12-a457-7abc-8def-{attempt:012x}"),
            kind: SpoolObjectKind::Put,
        }
    }

    /// The quarantine name a key's blob takes: `<logical>.<attempt>.blob`.
    fn quarantine_name(key: &SpoolObjectKey) -> String {
        format!("{}.{}.blob", key.logical_request_id, key.attempt_id)
    }

    /// Every body is below this floor.
    const FLOOR: i64 = i64::MAX;

    /// A read error on the boundary's `put` directory is the whole tree failing to read, so the
    /// step fails rather than report a completed traversal, and the next step starts over.
    #[test]
    fn a_read_error_on_the_put_directory_fails_the_step_and_the_next_step_starts_over() {
        let root = test_root("put-read-error");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");
        let below = key(1);
        writer
            .write_put_body(&layout, &below, b"below-the-floor")
            .expect("place the body");

        super::platform::reclaim_read_fault::install(|depth| (depth == 1).then_some(Errno::IO));
        let failed = writer.reclaim_step(&layout, BOUNDARY, FLOOR, 64);
        super::platform::reclaim_read_fault::clear();
        assert_eq!(
            failed,
            Err(SpoolWriteError::RootUnavailable),
            "an unreadable put directory fails the step, never completed = true"
        );
        assert!(
            !root.0.join("quarantine").exists(),
            "the failed step moved nothing"
        );

        assert_eq!(
            walk(&writer, &layout),
            (1, 0),
            "the next traversal starts over and quarantines the body"
        );
        assert!(
            root.0
                .join("quarantine")
                .join(quarantine_name(&below))
                .is_file()
        );
    }

    /// A read error inside a fan-out directory skips the rest of that directory, counts it and
    /// lets the traversal complete; the next traversal reads it again.
    #[test]
    fn a_read_error_in_a_fanout_directory_is_skipped_counted_and_retried_next_traversal() {
        let root = test_root("fanout-read-error");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");
        let below = key(2);
        writer
            .write_put_body(&layout, &below, b"below-the-floor")
            .expect("place the body");

        let mut fired = false;
        super::platform::reclaim_read_fault::install(move |depth| {
            (depth == 2 && !std::mem::replace(&mut fired, true)).then_some(Errno::IO)
        });
        let walked = walk(&writer, &layout);
        super::platform::reclaim_read_fault::clear();
        assert_eq!(
            walked,
            (0, 1),
            "the unreadable fan-out directory is skipped and counted, and the walk completes"
        );
        assert_eq!(
            walk(&writer, &layout),
            (1, 0),
            "the next traversal reads it again and quarantines the body"
        );
    }

    /// A failed directory sync after the rename does not hide the move: the body is in
    /// quarantine and counts as quarantined, not skipped.
    #[test]
    fn a_failed_fsync_after_the_rename_still_counts_the_move() {
        let root = test_root("fsync-after-rename");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");
        let below = key(3);
        writer
            .write_put_body(&layout, &below, b"below-the-floor")
            .expect("place the body");

        super::platform::fsync_fault::install(|_which| Some(Errno::IO));
        let walked = walk(&writer, &layout);
        super::platform::fsync_fault::clear();
        assert_eq!(walked, (1, 0), "the move counts, and nothing is skipped");
        assert!(
            root.0
                .join("quarantine")
                .join(quarantine_name(&below))
                .is_file(),
            "the body is in quarantine"
        );
    }

    /// Step to the end of a traversal; returns `(quarantined_files, skipped_entries)`.
    fn walk(writer: &LinuxSpoolWriter, layout: &SpoolLayout) -> (u64, u64) {
        let (mut moved, mut skipped) = (0, 0);
        for _ in 0..64 {
            let step = writer
                .reclaim_step(layout, BOUNDARY, FLOOR, 64)
                .expect("a per-entry failure does not fail the step");
            moved += step.quarantined_files;
            skipped += step.skipped_entries;
            if step.completed {
                return (moved, skipped);
            }
        }
        panic!("the walk must complete");
    }

    fn open(label: &str) -> (TestRoot, SpoolLayout, LinuxSpoolWriter) {
        let root = test_root(label);
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap();
        (root, layout, writer)
    }

    #[test]
    fn the_probe_reports_unsupported_for_einval_enosys_and_exdev_and_cleans_up() {
        for errno in [Errno::INVAL, Errno::NOSYS, Errno::XDEV] {
            let (root, _layout, writer) = open("probe-unsupported");
            let fault = Fault::install(move |_attempt| Some(errno));
            let result = writer.probe_quarantine_rename();
            drop(fault);
            assert_eq!(
                result,
                Err(SpoolWriteError::RenameNoReplaceUnsupported),
                "{errno:?}"
            );
            assert_eq!(
                fs::read_dir(root.0.join("quarantine")).unwrap().count(),
                0,
                "{errno:?}: the probe file is removed"
            );
        }
    }

    #[test]
    fn another_probe_failure_is_an_io_error_not_unsupported() {
        let (_root, _layout, writer) = open("probe-other");
        let fault = Fault::install(|_attempt| Some(Errno::ACCESS));
        let result = writer.probe_quarantine_rename();
        drop(fault);
        assert!(
            matches!(result, Err(SpoolWriteError::Io { .. })),
            "only EINVAL, ENOSYS and EXDEV mean unsupported: {result:?}"
        );
    }

    #[test]
    fn a_real_probe_succeeds_and_leaves_only_the_quarantine_directory() {
        let (root, _layout, writer) = open("probe-real");
        writer
            .probe_quarantine_rename()
            .expect("a tmp root supports RENAME_NOREPLACE");
        let names: Vec<_> = fs::read_dir(&root.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("quarantine")]);
        assert_eq!(fs::read_dir(root.0.join("quarantine")).unwrap().count(), 0);
        writer.probe_quarantine_rename().expect("and again");
    }

    #[test]
    fn an_injected_exdev_or_einval_leaves_the_file_in_place_and_counts_it_skipped() {
        for errno in [Errno::XDEV, Errno::INVAL] {
            let (_root, layout, writer) = open("rename-fails");
            let key = key(1);
            writer.write_put_body(&layout, &key, b"stays").unwrap();
            let path = layout
                .derive_paths(&key)
                .unwrap()
                .final_path()
                .to_path_buf();
            let fault = Fault::install(move |_attempt| Some(errno));
            let (moved, skipped) = walk(&writer, &layout);
            drop(fault);
            assert_eq!((moved, skipped), (0, 1), "{errno:?}");
            assert_eq!(
                fs::read(&path).unwrap(),
                b"stays",
                "{errno:?}: left in place"
            );
        }
    }

    #[test]
    fn eexist_on_the_first_four_names_lands_the_file_at_suffix_four() {
        let (root, layout, writer) = open("suffix-four");
        let key = key(2);
        writer.write_put_body(&layout, &key, b"suffixed").unwrap();
        let fault = Fault::install(|attempt| (attempt <= 3).then_some(Errno::EXIST));
        let (moved, skipped) = walk(&writer, &layout);
        drop(fault);
        assert_eq!((moved, skipped), (1, 0));
        let landed = root
            .0
            .join("quarantine")
            .join(format!("{}.4", quarantine_name(&key)));
        assert_eq!(fs::read(landed).unwrap(), b"suffixed");
        assert!(!layout.derive_paths(&key).unwrap().final_path().exists());
        assert_eq!(fs::read_dir(root.0.join("quarantine")).unwrap().count(), 1);
    }

    #[test]
    fn names_that_really_exist_push_the_file_to_the_next_free_suffix() {
        let (root, layout, writer) = open("suffix-real");
        let key = key(3);
        let quarantine = root.0.join("quarantine");
        fs::create_dir(&quarantine).unwrap();
        let base = quarantine_name(&key);
        for (suffix, body) in [("", "old-0"), (".1", "old-1"), (".2", "old-2")] {
            fs::write(quarantine.join(format!("{base}{suffix}")), body).unwrap();
        }
        writer
            .write_put_body(&layout, &key, b"new-arrival")
            .unwrap();
        assert_eq!(walk(&writer, &layout), (1, 0));
        assert_eq!(
            fs::read(quarantine.join(format!("{base}.3"))).unwrap(),
            b"new-arrival"
        );
        for (suffix, body) in [("", "old-0"), (".1", "old-1"), (".2", "old-2")] {
            assert_eq!(
                fs::read(quarantine.join(format!("{base}{suffix}"))).unwrap(),
                body.as_bytes(),
                "an existing quarantined file is never replaced"
            );
        }
    }

    #[test]
    fn eexist_on_all_nine_names_skips_the_file_and_loses_nothing() {
        let (root, layout, writer) = open("suffix-exhausted");
        let key = key(4);
        writer.write_put_body(&layout, &key, b"kept").unwrap();
        let path = layout
            .derive_paths(&key)
            .unwrap()
            .final_path()
            .to_path_buf();
        let fault = Fault::install(|_attempt| Some(Errno::EXIST));
        let (moved, skipped) = walk(&writer, &layout);
        drop(fault);
        assert_eq!(
            (moved, skipped),
            (0, 1),
            "the ninth collision skips the entry"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            b"kept",
            "nothing moved, nothing lost"
        );
        assert_eq!(fs::read_dir(root.0.join("quarantine")).unwrap().count(), 0);
        // With the fault gone the same file moves on the next traversal.
        assert_eq!(walk(&writer, &layout), (1, 0));
        assert!(!path.exists());
    }

    #[test]
    fn a_poisoned_reclaim_cursor_recovers_on_the_next_step() {
        let (root, layout, writer) = open("poisoned");
        let key = key(5);
        writer
            .write_put_body(&layout, &key, b"after-poison")
            .unwrap();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            writer.poison_reclaim_cursor_for_test();
        }));
        assert!(
            poisoned.is_err(),
            "the hook panics while holding the cursor"
        );
        assert_eq!(
            walk(&writer, &layout),
            (1, 0),
            "the next step recovers the cursor and the walk completes"
        );
        assert_eq!(
            fs::read(root.0.join("quarantine").join(quarantine_name(&key))).unwrap(),
            b"after-poison"
        );
        // Recovery is permanent, not a one-off: later steps keep working.
        let later = writer.reclaim_step(&layout, BOUNDARY, FLOOR, 64).unwrap();
        assert!(later.completed);
    }
}
