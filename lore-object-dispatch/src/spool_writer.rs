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
    #[error("shared spool write failed at {operation}")]
    Io { operation: &'static str },
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
    use super::SpoolInventoryStep;
    use super::SpoolLayout;
    use super::SpoolObjectKey;
    use super::SpoolPhysicalInventory;
    use super::SpoolWriteError;
    use super::SpoolWriteReceipt;
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
    };

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

    pub struct LinuxSpoolWriter {
        root_path: PathBuf,
        relative_root: PathBuf,
        filesystem_root_fd: OwnedFd,
        root_fd: OwnedFd,
        root_device: u64,
        root_inode: u64,
        maximum_body_bytes: u64,
        physical_inventory: Mutex<PhysicalInventory>,
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
                .map_err(|_error| SpoolWriteError::Io {
                    operation: "reconcile read",
                })?;
            if found != body {
                return Err(SpoolWriteError::InvalidBodySize);
            }
            file.sync_all().map_err(|_error| SpoolWriteError::Io {
                operation: "reconcile fsync",
            })?;
            let parent = relative
                .parent()
                .ok_or(SpoolWriteError::PathBindingMismatch)?;
            let directory = self.ensure_directory_chain(parent)?;
            rustix::fs::fsync(&directory).map_err(|_error| SpoolWriteError::Io {
                operation: "reconcile directory fsync",
            })?;
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
                        rustix::fs::fsync(&directory).map_err(|_error| SpoolWriteError::Io {
                            operation: "purge missing directory fsync",
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
                    Err(_) => {
                        return Err(SpoolWriteError::Io {
                            operation: "purge unlink",
                        });
                    }
                }
            }
            rustix::fs::fsync(&directory).map_err(|_error| SpoolWriteError::Io {
                operation: "purge directory fsync",
            })?;
            remove_empty_parents(&chain);
            self.assert_configured_root_stable()?;
            Ok(removed)
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
                Err(_) => {
                    return Err(SpoolWriteError::Io {
                        operation: "blob probe",
                    });
                }
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
                Err(_) => {
                    return Err(SpoolWriteError::Io {
                        operation: "part create",
                    });
                }
            };
            let mut part = File::from(part_fd);
            part.write_all(body).map_err(|_err| SpoolWriteError::Io {
                operation: "part write",
            })?;
            // Step 3. Contents and metadata, because the rename publishes both.
            part.sync_all().map_err(|_err| SpoolWriteError::Io {
                operation: "part fsync",
            })?;
            drop(part);

            // Step 4. Both sides are one component in the leaf descriptor, so
            // the rename cannot leave it and is atomic within the one filesystem
            // `NO_XDEV` has already held every open to. The leaf holds the part
            // file now, so no purge can remove it.
            rustix::fs::renameat(directory_fd, part_name, directory_fd, blob_name).map_err(
                |_err| SpoolWriteError::Io {
                    operation: "part rename",
                },
            )?;

            // Step 5.
            rustix::fs::fsync(directory_fd).map_err(|_err| SpoolWriteError::Io {
                operation: "leaf directory fsync",
            })
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
                .map_err(|_err| SpoolWriteError::Io {
                    operation: "root descriptor clone",
                })?;
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
                    Err(_) => {
                        return Err(SpoolWriteError::Io {
                            operation: "fanout create",
                        });
                    }
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
                    Err(_) => {
                        return Err(SpoolWriteError::Io {
                            operation: "fanout open",
                        });
                    }
                };
                rustix::fs::fsync(&parent).map_err(|_err| SpoolWriteError::Io {
                    operation: "fanout parent fsync",
                })?;
                let stat = rustix::fs::fstat(&child).map_err(|_err| SpoolWriteError::Io {
                    operation: "fanout stat",
                })?;
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
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::SpoolInventoryStep;
    use super::SpoolLayout;
    use super::SpoolObjectKey;
    use super::SpoolPhysicalInventory;
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
        pub(crate) fn purge_put_body(
            &self,
            _layout: &SpoolLayout,
            _key: &SpoolObjectKey,
        ) -> Result<bool, SpoolWriteError> {
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

#[cfg(all(test, target_os = "linux"))]
mod purge_tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::LinuxSpoolWriter;
    use super::MAX_SPOOL_BODY_BYTES;
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
