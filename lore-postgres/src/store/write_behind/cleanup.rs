// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Exact local cleanup of one staged epoch.
//!
//! This is the [`StagedEpochCleanup`] implementation the obliterate path
//! already consumes (`store/immutable_store.rs`'s staged arms in
//! `load_obliterate_representation` and `purge_obliterate_target`). The trait
//! predates this module and its doc comment already names this seam as its
//! supplier, so no new cleanup trait is introduced.
//!
//! # This module never decides that bytes are unprotected
//!
//! It acts only on a [`FragmentPurgeTarget`] the coordinator computed under the
//! fragment head lock, after `obliterate_blocked_until_locked` folded every live
//! staged reader lease's deadline into the intent's `blocked_until`. The
//! obliterate loop sleeps on `FragmentObliterateBegin::Blocked` rather than
//! reaching here. So the deletion barrier is upheld by construction: this module
//! has no lease query, no clock comparison, and no database resource with which
//! to acquire either.
//!
//! Two further guards, both local:
//!
//! - a target whose authority is not [`EpochAuthority::Staged`] is refused. A
//!   `Remote` target names an object in the provider's keyspace, and unlinking
//!   anything for it would be acting on a key this tier does not own.
//! - the path unlinked is the one **derived** from the target's own typed
//!   `(hash, epoch)`, and the target's stored key must be byte-equal to that
//!   derivation. A target naming a different epoch therefore cannot reach
//!   another epoch's bytes, which is what keeps a quarantined predecessor and
//!   its successor separable.
//!
//! # Absence
//!
//! `purge_exact` treats an already-absent file as success: a purge retried after
//! a crash must converge, and a second unlink of a path this process already
//! removed is the expected case, not a fault.
//!
//! `read_exact` is the opposite shape, because the trait's contract makes `None`
//! decisive: only a real `ENOENT` under a root this process has proven it owns
//! yields `Ok(None)`. Every uncertain condition — unset root, lost mount, wrong
//! device — is an error, which keeps the head deleting instead of concluding a
//! child set is empty.

use async_trait::async_trait;
use bytes::Bytes;
use lore_storage::StoreError;

use super::StagedRead;
use super::WriteBehindError;
use super::WriteBehindStage;
use crate::domain::fragments::EpochAuthority;
use crate::domain::fragments::FragmentPurgeTarget;
use crate::store::immutable_store::StagedEpochCleanup;

/// A parsed candidate has no deletion authority. Its placement is derived again
/// after the coordinator grants the exact epoch's reclaim seal.
#[derive(Debug, Clone)]
pub struct StageFileCandidate {
    pub hash: [u8; 32],
    pub epoch: i64,
    temporary: bool,
}
impl StageFileCandidate {
    pub(crate) fn final_for(target: &FragmentPurgeTarget) -> Result<Self, WriteBehindError> {
        Ok(Self {
            hash: target
                .hash()
                .try_into()
                .map_err(|_error| WriteBehindError::HashWidth)?,
            epoch: target.epoch(),
            temporary: false,
        })
    }
}

#[derive(Default)]
pub struct StageFileScanner {
    #[cfg(unix)]
    directories: Vec<(std::os::fd::OwnedFd, rustix::fs::Dir, std::path::PathBuf)>,
    #[cfg(unix)]
    cycle_bytes: u64,
    #[cfg(unix)]
    cycle_files: u64,
    #[cfg(unix)]
    cycle_unknown: u64,
    /// Fan-out acts skipped because the directory went stale (ESTALE), over
    /// this scanner's life. Diagnostic only.
    #[cfg(unix)]
    stale_fanout_skips: u64,
    physical: Option<(std::time::Instant, u64, u64, u64)>,
}

impl StageFileScanner {
    /// Last completed traversal: monotonic completion time, bytes, files and
    /// unknown entries. A partial cycle never publishes a smaller occupancy.
    pub fn physical_observation(&self) -> Option<(std::time::Instant, u64, u64, u64)> {
        self.physical
    }

    /// Whether a traversal is part-way through. The next `scan` starts a new
    /// traversal when this is false.
    pub fn walk_in_progress(&self) -> bool {
        #[cfg(unix)]
        return !self.directories.is_empty();
        #[cfg(not(unix))]
        false
    }

    /// How many fan-out acts this scanner skipped because the directory went
    /// stale (ESTALE, the NFS form of a removed directory). Diagnostic only.
    pub fn stale_fanout_skips(&self) -> u64 {
        #[cfg(unix)]
        return self.stale_fanout_skips;
        #[cfg(not(unix))]
        0
    }

    /// Bounded traversal with retained cursors, so late residue and high hashes
    /// are eventually revisited without an unbounded recursive enumeration.
    pub fn scan(
        &mut self,
        stage: &WriteBehindStage,
        limit: usize,
    ) -> Result<Vec<StageFileCandidate>, WriteBehindError> {
        let result = self.scan_inner(stage, limit);
        if result.is_err() {
            self.physical = None;
            #[cfg(unix)]
            self.directories.clear();
        }
        result
    }

    #[cfg(not(unix))]
    #[allow(clippy::unused_self)] // Keeps the unix signature.
    fn scan_inner(
        &mut self,
        _stage: &WriteBehindStage,
        _limit: usize,
    ) -> Result<Vec<StageFileCandidate>, WriteBehindError> {
        Err(WriteBehindError::UnsupportedPlatform)
    }

    #[cfg(unix)]
    fn scan_inner(
        &mut self,
        stage: &WriteBehindStage,
        limit: usize,
    ) -> Result<Vec<StageFileCandidate>, WriteBehindError> {
        use std::os::unix::ffi::OsStrExt as _;

        use rustix::fs::AtFlags;
        use rustix::fs::FileType;
        use rustix::fs::Mode;
        use rustix::fs::OFlags;
        use rustix::io::Errno;

        if limit == 0 || limit > 256 {
            return Err(WriteBehindError::PayloadOversized);
        }
        let root = stage.root();
        let root_directory = root.verified_root_directory()?;
        let root_stat = rustix::fs::fstat(&root_directory)
            .map_err(|error| WriteBehindError::io("stage inventory root stat", &error.into()))?;
        if self.directories.is_empty() {
            self.cycle_bytes = 0;
            self.cycle_files = 0;
            self.cycle_unknown = 0;
            // Include unknown files beside the two normal entry points too.
            let entries = rustix::fs::Dir::read_from(&root_directory)
                .map_err(|error| WriteBehindError::io("stage inventory", &error.into()))?;
            self.directories
                .push((root_directory.into(), entries, std::path::PathBuf::new()));
        }
        let inventory_root = root.inventory_root();
        let mut found = Vec::new();
        for _ in 0..limit {
            let Some((directory, entries, relative)) = self.directories.last_mut() else {
                break;
            };
            let entry = match super::root::inventory_injected(
                "stage inventory entry",
                inventory_root,
                relative,
            ) {
                Ok(()) => entries.next(),
                Err(error) => Some(Err(error)),
            };
            let Some(entry) = entry else {
                self.directories.pop();
                continue;
            };
            let entry = match entry {
                Ok(entry) => entry,
                // Purge removes empty fan-out directories, and reading a removed
                // directory is ENOENT (ESTALE on NFS). That ends this directory;
                // the root's device is revalidated below.
                Err(Errno::NOENT) => {
                    self.directories.pop();
                    continue;
                }
                Err(error)
                    if skip_stale_fanout(
                        &mut self.stale_fanout_skips,
                        "stage inventory entry",
                        error,
                        relative,
                    ) =>
                {
                    self.directories.pop();
                    continue;
                }
                Err(error) => {
                    return Err(WriteBehindError::io("stage inventory entry", &error.into()));
                }
            };
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            let metadata = match super::root::inventory_injected(
                "stage inventory stat",
                inventory_root,
                relative,
            )
            .and_then(|()| rustix::fs::statat(&*directory, name, AtFlags::SYMLINK_NOFOLLOW))
            {
                Ok(metadata) => metadata,
                Err(Errno::NOENT) => continue,
                // The held fan-out directory was removed: on NFS the lookup in
                // it is ESTALE. The entry is absent, as for ENOENT.
                Err(error)
                    if skip_stale_fanout(
                        &mut self.stale_fanout_skips,
                        "stage inventory stat",
                        error,
                        relative,
                    ) =>
                {
                    continue;
                }
                Err(error) => {
                    return Err(WriteBehindError::io("stage inventory stat", &error.into()));
                }
            };
            if metadata.st_dev != root_stat.st_dev {
                return Err(WriteBehindError::RootDeviceChanged);
            }
            let kind = FileType::from_raw_mode(metadata.st_mode);
            if kind.is_dir()
                && relative.as_os_str().is_empty()
                && name.to_bytes() == super::root::LIVENESS_DIR.as_bytes()
            {
                // WP-115 K11: the replicas' liveness probes, never staged data.
                continue;
            }
            let path = relative.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
            if kind.is_dir() {
                // Retained depth-first cursors bound open handles as well as
                // per-pass work. Do not certify a partial inventory as complete.
                if path.components().count() > 16 {
                    return Err(WriteBehindError::Io {
                        operation: "stage inventory depth",
                        kind: std::io::ErrorKind::InvalidData,
                    });
                }
                let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                let injected = super::root::inventory_injected(
                    "stage inventory descend",
                    inventory_root,
                    relative,
                );
                #[cfg(target_os = "linux")]
                let child = injected.and_then(|()| {
                    rustix::fs::openat2(
                        &*directory,
                        name,
                        flags,
                        Mode::empty(),
                        rustix::fs::ResolveFlags::BENEATH
                            | rustix::fs::ResolveFlags::NO_SYMLINKS
                            | rustix::fs::ResolveFlags::NO_XDEV,
                    )
                });
                #[cfg(not(target_os = "linux"))]
                let child = injected
                    .and_then(|()| rustix::fs::openat(&*directory, name, flags, Mode::empty()));
                // A directory purged between the stat and the open is absent,
                // exactly like an entry purged before the stat. On NFS, an
                // open in a held fan-out directory that was removed is ESTALE.
                let child = match child {
                    Ok(child) => child,
                    Err(Errno::NOENT) => continue,
                    Err(error)
                        if skip_stale_fanout(
                            &mut self.stale_fanout_skips,
                            "stage inventory descend",
                            error,
                            relative,
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => {
                        return Err(WriteBehindError::io(
                            "stage inventory descend",
                            &error.into(),
                        ));
                    }
                };
                // From here the act is on `child` itself. On NFS a child
                // fan-out directory purged since the open is ESTALE; it is
                // absent, as above. Only a fan-out child is skipped.
                let child_stat = match super::root::inventory_injected(
                    "stage inventory child stat",
                    inventory_root,
                    &path,
                )
                .and_then(|()| rustix::fs::fstat(&child))
                {
                    Ok(child_stat) => child_stat,
                    Err(error)
                        if skip_stale_fanout(
                            &mut self.stale_fanout_skips,
                            "stage inventory child stat",
                            error,
                            &path,
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => {
                        return Err(WriteBehindError::io(
                            "stage inventory child stat",
                            &error.into(),
                        ));
                    }
                };
                if child_stat.st_dev != root_stat.st_dev {
                    return Err(WriteBehindError::RootDeviceChanged);
                }
                if child_stat.st_ino != metadata.st_ino {
                    // Purged and recreated between the stat and the open. The
                    // open was confined beneath this directory, so skip the new
                    // one; the next traversal counts it.
                    continue;
                }
                let entries = match super::root::inventory_injected(
                    "stage inventory child read",
                    inventory_root,
                    &path,
                )
                .and_then(|()| rustix::fs::Dir::read_from(&child))
                {
                    Ok(entries) => entries,
                    Err(Errno::NOENT) => continue,
                    Err(error)
                        if skip_stale_fanout(
                            &mut self.stale_fanout_skips,
                            "stage inventory child read",
                            error,
                            &path,
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => {
                        return Err(WriteBehindError::io(
                            "stage inventory descend",
                            &error.into(),
                        ));
                    }
                };
                self.directories.push((child, entries, path));
                continue;
            }
            if !kind.is_file() {
                self.cycle_unknown = self.cycle_unknown.saturating_add(1);
                continue;
            }
            if metadata.st_size < 0 {
                return Err(WriteBehindError::NotARegularFile);
            }
            self.cycle_bytes = self.cycle_bytes.saturating_add(metadata.st_size as u64);
            self.cycle_files = self.cycle_files.saturating_add(1);
            let Ok(name) = name.to_str() else {
                self.cycle_unknown = self.cycle_unknown.saturating_add(1);
                continue;
            };
            if let Some(candidate) = parse_candidate(name) {
                let correct_path = match candidate.temporary {
                    true => path.parent() == Some(std::path::Path::new(super::root::INCOMING_DIR)),
                    false => root
                        .resolve(&candidate.hash, candidate.epoch, name)
                        .is_ok_and(|p| p.path() == root.inventory_root().join(&path)),
                };
                if correct_path {
                    found.push(candidate);
                    continue;
                }
            }
            self.cycle_unknown = self.cycle_unknown.saturating_add(1);
        }
        root.verify_device()?;
        if self.directories.is_empty() {
            self.physical = Some((
                std::time::Instant::now(),
                self.cycle_bytes,
                self.cycle_files,
                self.cycle_unknown,
            ));
        }
        Ok(found)
    }
}

/// FORK-LOCAL (Tideshift): an ESTALE on `relative`, a directory the inventory
/// walk holds or has just opened. True, counted and logged at debug, when
/// `relative` is a fan-out level (`staged/<aa>` or `staged/<aa>/<bb>`): on NFS
/// a directory a concurrent purge removed gives ESTALE where a local disk
/// gives ENOENT, so the caller treats it like that ENOENT. False for the root,
/// `staged/`, `incoming/` or anything else: an ESTALE there stays an error.
/// `root.verify_device()` at the end of every step still proves that the root
/// and the pinned `staged/` are the ones opened.
#[cfg(unix)]
fn skip_stale_fanout(
    skips: &mut u64,
    site: &'static str,
    error: rustix::io::Errno,
    relative: &std::path::Path,
) -> bool {
    if error != rustix::io::Errno::STALE || !is_removable_fanout(relative) {
        return false;
    }
    *skips = skips.saturating_add(1);
    tracing::debug!(
        site,
        errno = error.raw_os_error(),
        directory = %relative.display(),
        "write-behind: stage inventory skipped a stale fan-out directory, treated as removed"
    );
    true
}

/// Whether `relative` (from the stage root) is a fan-out level a purge can
/// remove: `staged/<aa>` or `staged/<aa>/<bb>`. Never the root, `staged/`
/// itself, `incoming/`, or anything deeper or elsewhere.
#[cfg(unix)]
fn is_removable_fanout(relative: &std::path::Path) -> bool {
    let mut components = relative.components();
    components.next()
        == Some(std::path::Component::Normal(
            super::root::STAGED_DIR.as_ref(),
        ))
        && (1..=super::root::REMOVABLE_FANOUT_LEVELS).contains(&components.count())
}

#[cfg(unix)]
fn parse_candidate(name: &str) -> Option<StageFileCandidate> {
    let (key, temporary) = if let Some(key) = name.strip_suffix(".tmp") {
        (key, true)
    } else {
        (name, false)
    };
    let (hash, epoch) = key.split_once(".s")?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16).ok()?;
    }
    let epoch = epoch.parse::<i64>().ok()?;
    if epoch < 0 || super::root::derived_staged_key(&bytes, epoch).ok()? != key {
        return None;
    }
    Some(StageFileCandidate {
        hash: bytes,
        epoch,
        temporary,
    })
}

impl WriteBehindStage {
    /// Blocking exact unlink, used only after a matching coordinator grant.
    pub fn purge_candidate(
        &self,
        candidate: &StageFileCandidate,
        target: &FragmentPurgeTarget,
    ) -> Result<(), WriteBehindError> {
        if target.authority() != EpochAuthority::Staged
            || target.hash() != candidate.hash
            || target.epoch() != candidate.epoch
        {
            return Err(WriteBehindError::KeyMismatch);
        }
        let resolved =
            self.root()
                .resolve(&candidate.hash, candidate.epoch, target.object_key())?;
        self.root()
            .remove_placement_blocking(&resolved, candidate.temporary)
    }

    pub(crate) fn purge_placement(
        &self,
        target: &FragmentPurgeTarget,
    ) -> Result<(), WriteBehindError> {
        let mut candidate = StageFileCandidate::final_for(target)?;
        // Remove temp first. A delayed rename can only land at the exact final
        // placement, which is removed next and revisited through the tombstone.
        candidate.temporary = true;
        self.purge_candidate(&candidate, target)?;
        candidate.temporary = false;
        self.purge_candidate(&candidate, target)
    }
}

#[async_trait]
impl StagedEpochCleanup for WriteBehindStage {
    async fn read_exact(&self, target: &FragmentPurgeTarget) -> Result<Option<Bytes>, StoreError> {
        require_staged(target)?;
        match self
            .read_staged(target.hash(), target.epoch(), target.object_key())
            .await
        {
            StagedRead::Found(bytes) => Ok(Some(bytes)),
            StagedRead::Absent => Ok(None),
            StagedRead::Unavailable(error) => Err(error.store_error()),
        }
    }

    async fn purge_exact(&self, target: &FragmentPurgeTarget) -> Result<(), StoreError> {
        require_staged(target)?;
        let resolved = self
            .root()
            .resolve(target.hash(), target.epoch(), target.object_key())
            .map_err(WriteBehindError::store_error)?;
        self.root()
            .remove_regular(&resolved)
            .await
            .map_err(WriteBehindError::store_error)
    }
}

/// Refuse any authority but `Staged`.
///
/// Internal rather than retryable: a `Remote` target reaching the staging tier
/// means the obliterate path dispatched on authority incorrectly, and no number
/// of retries changes which keyspace a key belongs to.
fn require_staged(target: &FragmentPurgeTarget) -> Result<(), StoreError> {
    if target.authority() == EpochAuthority::Staged {
        return Ok(());
    }
    Err(StoreError::internal(
        "write-behind staging cleanup received a non-staged purge target",
    ))
}
