// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! WP-114 CD-7's cell-local durable write-behind staging tier (ADR-00027).
//!
//! This module owns the file half of write-behind: a confined staging root,
//! durable file finalization, bounded validation, staged reads, admission
//! watermarks, and exact local cleanup. Lifecycle, associations, metering,
//! claims and leases stay with the fragment coordinator
//! (`crate::domain::fragments`); nothing here writes Postgres.
//!
//! # The one hard rule
//!
//! **No database resource is held across file I/O**, and nothing in this module
//! can hold one: no type here names a `Pool`, a `Transaction`, or a connection
//! checkout, so the rule is a compile-time property rather than a review
//! convention. `store/write_behind_source_pins.rs` pins that by source scan.
//!
//! # Why the read path must never answer "absent" for an unavailable root
//!
//! `PostgresImmutableStore::load_coordinated`'s staged arm maps a not-found
//! staged file to [`MissingDiagnostic::Absent`], which reaches
//! `mark_coordinated_missing` -> `PostgresFragmentCoordinator::mark_missing` and
//! **demotes a healthy fragment to `Missing`**. A replica whose staging root is
//! unset or unmounted would therefore convert every staged fragment in the cell
//! into a `Missing` head while a sibling replica serves the same bytes happily.
//!
//! So [`StagedRead`] separates the two answers at the type level.
//! [`StagedRead::Absent`] is reachable only from a real `ENOENT` **under a root
//! this process has proven it owns**; every other condition is
//! [`StagedRead::Unavailable`], which the caller maps to `SlowDown`. A decisive
//! per-read error would be the wrong shape too, because it fails one client for
//! a cell-level condition another replica may not share; the matching decisive
//! signal is the store's readiness verdict, not the read.
//!
//! [`MissingDiagnostic::Absent`]: crate::domain::fragments::MissingDiagnostic::Absent

pub mod admission;
pub mod cleanup;
pub mod finalize;
pub mod root;

use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use lore_base::types::FRAGMENT_SIZE_THRESHOLD;
use lore_storage::StoreError;
use lore_storage::errors::SlowDown;
use tokio_util::task::AbortOnDropHandle;

use self::admission::Admission;
pub use self::admission::StagingMode;
pub use self::admission::WriteBehindWatermarks;
use self::root::ConfinedRoot;

/// Closed failures from the staging tier.
///
/// Deliberately carries no path, no root, and no `std::io::Error`: the first two
/// are operator configuration and the third is not `PartialEq`, which the code
/// standards require for testability. An I/O failure is reduced to its
/// [`ErrorKind`] plus a fixed operation label, which is what a caller can act
/// on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WriteBehindError {
    #[error("write-behind staging requires a Unix host")]
    UnsupportedPlatform,
    #[error("write-behind staging root could not be resolved")]
    RootUnresolvable,
    #[error("write-behind staging root is not a directory")]
    RootNotADirectory,
    #[error("write-behind staging root failed its durability probe")]
    RootProbeFailed,
    #[error("write-behind staging root left its recorded filesystem")]
    RootDeviceChanged,
    #[error("a fragment hash for staging was not 32 bytes")]
    HashWidth,
    #[error("a staged epoch was negative")]
    EpochNegative,
    #[error("a stored staged key does not match its derived key")]
    KeyMismatch,
    #[error("a staged path resolved to something that is not a regular file")]
    NotARegularFile,
    #[error("a staged payload exceeds the fragment size threshold")]
    PayloadOversized,
    #[error("write-behind staging I/O failed during {operation}")]
    Io {
        operation: &'static str,
        kind: ErrorKind,
    },
}

impl WriteBehindError {
    pub(crate) fn io(operation: &'static str, error: &std::io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
        }
    }

    /// Map onto the store's error vocabulary.
    ///
    /// The split is between *environmental* failures, which another attempt or
    /// another replica may well serve, and *structural* ones, which mean the
    /// database and the filesystem disagree about what exists. The first are
    /// retryable `SlowDown`; the second are `Internal`, because retrying a
    /// key that does not match its own derivation cannot start matching.
    ///
    /// Nothing here maps to `AddressNotFound`. Absence is not an error in this
    /// module — it is [`StagedRead::Absent`], and only a real `ENOENT` under a
    /// proven-owned root can produce it.
    pub(crate) fn store_error(self) -> StoreError {
        match self {
            Self::UnsupportedPlatform
            | Self::RootUnresolvable
            | Self::RootNotADirectory
            | Self::RootProbeFailed
            | Self::RootDeviceChanged
            | Self::Io { .. } => StoreError::from(SlowDown),
            Self::HashWidth
            | Self::EpochNegative
            | Self::KeyMismatch
            | Self::NotARegularFile
            | Self::PayloadOversized => StoreError::internal(self.to_string()),
        }
    }
}

/// One staged read's answer.
///
/// The three arms are not interchangeable and the type exists to stop them being
/// treated as such; see this module's header.
#[derive(Debug)]
pub enum StagedRead {
    /// Bytes read from a path this process derived and owns.
    Found(Bytes),
    /// A real `ENOENT` under a proven-owned root. The only arm a caller may turn
    /// into a `Missing` publication.
    Absent,
    /// The root is unset, unmounted, on the wrong device, or the read failed for
    /// any other reason. Never evidence of absence.
    Unavailable(WriteBehindError),
}

/// Operator configuration for the staging tier.
#[derive(Debug, Clone)]
pub struct WriteBehindSettings {
    /// The confined staging root. Required; there is no default, because a
    /// defaulted path would stage onto a container's ephemeral layer, which
    /// ADR-00027 rejects outright.
    pub root: PathBuf,
    /// Byte, count and free-space thresholds with hysteresis.
    pub watermarks: WriteBehindWatermarks,
    /// A drain heartbeat older than this selects direct fallback.
    pub drain_stale_after: Duration,
    /// How often the admission sampler refreshes its snapshot. The sampler
    /// exists so `statvfs` never runs on the PUT path.
    pub sample_interval: Duration,
}

/// The staging tier.
///
/// Constructed once per store and shared. Holds the confined root, the admission
/// snapshot, and the sampler task that refreshes it.
pub struct WriteBehindStage {
    root: ConfinedRoot,
    admission: Admission,
    /// Whether this process must assume acknowledged staged bytes exist that it
    /// cannot read.
    ///
    /// **Defaults to `true`, and that is the point.** An unavailable root plus
    /// no evidence about pending data is exactly the case where a fallback to
    /// direct writes would mask inaccessible acknowledged bytes, so the unknown
    /// state must read as unready. Only a positive observation of zero pending
    /// staged rows clears it, through [`WriteBehindStage::note_pending_staged`].
    pending_staged: AtomicBool,
    /// Aborted on drop, so a store that goes away cannot leave a sampler probing
    /// a root it no longer owns. `lore_spawn!` gives the task `LORE_CONTEXT`;
    /// the `AbortOnDropHandle` wrapper gives it the stage's lifetime, which is
    /// the shape `docs/developing/code-standards/tasks.md` requires for a scoped
    /// background task.
    #[expect(dead_code, reason = "held only for its Drop; aborting the sampler")]
    sampler: AbortOnDropHandle<()>,
}

impl WriteBehindStage {
    /// Open and prove the staging root, then start the admission sampler.
    ///
    /// Proving is not probing for existence: [`ConfinedRoot::open`] writes,
    /// fsyncs, renames and unlinks a probe file through the real finalization
    /// path, so a mount that cannot fsync a directory fails here rather than at
    /// the first acknowledged PUT.
    ///
    /// # Errors
    ///
    /// Returns [`WriteBehindError::UnsupportedPlatform`] off Unix, and the
    /// `Root*` variants when the configured root cannot be proven.
    pub fn open(settings: WriteBehindSettings) -> Result<Arc<Self>, WriteBehindError> {
        let root = ConfinedRoot::open(&settings.root)?;
        let admission = Admission::new(settings.watermarks, settings.drain_stale_after);
        let sampler_root = root.clone();
        let sampler_admission = admission.clone();
        let interval = settings.sample_interval;
        let sampler = AbortOnDropHandle::new(lore_base::lore_spawn!(
            "write-behind-admission",
            async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    sampler_admission.observe_root(sampler_root.sample());
                }
            }
        ));
        Ok(Arc::new(Self {
            root,
            admission,
            pending_staged: AtomicBool::new(true),
            sampler,
        }))
    }

    /// The current admission mode.
    #[must_use]
    pub fn mode(&self) -> StagingMode {
        if self.admission.root_unavailable() && self.pending_staged.load(Ordering::Acquire) {
            return StagingMode::Unready;
        }
        self.admission.mode()
    }

    /// The full admission picture, for the composing server's readiness probe
    /// and metrics.
    ///
    /// Its `mode` is [`Self::mode`]'s, not the admission layer's: the
    /// `Unready` upgrade depends on the pending-staged observation, which
    /// admission cannot see because it holds no database resource.
    #[must_use]
    pub fn snapshot(&self) -> AdmissionSnapshot {
        let mut snapshot = self.admission.snapshot();
        snapshot.mode = self.mode();
        snapshot
    }

    /// Record a bounded observation of whether any acknowledged staged data
    /// exists that this cell must be able to read.
    ///
    /// The caller owns the query, because this module holds no database
    /// resource. It must be called repeatedly, not once at startup: a replica
    /// that observed an empty cell at boot and then lost its mount while a peer
    /// staged new fragments would otherwise serve direct writes over
    /// inaccessible acknowledged bytes forever.
    pub fn note_pending_staged(&self, pending: bool) {
        self.pending_staged.store(pending, Ordering::Release);
    }

    /// Feed one drain heartbeat. A stale heartbeat selects direct fallback.
    pub fn note_drain_heartbeat(&self) {
        self.admission.note_drain_heartbeat();
    }

    /// Record staged occupancy after a stage or a reclaim.
    pub fn note_occupancy(&self, staged_bytes: u64, staged_count: u64) {
        self.admission.note_occupancy(staged_bytes, staged_count);
    }

    /// Durably finalize one fragment's payload under the staging root.
    ///
    /// `object_key` is the coordinator's own staged key, taken verbatim from the
    /// `begin_stage` intent. It is not invented here, and it is checked against
    /// the key this module derives from `(hash, epoch)` before anything touches
    /// the filesystem — see [`root::ConfinedRoot::resolve`].
    ///
    /// Returns once the payload is flushed, atomically finalized under its
    /// content-derived identity, and the required directory durability operation
    /// has completed. The caller commits `Staged` only after this returns.
    ///
    /// # Errors
    ///
    /// Returns [`WriteBehindError::PayloadOversized`] above
    /// [`FRAGMENT_SIZE_THRESHOLD`], [`WriteBehindError::KeyMismatch`] when the
    /// coordinator's key is not the derived key, and `Io` for a filesystem
    /// failure.
    pub async fn stage(
        &self,
        hash: &[u8],
        epoch: i64,
        object_key: &str,
        payload: &Bytes,
    ) -> Result<(), WriteBehindError> {
        if payload.len() > FRAGMENT_SIZE_THRESHOLD {
            return Err(WriteBehindError::PayloadOversized);
        }
        let resolved = self.root.resolve(hash, epoch, object_key)?;
        finalize::finalize(&self.root, &resolved, payload).await
    }

    /// Read one staged fragment's bytes.
    ///
    /// Never returns [`StagedRead::Absent`] for an unavailable root; see this
    /// module's header for why that distinction is load-bearing.
    pub async fn read_staged(&self, hash: &[u8], epoch: i64, object_key: &str) -> StagedRead {
        let resolved = match self.root.resolve(hash, epoch, object_key) {
            Ok(resolved) => resolved,
            Err(error) => return StagedRead::Unavailable(error),
        };
        match self.root.read_regular(&resolved).await {
            Ok(Some(bytes)) => StagedRead::Found(bytes),
            // An `ENOENT` is decisive absence only because `read_regular`
            // revalidates the root's device first. Without that check this arm
            // would also cover "the mount went away", which is the demotion
            // hazard this type exists to prevent.
            Ok(None) => StagedRead::Absent,
            Err(error) => StagedRead::Unavailable(error),
        }
    }

    /// The confined root, for the cleanup collaborator.
    pub(crate) fn root(&self) -> &ConfinedRoot {
        &self.root
    }
}

/// One admission snapshot, exposed for the store's metrics and readiness.
pub use self::admission::AdmissionSnapshot;
