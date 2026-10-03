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
use tokio::task::JoinHandle;
use tokio_util::task::AbortOnDropHandle;

use self::admission::Admission;
use self::admission::AdmissionSample;
pub use self::admission::StagingMode;
pub use self::admission::WriteBehindWatermarks;
use self::root::ConfinedRoot;
pub(crate) use self::root::StageIoPath;

/// One reserved staging I/O slot. See [`WriteBehindStage::reserve_io`].
pub(crate) struct StageIoPermit(tokio::sync::OwnedSemaphorePermit);

/// Whether one staging attempt may still withdraw its preparation.
///
/// The durable-effect boundary is the rename into the staged leaf (finalize
/// step 4). Before it, the attempt has placed nothing under `staged/`, so its
/// `PreparingStage` head can be withdrawn and a retry admitted at once. From
/// the moment the finalizer claims the rename, the file may exist, and the
/// preparation is left for the prepare deadline and fenced cleanup as before.
///
/// The finalizer and the withdrawer race through one compare-and-set, so
/// exactly one wins: a withdrawn attempt never renames, and an attempt that
/// may have renamed is never withdrawn. This holds even when the awaiting
/// future is cancelled while its blocking finalizer is still running.
#[derive(Clone, Default)]
pub(crate) struct StageAttempt(Arc<std::sync::atomic::AtomicU8>);

impl StageAttempt {
    const UNPLACED: u8 = 0;
    const PLACING: u8 = 1;
    const WITHDRAWN: u8 = 2;

    /// Claim the rename. `false` when the attempt was already withdrawn.
    pub(crate) fn claim_placement(&self) -> bool {
        self.0
            .compare_exchange(
                Self::UNPLACED,
                Self::PLACING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Release a claimed rename that returned an error, so withdrawal is
    /// possible again. On a remote mount the body can still be in place; see
    /// the release comment in `finalize_blocking` for why that is harmless.
    pub(crate) fn placement_failed(&self) {
        let released = self.0.compare_exchange(
            Self::PLACING,
            Self::UNPLACED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        // Only `claim_placement` enters `PLACING`, and nothing but this call
        // leaves it, so the claim this finalizer took is still held here.
        debug_assert!(
            released.is_ok(),
            "placement_failed without a held rename claim: state {released:?}"
        );
    }

    /// Take the right to withdraw the preparation. `false` once a rename was
    /// claimed, or when another path already withdrew.
    pub(crate) fn withdraw(&self) -> bool {
        self.0
            .compare_exchange(
                Self::UNPLACED,
                Self::WITHDRAWN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

/// How long one admission sample may run before the sampler reports the root
/// unavailable for that tick.
///
/// Deliberately a constant rather than a function of `sample_interval`. The
/// interval is how often an operator wants the picture refreshed; this is how
/// long the tier is willing to say nothing about a mount that has stopped
/// answering. Tying the second to the first would mean a cell configured with a
/// relaxed interval also takes that long to notice a wedge, which is backwards:
/// the slower the sampling, the more each missed sample matters.
const SAMPLE_BUDGET: Duration = Duration::from_secs(5);

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
    /// The attempt was withdrawn before the finalizer claimed its rename, so
    /// nothing was placed. Seen only by a finalizer whose put already failed
    /// or was cancelled.
    #[error("write-behind staging attempt was withdrawn before its rename")]
    Withdrawn,
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
            | Self::Withdrawn
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
    /// How long a PUT waits for a staging I/O slot before it answers
    /// `SlowDown`. Zero refuses at once, the behaviour before row 76's fix.
    pub stage_io_wait: Duration,
}

/// [`WriteBehindSettings::stage_io_wait`]'s default. Long enough for a burst of
/// one commit's fragments to drain through the pool, short against the
/// client's retry backoff, which grows to 10 s.
pub const DEFAULT_STAGE_IO_WAIT: Duration = Duration::from_millis(DEFAULT_STAGE_IO_WAIT_MILLIS);

/// [`DEFAULT_STAGE_IO_WAIT`] in milliseconds, the unit configuration uses.
pub const DEFAULT_STAGE_IO_WAIT_MILLIS: u64 = 1_000;

/// How staging admission reads one capacity observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityVerdict {
    /// Every capacity predicate holds.
    Available,
    /// Only a physical inventory above its ledger bound failed. A walk and a
    /// ledger read are not atomic, so this disagrees transiently while bodies
    /// arrive and leave; it refuses only once it outlives the budget.
    Reconciling,
    /// A predicate that does not clear by waiting failed. It refuses at once.
    Unavailable,
}

/// Staging admission's view of the capacity observations so far.
///
/// The budget is the one readiness gives `capacity_unavailable`: the same
/// `drain_stale_after`, measured from the first sample of an unbroken run that
/// was not `Available`. Before 2026-09-28 one reconciling sample refused
/// staging, so each transient disagreement answered PUTs with `SlowDown` while
/// readiness stayed green (INV-FT F2, WP-115 ledger row 67).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CapacityState {
    /// The latest observation failed a predicate that refuses at once.
    unavailable: bool,
    /// When the current unbroken run of non-`Available` samples began. A hard
    /// sample inside the run keeps its start, as readiness's run does.
    unavailable_since: Option<std::time::Instant>,
}

impl CapacityState {
    fn note(&mut self, verdict: CapacityVerdict, at: std::time::Instant) {
        match verdict {
            CapacityVerdict::Available => *self = Self::default(),
            CapacityVerdict::Reconciling => {
                self.unavailable = false;
                self.unavailable_since.get_or_insert(at);
            }
            CapacityVerdict::Unavailable => {
                self.unavailable = true;
                self.unavailable_since.get_or_insert(at);
            }
        }
    }

    /// A failed observation changes nothing here: it is not evidence that room
    /// returned, and a run already in progress keeps aging toward refusal.
    fn refuses(&self, now: std::time::Instant, budget: Duration) -> bool {
        self.unavailable
            || self
                .unavailable_since
                .is_some_and(|since| now.saturating_duration_since(since) >= budget)
    }
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
    pending_observed: std::sync::Mutex<Option<std::time::Instant>>,
    observation_stale_after: Duration,
    capacity: std::sync::Mutex<CapacityState>,
    min_free_bytes: u64,
    hard_limits: (u64, u64),
    stage_io_wait: Duration,
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
    /// # The first sample is taken here, synchronously, on purpose
    ///
    /// An `Admission` starts with an *unknown* root, and unknown reads as
    /// unavailable. Because [`Self::pending_staged`] also starts `true`, an
    /// unknown root is not merely `DirectFallback` at boot — it is
    /// [`StagingMode::Unready`], which takes `SlowDown` on every PUT. Waiting a
    /// whole sampler interval to leave that state is a window this call can
    /// simply close.
    ///
    /// Doing it here costs nothing new: `open` is already synchronous and has
    /// already canonicalized, created, fsynced and probed this root through the
    /// real finalization path a few lines above. A `stat` plus a `statvfs` on a
    /// mount that has just accepted a write, an fsync and a rename adds no
    /// failure mode the probe did not already take — a mount that would wedge
    /// this sample wedges the probe first.
    ///
    /// After this call the cell is therefore in `DirectFallback`, not `Unready`,
    /// and reaches `Stage` on the first drain heartbeat.
    ///
    /// # Errors
    ///
    /// Returns [`WriteBehindError::UnsupportedPlatform`] off Unix, and the
    /// `Root*` variants when the configured root cannot be proven.
    pub fn open(settings: WriteBehindSettings) -> Result<Arc<Self>, WriteBehindError> {
        let root = ConfinedRoot::open(&settings.root)?;
        let admission = Admission::new(settings.watermarks, settings.drain_stale_after);
        admission.observe_root(root.sample());
        let sampler_root = root.clone();
        let sampler_admission = admission.clone();
        let interval = settings.sample_interval;
        let sampler = AbortOnDropHandle::new(lore_base::lore_spawn!(
            "write-behind-admission",
            async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                // `interval`'s first tick fires immediately. `open` has just
                // sampled this root synchronously, so that tick would re-run
                // the same two syscalls for the same answer; consume it.
                ticker.tick().await;
                let mut in_flight = None;
                loop {
                    ticker.tick().await;
                    let sample = sample_within_budget(&mut in_flight, SAMPLE_BUDGET, || {
                        let root = sampler_root.clone();
                        lore_base::lore_spawn_blocking!("write-behind-sample", move || root
                            .sample())
                    })
                    .await;
                    sampler_admission.observe_root(sample);
                }
            }
        ));
        Ok(Arc::new(Self {
            root,
            admission,
            pending_staged: AtomicBool::new(true),
            pending_observed: std::sync::Mutex::new(None),
            observation_stale_after: settings.drain_stale_after,
            capacity: std::sync::Mutex::new(CapacityState::default()),
            min_free_bytes: settings.watermarks.min_free_bytes,
            hard_limits: (
                settings.watermarks.hard_bytes,
                settings.watermarks.hard_count,
            ),
            stage_io_wait: settings.stage_io_wait,
            sampler,
        }))
    }

    /// The current admission mode.
    #[must_use]
    pub fn mode(&self) -> StagingMode {
        let fresh = self
            .pending_observed
            .lock()
            .ok()
            .and_then(|time| *time)
            .is_some_and(|time| time.elapsed() < self.observation_stale_after);
        let capacity_refused = self
            .capacity
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .refuses(std::time::Instant::now(), self.observation_stale_after);
        staging_mode(
            &self.admission,
            fresh,
            self.pending_staged.load(Ordering::Acquire),
            capacity_refused,
        )
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
        if let Ok(mut time) = self.pending_observed.lock() {
            *time = Some(std::time::Instant::now());
        }
    }

    pub fn note_observation_unknown(&self) {
        self.pending_staged.store(true, Ordering::Release);
        if let Ok(mut time) = self.pending_observed.lock() {
            *time = None;
        }
    }

    pub(crate) fn note_capacity(&self, verdict: CapacityVerdict) {
        self.capacity
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .note(verdict, std::time::Instant::now());
    }

    pub(crate) fn min_free_bytes(&self) -> u64 {
        self.min_free_bytes
    }

    pub(crate) fn hard_limits(&self) -> (u64, u64) {
        self.hard_limits
    }

    pub fn note_worker_stopped(&self) {
        self.admission.note_worker_stopped();
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
        let permit = self.reserve_io().await?;
        self.stage_reserved(
            permit,
            &StageAttempt::default(),
            hash,
            epoch,
            object_key,
            payload,
        )
        .await
    }

    /// Reserve the I/O slot one [`Self::stage_reserved`] will use.
    ///
    /// Take it before `begin_stage`. A refusal after `begin_stage` leaves a
    /// live `PreparingStage` head that fences every retry of the hash until
    /// its preparation deadline passes. Waits up to
    /// [`WriteBehindSettings::stage_io_wait`] for a slot; a burst then queues
    /// instead of taking `SlowDown` and the client's retry backoff.
    pub(crate) async fn reserve_io(&self) -> Result<StageIoPermit, WriteBehindError> {
        self.root
            .io_permit_within(StageIoPath::Put, self.stage_io_wait)
            .await
            .map(StageIoPermit)
    }

    /// [`Self::stage`] with a slot from [`Self::reserve_io`]. The rename is
    /// skipped when `attempt` was withdrawn first; see [`StageAttempt`].
    pub(crate) async fn stage_reserved(
        &self,
        permit: StageIoPermit,
        attempt: &StageAttempt,
        hash: &[u8],
        epoch: i64,
        object_key: &str,
        payload: &Bytes,
    ) -> Result<(), WriteBehindError> {
        if payload.len() > FRAGMENT_SIZE_THRESHOLD {
            return Err(WriteBehindError::PayloadOversized);
        }
        let resolved = self.root.resolve(hash, epoch, object_key)?;
        finalize::finalize_reserved(permit.0, attempt.clone(), &self.root, &resolved, payload).await
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

/// Take one admission sample without running it on a runtime worker, and
/// without letting a wedged mount accumulate blocking threads.
///
/// `ConfinedRoot::sample` is `stat` then `statvfs`, both blocking FFI. Running
/// it inline in the sampler task would mean that a hung mount — the exact
/// condition the sampler exists to report — parks a Tokio worker instead of
/// producing [`AdmissionSample::RootUnavailable`]. So it goes to the blocking
/// pool, and the wait for it is bounded.
///
/// # Why the handle is carried across ticks
///
/// A blocking task cannot be cancelled. Dropping or aborting its
/// [`JoinHandle`] stops this task waiting; it does not unpark the thread
/// sitting inside `statvfs`. Spawning a fresh sample on every tick would
/// therefore leak one pool thread per tick for as long as the mount stays
/// wedged, and the blocking pool is bounded — the tier would eventually starve
/// every other blocking caller in the process, including the staged read path.
///
/// `in_flight` is that defence. A new task is spawned only when the slot is
/// empty, so **N consecutive wedged samples cost exactly one blocked thread,
/// not N**. Each of those N ticks still reports `RootUnavailable`, which is
/// the answer a wedged mount deserves, and the tick that finally sees the task
/// finish observes its real result and frees the slot.
///
/// A panicked or cancelled join is `RootUnavailable` too, following
/// `root.rs`'s `join` helper: a sample that did not complete is not evidence
/// that the root is fine.
async fn sample_within_budget<F>(
    in_flight: &mut Option<JoinHandle<AdmissionSample>>,
    budget: Duration,
    spawn_sample: F,
) -> AdmissionSample
where
    F: FnOnce() -> JoinHandle<AdmissionSample>,
{
    let handle = in_flight.get_or_insert_with(spawn_sample);
    let outcome = tokio::time::timeout(budget, handle).await;
    match outcome {
        Ok(Ok(sample)) => {
            in_flight.take();
            sample
        }
        Ok(Err(_)) => {
            in_flight.take();
            AdmissionSample::RootUnavailable
        }
        // Still running. Keep the handle so the next tick waits on this task
        // rather than spawning a second one.
        Err(_) => AdmissionSample::RootUnavailable,
    }
}

/// [`WriteBehindStage::mode`]'s decision over values the stage has already
/// read. Split out so the decision is testable without a Unix staging root.
fn staging_mode(
    admission: &Admission,
    pending_fresh: bool,
    pending_staged: bool,
    capacity_refused: bool,
) -> StagingMode {
    if admission.root_unavailable() && (!pending_fresh || pending_staged) {
        return StagingMode::Unready;
    }
    if capacity_refused {
        return StagingMode::Refuse;
    }
    admission.mode()
}

/// One admission snapshot, exposed for the store's metrics and readiness.
pub use self::admission::AdmissionSnapshot;

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    use super::*;

    /// Budget short enough that an unanswered sample is decided quickly.
    const SHORT_BUDGET: Duration = Duration::from_millis(100);
    /// Budget long enough that an answered sample is never cut off by it.
    const GENEROUS_BUDGET: Duration = Duration::from_secs(10);
    /// How long a stand-in sample refuses to answer before giving up.
    ///
    /// Bounded rather than infinite on purpose: a regression that ran the
    /// sample inline must fail an assertion, not hang the test binary.
    const WEDGE_LIMIT: Duration = Duration::from_secs(5);

    /// A sample that does not answer until `released` is set — the shape of a
    /// mount that has stopped responding.
    fn wedged_sample(
        released: &Arc<AtomicBool>,
        spawns: &Arc<AtomicUsize>,
    ) -> JoinHandle<AdmissionSample> {
        spawns.fetch_add(1, Ordering::Relaxed);
        let released = Arc::clone(released);
        lore_base::lore_spawn_blocking!("write-behind-sample-test", move || {
            let deadline = Instant::now() + WEDGE_LIMIT;
            while !released.load(Ordering::Acquire) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            AdmissionSample::Reachable { free_bytes: 42 }
        })
    }

    fn staging_admission() -> Admission {
        let admission = Admission::new(
            WriteBehindWatermarks {
                low_bytes: 100,
                high_bytes: 200,
                hard_bytes: 300,
                low_count: 10,
                high_count: 20,
                hard_count: 30,
                min_free_bytes: 50,
            },
            Duration::from_secs(60),
        );
        admission.observe_root(AdmissionSample::Reachable { free_bytes: 1_000 });
        admission.note_drain_heartbeat();
        admission
    }

    /// Replaces the documented gap `documented_gap_one_false_capacity_sample_
    /// refuses_staging_with_no_budget` (WP-115 ledger row 67, KV ruling
    /// 2026-09-28). A reconciling sample keeps staging until its run outlives
    /// the budget readiness uses; an available sample clears the run at once.
    #[test]
    fn a_reconciling_capacity_run_refuses_staging_only_once_it_outlives_the_budget() {
        let admission = staging_admission();
        let budget = Duration::from_secs(5);
        let start = Instant::now();
        let mut capacity = CapacityState::default();
        let mode = |capacity: &CapacityState, now: Instant| {
            staging_mode(&admission, true, false, capacity.refuses(now, budget))
        };
        assert_eq!(mode(&capacity, start), StagingMode::Stage);

        capacity.note(CapacityVerdict::Reconciling, start);
        assert_eq!(mode(&capacity, start), StagingMode::Stage, "one sample");
        capacity.note(CapacityVerdict::Reconciling, start + Duration::from_secs(4));
        assert_eq!(
            mode(&capacity, start + Duration::from_millis(4_999)),
            StagingMode::Stage,
            "the run is measured from its first sample, not its latest"
        );
        assert_eq!(
            mode(&capacity, start + budget),
            StagingMode::Refuse,
            "a run that outlives the budget refuses"
        );

        capacity.note(CapacityVerdict::Available, start + Duration::from_secs(6));
        assert_eq!(
            mode(&capacity, start + Duration::from_secs(6)),
            StagingMode::Stage,
            "an available sample clears the run at once"
        );
        capacity.note(CapacityVerdict::Reconciling, start + Duration::from_secs(7));
        assert_eq!(
            mode(&capacity, start + Duration::from_millis(11_999)),
            StagingMode::Stage,
            "a new run gets a fresh budget"
        );
    }

    /// A predicate that waiting does not clear refuses on its first sample, and
    /// the next available sample restores staging at once.
    #[test]
    fn a_hard_capacity_sample_refuses_staging_at_once() {
        let admission = staging_admission();
        let budget = Duration::from_secs(5);
        let now = Instant::now();
        let mut capacity = CapacityState::default();
        capacity.note(CapacityVerdict::Unavailable, now);
        assert_eq!(
            staging_mode(&admission, true, false, capacity.refuses(now, budget)),
            StagingMode::Refuse
        );
        capacity.note(CapacityVerdict::Available, now);
        assert_eq!(
            staging_mode(&admission, true, false, capacity.refuses(now, budget)),
            StagingMode::Stage
        );
    }

    /// WP-115 row 78, end to end at the admission level: a walk bound by the
    /// charge counters (`lore_fragment_provider::WalkLedgerBound`) feeding the
    /// same capacity run staging admission keeps. One observation per second,
    /// a 5 s budget, a ledger steady at 100 files.
    ///
    /// Turnover: each walk counts 5 files more than any read held (released
    /// after the walk counted them, or charged before the walk reached them),
    /// while 10 are charged and 10 released per second. Before row 78 the
    /// counters did not exist and that refused staging after 5 s; now it never
    /// does. A real orphan, one file no reservation charged, still refuses once
    /// its run outlives the budget, and not before.
    #[test]
    fn turnover_never_refuses_staging_and_an_orphan_refuses_within_budget() {
        use lore_fragment_provider::WalkLedgerBound;
        use lore_fragment_provider::WalkLedgerRead;

        let admission = staging_admission();
        let budget = Duration::from_secs(5);
        let start = Instant::now();
        // `charge_per_tick` charged and as many released each second; each
        // walk counts `walk` files. Returns the first second staging refused.
        let run = |charge_per_tick: u64, walk: u64, counters: bool| {
            let mut bound = WalkLedgerBound::<u64>::default();
            let mut capacity = CapacityState::default();
            let mut charged = 1_000;
            bound.record_ledger(WalkLedgerRead {
                live: (0, 100),
                charged: (0, charged),
            });
            for tick in 1..=12_u64 {
                let before = bound.last_ledger();
                bound.record_step(before, true, Some(walk));
                if counters {
                    charged += charge_per_tick;
                }
                bound.record_ledger(WalkLedgerRead {
                    live: (0, 100),
                    charged: (0, charged),
                });
                let (physical, (_, files)) = bound.current().expect("a bound walk");
                let at = start + Duration::from_secs(tick);
                let verdict = if physical > files {
                    CapacityVerdict::Reconciling
                } else {
                    CapacityVerdict::Available
                };
                capacity.note(verdict, at);
                if staging_mode(&admission, true, false, capacity.refuses(at, budget))
                    == StagingMode::Refuse
                {
                    return Some(tick);
                }
            }
            None
        };
        assert_eq!(
            run(10, 105, false),
            Some(6),
            "without the counters, turnover alone refused staging past the budget"
        );
        assert_eq!(run(10, 105, true), None, "turnover never refuses");
        assert_eq!(
            run(0, 101, true),
            Some(6),
            "an orphan with no charge in its window refuses once its run outlives the budget"
        );
        assert_eq!(
            run(10, 111, true),
            Some(6),
            "an orphan larger than one walk's charges refuses under load too"
        );
    }

    /// A hard sample inside a reconciling run keeps the run's start, so the
    /// reconciling samples after it do not get a fresh budget.
    #[test]
    fn a_hard_sample_inside_a_run_keeps_the_run_start() {
        let budget = Duration::from_secs(5);
        let start = Instant::now();
        let mut capacity = CapacityState::default();
        capacity.note(CapacityVerdict::Reconciling, start);
        capacity.note(CapacityVerdict::Unavailable, start + Duration::from_secs(1));
        capacity.note(CapacityVerdict::Reconciling, start + Duration::from_secs(2));
        assert!(!capacity.refuses(start + Duration::from_millis(4_999), budget));
        assert!(capacity.refuses(start + budget, budget));
    }

    #[tokio::test]
    async fn a_sample_that_does_not_answer_degrades_to_root_unavailable() {
        let released = Arc::new(AtomicBool::new(false));
        let spawns = Arc::new(AtomicUsize::new(0));
        let mut in_flight = None;

        let started = Instant::now();
        let sample = sample_within_budget(&mut in_flight, SHORT_BUDGET, || {
            wedged_sample(&released, &spawns)
        })
        .await;
        let elapsed = started.elapsed();

        assert_eq!(sample, AdmissionSample::RootUnavailable);
        // The point of the whole change: the wait is bounded and the sampler
        // task stayed on the runtime. A sample run inline on the worker would
        // take the full `WEDGE_LIMIT` and report `Reachable`.
        assert!(
            elapsed < WEDGE_LIMIT,
            "a wedged sample must be decided by the budget, not by the mount; took {elapsed:?}"
        );
        assert!(
            in_flight.is_some(),
            "the unfinished task must be kept, not dropped and forgotten"
        );
        released.store(true, Ordering::Release);
    }

    #[tokio::test]
    async fn consecutive_wedged_samples_never_spawn_a_second_blocking_task() {
        let released = Arc::new(AtomicBool::new(false));
        let spawns = Arc::new(AtomicUsize::new(0));
        let mut in_flight = None;

        for tick in 1..=3 {
            let sample = sample_within_budget(&mut in_flight, SHORT_BUDGET, || {
                wedged_sample(&released, &spawns)
            })
            .await;
            assert_eq!(
                sample,
                AdmissionSample::RootUnavailable,
                "tick {tick} of a wedged mount must report the root unavailable"
            );
        }

        // The defence that matters over time. A blocking task cannot be
        // cancelled, so one spawn per tick would park one pool thread per tick
        // until the mount recovers, starving the shared core blocking pool.
        assert_eq!(
            spawns.load(Ordering::Relaxed),
            1,
            "three wedged ticks must cost exactly one blocked thread"
        );
        released.store(true, Ordering::Release);
    }

    #[tokio::test]
    async fn the_tick_after_a_wedge_clears_observes_the_real_sample() {
        let released = Arc::new(AtomicBool::new(false));
        let spawns = Arc::new(AtomicUsize::new(0));
        let mut in_flight = None;

        let wedged = sample_within_budget(&mut in_flight, SHORT_BUDGET, || {
            wedged_sample(&released, &spawns)
        })
        .await;
        assert_eq!(wedged, AdmissionSample::RootUnavailable);

        released.store(true, Ordering::Release);
        let recovered = sample_within_budget(&mut in_flight, GENEROUS_BUDGET, || {
            wedged_sample(&released, &spawns)
        })
        .await;
        assert_eq!(
            recovered,
            AdmissionSample::Reachable { free_bytes: 42 },
            "the tick that finally sees the task finish must observe its real answer"
        );
        assert_eq!(
            spawns.load(Ordering::Relaxed),
            1,
            "the recovering tick must wait on the existing task, not spawn another"
        );
        assert!(
            in_flight.is_none(),
            "a finished task must free the slot for the next tick"
        );

        let next = sample_within_budget(&mut in_flight, GENEROUS_BUDGET, || {
            wedged_sample(&released, &spawns)
        })
        .await;
        assert_eq!(next, AdmissionSample::Reachable { free_bytes: 42 });
        assert_eq!(
            spawns.load(Ordering::Relaxed),
            2,
            "with the slot free the next tick samples again"
        );
    }

    /// The withdraw/rename boundary as a pure state machine, so it runs on
    /// every platform rather than only behind the Unix staging root.
    #[test]
    fn stage_attempt_lets_exactly_one_of_rename_and_withdraw_win() {
        // A withdrawal first: the rename is refused, and so is a second
        // withdrawal.
        let withdrawn = StageAttempt::default();
        assert!(withdrawn.withdraw());
        assert!(
            !withdrawn.claim_placement(),
            "a withdrawn attempt never renames"
        );
        assert!(!withdrawn.withdraw(), "only one path withdraws");

        // A claimed rename first: withdrawal is refused while it is held.
        let placing = StageAttempt::default();
        assert!(placing.claim_placement());
        assert!(
            !placing.withdraw(),
            "an attempt that may have renamed is kept"
        );
        assert!(!placing.claim_placement(), "the claim is not re-entrant");

        // A rename that failed releases its claim, and withdrawal wins again.
        placing.placement_failed();
        assert!(placing.withdraw());
        assert!(!placing.claim_placement());

        // A clone shares the state: the cancellation guard and the finalizer
        // hold clones of one attempt.
        let shared = StageAttempt::default();
        let finalizer = shared.clone();
        assert!(finalizer.claim_placement());
        assert!(!shared.withdraw());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "placement_failed without a held rename claim")]
    fn stage_attempt_release_without_a_claim_is_a_bug() {
        let attempt = StageAttempt::default();
        assert!(attempt.withdraw());
        attempt.placement_failed();
    }

    #[test]
    fn a_withdrawn_attempt_is_retryable_backpressure() {
        assert!(WriteBehindError::Withdrawn.store_error().is_slow_down());
    }
}
