// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The durable invalidation receiver: one task per replica.
//!
//! # The bootstrap is an ordered proof, not a startup sequence
//!
//! Every step exists to close one way a receiver could declare itself caught
//! up without being caught up:
//!
//! | Step | What it rules out |
//! | --- | --- |
//! | `join` at the read membership version | two replicas sharing one generation |
//! | capture the stream position | a baseline taken against an epoch nothing recorded |
//! | record the capture before the baseline | a live edge sampled after the baseline, so events published during it fall outside the drained interval |
//! | authoritative baseline | a belief formed under a previous epoch surviving into this one |
//! | drain from the captured position | the interval between the capture and the baseline going unread |
//! | persist the frontier and blockers | a readiness claim with no checkpoint behind it |
//! | readiness compare-and-set | a placement that moved while all of the above was happening |
//!
//! The last one is why the order matters more than any single step. Step C's
//! `readiness_cas` rereads the authoritative identity and epoch and succeeds
//! only when both still equal the captured values, so a reset at *any* of the
//! four boundaries the contract names — capture-to-baseline,
//! baseline-to-drain, drain-to-CAS, or racing the CAS itself — retires this
//! generation. The receiver's response to all four is identical and is the
//! only response there is: start a new generation with a new capture, a fresh
//! baseline, and a fresh drain. It never resumes an impossible old epoch.
//!
//! # The six steady-state outcomes
//!
//! | Delivery | Action | Acknowledged |
//! | --- | --- | --- |
//! | next version | apply, record the version | yes |
//! | duplicate | nothing | yes |
//! | stale | nothing | yes |
//! | gap or incomparable | authoritative refetch of that repository | yes, after the refetch |
//! | transient failure | back off, fail lag readiness | **no** |
//! | poison | park, fail readiness | **no** |
//!
//! The two that do not acknowledge are the load-bearing ones. An unresolved
//! poison or an unacknowledged transient failure stalls the contiguous
//! frontier by construction (see [`super::frontier`]), which is what stops
//! WP-119's reaper from releasing a row this receiver never consumed.
//!
//! # Why an application failure is not modelled
//!
//! [`InvalidationTarget`]'s methods are infallible. An invalidation instructs
//! the process to *discard* a belief, and a discard that could fail would
//! leave the process holding state it has been told is wrong. A target that
//! needs I/O evicts synchronously and refreshes lazily, so the transient class
//! here covers the stream and the store only.
//!
//! # Shutdown
//!
//! Cancellation stops the loop at the next boundary, reports a final
//! checkpoint if there is anything unreported, and returns. It never
//! acknowledges to make the shutdown tidy: an event accepted but not applied
//! is redelivered to the next generation, which is exactly right.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use lore_postgres::domain::outbox::CheckpointOutcome;
use lore_postgres::domain::outbox::CheckpointReport;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::VersionOrder;
use lore_postgres::domain::outbox::membership::CapturedPosition;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::apply::AggregateKey;
use super::apply::AppliedVersions;
use super::apply::InvalidationTarget;
use super::apply::decode_durable_delivery;
use super::apply::to_stored;
use super::config::ReceiverConfig;
use super::config::RemoteNotificationConfig;
use super::frontier::AckFrontier;
use super::metrics;
use super::stream::CaptureRequest;
use super::stream::CapturedStreamPosition;
use super::stream::DeliveredEnvelope;
use super::stream::DurableStreamSource;
use super::stream::StreamDelivery;
use super::stream::StreamError;
use super::stream::StreamPlacement;
use crate::plugins::PluginError;

/// The closed readiness-reason set.
///
/// `&'static str` from a fixed list, for the same reason the metric labels
/// are: a reason built by interpolation would carry a repository or an event
/// identifier into a readiness surface that is scraped.
pub const REASON_NOT_STARTED: &str = "not_started";
/// Bootstrapping: a generation exists but has not passed its readiness CAS.
pub const REASON_BOOTSTRAPPING: &str = "bootstrapping";
/// The contiguous frontier is further behind than the configured threshold.
pub const REASON_LAG_THRESHOLD: &str = "lag_threshold_exceeded";
/// The durable stream could not be read.
pub const REASON_STREAM_UNAVAILABLE: &str = "stream_unavailable";
/// The receiver store could not be read or written.
pub const REASON_STORE_UNAVAILABLE: &str = "store_unavailable";
/// At least one event is parked and unresolved.
pub const REASON_POISON_PARKED: &str = "poison_parked";
/// The authoritative placement moved; this generation is retired.
pub const REASON_PLACEMENT_MOVED: &str = "placement_moved";
/// The cell has no authoritative placement recorded yet.
pub const REASON_NO_CURRENT_PLACEMENT: &str = "no_current_placement";
/// The configuration was rejected by the durable store.
pub const REASON_CONFIGURATION_REJECTED: &str = "configuration_rejected";
/// The task was cancelled.
pub const REASON_STOPPED: &str = "stopped";

/// Bounded retries of one stream read inside a single drain.
///
/// A blip mid-drain must not cost a generation: allocating a new one on every
/// transient failure would burn the membership counter and force a fresh
/// baseline for a broker that was briefly busy. After this many, the bootstrap
/// restarts, which is the conservative answer.
const DRAIN_READ_RETRIES: usize = 5;

/// The three ways one bootstrap attempt can fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapFailure {
    /// Something was briefly unavailable. Retry the whole bootstrap after a
    /// backoff; the readiness reason says which side was unavailable.
    Transient(&'static str),
    /// This generation cannot proceed and has been (or must be treated as)
    /// retired. Start a new one.
    Retired(&'static str),
    /// The durable store refused the request itself. A configuration fault,
    /// not a transient one, so it is logged at error and retried slowly rather
    /// than spun on.
    Rejected(String),
}

impl BootstrapFailure {
    /// The readiness reason this failure presents.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Transient(reason) | Self::Retired(reason) => reason,
            Self::Rejected(_) => REASON_CONFIGURATION_REJECTED,
        }
    }
}

/// What one steady-state step did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// Nothing was pending.
    Idle,
    /// One event was applied and acknowledged.
    Applied,
    /// One event was a duplicate and was acknowledged as a no-op.
    Duplicate,
    /// One event was stale and was acknowledged as a no-op.
    Stale,
    /// A gap or an incomparable version forced an authoritative refetch, which
    /// completed before the acknowledgement.
    Refetched,
    /// One event was parked. Not acknowledged; readiness is false.
    Parked(&'static str),
    /// The stream or the store was briefly unavailable. Nothing was
    /// acknowledged.
    Transient(&'static str),
    /// The authoritative placement moved. This generation is retired.
    Retired(&'static str),
}

impl StepOutcome {
    /// True when this outcome acknowledged the delivery.
    pub fn acknowledged(&self) -> bool {
        matches!(
            self,
            Self::Applied | Self::Duplicate | Self::Stale | Self::Refetched
        )
    }
}

/// The receiver's readiness facet.
///
/// Deliberately its own handle rather than a write into
/// `event_relay::readiness`: that module's receiver facet reports whether the
/// consumer-safety **evaluator** proved a verdict, which is a different
/// question from whether **this replica's** receiver is caught up. `SCHEMA-119`
/// aggregates the two. Keeping them separate means a receiver that is behind
/// cannot be masked by an evaluator that has nothing to evaluate.
#[derive(Debug)]
pub struct ReceiverReadiness {
    state: Mutex<ReceiverReadinessSnapshot>,
}

/// One reading of the receiver facet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverReadinessSnapshot {
    /// True only when a generation is ready, caught up inside its threshold,
    /// and carrying no unresolved blocker.
    pub ready: bool,
    /// Why it is false, from the closed set above. `None` when ready.
    pub reason: Option<&'static str>,
    /// Distance from the contiguous frontier to the highest sequence seen.
    pub lag: u64,
    /// The generation currently running, once one has been allocated.
    pub generation: Option<i64>,
    /// Unresolved gaps plus parked events.
    pub blockers: usize,
}

impl Default for ReceiverReadiness {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiverReadiness {
    /// A handle that is not ready, because nothing has started.
    ///
    /// Fail-closed on silence: a receiver that never runs must not read as
    /// ready, so the initial state is false with a reason rather than true.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ReceiverReadinessSnapshot {
                ready: false,
                reason: Some(REASON_NOT_STARTED),
                lag: 0,
                generation: None,
                blockers: 0,
            }),
        }
    }

    /// The current reading.
    pub fn snapshot(&self) -> ReceiverReadinessSnapshot {
        self.lock().clone()
    }

    /// True when the facet is ready.
    pub fn is_ready(&self) -> bool {
        self.lock().ready
    }

    fn set_blocked(&self, reason: &'static str, generation: Option<i64>) {
        let mut state = self.lock();
        state.ready = false;
        state.reason = Some(reason);
        state.generation = generation;
    }

    fn set_from_session(&self, session: &ReceiverSession, threshold: u64) {
        let lag = session.frontier.lag();
        let blockers = session.frontier.gaps().len() + session.frontier.poison().len();
        let reason = if !session.ready {
            Some(REASON_BOOTSTRAPPING)
        } else if !session.frontier.poison().is_empty() || session.frontier.is_saturated() {
            Some(REASON_POISON_PARKED)
        } else if lag > threshold {
            Some(REASON_LAG_THRESHOLD)
        } else {
            None
        };
        let mut state = self.lock();
        state.ready = reason.is_none();
        state.reason = reason;
        state.lag = lag;
        state.generation = Some(session.membership_generation);
        state.blockers = blockers;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ReceiverReadinessSnapshot> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// The three collaborators one receiver runs against.
#[derive(Clone)]
pub struct ReceiverRuntime {
    /// WP-119's Step C membership and checkpoint projection.
    pub store: Arc<dyn super::receiver_store::ReceiverStore>,
    /// The durable stream. See [`super::stream`]'s `BLOCKED(WP-111)` note for
    /// why this is a trait today.
    pub stream: Arc<dyn DurableStreamSource>,
    /// The process-local derived state invalidations act on.
    pub target: Arc<dyn InvalidationTarget>,
}

impl std::fmt::Debug for ReceiverRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiverRuntime")
            .field("store", &self.store)
            .field("stream", &self.stream)
            .field("target", &self.target)
            .finish()
    }
}

/// One receiver generation's live state.
///
/// Every field is generation-scoped, including the applied-version map: a new
/// generation takes an authoritative baseline, so inheriting a predecessor's
/// beliefs would defeat the step that exists to discard them.
#[derive(Debug)]
pub struct ReceiverSession {
    /// The generation Step C allocated.
    pub membership_generation: i64,
    /// The membership version the last accepted write saw.
    pub membership_version: i64,
    /// The position this generation is pinned to.
    pub captured: CapturedStreamPosition,
    /// True once the readiness CAS succeeded.
    pub ready: bool,
    frontier: AckFrontier,
    applied: AppliedVersions,
    events_since_checkpoint: u64,
    last_checkpoint: Instant,
    reported_frontier: Option<i64>,
}

impl ReceiverSession {
    /// The contiguous frontier this generation has proved.
    pub fn contiguous_frontier(&self) -> i64 {
        self.frontier.contiguous_frontier()
    }

    /// How far behind the highest seen sequence the frontier is.
    pub fn lag(&self) -> u64 {
        self.frontier.lag()
    }

    /// True when a gap or a parked event blocks advancement.
    pub fn has_blockers(&self) -> bool {
        self.frontier.has_blockers()
    }

    /// The checkpoint report this generation would send right now.
    pub fn checkpoint_report(&self, receiver_identity: &str) -> CheckpointReport {
        CheckpointReport {
            stream_identity: self.captured.placement.stream_identity.clone(),
            stream_epoch: self.captured.placement.stream_epoch,
            receiver_identity: receiver_identity.to_string(),
            membership_generation: self.membership_generation,
            membership_version: self.membership_version,
            contiguous_frontier: self.frontier.contiguous_frontier(),
            gaps: self.frontier.gaps(),
            poison: self.frontier.poison(),
        }
    }

    fn needs_checkpoint(&self, config: &ReceiverConfig) -> bool {
        if self.reported_frontier == Some(self.frontier.contiguous_frontier())
            && self.events_since_checkpoint == 0
        {
            return false;
        }
        self.events_since_checkpoint >= config.checkpoint_every_events
            || self.last_checkpoint.elapsed() >= config.checkpoint_interval
    }
}

/// The durable invalidation receiver.
pub struct DurableReceiver {
    cell_id: String,
    receiver: ReceiverConfig,
    payload_version_min: u32,
    payload_version_max: u32,
    backoff_initial: Duration,
    backoff_max: Duration,
    runtime: ReceiverRuntime,
    readiness: Arc<ReceiverReadiness>,
    cancel: CancellationToken,
}

impl std::fmt::Debug for DurableReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableReceiver")
            .field("cell_id", &self.cell_id)
            .field("receiver_identity", &self.receiver.membership_identity)
            .finish_non_exhaustive()
    }
}

impl DurableReceiver {
    /// Build a receiver from a validated plugin configuration.
    ///
    /// Returns `None` when the cell declares no required receiver, which is
    /// every cell that has not been cut over.
    pub fn new(config: &RemoteNotificationConfig, runtime: ReceiverRuntime) -> Option<Self> {
        let receiver = config.receiver.clone()?;
        Some(Self {
            cell_id: config.cell_id.clone(),
            receiver,
            payload_version_min: config.contract.durable_payload_version_min,
            payload_version_max: config.contract.durable_payload_version_max,
            backoff_initial: config.retry.initial_backoff,
            backoff_max: config.retry.max_backoff,
            runtime,
            readiness: Arc::new(ReceiverReadiness::new()),
            cancel: CancellationToken::new(),
        })
    }

    /// The readiness facet this receiver publishes.
    pub fn readiness(&self) -> Arc<ReceiverReadiness> {
        Arc::clone(&self.readiness)
    }

    /// A handle that stops the loop at its next boundary.
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// The receiver identity this task binds to.
    pub fn receiver_identity(&self) -> &str {
        &self.receiver.membership_identity
    }

    /// Run until cancelled.
    ///
    /// Never returns `Err`. The server's `JoinSet` treats a returned error as
    /// a failed plugin task and logs it as a fault; a receiver that cannot
    /// reach its broker is not a fault, it is a false readiness facet, and
    /// conflating the two would take down a cell that is serving storage
    /// perfectly well.
    ///
    /// # Errors
    /// None in practice. The signature matches
    /// [`crate::plugins::NotificationReceiver`].
    pub async fn run(self) -> Result<(), PluginError> {
        info!(
            cell_id = %self.cell_id,
            receiver_identity = %self.receiver.membership_identity,
            "durable invalidation receiver starting"
        );
        let mut backoff = self.backoff_initial;

        while !self.cancel.is_cancelled() {
            match self.bootstrap().await {
                Ok(mut session) => {
                    backoff = self.backoff_initial;
                    self.steady_state(&mut session).await;
                    // The steady state returns only on cancellation or on a
                    // retirement, and a final checkpoint is attempted in both
                    // cases: an unreported frontier is retention a successor
                    // has to re-prove.
                    self.final_checkpoint(&mut session).await;
                    if self.cancel.is_cancelled() {
                        break;
                    }
                }
                Err(failure) => {
                    self.readiness.set_blocked(failure.reason(), None);
                    match &failure {
                        BootstrapFailure::Rejected(message) => error!(
                            cell_id = %self.cell_id,
                            receiver_identity = %self.receiver.membership_identity,
                            %message,
                            "durable receiver bootstrap was rejected by the durable store"
                        ),
                        other => debug!(
                            cell_id = %self.cell_id,
                            receiver_identity = %self.receiver.membership_identity,
                            reason = other.reason(),
                            "durable receiver bootstrap did not complete"
                        ),
                    }
                    metrics::record_receiver_bootstrap(failure.reason());
                    self.sleep(backoff).await;
                    backoff = (backoff * 2).min(self.backoff_max);
                }
            }
        }

        self.readiness.set_blocked(REASON_STOPPED, None);
        info!(
            cell_id = %self.cell_id,
            receiver_identity = %self.receiver.membership_identity,
            "durable invalidation receiver stopped"
        );
        Ok(())
    }

    /// Run the contract's ordered bootstrap once.
    ///
    /// # Errors
    /// [`BootstrapFailure`] naming which boundary refused and whether the
    /// generation survives.
    pub async fn bootstrap(&self) -> Result<ReceiverSession, BootstrapFailure> {
        let identity = self.receiver.membership_identity.as_str();

        // 1. Read the membership version this join will compare against. The
        //    reset fence is deliberately NOT a reason to stop here: a fence
        //    stands precisely because a replacement generation is required,
        //    and this bootstrap is that replacement. Only the readiness CAS
        //    clears it, and only after a fresh checkpoint.
        let snapshot = self
            .runtime
            .store
            .read_membership()
            .await
            .map_err(|_| BootstrapFailure::Transient(REASON_STORE_UNAVAILABLE))?;
        let Some(snapshot) = snapshot else {
            return Err(BootstrapFailure::Rejected(format!(
                "cell {} has no outbox membership state; SCHEMA-119's install has not run here",
                self.cell_id
            )));
        };
        if snapshot.reset_in_progress {
            debug!(
                cell_id = %self.cell_id,
                "a stream reset fence stands; this generation is the required replacement"
            );
        }
        let cell_membership_version = snapshot.state.membership_version;

        // The placement this receiver will assert to the gateway. Both are
        // required: A-24's `ConsumeRequestV1` carries the identity, epoch, and
        // revision the receiver believes authoritative, so a disagreement is
        // refused at the capture rather than discovered at the readiness
        // compare-and-set several steps later. A cell whose placement is not
        // set yet has not finished its own install, which resolves without
        // this receiver doing anything, so it waits rather than failing.
        let (Some(stream_identity), Some(stream_epoch)) = (
            snapshot.state.current_stream_identity.clone(),
            snapshot.state.current_stream_epoch,
        ) else {
            debug!(
                cell_id = %self.cell_id,
                "the cell has no current placement yet; waiting rather than capturing"
            );
            return Err(BootstrapFailure::Transient(REASON_NO_CURRENT_PLACEMENT));
        };
        let placement = StreamPlacement {
            stream_identity,
            stream_epoch,
        };
        let placement_revision = snapshot.state.current_placement_revision;

        // 2. Take this generation. Reusing an uncaptured one is not an
        //    optimisation.
        //
        //    A bootstrap that fails after the join leaves a `joining` row with
        //    no captured position, and nothing retires it: Step C's
        //    `retire_generation` needs either a checkpoint or a ready
        //    successor, and this row has neither. Joining again on every
        //    backoff tick would therefore add one orphan row and two cell
        //    version bumps per tick for as long as the broker is down —
        //    unbounded table growth, and a moving version that makes every
        //    other lane's compare-and-set retry. An uncaptured `joining` row
        //    is byte-for-byte what a fresh join produces, so reusing ours is
        //    both correct and the only way to bound that.
        //
        //    A generation that HAS captured is deliberately not reused: its
        //    position is pinned and this seam has no way to resume a consumer
        //    at a recorded position.
        //
        //    TODO(WP-111): resume a captured-but-not-ready generation once
        //    WP-110 pins a receiver-side RPC, which is what would give
        //    `DurableStreamSource` a resume-at-position operation. Until then
        //    that path costs one generation, and only when the capture
        //    succeeded and a later step failed.
        let reusable = snapshot
            .members
            .iter()
            .filter(|member| {
                member.receiver_identity == identity
                    && member.state == "joining"
                    && member.captured.is_none()
                    && member.baseline_at.is_none()
            })
            .max_by_key(|member| member.membership_generation);

        // A join BUMPS the cell's version, and returns the value after the
        // bump. Carrying the pre-join read forward instead would make the
        // bootstrap's own checkpoint report conflict every single time — a
        // guaranteed wasted round trip, and one that would hide a real
        // conflict behind an expected one.
        let (cell_membership_version, membership_generation) = if let Some(member) = reusable {
            debug!(
                cell_id = %self.cell_id,
                receiver_identity = %identity,
                membership_generation = member.membership_generation,
                "reusing this receiver's uncaptured generation rather than allocating another"
            );
            (cell_membership_version, member.membership_generation)
        } else {
            match self
                .runtime
                .store
                .join(identity, cell_membership_version)
                .await
                .map_err(store_failure)?
            {
                MembershipCas::Applied {
                    membership_version,
                    membership_generation,
                } => (membership_version, membership_generation),
                MembershipCas::VersionConflict { .. } => {
                    // Another replica joined between the read and the write.
                    // The retry is cheap and correct: reread and allocate our
                    // own.
                    return Err(BootstrapFailure::Transient(REASON_BOOTSTRAPPING));
                }
                MembershipCas::CellUnknown => {
                    return Err(BootstrapFailure::Rejected(format!(
                        "cell {} is unknown to the outbox membership state",
                        self.cell_id
                    )));
                }
                other => {
                    return Err(BootstrapFailure::Rejected(format!(
                        "joining receiver {identity} answered {other:?}"
                    )));
                }
            }
        };
        if membership_generation < i64::try_from(self.receiver.lifecycle_generation).unwrap_or(0) {
            warn!(
                cell_id = %self.cell_id,
                receiver_identity = %identity,
                allocated = membership_generation,
                configured_floor = self.receiver.lifecycle_generation,
                "the allocated membership generation is below the configured floor; the cell's \
                 generation counter may have moved backwards"
            );
        }

        // 3. Capture the durable consumer's position, BEFORE the baseline.
        //
        //    Always `capture_new`. Resuming a captured position is the
        //    contract's crash/retry case and the wire supports it, but doing it
        //    correctly needs this generation's PERSISTED frontier read back:
        //    the broker does not redeliver a sequence this generation already
        //    acknowledged, so a resume that rebuilt its frontier from the
        //    capture would stall at the first such sequence and never advance
        //    again. The reuse above is therefore restricted to generations that
        //    never captured, where there is no frontier to lose.
        //
        //    TODO(WP-111): add `read_checkpoint` to `ReceiverStore` and resume
        //    a captured generation from its persisted frontier, using
        //    `CaptureRequest::resume_from`.
        let captured = self
            .runtime
            .stream
            .capture(&CaptureRequest {
                receiver_identity: identity.to_string(),
                membership_generation,
                placement: placement.clone(),
                placement_revision,
                resume_from: None,
            })
            .await
            .map_err(stream_failure)?;

        // 4. Record the capture. Step C refuses a second capture on one
        //    generation, so this is where the ordering becomes a shape.
        match self
            .runtime
            .store
            .record_capture(
                identity,
                membership_generation,
                &CapturedPosition {
                    stream_identity: captured.placement.stream_identity.clone(),
                    stream_epoch: captured.placement.stream_epoch,
                    start_sequence: captured.start_sequence,
                },
            )
            .await
            .map_err(store_failure)?
        {
            // The `membership_version` these two answers carry is the MEMBER
            // row's column, stamped once at join and never updated — not the
            // cell's live counter. `report_checkpoint` compares against the
            // cell's, so adopting the member row's value here would send a
            // version that is stale by construction the moment any other
            // replica joins. The cell version read at step 1 is the right one,
            // and a conflict on it is resolved where the conflict is reported.
            MembershipCas::Applied { .. } | MembershipCas::AlreadyRecorded => {}
            other => return Err(retire_on(other)),
        }

        // 5. The authoritative baseline, then 6. record it.
        self.runtime.target.baseline().await;
        match self
            .runtime
            .store
            .record_baseline(identity, membership_generation)
            .await
            .map_err(store_failure)?
        {
            // Same reasoning as the capture above: the member row's version is
            // join-stamped, so it is not what a checkpoint report is compared
            // against.
            MembershipCas::Applied { .. } | MembershipCas::AlreadyRecorded => {}
            other => return Err(retire_on(other)),
        }

        let mut session = ReceiverSession {
            membership_generation,
            membership_version: cell_membership_version,
            frontier: AckFrontier::starting_at(captured.start_sequence),
            applied: AppliedVersions::new(),
            captured,
            ready: false,
            events_since_checkpoint: 0,
            last_checkpoint: Instant::now(),
            reported_frontier: None,
        };
        self.readiness
            .set_from_session(&session, self.receiver.lag_readiness_threshold);

        // 7. Drain everything from the captured position.
        self.drain(&mut session).await?;

        // 8. Persist the frontier and the blockers BEFORE claiming readiness.
        //    A baseline alone never marks a receiver caught up, and Step C
        //    enforces that by refusing the CAS without a checkpoint at the
        //    current placement.
        //
        //    A membership version conflict here is resolved in place rather
        //    than by failing the bootstrap. `checkpoint` adopts the current
        //    version on a conflict, so the resend is the same frontier under
        //    the right version; failing instead would discard a generation
        //    that had already captured, baselined, and drained, and cost
        //    another one, every time a second replica happened to join
        //    mid-bootstrap.
        if let Err(BootstrapFailure::Transient(_)) = self.checkpoint(&mut session).await {
            self.checkpoint(&mut session).await?;
        }

        // 9. The readiness compare-and-set, which rereads the authoritative
        //    placement.
        match self
            .runtime
            .store
            .readiness_cas(identity, session.membership_generation)
            .await
            .map_err(store_failure)?
        {
            MembershipCas::Applied {
                membership_version, ..
            } => {
                session.membership_version = membership_version;
                session.ready = true;
            }
            MembershipCas::PlacementMoved { .. } => {
                return Err(BootstrapFailure::Retired(REASON_PLACEMENT_MOVED));
            }
            MembershipCas::NoCheckpointAtCurrentPlacement => {
                return Err(BootstrapFailure::Retired(REASON_PLACEMENT_MOVED));
            }
            MembershipCas::VersionConflict { .. } => {
                return Err(BootstrapFailure::Transient(REASON_BOOTSTRAPPING));
            }
            other => return Err(retire_on(other)),
        }

        self.readiness
            .set_from_session(&session, self.receiver.lag_readiness_threshold);
        info!(
            cell_id = %self.cell_id,
            receiver_identity = %identity,
            membership_generation = session.membership_generation,
            stream_epoch = session.captured.placement.stream_epoch,
            contiguous_frontier = session.contiguous_frontier(),
            "durable invalidation receiver is ready"
        );
        Ok(session)
    }

    /// Read every event from the captured position to the current edge.
    async fn drain(&self, session: &mut ReceiverSession) -> Result<(), BootstrapFailure> {
        let mut transient_reads = 0usize;
        loop {
            if self.cancel.is_cancelled() {
                return Ok(());
            }
            match self.step(session).await {
                StepOutcome::Idle => return Ok(()),
                StepOutcome::Retired(reason) => return Err(BootstrapFailure::Retired(reason)),
                StepOutcome::Transient(reason) => {
                    transient_reads += 1;
                    if transient_reads > DRAIN_READ_RETRIES {
                        return Err(BootstrapFailure::Transient(reason));
                    }
                    self.sleep(self.backoff_initial).await;
                }
                _ => {
                    transient_reads = 0;
                }
            }
        }
    }

    /// Consume until cancelled or retired.
    async fn steady_state(&self, session: &mut ReceiverSession) {
        let mut backoff = self.backoff_initial;
        while !self.cancel.is_cancelled() {
            let outcome = self.step(session).await;
            self.readiness
                .set_from_session(session, self.receiver.lag_readiness_threshold);

            match outcome {
                StepOutcome::Retired(reason) => {
                    warn!(
                        cell_id = %self.cell_id,
                        receiver_identity = %self.receiver.membership_identity,
                        membership_generation = session.membership_generation,
                        reason,
                        "retiring this receiver generation; a new one will capture, baseline, and \
                         drain from scratch"
                    );
                    self.readiness
                        .set_blocked(reason, Some(session.membership_generation));
                    return;
                }
                StepOutcome::Transient(reason) => {
                    self.readiness
                        .set_blocked(reason, Some(session.membership_generation));
                    self.sleep(backoff).await;
                    backoff = (backoff * 2).min(self.backoff_max);
                    continue;
                }
                StepOutcome::Idle => {
                    backoff = self.backoff_initial;
                    if session.needs_checkpoint(&self.receiver)
                        && let Err(failure) = self.checkpoint(session).await
                    {
                        self.readiness
                            .set_blocked(failure.reason(), Some(session.membership_generation));
                        if matches!(failure, BootstrapFailure::Retired(_)) {
                            return;
                        }
                    }
                    self.sleep(self.receiver.idle_poll).await;
                    continue;
                }
                _ => {
                    backoff = self.backoff_initial;
                }
            }

            if session.needs_checkpoint(&self.receiver)
                && let Err(failure) = self.checkpoint(session).await
            {
                self.readiness
                    .set_blocked(failure.reason(), Some(session.membership_generation));
                if matches!(failure, BootstrapFailure::Retired(_)) {
                    return;
                }
            }
        }
    }

    /// Read and dispose of at most one delivery.
    pub async fn step(&self, session: &mut ReceiverSession) -> StepOutcome {
        let delivery = match self.runtime.stream.next().await {
            Ok(delivery) => delivery,
            Err(StreamError::Transient(message)) => {
                debug!(%message, "durable stream read failed transiently");
                return StepOutcome::Transient(REASON_STREAM_UNAVAILABLE);
            }
            Err(StreamError::PlacementMoved { .. }) => {
                return StepOutcome::Retired(REASON_PLACEMENT_MOVED);
            }
            Err(StreamError::Refused(message)) => {
                warn!(%message, "durable stream refused this receiver");
                return StepOutcome::Retired(REASON_PLACEMENT_MOVED);
            }
        };

        let delivered = match delivery {
            StreamDelivery::CaughtUp => return StepOutcome::Idle,
            StreamDelivery::Message(delivered) => delivered,
        };
        self.dispose(session, *delivered).await
    }

    /// Classify one delivered envelope and act on it.
    async fn dispose(
        &self,
        session: &mut ReceiverSession,
        delivered: DeliveredEnvelope,
    ) -> StepOutcome {
        let sequence = delivered.broker_sequence;
        session.frontier.observe(sequence);

        // A message served from a placement this generation did not capture is
        // not a poison event: it is evidence the epoch moved. Parking it would
        // record a blocker against a generation that is about to be retired.
        if delivered.placement != session.captured.placement {
            return StepOutcome::Retired(REASON_PLACEMENT_MOVED);
        }

        let decoded = match decode_durable_delivery(
            &delivered.envelope,
            &self.cell_id,
            self.payload_version_min,
            self.payload_version_max,
        ) {
            Ok(decoded) => decoded,
            Err(violation) => {
                let class = violation.poison_class();
                warn!(
                    cell_id = %self.cell_id,
                    broker_sequence = sequence,
                    class,
                    "parking a durable invalidation the receiver cannot apply"
                );
                session.frontier.record_poison(sequence, class);
                metrics::record_receiver_outcome("parked");
                return StepOutcome::Parked(class);
            }
        };

        let repository = decoded.repository;
        let incoming = match to_stored(&decoded.body.aggregate_version) {
            Ok(version) => version,
            Err(error) => {
                let class = error.poison_class();
                session.frontier.record_poison(sequence, class);
                metrics::record_receiver_outcome("parked");
                return StepOutcome::Parked(class);
            }
        };
        let key = AggregateKey::of(repository, &decoded.body);

        let outcome = match session.applied.verdict(&key, &incoming) {
            VersionOrder::NextOrdinal => {
                self.runtime
                    .target
                    .apply_invalidation(repository, &decoded.body)
                    .await;
                session.applied.record(key, incoming);
                StepOutcome::Applied
            }
            VersionOrder::Equal => StepOutcome::Duplicate,
            VersionOrder::Older => StepOutcome::Stale,
            VersionOrder::Newer | VersionOrder::Incomparable => {
                // The contract's rule: a gap or an incomparable version is
                // resolved by authoritative refetch BEFORE the acknowledgement,
                // never by picking an order.
                self.runtime.target.refetch_repository(repository).await;
                session.applied.forget_repository(repository);
                StepOutcome::Refetched
            }
        };

        // The acknowledgement is last, and its failure does not undo the
        // application: applying is idempotent, so a redelivery of an applied
        // event is a duplicate, which is an acknowledged no-op.
        if let Err(error) = self.runtime.stream.ack(sequence).await {
            debug!(broker_sequence = sequence, %error, "acknowledgement failed");
            return match error {
                StreamError::PlacementMoved { .. } | StreamError::Refused(_) => {
                    StepOutcome::Retired(REASON_PLACEMENT_MOVED)
                }
                StreamError::Transient(_) => StepOutcome::Transient(REASON_STREAM_UNAVAILABLE),
            };
        }
        session.frontier.record_ack(sequence);
        session.events_since_checkpoint = session.events_since_checkpoint.saturating_add(1);
        metrics::record_receiver_outcome(match outcome {
            StepOutcome::Applied => "applied",
            StepOutcome::Duplicate => "duplicate",
            StepOutcome::Stale => "stale",
            _ => "refetched",
        });
        outcome
    }

    /// Project the current frontier and blockers.
    async fn checkpoint(&self, session: &mut ReceiverSession) -> Result<(), BootstrapFailure> {
        let report = session.checkpoint_report(&self.receiver.membership_identity);
        match self
            .runtime
            .store
            .report_checkpoint(&report)
            .await
            .map_err(store_failure)?
        {
            CheckpointOutcome::Applied {
                contiguous_frontier,
            } => {
                session.reported_frontier = Some(contiguous_frontier);
                session.events_since_checkpoint = 0;
                session.last_checkpoint = Instant::now();
                metrics::record_receiver_checkpoint("applied");
                Ok(())
            }
            CheckpointOutcome::MembershipVersionConflict {
                current_membership_version,
            } => {
                // The snapshot moved under this report. Adopt the current
                // version and let the next cadence tick resend; the frontier
                // itself is unchanged and nothing was lost.
                session.membership_version = current_membership_version;
                metrics::record_receiver_checkpoint("version_conflict");
                Err(BootstrapFailure::Transient(REASON_BOOTSTRAPPING))
            }
            CheckpointOutcome::EpochMismatch { .. } => {
                metrics::record_receiver_checkpoint("epoch_mismatch");
                Err(BootstrapFailure::Retired(REASON_PLACEMENT_MOVED))
            }
            CheckpointOutcome::StaleGeneration { .. } | CheckpointOutcome::RetiredGeneration => {
                metrics::record_receiver_checkpoint("stale_generation");
                Err(BootstrapFailure::Retired(REASON_PLACEMENT_MOVED))
            }
            CheckpointOutcome::FrontierRegressed { .. } => {
                metrics::record_receiver_checkpoint("frontier_regressed");
                Err(BootstrapFailure::Retired(REASON_PLACEMENT_MOVED))
            }
            other => {
                metrics::record_receiver_checkpoint("rejected");
                Err(BootstrapFailure::Rejected(format!(
                    "checkpoint report answered {other:?}"
                )))
            }
        }
    }

    /// Report a last checkpoint on the way out, if anything is unreported.
    ///
    /// Best effort by construction: the process is stopping or the generation
    /// is retired, and neither state is improved by blocking on a store that
    /// is not answering.
    async fn final_checkpoint(&self, session: &mut ReceiverSession) {
        if session.reported_frontier == Some(session.contiguous_frontier())
            && session.events_since_checkpoint == 0
        {
            return;
        }
        if let Err(failure) = self.checkpoint(session).await {
            debug!(
                reason = failure.reason(),
                "the receiver's final checkpoint was not accepted"
            );
        }
    }

    /// Sleep, unless cancellation arrives first.
    async fn sleep(&self, duration: Duration) {
        tokio::select! {
            () = tokio::time::sleep(duration) => {}
            () = self.cancel.cancelled() => {}
        }
    }
}

/// A membership answer that means this generation cannot continue.
fn retire_on(outcome: MembershipCas) -> BootstrapFailure {
    match outcome {
        MembershipCas::PlacementMoved { .. }
        | MembershipCas::NoCheckpointAtCurrentPlacement
        | MembershipCas::WrongState { .. }
        | MembershipCas::GenerationNotFound => BootstrapFailure::Retired(REASON_PLACEMENT_MOVED),
        MembershipCas::VersionConflict { .. } => BootstrapFailure::Transient(REASON_BOOTSTRAPPING),
        other => BootstrapFailure::Rejected(format!("membership write answered {other:?}")),
    }
}

/// Classify a store failure into a bootstrap failure.
fn store_failure(error: super::receiver_store::ReceiverStoreError) -> BootstrapFailure {
    match error {
        super::receiver_store::ReceiverStoreError::Unavailable(_) => {
            BootstrapFailure::Transient(REASON_STORE_UNAVAILABLE)
        }
        super::receiver_store::ReceiverStoreError::Rejected(message) => {
            BootstrapFailure::Rejected(message)
        }
    }
}

/// Classify a stream failure into a bootstrap failure.
fn stream_failure(error: StreamError) -> BootstrapFailure {
    match error {
        StreamError::Transient(_) => BootstrapFailure::Transient(REASON_STREAM_UNAVAILABLE),
        StreamError::PlacementMoved { .. } | StreamError::Refused(_) => {
            BootstrapFailure::Retired(REASON_PLACEMENT_MOVED)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use bytes::Bytes;
    use lore_base::types::RepositoryId;

    use super::super::apply::RecordingInvalidationTarget;
    use super::super::apply::TargetCall;
    use super::super::config::RemoteNotificationConfig;
    use super::super::envelope::AggregateVersion;
    use super::super::envelope::DurableEnvelopeV1;
    use super::super::envelope::DurableInvalidationBody;
    use super::super::envelope::EnvelopeCommon;
    use super::super::envelope::EventId;
    use super::super::receiver_store::InMemoryReceiverStore;
    use super::super::receiver_store::StoreCall;
    use super::super::stream::FakeDurableStream;
    use super::super::stream::StreamPlacement;
    use super::*;

    const CELL: &str = "sfo3-cell-a";
    const IDENTITY: &str = "loreserver-sfo3-cell-a-2";

    const TEST_CONFIG: &str = r#"
        gateway_uri = "http://127.0.0.1:1"
        cell_id = "sfo3-cell-a"
        placement_epoch = 12
        producer_instance_id = "loreserver-sfo3-cell-a-2"
        allow_insecure_transport_for_test = true

        [retry]
        initial_backoff_ms = 1
        max_backoff_ms = 2
        max_attempts = 2

        [receiver]
        membership_identity = "loreserver-sfo3-cell-a-2"
        lifecycle_generation = 1
        lag_readiness_threshold = 5000
        checkpoint_interval_ms = 100
        checkpoint_every_events = 2
        idle_poll_ms = 10
    "#;

    fn config() -> RemoteNotificationConfig {
        let value: toml::Value = toml::from_str(TEST_CONFIG).expect("test config parses");
        RemoteNotificationConfig::parse(&value).expect("test config validates")
    }

    fn repository(byte: u8) -> RepositoryId {
        let mut id = RepositoryId::default();
        *id.data_mut() = [byte; 16];
        id
    }

    /// One valid durable envelope for `repository`, at `ordinal`.
    fn durable(
        repository_byte: u8,
        ordinal: u64,
        identity: Option<&str>,
    ) -> super::super::wire::PrivateEnvelopeV1 {
        DurableEnvelopeV1 {
            common: EnvelopeCommon {
                cell_id: CELL.to_string(),
                placement_epoch: 12,
                event_id: EventId::from_bytes([ordinal as u8; 16]),
                repository: repository(repository_byte),
                producer_instance_id: IDENTITY.to_string(),
                produced_at: UNIX_EPOCH,
            },
            body: DurableInvalidationBody {
                payload_version: 1,
                idempotency_key: [7; 32],
                event_kind: "branch.pushed".to_string(),
                repository_generation: 1,
                aggregate_kind: "branch".to_string(),
                aggregate_identity: "0123456789abcdef".to_string(),
                aggregate_version: AggregateVersion {
                    ordinal,
                    identity: identity.map(str::to_string),
                },
                payload: Bytes::new(),
                committed_at: UNIX_EPOCH,
                actor: None,
            },
        }
        .encode(1..=1)
        .expect("the test envelope is inside every contract bound")
    }

    struct Harness {
        receiver: DurableReceiver,
        store: InMemoryReceiverStore,
        stream: FakeDurableStream,
        target: RecordingInvalidationTarget,
    }

    fn harness(start_sequence: i64) -> Harness {
        let store = InMemoryReceiverStore::new(CELL);
        let stream = FakeDurableStream::at(
            StreamPlacement::new("DURABLE-sfo3-cell-a", 8),
            start_sequence,
        );
        let target = RecordingInvalidationTarget::new();
        let receiver = DurableReceiver::new(
            &config(),
            ReceiverRuntime {
                store: Arc::new(store.clone()),
                stream: Arc::new(stream.clone()),
                target: Arc::new(target.clone()),
            },
        )
        .expect("the test config declares a required receiver");
        Harness {
            receiver,
            store,
            stream,
            target,
        }
    }

    /// The whole happy path, executed: join, capture, baseline, drain,
    /// checkpoint, readiness CAS — in that order — then steady-state
    /// consumption of the four disposed outcomes.
    #[tokio::test]
    async fn the_bootstrap_runs_the_contracts_order_and_reaches_readiness() {
        let harness = harness(900);
        harness.stream.push_envelope(900, durable(0x9f, 1, None));

        let session = harness
            .receiver
            .bootstrap()
            .await
            .expect("the happy-path bootstrap reaches readiness");

        assert!(session.ready);
        assert_eq!(session.membership_generation, 1);
        assert_eq!(
            session.contiguous_frontier(),
            900,
            "the drained event advances the frontier to the captured start"
        );

        // The store saw the contract's order, and nothing else.
        let kinds: Vec<&'static str> = harness
            .store
            .calls()
            .iter()
            .map(|call| match call {
                StoreCall::ReadMembership => "read",
                StoreCall::Join { .. } => "join",
                StoreCall::Capture { .. } => "capture",
                StoreCall::Baseline { .. } => "baseline",
                StoreCall::Checkpoint(_) => "checkpoint",
                StoreCall::Readiness { .. } => "readiness",
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                "read",
                "join",
                "capture",
                "baseline",
                "checkpoint",
                "readiness"
            ],
            "the capture must precede the baseline, and the checkpoint must precede the readiness \
             compare-and-set"
        );

        // Exactly one baseline, taken before the drained event was applied.
        assert_eq!(harness.target.baselines(), 1);
        assert!(matches!(
            harness.target.calls().first(),
            Some(TargetCall::Baseline)
        ));
        assert!(harness.receiver.readiness().is_ready());
        assert_eq!(harness.stream.acked(), vec![900]);
    }

    /// The four disposed outcomes, each acknowledged, and the two undisposed
    /// ones, neither acknowledged.
    #[tokio::test]
    async fn the_steady_state_disposes_each_outcome_class() {
        let harness = harness(900);
        let mut session = harness.receiver.bootstrap().await.expect("bootstraps");
        assert_eq!(session.contiguous_frontier(), 899);

        // Next version: applied.
        harness.stream.push_envelope(900, durable(0x9f, 5, None));
        assert_eq!(
            harness.receiver.step(&mut session).await,
            StepOutcome::Applied
        );

        // The same version again: an acknowledged no-op.
        harness.stream.push_envelope(901, durable(0x9f, 5, None));
        assert_eq!(
            harness.receiver.step(&mut session).await,
            StepOutcome::Duplicate
        );

        // A lower ordinal: an acknowledged no-op.
        harness.stream.push_envelope(902, durable(0x9f, 4, None));
        assert_eq!(
            harness.receiver.step(&mut session).await,
            StepOutcome::Stale
        );

        // A skipped ordinal: an authoritative refetch before the acknowledgement.
        harness.stream.push_envelope(903, durable(0x9f, 9, None));
        assert_eq!(
            harness.receiver.step(&mut session).await,
            StepOutcome::Refetched
        );
        assert!(
            harness
                .target
                .calls()
                .iter()
                .any(|call| matches!(call, TargetCall::Refetch(_))),
            "a gap must be resolved by refetch, not by picking an order"
        );

        assert_eq!(harness.stream.acked(), vec![900, 901, 902, 903]);
        assert_eq!(session.contiguous_frontier(), 903);
        assert!(!session.has_blockers());

        // Poison: parked, unacknowledged, and the frontier stops below it.
        let mut malformed = durable(0x9f, 10, None);
        malformed.transport_version = 99;
        harness.stream.push_envelope(904, malformed);
        assert_eq!(
            harness.receiver.step(&mut session).await,
            StepOutcome::Parked("UNSUPPORTED_SCHEMA")
        );
        assert_eq!(harness.stream.acked(), vec![900, 901, 902, 903]);
        assert_eq!(session.contiguous_frontier(), 903);
        assert!(session.has_blockers());

        // A later event acknowledges but cannot skip the park.
        harness.stream.push_envelope(905, durable(0x9f, 10, None));
        assert_eq!(
            harness.receiver.step(&mut session).await,
            StepOutcome::Applied
        );
        assert_eq!(
            session.contiguous_frontier(),
            903,
            "an acknowledgement above an unresolved park must never advance the frontier"
        );

        // Transient: unacknowledged, and nothing is applied.
        harness
            .stream
            .push_error(StreamError::Transient("broker down".into()));
        assert_eq!(
            harness.receiver.step(&mut session).await,
            StepOutcome::Transient(REASON_STREAM_UNAVAILABLE)
        );

        // Caught up.
        assert_eq!(harness.receiver.step(&mut session).await, StepOutcome::Idle);
    }

    /// A message served from an epoch this generation did not capture retires
    /// the generation. It is not parked: a park would record a blocker against
    /// a generation that is about to be replaced.
    #[tokio::test]
    async fn an_event_from_another_epoch_retires_rather_than_parking() {
        let harness = harness(900);
        let mut session = harness.receiver.bootstrap().await.expect("bootstraps");
        harness.stream.push_envelope_at(
            900,
            StreamPlacement::new("DURABLE-sfo3-cell-a-r2", 1),
            durable(0x9f, 1, None),
        );
        assert_eq!(
            harness.receiver.step(&mut session).await,
            StepOutcome::Retired(REASON_PLACEMENT_MOVED)
        );
        assert!(harness.stream.acked().is_empty());
    }

    /// The four reset boundaries the contract names collapse to one response:
    /// retire the generation. This exercises the last of them, the readiness
    /// CAS race, which is the only one the receiver cannot see coming.
    #[tokio::test]
    async fn a_placement_that_moved_during_the_bootstrap_fails_the_readiness_cas() {
        let harness = harness(900);
        harness
            .store
            .next_readiness(Ok(MembershipCas::PlacementMoved {
                current_stream_identity: Some("DURABLE-sfo3-cell-a-r2".to_string()),
                current_stream_epoch: Some(1),
            }));
        assert_eq!(
            harness.receiver.bootstrap().await.err(),
            Some(BootstrapFailure::Retired(REASON_PLACEMENT_MOVED))
        );
    }

    /// Step C refuses a readiness CAS with no checkpoint at the current
    /// placement. A receiver that read that as retryable would spin claiming
    /// readiness it never proved.
    #[tokio::test]
    async fn a_baseline_alone_cannot_reach_readiness() {
        let harness = harness(900);
        harness
            .store
            .next_readiness(Ok(MembershipCas::NoCheckpointAtCurrentPlacement));
        assert_eq!(
            harness.receiver.bootstrap().await.err(),
            Some(BootstrapFailure::Retired(REASON_PLACEMENT_MOVED))
        );
    }

    /// A capture failure never leaves a baseline recorded against a position
    /// nothing pinned.
    #[tokio::test]
    async fn a_failed_capture_stops_before_the_baseline() {
        let harness = harness(900);
        harness
            .stream
            .fail_next_capture_with(StreamError::Transient("broker down".into()));
        assert_eq!(
            harness.receiver.bootstrap().await.err(),
            Some(BootstrapFailure::Transient(REASON_STREAM_UNAVAILABLE))
        );
        assert_eq!(harness.target.baselines(), 0);
        assert!(
            !harness
                .store
                .calls()
                .iter()
                .any(|call| matches!(call, StoreCall::Baseline { .. })),
            "no baseline may be recorded for a generation whose position was never captured"
        );
    }

    /// A reset fence is not a reason to refuse to bootstrap: the fence stands
    /// because a replacement generation is required, and this is it.
    #[tokio::test]
    async fn a_generation_still_bootstraps_while_a_reset_fence_stands() {
        let harness = harness(900);
        harness.store.set_reset_in_progress(true);
        let session = harness
            .receiver
            .bootstrap()
            .await
            .expect("the replacement generation bootstraps under the fence");
        assert!(
            session.ready,
            "the fence stands because a replacement generation is required; refusing to \
             bootstrap under it would make the fence permanent"
        );
    }

    /// A bootstrap that fails after joining must not cost a generation on the
    /// next attempt. Nothing retires an uncaptured `joining` row, so joining
    /// again per backoff tick would grow the membership table without bound
    /// for as long as the broker is down.
    #[tokio::test]
    async fn a_retried_bootstrap_reuses_its_uncaptured_generation() {
        let harness = harness(900);
        harness
            .stream
            .fail_next_capture_with(StreamError::Transient("broker down".into()));
        assert!(harness.receiver.bootstrap().await.is_err());

        let joins_after_first = harness
            .store
            .calls()
            .iter()
            .filter(|call| matches!(call, StoreCall::Join { .. }))
            .count();
        assert_eq!(joins_after_first, 1);

        let session = harness
            .receiver
            .bootstrap()
            .await
            .expect("the retry bootstraps");
        assert_eq!(
            session.membership_generation, 1,
            "the retry must reuse the uncaptured generation the failed attempt left behind"
        );
        assert_eq!(
            harness
                .store
                .calls()
                .iter()
                .filter(|call| matches!(call, StoreCall::Join { .. }))
                .count(),
            1,
            "a second join would leak a generation and bump the cell version again"
        );
    }

    /// A concurrent join moves the cell's membership version under the
    /// bootstrap's checkpoint. That costs one resend, not a whole generation
    /// that had already captured, baselined, and drained.
    #[tokio::test]
    async fn a_membership_version_conflict_during_bootstrap_resends_in_place() {
        let harness = harness(900);
        harness.store.advance_membership_version_after_join(7);
        let session = harness
            .receiver
            .bootstrap()
            .await
            .expect("the conflicting report is resent, not abandoned");
        assert!(session.ready);
        assert_eq!(session.membership_generation, 1);

        let reports: Vec<i64> = harness
            .store
            .calls()
            .iter()
            .filter_map(|call| match call {
                StoreCall::Checkpoint(report) => Some(report.membership_version),
                _ => None,
            })
            .collect();
        assert_eq!(
            reports.len(),
            2,
            "the conflict costs exactly one extra report"
        );
        assert_eq!(reports[0], 2, "the first report carries the joined version");
        assert_eq!(
            reports[1], 9,
            "the resend must carry the version the conflict reported"
        );
    }

    /// The checkpoint report carries the version the JOIN returned, which is
    /// the cell counter after the join's own bump — not the version read
    /// before it, and not the member row's join-stamped column. Either of
    /// those would make the bootstrap's own report conflict every time.
    #[tokio::test]
    async fn the_checkpoint_report_carries_the_post_join_cell_version() {
        let harness = harness(900);
        let session = harness.receiver.bootstrap().await.expect("bootstraps");
        let reports: Vec<i64> = harness
            .store
            .calls()
            .iter()
            .filter_map(|call| match call {
                StoreCall::Checkpoint(report) => Some(report.membership_version),
                _ => None,
            })
            .collect();
        assert_eq!(
            reports,
            vec![2],
            "one accepted report, at the version the join returned"
        );
        let report = session.checkpoint_report(IDENTITY);
        assert_eq!(report.stream_identity, "DURABLE-sfo3-cell-a");
        assert_eq!(report.stream_epoch, 8);
        assert_eq!(report.membership_generation, 1);
    }

    /// A cell whose `SCHEMA-119` install never ran is a configuration fault,
    /// not a transient one. Reading it as transient would spin a backoff loop
    /// against a database that is never going to grow the row.
    #[tokio::test]
    async fn a_cell_with_no_membership_state_is_a_rejection_not_a_retry() {
        let harness = harness(900);
        harness.store.uninstalled();
        let failure = harness
            .receiver
            .bootstrap()
            .await
            .expect_err("an uninstalled cell cannot bootstrap");
        assert!(matches!(failure, BootstrapFailure::Rejected(_)));
        assert_eq!(failure.reason(), REASON_CONFIGURATION_REJECTED);
        assert_eq!(harness.target.baselines(), 0);
    }

    /// A cancelled receiver stops and reports the closed stopped reason rather
    /// than an error, because an unreachable broker is a false readiness facet
    /// and not a failed plugin task.
    #[tokio::test]
    async fn cancellation_stops_the_loop_without_returning_an_error() {
        let harness = harness(900);
        let readiness = harness.receiver.readiness();
        let cancel = harness.receiver.cancellation_token();
        cancel.cancel();
        assert!(harness.receiver.run().await.is_ok());
        assert_eq!(readiness.snapshot().reason, Some(REASON_STOPPED));
    }

    #[test]
    fn a_fresh_readiness_handle_is_not_ready() {
        let readiness = ReceiverReadiness::new();
        let snapshot = readiness.snapshot();
        assert!(!snapshot.ready);
        assert_eq!(snapshot.reason, Some(REASON_NOT_STARTED));
        assert_eq!(snapshot.generation, None);
    }

    #[test]
    fn only_the_four_disposed_outcomes_acknowledge() {
        assert!(StepOutcome::Applied.acknowledged());
        assert!(StepOutcome::Duplicate.acknowledged());
        assert!(StepOutcome::Stale.acknowledged());
        assert!(StepOutcome::Refetched.acknowledged());
        assert!(
            !StepOutcome::Parked("UNSUPPORTED_SCHEMA").acknowledged(),
            "a parked event must never be acknowledged; the unacknowledged sequence is what \
             stalls the frontier"
        );
        assert!(!StepOutcome::Transient(REASON_STREAM_UNAVAILABLE).acknowledged());
        assert!(!StepOutcome::Retired(REASON_PLACEMENT_MOVED).acknowledged());
        assert!(!StepOutcome::Idle.acknowledged());
    }

    #[test]
    fn every_readiness_reason_is_a_closed_low_cardinality_label() {
        for reason in [
            REASON_NOT_STARTED,
            REASON_BOOTSTRAPPING,
            REASON_LAG_THRESHOLD,
            REASON_STREAM_UNAVAILABLE,
            REASON_STORE_UNAVAILABLE,
            REASON_POISON_PARKED,
            REASON_PLACEMENT_MOVED,
            REASON_CONFIGURATION_REJECTED,
            REASON_STOPPED,
        ] {
            assert!(!reason.is_empty());
            assert!(reason.is_ascii());
            assert!(!reason.contains(' '));
        }
    }

    /// A membership version conflict is retryable; a placement move is not.
    /// Getting this backwards would either spin on a dead generation or throw
    /// away a live one.
    #[test]
    fn membership_answers_split_into_retry_and_retire() {
        assert_eq!(
            retire_on(MembershipCas::VersionConflict {
                current_membership_version: 9,
            }),
            BootstrapFailure::Transient(REASON_BOOTSTRAPPING)
        );
        assert_eq!(
            retire_on(MembershipCas::PlacementMoved {
                current_stream_identity: Some("DURABLE-a-r2".to_string()),
                current_stream_epoch: Some(1),
            }),
            BootstrapFailure::Retired(REASON_PLACEMENT_MOVED)
        );
        assert_eq!(
            retire_on(MembershipCas::NoCheckpointAtCurrentPlacement),
            BootstrapFailure::Retired(REASON_PLACEMENT_MOVED)
        );
    }

    #[test]
    fn a_transient_store_failure_retries_and_a_rejection_does_not() {
        assert_eq!(
            store_failure(
                super::super::receiver_store::ReceiverStoreError::Unavailable(
                    "pool exhausted".into()
                )
            ),
            BootstrapFailure::Transient(REASON_STORE_UNAVAILABLE)
        );
        assert!(matches!(
            store_failure(super::super::receiver_store::ReceiverStoreError::Rejected(
                "stream_epoch must be >= 1".into()
            )),
            BootstrapFailure::Rejected(_)
        ));
    }

    #[test]
    fn a_moved_placement_retires_rather_than_backing_off() {
        assert_eq!(
            stream_failure(StreamError::PlacementMoved {
                current: super::super::stream::StreamPlacement::new("DURABLE-a-r2", 1),
            }),
            BootstrapFailure::Retired(REASON_PLACEMENT_MOVED)
        );
        assert_eq!(
            stream_failure(StreamError::Transient("broker down".into())),
            BootstrapFailure::Transient(REASON_STREAM_UNAVAILABLE)
        );
    }
}
