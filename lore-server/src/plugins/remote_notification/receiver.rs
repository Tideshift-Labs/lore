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
//! # Resuming an existing generation
//!
//! A process restart does not always cost a generation. When this receiver's
//! own highest generation already captured a position, is not retired, and
//! its captured identity and epoch still equal the cell's
//! authoritative placement, the bootstrap resumes it: it reads that
//! generation's PERSISTED frontier back through
//! [`super::receiver_store::ReceiverStore::read_checkpoint`], attaches with the
//! original `captured_position`, and seeds its local frontier from that saved
//! checkpoint. It takes a fresh baseline and drains pending deliveries without
//! joining or re-recording the capture.
//!
//! The persisted frontier is the load-bearing part. The broker does not
//! redeliver a sequence this generation already acknowledged, so a resume that
//! rebuilt its frontier from the captured position would stall at the first
//! such sequence forever. For the same reason a persisted checkpoint carrying
//! a gap or a park is NOT resumed — the projection records blockers but not
//! the acknowledgements above them — and those cases start a new generation
//! exactly as they did before resume existed. Every other outcome of the
//! ordered proof below is unchanged.
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
//! Cancellation stops the loop at the next boundary and returns. It never
//! acknowledges to make the shutdown tidy: an event accepted but not applied
//! is redelivered to the next generation, which is exactly right.
//!
//! A ready generation's graceful stop reports its final checkpoint and marks
//! the generation `draining` in one transaction, even when the frontier is
//! already reported (WP-115 row 68). The marker is how an operator's
//! `retire-generation` tells a stopped receiver from an idle one. A
//! restart resumes a `draining` generation like any other resumable one, and
//! the readiness compare-and-set moves it back to `ready`. A generation that
//! is not ready, or whose marker write is refused, reports an ordinary final
//! checkpoint if there is anything unreported.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use lore_postgres::domain::outbox::CheckpointOutcome;
use lore_postgres::domain::outbox::CheckpointReport;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::MembershipSnapshot;
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
    /// The durable stream. A trait so the lifecycle races this receiver's hard
    /// cases are made of can be scripted in process; `SCHEMA-119` hands in
    /// [`super::stream::GrpcDurableStream`] over the cell's `receiver`-role
    /// channel.
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
#[lore_macro::test_pub]
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

    /// Park one sequence AND make that park reportable.
    ///
    /// [`AckFrontier::record_poison`] alone updates only this process's own
    /// frontier, which is enough for the readiness facet and not enough for the
    /// durable projection. A park acknowledges nothing, so the contiguous
    /// frontier does not move, and `events_since_checkpoint` is incremented
    /// only on the acknowledgement path — so both terms of
    /// [`Self::needs_checkpoint`]'s short circuit hold and it answers false for
    /// as long as nothing else arrives. The blocker would then reach readiness
    /// and NEVER the checkpoint row: not late, never, because
    /// [`ReceiverLoop::final_checkpoint`] carries the same guard and skips it on
    /// the way out too.
    ///
    /// Counting the park as an event is what makes "this generation is parked"
    /// a durable fact another process, an operator query, or a replacement
    /// generation's resume decision can read. The cadence still bounds the
    /// write: this only makes a checkpoint DUE, it does not send one.
    ///
    /// Deduplication stays in [`AckFrontier::record_poison`] and deliberately
    /// not here, so a broker redelivering the same parked message re-arms the
    /// checkpoint without adding a second blocker. The cost is one idempotent
    /// re-write of an unchanged row per redelivery — roughly one per the
    /// broker's `ack_wait` — which is the price of the park staying true in the
    /// projection rather than only in this process.
    #[lore_macro::test_pub]
    fn park(&mut self, broker_sequence: i64, class: &'static str) {
        self.frontier.record_poison(broker_sequence, class);
        self.events_since_checkpoint = self.events_since_checkpoint.saturating_add(1);
    }

    /// True when the projection does not yet hold everything this generation
    /// proved: a frontier move or a park since the last accepted report.
    fn has_unreported_work(&self) -> bool {
        self.reported_frontier != Some(self.frontier.contiguous_frontier())
            || self.events_since_checkpoint != 0
    }

    #[lore_macro::test_pub]
    fn needs_checkpoint(&self, config: &ReceiverConfig) -> bool {
        if !self.has_unreported_work() {
            return false;
        }
        self.events_since_checkpoint >= config.checkpoint_every_events
            || self.last_checkpoint.elapsed() >= config.checkpoint_interval
    }

    /// When the interval term of [`Self::needs_checkpoint`] comes due, or
    /// `None` when nothing is unreported and so nothing can come due.
    ///
    /// The steady-state read races this deadline. The gateway sends nothing on
    /// an idle stream, so a burst's last acknowledgements would otherwise stay
    /// unreported until the next delivery (WP-115 ledger row 64).
    #[lore_macro::test_pub]
    fn checkpoint_deadline(&self, config: &ReceiverConfig) -> Option<Instant> {
        if !self.has_unreported_work() {
            return None;
        }
        self.last_checkpoint.checked_add(config.checkpoint_interval)
    }
}

/// A generation this bootstrap may resume rather than replace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResumableGeneration {
    /// The generation to resume. Already joined, already captured.
    membership_generation: i64,
    /// The original durable capture, echoed unchanged by the gateway on resume.
    captured_start_sequence: i64,
    /// The first sequence this bootstrap is responsible for: one past the
    /// persisted contiguous frontier, or the captured position when this
    /// generation never reported one.
    frontier_start_sequence: i64,
    /// The generation is `draining`: this receiver's own graceful stop. It
    /// moves back to `ready` before this bootstrap consumes anything.
    draining: bool,
}

/// The durable invalidation receiver.
#[lore_macro::test_pub]
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

    /// Observe the server shutdown signal and finish through the normal
    /// cancellation path, including the final checkpoint of accepted work.
    ///
    /// # Errors
    /// Returns any error from [`Self::run`].
    pub async fn run_with_shutdown(
        self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), PluginError> {
        let cancel = self.cancellation_token();
        let run = self.run();
        tokio::pin!(run);
        tokio::select! {
            biased;
            // A dropped signal owner also ends this receiver. Treat channel
            // closure like shutdown, matching the server endpoint listeners.
            _ = shutdown.wait_for(|&value| value) => cancel.cancel(),
            result = &mut run => return result,
        }
        run.await
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
                    // has to re-prove. A graceful stop of a ready generation
                    // also marks it `draining` with that checkpoint.
                    if self.cancel.is_cancelled() {
                        if session.ready {
                            self.draining_checkpoint(&mut session).await;
                        } else {
                            self.final_checkpoint(&mut session).await;
                        }
                        break;
                    }
                    self.final_checkpoint(&mut session).await;
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
            .map_err(|_err| BootstrapFailure::Transient(REASON_STORE_UNAVAILABLE))?;
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

        // 2. Take this generation.
        //
        //    A restart is the first case. A generation that already captured a
        //    position and whose captured identity and epoch still equal the
        //    cell's authoritative placement is resumed rather than replaced,
        //    which is the contract's crash-and-retry rule: "crash and retry
        //    resume the same receiver generation and captured position only
        //    while authoritative identity and epoch still match". Resuming
        //    reads the generation's PERSISTED frontier back, because the broker
        //    does not redeliver a sequence this generation already acknowledged
        //    — a resume that rebuilt its frontier from the captured position
        //    would stall at the first such sequence and never advance again.
        //
        //    Reusing an uncaptured one is the second case, and is not an
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
        //    A captured generation that is NOT resumable — a moved placement,
        //    a retired row, or a persisted checkpoint carrying a blocker —
        //    falls through to the same fresh join, exactly as before.
        let resumable = self
            .resumable_generation(&snapshot, identity, &placement)
            .await?;

        // A resumed `draining` generation leaves `draining` BEFORE this
        // bootstrap consumes anything. Left for step 9, the row would read as
        // a stopped, caught-up receiver while this process acknowledged and
        // checkpointed deliveries, and a graceful `retire-generation` in that
        // window would retire a running receiver (WP-115 row 68). The proof
        // `readiness_cas` needs is already persisted: the draining write's
        // checkpoint at the captured placement. `ready` and `draining` count
        // toward safety alike, so this changes nothing an evaluation reads.
        // A retirement that won the race answers here, before any capture.
        if let Some(resume) = resumable
            && resume.draining
        {
            match self
                .runtime
                .store
                .readiness_cas(identity, resume.membership_generation)
                .await
                .map_err(store_failure)?
            {
                MembershipCas::Applied { .. } | MembershipCas::AlreadyRecorded => {}
                MembershipCas::VersionConflict { .. } => {
                    return Err(BootstrapFailure::Transient(REASON_BOOTSTRAPPING));
                }
                other => return Err(retire_on(other)),
            }
        }

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
        let (cell_membership_version, membership_generation, resume_from) =
            if let Some(resume) = resumable {
                info!(
                    cell_id = %self.cell_id,
                    receiver_identity = %identity,
                    membership_generation = resume.membership_generation,
                    captured_start_sequence = resume.captured_start_sequence,
                    frontier_start_sequence = resume.frontier_start_sequence,
                    "resuming this receiver's captured generation from its persisted position"
                );
                (
                    cell_membership_version,
                    resume.membership_generation,
                    Some(resume.captured_start_sequence),
                )
            } else if let Some(member) = reusable {
                debug!(
                    cell_id = %self.cell_id,
                    receiver_identity = %identity,
                    membership_generation = member.membership_generation,
                    "reusing this receiver's uncaptured generation rather than allocating another"
                );
                (cell_membership_version, member.membership_generation, None)
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
                    } => (membership_version, membership_generation, None),
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
        //    `capture_new` for a generation that never captured, and
        //    `captured_position` for a resume. The gateway echoes a requested
        //    resume position byte-exactly or fails the stream, so a resume
        //    that returns a nearby position is a refusal rather than a silently
        //    skipped event.
        let captured = self
            .runtime
            .stream
            .capture(&CaptureRequest {
                receiver_identity: identity.to_string(),
                membership_generation,
                placement: placement.clone(),
                placement_revision,
                resume_from,
            })
            .await
            .map_err(stream_failure)?;

        // 3b. The resume echo, checked HERE and not only in the transport.
        //
        //     A resume must attach to the original durable capture. The local
        //     frontier is restored independently from its persisted checkpoint;
        //     it does not authorize moving the broker's capture. The transport
        //     already checks the echo, but the receiver also enforces it for
        //     every implementation of `DurableStreamSource`.
        if let Some(requested) = resume_from
            && captured.start_sequence != requested
        {
            warn!(
                cell_id = %self.cell_id,
                receiver_identity = %identity,
                membership_generation,
                requested,
                echoed = captured.start_sequence,
                "the durable stream did not echo the requested resume position; retiring this \
                 generation rather than trusting a position nothing pinned"
            );
            return Err(BootstrapFailure::Retired(REASON_PLACEMENT_MOVED));
        }

        // 4. Record the capture. Step C refuses a second capture on one
        //    generation, so this is where the ordering becomes a shape.
        //
        //    A resume skips it. The capture it would record is this
        //    generation's ALREADY RECORDED position. The persisted frontier
        //    restores local progress without changing that capture.
        if resume_from.is_none() {
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
                // The `membership_version` these two answers carry is the
                // MEMBER row's column, stamped once at join and never updated —
                // not the cell's live counter. `report_checkpoint` compares
                // against the cell's, so adopting the member row's value here
                // would send a version that is stale by construction the moment
                // any other replica joins. The cell version read at step 1 is
                // the right one, and a conflict on it is resolved where the
                // conflict is reported.
                MembershipCas::Applied { .. } | MembershipCas::AlreadyRecorded => {}
                other => return Err(retire_on(other)),
            }
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
            frontier: AckFrontier::starting_at(
                resumable.map_or(captured.start_sequence, |resume| {
                    resume.frontier_start_sequence
                }),
            ),
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
        //
        //    Every OTHER failure propagates. It must: a `Retired` answer here
        //    is Step C reporting that this generation's epoch moved, that a
        //    successor replaced it, or that it is already retired, and the
        //    readiness compare-and-set below cannot be relied on to catch any
        //    of them — `readiness_cas` answers `AlreadyRecorded` for a row that
        //    is already `ready` BEFORE it rereads the placement, so a resumed
        //    generation whose checkpoint was refused would otherwise claim
        //    readiness while every future checkpoint it sends is refused too.
        match self.checkpoint(&mut session).await {
            Ok(()) => {}
            Err(BootstrapFailure::Transient(_)) => self.checkpoint(&mut session).await?,
            Err(other) => return Err(other),
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
            // A resumed generation that was already ready before the restart.
            // Step C does not rewrite it and does not bump the cell's version,
            // so the version read at step 1 (and adopted by the checkpoint
            // above on a conflict) is still the current one. The generation is
            // ready by the same proof it was ready by before: this bootstrap
            // took a fresh baseline, drained from its persisted frontier, and
            // reported a checkpoint that Step C accepted at the current
            // placement — the checkpoint is what fences the epoch here, because
            // this answer is returned before `readiness_cas` rereads it.
            MembershipCas::AlreadyRecorded => {
                session.ready = true;
            }
            MembershipCas::PlacementMoved { .. }
            | MembershipCas::NoCheckpointAtCurrentPlacement => {
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

    /// Decide whether this bootstrap resumes an existing generation.
    ///
    /// Reads the receiver's own highest generation and, when it qualifies,
    /// the persisted frontier that generation proved. Returns `None` for
    /// every case that must start a new generation, which is the behaviour
    /// this seam had before resume existed.
    ///
    /// # Why a persisted blocker refuses the resume
    ///
    /// The projection records the frontier, the gaps, and the parks — not the
    /// acknowledged sequences. Where there is no blocker that is a complete
    /// record: [`AckFrontier`] closes every run that starts one past the
    /// frontier as it acknowledges, so an empty gap and poison list means
    /// nothing above the frontier was ever acknowledged, and
    /// `AckFrontier::starting_at(frontier + 1)` reproduces the persisted state
    /// exactly.
    ///
    /// A blocker breaks that. A gap is by construction below some
    /// acknowledged sequence, and a park is normally below several, and none
    /// of those acknowledgements survives in the projection. The broker will
    /// not redeliver them, so a resumed frontier would stop at the first one
    /// and never advance again — a permanent stall where starting a new
    /// generation is merely one generation more expensive. A park is also
    /// exactly the state an operator restarts a process to clear, and
    /// resuming it would take that away.
    ///
    /// # Errors
    /// [`BootstrapFailure`] when the checkpoint read could not complete. The
    /// read is not optional: guessing "no checkpoint" from an unavailable
    /// store would resume at the captured position and re-consume every
    /// sequence this generation already proved.
    async fn resumable_generation(
        &self,
        snapshot: &MembershipSnapshot,
        identity: &str,
        placement: &StreamPlacement,
    ) -> Result<Option<ResumableGeneration>, BootstrapFailure> {
        // A standing reset fence requires a REPLACEMENT generation with a
        // newly captured identity, epoch, and position — that is what the fence
        // is for, and `readiness_cas` clears it only on the transition to
        // ready, which a resumed already-ready generation never makes. Today
        // `accept_reset` also moves the placement and retires every member, so
        // the two checks below would refuse the resume anyway; this one states
        // the rule directly rather than leaving it a consequence of two others.
        if snapshot.reset_in_progress {
            return Ok(None);
        }

        // The receiver's own highest generation, and only that one. A lower
        // generation cannot checkpoint at all — Step C answers `StaleGeneration`
        // for anything but the greatest this identity holds.
        let latest = snapshot
            .members
            .iter()
            .filter(|member| member.receiver_identity == identity)
            .max_by_key(|member| member.membership_generation);
        let Some(latest) = latest else {
            return Ok(None);
        };
        // `draining` resumes too: it is this receiver's own graceful stop, and
        // the readiness compare-and-set moves it back to `ready` on the same
        // placement and checkpoint proof. Replacing it instead would cost a
        // generation on every rolling restart.
        if latest.state != "joining" && latest.state != "ready" && latest.state != "draining" {
            return Ok(None);
        }
        let Some(captured) = latest.captured.as_ref() else {
            return Ok(None);
        };
        // The contract's own condition: a crash resumes the same generation and
        // captured position ONLY while the authoritative identity and epoch
        // still match. They do not, so this generation is retired by the same
        // path a placement move takes.
        if captured.stream_identity != placement.stream_identity
            || captured.stream_epoch != placement.stream_epoch
        {
            debug!(
                cell_id = %self.cell_id,
                receiver_identity = %identity,
                membership_generation = latest.membership_generation,
                captured_epoch = captured.stream_epoch,
                current_epoch = placement.stream_epoch,
                "the captured generation is bound to a placement that moved; starting a new one"
            );
            return Ok(None);
        }

        let record = self
            .runtime
            .store
            .read_checkpoint(
                &captured.stream_identity,
                captured.stream_epoch,
                identity,
                latest.membership_generation,
            )
            .await
            .map_err(store_failure)?;

        let start_sequence = match record {
            Some(record) if record.has_blockers() => {
                debug!(
                    cell_id = %self.cell_id,
                    receiver_identity = %identity,
                    membership_generation = latest.membership_generation,
                    gaps = record.gaps.len(),
                    poison = record.poison.len(),
                    "the captured generation's checkpoint carries a blocker; starting a new one"
                );
                return Ok(None);
            }
            // One past everything this generation proved.
            Some(record) => record.contiguous_frontier.saturating_add(1),
            // It captured and never reported, so the captured position is
            // still the first sequence it is responsible for.
            None => captured.start_sequence,
        };

        Ok(Some(ResumableGeneration {
            membership_generation: latest.membership_generation,
            captured_start_sequence: captured.start_sequence,
            frontier_start_sequence: start_sequence,
            draining: latest.state == "draining",
        }))
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
            let deadline = session.checkpoint_deadline(&self.receiver);
            let Some(outcome) = self.step_until(session, deadline).await else {
                // The checkpoint came due while the stream was idle. A refused
                // report leaves the deadline in the past, so back off before
                // the next attempt rather than spin on the store.
                match self.checkpoint(session).await {
                    Ok(()) => self
                        .readiness
                        .set_from_session(session, self.receiver.lag_readiness_threshold),
                    Err(failure) => {
                        self.readiness
                            .set_blocked(failure.reason(), Some(session.membership_generation));
                        if matches!(failure, BootstrapFailure::Retired(_)) {
                            return;
                        }
                        self.sleep(backoff).await;
                        backoff = (backoff * 2).min(self.backoff_max);
                    }
                }
                continue;
            };
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
    ///
    /// The read gives way to cancellation. The gateway sends nothing on an idle
    /// stream, so an uncancellable read held shutdown until the server's
    /// force-close deadline. Only the read is raced: a delivery already read is
    /// disposed of in full. Dropping the read loses nothing, because nothing was
    /// acknowledged and the broker redelivers it.
    pub async fn step(&self, session: &mut ReceiverSession) -> StepOutcome {
        // With no deadline the read never gives way to one.
        self.step_until(session, None)
            .await
            .unwrap_or(StepOutcome::Idle)
    }

    /// [`Self::step`], with the read also giving way to a checkpoint
    /// deadline. `None` means the deadline passed first and nothing was read.
    ///
    /// Dropping the read for the deadline is as safe as dropping it for
    /// cancellation: nothing was observed or acknowledged, and the next call
    /// reads the same message. Cancellation still wins a tie.
    async fn step_until(
        &self,
        session: &mut ReceiverSession,
        deadline: Option<Instant>,
    ) -> Option<StepOutcome> {
        let checkpoint_due = async {
            match deadline {
                Some(deadline) => {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        let read = tokio::select! {
            biased;
            read = self.runtime.stream.next() => read,
            () = self.cancel.cancelled() => return Some(StepOutcome::Transient(REASON_STOPPED)),
            () = checkpoint_due => return None,
        };
        Some(self.dispose_read(session, read).await)
    }

    /// Dispose of one completed read.
    async fn dispose_read(
        &self,
        session: &mut ReceiverSession,
        read: Result<StreamDelivery, StreamError>,
    ) -> StepOutcome {
        let delivery = match read {
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
                session.park(sequence, class);
                metrics::record_receiver_outcome("parked");
                return StepOutcome::Parked(class);
            }
        };

        let repository = decoded.repository;
        let incoming = match to_stored(&decoded.body.aggregate_version) {
            Ok(version) => version,
            Err(error) => {
                let class = error.poison_class();
                session.park(sequence, class);
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
    #[lore_macro::test_pub]
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
                // itself is unchanged and nothing was lost. The attempt spends
                // this tick: restart the interval and clear the event count, or
                // a persistent conflict re-sends on every idle poll. Clearing
                // `reported_frontier` keeps the unreported work due, since a
                // park moves no frontier and would otherwise look reported.
                session.membership_version = current_membership_version;
                session.last_checkpoint = Instant::now();
                session.events_since_checkpoint = 0;
                session.reported_frontier = None;
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
    #[lore_macro::test_pub]
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

    /// Report the final checkpoint AND mark this generation `draining`, on a
    /// graceful stop (WP-115 row 68).
    ///
    /// Sent even when the frontier is already reported: the marker is the
    /// point. It is what lets `loreserver outbox retire-generation` tell a
    /// stopped receiver from an idle one, whose caught-up frontier looks the
    /// same. A membership version conflict is adopted and resent once, as the
    /// bootstrap does. Any other refusal falls back to the ordinary final
    /// checkpoint, and the operator then needs `--confirm-receiver-stopped`
    /// to retire this generation. That includes `FrontierRegressed`, which a
    /// single process reporting its own generation should never meet: it is
    /// logged and left unmarked rather than retried with a guessed frontier.
    async fn draining_checkpoint(&self, session: &mut ReceiverSession) {
        for _ in 0..2 {
            let report = session.checkpoint_report(&self.receiver.membership_identity);
            match self.runtime.store.report_draining_checkpoint(&report).await {
                Ok(CheckpointOutcome::Applied {
                    contiguous_frontier,
                }) => {
                    session.reported_frontier = Some(contiguous_frontier);
                    session.events_since_checkpoint = 0;
                    session.last_checkpoint = Instant::now();
                    metrics::record_receiver_checkpoint("draining");
                    info!(
                        cell_id = %self.cell_id,
                        receiver_identity = %self.receiver.membership_identity,
                        membership_generation = session.membership_generation,
                        contiguous_frontier,
                        "marked this receiver generation draining with its final checkpoint"
                    );
                    return;
                }
                Ok(CheckpointOutcome::MembershipVersionConflict {
                    current_membership_version,
                }) => {
                    session.membership_version = current_membership_version;
                }
                Ok(other) => {
                    warn!(
                        cell_id = %self.cell_id,
                        receiver_identity = %self.receiver.membership_identity,
                        membership_generation = session.membership_generation,
                        outcome = ?other,
                        "this receiver generation was not marked draining on shutdown"
                    );
                    break;
                }
                Err(error) => {
                    warn!(
                        cell_id = %self.cell_id,
                        receiver_identity = %self.receiver.membership_identity,
                        membership_generation = session.membership_generation,
                        %error,
                        "this receiver generation was not marked draining on shutdown"
                    );
                    break;
                }
            }
        }
        self.final_checkpoint(session).await;
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
#[lore_macro::test_pub]
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
#[lore_macro::test_pub]
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
#[lore_macro::test_pub]
fn stream_failure(error: StreamError) -> BootstrapFailure {
    match error {
        StreamError::Transient(_) => BootstrapFailure::Transient(REASON_STREAM_UNAVAILABLE),
        StreamError::PlacementMoved { .. } | StreamError::Refused(_) => {
            BootstrapFailure::Retired(REASON_PLACEMENT_MOVED)
        }
    }
}
