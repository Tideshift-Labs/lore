// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Per-replica bounded write-behind scheduling. Database and filesystem ownership
//! remain behind the store's opaque handle.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;

use anyhow::Result;
use anyhow::bail;
use lore_base::lore_spawn;
use lore_postgres::store::fragment_write_behind::CapacityEvidence;
use lore_postgres::store::fragment_write_behind::FragmentWriteBehindHandle;
use lore_postgres::store::fragment_write_behind::ObserveStep;
use lore_postgres::store::fragment_write_behind::ObserveTrace;
use lore_postgres::store::fragment_write_behind::WriteBehindActivity;
use lore_postgres::store::fragment_write_behind::WriteBehindObservation;
use lore_postgres::store::write_behind::StagingMode;
use lore_storage::StoreError;
use lore_telemetry::InstrumentProvider;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use opentelemetry::metrics::Gauge;
use opentelemetry::metrics::Histogram;
use serde::Serialize;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::debug;
use tracing::info;
use tracing::warn;

struct WriteBehindInstrumentProvider;
impl InstrumentProvider for WriteBehindInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.fragment.write_behind"
    }
}
struct Instruments {
    promoted: Counter<u64>,
    cleaned: Counter<u64>,
    ready: Gauge<u64>,
    /// 1 while cleanup is degraded (`Snapshot.degraded`); never a readiness input.
    cleanup_not_progressing: Gauge<u64>,
    pending: Gauge<u64>,
    usage: Gauge<u64>,
    /// Each `observe()` step's duration, by `step` and `outcome`.
    observe_step_ms: Histogram<f64>,
}
fn instruments() -> &'static Instruments {
    static INSTRUMENTS: OnceLock<Instruments> = OnceLock::new();
    INSTRUMENTS.get_or_init(|| {
        let provider = WriteBehindInstrumentProvider;
        let meter = provider.meter();
        Instruments {
            promoted: meter.u64_counter(provider.scope_name("promoted")).build(),
            cleaned: meter.u64_counter(provider.scope_name("cleaned")).build(),
            ready: meter.u64_gauge(provider.scope_name("ready")).build(),
            cleanup_not_progressing: meter
                .u64_gauge(provider.scope_name("cleanup_not_progressing"))
                .build(),
            pending: meter
                .u64_gauge(provider.scope_name("pending_files"))
                .build(),
            usage: meter.u64_gauge(provider.scope_name("usage_bytes")).build(),
            observe_step_ms: provider.latency_histogram_ms("observe_step"),
        }
    })
}

#[derive(Debug, Clone)]
pub(crate) struct FragmentWriteBehindSettings {
    worker_interval: Duration,
    worker_batch: u32,
    observer_interval: Duration,
    stale_after: Duration,
    cleanup_interval: Duration,
    cleanup_batch: u32,
}

impl FragmentWriteBehindSettings {
    pub(crate) fn new(
        worker: u64,
        batch: u32,
        observer: u64,
        stale: u64,
        cleanup: u64,
        cleanup_batch: u32,
    ) -> Result<Self> {
        if [worker, observer, stale, cleanup]
            .iter()
            .any(|value| !(1..=60_000).contains(value))
        {
            bail!("write-behind intervals must be between 1 and 60000 milliseconds");
        }
        if stale <= observer || stale <= worker {
            bail!(
                "drain_stale_after_millis must exceed observer_interval_millis and worker_interval_millis"
            );
        }
        if !(1..=256).contains(&batch) || !(1..=256).contains(&cleanup_batch) {
            bail!("write-behind worker_batch and cleanup_batch must be between 1 and 256");
        }
        Ok(Self {
            worker_interval: Duration::from_millis(worker),
            worker_batch: batch,
            observer_interval: Duration::from_millis(observer),
            stale_after: Duration::from_millis(stale),
            cleanup_interval: Duration::from_millis(cleanup),
            cleanup_batch,
        })
    }
}

#[derive(Default)]
struct State {
    observation: Option<(Instant, WriteBehindObservation)>,
    worker: Option<Instant>,
    progress: Option<Instant>,
    cleanup: Option<Instant>,
    cleanup_progress: Option<Instant>,
    /// When the current unbroken run of backpressure began, per loop. `None`
    /// once a pass completes, so a self-clearing stall leaves no trace.
    drain_backpressure_since: Option<Instant>,
    cleanup_backpressure_since: Option<Instant>,
    /// When the stage last started reporting no room, and still is.
    ///
    /// `capacity_available` is not a free-space measurement. It is a
    /// reconciliation predicate over the stage and spool ledgers, and it goes
    /// false transiently whenever the physical inventory and the charged ledger
    /// disagree — which they do by construction while fragments are arriving.
    /// Recording when the run began is what lets a transient disagreement clear
    /// without ever reaching the readiness verdict.
    capacity_unavailable_since: Option<Instant>,
    /// When the current unbroken run of failed observations began. `None` once
    /// an observation succeeds. The observer was blind for this run, so see
    /// `record_observation` for what that time does and does not count against.
    observation_failed_since: Option<Instant>,
    stopped: bool,
}

pub struct FragmentWriteBehindReadiness {
    handle: Arc<FragmentWriteBehindHandle>,
    state: Mutex<State>,
    stale_after: Duration,
    cleanup_stale_after: Duration,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub mode: &'static str,
    pub ready: bool,
    pub reason: Option<&'static str>,
    /// Slow conditions that do not fail readiness: `ready` can be true while
    /// this is non-empty. A list, like `CapacityDetail.failing`, so a second
    /// condition does not change its shape. See `degraded_reason`.
    pub degraded: Vec<&'static str>,
    pub worker_age_millis: Option<u64>,
    pub observation_age_millis: Option<u64>,
    pub pending_bytes: Option<u64>,
    pub pending_files: Option<u64>,
    pub oldest_pending_age_millis: Option<u64>,
    pub stage_bytes: Option<u64>,
    pub stage_files: Option<u64>,
    pub spool_bytes: Option<u64>,
    pub spool_files: Option<u64>,
    pub cleanup_backlog: Option<u64>,
    /// How long each loop has been under unbroken backpressure. Present so a
    /// 503 can be told apart from a wedge without reading the server log.
    pub drain_backpressure_millis: Option<u64>,
    pub cleanup_backpressure_millis: Option<u64>,
    /// How long the stage has been reporting no room without a break. Present so
    /// a 503 can be told from a transient ledger disagreement without reading the
    /// server log, the same way the backpressure ages are.
    pub capacity_unavailable_millis: Option<u64>,
    /// Which capacity predicates failed at the last observation, the age of
    /// each physical inventory when it was compared, and both sides of each
    /// comparison. The `*_ledger_*` side is the ledger bound that walk was
    /// compared with, not the latest read. Observability only; no readiness
    /// decision reads it.
    pub capacity: Option<CapacityDetail>,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct CapacityDetail {
    pub failing: Vec<&'static str>,
    pub stage_inventory_age_millis: Option<u64>,
    pub spool_inventory_age_millis: Option<u64>,
    pub stage_physical_bytes: Option<u64>,
    pub stage_physical_files: Option<u64>,
    pub stage_ledger_bytes: u64,
    pub stage_ledger_files: u64,
    pub spool_physical_bytes: Option<u64>,
    pub spool_physical_files: Option<u64>,
    pub spool_ledger_bytes: u64,
    pub spool_ledger_files: u64,
    pub available_bytes: Option<u64>,
}

impl From<&CapacityEvidence> for CapacityDetail {
    fn from(evidence: &CapacityEvidence) -> Self {
        Self {
            failing: evidence.failing.clone(),
            stage_inventory_age_millis: evidence.stage_inventory_age.map(millis),
            spool_inventory_age_millis: evidence.spool_inventory_age.map(millis),
            stage_physical_bytes: evidence.stage_physical_bytes,
            stage_physical_files: evidence.stage_physical_files,
            stage_ledger_bytes: evidence.stage_ledger_bytes,
            stage_ledger_files: evidence.stage_ledger_files,
            spool_physical_bytes: evidence.spool_physical_bytes,
            spool_physical_files: evidence.spool_physical_files,
            spool_ledger_bytes: evidence.spool_ledger_bytes,
            spool_ledger_files: evidence.spool_ledger_files,
            available_bytes: evidence.available_bytes,
        }
    }
}

/// `Some(new value)` when this observation flips `capacity_available`, or is
/// the first after a gap and reports it false. A first observation reporting
/// true is the expected state and is not a transition worth a log line.
fn capacity_transition(previous: Option<bool>, current: bool) -> Option<bool> {
    match previous {
        Some(previous) if previous == current => None,
        None if current => None,
        _ => Some(current),
    }
}

/// Record a successful observation and return the capacity transition it made,
/// if any. The caller logs the transition after releasing the state lock.
fn record_capacity_observation(
    state: &mut State,
    observation: WriteBehindObservation,
    at: Instant,
) -> Option<(bool, CapacityDetail)> {
    let previous = state
        .observation
        .as_ref()
        .map(|(_, value)| value.capacity_available);
    let transition = capacity_transition(previous, observation.capacity_available)
        .map(|available| (available, CapacityDetail::from(&observation.capacity)));
    record_observation(state, Some(observation), at);
    transition
}

fn log_capacity_transition(available: bool, detail: &CapacityDetail) {
    if available {
        info!(?detail, "write-behind capacity predicate holds again");
    } else {
        info!(?detail, "write-behind capacity predicate failed");
    }
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

/// Which worker loop a pass belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PassLoop {
    Drain,
    Cleanup,
}

/// What one worker pass says about the loop that ran it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PassOutcome {
    /// The pass completed.
    Advanced,
    /// The store asked this loop to yield its tick.
    Backpressure,
    /// Anything else. The loop may be wedged.
    Failed,
}

/// Separate backpressure from failure at the point the outcome is recorded.
///
/// `SlowDown` is already the store layer's name for "transient": `domain_store_err`
/// and `provider_store_err` map every non-transient failure to `StoreError::Internal`,
/// so singling it out here cannot swallow a real fault.
fn classify_pass<T>(result: &Result<T, StoreError>) -> PassOutcome {
    match result {
        Ok(_) => PassOutcome::Advanced,
        Err(StoreError::SlowDown(_)) => PassOutcome::Backpressure,
        Err(_) => PassOutcome::Failed,
    }
}

/// Fold one pass's outcome into readiness state.
///
/// **Backpressure is not unreadiness.** A loop that is told to slow down is
/// alive and answering; only a loop that cannot run is wedged. Freezing the loop
/// clock on a `SlowDown` is what turns a self-clearing timing condition into
/// `worker_stale`/`cleanup_stale`, which ejects the replica from the load
/// balancer and drops admission to `DirectFallback`. So backpressure advances
/// the loop clock and leaves the *progress* clock alone, because nothing was
/// drained or cleaned.
///
/// A `Failed` pass still freezes both clocks, so a genuine wedge ages out to 503
/// exactly as before.
///
/// Sustained backpressure is not hidden: the first stall of a run is remembered,
/// and `readiness_reason` reports it once the run outlives the same budget a
/// frozen clock would have been given.
///
/// Pure and synchronous, so these rules are testable without a store, a runtime
/// or a Postgres fixture.
fn record_pass_outcome(
    state: &mut State,
    loop_kind: PassLoop,
    outcome: PassOutcome,
    at: Instant,
    progressed: bool,
) {
    if outcome == PassOutcome::Failed {
        return;
    }
    let (clock, progress_clock, backpressure_since) = match loop_kind {
        PassLoop::Drain => (
            &mut state.worker,
            &mut state.progress,
            &mut state.drain_backpressure_since,
        ),
        PassLoop::Cleanup => (
            &mut state.cleanup,
            &mut state.cleanup_progress,
            &mut state.cleanup_backpressure_since,
        ),
    };
    *clock = Some(at);
    if outcome == PassOutcome::Advanced {
        *backpressure_since = None;
        if progressed {
            *progress_clock = Some(at);
        }
    } else {
        // Keep the start of the run, not the latest stall, or the age never grows.
        backpressure_since.get_or_insert(at);
    }
}

/// Fold one observation into readiness state.
///
/// **A stage with no room is not the same claim as a ledger that disagrees with
/// itself.** `capacity_available` is computed by comparing the last completed
/// physical inventory against the charged ledger read around that walk (the
/// larger of the reads before it started and after it completed). A walk that
/// overlapped both new charges and releases can still exceed both reads, so the
/// predicate can go false transiently while fragments are being staged. Treating that instant as unreadiness is what
/// ejects every replica of a cell at once, because they all read the same ledger.
///
/// So the run is remembered and `readiness_reason` reports it only once it has
/// outlived the same budget every other transient condition is given. A stage
/// that is genuinely full never recovers, so it still reaches 503 one budget
/// later.
///
/// An observation that could not be taken CLEARS the run. Not knowing is not
/// evidence that room returned, but it is equally not evidence that the stage is
/// full, and the two mistakes are not symmetric. Keeping the run across a gap
/// means the first sample after recovery arrives with the budget already spent,
/// so a cell-wide `observe()` blip — one database stall reaches every replica
/// identically — is followed by an instant all-replica ejection on the very next
/// ordinary transient disagreement. That is the failure this change exists to
/// remove. Clearing costs one extra budget before a genuinely full stage ages
/// out.
///
/// **A failed observation is not an unknown one yet (row 76).** It keeps the
/// last good observation, which ages out over `stale_after` like every other
/// transient condition, so `observation_unknown` answers 503 only once the
/// failures have outlived the budget. A one-tick `observe()` stall used to answer
/// 503 at once, and when it met a peer's own 503 the cell had no ready replica.
///
/// **Blind time is not drain time.** Drain progress is credited only by this
/// replica's own promotions or a fresh observation showing nothing pending, and
/// `pending_files` is cell-wide. During a run of failed observations nothing can
/// credit it, so the first good observation after a long run found the clock
/// already past `stale_after` and answered `drain_not_progressing` at once. So
/// the first good observation after a run extends the progress clock by the
/// length of the run, capped at now. It is extended, not reset: age the clock
/// had before the run survives it, so a wedged drain behind flapping
/// observations still ages out.
///
/// **A cell-wide cleanup backlog that fell since the last sample is cleanup
/// progress.** A pass reports progress only for a body it unlinked, so a release
/// that finishes a row whose body an earlier, lost release already unlinked
/// counts as nothing. The backlog falls only when a row is released, by any
/// replica, so it is the direct measure. A gap leaves nothing to compare with.
/// The cost: a replica whose passes succeed but clean nothing reads ready while
/// a peer drains the cell. A replica whose passes fail still ages out through
/// `cleanup_stale`.
///
/// Pure and synchronous, so the rule is testable without a store, a runtime or a
/// Postgres fixture — the same reason `record_pass_outcome` is.
fn record_observation(state: &mut State, observation: Option<WriteBehindObservation>, at: Instant) {
    let Some(value) = observation else {
        state.capacity_unavailable_since = None;
        state.observation_failed_since.get_or_insert(at);
        return;
    };
    let after_gap = state.observation_failed_since.take();
    if let Some(failed_since) = after_gap {
        let blind = at.saturating_duration_since(failed_since);
        state.progress = state
            .progress
            .map(|progress| progress.checked_add(blind).map_or(at, |end| end.min(at)));
    }
    if value.capacity_available {
        state.capacity_unavailable_since = None;
    } else {
        state.capacity_unavailable_since.get_or_insert(at);
    }
    if after_gap.is_none()
        && state
            .observation
            .as_ref()
            .is_some_and(|(_, previous)| value.cleanup_backlog < previous.cleanup_backlog)
    {
        state.cleanup_progress = state.cleanup_progress.max(Some(at));
    }
    state.observation = Some((at, value));
}

/// How one `observe()` attempt ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObserveOutcome {
    Ok,
    Failed,
    TimedOut,
}

impl ObserveOutcome {
    fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "error",
            Self::TimedOut => "timeout",
        }
    }
}

/// Each step of one attempt with its duration. A step that never returned is
/// timed up to `now` and flagged, so a timeout names the step it was waiting on.
fn step_timings(trace: &ObserveTrace, now: Instant) -> Vec<(ObserveStep, Duration, bool)> {
    let mut steps: Vec<_> = trace
        .completed
        .iter()
        .map(|(step, elapsed)| (*step, *elapsed, false))
        .collect();
    if let Some((step, started)) = trace.in_flight {
        steps.push((step, now.saturating_duration_since(started), true));
    }
    steps
}

fn format_steps(steps: &[(ObserveStep, Duration, bool)]) -> String {
    steps
        .iter()
        .map(|(step, elapsed, in_flight)| {
            let suffix = if *in_flight { "(in_flight)" } else { "" };
            format!("{}={}ms{suffix}", step.name(), millis(*elapsed))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether an attempt deserves a warning: it did not succeed, a step took at
/// least `threshold`, or the attempt started at least two intervals after the
/// previous one (the observer itself was late, not a step).
fn observe_attempt_is_slow(
    outcome: ObserveOutcome,
    steps: &[(ObserveStep, Duration, bool)],
    threshold: Duration,
    since_last_attempt: Option<Duration>,
    interval: Duration,
) -> bool {
    outcome != ObserveOutcome::Ok
        || steps.iter().any(|(_, elapsed, _)| *elapsed >= threshold)
        || since_last_attempt.is_some_and(|gap| gap >= interval * 2)
}

/// At most one warning per `every`, counting what it held back.
#[derive(Default)]
struct WarnLimiter {
    last: Option<Instant>,
    suppressed: u64,
}

impl WarnLimiter {
    /// `Some(warnings held back since the last one)` when a warning may be
    /// logged at `at`, else `None`.
    fn allow(&mut self, at: Instant, every: Duration) -> Option<u64> {
        if self
            .last
            .is_some_and(|last| at.saturating_duration_since(last) < every)
        {
            self.suppressed += 1;
            None
        } else {
            self.last = Some(at);
            Some(std::mem::take(&mut self.suppressed))
        }
    }
}

const OBSERVE_WARN_EVERY: Duration = Duration::from_secs(10);

/// Log and record one attempt's step timings: debug always, a rate-limited warn
/// when the attempt was slow, and one histogram sample per step.
fn report_observe_attempt(
    trace: &ObserveTrace,
    outcome: ObserveOutcome,
    error: Option<&str>,
    since_last_attempt: Option<Duration>,
    interval: Duration,
    limiter: &mut WarnLimiter,
) {
    let now = Instant::now();
    let steps = step_timings(trace, now);
    for (step, elapsed, in_flight) in &steps {
        let step_outcome = if *in_flight {
            ObserveOutcome::TimedOut.name()
        } else if trace.failed == Some(*step) {
            ObserveOutcome::Failed.name()
        } else {
            ObserveOutcome::Ok.name()
        };
        instruments().observe_step_ms.record(
            elapsed.as_secs_f64() * 1000.0,
            &[
                KeyValue::new("step", step.name()),
                KeyValue::new("outcome", step_outcome),
            ],
        );
    }
    let formatted = format_steps(&steps);
    let since_last_attempt_ms = since_last_attempt.map(millis);
    debug!(
        outcome = outcome.name(),
        steps = %formatted,
        ?since_last_attempt_ms,
        error,
        "write-behind observe timing"
    );
    if observe_attempt_is_slow(outcome, &steps, interval / 2, since_last_attempt, interval)
        && let Some(suppressed) = limiter.allow(now, OBSERVE_WARN_EVERY)
    {
        warn!(
            outcome = outcome.name(),
            steps = %formatted,
            ?since_last_attempt_ms,
            error,
            suppressed,
            "write-behind observe slow or failed"
        );
    }
}

fn readiness_reason(
    state: &State,
    stale_after: Duration,
    cleanup_stale_after: Duration,
) -> Option<&'static str> {
    let observation = state.observation.as_ref().map(|(_, value)| value);
    let observation_age = state.observation.as_ref().map(|(at, _)| at.elapsed());
    let worker_age = state.worker.map(|at| at.elapsed());
    if state.stopped {
        Some("worker_stopped")
    } else if observation_age.is_none_or(|age| age >= stale_after) {
        Some("observation_unknown")
    } else if observation.is_none_or(|value| !value.roots_usable) {
        Some("root_unavailable")
    } else if state
        .capacity_unavailable_since
        .is_some_and(|at| at.elapsed() >= stale_after)
    {
        Some("capacity_unavailable")
    } else if worker_age.is_none_or(|age| age >= stale_after) {
        Some("worker_stale")
    } else if state
        .drain_backpressure_since
        .is_some_and(|at| at.elapsed() >= stale_after)
    {
        // Backpressure that has outlived the budget a frozen clock would have
        // been given is no longer transient.
        Some("drain_backpressure_sustained")
    } else if observation.is_some_and(|value| value.pending_files > 0)
        && state.progress.is_none_or(|at| at.elapsed() >= stale_after)
    {
        Some("drain_not_progressing")
    } else if state
        .cleanup
        .is_none_or(|at| at.elapsed() >= cleanup_stale_after)
    {
        Some("cleanup_stale")
    } else if state
        .cleanup_backpressure_since
        .is_some_and(|at| at.elapsed() >= cleanup_stale_after)
    {
        Some("cleanup_backpressure_sustained")
    } else {
        None
    }
}

/// A slow condition that is reported but does not fail readiness.
///
/// **A slow cell-wide cleanup is not unreadiness (INV-FT, row 71).** The backlog
/// is shared by the cell, so the verdict is the same on every replica: failing
/// readiness on it ejects all of them at once, and taking a replica out of the
/// load balancer does not speed cleanup up. Spool exhaustion from slow cleanup
/// is already gated by `capacity_unavailable`, and a cleanup loop that cannot
/// run still fails readiness through `cleanup_stale` and
/// `cleanup_backpressure_sustained`. So this is a snapshot field and a metric,
/// never a 503 or `direct_fallback`.
fn degraded_reason(state: &State, cleanup_stale_after: Duration) -> Option<&'static str> {
    let observation = state.observation.as_ref().map(|(_, value)| value);
    if observation.is_some_and(|value| value.cleanup_backlog > 0)
        && state
            .cleanup_progress
            .is_none_or(|at| at.elapsed() >= cleanup_stale_after)
    {
        Some("cleanup_not_progressing")
    } else {
        None
    }
}

/// Record 1 on `gauge` while `degraded` names `cleanup_not_progressing`, else 0.
fn record_cleanup_not_progressing(gauge: &Gauge<u64>, degraded: &[&'static str]) {
    gauge.record(
        u64::from(degraded.contains(&"cleanup_not_progressing")),
        &[],
    );
}

/// Merge completed per-item activity without extending any timestamp merely
/// because the observer ran. A wedged next operation still ages out naturally.
fn refresh_activity(state: &mut State, activity: WriteBehindActivity) {
    state.worker = state.worker.max(activity.drain_loop);
    state.progress = state.progress.max(activity.drain_progress);
    state.cleanup = state.cleanup.max(activity.cleanup_loop);
    state.cleanup_progress = state.cleanup_progress.max(activity.cleanup_progress);
}

impl FragmentWriteBehindReadiness {
    pub fn snapshot(&self) -> Snapshot {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        refresh_activity(&mut state, self.handle.activity());
        let observation = state.observation.as_ref().map(|(_, value)| value);
        let observation_age = state.observation.as_ref().map(|(at, _)| at.elapsed());
        let worker_age = state.worker.map(|at| at.elapsed());
        let reason = readiness_reason(&state, self.stale_after, self.cleanup_stale_after);
        Snapshot {
            mode: match self.handle.mode() {
                StagingMode::Stage => "stage",
                StagingMode::DirectFallback => "direct_fallback",
                StagingMode::Refuse => "refuse",
                StagingMode::Unready => "unready",
            },
            ready: reason.is_none(),
            reason,
            degraded: degraded_reason(&state, self.cleanup_stale_after)
                .into_iter()
                .collect(),
            worker_age_millis: worker_age.map(millis),
            observation_age_millis: observation_age.map(millis),
            pending_bytes: observation.map(|value| value.pending_bytes),
            pending_files: observation.map(|value| value.pending_files),
            oldest_pending_age_millis: observation
                .and_then(|value| value.oldest_pending_age)
                .map(millis),
            stage_bytes: observation.map(|value| value.stage_bytes),
            stage_files: observation.map(|value| value.stage_files),
            spool_bytes: observation.map(|value| value.spool_bytes),
            spool_files: observation.map(|value| value.spool_files),
            cleanup_backlog: observation.map(|value| value.cleanup_backlog),
            drain_backpressure_millis: state
                .drain_backpressure_since
                .map(|at| millis(at.elapsed())),
            cleanup_backpressure_millis: state
                .cleanup_backpressure_since
                .map(|at| millis(at.elapsed())),
            capacity_unavailable_millis: state
                .capacity_unavailable_since
                .map(|at| millis(at.elapsed())),
            capacity: observation.map(|value| CapacityDetail::from(&value.capacity)),
        }
    }
}

struct StopGuard(
    Arc<FragmentWriteBehindHandle>,
    Arc<FragmentWriteBehindReadiness>,
);
impl Drop for StopGuard {
    fn drop(&mut self) {
        self.0.note_worker_stopped();
        self.1
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stopped = true;
    }
}

/// A missing handle is inert; partial enabled composition is refused.
pub(crate) fn configure_fragment_write_behind(
    handle: Option<Arc<FragmentWriteBehindHandle>>,
    settings: Option<FragmentWriteBehindSettings>,
    endpoints: &mut JoinSet<Result<()>>,
    shutdown: watch::Receiver<bool>,
) -> Result<Option<Arc<FragmentWriteBehindReadiness>>> {
    let (handle, settings) = match (handle, settings) {
        (None, None) => return Ok(None),
        (Some(handle), Some(settings)) => (handle, settings),
        _ => bail!("write-behind runtime composition is incomplete"),
    };
    let readiness = Arc::new(FragmentWriteBehindReadiness {
        handle: handle.clone(),
        state: Mutex::new(State::default()),
        stale_after: settings.stale_after,
        cleanup_stale_after: settings.cleanup_interval * 2 + settings.stale_after,
    });
    let worker_handle = handle.clone();
    let worker_readiness = readiness.clone();
    let mut worker_shutdown = shutdown.clone();
    lore_spawn!(endpoints, async move {
        let _guard = StopGuard(worker_handle.clone(), worker_readiness.clone());
        let mut ticks = tokio::time::interval(settings.worker_interval);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! { biased;
                _ = worker_shutdown.wait_for(|value| *value) => break,
                _ = ticks.tick() => {}
            }
            // Cancellation leaves the durable claim's late-effect barrier intact.
            let result = tokio::select! { biased;
                _ = worker_shutdown.wait_for(|value| *value) => break,
                result = worker_handle.drain_pass(settings.worker_batch) => result,
            };
            let outcome = classify_pass(&result);
            match &result {
                Ok(promoted) => instruments().promoted.add(u64::from(*promoted), &[]),
                // Backpressure is expected and self-clearing; only a real
                // failure deserves a warning.
                Err(error) if outcome == PassOutcome::Backpressure => {
                    debug!(%error, "write-behind drain pass yielded to backpressure");
                }
                Err(error) => warn!(%error, "write-behind drain pass failed"),
            }
            {
                let mut state = worker_readiness
                    .state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let progressed = state.observation.as_ref().is_some_and(|(at, value)| {
                    at.elapsed() < settings.stale_after && value.pending_files == 0
                });
                record_pass_outcome(
                    &mut state,
                    PassLoop::Drain,
                    outcome,
                    Instant::now(),
                    progressed,
                );
            }
        }
        Ok(())
    });
    let cleanup_handle = handle.clone();
    let cleanup_readiness = readiness.clone();
    let mut cleanup_shutdown = shutdown.clone();
    lore_spawn!(endpoints, async move {
        let mut ticks = tokio::time::interval(settings.cleanup_interval);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! { biased;
                _ = cleanup_shutdown.wait_for(|value| *value) => break,
                _ = ticks.tick() => {}
            }
            let result = tokio::select! { biased;
                _ = cleanup_shutdown.wait_for(|value| *value) => break,
                result = cleanup_handle.cleanup_pass(settings.cleanup_batch) => result,
            };
            let outcome = classify_pass(&result);
            match &result {
                Ok(cleaned) => instruments().cleaned.add(u64::from(*cleaned), &[]),
                Err(error) if outcome == PassOutcome::Backpressure => {
                    debug!(%error, "write-behind cleanup pass yielded to backpressure");
                }
                Err(error) => warn!(%error, "write-behind cleanup pass failed"),
            }
            {
                let mut state = cleanup_readiness
                    .state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let progressed = state.observation.as_ref().is_some_and(|(at, value)| {
                    at.elapsed() < settings.stale_after && value.cleanup_backlog == 0
                });
                record_pass_outcome(
                    &mut state,
                    PassLoop::Cleanup,
                    outcome,
                    Instant::now(),
                    progressed,
                );
            }
        }
        Ok(())
    });
    let observer_readiness = readiness.clone();
    let mut observer_shutdown = shutdown;
    lore_spawn!(endpoints, async move {
        let mut ticks = tokio::time::interval(settings.observer_interval);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut limiter = WarnLimiter::default();
        let mut previous_attempt: Option<Instant> = None;
        loop {
            tokio::select! { biased;
                _ = observer_shutdown.wait_for(|value| *value) => break,
                _ = ticks.tick() => {}
            }
            handle.note_observation_unknown();
            let attempt = Instant::now();
            let result = tokio::select! { biased;
                _ = observer_shutdown.wait_for(|value| *value) => break,
                result = tokio::time::timeout(settings.observer_interval, handle.observe()) => result,
            };
            let (outcome, error) = match &result {
                Ok(Ok(_)) => (ObserveOutcome::Ok, None),
                Ok(Err(error)) => (ObserveOutcome::Failed, Some(error.to_string())),
                Err(_) => (ObserveOutcome::TimedOut, None),
            };
            report_observe_attempt(
                &handle.observe_trace(),
                outcome,
                error.as_deref(),
                previous_attempt.map(|previous| attempt.saturating_duration_since(previous)),
                settings.observer_interval,
                &mut limiter,
            );
            previous_attempt = Some(attempt);
            if let Ok(Ok(observation)) = result {
                instruments().pending.record(observation.pending_files, &[]);
                instruments()
                    .usage
                    .record(observation.stage_bytes, &[KeyValue::new("root", "stage")]);
                instruments()
                    .usage
                    .record(observation.spool_bytes, &[KeyValue::new("root", "spool")]);
                // Explicit block, matching the worker loops: the guard is released at the
                // brace rather than at a statement temporary, so `snapshot()` below cannot
                // be folded into the same expression and self-deadlock this std `Mutex`.
                let transition = {
                    let mut state = observer_readiness
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    record_capacity_observation(&mut state, observation, Instant::now())
                };
                if let Some((available, detail)) = transition {
                    log_capacity_transition(available, &detail);
                }
                if observer_readiness.snapshot().ready {
                    handle.note_drain_heartbeat();
                } else {
                    handle.note_worker_stopped();
                }
            } else {
                {
                    let mut state = observer_readiness
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    record_observation(&mut state, None, Instant::now());
                }
                handle.note_observation_unknown();
                // Inside the budget the last good observation still stands, so the
                // drain heartbeat is left to age out over the same `stale_after`
                // rather than dropped at once.
                if !observer_readiness.snapshot().ready {
                    handle.note_worker_stopped();
                }
            }
            let snapshot = observer_readiness.snapshot();
            instruments().ready.record(
                u64::from(snapshot.ready),
                &[KeyValue::new(
                    "reason",
                    snapshot.reason.unwrap_or("healthy"),
                )],
            );
            record_cleanup_not_progressing(
                &instruments().cleanup_not_progressing,
                &snapshot.degraded,
            );
        }
        handle.note_worker_stopped();
        Ok(())
    });
    Ok(Some(readiness))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_scheduler_settings_require_room_for_fresh_observations() {
        assert!(FragmentWriteBehindSettings::new(1000, 64, 1000, 5000, 5000, 64).is_ok());
        for (worker, batch, observer, stale, cleanup, cleanup_batch) in [
            (0, 64, 1000, 5000, 5000, 64),
            (1000, 0, 1000, 5000, 5000, 64),
            (1000, 257, 1000, 5000, 5000, 64),
            (1000, 64, 0, 5000, 5000, 64),
            (1000, 64, 5000, 5000, 5000, 64),
            (5000, 64, 1000, 5000, 5000, 64),
            (1000, 64, 1000, 5000, 60_001, 64),
            (1000, 64, 1000, 5000, 5000, 0),
            (1000, 64, 1000, 5000, 5000, 257),
        ] {
            assert!(
                FragmentWriteBehindSettings::new(
                    worker,
                    batch,
                    observer,
                    stale,
                    cleanup,
                    cleanup_batch
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn absent_configuration_starts_no_tasks_and_partial_configuration_refuses() {
        let mut tasks = JoinSet::new();
        let (_, shutdown) = watch::channel(false);
        assert!(
            configure_fragment_write_behind(None, None, &mut tasks, shutdown.clone())
                .unwrap()
                .is_none()
        );
        assert!(tasks.is_empty());
        let settings = FragmentWriteBehindSettings::new(1000, 64, 1000, 5000, 5000, 64).unwrap();
        assert!(
            configure_fragment_write_behind(None, Some(settings), &mut tasks, shutdown).is_err()
        );
        assert!(tasks.is_empty());
    }

    fn reason(state: &State) -> Option<&'static str> {
        readiness_reason(state, Duration::from_secs(5), Duration::from_secs(15))
    }

    fn degraded(state: &State) -> Option<&'static str> {
        degraded_reason(state, Duration::from_secs(15))
    }

    #[test]
    fn no_observation_or_stopped_worker_never_reports_ready() {
        let mut state = State::default();
        assert_eq!(reason(&state), Some("observation_unknown"));
        state.stopped = true;
        assert_eq!(reason(&state), Some("worker_stopped"));
    }

    #[test]
    fn per_item_activity_keeps_a_long_batch_healthy_but_cannot_hide_a_blocked_operation() {
        let now = Instant::now();
        let old = now - Duration::from_secs(30);
        let mut state = State {
            observation: Some((
                now,
                WriteBehindObservation {
                    pending_files: 4,
                    pending_bytes: 512,
                    stage_bytes: 512,
                    stage_files: 4,
                    spool_bytes: 128,
                    spool_files: 1,
                    oldest_pending_age: None,
                    cleanup_backlog: 4,
                    roots_usable: true,
                    capacity_available: true,
                    capacity: CapacityEvidence::default(),
                },
            )),
            worker: Some(old),
            progress: Some(old),
            cleanup: Some(old),
            cleanup_progress: Some(old),
            stopped: false,
            ..State::default()
        };
        assert_eq!(reason(&state), Some("worker_stale"));
        refresh_activity(
            &mut state,
            WriteBehindActivity {
                drain_loop: Some(now),
                drain_progress: Some(now),
                cleanup_loop: Some(now),
                cleanup_progress: Some(now),
            },
        );
        assert_eq!(
            reason(&state),
            None,
            "per-item progress does not wait for the whole batch"
        );
        refresh_activity(
            &mut state,
            WriteBehindActivity {
                drain_loop: Some(old),
                drain_progress: Some(old),
                cleanup_loop: Some(old),
                cleanup_progress: Some(old),
            },
        );
        assert_eq!(
            state.progress,
            Some(now),
            "old snapshots cannot regress progress"
        );
        state.progress = Some(old);
        refresh_activity(
            &mut state,
            WriteBehindActivity {
                drain_loop: Some(now),
                ..WriteBehindActivity::default()
            },
        );
        assert_eq!(
            reason(&state),
            Some("drain_not_progressing"),
            "loop activity alone cannot hide a blocked item"
        );
        state.progress = Some(now);
        state.observation.as_mut().unwrap().0 = old;
        assert_eq!(
            reason(&state),
            Some("observation_unknown"),
            "progress cannot replace an observation"
        );
    }

    #[test]
    fn stale_observation_dead_worker_and_blocked_backlog_each_disable_admission() {
        let now = Instant::now();
        let old = now - Duration::from_secs(30);
        let observation = WriteBehindObservation {
            pending_files: 0,
            pending_bytes: 0,
            stage_bytes: 128,
            stage_files: 1,
            spool_bytes: 128,
            spool_files: 1,
            oldest_pending_age: None,
            cleanup_backlog: 0,
            roots_usable: true,
            capacity_available: true,
            capacity: CapacityEvidence::default(),
        };
        let mut state = State {
            observation: Some((now, observation)),
            worker: Some(now),
            progress: None,
            cleanup: Some(now),
            cleanup_progress: None,
            stopped: false,
            ..State::default()
        };
        assert_eq!(
            reason(&state),
            None,
            "idle with fresh observations is healthy"
        );
        state.observation.as_mut().unwrap().0 = old;
        assert_eq!(reason(&state), Some("observation_unknown"));
        state.observation.as_mut().unwrap().0 = now;
        state.worker = Some(old);
        assert_eq!(reason(&state), Some("worker_stale"));
        state.worker = Some(now);
        state.observation.as_mut().unwrap().1.pending_files = 1;
        assert_eq!(reason(&state), Some("drain_not_progressing"));
        state.progress = Some(now);
        assert_eq!(reason(&state), None);
        state.observation.as_mut().unwrap().1.roots_usable = false;
        assert_eq!(reason(&state), Some("root_unavailable"));
        state.observation.as_mut().unwrap().1.roots_usable = true;

        // `capacity_unavailable` needs its run to outlive `stale_after`
        // before it reports -- route through `record_observation` (one old
        // sample to start the run, one fresh one so the observation itself
        // stays current) so this pins the same run-tracking the observer
        // loop relies on, not just a raw flag flip.
        record_observation(&mut state, Some(capacity_observation(false)), old);
        record_observation(&mut state, Some(capacity_observation(false)), now);
        assert_eq!(reason(&state), Some("capacity_unavailable"));

        record_observation(&mut state, Some(capacity_observation(true)), now);
        state.observation.as_mut().unwrap().1.cleanup_backlog = 1;
        assert_eq!(
            reason(&state),
            None,
            "a slow cell-wide cleanup is degraded, not unready"
        );
        assert_eq!(degraded(&state), Some("cleanup_not_progressing"));
        state.cleanup_progress = Some(now);
        assert_eq!(reason(&state), None);
        assert_eq!(degraded(&state), None);
    }

    // --- Row 71: cleanup_not_progressing is degraded, not unready ----------

    #[test]
    fn cleanup_not_progressing_never_fails_readiness_and_is_reported_as_degraded() {
        // INV-FT: the backlog is cell-wide, so failing readiness on it ejects every replica at
        // once while slow cleanup is the only effect (row 2: 106 of 471 dual-503 rounds).
        let now = Instant::now();
        let old = now - Duration::from_secs(600);
        let mut state = healthy_state(now);
        state.cleanup_progress = Some(old);
        record_observation(&mut state, Some(backlog_observation(654)), now);
        assert_eq!(reason(&state), None);
        assert_eq!(degraded(&state), Some("cleanup_not_progressing"));
        // No backlog, no degraded signal, however old the progress clock.
        record_observation(&mut state, Some(backlog_observation(0)), now);
        state.cleanup_progress = Some(old);
        assert_eq!(degraded(&state), None);
    }

    /// The gauge the observer records each pass, read back from a meter of this test's own rather
    /// than the process-wide one the instruments use.
    #[test]
    fn the_cleanup_not_progressing_gauge_follows_the_degraded_field() {
        use opentelemetry::metrics::MeterProvider as _;
        use opentelemetry_sdk::metrics::InMemoryMetricExporter;
        use opentelemetry_sdk::metrics::SdkMeterProvider;
        use opentelemetry_sdk::metrics::data::AggregatedMetrics;
        use opentelemetry_sdk::metrics::data::MetricData;

        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_periodic_exporter(exporter.clone())
            .build();
        let gauge = provider
            .meter("test")
            .u64_gauge("cleanup_not_progressing")
            .build();
        let value = || {
            provider.force_flush().expect("flush the test meter");
            let metrics = exporter.get_finished_metrics().expect("read metrics");
            let resource = metrics.last().expect("one export per flush");
            let metric = resource
                .scope_metrics()
                .flat_map(|scope| scope.metrics())
                .next()
                .expect("the gauge was recorded");
            match metric.data() {
                AggregatedMetrics::U64(MetricData::Gauge(gauge)) => {
                    gauge.data_points().next().expect("one data point").value()
                }
                data => panic!("expected a u64 gauge, got {data:?}"),
            }
        };
        let degraded_now = |state: &State| -> Vec<&'static str> {
            degraded_reason(state, Duration::from_secs(15))
                .into_iter()
                .collect()
        };

        let now = Instant::now();
        let mut state = healthy_state(now);
        state.cleanup_progress = Some(now - Duration::from_secs(600));
        record_observation(&mut state, Some(backlog_observation(654)), now);
        let degraded = degraded_now(&state);
        assert_eq!(degraded, ["cleanup_not_progressing"]);
        record_cleanup_not_progressing(&gauge, &degraded);
        assert_eq!(value(), 1);

        state.cleanup_progress = Some(now);
        let degraded = degraded_now(&state);
        assert!(degraded.is_empty());
        record_cleanup_not_progressing(&gauge, &degraded);
        assert_eq!(value(), 0);

        // Only that name sets it: another degraded condition leaves it at 0.
        record_cleanup_not_progressing(&gauge, &["some_other_condition"]);
        assert_eq!(value(), 0);
    }

    #[test]
    fn the_cleanup_signals_that_stay_readiness_failing_still_fail_readiness() {
        let now = Instant::now();
        let old = now - Duration::from_secs(30);

        let mut state = healthy_state(now);
        state.cleanup = Some(old);
        assert_eq!(reason(&state), Some("cleanup_stale"));

        let mut state = healthy_state(now);
        state.cleanup_backpressure_since = Some(old);
        assert_eq!(reason(&state), Some("cleanup_backpressure_sustained"));

        // A readiness failure outranks the degraded field: an unready replica reports its
        // reason, and the degraded field still says what else is slow.
        let mut state = healthy_state(now);
        state.cleanup = Some(old);
        state.cleanup_progress = Some(old);
        record_observation(&mut state, Some(backlog_observation(10)), now);
        assert_eq!(reason(&state), Some("cleanup_stale"));
        assert_eq!(degraded(&state), Some("cleanup_not_progressing"));
    }

    // --- A falling cell-wide cleanup backlog is cleanup progress -----------

    fn backlog_observation(cleanup_backlog: u64) -> WriteBehindObservation {
        WriteBehindObservation {
            cleanup_backlog,
            ..healthy_observation()
        }
    }

    #[test]
    fn a_falling_cleanup_backlog_counts_as_cleanup_progress() {
        // Row 34, 2026-09-27: after load stopped, releases of spool rows whose body an earlier,
        // lost release had already unlinked removed no file, so no pass reported progress. The
        // backlog fell from 654 to 102 over 35 minutes while both idle replicas answered 503
        // `cleanup_not_progressing`. The backlog falling is the progress.
        let now = Instant::now();
        let old = now - Duration::from_secs(30);
        let mut state = healthy_state(now);
        state.cleanup_progress = Some(old);
        record_observation(&mut state, Some(backlog_observation(654)), now);
        assert_eq!(degraded(&state), Some("cleanup_not_progressing"));
        record_observation(&mut state, Some(backlog_observation(643)), now);
        assert_eq!(state.cleanup_progress, Some(now));
        assert_eq!(degraded(&state), None);
    }

    #[test]
    fn a_flat_or_rising_cleanup_backlog_is_not_cleanup_progress() {
        let now = Instant::now();
        let old = now - Duration::from_secs(30);
        for next in [654, 655] {
            let mut state = healthy_state(now);
            state.cleanup_progress = Some(old);
            record_observation(&mut state, Some(backlog_observation(654)), now);
            record_observation(&mut state, Some(backlog_observation(next)), now);
            assert_eq!(state.cleanup_progress, Some(old), "backlog {next}");
            assert_eq!(degraded(&state), Some("cleanup_not_progressing"));
        }
    }

    #[test]
    fn a_backlog_read_after_an_observation_gap_is_not_cleanup_progress() {
        // No earlier sample means nothing to compare against.
        let now = Instant::now();
        let old = now - Duration::from_secs(30);
        let mut state = healthy_state(now);
        state.cleanup_progress = Some(old);
        record_observation(&mut state, Some(backlog_observation(654)), now);
        record_observation(&mut state, None, now);
        record_observation(&mut state, Some(backlog_observation(10)), now);
        assert_eq!(state.cleanup_progress, Some(old));
        assert_eq!(degraded(&state), Some("cleanup_not_progressing"));
    }

    // --- Row 76: a failed observation ages out; a gap does not spend drain budget --

    fn pending_observation(pending_files: u64) -> WriteBehindObservation {
        WriteBehindObservation {
            pending_files,
            ..healthy_observation()
        }
    }

    #[test]
    fn a_failed_observation_keeps_the_last_good_one_until_it_is_stale() {
        // Row 76: a 1-sample `observe()` failure on one replica answered 503 at once, at the
        // same second a peer was unready, so both replicas were out of the balancer.
        let now = Instant::now();
        let mut state = healthy_state(now);
        record_observation(
            &mut state,
            Some(healthy_observation()),
            now - Duration::from_secs(1),
        );
        record_observation(&mut state, None, now);
        assert_eq!(
            reason(&state),
            None,
            "a failure inside the stale_after budget keeps the last good observation"
        );
        assert!(state.observation.is_some());
    }

    #[test]
    fn a_run_of_failed_observations_ages_out_at_stale_after() {
        let now = Instant::now();
        let mut state = healthy_state(now);
        let last_good = now - Duration::from_millis(4_500);
        record_observation(&mut state, Some(healthy_observation()), last_good);
        for seconds in (0..4).rev() {
            record_observation(&mut state, None, now - Duration::from_secs(seconds));
        }
        assert_eq!(reason(&state), None, "4.5 s old is inside the 5 s budget");

        let mut state = healthy_state(now);
        let last_good = now - Duration::from_millis(5_500);
        record_observation(&mut state, Some(healthy_observation()), last_good);
        for seconds in (0..5).rev() {
            record_observation(&mut state, None, now - Duration::from_secs(seconds));
        }
        assert_eq!(
            reason(&state),
            Some("observation_unknown"),
            "a failure run longer than the budget still answers 503"
        );
    }

    #[test]
    fn the_first_observation_after_a_gap_does_not_report_drain_not_progressing() {
        // Row 76: the dual 503s were one replica's first sample after a 10-12 s gap. Its
        // progress clock aged through the gap, when nothing could credit it, and the first
        // observation with cell-wide pending files > 0 answered `drain_not_progressing`.
        let now = Instant::now();
        let mut state = healthy_state(now);
        let last_good = now - Duration::from_secs(12);
        record_observation(&mut state, Some(healthy_observation()), last_good);
        state.progress = Some(last_good);
        for seconds in (0..=11).rev() {
            record_observation(&mut state, None, now - Duration::from_secs(seconds));
        }
        assert_eq!(reason(&state), Some("observation_unknown"));
        record_observation(&mut state, Some(pending_observation(39)), now);
        assert_eq!(
            reason(&state),
            None,
            "the time the observer was blind does not count against the drain"
        );
    }

    #[test]
    fn a_gap_extends_the_drain_clock_by_the_blind_time_only() {
        // Extended, not reset: progress that was already old before the gap stays old, so a
        // wedged drain behind flapping observations still ages out.
        let now = Instant::now();
        let mut state = healthy_state(now);
        let last_good = now - Duration::from_secs(5);
        record_observation(&mut state, Some(healthy_observation()), last_good);
        state.progress = Some(now - Duration::from_secs(10));
        for seconds in (0..=4).rev() {
            record_observation(&mut state, None, now - Duration::from_secs(seconds));
        }
        record_observation(&mut state, Some(pending_observation(3)), now);
        assert_eq!(
            reason(&state),
            Some("drain_not_progressing"),
            "5 s of pre-gap age survives a 4 s gap"
        );
    }

    #[test]
    fn consecutive_good_observations_never_move_the_drain_clock() {
        let now = Instant::now();
        let mut state = healthy_state(now);
        let old = now - Duration::from_secs(30);
        state.progress = Some(old);
        for seconds in (0..=10).rev() {
            record_observation(
                &mut state,
                Some(pending_observation(3)),
                now - Duration::from_secs(seconds),
            );
        }
        assert_eq!(state.progress, Some(old));
        assert_eq!(reason(&state), Some("drain_not_progressing"));
    }

    #[test]
    fn step_timings_name_the_step_a_timeout_was_waiting_on() {
        let now = Instant::now();
        let trace = ObserveTrace {
            completed: vec![
                (ObserveStep::PhysicalInventory, Duration::from_millis(2)),
                (ObserveStep::StagePolicy, Duration::from_millis(15)),
            ],
            in_flight: Some((ObserveStep::StageLedger, now - Duration::from_millis(980))),
            failed: None,
        };
        let steps = step_timings(&trace, now);
        assert_eq!(steps.len(), 3);
        assert_eq!(
            steps[2],
            (ObserveStep::StageLedger, Duration::from_millis(980), true)
        );
        assert_eq!(
            format_steps(&steps),
            "physical_inventory=2ms stage_policy=15ms stage_ledger=980ms(in_flight)"
        );
    }

    #[test]
    fn an_attempt_is_slow_when_it_fails_a_step_is_long_or_the_observer_is_late() {
        let interval = Duration::from_secs(1);
        let threshold = interval / 2;
        let fast = [(ObserveStep::StageLedger, Duration::from_millis(40), false)];
        let long = [(ObserveStep::SpoolObserve, Duration::from_millis(600), false)];
        let on_time = Some(interval);
        let slow = |outcome, steps: &[_], since| {
            observe_attempt_is_slow(outcome, steps, threshold, since, interval)
        };
        assert!(!slow(ObserveOutcome::Ok, &fast, on_time));
        assert!(!slow(ObserveOutcome::Ok, &fast, None));
        assert!(slow(ObserveOutcome::Failed, &fast, on_time));
        assert!(slow(ObserveOutcome::TimedOut, &fast, on_time));
        assert!(slow(ObserveOutcome::Ok, &long, on_time));
        assert!(slow(ObserveOutcome::Ok, &fast, Some(interval * 3)));
    }

    #[test]
    fn the_warn_limiter_allows_one_per_window_and_counts_the_rest() {
        let start = Instant::now();
        let every = Duration::from_secs(10);
        let mut limiter = WarnLimiter::default();
        assert_eq!(limiter.allow(start, every), Some(0));
        assert_eq!(limiter.allow(start + Duration::from_secs(1), every), None);
        assert_eq!(limiter.allow(start + Duration::from_secs(9), every), None);
        assert_eq!(
            limiter.allow(start + Duration::from_secs(10), every),
            Some(2)
        );
        assert_eq!(limiter.allow(start + Duration::from_secs(11), every), None);
    }

    // --- CR-035: write-behind backpressure is not unreadiness --------------

    fn healthy_observation() -> WriteBehindObservation {
        WriteBehindObservation {
            pending_files: 0,
            pending_bytes: 0,
            stage_bytes: 0,
            stage_files: 0,
            spool_bytes: 0,
            spool_files: 0,
            oldest_pending_age: None,
            cleanup_backlog: 0,
            roots_usable: true,
            capacity_available: true,
            capacity: CapacityEvidence::default(),
        }
    }

    /// A fully healthy state: fresh observation, fresh loop clocks, nothing
    /// pending. Individual fields are perturbed per-test.
    fn healthy_state(now: Instant) -> State {
        State {
            observation: Some((now, healthy_observation())),
            worker: Some(now),
            progress: Some(now),
            cleanup: Some(now),
            cleanup_progress: Some(now),
            ..State::default()
        }
    }

    #[test]
    fn classify_pass_separates_backpressure_from_other_failures() {
        let ok: Result<u32, StoreError> = Ok(7);
        assert_eq!(classify_pass(&ok), PassOutcome::Advanced);

        let slow_down: Result<u32, StoreError> =
            Err(StoreError::from(lore_storage::errors::SlowDown));
        assert_eq!(classify_pass(&slow_down), PassOutcome::Backpressure);

        // At least two other variants: neither is special-cased, both are a
        // real wedge.
        let disconnected: Result<u32, StoreError> =
            Err(StoreError::from(lore_storage::errors::Disconnected));
        assert_eq!(classify_pass(&disconnected), PassOutcome::Failed);
        let not_authorized: Result<u32, StoreError> =
            Err(StoreError::from(lore_storage::errors::NotAuthorized));
        assert_eq!(classify_pass(&not_authorized), PassOutcome::Failed);
    }

    #[test]
    fn a_run_of_backpressure_passes_keeps_the_loop_clock_fresh_for_either_loop() {
        let now = Instant::now();
        // 30s comfortably exceeds both the 5s and 15s budgets `reason()` uses,
        // so under the pre-fix rule this would have gone stale.
        let would_have_gone_stale = now - Duration::from_secs(30);

        let mut state = healthy_state(now);
        state.worker = Some(would_have_gone_stale);
        record_pass_outcome(
            &mut state,
            PassLoop::Drain,
            PassOutcome::Backpressure,
            now,
            true,
        );
        assert_eq!(
            state.worker,
            Some(now),
            "backpressure still advances the loop clock"
        );
        assert_eq!(
            reason(&state),
            None,
            "a fresh backpressure pass must not read as worker_stale"
        );

        let mut state = healthy_state(now);
        state.cleanup = Some(would_have_gone_stale);
        record_pass_outcome(
            &mut state,
            PassLoop::Cleanup,
            PassOutcome::Backpressure,
            now,
            true,
        );
        assert_eq!(
            state.cleanup,
            Some(now),
            "backpressure still advances the loop clock"
        );
        assert_eq!(
            reason(&state),
            None,
            "a fresh backpressure pass must not read as cleanup_stale"
        );
    }

    #[test]
    fn a_failed_pass_leaves_both_clocks_frozen_so_a_genuine_wedge_still_ages_out() {
        let now = Instant::now();
        let old = now - Duration::from_secs(30);

        let mut state = healthy_state(now);
        state.worker = Some(old);
        state.progress = Some(old);
        record_pass_outcome(&mut state, PassLoop::Drain, PassOutcome::Failed, now, true);
        assert_eq!(
            state.worker,
            Some(old),
            "a real failure must not refresh the loop clock"
        );
        assert_eq!(state.progress, Some(old));
        assert_eq!(reason(&state), Some("worker_stale"));

        let mut state = healthy_state(now);
        state.cleanup = Some(old);
        state.cleanup_progress = Some(old);
        record_pass_outcome(
            &mut state,
            PassLoop::Cleanup,
            PassOutcome::Failed,
            now,
            true,
        );
        assert_eq!(
            state.cleanup,
            Some(old),
            "a real failure must not refresh the loop clock"
        );
        assert_eq!(state.cleanup_progress, Some(old));
        assert_eq!(reason(&state), Some("cleanup_stale"));
    }

    #[test]
    fn backpressure_never_advances_the_progress_clock_even_when_progressed_is_true() {
        let now = Instant::now();
        let old = now - Duration::from_secs(30);

        let mut state = healthy_state(now);
        state.progress = Some(old);
        record_pass_outcome(
            &mut state,
            PassLoop::Drain,
            PassOutcome::Backpressure,
            now,
            true,
        );
        assert_eq!(
            state.progress,
            Some(old),
            "nothing was drained, so backpressure must not move the progress clock"
        );

        let mut state = healthy_state(now);
        state.cleanup_progress = Some(old);
        record_pass_outcome(
            &mut state,
            PassLoop::Cleanup,
            PassOutcome::Backpressure,
            now,
            true,
        );
        assert_eq!(
            state.cleanup_progress,
            Some(old),
            "nothing was cleaned, so backpressure must not move the progress clock"
        );
    }

    #[test]
    fn backpressure_since_records_the_start_of_the_run_not_the_latest_stall() {
        let now = Instant::now();
        let start_of_run = now - Duration::from_secs(20);
        let a_later_stall_in_the_same_run = now - Duration::from_secs(3);

        let mut state = healthy_state(now);
        record_pass_outcome(
            &mut state,
            PassLoop::Drain,
            PassOutcome::Backpressure,
            start_of_run,
            false,
        );
        assert_eq!(state.drain_backpressure_since, Some(start_of_run));

        record_pass_outcome(
            &mut state,
            PassLoop::Drain,
            PassOutcome::Backpressure,
            a_later_stall_in_the_same_run,
            false,
        );
        assert_eq!(
            state.drain_backpressure_since,
            Some(start_of_run),
            "a later stall in the same run must not reset the recorded start, \
             or the sustained age would never grow"
        );

        // The start stayed anchored well past the 5s budget `reason()` uses,
        // so the recorded age has grown enough to be sustained.
        assert_eq!(reason(&state), Some("drain_backpressure_sustained"));
    }

    #[test]
    fn an_advanced_pass_clears_backpressure_since_so_a_self_clearing_stall_leaves_no_trace() {
        let now = Instant::now();
        let mut state = healthy_state(now);
        state.drain_backpressure_since = Some(now - Duration::from_secs(20));
        state.cleanup_backpressure_since = Some(now - Duration::from_secs(20));

        record_pass_outcome(
            &mut state,
            PassLoop::Drain,
            PassOutcome::Advanced,
            now,
            true,
        );
        assert_eq!(state.drain_backpressure_since, None);
        assert_eq!(
            state.cleanup_backpressure_since,
            Some(now - Duration::from_secs(20)),
            "clearing drain's stall must not touch cleanup's"
        );

        record_pass_outcome(
            &mut state,
            PassLoop::Cleanup,
            PassOutcome::Advanced,
            now,
            true,
        );
        assert_eq!(state.cleanup_backpressure_since, None);
    }

    #[test]
    fn an_idle_ok_zero_pass_clears_backpressure_without_advancing_progress() {
        // `Ok(0)` — nothing drained or cleaned, but the store did not ask us
        // to slow down — is `PassOutcome::Advanced` with `progressed: false`.
        // This is the idle-cell case: it must clear the backpressure marker
        // (or the marker only ever grows) but must NOT move the progress
        // clock (nothing actually progressed).
        let now = Instant::now();
        let old = now - Duration::from_secs(30);

        let mut state = healthy_state(now);
        state.drain_backpressure_since = Some(old);
        state.progress = Some(old);
        record_pass_outcome(
            &mut state,
            PassLoop::Drain,
            PassOutcome::Advanced,
            now,
            false,
        );
        assert_eq!(
            state.drain_backpressure_since, None,
            "an Ok(0) pass still completed; it must clear a prior backpressure run"
        );
        assert_eq!(
            state.progress,
            Some(old),
            "an Ok(0) pass drained nothing, so it must not advance the progress clock"
        );

        let mut state = healthy_state(now);
        state.cleanup_backpressure_since = Some(old);
        state.cleanup_progress = Some(old);
        record_pass_outcome(
            &mut state,
            PassLoop::Cleanup,
            PassOutcome::Advanced,
            now,
            false,
        );
        assert_eq!(
            state.cleanup_backpressure_since, None,
            "an Ok(0) pass still completed; it must clear a prior backpressure run"
        );
        assert_eq!(
            state.cleanup_progress,
            Some(old),
            "an Ok(0) pass cleaned nothing, so it must not advance the progress clock"
        );
    }

    #[test]
    fn alternating_backpressure_and_idle_ok_passes_never_reach_a_sustained_verdict() {
        // The idle-cell case, run out to its conclusion: a cell that is
        // merely being told to slow down, then answers `Ok(0)`, then is told
        // to slow down again, forever, must never accumulate into
        // `drain_backpressure_sustained` / `cleanup_backpressure_sustained`.
        // Each `Ok(0)` resets the run before it can age past the budget.
        // A constant `at` (no synthetic aging of the loop clock itself) keeps
        // this a pure proof about the backpressure marker: 50 iterations
        // would comfortably sum past both the 5s and 15s budgets `reason()`
        // uses if the marker were ever allowed to survive an intervening
        // `Ok(0)`.
        let now = Instant::now();
        let mut state = healthy_state(now);

        for step in 0..50u32 {
            record_pass_outcome(
                &mut state,
                PassLoop::Drain,
                PassOutcome::Backpressure,
                now,
                false,
            );
            record_pass_outcome(
                &mut state,
                PassLoop::Drain,
                PassOutcome::Advanced,
                now,
                false,
            );
            record_pass_outcome(
                &mut state,
                PassLoop::Cleanup,
                PassOutcome::Backpressure,
                now,
                false,
            );
            record_pass_outcome(
                &mut state,
                PassLoop::Cleanup,
                PassOutcome::Advanced,
                now,
                false,
            );

            assert_eq!(
                state.drain_backpressure_since, None,
                "the intervening Ok(0) at step {step} must have cleared the drain marker"
            );
            assert_eq!(
                state.cleanup_backpressure_since, None,
                "the intervening Ok(0) at step {step} must have cleared the cleanup marker"
            );
            assert_eq!(
                reason(&state),
                None,
                "an idle cell being told to slow down must never age into unreadiness (step {step})"
            );
        }
    }

    #[test]
    fn sustained_reason_fires_once_the_run_outlives_the_budget_and_not_before() {
        let now = Instant::now();

        let mut state = healthy_state(now);
        state.drain_backpressure_since = Some(now - Duration::from_secs(4));
        assert_eq!(
            reason(&state),
            None,
            "under the 5s budget is not sustained yet"
        );
        state.drain_backpressure_since = Some(now - Duration::from_secs(6));
        assert_eq!(reason(&state), Some("drain_backpressure_sustained"));

        let mut state = healthy_state(now);
        state.cleanup_backpressure_since = Some(now - Duration::from_secs(10));
        assert_eq!(
            reason(&state),
            None,
            "under the 15s budget is not sustained yet"
        );
        state.cleanup_backpressure_since = Some(now - Duration::from_secs(16));
        assert_eq!(reason(&state), Some("cleanup_backpressure_sustained"));
    }

    #[test]
    fn readiness_reason_still_resolves_in_priority_order_around_the_new_branches() {
        let now = Instant::now();
        let stale = now - Duration::from_secs(30);
        let sustained_backpressure = now - Duration::from_secs(30);

        // A genuinely stale worker clock outranks a sustained-backpressure
        // verdict for the same loop.
        let mut state = healthy_state(now);
        state.worker = Some(stale);
        state.drain_backpressure_since = Some(sustained_backpressure);
        assert_eq!(reason(&state), Some("worker_stale"));

        // `worker_stopped` outranks it.
        let mut state = healthy_state(now);
        state.stopped = true;
        state.drain_backpressure_since = Some(sustained_backpressure);
        state.cleanup_backpressure_since = Some(sustained_backpressure);
        assert_eq!(reason(&state), Some("worker_stopped"));

        // `observation_unknown` outranks it.
        let mut state = healthy_state(now);
        state.observation.as_mut().unwrap().0 = stale;
        state.drain_backpressure_since = Some(sustained_backpressure);
        assert_eq!(reason(&state), Some("observation_unknown"));

        // `root_unavailable` outranks it.
        let mut state = healthy_state(now);
        state.observation.as_mut().unwrap().1.roots_usable = false;
        state.drain_backpressure_since = Some(sustained_backpressure);
        assert_eq!(reason(&state), Some("root_unavailable"));

        // `capacity_unavailable` outranks it, once its run has outlived the
        // budget -- a single false sample is not enough (see the CR-037
        // tests below), so route through `record_observation` rather than
        // poking the flag directly: one old sample to start the run, then a
        // fresh one so the observation itself stays current.
        let mut state = healthy_state(now);
        record_observation(&mut state, Some(capacity_observation(false)), stale);
        record_observation(&mut state, Some(capacity_observation(false)), now);
        state.drain_backpressure_since = Some(sustained_backpressure);
        assert_eq!(reason(&state), Some("capacity_unavailable"));

        // It still outranks `worker_stale` once its own budget has elapsed.
        let mut state = healthy_state(now);
        record_observation(&mut state, Some(capacity_observation(false)), stale);
        record_observation(&mut state, Some(capacity_observation(false)), now);
        state.worker = Some(stale);
        assert_eq!(reason(&state), Some("capacity_unavailable"));

        // `root_unavailable` still outranks `capacity_unavailable`, even
        // once the latter's run has outlived its own budget.
        let mut state = healthy_state(now);
        record_observation(&mut state, Some(capacity_observation(false)), stale);
        let mut roots_down = capacity_observation(false);
        roots_down.roots_usable = false;
        record_observation(&mut state, Some(roots_down), now);
        assert_eq!(reason(&state), Some("root_unavailable"));

        // `drain_backpressure_sustained` itself outranks `drain_not_progressing`:
        // construct a state where both conditions independently hold (a fresh
        // worker clock so neither is masked by `worker_stale`, a sustained
        // backpressure run, pending files, and a stale progress clock) and
        // confirm the backpressure reason wins.
        let mut state = healthy_state(now);
        state.drain_backpressure_since = Some(sustained_backpressure);
        state.observation.as_mut().unwrap().1.pending_files = 1;
        state.progress = Some(stale);
        assert_eq!(reason(&state), Some("drain_backpressure_sustained"));
    }

    #[test]
    fn the_two_loops_track_backpressure_independently() {
        let now = Instant::now();
        let sustained = now - Duration::from_secs(30);

        // Drain sustained, cleanup untouched: reports the drain reason.
        let mut state = healthy_state(now);
        state.drain_backpressure_since = Some(sustained);
        assert_eq!(reason(&state), Some("drain_backpressure_sustained"));

        // Cleanup sustained, drain untouched: reports the cleanup reason.
        let mut state = healthy_state(now);
        state.cleanup_backpressure_since = Some(sustained);
        assert_eq!(reason(&state), Some("cleanup_backpressure_sustained"));

        // Recording a drain pass must not touch cleanup's recorded state.
        let mut state = healthy_state(now);
        state.cleanup_backpressure_since = Some(sustained);
        record_pass_outcome(
            &mut state,
            PassLoop::Drain,
            PassOutcome::Backpressure,
            now,
            false,
        );
        assert_eq!(
            state.cleanup_backpressure_since,
            Some(sustained),
            "a drain pass must not affect cleanup's backpressure state"
        );

        // Recording a cleanup pass must not touch drain's recorded state.
        let mut state = healthy_state(now);
        state.drain_backpressure_since = Some(sustained);
        record_pass_outcome(
            &mut state,
            PassLoop::Cleanup,
            PassOutcome::Backpressure,
            now,
            false,
        );
        assert_eq!(
            state.drain_backpressure_since,
            Some(sustained),
            "a cleanup pass must not affect drain's backpressure state"
        );
    }

    // --- INV-FT F2(c): name the failing capacity predicate and inventory age --

    fn failing_evidence() -> CapacityEvidence {
        CapacityEvidence {
            failing: vec!["spool_bytes_over_ledger", "spool_files_over_ledger"],
            stage_inventory_age: Some(Duration::from_millis(6_250)),
            spool_inventory_age: Some(Duration::from_millis(1_200)),
            stage_physical_bytes: Some(10),
            stage_physical_files: Some(1),
            stage_ledger_bytes: 20,
            stage_ledger_files: 2,
            spool_physical_bytes: Some(26_521_120),
            spool_physical_files: Some(392),
            spool_ledger_bytes: 22_609_473,
            spool_ledger_files: 330,
            available_bytes: Some(1 << 30),
        }
    }

    #[test]
    fn capacity_detail_carries_the_failing_predicates_and_both_inventory_ages() {
        let detail = CapacityDetail::from(&failing_evidence());
        assert_eq!(
            detail.failing,
            vec!["spool_bytes_over_ledger", "spool_files_over_ledger"]
        );
        assert_eq!(detail.stage_inventory_age_millis, Some(6_250));
        assert_eq!(detail.spool_inventory_age_millis, Some(1_200));
        assert_eq!(
            (detail.spool_physical_bytes, detail.spool_ledger_bytes),
            (Some(26_521_120), 22_609_473)
        );
        assert_eq!(
            (detail.spool_physical_files, detail.spool_ledger_files),
            (Some(392), 330)
        );
    }

    /// The field names are the operator-facing surface of `/event_readiness`.
    #[test]
    fn capacity_detail_serializes_under_stable_field_names() {
        let json = serde_json::to_value(CapacityDetail::from(&failing_evidence())).expect("json");
        assert_eq!(json["failing"][0], "spool_bytes_over_ledger");
        assert_eq!(json["stage_inventory_age_millis"], 6_250);
        assert_eq!(json["spool_inventory_age_millis"], 1_200);
        assert_eq!(json["spool_physical_bytes"], 26_521_120);
        assert_eq!(json["spool_ledger_bytes"], 22_609_473);
        assert_eq!(json["available_bytes"], 1_u64 << 30);
        let missing =
            serde_json::to_value(CapacityDetail::from(&CapacityEvidence::default())).expect("json");
        assert!(missing["stage_inventory_age_millis"].is_null());
        assert!(missing["spool_inventory_age_millis"].is_null());
    }

    #[test]
    fn a_capacity_transition_is_a_flip_or_a_false_first_sample() {
        assert_eq!(capacity_transition(Some(true), false), Some(false));
        assert_eq!(capacity_transition(Some(false), true), Some(true));
        assert_eq!(capacity_transition(Some(true), true), None);
        assert_eq!(capacity_transition(Some(false), false), None);
        assert_eq!(capacity_transition(None, false), Some(false));
        assert_eq!(capacity_transition(None, true), None);
    }

    /// The observer loop's recording step: a run of samples yields exactly one
    /// transition per flip, carrying the evidence of the flipping sample.
    #[test]
    fn recording_observations_yields_one_transition_per_flip() {
        let now = Instant::now();
        let mut state = healthy_state(now);
        let mut transitions = Vec::new();
        for available in [true, true, false, false, false, true, true, false] {
            let observation = WriteBehindObservation {
                capacity: if available {
                    CapacityEvidence::default()
                } else {
                    failing_evidence()
                },
                ..capacity_observation(available)
            };
            transitions.push(record_capacity_observation(&mut state, observation, now));
        }
        let flips: Vec<(usize, bool, Vec<&'static str>)> = transitions
            .into_iter()
            .enumerate()
            .filter_map(|(index, transition)| {
                transition.map(|(available, detail)| (index, available, detail.failing))
            })
            .collect();
        let failing = failing_evidence().failing;
        assert_eq!(
            flips,
            vec![
                (2, false, failing.clone()),
                (5, true, Vec::new()),
                (7, false, failing),
            ]
        );
        assert!(state.observation.is_some());
    }

    /// Observability must not move the verdict: evidence naming failures on an
    /// observation whose `capacity_available` is true changes nothing, and the
    /// reverse still starts the run.
    #[test]
    fn capacity_evidence_does_not_drive_the_readiness_decision() {
        let now = Instant::now();
        let mut state = healthy_state(now);
        let observation = WriteBehindObservation {
            capacity: failing_evidence(),
            ..capacity_observation(true)
        };
        record_observation(&mut state, Some(observation), now);
        assert_eq!(state.capacity_unavailable_since, None);
        let observation = WriteBehindObservation {
            capacity: CapacityEvidence::default(),
            ..capacity_observation(false)
        };
        record_observation(&mut state, Some(observation), now);
        assert_eq!(state.capacity_unavailable_since, Some(now));
    }

    // --- CR-037: capacity_unavailable needs a sustained run, not one sample --

    fn capacity_observation(available: bool) -> WriteBehindObservation {
        WriteBehindObservation {
            capacity_available: available,
            ..healthy_observation()
        }
    }

    #[test]
    fn capacity_unavailable_since_records_the_start_of_the_run_not_the_latest_false_sample() {
        let now = Instant::now();
        let start_of_run = now - Duration::from_secs(20);
        let a_later_sample_in_the_same_run = now - Duration::from_secs(3);

        let mut state = healthy_state(now);
        record_observation(&mut state, Some(capacity_observation(false)), start_of_run);
        assert_eq!(state.capacity_unavailable_since, Some(start_of_run));

        record_observation(
            &mut state,
            Some(capacity_observation(false)),
            a_later_sample_in_the_same_run,
        );
        assert_eq!(
            state.capacity_unavailable_since,
            Some(start_of_run),
            "a later false sample in the same run must not reset the recorded \
             start, or the age would never grow"
        );

        // The start stayed anchored well past the 5s budget `reason()` uses,
        // so the recorded age has grown enough to be reported even though
        // the latest sample was only 3s ago.
        assert_eq!(reason(&state), Some("capacity_unavailable"));
    }

    #[test]
    fn an_available_sample_clears_capacity_unavailable_since() {
        let now = Instant::now();
        let mut state = healthy_state(now);
        state.capacity_unavailable_since = Some(now - Duration::from_secs(20));

        record_observation(&mut state, Some(capacity_observation(true)), now);
        assert_eq!(state.capacity_unavailable_since, None);
    }

    #[test]
    fn flapping_capacity_availability_never_reaches_a_sustained_verdict_however_long_it_flaps() {
        // The core of the fix: a predicate that disagrees with itself and
        // recovers, over and over, must never accumulate into
        // `capacity_unavailable`. Each `true` sample clears the run before
        // it can age past the budget, exactly like backpressure's
        // idle-`Ok(0)` case above.
        let now = Instant::now();
        let mut state = healthy_state(now);

        for step in 0..50u32 {
            record_observation(&mut state, Some(capacity_observation(false)), now);
            record_observation(&mut state, Some(capacity_observation(true)), now);
            assert_eq!(
                state.capacity_unavailable_since, None,
                "the intervening true sample at step {step} must have cleared the run"
            );
            assert_eq!(
                reason(&state),
                None,
                "a flapping predicate must never age into unreadiness (step {step})"
            );
        }
    }

    #[test]
    fn capacity_unavailable_reason_fires_once_the_run_outlives_the_budget_and_not_before() {
        let now = Instant::now();
        let mut state = healthy_state(now);
        state.capacity_unavailable_since = Some(now - Duration::from_secs(4));
        assert_eq!(
            reason(&state),
            None,
            "under the 5s budget is not unavailable yet"
        );
        state.capacity_unavailable_since = Some(now - Duration::from_secs(6));
        assert_eq!(reason(&state), Some("capacity_unavailable"));
    }

    #[test]
    fn a_none_sample_clears_the_run_so_a_fresh_budget_must_elapse_before_capacity_unavailable_reappears()
     {
        // Revised rule (independent review, post-dating the test this
        // replaces): a missing observation CLEARS `capacity_unavailable_since`
        // rather than leaving it anchored. Keeping the run across a gap meant
        // the first sample after recovery arrived with its budget already
        // spent -- a cell-wide `observe()` blip hits every replica
        // identically, so the very next ordinary transient disagreement
        // produced an instant all-replica ejection. `observation_unknown`
        // still answers 503 once the gap outlives the budget (row 76), so nothing is unguarded.
        let now = Instant::now();
        // Already well past the 5s budget by the time the gap closes below --
        // if this age survived the gap, `capacity_unavailable` would reappear
        // the instant the gap closes instead of needing a fresh budget.
        let start_of_run = now - Duration::from_secs(20);
        let mut state = healthy_state(now);

        record_observation(&mut state, Some(capacity_observation(false)), start_of_run);
        // Refresh the observation itself (without disturbing the anchored
        // run) so the sanity check below is not masked by
        // `observation_unknown` -- same two-call pattern as
        // `capacity_unavailable_since_records_the_start_of_the_run_not_the_latest_false_sample`.
        record_observation(
            &mut state,
            Some(capacity_observation(false)),
            now - Duration::from_secs(1),
        );
        assert_eq!(state.capacity_unavailable_since, Some(start_of_run));
        assert_eq!(
            reason(&state),
            Some("capacity_unavailable"),
            "sanity: this run is already old enough to report, before the gap"
        );

        // A gap: the observer could not take an observation this tick.
        record_observation(&mut state, None, now);
        assert!(
            state.observation.is_some(),
            "a missing observation keeps the last good one until it is stale"
        );
        assert_eq!(
            state.capacity_unavailable_since, None,
            "a missing observation clears the run, it does not just mask it"
        );
        assert_eq!(
            reason(&state),
            None,
            "inside the budget, a failed observation is neither unknown nor unavailable"
        );

        // The gap closes with a fresh false sample. This starts a NEW run;
        // it must not resume the pre-gap one.
        record_observation(&mut state, Some(capacity_observation(false)), now);
        assert_eq!(
            state.capacity_unavailable_since,
            Some(now),
            "the run restarts from this sample, not from the pre-gap start_of_run"
        );
        assert_eq!(
            reason(&state),
            None,
            "a fresh budget must elapse before capacity_unavailable reappears -- \
             the pre-gap age must not carry over the gap and fire immediately"
        );
    }

    #[test]
    fn a_single_fresh_false_observation_must_not_report_capacity_unavailable() {
        // The regression this exists to pin: a single observation with
        // `capacity_available == false` must leave `readiness_reason`
        // returning `None`. `capacity_available` is a reconciliation
        // predicate over the stage and spool ledgers, not a free-space
        // measurement, and it goes false transiently as a matter of course
        // while fragments are being staged -- reporting `capacity_unavailable`
        // off a single sample would eject a replica for a condition that
        // clears on its own within the next observation or two.
        //
        // This test fails if the budget gating in `readiness_reason` /
        // `record_observation` is removed and a fresh `false` sample reports
        // immediately instead of waiting for `capacity_unavailable_since` to
        // age past `stale_after`. Confirmed by temporarily reverting the
        // gate locally and observing this test go red, then restoring it and
        // observing it go green again (see the run report).
        let now = Instant::now();
        let mut state = healthy_state(now);

        record_observation(&mut state, Some(capacity_observation(false)), now);

        assert_eq!(
            reason(&state),
            None,
            "one fresh false sample alone must not report capacity_unavailable"
        );
    }

    #[test]
    fn capacity_unavailable_millis_is_none_with_no_run_and_grows_with_one() {
        // `Snapshot.capacity_unavailable_millis` is
        // `state.capacity_unavailable_since.map(|at| millis(at.elapsed()))`
        // (see `FragmentWriteBehindReadiness::snapshot`). Building a full
        // `Snapshot` needs a live store handle, which this module cannot
        // construct, so pin the same computation directly against `State`.
        let state = State::default();
        assert_eq!(
            state
                .capacity_unavailable_since
                .map(|at| millis(at.elapsed())),
            None,
            "no run means no reported age"
        );

        let mut state = State::default();
        record_observation(
            &mut state,
            Some(capacity_observation(false)),
            Instant::now() - Duration::from_millis(50),
        );
        let reported = state
            .capacity_unavailable_since
            .map(|at| millis(at.elapsed()))
            .expect("a run is in progress");
        assert!(
            reported >= 50,
            "the reported age should reflect the recorded start of the run, got {reported}ms"
        );
    }
}
