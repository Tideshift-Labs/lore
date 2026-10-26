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
use lore_postgres::store::fragment_write_behind::CleanupSkips;
use lore_postgres::store::fragment_write_behind::FragmentWriteBehindHandle;
use lore_postgres::store::fragment_write_behind::MAX_DRAIN_CONCURRENCY;
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
    /// Released stage custody rows kept as the only cleanup authority for
    /// their epoch (WP-115 f1). Each still holds a metadata row.
    stage_tombstones_kept: Gauge<u64>,
    /// Cleanup steps skipped, by `cause`.
    cleanup_skipped: Counter<u64>,
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
            stage_tombstones_kept: meter
                .u64_gauge(provider.scope_name("stage_tombstones_kept"))
                .build(),
            cleanup_skipped: meter
                .u64_counter(provider.scope_name("cleanup_skipped"))
                .build(),
            observe_step_ms: provider.latency_histogram_ms("observe_step"),
        }
    })
}

#[lore_macro::test_pub]
#[derive(Debug, Clone)]
pub(crate) struct FragmentWriteBehindSettings {
    worker_interval: Duration,
    worker_batch: u32,
    /// `None` keeps the handle's default (row 77).
    worker_concurrency: Option<usize>,
    observer_interval: Duration,
    stale_after: Duration,
    cleanup_interval: Duration,
    cleanup_batch: u32,
}

impl FragmentWriteBehindSettings {
    #[lore_macro::test_pub]
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
            worker_concurrency: None,
            observer_interval: Duration::from_millis(observer),
            stale_after: Duration::from_millis(stale),
            cleanup_interval: Duration::from_millis(cleanup),
            cleanup_batch,
        })
    }

    /// Set how many promotions one drain pass runs at once, or keep the
    /// handle's default with `None`.
    #[lore_macro::test_pub]
    pub(crate) fn with_worker_concurrency(mut self, concurrency: Option<usize>) -> Result<Self> {
        if concurrency.is_some_and(|value| !(1..=MAX_DRAIN_CONCURRENCY).contains(&value)) {
            bail!("write-behind worker_concurrency must be between 1 and {MAX_DRAIN_CONCURRENCY}");
        }
        self.worker_concurrency = concurrency;
        Ok(self)
    }

    /// How often the observer runs, which is also each attempt's budget.
    pub(crate) fn observer_interval(&self) -> Duration {
        self.observer_interval
    }
}

#[lore_macro::test_pub]
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
    /// Whether the current `capacity_unavailable_since` run began at the first
    /// good observation after a stale gap. See `record_observation`.
    capacity_run_began_after_stale_gap: bool,
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
#[lore_macro::test_pub]
fn capacity_transition(previous: Option<bool>, current: bool) -> Option<bool> {
    match previous {
        Some(previous) if previous == current => None,
        None if current => None,
        _ => Some(current),
    }
}

/// Record a successful observation and return the capacity transition it made,
/// if any. The caller logs the transition after releasing the state lock.
#[lore_macro::test_pub]
fn record_capacity_observation(
    state: &mut State,
    observation: WriteBehindObservation,
    at: Instant,
    stale_after: Duration,
) -> Option<(bool, CapacityDetail)> {
    let previous = state
        .observation
        .as_ref()
        .map(|(_, value)| value.capacity_available);
    let transition = capacity_transition(previous, observation.capacity_available)
        .map(|available| (available, CapacityDetail::from(&observation.capacity)));
    record_observation(state, Some(observation), at, stale_after);
    transition
}

fn log_capacity_transition(available: bool, detail: &CapacityDetail) {
    if available {
        info!(?detail, "write-behind capacity predicate holds again");
    } else {
        info!(?detail, "write-behind capacity predicate failed");
    }
}

#[lore_macro::test_pub]
fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

/// Which worker loop a pass belongs to.
#[lore_macro::test_pub]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PassLoop {
    Drain,
    Cleanup,
}

/// What one worker pass says about the loop that ran it.
#[lore_macro::test_pub]
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
#[lore_macro::test_pub]
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
#[lore_macro::test_pub]
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
/// **A failed observation keeps the run; a failure run that let the last good
/// observation reach `stale_after` clears it.** A short failure run is the same
/// claim as the last good observation, which still stands (below), so it cannot
/// restart the budget: clearing on every failure let a full stage stay hidden
/// from readiness for as long as `observe()` failed once per `stale_after`. A
/// long failure run has already answered `observation_unknown`, and keeping the
/// run across it would
/// meet the first sample after recovery with the budget spent. One database
/// stall reaches every replica, so the next ordinary transient disagreement
/// would then eject every replica at once. So that run starts again.
///
/// **A run that began right after a stale gap survives the next one (row 76
/// review).** Restarting at every stale gap hid a full stage whose good
/// observations all arrived at least `stale_after` apart: each restarted the
/// run, so it alternated `observation_unknown` and ready and never answered
/// `capacity_unavailable`. So a run that began at the first good observation
/// after a stale gap, and has seen no room since, is kept across the next stale
/// gap. The stall-then-recovery case above is unchanged: its run began before
/// the stall and still restarts. The cost: two stale gaps in a row, each
/// followed by a transient disagreement with no sample showing room in between,
/// answer `capacity_unavailable` at once.
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
/// It ages out late, and this is the bound. In the worst case observations fail
/// for just under `stale_after` between single good ones. Each such cycle lasts
/// about `stale_after` and ages the clock by about one observer interval, so a
/// wedged drain reads ready for about `stale_after² / interval` before
/// `drain_not_progressing` (5 s and 1 s: 25 s, not 5 s). The test
/// `a_wedged_drain_behind_flapping_observations_ages_out_at_stale_after_squared_over_interval`
/// pins it.
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
#[lore_macro::test_pub]
fn record_observation(
    state: &mut State,
    observation: Option<WriteBehindObservation>,
    at: Instant,
    stale_after: Duration,
) {
    let Some(value) = observation else {
        state.observation_failed_since.get_or_insert(at);
        return;
    };
    let after_gap = state.observation_failed_since.take();
    let mut after_stale_gap = false;
    if let Some(failed_since) = after_gap {
        let blind = at.saturating_duration_since(failed_since);
        state.progress = state
            .progress
            .map(|progress| progress.checked_add(blind).map_or(at, |end| end.min(at)));
        // The clock `observation_unknown` read during the gap: the age of the
        // last good observation, not the failure run, which starts up to one
        // interval later and, for a timed-out attempt, is recorded only when
        // the attempt ends.
        after_stale_gap = state
            .observation
            .as_ref()
            .is_some_and(|(previous, _)| at.saturating_duration_since(*previous) >= stale_after);
        if after_stale_gap && !state.capacity_run_began_after_stale_gap {
            state.capacity_unavailable_since = None;
        }
    }
    if value.capacity_available {
        state.capacity_unavailable_since = None;
        state.capacity_run_began_after_stale_gap = false;
    } else if state.capacity_unavailable_since.is_none() {
        state.capacity_unavailable_since = Some(at);
        state.capacity_run_began_after_stale_gap = after_stale_gap;
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
#[lore_macro::test_pub]
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
#[lore_macro::test_pub]
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

#[lore_macro::test_pub]
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
#[lore_macro::test_pub]
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
#[lore_macro::test_pub]
#[derive(Default)]
struct WarnLimiter {
    last: Option<Instant>,
    suppressed: u64,
}

impl WarnLimiter {
    /// `Some(warnings held back since the last one)` when a warning may be
    /// logged at `at`, else `None`.
    #[lore_macro::test_pub]
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

#[lore_macro::test_pub]
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
#[lore_macro::test_pub]
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
#[lore_macro::test_pub]
fn record_cleanup_not_progressing(gauge: &Gauge<u64>, degraded: &[&'static str]) {
    gauge.record(
        u64::from(degraded.contains(&"cleanup_not_progressing")),
        &[],
    );
}

/// Add each cleanup skip cause's growth since `previous` to `counter`, labelled
/// `cause`, and remember `now`. The handle's counts only grow.
#[lore_macro::test_pub]
fn record_cleanup_skips(counter: &Counter<u64>, previous: &mut CleanupSkips, now: CleanupSkips) {
    for (cause, before, after) in [
        (
            "stage_capacity",
            previous.stage_capacity,
            now.stage_capacity,
        ),
        (
            "stage_key_taken",
            previous.stage_key_taken,
            now.stage_key_taken,
        ),
        (
            "tombstone_sweep_failed",
            previous.tombstone_sweep_failed,
            now.tombstone_sweep_failed,
        ),
    ] {
        let grown = after.saturating_sub(before);
        if grown > 0 {
            counter.add(grown, &[KeyValue::new("cause", cause)]);
        }
    }
    *previous = now;
}

/// Merge completed per-item activity without extending any timestamp merely
/// because the observer ran. A wedged next operation still ages out naturally.
#[lore_macro::test_pub]
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

/// What one observer attempt does to the store's drain heartbeat.
#[lore_macro::test_pub]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeartbeatAction {
    Beat,
    /// Neither beat nor stop: the heartbeat ages out over `stale_after` alone.
    Keep,
    Stop,
}

/// An unready replica stops its heartbeat at once, and a good observation on a
/// ready one beats it. A failed observation on a replica that is still ready
/// keeps it (row 76): inside the budget the last good observation still
/// stands, so dropping the heartbeat would send PUTs to `DirectFallback` for a
/// one-tick blip, and beating it would claim an observation nobody took.
#[lore_macro::test_pub]
fn heartbeat_action(observed: bool, ready: bool) -> HeartbeatAction {
    match (observed, ready) {
        (_, false) => HeartbeatAction::Stop,
        (true, true) => HeartbeatAction::Beat,
        (false, true) => HeartbeatAction::Keep,
    }
}

fn apply_heartbeat(handle: &FragmentWriteBehindHandle, action: HeartbeatAction) {
    match action {
        HeartbeatAction::Beat => handle.note_drain_heartbeat(),
        HeartbeatAction::Keep => {}
        HeartbeatAction::Stop => handle.note_worker_stopped(),
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
#[lore_macro::test_pub]
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
    if let Some(concurrency) = settings.worker_concurrency {
        handle.set_drain_concurrency(concurrency);
    }
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
        let mut counted_skips = CleanupSkips::default();
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
            // Every tick, not only after a good observation: skips are most
            // likely while the database is failing.
            record_cleanup_skips(
                &instruments().cleanup_skipped,
                &mut counted_skips,
                handle.cleanup_skips(),
            );
            if let Ok(Ok(observation)) = result {
                instruments().pending.record(observation.pending_files, &[]);
                instruments()
                    .usage
                    .record(observation.stage_bytes, &[KeyValue::new("root", "stage")]);
                instruments()
                    .usage
                    .record(observation.spool_bytes, &[KeyValue::new("root", "spool")]);
                instruments()
                    .stage_tombstones_kept
                    .record(observation.stage_tombstones_kept, &[]);
                // Explicit block, matching the worker loops: the guard is released at the
                // brace rather than at a statement temporary, so `snapshot()` below cannot
                // be folded into the same expression and self-deadlock this std `Mutex`.
                let transition = {
                    let mut state = observer_readiness
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    record_capacity_observation(
                        &mut state,
                        observation,
                        Instant::now(),
                        settings.stale_after,
                    )
                };
                if let Some((available, detail)) = transition {
                    log_capacity_transition(available, &detail);
                }
                apply_heartbeat(
                    &handle,
                    heartbeat_action(true, observer_readiness.snapshot().ready),
                );
            } else {
                {
                    let mut state = observer_readiness
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    record_observation(&mut state, None, Instant::now(), settings.stale_after);
                }
                handle.note_observation_unknown();
                apply_heartbeat(
                    &handle,
                    heartbeat_action(false, observer_readiness.snapshot().ready),
                );
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
