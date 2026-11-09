// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Per-replica bounded write-behind scheduling. Database and filesystem ownership
//! remain behind the store's opaque handle.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
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

use crate::drain::DrainState;
use crate::stage_liveness::StageLiveness;
use crate::stage_liveness::StageLivenessSnapshot;

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
    /// Seconds the spool retired floor trails this replica's clock (WP-115 f2). Recorded every
    /// tick from memory, so it keeps growing while the floor is stuck or the database fails.
    spool_retired_floor_age: Gauge<u64>,
    /// Age in seconds of the cell's oldest staged, unpromoted fragment, read
    /// from Postgres by every replica's observer (0 when nothing is pending).
    /// WP-115 K6: the cell-wide drain-stall signal. It is exported by the stage
    /// replicas too, so it keeps growing after the drain worker dies.
    oldest_pending_age: Gauge<u64>,
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
            spool_retired_floor_age: meter
                .u64_gauge(provider.scope_name("spool_retired_floor_age_seconds"))
                .build(),
            oldest_pending_age: meter
                .u64_gauge(provider.scope_name("oldest_pending_age_seconds"))
                .build(),
            observe_step_ms: provider.latency_histogram_ms("observe_step"),
        }
    })
}

/// FORK-LOCAL (Tideshift): which write-behind work this replica runs (WP-115 K6).
///
/// The stage is one tree shared by every replica of the cell (an NFS export
/// in the multi-host topology), so the drain does not have to run where the
/// writes land. `Full` is the default and is the behaviour every existing
/// configuration already has.
///
/// The Postgres claims stay the only authority over who promotes or cleans
/// what. A role only decides which loops this process starts; it grants
/// nothing. Two drain workers in one cell, or a `full` replica beside a
/// `drain` one, is therefore wasted work, never a correctness fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteBehindRole {
    /// Stage writes and run the drain, cleanup and observer loops.
    #[default]
    Full,
    /// Stage writes, serve staged reads and run the observer only. No
    /// promotion, no stage or spool cleanup, no spool writes.
    ///
    /// Two things still touch disk here, by design. `spool_root` is still
    /// required: boot opens the spool writer (one probe file), and the observer
    /// walks that empty local spool and reads its free space into the capacity
    /// check. And an obliterate request purges its staged epoch on whichever
    /// replica serves it; that path is request-driven and claim-gated, not a
    /// background loop.
    Stage,
    /// The cell's dedicated drain worker: the same loops as `Full`. It is not a
    /// load-balancer member, so `/lb_health` always answers 503 `drain_role`.
    Drain,
}

impl WriteBehindRole {
    pub fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Stage => "stage",
            Self::Drain => "drain",
        }
    }

    /// Whether this role runs the drain and cleanup loops.
    pub fn runs_drain(self) -> bool {
        !matches!(self, Self::Stage)
    }

    /// What this role starts and records. One derivation for every role gate
    /// in [`configure_fragment_write_behind`] and its observer, so a table
    /// test pins all of them.
    #[lore_macro::test_pub]
    pub(crate) fn tasks(self) -> RoleTasks {
        let drain = self.runs_drain();
        RoleTasks {
            drain_and_cleanup: drain,
            // Without a drain loop to own it, the observer owns the stop
            // guard, so a dead observer still answers `observer_stopped`.
            observer_owns_stop_guard: !drain,
            // A stage replica has no cleanup verdict; see the observer loop.
            records_cleanup_gauge: drain,
        }
    }
}

/// The per-role task gates. See [`WriteBehindRole::tasks`].
#[lore_macro::test_pub]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoleTasks {
    pub(crate) drain_and_cleanup: bool,
    pub(crate) observer_owns_stop_guard: bool,
    pub(crate) records_cleanup_gauge: bool,
}

#[lore_macro::test_pub]
#[derive(Debug, Clone)]
pub(crate) struct FragmentWriteBehindSettings {
    role: WriteBehindRole,
    worker_interval: Duration,
    worker_batch: u32,
    /// `None` keeps the handle's default (row 77).
    worker_concurrency: Option<usize>,
    observer_interval: Duration,
    stale_after: Duration,
    cleanup_interval: Duration,
    cleanup_batch: u32,
    /// WP-115 K11: run the per-replica stage liveness probe. Honoured only on
    /// a `stage` replica; on by default.
    stage_liveness: bool,
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
            role: WriteBehindRole::Full,
            worker_interval: Duration::from_millis(worker),
            worker_batch: batch,
            worker_concurrency: None,
            observer_interval: Duration::from_millis(observer),
            stale_after: Duration::from_millis(stale),
            cleanup_interval: Duration::from_millis(cleanup),
            cleanup_batch,
            stage_liveness: true,
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

    /// Set which loops this replica runs (WP-115 K6).
    #[lore_macro::test_pub]
    pub(crate) fn with_role(mut self, role: WriteBehindRole) -> Self {
        self.role = role;
        self
    }

    #[lore_macro::test_pub]
    pub(crate) fn role(&self) -> WriteBehindRole {
        self.role
    }

    /// Turn the WP-115 K11 stage liveness probe on or off.
    #[lore_macro::test_pub]
    pub(crate) fn with_stage_liveness(mut self, enabled: bool) -> Self {
        self.stage_liveness = enabled;
        self
    }

    /// Whether this replica runs the WP-115 K11 stage liveness probe: only a
    /// `stage` replica, and only while it is enabled. A `full` replica is the
    /// only one in its cell, so it has no peer to compare with. A `drain`
    /// replica already answers 503 `drain_role`, and its local stage would be
    /// a false "fresh peer" for the web replicas.
    #[lore_macro::test_pub]
    pub(crate) fn runs_stage_liveness(&self) -> bool {
        self.role == WriteBehindRole::Stage && self.stage_liveness
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
    role: WriteBehindRole,
    state: Mutex<State>,
    stale_after: Duration,
    cleanup_stale_after: Duration,
    /// WP-115 K11: this replica's stage liveness, on a `stage` replica only.
    stage_liveness: Option<Arc<StageLiveness>>,
}

#[derive(Serialize)]
pub struct Snapshot {
    /// `full`, `stage` or `drain` (WP-115 K6).
    pub role: &'static str,
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
    /// WP-115 K11: the stage liveness probe and peer view, on a `stage`
    /// replica. `fault` is what `/lb_health` answers from it.
    pub stage_liveness: Option<StageLivenessSnapshot>,
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

/// The `oldest_pending_age_seconds` gauge value for one observation: 0 when
/// nothing is pending.
#[lore_macro::test_pub]
fn oldest_pending_age_seconds(observation: &WriteBehindObservation) -> u64 {
    observation
        .oldest_pending_age
        .map_or(0, |age| age.as_secs())
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
/// **Blind time is not drain time.** Drain progress is credited by this
/// replica's own promotions, a fresh observation showing nothing pending, or a
/// cell-wide pending count that fell (below). During a run of failed
/// observations nothing can credit it, so the first good observation after a
/// long run found the clock
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
/// **A cell-wide pending count that fell since the last sample is drain
/// progress, by the same rule.** `pending_files` is cell-wide, so a replica
/// whose peer promoted its work, or whose own claims are cooling down after
/// reserve contention, promoted nothing itself while the cell drained. Crediting
/// only its own promotions answered `drain_not_progressing` there. A count that
/// stays flat or rises with no own promotion still ages out over `stale_after`,
/// measured from the last fall.
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
        && let Some((_, previous)) = state.observation.as_ref()
    {
        if value.pending_files < previous.pending_files {
            state.progress = state.progress.max(Some(at));
        }
        if value.cleanup_backlog < previous.cleanup_backlog {
            state.cleanup_progress = state.cleanup_progress.max(Some(at));
        }
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

/// FORK-LOCAL (Tideshift): the write-behind faults that belong to THIS replica
/// alone, for `/lb_health`.
///
/// Only two conditions qualify. `worker_stopped`: this process's write-behind
/// task has ended. `root_unavailable`: a fresh observation says this host's own
/// stage or spool root cannot be read. The stage and spool are a per-host
/// volume, so no other replica shares that fault.
///
/// Every other `readiness_reason` is computed from the cell's shared Postgres
/// and spool, so it is the same on every replica and must not eject one. A
/// stale or absent observation is "cannot decide", which is `None`, never a
/// fault: the roots are unknown, not unusable.
#[lore_macro::test_pub]
fn replica_fault(state: &State, stale_after: Duration) -> Option<&'static str> {
    if state.stopped {
        return Some("worker_stopped");
    }
    match state.observation.as_ref() {
        Some((at, value)) if at.elapsed() < stale_after && !value.roots_usable => {
            Some("root_unavailable")
        }
        _ => None,
    }
}

/// FORK-LOCAL (Tideshift): readiness for a `stage` role replica (WP-115 K6).
///
/// A stage replica runs only the observer. It has no drain or cleanup loop,
/// so every verdict about those loops (`worker_stale`,
/// `drain_backpressure_sustained`, `drain_not_progressing`, `cleanup_stale`,
/// `cleanup_backpressure_sustained`) belongs to the drain worker and is left
/// out here. What remains is what this replica's own PUTs and staged reads
/// depend on: a live observer, a fresh observation, usable roots and room on
/// the stage.
///
/// `observer_stopped` replaces `worker_stopped`: the task that ended is the
/// observer, the only write-behind task this replica has.
#[lore_macro::test_pub]
fn stage_readiness_reason(state: &State, stale_after: Duration) -> Option<&'static str> {
    let observation = state.observation.as_ref().map(|(_, value)| value);
    let observation_age = state.observation.as_ref().map(|(at, _)| at.elapsed());
    if state.stopped {
        Some("observer_stopped")
    } else if observation_age.is_none_or(|age| age >= stale_after) {
        Some("observation_unknown")
    } else if observation.is_none_or(|value| !value.roots_usable) {
        Some("root_unavailable")
    } else if state
        .capacity_unavailable_since
        .is_some_and(|at| at.elapsed() >= stale_after)
    {
        Some("capacity_unavailable")
    } else {
        None
    }
}

/// FORK-LOCAL (Tideshift): the `/lb_health` fault for a `stage` role replica
/// (WP-115 K6).
///
/// Only `observer_stopped` qualifies. `root_unavailable` is left out on
/// purpose: in this topology the stage is one shared export, so a stage-root
/// fault is the same on every web replica, and ejecting them one after another
/// refuses the whole cell. It stays on `/health_check` and in the metrics.
#[lore_macro::test_pub]
fn stage_replica_fault(state: &State) -> Option<&'static str> {
    state.stopped.then_some("observer_stopped")
}

/// The `/lb_health` word a `drain` role replica always answers. The worker is
/// not a load-balancer member; this keeps a misconfigured pool from sending it
/// client connections.
pub const DRAIN_ROLE_LB_FAULT: &str = "drain_role";

/// The `/lb_health` fault for `role`. Pure, so the per-role mapping is
/// testable without a live handle.
#[lore_macro::test_pub]
fn role_replica_fault(
    role: WriteBehindRole,
    state: &State,
    stale_after: Duration,
) -> Option<&'static str> {
    match role {
        WriteBehindRole::Full => replica_fault(state, stale_after),
        WriteBehindRole::Stage => stage_replica_fault(state),
        WriteBehindRole::Drain => Some(DRAIN_ROLE_LB_FAULT),
    }
}

/// WP-115 K11: [`role_replica_fault`] plus the stage liveness fault. Only a
/// `stage` replica takes the liveness fault, and only when nothing else
/// already answers.
#[lore_macro::test_pub]
fn combined_replica_fault(
    role: WriteBehindRole,
    base: Option<&'static str>,
    stage_local: Option<&'static str>,
) -> Option<&'static str> {
    match role {
        WriteBehindRole::Stage => base.or(stage_local),
        WriteBehindRole::Full | WriteBehindRole::Drain => base,
    }
}

/// The readiness reason and the degraded condition for `role`.
///
/// A stage replica runs no cleanup loop, so it never credits cleanup progress
/// and would read `cleanup_not_progressing` whenever the backlog is non-zero.
/// That verdict belongs to the drain worker, so a stage replica reports none.
#[lore_macro::test_pub]
fn role_readiness(
    role: WriteBehindRole,
    state: &State,
    stale_after: Duration,
    cleanup_stale_after: Duration,
) -> (Option<&'static str>, Option<&'static str>) {
    if role.runs_drain() {
        (
            readiness_reason(state, stale_after, cleanup_stale_after),
            degraded_reason(state, cleanup_stale_after),
        )
    } else {
        (stage_readiness_reason(state, stale_after), None)
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
        (
            "spool_retire_failed",
            previous.spool_retire_failed,
            now.spool_retire_failed,
        ),
        (
            "spool_retire_contended",
            previous.spool_retire_contended,
            now.spool_retire_contended,
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
    /// The replica-local fault `/lb_health` acts on. Reads in-memory state only.
    pub fn replica_fault(&self) -> Option<&'static str> {
        let base = {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            role_replica_fault(self.role, &state, self.stale_after)
        };
        let stage_local = self
            .stage_liveness
            .as_ref()
            .and_then(|liveness| liveness.fault(Instant::now()));
        combined_replica_fault(self.role, base, stage_local)
    }

    /// WP-115 K11: this replica's stage liveness, when it runs one.
    pub fn stage_liveness(&self) -> Option<&Arc<StageLiveness>> {
        self.stage_liveness.as_ref()
    }

    pub fn role(&self) -> WriteBehindRole {
        self.role
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        refresh_activity(&mut state, self.handle.activity());
        let observation = state.observation.as_ref().map(|(_, value)| value);
        let observation_age = state.observation.as_ref().map(|(at, _)| at.elapsed());
        let worker_age = state.worker.map(|at| at.elapsed());
        let (reason, degraded) = role_readiness(
            self.role,
            &state,
            self.stale_after,
            self.cleanup_stale_after,
        );
        Snapshot {
            role: self.role.name(),
            mode: match self.handle.mode() {
                StagingMode::Stage => "stage",
                StagingMode::DirectFallback => "direct_fallback",
                StagingMode::Refuse => "refuse",
                StagingMode::Unready => "unready",
            },
            ready: reason.is_none(),
            reason,
            degraded: degraded.into_iter().collect(),
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
            stage_liveness: self
                .stage_liveness
                .as_ref()
                .map(|liveness| liveness.snapshot(Instant::now())),
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
    drain: Option<Arc<DrainState>>,
) -> Result<Option<Arc<FragmentWriteBehindReadiness>>> {
    let (handle, settings) = match (handle, settings) {
        (None, None) => return Ok(None),
        (Some(handle), Some(settings)) => (handle, settings),
        _ => bail!("write-behind runtime composition is incomplete"),
    };
    if let Some(concurrency) = settings.worker_concurrency {
        handle.set_drain_concurrency(concurrency);
    }
    let stage_liveness = if settings.runs_stage_liveness() {
        start_stage_liveness(&handle, endpoints, &shutdown, drain)?
    } else {
        None
    };
    let readiness = Arc::new(FragmentWriteBehindReadiness {
        handle: handle.clone(),
        role: settings.role,
        state: Mutex::new(State::default()),
        stale_after: settings.stale_after,
        cleanup_stale_after: settings.cleanup_interval * 2 + settings.stale_after,
        stage_liveness,
    });
    info!(
        role = settings.role.name(),
        "write-behind role selects which loops this replica runs"
    );
    let tasks = settings.role.tasks();
    if tasks.drain_and_cleanup {
        spawn_drain_and_cleanup(&handle, &readiness, &settings, endpoints, &shutdown);
    }
    let observer_readiness = readiness.clone();
    // A stage replica has no drain loop to own the stop guard, so its observer
    // owns it: the observer is the one task whose end leaves this replica
    // unable to keep admission fresh.
    let observer_guard = tasks
        .observer_owns_stop_guard
        .then(|| StopGuard(handle.clone(), readiness.clone()));
    let mut observer_shutdown = shutdown;
    lore_spawn!(endpoints, async move {
        let _guard = observer_guard;
        observe_loop(handle, observer_readiness, settings, &mut observer_shutdown).await;
        Ok(())
    });
    Ok(Some(readiness))
}

/// WP-115 K11: start the stage liveness probe thread and its exchange task.
///
/// `None` where the platform opens no stage (the handle reports no root).
fn start_stage_liveness(
    handle: &Arc<FragmentWriteBehindHandle>,
    endpoints: &mut JoinSet<Result<()>>,
    shutdown: &watch::Receiver<bool>,
    drain: Option<Arc<DrainState>>,
) -> Result<Option<Arc<StageLiveness>>> {
    let Some(root) = handle.stage_root() else {
        return Ok(None);
    };
    let replica_id = crate::stage_liveness::default_replica_id();
    let liveness = Arc::new(StageLiveness::new(replica_id.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    crate::stage_liveness::spawn_probe_thread(
        &liveness,
        crate::stage_liveness::file_probe(root, &replica_id),
        crate::stage_liveness::PROBE_INTERVAL,
        stop.clone(),
    )?;
    info!(
        replica_id = %replica_id,
        stale_after_millis = millis(liveness.stale_after()),
        "stage liveness probe started"
    );
    let exchange_handle = handle.clone();
    let exchange_liveness = liveness.clone();
    let mut exchange_shutdown = shutdown.clone();
    lore_spawn!(endpoints, async move {
        // Stops the probe thread at shutdown. A thread parked in a hung write
        // never sees it, and the process exit ends it.
        let _stop = StopFlag(stop);
        let mut ticks = tokio::time::interval(crate::stage_liveness::EXCHANGE_INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut warned = None;
        let mut withdrawn = false;
        let draining = || drain.as_ref().is_some_and(|drain| drain.is_draining());
        loop {
            tokio::select! { biased;
                _ = exchange_shutdown.wait_for(|value| *value) => break,
                _ = ticks.tick() => {}
            }
            tokio::select! { biased;
                _ = exchange_shutdown.wait_for(|value| *value) => break,
                _ = crate::stage_liveness::liveness_tick(
                    &exchange_liveness,
                    draining(),
                    &mut withdrawn,
                    |last_good| exchange_handle.exchange_stage_liveness(
                        exchange_liveness.replica_id(),
                        last_good,
                        exchange_liveness.stale_after(),
                        exchange_liveness.prove_margin(),
                        crate::stage_liveness::RETAIN,
                    ),
                    || exchange_handle.withdraw_stage_liveness(exchange_liveness.replica_id()),
                    crate::stage_liveness::EXCHANGE_TIMEOUT,
                    &mut warned,
                ) => {}
            }
            exchange_liveness.report(Instant::now());
        }
        // Shutdown without a drain phase (or before the tick that would have
        // withdrawn): withdraw now, bounded, so peers stop counting this row.
        let _ = crate::stage_liveness::liveness_tick(
            &exchange_liveness,
            true,
            &mut withdrawn,
            |_last_good| {
                std::future::ready(Ok(
                    lore_postgres::domain::fragments::StagePeerLiveness::default(),
                ))
            },
            || exchange_handle.withdraw_stage_liveness(exchange_liveness.replica_id()),
            crate::stage_liveness::EXCHANGE_TIMEOUT,
            &mut warned,
        )
        .await;
        Ok(())
    });
    Ok(Some(liveness))
}

/// Sets the flag when dropped.
struct StopFlag(Arc<AtomicBool>);
impl Drop for StopFlag {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The drain and cleanup loops, which only `full` and `drain` replicas run.
fn spawn_drain_and_cleanup(
    handle: &Arc<FragmentWriteBehindHandle>,
    readiness: &Arc<FragmentWriteBehindReadiness>,
    settings: &FragmentWriteBehindSettings,
    endpoints: &mut JoinSet<Result<()>>,
    shutdown: &watch::Receiver<bool>,
) {
    let cleanup_settings = settings.clone();
    let settings = settings.clone();
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
        let settings = cleanup_settings;
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
}

/// The observer loop, which every role runs. It feeds admission (occupancy,
/// capacity, pending, heartbeat) and readiness from the cell's Postgres and
/// this host's view of the roots.
async fn observe_loop(
    handle: Arc<FragmentWriteBehindHandle>,
    observer_readiness: Arc<FragmentWriteBehindReadiness>,
    settings: FragmentWriteBehindSettings,
    observer_shutdown: &mut watch::Receiver<bool>,
) {
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
        instruments()
            .spool_retired_floor_age
            .record(handle.spool_retired_floor_age().as_secs(), &[]);
        if let Ok(Ok(observation)) = result {
            instruments().pending.record(observation.pending_files, &[]);
            instruments()
                .oldest_pending_age
                .record(oldest_pending_age_seconds(&observation), &[]);
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
        // The gauge carries no labels, so every replica of a cell writes one
        // series and the monitoring rule reads it across replicas. A stage
        // replica has no cleanup verdict; recording 0 there would hide the
        // drain worker's 1 from a `min` rule. So it records nothing.
        if settings.role.tasks().records_cleanup_gauge {
            record_cleanup_not_progressing(
                &instruments().cleanup_not_progressing,
                &snapshot.degraded,
            );
        }
    }
    handle.note_worker_stopped();
}
