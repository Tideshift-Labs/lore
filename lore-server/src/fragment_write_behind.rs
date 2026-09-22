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
use lore_postgres::store::fragment_write_behind::FragmentWriteBehindHandle;
use lore_postgres::store::fragment_write_behind::WriteBehindActivity;
use lore_postgres::store::fragment_write_behind::WriteBehindObservation;
use lore_postgres::store::write_behind::StagingMode;
use lore_storage::StoreError;
use lore_telemetry::InstrumentProvider;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use opentelemetry::metrics::Gauge;
use serde::Serialize;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::debug;
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
    pending: Gauge<u64>,
    usage: Gauge<u64>,
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
            pending: meter
                .u64_gauge(provider.scope_name("pending_files"))
                .build(),
            usage: meter.u64_gauge(provider.scope_name("usage_bytes")).build(),
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
/// physical inventory against a freshly read charged ledger, so it goes false
/// whenever the two are momentarily out of step — which is the normal condition
/// while fragments are being staged. Treating that instant as unreadiness is what
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
/// out, and `observation_unknown` answers 503 throughout the gap regardless.
///
/// Pure and synchronous, so the rule is testable without a store, a runtime or a
/// Postgres fixture — the same reason `record_pass_outcome` is.
fn record_observation(state: &mut State, observation: Option<WriteBehindObservation>, at: Instant) {
    match observation {
        Some(value) => {
            if value.capacity_available {
                state.capacity_unavailable_since = None;
            } else {
                state.capacity_unavailable_since.get_or_insert(at);
            }
            state.observation = Some((at, value));
        }
        None => {
            state.capacity_unavailable_since = None;
            state.observation = None;
        }
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
    } else if observation.is_some_and(|value| value.cleanup_backlog > 0)
        && state
            .cleanup_progress
            .is_none_or(|at| at.elapsed() >= cleanup_stale_after)
    {
        Some("cleanup_not_progressing")
    } else {
        None
    }
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
        loop {
            tokio::select! { biased;
                _ = observer_shutdown.wait_for(|value| *value) => break,
                _ = ticks.tick() => {}
            }
            handle.note_observation_unknown();
            let result = tokio::select! { biased;
                _ = observer_shutdown.wait_for(|value| *value) => break,
                result = tokio::time::timeout(settings.observer_interval, handle.observe()) => result,
            };
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
                {
                    let mut state = observer_readiness
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    record_observation(&mut state, Some(observation), Instant::now());
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
                handle.note_worker_stopped();
            }
            let snapshot = observer_readiness.snapshot();
            instruments().ready.record(
                u64::from(snapshot.ready),
                &[KeyValue::new(
                    "reason",
                    snapshot.reason.unwrap_or("healthy"),
                )],
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
        assert_eq!(reason(&state), Some("cleanup_not_progressing"));
        state.cleanup_progress = Some(now);
        assert_eq!(reason(&state), None);
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
        // still answers 503 throughout the gap, so nothing is unguarded.
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
            state.observation.is_none(),
            "a missing observation clears the last observation"
        );
        assert_eq!(
            state.capacity_unavailable_since, None,
            "a missing observation clears the run, it does not just mask it"
        );
        assert_eq!(
            reason(&state),
            Some("observation_unknown"),
            "observation_unknown still covers the gap itself, ahead of \
             capacity_unavailable in priority order"
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
