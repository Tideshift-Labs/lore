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
use lore_telemetry::InstrumentProvider;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use opentelemetry::metrics::Gauge;
use serde::Serialize;
use tokio::sync::watch;
use tokio::task::JoinSet;
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
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
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
    } else if observation.is_none_or(|value| !value.capacity_available) {
        Some("capacity_unavailable")
    } else if worker_age.is_none_or(|age| age >= stale_after) {
        Some("worker_stale")
    } else if observation.is_some_and(|value| value.pending_files > 0)
        && state.progress.is_none_or(|at| at.elapsed() >= stale_after)
    {
        Some("drain_not_progressing")
    } else if state
        .cleanup
        .is_none_or(|at| at.elapsed() >= cleanup_stale_after)
    {
        Some("cleanup_stale")
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
            match result {
                Ok(promoted) => {
                    instruments().promoted.add(u64::from(promoted), &[]);
                    let mut state = worker_readiness
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    state.worker = Some(Instant::now());
                    if state.observation.as_ref().is_some_and(|(at, value)| {
                        at.elapsed() < settings.stale_after && value.pending_files == 0
                    }) {
                        state.progress = state.worker;
                    }
                }
                Err(error) => warn!(%error, "write-behind drain pass failed"),
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
            match result {
                Ok(cleaned) => {
                    instruments().cleaned.add(u64::from(cleaned), &[]);
                    let mut state = cleanup_readiness
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    state.cleanup = Some(Instant::now());
                    if state.observation.as_ref().is_some_and(|(at, value)| {
                        at.elapsed() < settings.stale_after && value.cleanup_backlog == 0
                    }) {
                        state.cleanup_progress = state.cleanup;
                    }
                }
                Err(error) => warn!(%error, "write-behind cleanup pass failed"),
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
                observer_readiness
                    .state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .observation = Some((Instant::now(), observation));
                if observer_readiness.snapshot().ready {
                    handle.note_drain_heartbeat();
                } else {
                    handle.note_worker_stopped();
                }
            } else {
                observer_readiness
                    .state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .observation = None;
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
        state.observation.as_mut().unwrap().1.capacity_available = false;
        assert_eq!(reason(&state), Some("capacity_unavailable"));
        state.observation.as_mut().unwrap().1.capacity_available = true;
        state.observation.as_mut().unwrap().1.cleanup_backlog = 1;
        assert_eq!(reason(&state), Some("cleanup_not_progressing"));
        state.cleanup_progress = Some(now);
        assert_eq!(reason(&state), None);
    }
}
