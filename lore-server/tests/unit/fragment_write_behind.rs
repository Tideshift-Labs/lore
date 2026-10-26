// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): `fragment_write_behind` tests, moved out of the
//! inline `tests` module when upstream set `[lib] test = false`.

use std::time::Duration;
use std::time::Instant;

use lore_postgres::store::fragment_write_behind::CapacityEvidence;
use lore_postgres::store::fragment_write_behind::MAX_DRAIN_CONCURRENCY;
use lore_postgres::store::fragment_write_behind::ObserveStep;
use lore_postgres::store::fragment_write_behind::ObserveTrace;
use lore_postgres::store::fragment_write_behind::WriteBehindActivity;
use lore_postgres::store::fragment_write_behind::WriteBehindObservation;
use lore_server::fragment_write_behind::*;
use lore_storage::StoreError;
use tokio::sync::watch;
use tokio::task::JoinSet;

#[test]
fn worker_concurrency_is_optional_and_bounded() {
    let settings = || FragmentWriteBehindSettings::new(1000, 64, 1000, 5000, 5000, 64).unwrap();
    assert_eq!(settings().worker_concurrency, None);
    for value in [1, MAX_DRAIN_CONCURRENCY] {
        let set = settings().with_worker_concurrency(Some(value)).unwrap();
        assert_eq!(set.worker_concurrency, Some(value));
    }
    assert_eq!(
        settings()
            .with_worker_concurrency(None)
            .unwrap()
            .worker_concurrency,
        None
    );
    for value in [0, MAX_DRAIN_CONCURRENCY + 1] {
        assert!(settings().with_worker_concurrency(Some(value)).is_err());
    }
}

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
    assert!(configure_fragment_write_behind(None, Some(settings), &mut tasks, shutdown).is_err());
    assert!(tasks.is_empty());
}

fn reason(state: &State) -> Option<&'static str> {
    readiness_reason(state, Duration::from_secs(5), Duration::from_secs(15))
}

fn degraded(state: &State) -> Option<&'static str> {
    degraded_reason(state, Duration::from_secs(15))
}

/// `lore_server::fragment_write_behind::record_observation` at the 5 s budget `reason()` reads with.
/// Shadows the glob import for every test in this module.
fn record_observation(state: &mut State, observation: Option<WriteBehindObservation>, at: Instant) {
    lore_server::fragment_write_behind::record_observation(
        state,
        observation,
        at,
        Duration::from_secs(5),
    );
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
                stage_tombstones_kept: 0,
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
        stage_tombstones_kept: 0,
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

/// Each cleanup skip cause adds its growth under its own `cause` label, so the
/// counter's total equals the handle's cumulative count (WP-115 f1).
#[test]
fn the_cleanup_skipped_counter_adds_each_causes_growth_by_label() {
    use std::collections::BTreeMap;

    use lore_postgres::store::fragment_write_behind::CleanupSkips;
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::InMemoryMetricExporter;
    use opentelemetry_sdk::metrics::SdkMeterProvider;
    use opentelemetry_sdk::metrics::data::AggregatedMetrics;
    use opentelemetry_sdk::metrics::data::MetricData;

    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_periodic_exporter(exporter.clone())
        .build();
    let counter = provider
        .meter("test")
        .u64_counter("cleanup_skipped")
        .build();
    let values = || -> BTreeMap<String, u64> {
        provider.force_flush().expect("flush the test meter");
        let metrics = exporter.get_finished_metrics().expect("read metrics");
        let resource = metrics.last().expect("one export per flush");
        let metric = resource
            .scope_metrics()
            .flat_map(|scope| scope.metrics())
            .next()
            .expect("the counter was recorded");
        match metric.data() {
            AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                .data_points()
                .map(|point| {
                    let cause = point
                        .attributes()
                        .find(|kv| kv.key.as_str() == "cause")
                        .expect("a cause label")
                        .value
                        .to_string();
                    (cause, point.value())
                })
                .collect(),
            data => panic!("expected a u64 sum, got {data:?}"),
        }
    };

    let mut counted = CleanupSkips::default();
    record_cleanup_skips(
        &counter,
        &mut counted,
        CleanupSkips {
            stage_capacity: 3,
            stage_key_taken: 1,
            tombstone_sweep_failed: 0,
            spool_retire_failed: 0,
            spool_retire_contended: 0,
        },
    );
    // A cause that has not grown adds nothing and has no data point yet.
    assert_eq!(
        values(),
        BTreeMap::from([
            ("stage_capacity".to_owned(), 3),
            ("stage_key_taken".to_owned(), 1),
        ])
    );
    let later = CleanupSkips {
        stage_capacity: 4,
        stage_key_taken: 1,
        tombstone_sweep_failed: 2,
        spool_retire_failed: 5,
        spool_retire_contended: 4,
    };
    record_cleanup_skips(&counter, &mut counted, later);
    // The same snapshot again adds nothing.
    record_cleanup_skips(&counter, &mut counted, later);
    assert_eq!(
        values(),
        BTreeMap::from([
            ("stage_capacity".to_owned(), 4),
            ("stage_key_taken".to_owned(), 1),
            ("tombstone_sweep_failed".to_owned(), 2),
            ("spool_retire_failed".to_owned(), 5),
            ("spool_retire_contended".to_owned(), 4),
        ])
    );
    assert_eq!(counted, later);
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

/// A drain that never progresses after `start`, observed by a replica whose
/// `observe()` fails 4 ticks of every 5 (1 s ticks, the 5 s budget).
fn flapping_drain(cycles: u64) -> State {
    let now = Instant::now();
    let start = now - Duration::from_secs(5 * cycles);
    let mut state = healthy_state(now);
    record_observation(&mut state, Some(pending_observation(3)), start);
    state.progress = Some(start);
    for cycle in 0..cycles {
        let base = start + Duration::from_secs(5 * cycle);
        for second in 1..=4 {
            record_observation(&mut state, None, base + Duration::from_secs(second));
        }
        record_observation(
            &mut state,
            Some(pending_observation(3)),
            base + Duration::from_secs(5),
        );
    }
    state
}

#[test]
fn a_wedged_drain_behind_flapping_observations_ages_out_at_stale_after_squared_over_interval() {
    // Each 5 s cycle credits 4 s of blind time, so the clock ages 1 s per
    // cycle: stale_after / interval cycles of stale_after each.
    assert_eq!(
        reason(&flapping_drain(4)),
        None,
        "20 s after the wedge the drain clock reads only 4 s old"
    );
    assert_eq!(
        reason(&flapping_drain(5)),
        Some("drain_not_progressing"),
        "it ages out at 25 s = 5 s * 5 s / 1 s"
    );
}

#[test]
fn a_failed_observation_keeps_the_drain_heartbeat_until_the_replica_is_unready() {
    // Row 76: the observer used to stop the heartbeat on any failed
    // observation, which sent PUTs to direct fallback for a one-tick blip.
    let now = Instant::now();
    let mut state = healthy_state(now);
    record_observation(
        &mut state,
        Some(healthy_observation()),
        now - Duration::from_secs(1),
    );
    record_observation(&mut state, None, now);
    assert_eq!(
        heartbeat_action(false, reason(&state).is_none()),
        HeartbeatAction::Keep,
        "inside the budget a failure neither beats nor stops the heartbeat"
    );

    let mut state = healthy_state(now);
    record_observation(
        &mut state,
        Some(healthy_observation()),
        now - Duration::from_secs(6),
    );
    for seconds in (0..=5).rev() {
        record_observation(&mut state, None, now - Duration::from_secs(seconds));
    }
    assert_eq!(
        heartbeat_action(false, reason(&state).is_none()),
        HeartbeatAction::Stop,
        "a failure run past the budget stops it"
    );
    assert_eq!(heartbeat_action(true, true), HeartbeatAction::Beat);
    assert_eq!(heartbeat_action(true, false), HeartbeatAction::Stop);
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
        stage_tombstones_kept: 0,
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

    let slow_down: Result<u32, StoreError> = Err(StoreError::from(lore_storage::errors::SlowDown));
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
        transitions.push(record_capacity_observation(
            &mut state,
            observation,
            now,
            Duration::from_secs(5),
        ));
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
fn a_full_stage_behind_intermittent_observe_failures_still_reports_capacity_unavailable() {
    // Review of row 76's fix: a failed observation used to CLEAR the run.
    // Once failures stopped answering 503 at once, a stage that never had
    // room stayed ready for as long as `observe()` failed at least once per
    // budget, because each failure restarted it.
    let now = Instant::now();
    let mut state = healthy_state(now);
    for seconds in (0..=6u64).rev() {
        let at = now - Duration::from_secs(seconds);
        let observation = (seconds % 2 == 0).then(|| capacity_observation(false));
        record_observation(&mut state, observation, at);
    }
    assert_eq!(
        state.capacity_unavailable_since,
        Some(now - Duration::from_secs(6)),
        "a short failure run keeps the run's start"
    );
    assert_eq!(
        reason(&state),
        Some("capacity_unavailable"),
        "6 s without room is past the 5 s budget, whatever failed in between"
    );
}

#[test]
fn a_failure_run_of_stale_after_or_longer_restarts_the_capacity_run() {
    // A failure run that long has already answered `observation_unknown`.
    // Keeping the run across it would meet the first sample after recovery
    // with the budget spent. One database stall reaches every replica, so
    // the next ordinary transient disagreement would eject every replica.
    let now = Instant::now();
    let start_of_run = now - Duration::from_secs(20);
    let mut state = healthy_state(now);
    record_observation(&mut state, Some(capacity_observation(false)), start_of_run);
    record_observation(
        &mut state,
        Some(capacity_observation(false)),
        now - Duration::from_secs(6),
    );
    for seconds in (1..=5u64).rev() {
        record_observation(&mut state, None, now - Duration::from_secs(seconds));
    }
    assert_eq!(
        state.capacity_unavailable_since,
        Some(start_of_run),
        "failures alone never clear the run"
    );
    assert_eq!(reason(&state), Some("observation_unknown"));

    record_observation(&mut state, Some(capacity_observation(false)), now);
    assert_eq!(
        state.capacity_unavailable_since,
        Some(now),
        "after a 5 s failure run the run restarts from this sample"
    );
    assert_eq!(reason(&state), None, "a fresh budget must elapse first");
}

#[test]
fn the_restart_reads_the_last_good_observations_age_not_the_failure_runs_length() {
    // Independent review of d8c4a7a8: failures at -4 s and -2 s are a 4 s
    // run, but the last good observation was 6 s old at -0, so
    // `observation_unknown` already answered and the run must restart.
    let now = Instant::now();
    let mut state = healthy_state(now);
    record_observation(
        &mut state,
        Some(capacity_observation(false)),
        now - Duration::from_secs(20),
    );
    record_observation(
        &mut state,
        Some(capacity_observation(false)),
        now - Duration::from_secs(6),
    );
    for seconds in [4, 2] {
        record_observation(&mut state, None, now - Duration::from_secs(seconds));
    }
    record_observation(&mut state, Some(capacity_observation(false)), now);
    assert_eq!(state.capacity_unavailable_since, Some(now));
    assert_eq!(reason(&state), None);
}

/// One good observation after `failures` seconds of failed ones, ending at
/// `at`.
fn observe_after_failures(
    state: &mut State,
    at: Instant,
    failures: u64,
    observation: WriteBehindObservation,
) {
    for seconds in (1..=failures).rev() {
        record_observation(state, None, at - Duration::from_secs(seconds));
    }
    record_observation(state, Some(observation), at);
}

#[test]
fn a_full_stage_seen_only_between_stale_gaps_still_reaches_capacity_unavailable() {
    // Row 76 review: good observations 6 s apart, each after a failure run
    // long enough to answer `observation_unknown`. Each restarted the run,
    // so a full stage alternated `observation_unknown` and ready and never
    // answered `capacity_unavailable`.
    let now = Instant::now();
    let mut state = healthy_state(now);
    for cycle in (0..=3u64).rev() {
        let at = now - Duration::from_secs(cycle * 6);
        observe_after_failures(&mut state, at, 5, capacity_observation(false));
    }
    assert_eq!(
        state.capacity_unavailable_since,
        Some(now - Duration::from_secs(12)),
        "the run restarted after the first stale gap survives the next ones"
    );
    assert_eq!(reason(&state), Some("capacity_unavailable"));
}

#[test]
fn a_room_sample_after_a_stale_gap_ends_the_carry() {
    // The carry is for a run that began right after a stale gap and saw no
    // room since. A sample with room ends that run, and a later run that
    // began on an ordinary sample restarts at the next stale gap as before.
    let now = Instant::now();
    let mut state = healthy_state(now);
    let at = now - Duration::from_secs(18);
    observe_after_failures(&mut state, at, 5, capacity_observation(false));
    let at = now - Duration::from_secs(12);
    observe_after_failures(&mut state, at, 5, capacity_observation(false));
    let at = now - Duration::from_secs(11);
    record_observation(&mut state, Some(capacity_observation(true)), at);
    let at = now - Duration::from_secs(6);
    record_observation(&mut state, Some(capacity_observation(false)), at);
    observe_after_failures(&mut state, now, 5, capacity_observation(false));
    assert_eq!(state.capacity_unavailable_since, Some(now));
    assert_eq!(reason(&state), None);
}

#[test]
fn a_failure_run_shorter_than_stale_after_keeps_the_capacity_run() {
    let now = Instant::now();
    let start_of_run = now - Duration::from_secs(20);
    let mut state = healthy_state(now);
    record_observation(&mut state, Some(capacity_observation(false)), start_of_run);
    record_observation(
        &mut state,
        Some(capacity_observation(false)),
        now - Duration::from_secs(4),
    );
    for seconds in (1..=3u64).rev() {
        record_observation(&mut state, None, now - Duration::from_secs(seconds));
    }
    assert_eq!(
        reason(&state),
        Some("capacity_unavailable"),
        "inside the budget the last good observation stands, and it had no room"
    );
    record_observation(&mut state, Some(capacity_observation(false)), now);
    assert_eq!(state.capacity_unavailable_since, Some(start_of_run));
    assert_eq!(reason(&state), Some("capacity_unavailable"));
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

/// The retired-floor age is read from memory, so it must be recorded on EVERY observer tick. If it
/// moved inside the good-observation branch it would freeze exactly when the database fails and
/// the floor cannot advance, which is when the alert needs it to grow. Source pin: the `OTel` gauge
/// cannot be read back in a unit test (process-global meter provider).
#[test]
fn the_retired_floor_age_gauge_is_recorded_outside_the_good_observation_branch() {
    const SOURCE: &str = include_str!("../../src/fragment_write_behind.rs");
    let record = SOURCE
        .find("handle.spool_retired_floor_age().as_secs()")
        .expect("the observer records the retired-floor age");
    assert_eq!(
        SOURCE.matches("handle.spool_retired_floor_age()").count(),
        1,
        "exactly one recording site"
    );
    let skips = SOURCE
        .find("handle.cleanup_skips(),\n            );")
        .expect("the per-tick cleanup skip recording is present");
    let good_branch = SOURCE
        .find("if let Ok(Ok(observation)) = result {")
        .expect("the good-observation branch is present");
    assert!(
        skips < record && record < good_branch,
        "the age gauge is recorded every tick, after the skip counters and before the \
         good-observation branch (skips {skips}, record {record}, branch {good_branch})"
    );
}
