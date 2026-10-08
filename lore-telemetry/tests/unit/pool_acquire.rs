// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Moved from `src/pool_acquire.rs` when the crate's lib test harness was turned off.
use std::sync::Arc;
use std::time::Duration;

use lore_telemetry::*;

struct TestProvider;

impl InstrumentProvider for TestProvider {
    fn namespace(&self) -> &'static str {
        "test.pool"
    }
}

fn metrics() -> PoolAcquireMetrics {
    PoolAcquireMetrics::new(&TestProvider, "immutable")
}

/// A wait guaranteed to land in bucket `index` (0-based; the value one past
/// the last real boundary, i.e. `POOL_ACQUIRE_BUCKET_BOUNDARIES_MS.len()`,
/// means the overflow bucket). Each value is the midpoint between that
/// bucket's boundary and the previous one, so it sits comfortably inside
/// the bucket rather than near an edge — this is for rank tests where only
/// *which bucket* a sample lands in matters, not boundary exactness.
/// [`a_sample_exactly_on_a_boundarys_bucket`] and its siblings cover exact
/// boundary inclusivity separately, with real millisecond `Duration`s.
fn wait_in_bucket(index: usize) -> Duration {
    let midpoint_ms: f64 = match index {
        0 => 0.025,
        1 => 0.075,
        2 => 0.175,
        3 => 0.375,
        4 => 0.75,
        5 => 1.75,
        6 => 3.75,
        7 => 7.5,
        8 => 17.5,
        9 => 37.5,
        10 => 75.0,
        11 => 175.0,
        12 => 375.0,
        13 => 750.0,
        14 => 3000.0,
        _ => 6000.0, // overflow bucket: comfortably above the 5000.0 ms boundary
    };
    Duration::from_secs_f64(midpoint_ms / 1000.0)
}

/// Records `n` successful waits, rank `i+1` (1-indexed) placed in bucket
/// `min(i, 15)`. Because bucket assignment is monotonic in rank, the
/// `target`-th sample (1-indexed) is, by construction of this fixture and
/// independent of the implementation under test, in bucket
/// `min(target - 1, 15)`. That lets each rank test below state its expected
/// bucket, and thus its expected boundary value, from first principles
/// rather than by re-deriving the production formula.
fn record_ranked_samples(metrics: &PoolAcquireMetrics, n: usize) {
    for i in 0..n {
        metrics.record(wait_in_bucket(i.min(15)), AcquireOutcome::Acquired);
    }
}

#[test]
fn an_empty_snapshot_reports_no_quantile_rather_than_zero() {
    let snapshot = metrics().snapshot();

    assert_eq!(snapshot.acquired(), 0);
    assert_eq!(snapshot.p95_upper_bound_ms(), None);
    assert_eq!(snapshot.mean_ms(), None);
}

#[test]
fn a_failed_checkout_is_counted_but_never_enters_the_quantile() {
    let metrics = metrics();
    metrics.record(Duration::from_millis(900), AcquireOutcome::Failed);
    metrics.record(Duration::from_micros(10), AcquireOutcome::Acquired);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.failed(), 1);
    assert_eq!(snapshot.acquired(), 1);
    // 900 ms would land in the 1000 ms bucket had it been counted.
    assert_eq!(snapshot.p95_upper_bound_ms(), Some(0.05));
}

#[test]
fn the_p95_bucket_is_the_one_holding_the_95th_sample() {
    let metrics = metrics();
    // 95 fast, 5 slow: the 95th of 100 samples is the last fast one.
    for _ in 0..95 {
        metrics.record(Duration::from_micros(20), AcquireOutcome::Acquired);
    }
    for _ in 0..5 {
        metrics.record(Duration::from_millis(400), AcquireOutcome::Acquired);
    }

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.acquired(), 100);
    assert_eq!(snapshot.p95_upper_bound_ms(), Some(0.05));
    assert_eq!(snapshot.quantile_upper_bound_ms(1.0), Some(500.0));
}

#[test]
fn a_wait_above_the_last_boundary_reports_infinity_not_the_last_bucket() {
    let metrics = metrics();
    metrics.record(Duration::from_secs(6), AcquireOutcome::Acquired);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.p95_upper_bound_ms(), Some(f64::INFINITY));
    assert_eq!(
        snapshot.buckets().last().copied(),
        Some(1),
        "the overflow bucket holds it"
    );
}

#[test]
fn a_sample_exactly_on_a_boundary_lands_in_that_boundarys_bucket() {
    let metrics = metrics();
    metrics.record(Duration::from_millis(100), AcquireOutcome::Acquired);

    // 100.0 is the gate threshold; a sample exactly at it must not be
    // pushed into the 250 ms bucket and read as a gate failure.
    assert_eq!(metrics.snapshot().p95_upper_bound_ms(), Some(100.0));
}

#[test]
fn max_and_mean_come_from_successful_waits_only() {
    let metrics = metrics();
    metrics.record(Duration::from_millis(10), AcquireOutcome::Acquired);
    metrics.record(Duration::from_millis(30), AcquireOutcome::Acquired);
    metrics.record(Duration::from_secs(9), AcquireOutcome::Failed);

    let snapshot = metrics.snapshot();
    assert!((snapshot.max_ms() - 30.0).abs() < 0.001, "{snapshot:?}");
    let mean = snapshot.mean_ms().expect("two successful waits");
    assert!((mean - 20.0).abs() < 0.001, "{snapshot:?}");
}

#[tokio::test]
async fn measure_classifies_by_the_futures_result() {
    let metrics = metrics();
    let ok: Result<u8, ()> = metrics.measure(async { Ok(7) }).await;
    let err: Result<u8, ()> = metrics.measure(async { Err(()) }).await;

    assert_eq!(ok, Ok(7));
    assert_eq!(err, Err(()));
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.acquired(), 1);
    assert_eq!(snapshot.failed(), 1);
}

#[test]
fn measure_records_the_actual_wait_not_a_zero_duration() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("build a current-thread runtime with the time driver enabled");
    // Real time, not `start_paused`: `tokio::time::sleep` under a paused
    // clock resolves without any wall-clock wait at all, which would make
    // this assertion trivially true regardless of whether `measure` timed
    // anything. See docs/testing-gotchas.md, "Deterministic async tests".
    runtime.block_on(async {
        let metrics = metrics();
        let sleep_for = Duration::from_millis(100);
        let result: Result<(), ()> = metrics
            .measure(async {
                tokio::time::sleep(sleep_for).await;
                Ok(())
            })
            .await;
        assert_eq!(result, Ok(()));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.acquired(), 1);
        // Lower bound only, with a tolerant margin: `measure` must not report
        // less time than the checkout actually took, but asserting a tight
        // upper bound would flake under scheduler load. 90 ms against a
        // 100 ms sleep leaves headroom for coarse OS timer resolution
        // without accepting a measurement that skipped the wait.
        assert!(
            snapshot.max_ms() >= 90.0,
            "measured {} ms for a {} ms sleep",
            snapshot.max_ms(),
            sleep_for.as_millis()
        );
    });
}

#[test]
fn concurrent_recordings_do_not_lose_an_increment() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("build a multi-thread runtime");
    runtime.block_on(async {
        let metrics = Arc::new(metrics());
        let tasks_count = 50_usize;
        let acquired_per_task = 15_usize;
        let failed_per_task = 5_usize;

        let mut handles = Vec::with_capacity(tasks_count);
        for _ in 0..tasks_count {
            let metrics = Arc::clone(&metrics);
            let handle = lore_base::lore_spawn!(async move {
                for _ in 0..acquired_per_task {
                    metrics.record(Duration::from_micros(20), AcquireOutcome::Acquired);
                }
                for _ in 0..failed_per_task {
                    metrics.record(Duration::from_millis(5), AcquireOutcome::Failed);
                }
            });
            handles.push(handle);
        }
        for handle in handles {
            handle.await.expect("recorder task panicked");
        }

        let snapshot = metrics.snapshot();
        assert_eq!(
            snapshot.acquired(),
            (tasks_count * acquired_per_task) as u64
        );
        assert_eq!(snapshot.failed(), (tasks_count * failed_per_task) as u64);
        assert_eq!(
            snapshot.buckets().iter().sum::<u64>(),
            snapshot.acquired(),
            "the bucket tally must match the acquired count exactly under contention: \
             a torn or lost increment would under-count it"
        );
    });
}

#[test]
fn buckets_len_matches_boundaries_plus_one_and_sums_to_acquired() {
    let metrics = metrics();
    metrics.record(Duration::from_micros(20), AcquireOutcome::Acquired);
    metrics.record(Duration::from_millis(30), AcquireOutcome::Acquired);
    metrics.record(Duration::from_secs(6), AcquireOutcome::Acquired);
    metrics.record(Duration::from_millis(400), AcquireOutcome::Failed);

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.buckets().len(),
        POOL_ACQUIRE_BUCKET_BOUNDARIES_MS.len() + 1
    );
    assert_eq!(snapshot.buckets().iter().sum::<u64>(), snapshot.acquired());
    assert_eq!(snapshot.acquired(), 3);
}

#[test]
fn an_all_failed_run_reports_no_quantile_not_a_clean_p95() {
    let metrics = metrics();
    for millis in [5, 10, 20, 50, 900] {
        metrics.record(Duration::from_millis(millis), AcquireOutcome::Failed);
    }

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.acquired(), 0);
    assert_eq!(snapshot.failed(), 5);
    // Not 0.0 and not some interpolation of the failed waits: a run that
    // never produced a connection must say so, not read as a fast p95.
    assert_eq!(snapshot.p95_upper_bound_ms(), None);
    assert_eq!(snapshot.mean_ms(), None);
}

#[test]
fn out_of_range_quantile_returns_none_not_a_panic() {
    let metrics = metrics();
    metrics.record(Duration::from_millis(10), AcquireOutcome::Acquired);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.quantile_upper_bound_ms(-0.1), None);
    assert_eq!(snapshot.quantile_upper_bound_ms(1.1), None);
    assert_eq!(snapshot.quantile_upper_bound_ms(f64::NAN), None);
    // The valid endpoints must still work on the same snapshot, so the
    // rejections above are a range check and not an accidental blanket one.
    // The one recorded sample is 10 ms, exactly the bucket-7 boundary.
    assert_eq!(snapshot.quantile_upper_bound_ms(0.0), Some(10.0));
    assert_eq!(snapshot.quantile_upper_bound_ms(1.0), Some(10.0));
}

#[test]
fn first_boundary_0_05_is_inclusive() {
    let metrics = metrics();
    metrics.record(Duration::from_micros(50), AcquireOutcome::Acquired);

    assert_eq!(metrics.snapshot().quantile_upper_bound_ms(1.0), Some(0.05));
}

#[test]
fn boundary_100_and_250_are_inclusive_not_pushed_to_the_next_bucket() {
    // The two placement-gate thresholds: a sample exactly at either must
    // stay in that boundary's bucket, not the next one up, or a gate
    // stated as "p95 at or below 100 ms" silently fails a clean run.
    let at_100 = metrics();
    at_100.record(Duration::from_millis(100), AcquireOutcome::Acquired);
    assert_eq!(at_100.snapshot().quantile_upper_bound_ms(1.0), Some(100.0));

    let at_250 = metrics();
    at_250.record(Duration::from_millis(250), AcquireOutcome::Acquired);
    assert_eq!(at_250.snapshot().quantile_upper_bound_ms(1.0), Some(250.0));
}

#[test]
fn last_boundary_5000_is_inclusive_not_overflow() {
    let metrics = metrics();
    metrics.record(Duration::from_secs(5), AcquireOutcome::Acquired);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.quantile_upper_bound_ms(1.0), Some(5000.0));
    assert_eq!(
        snapshot.buckets().last().copied(),
        Some(0),
        "exactly 5000 ms must not fall into the overflow bucket"
    );
}

#[test]
fn quantile_at_zero_names_the_first_sample_even_when_early_buckets_are_empty() {
    // All five samples sit in bucket 8 (boundary 25.0); buckets 0-7 are
    // empty. A quantile-rank computation that starts counting from 0
    // instead of 1 (i.e. omits `.max(1.0)` on the target rank) would stop
    // at the very first bucket it scans, bucket 0, and wrongly report
    // 0.05 even though no sample is anywhere near it.
    let metrics = metrics();
    for _ in 0..5 {
        metrics.record(wait_in_bucket(8), AcquireOutcome::Acquired);
    }

    assert_eq!(metrics.snapshot().quantile_upper_bound_ms(0.0), Some(25.0));
}

#[test]
fn quantile_rank_is_correct_for_n_1() {
    let metrics = metrics();
    record_ranked_samples(&metrics, 1);
    let snapshot = metrics.snapshot();

    for quantile in [0.0, 0.5, 0.95, 1.0] {
        assert_eq!(
            snapshot.quantile_upper_bound_ms(quantile),
            Some(0.05),
            "n=1, q={quantile}: the only sample is always both endpoints"
        );
    }
}

#[test]
fn quantile_rank_is_correct_for_n_2() {
    let metrics = metrics();
    record_ranked_samples(&metrics, 2);
    let snapshot = metrics.snapshot();

    // q=0.95: n*q = 1.9. A `floor` implementation names rank 1 (0.05, the
    // wrong, earlier bucket); the correct `ceil` names rank 2 (0.1).
    let expected = [(0.0, 0.05), (0.5, 0.05), (0.95, 0.1), (1.0, 0.1)];
    for (quantile, expected_ms) in expected {
        assert_eq!(
            snapshot.quantile_upper_bound_ms(quantile),
            Some(expected_ms),
            "n=2, q={quantile}"
        );
    }
}

#[test]
fn quantile_rank_is_correct_for_n_19_and_distinguishes_ceil_from_floor() {
    let metrics = metrics();
    record_ranked_samples(&metrics, 19);
    let snapshot = metrics.snapshot();

    // q=0.5: n*q = 9.5. `ceil` names rank 10 (bucket 9, boundary 50.0).
    // A `floor` implementation would name rank 9 (bucket 8, boundary
    // 25.0) instead — this is the designated ceil-vs-floor mutation probe.
    let expected = [
        (0.0, 0.05),
        (0.5, 50.0),
        (0.95, f64::INFINITY),
        (1.0, f64::INFINITY),
    ];
    for (quantile, expected_ms) in expected {
        assert_eq!(
            snapshot.quantile_upper_bound_ms(quantile),
            Some(expected_ms),
            "n=19, q={quantile}"
        );
    }
}

#[test]
fn quantile_rank_is_correct_for_n_20() {
    let metrics = metrics();
    record_ranked_samples(&metrics, 20);
    let snapshot = metrics.snapshot();

    let expected = [
        (0.0, 0.05),
        (0.5, 50.0),
        (0.95, f64::INFINITY),
        (1.0, f64::INFINITY),
    ];
    for (quantile, expected_ms) in expected {
        assert_eq!(
            snapshot.quantile_upper_bound_ms(quantile),
            Some(expected_ms),
            "n=20, q={quantile}"
        );
    }
}

#[test]
fn quantile_rank_is_correct_for_n_100_against_a_placement_gate_shape() {
    // A realistic placement-gate shape, 100 samples total: 50 fast
    // (bucket 0, boundary 0.05), 45 exactly at the 100 ms gate threshold
    // (bucket 10), and 5 in a slow tail at the last boundary (bucket 14,
    // boundary 5000.0).
    let metrics = metrics();
    for _ in 0..50 {
        metrics.record(wait_in_bucket(0), AcquireOutcome::Acquired);
    }
    for _ in 0..45 {
        metrics.record(wait_in_bucket(10), AcquireOutcome::Acquired);
    }
    for _ in 0..5 {
        metrics.record(wait_in_bucket(14), AcquireOutcome::Acquired);
    }
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.acquired(), 100);

    // q=0.0 and q=0.5: ranks 1 and 50 are both within the first 50 fast
    // samples (bucket 0).
    // q=0.95: rank 95 is the 45th sample in the 100.0 ms group
    // (cumulative 50 + 45 = 95) — this pins the p95 gate threshold exactly.
    // q=1.0: rank 100 is the last of the 5000.0 ms group.
    let expected = [(0.0, 0.05), (0.5, 0.05), (0.95, 100.0), (1.0, 5000.0)];
    for (quantile, expected_ms) in expected {
        assert_eq!(
            snapshot.quantile_upper_bound_ms(quantile),
            Some(expected_ms),
            "n=100, q={quantile}"
        );
    }
}

/// Pins behaviour that is correct **and** surprising, so the next reader
/// who notices the gap does not "fix" it.
///
/// The guard lives in `measure`'s async body, which does not run until the
/// first poll — so a future dropped before then records nothing at all.
/// That is right, not a hole: such a call never polled the inner checkout
/// either, so no connection was requested and no time elapsed. Recording it
/// would add a 0 ms entry describing a wait that never happened, and it
/// cannot hide a long wait, because every long wait is by construction one
/// that *was* polled and then cancelled — which
/// `a_cancelled_measure_records_abandoned_not_nothing_and_not_failed`
/// covers.
///
/// The general rule, which is what makes this worth pinning: a `Drop` guard
/// constructed inside an async body leaves the pre-first-poll case open,
/// and that is correct exactly when the obligation cannot exist before the
/// first poll. It is a defect only for an obligation incurred at
/// *construction* time — a reserved slot, a taken ticket, a preallocated
/// id. A wait is not one of those.
#[test]
fn a_measure_future_dropped_before_its_first_poll_records_nothing_because_it_never_waited() {
    // Deterministic by construction: no runtime, no timer, no scheduling.
    let metrics = metrics();
    let never_polled = metrics.measure(std::future::pending::<Result<(), ()>>());
    drop(never_polled);

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.abandoned(),
        0,
        "a checkout that was never polled never waited; counting it would \
         add a 0 ms entry for a wait that did not happen"
    );
    assert_eq!(snapshot.acquired(), 0);
    assert_eq!(snapshot.failed(), 0);
    assert_eq!(
        snapshot.buckets().iter().sum::<u64>(),
        0,
        "and nothing may reach the quantile tally"
    );
}

#[test]
fn a_cancelled_measure_records_abandoned_not_nothing_and_not_failed() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("build a current-thread runtime with the time driver enabled");
    runtime.block_on(async {
        let metrics = metrics();
        // A checkout that never resolves on its own; the timeout drops the
        // `measure` future (and with it the in-flight `AcquireGuard`)
        // before it ever reaches its `.await` continuation.
        let pending = std::future::pending::<Result<(), ()>>();
        let outcome =
            tokio::time::timeout(Duration::from_millis(20), metrics.measure(pending)).await;
        assert!(
            outcome.is_err(),
            "the timeout must elapse before the checkout resolves, or this test proves nothing"
        );

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.abandoned(), 1);
        assert_eq!(snapshot.acquired(), 0);
        assert_eq!(snapshot.failed(), 0);
    });
}

#[test]
fn an_abandoned_wait_never_enters_the_quantile_or_bucket_tally() {
    let metrics = metrics();
    // 9 s would land in the overflow bucket and dominate any quantile had
    // it been counted; it must not be.
    metrics.record(Duration::from_secs(9), AcquireOutcome::Abandoned);
    metrics.record(Duration::from_micros(10), AcquireOutcome::Acquired);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.abandoned(), 1);
    assert_eq!(snapshot.acquired(), 1);
    assert_eq!(snapshot.p95_upper_bound_ms(), Some(0.05));
    assert_eq!(
        snapshot.buckets().iter().sum::<u64>(),
        snapshot.acquired(),
        "an abandoned wait must not appear in the bucket tally"
    );
}

#[test]
fn abandoned_max_ms_tracks_the_longest_abandoned_wait_independent_of_max_ms() {
    let metrics = metrics();
    assert_eq!(
        metrics.snapshot().abandoned_max_ms(),
        0.0,
        "no abandoned waits yet"
    );

    metrics.record(Duration::from_millis(50), AcquireOutcome::Abandoned);
    metrics.record(Duration::from_millis(900), AcquireOutcome::Abandoned);
    metrics.record(Duration::from_millis(10), AcquireOutcome::Acquired);

    let snapshot = metrics.snapshot();
    assert!(
        (snapshot.abandoned_max_ms() - 900.0).abs() < 0.001,
        "{snapshot:?}"
    );
    // `max_ms` stays successes-only: the 900 ms abandoned wait, longer than
    // the one successful wait, must not leak into it.
    assert!((snapshot.max_ms() - 10.0).abs() < 0.001, "{snapshot:?}");
}

#[test]
fn acquire_guard_records_the_settled_outcome_on_drop() {
    let metrics = metrics();
    {
        let mut guard = AcquireGuard::new(&metrics);
        guard.settle(AcquireOutcome::Acquired);
    }
    {
        let mut guard = AcquireGuard::new(&metrics);
        guard.settle(AcquireOutcome::Failed);
    }

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.acquired(), 1);
    assert_eq!(snapshot.failed(), 1);
    assert_eq!(snapshot.abandoned(), 0);
}

#[test]
fn acquire_guard_defaults_to_abandoned_when_dropped_unsettled() {
    let metrics = metrics();
    {
        let _guard = AcquireGuard::new(&metrics);
        // Dropped without ever calling `settle`.
    }

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.abandoned(), 1);
    assert_eq!(snapshot.acquired(), 0);
    assert_eq!(snapshot.failed(), 0);
}

#[test]
fn acquire_guard_records_on_an_early_return_path_not_just_a_clean_fall_through() {
    fn fallible_step() -> Result<(), &'static str> {
        Err("boom")
    }

    // A realistic hand-rolled checkout: the guard is created up front and
    // `settle` is only reached at the end of a successful path. A `?` bail
    // partway through must still produce a measurement — that is the whole
    // point of recording from `Drop` rather than from an explicit call at
    // the end of the function.
    fn checkout_that_fails_early(metrics: &PoolAcquireMetrics) -> Result<(), &'static str> {
        let mut guard = AcquireGuard::new(metrics);
        fallible_step()?;
        guard.settle(AcquireOutcome::Acquired);
        Ok(())
    }

    let metrics = metrics();
    let result = checkout_that_fails_early(&metrics);
    assert_eq!(result, Err("boom"));

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.abandoned(),
        1,
        "the guard must still record when `?` exits before `settle`"
    );
    assert_eq!(snapshot.acquired(), 0);
}
