// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Pool **acquisition** latency: how long a caller waits to check a connection
//! *out* of a pool, before any SQL is sent.
//!
//! This is deliberately its own instrument, because the two things already in
//! the tree that look like it measure something else and neither substitutes
//! for it:
//!
//! - [`crate::METRICS_OPERATION_LATENCY_METRIC_NAME`] (`operation_duration`)
//!   times a whole store operation — the checkout wait *plus* the SQL *plus*
//!   any object-store round trip. An operation that is slow because the query
//!   is slow and one that is slow because the pool is empty are
//!   indistinguishable in it.
//! - `pool_waiting` / `pool_available` are queue-depth **gauges** sampled at an
//!   instant. They say how many callers were queued when someone looked; they
//!   never say how long any of them waited.
//!
//! A placement gate stated as a p95 on the wait therefore needs the wait
//! itself, recorded per checkout.
//!
//! Every recorder keeps an in-process bucket tally beside the OpenTelemetry
//! histogram. The OTLP pipeline is how an operator reads this in a cell; the
//! tally is how a test, a probe, or an operator surface reads it in the same
//! process without standing up a collector. Both are fed from one measurement,
//! so they cannot disagree.

use std::borrow::Cow;
use std::future::Future;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use opentelemetry::KeyValue;
use opentelemetry::metrics::Histogram;

use crate::InstrumentProvider;

/// The metric name every connection pool records its checkout wait under.
pub const METRICS_POOL_ACQUIRE_METRIC_NAME: &str = "pool_acquire_duration";

/// The label carrying which pool a measurement came from.
pub const METRICS_POOL_ATTRIBUTE_NAME: &str = "pool";

/// The label carrying whether the checkout succeeded.
pub const METRICS_ACQUIRE_OUTCOME_ATTRIBUTE_NAME: &str = "outcome";

/// Bucket boundaries, in milliseconds.
///
/// [`InstrumentProvider::latency_histogram_ms`]'s boundaries start at 10 ms,
/// which collapses every uncontended checkout — normally tens of microseconds —
/// into a single bucket and makes any p95 below 10 ms unreadable. These start
/// at 50 us.
///
/// **100.0 and 250.0 are boundaries on purpose**: they are the two thresholds
/// a p95 acquisition gate is stated against, so the gate is answered by
/// comparing bucket counts rather than by interpolating across a bucket that
/// straddles the threshold.
pub const POOL_ACQUIRE_BUCKET_BOUNDARIES_MS: &[f64] = &[
    0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0,
];

/// How a checkout ended. A failed checkout still waited, and its wait is the
/// most interesting one there is, so it is recorded rather than dropped — under
/// its own label so a p95 can be taken over successes alone when that is what
/// is wanted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcquireOutcome {
    /// A connection was handed to the caller.
    Acquired,
    /// The checkout failed or timed out. The recorded duration is the wait
    /// before the failure, not a service time.
    Failed,
    /// The caller went away while still waiting — a deadline elapsed, a
    /// `select!` branch lost, the request was cancelled — so the checkout future
    /// was dropped before it resolved.
    ///
    /// This exists because leaving it out silently biases the quantile **low in
    /// exactly the conditions the gate is about**: the waits that get abandoned
    /// are the long ones, and a pool under real pressure sheds its worst
    /// waiters through upstream deadlines. A p95 computed from only the
    /// checkouts that survived would look healthiest at the moment the pool was
    /// least healthy. It is not folded into `Failed` because nothing failed;
    /// the caller left.
    Abandoned,
}

impl AcquireOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Acquired => "acquired",
            Self::Failed => "failed",
            Self::Abandoned => "abandoned",
        }
    }
}

/// One pool's acquisition-latency recorder.
///
/// Construct one per pool and share it by reference; the counters are atomic
/// and the recording path allocates nothing.
#[derive(Debug)]
pub struct PoolAcquireMetrics {
    histogram: Histogram<f64>,
    acquired_labels: [KeyValue; 2],
    failed_labels: [KeyValue; 2],
    abandoned_labels: [KeyValue; 2],
    /// One counter per boundary plus one overflow counter, successes only.
    buckets: Box<[AtomicU64]>,
    acquired: AtomicU64,
    failed: AtomicU64,
    abandoned: AtomicU64,
    abandoned_max_nanos: AtomicU64,
    total_nanos: AtomicU64,
    max_nanos: AtomicU64,
}

impl PoolAcquireMetrics {
    /// Build a recorder for `pool` (`immutable`, `relay`, `dispatch`, ...)
    /// under `provider`'s namespace.
    pub fn new(provider: &impl InstrumentProvider, pool: impl Into<Cow<'static, str>>) -> Self {
        let pool = pool.into();
        let histogram = provider
            .meter()
            .f64_histogram(provider.scope_name(METRICS_POOL_ACQUIRE_METRIC_NAME))
            .with_unit("milliseconds")
            .with_boundaries(POOL_ACQUIRE_BUCKET_BOUNDARIES_MS.to_vec())
            .build();
        let label = |outcome: AcquireOutcome| {
            [
                KeyValue::new(METRICS_POOL_ATTRIBUTE_NAME, pool.clone()),
                KeyValue::new(METRICS_ACQUIRE_OUTCOME_ATTRIBUTE_NAME, outcome.as_str()),
            ]
        };
        Self {
            histogram,
            acquired_labels: label(AcquireOutcome::Acquired),
            failed_labels: label(AcquireOutcome::Failed),
            abandoned_labels: label(AcquireOutcome::Abandoned),
            buckets: (0..=POOL_ACQUIRE_BUCKET_BOUNDARIES_MS.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            acquired: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            abandoned: AtomicU64::new(0),
            abandoned_max_nanos: AtomicU64::new(0),
            total_nanos: AtomicU64::new(0),
            max_nanos: AtomicU64::new(0),
        }
    }

    /// Record one checkout's wait.
    ///
    /// Only successful checkouts enter the in-process bucket tally, so a
    /// quantile taken from [`PoolAcquireMetrics::snapshot`] is a quantile over
    /// waits that actually produced a connection. Failed and abandoned
    /// checkouts are counted separately and exported to OTLP under their own
    /// `outcome` label, so neither a run where the pool was exhausted nor one
    /// where callers timed out and left can read as a clean p95. The longest
    /// abandoned wait is retained too
    /// ([`PoolAcquireSnapshot::abandoned_max_ms`]), because it is the figure
    /// that tells a reader the quantile above it is an underestimate.
    pub fn record(&self, waited: Duration, outcome: AcquireOutcome) {
        let millis = waited.as_secs_f64() * 1000.0;
        match outcome {
            AcquireOutcome::Acquired => {
                self.histogram.record(millis, &self.acquired_labels);
                let index = POOL_ACQUIRE_BUCKET_BOUNDARIES_MS
                    .iter()
                    .position(|boundary| millis <= *boundary)
                    .unwrap_or(POOL_ACQUIRE_BUCKET_BOUNDARIES_MS.len());
                // `buckets` is built with exactly this length, so the index is
                // always in range; `get` keeps that true by construction rather
                // than by an indexing panic if the lengths ever drift.
                if let Some(bucket) = self.buckets.get(index) {
                    bucket.fetch_add(1, Ordering::Relaxed);
                }
                self.acquired.fetch_add(1, Ordering::Relaxed);
                let nanos = u64::try_from(waited.as_nanos()).unwrap_or(u64::MAX);
                self.total_nanos.fetch_add(nanos, Ordering::Relaxed);
                self.max_nanos.fetch_max(nanos, Ordering::Relaxed);
            }
            AcquireOutcome::Failed => {
                self.histogram.record(millis, &self.failed_labels);
                self.failed.fetch_add(1, Ordering::Relaxed);
            }
            AcquireOutcome::Abandoned => {
                self.histogram.record(millis, &self.abandoned_labels);
                self.abandoned.fetch_add(1, Ordering::Relaxed);
                let nanos = u64::try_from(waited.as_nanos()).unwrap_or(u64::MAX);
                self.abandoned_max_nanos.fetch_max(nanos, Ordering::Relaxed);
            }
        }
    }

    /// Time `checkout` and record its wait, classifying by how it ended.
    ///
    /// The timer starts when the returned future is **first polled** — this is
    /// an `async fn`, so its body does not run before that — and stops the
    /// instant the checkout resolves. It therefore covers the queue wait and,
    /// for a pool that opens connections lazily, the connect: what a caller
    /// actually waits for, and what exhausts a cell instance.
    ///
    /// **A future dropped before it is ever polled records nothing**, because
    /// the guard below is constructed in the body. That is deliberate rather
    /// than an oversight: such a call never polled the checkout either, so no
    /// connection was requested and no time elapsed. It cannot hide a long
    /// wait — every long wait is by definition one that was polled and then
    /// cancelled, which the guard does record. What it does mean is that
    /// `abandoned()` counts abandoned *waits*, not abandoned *intentions*; see
    /// [`AcquireGuard`] if you need the latter.
    ///
    /// **A caller that goes away mid-wait is recorded, not lost.** The timing
    /// lives in a guard whose `Drop` does the recording, so cancelling the
    /// returned future — an elapsed deadline, a losing `select!` branch, a
    /// dropped request — still produces a measurement, classified
    /// [`AcquireOutcome::Abandoned`]. Recording only on resolution would drop
    /// precisely the longest waits, because a pool under pressure sheds its
    /// worst waiters through upstream deadlines, and the p95 would then look
    /// best when the pool was worst.
    pub async fn measure<T, E, F>(&self, checkout: F) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        let mut guard = AcquireGuard {
            metrics: self,
            start: Instant::now(),
            outcome: AcquireOutcome::Abandoned,
        };
        let result = checkout.await;
        // Reached only if the future was not cancelled; otherwise the guard is
        // dropped still holding `Abandoned`.
        guard.outcome = if result.is_ok() {
            AcquireOutcome::Acquired
        } else {
            AcquireOutcome::Failed
        };
        result
    }

    /// Read the in-process tally. Cheap; takes no lock.
    pub fn snapshot(&self) -> PoolAcquireSnapshot {
        PoolAcquireSnapshot {
            buckets: self
                .buckets
                .iter()
                .map(|bucket| bucket.load(Ordering::Relaxed))
                .collect(),
            acquired: self.acquired.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            abandoned: self.abandoned.load(Ordering::Relaxed),
            abandoned_max_nanos: self.abandoned_max_nanos.load(Ordering::Relaxed),
            total_nanos: self.total_nanos.load(Ordering::Relaxed),
            max_nanos: self.max_nanos.load(Ordering::Relaxed),
        }
    }
}

/// Times one checkout and records it on drop, so a cancelled wait is measured
/// rather than silently discarded.
///
/// Public so a pool that cannot use [`PoolAcquireMetrics::measure`] — one whose
/// checkout is not a single future, such as a hand-rolled permit-then-connect
/// pool — can still get cancellation-safe timing instead of an `Instant` pair
/// that a `?` or a cancellation skips past.
pub struct AcquireGuard<'a> {
    metrics: &'a PoolAcquireMetrics,
    start: Instant,
    outcome: AcquireOutcome,
}

impl<'a> AcquireGuard<'a> {
    /// Start timing. The guard records [`AcquireOutcome::Abandoned`] unless
    /// [`AcquireGuard::settle`] says otherwise before it drops, so every exit
    /// path — including an early `?` and a cancellation — is accounted for.
    pub fn new(metrics: &'a PoolAcquireMetrics) -> Self {
        Self {
            metrics,
            start: Instant::now(),
            outcome: AcquireOutcome::Abandoned,
        }
    }

    /// Classify this checkout. The measurement is still taken on drop.
    pub fn settle(&mut self, outcome: AcquireOutcome) {
        self.outcome = outcome;
    }
}

impl Drop for AcquireGuard<'_> {
    fn drop(&mut self) {
        self.metrics.record(self.start.elapsed(), self.outcome);
    }
}

/// A point-in-time read of one pool's acquisition tally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolAcquireSnapshot {
    buckets: Vec<u64>,
    acquired: u64,
    failed: u64,
    abandoned: u64,
    abandoned_max_nanos: u64,
    total_nanos: u64,
    max_nanos: u64,
}

impl PoolAcquireSnapshot {
    /// Checkouts that produced a connection.
    pub const fn acquired(&self) -> u64 {
        self.acquired
    }

    /// Checkouts whose caller left while still waiting.
    ///
    /// **Read this beside any quantile below.** These waits are excluded from
    /// the bucket tally because they never produced a connection, and they skew
    /// long, so a nonzero count means the reported quantile is a lower bound on
    /// what callers actually experienced.
    pub const fn abandoned(&self) -> u64 {
        self.abandoned
    }

    /// Longest abandoned wait, in milliseconds; `0.0` when none were abandoned.
    pub fn abandoned_max_ms(&self) -> f64 {
        self.abandoned_max_nanos as f64 / 1_000_000.0
    }

    /// Checkouts that failed or timed out waiting.
    pub const fn failed(&self) -> u64 {
        self.failed
    }

    /// Longest successful wait, in milliseconds.
    pub fn max_ms(&self) -> f64 {
        self.max_nanos as f64 / 1_000_000.0
    }

    /// Mean successful wait, in milliseconds. `None` when nothing was acquired.
    pub fn mean_ms(&self) -> Option<f64> {
        (self.acquired > 0).then(|| self.total_nanos as f64 / self.acquired as f64 / 1_000_000.0)
    }

    /// Per-bucket counts, in [`POOL_ACQUIRE_BUCKET_BOUNDARIES_MS`] order, with
    /// one trailing overflow count.
    pub fn buckets(&self) -> &[u64] {
        &self.buckets
    }

    /// The **upper bound** of the bucket holding the `quantile`th successful
    /// wait.
    ///
    /// This deliberately does not interpolate. A histogram knows which bucket a
    /// quantile falls in and nothing finer; interpolating inside the bucket
    /// invents a figure the data does not carry, and a gate stated as
    /// "p95 below 100 ms" is answered exactly by "the p95 bucket's upper bound
    /// is at or below 100 ms" because 100.0 is itself a boundary.
    ///
    /// Returns `None` when nothing was acquired, and `f64::INFINITY` when the
    /// quantile lands in the overflow bucket above the last boundary — which is
    /// a real answer ("above 5 s"), not a missing one.
    pub fn quantile_upper_bound_ms(&self, quantile: f64) -> Option<f64> {
        if self.acquired == 0 || !(0.0..=1.0).contains(&quantile) {
            return None;
        }
        // The rank of the sample the quantile names, counting from 1.
        let target = ((self.acquired as f64) * quantile).ceil().max(1.0) as u64;
        let mut seen = 0_u64;
        for (index, count) in self.buckets.iter().enumerate() {
            seen += count;
            if seen >= target {
                return Some(
                    POOL_ACQUIRE_BUCKET_BOUNDARIES_MS
                        .get(index)
                        .copied()
                        .unwrap_or(f64::INFINITY),
                );
            }
        }
        Some(f64::INFINITY)
    }

    /// The p95 upper bound, the figure a placement gate is stated against.
    pub fn p95_upper_bound_ms(&self) -> Option<f64> {
        self.quantile_upper_bound_ms(0.95)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

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
}
