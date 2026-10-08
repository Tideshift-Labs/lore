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
