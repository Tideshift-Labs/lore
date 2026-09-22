// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Pool-**acquisition** latency under controlled contention (WP-109 Phase 5,
//! Case K).
//!
//! This measures the thing WP-121's placement gate is stated against and that
//! nothing in the fork could measure before: how long a caller waits to check a
//! connection *out* of a pool. Two figures already in the tree look like it and
//! are not it, and this case is built so that neither could produce its result:
//!
//! - `operation_duration` times a whole store operation. The work here is
//!   `SELECT 1`, so an operation timer would report the wait plus a microsecond
//!   and could not say which part was which. This case never runs a store
//!   operation at all — it holds a bare connection — so there is no operation
//!   duration to mistake for the answer.
//! - `pool_waiting` is a queue depth at an instant. It is sampled below as
//!   corroboration that contention really happened, but it is a count, and no
//!   sequence of counts yields a wait in milliseconds.
//!
//! **The case fails if the pool did not actually contend.** A contention proof
//! that passes when nothing queued is the failure mode WP-109's own "Context"
//! warns about, so the contended phase asserts a floor on the wait and on the
//! observed queue depth, not just an upper bound.
//!
//! Gated on `LORE_TEST_PG_URL` and `#[ignore]`d: without a real Postgres there
//! is nothing to contend for, and a body that skipped its setup would be
//! **NOT RUN**, never a pass.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use lore_postgres::pool::Pool;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool_named;

/// Connections the contended phase is allowed. Small on purpose: contention is
/// the subject, not an accident of load.
const CONTENDED_POOL_MAX: u32 = 4;
/// Concurrent callers in the contended phase.
const CONTENDED_WAITERS: usize = 32;
/// How long each contended caller holds its connection before releasing it.
const HOLD: Duration = Duration::from_millis(40);
/// Connections and callers in the uncontended phase — one each, so nobody ever
/// queues.
const BASELINE_POOL_MAX: u32 = 16;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

/// Open every connection the pool is allowed **without** recording a
/// measurement, so the measured phase times a warm checkout rather than a TCP
/// connect and a TLS handshake.
///
/// This is the one intended use of [`Pool::raw`]: a checkout taken through it
/// is deliberately absent from the tally. Warming through `Pool::get` would put
/// `pool_max` cold connects into the very histogram whose point is to separate
/// queue wait from everything else.
async fn warm(pool: &Pool, connections: u32) {
    let mut held = Vec::new();
    for _ in 0..connections {
        held.push(
            pool.raw()
                .get()
                .await
                .expect("warming a pool against a live Postgres must succeed"),
        );
    }
    // All `connections` are out at once, so the pool is forced to open every
    // one rather than handing the same connection back repeatedly.
    drop(held);
}

/// Run `waiters` concurrent measured checkouts, each holding its connection for
/// `hold`. Returns the peak `pool_waiting` depth a sampler saw, as independent
/// corroboration that the queue was real.
async fn contend(pool: Arc<Pool>, waiters: usize, hold: Duration) -> usize {
    let sampler_pool = Arc::clone(&pool);
    let sampling = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let sampler_flag = Arc::clone(&sampling);
    let sampler = lore_base::lore_spawn!(async move {
        let mut peak = 0_usize;
        while sampler_flag.load(std::sync::atomic::Ordering::Relaxed) {
            peak = peak.max(sampler_pool.status().waiting);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        peak
    });

    let mut callers = Vec::with_capacity(waiters);
    for _ in 0..waiters {
        let pool = Arc::clone(&pool);
        callers.push(lore_base::lore_spawn!(async move {
            let client = pool.get().await.expect("a checkout must not fail");
            tokio::time::sleep(hold).await;
            drop(client);
        }));
    }
    for caller in callers {
        caller.await.expect("no caller task may panic");
    }

    sampling.store(false, std::sync::atomic::Ordering::Relaxed);
    sampler.await.expect("the sampler task must not panic")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a real Postgres in LORE_TEST_PG_URL"]
async fn pool_acquisition_p95_separates_queue_wait_from_work_under_controlled_contention() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping the pool-acquisition contention case");
        return;
    };

    // ---- Phase A: uncontended baseline -------------------------------------
    // `BASELINE_POOL_MAX` connections for `BASELINE_POOL_MAX` callers, all warm.
    // Nobody can queue, so this is the floor the instrument reports when the
    // pool is not the bottleneck.
    let baseline = build_pool_named(
        &url,
        BASELINE_POOL_MAX,
        &TlsConfig::default(),
        "contention_baseline",
    )
    .expect("building a pool is lazy and must succeed");
    warm(&baseline, BASELINE_POOL_MAX).await;
    let baseline_peak_waiting = contend(
        Arc::new(baseline.clone()),
        BASELINE_POOL_MAX as usize,
        Duration::ZERO,
    )
    .await;
    let uncontended = baseline.acquire_snapshot();

    // ---- Phase B: controlled contention ------------------------------------
    // `CONTENDED_WAITERS` callers for `CONTENDED_POOL_MAX` connections, each
    // holding `HOLD`. Service order aside, the kth caller served waits about
    // `floor(k / CONTENDED_POOL_MAX) * HOLD`, so the run has an analytic shape
    // rather than being "some load".
    let contended_pool = build_pool_named(
        &url,
        CONTENDED_POOL_MAX,
        &TlsConfig::default(),
        "contention",
    )
    .expect("building a pool is lazy and must succeed");
    warm(&contended_pool, CONTENDED_POOL_MAX).await;
    let started = Instant::now();
    let contended_peak_waiting =
        contend(Arc::new(contended_pool.clone()), CONTENDED_WAITERS, HOLD).await;
    let wall_clock = started.elapsed();
    let contended = contended_pool.acquire_snapshot();

    // The analytic bound on the last caller's wait, with generous slack for a
    // loaded machine. A figure above this means the model is wrong, not that
    // the pool is slow, and the number should not be quoted.
    let waves = CONTENDED_WAITERS.div_ceil(CONTENDED_POOL_MAX as usize) as u32;
    let analytic_max_ms = f64::from(waves) * HOLD.as_secs_f64() * 1000.0;

    println!(
        "PHASE5-ACQ pool_max_baseline={BASELINE_POOL_MAX} pool_max_contended={CONTENDED_POOL_MAX} waiters={CONTENDED_WAITERS} hold_ms={}",
        HOLD.as_millis()
    );
    println!(
        "PHASE5-ACQ uncontended acquired={} failed={} abandoned={} p95_upper_ms={:?} max_ms={:.3} mean_ms={:?} peak_waiting={baseline_peak_waiting}",
        uncontended.acquired(),
        uncontended.failed(),
        uncontended.abandoned(),
        uncontended.p95_upper_bound_ms(),
        uncontended.max_ms(),
        uncontended.mean_ms(),
    );
    println!(
        "PHASE5-ACQ contended   acquired={} failed={} abandoned={} p95_upper_ms={:?} max_ms={:.3} mean_ms={:?} peak_waiting={contended_peak_waiting} analytic_max_ms={analytic_max_ms:.1} wall_clock_ms={:.1}",
        contended.acquired(),
        contended.failed(),
        contended.abandoned(),
        contended.p95_upper_bound_ms(),
        contended.max_ms(),
        contended.mean_ms(),
        wall_clock.as_secs_f64() * 1000.0,
    );
    println!(
        "PHASE5-ACQ contended_buckets boundaries_ms={:?} counts={:?}",
        lore_telemetry::POOL_ACQUIRE_BUCKET_BOUNDARIES_MS,
        contended.buckets(),
    );

    // ---- Every checkout is accounted for -----------------------------------
    // A p95 over a partial tally is not a p95. These pin that the instrument
    // saw every caller and that none of them failed, so neither figure can be
    // a clean-looking quantile over a run that was really pool exhaustion.
    assert_eq!(
        uncontended.acquired(),
        u64::from(BASELINE_POOL_MAX),
        "every baseline caller must be measured"
    );
    assert_eq!(uncontended.failed(), 0, "no baseline checkout may fail");
    assert_eq!(
        contended.acquired(),
        CONTENDED_WAITERS as u64,
        "every contended caller must be measured"
    );
    assert_eq!(contended.failed(), 0, "no contended checkout may fail");
    // Nobody is cancelled in either phase, so a nonzero count here means a
    // caller was dropped mid-wait and the quantiles below are computed over
    // fewer waits than the run actually produced — which would make them
    // underestimates, not the figures this case claims to report.
    assert_eq!(
        uncontended.abandoned(),
        0,
        "no baseline caller was cancelled; an abandoned wait would mean the \
         reported p95 is a lower bound rather than the measurement"
    );
    assert_eq!(
        contended.abandoned(),
        0,
        "no contended caller was cancelled; an abandoned wait would mean the \
         reported p95 is a lower bound rather than the measurement"
    );
    assert_eq!(
        contended.buckets().iter().sum::<u64>(),
        contended.acquired(),
        "the bucket tally must account for exactly the acquired checkouts"
    );

    // ---- The contended phase actually contended ----------------------------
    // Without these the case would pass on a run where the pool was never the
    // bottleneck, which would prove nothing at all.
    assert!(
        contended_peak_waiting > 0,
        "no caller ever queued (peak pool_waiting = 0), so this run did not \
         exercise contention and its p95 means nothing"
    );
    let contended_p95 = contended
        .p95_upper_bound_ms()
        .expect("the contended phase acquired connections");
    assert!(
        contended_p95 >= 250.0,
        "contended p95 upper bound was {contended_p95} ms; with {CONTENDED_WAITERS} \
         callers queueing for {CONTENDED_POOL_MAX} connections held {} ms each the \
         wait cannot be this small, so the instrument is not measuring the queue",
        HOLD.as_millis()
    );
    assert!(
        contended.max_ms() <= analytic_max_ms * 4.0,
        "longest wait {} ms exceeds four times the analytic bound {analytic_max_ms} ms; \
         the measurement is not the queue wait this model describes",
        contended.max_ms()
    );

    // ---- The instrument separates wait from work ---------------------------
    // The same trivial work ran in both phases. Only the queue differed, and
    // the figure moved by orders of magnitude — which is the whole claim.
    let uncontended_p95 = uncontended
        .p95_upper_bound_ms()
        .expect("the baseline phase acquired connections");
    assert!(
        // 5 ms, not the 250 ms gate: a warm checkout measures in tens of
        // microseconds, so a bound near the gate would pass on a broken warm-up
        // that put whole TCP connects in the tally. Still ~50x the observed
        // figure, so it does not flake on a loaded machine.
        uncontended_p95 <= 5.0,
        "a warm uncontended checkout reported a p95 upper bound of {uncontended_p95} ms; \
         either the pool was not warmed or this figure includes something other than \
         the checkout wait"
    );
    assert!(
        contended_p95 > uncontended_p95 * 10.0,
        "contended p95 {contended_p95} ms is not decisively above the uncontended \
         {uncontended_p95} ms, so the instrument does not distinguish a queued \
         checkout from a free one"
    );
    assert_eq!(
        baseline_peak_waiting, 0,
        "the baseline phase must never queue; it had one connection per caller"
    );
}
