// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! WP-115 row 80: the drain's per-replica reserve permit and retry schedule,
//! driven through the public `drain_reserve` API only.
//!
//! Infrastructure-free and cross-platform. Time is paused (`start_paused`), so
//! every delay assertion measures the exact virtual sleep the gate asked for,
//! not wall-clock luck. `DrainReserveGate::run` draws its jitter from the
//! thread RNG, so timing assertions here are bounds, never exact values; the
//! seeded cases exercise the pure `backoff_delay` instead.
//!
//! What this file does NOT prove: that `send_promotion` wires the gate around
//! `reserve_spool`, or which errors it retries. Those are call-site facts
//! pinned in `write_behind_source_pins.rs`.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lore_postgres::store::write_behind::drain_reserve::DEFAULT_DRAIN_RESERVE_ATTEMPTS;
use lore_postgres::store::write_behind::drain_reserve::DEFAULT_DRAIN_RESERVE_BACKOFF_BASE_MILLIS;
use lore_postgres::store::write_behind::drain_reserve::DEFAULT_DRAIN_RESERVE_BACKOFF_CAP_MILLIS;
use lore_postgres::store::write_behind::drain_reserve::DEFAULT_DRAIN_RESERVE_PERMIT_WAIT_MILLIS;
use lore_postgres::store::write_behind::drain_reserve::DEFAULT_DRAIN_RESERVE_PERMITS;
use lore_postgres::store::write_behind::drain_reserve::DrainReserveGate;
use lore_postgres::store::write_behind::drain_reserve::DrainReserveSettings;
use lore_postgres::store::write_behind::drain_reserve::GatedReserve;
use lore_postgres::store::write_behind::drain_reserve::MAX_DRAIN_RESERVE_ATTEMPTS;
use lore_postgres::store::write_behind::drain_reserve::MAX_DRAIN_RESERVE_BACKOFF_MILLIS;
use lore_postgres::store::write_behind::drain_reserve::backoff_ceiling;
use lore_postgres::store::write_behind::drain_reserve::backoff_delay;
use lore_postgres::store::write_behind::drain_reserve::max_total_backoff;
use rand::SeedableRng;
use tokio::time::Instant;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

/// Run `tasks` concurrent single-shot attempts that each hold their permit for
/// `hold`, and return the highest number ever in flight at once.
async fn peak_in_flight(permits: usize, tasks: usize, hold: Duration) -> usize {
    let gate = DrainReserveGate::new(DrainReserveSettings {
        permits,
        permit_wait: ms(60_000),
        ..DrainReserveSettings::default()
    });
    let in_flight = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let contenders: Vec<BoxedFuture<'_, _>> = (0..tasks)
        .map(|_| {
            let (gate, in_flight, peak) = (&gate, &in_flight, &peak);
            let contender: BoxedFuture<'_, _> = Box::pin(async move {
                gate.run(
                    || async move {
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        tokio::time::sleep(hold).await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        Ok::<(), ()>(())
                    },
                    |_| false,
                )
                .await
            });
            contender
        })
        .collect();
    for result in join_all(contenders).await {
        assert_eq!(result, Ok(()));
    }
    assert_eq!(gate.available_permits(), permits, "every permit comes back");
    peak.load(Ordering::SeqCst)
}

type BoxedFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>;

/// Drive every future on the calling task, so paused time stays deterministic and
/// the workspace's `tokio::spawn` ban is respected.
async fn join_all<T>(futures: Vec<BoxedFuture<'_, T>>) -> Vec<T> {
    let mut slots: Vec<(BoxedFuture<'_, T>, Option<T>)> =
        futures.into_iter().map(|future| (future, None)).collect();
    std::future::poll_fn(|context| {
        let mut pending = false;
        for (future, output) in &mut slots {
            if output.is_none() {
                match future.as_mut().poll(context) {
                    std::task::Poll::Ready(value) => *output = Some(value),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    slots
        .into_iter()
        .map(|(_, output)| output.expect("every future completed"))
        .collect()
}

/// (a) The default is one permit, and N+1 contenders never put more than N in
/// flight. `peak == N` (not `<= N`) also proves the gate admits N at once, so a
/// gate that serialised everything would fail the N=2 case.
#[tokio::test(start_paused = true)]
async fn the_default_permit_count_is_one_and_n_plus_one_contenders_never_exceed_n() {
    assert_eq!(DEFAULT_DRAIN_RESERVE_PERMITS, 1);
    assert_eq!(DrainReserveSettings::default().permits, 1);
    assert_eq!(
        peak_in_flight(1, 2, ms(5)).await,
        1,
        "default N=1, 2 contenders"
    );
    assert_eq!(
        peak_in_flight(1, 8, ms(5)).await,
        1,
        "default N=1, 8 contenders"
    );
    assert_eq!(
        peak_in_flight(2, 3, ms(5)).await,
        2,
        "configured N=2, 3 contenders"
    );
    assert_eq!(
        peak_in_flight(2, 8, ms(5)).await,
        2,
        "configured N=2, 8 contenders"
    );
}

/// (a) A zero permit or attempt count is raised to one, never a gate that
/// admits nothing or runs nothing.
#[tokio::test(start_paused = true)]
async fn a_zero_permit_count_still_admits_exactly_one_attempt_at_a_time() {
    let gate = Arc::new(DrainReserveGate::new(DrainReserveSettings {
        permits: 0,
        attempts: 0,
        permit_wait: ms(60_000),
        ..DrainReserveSettings::default()
    }));
    assert_eq!(gate.available_permits(), 1);
    let calls = AtomicUsize::new(0);
    let result = gate
        .run(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>("contended") }
            },
            |_| true,
        )
        .await;
    assert_eq!(result, Err(GatedReserve::Failed("contended")));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "attempts 0 means one try");
}

/// (b) A permit held past `permit_wait` is a `PermitTimeout` after exactly the
/// configured wait; the attempt never runs; the held permit is untouched; and
/// the gate works again once it is released.
#[tokio::test(start_paused = true)]
async fn a_permit_held_past_the_wait_is_a_permit_timeout_and_the_attempt_never_runs() {
    let gate = DrainReserveGate::new(DrainReserveSettings {
        permit_wait: ms(50),
        ..DrainReserveSettings::default()
    });
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let started = tokio::sync::Notify::new();
    let calls = AtomicUsize::new(0);
    let mut released = Some(released);
    // The holder's attempt owns the only permit until `release` fires.
    let holder = gate.run(
        || {
            let released = released.take();
            let started = &started;
            async move {
                started.notify_one();
                if let Some(released) = released {
                    let _ = released.await;
                }
                Ok::<(), ()>(())
            }
        },
        |_| false,
    );
    let contender = async {
        started.notified().await;
        assert_eq!(
            gate.available_permits(),
            0,
            "the holder owns the only permit"
        );
        let began = Instant::now();
        let result = gate
            .run(
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok::<(), ()>(()) }
                },
                |_| true,
            )
            .await;
        assert_eq!(result, Err(GatedReserve::PermitTimeout));
        assert_eq!(
            began.elapsed(),
            ms(50),
            "waits exactly the configured bound"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no attempt without a permit"
        );
        assert_eq!(
            gate.available_permits(),
            0,
            "a timeout must not steal the permit"
        );
        release.send(()).expect("holder still waiting");
    };
    let (held, ()) = tokio::join!(holder, contender);
    assert_eq!(held, Ok(()));
    assert_eq!(gate.available_permits(), 1);
    let after = gate.run(|| async { Ok::<_, ()>(7) }, |_| false).await;
    assert_eq!(after, Ok(7), "the gate recovers once the permit is free");
}

/// (b) A permit timeout on a RETRY ends the run too, without a further attempt
/// and without a new error class: still `PermitTimeout`.
#[tokio::test(start_paused = true)]
async fn a_permit_lost_during_the_backoff_sleep_times_out_the_retry() {
    let gate = DrainReserveGate::new(DrainReserveSettings {
        permit_wait: ms(20),
        backoff_base: ms(200),
        backoff_cap: ms(200),
        ..DrainReserveSettings::default()
    });
    let calls = AtomicUsize::new(0);
    let runner = gate.run(
        || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>("contended") }
        },
        |_| true,
    );
    // The first try fails at once, so the runner is asleep for 100..=200 ms.
    // Another attempt takes the freed permit at 10 ms and keeps it past the sleep.
    let blocker = async {
        tokio::time::sleep(ms(10)).await;
        gate.run(
            || async {
                tokio::time::sleep(ms(500)).await;
                Ok::<(), ()>(())
            },
            |_| false,
        )
        .await
    };
    let (runner, blocker) = tokio::join!(runner, blocker);
    assert_eq!(runner, Err(GatedReserve::PermitTimeout));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "no second try without a permit"
    );
    assert_eq!(blocker, Ok(()));
    assert_eq!(gate.available_permits(), 1);
}

/// (c) The documented defaults, and the exact try count and per-gap bounds of
/// the real `run` loop under a permanently contended fake.
#[tokio::test(start_paused = true)]
async fn the_real_loop_makes_five_tries_with_each_gap_in_its_ceiling_band() {
    assert_eq!(DEFAULT_DRAIN_RESERVE_ATTEMPTS, 5);
    assert_eq!(DEFAULT_DRAIN_RESERVE_BACKOFF_BASE_MILLIS, 5);
    assert_eq!(DEFAULT_DRAIN_RESERVE_BACKOFF_CAP_MILLIS, 80);
    assert_eq!(DEFAULT_DRAIN_RESERVE_PERMIT_WAIT_MILLIS, 1_000);
    let settings = DrainReserveSettings::default();
    let gate = DrainReserveGate::new(settings);
    let starts = Mutex::new(Vec::<Instant>::new());
    let result = gate
        .run(
            || {
                starts.lock().expect("lock").push(Instant::now());
                async { Err::<(), _>("contended") }
            },
            |_| true,
        )
        .await;
    assert_eq!(result, Err(GatedReserve::Failed("contended")));
    let starts = starts.into_inner().expect("lock");
    assert_eq!(starts.len(), 5, "five tries in total, not five retries");
    let mut total = Duration::ZERO;
    for (retry, pair) in starts.windows(2).enumerate() {
        let gap = pair[1] - pair[0];
        let ceiling = backoff_ceiling(&settings, retry as u32);
        assert!(
            gap >= ceiling / 2 && gap <= ceiling,
            "gap {retry} was {gap:?}, expected within [{:?}, {ceiling:?}]",
            ceiling / 2
        );
        total += gap;
    }
    assert!(total <= max_total_backoff(&settings));
    assert_eq!(max_total_backoff(&settings), ms(75), "5+10+20+40");
}

/// (c) Ceilings double, never decrease, never pass the cap, and survive a shift
/// that would overflow a `u32`.
#[test]
fn backoff_ceilings_are_monotone_doubling_and_capped_even_past_shift_overflow() {
    let settings = DrainReserveSettings::default();
    let ceilings: Vec<_> = (0..6).map(|n| backoff_ceiling(&settings, n)).collect();
    assert_eq!(ceilings, [ms(5), ms(10), ms(20), ms(40), ms(80), ms(80)]);
    for config in [
        settings,
        DrainReserveSettings {
            backoff_base: ms(1),
            backoff_cap: ms(MAX_DRAIN_RESERVE_BACKOFF_MILLIS),
            ..settings
        },
        DrainReserveSettings {
            backoff_base: ms(MAX_DRAIN_RESERVE_BACKOFF_MILLIS),
            backoff_cap: ms(MAX_DRAIN_RESERVE_BACKOFF_MILLIS),
            ..settings
        },
    ] {
        let mut previous = Duration::ZERO;
        for retry in 0..100 {
            let ceiling = backoff_ceiling(&config, retry);
            assert!(ceiling >= previous, "retry {retry} went down");
            assert!(
                ceiling <= config.backoff_cap,
                "retry {retry} passed the cap"
            );
            previous = ceiling;
        }
        assert_eq!(previous, config.backoff_cap, "the cap is reached");
    }
}

/// (c) Every drawn delay is inside `[ceiling/2, ceiling]`, the summed worst case
/// bounds a whole run, two seeds jitter differently, and one seed repeats.
#[test]
fn seeded_jitter_stays_in_band_differs_by_seed_and_repeats_for_one_seed() {
    let settings = DrainReserveSettings::default();
    let sequence = |seed: u64| -> Vec<Duration> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        (0..100)
            .map(|index| backoff_delay(&settings, index % 5, &mut rng))
            .collect()
    };
    let (first, second) = (sequence(1), sequence(2));
    for (index, delay) in first.iter().chain(second.iter()).enumerate() {
        let ceiling = backoff_ceiling(&settings, (index % 100) as u32 % 5);
        assert!(
            *delay >= ceiling / 2 && *delay <= ceiling,
            "{delay:?} outside [{:?}, {ceiling:?}]",
            ceiling / 2
        );
    }
    assert_ne!(first, second, "two seeds must not give one schedule");
    assert_eq!(first, sequence(1), "one seed is repeatable");
    assert!(
        first
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            > 5,
        "the jitter must actually vary, not collapse onto the ceilings"
    );
}

/// (c) The worst-case sleep is bounded at the configuration limits too: the
/// largest legal configuration cannot sleep unboundedly.
#[test]
fn the_worst_case_sleep_is_bounded_at_the_configuration_limits() {
    let widest = DrainReserveSettings {
        attempts: MAX_DRAIN_RESERVE_ATTEMPTS,
        backoff_base: ms(MAX_DRAIN_RESERVE_BACKOFF_MILLIS),
        backoff_cap: ms(MAX_DRAIN_RESERVE_BACKOFF_MILLIS),
        ..DrainReserveSettings::default()
    };
    assert_eq!(
        max_total_backoff(&widest),
        ms((u64::from(MAX_DRAIN_RESERVE_ATTEMPTS) - 1) * MAX_DRAIN_RESERVE_BACKOFF_MILLIS)
    );
    let single = DrainReserveSettings {
        attempts: 1,
        ..DrainReserveSettings::default()
    };
    assert_eq!(
        max_total_backoff(&single),
        Duration::ZERO,
        "one try never sleeps"
    );
}

/// (d, gate half) The predicate decides: a non-retryable error is one try and is
/// returned unchanged; a retryable one stops at `attempts`. Which real errors
/// are retryable is pinned in `write_behind_source_pins.rs`.
#[tokio::test(start_paused = true)]
async fn only_errors_the_predicate_accepts_are_retried() {
    let gate = DrainReserveGate::new(DrainReserveSettings::default());
    for (error, expected_calls) in [("contended", 5usize), ("unavailable", 5), ("refused", 1)] {
        let calls = AtomicUsize::new(0);
        let result = gate
            .run(
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async move { Err::<(), _>(error) }
                },
                |error| matches!(*error, "contended" | "unavailable"),
            )
            .await;
        assert_eq!(result, Err(GatedReserve::Failed(error)));
        assert_eq!(calls.load(Ordering::SeqCst), expected_calls, "{error}");
    }
}

/// (e) The permit is free while a run sleeps. With one permit and a 100..=200 ms
/// backoff, a second run that waits at most 20 ms for the permit succeeds during
/// the first run's sleep. If the first run kept its permit while sleeping, the
/// second would time out.
#[tokio::test(start_paused = true)]
async fn another_attempt_runs_during_a_backoff_sleep() {
    let gate = DrainReserveGate::new(DrainReserveSettings {
        permit_wait: ms(20),
        attempts: 2,
        backoff_base: ms(200),
        backoff_cap: ms(200),
        ..DrainReserveSettings::default()
    });
    let began = Instant::now();
    let sleeper = gate.run(|| async { Err::<(), _>("contended") }, |_| true);
    let neighbour = async {
        tokio::time::sleep(ms(10)).await;
        gate.run(|| async { Ok::<_, ()>(Instant::now()) }, |_| false)
            .await
    };
    let (sleeper, neighbour) = tokio::join!(sleeper, neighbour);
    let ran_at = neighbour.expect("the neighbour must get the permit during the sleep");
    assert!(
        ran_at - began < ms(100),
        "ran inside the first run's minimum sleep"
    );
    assert_eq!(sleeper, Err(GatedReserve::Failed("contended")));
    assert_eq!(gate.available_permits(), 1);
}

/// (e) The permit is also dropped when an attempt fails for good, and when a
/// run is cancelled mid-attempt, so a dropped promotion cannot leak the permit.
#[tokio::test(start_paused = true)]
async fn the_permit_returns_after_a_terminal_failure_and_after_cancellation() {
    let gate = DrainReserveGate::new(DrainReserveSettings::default());
    let failed = gate
        .run(|| async { Err::<(), _>("refused") }, |_| false)
        .await;
    assert_eq!(failed, Err(GatedReserve::Failed("refused")));
    assert_eq!(gate.available_permits(), 1);

    // Cancellation without a task: race the run against a short timer and let
    // the timer win, which drops the run future mid-attempt.
    let raced = tokio::time::timeout(
        ms(10),
        gate.run(
            || async {
                tokio::time::sleep(ms(10_000)).await;
                Ok::<(), ()>(())
            },
            |_| false,
        ),
    )
    .await;
    assert!(raced.is_err(), "the timer must win the race");
    assert_eq!(
        gate.available_permits(),
        1,
        "an aborted run frees its permit"
    );
}
