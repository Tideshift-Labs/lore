// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! WP-115 row 80: the drain's per-replica reserve permit and retry schedule.
//!
//! `drain_reserve_v1` updates four single hot rows (three quota rows and the
//! cell's `drain_policies` row) under SERIALIZABLE on every reservation. Row
//! 80's cause split measured 84% of drain promotion abandons as
//! `reserve_spool / drain_contended`: every drain slot of every replica raced
//! the same rows, and the old retry replayed twice at once.
//!
//! Two bounds answer it, and neither changes any SQL:
//!
//! - **One permit per replica** (by default) around each reserve attempt, so a
//!   replica's own slots never conflict with each other there. The permit is
//!   taken before the attempt checks out any dispatch connection (the attempt
//!   does that itself) and dropped before any backoff sleep, so it is never
//!   held while waiting for a connection or while sleeping. Its wait is bounded;
//!   a timeout is [`GatedReserve::PermitTimeout`], which the drain abandons on
//!   the existing deferral path.
//! - **Jittered exponential backoff** between attempts, so two replicas that
//!   conflicted once do not retry in lockstep.
//!
//! The global cap and the reservation accounting are the database's and stay
//! unchanged. Replaying the same prepared descriptor after a conflict is safe;
//! that is the caller's property (see the drain's `send_promotion`).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

/// Most reserve permits one replica may configure: one per drain slot.
pub const MAX_DRAIN_RESERVE_PERMITS: usize = 8;
/// Most reserve attempts one promotion may configure.
pub const MAX_DRAIN_RESERVE_ATTEMPTS: u32 = 10;
/// Upper bound on the permit wait, in milliseconds.
pub const MAX_DRAIN_RESERVE_PERMIT_WAIT_MILLIS: u64 = 10_000;
/// Upper bound on each backoff duration, in milliseconds.
pub const MAX_DRAIN_RESERVE_BACKOFF_MILLIS: u64 = 1_000;

/// [`DrainReserveSettings::permits`]'s default.
pub const DEFAULT_DRAIN_RESERVE_PERMITS: usize = 1;
/// [`DrainReserveSettings::permit_wait`]'s default, in milliseconds. A reserve
/// is one short transaction, so a queue of the other three default slots
/// clears far inside it.
pub const DEFAULT_DRAIN_RESERVE_PERMIT_WAIT_MILLIS: u64 = 1_000;
/// [`DrainReserveSettings::attempts`]'s default: total tries, not retries.
pub const DEFAULT_DRAIN_RESERVE_ATTEMPTS: u32 = 5;
/// [`DrainReserveSettings::backoff_base`]'s default, in milliseconds.
pub const DEFAULT_DRAIN_RESERVE_BACKOFF_BASE_MILLIS: u64 = 5;
/// [`DrainReserveSettings::backoff_cap`]'s default, in milliseconds.
pub const DEFAULT_DRAIN_RESERVE_BACKOFF_CAP_MILLIS: u64 = 80;

/// Operator configuration for the drain's reserve permit and retry schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainReserveSettings {
    /// Reserve attempts one replica runs at once. At least 1; there is no
    /// "unlimited" value.
    pub permits: usize,
    /// How long one attempt waits for a permit before the promotion is
    /// abandoned with cause `permit_timeout`.
    pub permit_wait: Duration,
    /// Total reserve tries per promotion, counting the first.
    pub attempts: u32,
    /// The first backoff ceiling. Retry `n` (from 0) sleeps a uniform duration
    /// in `[c/2, c]` where `c = min(backoff_cap, backoff_base * 2^n)`.
    pub backoff_base: Duration,
    /// The largest backoff ceiling.
    pub backoff_cap: Duration,
}

impl Default for DrainReserveSettings {
    fn default() -> Self {
        Self {
            permits: DEFAULT_DRAIN_RESERVE_PERMITS,
            permit_wait: Duration::from_millis(DEFAULT_DRAIN_RESERVE_PERMIT_WAIT_MILLIS),
            attempts: DEFAULT_DRAIN_RESERVE_ATTEMPTS,
            backoff_base: Duration::from_millis(DEFAULT_DRAIN_RESERVE_BACKOFF_BASE_MILLIS),
            backoff_cap: Duration::from_millis(DEFAULT_DRAIN_RESERVE_BACKOFF_CAP_MILLIS),
        }
    }
}

/// The backoff ceiling before retry `retry` (0 for the sleep after the first
/// failed attempt): `min(backoff_cap, backoff_base * 2^retry)`.
#[must_use]
pub fn backoff_ceiling(settings: &DrainReserveSettings, retry: u32) -> Duration {
    let factor = 1u32.checked_shl(retry).unwrap_or(u32::MAX);
    settings
        .backoff_base
        .saturating_mul(factor)
        .min(settings.backoff_cap)
}

/// One jittered backoff before retry `retry`: uniform in `[c/2, c]` for
/// [`backoff_ceiling`]'s `c`. Half the ceiling is kept so a retry never fires
/// at once into the conflict it just lost.
#[must_use]
pub fn backoff_delay<R: rand::Rng + ?Sized>(
    settings: &DrainReserveSettings,
    retry: u32,
    rng: &mut R,
) -> Duration {
    let ceiling = backoff_ceiling(settings, retry);
    let floor = ceiling / 2;
    if ceiling <= floor {
        return ceiling;
    }
    rng.random_range(floor..=ceiling)
}

/// The most one promotion can sleep across all its retries: the sum of the
/// ceilings. 75 ms at the defaults (5 + 10 + 20 + 40), and at most
/// `(MAX_DRAIN_RESERVE_ATTEMPTS - 1) * MAX_DRAIN_RESERVE_BACKOFF_MILLIS` (9 s)
/// at the configuration bounds.
#[must_use]
pub fn max_total_backoff(settings: &DrainReserveSettings) -> Duration {
    (0..settings.attempts.saturating_sub(1))
        .map(|retry| backoff_ceiling(settings, retry))
        .fold(Duration::ZERO, Duration::saturating_add)
}

/// Why a gated reserve did not succeed.
#[derive(Debug, PartialEq, Eq)]
pub enum GatedReserve<E> {
    /// The last attempt's own error: not retryable, or the attempts ran out.
    Failed(E),
    /// No permit came free within [`DrainReserveSettings::permit_wait`].
    PermitTimeout,
}

/// One replica's reserve permit pool and retry schedule. Built once per
/// write-behind handle, so the permit count is per replica.
#[derive(Debug)]
pub struct DrainReserveGate {
    settings: DrainReserveSettings,
    permits: Arc<Semaphore>,
}

impl DrainReserveGate {
    /// A gate with `settings.permits` permits; a zero count is raised to 1 so
    /// the gate can never block every attempt forever.
    #[must_use]
    pub fn new(settings: DrainReserveSettings) -> Self {
        let settings = DrainReserveSettings {
            permits: settings.permits.max(1),
            attempts: settings.attempts.max(1),
            ..settings
        };
        Self {
            permits: Arc::new(Semaphore::new(settings.permits)),
            settings,
        }
    }

    #[must_use]
    pub fn settings(&self) -> DrainReserveSettings {
        self.settings
    }

    /// Permits free right now (test and diagnostic seam).
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    /// Run `attempt` under one permit per try, retrying while `retryable`
    /// accepts the error, up to [`DrainReserveSettings::attempts`] tries.
    ///
    /// The permit is held only while one attempt runs. It is dropped before the
    /// backoff sleep, and a permit timeout on any try ends the run.
    pub async fn run<T, E, F, Fut>(
        &self,
        mut attempt: F,
        retryable: impl Fn(&E) -> bool,
    ) -> Result<T, GatedReserve<E>>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let mut retry = 0u32;
        loop {
            let result = {
                let _permit =
                    match tokio::time::timeout(self.settings.permit_wait, self.permits.acquire())
                        .await
                    {
                        Ok(Ok(permit)) => permit,
                        // The semaphore is never closed; a closed one admits nothing,
                        // which is a refusal to wait, not a new failure class.
                        Ok(Err(_)) | Err(_) => return Err(GatedReserve::PermitTimeout),
                    };
                attempt().await
            };
            match result {
                Err(error) if retry + 1 < self.settings.attempts && retryable(&error) => {
                    let delay = backoff_delay(&self.settings, retry, &mut rand::rng());
                    tokio::time::sleep(delay).await;
                    retry += 1;
                }
                other => return other.map_err(GatedReserve::Failed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use rand::SeedableRng;

    use super::*;

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    #[test]
    fn defaults_are_one_permit_five_tries_and_a_5_to_80_ms_schedule() {
        let settings = DrainReserveSettings::default();
        assert_eq!(settings.permits, 1);
        assert_eq!(settings.attempts, 5);
        assert_eq!(settings.permit_wait, ms(1_000));
        let ceilings: Vec<_> = (0..6).map(|n| backoff_ceiling(&settings, n)).collect();
        assert_eq!(ceilings, [ms(5), ms(10), ms(20), ms(40), ms(80), ms(80)]);
        assert_eq!(max_total_backoff(&settings), ms(75));
    }

    #[test]
    fn every_delay_lies_in_half_to_full_ceiling() {
        let settings = DrainReserveSettings::default();
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for retry in 0..40 {
            let ceiling = backoff_ceiling(&settings, retry);
            for _ in 0..200 {
                let delay = backoff_delay(&settings, retry, &mut rng);
                assert!(
                    delay >= ceiling / 2 && delay <= ceiling,
                    "{retry}: {delay:?}"
                );
            }
        }
    }

    #[test]
    fn the_worst_case_total_sleep_is_bounded_at_the_configuration_limits() {
        let settings = DrainReserveSettings {
            attempts: MAX_DRAIN_RESERVE_ATTEMPTS,
            backoff_base: ms(MAX_DRAIN_RESERVE_BACKOFF_MILLIS),
            backoff_cap: ms(MAX_DRAIN_RESERVE_BACKOFF_MILLIS),
            ..DrainReserveSettings::default()
        };
        assert_eq!(max_total_backoff(&settings), ms(9_000));
    }

    #[test]
    fn a_zero_permit_or_attempt_count_is_raised_to_one() {
        let gate = DrainReserveGate::new(DrainReserveSettings {
            permits: 0,
            attempts: 0,
            ..DrainReserveSettings::default()
        });
        assert_eq!(gate.available_permits(), 1);
        assert_eq!(gate.settings().attempts, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn at_most_the_permit_count_runs_at_once_under_a_saturated_fake() {
        // Eight concurrent callers, the drain's slot ceiling, joined on this
        // task so the paused clock governs every sleep.
        for permits in [1usize, 2, 3] {
            let gate = DrainReserveGate::new(DrainReserveSettings {
                permits,
                permit_wait: ms(60_000),
                ..DrainReserveSettings::default()
            });
            let in_flight = AtomicUsize::new(0);
            let peak = AtomicUsize::new(0);
            let caller = || {
                gate.run(
                    || async {
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        tokio::time::sleep(ms(3)).await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        Err::<(), _>("contended")
                    },
                    |_| true,
                )
            };
            let results = tokio::join!(
                caller(),
                caller(),
                caller(),
                caller(),
                caller(),
                caller(),
                caller(),
                caller()
            );
            for result in [
                results.0, results.1, results.2, results.3, results.4, results.5, results.6,
                results.7,
            ] {
                assert_eq!(result, Err(GatedReserve::Failed("contended")));
            }
            assert_eq!(peak.load(Ordering::SeqCst), permits);
            assert_eq!(gate.available_permits(), permits);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_permit_wait_that_elapses_is_a_permit_timeout() {
        let gate = DrainReserveGate::new(DrainReserveSettings {
            permit_wait: ms(50),
            ..DrainReserveSettings::default()
        });
        let held = gate.permits.clone().acquire_owned().await.unwrap();
        let calls = AtomicUsize::new(0);
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
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(held);
        assert_eq!(gate.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_stop_at_the_attempt_count_or_a_non_retryable_error() {
        let gate = DrainReserveGate::new(DrainReserveSettings::default());
        let calls = AtomicUsize::new(0);
        let started = tokio::time::Instant::now();
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
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        let slept = started.elapsed();
        assert!(slept >= ms(75) / 2 && slept <= ms(75), "{slept:?}");

        let calls = AtomicUsize::new(0);
        let result = gate
            .run(
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Err::<(), _>("refused") }
                },
                |error| *error == "contended",
            )
            .await;
        assert_eq!(result, Err(GatedReserve::Failed("refused")));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_permit_is_free_during_the_backoff_sleep() {
        let gate = DrainReserveGate::new(DrainReserveSettings {
            attempts: 2,
            backoff_base: ms(500),
            backoff_cap: ms(500),
            ..DrainReserveSettings::default()
        });
        let calls = AtomicUsize::new(0);
        let (result, free_while_sleeping) = tokio::join!(
            gate.run(
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Err::<(), _>("contended") }
                },
                |_| true,
            ),
            async {
                // The first attempt fails at once; the run then sleeps >= 250 ms.
                tokio::time::sleep(ms(100)).await;
                (calls.load(Ordering::SeqCst), gate.available_permits())
            }
        );
        assert_eq!(free_while_sleeping, (1, 1));
        assert_eq!(result, Err(GatedReserve::Failed("contended")));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn success_returns_the_value_and_releases_the_permit() {
        let gate = DrainReserveGate::new(DrainReserveSettings::default());
        let calls = AtomicUsize::new(0);
        let result = gate
            .run(
                || {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    async move { if n < 2 { Err("contended") } else { Ok(n) } }
                },
                |_| true,
            )
            .await;
        assert_eq!(result, Ok(2));
        assert_eq!(gate.available_permits(), 1);
    }
}
