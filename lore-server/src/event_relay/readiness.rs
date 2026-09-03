// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Relay and event readiness, kept separate from storage readiness.
//!
//! CR-032 is explicit that broker loss must not make reads or unrelated storage
//! unavailable, so nothing here can reach `/health_check`, which a load
//! balancer uses to decide whether this node serves traffic at all. These
//! facets are reported on their own endpoint and read by whatever decides
//! whether the cell may accept **required-event** mutations.
//!
//! Two facets, from CR-032's "Lag, readiness, and backpressure":
//!
//! * **relay** — false when the loop is not running, or the oldest unpublished
//!   row is older than the configured threshold (30 seconds initially).
//! * **event** — false while any unresolved terminal row sits in the dead-letter
//!   table. That is a correctness incident an operator has to dispose of; it is
//!   not self-healing and must not silently clear.
//!
//! # Fail closed on silence
//!
//! A facet computed from a backlog observation is only as good as the
//! observation. Two states report **not ready** rather than optimistically
//! ready: no observation has been taken yet, and the last observation is older
//! than the staleness bound. The second one is the important one — a loop
//! wedged inside a publish keeps `loop_running` true while its backlog view
//! silently ages, and a readiness signal that cannot tell "healthy" from "not
//! looked at recently" is not a readiness signal.

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use lore_postgres::domain::outbox::OutboxBacklog;

use crate::event_relay::metrics;

/// A point-in-time view of both facets and the evidence behind them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessSnapshot {
    /// Relay facet.
    pub relay_ready: bool,
    /// Event facet.
    pub event_ready: bool,
    /// Whether the worker loop reports itself alive.
    pub loop_running: bool,
    /// Oldest unpublished row age at the last observation, if any.
    pub oldest_unpublished_age: Option<Duration>,
    /// Unpublished rows at the last observation, capped by the store's bounded
    /// probe.
    pub pending_count: i64,
    /// Dead letters awaiting an operator disposition at the last observation.
    pub dead_letter_count: i64,
    /// Age of the last observation itself.
    pub observation_age: Option<Duration>,
    /// Whether that observation is too old to decide on.
    pub stale: bool,
    /// Why the relay facet is false, or `None` when it is true. A fixed,
    /// low-cardinality string.
    pub relay_reason: Option<&'static str>,
}

/// Reasons the relay facet reports false. Fixed strings; never interpolated.
pub const REASON_LOOP_NOT_RUNNING: &str = "loop_not_running";
pub const REASON_NO_OBSERVATION: &str = "no_backlog_observation";
pub const REASON_STALE_OBSERVATION: &str = "stale_backlog_observation";
pub const REASON_OLDEST_UNPUBLISHED: &str = "oldest_unpublished_over_threshold";

#[derive(Debug, Clone)]
struct Observation {
    at: Instant,
    oldest_pending_age: Option<Duration>,
    pending_count: i64,
    dead_letter_count: i64,
}

/// The shared readiness handle. Written by the worker loop, read by the health
/// surface.
#[derive(Debug)]
pub struct EventRelayReadiness {
    loop_running: AtomicBool,
    last: Mutex<Option<Observation>>,
    max_oldest_unpublished: Duration,
    /// Twice the probe interval plus one publish deadline. Precomputed so the
    /// read path does no arithmetic on configuration it does not own.
    staleness_bound: Duration,
}

impl EventRelayReadiness {
    /// Build a handle for a worker configured with these thresholds.
    ///
    /// `publish_deadline` is not a threshold this type reports on; it is the
    /// longest the worker can legitimately be busy between two probes, and the
    /// staleness bound has to clear it. At the shipped defaults a five-second
    /// probe interval alone gives a ten-second bound while one publish may take
    /// ten seconds, so a single slow-but-healthy row would report a lag
    /// incident. Folding the deadline in keeps the bound tight enough to catch
    /// a wedged loop within about twenty seconds while making a busy relay
    /// quiet.
    pub fn new(
        max_oldest_unpublished: Duration,
        probe_interval: Duration,
        publish_deadline: Duration,
    ) -> Self {
        Self {
            loop_running: AtomicBool::new(false),
            last: Mutex::new(None),
            max_oldest_unpublished,
            // Doubling the interval gives one whole missed probe of tolerance,
            // so an ordinary scheduling hiccup is not an incident; the deadline
            // covers the one publish that can be in flight across a probe.
            staleness_bound: probe_interval
                .saturating_mul(2)
                .saturating_add(publish_deadline),
        }
    }

    /// Mark the loop alive or stopped.
    pub fn set_loop_running(&self, running: bool) {
        self.loop_running.store(running, Ordering::Relaxed);
    }

    /// Record a fresh bounded backlog probe.
    pub fn record_backlog(&self, backlog: &OutboxBacklog) {
        metrics::record_backlog(
            backlog
                .oldest_pending_age
                .map(|age| age.as_secs_f64())
                .unwrap_or(0.0),
            backlog.pending_count.max(0) as u64,
            backlog.dead_letter_count.max(0) as u64,
        );
        let observation = Observation {
            at: Instant::now(),
            oldest_pending_age: backlog.oldest_pending_age,
            pending_count: backlog.pending_count,
            dead_letter_count: backlog.dead_letter_count,
        };
        *self.lock() = Some(observation);
    }

    /// Both facets plus the evidence behind them.
    pub fn snapshot(&self) -> ReadinessSnapshot {
        let loop_running = self.loop_running.load(Ordering::Relaxed);
        let observation = self.lock().clone();
        let observation_age = observation.as_ref().map(|o| o.at.elapsed());
        let stale = observation_age.is_some_and(|age| age > self.staleness_bound);

        let relay_reason = if !loop_running {
            Some(REASON_LOOP_NOT_RUNNING)
        } else {
            match observation.as_ref() {
                None => Some(REASON_NO_OBSERVATION),
                Some(_) if stale => Some(REASON_STALE_OBSERVATION),
                Some(o) => o
                    .oldest_pending_age
                    .filter(|age| *age > self.max_oldest_unpublished)
                    .map(|_| REASON_OLDEST_UNPUBLISHED),
            }
        };

        // The event facet deliberately does NOT depend on the loop running. A
        // dead letter is an unresolved correctness incident whether or not this
        // process is currently relaying, and clearing the facet by stopping the
        // worker would be the wrong signal entirely. It does depend on having
        // an observation: with none, there is no evidence the table is empty.
        let dead_letter_count = observation.as_ref().map_or(0, |o| o.dead_letter_count);
        let event_ready = observation.is_some() && !stale && dead_letter_count == 0;

        ReadinessSnapshot {
            relay_ready: relay_reason.is_none(),
            event_ready,
            loop_running,
            oldest_unpublished_age: observation.as_ref().and_then(|o| o.oldest_pending_age),
            pending_count: observation.as_ref().map_or(0, |o| o.pending_count),
            dead_letter_count,
            observation_age,
            stale,
            relay_reason,
        }
    }

    /// The relay facet alone.
    pub fn relay_ready(&self) -> bool {
        self.snapshot().relay_ready
    }

    /// The event facet alone.
    pub fn event_ready(&self) -> bool {
        self.snapshot().event_ready
    }

    /// See `drain::ConnectionRegistry` for the same poisoning rationale: a
    /// panic while holding this lock must not take readiness reporting down
    /// with it, and the guarded value is a plain snapshot with no invariant a
    /// panic could have broken halfway.
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Observation>> {
        match self.last.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backlog(oldest: Option<Duration>, dead_letters: i64) -> OutboxBacklog {
        OutboxBacklog {
            pending_count: 2,
            pending_bytes: 64,
            oldest_pending_age: oldest,
            claimed_count: 0,
            dead_letter_count: dead_letters,
        }
    }

    fn readiness() -> EventRelayReadiness {
        EventRelayReadiness::new(
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_secs(10),
        )
    }

    #[test]
    fn a_fresh_handle_is_not_ready_on_either_facet() {
        let readiness = readiness();
        let snapshot = readiness.snapshot();
        assert!(!snapshot.relay_ready);
        assert!(!snapshot.event_ready);
        assert_eq!(snapshot.relay_reason, Some(REASON_LOOP_NOT_RUNNING));
    }

    #[test]
    fn a_running_loop_with_no_observation_is_still_not_ready() {
        let readiness = readiness();
        readiness.set_loop_running(true);
        let snapshot = readiness.snapshot();
        assert!(!snapshot.relay_ready);
        assert!(!snapshot.event_ready);
        assert_eq!(snapshot.relay_reason, Some(REASON_NO_OBSERVATION));
    }

    #[test]
    fn a_running_loop_with_a_fresh_healthy_observation_is_ready_on_both_facets() {
        let readiness = readiness();
        readiness.set_loop_running(true);
        readiness.record_backlog(&backlog(Some(Duration::from_secs(1)), 0));
        let snapshot = readiness.snapshot();
        assert!(snapshot.relay_ready);
        assert!(snapshot.event_ready);
        assert_eq!(snapshot.relay_reason, None);
        assert_eq!(snapshot.pending_count, 2);
    }

    #[test]
    fn an_empty_backlog_is_ready() {
        let readiness = readiness();
        readiness.set_loop_running(true);
        readiness.record_backlog(&backlog(None, 0));
        assert!(readiness.relay_ready());
    }

    #[test]
    fn an_oldest_unpublished_row_over_the_threshold_fails_the_relay_facet_only() {
        let readiness = readiness();
        readiness.set_loop_running(true);
        readiness.record_backlog(&backlog(Some(Duration::from_secs(31)), 0));
        let snapshot = readiness.snapshot();
        assert!(!snapshot.relay_ready);
        assert_eq!(snapshot.relay_reason, Some(REASON_OLDEST_UNPUBLISHED));
        assert!(
            snapshot.event_ready,
            "lag is a relay incident, not an event-poison incident"
        );
    }

    /// Exactly at the threshold is healthy; CR-032 says "above 30 seconds".
    #[test]
    fn the_threshold_itself_is_still_ready() {
        let readiness = readiness();
        readiness.set_loop_running(true);
        readiness.record_backlog(&backlog(Some(Duration::from_secs(30)), 0));
        assert!(readiness.relay_ready());
    }

    #[test]
    fn an_unresolved_dead_letter_fails_the_event_facet_only() {
        let readiness = readiness();
        readiness.set_loop_running(true);
        readiness.record_backlog(&backlog(Some(Duration::from_secs(1)), 1));
        let snapshot = readiness.snapshot();
        assert!(!snapshot.event_ready);
        assert!(
            snapshot.relay_ready,
            "a parked poison row must not fail the relay facet: the relay is keeping up"
        );
    }

    #[test]
    fn a_stopped_loop_fails_the_relay_facet_even_with_a_healthy_observation() {
        let readiness = readiness();
        readiness.set_loop_running(true);
        readiness.record_backlog(&backlog(Some(Duration::from_secs(1)), 0));
        readiness.set_loop_running(false);
        let snapshot = readiness.snapshot();
        assert!(!snapshot.relay_ready);
        assert_eq!(snapshot.relay_reason, Some(REASON_LOOP_NOT_RUNNING));
    }

    /// The wedged-loop case: `loop_running` is true and the observation is
    /// healthy, but it stopped being refreshed. A zero-length probe interval
    /// makes any elapsed time stale, which is how this is provable without
    /// sleeping.
    #[test]
    fn a_stale_observation_fails_both_facets_even_though_it_looked_healthy() {
        let readiness =
            EventRelayReadiness::new(Duration::from_secs(30), Duration::ZERO, Duration::ZERO);
        readiness.set_loop_running(true);
        readiness.record_backlog(&backlog(Some(Duration::from_secs(1)), 0));
        // Any elapsed time at all is past a zero staleness bound.
        while readiness.snapshot().observation_age == Some(Duration::ZERO) {
            std::hint::spin_loop();
        }
        let snapshot = readiness.snapshot();
        assert!(snapshot.stale);
        assert!(!snapshot.relay_ready);
        assert_eq!(snapshot.relay_reason, Some(REASON_STALE_OBSERVATION));
        assert!(
            !snapshot.event_ready,
            "a stale observation is not evidence the dead-letter table is empty"
        );
    }

    #[test]
    fn every_reason_is_a_bounded_label() {
        for reason in [
            REASON_LOOP_NOT_RUNNING,
            REASON_NO_OBSERVATION,
            REASON_STALE_OBSERVATION,
            REASON_OLDEST_UNPUBLISHED,
        ] {
            assert!(!reason.is_empty());
            assert!(reason.is_ascii());
            assert!(!reason.contains(' '));
        }
    }
}
