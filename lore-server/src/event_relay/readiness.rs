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
//! Three facets, from CR-032's "Lag, readiness, and backpressure":
//!
//! * **relay** — false when the loop is not running, or the oldest unpublished
//!   row is older than the configured threshold (30 seconds initially).
//! * **event** — false while any unresolved terminal row sits in the dead-letter
//!   table. That is a correctness incident an operator has to dispose of; it is
//!   not self-healing and must not silently clear.
//! * **receiver** — false while the `consumer_safe` evaluator cannot prove a
//!   verdict: a reset fence, an empty or unready required membership, a missing
//!   checkpoint, or no observation at all. Separate from the relay facet
//!   because a cell can be publishing perfectly while no consumer is safe, and
//!   from storage readiness because broker loss must never make reads
//!   unavailable.
//!
//! # The two receiver facets are different questions
//!
//! `receiver_ready` above is the **cell's** question: can any consumer be
//! declared safe, from the `consumer_safe` evaluator's view of the whole
//! required membership. `durable_receiver_ready` is **this process's** question:
//! is the durable invalidation receiver running in this loreserver caught up
//! inside its own lag threshold with no unresolved blocker. A cell can answer
//! the first while this process's receiver is bootstrapping, and this process's
//! receiver can be perfectly ready while the cell's required set is not
//! satisfied, so the two are reported side by side rather than merged.
//!
//! The durable facet is `None` — absent, not false — on a cell that runs no
//! receiver, because "no receiver is configured here" and "the receiver is
//! behind" are different states and a reader that cannot tell them apart is
//! exactly what this endpoint exists to avoid.
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

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use lore_postgres::domain::outbox::OutboxBacklog;

use crate::event_relay::metrics;
use crate::plugins::remote_notification::ReceiverReadiness;

/// A point-in-time view of all three facets and the evidence behind them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessSnapshot {
    /// Relay facet.
    pub relay_ready: bool,
    /// Event facet.
    pub event_ready: bool,
    /// Receiver facet.
    pub receiver_ready: bool,
    /// Required receiver generations the last proven evaluation covered.
    pub required_receivers: usize,
    /// Age of the last receiver observation, if any.
    pub receiver_observation_age: Option<Duration>,
    /// Why the receiver facet is false, or `None` when it is true. A fixed,
    /// low-cardinality string.
    pub receiver_reason: Option<&'static str>,
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
    /// This process's own durable-receiver facet, or `None` when this
    /// loreserver runs no receiver.
    pub durable_receiver_ready: Option<bool>,
    /// Why that facet is false, from the receiver's own closed reason set.
    pub durable_receiver_reason: Option<&'static str>,
    /// Distance from the receiver's contiguous frontier to the highest
    /// sequence it has seen. Zero when no receiver runs.
    pub durable_receiver_lag: u64,
    /// The membership generation the receiver is running, once it has one.
    pub durable_receiver_generation: Option<i64>,
}

/// Reasons the relay facet reports false. Fixed strings; never interpolated.
pub const REASON_LOOP_NOT_RUNNING: &str = "loop_not_running";
pub const REASON_NO_OBSERVATION: &str = "no_backlog_observation";
pub const REASON_STALE_OBSERVATION: &str = "stale_backlog_observation";
pub const REASON_OLDEST_UNPUBLISHED: &str = "oldest_unpublished_over_threshold";
/// The receiver facet has no evaluation to report on yet.
pub const REASON_NO_EVALUATION: &str = "no_consumer_safety_evaluation";
/// The last evaluation is older than the staleness bound, so the facet cannot
/// tell healthy from not-looked-at-recently.
pub const REASON_STALE_EVALUATION: &str = "stale_consumer_safety_evaluation";

#[derive(Debug, Clone)]
struct Observation {
    at: Instant,
    oldest_pending_age: Option<Duration>,
    pending_count: i64,
    dead_letter_count: i64,
}

/// The last thing the `consumer_safe` evaluator proved, or the reason it could
/// not.
#[derive(Debug, Clone)]
struct ReceiverObservation {
    at: Instant,
    /// The evaluator's own block label, or `None` when it proved a verdict.
    ///
    /// Carried as the label rather than the typed block so this module does not
    /// depend on the evaluator's variant set: the mapping already exists in one
    /// place, and duplicating it here would be a second place to forget.
    block: Option<&'static str>,
    required_receivers: usize,
}

/// The shared readiness handle. Written by the worker loop, read by the health
/// surface.
#[derive(Debug)]
pub struct EventRelayReadiness {
    loop_running: AtomicBool,
    last: Mutex<Option<Observation>>,
    last_receiver: Mutex<Option<ReceiverObservation>>,
    /// This process's own durable receiver, attached once by server
    /// construction when the cell declares one.
    ///
    /// A handle rather than a value because the receiver moves between
    /// generations, and each new generation writes through the same handle; a
    /// snapshot copied in at wiring time would report the bootstrap forever.
    durable_receiver: OnceLock<Arc<ReceiverReadiness>>,
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
            last_receiver: Mutex::new(None),
            durable_receiver: OnceLock::new(),
            max_oldest_unpublished,
            // Doubling the interval gives one whole missed probe of tolerance,
            // so an ordinary scheduling hiccup is not an incident; the deadline
            // covers the one publish that can be in flight across a probe.
            staleness_bound: probe_interval
                .saturating_mul(2)
                .saturating_add(publish_deadline),
        }
    }

    /// Attach this process's durable-receiver facet.
    ///
    /// Once only, and a second attach is an error rather than a replacement:
    /// two receivers over one cell in one process would mean two facets and a
    /// coin flip over which one this surface reported.
    ///
    /// # Errors
    /// Returns the rejected handle when one is already attached.
    pub fn attach_durable_receiver(
        &self,
        receiver: Arc<ReceiverReadiness>,
    ) -> Result<(), Arc<ReceiverReadiness>> {
        self.durable_receiver.set(receiver)
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

    /// Record an evaluation that proved a verdict over `required_receivers`
    /// generations.
    pub fn record_receiver_proof(&self, required_receivers: usize) {
        metrics::record_receiver_lag_rows(0);
        *self.lock_receiver() = Some(ReceiverObservation {
            at: Instant::now(),
            block: None,
            required_receivers,
        });
    }

    /// Record an evaluation that proved nothing, and why.
    ///
    /// `reason` must come from the evaluator's closed label set; it is reported
    /// verbatim as the facet's reason and as a metric label.
    pub fn record_receiver_block(&self, reason: &'static str) {
        *self.lock_receiver() = Some(ReceiverObservation {
            at: Instant::now(),
            block: Some(reason),
            required_receivers: 0,
        });
    }

    /// All three facets plus the evidence behind them.
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

        // The receiver facet, on the same fail-closed-on-silence rule. Its
        // staleness bound is the shared one: the evaluator runs on the same
        // probe interval as the backlog observation, so an evaluator that
        // wedged or whose database went away stops refreshing this and the
        // facet goes false rather than staying green on an old verdict.
        let receiver = self.lock_receiver().clone();
        let receiver_observation_age = receiver.as_ref().map(|o| o.at.elapsed());
        let receiver_stale = receiver_observation_age.is_some_and(|age| age > self.staleness_bound);
        let receiver_reason = match receiver.as_ref() {
            None => Some(REASON_NO_EVALUATION),
            Some(_) if receiver_stale => Some(REASON_STALE_EVALUATION),
            Some(observation) => observation.block,
        };

        // This process's own receiver, read live through its handle. No
        // staleness rule applies: the receiver writes its facet on every step
        // and on every blocked boundary, so there is no observation to age.
        let durable = self.durable_receiver.get().map(|handle| handle.snapshot());

        ReadinessSnapshot {
            relay_ready: relay_reason.is_none(),
            event_ready,
            receiver_ready: receiver_reason.is_none(),
            required_receivers: receiver.as_ref().map_or(0, |o| o.required_receivers),
            receiver_observation_age,
            receiver_reason,
            loop_running,
            oldest_unpublished_age: observation.as_ref().and_then(|o| o.oldest_pending_age),
            pending_count: observation.as_ref().map_or(0, |o| o.pending_count),
            dead_letter_count,
            observation_age,
            stale,
            relay_reason,
            durable_receiver_ready: durable.as_ref().map(|snapshot| snapshot.ready),
            durable_receiver_reason: durable.as_ref().and_then(|snapshot| snapshot.reason),
            durable_receiver_lag: durable.as_ref().map_or(0, |snapshot| snapshot.lag),
            durable_receiver_generation: durable.as_ref().and_then(|snapshot| snapshot.generation),
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

    /// The receiver facet alone.
    pub fn receiver_ready(&self) -> bool {
        self.snapshot().receiver_ready
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

    /// Same poisoning rationale as [`Self::lock`].
    fn lock_receiver(&self) -> std::sync::MutexGuard<'_, Option<ReceiverObservation>> {
        match self.last_receiver.lock() {
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

    /// A fresh handle has no evaluation, so the receiver facet is false. Zero
    /// evidence is never readiness.
    #[test]
    fn a_fresh_handle_is_not_receiver_ready() {
        let snapshot = readiness().snapshot();
        assert!(!snapshot.receiver_ready);
        assert_eq!(snapshot.receiver_reason, Some(REASON_NO_EVALUATION));
        assert_eq!(snapshot.required_receivers, 0);
    }

    #[test]
    fn a_proven_evaluation_makes_the_receiver_facet_ready() {
        let readiness = readiness();
        readiness.record_receiver_proof(2);
        let snapshot = readiness.snapshot();
        assert!(snapshot.receiver_ready);
        assert_eq!(snapshot.receiver_reason, None);
        assert_eq!(snapshot.required_receivers, 2);
    }

    /// A reset fence fails the receiver facet and nothing else. The relay is
    /// still publishing and storage is untouched.
    #[test]
    fn a_reset_fence_fails_the_receiver_facet_only() {
        let readiness = readiness();
        readiness.set_loop_running(true);
        readiness.record_backlog(&backlog(Some(Duration::from_secs(1)), 0));
        readiness.record_receiver_block("reset_in_progress");
        let snapshot = readiness.snapshot();
        assert!(!snapshot.receiver_ready);
        assert_eq!(snapshot.receiver_reason, Some("reset_in_progress"));
        assert!(snapshot.relay_ready);
        assert!(snapshot.event_ready);
    }

    /// The wedged-evaluator case: a verdict was proven once and then stopped
    /// being refreshed. Staleness is not readiness.
    #[test]
    fn a_stale_evaluation_fails_the_receiver_facet() {
        let readiness =
            EventRelayReadiness::new(Duration::from_secs(30), Duration::ZERO, Duration::ZERO);
        readiness.record_receiver_proof(2);
        while readiness.snapshot().receiver_observation_age == Some(Duration::ZERO) {
            std::hint::spin_loop();
        }
        let snapshot = readiness.snapshot();
        assert!(!snapshot.receiver_ready);
        assert_eq!(snapshot.receiver_reason, Some(REASON_STALE_EVALUATION));
    }

    /// A later proof clears an earlier block; the facet is the last evaluation,
    /// not a latch. A dead letter is a latch and this deliberately is not: the
    /// blocks it reports are all self-healing conditions.
    #[test]
    fn a_later_proof_clears_an_earlier_block() {
        let readiness = readiness();
        readiness.record_receiver_block("empty_required_membership");
        assert!(!readiness.receiver_ready());
        readiness.record_receiver_proof(1);
        assert!(readiness.receiver_ready());
    }

    #[test]
    fn every_reason_is_a_bounded_label() {
        for reason in [
            REASON_LOOP_NOT_RUNNING,
            REASON_NO_OBSERVATION,
            REASON_STALE_OBSERVATION,
            REASON_OLDEST_UNPUBLISHED,
            REASON_NO_EVALUATION,
            REASON_STALE_EVALUATION,
        ] {
            assert!(!reason.is_empty());
            assert!(reason.is_ascii());
            assert!(!reason.contains(' '));
        }
    }

    // -- this process's own durable receiver -------------------------------

    /// Absent, not false. A cell that runs no receiver and a cell whose
    /// receiver is behind are different states, and collapsing them would make
    /// the facet unreadable.
    #[test]
    fn the_durable_receiver_facet_is_absent_until_one_is_attached() {
        let snapshot = readiness().snapshot();
        assert_eq!(snapshot.durable_receiver_ready, None);
        assert_eq!(snapshot.durable_receiver_reason, None);
        assert_eq!(snapshot.durable_receiver_generation, None);
    }

    /// An attached receiver that has not started reports FALSE with its own
    /// reason, which is the fail-closed initial state the handle ships with.
    #[test]
    fn an_attached_receiver_reports_its_own_not_started_state() {
        let readiness = readiness();
        readiness
            .attach_durable_receiver(Arc::new(ReceiverReadiness::new()))
            .expect("the first attach must be accepted");
        let snapshot = readiness.snapshot();
        assert_eq!(snapshot.durable_receiver_ready, Some(false));
        assert_eq!(
            snapshot.durable_receiver_reason,
            Some(crate::plugins::remote_notification::receiver::REASON_NOT_STARTED)
        );
    }

    /// The relay facet is untouched by the receiver's. A receiver that has not
    /// started must not make a caught-up relay report itself behind.
    #[test]
    fn the_durable_receiver_facet_does_not_move_the_relay_or_event_facets() {
        let readiness = readiness();
        readiness.set_loop_running(true);
        readiness.record_backlog(&backlog(Some(Duration::from_secs(1)), 0));
        readiness
            .attach_durable_receiver(Arc::new(ReceiverReadiness::new()))
            .expect("the first attach must be accepted");
        let snapshot = readiness.snapshot();
        assert!(snapshot.relay_ready);
        assert!(snapshot.event_ready);
        assert_eq!(snapshot.durable_receiver_ready, Some(false));
    }

    #[test]
    fn a_second_durable_receiver_attach_is_refused_rather_than_replacing_the_first() {
        let readiness = readiness();
        readiness
            .attach_durable_receiver(Arc::new(ReceiverReadiness::new()))
            .expect("the first attach must be accepted");
        assert!(
            readiness
                .attach_durable_receiver(Arc::new(ReceiverReadiness::new()))
                .is_err(),
            "two receivers over one cell in one process would mean two facets and a coin flip \
             over which one this surface reported"
        );
    }
}
