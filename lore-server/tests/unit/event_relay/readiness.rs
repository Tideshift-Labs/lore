// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::time::Duration;

use lore_postgres::domain::outbox::OutboxBacklog;
use lore_server::event_relay::readiness::*;
use lore_server::plugins::remote_notification::ReceiverReadiness;

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
        Some(lore_server::plugins::remote_notification::receiver::REASON_NOT_STARTED)
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
