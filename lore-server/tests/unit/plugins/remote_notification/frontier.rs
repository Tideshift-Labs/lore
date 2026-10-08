// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_postgres::domain::outbox::PoisonEntry;
use lore_postgres::domain::outbox::SequenceGap;
use lore_postgres::domain::outbox::schema::MAX_CHECKPOINT_BLOCKERS;
use lore_server::plugins::remote_notification::frontier::*;

#[test]
fn a_fresh_frontier_sits_one_below_the_captured_start() {
    let frontier = AckFrontier::starting_at(900);
    assert_eq!(frontier.contiguous_frontier(), 899);
    assert!(!frontier.has_blockers());
    assert_eq!(frontier.lag(), 0);
}

/// A broker sequence is never zero, so a capture at zero has nothing below
/// it and saturating to zero is vacuously true.
#[test]
fn a_capture_at_zero_saturates_rather_than_going_negative() {
    assert_eq!(AckFrontier::starting_at(0).contiguous_frontier(), 0);
}

#[test]
fn in_order_acknowledgements_advance_the_frontier() {
    let mut frontier = AckFrontier::starting_at(900);
    for sequence in 900..=905 {
        frontier.record_ack(sequence);
    }
    assert_eq!(frontier.contiguous_frontier(), 905);
    assert!(!frontier.has_blockers());
}

/// The contract's named case: acknowledgements at 900..=916 and 919..=930
/// with 917..=918 unresolved must report 916, never 930.
#[test]
fn an_acknowledgement_above_a_gap_does_not_advance_the_frontier() {
    let mut frontier = AckFrontier::starting_at(900);
    for sequence in 900..=916 {
        frontier.record_ack(sequence);
    }
    for sequence in 919..=930 {
        frontier.record_ack(sequence);
    }
    assert_eq!(
        frontier.contiguous_frontier(),
        916,
        "a later acknowledgement must never skip an unresolved gap"
    );
    assert_eq!(frontier.gaps(), vec![SequenceGap { from: 917, to: 918 }]);
    assert!(frontier.has_blockers());
}

#[test]
fn resolving_the_gap_closes_the_whole_run_at_once() {
    let mut frontier = AckFrontier::starting_at(900);
    for sequence in 900..=916 {
        frontier.record_ack(sequence);
    }
    for sequence in 919..=930 {
        frontier.record_ack(sequence);
    }
    frontier.record_ack(918);
    assert_eq!(frontier.contiguous_frontier(), 916);
    frontier.record_ack(917);
    assert_eq!(frontier.contiguous_frontier(), 930);
    assert!(!frontier.has_blockers());
}

/// The contract's `unresolved-poison-blocks-advancement` case: frontier
/// 916 with a park at 917, even though later sequences acknowledged.
#[test]
fn an_unresolved_park_blocks_advancement_and_is_reported_as_poison() {
    let mut frontier = AckFrontier::starting_at(900);
    for sequence in 900..=916 {
        frontier.record_ack(sequence);
    }
    frontier.record_poison(917, "UNSUPPORTED_SCHEMA");
    for sequence in 918..=930 {
        frontier.record_ack(sequence);
    }
    assert_eq!(frontier.contiguous_frontier(), 916);
    assert_eq!(
        frontier.poison(),
        vec![PoisonEntry {
            broker_sequence: 917,
            class: "UNSUPPORTED_SCHEMA".to_string(),
        }]
    );
    assert!(
        frontier.gaps().is_empty(),
        "a parked sequence is reported as poison, never also as a gap"
    );
    assert!(frontier.has_blockers());
}

#[test]
fn a_redelivered_park_does_not_multiply_the_blocker() {
    let mut frontier = AckFrontier::starting_at(900);
    frontier.record_poison(917, "UNSUPPORTED_SCHEMA");
    frontier.record_poison(917, "SCOPE_MISMATCH");
    assert_eq!(frontier.poison().len(), 1);
    assert_eq!(frontier.poison()[0].class, "UNSUPPORTED_SCHEMA");
}

#[test]
fn an_acknowledgement_at_or_below_the_frontier_is_a_no_op() {
    let mut frontier = AckFrontier::starting_at(900);
    frontier.record_ack(900);
    frontier.record_ack(900);
    frontier.record_ack(850);
    assert_eq!(frontier.contiguous_frontier(), 900);
    assert!(!frontier.has_blockers());
}

#[test]
fn lag_is_the_distance_from_the_highest_seen_sequence() {
    let mut frontier = AckFrontier::starting_at(900);
    frontier.record_ack(900);
    frontier.observe(950);
    assert_eq!(frontier.lag(), 50);
}

/// A park with a long run of acknowledgements above it reports one park
/// and no gaps, and does so without walking the whole span.
#[test]
fn a_park_under_a_long_acknowledged_run_reports_one_blocker() {
    let mut frontier = AckFrontier::starting_at(900);
    frontier.record_poison(900, "UNSUPPORTED_SCHEMA");
    for sequence in 901..=50_000 {
        frontier.record_ack(sequence);
    }
    assert_eq!(frontier.contiguous_frontier(), 899);
    assert!(frontier.gaps().is_empty());
    assert_eq!(frontier.poison().len(), 1);
    assert_eq!(frontier.poison()[0].broker_sequence, 900);
    assert_eq!(frontier.lag(), 49_101);
}

/// The poison list is bounded at the projection's cap; past it the tracker
/// saturates rather than growing without bound.
#[test]
fn a_park_flood_saturates_instead_of_growing_the_list() {
    let mut frontier = AckFrontier::starting_at(1);
    for sequence in 1..=(MAX_CHECKPOINT_BLOCKERS as i64 + 50) {
        frontier.record_poison(sequence, "UNSUPPORTED_SCHEMA");
    }
    assert!(frontier.is_saturated());
    assert!(frontier.has_blockers());
    assert!(frontier.poison().len() <= MAX_CHECKPOINT_BLOCKERS);
    assert_eq!(
        frontier.contiguous_frontier(),
        0,
        "nothing was acknowledged, so nothing advanced"
    );
}

/// Every blocker the projection sees must be strictly above the frontier,
/// because `report_checkpoint` refuses a report that violates that.
#[test]
fn every_reported_blocker_sits_strictly_above_the_frontier() {
    let mut frontier = AckFrontier::starting_at(900);
    for sequence in 900..=916 {
        frontier.record_ack(sequence);
    }
    frontier.record_poison(917, "UNSUPPORTED_SCHEMA");
    frontier.record_ack(920);
    let reported = frontier.contiguous_frontier();
    for gap in frontier.gaps() {
        assert!(gap.from > reported);
        assert!(gap.to >= gap.from);
    }
    for entry in frontier.poison() {
        assert!(entry.broker_sequence > reported);
    }
}
