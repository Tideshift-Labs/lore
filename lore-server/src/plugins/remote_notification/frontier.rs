// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The contiguous acknowledgement frontier, and the blockers that stop it.
//!
//! This module is pure: no I/O, no clock, no async. That is deliberate. The
//! contract calls the frontier rule "the single most important frontier rule"
//! — *a later acknowledgement cannot skip an unresolved gap* — and a rule that
//! important should be provable without a broker, a database, or a runtime.
//!
//! # What the frontier means
//!
//! The highest broker sequence at or below which **every** event has been
//! applied, refetched, or acknowledged as a no-op. It is what WP-119's
//! retention reaper advances through, so an overstated frontier deletes a row
//! a receiver never consumed. Every operation here is therefore biased toward
//! understating it.
//!
//! # Why a park never advances the frontier
//!
//! A poisoned event is never acknowledged. Because advancement requires an
//! unbroken run of acknowledged sequences, the park blocks advancement by
//! construction rather than by a rule someone has to remember to apply. The
//! explicit poison list exists so the blocker is *legible* in the projection,
//! not so it can be enforced there.
//!
//! # The starting value
//!
//! A generation captured at start sequence `S` is responsible for `S` onward,
//! so its frontier starts at `S - 1`: everything strictly below `S` is not
//! this generation's business. A capture at `0` saturates to `0`, which is
//! vacuously true because a broker sequence is never `0`.

use std::collections::BTreeSet;

use lore_postgres::domain::outbox::PoisonEntry;
use lore_postgres::domain::outbox::SequenceGap;
use lore_postgres::domain::outbox::schema::MAX_CHECKPOINT_BLOCKERS;

/// Out-of-order acknowledgements tracked before the tracker declares itself
/// saturated.
///
/// A durable stream delivers in sequence order, so the set is normally empty
/// and never larger than the number of parked events. A stream that produced
/// more than this many out-of-order acknowledgements is pathological, and
/// growing an unbounded set to follow it would trade a correctness problem for
/// a memory one.
pub const MAX_TRACKED_OUT_OF_ORDER_ACKS: usize = 65_536;

/// The poison class recorded when the tracker saturates.
pub const POISON_CLASS_TRACKER_SATURATED: &str = "FRONTIER_TRACKER_SATURATED";

/// One receiver generation's frontier and its unresolved blockers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckFrontier {
    /// The highest sequence proved complete.
    frontier: i64,
    /// Acknowledged sequences strictly above `frontier`, waiting for the run
    /// below them to close.
    acked_above: BTreeSet<i64>,
    /// Parked sequences, with the class that parked them. Never acknowledged.
    poison: Vec<(i64, String)>,
    /// The highest sequence this generation has seen at all, acknowledged or
    /// not. Drives the lag figure.
    highest_seen: i64,
    /// Set once the out-of-order set hits its bound.
    saturated: bool,
}

impl AckFrontier {
    /// A fresh frontier for a generation captured at `start_sequence`.
    pub fn starting_at(start_sequence: i64) -> Self {
        Self {
            frontier: start_sequence.saturating_sub(1).max(0),
            acked_above: BTreeSet::new(),
            poison: Vec::new(),
            highest_seen: start_sequence.saturating_sub(1).max(0),
            saturated: false,
        }
    }

    /// Note that a sequence was delivered, whatever became of it.
    pub fn observe(&mut self, broker_sequence: i64) {
        self.highest_seen = self.highest_seen.max(broker_sequence);
    }

    /// Record one acknowledged sequence and close whatever run it completes.
    ///
    /// An acknowledgement at or below the frontier is already covered and is
    /// dropped rather than re-counted, which is what makes a redelivery of an
    /// already-acknowledged sequence a no-op here as well as at the applier.
    pub fn record_ack(&mut self, broker_sequence: i64) {
        self.observe(broker_sequence);
        if broker_sequence <= self.frontier {
            return;
        }
        if self.acked_above.len() >= MAX_TRACKED_OUT_OF_ORDER_ACKS
            && !self.acked_above.contains(&broker_sequence)
        {
            self.saturated = true;
            return;
        }
        self.acked_above.insert(broker_sequence);
        self.advance();
    }

    /// Park one sequence. It is never acknowledged, so it blocks advancement.
    ///
    /// Parking the same sequence twice keeps the first class: a redelivered
    /// poison event must not multiply the blocker list.
    /// The list is bounded at the projection's own cap. Past it the tracker
    /// saturates instead of growing: a stream producing more than this many
    /// distinct unresolved parks has a problem no larger list would describe
    /// better, and the frontier has long since stopped either way.
    pub fn record_poison(&mut self, broker_sequence: i64, class: impl Into<String>) {
        self.observe(broker_sequence);
        if self
            .poison
            .iter()
            .any(|(sequence, _)| *sequence == broker_sequence)
        {
            return;
        }
        if self.poison.len() >= MAX_CHECKPOINT_BLOCKERS {
            self.saturated = true;
            return;
        }
        self.poison.push((broker_sequence, class.into()));
        self.poison.sort_by_key(|(sequence, _)| *sequence);
    }

    /// The highest sequence proved complete.
    pub fn contiguous_frontier(&self) -> i64 {
        self.frontier
    }

    /// The highest sequence seen at all.
    pub fn highest_seen(&self) -> i64 {
        self.highest_seen
    }

    /// How far behind the highest seen sequence the frontier is.
    pub fn lag(&self) -> u64 {
        u64::try_from(self.highest_seen.saturating_sub(self.frontier)).unwrap_or(u64::MAX)
    }

    /// True when a gap, a park, or tracker saturation blocks advancement.
    ///
    /// Reads the same filtered views the projection is built from, so this
    /// answer and the reported blockers can never disagree.
    pub fn has_blockers(&self) -> bool {
        self.saturated
            || self
                .poison
                .iter()
                .any(|(sequence, _)| *sequence > self.frontier)
            || !self.gap_sequences().is_empty()
    }

    /// True once the out-of-order tracker hit its bound. A saturated tracker
    /// can no longer prove contiguity, so it is reported as a blocker.
    pub fn is_saturated(&self) -> bool {
        self.saturated
    }

    /// The unresolved gaps, as ascending non-overlapping ranges strictly above
    /// the frontier.
    ///
    /// Parked sequences are excluded: they are reported as poison, and
    /// reporting one sequence as both would double-count the blocker. The list
    /// is truncated at the projection's own cap; the frontier already carries
    /// the safety property, so a truncated diagnostic cannot make an unsafe
    /// row look safe.
    pub fn gaps(&self) -> Vec<SequenceGap> {
        let mut ranges: Vec<SequenceGap> = Vec::new();
        for sequence in self.gap_sequences() {
            match ranges.last_mut() {
                Some(last) if last.to + 1 == sequence => last.to = sequence,
                _ => ranges.push(SequenceGap {
                    from: sequence,
                    to: sequence,
                }),
            }
            if ranges.len() > MAX_CHECKPOINT_BLOCKERS {
                break;
            }
        }
        ranges.truncate(MAX_CHECKPOINT_BLOCKERS);
        ranges
    }

    /// The unresolved poison dispositions, ascending and truncated at the
    /// projection's cap.
    ///
    /// Filtered to sequences strictly above the frontier, because
    /// `report_checkpoint` refuses a report whose frontier sits at or above
    /// one of its own blockers. A park below the frontier cannot happen while
    /// a parked sequence is never acknowledged — the frontier stops at it by
    /// construction — but the filter makes the report valid by shape rather
    /// than by that argument, so a later change to either side cannot make
    /// every subsequent report of this generation rejected.
    pub fn poison(&self) -> Vec<PoisonEntry> {
        let mut entries: Vec<PoisonEntry> = self
            .poison
            .iter()
            .filter(|(broker_sequence, _)| *broker_sequence > self.frontier)
            .map(|(broker_sequence, class)| PoisonEntry {
                broker_sequence: *broker_sequence,
                class: class.clone(),
            })
            .collect();
        if self.saturated {
            entries.push(PoisonEntry {
                broker_sequence: self.frontier.saturating_add(1),
                class: POISON_CLASS_TRACKER_SATURATED.to_string(),
            });
            entries.sort_by_key(|entry| entry.broker_sequence);
            entries.dedup_by_key(|entry| entry.broker_sequence);
        }
        entries.truncate(MAX_CHECKPOINT_BLOCKERS);
        entries
    }

    /// Every individual sequence above the frontier that is neither
    /// acknowledged nor parked, up to the highest sequence acknowledged out of
    /// order.
    ///
    /// Bounded by the acknowledged set: a sequence that has merely not arrived
    /// yet is not a gap, it is the frontier's next step.
    ///
    /// # Why this walks the acknowledged set rather than the integer range
    ///
    /// The obvious form — count from `frontier + 1` to the highest
    /// acknowledged sequence and test each — costs one iteration per sequence
    /// in that span. One park with a hundred thousand acknowledgements above
    /// it makes that a hundred thousand iterations, and every readiness read
    /// and every checkpoint pays it again. Walking the ordered set instead
    /// costs one iteration per acknowledged entry plus one per sequence
    /// actually missing, and the missing ones are what the result is made of.
    fn gap_sequences(&self) -> Vec<i64> {
        if self.acked_above.is_empty() {
            return Vec::new();
        }
        let cap = MAX_CHECKPOINT_BLOCKERS.saturating_mul(2);
        let mut sequences = Vec::new();
        let mut expected = self.frontier.saturating_add(1);
        for acked in &self.acked_above {
            while expected < *acked {
                if !self.poison.iter().any(|(parked, _)| *parked == expected) {
                    sequences.push(expected);
                    if sequences.len() >= cap {
                        return sequences;
                    }
                }
                expected = expected.saturating_add(1);
            }
            expected = acked.saturating_add(1);
        }
        sequences
    }

    /// Close every run the acknowledged set now completes.
    ///
    /// The loop stops at the first sequence that is not acknowledged, which is
    /// how a parked sequence blocks advancement without a special case: a park
    /// is exactly "never acknowledged".
    fn advance(&mut self) {
        loop {
            let next = self.frontier.saturating_add(1);
            if !self.acked_above.remove(&next) {
                break;
            }
            self.frontier = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
