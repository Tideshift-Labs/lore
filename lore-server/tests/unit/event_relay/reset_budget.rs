// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::time::Duration;
use std::time::Instant;

use lore_server::event_relay::reset_budget::*;

fn budget() -> ReportBudget {
    ReportBudget::new(3, Duration::from_secs(60), 4)
}

#[test]
fn the_first_charges_are_reported_and_the_next_is_the_transition() {
    let budget = budget();
    let now = Instant::now();
    assert_eq!(budget.charge("a", now), Charge::Report);
    assert_eq!(budget.charge("a", now), Charge::Report);
    assert_eq!(budget.charge("a", now), Charge::Report);
    assert_eq!(
        budget.charge("a", now),
        Charge::Quarantining,
        "the transition is announced exactly once"
    );
    assert_eq!(budget.charge("a", now), Charge::Quarantined);
    assert_eq!(budget.charge("a", now), Charge::Quarantined);
}

/// One emitter's flood must not spend another's budget. This is the whole
/// point of keying per principal rather than counting globally.
#[test]
fn one_emitters_flood_does_not_quarantine_another() {
    let budget = budget();
    let now = Instant::now();
    for _ in 0..10 {
        budget.charge("noisy", now);
    }
    assert_eq!(budget.charge("quiet", now), Charge::Report);
}

#[test]
fn a_token_comes_back_after_the_refill_interval() {
    let budget = budget();
    let start = Instant::now();
    for _ in 0..4 {
        budget.charge("a", start);
    }
    assert_eq!(budget.charge("a", start), Charge::Quarantined);
    let later = start + Duration::from_secs(60);
    assert_eq!(
        budget.charge("a", later),
        Charge::Report,
        "one interval must return exactly one token"
    );
    assert_eq!(
        budget.charge("a", later),
        Charge::Quarantining,
        "and only one; the emitter falls back into quarantine immediately"
    );
}

/// The refill must not be starved by charges arriving faster than the
/// interval. Advancing `refilled_at` to `now` on every charge would discard
/// the remainder each time and never grant a token; advancing it by whole
/// intervals earned does not.
#[test]
fn frequent_charges_do_not_starve_the_refill() {
    let budget = budget();
    let start = Instant::now();
    for _ in 0..4 {
        budget.charge("a", start);
    }
    // Ten charges spread across one interval, none of them a whole one.
    let mut granted = 0;
    for step in 1..=10_u32 {
        let at = start + Duration::from_secs(6) * step;
        if budget.charge("a", at) == Charge::Report {
            granted += 1;
        }
    }
    assert_eq!(
        granted, 1,
        "exactly one whole interval elapsed, so exactly one token was earned"
    );
}

#[test]
fn the_refill_never_exceeds_the_budget() {
    let budget = budget();
    let start = Instant::now();
    for _ in 0..4 {
        budget.charge("a", start);
    }
    // A very long idle period must return the cap, not the elapsed count.
    let much_later = start + Duration::from_secs(60 * 60 * 24);
    let mut reported = 0;
    for step in 0..10 {
        if budget.charge("a", much_later + Duration::from_millis(step)) == Charge::Report {
            reported += 1;
        }
    }
    assert_eq!(reported, 3, "the cap is the configured budget");
}

#[test]
fn the_map_is_bounded_and_evicts_the_least_recently_charged() {
    let budget = budget();
    let start = Instant::now();
    for (step, principal) in ["a", "b", "c", "d"].into_iter().enumerate() {
        budget.charge(principal, start + Duration::from_secs(step as u64));
    }
    assert_eq!(budget.tracked(), 4);
    budget.charge("e", start + Duration::from_secs(10));
    assert_eq!(budget.tracked(), 4, "the cap holds");
    // "a" was charged first and never again, so it is the one evicted: it
    // gets a full budget back on its next charge.
    assert_eq!(
        budget.charge("a", start + Duration::from_secs(11)),
        Charge::Report
    );
}

/// A success clears the emitter, so its next failure is fully logged.
#[test]
fn forgiving_an_emitter_restores_its_whole_budget() {
    let budget = budget();
    let now = Instant::now();
    for _ in 0..5 {
        budget.charge("a", now);
    }
    assert_eq!(budget.charge("a", now), Charge::Quarantined);
    budget.forgive("a");
    assert_eq!(budget.tracked(), 0);
    assert_eq!(budget.charge("a", now), Charge::Report);
}

/// Degenerate bounds are corrected rather than refused: this type must never
/// be the reason a reset report is not served.
#[test]
fn degenerate_bounds_are_corrected() {
    let budget = ReportBudget::new(0, Duration::ZERO, 0);
    let now = Instant::now();
    assert_eq!(
        budget.charge("a", now),
        Charge::Report,
        "a zero budget must still log the first rejection"
    );
}
