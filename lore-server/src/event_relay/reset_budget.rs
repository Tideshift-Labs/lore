// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! A per-emitter diagnostic budget for rejected stream reset reports
//! (WP-119 Phase 8).
//!
//! WP-110 reports a detected broker reset with bounded retry. A *correct*
//! emitter therefore sends a small number of reports and stops. An emitter that
//! is misconfigured, is chasing a detection this cell will never accept, or is
//! probing, sends the same rejection forever — and every one of those costs a
//! `warn!` line carrying its principal. That is the shape of an incident that
//! fills a cell's log budget with one caller's mistake, and buries the
//! diagnostics for everything else.
//!
//! # What this does NOT do
//!
//! **It never changes a verdict.** An emitter over its budget receives exactly
//! the same `tonic::Status`, derived from exactly the same checks, in exactly
//! the same order, as one under it. Nothing here mutates correctness state, skips
//! a check, short-circuits the database, or delays a response.
//!
//! That restraint is deliberate rather than conservative. The obvious stronger
//! design — refuse an over-budget caller before the durable lookup — would save
//! a pool connection per rejection, and would also break the one case this
//! service exists for: an emitter whose earlier reports were rejected, that has
//! since been corrected, retrying the *now-valid* report. Its budget is
//! exhausted precisely because it was previously wrong, and refusing it would
//! turn a fixed misconfiguration into a permanent one. A reset report installs
//! the fence that stops a cell publishing into a void epoch; it is not
//! something to drop to save a log line.
//!
//! So what is rate-limited is the **diagnostics**, and the signal an operator
//! gets instead of a flood is a counter plus one structured line at the moment
//! an emitter crosses into quarantine.
//!
//! # Bounds
//!
//! The map holds at most [`MAX_TRACKED_EMITTERS`] entries and only ever gains
//! one for an emitter that has been *rejected*, so a healthy cell's map is
//! empty. At the cap the least-recently-charged entry is evicted, which is the
//! entry least likely to still be flooding.
//!
//! Eviction is a real, accepted weakness: a caller that could present many
//! distinct principals could churn a genuine offender's bucket out and regain
//! its full budget. Reaching this service at all requires an internal-service
//! mTLS identity that maps to this cell, so the set of principals is bounded by
//! what the deployment issued rather than by what a caller can invent. The cap
//! exists so that assumption failing costs bounded memory rather than unbounded.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

/// Rejections one emitter may have logged in full before it is quarantined.
///
/// Eight: enough to cover WP-110's whole bounded retry of one genuinely
/// rejected report, so a single real misconfiguration is still fully visible in
/// the log, and small enough that a stuck emitter is quiet within a minute.
pub const REJECTION_BUDGET: u32 = 8;

/// How long one token takes to come back.
///
/// A minute. An emitter that has been corrected earns its diagnostics back on
/// roughly the timescale an operator watching a log would look again, and a
/// permanently stuck one is granted one line a minute rather than one per
/// retry.
pub const REJECTION_REFILL_INTERVAL: Duration = Duration::from_secs(60);

/// Emitters tracked at once. See the module documentation's bounds section.
pub const MAX_TRACKED_EMITTERS: usize = 256;

/// The bucket key used when a report failed authentication, and so has no
/// principal at all.
///
/// One shared bucket rather than one per connection: an unauthenticated caller
/// has no stable identity to key on, and keying on something it controls (a
/// peer address, a presented certificate) would be exactly the unbounded
/// cardinality this module exists to bound.
pub const UNAUTHENTICATED_KEY: &str = "\u{0}unauthenticated";

/// What to do with one rejection's diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// Inside budget. Log it in full.
    Report,
    /// This charge crossed the emitter into quarantine. Log **this one** in
    /// full, saying so — it is the line that tells an operator why the rest are
    /// missing.
    Quarantining,
    /// Already quarantined. Count it; do not log it at `warn`.
    Quarantined,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Whole tokens remaining. Fractional refill is carried in `refilled_at`
    /// rather than as a float, so a stream of sub-interval charges cannot
    /// accumulate rounding into a free token.
    tokens: u32,
    /// The instant `tokens` was last correct for.
    refilled_at: Instant,
    /// Last time this emitter was charged, for eviction ordering.
    last_charged: Instant,
    /// Whether this emitter is currently quarantined, so the transition is
    /// reported once rather than on every charge after it.
    quarantined: bool,
}

/// The per-emitter budget for one cell's reset service.
#[derive(Debug)]
pub struct ReportBudget {
    budget: u32,
    refill_interval: Duration,
    max_tracked: usize,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl Default for ReportBudget {
    fn default() -> Self {
        Self::new(
            REJECTION_BUDGET,
            REJECTION_REFILL_INTERVAL,
            MAX_TRACKED_EMITTERS,
        )
    }
}

impl ReportBudget {
    /// Build a budget with explicit bounds.
    ///
    /// Public so a test can drive the refill without sleeping for a minute; the
    /// service itself always uses [`Default`].
    pub fn new(budget: u32, refill_interval: Duration, max_tracked: usize) -> Self {
        Self {
            // A zero budget would quarantine every emitter on its first
            // rejection, hiding the one line that explains an incident. A zero
            // refill interval would divide by zero below. Both are caller bugs
            // rather than configuration, so they are corrected rather than
            // refused: this type must never be the reason a reset is not served.
            budget: budget.max(1),
            refill_interval: refill_interval.max(Duration::from_millis(1)),
            max_tracked: max_tracked.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Charge one rejection against `principal` and say how loudly to report it.
    ///
    /// `now` is passed in rather than taken here so the refill is testable
    /// without sleeping.
    pub fn charge(&self, principal: &str, now: Instant) -> Charge {
        let mut buckets = self.lock();

        if !buckets.contains_key(principal) && buckets.len() >= self.max_tracked {
            evict_oldest(&mut buckets);
        }

        let bucket = buckets.entry(principal.to_owned()).or_insert(Bucket {
            tokens: self.budget,
            refilled_at: now,
            last_charged: now,
            quarantined: false,
        });
        bucket.last_charged = now;

        // Refill whole intervals only, and advance `refilled_at` by exactly the
        // intervals granted rather than to `now`. Advancing to `now` would
        // discard the remainder every time and, under charges arriving faster
        // than the interval, would starve the refill entirely.
        let elapsed = now.saturating_duration_since(bucket.refilled_at);
        let earned = (elapsed.as_nanos() / self.refill_interval.as_nanos().max(1)) as u64;
        if earned > 0 {
            let earned_u32 = u32::try_from(earned).unwrap_or(u32::MAX);
            bucket.tokens = bucket.tokens.saturating_add(earned_u32).min(self.budget);
            bucket.refilled_at += self
                .refill_interval
                .saturating_mul(u32::try_from(earned).unwrap_or(u32::MAX));
        }

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            bucket.quarantined = false;
            return Charge::Report;
        }
        if bucket.quarantined {
            Charge::Quarantined
        } else {
            bucket.quarantined = true;
            Charge::Quarantining
        }
    }

    /// Forget an emitter's budget after it succeeds.
    ///
    /// An accepted or replayed report is proof the emitter is working, so its
    /// next genuine failure deserves a full log rather than whatever remained of
    /// a budget spent while it was broken. It also keeps the map empty on a
    /// healthy cell, which is what makes the cap unreachable in normal
    /// operation.
    pub fn forgive(&self, principal: &str) {
        self.lock().remove(principal);
    }

    /// How many emitters are currently tracked. Diagnostics and tests only.
    pub fn tracked(&self) -> usize {
        self.lock().len()
    }

    /// Same poisoning rationale as `readiness`: a panic while holding this lock
    /// must not take the reset service down with it, and the guarded value is a
    /// diagnostic budget with no invariant a panic could have broken halfway.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Bucket>> {
        match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Drop the least-recently-charged entry.
///
/// Linear over a map bounded at [`MAX_TRACKED_EMITTERS`], and reached only on
/// the rejection path of a full map — so the cost is bounded and paid only in
/// the situation it exists for.
fn evict_oldest(buckets: &mut HashMap<String, Bucket>) {
    let Some(oldest) = buckets
        .iter()
        .min_by_key(|(_, bucket)| bucket.last_charged)
        .map(|(key, _)| key.clone())
    else {
        return;
    };
    buckets.remove(&oldest);
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
