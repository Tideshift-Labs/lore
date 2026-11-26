// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The pure rule of a reconnect's deadline: a bound counts from when the path went silent, not from
//! when the reconnect starts, with a floor of one handshake attempt from now.
//!
//! [CLIENT]-class (`lore-transport`). `reconnect_deadline_from(now, loss, bound)` takes the recorded
//! loss as `(when it was found, whether it was quinn's idle timeout)`. `PathLoss`, which records it,
//! is `pub(crate)` and not reachable from here, so the rule is pinned through the tuple it is
//! built from; the stream reader's recording is covered end to end by `quic_warm_unmanaged_sync` in
//! `lore-integration-tests`.
use std::time::Duration;
use std::time::Instant;

use lore_transport::quic::client::reconnect_deadline_from;

/// Quinn's idle timeout (`IDLE_TIMEOUT_MS`): an idle loss means nothing was heard for this long
/// before it was found.
const IDLE: Duration = Duration::from_secs(30);

/// One handshake attempt (`HANDSHAKE_TIMEOUT_SECS`): the floor from now.
const FLOOR: Duration = Duration::from_secs(5);

const BOUND: Duration = Duration::from_secs(30);

/// An instant `ago` before `now`.
fn before(now: Instant, ago: Duration) -> Instant {
    now.checked_sub(ago)
        .expect("the monotonic clock is older than the test offset")
}

#[test]
fn no_recorded_loss_gives_the_whole_bound_from_now() {
    let now = Instant::now();
    assert_eq!(reconnect_deadline_from(now, None, BOUND), now + BOUND);
    assert_eq!(
        reconnect_deadline_from(now, None, Duration::from_secs(60)),
        now + Duration::from_secs(60)
    );
}

#[test]
fn a_fresh_idle_loss_found_now_leaves_only_the_floor() {
    // Silent since `now - 30 s`, so the 30 s bound is already used up: one handshake remains.
    let now = Instant::now();
    assert_eq!(
        reconnect_deadline_from(now, Some((now, true)), BOUND),
        now + FLOOR
    );
}

#[test]
fn a_fresh_non_idle_loss_counts_from_when_it_was_found() {
    // A close frame: the path was alive until it was found two seconds ago.
    let now = Instant::now();
    let found = before(now, Duration::from_secs(2));
    assert_eq!(
        reconnect_deadline_from(now, Some((found, false)), BOUND),
        found + BOUND
    );
    assert_eq!(found + BOUND, now + Duration::from_secs(28));
}

#[test]
fn a_loss_found_more_than_one_bound_ago_is_stale_and_gets_the_whole_bound() {
    let now = Instant::now();
    let found = before(now, BOUND + Duration::from_secs(1));
    for by_idle in [false, true] {
        assert_eq!(
            reconnect_deadline_from(now, Some((found, by_idle)), BOUND),
            now + BOUND,
            "by_idle={by_idle}"
        );
    }
}

#[test]
fn a_loss_found_exactly_one_bound_ago_is_not_yet_stale() {
    // The boundary: `found == now - bound` still counts, and the floor then applies.
    let now = Instant::now();
    let found = before(now, BOUND);
    assert_eq!(
        reconnect_deadline_from(now, Some((found, false)), BOUND),
        now + FLOOR
    );
}

#[test]
fn an_idle_loss_found_now_with_the_managed_bound_counts_from_thirty_seconds_back() {
    // Managed bound 60 s: silent since `now - 30 s`, so 30 s remain.
    let now = Instant::now();
    let managed = Duration::from_secs(60);
    assert_eq!(
        reconnect_deadline_from(now, Some((now, true)), managed),
        before(now, IDLE) + managed
    );
    assert_eq!(
        reconnect_deadline_from(now, Some((now, true)), managed),
        now + Duration::from_secs(30)
    );
}

#[test]
fn the_floor_wins_when_the_silence_has_used_the_bound() {
    let now = Instant::now();
    // Non-idle, found 28 s ago: `found + bound` is 2 s from now, under the 5 s floor.
    let found = before(now, Duration::from_secs(28));
    assert_eq!(
        reconnect_deadline_from(now, Some((found, false)), BOUND),
        now + FLOOR
    );
    // Idle, found 10 s ago: silent for 40 s, past the whole bound.
    let found = before(now, Duration::from_secs(10));
    assert_eq!(
        reconnect_deadline_from(now, Some((found, true)), BOUND),
        now + FLOOR
    );
}

#[test]
fn the_deadline_is_never_earlier_than_the_floor() {
    let now = Instant::now();
    for found_ago in [0u64, 1, 10, 25, 29, 30, 31, 90] {
        for by_idle in [false, true] {
            for bound in [Duration::from_secs(30), Duration::from_secs(60)] {
                let found = before(now, Duration::from_secs(found_ago));
                let deadline = reconnect_deadline_from(now, Some((found, by_idle)), bound);
                assert!(
                    deadline >= now + FLOOR,
                    "found {found_ago} s ago, idle {by_idle}, bound {bound:?}: under the floor"
                );
                assert!(
                    deadline <= now + bound.max(FLOOR),
                    "found {found_ago} s ago, idle {by_idle}, bound {bound:?}: over a whole bound"
                );
            }
        }
    }
}
