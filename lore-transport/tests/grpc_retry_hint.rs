// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// CR-032 client-side retry-hint honouring.
//
// [CLIENT]-class: `lore-transport` is a client-path crate. Every gRPC client verb in this crate
// (admin, domain-operation, environment, lock, revision, repository) routes a RESOURCE_EXHAUSTED
// through `grpc::mod`'s private `handle_error`, so a bug here is felt everywhere, not just on one
// call site. See `lorehub/docs/learnings/a-server-side-backoff-constant-is-only-a-contract-if-the-
// clients-retry-policy-is-pinned-beside-it.md` for why this exists: the server's admission gate
// (CR-032) sends a bounded `google.rpc.RetryInfo` of 10 s and the shipped client never read it,
// so a refused RPC retried for a measured 538 s while re-reading the identical cached verdict.
//
// This file exercises two public seams `grpc::mod` exposes for exactly this:
//   * `retry_delay_hint(&Status) -> Option<Duration>` -- decode the hint, clamped to the client's
//     own 10 s cap, never panicking on malformed bytes.
//   * `wait_with_hint(&mut Retry, Option<Duration>) -> bool` -- wait max(own backoff step, hint),
//     counted as exactly one attempt, with `hint: None` behaving identically to `retry.wait()`.
//
// `lore-transport` must not depend on `lore-server`, so the two frozen wire messages
// (`google.rpc.Status`, `google.rpc.RetryInfo`) are hand-transcribed again here, the same way
// `lore-server/src/event_relay/retry_info.rs` transcribes them on the encode side (see that
// module's doc comment for why: `protoc` is optional in this workspace, and both messages have
// been frozen for over a decade in `google/rpc/status.proto` and `google/rpc/error_details.proto`).
// This is an independent transcription used only to build fixtures here -- it is not linked into
// the production decoder under test, and `the_fixture_encoder_round_trips_through_an_independent_
// decode` below exists so a bug in this file's own encoder can't silently agree with a bug in
// production's decoder just because both were copy-pasted from the same shape.

use std::time::Duration;

use bytes::Bytes;
use prost::Message;
use tonic::Code;
use tonic::Status;

/// `google.rpc.Status`, the payload of the `grpc-status-details-bin` trailer `tonic::Status`
/// stores under `details()`.
#[derive(Clone, PartialEq, Message)]
struct FixtureRpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
    #[prost(message, repeated, tag = "3")]
    details: Vec<prost_types::Any>,
}

/// `google.rpc.RetryInfo`.
#[derive(Clone, PartialEq, Message)]
struct FixtureRetryInfo {
    #[prost(message, optional, tag = "1")]
    retry_delay: Option<prost_types::Duration>,
}

const RETRY_INFO_TYPE_URL: &str = "type.googleapis.com/google.rpc.RetryInfo";
/// An unrelated, real `google.rpc` detail type, used to prove the decoder does not treat "some
/// `Any`" as "the `RetryInfo` `Any`".
const OTHER_TYPE_URL: &str = "type.googleapis.com/google.rpc.DebugInfo";

fn retry_info_any(retry_delay: Option<prost_types::Duration>) -> prost_types::Any {
    let retry_info = FixtureRetryInfo { retry_delay };
    prost_types::Any {
        type_url: RETRY_INFO_TYPE_URL.to_string(),
        value: retry_info.encode_to_vec(),
    }
}

fn status_details_bytes(details: Vec<prost_types::Any>) -> Bytes {
    let status = FixtureRpcStatus {
        code: Code::ResourceExhausted as i32,
        message: "the backlog is too old".to_string(),
        details,
    };
    Bytes::from(status.encode_to_vec())
}

/// A `RESOURCE_EXHAUSTED` status carrying a `RetryInfo` hint of exactly `seconds`/`nanos`.
fn hinted_status(seconds: i64, nanos: i32) -> Status {
    let any = retry_info_any(Some(prost_types::Duration { seconds, nanos }));
    Status::with_details(
        Code::ResourceExhausted,
        "the backlog is too old",
        status_details_bytes(vec![any]),
    )
}

// ---------------------------------------------------------------------------
// retry_delay_hint
// ---------------------------------------------------------------------------

#[test]
fn a_ten_second_hint_decodes_to_ten_seconds() {
    let status = hinted_status(10, 0);
    assert_eq!(
        lore_transport::grpc::retry_delay_hint(&status),
        Some(Duration::from_secs(10))
    );
}

#[test]
fn a_hint_above_the_cap_is_clamped_to_ten_seconds() {
    let status = hinted_status(300, 0);
    assert_eq!(
        lore_transport::grpc::retry_delay_hint(&status),
        Some(Duration::from_secs(10)),
        "a 300s hint must be clamped to RETRY_MAX_BACKOFF_MS, not passed through"
    );
}

#[test]
fn no_details_returns_none() {
    let status = Status::resource_exhausted("no retry info attached");
    assert_eq!(lore_transport::grpc::retry_delay_hint(&status), None);
}

#[test]
fn garbage_or_empty_details_return_none_without_panicking() {
    for details in [
        Bytes::from_static(&[0xFF, 0xFF, 0xFF]),
        Bytes::new(),
        Bytes::from_static(b"not even close to protobuf"),
    ] {
        let status = Status::with_details(Code::ResourceExhausted, "malformed", details.clone());
        assert_eq!(
            lore_transport::grpc::retry_delay_hint(&status),
            None,
            "details {details:?} must decode to no hint, not panic"
        );
    }
}

#[test]
fn a_well_formed_status_carrying_only_another_any_type_returns_none() {
    let other = prost_types::Any {
        type_url: OTHER_TYPE_URL.to_string(),
        value: Vec::new(),
    };
    let status = Status::with_details(
        Code::ResourceExhausted,
        "unrelated detail",
        status_details_bytes(vec![other]),
    );
    assert_eq!(lore_transport::grpc::retry_delay_hint(&status), None);
}

#[test]
fn a_retry_info_with_no_retry_delay_returns_none() {
    let any = retry_info_any(None);
    let status = Status::with_details(
        Code::ResourceExhausted,
        "empty retry info",
        status_details_bytes(vec![any]),
    );
    assert_eq!(lore_transport::grpc::retry_delay_hint(&status), None);
}

#[test]
fn a_negative_retry_delay_returns_none() {
    // Negative seconds and negative nanos are two independent ways to encode a nonsensical
    // delay; both must be rejected rather than producing a negative or garbage `Duration`.
    for (seconds, nanos) in [(-5, 0), (1, -500_000_000)] {
        let status = hinted_status(seconds, nanos);
        assert_eq!(
            lore_transport::grpc::retry_delay_hint(&status),
            None,
            "seconds={seconds} nanos={nanos} must not decode to a hint"
        );
    }
}

/// `google.rpc.Status.details` is a `repeated Any`, so a status carrying two `RetryInfo` entries
/// is a shape the wire format permits even though no encoder in this codebase produces it. The
/// decoder must resolve it deterministically rather than erroring or silently picking whichever
/// one a future refactor of the lookup happens to visit last.
#[test]
fn two_retry_info_entries_use_the_first() {
    let first = retry_info_any(Some(prost_types::Duration {
        seconds: 3,
        nanos: 0,
    }));
    let second = retry_info_any(Some(prost_types::Duration {
        seconds: 9,
        nanos: 0,
    }));
    let status = Status::with_details(
        Code::ResourceExhausted,
        "two retry infos",
        status_details_bytes(vec![first, second]),
    );
    assert_eq!(
        lore_transport::grpc::retry_delay_hint(&status),
        Some(Duration::from_secs(3)),
        "two RetryInfo details must resolve to the first one found, deterministically"
    );
}

/// `google.protobuf.Duration`'s own doc restricts `nanos` to `[-999_999_999, 999_999_999]`, but
/// nothing in the wire format enforces that range. The decoder does not validate it either -- it
/// adds `seconds` and `nanos` independently via `Duration::from_secs(..).saturating_add(..)` --
/// so an out-of-range `nanos` is folded into the total rather than rejected. Pinned so a future
/// range check is a deliberate decision, not an accidental behavior change.
#[test]
fn unnormalized_nanos_at_or_above_one_second_are_added_rather_than_rejected() {
    let status = hinted_status(1, 1_500_000_000);
    assert_eq!(
        lore_transport::grpc::retry_delay_hint(&status),
        Some(Duration::from_millis(2_500))
    );
}

/// Proves this file's own fixture encoder is internally consistent before the tests above trust
/// it as an oracle for production's decoder. Decodes with the same local structs used to encode
/// (not `retry_delay_hint`), so it cannot substitute for the tests above -- it only rules out a
/// bug in the fixture builder itself (wrong nesting, wrong `Any` construction) that could
/// otherwise make every case above pass or fail for the wrong reason.
#[test]
fn the_fixture_encoder_round_trips_through_an_independent_decode() {
    let delay = prost_types::Duration {
        seconds: 7,
        nanos: 250_000_000,
    };
    let encoded = status_details_bytes(vec![retry_info_any(Some(delay))]);

    let status = FixtureRpcStatus::decode(encoded.as_ref()).expect("decodes as google.rpc.Status");
    assert_eq!(status.code, Code::ResourceExhausted as i32);
    assert_eq!(status.details.len(), 1);
    assert_eq!(status.details[0].type_url, RETRY_INFO_TYPE_URL);

    let retry_info =
        FixtureRetryInfo::decode(&status.details[0].value[..]).expect("decodes as RetryInfo");
    assert_eq!(retry_info.retry_delay, Some(delay));
}

// ---------------------------------------------------------------------------
// wait_with_hint
// ---------------------------------------------------------------------------

/// The no-regression pin: with no hint, `wait_with_hint` must behave exactly like calling
/// `retry.wait()` directly. Mirrors `lore-server/tests/outbox_load_proof.rs`'s
/// `measure_the_real_lore_client_resource_exhausted_retry_budget`, which pins this same 60-attempt,
/// 532.75s-539s window against the raw `Retry::wait()` loop.
#[tokio::test(start_paused = true)]
async fn no_hint_keeps_the_unhinted_sixty_attempt_budget_unchanged() {
    let mut retry = lore_transport::util::retry(50, 10_000, 60);
    let started = tokio::time::Instant::now();
    let mut attempts = 0_usize;
    while lore_transport::grpc::wait_with_hint(&mut retry, None).await {
        attempts += 1;
    }
    let total = started.elapsed();

    assert_eq!(attempts, 60);
    assert_eq!(retry.counter(), 60);
    assert!(
        total >= Duration::from_millis(532_750) && total <= Duration::from_secs(539),
        "no-hint total {total:?} is outside the unchanged schedule; wait_with_hint(None) must \
         match retry.wait() exactly"
    );
}

/// A hint that dominates every one of the first eight backoff steps (50/100/200/400/800/1600/
/// 3200/6400 ms, all under the 10s hint) must make each of those eight waits at least 10s, and
/// the full 60-attempt run must still cost exactly 60 attempts -- honouring the hint must not
/// spend extra budget. Window derivation: attempts 1-8 at 10,000ms each = 80s; attempts 9-60 (52
/// of them) have a 10,000ms base step already at the cap, plus up to 100ms jitter each = 520.0s
/// to 525.2s; total 600.0s to 605.2s.
#[tokio::test(start_paused = true)]
async fn a_ten_second_hint_dominates_the_early_short_steps_and_the_total_lands_in_the_derived_window()
 {
    let mut retry = lore_transport::util::retry(50, 10_000, 60);
    let hint = Some(Duration::from_secs(10));
    let started = tokio::time::Instant::now();
    let mut attempts = 0_usize;
    let mut per_attempt = Vec::new();
    let mut last = started;
    while lore_transport::grpc::wait_with_hint(&mut retry, hint).await {
        attempts += 1;
        let now = tokio::time::Instant::now();
        per_attempt.push(now - last);
        last = now;
    }
    let total = started.elapsed();

    assert_eq!(attempts, 60);
    assert_eq!(retry.counter(), 60);
    for (index, step) in per_attempt.iter().take(8).enumerate() {
        assert!(
            *step >= Duration::from_secs(10),
            "attempt {} waited {:?}, expected the 10s hint to dominate its own backoff step",
            index + 1,
            step
        );
    }
    assert!(
        total >= Duration::from_millis(600_000) && total <= Duration::from_millis(605_200),
        "hinted total {total:?} is outside the derived 600.0s-605.2s window"
    );
}

/// The other direction of `max`: a hint SHORTER than a late backoff step must not shorten that
/// step. The hint is a floor a server may raise, never a ceiling it may lower -- without this
/// case, a `min` where the code should compute a `max` would still pass every other test in this
/// file. Drives the retry forward to attempt 20, well past attempt 9 where the base schedule
/// already sits at the 10,000 ms cap, then asks for a 1s hint and asserts the wait stayed at the
/// 10s ceiling rather than being pulled down to it.
#[tokio::test(start_paused = true)]
async fn a_hint_shorter_than_a_capped_late_backoff_step_does_not_shorten_it() {
    let mut retry = lore_transport::util::retry(50, 10_000, 60);
    for attempt in 1..20 {
        assert!(
            retry.wait().await,
            "the retry budget must not exhaust before attempt 20 (failed at {attempt})"
        );
    }

    let started = tokio::time::Instant::now();
    let waited =
        lore_transport::grpc::wait_with_hint(&mut retry, Some(Duration::from_secs(1))).await;
    let elapsed = started.elapsed();

    assert!(waited);
    assert!(
        elapsed >= Duration::from_secs(10),
        "a 1s hint must not shorten an already-capped 10s backoff step: waited {elapsed:?}"
    );
}

/// An already-exhausted retry budget must not sleep the hint before reporting exhaustion --
/// `wait_with_hint` returns whatever `retry.wait()` returned, and a `false` from an exhausted
/// counter must come back promptly.
#[tokio::test(start_paused = true)]
async fn an_already_exhausted_budget_returns_false_without_sleeping_the_hint() {
    let mut retry = lore_transport::util::retry(50, 10_000, 0);
    let started = tokio::time::Instant::now();

    let waited =
        lore_transport::grpc::wait_with_hint(&mut retry, Some(Duration::from_secs(10))).await;

    assert!(!waited);
    assert_eq!(retry.counter(), 0);
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "an exhausted budget must not sleep the 10s hint: elapsed {:?}",
        started.elapsed()
    );
}

// ---------------------------------------------------------------------------
// `RetryBudget` -- the 120s total wall-clock cap over `grpc_retry()`
// ---------------------------------------------------------------------------
//
// `wait_with_hint`/`util::Retry` above are the unbudgeted primitive and stay exactly as they
// were (the two tests above already pin their 532.75s-539s and 600.0s-605.2s windows
// unchanged). `RetryBudget` wraps that primitive with a 120s deadline: before starting any
// wait it computes `max(retry.next_delay_upper_bound(), hint)` and refuses -- returning
// `false` without sleeping -- if starting a wait that long could finish after the deadline.

/// Unhinted worst case through the shipped per-RPC policy (`grpc_retry()`), now capped by the
/// 120s wall-clock budget. Derivation: base steps 50+100+200+400+800+1600+3200+6400 = 12,750 ms
/// over 8 attempts, then 10,000 ms each; 12,750 + 10*10,000 = 112,750 ms after 18 attempts. A
/// 19th attempt needs a 10,100 ms upper bound (10,000 ms base step plus the 100 ms jitter cap),
/// and 112,750 + 10,100 = 122,850 ms > 120,000 ms, so it is refused before ever sleeping.
/// Jitter across the 18 real waits: the first five steps (50/100/200/400/800 ms) are below the
/// 1,000 ms jitter-cap threshold, where `jitter = min((raw * current) as u64, 100)` truncates a
/// real-valued draw strictly below its supremum (`raw` is `rand::random::<f32>() * 0.1`, so
/// `raw * current` is strictly less than 5/10/20/40/80 respectively) -- the achievable integer
/// maximum is one less than each supremum: 4+9+19+39+79 = 150 ms, not the naive 5+10+20+40+80 =
/// 155 ms. The remaining 13 steps (1600/3200/6400 ms, then 10,000 ms x 10) clear the 100 ms cap
/// well before the same truncation matters (`raw` only needs to exceed 100/1600 = 0.0625 of its
/// 0.1 ceiling), so each is capped at exactly 100 ms = 1,300 ms; total at most 1,450 ms. The
/// assertion below still allows up to 114,205 ms rather than the tighter 114,200 ms this implies
/// -- 5 ms of slack, kept for the same paused-clock rounding reason the hinted case's window
/// documents below, and small enough that it cannot mask a real regression.
#[tokio::test(start_paused = true)]
async fn grpc_retry_unhinted_worst_case_is_bounded_by_the_wall_clock_budget() {
    let mut budget = lore_transport::grpc::grpc_retry();
    let started = tokio::time::Instant::now();
    let mut attempts = 0_usize;
    while budget.wait(None).await {
        attempts += 1;
    }
    let total = started.elapsed();

    assert_eq!(
        attempts, 18,
        "expected the budget to refuse the 19th attempt"
    );
    assert_eq!(budget.counter(), 18);
    assert!(
        total >= Duration::from_millis(112_750) && total <= Duration::from_millis(114_205),
        "unhinted budgeted total {total:?} is outside the derived 112.750s-114.205s window"
    );
    assert!(
        total <= Duration::from_secs(120),
        "the wall-clock budget must never be exceeded: {total:?}"
    );
}

/// Hinted worst case (a 10s hint, the value CR-032's admission gate sends) through the shipped
/// policy, still capped at 120s total. The hint is built the same way the tests above build one
/// -- through this file's own fixture encoder, a real `tonic::Status`, and back through
/// `lore_transport::grpc::retry_delay_hint` -- so this is joined on real bytes, not a
/// hand-built `Duration`.
///
/// Derivation: attempts 1-8 have a base step under 10s, so `wait_with_hint`'s
/// `max(step, hint)` resolves to the hint exactly: 8 * 10,000 ms = 80,000 ms, and each of those
/// eight waits is therefore at least 10s (the hint is still honoured within the budget). Attempts
/// 9-11 sit at the 10,000 ms base-step ceiling (already >= the hint) plus up to 100 ms jitter
/// (reachable, not just a supremum: `min` saturates to exactly 100 whenever the raw draw clears
/// 0.01 of its 0.1 ceiling, comfortably likely), so cumulative time after 11 attempts is at most
/// 80,000 + 3*10,100 = 110,300 ms exactly. A 12th attempt needs a 10,100 ms upper bound; even the
/// minimum possible cumulative total (110,000 ms) plus that exceeds the 120,000 ms deadline, so a
/// 12th attempt is always refused.
///
/// The assertion's ceiling is 110,400 ms, not the tight 110,300 ms this derives: paused-clock
/// `Instant` arithmetic can accumulate a tick of rounding across 11 `tokio::time::advance` calls,
/// and an independent re-measurement of this same derivation once read 110.311 s. The 100 ms of
/// slack absorbs that without hiding a real regression -- a genuine defect here (dropping the
/// hint, a different cap, an extra attempt) moves the reading by seconds, not milliseconds, so do
/// not "tidy" this back down to the derived 110,300 ms figure.
#[tokio::test(start_paused = true)]
async fn grpc_retry_hinted_worst_case_is_bounded_by_the_wall_clock_budget() {
    let hint_status = hinted_status(10, 0);
    let hint = lore_transport::grpc::retry_delay_hint(&hint_status);
    assert_eq!(hint, Some(Duration::from_secs(10)));

    let mut budget = lore_transport::grpc::grpc_retry();
    let started = tokio::time::Instant::now();
    let mut attempts = 0_usize;
    let mut per_attempt = Vec::new();
    let mut last = started;
    while budget.wait(hint).await {
        attempts += 1;
        let now = tokio::time::Instant::now();
        per_attempt.push(now - last);
        last = now;
    }
    let total = started.elapsed();

    assert_eq!(
        attempts, 11,
        "expected the budget to refuse the 12th attempt"
    );
    assert_eq!(budget.counter(), 11);
    for (index, step) in per_attempt.iter().take(8).enumerate() {
        assert!(
            *step >= Duration::from_secs(10),
            "attempt {} waited {:?}, expected the 10s hint to dominate within the budget",
            index + 1,
            step
        );
    }
    assert!(
        total >= Duration::from_millis(110_000) && total <= Duration::from_millis(110_400),
        "hinted budgeted total {total:?} is outside the 110.000s-110.400s window (110.300s tight \
         derivation plus 100ms of paused-clock rounding slack -- see the doc comment above)"
    );
    assert!(
        total <= Duration::from_secs(120),
        "the wall-clock budget must never be exceeded: {total:?}"
    );
}

/// A hint longer than the remaining budget must end retrying rather than truncating the wait.
/// Drives a fresh `grpc_retry()` budget until it refuses on its own (the unhinted worst case
/// above: 18 real attempts, leaving only a few seconds of the 120s deadline), then asks for a
/// wait with a 60s hint -- far longer than what remains. The budget must refuse promptly rather
/// than sleeping any part of that hint past its deadline, and refusing must not consume an
/// attempt.
#[tokio::test(start_paused = true)]
async fn a_hint_exceeding_the_remaining_budget_refuses_promptly_without_truncating_the_wait() {
    let mut budget = lore_transport::grpc::grpc_retry();
    while budget.wait(None).await {}
    let attempts_before_refusal = budget.counter();

    let started = tokio::time::Instant::now();
    let waited = budget.wait(Some(Duration::from_secs(60))).await;
    let elapsed = started.elapsed();

    assert!(
        !waited,
        "a hint exceeding the remaining budget must not be honoured by sleeping past the deadline"
    );
    assert_eq!(
        budget.counter(),
        attempts_before_refusal,
        "a refusal must not consume an attempt"
    );
    assert!(
        elapsed < Duration::from_millis(5),
        "a refusal must be prompt, not sleep any part of the hint: {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// `util::Retry::next_delay_upper_bound`
// ---------------------------------------------------------------------------

/// `next_delay_upper_bound` must be a true upper bound on the *next* wait (jitter included), not
/// a state change: calling it twice in a row must return the same value while `counter()` does
/// not move, and it must report `None` once the attempt limit is reached rather than some stale
/// last-known bound.
#[tokio::test(start_paused = true)]
async fn next_delay_upper_bound_is_a_true_upper_bound_and_not_a_state_change() {
    let mut retry = lore_transport::util::retry(50, 10_000, 3);

    let first = retry.next_delay_upper_bound();
    let second = retry.next_delay_upper_bound();
    assert!(
        first.is_some(),
        "an unexhausted Retry must report an upper bound"
    );
    assert_eq!(first, second, "calling it twice must not change the answer");
    assert_eq!(retry.counter(), 0, "calling it must not consume an attempt");

    for attempt in 1..=3 {
        assert!(
            retry.wait().await,
            "the retry budget must not exhaust before attempt {attempt}"
        );
    }
    assert_eq!(retry.counter(), 3);

    assert_eq!(
        retry.next_delay_upper_bound(),
        None,
        "an exhausted Retry must report no upper bound"
    );
    assert_eq!(
        retry.next_delay_upper_bound(),
        None,
        "calling it again on an exhausted Retry must still report no upper bound"
    );
    assert_eq!(
        retry.counter(),
        3,
        "exhaustion checks must not move the counter"
    );
}

// ---------------------------------------------------------------------------
// `handle_error` stays on the budgeted path
// ---------------------------------------------------------------------------

/// `wait_with_hint`/`util::Retry` stay `pub` -- deliberately, so the two no-regression pins above
/// can keep driving the unbudgeted primitive directly. That same reachability means a future
/// `RESOURCE_EXHAUSTED` call site could call `wait_with_hint` instead of `RetryBudget::wait` and
/// silently lose the 120s wall-clock cap: every case above drives one function or the other
/// directly, so none of them would notice a regression in which one `handle_error` itself calls.
///
/// Pinned the way `lore-server/tests/outbox_load_proof.rs`'s
/// `measure_the_real_lore_client_resource_exhausted_retry_budget` pins this same file: read the
/// production source and assert the one line that routes a refused RPC through the budgeted
/// `RetryBudget::wait` rather than the unbudgeted `wait_with_hint`. This proves only that the call
/// site still reads that way in source today -- it is not a substitute for the behavioural cases
/// above, and it does not prove no *other* call site exists. If it ever fails, the right response
/// is to re-measure the budget this file pins against whatever `handle_error` now does, not to
/// update this string to match it.
#[test]
fn handle_error_stays_on_the_budgeted_retry_path() {
    let source = include_str!("../src/grpc/mod.rs");
    assert!(
        source.contains("if !retry.wait(hint).await {"),
        "lore-transport's RESOURCE_EXHAUSTED handler no longer calls RetryBudget::wait(hint) -- \
         if it now calls the unbudgeted wait_with_hint instead, the 120s wall-clock cap this file \
         measures no longer applies to a real RPC. Re-measure the budget this file pins before \
         assuming these numbers still describe production behaviour."
    );
}
