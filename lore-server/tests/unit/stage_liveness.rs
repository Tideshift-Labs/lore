// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift), WP-115 K11: stage liveness decision, probe thread
//! and exchange, without Postgres. The Postgres-backed half is
//! `tests/stage_liveness_live.rs`.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use axum::http::StatusCode;
use lore_postgres::domain::fragments::StagePeerLiveness;
use lore_server::fragment_write_behind::WriteBehindRole;
use lore_server::fragment_write_behind::combined_replica_fault;
use lore_server::http::lb_health::verdict_from;
use lore_server::stage_liveness::*;

const LOCAL: Option<&str> = Some(STAGE_UNAVAILABLE_LOCAL);

/// A view where every fresh peer also proves a write after this replica's
/// last one.
fn view(fresh_peers: u64, peers: u64) -> StagePeerLiveness {
    StagePeerLiveness {
        fresh_peers,
        proving_peers: fresh_peers,
        peers,
        ..StagePeerLiveness::default()
    }
}

/// Every case of the rule: self fresh/stale x peers unknown (Postgres down or
/// slow) / none fresh / one fresh.
#[test]
fn decide_ejects_only_a_stale_replica_with_a_fresh_peer() {
    let cases = [
        (false, PeerEvidence::Unknown, None),
        (false, PeerEvidence::NoFreshPeer, None),
        (false, PeerEvidence::FreshPeer, None),
        (true, PeerEvidence::Unknown, None),
        (true, PeerEvidence::NoFreshPeer, None),
        (true, PeerEvidence::FreshPeer, LOCAL),
    ];
    for (self_stale, peers, expected) in cases {
        assert_eq!(
            decide(self_stale, peers),
            expected,
            "self_stale={self_stale} peers={peers:?}"
        );
    }
}

fn liveness(stale_after: Duration, peer_view_max_age: Duration) -> StageLiveness {
    StageLiveness::with_thresholds(
        "replica-a".to_owned(),
        stale_after,
        peer_view_max_age,
        PROVE_MARGIN,
    )
}

/// The reviewer's double eject, without Postgres. Just before the threshold
/// the view shows a peer that is fresh and even proves a later write; the
/// replica then goes stale with that view still inside its max age. The view
/// says nothing about after this replica stopped, so it must not eject.
#[test]
fn a_view_taken_before_self_went_stale_is_no_evidence() {
    let stale_after = Duration::from_secs(15);
    let state = liveness(stale_after, Duration::from_secs(10));
    let start = Instant::now();
    let before = start + stale_after - Duration::from_millis(150);
    state.note_peers(before, view(1, 1));
    let stale = start + stale_after + Duration::from_millis(400);
    assert_eq!(state.peer_evidence(stale), PeerEvidence::Unknown);
    assert_eq!(state.fault(stale), None);
    // The next view, taken after self went stale, decides.
    state.note_peers(stale, view(1, 1));
    assert_eq!(state.fault(stale), LOCAL);
}

/// A fresh peer that does not prove a later write is not evidence: in a
/// cell-wide hang every peer is still fresh for a moment.
#[test]
fn a_fresh_peer_without_a_later_write_is_no_evidence() {
    let stale_after = Duration::from_secs(15);
    let state = liveness(stale_after, Duration::from_secs(10));
    let late = Instant::now() + Duration::from_secs(16);
    state.note_peers(
        late,
        StagePeerLiveness {
            fresh_peers: 1,
            proving_peers: 0,
            peers: 1,
            ..StagePeerLiveness::default()
        },
    );
    assert_eq!(state.peer_evidence(late), PeerEvidence::NoFreshPeer);
    assert_eq!(state.fault(late), None);
}

/// The margin covers a cell-wide hang's spread, and still lets a real local
/// fault eject. See `PROVE_MARGIN`'s doc for the terms.
#[test]
fn the_prove_margin_sits_between_the_hang_spread_and_a_local_fault() {
    assert!(PROVE_MARGIN > PROBE_INTERVAL + EXCHANGE_TIMEOUT);
    assert!(STALE_AFTER > PROVE_MARGIN + PROBE_INTERVAL + EXCHANGE_INTERVAL + EXCHANGE_TIMEOUT);
    assert!(PEER_VIEW_MAX_AGE > EXCHANGE_INTERVAL + EXCHANGE_TIMEOUT);
}

/// A row this process did not write is another process with the same id.
/// The check is quiet on the first exchange, on a matching row, and after a
/// failed exchange (which may have written the row anyway).
#[tokio::test]
async fn a_row_this_process_did_not_write_is_a_duplicate_identity() {
    let state = liveness(Duration::from_secs(15), Duration::from_secs(10));
    let published = |prior: Option<i64>, now: i64| StagePeerLiveness {
        prior_last_good_micros: prior,
        published_last_good_micros: Some(now),
        ..StagePeerLiveness::default()
    };
    async fn run(state: &StageLiveness, view: Result<StagePeerLiveness, String>) -> bool {
        exchange_once(
            state,
            |_last_good| async move { view },
            Duration::from_secs(1),
            &mut None,
        )
        .await
    }
    // The log line is the operator's signal; what the test pins is the
    // comparison behind it.
    assert!(run(&state, Ok(published(Some(7), 100))).await);
    assert_eq!(state.duplicate_identity_seen(), None, "first exchange");
    assert!(run(&state, Ok(published(Some(100), 200))).await);
    assert_eq!(state.duplicate_identity_seen(), None, "matching row");
    assert!(run(&state, Ok(published(Some(150), 300))).await);
    assert_eq!(
        state.duplicate_identity_seen(),
        Some((200, 150)),
        "a row written by someone else"
    );

    // After a failed exchange the row may hold what that exchange wrote, so
    // the next one does not compare.
    let state = liveness(Duration::from_secs(15), Duration::from_secs(10));
    assert!(run(&state, Ok(published(None, 100))).await);
    assert!(!run(&state, Err("connection reset".to_owned())).await);
    assert!(run(&state, Ok(published(Some(150), 200))).await);
    assert_eq!(state.duplicate_identity_seen(), None, "after a failure");
}

/// The same matrix through the stateful type: the probe age decides
/// self-staleness, the peer view's own age decides whether it counts.
#[test]
fn the_fault_reads_probe_age_and_peer_view_age() {
    let stale_after = Duration::from_secs(15);
    let view_max = Duration::from_secs(10);
    let state = liveness(stale_after, view_max);
    let start = Instant::now();

    // No peer view at all: Postgres never answered. Even far past stale.
    assert_eq!(state.peer_evidence(start), PeerEvidence::Unknown);
    assert_eq!(state.fault(start + Duration::from_secs(60)), None);

    // Fresh self, fresh peer: no eject.
    state.note_peers(start, view(1, 1));
    assert_eq!(state.fault(start + Duration::from_secs(1)), None);

    // Stale self (no good probe for 15 s), recent view with a fresh peer.
    let late = start + Duration::from_secs(16);
    state.note_peers(late, view(1, 2));
    assert_eq!(state.peer_evidence(late), PeerEvidence::FreshPeer);
    assert_eq!(state.fault(late), LOCAL);

    // Stale self, recent view, no fresh peer: cell-wide, no eject.
    state.note_peers(late, view(0, 2));
    assert_eq!(state.peer_evidence(late), PeerEvidence::NoFreshPeer);
    assert_eq!(state.fault(late), None);

    // Stale self, the fresh-peer view has aged out (Postgres went away).
    state.note_peers(late, view(1, 2));
    let after = late + view_max;
    assert_eq!(state.peer_evidence(after), PeerEvidence::Unknown);
    assert_eq!(state.fault(after), None);

    // One good probe brings the replica back at once.
    state.note_peers(after, view(1, 2));
    assert_eq!(state.fault(after), LOCAL);
    state.note_good(after);
    assert_eq!(state.fault(after), None);
}

/// The threshold is the hysteresis: just under `stale_after` is not stale,
/// so one slow probe does not flap the host.
#[test]
fn a_probe_just_under_the_threshold_does_not_eject() {
    let stale_after = Duration::from_secs(15);
    let state = liveness(stale_after, Duration::from_secs(10));
    let start = Instant::now();
    let almost = start + stale_after - Duration::from_millis(1);
    state.note_peers(almost, view(1, 1));
    assert_eq!(state.fault(almost), None);
    let exact = start + stale_after;
    state.note_peers(exact, view(1, 1));
    assert_eq!(state.fault(exact), LOCAL);
}

/// `note_good` never moves the clock back.
#[test]
fn an_older_good_probe_does_not_rewind_the_clock() {
    let state = liveness(Duration::from_secs(15), Duration::from_secs(10));
    let start = Instant::now();
    state.note_good(start + Duration::from_secs(20));
    state.note_good(start + Duration::from_secs(5));
    assert_eq!(
        state.last_good_age(start + Duration::from_secs(21)),
        Duration::from_secs(1)
    );
}

/// The liveness fault reaches `/lb_health` only on a stage replica, and never
/// overrides a fault that already answers.
#[test]
fn the_combined_fault_is_stage_only_and_never_overrides() {
    assert_eq!(
        combined_replica_fault(WriteBehindRole::Stage, None, LOCAL),
        LOCAL
    );
    assert_eq!(
        combined_replica_fault(WriteBehindRole::Stage, None, None),
        None
    );
    assert_eq!(
        combined_replica_fault(WriteBehindRole::Stage, Some("observer_stopped"), LOCAL),
        Some("observer_stopped")
    );
    assert_eq!(
        combined_replica_fault(WriteBehindRole::Full, None, LOCAL),
        None
    );
    assert_eq!(
        combined_replica_fault(WriteBehindRole::Drain, Some("drain_role"), LOCAL),
        Some("drain_role")
    );
    // And the HTTP verdict maps it to a 503 with the word as the body.
    assert_eq!(
        verdict_from(None, LOCAL),
        (StatusCode::SERVICE_UNAVAILABLE, STAGE_UNAVAILABLE_LOCAL)
    );
}

/// A probe that never returns, as a write on a hung hard mount. The runtime
/// stays responsive, the replica ages to stale and is ejected while a peer is
/// fresh, and exactly one probe thread and one probe ever start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hung_probe_parks_one_thread_and_ages_the_replica_to_stale() {
    let stale_after = Duration::from_millis(300);
    let state = Arc::new(StageLiveness::with_thresholds(
        "replica-hung".to_owned(),
        stale_after,
        Duration::from_secs(10),
        PROVE_MARGIN,
    ));
    let (release, wait) = mpsc::channel::<()>();
    let wait = Mutex::new(wait);
    let entered = Arc::new(AtomicBool::new(false));
    let probe_entered = entered.clone();
    let probe: ProbeFn = Arc::new(move || {
        probe_entered.store(true, Ordering::SeqCst);
        // Blocks until the test releases it, like a hung NFS write.
        let _ = wait
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .recv();
        Ok(())
    });
    let stop = Arc::new(AtomicBool::new(false));
    assert!(
        spawn_probe_thread(
            &state,
            probe.clone(),
            Duration::from_millis(10),
            stop.clone()
        )
        .unwrap()
    );
    // A second start is refused: one thread per replica, ever.
    assert!(!spawn_probe_thread(&state, probe, Duration::from_millis(10), stop.clone()).unwrap());

    let deadline = Instant::now() + Duration::from_secs(5);
    while !entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline, "probe never started");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // The runtime keeps serving: exchanges run while the probe is parked.
    let mut warned = None;
    let mut exchanged = 0;
    let started = Instant::now();
    while started.elapsed() < stale_after + Duration::from_millis(200) {
        let ok = exchange_once(
            &state,
            |_age| async { Ok::<_, String>(view(1, 2)) },
            Duration::from_secs(1),
            &mut warned,
        )
        .await;
        assert!(ok);
        exchanged += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(exchanged > 5, "the runtime must stay responsive");

    let now = Instant::now();
    assert_eq!(state.fault(now), LOCAL);
    assert!(state.snapshot(now).probe_in_flight);
    assert_eq!(state.threads_started(), 1);
    assert_eq!(
        state.probes_started(),
        1,
        "no second probe while one is parked"
    );

    // Release the hung write: the probe succeeds and the replica returns.
    stop.store(true, Ordering::SeqCst);
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while state.fault(Instant::now()).is_some() {
        assert!(
            Instant::now() < deadline,
            "a good probe must clear the fault"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// A failed or timed-out exchange records nothing, so the peer view ages to
/// unknown and this signal cannot eject without Postgres.
#[tokio::test(start_paused = true)]
async fn a_failed_or_slow_exchange_leaves_no_peer_view() {
    let state = liveness(Duration::from_secs(15), Duration::from_secs(10));
    let mut warned = None;
    let failed = exchange_once(
        &state,
        |_age| async { Err::<StagePeerLiveness, _>("connection refused") },
        Duration::from_secs(1),
        &mut warned,
    )
    .await;
    assert!(!failed);
    assert_eq!(state.peer_evidence(Instant::now()), PeerEvidence::Unknown);

    let slow = exchange_once(
        &state,
        |_age| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<_, String>(view(1, 1))
        },
        Duration::from_secs(1),
        &mut warned,
    )
    .await;
    assert!(!slow);
    assert_eq!(state.peer_evidence(Instant::now()), PeerEvidence::Unknown);
}

/// The exchange hands the store the instant of the last good probe, so the
/// store measures the age after its checkout, and the view is recorded at
/// the instant the exchange started, not when it returned.
#[tokio::test]
async fn the_exchange_publishes_the_last_good_probe_instant() {
    let state = liveness(Duration::from_secs(15), Duration::from_secs(10));
    let good = Instant::now();
    state.note_good(good);
    let published = Mutex::new(None);
    let started = Instant::now();
    let ok = exchange_once(
        &state,
        |last_good| {
            *published.lock().unwrap() = Some(last_good);
            async {
                // A slow checkout.
                tokio::time::sleep(Duration::from_millis(900)).await;
                Ok::<_, String>(view(0, 0))
            }
        },
        Duration::from_secs(1),
        &mut None,
    )
    .await;
    assert!(ok);
    let last_good = published.lock().unwrap().expect("published");
    assert!(
        last_good.saturating_duration_since(good) < Duration::from_millis(1),
        "the instant, not an age measured before the checkout"
    );
    // Keyed by the start, the view is already about 900 ms old at return.
    let view_age = state
        .snapshot(started + Duration::from_millis(850))
        .peer_view_age_millis
        .expect("a view");
    assert!(
        view_age >= 840,
        "the view is keyed by the exchange's start: {view_age} ms"
    );
}

/// The real probe writes, fsyncs and removes its file, leaves nothing behind,
/// and recreates its directory when it is gone.
#[test]
fn the_file_probe_leaves_nothing_and_heals_its_directory() {
    let root = tempfile::tempdir().unwrap();
    let probe = file_probe(root.path().to_path_buf(), "replica-a");
    probe().unwrap();
    let directory = root.path().join("liveness");
    assert!(directory.is_dir());
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
    std::fs::remove_dir(&directory).unwrap();
    probe().unwrap();
    assert!(directory.is_dir());
}

/// A probe against a root that does not exist fails rather than reporting
/// success.
#[test]
fn the_file_probe_fails_on_a_missing_root() {
    let root = tempfile::tempdir().unwrap();
    let probe = file_probe(root.path().join("absent"), "replica-a");
    assert!(probe().is_err());
}

#[test]
fn replica_ids_are_file_safe_and_bounded() {
    assert_eq!(sanitize_replica_id("web-1/42"), "web-1_42");
    assert_eq!(sanitize_replica_id(""), "replica");
    assert_eq!(sanitize_replica_id(".."), "replica");
    assert_eq!(sanitize_replica_id(&"x".repeat(500)).len(), 128);
    let id = default_replica_id();
    assert!(!id.is_empty() && id.len() <= 128);
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
        "{id}"
    );
}

/// A draining replica never publishes again: it withdraws its row once, and
/// a failed withdraw is retried on the next tick.
#[tokio::test]
async fn a_draining_replica_withdraws_once_and_never_publishes() {
    let state = liveness(Duration::from_secs(15), Duration::from_secs(10));
    let exchanges = std::sync::atomic::AtomicUsize::new(0);
    let withdraws = std::sync::atomic::AtomicUsize::new(0);
    let mut withdrawn = false;
    let mut warned = None;
    let exchange = |_last_good: Instant| {
        exchanges.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, String>(view(1, 1)) }
    };
    let ok_withdraw = || {
        withdraws.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, String>(true) }
    };
    let timeout = Duration::from_secs(1);

    // Serving: exchanges, never withdraws.
    let tick = liveness_tick(
        &state,
        false,
        &mut withdrawn,
        exchange,
        ok_withdraw,
        timeout,
        &mut warned,
    )
    .await;
    assert_eq!(tick, LivenessTick::Exchanged);
    assert_eq!(
        (
            exchanges.load(Ordering::SeqCst),
            withdraws.load(Ordering::SeqCst)
        ),
        (1, 0)
    );

    // Draining, the delete fails: no publish, retried next tick.
    let failing_withdraw = || {
        withdraws.fetch_add(1, Ordering::SeqCst);
        async { Err::<bool, _>("connection refused".to_owned()) }
    };
    let tick = liveness_tick(
        &state,
        true,
        &mut withdrawn,
        exchange,
        failing_withdraw,
        timeout,
        &mut warned,
    )
    .await;
    assert_eq!(tick, LivenessTick::WithdrawFailed);
    assert!(!withdrawn);

    // Draining: withdraws, and never publishes.
    let tick = liveness_tick(
        &state,
        true,
        &mut withdrawn,
        exchange,
        ok_withdraw,
        timeout,
        &mut warned,
    )
    .await;
    assert_eq!(tick, LivenessTick::Withdrew);
    assert!(withdrawn);
    let tick = liveness_tick(
        &state,
        true,
        &mut withdrawn,
        exchange,
        ok_withdraw,
        timeout,
        &mut warned,
    )
    .await;
    assert_eq!(tick, LivenessTick::Withdrawn);
    assert_eq!(
        (
            exchanges.load(Ordering::SeqCst),
            withdraws.load(Ordering::SeqCst)
        ),
        (1, 2),
        "a draining replica must never publish again, and withdraws once it succeeds"
    );
}
