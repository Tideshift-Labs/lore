// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift), WP-115 K11: stage liveness decision, probe thread
//! and exchange, without Postgres. The Postgres-backed half is
//! `tests/stage_liveness_live.rs`.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use axum::http::StatusCode;
use lore_postgres::domain::fragments::StageLivenessPublication;
use lore_postgres::domain::fragments::StagePeerLiveness;
use lore_postgres::domain::fragments::StagePeerProgress;
use lore_postgres::domain::fragments::StageProgressRecord;
use lore_server::fragment_write_behind::WriteBehindRole;
use lore_server::fragment_write_behind::combined_replica_fault;
use lore_server::http::lb_health::verdict_from;
use lore_server::stage_liveness::*;

const LOCAL: Option<&str> = Some(STAGE_UNAVAILABLE_LOCAL);
const STALE: Duration = Duration::from_secs(15);

fn record(incarnation: &str, progress: i64, progressed_micros: i64) -> StageProgressRecord {
    StageProgressRecord {
        incarnation: incarnation.to_owned(),
        progress,
        progressed_micros,
    }
}

/// A peer view read at database time `clock`, with peers as
/// `(replica, incarnation, count, accepted_at)`.
fn view(clock: i64, peers: &[(&str, &str, i64, i64)]) -> StagePeerLiveness {
    StagePeerLiveness {
        peers: peers
            .iter()
            .map(|(id, incarnation, progress, at)| StagePeerProgress {
                replica_id: (*id).to_owned(),
                record: record(incarnation, *progress, *at),
            })
            .collect(),
        db_clock_micros: clock,
        ..StagePeerLiveness::default()
    }
}

fn liveness(stale_after: Duration, peer_view_max_age: Duration) -> StageLiveness {
    StageLiveness::with_thresholds(
        "replica-a".to_owned(),
        LivenessThresholds {
            stale_after,
            peer_view_max_age,
            ..LivenessThresholds::default()
        },
    )
}

/// Every case of the rule: self fresh/stale x peers unknown (Postgres down or
/// slow) / no progress / a progressing peer.
#[test]
fn decide_ejects_only_a_stale_replica_with_a_progressing_peer() {
    let cases = [
        (false, PeerEvidence::Unknown, None),
        (false, PeerEvidence::NoProgress, None),
        (false, PeerEvidence::ProgressingPeer, None),
        (true, PeerEvidence::Unknown, None),
        (true, PeerEvidence::NoProgress, None),
        (true, PeerEvidence::ProgressingPeer, LOCAL),
    ];
    for (self_stale, peers, expected) in cases {
        assert_eq!(
            decide(self_stale, peers),
            expected,
            "self_stale={self_stale} peers={peers:?}"
        );
    }
}

/// Progress made before this replica went stale is no evidence. A view from
/// before the threshold is never the baseline, so a count that rose before
/// the threshold does not count once the replica is stale.
#[test]
fn a_view_taken_before_self_went_stale_is_never_the_baseline() {
    let state = liveness(STALE, Duration::from_secs(10));
    let start = Instant::now();
    let before = start + STALE - Duration::from_millis(150);
    state.note_peers(before, &view(100, &[("b", "i", 1, 50)]));
    assert_eq!(state.peer_evidence(before), PeerEvidence::Unknown);
    // b's last success (count 2) landed just before the hang.
    let stale = start + STALE + Duration::from_millis(100);
    state.note_peers(stale, &view(200, &[("b", "i", 2, 150)]));
    assert_eq!(state.peer_evidence(stale), PeerEvidence::NoProgress);
    let later = stale + Duration::from_secs(2);
    state.note_peers(later, &view(300, &[("b", "i", 2, 150)]));
    assert_eq!(
        state.fault(later),
        None,
        "no count moved after the baseline: a cell-wide fault"
    );
    // Real progress after the baseline ejects.
    let progress = later + Duration::from_secs(2);
    state.note_peers(progress, &view(400, &[("b", "i", 3, 350)]));
    assert_eq!(state.peer_evidence(progress), PeerEvidence::ProgressingPeer);
    assert_eq!(state.fault(progress), LOCAL);
}

/// A higher count whose increase ran before the baseline view, but committed
/// after it (a delayed commit), proves nothing.
#[test]
fn an_increase_that_ran_before_the_baseline_proves_nothing() {
    let state = liveness(STALE, Duration::from_secs(10));
    let stale = Instant::now() + STALE + Duration::from_secs(1);
    state.note_peers(stale, &view(200, &[("b", "i", 1, 100)]));
    let later = stale + Duration::from_secs(2);
    state.note_peers(later, &view(300, &[("b", "i", 2, 180)]));
    assert_eq!(state.fault(later), None);
    let progress = later + Duration::from_secs(2);
    state.note_peers(progress, &view(400, &[("b", "i", 3, 250)]));
    assert_eq!(state.fault(progress), LOCAL);
}

/// A restarted peer (new incarnation) starts a new baseline. Its count is
/// not compared with the old process's; only progress within the new
/// incarnation counts.
#[test]
fn a_restarted_peer_starts_a_new_baseline() {
    let state = liveness(STALE, Duration::from_secs(10));
    let stale = Instant::now() + STALE + Duration::from_secs(1);
    state.note_peers(stale, &view(200, &[("b", "old", 7, 100)]));
    let restarted = stale + Duration::from_secs(2);
    state.note_peers(restarted, &view(300, &[("b", "new", 1, 250)]));
    assert_eq!(state.fault(restarted), None, "a restart is not progress");
    let progress = restarted + Duration::from_secs(2);
    state.note_peers(progress, &view(400, &[("b", "new", 2, 350)]));
    assert_eq!(
        state.fault(progress),
        LOCAL,
        "progress in the new incarnation counts, though its count is below the old one"
    );
}

/// A withdrawn (draining) peer leaves the baseline. If its row comes back
/// (a delayed write after the delete), it starts from that view.
#[test]
fn a_withdrawn_peer_leaves_the_baseline() {
    let state = liveness(STALE, Duration::from_secs(10));
    let stale = Instant::now() + STALE + Duration::from_secs(1);
    state.note_peers(stale, &view(200, &[("b", "i", 1, 100)]));
    let gone = stale + Duration::from_secs(1);
    state.note_peers(gone, &view(300, &[]));
    assert_eq!(state.peer_evidence(gone), PeerEvidence::NoProgress);
    let back = gone + Duration::from_secs(1);
    state.note_peers(back, &view(400, &[("b", "i", 5, 350)]));
    assert_eq!(state.fault(back), None);
}

/// Several peers: one progressing peer is enough, and the snapshot counts it.
#[test]
fn one_progressing_peer_of_several_is_enough() {
    let state = liveness(STALE, Duration::from_secs(10));
    let stale = Instant::now() + STALE + Duration::from_secs(1);
    state.note_peers(stale, &view(200, &[("b", "i", 1, 100), ("c", "j", 4, 90)]));
    let later = stale + Duration::from_secs(2);
    state.note_peers(later, &view(300, &[("b", "i", 1, 100), ("c", "j", 5, 250)]));
    assert_eq!(state.fault(later), LOCAL);
    let snapshot = state.snapshot(later);
    assert_eq!(snapshot.progressing_peers, Some(1));
    assert_eq!(snapshot.peers, Some(2));
}

/// When the progressing peer stops too (the fault became cell-wide), its last
/// increase leaves the window and the stale replica is readmitted.
#[test]
fn a_peer_that_stops_progressing_stops_ejecting() {
    let state = liveness(STALE, Duration::from_secs(10));
    let stale = Instant::now() + STALE + Duration::from_secs(1);
    let second = 1_000_000;
    state.note_peers(stale, &view(20 * second, &[("b", "i", 1, 19 * second)]));
    let later = stale + Duration::from_secs(2);
    state.note_peers(later, &view(22 * second, &[("b", "i", 2, 21 * second)]));
    assert_eq!(state.fault(later), LOCAL);
    let cell_wide = later + Duration::from_secs(2);
    state.note_peers(cell_wide, &view(30 * second, &[("b", "i", 2, 21 * second)]));
    assert_eq!(state.fault(cell_wide), LOCAL, "still inside the window");
    let gone = cell_wide + Duration::from_secs(2);
    state.note_peers(gone, &view(32 * second, &[("b", "i", 2, 21 * second)]));
    assert_eq!(
        state.fault(gone),
        None,
        "the peer's last increase is older than the window"
    );
}

/// The bounds that make the rule sound. See the module doc.
#[test]
fn the_publish_bounds_sit_inside_the_stale_window() {
    // An accepted increase reports a success at most this long before it
    // ran; it must be shorter than the window, or a cell-wide fault could
    // eject one replica.
    assert!(PUBLISH_FRESH + PUBLISH_DEADLINE < STALE_AFTER);
    // A healthy peer's success is published by its next exchange.
    assert!(PUBLISH_FRESH >= EXCHANGE_INTERVAL + EXCHANGE_TIMEOUT);
    // An increase that runs after its sender gave up changes nothing.
    assert!(PUBLISH_DEADLINE <= EXCHANGE_TIMEOUT);
    assert!(PEER_VIEW_MAX_AGE > EXCHANGE_INTERVAL + EXCHANGE_TIMEOUT);
    assert!(PEER_VIEW_MAX_AGE < STALE_AFTER);
    // A slow but working peer (a 4 s probe every 6 s, published by the next
    // exchange) keeps an increase inside the window.
    assert!(PROGRESS_WINDOW > Duration::from_secs(6) + EXCHANGE_INTERVAL);
    let defaults = LivenessThresholds::default();
    assert_eq!(defaults.statement_timeout, EXCHANGE_TIMEOUT);
    assert_eq!(defaults.publish_deadline, PUBLISH_DEADLINE);
}

/// A row this process did not write is another process with the same id.
/// The check is quiet on the first exchange, on a matching row, and after a
/// failed exchange (which may have written the row anyway).
#[tokio::test]
async fn a_row_this_process_did_not_write_is_a_duplicate_identity() {
    let state = liveness(STALE, Duration::from_secs(10));
    let published =
        |prior: Option<StageProgressRecord>, now: StageProgressRecord| StagePeerLiveness {
            prior,
            published: Some(now),
            ..StagePeerLiveness::default()
        };
    async fn run(state: &StageLiveness, view: Result<StagePeerLiveness, String>) -> bool {
        exchange_once(
            state,
            |_publication| async move { view },
            Duration::from_secs(1),
            &mut None,
        )
        .await
    }
    let mine = |progress| record("me", progress, 0);
    // The log line is the operator's signal; what the test pins is the
    // comparison behind it.
    assert!(run(&state, Ok(published(Some(record("x", 9, 0)), mine(1)))).await);
    assert_eq!(state.duplicate_identity_seen(), None, "first exchange");
    assert!(run(&state, Ok(published(Some(mine(1)), mine(2)))).await);
    assert_eq!(state.duplicate_identity_seen(), None, "matching row");
    assert!(run(&state, Ok(published(Some(record("other", 2, 0)), mine(3)))).await);
    assert_eq!(
        state.duplicate_identity_seen(),
        Some((mine(2), record("other", 2, 0))),
        "a row written by someone else"
    );

    // After a failed exchange the row may hold what that exchange wrote, so
    // the next one does not compare.
    let state = liveness(STALE, Duration::from_secs(10));
    assert!(run(&state, Ok(published(None, mine(1)))).await);
    assert!(!run(&state, Err("connection reset".to_owned())).await);
    assert!(run(&state, Ok(published(Some(mine(5)), mine(6)))).await);
    assert_eq!(state.duplicate_identity_seen(), None, "after a failure");
}

/// The same matrix through the stateful type: the probe age decides
/// self-staleness, the peer view's own age decides whether it counts.
#[test]
fn the_fault_reads_probe_age_and_peer_view_age() {
    let view_max = Duration::from_secs(10);
    let state = liveness(STALE, view_max);
    let start = Instant::now();

    // No peer view at all: Postgres never answered. Even far past stale.
    assert_eq!(state.peer_evidence(start), PeerEvidence::Unknown);
    assert_eq!(state.fault(start + Duration::from_secs(60)), None);

    // Fresh self, progressing peer: no eject.
    state.note_peers(start, &view(100, &[("b", "i", 1, 50)]));
    state.note_peers(start, &view(200, &[("b", "i", 2, 150)]));
    assert_eq!(state.fault(start + Duration::from_secs(1)), None);

    // Stale self (no good probe for 15 s): a baseline, then progress.
    let late = start + Duration::from_secs(16);
    state.note_peers(late, &view(300, &[("b", "i", 3, 250)]));
    assert_eq!(state.peer_evidence(late), PeerEvidence::NoProgress);
    assert_eq!(state.fault(late), None, "one view is only a baseline");
    let later = late + Duration::from_secs(2);
    state.note_peers(later, &view(400, &[("b", "i", 4, 350)]));
    assert_eq!(state.peer_evidence(later), PeerEvidence::ProgressingPeer);
    assert_eq!(state.fault(later), LOCAL);

    // The progressing view has aged out (Postgres went away).
    let after = later + view_max;
    assert_eq!(state.peer_evidence(after), PeerEvidence::Unknown);
    assert_eq!(state.fault(after), None);

    // A new view with more progress ejects again; one good probe brings the
    // replica back at once.
    state.note_peers(after, &view(500, &[("b", "i", 5, 450)]));
    assert_eq!(state.fault(after), LOCAL);
    state.note_good(after);
    assert_eq!(state.fault(after), None);
}

/// A new stale period needs a new baseline: progress measured against the
/// baseline of an earlier stale period does not count.
#[test]
fn a_recovery_ends_the_baseline() {
    let state = liveness(STALE, Duration::from_secs(10));
    let start = Instant::now();
    let stale = start + STALE + Duration::from_secs(1);
    state.note_peers(stale, &view(200, &[("b", "i", 1, 100)]));
    // One own success, then stale again.
    let recovered = stale + Duration::from_secs(1);
    state.note_good(recovered);
    let stale_again = recovered + STALE + Duration::from_secs(1);
    state.note_peers(stale_again, &view(900, &[("b", "i", 9, 800)]));
    assert_eq!(
        state.fault(stale_again),
        None,
        "the first view of a new stale period is only a baseline"
    );
}

/// The threshold is the hysteresis: just under `stale_after` is not stale,
/// so one slow probe does not flap the host.
#[test]
fn a_probe_just_under_the_threshold_does_not_eject() {
    let state = liveness(STALE, Duration::from_secs(10));
    let start = Instant::now();
    let almost = start + STALE - Duration::from_millis(1);
    state.note_peers(almost, &view(100, &[("b", "i", 1, 50)]));
    state.note_peers(almost, &view(200, &[("b", "i", 2, 150)]));
    assert_eq!(state.fault(almost), None);
    let exact = start + STALE;
    state.note_peers(exact, &view(300, &[("b", "i", 3, 250)]));
    state.note_peers(exact, &view(400, &[("b", "i", 4, 350)]));
    assert_eq!(state.fault(exact), LOCAL);
}

/// `note_good` counts every success and never moves the success time back.
#[test]
fn an_older_good_probe_counts_but_does_not_rewind_the_clock() {
    let state = liveness(STALE, Duration::from_secs(10));
    let start = Instant::now();
    state.note_good(start + Duration::from_secs(20));
    state.note_good(start + Duration::from_secs(5));
    assert_eq!(
        state.last_good_age(start + Duration::from_secs(21)),
        Duration::from_secs(1)
    );
    assert_eq!(state.progress(), 2);
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

/// A peer view whose count, and accept time, grow by one on every call.
fn progressing_peer() -> impl Fn() -> StagePeerLiveness {
    let calls = Arc::new(AtomicI64::new(0));
    move || {
        let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
        view(call * 10, &[("b", "i", call, call * 10 - 1)])
    }
}

/// A probe that never returns, as a write on a hung hard mount. The runtime
/// stays responsive, the replica ages to stale and is ejected while a peer
/// makes progress, and exactly one probe thread and one probe ever start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hung_probe_parks_one_thread_and_ages_the_replica_to_stale() {
    let stale_after = Duration::from_millis(300);
    let state = Arc::new(liveness(stale_after, Duration::from_secs(10)));
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
    let peer = progressing_peer();
    let mut warned = None;
    let mut exchanged = 0;
    let started = Instant::now();
    while started.elapsed() < stale_after + Duration::from_millis(200) {
        let next = peer();
        let ok = exchange_once(
            &state,
            |_publication| async { Ok::<_, String>(next) },
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
    assert_eq!(state.progress(), 0, "a parked probe is no progress");

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
    assert_eq!(state.progress(), 1);
}

/// A failed or timed-out exchange records nothing, so the peer view ages to
/// unknown and this signal cannot eject without Postgres.
#[tokio::test(start_paused = true)]
async fn a_failed_or_slow_exchange_leaves_no_peer_view() {
    let state = liveness(STALE, Duration::from_secs(10));
    let mut warned = None;
    let failed = exchange_once(
        &state,
        |_publication| async { Err::<StagePeerLiveness, _>("connection refused") },
        Duration::from_secs(1),
        &mut warned,
    )
    .await;
    assert!(!failed);
    assert_eq!(state.peer_evidence(Instant::now()), PeerEvidence::Unknown);
    assert_eq!(state.publication().clock, None, "no clock anchor either");

    let slow = exchange_once(
        &state,
        |_publication| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<_, String>(view(1, &[]))
        },
        Duration::from_secs(1),
        &mut warned,
    )
    .await;
    assert!(!slow);
    assert_eq!(state.peer_evidence(Instant::now()), PeerEvidence::Unknown);
    assert_eq!(state.publication().clock, None);
}

/// The exchange hands the store this process's incarnation, count and last
/// success instant, and the clock anchor of the last successful exchange.
/// The view is recorded at the instant the exchange started.
#[tokio::test]
async fn the_exchange_publishes_progress_and_the_clock_anchor() {
    let state = liveness(STALE, Duration::from_secs(10));
    let good = Instant::now();
    state.note_good(good);
    state.note_good(good);
    let published = Mutex::new(Vec::new());
    let started = Instant::now();
    for clock in [1_000, 2_000] {
        let ok = exchange_once(
            &state,
            |publication| {
                published.lock().unwrap().push(publication);
                async move {
                    // A slow checkout.
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    Ok::<_, String>(view(clock, &[]))
                }
            },
            Duration::from_secs(1),
            &mut None,
        )
        .await;
        assert!(ok);
    }
    let published = published.lock().unwrap();
    assert_eq!(published[0].incarnation, state.incarnation());
    assert_eq!(published[0].progress, 2);
    assert!(published[0].last_good.saturating_duration_since(good) < Duration::from_millis(1));
    assert_eq!(published[0].clock, None, "no anchor before the first reply");
    let anchor = published[1].clock.expect("the first reply is the anchor");
    assert_eq!(anchor.db_micros, 1_000);
    assert!(anchor.received >= started + Duration::from_millis(300));
    // Keyed by the start, the second view is already about 300 ms old at return.
    let view_age = state
        .snapshot(started + Duration::from_millis(600))
        .peer_view_age_millis
        .expect("a view");
    assert!(
        (280..=320).contains(&view_age),
        "the view is keyed by the exchange's start: {view_age} ms"
    );
    // Incarnations are unique per process instance.
    assert_ne!(
        state.incarnation(),
        liveness(STALE, Duration::from_secs(10)).incarnation()
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
    let state = liveness(STALE, Duration::from_secs(10));
    let exchanges = std::sync::atomic::AtomicUsize::new(0);
    let withdraws = std::sync::atomic::AtomicUsize::new(0);
    let mut withdrawn = false;
    let mut warned = None;
    let exchange = |_publication: StageLivenessPublication| {
        exchanges.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, String>(view(1, &[])) }
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
