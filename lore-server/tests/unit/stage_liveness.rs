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
use lore_postgres::domain::fragments::StageLivenessRole;
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
                ..StagePeerProgress::default()
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

// ---------------------------------------------------------------------------
// WP-115 K11 guard: the shared-stage check.
// ---------------------------------------------------------------------------

const GRACE: Duration = Duration::from_millis(200);

fn guarded(id: &str) -> StageLiveness {
    StageLiveness::with_thresholds(
        id.to_owned(),
        LivenessThresholds {
            share_grace: GRACE,
            ..LivenessThresholds::default()
        },
    )
    .with_share_guard()
}

fn drain_worker(id: &str) -> StageLiveness {
    StageLiveness::with_thresholds(id.to_owned(), LivenessThresholds::default())
        .with_role(StageLivenessRole::Drain)
}

/// A view at database time `clock` with stage peers as
/// `(replica, incarnation, published)`.
fn share_view(clock: i64, peers: &[(&str, &str, i64)]) -> StagePeerLiveness {
    StagePeerLiveness {
        peers: peers
            .iter()
            .map(|(id, incarnation, published)| StagePeerProgress {
                replica_id: (*id).to_owned(),
                record: record(incarnation, 1, 0),
                published_micros: *published,
                role: StageLivenessRole::Stage,
            })
            .collect(),
        db_clock_micros: clock,
        ..StagePeerLiveness::default()
    }
}

/// `view` plus drain rows `(replica, incarnation, published, role)`.
fn with_drains(
    mut view: StagePeerLiveness,
    drains: &[(&str, &str, i64, StageLivenessRole)],
) -> StagePeerLiveness {
    for (id, incarnation, published, role) in drains {
        view.peers.push(StagePeerProgress {
            replica_id: (*id).to_owned(),
            record: record(incarnation, 0, 0),
            published_micros: *published,
            role: *role,
        });
    }
    view
}

fn gate_held(replica: &StageLiveness) -> bool {
    replica.share_gate().load(Ordering::Acquire)
}

/// The gate the stage reads and the verdict the gauge reads must agree:
/// staging is off exactly when the verdict holds staging.
fn assert_gate_agrees(replica: &StageLiveness, now: Instant) {
    assert_eq!(
        gate_held(replica),
        replica.share_verdict(now).holds_staging(),
        "gate and verdict disagree at {:?}",
        replica.share_verdict(now)
    );
}

/// Every verdict but `Shared` keeps staging off; only `Unverified`,
/// `NotShared` and `PendingTooLong` answer 503; every word is distinct.
#[test]
fn every_share_verdict_but_shared_keeps_staging_off() {
    for verdict in ShareVerdict::ALL {
        assert_eq!(
            verdict.holds_staging(),
            verdict != ShareVerdict::Shared,
            "{verdict:?}"
        );
    }
    let faults: Vec<_> = ShareVerdict::ALL
        .iter()
        .map(|verdict| (verdict.name(), verdict.fault()))
        .collect();
    assert_eq!(
        faults,
        vec![
            ("pending", None),
            ("pending_too_long", Some(STAGE_SHARE_PENDING)),
            ("no_anchor", None),
            ("unverified", Some(STAGE_SHARE_UNVERIFIED)),
            ("not_shared", Some(STAGE_NOT_SHARED)),
            ("undecided", None),
            ("shared", None),
        ]
    );
}

/// A stage directory where `id`'s marker cannot be read: a directory sits at
/// the marker path, so the read fails with an I/O error (Windows refuses the
/// open, Linux the read), not with "not found".
fn unreadable_marker_stage(id: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(
        root.path()
            .join("liveness")
            .join(format!("{id}{SHARE_MARKER_SUFFIX}")),
    )
    .unwrap();
    assert!(
        ShareMarkers::new(root.path()).read(id).is_err(),
        "control: the marker read fails with an I/O error"
    );
    root
}

/// Review probe RV3-B, unit half. A marker read that fails with an I/O error
/// is "cannot decide": 200, staging off, word `undecided`, for longer than
/// the grace. A later completed read without the marker decides again (503).
#[test]
fn a_marker_read_error_is_undecided_and_answers_200() {
    let broken = unreadable_marker_stage("drain-1");
    let markers = ShareMarkers::new(broken.path());
    let b = guarded("web-b");
    let clock = 9_000_000;
    let now = Instant::now();
    let drains = with_drains(
        share_view(clock, &[]),
        &[("drain-1", "inc-d", clock, StageLivenessRole::Drain)],
    );
    b.note_share(now, &drains);
    b.share_step(&markers).unwrap();
    for at in [now, now + GRACE * 3] {
        assert_eq!(b.share_verdict(at), ShareVerdict::Undecided);
        assert_eq!(b.fault(at), None, "cannot decide is 200");
        assert!(gate_held(&b), "staging stays off");
        assert_gate_agrees(&b, at);
    }
    assert_eq!(b.snapshot(now).share, Some("undecided"));
    assert_eq!(
        b.snapshot(now).share_unconfirmed,
        vec!["drain-1".to_owned()]
    );

    // The fault clears and the directory reads without the marker: decided.
    std::fs::remove_dir(broken.path().join("liveness").join("drain-1.present")).unwrap();
    b.share_step(&markers).unwrap();
    assert_eq!(b.share_verdict(now), ShareVerdict::Unverified);
    assert_eq!(b.fault(now), Some(STAGE_SHARE_UNVERIFIED));
    assert_eq!(b.fault(now + GRACE), Some(STAGE_NOT_SHARED));
}

/// One unreadable drain marker does not hide a second fresh drain whose
/// marker a completed read did not find: that one still counts toward 503.
#[test]
fn a_readable_missing_marker_still_answers_503_beside_an_unreadable_one() {
    let root = unreadable_marker_stage("drain-1");
    let markers = ShareMarkers::new(root.path());
    let b = guarded("web-b");
    let clock = 9_000_000;
    let now = Instant::now();
    b.note_share(
        now,
        &with_drains(
            share_view(clock, &[]),
            &[
                ("drain-1", "inc-1", clock, StageLivenessRole::Drain),
                ("drain-2", "inc-2", clock, StageLivenessRole::Drain),
            ],
        ),
    );
    b.share_step(&markers).unwrap();
    assert_eq!(b.share_verdict(now), ShareVerdict::Unverified);
    assert_eq!(b.fault(now), Some(STAGE_SHARE_UNVERIFIED));
    assert!(gate_held(&b));
}

/// A probe-thread step that hangs (an NFS hard mount whose server is gone)
/// never completes a marker read. After `marker_stuck_after` the check is
/// "cannot decide": 200, staging off. When the step finishes and reads the
/// directory without the marker, it decides again.
#[test]
fn a_hung_probe_step_is_undecided_and_answers_200() {
    let root = tempfile::tempdir().unwrap();
    let stuck_after = Duration::from_millis(150);
    let b = Arc::new(
        StageLiveness::with_thresholds(
            "web-b".to_owned(),
            LivenessThresholds {
                share_grace: GRACE,
                marker_stuck_after: stuck_after,
                ..LivenessThresholds::default()
            },
        )
        .with_share_guard(),
    );
    let clock = 9_000_000;
    b.note_share(
        Instant::now(),
        &with_drains(
            share_view(clock, &[]),
            &[("drain-1", "inc-d", clock, StageLivenessRole::Drain)],
        ),
    );
    assert_eq!(
        b.fault(Instant::now()),
        Some(STAGE_SHARE_UNVERIFIED),
        "control: the start-up 503 before any marker step (RV3-C)"
    );
    let (release, hold) = mpsc::channel::<()>();
    let hold = Mutex::new(hold);
    let entered = Arc::new(AtomicBool::new(false));
    let probe: ProbeFn = {
        let entered = entered.clone();
        Arc::new(move || {
            entered.store(true, Ordering::SeqCst);
            let _ = hold.lock().unwrap().recv();
            Ok(())
        })
    };
    let stop = Arc::new(AtomicBool::new(false));
    assert!(
        spawn_probe_thread_with_markers(
            &b,
            probe,
            Some(ShareMarkers::new(root.path())),
            Duration::from_millis(20),
            stop.clone(),
        )
        .unwrap()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline, "the probe thread must start");
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(stuck_after + Duration::from_millis(50));
    let now = Instant::now();
    assert!(b.step_stuck(now));
    assert_eq!(b.share_verdict(now), ShareVerdict::Undecided);
    assert_eq!(b.fault(now), None, "a hung step is 200");
    assert!(gate_held(&b));
    assert_gate_agrees(&b, now);

    // The mount comes back: the step ends and reads a directory with no
    // drain marker, so the check decides again.
    stop.store(true, Ordering::SeqCst);
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while b.step_stuck(Instant::now()) || b.share_verdict(Instant::now()) == ShareVerdict::Undecided
    {
        assert!(Instant::now() < deadline, "the step must finish");
        std::thread::sleep(Duration::from_millis(5));
    }
    // The pair was required more than the grace ago, so the decided word is
    // `stage_not_shared`.
    assert_eq!(b.share_verdict(Instant::now()), ShareVerdict::NotShared);
    assert_eq!(b.fault(Instant::now()), Some(STAGE_NOT_SHARED));
}

/// Review k11-guard-4 should-fix. A completed read found the drain's marker
/// absent (a misplaced replica, 503). Then its probe step hangs. The hang
/// says nothing new, so the last completed read stands: the replica stays
/// 503 and does not flap to 200 at `marker_stuck_after`.
#[test]
fn a_hung_step_keeps_a_marker_a_completed_read_found_absent() {
    let wrong = tempfile::tempdir().unwrap();
    let stuck_after = Duration::from_millis(150);
    let b = Arc::new(
        StageLiveness::with_thresholds(
            "web-b".to_owned(),
            LivenessThresholds {
                share_grace: GRACE,
                marker_stuck_after: stuck_after,
                ..LivenessThresholds::default()
            },
        )
        .with_share_guard(),
    );
    let clock = 9_000_000;
    b.note_share(
        Instant::now(),
        &with_drains(
            share_view(clock, &[]),
            &[("drain-1", "inc-d", clock, StageLivenessRole::Drain)],
        ),
    );
    b.share_step(&ShareMarkers::new(wrong.path())).unwrap();
    assert_eq!(
        b.fault(Instant::now()),
        Some(STAGE_SHARE_UNVERIFIED),
        "control: a completed read found the marker absent"
    );
    let (release, hold) = mpsc::channel::<()>();
    let hold = Mutex::new(hold);
    let entered = Arc::new(AtomicBool::new(false));
    let probe: ProbeFn = {
        let entered = entered.clone();
        Arc::new(move || {
            entered.store(true, Ordering::SeqCst);
            let _ = hold.lock().unwrap().recv();
            Ok(())
        })
    };
    let stop = Arc::new(AtomicBool::new(false));
    assert!(
        spawn_probe_thread_with_markers(
            &b,
            probe,
            Some(ShareMarkers::new(wrong.path())),
            Duration::from_millis(20),
            stop.clone(),
        )
        .unwrap()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline, "the probe thread must start");
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(stuck_after + Duration::from_millis(50));
    let now = Instant::now();
    assert!(b.step_stuck(now), "control: the step is hung");
    assert_ne!(b.share_verdict(now), ShareVerdict::Undecided);
    assert!(
        matches!(
            b.fault(now),
            Some(STAGE_SHARE_UNVERIFIED | STAGE_NOT_SHARED)
        ),
        "a hung step must not turn a decided 503 into 200: {:?}",
        b.fault(now)
    );
    assert_eq!(b.fault(now + GRACE), Some(STAGE_NOT_SHARED));
    assert!(gate_held(&b));
    assert_gate_agrees(&b, now);

    stop.store(true, Ordering::SeqCst);
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while b.step_stuck(Instant::now()) {
        assert!(Instant::now() < deadline, "the step must finish");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The first replica, no drain row: it serves (200) but never stages.
#[test]
fn a_replica_with_no_drain_row_serves_but_never_stages() {
    let root = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(root.path());
    let first = guarded("web-a");
    let now = Instant::now();
    assert_eq!(first.share_verdict(now), ShareVerdict::Pending);
    assert!(
        gate_held(&first),
        "nothing is proven before the first exchange"
    );
    assert_eq!(first.fault(now), None, "pending is 200");
    assert_gate_agrees(&first, now);

    first.share_step(&markers).unwrap();
    first.note_share(now, &share_view(1_000, &[]));
    first.share_step(&markers).unwrap();
    assert_eq!(first.share_verdict(now), ShareVerdict::NoAnchor);
    assert!(gate_held(&first), "no anchor proof, so no staging");
    assert_eq!(first.fault(now), None, "no drain row is 200");
    assert_eq!(
        first.fault(now + GRACE * 10),
        None,
        "for as long as it lasts"
    );
    assert_gate_agrees(&first, now);
    assert_eq!(first.snapshot(now).share, Some("no_anchor"));
}

/// Review probe R2: no drain row; web-a on a WRONG directory joined first,
/// web-b on the real stage. Neither stages, and neither is ejected. (Before,
/// the earliest-joined replica opened staging on the wrong directory.)
#[test]
fn no_drain_row_opens_staging_for_nobody_and_ejects_nobody() {
    let (real, wrong) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (real_markers, wrong_markers) = (
        ShareMarkers::new(real.path()),
        ShareMarkers::new(wrong.path()),
    );
    let a = guarded("web-a");
    let b = guarded("web-b");
    let clock = 9_000_000;
    let now = Instant::now();
    for _ in 0..3 {
        a.share_step(&wrong_markers).unwrap();
        b.share_step(&real_markers).unwrap();
        a.note_share(
            now,
            &share_view(clock, &[("web-b", b.incarnation(), clock)]),
        );
        b.note_share(
            now,
            &share_view(clock, &[("web-a", a.incarnation(), clock)]),
        );
    }
    let later = now + GRACE * 3;
    for replica in [&a, &b] {
        assert!(gate_held(replica), "{}", replica.replica_id());
        assert_eq!(replica.share_verdict(later), ShareVerdict::NoAnchor);
        assert_eq!(replica.fault(later), None);
        assert_gate_agrees(replica, later);
    }
}

/// A fresh, verified drain row is the anchor: staging opens only once this
/// replica has seen the drain's marker. Before that, 503 unverified.
#[test]
fn a_replica_stages_only_after_it_sees_the_fresh_drains_marker() {
    let root = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(root.path());
    let worker = drain_worker("drain-1");
    worker.share_step(&markers).unwrap();
    let b = guarded("web-b");
    let clock = 5_000_000;
    let now = Instant::now();
    b.note_share(
        now,
        &with_drains(
            share_view(clock, &[]),
            &[(
                "drain-1",
                worker.incarnation(),
                clock,
                StageLivenessRole::Drain,
            )],
        ),
    );
    assert_eq!(b.share_verdict(now), ShareVerdict::Unverified);
    assert!(gate_held(&b));
    assert_eq!(b.fault(now), Some(STAGE_SHARE_UNVERIFIED));
    assert_eq!(
        b.share_checks(),
        vec![("drain-1".to_owned(), worker.incarnation().to_owned())]
    );
    assert_gate_agrees(&b, now);

    b.share_step(&markers).unwrap();
    assert_eq!(b.share_verdict(now), ShareVerdict::Shared);
    assert!(!gate_held(&b));
    assert_eq!(b.fault(now), None);
    assert_gate_agrees(&b, now);
}

/// D1's topology with a drain: web-a on its own directory, web-b and the
/// drain on the real stage. web-a never stages and reads `stage_not_shared`
/// after the grace; web-b stages. The drain's row is never a K11 peer.
#[test]
fn a_misplaced_replica_is_held_and_the_right_one_stages() {
    let (real, wrong) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let worker = drain_worker("drain-1");
    worker.share_step(&ShareMarkers::new(real.path())).unwrap();
    let clock = 9_000_000;
    let now = Instant::now();
    let early = guarded("web-a");
    let late = guarded("web-b");
    let drains = [(
        "drain-1",
        worker.incarnation(),
        clock,
        StageLivenessRole::Drain,
    )];
    early.note_share(
        now,
        &with_drains(
            share_view(clock, &[("web-b", late.incarnation(), clock)]),
            &drains,
        ),
    );
    late.note_share(
        now,
        &with_drains(
            share_view(clock, &[("web-a", early.incarnation(), clock)]),
            &drains,
        ),
    );
    assert_eq!(
        early.share_checks(),
        vec![("drain-1".to_owned(), worker.incarnation().to_owned())],
        "only the drain is required, never a web peer"
    );
    early.share_step(&ShareMarkers::new(wrong.path())).unwrap();
    late.share_step(&ShareMarkers::new(real.path())).unwrap();
    assert_eq!(early.fault(now), Some(STAGE_SHARE_UNVERIFIED));
    assert_eq!(late.share_verdict(now), ShareVerdict::Shared);
    let later = now + GRACE;
    assert_eq!(early.share_verdict(later), ShareVerdict::NotShared);
    assert_eq!(early.fault(later), Some(STAGE_NOT_SHARED));
    assert!(gate_held(&early));
    assert_eq!(early.snapshot(later).share, Some("not_shared"));
    assert_eq!(
        early.snapshot(later).share_unconfirmed,
        vec!["drain-1".to_owned()]
    );
    assert_gate_agrees(&early, later);
    // The drain's row is never a K11 peer.
    late.note_peers(now, &with_drains(StagePeerLiveness::default(), &drains));
    assert_eq!(late.snapshot(now).peers, Some(0));
}

/// A stale drain row, or a fresh `drain_unverified` row, is no anchor: the
/// replica serves without staging, and the unverified drain is not a K11
/// peer either.
#[test]
fn a_stale_or_unverified_drain_row_is_not_an_anchor() {
    let clock = 100_000_000;
    let old = clock - i64::try_from(SHARE_PEER_FRESH.as_micros()).unwrap() - 1;
    let now = Instant::now();
    for (published, role) in [
        (old, StageLivenessRole::Drain),
        (clock, StageLivenessRole::DrainUnverified),
    ] {
        let first = guarded("web-a");
        let view = with_drains(
            share_view(clock, &[]),
            &[("drain-1", "inc-d", published, role)],
        );
        first.note_share(now, &view);
        assert_eq!(first.share_verdict(now), ShareVerdict::NoAnchor, "{role:?}");
        assert!(gate_held(&first));
        assert_eq!(first.fault(now), None);
        assert!(first.share_checks().is_empty());
        first.note_peers(now, &view);
        assert_eq!(
            first.snapshot(now).peers,
            Some(0),
            "{role:?} is no K11 peer"
        );
    }
}

/// Once a drain's marker was seen, a later transient fault cannot hold the
/// replica again: the proof latches.
#[test]
fn an_anchor_proven_replica_is_never_held_again() {
    let root = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(root.path());
    let worker = drain_worker("drain-1");
    worker.share_step(&markers).unwrap();
    let b = guarded("web-b");
    let clock = 9_000_000;
    let now = Instant::now();
    let anchored = |incarnation: &str| {
        with_drains(
            share_view(clock, &[]),
            &[("drain-1", incarnation, clock, StageLivenessRole::Drain)],
        )
    };
    b.note_share(now, &anchored(worker.incarnation()));
    assert!(
        gate_held(&b),
        "control: held until the drain marker is seen"
    );
    b.share_step(&markers).unwrap();
    assert_eq!(b.share_verdict(now), ShareVerdict::Shared);
    // The marker disappears, the drain restarts, then the drain leaves.
    markers.remove_if("drain-1", worker.incarnation()).unwrap();
    b.note_share(now, &anchored("restarted"));
    b.share_step(&markers).unwrap();
    b.note_share(now, &share_view(clock, &[]));
    assert_eq!(b.share_verdict(now + GRACE), ShareVerdict::Shared);
    assert!(!gate_held(&b));
    assert!(b.share_checks().is_empty());
    assert_gate_agrees(&b, now + GRACE);
}

/// A drain's restart (new incarnation) needs its new marker: the old marker
/// does not confirm it.
#[test]
fn a_marker_confirms_only_the_incarnation_it_holds() {
    let root = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(root.path());
    let worker = drain_worker("drain-1");
    worker.share_step(&markers).unwrap();
    let b = guarded("web-b");
    let clock = 9_000_000;
    let now = Instant::now();
    b.note_share(
        now,
        &with_drains(
            share_view(clock, &[]),
            &[(
                "drain-1",
                "another-incarnation",
                clock,
                StageLivenessRole::Drain,
            )],
        ),
    );
    b.share_step(&markers).unwrap();
    assert_eq!(b.share_verdict(now), ShareVerdict::Unverified);
    assert!(gate_held(&b));
}

#[test]
fn the_guard_off_never_answers_lb_health() {
    let b = StageLiveness::with_thresholds("web-b".to_owned(), LivenessThresholds::default());
    let clock = 9_000_000;
    let now = Instant::now();
    b.note_share(
        now,
        &with_drains(
            share_view(clock, &[]),
            &[("drain-1", "inc-d", clock, StageLivenessRole::Drain)],
        ),
    );
    assert_eq!(b.share_verdict(now), ShareVerdict::Unverified);
    assert_eq!(b.fault(now), None);
    assert_eq!(b.snapshot(now).share, None);
}

#[test]
fn markers_are_written_once_kept_per_incarnation_and_never_read_for_unsafe_ids() {
    let root = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(root.path());
    assert!(markers.ensure("web-a", "one").unwrap(), "first write");
    assert!(
        !markers.ensure("web-a", "one").unwrap(),
        "unchanged: no write"
    );
    assert_eq!(markers.read("web-a").unwrap().as_deref(), Some("one"));
    assert!(
        markers.ensure("web-a", "two").unwrap(),
        "a new value is written"
    );
    markers.remove_if("web-a", "one").unwrap();
    assert_eq!(
        markers.read("web-a").unwrap().as_deref(),
        Some("two"),
        "a stopping process never removes a newer marker"
    );
    markers.remove_if("web-a", "two").unwrap();
    assert_eq!(markers.read("web-a").unwrap(), None);
    for unsafe_id in ["..", "a/b", "a\\b", ""] {
        assert_eq!(markers.read(unsafe_id).unwrap(), None, "{unsafe_id:?}");
    }
}

/// The probe thread keeps the marker and removes it when it stops.
#[test]
fn the_probe_thread_writes_the_marker_and_removes_it_at_stop() {
    let root = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(root.path());
    let replica = Arc::new(guarded("web-a"));
    let stop = Arc::new(AtomicBool::new(false));
    let probe: ProbeFn = Arc::new(|| Ok(()));
    assert!(
        spawn_probe_thread_with_markers(
            &replica,
            probe,
            Some(markers.clone()),
            Duration::from_millis(20),
            stop.clone(),
        )
        .unwrap()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while markers.read("web-a").unwrap().as_deref() != Some(replica.incarnation()) {
        assert!(Instant::now() < deadline, "the marker was never written");
        std::thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_secs(5);
    while markers.read("web-a").unwrap().is_some() {
        assert!(Instant::now() < deadline, "the marker was never removed");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The drain is never held, whatever it sees. Its one fault is its own
/// anchor, which `/lb_health` never shows (it answers `drain_role`).
#[test]
fn the_drain_is_never_held() {
    let root = tempfile::tempdir().unwrap();
    let worker = drain_worker("drain-1").with_share_guard();
    worker.share_step(&ShareMarkers::new(root.path())).unwrap();
    let clock = 9_000_000;
    let now = Instant::now();
    worker.note_share(
        now,
        &with_drains(
            share_view(clock, &[("web-a", "inc-a", clock)]),
            &[("drain-2", "inc-d", clock, StageLivenessRole::Drain)],
        ),
    );
    assert_eq!(worker.share_verdict(now), ShareVerdict::Shared);
    assert_eq!(worker.fault(now), None);
    assert_eq!(
        verdict_from(
            None,
            combined_replica_fault(WriteBehindRole::Drain, None, Some(STAGE_ANCHOR_UNVERIFIED)),
        ),
        (StatusCode::OK, "ok"),
        "the drain's own anchor word never reaches /lb_health"
    );
}

/// Review should-fix R1, without Postgres: the drain publishes `drain` (an
/// anchor) only while a read-back of its own marker shows its incarnation.
/// A marker it cannot write, or a read-back older than the limit (a hung
/// marker thread), publishes `drain_unverified` and raises its fault.
#[test]
fn the_drain_anchors_only_while_it_reads_its_own_marker_back() {
    let root = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(root.path());
    let worker = StageLiveness::with_thresholds(
        "drain-1".to_owned(),
        LivenessThresholds {
            anchor_verify_max_age: Duration::from_millis(100),
            ..LivenessThresholds::default()
        },
    )
    .with_role(StageLivenessRole::Drain);
    assert_eq!(
        worker.publication().role,
        StageLivenessRole::DrainUnverified,
        "no read-back yet"
    );
    assert_eq!(worker.fault(Instant::now()), Some(STAGE_ANCHOR_UNVERIFIED));

    // A directory where the marker file belongs: the write fails, as an
    // EACCES or a wrong-uid `liveness/` would.
    let blocker = root.path().join("liveness").join("drain-1.present");
    std::fs::create_dir_all(&blocker).unwrap();
    assert!(worker.share_step(&markers).is_err());
    assert_eq!(
        worker.publication().role,
        StageLivenessRole::DrainUnverified
    );
    assert_eq!(worker.fault(Instant::now()), Some(STAGE_ANCHOR_UNVERIFIED));

    std::fs::remove_dir(&blocker).unwrap();
    worker.share_step(&markers).unwrap();
    assert_eq!(worker.publication().role, StageLivenessRole::Drain);
    assert_eq!(worker.fault(Instant::now()), None);

    // No new read-back: it ages out.
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(
        worker.publication().role,
        StageLivenessRole::DrainUnverified
    );
    assert_eq!(worker.fault(Instant::now()), Some(STAGE_ANCHOR_UNVERIFIED));

    // A web replica never publishes a drain role.
    assert_eq!(
        guarded("web-a").publication().role,
        StageLivenessRole::Stage
    );
}

/// The drain's marker thread writes, reads back, and removes its marker.
#[test]
fn the_drain_marker_thread_verifies_its_marker_and_removes_it_at_stop() {
    let root = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(root.path());
    let worker = Arc::new(drain_worker("drain-1"));
    let stop = Arc::new(AtomicBool::new(false));
    assert!(
        spawn_marker_thread(
            &worker,
            markers.clone(),
            Duration::from_millis(20),
            stop.clone()
        )
        .unwrap()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while worker.publication().role != StageLivenessRole::Drain {
        assert!(Instant::now() < deadline, "the anchor was never verified");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        markers.read("drain-1").unwrap().as_deref(),
        Some(worker.incarnation())
    );
    stop.store(true, Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_secs(5);
    while markers.read("drain-1").unwrap().is_some() {
        assert!(Instant::now() < deadline, "the marker was never removed");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// No exchange has succeeded for the grace: 503 `stage_share_pending`.
/// Staging is off throughout.
#[test]
fn a_replica_pending_past_the_grace_answers_stage_share_pending() {
    let a = guarded("web-a");
    let now = Instant::now();
    assert_eq!(a.share_verdict(now), ShareVerdict::Pending);
    assert_eq!(a.fault(now), None);
    let later = now + GRACE;
    assert_eq!(a.share_verdict(later), ShareVerdict::PendingTooLong);
    assert_eq!(a.fault(later), Some(STAGE_SHARE_PENDING));
    assert!(gate_held(&a));
    assert_gate_agrees(&a, later);
    assert_eq!(a.snapshot(later).share, Some("pending_too_long"));
}
