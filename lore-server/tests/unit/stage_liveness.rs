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
use lore_postgres::domain::fragments::StagerIdentity;
use lore_postgres::domain::fragments::prune_in_passes;
use lore_postgres::store::fragment_write_behind::ConfirmedStagers;
use lore_postgres::store::fragment_write_behind::DrainAbsenceCounts;
use lore_server::fragment_write_behind::StageAttach;
use lore_server::fragment_write_behind::WriteBehindRole;
use lore_server::fragment_write_behind::combined_replica_fault;
use lore_server::fragment_write_behind::stage_liveness_for_role;
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
    // The state stamped its own "last good" at construction, before `start`.
    // Pin the success time to `start` so the 1 ms margin is exact.
    state.note_good(start);
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
    // The marker holds the bare incarnation; the challenge file is the
    // replica's own (drain guard).
    while markers.read("web-a").unwrap().as_deref() != Some(replica.incarnation())
        || markers.read_challenge("web-a").unwrap().is_none()
    {
        assert!(
            Instant::now() < deadline,
            "the marker and the challenge were never written"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_secs(5);
    while markers.read("web-a").unwrap().is_some()
        || markers.read_challenge("web-a").unwrap().is_some()
    {
        assert!(
            Instant::now() < deadline,
            "the marker and the challenge were never removed"
        );
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

// ---------------------------------------------------------------------------
// WP-115 drain guard (module docs, "Drain guard").
// ---------------------------------------------------------------------------

fn stager(id: &str, incarnation: &str) -> StagerIdentity {
    StagerIdentity::new(id, incarnation).unwrap()
}

const CLOCK: i64 = 9_000_000_000;

/// The default freshness window, in microseconds.
fn fresh_micros() -> i64 {
    i64::try_from(SHARE_PEER_FRESH.as_micros()).unwrap()
}

/// A view at database time `clock` with rows as
/// `(replica, incarnation, role, published)`.
fn guard_view(clock: i64, rows: &[(&str, &str, StageLivenessRole, i64)]) -> StagePeerLiveness {
    StagePeerLiveness {
        peers: rows
            .iter()
            .map(|(id, incarnation, role, published)| StagePeerProgress {
                replica_id: (*id).to_owned(),
                record: record(incarnation, 1, 0),
                published_micros: *published,
                role: *role,
            })
            .collect(),
        db_clock_micros: clock,
        ..StagePeerLiveness::default()
    }
}

/// A view at [`CLOCK`] with fresh web stage rows `(replica, incarnation)`.
fn web_rows(rows: &[(&str, &str)]) -> StagePeerLiveness {
    let rows: Vec<(&str, &str, StageLivenessRole, i64)> = rows
        .iter()
        .map(|(id, incarnation)| (*id, *incarnation, StageLivenessRole::Stage, CLOCK))
        .collect();
    guard_view(CLOCK, &rows)
}

/// The view `me` reads of the live processes `all` (itself left out, as the
/// exchange leaves out its own row), every row fresh at [`CLOCK`].
fn view_of(me: &StageLiveness, all: &[&StageLiveness]) -> StagePeerLiveness {
    let mut peers: Vec<StagePeerProgress> = all
        .iter()
        .filter(|other| other.replica_id() != me.replica_id())
        .map(|other| StagePeerProgress {
            replica_id: other.replica_id().to_owned(),
            record: record(other.incarnation(), 1, 0),
            published_micros: CLOCK,
            role: other.role(),
        })
        .collect();
    peers.sort_by(|x, y| x.replica_id.cmp(&y.replica_id));
    StagePeerLiveness {
        peers,
        db_clock_micros: CLOCK,
        ..StagePeerLiveness::default()
    }
}

/// Write `stager_id`'s echo file as a web replica of incarnation
/// `stager_incarnation` would: its incarnation, then one
/// `<reader incarnation> <challenge>` line per echo.
fn write_echo(
    markers: &ShareMarkers,
    stager_id: &str,
    stager_incarnation: &str,
    echoes: &[(&str, &str)],
) {
    let mut content = stager_incarnation.to_owned();
    for (reader, challenge) in echoes {
        content.push_str(&format!("\n{reader} {challenge}"));
    }
    markers.write_echo(stager_id, &content).unwrap();
}

/// `reader`'s current challenge, after the step that wrote it.
fn current(reader: &StageLiveness) -> (u64, String) {
    reader
        .current_challenge()
        .expect("the reader has a current challenge")
}

/// Run `reader`'s challenge steps until its challenge rotates. Returns the
/// new current challenge.
fn rotate(reader: &StageLiveness, markers: &ShareMarkers) -> (u64, String) {
    let before = reader.current_challenge();
    for _ in 0..=CHALLENGE_EVERY_STEPS {
        reader.challenge_step(markers);
        if reader.current_challenge() != before {
            return current(reader);
        }
    }
    panic!("the challenge did not rotate within {CHALLENGE_EVERY_STEPS} steps");
}

/// A root check that answers from a queue, one answer per call, and `true`
/// once the queue is empty. Returns the check and the queue.
fn scripted_root() -> (RootCheck, Arc<Mutex<std::collections::VecDeque<bool>>>) {
    let queue = Arc::new(Mutex::new(std::collections::VecDeque::new()));
    let answers = queue.clone();
    let check: RootCheck = Arc::new(move || answers.lock().unwrap().pop_front().unwrap_or(true));
    (check, queue)
}

fn script(queue: &Mutex<std::collections::VecDeque<bool>>, answers: &[bool]) {
    let mut queue = queue.lock().unwrap();
    queue.clear();
    queue.extend(answers.iter().copied());
}

/// The confirmation rule, step by step: a reader confirms a web replica
/// process only when its echo file, read in the reader's own directory,
/// names that process and echoes the reader's CURRENT challenge under the
/// reader's own incarnation, and then a LATER current challenge. Nothing
/// else confirms: no challenge yet, one challenge echoed again and again, or
/// an echo of a value the reader never wrote.
#[test]
fn a_reader_confirms_a_stager_only_after_echo_files_of_two_current_challenges() {
    let dir = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(dir.path());
    let worker = drain_worker("drain-1");
    let now = Instant::now();
    let a = stager("web-a", "inc-a");
    worker.note_share(now, &web_rows(&[("web-a", "inc-a")]));
    write_echo(&markers, "web-a", "inc-a", &[(worker.incarnation(), "x")]);
    // No challenge yet: nothing can match, and the guard is unproven.
    worker.confirm_step(&markers);
    assert!(!worker.confirms(&a));
    assert!(worker.absence_unproven());
    assert_eq!(
        worker.snapshot(now).absence,
        Some(ABSENCE_NO_CHALLENGE),
        "no challenge yet"
    );

    worker.challenge_step(&markers);
    let (first_seq, first) = current(&worker);
    assert_eq!(
        markers.read_challenge("drain-1").unwrap(),
        Some(format!("{} {first}", worker.incarnation())),
        "the challenge file holds `<incarnation> <challenge>`"
    );
    write_echo(
        &markers,
        "web-a",
        "inc-a",
        &[(worker.incarnation(), &first)],
    );
    for _ in 0..3 {
        worker.confirm_step(&markers);
    }
    assert!(!worker.confirms(&a), "one challenge echoed again and again");
    write_echo(
        &markers,
        "web-a",
        "inc-a",
        &[(worker.incarnation(), "never-written")],
    );
    worker.confirm_step(&markers);
    assert!(!worker.confirms(&a), "a value the reader never wrote");

    let (second_seq, second) = rotate(&worker, &markers);
    assert!(second_seq > first_seq);
    assert_ne!(second, first);
    assert!(
        worker.absence_unproven(),
        "web-a is in the view, unconfirmed"
    );
    assert_eq!(
        worker.snapshot(now).absence_unconfirmed,
        vec!["web-a".to_owned()]
    );
    write_echo(
        &markers,
        "web-a",
        "inc-a",
        &[(worker.incarnation(), &second)],
    );
    worker.confirm_step(&markers);
    assert!(
        worker.confirms(&a),
        "a second, later current challenge confirms"
    );
    assert!(!worker.absence_unproven());
    let snapshot = worker.snapshot(now);
    assert_eq!(snapshot.absence, Some("guarded"));
    assert_eq!(snapshot.absence_confirmed, Some(1));
    assert!(snapshot.absence_unconfirmed.is_empty());
    assert!(
        !worker.confirms(&stager("web-a", "inc-other")),
        "another incarnation of the same replica id is another process"
    );
}

/// Mutant "the reader accepts an old challenge": a web replica whose echo
/// file shows the reader's FIRST challenge only after it rotated (a late,
/// one-off copy of the old file), then the second, has echoed only ONE
/// current challenge. It is not confirmed. The control echoes both while
/// current.
#[test]
fn an_echo_of_an_old_challenge_never_counts() {
    let dir = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(dir.path());
    let worker = drain_worker("drain-1");
    let now = Instant::now();
    let (late, control) = (stager("web-late", "inc-l"), stager("web-ok", "inc-o"));
    worker.note_share(
        now,
        &web_rows(&[("web-late", "inc-l"), ("web-ok", "inc-o")]),
    );
    worker.challenge_step(&markers);
    let (_, first) = current(&worker);
    let me = worker.incarnation().to_owned();
    write_echo(&markers, "web-ok", "inc-o", &[(&me, &first)]);
    worker.confirm_step(&markers);
    let (_, second) = rotate(&worker, &markers);
    // web-late now echoes the old challenge: it is not current.
    write_echo(&markers, "web-late", "inc-l", &[(&me, &first)]);
    write_echo(&markers, "web-ok", "inc-o", &[(&me, &second)]);
    worker.confirm_step(&markers);
    assert!(worker.confirms(&control), "control: two current echoes");
    assert!(!worker.confirms(&late));
    // web-late then echoes the current one: still only one current echo.
    write_echo(&markers, "web-late", "inc-l", &[(&me, &second)]);
    worker.confirm_step(&markers);
    assert!(
        !worker.confirms(&late),
        "an old challenge plus one current one is one current echo"
    );
    let (_, third) = rotate(&worker, &markers);
    write_echo(&markers, "web-late", "inc-l", &[(&me, &third)]);
    worker.confirm_step(&markers);
    assert!(worker.confirms(&late), "two current echoes confirm");
}

/// Mutant "the reader accepts any challenge it finds": an echo file that
/// stays the same while the reader rotates (a one-off copy of an old echo,
/// or a value the reader never wrote) never confirms, however many
/// rotations pass. Only the echo of the challenge current at each read
/// counts.
#[test]
fn an_unchanging_echo_never_confirms_across_rotations() {
    let dir = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(dir.path());
    let worker = drain_worker("drain-1");
    let now = Instant::now();
    let (old, junk) = (stager("web-old", "inc-o"), stager("web-junk", "inc-j"));
    worker.note_share(
        now,
        &web_rows(&[("web-old", "inc-o"), ("web-junk", "inc-j")]),
    );
    let me = worker.incarnation().to_owned();
    let (_, first) = rotate(&worker, &markers);
    write_echo(&markers, "web-old", "inc-o", &[(&me, &first)]);
    write_echo(&markers, "web-junk", "inc-j", &[(&me, "never-written")]);
    for _ in 0..4 {
        worker.confirm_step(&markers);
        rotate(&worker, &markers);
    }
    worker.confirm_step(&markers);
    assert!(!worker.confirms(&old), "one old echo, read again and again");
    assert!(!worker.confirms(&junk), "a value the reader never wrote");
}

/// Mutant "the reader accepts another reader's challenge": an echo counts
/// only under the reader's own incarnation. A file that carries this reader's
/// current challenge under another reader's incarnation is never this
/// reader's echo. Mutant "the reader ignores who wrote the file": an echo
/// file whose first line names another incarnation of the same replica id
/// (an old process's file, or a duplicate id) is never that candidate's.
#[test]
fn an_echo_under_another_incarnation_never_counts() {
    let dir = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(dir.path());
    let worker = drain_worker("drain-1");
    let other = drain_worker("drain-2");
    let now = Instant::now();
    let a = stager("web-a", "inc-a");
    worker.note_share(now, &web_rows(&[("web-a", "inc-a")]));
    let me = worker.incarnation().to_owned();
    for _ in 0..2 {
        let (_, challenge) = rotate(&worker, &markers);
        write_echo(
            &markers,
            "web-a",
            "inc-a",
            &[(other.incarnation(), &challenge)],
        );
        worker.confirm_step(&markers);
    }
    assert!(
        !worker.confirms(&a),
        "never under another reader incarnation"
    );
    for _ in 0..2 {
        let (_, challenge) = rotate(&worker, &markers);
        write_echo(&markers, "web-a", "inc-old", &[(&me, &challenge)]);
        worker.confirm_step(&markers);
    }
    assert!(
        !worker.confirms(&a),
        "never from a file another process of that id wrote"
    );
    // Control: the same values under the right names, with noise beside.
    for _ in 0..2 {
        let (_, challenge) = rotate(&worker, &markers);
        write_echo(
            &markers,
            "web-a",
            "inc-a",
            &[(other.incarnation(), "noise"), (&me, &challenge)],
        );
        worker.confirm_step(&markers);
    }
    assert!(worker.confirms(&a), "control: its own incarnation confirms");
}

/// The echo file format: the writer's incarnation on the first line, then
/// `<reader incarnation> <challenge>` lines. A lookup matches both
/// incarnations exactly.
#[test]
fn echoed_challenge_matches_only_the_exact_writer_and_reader() {
    let content = "inc-w\ninc-a c1\nbad line here\ninc-c c4";
    assert_eq!(echoed_challenge(content, "inc-w", "inc-a"), Some("c1"));
    assert_eq!(echoed_challenge(content, "inc-w", "inc-c"), Some("c4"));
    assert_eq!(echoed_challenge(content, "inc-w", "inc"), None);
    assert_eq!(echoed_challenge(content, "inc-x", "inc-a"), None);
    assert_eq!(echoed_challenge("", "inc-w", "inc-a"), None);
    assert_eq!(echoed_challenge("inc-w\ninc-a", "inc-w", "inc-a"), None);
}

/// Mutant "a confirmation survives a reader restart": a restarted reader is a
/// new incarnation in the same directory, under the same replica id, with no
/// confirmations. Echoes of the old incarnation's challenges never count
/// for it, and it confirms only through its own new challenges.
#[test]
fn confirmations_do_not_survive_a_reader_restart() {
    let dir = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(dir.path());
    let now = Instant::now();
    let a = stager("web-a", "inc-a");
    let first = drain_worker("drain-1");
    first.note_share(now, &web_rows(&[("web-a", "inc-a")]));
    let mut last = String::new();
    for _ in 0..2 {
        let (_, challenge) = rotate(&first, &markers);
        write_echo(
            &markers,
            "web-a",
            "inc-a",
            &[(first.incarnation(), &challenge)],
        );
        first.confirm_step(&markers);
        last = challenge;
    }
    assert!(
        first.confirms(&a),
        "control: the first incarnation confirms"
    );

    let restarted = drain_worker("drain-1");
    assert_ne!(restarted.incarnation(), first.incarnation());
    assert!(
        !restarted.confirms(&a),
        "a new incarnation starts with none"
    );
    restarted.note_share(now, &web_rows(&[("web-a", "inc-a")]));
    for _ in 0..3 {
        rotate(&restarted, &markers);
        write_echo(&markers, "web-a", "inc-a", &[(first.incarnation(), &last)]);
        restarted.confirm_step(&markers);
    }
    assert!(
        !restarted.confirms(&a),
        "echoes of the old incarnation's challenge never count"
    );
    assert!(restarted.absence_unproven());
    assert!(
        first.confirms(&a),
        "the old incarnation's memory is its own"
    );
}

/// One round of a cell over real stage directories, in the order the threads
/// and tasks run: each reader steps in its own directory (challenge, then
/// the echo files of its candidates); each web replica reads its view and
/// steps in its own directory (challenge, echo files, its own echo file);
/// each process then reads its view.
fn cell_round(
    readers: &[(&StageLiveness, &ShareMarkers)],
    webs: &[(&StageLiveness, &ShareMarkers)],
) {
    let now = Instant::now();
    let all: Vec<&StageLiveness> = readers.iter().chain(webs.iter()).map(|(p, _)| *p).collect();
    for (reader, markers) in readers {
        reader.share_step(markers).unwrap();
    }
    for (web, markers) in webs {
        web.note_share(now, &view_of(web, &all));
        web.share_step(markers).unwrap();
    }
    for (process, _) in readers.iter().chain(webs.iter()) {
        process.note_share(now, &view_of(process, &all));
    }
}

fn identity(replica: &StageLiveness) -> StagerIdentity {
    stager(replica.replica_id(), replica.incarnation())
}

/// Copy every file of `from`'s liveness directory into `to`'s (overwriting),
/// as `rsync -a` of the directory does. Files whose name starts with one of
/// `except` are left out.
fn copy_liveness_except(from: &std::path::Path, to: &std::path::Path, except: &[&str]) {
    let (from, to) = (from.join("liveness"), to.join("liveness"));
    std::fs::create_dir_all(&to).unwrap();
    if !from.exists() {
        return;
    }
    for entry in std::fs::read_dir(&from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if except.iter().any(|prefix| name.starts_with(prefix)) {
            continue;
        }
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

fn copy_liveness(from: &std::path::Path, to: &std::path::Path) {
    copy_liveness_except(from, to, &[]);
}

/// The challenge of `reader` that `web`'s echo file in `markers` shows, if
/// any.
fn echo_in(markers: &ShareMarkers, web: &StageLiveness, reader: &StageLiveness) -> Option<String> {
    markers
        .read_echo(web.replica_id())
        .unwrap()
        .and_then(|content| {
            echoed_challenge(&content, web.incarnation(), reader.incarnation()).map(str::to_owned)
        })
}

/// Review N1 (round 2) at the liveness level: B is a full copy of A, taken
/// while drain d1 and web-a ran on A (so B holds the same files, d1's
/// challenge and web-a's echo included, as a volume clone or rsync gives).
/// The drain restarts as d2 on B; web-a keeps running on A. web-a never sees
/// d2's challenges, so d2 never confirms it, however long they run. The web
/// side too: web-c on B (a reader) never confirms web-a. Control: d1 on A
/// confirms web-a.
#[test]
fn a_copy_of_the_stage_never_confirms_a_web_replica_on_the_original() {
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (
        ShareMarkers::new(a_dir.path()),
        ShareMarkers::new(b_dir.path()),
    );
    let d1 = drain_worker("drain-1");
    let web_a = guarded("web-a");
    for _ in 0..(CHALLENGE_EVERY_STEPS * 3) {
        cell_round(&[(&d1, &a)], &[(&web_a, &a)]);
    }
    assert!(
        d1.confirms(&identity(&web_a)),
        "control: d1 on A confirms web-a"
    );
    copy_liveness(a_dir.path(), b_dir.path());

    let d2 = drain_worker("drain-2");
    let web_c = guarded("web-c");
    for _ in 0..(CHALLENGE_EVERY_STEPS * 4) {
        cell_round(&[(&d2, &b)], &[(&web_a, &a), (&web_c, &b)]);
    }
    assert!(
        !d2.confirms(&identity(&web_a)),
        "a drain on the copy never confirms a web replica on the original"
    );
    assert!(
        !web_c.confirms(&identity(&web_a)),
        "nor does a web replica on the copy"
    );
    assert!(
        d2.confirms(&identity(&web_c)),
        "control: web-c is on B with d2"
    );
    assert!(
        !web_a.confirms(&identity(&web_c)),
        "web-a on A never confirms web-c on B"
    );
    assert!(
        web_a.confirms(&identity(&web_a)),
        "a web replica confirms itself"
    );
}

/// Review S1 (round 2): a one-way copy loop from web-a's directory A to the
/// drain's directory B (rsync or lsyncd, every step) brings web-a's files to
/// B, but never brings the drain's challenge to web-a. The drain on B never
/// confirms web-a.
#[test]
fn a_one_way_copy_loop_from_the_web_directory_never_confirms() {
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (
        ShareMarkers::new(a_dir.path()),
        ShareMarkers::new(b_dir.path()),
    );
    let drain = drain_worker("drain-b");
    let web_a = guarded("web-a");
    for _ in 0..(CHALLENGE_EVERY_STEPS * 4) {
        cell_round(&[(&drain, &b)], &[(&web_a, &a)]);
        copy_liveness(a_dir.path(), b_dir.path());
    }
    assert!(
        b.read_echo(web_a.replica_id()).unwrap().is_some(),
        "the loop does copy web-a's echo file to B"
    );
    assert!(!drain.confirms(&identity(&web_a)));
    assert_eq!(
        echo_in(&b, &web_a, &drain),
        None,
        "it never echoes the drain"
    );
}

/// Review B1 (round 3), probe P1: a one-way copy loop from the drain's
/// directory B to web-a's directory A, every round. web-a reads the drain's
/// challenges (round 3 confirmed it from that alone), but its echo stays in
/// A. The drain on B never confirms web-a. The control shows that web-a's
/// echo file in A really echoes the drain's current challenge.
#[test]
fn a_one_way_copy_loop_from_the_reader_directory_never_confirms() {
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (
        ShareMarkers::new(a_dir.path()),
        ShareMarkers::new(b_dir.path()),
    );
    let drain = drain_worker("drain-b");
    let web_a = guarded("web-a");
    for _ in 0..(CHALLENGE_EVERY_STEPS * 4) {
        cell_round(&[(&drain, &b)], &[(&web_a, &a)]);
        copy_liveness(b_dir.path(), a_dir.path());
    }
    assert!(
        !drain.confirms(&identity(&web_a)),
        "a one-way B -> A copy never confirms web-a"
    );
    assert!(drain.absence_unproven());
    assert!(
        echo_in(&a, &web_a, &drain).is_some(),
        "control: web-a in A does echo the drain's challenge"
    );
}

/// Review B1 (round 3), probe P1b: the same with a slow loop (a cron rsync,
/// one copy every 7 rounds), over 200 rounds.
#[test]
fn a_slow_one_way_copy_loop_from_the_reader_directory_never_confirms() {
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (
        ShareMarkers::new(a_dir.path()),
        ShareMarkers::new(b_dir.path()),
    );
    let drain = drain_worker("drain-b");
    let web_a = guarded("web-a");
    for round in 0..200 {
        cell_round(&[(&drain, &b)], &[(&web_a, &a)]);
        if round % 7 == 0 {
            copy_liveness(b_dir.path(), a_dir.path());
        }
    }
    assert!(!drain.confirms(&identity(&web_a)));
}

/// Review B1 (round 3): a union (overlay) mount, reads see the shared
/// directory S, writes land in a local upper directory. Emulated by showing
/// the process every file of S that it did not write itself (its own files
/// shadow S's, as an upper layer does) before each of its steps.
///
/// - Web side: web-a's union reads the drain's challenges in S, but its echo
///   (and its staged files) stay in its upper directory. The drain on S never
///   confirms web-a.
/// - Reader side: the drain's union shows it web-a's files in S, but its
///   challenges stay in its upper directory, so web-a in S never echoes them.
///
/// Control: the same processes all on S confirm.
#[test]
fn a_union_mount_on_either_side_never_confirms() {
    let (shared_dir, upper_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (shared, upper) = (
        ShareMarkers::new(shared_dir.path()),
        ShareMarkers::new(upper_dir.path()),
    );
    let drain = drain_worker("drain-s");
    let web_a = guarded("web-a");
    for _ in 0..(CHALLENGE_EVERY_STEPS * 4) {
        copy_liveness_except(shared_dir.path(), upper_dir.path(), &["web-a."]);
        cell_round(&[(&drain, &shared)], &[(&web_a, &upper)]);
    }
    assert!(
        echo_in(&upper, &web_a, &drain).is_some(),
        "the web-side union does read the drain's challenge"
    );
    assert!(
        !drain.confirms(&identity(&web_a)),
        "web-side union: the echo never reaches the drain"
    );

    let (shared_dir, upper_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (shared, upper) = (
        ShareMarkers::new(shared_dir.path()),
        ShareMarkers::new(upper_dir.path()),
    );
    let drain = drain_worker("drain-u");
    let web_a = guarded("web-a");
    for _ in 0..(CHALLENGE_EVERY_STEPS * 4) {
        copy_liveness_except(shared_dir.path(), upper_dir.path(), &["drain-u."]);
        cell_round(&[(&drain, &upper)], &[(&web_a, &shared)]);
    }
    assert!(
        !drain.confirms(&identity(&web_a)),
        "reader-side union: the challenge never reaches web-a"
    );

    let dir = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(dir.path());
    let (drain, web_a) = (drain_worker("drain-s"), guarded("web-a"));
    for _ in 0..(CHALLENGE_EVERY_STEPS * 4) {
        cell_round(&[(&drain, &markers)], &[(&web_a, &markers)]);
    }
    assert!(drain.confirms(&identity(&web_a)), "control: one directory");
}

/// A web replica is a reader too: on A it confirms itself and a peer (web-b)
/// whose echo file in A shows its challenges, never web-c on B. The K11
/// share state and `/lb_health` are what they were.
#[test]
fn a_web_replica_confirms_itself_and_peers_only_in_its_own_stage() {
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (
        ShareMarkers::new(a_dir.path()),
        ShareMarkers::new(b_dir.path()),
    );
    let (web_a, web_b, web_c) = (guarded("web-a"), guarded("web-b"), guarded("web-c"));
    for _ in 0..(CHALLENGE_EVERY_STEPS * 3) {
        cell_round(&[], &[(&web_a, &a), (&web_b, &a), (&web_c, &b)]);
    }
    assert!(web_a.confirms(&identity(&web_a)));
    assert!(web_a.confirms(&identity(&web_b)));
    assert!(!web_a.confirms(&identity(&web_c)));
    assert!(web_c.confirms(&identity(&web_c)));
    assert!(!web_c.confirms(&identity(&web_a)));
    let now = Instant::now();
    assert_eq!(web_a.share_verdict(now), ShareVerdict::NoAnchor);
    assert!(gate_held(&web_a));
    assert_eq!(web_a.fault(now), None, "the guard adds no /lb_health fault");
    assert_eq!(
        web_a.snapshot(now).absence,
        None,
        "no counts attached: no absence block"
    );
    assert!(
        !drain_worker("d").confirms(&stager("d", "x")),
        "a drain is never a stager of its own"
    );
}

/// Review A1/A2 and B S1 (round 3), with the fail-safe kept. web-c stages
/// into another directory B and then crashes: its row stays in the table
/// (for [`RETAIN`]) but stops being fresh. The drain on A never confirmed
/// it, and never does: its files stay kept. Once web-c's row is stale it no
/// longer holds the "not confirmed yet" signal, so the drain's guard reads
/// proven for the live cell, where web-a (same directory, fresh) is
/// confirmed and its files prove absence as before.
#[test]
fn a_departed_stager_in_another_directory_stays_unconfirmed_after_its_row_goes_stale() {
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (
        ShareMarkers::new(a_dir.path()),
        ShareMarkers::new(b_dir.path()),
    );
    let drain = drain_worker("drain-a");
    let (web_a, web_c) = (guarded("web-a"), guarded("web-c"));
    for _ in 0..(CHALLENGE_EVERY_STEPS * 4) {
        cell_round(&[(&drain, &a)], &[(&web_a, &a), (&web_c, &b)]);
    }
    assert!(drain.confirms(&identity(&web_a)), "control: same directory");
    assert!(!drain.confirms(&identity(&web_c)));
    assert!(drain.absence_unproven(), "web-c is fresh and unconfirmed");

    // web-c crashes: no withdraw, its row ages. The drain and web-a go on.
    let now = Instant::now();
    let rows = |clock: i64| {
        guard_view(
            clock,
            &[
                (
                    web_a.replica_id(),
                    web_a.incarnation(),
                    StageLivenessRole::Stage,
                    clock,
                ),
                (
                    web_c.replica_id(),
                    web_c.incarnation(),
                    StageLivenessRole::Stage,
                    CLOCK,
                ),
            ],
        )
    };
    let fresh_edge = CLOCK + fresh_micros();
    drain.note_share(now, &rows(fresh_edge));
    assert!(
        drain.absence_unproven(),
        "at the edge of the window web-c's row is still fresh"
    );
    let stale = fresh_edge + 1;
    for _ in 0..(CHALLENGE_EVERY_STEPS * 3) {
        drain.share_step(&a).unwrap();
        drain.note_share(now, &rows(stale));
    }
    assert!(
        !drain.absence_unproven(),
        "a stale row no longer holds the aggregate signal"
    );
    assert!(drain.snapshot(now).absence_unconfirmed.is_empty());
    assert!(
        !drain.confirms(&identity(&web_c)),
        "fail-safe: a stager this reader never confirmed stays unconfirmed"
    );
    assert!(drain.confirms(&identity(&web_a)));

    // A restarted drain never confirms the departed web-c either, also with
    // web-c's old echo file copied into A.
    copy_liveness(b_dir.path(), a_dir.path());
    let restarted = drain_worker("drain-a");
    for _ in 0..(CHALLENGE_EVERY_STEPS * 3) {
        restarted.share_step(&a).unwrap();
        restarted.note_share(now, &rows(stale));
    }
    assert!(!restarted.confirms(&identity(&web_c)));
}

/// Run rounds in one directory: the readers step, web-a reads a view of
/// `extra` rows plus the readers, steps (echo), and each reader reads web-a.
fn crowded_rounds(
    a: &ShareMarkers,
    readers: &[&StageLiveness],
    web_a: &StageLiveness,
    extra: &[(String, String, i64)],
) {
    let now = Instant::now();
    for _ in 0..(CHALLENGE_EVERY_STEPS * 4) {
        for reader in readers {
            reader.share_step(a).unwrap();
        }
        let mut rows: Vec<(&str, &str, StageLivenessRole, i64)> = extra
            .iter()
            .map(|(id, inc, published)| {
                (
                    id.as_str(),
                    inc.as_str(),
                    StageLivenessRole::Stage,
                    *published,
                )
            })
            .collect();
        for reader in readers {
            rows.push((
                reader.replica_id(),
                reader.incarnation(),
                reader.role(),
                CLOCK,
            ));
        }
        rows.sort_by(|x, y| x.0.cmp(y.0));
        web_a.note_share(now, &guard_view(CLOCK, &rows));
        web_a.share_step(a).unwrap();
        for reader in readers {
            reader.note_share(now, &view_of(reader, &[web_a]));
        }
    }
}

/// Review B S1 (round 3), probe P3: the echo slots. The readers and web-a
/// share A, and web-a's view is crowded with rows that sort first.
///
/// - 70 dead rows (more than [`MAX_CHALLENGE_ECHOES`]): a dead row takes no
///   slot, so a fresh web reader (web-b) and the drain both confirm web-a.
/// - 80 live web rows with no challenge file: drain rows go first, so the
///   drain still confirms web-a.
#[test]
fn dead_and_extra_rows_never_crowd_a_reader_out_of_the_echo() {
    let dir = tempfile::tempdir().unwrap();
    let a = ShareMarkers::new(dir.path());
    let dead: Vec<(String, String, i64)> = (0..70)
        .map(|i| (format!("aa-dead-{i:02}"), format!("dead-inc-{i}"), 0))
        .collect();
    let (drain, web_b, web_a) = (drain_worker("zz-drain"), guarded("web-b"), guarded("web-a"));
    crowded_rounds(&a, &[&drain, &web_b], &web_a, &dead);
    assert!(
        web_b.confirms(&identity(&web_a)),
        "dead rows take no echo slot"
    );
    assert!(drain.confirms(&identity(&web_a)));

    let live: Vec<(String, String, i64)> = (0..80)
        .map(|i| (format!("ab-live-{i:02}"), format!("live-inc-{i}"), CLOCK))
        .collect();
    let (drain, web_a) = (drain_worker("zz-drain"), guarded("web-a"));
    crowded_rounds(&a, &[&drain], &web_a, &live);
    assert!(
        drain.confirms(&identity(&web_a)),
        "the drain's echo slot is never taken"
    );
}

/// A root path that no longer names the pinned stage root (a remount or a
/// moved symlink): the reader has no current challenge, and the web replica
/// writes no echo file, though the challenge files are there.
#[test]
fn a_failed_root_check_clears_the_challenge_and_writes_no_echo() {
    let dir = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(dir.path());
    let pinned = Arc::new(AtomicBool::new(true));
    let check = pinned.clone();
    let worker =
        drain_worker("drain-1").with_root_check(Arc::new(move || check.load(Ordering::SeqCst)));
    let check = pinned.clone();
    let web = guarded("web-a").with_root_check(Arc::new(move || check.load(Ordering::SeqCst)));
    for _ in 0..2 {
        cell_round(&[(&worker, &markers)], &[(&web, &markers)]);
    }
    assert!(worker.current_challenge().is_some(), "control");
    assert!(echo_in(&markers, &web, &worker).is_some(), "control");

    pinned.store(false, Ordering::SeqCst);
    std::fs::remove_file(dir.path().join("liveness").join("web-a.echo")).unwrap();
    cell_round(&[(&worker, &markers)], &[(&web, &markers)]);
    assert_eq!(worker.current_challenge(), None);
    assert!(worker.absence_unproven());
    assert_eq!(markers.read_echo("web-a").unwrap(), None, "no echo written");
    assert!(
        markers.read_challenge("drain-1").unwrap().is_some(),
        "the file is still there"
    );
}

/// Mutant ME (review B S2): the root path moves while the challenge is
/// written (the check before passes, the check after fails). The challenge
/// it wrote is not current. Control: both checks pass.
#[test]
fn a_challenge_written_while_the_root_moved_is_never_current() {
    let dir = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(dir.path());
    let (check, queue) = scripted_root();
    let reader = drain_worker("drain-1").with_root_check(check);
    script(&queue, &[true, false]);
    reader.challenge_step(&markers);
    assert_eq!(reader.current_challenge(), None);
    assert!(queue.lock().unwrap().is_empty(), "both checks ran");
    script(&queue, &[true, true]);
    reader.challenge_step(&markers);
    assert!(reader.current_challenge().is_some(), "control");
}

/// Mutants MD and MD2 (review B S2): the echo step checks the root path
/// before its reads and after its write. A path that names another
/// directory before the reads touches nothing there (no read, no write, no
/// removal); one that moves during the step takes the echo file it now
/// names back. Control: both checks pass.
#[test]
fn an_echo_is_written_only_while_the_root_holds_before_and_after() {
    let dir = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(dir.path());
    let reader = drain_worker("drain-1");
    reader.challenge_step(&markers);
    let (check, queue) = scripted_root();
    let web = guarded("web-a").with_root_check(check);
    web.note_share(Instant::now(), &view_of(&web, &[&reader]));

    // Control: both checks pass, the echo is written.
    script(&queue, &[true, true]);
    web.echo_step(&markers);
    assert!(queue.lock().unwrap().is_empty(), "both checks ran");
    let written = markers.read_echo("web-a").unwrap();
    assert!(echo_in(&markers, &web, &reader).is_some(), "control");

    // MD: moved before the reads. The step stops at once: the file the path
    // names is left as it was. (Without the check, the step would read,
    // write, and then take the file back on the failed check after.)
    script(&queue, &[false]);
    web.echo_step(&markers);
    assert!(queue.lock().unwrap().is_empty());
    assert_eq!(
        markers.read_echo("web-a").unwrap(),
        written,
        "MD: nothing touched"
    );

    // MD2: moved during the step.
    script(&queue, &[true, false]);
    web.echo_step(&markers);
    assert!(queue.lock().unwrap().is_empty(), "both checks ran");
    assert_eq!(
        markers.read_echo("web-a").unwrap(),
        None,
        "MD2: the echo is taken back"
    );

    // The next good step writes again.
    script(&queue, &[true, true]);
    web.echo_step(&markers);
    assert!(echo_in(&markers, &web, &reader).is_some(), "written again");
}

/// The reader's echo reads are bounded by the same root checks: a path that
/// names another directory before or after the reads confirms nothing.
/// Control: both checks pass.
#[test]
fn echo_reads_count_only_while_the_root_holds_before_and_after() {
    let dir = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(dir.path());
    let (check, queue) = scripted_root();
    let reader = drain_worker("drain-1").with_root_check(check);
    let a = stager("web-a", "inc-a");
    reader.note_share(Instant::now(), &web_rows(&[("web-a", "inc-a")]));
    let me = reader.incarnation().to_owned();
    let (_, first) = rotate(&reader, &markers);
    write_echo(&markers, "web-a", "inc-a", &[(&me, &first)]);
    reader.confirm_step(&markers);
    let (_, second) = rotate(&reader, &markers);
    write_echo(&markers, "web-a", "inc-a", &[(&me, &second)]);

    script(&queue, &[false]);
    reader.confirm_step(&markers);
    assert!(!reader.confirms(&a), "moved before the reads");
    script(&queue, &[true, false]);
    reader.confirm_step(&markers);
    assert!(queue.lock().unwrap().is_empty(), "both checks ran");
    assert!(!reader.confirms(&a), "moved during the reads");
    script(&queue, &[true, true]);
    reader.confirm_step(&markers);
    assert!(reader.confirms(&a), "control");
}

/// A stopped reader removes its challenge file, and a stopped web replica
/// its echo file, only while it names its own incarnation.
#[test]
fn remove_challenge_and_echo_if_keep_another_processes_file() {
    let root = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(root.path());
    markers.write_challenge("drain-1", "inc-a c1").unwrap();
    markers.remove_challenge_if("drain-1", "inc-b").unwrap();
    assert!(markers.read_challenge("drain-1").unwrap().is_some());
    markers.remove_challenge_if("drain-1", "inc-a").unwrap();
    assert_eq!(markers.read_challenge("drain-1").unwrap(), None);
    assert!(markers.write_challenge("..", "inc c").is_err());
    assert_eq!(markers.read_challenge("a/b").unwrap(), None);
    markers.write_echo("web-a", "inc-a\ninc-r c1").unwrap();
    markers.remove_echo_if("web-a", "inc-b").unwrap();
    assert!(markers.read_echo("web-a").unwrap().is_some());
    markers.remove_echo_if("web-a", "inc-a").unwrap();
    assert_eq!(markers.read_echo("web-a").unwrap(), None);
    assert!(markers.write_echo("..", "inc").is_err());
    assert_eq!(markers.read_echo("a/b").unwrap(), None);
    assert_eq!(parse_marker("inc-a c1 extra"), None);
    assert_eq!(parse_marker(""), None);
    assert_eq!(parse_marker("inc-a"), Some(("inc-a", None)));
}

/// Mutant "prune without the loop" (review S2): passes run until one deletes
/// fewer than the limit, never more than the bound, and an error stops them.
#[tokio::test]
async fn the_prune_runs_passes_until_one_is_short() {
    let script = |counts: Vec<u64>| {
        let calls = Arc::new(Mutex::new(counts.into_iter()));
        let seen = Arc::new(AtomicI64::new(0));
        let (calls_in, seen_in) = (calls.clone(), seen.clone());
        let pass = move || {
            seen_in.fetch_add(1, Ordering::SeqCst);
            let next = calls_in.lock().unwrap().next().unwrap_or(0);
            std::future::ready(Ok::<u64, String>(next))
        };
        (pass, seen)
    };
    let (pass, seen) = script(vec![10, 10, 4, 10]);
    let pruned = prune_in_passes(10, 10, pass).await.unwrap();
    assert_eq!((pruned.stagers, pruned.passes), (24, 3));
    assert_eq!(seen.load(Ordering::SeqCst), 3);
    let (pass, _) = script(vec![10; 20]);
    let pruned = prune_in_passes(10, 4, pass).await.unwrap();
    assert_eq!((pruned.stagers, pruned.passes), (40, 4), "bounded per tick");
    let (pass, _) = script(vec![0]);
    assert_eq!(
        prune_in_passes(10, 0, pass).await.unwrap().passes,
        1,
        "at least one"
    );
    let failed = prune_in_passes(10, 5, || std::future::ready(Err::<u64, _>("down"))).await;
    assert_eq!(failed, Err("down"));
}

/// Review S2 of round 1: the default replica id is unique per call (per
/// process), and a long host name is cut so the process id and random part
/// survive.
#[test]
fn the_default_replica_id_is_unique_and_keeps_its_random_part() {
    let (a, b) = (default_replica_id(), default_replica_id());
    assert_ne!(a, b);
    assert!(is_marker_safe_id(&a));
    let long = replica_id_for(&"h".repeat(300), 1, "abcdef12");
    assert!(long.len() <= 128, "{}", long.len());
    assert!(long.ends_with("-1-abcdef12"), "{long}");
    assert_eq!(replica_id_for("host/a", 7, "0011aabb"), "host_a-7-0011aabb");
}

/// The drain guard's report logs the first unproven state at info,
/// escalates once after the grace, logs the move to proven, and logs a new
/// unproven state as a warning.
#[test]
fn report_absence_starts_escalates_once_and_logs_each_change() {
    let dir = tempfile::tempdir().unwrap();
    let worker = StageLiveness::with_thresholds(
        "drain-1".to_owned(),
        LivenessThresholds {
            share_grace: GRACE,
            ..LivenessThresholds::default()
        },
    )
    .with_role(StageLivenessRole::Drain);
    let t0 = Instant::now();
    let report = |at: Instant| worker.report_absence(at, &worker.snapshot(at));
    assert_eq!(report(t0), AbsenceLog::StartHeld, "no challenge yet");
    assert_eq!(report(t0), AbsenceLog::None);
    assert_eq!(report(t0 + GRACE), AbsenceLog::Escalated);
    assert_eq!(report(t0 + GRACE * 3), AbsenceLog::None, "once per hold");

    worker.share_step(&ShareMarkers::new(dir.path())).unwrap();
    assert_eq!(
        report(t0 + GRACE * 3),
        AbsenceLog::Proven,
        "no web row left unconfirmed"
    );
    worker.note_share(t0, &web_rows(&[("web-a", "inc-a")]));
    assert_eq!(report(t0 + GRACE * 3), AbsenceLog::Held);
    assert_eq!(report(t0 + GRACE * 4), AbsenceLog::Escalated);
}

/// Review S3 (round 3): a web stage replica with the absence guard reports
/// its own absence state from `report`, as the drain does. A web replica
/// without the guard (no counts attached) does not.
#[test]
fn a_web_reader_reports_its_absence_state() {
    let root = tempfile::tempdir().unwrap();
    let attach = FakeAttach::default();
    let web = stage_liveness_for_role(
        &attach,
        WriteBehindRole::Stage,
        "web-a".to_owned(),
        root.path().to_path_buf(),
        Arc::new(AtomicBool::new(true)),
    )
    .unwrap();
    let now = Instant::now();
    web.report(now);
    assert_eq!(
        web.report_absence(now, &web.snapshot(now)),
        AbsenceLog::None,
        "report already logged the start state"
    );

    let bare = guarded("web-b");
    bare.report(now);
    assert_eq!(
        bare.report_absence(now, &bare.snapshot(now)),
        AbsenceLog::StartHeld,
        "no guard: report never ran it"
    );
}

/// A fake stage that records what `stage_liveness_for_role` attaches.
#[derive(Default)]
struct FakeAttach {
    share_gates: Mutex<Vec<Arc<AtomicBool>>>,
    stagers: Mutex<Vec<StagerIdentity>>,
    guards: Mutex<Vec<ConfirmedStagers>>,
    /// The minimum staged age each attached guard was given.
    guard_ages: Mutex<Vec<Duration>>,
    roots: Mutex<Vec<std::path::PathBuf>>,
    refuse_guard: bool,
    /// The loss ruling hooks each attach got (drain role only).
    loss_rulings: Mutex<Vec<lore_postgres::store::fragment_write_behind::LossRulingHooks>>,
}

impl StageAttach for FakeAttach {
    fn share_gate(&self, gate: Arc<AtomicBool>) -> bool {
        self.share_gates.lock().unwrap().push(gate);
        true
    }

    fn stager(&self, stager: StagerIdentity) -> bool {
        self.stagers.lock().unwrap().push(stager);
        true
    }

    fn drain_absence_guard(
        &self,
        confirmed: ConfirmedStagers,
        min_staged_age: Duration,
    ) -> Option<Arc<DrainAbsenceCounts>> {
        if self.refuse_guard {
            return None;
        }
        self.guards.lock().unwrap().push(confirmed);
        self.guard_ages.lock().unwrap().push(min_staged_age);
        Some(Arc::new(DrainAbsenceCounts::default()))
    }

    fn loss_rulings(
        &self,
        hooks: lore_postgres::store::fragment_write_behind::LossRulingHooks,
    ) -> bool {
        self.loss_rulings.lock().unwrap().push(hooks);
        true
    }

    fn liveness(&self, root: &std::path::Path) -> (ShareMarkers, RootCheck) {
        self.roots.lock().unwrap().push(root.to_path_buf());
        (ShareMarkers::new(root), Arc::new(|| true))
    }
}

/// The drain path attaches the absence guard (and nothing else), whose
/// confirmations are this liveness's own, checked against the stage root.
/// Its marker thread writes the challenge. A second guard is refused.
#[test]
fn the_drain_role_attaches_the_drain_guard() {
    let root = tempfile::tempdir().unwrap();
    let attach = FakeAttach::default();
    let stop = Arc::new(AtomicBool::new(false));
    let liveness = stage_liveness_for_role(
        &attach,
        WriteBehindRole::Drain,
        "drain-1".to_owned(),
        root.path().to_path_buf(),
        stop.clone(),
    )
    .unwrap();
    assert_eq!(liveness.role(), StageLivenessRole::Drain);
    assert!(attach.share_gates.lock().unwrap().is_empty());
    assert!(attach.stagers.lock().unwrap().is_empty());
    assert_eq!(
        *attach.roots.lock().unwrap(),
        vec![root.path().to_path_buf()]
    );
    let confirmed = attach
        .guards
        .lock()
        .unwrap()
        .pop()
        .expect("the drain guard is attached");
    assert!(
        !confirmed(&stager("drain-1", liveness.incarnation())),
        "a drain confirms nobody on its own"
    );
    assert_eq!(
        *attach.guard_ages.lock().unwrap(),
        vec![lore_postgres::store::fragment_write_behind::MIN_STAGED_ABSENCE_AGE],
        "the drain guard gets the production minimum staged age, never zero"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while liveness.current_challenge().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        liveness.current_challenge().is_some(),
        "the marker thread writes the challenge"
    );
    assert_eq!(
        liveness.snapshot(Instant::now()).absence_counts,
        Some(AbsenceCounts::default()),
        "the guard's counts reach the snapshot"
    );
    // `stage resolve-lost`: the drain, and only the drain, gets the loss
    // ruling hooks. They report this liveness's identity and its own guard
    // state: healthy once it has a current challenge and no unconfirmed web
    // replica (none in view here).
    let hooks = attach
        .loss_rulings
        .lock()
        .unwrap()
        .pop()
        .expect("the drain attaches the loss ruling hooks");
    assert_eq!(hooks.reader.replica_id, "drain-1");
    assert_eq!(hooks.reader.incarnation, liveness.incarnation());
    assert_eq!(
        (hooks.guard_healthy)(),
        !liveness.absence_unproven(),
        "the hook is the guard's own state"
    );
    assert!(
        (hooks.guard_healthy)(),
        "a challenge and no unconfirmed peer"
    );
    let web = guarded("web-z");
    liveness.note_guard_view(&view_of(&liveness, &[&liveness, &web]));
    assert!(
        !(hooks.guard_healthy)(),
        "a fresh web replica the drain has not confirmed makes the guard unhealthy"
    );
    assert_eq!(
        (hooks.stager_echo)(&identity(&web)),
        Some(false),
        "no echo file yet"
    );
    std::fs::write(
        root.path().join("liveness").join("web-z.echo"),
        format!("{}\nother-reader nonce", web.incarnation()),
    )
    .unwrap();
    assert_eq!(
        (hooks.stager_echo)(&identity(&web)),
        Some(true),
        "a crashed stager's echo file in the drain's stage is evidence"
    );
    stop.store(true, Ordering::Relaxed);

    let refusing = FakeAttach {
        refuse_guard: true,
        ..FakeAttach::default()
    };
    let other = tempfile::tempdir().unwrap();
    assert!(
        stage_liveness_for_role(
            &refusing,
            WriteBehindRole::Drain,
            "drain-2".to_owned(),
            other.path().to_path_buf(),
            Arc::new(AtomicBool::new(true)),
        )
        .is_err()
    );
}

/// The web stage role attaches the share gate, held at start, its stager
/// identity (its own replica id and incarnation), and the absence guard,
/// which confirms this process itself and no one else yet.
#[test]
fn the_stage_role_attaches_the_share_gate_and_its_stager() {
    let root = tempfile::tempdir().unwrap();
    let attach = FakeAttach::default();
    let stop = Arc::new(AtomicBool::new(true));
    let liveness = stage_liveness_for_role(
        &attach,
        WriteBehindRole::Stage,
        "web-a".to_owned(),
        root.path().to_path_buf(),
        stop,
    )
    .unwrap();
    let gates = attach.share_gates.lock().unwrap();
    assert_eq!(gates.len(), 1);
    assert!(Arc::ptr_eq(&gates[0], &liveness.share_gate()));
    assert!(
        gates[0].load(Ordering::Acquire),
        "the share gate starts held"
    );
    assert_eq!(
        *attach.stagers.lock().unwrap(),
        vec![stager("web-a", liveness.incarnation())]
    );
    let confirmed = attach
        .guards
        .lock()
        .unwrap()
        .pop()
        .expect("the web-side absence guard is attached");
    assert!(
        confirmed(&stager("web-a", liveness.incarnation())),
        "itself"
    );
    assert!(!confirmed(&stager("web-b", "inc-b")), "a peer not yet");
    assert_eq!(
        *attach.guard_ages.lock().unwrap(),
        vec![lore_postgres::store::fragment_write_behind::MIN_STAGED_ABSENCE_AGE],
        "the web-side guard gets the production minimum staged age, never zero"
    );
    assert!(liveness.snapshot(Instant::now()).absence_counts.is_some());
    assert!(
        attach.loss_rulings.lock().unwrap().is_empty(),
        "a web replica never carries out loss rulings"
    );
}

/// `stage resolve-lost` echo evidence: only an echo file in the reader's own
/// stage whose FIRST line is the stager's exact incarnation counts, and only
/// while the root check holds before and after the read.
#[test]
fn stager_echo_evidence_needs_the_exact_incarnation_and_an_intact_root() {
    let root = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(root.path());
    let intact: RootCheck = Arc::new(|| true);
    let web = stager("web-a", "inc-a");
    assert_eq!(stager_echo_evidence(&markers, &intact, &web), Some(false));
    markers.write_echo("web-a", "inc-b\ninc-r nonce").unwrap();
    assert_eq!(
        stager_echo_evidence(&markers, &intact, &web),
        Some(false),
        "a restart under the same replica id replaced the old incarnation's echo"
    );
    markers.write_echo("web-a", "inc-r nonce\ninc-a").unwrap();
    assert_eq!(
        stager_echo_evidence(&markers, &intact, &web),
        Some(false),
        "the incarnation must be the first line, not a reader line"
    );
    markers.write_echo("web-a", "inc-a\ninc-r nonce").unwrap();
    assert_eq!(stager_echo_evidence(&markers, &intact, &web), Some(true));
    let moved: RootCheck = Arc::new(|| false);
    assert_eq!(
        stager_echo_evidence(&markers, &moved, &web),
        None,
        "a failed root check decides nothing"
    );
    // The root check runs before AND after: fail only the second call.
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = calls.clone();
    let after: RootCheck = Arc::new(move || counter.fetch_add(1, Ordering::SeqCst) == 0);
    assert_eq!(stager_echo_evidence(&markers, &after, &web), None);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        stager_echo_evidence(&markers, &intact, &stager("../web-a", "inc-a")),
        Some(false),
        "an id unsafe as a file name is never read"
    );
}

/// Review B S1 (round 5): the production `StageAttach` forwards the age
/// `stage_liveness_for_role` chose to the handle unchanged. No unit test
/// builds a real write-behind handle (it needs the governed route and a live
/// database), so this pins the forward in the source: the impl body passes
/// its `min_staged_age` parameter and names no other age.
#[test]
fn the_production_attach_forwards_the_minimum_staged_age() {
    let source = include_str!("../../src/fragment_write_behind.rs");
    let start = source
        .find("impl StageAttach for FragmentWriteBehindHandle {")
        .expect("the production impl");
    let rest = &source[start..];
    let end = rest.find("\n}\n").expect("the impl ends");
    let body = &rest[..end];
    let forward = body
        .find("fn drain_absence_guard(")
        .map(|at| &body[at..])
        .expect("the production drain_absence_guard");
    let forward = &forward[..forward.find("\n    }").expect("the fn ends")];
    let calls: String = forward.split_whitespace().collect();
    assert!(
        calls.contains("self.attach_drain_absence_guard(confirmed,min_staged_age)"),
        "the impl forwards its own min_staged_age: {forward}"
    );
    for other in [
        "Duration::",
        "MIN_STAGED_ABSENCE_AGE",
        "from_secs",
        "from_millis",
    ] {
        assert!(
            !forward.contains(other),
            "the impl names no age of its own ({other}): {forward}"
        );
    }
}

// ---------------------------------------------------------------------------
// WP-115 drain guard, review B1 of round 4: the stage liveness files and the
// staged reads go through the stage tree pinned at open, never through a
// path that a symlink or a mount can redirect. Linux only: elsewhere the root
// check is always false.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod pinned_tree {
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;

    use bytes::Bytes;
    use lore_postgres::store::write_behind::StagedRead;
    use lore_postgres::store::write_behind::WriteBehindError;
    use lore_postgres::store::write_behind::WriteBehindSettings;
    use lore_postgres::store::write_behind::WriteBehindStage;
    use lore_postgres::store::write_behind::WriteBehindWatermarks;
    use lore_server::stage_liveness::*;

    use super::drain_worker;
    use super::guarded;
    use super::identity;
    use super::view_of;

    /// Rounds that confirm a stager in one shared directory (the control
    /// below confirms within them).
    const ROUNDS: u64 = CHALLENGE_EVERY_STEPS * 6;

    fn settings(root: &Path) -> WriteBehindSettings {
        WriteBehindSettings {
            root: root.to_path_buf(),
            watermarks: WriteBehindWatermarks {
                low_bytes: 10_000_000,
                high_bytes: 20_000_000,
                hard_bytes: 30_000_000,
                low_count: 1_000,
                high_count: 2_000,
                hard_count: 3_000,
                min_free_bytes: 0,
            },
            drain_stale_after: std::time::Duration::from_secs(60),
            sample_interval: std::time::Duration::from_secs(3_600),
            stage_io_wait: lore_postgres::store::write_behind::DEFAULT_STAGE_IO_WAIT,
            stage_read_wait: lore_postgres::store::write_behind::DEFAULT_STAGE_READ_WAIT,
            drain_reserve: Default::default(),
        }
    }

    fn open(root: &Path) -> Arc<WriteBehindStage> {
        match WriteBehindStage::open(settings(root)) {
            Ok(stage) => stage,
            Err(error) => panic!("the stage opens: {error}"),
        }
    }

    fn refused(root: &Path) -> Option<WriteBehindError> {
        WriteBehindStage::open(settings(root)).err()
    }

    /// A process's stage liveness on `stage`, as production wires it: the
    /// pinned `liveness/` and the pinned tree check.
    fn wired(
        liveness: StageLiveness,
        stage: &Arc<WriteBehindStage>,
    ) -> (StageLiveness, ShareMarkers) {
        let check = stage.clone();
        (
            liveness.with_root_check(Arc::new(move || check.pinned_tree_intact())),
            ShareMarkers::pinned(stage.liveness_dir()),
        )
    }

    /// Run `ROUNDS` cell rounds; the round in which `drain` confirmed `web`.
    fn confirm_round(
        drain: (&StageLiveness, &ShareMarkers),
        web: (&StageLiveness, &ShareMarkers),
    ) -> Option<u64> {
        (0..ROUNDS).find(|_| {
            // cell_round, except that a failed step (a liveness file call
            // refused under an unpinnable tree) is not a test failure.
            let now = std::time::Instant::now();
            let all = [drain.0, web.0];
            let _ = drain.0.share_step(drain.1);
            web.0.note_share(now, &view_of(web.0, &all));
            let _ = web.0.share_step(web.1);
            for process in all {
                process.note_share(now, &view_of(process, &all));
            }
            drain.0.confirms(&identity(web.0))
        })
    }

    fn key(hash: &[u8; 32], epoch: i64) -> String {
        format!("{}.s{epoch}", hex::encode(hash))
    }

    /// Control: two processes on one root, wired through their pinned trees,
    /// confirm. Without this, every "never confirms" below could pass on a
    /// guard that never confirms anything.
    #[test]
    fn processes_on_one_pinned_tree_confirm() {
        let root = tempfile::tempdir().unwrap();
        let (drain_stage, web_stage) = (open(root.path()), open(root.path()));
        assert!(drain_stage.pinned_tree_intact() && web_stage.pinned_tree_intact());
        let (drain, drain_markers) = wired(drain_worker("drain-1"), &drain_stage);
        let (web, web_markers) = wired(guarded("web-a"), &web_stage);
        assert!(drain_markers.is_pinned());
        let round = confirm_round((&drain, &drain_markers), (&web, &web_markers));
        assert!(round.is_some(), "one shared pinned tree confirms");
    }

    /// Probe L1 before boot: data roots A and B differ, and `<A>/liveness`
    /// and `<B>/liveness` are already symlinks to one directory S. The stages
    /// open (`liveness/` is pinned on first use), but every liveness file
    /// call and root check fails, nothing is written into S, and the drain on
    /// B never confirms web-a on A. A symlinked `staged` refuses to start.
    #[test]
    fn a_symlinked_liveness_dir_before_open_never_confirms() {
        let (a, b, shared) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        std::os::unix::fs::symlink(shared.path(), a.path().join("liveness")).unwrap();
        std::os::unix::fs::symlink(shared.path(), b.path().join("liveness")).unwrap();
        let (stage_a, stage_b) = (open(a.path()), open(b.path()));
        assert!(!stage_a.pinned_tree_intact() && !stage_b.pinned_tree_intact());
        assert!(stage_a.liveness_dir().read("x.present", 16).is_err());
        let (drain, drain_markers) = wired(drain_worker("drain-b"), &stage_b);
        let (web, web_markers) = wired(guarded("web-a"), &stage_a);
        assert_eq!(
            confirm_round((&drain, &drain_markers), (&web, &web_markers)),
            None,
            "the drain on B confirmed web-a on A through a shared liveness symlink"
        );
        assert!(
            std::fs::read_dir(shared.path()).unwrap().next().is_none(),
            "nothing was written through the symlink"
        );
        let staged = tempfile::tempdir().unwrap();
        let c = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(staged.path(), c.path().join("staged")).unwrap();
        assert_eq!(
            refused(c.path()),
            Some(WriteBehindError::StageTreeUnconfined),
            "a symlinked staged dir refuses too"
        );
    }

    /// Probe L1 ported (review B1 of round 4): split data roots A and B, both
    /// opened on real directories, then `<A>/liveness` and `<B>/liveness` are
    /// replaced by symlinks to one directory S. The drain on B never confirms
    /// web-a on A: the files go through each process's pinned `liveness/`
    /// (two different directories), and the root checks fail.
    #[test]
    fn a_shared_liveness_symlink_after_open_never_confirms_split_data_dirs() {
        let (a, b, shared) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        let (stage_a, stage_b) = (open(a.path()), open(b.path()));
        assert!(
            stage_a.pinned_tree_intact() && stage_b.pinned_tree_intact(),
            "control: intact (this also pins liveness/)"
        );
        for dir in [a.path(), b.path()] {
            std::fs::rename(dir.join("liveness"), dir.join("liveness.moved")).unwrap();
            std::os::unix::fs::symlink(shared.path(), dir.join("liveness")).unwrap();
        }
        assert!(!stage_a.pinned_tree_intact() && !stage_b.pinned_tree_intact());
        let (drain, drain_markers) = wired(drain_worker("drain-b"), &stage_b);
        let (web, web_markers) = wired(guarded("web-a"), &stage_a);
        assert_eq!(
            confirm_round((&drain, &drain_markers), (&web, &web_markers)),
            None,
            "the drain on B confirmed web-a on A through a shared liveness symlink"
        );
        assert!(drain.current_challenge().is_none(), "no current challenge");
        // The path-based files of the review probe, with the real pinned
        // check: still nothing.
        let (drain_path, web_path) = (
            drain_worker("drain-b2").with_root_check({
                let s = stage_b.clone();
                Arc::new(move || s.pinned_tree_intact())
            }),
            guarded("web-a2").with_root_check({
                let s = stage_a.clone();
                Arc::new(move || s.pinned_tree_intact())
            }),
        );
        let (pb, pa) = (ShareMarkers::new(b.path()), ShareMarkers::new(a.path()));
        assert_eq!(confirm_round((&drain_path, &pb), (&web_path, &pa)), None);
    }

    /// One root R, both processes opened on it, then `<R>/liveness` is
    /// replaced by a new directory. Their pinned `liveness/` is still one
    /// directory, but the tree is no longer the one pinned at open, so
    /// nothing confirms (kills a root check that always holds).
    #[test]
    fn a_replaced_liveness_dir_fails_the_root_check_and_never_confirms() {
        let root = tempfile::tempdir().unwrap();
        let (drain_stage, web_stage) = (open(root.path()), open(root.path()));
        assert!(
            drain_stage.pinned_tree_intact() && web_stage.pinned_tree_intact(),
            "control: intact (this also pins liveness/)"
        );
        std::fs::rename(
            root.path().join("liveness"),
            root.path().join("liveness.moved"),
        )
        .unwrap();
        std::fs::create_dir(root.path().join("liveness")).unwrap();
        assert!(!drain_stage.pinned_tree_intact());
        let (drain, drain_markers) = wired(drain_worker("drain-1"), &drain_stage);
        let (web, web_markers) = wired(guarded("web-a"), &web_stage);
        assert_eq!(
            confirm_round((&drain, &drain_markers), (&web, &web_markers)),
            None
        );
    }

    /// One root R, both processes opened on it, then `<R>/staged` is
    /// replaced by a new directory. The tree check fails, nothing confirms,
    /// and a staged read is `Unavailable`, never `Absent`, even for a file
    /// staged before the swap.
    #[tokio::test]
    async fn a_replaced_staged_dir_fails_the_root_check_and_no_read_is_absent() {
        let root = tempfile::tempdir().unwrap();
        let (drain_stage, web_stage) = (open(root.path()), open(root.path()));
        let hash = [0x5a; 32];
        web_stage
            .stage(&hash, 1, &key(&hash, 1), &Bytes::from_static(b"payload"))
            .await
            .expect("staged before the swap");
        assert!(
            matches!(
                drain_stage.read_staged(&hash, 1, &key(&hash, 1)).await,
                StagedRead::Found(_)
            ),
            "control: found before the swap"
        );
        std::fs::rename(root.path().join("staged"), root.path().join("staged.moved")).unwrap();
        std::fs::create_dir(root.path().join("staged")).unwrap();
        assert!(!drain_stage.pinned_tree_intact());
        for (what, epoch) in [("a staged file", 1), ("a missing file", 2)] {
            let read = drain_stage
                .read_staged(&hash, epoch, &key(&hash, epoch))
                .await;
            assert!(
                matches!(
                    read,
                    StagedRead::Unavailable(WriteBehindError::RootDeviceChanged)
                ),
                "{what}: {read:?}"
            );
        }
        let (drain, drain_markers) = wired(drain_worker("drain-1"), &drain_stage);
        let (web, web_markers) = wired(guarded("web-a"), &web_stage);
        assert_eq!(
            confirm_round((&drain, &drain_markers), (&web, &web_markers)),
            None
        );
    }

    /// A symlink at a fan-out directory under `staged/` is a refusal, never
    /// a read through it and never a miss: staged reads open beneath the
    /// pinned `staged/` with no symlink anywhere. A path-based read would
    /// find the file through the symlink, or miss in the other directory.
    #[tokio::test]
    async fn a_symlinked_fanout_dir_is_unavailable_not_found_nor_absent() {
        let (root, elsewhere) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let stage = open(root.path());
        let hash = [0xab; 32];
        let key1 = key(&hash, 1);
        std::fs::create_dir_all(elsewhere.path().join("ab")).unwrap();
        std::fs::write(elsewhere.path().join("ab").join(&key1), b"elsewhere").unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), root.path().join("staged/ab")).unwrap();
        for (what, epoch) in [("a file through the symlink", 1), ("a miss through it", 2)] {
            let read = stage.read_staged(&hash, epoch, &key(&hash, epoch)).await;
            assert!(
                matches!(read, StagedRead::Unavailable(WriteBehindError::Io { .. })),
                "{what}: {read:?}"
            );
        }
        // Control: a real miss in the pinned `staged/` is absent.
        let other = [0xcd; 32];
        assert!(matches!(
            stage.read_staged(&other, 1, &key(&other, 1)).await,
            StagedRead::Absent
        ));
    }

    /// Unmounts on drop, so a failed assertion leaves no mount behind.
    struct Mounted(PathBuf);

    impl Mounted {
        fn bind(source: &Path, target: &Path) -> Self {
            let status = std::process::Command::new("mount")
                .arg("--bind")
                .arg(source)
                .arg(target)
                .status()
                .expect("run mount");
            assert!(
                status.success(),
                "mount --bind needs CAP_SYS_ADMIN (run in a privileged container)"
            );
            Self(target.to_path_buf())
        }
    }

    impl Drop for Mounted {
        fn drop(&mut self) {
            let _ = std::process::Command::new("umount")
                .arg("-l")
                .arg(&self.0)
                .status();
        }
    }

    /// Review B1, bind-mount variant: one shared root R; a host-local bind
    /// mount on `<R>/staged` only (data diverted, root and liveness shared).
    /// A process opened after the mount refuses to start. Processes opened
    /// before it fail the tree check: nothing confirms, a staged read of a
    /// missing file is `Unavailable` (never `Absent`), and staging refuses.
    /// The same for a bind mount on `<R>/liveness`, except that a process
    /// opened after it starts and then cannot pin `liveness/`.
    #[tokio::test]
    #[ignore = "needs CAP_SYS_ADMIN for a bind mount; run in a privileged Linux container"]
    async fn a_bind_mount_on_staged_or_liveness_never_confirms_nor_reads_absent() {
        for subdir in ["staged", "liveness"] {
            let (root, diverted) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let (drain_stage, web_stage) = (open(root.path()), open(root.path()));
            let hash = [0x77; 32];
            assert!(
                matches!(
                    drain_stage.read_staged(&hash, 1, &key(&hash, 1)).await,
                    StagedRead::Absent
                ),
                "control: a real miss before the mount is absent"
            );
            assert!(
                drain_stage.pinned_tree_intact() && web_stage.pinned_tree_intact(),
                "control: the tree is intact (this also pins liveness/)"
            );
            let _mount = Mounted::bind(diverted.path(), &root.path().join(subdir));
            if subdir == "staged" {
                assert_eq!(
                    refused(root.path()),
                    Some(WriteBehindError::StageTreeUnconfined),
                    "a process opened after the mount refuses to start"
                );
            } else {
                let late = open(root.path());
                assert!(
                    !late.pinned_tree_intact() && late.liveness_dir().read("x", 16).is_err(),
                    "a process opened after the mount cannot pin liveness/"
                );
            }
            assert!(
                !drain_stage.pinned_tree_intact() && !web_stage.pinned_tree_intact(),
                "{subdir}: the tree check fails"
            );
            let (drain, drain_markers) = wired(drain_worker("drain-1"), &drain_stage);
            let (web, web_markers) = wired(guarded("web-a"), &web_stage);
            assert_eq!(
                confirm_round((&drain, &drain_markers), (&web, &web_markers)),
                None,
                "{subdir}: nothing confirms"
            );
            if subdir == "staged" {
                let read = drain_stage.read_staged(&hash, 1, &key(&hash, 1)).await;
                assert!(
                    matches!(read, StagedRead::Unavailable(_)),
                    "a miss under a bind-mounted staged dir is never absent: {read:?}"
                );
                assert!(
                    web_stage
                        .stage(&hash, 3, &key(&hash, 3), &Bytes::from_static(b"payload"))
                        .await
                        .is_err(),
                    "staging refuses under a bind-mounted staged dir"
                );
            }
        }
    }
}

/// Review A nit (round 4): the real view lists this process too. It is
/// neither a checker (its echo file carries no line for its own challenge)
/// nor a candidate (it confirms itself anyway, so it never holds the "not
/// confirmed yet" signal).
#[test]
fn a_web_replica_neither_echoes_nor_waits_for_itself() {
    let dir = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(dir.path());
    let drain = drain_worker("drain-1");
    let web = guarded("web-a");
    let mut with_self = view_of(&web, &[&drain]);
    with_self.peers.push(StagePeerProgress {
        replica_id: web.replica_id().to_owned(),
        record: record(web.incarnation(), 1, 0),
        published_micros: CLOCK,
        role: StageLivenessRole::Stage,
    });
    drain.share_step(&markers).unwrap();
    web.note_share(Instant::now(), &with_self);
    web.share_step(&markers).unwrap();
    assert!(web.current_challenge().is_some(), "control: a challenge");
    assert!(
        !web.absence_unproven(),
        "no fresh web peer but itself: nothing is unconfirmed"
    );
    let echo = markers.read_echo("web-a").unwrap().expect("an echo file");
    let lines: Vec<&str> = echo.lines().collect();
    assert_eq!(lines.first(), Some(&web.incarnation()));
    assert!(
        lines
            .iter()
            .skip(1)
            .all(|line| !line.starts_with(web.incarnation())),
        "no echo line for its own challenge: {echo}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with(drain.incarnation())),
        "control: the drain's challenge is echoed: {echo}"
    );
}

/// Review B S1 (round 4): the minimum staged age before a confirmed miss
/// reads as absent spans several challenge rotations, so a two-way sync
/// that keeps up with the echo has carried a staged file long before.
#[test]
fn the_minimum_staged_age_spans_several_challenge_rotations() {
    let rotation = PROBE_INTERVAL * u32::try_from(CHALLENGE_EVERY_STEPS).unwrap();
    assert!(
        lore_postgres::store::fragment_write_behind::MIN_STAGED_ABSENCE_AGE >= rotation * 5,
        "at least five rotations"
    );
}
