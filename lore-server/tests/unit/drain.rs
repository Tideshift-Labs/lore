// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, CR-009): the graceful-drain tests, moved out of the
//! inline `drain::tests` module when upstream set `[lib] test = false`.

mod rpc_tests;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lore_server::drain::ConnectionRegistry;
use lore_server::drain::DrainConnection;
use lore_server::drain::DrainState;
use lore_server::drain::count_termination_signals;
use lore_server::drain::lame_duck_then_shutdown;
use lore_server::drain::run_drain;

/// A `DrainConnection` double whose frame count and closed flag are
/// backed by shared `Arc`s, so a clone kept by the test observes the same
/// state as the clone handed to the registry (which is what `run_drain`
/// acts on via `snapshot()`).
#[derive(Clone)]
struct MockConn {
    id: usize,
    frames: std::sync::Arc<AtomicU64>,
    close_calls: std::sync::Arc<AtomicU64>,
}

impl MockConn {
    fn new(id: usize) -> Self {
        Self {
            id,
            frames: std::sync::Arc::new(AtomicU64::new(0)),
            close_calls: std::sync::Arc::new(AtomicU64::new(0)),
        }
    }

    fn advance(&self, frames: u64) {
        self.frames.fetch_add(frames, Ordering::Relaxed);
    }

    fn is_closed(&self) -> bool {
        self.close_call_count() > 0
    }

    fn close_call_count(&self) -> u64 {
        self.close_calls.load(Ordering::Relaxed)
    }
}

impl DrainConnection for MockConn {
    fn stable_id(&self) -> usize {
        self.id
    }

    fn stream_frame_count(&self) -> u64 {
        self.frames.load(Ordering::Relaxed)
    }

    fn drain_close(&self) {
        self.close_calls.fetch_add(1, Ordering::Relaxed);
    }
}

// --- ConnectionRegistry mechanics -------------------------------------

#[test]
fn register_and_drop_guard_updates_active_count() {
    let registry = ConnectionRegistry::<MockConn>::new("public");
    assert_eq!(registry.active(), 0);

    let guard = registry.register(MockConn::new(1));
    assert_eq!(registry.active(), 1);

    drop(guard);
    assert_eq!(registry.active(), 0);
}

#[test]
fn snapshot_contains_every_registered_connection() {
    let registry = ConnectionRegistry::<MockConn>::new("public");
    let _guard_a = registry.register(MockConn::new(1));
    let _guard_b = registry.register(MockConn::new(2));

    let mut ids: Vec<usize> = registry.snapshot().iter().map(|c| c.stable_id()).collect();
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2]);
}

#[test]
fn snapshot_drops_entries_once_their_guard_is_dropped() {
    let registry = ConnectionRegistry::<MockConn>::new("public");
    let guard = registry.register(MockConn::new(1));
    assert_eq!(registry.snapshot().len(), 1);

    drop(guard);
    assert!(registry.snapshot().is_empty());
}

#[test]
fn begin_drain_flips_is_draining() {
    let registry = ConnectionRegistry::<MockConn>::new("public");
    assert!(!registry.is_draining());

    registry.begin_drain();
    assert!(registry.is_draining());
}

#[test]
fn drain_state_aggregates_active_counts_across_registries() {
    // DrainState::add_registry only accepts the concrete
    // QuinnConnectionRegistry (Arc<ConnectionRegistry<quinn::Connection>>),
    // and a real quinn::Connection can only come from a live handshake.
    // Poke the private `count` field directly (this test module is a
    // child of `drain`, so it shares field access) to simulate active
    // connections without a live endpoint.
    let state = DrainState::new();
    let public = lore_server::drain::QuinnConnectionRegistry::new("public");
    let internal = lore_server::drain::QuinnConnectionRegistry::new("internal");
    public.count.store(2, Ordering::Relaxed);
    internal.count.store(5, Ordering::Relaxed);

    state.add_registry(public.clone());
    state.add_registry(internal.clone());

    assert_eq!(state.total_active(), 7);
    let mut counts = state.endpoint_counts();
    counts.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        counts,
        vec![("internal".to_string(), 5), ("public".to_string(), 2)]
    );
}

#[test]
fn drain_state_begin_drain_flips_is_draining() {
    let state = DrainState::new();
    assert!(!state.is_draining());

    state.begin_drain();
    assert!(state.is_draining());
}

// --- pending handshakes ------------------------------------------------

#[test]
fn handshake_guard_drop_decrements_pending() {
    let registry = ConnectionRegistry::<MockConn>::new("public");
    assert_eq!(registry.pending(), 0);

    let guard = registry.begin_handshake();
    assert_eq!(registry.pending(), 1);

    drop(guard);
    assert_eq!(registry.pending(), 0);
}

#[test]
fn multiple_pending_handshakes_are_counted_independently() {
    let registry = ConnectionRegistry::<MockConn>::new("public");
    let first = registry.begin_handshake();
    let second = registry.begin_handshake();
    assert_eq!(registry.pending(), 2);

    drop(first);
    assert_eq!(
        registry.pending(),
        1,
        "dropping one guard must not affect the other"
    );

    drop(second);
    assert_eq!(registry.pending(), 0);
}

#[test]
fn drain_state_total_active_includes_pending_handshakes() {
    // Same private-field access rationale as
    // drain_state_aggregates_active_counts_across_registries: a real
    // quinn::Connection handshake can't be simulated without a live
    // endpoint, so drive the counters directly.
    let state = DrainState::new();
    let registry = lore_server::drain::QuinnConnectionRegistry::new("public");
    registry.count.store(2, Ordering::Relaxed);
    registry.pending_handshakes.store(3, Ordering::Relaxed);
    state.add_registry(registry.clone());

    assert_eq!(
        state.total_active(),
        5,
        "total_active must sum established (2) and pending-handshake (3) connections"
    );
    assert_eq!(
        state.endpoint_counts(),
        vec![("public".to_string(), 2)],
        "endpoint_counts reports established connections only, not pending handshakes"
    );
}

#[tokio::test(start_paused = true)]
async fn wait_idle_resolves_once_active_count_returns_to_zero() {
    // Same constraint as above: simulate a guard's register/deregister
    // lifecycle on the concrete QuinnConnectionRegistry by driving its
    // private `count` field directly, since a real quinn::Connection
    // guard needs a live handshake.
    let state = DrainState::new();
    let registry = lore_server::drain::QuinnConnectionRegistry::new("public");
    registry.count.store(1, Ordering::Relaxed);
    state.add_registry(registry.clone());

    let state_for_task = state.clone();
    let handle = lore_base::lore_spawn!(async move { state_for_task.wait_idle().await });

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !handle.is_finished(),
        "wait_idle must not resolve while an endpoint still reports an active connection"
    );

    registry.count.store(0, Ordering::Relaxed);

    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("wait_idle should resolve once total_active() reaches zero")
        .expect("wait_idle task panicked");
}

// --- run_drain -----------------------------------------------------

#[tokio::test(start_paused = true)]
async fn run_drain_completes_immediately_with_no_active_connections() {
    let registry = ConnectionRegistry::<MockConn>::new("public");

    tokio::time::timeout(Duration::from_secs(2), run_drain(&registry, None, None))
        .await
        .expect("run_drain should return promptly when nothing is active");

    assert!(registry.is_draining());
}

#[tokio::test(start_paused = true)]
async fn run_drain_waits_for_active_connection_then_completes_on_guard_drop() {
    let registry = ConnectionRegistry::<MockConn>::new("public");
    let guard = registry.register(MockConn::new(1));

    let registry_for_task = registry.clone();
    let handle = lore_base::lore_spawn!(async move {
        run_drain(&registry_for_task, None, None).await;
    });

    // Let several drain ticks pass with the connection still active; the
    // task must not have completed.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        !handle.is_finished(),
        "run_drain must keep waiting while a connection is still registered"
    );

    drop(guard);

    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("run_drain should notice the guard drop and return")
        .expect("run_drain task panicked");
}

#[tokio::test(start_paused = true)]
async fn run_drain_bounded_mode_returns_at_deadline_with_connection_still_active() {
    let registry = ConnectionRegistry::<MockConn>::new("public");
    let _guard = registry.register(MockConn::new(1)); // never dropped

    tokio::time::timeout(
        Duration::from_secs(10),
        run_drain(&registry, Some(Duration::from_secs(3)), None),
    )
    .await
    .expect("run_drain should return once its own drain_timeout elapses");

    assert_eq!(
        registry.active(),
        1,
        "run_drain only stops waiting at the deadline; closing is the caller's job"
    );
}

#[tokio::test(start_paused = true)]
async fn run_drain_stall_guard_closes_only_the_stalled_connection() {
    let registry = ConnectionRegistry::<MockConn>::new("public");
    let stalled = MockConn::new(1);
    let progressing = MockConn::new(2);
    let _stalled_guard = registry.register(stalled.clone());
    let _progressing_guard = registry.register(progressing.clone());

    // Keep the healthy connection's frame count moving faster than the
    // stall window so it never looks wedged.
    let progressing_for_bumper = progressing.clone();
    let bumper = lore_base::lore_spawn!(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(500));
        loop {
            ticker.tick().await;
            progressing_for_bumper.advance(1);
        }
    });

    // Bounded so the test terminates even though neither guard is
    // dropped (drain_close only flags the mock; removing it from the
    // registry is the connection handler's job in production).
    tokio::time::timeout(
        Duration::from_secs(10),
        run_drain(
            &registry,
            Some(Duration::from_secs(6)),
            Some(Duration::from_secs(2)),
        ),
    )
    .await
    .expect("run_drain should return at its bounded deadline");

    bumper.abort();

    assert!(
        stalled.is_closed(),
        "a connection with no stream-frame progress for the stall window must be drain_close()d"
    );
    assert!(
        !progressing.is_closed(),
        "a connection whose frame count keeps advancing must not be closed"
    );
}

#[tokio::test(start_paused = true)]
async fn run_drain_without_stall_timeout_never_force_closes() {
    let registry = ConnectionRegistry::<MockConn>::new("public");
    let wedged = MockConn::new(1);
    let _guard = registry.register(wedged.clone());

    tokio::time::timeout(
        Duration::from_secs(10),
        run_drain(&registry, Some(Duration::from_secs(8)), None),
    )
    .await
    .expect("run_drain should return once its bounded deadline elapses");

    assert!(
        !wedged.is_closed(),
        "stall_timeout = None must never force-close a connection, no matter how long it's wedged"
    );
}

#[tokio::test(start_paused = true)]
async fn run_drain_stall_guard_closes_at_most_once_per_stall_window() {
    // Regression test for the re-close-every-tick bug: a permanently
    // wedged connection must be re-closed roughly once per stall_timeout
    // window, not on every DRAIN_TICK. With stall_timeout = 2s over a 5s
    // bounded drain, the stall condition is observed at t=2s and t=4s
    // (DRAIN_TICK = 1s ticks land on whole seconds) -> exactly 2 calls.
    // Without resetting the progress-window timestamp after closing, the
    // buggy behavior would call drain_close() at t=2s, 3s, and 4s (3
    // calls) since duration-since-last-progress only grows.
    let registry = ConnectionRegistry::<MockConn>::new("public");
    let wedged = MockConn::new(1);
    let _guard = registry.register(wedged.clone());

    tokio::time::timeout(
        Duration::from_secs(10),
        run_drain(
            &registry,
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(2)),
        ),
    )
    .await
    .expect("run_drain should return at its bounded deadline");

    assert_eq!(
        wedged.close_call_count(),
        2,
        "expected exactly one drain_close() per elapsed stall window, not one per tick"
    );
}

#[tokio::test(start_paused = true)]
async fn run_drain_waits_for_pending_handshake_even_with_zero_registered_connections() {
    // Closes the handshake-window race: a connection that passed the
    // accept-loop draining check but hasn't registered yet must not be
    // cut by the endpoint close that follows the drain.
    let registry = ConnectionRegistry::<MockConn>::new("public");
    let handshake_guard = registry.begin_handshake();
    assert_eq!(registry.active(), 0);
    assert_eq!(registry.pending(), 1);

    let registry_for_task = registry.clone();
    let handle = lore_base::lore_spawn!(async move {
        run_drain(&registry_for_task, None, None).await;
    });

    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        !handle.is_finished(),
        "run_drain must keep waiting while a handshake is pending, even with zero \
         registered connections"
    );

    drop(handshake_guard);

    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("run_drain should notice the pending handshake clear and return")
        .expect("run_drain task panicked");
}

// --- gRPC/HTTP shutdown-signal composition --------------------------
//
// `server.rs::launch_grpc_server` (and `launch_http_server`, the
// pre-existing pattern it mirrors) build the tonic/axum shutdown future
// inline as `shutdown_rx.wait_for(|&v| v).await; if graceful_drain {
// drain_state.wait_idle().await; }` — there is no free fn to call
// directly, and pinning the "active connections keep it pending" case
// needs the same private `count` poke on `QuinnConnectionRegistry` used
// above, which is only reachable from a `drain`-module test. `shutdown_signal`
// below is a same-shape, test-only mirror (not a call into server.rs) kept
// behavior-identical to the two call sites; a future edit to either that
// changes the composition itself won't be caught here, only a drift in
// `wait_idle`/`total_active` semantics will.

async fn shutdown_signal(
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    drain_state: std::sync::Arc<DrainState>,
    graceful_drain: bool,
) {
    let _ = shutdown_rx.wait_for(|&v| v).await;
    if graceful_drain {
        drain_state.wait_idle().await;
    }
}

#[tokio::test(start_paused = true)]
async fn shutdown_signal_does_not_resolve_before_shutdown_fires() {
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let state = DrainState::new();

    let handle = lore_base::lore_spawn!(shutdown_signal(rx, state, true));

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !handle.is_finished(),
        "must wait for the shutdown watch to fire before considering the drain state at all"
    );

    handle.abort();
}

#[tokio::test(start_paused = true)]
async fn shutdown_signal_resolves_immediately_when_graceful_drain_is_off() {
    let (tx, rx) = tokio::sync::watch::channel(false);
    let state = DrainState::new();
    let registry = lore_server::drain::QuinnConnectionRegistry::new("public");
    registry.count.store(3, Ordering::Relaxed);
    state.add_registry(registry);

    tx.send(true).expect("receiver still alive");

    tokio::time::timeout(Duration::from_secs(1), shutdown_signal(rx, state, false))
        .await
        .expect(
            "graceful_drain=false must resolve on the shutdown signal alone, ignoring \
             active connections entirely",
        );
}

#[tokio::test(start_paused = true)]
async fn shutdown_signal_with_graceful_drain_and_zero_active_resolves_promptly() {
    let (tx, rx) = tokio::sync::watch::channel(false);
    let state = DrainState::new();
    tx.send(true).expect("receiver still alive");

    tokio::time::timeout(Duration::from_secs(1), shutdown_signal(rx, state, true))
        .await
        .expect(
            "graceful_drain=true with nothing active must resolve promptly, not hang \
             waiting on a wait_idle poll that was already satisfied",
        );
}

#[tokio::test(start_paused = true)]
async fn shutdown_signal_with_graceful_drain_waits_for_active_then_resolves() {
    let (tx, rx) = tokio::sync::watch::channel(false);
    let state = DrainState::new();
    let registry = lore_server::drain::QuinnConnectionRegistry::new("public");
    registry.count.store(1, Ordering::Relaxed);
    state.add_registry(registry.clone());

    tx.send(true).expect("receiver still alive");

    let handle = lore_base::lore_spawn!(shutdown_signal(rx, state, true));

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !handle.is_finished(),
        "graceful_drain=true must keep the signal future pending — this is the exact \
         behavior the gRPC leg was missing before this delta — while a connection is active"
    );

    registry.count.store(0, Ordering::Relaxed);

    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("shutdown_signal should resolve once total_active() reaches zero")
        .expect("shutdown_signal task panicked");
}

fn lame_duck_harness() -> (
    tokio::sync::watch::Sender<u32>,
    tokio::sync::watch::Sender<bool>,
    tokio::sync::watch::Receiver<bool>,
    Arc<DrainState>,
) {
    let (term_tx, _) = tokio::sync::watch::channel(0u32);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    (term_tx, shutdown_tx, shutdown_rx, DrainState::new())
}

#[test]
fn begin_lame_duck_is_draining_but_not_drained_until_it_ends() {
    let state = DrainState::new();
    state.begin_lame_duck();
    assert!(state.is_lame_duck());
    assert!(state.is_draining());
    assert!(!state.is_drained(), "lame duck must never read as drained");

    state.end_lame_duck();
    assert!(!state.is_lame_duck());
    assert!(state.is_draining(), "end_lame_duck clears only lame_duck");
    assert!(state.is_drained());
}

#[tokio::test(start_paused = true)]
async fn lame_duck_period_holds_shutdown_then_fires() {
    let (term_tx, shutdown_tx, shutdown_rx, state) = lame_duck_harness();
    let handle = lore_base::lore_spawn!(lame_duck_then_shutdown(
        term_tx.subscribe(),
        shutdown_tx,
        state.clone(),
        false,
        Some(Duration::from_secs(6)),
    ));

    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(!*shutdown_rx.borrow(), "nothing flips before termination");
    assert!(!state.is_draining());

    term_tx.send(1).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(state.is_draining() && state.is_lame_duck());
    assert!(!*shutdown_rx.borrow());

    tokio::time::sleep(Duration::from_millis(5800)).await; // 5.9 s total
    assert!(!*shutdown_rx.borrow(), "still lame duck at 5.9 s");
    assert!(state.is_lame_duck());

    tokio::time::sleep(Duration::from_millis(200)).await; // past 6 s
    assert!(*shutdown_rx.borrow());
    assert!(!state.is_lame_duck());
    assert!(state.is_draining());
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn lame_duck_ends_early_when_shutdown_is_sent_elsewhere() {
    let (term_tx, shutdown_tx, shutdown_rx, state) = lame_duck_harness();
    let handle = lore_base::lore_spawn!(lame_duck_then_shutdown(
        term_tx.subscribe(),
        shutdown_tx.clone(),
        state.clone(),
        false,
        Some(Duration::from_secs(600)),
    ));
    term_tx.send(1).unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(state.is_lame_duck());

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .expect("must return promptly, not wait out the period")
        .unwrap();
    assert!(!state.is_lame_duck());
    assert!(*shutdown_rx.borrow());
}

#[tokio::test(start_paused = true)]
async fn no_lame_duck_with_report_draining_drains_and_shuts_down_at_once() {
    let (term_tx, shutdown_tx, shutdown_rx, state) = lame_duck_harness();
    term_tx.send_replace(1);
    lame_duck_then_shutdown(term_tx.subscribe(), shutdown_tx, state.clone(), true, None).await;
    assert!(*shutdown_rx.borrow());
    assert!(state.is_draining());
    assert!(!state.is_lame_duck());
}

#[tokio::test(start_paused = true)]
async fn no_lame_duck_without_report_draining_only_shuts_down() {
    let (term_tx, shutdown_tx, shutdown_rx, state) = lame_duck_harness();
    term_tx.send_replace(1);
    lame_duck_then_shutdown(term_tx.subscribe(), shutdown_tx, state.clone(), false, None).await;
    assert!(*shutdown_rx.borrow());
    assert!(!state.is_draining());
}

#[tokio::test(start_paused = true)]
async fn dropped_termination_sender_still_drains_on_endpoint_shutdown() {
    let (term_tx, shutdown_tx, shutdown_rx, state) = lame_duck_harness();
    let rx = term_tx.subscribe();
    drop(term_tx);
    let handle = lore_base::lore_spawn!(lame_duck_then_shutdown(
        rx,
        shutdown_tx.clone(),
        state.clone(),
        true,
        Some(Duration::from_secs(6)),
    ));

    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(!*shutdown_rx.borrow(), "a dropped listener is not a signal");
    assert!(!state.is_draining());
    assert!(
        !handle.is_finished(),
        "an endpoint exit can still end the server"
    );

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .expect("must return once shutdown is signalled")
        .unwrap();
    assert!(state.is_draining());
    assert!(!state.is_lame_duck());
}

#[tokio::test(start_paused = true)]
async fn endpoint_exit_shutdown_without_termination_marks_draining() {
    // `wait_for_shutdown` sends the shutdown signal itself when an endpoint
    // exits. Health must then go 503 and `/drain_status` must reach drained,
    // with no lame duck because nothing is left to serve.
    let (term_tx, shutdown_tx, shutdown_rx, state) = lame_duck_harness();
    let handle = lore_base::lore_spawn!(lame_duck_then_shutdown(
        term_tx.subscribe(),
        shutdown_tx.clone(),
        state.clone(),
        true,
        Some(Duration::from_secs(600)),
    ));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!state.is_draining());

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .expect("must return promptly, not run a lame duck")
        .unwrap();
    assert!(*shutdown_rx.borrow());
    assert!(state.is_draining());
    assert!(!state.is_lame_duck());
    assert!(state.is_drained(), "an idle node must read as drained");
}

#[tokio::test(start_paused = true)]
async fn endpoint_exit_shutdown_without_report_draining_leaves_health_alone() {
    let (term_tx, shutdown_tx, _shutdown_rx, state) = lame_duck_harness();
    let handle = lore_base::lore_spawn!(lame_duck_then_shutdown(
        term_tx.subscribe(),
        shutdown_tx.clone(),
        state.clone(),
        false,
        None,
    ));
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .expect("must return promptly")
        .unwrap();
    assert!(!state.is_draining());
}

#[tokio::test(start_paused = true)]
async fn endpoint_exit_before_termination_with_only_a_lame_duck_marks_draining() {
    // `graceful_drain = false` but `lame_duck_seconds > 0`: the drain-status
    // docs say either setting flips health, so an endpoint exit must too.
    let (term_tx, shutdown_tx, _shutdown_rx, state) = lame_duck_harness();
    let handle = lore_base::lore_spawn!(lame_duck_then_shutdown(
        term_tx.subscribe(),
        shutdown_tx.clone(),
        state.clone(),
        false,
        Some(Duration::from_secs(600)),
    ));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!state.is_draining());

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .expect("must return promptly, not run a lame duck")
        .unwrap();
    assert!(
        state.is_draining(),
        "a lame-duck setting alone must flip health"
    );
    assert!(!state.is_lame_duck());
    assert!(state.is_drained());
}

#[tokio::test(start_paused = true)]
async fn endpoint_exit_during_lame_duck_without_report_draining_keeps_draining() {
    let (term_tx, shutdown_tx, shutdown_rx, state) = lame_duck_harness();
    let handle = lore_base::lore_spawn!(lame_duck_then_shutdown(
        term_tx.subscribe(),
        shutdown_tx.clone(),
        state.clone(),
        false,
        Some(Duration::from_secs(600)),
    ));
    term_tx.send(1).unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(state.is_lame_duck());
    assert!(!state.is_drained(), "never drained during the lame duck");

    // The endpoint exit, as `wait_for_shutdown` sends it.
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .expect("an endpoint exit must end the lame duck, not wait out the period")
        .unwrap();
    assert!(*shutdown_rx.borrow());
    assert!(!state.is_lame_duck());
    assert!(
        state.is_draining(),
        "health must stay 503 after the lame duck"
    );
    assert!(state.is_drained(), "an idle node must read as drained");
}

#[tokio::test(start_paused = true)]
async fn count_termination_signals_counts_each_signal_until_the_stream_ends() {
    let (term_tx, term_rx) = tokio::sync::watch::channel(0u32);
    count_termination_signals(
        futures::stream::iter(["SIGTERM", "SIGINT", "SIGTERM"]),
        term_tx,
    )
    .await;
    assert_eq!(*term_rx.borrow(), 3, "one count per signal");
}

#[tokio::test(start_paused = true)]
async fn count_termination_signals_counts_nothing_for_a_closed_stream() {
    let (term_tx, term_rx) = tokio::sync::watch::channel(0u32);
    tokio::time::timeout(
        Duration::from_secs(1),
        count_termination_signals(futures::stream::empty(), term_tx),
    )
    .await
    .expect("a closed stream must end the listener, not spin");
    assert_eq!(*term_rx.borrow(), 0, "a closed stream is not a signal");
}

#[tokio::test(start_paused = true)]
async fn count_termination_signals_stops_once_nothing_watches() {
    let (term_tx, term_rx) = tokio::sync::watch::channel(0u32);
    let (signal_tx, signal_rx) = tokio::sync::mpsc::unbounded_channel::<&'static str>();
    let handle = lore_base::lore_spawn!(count_termination_signals(
        tokio_stream::wrappers::UnboundedReceiverStream::new(signal_rx),
        term_tx,
    ));
    signal_tx.send("SIGTERM").unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(*term_rx.borrow(), 1);
    assert!(
        !handle.is_finished(),
        "an open stream keeps the listener up"
    );

    drop(term_rx);
    signal_tx.send("SIGINT").unwrap();
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .expect("the listener must stop once the count has no watcher")
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn second_termination_signal_ends_lame_duck_early() {
    let (term_tx, shutdown_tx, shutdown_rx, state) = lame_duck_harness();
    let handle = lore_base::lore_spawn!(lame_duck_then_shutdown(
        term_tx.subscribe(),
        shutdown_tx,
        state.clone(),
        false,
        Some(Duration::from_secs(600)),
    ));
    term_tx.send(1).unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(state.is_lame_duck());
    assert!(!*shutdown_rx.borrow());

    term_tx.send(2).unwrap();
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .expect("a second signal must end the lame duck, not wait out the period")
        .unwrap();
    assert!(*shutdown_rx.borrow());
    assert!(!state.is_lame_duck());
    assert!(state.is_draining());
}
