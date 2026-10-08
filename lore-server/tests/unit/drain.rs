// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, CR-009): the graceful-drain tests, moved out of the
//! inline `drain::tests` module when upstream set `[lib] test = false`.

mod rpc_tests;

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lore_server::drain::ConnectionRegistry;
use lore_server::drain::DrainConnection;
use lore_server::drain::DrainState;
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
