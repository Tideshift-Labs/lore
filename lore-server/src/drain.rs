// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Graceful-drain support for the QUIC endpoints.
//!
//! When `[server] graceful_drain = true`, a shutdown signal stops the QUIC
//! accept loops from admitting new connections but lets established
//! connections run to completion before the endpoint closes. The pieces here
//! track the established connections (so the drain knows when a node is
//! empty), expose that count to the health/status surface and metrics, and
//! run the drain loop itself, including the stall guard that closes
//! connections showing no stream activity.
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lore_base::lore_spawn;
use lore_telemetry::InstrumentProvider;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Gauge;
use tokio::time::Instant;
use tokio::time::MissedTickBehavior;
use tracing::info;
use tracing::warn;

/// How often the drain loop re-checks the active-connection count and the
/// stall tracker.
const DRAIN_TICK: Duration = Duration::from_secs(1);

/// How often `DrainState::wait_idle` re-polls the aggregate count.
const WAIT_IDLE_TICK: Duration = Duration::from_millis(250);

/// The subset of a QUIC connection the drain machinery needs. Abstracted so
/// the registry and drain loop are testable without a live endpoint.
pub trait DrainConnection {
    /// Stable in-process identifier for the connection.
    fn stable_id(&self) -> usize;
    /// Monotonic counter of STREAM frames sent + received. Keep-alive PING
    /// frames deliberately do not move this, so an idle-but-open connection
    /// reads as stalled rather than active.
    fn stream_frame_count(&self) -> u64;
    /// Close the connection because the drain declared it stalled.
    fn drain_close(&self);
}

impl DrainConnection for quinn::Connection {
    fn stable_id(&self) -> usize {
        quinn::Connection::stable_id(self)
    }

    fn stream_frame_count(&self) -> u64 {
        let stats = self.stats();
        stats.frame_rx.stream + stats.frame_tx.stream
    }

    fn drain_close(&self) {
        self.close(
            quinn::VarInt::from_u32(0),
            b"server draining: connection stalled",
        );
    }
}

/// Tracks the established connections of one QUIC endpoint, plus the
/// connections still handshaking (accepted but not yet established). The
/// pending count closes the drain race where a connection has passed the
/// accept-loop draining check but has not yet registered: the drain waits for
/// both counts to reach zero, so a mid-handshake connection is not cut by the
/// endpoint close that follows the drain.
pub struct ConnectionRegistry<C> {
    name: String,
    draining: AtomicBool,
    count: AtomicU64,
    pending_handshakes: AtomicU64,
    connections: Mutex<HashMap<usize, C>>,
}

pub type QuinnConnectionRegistry = ConnectionRegistry<quinn::Connection>;

impl<C: DrainConnection> ConnectionRegistry<C> {
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            draining: AtomicBool::new(false),
            count: AtomicU64::new(0),
            pending_handshakes: AtomicU64::new(0),
            connections: Mutex::new(HashMap::new()),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Register an established connection. The returned guard deregisters it
    /// on drop; hold it for the lifetime of the connection handler.
    pub fn register(self: &Arc<Self>, connection: C) -> ConnectionGuard<C> {
        let id = connection.stable_id();
        {
            let mut connections = self.lock_connections();
            connections.insert(id, connection);
            self.count
                .store(connections.len() as u64, Ordering::Relaxed);
        }
        ConnectionGuard {
            registry: self.clone(),
            id,
        }
    }

    pub fn active(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Connections accepted but still handshaking (not yet registered).
    pub fn pending(&self) -> u64 {
        self.pending_handshakes.load(Ordering::Relaxed)
    }

    /// Mark a connection as accepted-but-handshaking. Call synchronously in
    /// the accept loop (before spawning the handler) so the drain can never
    /// observe a moment where an admitted connection is in neither count;
    /// drop the guard once the connection is registered (or the handshake
    /// failed).
    pub fn begin_handshake(self: &Arc<Self>) -> HandshakeGuard<C> {
        self.pending_handshakes.fetch_add(1, Ordering::Relaxed);
        HandshakeGuard {
            registry: self.clone(),
        }
    }

    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    fn deregister(&self, id: usize) {
        let mut connections = self.lock_connections();
        connections.remove(&id);
        self.count
            .store(connections.len() as u64, Ordering::Relaxed);
    }

    /// The connections map is only locked for short insert/remove/clone
    /// operations that cannot panic while holding the guard, so a poisoned
    /// mutex can only mean a panic mid-`HashMap` operation; recovering the
    /// inner value is safe (worst case a connection entry is missing, which
    /// the drain loop already tolerates).
    fn lock_connections(&self) -> std::sync::MutexGuard<'_, HashMap<usize, C>> {
        match self.connections.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl<C: DrainConnection + Clone> ConnectionRegistry<C> {
    pub fn snapshot(&self) -> Vec<C> {
        self.lock_connections().values().cloned().collect()
    }
}

/// RAII registration of one connection; deregisters on drop.
pub struct ConnectionGuard<C: DrainConnection> {
    registry: Arc<ConnectionRegistry<C>>,
    id: usize,
}

impl<C: DrainConnection> Drop for ConnectionGuard<C> {
    fn drop(&mut self) {
        self.registry.deregister(self.id);
    }
}

/// RAII pending-handshake marker; decrements on drop.
pub struct HandshakeGuard<C> {
    registry: Arc<ConnectionRegistry<C>>,
}

impl<C> Drop for HandshakeGuard<C> {
    fn drop(&mut self) {
        self.registry
            .pending_handshakes
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Aggregate drain view across all QUIC endpoints of the process. Feeds the
/// `/health_check` 503, the `/drain_status` JSON, and the drain gauges.
#[derive(Default)]
pub struct DrainState {
    draining: AtomicBool,
    registries: Mutex<Vec<Arc<QuinnConnectionRegistry>>>,
}

impl DrainState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn add_registry(&self, registry: Arc<QuinnConnectionRegistry>) {
        self.lock_registries().push(registry);
    }

    /// Marks the process as draining for the health/status surface. The
    /// per-endpoint accept loops flip via their own registry in `run_drain`.
    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Established connections plus pending handshakes across all endpoints,
    /// so `wait_idle` (and the status surface) cannot report empty while a
    /// connection is mid-handshake.
    pub fn total_active(&self) -> u64 {
        self.lock_registries()
            .iter()
            .map(|r| r.active() + r.pending())
            .sum()
    }

    pub fn endpoint_counts(&self) -> Vec<(String, u64)> {
        self.lock_registries()
            .iter()
            .map(|r| (r.name().to_string(), r.active()))
            .collect()
    }

    /// Resolves once no endpoint holds an active connection.
    pub async fn wait_idle(&self) {
        let mut ticker = tokio::time::interval(WAIT_IDLE_TICK);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            if self.total_active() == 0 {
                return;
            }
            ticker.tick().await;
        }
    }

    /// See `ConnectionRegistry::lock_connections` for the poisoning rationale.
    fn lock_registries(&self) -> std::sync::MutexGuard<'_, Vec<Arc<QuinnConnectionRegistry>>> {
        match self.registries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Timeout knobs for one endpoint's graceful drain, derived from
/// `ServerSettings` (`drain_timeout_seconds`, `drain_stall_timeout_seconds`).
#[derive(Clone, Copy, Debug)]
pub struct DrainTimeouts {
    /// `None` = wait indefinitely for active connections to finish.
    pub drain_timeout: Option<Duration>,
    /// `None` = never force-close a stalled connection.
    pub stall_timeout: Option<Duration>,
}

/// Drain one endpoint: stop admitting new connections (the accept loop checks
/// `is_draining`) and wait until every established connection is gone.
///
/// * `drain_timeout` — `None` waits indefinitely; `Some(d)` gives up after `d`
///   (remaining connections are then cut by the endpoint close that follows).
/// * `stall_timeout` — `None` never force-closes; `Some(s)` closes a
///   connection whose stream-frame count has not advanced for `s`. This is
///   the escape hatch that keeps an unbounded drain from being wedged by an
///   idle or dead peer; the client resumes losslessly on a healthy replica.
pub async fn run_drain<C: DrainConnection + Clone>(
    registry: &Arc<ConnectionRegistry<C>>,
    drain_timeout: Option<Duration>,
    stall_timeout: Option<Duration>,
) {
    registry.begin_drain();

    let deadline = drain_timeout.map(|d| Instant::now() + d);
    let mut progress: HashMap<usize, (u64, Instant)> = HashMap::new();
    let mut ticker = tokio::time::interval(DRAIN_TICK);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // The first tick of a tokio interval fires immediately; consume it so the
    // loop body observes the initial state before any sleep.
    ticker.tick().await;

    info!(
        endpoint = registry.name(),
        active = registry.active(),
        "Draining endpoint: refusing new connections, waiting for active connections to finish"
    );

    loop {
        // Pending handshakes count too: a connection past the accept-loop
        // draining check but not yet registered must not be cut by the
        // endpoint close that follows this drain.
        let active = registry.active();
        if active == 0 && registry.pending() == 0 {
            info!(endpoint = registry.name(), "Endpoint drained");
            return;
        }

        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            warn!(
                endpoint = registry.name(),
                active, "Drain timeout reached with connections still active; closing endpoint"
            );
            return;
        }

        if let Some(stall) = stall_timeout {
            let now = Instant::now();
            let connections = registry.snapshot();
            let live: std::collections::HashSet<usize> =
                connections.iter().map(|c| c.stable_id()).collect();
            progress.retain(|id, _| live.contains(id));

            for connection in connections {
                let frames = connection.stream_frame_count();
                let entry = progress
                    .entry(connection.stable_id())
                    .or_insert((frames, now));
                if frames != entry.0 {
                    *entry = (frames, now);
                } else if now.duration_since(entry.1) >= stall {
                    warn!(
                        endpoint = registry.name(),
                        connection_id = connection.stable_id(),
                        stalled_for = ?now.duration_since(entry.1),
                        "Closing stalled connection during drain (no stream activity)"
                    );
                    connection.drain_close();
                    // Restart the window so the close isn't re-issued every
                    // tick while the handler winds down and deregisters.
                    entry.1 = now;
                }
            }
        }

        ticker.tick().await;
    }
}

struct DrainInstrumentProvider;

impl InstrumentProvider for DrainInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.server"
    }
}

struct DrainInstruments {
    active_connections: Gauge<u64>,
    draining: Gauge<u64>,
}

impl DrainInstruments {
    fn instance() -> &'static DrainInstruments {
        static INSTANCE: OnceLock<DrainInstruments> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            let provider = DrainInstrumentProvider;
            DrainInstruments {
                active_connections: provider.gauge("drain.active_connections"),
                draining: provider.gauge("drain.draining"),
            }
        })
    }
}

/// Periodically records the aggregate drain gauges (per-endpoint active
/// connections and the draining flag) so a deploy controller can also watch
/// the drain through the metrics pipeline.
pub fn spawn_drain_metrics(state: Arc<DrainState>, interval: Duration) {
    lore_spawn!(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let instruments = DrainInstruments::instance();
            instruments.draining.record(state.is_draining() as u64, &[]);
            for (endpoint, active) in state.endpoint_counts() {
                instruments
                    .active_connections
                    .record(active, &[KeyValue::new("quic_service_name", endpoint)]);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use super::ConnectionRegistry;
    use super::DrainConnection;
    use super::DrainState;
    use super::run_drain;

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
        let public = super::QuinnConnectionRegistry::new("public");
        let internal = super::QuinnConnectionRegistry::new("internal");
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
        let registry = super::QuinnConnectionRegistry::new("public");
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
        let registry = super::QuinnConnectionRegistry::new("public");
        registry.count.store(1, Ordering::Relaxed);
        state.add_registry(registry.clone());

        let state_for_task = state.clone();
        let handle = tokio::spawn(async move { state_for_task.wait_idle().await });

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
        let handle = tokio::spawn(async move {
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
        let bumper = tokio::spawn(async move {
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
        let handle = tokio::spawn(async move {
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
}
