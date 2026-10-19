// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Graceful-drain support for QUIC endpoints and public gRPC work.
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
#[lore_macro::test_pub]
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

/// Aggregate drain view across QUIC endpoints and public RPCs. Feeds the
/// `/health_check` 503, the `/drain_status` JSON, and the drain gauges.
#[derive(Default)]
pub struct DrainState {
    draining: AtomicBool,
    /// True while the node reports unhealthy but still serves everything, so
    /// the front stops routing to it before admission ends. Never drained.
    lame_duck: AtomicBool,
    registries: Mutex<Vec<Arc<QuinnConnectionRegistry>>>,
    active_rpc_requests: AtomicU64,
    public_grpc_servers: AtomicU64,
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
    ///
    /// Release/Acquire (as for `lame_duck`): `begin_lame_duck` stores
    /// `lame_duck` before `draining`, so a reader that sees `draining` also
    /// sees `lame_duck` and `is_drained` cannot read true at the lame-duck start.
    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::Release);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Enters the lame-duck phase: health goes 503 at once, but nothing stops
    /// serving and the node never reads as drained until it ends.
    pub fn begin_lame_duck(&self) {
        self.lame_duck.store(true, Ordering::Release);
        self.begin_drain();
    }

    /// Ends the lame-duck phase; admission is about to close.
    pub fn end_lame_duck(&self) {
        self.lame_duck.store(false, Ordering::Release);
    }

    pub fn is_lame_duck(&self) -> bool {
        self.lame_duck.load(Ordering::Acquire)
    }

    /// QUIC connections plus pending handshakes across all endpoints. RPCs have
    /// their own counter; this legacy connection count alone cannot prove idle.
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

    /// Public RPCs whose handler or response body is still live.
    pub fn active_rpc_requests(&self) -> u64 {
        self.active_rpc_requests.load(Ordering::Acquire)
    }

    pub fn begin_rpc(self: &Arc<Self>) -> RpcGuard {
        self.active_rpc_requests.fetch_add(1, Ordering::AcqRel);
        RpcGuard {
            state: self.clone(),
        }
    }

    /// Keep HTTP drain status available until tonic has stopped admitting calls
    /// and its server future has completed. An instantaneous zero RPC count is
    /// not an admission barrier.
    pub fn register_public_grpc(self: &Arc<Self>) -> PublicGrpcGuard {
        self.public_grpc_servers.fetch_add(1, Ordering::AcqRel);
        PublicGrpcGuard {
            state: self.clone(),
        }
    }

    /// A zero request count alone is not proof that gRPC admission has ended.
    pub fn is_drained(&self) -> bool {
        self.is_draining() && !self.is_lame_duck() && self.is_idle()
    }

    fn is_idle(&self) -> bool {
        self.total_active() == 0
            && self.public_grpc_servers.load(Ordering::Acquire) == 0
            && self.active_rpc_requests() == 0
    }

    /// Resolves after QUIC, public gRPC serving, and all counted RPC work ends.
    pub async fn wait_idle(&self) {
        let mut ticker = tokio::time::interval(WAIT_IDLE_TICK);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            if self.is_idle() {
                return;
            }
            ticker.tick().await;
        }
    }

    /// Keep public gRPC available for QUIC finalization, then let tonic close
    /// admission and finish its accepted calls. Waiting for the public server
    /// itself here would deadlock its shutdown future.
    pub async fn wait_quic_idle(&self) {
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

pub struct RpcGuard {
    state: Arc<DrainState>,
}

impl Drop for RpcGuard {
    fn drop(&mut self) {
        self.state
            .active_rpc_requests
            .fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct PublicGrpcGuard {
    state: Arc<DrainState>,
}

impl PublicGrpcGuard {
    pub(crate) fn active_requests(&self) -> u64 {
        self.state.active_rpc_requests()
    }

    pub(crate) async fn wait_for_requests(&self) {
        let mut ticker = tokio::time::interval(WAIT_IDLE_TICK);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        while self.active_requests() != 0 {
            ticker.tick().await;
        }
    }
}

impl Drop for PublicGrpcGuard {
    fn drop(&mut self) {
        self.state
            .public_grpc_servers
            .fetch_sub(1, Ordering::AcqRel);
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

/// Turn a termination signal into the shutdown signal every endpoint drains on.
///
/// With a lame-duck period the health check goes 503 at the signal while gRPC
/// and QUIC keep admitting work, so a front that probes health stops routing
/// here before admission closes. Only then does `shutdown_tx` fire. Without
/// one, `report_draining` alone decides whether health flips, and the shutdown
/// signal follows at once (the behavior before the lame-duck phase existed).
///
/// `termination_rx` counts the termination signals received. A second signal
/// during the lame-duck period ends it early, so an operator can skip the wait.
///
/// An endpoint that exits sends the shutdown signal itself. Before any
/// termination signal, that skips the lame duck and only marks the node as
/// draining (when `report_draining` or a lame-duck period is set, as for a
/// termination signal); during the lame-duck period, the wait ends early
/// rather than serving on.
pub async fn lame_duck_then_shutdown(
    mut termination_rx: tokio::sync::watch::Receiver<u32>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    drain_state: Arc<DrainState>,
    report_draining: bool,
    lame_duck: Option<Duration>,
) {
    // A lame-duck period reports draining at the signal, so an endpoint exit
    // must too: `/drain_status` documents either setting as flipping health.
    let report_draining = report_draining || lame_duck.is_some();
    let mut shutdown_rx = shutdown_tx.subscribe();
    let terminated = tokio::select! {
        signalled = termination_rx.wait_for(|&n| n > 0) => signalled.is_ok(),
        _ = shutdown_rx.wait_for(|&v| v) => false,
    };
    if !terminated {
        // Shutdown came from an endpoint exit, or the signal listener is gone
        // and only an endpoint exit can end the server now. This task holds a
        // sender, so the wait cannot fail.
        let _ = shutdown_rx.wait_for(|&v| v).await;
        if report_draining {
            info!(
                "Graceful drain: shutdown without a termination signal, marking server as draining"
            );
            drain_state.begin_drain();
        }
        return;
    }
    match lame_duck {
        Some(period) => {
            drain_state.begin_lame_duck();
            info!(
                lame_duck_seconds = period.as_secs(),
                "Lame duck: health reports 503, still serving gRPC and QUIC"
            );
            let second_signal = async {
                if termination_rx.wait_for(|&n| n > 1).await.is_err() {
                    // The listener is gone; only the period or a shutdown ends the wait.
                    std::future::pending::<()>().await;
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(period) => {
                    info!("Lame duck period elapsed: closing admission and draining");
                }
                _ = second_signal => {
                    warn!("Lame duck ended early: second termination signal received");
                }
                _ = shutdown_rx.wait_for(|&v| v) => {
                    warn!("Lame duck ended early: shutdown was already signalled");
                }
            }
            drain_state.end_lame_duck();
        }
        None => {
            if report_draining {
                info!("Graceful drain: marking server as draining");
                drain_state.begin_drain();
            }
        }
    }
    let _ = shutdown_tx.send(true);
}

/// Count each termination signal `signals` yields into `termination_tx`, which
/// `lame_duck_then_shutdown` watches. Returns when the stream ends or nothing
/// watches the count any more. The OS signal sources are wrapped by the
/// server's `listen_for_termination`; a test can inject any stream here.
pub async fn count_termination_signals<S>(
    signals: S,
    termination_tx: tokio::sync::watch::Sender<u32>,
) where
    S: futures::Stream<Item = &'static str>,
{
    use futures::StreamExt;
    let mut signals = std::pin::pin!(signals);
    while let Some(name) = signals.next().await {
        info!("Received {name}. Initiating graceful shutdown");
        termination_tx.send_modify(|count| *count = count.saturating_add(1));
        if termination_tx.is_closed() {
            return;
        }
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
    active_rpc_requests: Gauge<u64>,
    draining: Gauge<u64>,
}

impl DrainInstruments {
    fn instance() -> &'static DrainInstruments {
        static INSTANCE: OnceLock<DrainInstruments> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            let provider = DrainInstrumentProvider;
            DrainInstruments {
                active_connections: provider.gauge("drain.active_connections"),
                active_rpc_requests: provider.gauge("drain.active_rpc_requests"),
                draining: provider.gauge("drain.draining"),
            }
        })
    }
}

/// Periodically records the aggregate drain gauges (per-endpoint active
/// connections, public RPC requests and the draining flag) so a deploy controller can also watch
/// the drain through the metrics pipeline.
pub fn spawn_drain_metrics(state: Arc<DrainState>, interval: Duration) {
    lore_spawn!(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let instruments = DrainInstruments::instance();
            instruments.draining.record(state.is_draining() as u64, &[]);
            instruments
                .active_rpc_requests
                .record(state.active_rpc_requests(), &[]);
            for (endpoint, active) in state.endpoint_counts() {
                instruments
                    .active_connections
                    .record(active, &[KeyValue::new("quic_service_name", endpoint)]);
            }
        }
    });
}
