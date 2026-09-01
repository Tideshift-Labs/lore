// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::future::Future;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "test_seams")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use futures::TryFutureExt;
use futures::stream::FuturesUnordered;
use lore_base::error::Disconnected;
use lore_base::error::NotAuthorized;
use lore_base::lore_debug;
use lore_base::lore_error;
use lore_base::lore_info;
use lore_base::lore_trace;
use lore_base::lore_warn;
use lore_error_set::prelude::*;
use parking_lot::Mutex as SyncMutex;
use quinn::AckFrequencyConfig;
use quinn::IdleTimeout;
use quinn::VarInt;
use quinn::congestion;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::RootCertStore;
use rustls_native_certs::load_native_certs;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::sync::Semaphore;
use tokio::sync::SemaphorePermit;
use tokio::sync::oneshot;
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

use super::MAX_RTT_MS;
use super::PACKET_THRESHOLD;
use super::QuicClientError;
use super::QuicOpCode;
use super::TIME_THRESHOLD;
use super::command_header::CommandHeader;
use super::response_reader::ResponseReader;
use crate::connection::RECONNECT_MAX_ATTEMPTS;
use crate::connection::RECONNECT_MAX_DELAY;
use crate::connection::RECONNECT_START_DELAY;
use crate::error::ProtocolError;
use crate::replay::ATTEMPT_BUDGET;
use crate::replay::DispatchState;
use crate::replay::MutableOutcome;
use crate::replay::OutcomeUnknown;
use crate::replay::ReplayClass;
use crate::tls::load_certs;
use crate::tls::load_private_key;

pub const STREAM_COUNT: u32 = 8;
pub const PRIORITY_STREAM_COUNT: u32 = 2;

/// Configuration for establishing a QUIC connection to a remote endpoint.
#[derive(Clone, Debug)]
pub struct EndpointConfig {
    pub remote_url: String,
    pub default_port: u16,
    /// When `Some`, used as the `server_name` argument to `quinn::Endpoint::connect`
    /// instead of the URL host. This enables connections to IP-addressed peers (from
    /// topology) to present the correct server name for TLS validation.
    pub sni_override: Option<String>,
}

const IDLE_TIMEOUT_MS: u32 = 30000;
const KEEP_ALIVE_MS: u64 = 500;
const HANDSHAKE_TIMEOUT_SECS: u64 = 5;
const HAPPY_EYEBALLS_DELAY_MS: u64 = 250;
const HAPPY_EYEBALLS_MAX_IN_FLIGHT: usize = 10;
pub const DEFAULT_EXPECTED_RTT_MS: u64 = 100;

#[derive(Clone, Debug)]
pub struct ClientCerts {
    pub cert_file: PathBuf,
    pub pkey_file: PathBuf,
}

#[derive(Clone, Debug)]
pub struct CertificateSettings {
    // if the server is using a custom CA, clients can pass the file here
    pub custom_ca: Option<PathBuf>,
    // if clients should send certs, otherwise no certs are sent
    pub client: Option<ClientCerts>,
}

/// Statistics about UDP datagrams transmitted or received on a connection
pub struct UdpStats {
    /// The number of UDP datagrams observed
    pub datagrams: u64,
    /// The total bytes transferred inside UDP datagrams
    pub bytes: u64,
    /// The number of I/O operations executed (may be less than `datagrams` with GSO/GRO)
    pub ios: u64,
}

/// Number of frames transmitted or received, by frame type
pub struct FrameStats {
    pub data_blocked: u64,
    pub stream_data_blocked: u64,
    pub streams_blocked_bidi: u64,
    pub streams_blocked_uni: u64,
    pub max_data: u64,
    pub max_stream_data: u64,
    pub max_streams_bidi: u64,
    pub stream: u64,
    pub reset_stream: u64,
}

/// Statistics related to the current transmission path
pub struct PathStats {
    /// Current best estimate of this connection's latency (round-trip-time)
    pub rtt: Duration,
    /// Current congestion window of the connection in bytes
    pub cwnd: u64,
    /// Cumulative congestion events on the connection
    pub congestion_events: u64,
    /// Cumulative packets lost on this path
    pub lost_packets: u64,
    /// Cumulative bytes lost on this path
    pub lost_bytes: u64,
    /// Cumulative packets sent on this path
    pub sent_packets: u64,
    /// Number of black holes detected on the path
    pub black_holes_detected: u64,
    /// Largest UDP payload size the path currently supports
    pub current_mtu: u16,
}

/// Connection statistics, decoupled from the underlying QUIC implementation.
pub struct ConnectionStats {
    /// Statistics about UDP datagrams transmitted
    pub udp_tx: UdpStats,
    /// Statistics about UDP datagrams received
    pub udp_rx: UdpStats,
    /// Statistics about frames transmitted
    pub frame_tx: FrameStats,
    /// Statistics about frames received
    pub frame_rx: FrameStats,
    /// Statistics related to the current transmission path
    pub path: PathStats,
}

impl From<quinn::ConnectionStats> for ConnectionStats {
    fn from(s: quinn::ConnectionStats) -> Self {
        Self {
            udp_tx: UdpStats {
                datagrams: s.udp_tx.datagrams,
                bytes: s.udp_tx.bytes,
                ios: s.udp_tx.ios,
            },
            udp_rx: UdpStats {
                datagrams: s.udp_rx.datagrams,
                bytes: s.udp_rx.bytes,
                ios: s.udp_rx.ios,
            },
            frame_tx: FrameStats {
                data_blocked: s.frame_tx.data_blocked,
                stream_data_blocked: s.frame_tx.stream_data_blocked,
                streams_blocked_bidi: s.frame_tx.streams_blocked_bidi,
                streams_blocked_uni: s.frame_tx.streams_blocked_uni,
                max_data: s.frame_tx.max_data,
                max_stream_data: s.frame_tx.max_stream_data,
                max_streams_bidi: s.frame_tx.max_streams_bidi,
                stream: s.frame_tx.stream,
                reset_stream: s.frame_tx.reset_stream,
            },
            frame_rx: FrameStats {
                data_blocked: s.frame_rx.data_blocked,
                stream_data_blocked: s.frame_rx.stream_data_blocked,
                streams_blocked_bidi: s.frame_rx.streams_blocked_bidi,
                streams_blocked_uni: s.frame_rx.streams_blocked_uni,
                max_data: s.frame_rx.max_data,
                max_stream_data: s.frame_rx.max_stream_data,
                max_streams_bidi: s.frame_rx.max_streams_bidi,
                stream: s.frame_rx.stream,
                reset_stream: s.frame_rx.reset_stream,
            },
            path: PathStats {
                rtt: s.path.rtt,
                cwnd: s.path.cwnd,
                congestion_events: s.path.congestion_events,
                lost_packets: s.path.lost_packets,
                lost_bytes: s.path.lost_bytes,
                sent_packets: s.path.sent_packets,
                black_holes_detected: s.path.black_holes_detected,
                current_mtu: s.path.current_mtu,
            },
        }
    }
}

#[derive(Clone)]
pub enum CongestionAlgorithm {
    Bbr,
    Cubic,
}

#[derive(Clone)]
pub struct TransportConfig {
    pub max_bytes_bandwidth_per_second: u64,
    pub expected_rtt_ms: u64,
    pub congestion_algorithm: CongestionAlgorithm,
    /// Warm-start hint for Congestion Algorithms: seed the initial congestion window
    pub initial_cwnd: Option<u64>,
}

/// When working within a QUIC connection, these are the opportunities
/// for any authentication/authorization to occur. Errors raised will be mapped to `QuicClientError`
/// by the generic client logic
#[async_trait]
pub trait AuthAdapter: Send + Sync {
    type ErrorType: std::error::Error + Send + Sync;

    /// Called when first establishing the QUIC connection. See this as an opportunity
    /// to fail early and vocally if authentication/authorization is not correct
    async fn initial_authorize(
        &self,
        connection: Arc<QuicConnection>,
    ) -> Result<(), Self::ErrorType>;

    /// After previously successfully establishing a connection, this is the
    /// authentication/authorization logic that runs if we need to reestablish a connection.
    /// Since it was proven previously that a connection is possible, and we have correct
    /// credentials, this logic and its failures  should be seen as more background/benign.
    async fn reconnect_authorize(
        &self,
        connection: Arc<QuicConnection>,
    ) -> Result<(), QuicClientError>;

    /// The certs to provide when establishing the QUIC connection
    fn client_certs(&self) -> CertificateSettings;
}

/// When interacting with a QUIC server, these are the required functionality
/// a QUIC client should provide to use the QUIC client scaffolding
pub trait ServiceClient: Send + Sync {
    const ALPN: &'static str;
    const DEFAULT_PORT: u16;

    /// Concrete type that represents what opcodes can be sent
    type RequestType: Into<QuicOpCode> + Copy + Send;
    /// The concrete error types that `QuicClientError` can be converted into, when receiving
    /// error responses from the Server
    type ErrorType: std::error::Error + Send + Sync;

    /// Rate limiting message throughput
    fn acquire_command_permit(&self) -> impl Future<Output = Option<SemaphorePermit<'_>>> + Send;

    /// The underlying QUIC connection being used by this client
    fn quic(&self) -> &Arc<QuicConnection>;

    /// The endpoint configuration for connecting to the remote server
    fn endpoint_config(&self) -> EndpointConfig;

    /// The ALPN to use when connecting to the server
    fn alpn(&self) -> &str;

    /// Given a failure to send request bytes under the given `RequestType`,
    /// convert this generic error into the `ServiceClient` error space.
    /// This logic is done within the send function rather than outside it
    /// to the keep the size of the future as small as possible
    fn map_send_error(
        &self,
        failed_request: Self::RequestType,
        error: SendWithReconnectError,
    ) -> Self::ErrorType;

    /// The implementation of how authentication/authorization is done by this client
    fn auth_adapter(&self) -> &Arc<dyn AuthAdapter<ErrorType = Self::ErrorType>>;

    /// Defines how the underlying quic connection is configured
    fn transport_config(&self) -> TransportConfig;

    /// Whether this client uses the v4 protocol (12-byte headers with `session_id`).
    /// Default is false (v2, 8-byte headers).
    fn v4_protocol(&self) -> bool {
        false
    }

    /// Whether repeating `request` is safe once it has been dispatched.
    ///
    /// There is deliberately no default. A client that adds an opcode has to decide whether
    /// repeating it can publish, revive, or advance server state, and the compiler is what
    /// asks the question.
    fn replay_class(&self, request: Self::RequestType) -> ReplayClass;

    /// The wire name of `request`, carried by the typed outcome a lost mutable response
    /// reports so a consumer identifies the operation without parsing a message.
    fn request_name(&self, request: Self::RequestType) -> &'static str;
}

struct QuicQuinnConnection {
    connection: quinn::Connection,
    writer: Vec<Arc<Mutex<quinn::SendStream>>>,
    reader: Vec<ResponseReader>,
}

impl QuicQuinnConnection {
    async fn close(&mut self) {
        let connection_id = self.connection.stable_id();
        lore_debug!(
            "QUIC connection {connection_id} stats: {:?}",
            self.connection.stats()
        );
        // Skip per-stream finish() + stopped() + reader.task.await. The server treats
        // CONNECTION_CLOSE(app, 0) as a graceful close (see is_graceful_close in
        // lore-server/src/quic/stream_handler.rs), so the stream-level FIN handshake
        // (1 RTT per stream) is unnecessary. Dropping the reader/writer vecs detaches
        // the reader tasks; they exit promptly once the connection's close() below
        // terminates their recv streams.
        self.writer.clear();
        self.reader.clear();
        self.connection
            .close(quinn::VarInt::from(0u32), b"terminate");
        // Drive I/O until the close frame has been flushed to the peer. Without this,
        // the process can exit before the CONNECTION_CLOSE reaches the server, causing
        // server-side stream reads to surface as transport errors rather than normal close.
        self.connection.closed().await;
    }
}

pub struct QuicConnection {
    connection: RwLock<QuicQuinnConnection>,
    created: Instant,
    last_send: AtomicU64,
    last_recv: Arc<AtomicU64>,
    pub epoch: AtomicU32,
    /// Which underlying connection the streams inside `connection` belong to.
    ///
    /// Distinct from `epoch`, and not interchangeable with it. `epoch` counts *completed*
    /// reconnects: it is bumped after the replacement connection has been installed, its first
    /// stream opened, and its authorization run, so that a command waiting on a reconnect learns
    /// there is something usable to retry on. Between the swap and that bump, the streams are
    /// already the replacement's while `epoch` still reads the old value — which is exactly the
    /// state in which a session id from the old connection would be framed onto the new one.
    ///
    /// This counter is bumped inside the same write-lock section that swaps the connection, so a
    /// reader holding the read lock sees either the old connection with the old value or the new
    /// connection with the new one, and never a mixture. That is what makes it usable as the
    /// binding token at the write boundary.
    generation: AtomicU32,
    /// The generation each live server-side session id was issued on.
    ///
    /// The send path has the id but not the generation it came from, and threading one down
    /// through every `Storage` method would put it in the read path's future, which is size
    /// bounded. Recording it here instead keeps the answer reachable from the one place that can
    /// act on it — inside the read lock, immediately before the writer is taken.
    sessions: dashmap::DashMap<u32, u32>,
    #[cfg(feature = "test_seams")]
    pause_next_session_send: AtomicBool,
    #[cfg(feature = "test_seams")]
    session_send_paused: Semaphore,
    #[cfg(feature = "test_seams")]
    resume_session_send: Semaphore,
    max_reconnects: Option<u32>,
    reconnect_guard: Semaphore,
    counter: AtomicU32,
    non_priority_counter: AtomicU32,
    pub stream_count: AtomicU32,
    stream_inflight: Arc<[AtomicU64; STREAM_COUNT as usize]>,
    max_chunk_size: usize,
    v4: bool,
}

impl QuicConnection {
    pub fn new(connection: quinn::Connection, max_chunk_size: usize) -> Self {
        Self::with_v4(connection, max_chunk_size, false)
    }

    pub fn with_v4(connection: quinn::Connection, max_chunk_size: usize, v4: bool) -> Self {
        QuicConnection {
            connection: RwLock::new(QuicQuinnConnection {
                connection,
                writer: vec![],
                reader: vec![],
            }),
            created: Instant::now(),
            last_send: AtomicU64::new(0),
            last_recv: Arc::new(AtomicU64::new(0)),
            epoch: AtomicU32::new(1),
            generation: AtomicU32::new(1),
            sessions: dashmap::DashMap::new(),
            #[cfg(feature = "test_seams")]
            pause_next_session_send: AtomicBool::new(false),
            #[cfg(feature = "test_seams")]
            session_send_paused: Semaphore::new(0),
            #[cfg(feature = "test_seams")]
            resume_session_send: Semaphore::new(0),
            max_reconnects: None,
            reconnect_guard: Semaphore::new(1),
            counter: AtomicU32::new(0),
            non_priority_counter: AtomicU32::new(0),
            stream_count: AtomicU32::new(0),
            stream_inflight: Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
            max_chunk_size,
            v4,
        }
    }

    /// The connection generation a session id issued right now would belong to.
    ///
    /// Sample this *before* asking the server for a session, never after: a connection replaced
    /// while `session_start` is in flight leaves the id recorded against the older generation,
    /// which costs a rebind. Sampling afterwards would record a generation the id was never valid
    /// on, which costs correctness.
    pub fn connection_generation(&self) -> u32 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Record that the server issued `session_id` on `generation`.
    ///
    /// Crate-visible, and it has to stay that way. The registry is what the write boundary
    /// consults, so anything able to write it can mark an arbitrary id current on an arbitrary
    /// connection and put P0-1 straight back. The invariant it depends on — the generation was
    /// sampled *before* the `session_start` whose id this is — is held by the single caller in
    /// `quic/storage_service/client.rs`, and keeping the writer inside this crate is what makes
    /// that an invariant rather than a convention.
    ///
    /// The WP-108 regression suite does need to forge one from another crate, to prove the
    /// server's half of the fix holds against a client that did emit a stale id. It reaches
    /// [`QuicConnection::register_session_for_test`], behind the `test_seams` feature, rather
    /// than through this.
    pub(crate) fn register_session(&self, session_id: u32, generation: u32) {
        if session_id != 0 {
            self.sessions.insert(session_id, generation);
        }
    }

    /// Forge a session-id-to-generation binding. Tests only, and gated so it cannot be reached
    /// from a production build.
    ///
    /// A test in another crate uses this to put a session id on the wire that this connection
    /// never earned — the one thing [`QuicConnection::session_is_current`] exists to prevent —
    /// so that the server's independent defence can be exercised on its own. If you are reaching
    /// for this outside a test, the answer is no: call `session_start`.
    #[cfg(feature = "test_seams")]
    pub fn register_session_for_test(&self, session_id: u32, generation: u32) {
        self.register_session(session_id, generation);
    }

    /// Move to the exact reconnect interval in which replacement streams are installed but the
    /// completed-reconnect epoch is not yet published. Tests only.
    ///
    /// This advances the generation and invalidates its session registry under the same write
    /// lock used by a real reconnect. It deliberately leaves the underlying loopback connection
    /// and epoch in place so an in-flight request can return its real server answer while the
    /// session layer observes that its generation moved.
    #[cfg(feature = "test_seams")]
    pub async fn advance_generation_before_epoch_for_test(&self) {
        let _connection = self.connection.write().await;
        self.generation.fetch_add(1, Ordering::Relaxed);
        self.sessions.clear();
    }

    /// Pause the next session-bearing send after session resolution but before the connection
    /// read lock and write-boundary check. Tests only.
    #[cfg(feature = "test_seams")]
    pub fn arm_session_send_pause_for_test(&self) -> Result<(), ProtocolError> {
        self.pause_next_session_send
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ProtocolError::internal("session send pause is already armed"))
    }

    /// Wait until the armed session-bearing send reaches its pause. Tests only.
    #[cfg(feature = "test_seams")]
    pub async fn wait_for_session_send_pause_for_test(&self) -> Result<(), ProtocolError> {
        self.session_send_paused
            .acquire()
            .await
            .map_err(|_| ProtocolError::internal("session send pause closed"))?
            .forget();
        Ok(())
    }

    /// Release a session-bearing send held by [`Self::arm_session_send_pause_for_test`].
    #[cfg(feature = "test_seams")]
    pub fn resume_session_send_for_test(&self) {
        self.resume_session_send.add_permits(1);
    }

    /// Forget a session that has been stopped, or whose stop was attempted.
    pub(crate) fn forget_session(&self, session_id: u32) {
        self.sessions.remove(&session_id);
    }

    /// Whether `session_id` was issued on the connection as it is now.
    ///
    /// Answers `false` for an id this connection never issued as well as for one issued on a
    /// generation that has been replaced, because the two are the same thing to a send: neither
    /// may go on the wire. Call it while holding the connection read lock, so the answer cannot
    /// be invalidated by a swap before the writer is taken.
    fn session_is_current(&self, session_id: u32) -> bool {
        self.sessions
            .get(&session_id)
            .is_some_and(|generation| *generation == self.connection_generation())
    }

    pub async fn create_initial_stream(&self) -> Result<(), QuicClientError> {
        let last_recv = self.last_recv.clone();
        let created = self.created;

        {
            let mut connection = self.connection.write().await;

            let (send, recv) = connection
                .connection
                .open_bi()
                .await
                .map_err(|_err| QuicClientError::StreamOpen)?;
            connection.writer.push(Arc::new(Mutex::new(send)));
            connection.reader.push(ResponseReader::new(
                0,
                recv,
                self.max_chunk_size,
                last_recv,
                created,
                self.v4,
            ));
            lore_trace!("Created initial connect bidirectional stream");
        }

        Ok(())
    }

    pub async fn has_streams(&self) -> bool {
        !self.connection.read().await.reader.is_empty()
    }

    pub async fn close(&self) {
        let mut connection = self.connection.write().await;
        connection.close().await;
    }

    /// Close the QUIC connection immediately without waiting for streams to drain.
    /// Used in Drop to avoid blocking the runtime during shutdown.
    ///
    /// A read guard is enough, since `quinn::Connection::close` takes `&self`, so a
    /// concurrent reader does not cost the peer its close frame. The guard is still needed:
    /// a reconnect replaces the inner connection, so a handle cached outside the lock would
    /// close whichever connection had since been replaced.
    ///
    /// Nothing awaits the frame reaching the peer, because `Drop` cannot. It is still
    /// transmitted, because connections are closed before the runtimes are shut down and the
    /// endpoint driver is therefore live when this returns.
    pub fn close_immediate(&self) {
        if let Ok(connection) = self.connection.try_read() {
            connection
                .connection
                .close(quinn::VarInt::from(0u32), b"terminate");
        } else {
            // Unclosed, the peer keeps the session until its idle timeout expires.
            lore_warn!("QUIC connection busy on close, server not notified");
        }
    }

    pub fn set_max_reconnects(&mut self, max_reconnects: Option<u32>) {
        self.max_reconnects = max_reconnects;
    }

    pub async fn connection_stats(&self) -> ConnectionStats {
        self.connection.read().await.connection.stats().into()
    }
}

#[derive(Debug, Error)]
pub enum SendWithReconnectError {
    #[error("Failed to acquire permit to run command")]
    PermitAcquire,
    #[error("QUIC Client Error: {0}")]
    ClientError(#[from] QuicClientError),
    #[error("Disconnected from server")]
    Disconnected,
    #[error("Reconnect to server failed")]
    ReconnectFailed,
    /// A session-bearing send was refused before dispatch because its id belongs to the
    /// connection that is gone. The send is not retried here: the session-aware layer has to
    /// resolve a replacement session first. See [`crate::session::StorageSession`].
    #[error("Connection replaced; session must be rebound before this command is sent again")]
    SessionRebindRequired,
    /// The request was dispatched on the connection that was then replaced, and its response
    /// was lost. The command's replay class forbids sending it again, so whether the server
    /// applied it is unknown.
    #[error("{0}")]
    OutcomeUnknown(OutcomeUnknown),
}

/// Where an ambiguous mutable outcome is recorded, if anywhere.
///
/// A generic taken by value rather than an `Option<&mut _>` parameter, for the same reason
/// `HIGH_PRIORITY` is a const generic: the send future is the storage read path's, is
/// heap-allocated once per request through `async_trait`, and is held to a size bound by
/// `test_futures_size`. [`IgnoreOutcome`] is zero-sized, so a read carries no bytes for a
/// distinction only a mutable write asks about.
pub trait OutcomeSink: Copy + Send {
    fn record(self, unknown: &OutcomeUnknown);
}

/// Discards the outcome. Zero-sized, and what every read path passes.
#[derive(Clone, Copy)]
pub struct IgnoreOutcome;

impl OutcomeSink for IgnoreOutcome {
    fn record(self, _unknown: &OutcomeUnknown) {}
}

/// Records the outcome for a caller that asked for one.
///
/// A shared reference so the sink stays `Copy`, and a mutex rather than a `Cell` so the future
/// holding it is still `Send`.
#[derive(Clone, Copy)]
pub struct RecordOutcome<'a>(pub &'a SyncMutex<Option<OutcomeUnknown>>);

impl OutcomeSink for RecordOutcome<'_> {
    fn record(self, unknown: &OutcomeUnknown) {
        *self.0.lock() = Some(unknown.clone());
    }
}

/// A failed [`send_command`], with what the transport knows about whether the request reached
/// the server.
///
/// The dispatch state is what separates "the server cannot have seen this" from "the server
/// may have applied this and the answer was lost", which is the only basis on which a mutable
/// command may or may not be sent again.
struct SendFailure {
    error: QuicClientError,
    dispatched: DispatchState,
}

impl SendFailure {
    /// A failure that happened before any request byte could reach the wire.
    fn not_dispatched(error: QuicClientError) -> Self {
        Self {
            error,
            dispatched: DispatchState::NotDispatched,
        }
    }

    /// A failure after the request was handed to the stream, with no answer from the server.
    /// Written this way round on purpose: a partial write may already have reached the peer,
    /// so an incomplete write counts as dispatched rather than being assumed harmless.
    fn response_lost(error: QuicClientError) -> Self {
        Self {
            error,
            dispatched: DispatchState::DispatchedResponseLost,
        }
    }

    /// An error the server sent back. The command reached it; the answer does not prove the
    /// handler had no effect.
    fn answered(error: QuicClientError) -> Self {
        Self {
            error,
            dispatched: DispatchState::DispatchedAndAnswered,
        }
    }
}

#[error_set]
pub enum ReconnectError {
    Disconnected,
    NotAuthorized,
}

/// Send a command to the QUIC server, automatically reconnecting on transient failures.
///
/// Acquires a rate-limiting permit, sends the command via [`send_command`], and handles
/// the response. On transient errors (`Terminated`, `StreamOpen`), triggers a reconnect
/// and retries. On ambiguous errors, checks whether a concurrent reconnect already
/// occurred (via the epoch counter) and retries if so, otherwise propagates the error.
///
/// `HIGH_PRIORITY` is a const generic rather than a runtime parameter to keep it out of
/// the async future state. Because this function contains a retry loop with multiple await
/// points, any runtime parameter would be captured in the compiler-generated future struct
/// for the lifetime of the loop. The `Storage::get` future is heap-allocated via
/// `async_trait` boxing, so every byte in the future state is a per-request allocation
/// cost. Using a const generic resolves the priority value at compile time through
/// monomorphization, adding zero bytes to the future. This is validated by the
/// `test_futures_size` test which enforces a strict upper bound on the get future size.
///
/// `unknown` is how the typed path learns that the error it is about to see is an ambiguous
/// mutable write rather than a failure. See [`OutcomeSink`] for why it is a by-value generic
/// rather than a richer return type or an out-parameter.
pub async fn send_with_reconnect<
    ServiceClientType,
    Sink,
    const LEN: usize,
    const HIGH_PRIORITY: bool,
>(
    service_client: &ServiceClientType,
    request_type: ServiceClientType::RequestType,
    session_id: u32,
    chunks: impl Fn() -> [Bytes; LEN],
    unknown: Sink,
) -> Result<Bytes, ServiceClientType::ErrorType>
where
    ServiceClientType: ServiceClient,
    Sink: OutcomeSink,
{
    let epoch = service_client.quic().epoch.load(Ordering::Relaxed);
    let failure = {
        let Some(_permit) = service_client.acquire_command_permit().await else {
            return Err(
                service_client.map_send_error(request_type, SendWithReconnectError::PermitAcquire)
            );
        };
        // No session check here any more, deliberately. One used to sit at this point, comparing
        // the epoch after the permit wait, and it was unsound in both directions: it could not
        // see a connection replaced during the awaits that follow it, and the epoch it compared
        // is published after the swap rather than at it. The check now lives at the write
        // boundary inside `send_command_tracked`, under the connection read lock and in the same
        // section that takes the writer, where nothing can invalidate it before the bytes are
        // framed. Removing it here also keeps its captured epoch out of this future, which is
        // size bounded by `test_futures_size`.
        match send_command_tracked::<HIGH_PRIORITY>(
            service_client.quic().clone(),
            request_type.into(),
            session_id,
            service_client.v4_protocol(),
            &mut chunks(),
        )
        .await
        {
            Ok(payload) => return Ok(payload),
            Err(failure) => failure,
        }
        // The permit is released here, before anything reconnects.
    };

    // Resolved before the await below, not across it. A `Verdict` carries a mapped error, and
    // holding one over a reconnect would put that error in this function's future for the
    // length of the reconnect.
    match classify(service_client, request_type, epoch, &failure) {
        Verdict::Failed(error) => return Err(error),
        Verdict::Unknown => return Err(report_unknown(service_client, request_type, unknown)),
        Verdict::Reconnect => {}
    }

    // Everything past this point reconnects, and none of it belongs in this function's future:
    // that future is the read path's, is heap-allocated once per request through `async_trait`,
    // and is held to a size bound by `test_futures_size`. Boxing the recovery keeps the
    // recovery's own state off every successful read.
    Box::pin(reconnect_and_retry::<
        ServiceClientType,
        Sink,
        LEN,
        HIGH_PRIORITY,
    >(
        service_client,
        request_type,
        session_id,
        chunks,
        unknown,
        epoch,
        failure,
    ))
    .await
}

/// What to do about a failed send.
enum Verdict<ErrorType> {
    /// Definitely failed. Nothing to recover.
    Failed(ErrorType),
    /// Dispatched, response lost, and not repeatable.
    Unknown,
    /// Worth another attempt once the connection has been replaced.
    Reconnect,
}

/// Decide a failed send's fate.
///
/// Synchronous on purpose: it runs between the send and the reconnect, so anything it held
/// would live in the caller's future across the reconnect await.
fn classify<ServiceClientType>(
    service_client: &ServiceClientType,
    request_type: ServiceClientType::RequestType,
    epoch: u32,
    failure: &SendFailure,
) -> Verdict<ServiceClientType::ErrorType>
where
    ServiceClientType: ServiceClient,
{
    // Ambiguity first, whatever the error kind and whatever the epoch has done. Every error
    // below is either an answer the server sent or a failure before the wire, so reaching this
    // means the request went out and its answer did not come back — and for a command that must
    // not be repeated, that is the whole verdict. Checking it per-branch instead left
    // `WriteChunks` and `Read` reporting an ambiguous write as a plain failure.
    if outcome_is_unknown(
        service_client.replay_class(request_type),
        failure.dispatched,
    ) {
        return Verdict::Unknown;
    }

    // A peer can lose the response from its own lower transport and report that fact through the
    // storage protocol. The answer reached this client, but the mutation's outcome is still
    // unknown. Preserve that result instead of flattening it into a replayable answered error.
    if matches!(failure.error, QuicClientError::OutcomeUnknown) {
        return Verdict::Unknown;
    }

    // An answered error is never evidence that redispatch is safe. Some handlers durably apply
    // one step before a later step returns the error. A sibling reconnect moving the epoch while
    // the answer is in flight does not change that fact, so return the answer before consulting
    // either reconnect counter.
    if failure.dispatched == DispatchState::DispatchedAndAnswered {
        return Verdict::Failed(service_client.map_send_error(
            request_type,
            SendWithReconnectError::ClientError(failure.error.clone()),
        ));
    }

    match failure.error {
        // Answers from the server that reconnecting cannot change. Bubble them up.
        QuicClientError::SlowDown
        | QuicClientError::NotAuthorized
        | QuicClientError::NotFound
        | QuicClientError::ClientMessageTooBig => Verdict::Failed(service_client.map_send_error(
            request_type,
            SendWithReconnectError::ClientError(failure.error.clone()),
        )),
        // A non-retryable connection error, so mark as disconnected immediately.
        QuicClientError::CrytpoError => Verdict::Failed(
            service_client.map_send_error(request_type, SendWithReconnectError::Disconnected),
        ),
        // Errors that call for a reconnect. The ambiguous case already returned above, so
        // reaching a reconnect means no dispatched no-replay command is waiting on it: nothing
        // establishes a replacement connection, runs a replacement `session_start`, or sends an
        // epoch-N+1 byte on behalf of a command that must not be repeated.
        QuicClientError::Terminated | QuicClientError::StreamOpen => Verdict::Reconnect,
        // The write boundary refused the id. Reconnecting is the one thing that must not happen:
        // the connection is fine, it is the id that is stale, and retrying here would spend the
        // budget re-offering the same stale id. The session layer resolves a replacement session
        // and re-enters with a valid one.
        QuicClientError::SessionRebindRequired => Verdict::Failed(
            service_client
                .map_send_error(request_type, SendWithReconnectError::SessionRebindRequired),
        ),
        // Other transport failures. Only a proven pre-dispatch failure may ask the session layer
        // to rebind. A response-lost read is replayable by policy, but this frame no longer has
        // proof that the operation itself never reached the wire.
        _ => {
            let epoch_current = service_client.quic().epoch.load(Ordering::Relaxed);
            if epoch_current == 0 {
                return Verdict::Failed(
                    service_client
                        .map_send_error(request_type, SendWithReconnectError::Disconnected),
                );
            }
            if epoch >= epoch_current {
                // Nothing reconnected, so this is a real failure.
                return Verdict::Failed(service_client.map_send_error(
                    request_type,
                    SendWithReconnectError::ClientError(failure.error.clone()),
                ));
            }
            // The connection was replaced while this command was in flight, by somebody else's
            // reconnect. Only a failure before dispatch may use that replacement as retry
            // authority. Every other failure returns its original error.
            if failure.dispatched == DispatchState::NotDispatched {
                Verdict::Failed(
                    service_client.map_send_error(
                        request_type,
                        SendWithReconnectError::SessionRebindRequired,
                    ),
                )
            } else {
                Verdict::Failed(service_client.map_send_error(
                    request_type,
                    SendWithReconnectError::ClientError(failure.error.clone()),
                ))
            }
        }
    }
}

/// The cold half of [`send_with_reconnect`]: replace the connection, then spend the one
/// remaining attempt.
///
/// There is no loop. The end-to-end budget is two dispatches — the caller's first and the one
/// below — and expressing that structurally is what makes "no layer resets or nests it" a
/// property of the code rather than of a counter someone has to reason about.
async fn reconnect_and_retry<ServiceClientType, Sink, const LEN: usize, const HIGH_PRIORITY: bool>(
    service_client: &ServiceClientType,
    request_type: ServiceClientType::RequestType,
    session_id: u32,
    chunks: impl Fn() -> [Bytes; LEN],
    unknown: Sink,
    epoch: u32,
    first_failure: SendFailure,
) -> Result<Bytes, ServiceClientType::ErrorType>
where
    ServiceClientType: ServiceClient,
    Sink: OutcomeSink,
{
    if reconnect(
        service_client.endpoint_config(),
        service_client.alpn(),
        service_client.auth_adapter().clone(),
        service_client.transport_config(),
        service_client.quic().clone(),
        epoch,
    )
    .await
    .is_err()
    {
        return Err(
            service_client.map_send_error(request_type, SendWithReconnectError::ReconnectFailed)
        );
    }

    // The connection is now a new epoch with its own server-side session namespace. A captured
    // session id from the old one is meaningless to it and must never go on the wire, so the
    // session-aware layer resolves a replacement before anything is sent.
    if session_id != 0 {
        return Err(
            if first_failure.dispatched == DispatchState::NotDispatched {
                service_client
                    .map_send_error(request_type, SendWithReconnectError::SessionRebindRequired)
            } else {
                service_client.map_send_error(
                    request_type,
                    SendWithReconnectError::ClientError(first_failure.error),
                )
            },
        );
    }

    let first_error = first_failure.error;
    let epoch = service_client.quic().epoch.load(Ordering::Relaxed);
    let failure = {
        let Some(_permit) = service_client.acquire_command_permit().await else {
            return Err(
                service_client.map_send_error(request_type, SendWithReconnectError::PermitAcquire)
            );
        };
        match send_command_tracked::<HIGH_PRIORITY>(
            service_client.quic().clone(),
            request_type.into(),
            session_id,
            service_client.v4_protocol(),
            &mut chunks(),
        )
        .await
        {
            Ok(payload) => return Ok(payload),
            Err(failure) => failure,
        }
    };

    match classify(service_client, request_type, epoch, &failure) {
        Verdict::Failed(error) => Err(error),
        Verdict::Unknown => Err(report_unknown(service_client, request_type, unknown)),
        // The budget is spent. Reconnecting again here is the nested retry the contract
        // forbids, so the first attempt's error is what the caller is told.
        Verdict::Reconnect => Err(service_client.map_send_error(
            request_type,
            SendWithReconnectError::ClientError(first_error),
        )),
    }
}

/// The budget this module implements structurally rather than by counting. Both dispatches are
/// written out above; a change to the constant has to be a change to the code.
const _: () = assert!(
    ATTEMPT_BUDGET == 2,
    "send_with_reconnect performs exactly one retry after a reconnect"
);

/// Record an ambiguous mutable write for a caller that asked for one, and produce the error
/// every caller gets.
///
/// The error is produced either way, so a caller that did not ask sees exactly what it saw
/// before this distinction existed rather than a new failure mode it has no handling for.
fn report_unknown<ServiceClientType, Sink>(
    service_client: &ServiceClientType,
    request_type: ServiceClientType::RequestType,
    sink: Sink,
) -> ServiceClientType::ErrorType
where
    ServiceClientType: ServiceClient,
    Sink: OutcomeSink,
{
    let unknown = OutcomeUnknown {
        command: service_client.request_name(request_type),
    };
    sink.record(&unknown);
    service_client.map_send_error(
        request_type,
        SendWithReconnectError::OutcomeUnknown(unknown),
    )
}

/// Whether a failed command's fate is unknown rather than failed.
///
/// Both conditions are needed. A command that never reached the wire did not happen whatever
/// its class, and a read that reached the wire can simply be asked again.
fn outcome_is_unknown(replay_class: ReplayClass, dispatched: DispatchState) -> bool {
    replay_class == ReplayClass::MutableNoReplay
        && dispatched == DispatchState::DispatchedResponseLost
}

fn strip_ipv6_brackets(host: &str) -> &str {
    if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

pub mod insecure_client_auth {
    use std::sync::Arc;

    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::ServerName;
    use rustls::pki_types::UnixTime;

    #[derive(Debug)]
    pub struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

    impl SkipServerVerification {
        pub fn new() -> Arc<Self> {
            Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
        }
    }

    impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

fn client_crypto_config(
    alpn: &str,
    certificate_settings: CertificateSettings,
    validate_server_certificate: bool,
) -> Result<rustls::ClientConfig, ProtocolError> {
    let client_builder = if !validate_server_certificate {
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(insecure_client_auth::SkipServerVerification::new())
    } else {
        let mut cert_store = RootCertStore::empty();

        // load built in webpki certs
        cert_store.extend(TLS_SERVER_ROOTS.iter().cloned());

        // load native certs
        let native_certs = load_native_certs();
        if native_certs.certs.is_empty() {
            lore_warn!(
                "no certificates loaded from the OS trust store, continuing with the built-in webpki roots: {:?}",
                native_certs.errors
            );
        }
        for cert in native_certs.certs {
            let _ = cert_store.add(cert);
        }

        // load custom ca
        if let Some(ca_path) = &certificate_settings.custom_ca {
            let ca_certs = load_certs(ca_path).forward_with::<ProtocolError, _>(|| {
                format!("loading CA certificate from {}", ca_path.display())
            })?;
            for cert in ca_certs {
                let _ = cert_store.add(cert);
            }
        }

        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(cert_store)
    };

    let mut cfg = if let Some(client_certs) = certificate_settings.client {
        // Load client certificate(s)
        let mut certs =
            load_certs(&client_certs.cert_file).forward_with::<ProtocolError, _>(|| {
                format!(
                    "loading client certificate from {}",
                    client_certs.cert_file.display()
                )
            })?;

        // Append chain if provided
        if let Some(chain_path) = &certificate_settings.custom_ca {
            let chain_certs = load_certs(chain_path).forward_with::<ProtocolError, _>(|| {
                format!("loading certificate chain from {}", chain_path.display())
            })?;
            certs.extend(chain_certs);
        }

        // Load private key
        let key =
            load_private_key(&client_certs.pkey_file).forward_with::<ProtocolError, _>(|| {
                format!(
                    "loading private key from {}",
                    client_certs.pkey_file.display()
                )
            })?;

        client_builder
            .with_client_auth_cert(certs, key)
            .internal("building client auth certificate chain")?
    } else {
        client_builder.with_no_client_auth()
    };

    cfg.enable_early_data = true;
    cfg.alpn_protocols = vec![alpn.into()];

    Ok(cfg)
}

pub async fn connect(
    config: &EndpointConfig,
    certificate_settings: CertificateSettings,
    alpn: &str,
    transport: TransportConfig,
) -> Result<quinn::Connection, ProtocolError> {
    let remote_url = config.remote_url.as_str();
    let url = Url::parse(remote_url).internal_with(|| format!("remote {remote_url} is invalid"))?;
    let host = url.host_str().unwrap_or_default().to_string();
    let remote_addrs: Vec<_> = (
        strip_ipv6_brackets(host.as_str()),
        url.port().unwrap_or(config.default_port),
    )
        .to_socket_addrs()
        .internal_with(|| format!("remote {remote_url} is invalid"))?
        .collect();
    let remote_addrs = interleave_socket_addrs(remote_addrs);
    let server_name = config.sni_override.as_deref().unwrap_or(host.as_str());

    let validate_certificate = url.scheme().ends_with("s");
    let crypto_config = client_crypto_config(alpn, certificate_settings, validate_certificate)?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto_config).internal("configuring QUIC client crypto")?,
    ));

    let mut transport_config = quinn::TransportConfig::default();
    transport_config
        .max_concurrent_uni_streams(0_u8.into())
        .max_concurrent_bidi_streams(STREAM_COUNT.into());

    transport_config
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(IDLE_TIMEOUT_MS))))
        .keep_alive_interval(Some(Duration::from_millis(KEEP_ALIVE_MS)));

    let recv_window = (transport.max_bytes_bandwidth_per_second / 1000) * transport.expected_rtt_ms;
    let send_window = recv_window;
    // Any stream can use at most 3 times the average stream recv window
    let stream_recv_window = (recv_window / STREAM_COUNT as u64) * 3;

    transport_config
        .send_window(send_window)
        .receive_window(VarInt::from_u64(recv_window).map_err(|_err| {
            lore_warn!("recv_window {recv_window} exceeds VarInt max");
            ProtocolError::internal("client initialization failure")
        })?)
        .stream_receive_window(VarInt::from_u64(stream_recv_window).map_err(|_err| {
            lore_warn!("stream_recv_window {stream_recv_window} exceeds VarInt max");
            ProtocolError::internal("client initialization failure")
        })?)
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0);

    let mut ack_freq_config = AckFrequencyConfig::default();
    ack_freq_config.reordering_threshold(VarInt::from_u32(PACKET_THRESHOLD - 1));

    transport_config
        .send_fairness(false)
        .packet_threshold(PACKET_THRESHOLD)
        .time_threshold(TIME_THRESHOLD)
        .max_rtt(Duration::from_millis(MAX_RTT_MS))
        .ack_frequency_config(Some(ack_freq_config));

    let congestion_controller: Arc<dyn congestion::ControllerFactory + Send + Sync + 'static> =
        match transport.congestion_algorithm {
            CongestionAlgorithm::Bbr => {
                let mut bbr = congestion::BbrConfig::default();
                if let Some(cwnd) = transport.initial_cwnd {
                    bbr.initial_window(cwnd);
                }
                Arc::new(bbr)
            }
            CongestionAlgorithm::Cubic => {
                let mut cubic = congestion::CubicConfig::default();
                if let Some(cwnd) = transport.initial_cwnd {
                    cubic.initial_window(cwnd);
                }

                Arc::new(cubic)
            }
        };
    transport_config.congestion_controller_factory(congestion_controller);

    lore_debug!("QUIC transport config: {transport_config:?}");

    client_config.transport_config(Arc::new(transport_config));

    let connection = connect_happy_eyeballs(
        remote_addrs,
        Duration::from_millis(HAPPY_EYEBALLS_DELAY_MS),
        |remote_addr| {
            connect_to_addr(
                client_config.clone(),
                host.clone(),
                remote_addr,
                server_name.to_string(),
            )
        },
    )
    .await;
    if let Some(connection) = connection {
        return Ok(connection);
    }

    // Every candidate address failed; the server is unreachable. Classify as
    // `Disconnected`. Per-attempt details are logged above.
    lore_debug!("QUIC connect failed {remote_url}");
    Err(ProtocolError::from(Disconnected))
}

fn interleave_socket_addrs(remote_addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first) = remote_addrs.first() else {
        return remote_addrs;
    };
    let prefer_ipv6 = first.is_ipv6();
    let (preferred, fallback): (Vec<_>, Vec<_>) = remote_addrs
        .into_iter()
        .partition(|addr| addr.is_ipv6() == prefer_ipv6);
    let mut preferred = preferred.into_iter();
    let mut fallback = fallback.into_iter();
    let mut interleaved = Vec::with_capacity(preferred.len() + fallback.len());

    loop {
        if let Some(addr) = preferred.next() {
            interleaved.push(addr);
        } else {
            interleaved.extend(fallback);
            break;
        }
        if let Some(addr) = fallback.next() {
            interleaved.push(addr);
        } else {
            interleaved.extend(preferred);
            break;
        }
    }

    interleaved
}

async fn connect_happy_eyeballs<T, F, Fut>(
    remote_addrs: Vec<SocketAddr>,
    attempt_delay: Duration,
    mut connect: F,
) -> Option<T>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let mut remote_addrs = remote_addrs.into_iter();
    let mut attempts = FuturesUnordered::new();
    attempts.push(connect(remote_addrs.next()?));

    let mut next_addr = remote_addrs.next();
    let delay = tokio::time::sleep(attempt_delay);
    tokio::pin!(delay);

    loop {
        if next_addr.is_none() {
            while let Some(result) = attempts.next().await {
                if result.is_some() {
                    return result;
                }
            }
            return None;
        }

        tokio::select! {
            result = attempts.next(), if !attempts.is_empty() => {
                if let Some(Some(connection)) = result {
                    // Dropping `attempts` cancels the losing Quinn handshakes because each
                    // production future owns its `Connecting` and `Endpoint`.
                    return Some(connection);
                }
                if attempts.is_empty() {
                    let Some(addr) = next_addr.take() else {
                        continue;
                    };
                    attempts.push(connect(addr));
                    next_addr = remote_addrs.next();
                    delay.as_mut().reset(tokio::time::Instant::now() + attempt_delay);
                }
            }
            _ = &mut delay, if attempts.len() < HAPPY_EYEBALLS_MAX_IN_FLIGHT => {
                let Some(addr) = next_addr.take() else {
                    continue;
                };
                attempts.push(connect(addr));
                next_addr = remote_addrs.next();
                delay.as_mut().reset(tokio::time::Instant::now() + attempt_delay);
            }
        }
    }
}

async fn connect_to_addr(
    client_config: quinn::ClientConfig,
    host: String,
    remote_addr: SocketAddr,
    server_name: String,
) -> Option<quinn::Connection> {
    lore_debug!("QUIC connecting to {host} at {remote_addr}");
    let bind = if remote_addr.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    // The guard is what registers the UDP socket with net's reactor —
    // `tokio::net::UdpSocket::from_std` binds to whichever is current — and is scoped to the
    // synchronous construction, never held across an await. `NetRuntime` covers the drivers
    // quinn spawns later, here and on reconnect, but not this.
    //
    // This is `Endpoint::client` with the runtime supplied. Its dual-stack call is not
    // reproduced because the bind family is derived from the remote address above, so an
    // IPv6 socket is only ever used to reach an IPv6 peer.
    let endpoint = {
        let _guard = lore_base::runtime::net_runtime().enter();
        std::net::UdpSocket::bind(bind).and_then(|socket| {
            quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                socket,
                Arc::new(crate::quic::net_runtime::NetRuntime),
            )
        })
    };
    let mut endpoint = match endpoint {
        Ok(endpoint) => endpoint,
        Err(err) => {
            lore_debug!("QUIC failed binding socket to {bind} for {remote_addr}: {err}");
            return None;
        }
    };
    endpoint.set_default_client_config(client_config);

    // `connect` resolves timers and any lazily created state against the current runtime, so
    // enter net here too rather than relying on the caller's — this is also the reconnect path.
    let connect_result = {
        let _guard = lore_base::runtime::net_runtime().enter();
        endpoint.connect(remote_addr, server_name.as_str())
    };
    let connecting = match connect_result {
        Ok(connecting) => connecting,
        Err(err) => {
            lore_debug!("Failed QUIC connect to {remote_addr}: {err}");
            return None;
        }
    };
    match tokio::time::timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), connecting).await {
        Ok(Ok(connection)) => {
            lore_debug!("Success QUIC connecting to {remote_addr}");
            Some(connection)
        }
        Ok(Err(err)) => {
            lore_debug!("Failed QUIC connecting to {remote_addr}: {err}");
            None
        }
        Err(_) => {
            lore_debug!("QUIC handshake timeout to {remote_addr}");
            None
        }
    }
}

pub async fn reconnect<AuthErrorType>(
    config: EndpointConfig,
    alpn: &str,
    auth_adapter: Arc<dyn AuthAdapter<ErrorType = AuthErrorType>>,
    transport_config: TransportConfig,
    connection: Arc<QuicConnection>,
    epoch: u32,
) -> Result<(), ReconnectError>
where
    AuthErrorType: std::error::Error + Send + Sync,
{
    let remote_url = &config.remote_url;
    let Ok(_permit) = connection.reconnect_guard.acquire().await else {
        return Err(ReconnectError::from(Disconnected));
    };

    let epoch_current = connection.epoch.load(Ordering::Relaxed);
    if epoch_current == 0 {
        // Reconnection failed, give up
        return Err(ReconnectError::from(Disconnected));
    }
    if epoch < epoch_current {
        // Something else reconnected
        return Ok(());
    }

    let elapsed = connection.created.elapsed().as_millis() as u64;
    {
        let quinn = connection.connection.read().await;
        let connection_id = quinn.connection.stable_id();
        lore_warn!(
            "QUIC lost connection {connection_id} to {remote_url} after {:.2}s: {:?} (last send: {:.2}s, last recv: {:.2}s)",
            elapsed as f64 / 1000.0,
            quinn.connection.close_reason(),
            (elapsed - connection.last_send.load(Ordering::Relaxed)) as f64 / 1000.0,
            (elapsed - connection.last_recv.load(Ordering::Relaxed)) as f64 / 1000.0
        );

        lore_debug!(
            "QUIC connection {connection_id} stats: {:?}",
            quinn.connection.stats()
        );

        quinn.connection.close(0u32.into(), b"lost connection");
    }

    if let Some(max_reconnects) = connection.max_reconnects
        // will be 1 for the initial successful initial connect, therefore if greater
        // than the max is when we have reached the limit
        && epoch_current > max_reconnects
    {
        lore_info!("Total reconnects to {remote_url} exhausted - not reconnecting");
        // Indicate that any pending commands entering their retry flow should give up
        connection.epoch.store(0, Ordering::Relaxed);
        return Err(ReconnectError::from(Disconnected));
    }

    let mut retry_count = 1;
    let mut retry = crate::util::retry(
        RECONNECT_START_DELAY,
        RECONNECT_MAX_DELAY,
        RECONNECT_MAX_ATTEMPTS,
    );

    loop {
        lore_info!(
            "Reconnecting to {} attempt {retry_count} / {RECONNECT_MAX_ATTEMPTS}",
            remote_url
        );

        let start = Instant::now();

        match connect(
            &config,
            auth_adapter.client_certs(),
            alpn,
            transport_config.clone(),
        )
        .await
        {
            Ok(quic_connection) => {
                lore_debug!(
                    "QUIC reconnected to {remote_url} in {}ms",
                    start.elapsed().as_millis()
                );

                let connection_id = quic_connection.stable_id();

                {
                    let mut connection_lock = connection.connection.write().await;
                    for reader in connection_lock.reader.drain(..) {
                        let _ = reader.task.await;
                    }

                    connection_lock.reader = vec![];
                    connection_lock.writer = vec![];
                    connection_lock.connection = quic_connection;
                    // Under the same write guard as the swap, so no send can observe the
                    // replacement streams while still reading the generation the sessions on the
                    // old connection were issued on. `epoch` cannot serve here: it is bumped
                    // below, after the first stream and the authorization, and a send landing in
                    // between would pass an epoch check and then write onto the new connection.
                    //
                    // The ids are dropped rather than left to age out. Every one of them belongs
                    // to the connection that is gone, and dropping them bounds the map to the
                    // sessions actually live on the connection in hand. A `register_session`
                    // still in flight records the generation it sampled before its
                    // `session_start`, so an insert landing after this clear is refused by the
                    // generation comparison rather than resurrected by it.
                    connection.generation.fetch_add(1, Ordering::Relaxed);
                    connection.sessions.clear();
                }

                let restart_flow = connection
                    .create_initial_stream()
                    .and_then(|_| auth_adapter.reconnect_authorize(connection.clone()));
                match restart_flow.await {
                    Ok(_) => {
                        connection.stream_count.store(1, Ordering::Relaxed);
                        // Indicate that the reconnect attempt was successful and let any
                        // pending commands see that they can just early out and resend
                        let epoch_current = 1 + connection.epoch.fetch_add(1, Ordering::Relaxed);

                        lore_debug!(
                            "QUIC reconnection {connection_id} to {remote_url} complete in {}ms ({epoch} -> {epoch_current})",
                            start.elapsed().as_millis()
                        );

                        break;
                    }
                    Err(
                        QuicClientError::StreamOpen
                        | QuicClientError::Terminated
                        | QuicClientError::SlowDown,
                    ) => {
                        lore_debug!("Reconnect authorization failed, retry");
                        if !retry.wait().await {
                            lore_debug!("Reconnect attempts exhausted, giving up");
                            {
                                let connection = connection.connection.write().await;
                                connection.connection.close(0u32.into(), b"failed connect");
                            }
                            // Indicate that any pending commands entering this flow should give up
                            connection.epoch.store(0, Ordering::Relaxed);
                            return Err(ReconnectError::from(Disconnected));
                        }
                    }
                    Err(err) => {
                        {
                            let connection = connection.connection.read().await;
                            connection
                                .connection
                                .close(0u32.into(), b"failed authorization");
                        }
                        // Indicate that any pending commands entering this flow should give up
                        connection.epoch.store(0, Ordering::Relaxed);

                        lore_error!("Failed to reconnect, authorization failed: {err}");
                        return Err(ReconnectError::from(NotAuthorized));
                    }
                }
            }
            Err(err) => {
                lore_debug!("Reconnect attempt failed: {err}");
                if !retry.wait().await {
                    lore_debug!("Reconnect attempts exhausted, giving up");
                    {
                        let connection = connection.connection.write().await;
                        connection.connection.close(0u32.into(), b"failed connect");
                    }
                    // Indicate that any pending commands entering this flow should give up
                    connection.epoch.store(0, Ordering::Relaxed);
                    return Err(ReconnectError::from(Disconnected));
                }
            }
        }

        retry_count += 1;
    }

    lore_info!("Reconnected to {}", remote_url);

    Ok(())
}

/// Open an additional stream on the connection and return the index to send on.
///
/// `stream_count` is published as the number of open streams, so that `send_command`,
/// which compares its round-robin index against it, stops asking for more streams once
/// all `STREAM_COUNT` of them exist.
async fn add_stream(connection: Arc<QuicConnection>) -> Result<u32, QuicClientError> {
    let last_recv = connection.last_recv.clone();
    let created = connection.created;

    let mut connection_lock = connection.connection.write().await;

    let stream_index = connection_lock.writer.len() as u32;

    if stream_index < STREAM_COUNT {
        let (send, recv) = connection_lock
            .connection
            .open_bi()
            .await
            .inspect_err(|err| {
                if stream_index == 0 {
                    lore_debug!("Unable to open base stream: {err}");
                }
            })
            .map_err(|_err| QuicClientError::StreamOpen)?;
        connection_lock.writer.push(Arc::new(Mutex::new(send)));
        connection_lock.reader.push(ResponseReader::new(
            stream_index,
            recv,
            connection.max_chunk_size,
            last_recv.clone(),
            created,
            connection.v4,
        ));

        connection
            .stream_count
            .store(stream_index + 1, Ordering::Relaxed);

        Ok(stream_index)
    } else {
        Ok(stream_index - 1)
    }
}

/// Counts a request as outstanding on a stream for as long as the guard is alive.
///
/// The count is what the high priority path of [`select_stream`] balances on, so it has
/// to come back down on every way out of a send - error returns and a dropped send future
/// included, not just the successful path.
struct StreamInflightGuard<'a> {
    inflight: &'a AtomicU64,
}

impl<'a> StreamInflightGuard<'a> {
    fn new(inflight: &'a AtomicU64) -> Self {
        inflight.fetch_add(1, Ordering::Relaxed);
        Self { inflight }
    }
}

impl Drop for StreamInflightGuard<'_> {
    fn drop(&mut self) {
        self.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Select stream index based on priority scheduling.
fn select_stream(
    stream_inflight: &[AtomicU64],
    non_priority_counter: &AtomicU32,
    reader_count: u32,
    high_priority: bool,
) -> u32 {
    if high_priority {
        // Pick the stream with fewest outstanding requests
        let mut min_inflight = u64::MAX;
        let mut min_stream = 0u32;
        for i in 0..reader_count {
            let inflight = stream_inflight[i as usize].load(Ordering::Relaxed);
            if inflight < min_inflight {
                min_inflight = inflight;
                min_stream = i;
            }
        }
        min_stream
    } else {
        // Round-robin across streams PRIORITY_STREAM_COUNT..STREAM_COUNT
        let index = non_priority_counter.fetch_add(1, Ordering::Relaxed);
        if reader_count > PRIORITY_STREAM_COUNT {
            PRIORITY_STREAM_COUNT + (index % (reader_count - PRIORITY_STREAM_COUNT))
        } else {
            0
        }
    }
}

pub async fn send_normal(
    connection: Arc<QuicConnection>,
    command: QuicOpCode,
    session_id: u32,
    v4: bool,
    chunks: &mut [Bytes],
) -> Result<Bytes, QuicClientError> {
    send_command::<false>(connection, command, session_id, v4, chunks).await
}

pub async fn send_high_priority(
    connection: Arc<QuicConnection>,
    command: QuicOpCode,
    session_id: u32,
    v4: bool,
    chunks: &mut [Bytes],
) -> Result<Bytes, QuicClientError> {
    send_command::<true>(connection, command, session_id, v4, chunks).await
}

pub fn send_normal_with_reconnect<'a, ServiceClientType, const LEN: usize>(
    service_client: &'a ServiceClientType,
    request_type: ServiceClientType::RequestType,
    session_id: u32,
    chunks: impl Fn() -> [Bytes; LEN] + Send + 'a,
) -> impl Future<Output = Result<Bytes, ServiceClientType::ErrorType>> + Send + 'a
where
    ServiceClientType: ServiceClient,
{
    send_with_reconnect::<ServiceClientType, IgnoreOutcome, LEN, false>(
        service_client,
        request_type,
        session_id,
        chunks,
        IgnoreOutcome,
    )
}

pub fn send_high_priority_with_reconnect<'a, ServiceClientType, const LEN: usize>(
    service_client: &'a ServiceClientType,
    request_type: ServiceClientType::RequestType,
    session_id: u32,
    chunks: impl Fn() -> [Bytes; LEN] + Send + 'a,
) -> impl Future<Output = Result<Bytes, ServiceClientType::ErrorType>> + Send + 'a
where
    ServiceClientType: ServiceClient,
{
    send_with_reconnect::<ServiceClientType, IgnoreOutcome, LEN, true>(
        service_client,
        request_type,
        session_id,
        chunks,
        IgnoreOutcome,
    )
}

/// [`send_normal_with_reconnect`], reporting a lost dispatched response as
/// [`MutableOutcome::Unknown`] rather than as an error.
///
/// Only a caller that knows how to reconcile an ambiguous mutable write should use this. It
/// costs a frame the plain variant does not, which is affordable because this is the mutable
/// path rather than the read path the future-size bound protects.
pub async fn send_normal_with_reconnect_outcome<ServiceClientType, const LEN: usize>(
    service_client: &ServiceClientType,
    request_type: ServiceClientType::RequestType,
    session_id: u32,
    chunks: impl Fn() -> [Bytes; LEN] + Send,
) -> Result<MutableOutcome<Bytes>, ServiceClientType::ErrorType>
where
    ServiceClientType: ServiceClient,
{
    let unknown = SyncMutex::new(None);
    match send_with_reconnect::<ServiceClientType, RecordOutcome<'_>, LEN, false>(
        service_client,
        request_type,
        session_id,
        chunks,
        RecordOutcome(&unknown),
    )
    .await
    {
        Ok(payload) => Ok(MutableOutcome::Applied(payload)),
        // The error is the same one an unadopted caller is given. Having asked for the
        // distinction, this caller reads the outcome instead of the error.
        Err(error) => match unknown.into_inner() {
            Some(unknown) => Ok(MutableOutcome::Unknown(unknown)),
            None => Err(error),
        },
    }
}

pub async fn send_command<const HIGH_PRIORITY: bool>(
    connection: Arc<QuicConnection>,
    command: QuicOpCode,
    session_id: u32,
    v4: bool,
    chunks: &mut [Bytes],
) -> Result<Bytes, QuicClientError> {
    send_command_tracked::<HIGH_PRIORITY>(connection, command, session_id, v4, chunks)
        .await
        .map_err(|failure| failure.error)
}

/// [`send_command`], additionally reporting whether the request reached the wire.
///
/// Every early return below is a failure that happened before any byte of the request was
/// written, so only the write and the response wait are dispatched. That split is what the
/// replay contract branches on, so it is recorded here at the one place that can actually
/// observe it rather than inferred from an error kind further up.
async fn send_command_tracked<const HIGH_PRIORITY: bool>(
    connection: Arc<QuicConnection>,
    command: QuicOpCode,
    session_id: u32,
    v4: bool,
    chunks: &mut [Bytes],
) -> Result<Bytes, SendFailure> {
    {
        let stream_index = connection.counter.fetch_add(1, Ordering::Relaxed) % STREAM_COUNT;
        let stream_count = connection.stream_count.load(Ordering::Relaxed);

        if stream_count != 0 && stream_index >= stream_count {
            // Box the rare path to avoid increasing send_command future size
            let connection = connection.clone();
            Box::pin(async move { add_stream(connection).await })
                .await
                .map_err(SendFailure::not_dispatched)?;
        }
    }

    connection.last_send.store(
        connection.created.elapsed().as_millis() as u64,
        Ordering::Relaxed,
    );

    #[cfg(feature = "test_seams")]
    if session_id != 0
        && connection
            .pause_next_session_send
            .swap(false, Ordering::AcqRel)
    {
        connection.session_send_paused.add_permits(1);
        if let Ok(permit) = connection.resume_session_send.acquire().await {
            permit.forget();
        }
    }

    let (command_id, writer, rx, _inflight) = {
        let connection_lock = connection.connection.read().await;
        if connection_lock.reader.is_empty() {
            lore_debug!("No quic stream available when sending command");
            return Err(SendFailure::not_dispatched(QuicClientError::StreamOpen));
        }

        // The write boundary. Everything above is a caller's intent; from here the id is framed
        // and handed to a stream, so this is the last moment at which "is this id valid on the
        // connection I am about to write to" is still answerable — and the first at which the
        // answer cannot go stale, because a reconnect has to take this lock in write mode to
        // replace the connection, and cannot until the writer below has been taken.
        //
        // Refusing is the whole point. A session id the server issued on a connection that has
        // since been replaced is not merely unknown to the replacement: the replacement is free
        // to have issued the same number to a live session of its own, in which case the command
        // would be applied under that session's repository, user and permissions (INV-EO P0-1).
        // Nothing downstream can detect that, because the server answers it normally, so it is
        // refused here or not at all.
        //
        // The guard is released at the end of this block, before the write below, and the check
        // still holds afterwards for a reason worth stating because a refactor can destroy it:
        // the writer taken here is an `Arc` over one of *this* generation's `SendStream`s. A
        // reconnect replaces the vector, but this clone keeps pointing at a stream of the
        // connection that was closed, so a write after a swap fails rather than landing on the
        // replacement. Resolving the writer again after the guard drops — or reaching for
        // `connection.connection` below — would reopen P0-1.
        if session_id != 0 && !connection.session_is_current(session_id) {
            return Err(SendFailure::not_dispatched(
                QuicClientError::SessionRebindRequired,
            ));
        }

        // Select stream based on priority, computed inside lock to avoid living across await points
        let reader_count = connection_lock.reader.len() as u32;
        let stream_index = select_stream(
            connection.stream_inflight.as_slice(),
            &connection.non_priority_counter,
            reader_count,
            HIGH_PRIORITY,
        ) as usize
            % connection_lock.reader.len();
        let inflight = StreamInflightGuard::new(&connection.stream_inflight[stream_index]);

        let (tx, rx) = oneshot::channel();
        let command_id = connection_lock.reader[stream_index]
            .wait_for(tx)
            .map_err(SendFailure::not_dispatched)?;
        let writer = connection_lock.writer[stream_index].clone();
        (command_id, writer, rx, inflight)
    };

    {
        // Skip any previous header in case this is a resend
        let total_size: usize = chunks.iter().skip(1).map(|buffer| buffer.len()).sum();
        if total_size > connection.max_chunk_size {
            lore_debug!(
                "Client '{command}' message too big - message size '{total_size}' exceeds {}",
                connection.max_chunk_size
            );
            return Err(SendFailure::not_dispatched(
                QuicClientError::ClientMessageTooBig,
            ));
        }
        if v4 {
            let header =
                CommandHeader::new_with_session(command, command_id, total_size, session_id);
            chunks[0] = Bytes::from_owner(header.to_bytes_v4());
        } else {
            let header = CommandHeader::new(command, command_id, total_size);
            chunks[0] = Bytes::from_owner(header.to_bytes());
        }
    }

    {
        let mut stream = writer.lock_owned().await;
        // A failed `write_all_chunks` may still have flushed earlier chunks to the peer, so
        // this counts as dispatched. Treating a partial write as harmless is the assumption
        // that would let a mutable command be sent twice.
        stream.write_all_chunks(chunks).await.map_err(|err| {
            if let quinn::WriteError::ConnectionLost(_) = err {
                SendFailure::response_lost(QuicClientError::Terminated)
            } else {
                lore_warn!("{}: {err}", QuicClientError::WriteChunks);
                SendFailure::response_lost(QuicClientError::WriteChunks)
            }
        })?;
    }

    // The request is fully written by here, so the server has seen the command either way.
    // What is left is whether an answer came back, and the two ways it can fail to are not the
    // same thing to the replay contract.
    rx.await
        .map_err(|err| {
            lore_warn!("{}: {err}", QuicClientError::Read);
            SendFailure::response_lost(QuicClientError::Read)
        })?
        .map_err(|error| match error {
            // The reader task fails every still-pending command with exactly one of these two
            // when its stream ends (`ResponseReader::new`'s task, which drains `pending` on
            // exit). Reaching this arm therefore means the connection died with the answer
            // still outstanding, not that the server said no.
            QuicClientError::Terminated | QuicClientError::CrytpoError => {
                SendFailure::response_lost(error)
            }
            // Everything else was decoded from a response header the server actually sent.
            _ => SendFailure::answered(error),
        })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use parking_lot::Mutex;
    use tokio::sync::mpsc;

    use super::*;

    fn inflight_counters() -> [AtomicU64; STREAM_COUNT as usize] {
        std::array::from_fn(|_| AtomicU64::new(0))
    }

    #[test]
    fn inflight_guard_counts_a_request_only_while_it_is_outstanding() {
        let inflight = AtomicU64::new(0);

        {
            let _first = StreamInflightGuard::new(&inflight);
            assert_eq!(inflight.load(Ordering::Relaxed), 1);

            let _second = StreamInflightGuard::new(&inflight);
            assert_eq!(inflight.load(Ordering::Relaxed), 2);
        }

        assert_eq!(inflight.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn high_priority_spreads_concurrent_requests_over_every_stream() {
        let inflight = inflight_counters();
        let non_priority_counter = AtomicU32::new(0);

        let mut guards = Vec::new();
        let mut selected = Vec::new();
        for _ in 0..STREAM_COUNT {
            let stream = select_stream(&inflight, &non_priority_counter, STREAM_COUNT, true);
            guards.push(StreamInflightGuard::new(&inflight[stream as usize]));
            selected.push(stream);
        }

        selected.sort_unstable();
        assert_eq!(selected, (0..STREAM_COUNT).collect::<Vec<_>>());
    }

    #[test]
    fn high_priority_reuses_a_stream_once_its_request_completed() {
        let inflight = inflight_counters();
        let non_priority_counter = AtomicU32::new(0);

        for _ in 0..STREAM_COUNT * 4 {
            let stream = select_stream(&inflight, &non_priority_counter, STREAM_COUNT, true);
            let _guard = StreamInflightGuard::new(&inflight[stream as usize]);
            assert_eq!(stream, 0);
        }

        assert!(
            inflight
                .iter()
                .all(|count| count.load(Ordering::Relaxed) == 0)
        );
    }

    #[test]
    fn normal_priority_round_robins_over_the_non_priority_streams() {
        let inflight = inflight_counters();
        let non_priority_counter = AtomicU32::new(0);

        let selected: Vec<u32> = (PRIORITY_STREAM_COUNT..STREAM_COUNT)
            .map(|_| select_stream(&inflight, &non_priority_counter, STREAM_COUNT, false))
            .collect();

        assert_eq!(
            selected,
            (PRIORITY_STREAM_COUNT..STREAM_COUNT).collect::<Vec<_>>()
        );
    }
    fn ipv6_addr() -> SocketAddr {
        "[::1]:41337".parse().unwrap()
    }

    fn ipv4_addr() -> SocketAddr {
        "127.0.0.1:41337".parse().unwrap()
    }

    #[test]
    fn happy_eyeballs_interleaves_ipv6_first_addresses() {
        let ipv6_second = "[::2]:41337".parse().unwrap();
        let ipv6_third = "[::3]:41337".parse().unwrap();
        let ipv4_second = "127.0.0.2:41337".parse().unwrap();

        assert_eq!(
            interleave_socket_addrs(vec![
                ipv6_addr(),
                ipv6_second,
                ipv6_third,
                ipv4_addr(),
                ipv4_second,
            ]),
            vec![
                ipv6_addr(),
                ipv4_addr(),
                ipv6_second,
                ipv4_second,
                ipv6_third,
            ]
        );
    }

    #[test]
    fn happy_eyeballs_interleaves_ipv4_first_addresses() {
        let ipv4_second = "127.0.0.2:41337".parse().unwrap();
        let ipv6_second = "[::2]:41337".parse().unwrap();

        assert_eq!(
            interleave_socket_addrs(vec![ipv4_addr(), ipv4_second, ipv6_addr(), ipv6_second,]),
            vec![ipv4_addr(), ipv6_addr(), ipv4_second, ipv6_second]
        );
    }

    #[tokio::test]
    async fn happy_eyeballs_starts_fallback_while_first_attempt_is_stalled() {
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let attempt_log = attempts.clone();

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            connect_happy_eyeballs(
                vec![ipv6_addr(), ipv4_addr()],
                Duration::from_millis(10),
                move |addr| {
                    let attempt_log = attempt_log.clone();
                    async move {
                        attempt_log.lock().push(addr);
                        if addr.is_ipv6() {
                            std::future::pending().await
                        } else {
                            Some(addr)
                        }
                    }
                },
            ),
        )
        .await
        .expect("fallback should not wait for the stalled first attempt");

        assert_eq!(result, Some(ipv4_addr()));
        assert_eq!(*attempts.lock(), vec![ipv6_addr(), ipv4_addr()]);
    }

    #[tokio::test]
    async fn happy_eyeballs_advances_immediately_after_failure() {
        let started = std::time::Instant::now();

        let result = connect_happy_eyeballs(
            vec![ipv6_addr(), ipv4_addr()],
            Duration::from_secs(1),
            |addr| async move { if addr.is_ipv6() { None } else { Some(addr) } },
        )
        .await;

        assert_eq!(result, Some(ipv4_addr()));
        assert!(started.elapsed() < Duration::from_millis(750));
    }

    #[tokio::test]
    async fn happy_eyeballs_does_not_start_fallback_after_first_success() {
        let attempts = Arc::new(Mutex::new(HashMap::new()));
        let attempt_counts = attempts.clone();

        let result = connect_happy_eyeballs(
            vec![ipv6_addr(), ipv4_addr()],
            Duration::from_millis(10),
            move |addr| {
                let attempt_counts = attempt_counts.clone();
                async move {
                    *attempt_counts.lock().entry(addr).or_insert(0) += 1;
                    Some(addr)
                }
            },
        )
        .await;

        assert_eq!(result, Some(ipv6_addr()));
        assert_eq!(attempts.lock().get(&ipv6_addr()), Some(&1));
        assert_eq!(attempts.lock().get(&ipv4_addr()), None);
    }

    #[tokio::test]
    async fn happy_eyeballs_returns_none_when_all_attempts_fail() {
        let result = connect_happy_eyeballs(
            vec![ipv6_addr(), ipv4_addr()],
            Duration::from_millis(10),
            |_| async { None::<SocketAddr> },
        )
        .await;

        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn happy_eyeballs_bounds_in_flight_attempts() {
        let remote_addrs: Vec<_> = (1..=HAPPY_EYEBALLS_MAX_IN_FLIGHT + 1)
            .map(|port| SocketAddr::new(ipv6_addr().ip(), port as u16))
            .collect();
        let release = Arc::new(Semaphore::new(0));
        let attempt_release = release.clone();
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();

        let task = lore_base::lore_spawn!(connect_happy_eyeballs(
            remote_addrs.clone(),
            Duration::from_millis(1),
            move |addr| {
                started_tx.send(addr).unwrap();
                let attempt_release = attempt_release.clone();
                async move {
                    attempt_release.acquire().await.unwrap().forget();
                    None::<SocketAddr>
                }
            },
        ));

        for expected in remote_addrs.iter().take(HAPPY_EYEBALLS_MAX_IN_FLIGHT) {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
                    .await
                    .expect("attempt should start"),
                Some(*expected)
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), started_rx.recv())
                .await
                .is_err(),
            "attempts above the in-flight limit should remain queued"
        );

        release.add_permits(1);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
                .await
                .expect("queued attempt should start when a slot opens"),
            Some(remote_addrs[HAPPY_EYEBALLS_MAX_IN_FLIGHT])
        );

        task.abort();
    }

    /// A live loopback QUIC connection, self-signed and unverified (mirrors `connect()`'s own
    /// `validate_server_certificate: false` path). `session_is_current` and its two writers
    /// never touch the socket -- only `generation`/`sessions` -- but `QuicConnection` has no
    /// constructor that does not require a real `quinn::Connection`, so this builds the
    /// cheapest one that satisfies the type. Held connections/endpoints are leaked into the
    /// returned `JoinHandle` rather than gracefully closed; the process exits at the end of the
    /// test binary regardless, and this keeps the fixture to what the pin actually needs.
    async fn loopback_quic_connection() -> (quinn::Connection, tokio::task::JoinHandle<()>) {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::PrivateKeyDer;
        use rustls::pki_types::pem::PemObject;

        const ALPN: &str = "lore-transport-client-test-loopback";

        let cert = crate::tls::generate_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let cert_der = CertificateDer::from_pem_slice(cert.cert_pem.as_bytes())
            .expect("parse self-signed cert")
            .into_owned();
        let key_der =
            PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes()).expect("parse self-signed key");

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server crypto config");
        server_crypto.alpn_protocols = vec![ALPN.as_bytes().to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .expect("quic server crypto"),
        ));

        let server_endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
                .expect("bind server endpoint");
        let server_addr = server_endpoint.local_addr().unwrap();

        // Accept exactly one connection and hold both it and the endpoint alive for as long as
        // the caller keeps the returned task around.
        let accept_task = lore_base::lore_spawn!(async move {
            let incoming = server_endpoint.accept().await.expect("incoming connection");
            let _connection = incoming.await.expect("server-side handshake");
            std::future::pending::<()>().await
        });

        let client_crypto = client_crypto_config(
            ALPN,
            CertificateSettings {
                custom_ca: None,
                client: None,
            },
            false,
        )
        .expect("client crypto config");
        let client_config = quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_crypto).expect("quic client crypto"),
        ));
        let mut client_endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("bind client endpoint");
        client_endpoint.set_default_client_config(client_config);
        let quinn_connection = client_endpoint
            .connect(server_addr, "localhost")
            .expect("start connect")
            .await
            .expect("client-side handshake");

        (quinn_connection, accept_task)
    }

    /// Predicate-level coverage for the INV-EO P0-1 client-side gate:
    /// `session_is_current` must answer purely from `generation`/`sessions`.
    ///
    /// The enforcement pin is `not_dispatched_generation_mover_rebinds_and_retries_once` in
    /// `quic_session_rebind_test.rs`: it exercises `send_command_tracked` through the production
    /// path and fails if the write-boundary guard is removed. The server half (no two
    /// `SessionMap`s ever issue the same id) is pinned independently by
    /// `lore-server/src/protocol/storage/session.rs`'s `two_maps_never_issue_the_same_session_id`,
    /// and the end-to-end wire behavior (both layers composed, through a real loopback server)
    /// by `lore-integration-tests/tests/quic_session_rebind_test.rs`'s R1/R2.
    #[tokio::test]
    async fn a_session_id_stops_being_current_once_its_generation_is_replaced() {
        let (quinn_connection, accept_task) = loopback_quic_connection().await;
        let quic = QuicConnection::with_v4(quinn_connection, 65536, true);

        assert!(
            !quic.session_is_current(7),
            "an id this connection never issued must never be current"
        );

        let generation_before = quic.connection_generation();
        quic.register_session(7, generation_before);
        assert!(
            quic.session_is_current(7),
            "an id just registered on the connection's current generation must be current"
        );

        // Simulate the generation bump `establish_quic_connection`'s reconnect performs inside
        // the connection write-lock section, at the swap -- the one property `session_is_current`
        // exists to check. `sessions` is deliberately left un-cleared here (a real reconnect also
        // clears it, see `client.rs`'s connection-swap block) so this test isolates the
        // generation *comparison* itself from that separate cleanup step.
        quic.generation.fetch_add(1, Ordering::Relaxed);
        assert_ne!(
            quic.connection_generation(),
            generation_before,
            "the simulated reconnect must have moved the generation"
        );
        assert!(
            !quic.session_is_current(7),
            "an id registered on a generation that has since been replaced must stop being \
             current, even though its entry is still physically present in the sessions map"
        );

        // A session registered AFTER the bump, on the new generation, is current.
        let generation_after = quic.connection_generation();
        quic.register_session(9, generation_after);
        assert!(
            quic.session_is_current(9),
            "an id registered on the connection's current generation is current"
        );
        assert!(
            !quic.session_is_current(7),
            "the old id must remain stale even after a newer id is registered"
        );

        // `forget_session` removes an entry outright, not just marking it stale.
        quic.forget_session(9);
        assert!(
            !quic.session_is_current(9),
            "a forgotten session id must stop being current"
        );

        // register_session(0, ..) is a no-op: 0 is the wire's "no session" sentinel and must
        // never occupy an entry, matching `send_command_tracked`'s own `session_id != 0` guard.
        quic.register_session(0, generation_after);
        assert!(
            !quic.session_is_current(0),
            "id 0 must never become current -- it names no session on the wire"
        );

        accept_task.abort();
    }

    #[derive(Debug)]
    struct MockError(String);

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for MockError {}

    /// Never called by `classify` (it touches only `replay_class`/`map_send_error`), but every
    /// `ServiceClient` needs one to construct.
    struct NoopAuthAdapter;

    #[async_trait]
    impl AuthAdapter for NoopAuthAdapter {
        type ErrorType = MockError;

        async fn initial_authorize(
            &self,
            _connection: Arc<QuicConnection>,
        ) -> Result<(), MockError> {
            Ok(())
        }

        async fn reconnect_authorize(
            &self,
            _connection: Arc<QuicConnection>,
        ) -> Result<(), QuicClientError> {
            Ok(())
        }

        fn client_certs(&self) -> CertificateSettings {
            CertificateSettings {
                custom_ca: None,
                client: None,
            }
        }
    }

    /// Minimal `ServiceClient` for exercising `classify` directly. `quic` is real (`classify`
    /// never calls `.quic()`, but the trait requires a valid `&Arc<QuicConnection>` to exist to
    /// return one) -- see `loopback_quic_connection`. `map_send_error` records the
    /// `SendWithReconnectError` variant it was given as text, via `{:?}`, so the test can assert
    /// exactly which arm fired without needing a richer mock error type.
    struct MockServiceClient {
        quic: Arc<QuicConnection>,
        auth_adapter: Arc<dyn AuthAdapter<ErrorType = MockError>>,
    }

    impl ServiceClient for MockServiceClient {
        const ALPN: &'static str = "mock/0";
        const DEFAULT_PORT: u16 = 0;
        type RequestType = QuicOpCode;
        type ErrorType = MockError;

        async fn acquire_command_permit(&self) -> Option<SemaphorePermit<'_>> {
            None
        }

        fn quic(&self) -> &Arc<QuicConnection> {
            &self.quic
        }

        fn endpoint_config(&self) -> EndpointConfig {
            EndpointConfig {
                remote_url: "lore://127.0.0.1:0".to_string(),
                default_port: 0,
                sni_override: None,
            }
        }

        fn alpn(&self) -> &str {
            Self::ALPN
        }

        fn map_send_error(
            &self,
            _failed_request: Self::RequestType,
            error: SendWithReconnectError,
        ) -> Self::ErrorType {
            MockError(format!("{error:?}"))
        }

        fn auth_adapter(&self) -> &Arc<dyn AuthAdapter<ErrorType = Self::ErrorType>> {
            &self.auth_adapter
        }

        fn transport_config(&self) -> TransportConfig {
            TransportConfig {
                max_bytes_bandwidth_per_second: (1024 * 1024 * 1024) / 8,
                expected_rtt_ms: DEFAULT_EXPECTED_RTT_MS,
                congestion_algorithm: CongestionAlgorithm::Bbr,
                initial_cwnd: None,
            }
        }

        fn replay_class(&self, _request: Self::RequestType) -> ReplayClass {
            // Irrelevant here: `classify`'s `SessionRebindRequired` arm is checked after the
            // ambiguity check, but `SessionRebindRequired` is only ever raised for a command
            // that was NOT dispatched (`send_command_tracked`'s write-boundary refusal, before
            // any byte is framed), so `outcome_is_unknown` is false regardless of this value.
            ReplayClass::ReadRetryable
        }

        fn request_name(&self, _request: Self::RequestType) -> &'static str {
            "mock"
        }
    }

    /// INV-EO P0-1's write-boundary refusal (`QuicClientError::SessionRebindRequired`) must
    /// become `Verdict::Failed`, never `Verdict::Reconnect`. Reconnecting would spend the
    /// caller's retry budget re-offering the exact same stale id to the exact same connection
    /// generation that just refused it -- see `classify`'s own doc comment on this arm.
    #[tokio::test]
    async fn classify_maps_session_rebind_required_to_failed_not_reconnect() {
        let (quinn_connection, accept_task) = loopback_quic_connection().await;
        let mock = MockServiceClient {
            quic: Arc::new(QuicConnection::with_v4(quinn_connection, 65536, true)),
            auth_adapter: Arc::new(NoopAuthAdapter),
        };

        let failure = SendFailure::not_dispatched(QuicClientError::SessionRebindRequired);
        const PUT_OPCODE: QuicOpCode = 2; // storage_service::Command::Put's wire value
        let verdict = classify(&mock, PUT_OPCODE, 1, &failure);

        match verdict {
            Verdict::Failed(MockError(message)) => {
                assert!(
                    message.contains("SessionRebindRequired"),
                    "expected the SessionRebindRequired arm to have produced the error, got \
                     {message:?}"
                );
            }
            Verdict::Reconnect => panic!(
                "a refused stale session id must not be retried by reconnecting -- the id is \
                 stale, not the connection"
            ),
            Verdict::Unknown => panic!(
                "SessionRebindRequired is raised before any byte is dispatched, so it can never \
                 be the ambiguous case"
            ),
        }

        accept_task.abort();
    }
}
