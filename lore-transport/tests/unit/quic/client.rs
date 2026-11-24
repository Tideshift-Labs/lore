// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use lore_transport::quic::QuicClientError;
use lore_transport::quic::QuicOpCode;
use lore_transport::quic::client::*;
use lore_transport::replay::ReplayClass;
use parking_lot::Mutex;
use quinn::crypto::rustls::QuicClientConfig;
use tokio::sync::Semaphore;
use tokio::sync::SemaphorePermit;
use tokio::sync::mpsc;

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

    let mut guards = Vec::new();
    let mut selected = Vec::new();
    for _ in 0..STREAM_COUNT {
        let stream = select_stream(&inflight, STREAM_COUNT, true);
        guards.push(StreamInflightGuard::new(&inflight[stream as usize]));
        selected.push(stream);
    }

    selected.sort_unstable();
    assert_eq!(selected, (0..STREAM_COUNT).collect::<Vec<_>>());
}

#[test]
fn high_priority_reuses_a_stream_once_its_request_completed() {
    let inflight = inflight_counters();

    for _ in 0..STREAM_COUNT * 4 {
        let stream = select_stream(&inflight, STREAM_COUNT, true);
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
fn normal_priority_spreads_concurrent_requests_over_the_non_priority_streams() {
    let inflight = inflight_counters();

    let mut guards = Vec::new();
    let mut selected = Vec::new();
    for _ in PRIORITY_STREAM_COUNT..STREAM_COUNT {
        let stream = select_stream(&inflight, STREAM_COUNT, false);
        guards.push(StreamInflightGuard::new(&inflight[stream as usize]));
        selected.push(stream);
    }

    selected.sort_unstable();
    assert_eq!(
        selected,
        (PRIORITY_STREAM_COUNT..STREAM_COUNT).collect::<Vec<_>>()
    );
}

#[test]
fn normal_priority_leaves_the_priority_streams_to_metadata() {
    let inflight = inflight_counters();

    // Every non-priority stream is busy while the priority streams sit idle. Balancing on
    // outstanding requests alone would send bulk traffic to a priority stream; the reserved
    // window is what stops it.
    let _guards: Vec<_> = (PRIORITY_STREAM_COUNT..STREAM_COUNT)
        .map(|stream| StreamInflightGuard::new(&inflight[stream as usize]))
        .collect();

    let stream = select_stream(&inflight, STREAM_COUNT, false);
    assert!(
        stream >= PRIORITY_STREAM_COUNT,
        "bulk traffic must stay off the reserved streams, got {stream}"
    );
}

#[test]
fn normal_priority_shares_what_is_open_before_any_stream_can_be_reserved() {
    let inflight = inflight_counters();

    // With fewer streams open than the reservation needs, there is nothing to reserve.
    assert_eq!(select_stream(&inflight, 1, false), 0);
    assert_eq!(select_stream(&inflight, PRIORITY_STREAM_COUNT, false), 0);
}

#[test]
fn normal_priority_reuses_a_stream_once_its_request_completed() {
    let inflight = inflight_counters();

    for _ in 0..STREAM_COUNT * 4 {
        let stream = select_stream(&inflight, STREAM_COUNT, false);
        let _guard = StreamInflightGuard::new(&inflight[stream as usize]);
        assert_eq!(stream, PRIORITY_STREAM_COUNT);
    }

    assert!(
        inflight
            .iter()
            .all(|count| count.load(Ordering::Relaxed) == 0)
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

    let cert = lore_transport::tls::generate_self_signed(vec!["localhost".to_string()])
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

    let server_endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
        .expect("bind server endpoint");
    let server_addr = server_endpoint.local_addr().unwrap();

    // Accept exactly one connection and hold both it and the endpoint alive for as long as
    // the caller keeps the returned task around.
    let accept_task = lore_base::lore_spawn!(async move {
        let incoming = server_endpoint.accept().await.expect("incoming connection");
        let _connection = incoming.await.expect("server-side handshake");
        std::future::pending::<()>().await;
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
    quic.advance_generation_for_test();
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

    async fn initial_authorize(&self, _connection: Arc<QuicConnection>) -> Result<(), MockError> {
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

fn receive_buffer_size(socket: &std::net::UdpSocket) -> usize {
    socket2::SockRef::from(socket)
        .recv_buffer_size()
        .expect("socket receive buffer size should be readable")
}

fn bound_socket_with_receive_buffer(bytes: usize) -> std::net::UdpSocket {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");
    socket2::SockRef::from(&socket)
        .set_recv_buffer_size(bytes)
        .expect("receive buffer size should be settable");
    socket
}

#[test]
fn raise_receive_buffer_grows_a_smaller_buffer() {
    let socket = bound_socket_with_receive_buffer(64 * 1024);
    let before = receive_buffer_size(&socket);

    raise_receive_buffer(&socket, RECEIVE_BUFFER_BYTES);

    assert!(receive_buffer_size(&socket) > before);
}

#[test]
fn raise_receive_buffer_keeps_a_larger_buffer() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");
    let before = receive_buffer_size(&socket);

    // Asking for less than the buffer holds would shrink it, so an unchanged size shows the
    // request was not made.
    raise_receive_buffer(&socket, before / 4);

    assert_eq!(receive_buffer_size(&socket), before);
}

/// Held by the tests that drop a command part way through its frame, as one of them shortens the
/// time every dropped frame's remainder has to be written.
static FINISHING_FRAMES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A test server, and a client of it with a session started and the client's connection.
async fn served_connection() -> (
    crate::quic::storage_service::test_server::TestStorageServer,
    Arc<lore_transport::quic::storage_service::client::StorageClient>,
    Arc<QuicConnection>,
) {
    use lore_transport::traits::Storage;

    use crate::quic::storage_service::test_server::TestStorageServer;
    use crate::quic::storage_service::test_server::test_partition;

    let server = TestStorageServer::start();
    let client = server.connect_client().await;
    let quic = ServiceClient::quic(client.as_ref()).clone();
    client
        .session_start(test_partition(), "test")
        .await
        .expect("session start");
    (server, client, quic)
}

/// Drops, under a context of its own, a command whose frame the stream does not take whole while
/// the server reads nothing, once its write is held. Answers the index of the stream the frame is
/// finished on, the dropped command's context, and its payload, which it lends as a caller of the C
/// API does.
async fn drop_a_held_command(
    quic: &Arc<QuicConnection>,
) -> (
    usize,
    std::sync::Weak<dyn std::any::Any + Send + Sync>,
    std::sync::Weak<[u8]>,
) {
    use bytes::Bytes;
    use lore_transport::quic::storage_service::Command;

    let lent: Arc<[u8]> = Arc::from(vec![0xa5u8; 128 * 1024]);
    let dropped_payload = Arc::downgrade(&lent);
    let mut large = [Bytes::new(), Bytes::from_owner(lent)];
    let context: Arc<dyn std::any::Any + Send + Sync> = Arc::new(());
    let dropped_context = Arc::downgrade(&context);
    let dropped = tokio::time::timeout(
        Duration::from_millis(200),
        lore_base::runtime::LORE_CONTEXT.scope(
            context,
            send_normal(quic.clone(), Command::Put as u8, 0, true, &mut large),
        ),
    )
    .await;
    assert!(dropped.is_err(), "the write was not held: {dropped:?}");
    let inflight = quic.stream_inflight();
    assert_eq!(
        inflight.iter().sum::<u64>(),
        1,
        "the finish is not the one request outstanding: {inflight:?}"
    );
    let finishing = inflight
        .iter()
        .position(|&count| count == 1)
        .expect("the finish is counted on its stream");
    (finishing, dropped_context, dropped_payload)
}

/// A command dropped part way through writing its frame has the frame finished in the background,
/// so the command after it on the same stream reaches the server whole and is answered over the
/// same connection. Neither the background write nor a stream's reader, which serve every later
/// command, holds the dropped command's context, and the background write holds none of its
/// payload, which a caller may lend only until the command is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_command_dropped_mid_write_leaves_its_stream_framed() {
    use bytes::Bytes;
    use lore_transport::quic::storage_service::Command;

    use crate::quic::storage_service::test_server::wait_until;

    let _finishing = FINISHING_FRAMES.lock().await;
    let (server, _client, quic) = served_connection().await;
    server.pause_reading();
    let (finishing, dropped_context, dropped_payload) = drop_a_held_command(&quic).await;
    assert!(
        dropped_context.upgrade().is_none(),
        "a task the dropped command started holds its context"
    );
    wait_until(
        || dropped_payload.upgrade().is_none(),
        "the finish holds the dropped command's payload",
    )
    .await;
    server.resume_reading();
    wait_until(
        || quic.stream_inflight()[finishing] == 0,
        "the finish never released its stream",
    )
    .await;

    server.pause_reading();
    let after = {
        let quic = quic.clone();
        lore_base::lore_spawn!(async move {
            let mut small = [Bytes::new(), Bytes::from_static(b"after")];
            send_normal(quic, Command::Put as u8, 0, true, &mut small).await
        })
    };
    wait_until(
        || quic.stream_inflight()[finishing] == 1,
        "the command after the dropped one went out on another stream",
    )
    .await;
    server.resume_reading();
    let answered = tokio::time::timeout(Duration::from_secs(10), after)
        .await
        .expect("the command after the dropped one was never answered")
        .expect("the command's task");
    assert!(answered.is_ok(), "{answered:?}");
    assert_eq!(server.accepted_connections(), 1);
}

/// A command sent while a stream finishes a dropped frame goes out on another stream rather than
/// queueing behind the dropped frame's rest. The server reads nothing meanwhile, so it is written
/// only on a stream other than the dropped frame's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_finishing_a_dropped_frame_is_passed_over() {
    use bytes::Bytes;
    use lore_transport::quic::storage_service::Command;

    use crate::quic::storage_service::test_server::wait_until;

    let _finishing = FINISHING_FRAMES.lock().await;
    let (server, _client, quic) = served_connection().await;
    server.pause_reading();
    let (finishing, ..) = drop_a_held_command(&quic).await;

    let mut small = [Bytes::new(), Bytes::from_static(b"meanwhile")];
    let written = tokio::time::timeout(
        Duration::from_secs(5),
        send_without_response(quic.clone(), Command::Put as u8, 0, true, &mut small),
    )
    .await
    .expect("the command waited on the stream finishing a dropped frame");
    assert!(written.is_ok(), "{written:?}");

    server.resume_reading();
    wait_until(
        || quic.stream_inflight()[finishing] == 0,
        "the finish never released its stream",
    )
    .await;
}

/// A dropped frame whose remainder the server does not take in time has its stream reset. The
/// command after it on that stream fails as a lost connection does, so it is sent again over a new
/// connection and answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_command_after_a_reset_frame_is_answered_over_a_new_connection() {
    use lore_transport::traits::Storage;

    use crate::quic::storage_service::test_server::test_partition;
    use crate::quic::storage_service::test_server::wait_until;

    let _finishing = FINISHING_FRAMES.lock().await;
    let (server, client, quic) = served_connection().await;
    set_finish_frame_timeout(Some(Duration::from_millis(300)));
    server.pause_reading();
    let (finishing, ..) = drop_a_held_command(&quic).await;
    wait_until(
        || quic.stream_inflight()[finishing] == 0,
        "the finish never reset its stream",
    )
    .await;
    set_finish_frame_timeout(None);
    server.resume_reading();

    let answered = tokio::time::timeout(
        Duration::from_secs(10),
        client.session_start(test_partition(), "test"),
    )
    .await
    .expect("the command after the reset stream was never answered");
    assert!(answered.is_ok(), "{answered:?}");
    assert_eq!(server.accepted_connections(), 2);
}

/// Many commands queued at once on each stream, each frame larger than the stream takes in one
/// write, are each written whole and one after another: every command is answered, over the one
/// connection, and no stream's reader meets an answer it does not expect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_commands_queued_on_each_stream_are_all_answered() {
    use bytes::Bytes;
    use lore_transport::quic::storage_service::Command;

    use crate::quic::storage_service::test_server::wait_until;

    const COMMANDS: usize = 300;
    let (server, _client, quic) = served_connection().await;
    let writers = quic.hold_writers().await.expect("open every stream");
    let commands: Vec<_> = (0..COMMANDS)
        .map(|index| {
            let quic = quic.clone();
            lore_base::lore_spawn!(async move {
                let mut chunks = [
                    Bytes::new(),
                    Bytes::from(vec![index as u8; 1000 + index]),
                    Bytes::from_static(b"tail"),
                ];
                send_normal(quic, Command::Put as u8, 0, true, &mut chunks).await
            })
        })
        .collect();
    wait_until(
        || quic.stream_inflight().iter().sum::<u64>() == COMMANDS as u64,
        "the commands were never all queued",
    )
    .await;
    let inflight = quic.stream_inflight();
    assert!(
        inflight[PRIORITY_STREAM_COUNT as usize..]
            .iter()
            .all(|&count| count > 1),
        "a stream holds at most one command: {inflight:?}"
    );
    drop(writers);

    for command in commands {
        let answered = tokio::time::timeout(Duration::from_secs(10), command)
            .await
            .expect("a command was never answered")
            .expect("the command's task");
        assert!(answered.is_ok(), "{answered:?}");
    }
    assert_eq!(quic.pending_commands().await, 0);
    assert_eq!(quic.streams_ended(), 0);
    assert_eq!(server.accepted_connections(), 1);
}

/// A frame of more chunks than a queued frame holds reaches the server whole, its chunks one after
/// another.
///
/// FORK-LOCAL (Tideshift, D-QS2): the fork writes the frame itself and has no queued-frame chunk
/// limit, so the test uses upstream's limit (6) as a literal; the property still holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_frame_of_more_chunks_than_a_queued_frame_holds_arrives_whole() {
    use bytes::Bytes;

    use crate::quic::storage_service::test_server::ECHO;

    const FRAME_CHUNKS: usize = 6;
    let (_server, _client, quic) = served_connection().await;
    let mut chunks: Vec<Bytes> = std::iter::once(Bytes::new())
        .chain((0..FRAME_CHUNKS + 2).map(|index| Bytes::from(vec![index as u8; 100 + index])))
        .collect();
    let payload: Vec<u8> = chunks[1..].iter().flatten().copied().collect();
    let answered = tokio::time::timeout(
        Duration::from_secs(10),
        send_normal(quic, ECHO as u8, 0, true, &mut chunks),
    )
    .await
    .expect("the frame never arrived whole");
    assert_eq!(answered.expect("the echo"), payload);
}

/// A command too big to send is refused before anything is written, so no answer will come for it,
/// and it leaves no command waiting on the stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_command_too_big_to_send_leaves_nothing_pending() {
    use bytes::Bytes;
    use lore_transport::quic::QuicClientError;
    use lore_transport::quic::storage_service::Command;
    use lore_transport::quic::storage_service::MAX_CHUNK_SIZE;

    let (_server, _client, quic) = served_connection().await;
    let mut too_big = [Bytes::new(), Bytes::from(vec![0u8; MAX_CHUNK_SIZE + 1])];
    let refused = send_normal(quic.clone(), Command::Put as u8, 0, true, &mut too_big).await;
    assert!(
        matches!(refused, Err(QuicClientError::ClientMessageTooBig)),
        "{refused:?}"
    );
    assert_eq!(quic.pending_commands().await, 0);
}

/// A command dropped once its frame is written still waits on its stream, so the reader takes its
/// answer when it comes rather than ending the stream on an answer it does not expect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_command_dropped_after_its_write_is_answered_and_its_stream_kept() {
    use bytes::Bytes;
    use lore_transport::quic::storage_service::Command;

    let (server, _client, quic) = served_connection().await;
    server.pause_reading();
    let mut small = [Bytes::new(), Bytes::from_static(b"dropped")];
    let dropped = tokio::time::timeout(
        Duration::from_millis(100),
        send_normal(quic.clone(), Command::Put as u8, 0, true, &mut small),
    )
    .await;
    assert!(dropped.is_err(), "the command was answered: {dropped:?}");
    assert_eq!(quic.pending_commands().await, 1);

    server.resume_reading();
    tokio::time::timeout(Duration::from_secs(10), async {
        while quic.pending_commands().await != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the dropped command's answer never came");
    assert_eq!(quic.streams_ended(), 0);
}

mod controller_factory {
    use std::time::Instant;

    use quinn::congestion;

    use super::*;

    const MTU: u16 = 1200;
    const SEEDED_WINDOW: u64 = 64 * 1024 * 1024;
    const UNLIMITED_SEND_WINDOW: u64 = u64::MAX;
    const SMALL_SEND_WINDOW: u64 = 4 * 1024 * 1024;

    fn build(
        algorithm: CongestionAlgorithm,
        initial_window: Option<u64>,
        send_window: u64,
    ) -> Box<dyn congestion::Controller> {
        algorithm
            .controller_factory(initial_window, send_window)
            .build(Instant::now(), MTU)
    }

    #[test]
    fn cubic_builds_a_cubic_controller_seeded_with_the_initial_window() {
        let controller = build(
            CongestionAlgorithm::Cubic,
            Some(SEEDED_WINDOW),
            UNLIMITED_SEND_WINDOW,
        );

        assert_eq!(controller.initial_window(), SEEDED_WINDOW);
        controller
            .into_any()
            .downcast::<congestion::Cubic>()
            .expect("controller should be Cubic");
    }

    #[test]
    fn bbr_builds_a_bbr_controller_seeded_with_the_initial_window() {
        let controller = build(
            CongestionAlgorithm::Bbr,
            Some(SEEDED_WINDOW),
            UNLIMITED_SEND_WINDOW,
        );

        assert_eq!(controller.initial_window(), SEEDED_WINDOW);
        controller
            .into_any()
            .downcast::<congestion::Bbr>()
            .expect("controller should be BBR");
    }

    #[test]
    fn no_initial_window_keeps_the_algorithm_default() {
        for algorithm in [CongestionAlgorithm::Cubic, CongestionAlgorithm::Bbr] {
            let controller = build(algorithm, None, UNLIMITED_SEND_WINDOW);

            assert!(
                controller.initial_window() < SEEDED_WINDOW,
                "{algorithm:?} initial window ({}) should be its small default",
                controller.initial_window(),
            );
        }
    }

    #[test]
    fn bbr_window_is_held_to_the_send_window() {
        let controller = build(
            CongestionAlgorithm::Bbr,
            Some(SEEDED_WINDOW),
            SMALL_SEND_WINDOW,
        );

        assert_eq!(controller.window(), SMALL_SEND_WINDOW);
    }
}

mod observe_responses {
    use bytes::Bytes;
    use lore_transport::quic::response_observer::ObservedResponse;
    use lore_transport::quic::response_observer::ResponseObserver;
    use lore_transport::quic::storage_service::Command;

    use super::*;

    #[derive(Default)]
    struct Recorded(Mutex<Vec<ObservedResponse>>);

    impl ResponseObserver for Recorded {
        fn observe(&self, response: &ObservedResponse, _connection: &quinn::Connection) {
            self.0.lock().push(*response);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_observer_sees_each_answered_command() {
        let (_server, _client, quic) = served_connection().await;
        let recorded = Arc::new(Recorded::default());
        assert!(quic.observe_responses(recorded.clone()));

        let mut chunks = [Bytes::new(), Bytes::from_static(b"observed")];
        send_normal(quic.clone(), Command::Put as u8, 0, true, &mut chunks)
            .await
            .expect("the put is answered");

        // The reader observes a response once it has handed it over, so the observation can trail
        // the answer.
        let observed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let observed = recorded.0.lock().clone();
                if !observed.is_empty() {
                    return observed;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the response was never observed");
        let [response] = observed.as_slice() else {
            panic!("expected one observed response, got {observed:?}");
        };
        assert_eq!(response.opcode, Command::Put as u8);
        assert_eq!(response.error_status, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_observer_is_refused() {
        let (_server, _client, quic) = served_connection().await;

        assert!(quic.observe_responses(Arc::new(Recorded::default())));
        assert!(!quic.observe_responses(Arc::new(Recorded::default())));
    }
}
