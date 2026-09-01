// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//
// WP-108 QUIC session rebinding.
//
// `send_with_reconnect` (`lore-transport/src/quic/client.rs`) captures `session_id: u32` by
// value before its retry loop. On a transient failure it reconnects (bumping
// `QuicConnection::epoch`) and resends the SAME command with the SAME stale `session_id` on the
// replacement connection. QUIC storage sessions are per-connection (each accepted connection on
// the server gets a fresh `StorageServiceV4`/`SessionMap` -- see the comment at
// `lore-server/src/quic/quinn/quinn_server.rs`'s `handle_conn`), so the replacement connection's
// `SessionMap` never knows the stale id, even when the replacement lands back on the very same
// server process.
//
// [CLIENT]-class: this exercises `lore-transport`'s QUIC client (`StorageSession`,
// `send_with_reconnect`) against a real, in-process loopback `loreserver`, following the harness
// pattern in `remote_store_test.rs`. The server-side recording factory built here is test-only
// scaffolding, not a change to `lore-server` production code.
//
// Phase A (this file, today): characterization tests A1/A2 assert the DESIRED end state (no
// stale-session replay, command succeeds after reconnect) and are expected to FAIL against the
// pre-fix tree -- that failure is the required pre-fix reproduction evidence. Once WP-108 lands
// the real fix (`lore_transport::replay`, `Storage::connection_epoch`, epoch-bound
// `StorageSession` resolution), these same tests should go green and serve as the permanent
// regression guard for the same-server and cross-server cases.
#[cfg(all(test, feature = "integration_tests"))]
mod quic_session_rebind_tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use async_trait::async_trait;
    use bytes::BufMut;
    use bytes::Bytes;
    use bytes::BytesMut;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Hash;
    use lore_base::types::KeyType;
    use lore_revision::environment::EnvironmentConfig;
    use lore_revision::fragment;
    use lore_revision::lore::RepositoryId;
    use lore_revision::store::remote::RemoteImmutableStore;
    use lore_server::grpc::server::FeatureSettings;
    use lore_server::grpc::server::GrpcServerBuilder;
    use lore_server::hooks::HookDispatcher;
    use lore_server::protocol::attribute_map::AttributeMap;
    use lore_server::protocol::storage::messages::MessageHandleError;
    use lore_server::protocol::storage::messages::MessageParseError;
    use lore_server::quic::ProtocolErrorInfo;
    use lore_server::quic::QuicService;
    use lore_server::quic::StreamDataHandler;
    use lore_server::quic::StreamHandlerFactory;
    use lore_server::quic::quinn::QuinnConfigBuilder;
    use lore_server::quic::quinn::QuinnServer;
    use lore_server::quic::quinn::service_store::ServiceStore;
    use lore_server::quic::quinn::service_store::StreamDataHandlerBuilder;
    use lore_server::quic::storage_service_v4::ParsedStorageRequestV4;
    use lore_server::quic::storage_service_v4::StorageServiceV4;
    use lore_server::quic::stream_handler::StreamHandler;
    use lore_server::quic::tests::TEST_PROTOCOL_V4;
    use lore_server::quic::tests::server_certs;
    use lore_storage::ImmutableStore;
    use lore_storage::MutableStore;
    use lore_storage::local::immutable_store::ImmutableStoreCreateOptions;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;
    use lore_transport::quic::QuicOpCode;
    use lore_transport::quic::client::CertificateSettings;
    use lore_transport::quic::client::CongestionAlgorithm;
    use lore_transport::quic::client::DEFAULT_EXPECTED_RTT_MS;
    use lore_transport::quic::client::EndpointConfig;
    use lore_transport::quic::client::QuicConnection;
    use lore_transport::quic::client::TransportConfig;
    use lore_transport::quic::client::connect as raw_quic_connect;
    use lore_transport::quic::client::send_normal;
    use lore_transport::quic::command_header::CommandHeader;
    use lore_transport::quic::storage_service::Command;
    use lore_transport::quic::storage_service::MAX_CHUNK_SIZE;
    use rand::random;
    use tracing::Span;
    use zerocopy::IntoBytes;

    use crate::common::net_common::bind_matched_pair;
    use crate::setup_execution;

    type TestResult = Result<(), Box<dyn Error>>;

    /// One inbound `CommandHeader` observed on the server, recorded before it is parsed into a
    /// concrete request. This is what the client actually put on the wire, not what it meant to
    /// send.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Observed {
        opcode: u8,
        session_id: u32,
    }

    type Log = Arc<StdMutex<Vec<Observed>>>;

    /// A deterministic "dispatched, then response lost" fault: once the wrapped service has
    /// computed the real response for `opcode` (the real mutation has already happened), fire
    /// `notify_processed` so the test can sever the connection out from under the response, then
    /// sleep `grace_period` (comfortably longer than an in-process `QuinnServer::close()` takes)
    /// before returning the response to the framework. By the time this returns, the connection
    /// is already gone, so the write fails harmlessly and the client never sees an answer.
    ///
    /// Synchronization, not a race: the test AWAITS `notify_processed` before calling
    /// `close()`, so the connection is provably still alive when the real mutation happens and
    /// provably closed well before the response would otherwise reach the client.
    #[derive(Clone)]
    struct SeverResponse {
        opcode: u8,
        notify_processed: Arc<tokio::sync::Notify>,
        grace_period: Duration,
    }

    /// Holds a real server error after the handler has produced it but before the QUIC framework
    /// writes the error response. This lets a test move the client connection generation while
    /// the answered request is still in flight, without replacing the loopback connection or
    /// changing the server result.
    #[derive(Clone)]
    struct HoldAnsweredError {
        opcode: u8,
        notify_answered: Arc<tokio::sync::Notify>,
        release_answer: Arc<tokio::sync::Notify>,
        armed: Arc<AtomicBool>,
    }

    /// Delegates every `QuicService` call to a real `StorageServiceV4`, recording
    /// `(opcode, session_id)` off the header of every inbound command first, and optionally
    /// severing one command's response deterministically (see [`SeverResponse`]).
    struct RecordingStorageServiceV4 {
        inner: StorageServiceV4,
        log: Log,
        sever: Option<SeverResponse>,
        hold_answered_error: Option<HoldAnsweredError>,
    }

    #[async_trait]
    impl QuicService for RecordingStorageServiceV4 {
        type ParsedRequestType = ParsedStorageRequestV4;
        type RequestParseErrorType = MessageParseError;
        type RequestHandlerError = MessageHandleError;

        fn get_service_name_label(&self) -> &'static str {
            self.inner.get_service_name_label()
        }

        fn parse_request_bytes(
            &self,
            header: &CommandHeader,
            bytes: Bytes,
        ) -> Result<Self::ParsedRequestType, Self::RequestParseErrorType> {
            self.log.lock().expect("log mutex poisoned").push(Observed {
                opcode: header.cmd,
                session_id: header.session_id,
            });
            self.inner.parse_request_bytes(header, bytes)
        }

        async fn run_request_handler(
            &self,
            context: Arc<AttributeMap>,
            request: Self::ParsedRequestType,
        ) -> Result<Vec<Bytes>, Self::RequestHandlerError> {
            let opcode = match &request {
                ParsedStorageRequestV4::StorageCommand { opcode, .. } => Some(*opcode),
                _ => None,
            };
            let result = self.inner.run_request_handler(context, request).await;
            if result.is_err()
                && let Some(hold) = &self.hold_answered_error
                && opcode == Some(hold.opcode)
                && hold.armed.swap(false, Ordering::Relaxed)
            {
                hold.notify_answered.notify_one();
                hold.release_answer.notified().await;
            }
            if result.is_ok()
                && let Some(sever) = &self.sever
                && opcode == Some(sever.opcode)
            {
                // The real mutation is already applied (it happened inside the call above).
                // Tell the test it may sever the connection now, then hold the response long
                // enough that the severed connection wins the race deterministically rather than
                // by luck.
                sever.notify_processed.notify_one();
                tokio::time::sleep(sever.grace_period).await;
            }
            result
        }

        fn command_to_metrics_label(&self, opcode: QuicOpCode) -> &'static str {
            self.inner.command_to_metrics_label(opcode)
        }

        fn transform_protocol_error(&self, error: &Self::RequestHandlerError) -> ProtocolErrorInfo {
            self.inner.transform_protocol_error(error)
        }

        fn max_chunk_size(&self) -> usize {
            self.inner.max_chunk_size()
        }

        fn header_size(&self) -> usize {
            self.inner.header_size()
        }

        fn build_request_span(
            &self,
            header: &CommandHeader,
            message: &Self::ParsedRequestType,
            context: &Arc<AttributeMap>,
        ) -> Span {
            self.inner.build_request_span(header, message, context)
        }
    }

    /// Same wiring as `lore_server::quic::tests::TestHandlerFactory`, but the `lore-storage/0.4`
    /// service is wrapped in [`RecordingStorageServiceV4`] so the test can observe exactly what
    /// session id crossed the wire.
    struct RecordingHandlerFactory {
        service_store: ServiceStore,
    }

    impl RecordingHandlerFactory {
        fn new(
            immutable_store: Arc<dyn ImmutableStore>,
            mutable_store: Arc<dyn MutableStore>,
            log: Log,
        ) -> Self {
            Self::with_controls(immutable_store, mutable_store, log, None, None)
        }

        fn with_sever(
            immutable_store: Arc<dyn ImmutableStore>,
            mutable_store: Arc<dyn MutableStore>,
            log: Log,
            sever: Option<SeverResponse>,
        ) -> Self {
            Self::with_controls(immutable_store, mutable_store, log, sever, None)
        }

        fn with_answered_error_hold(
            immutable_store: Arc<dyn ImmutableStore>,
            mutable_store: Arc<dyn MutableStore>,
            log: Log,
            hold_answered_error: HoldAnsweredError,
        ) -> Self {
            Self::with_controls(
                immutable_store,
                mutable_store,
                log,
                None,
                Some(hold_answered_error),
            )
        }

        fn with_controls(
            immutable_store: Arc<dyn ImmutableStore>,
            mutable_store: Arc<dyn MutableStore>,
            log: Log,
            sever: Option<SeverResponse>,
            hold_answered_error: Option<HoldAnsweredError>,
        ) -> Self {
            let mut service_store = ServiceStore::default();
            service_store.add_service(
                TEST_PROTOCOL_V4,
                Box::new(move |context: Arc<AttributeMap>| {
                    let inner = StorageServiceV4::new(
                        Arc::new(None),
                        immutable_store.clone(),
                        immutable_store.clone(),
                        mutable_store.clone(),
                        false,
                    );
                    let service = RecordingStorageServiceV4 {
                        inner,
                        log: log.clone(),
                        sever: sever.clone(),
                        hold_answered_error: hold_answered_error.clone(),
                    };
                    Box::new(StreamHandler::new(Arc::new(service), context, 100, None))
                        as Box<dyn StreamDataHandler>
                }),
            );
            Self { service_store }
        }
    }

    impl StreamHandlerFactory for RecordingHandlerFactory {
        fn supported_protocols(&self) -> Vec<String> {
            self.service_store.get_supported_services()
        }

        fn get_stream_handler_builder(
            &self,
            protocol: &str,
        ) -> Option<(&&'static str, &StreamDataHandlerBuilder)> {
            self.service_store.get_stream_builder(protocol)
        }
    }

    /// Fresh in-memory immutable+mutable stores, independent of any other backend's.
    async fn fresh_stores() -> (Arc<dyn ImmutableStore>, Arc<dyn MutableStore>) {
        let immutable = lore_storage::local::immutable_store::create(
            None::<&str>,
            ImmutableStoreCreateOptions::none(),
            false,
            ImmutableStoreSettings {
                protect_local_fragment: false,
                implicit_durable_stored: true,
                isolate_partitions: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mutable = lore_storage::local::mutable_store::create(
            None::<&str>,
            lore_storage::MutableStoreSettings::default(),
            immutable.clone(),
        )
        .await
        .unwrap();
        (immutable, mutable)
    }

    /// The gRPC half of a `lore://` loopback server: environment resolution only, no revision or
    /// lock service. Mirrors `remote_store_test.rs`'s `start_backend`, trimmed to what
    /// `RemoteImmutableStore`'s storage-only path needs.
    async fn start_grpc_backend(
        listener: std::net::TcpListener,
        addr: SocketAddr,
    ) -> tokio::sync::oneshot::Sender<()> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let signal = async {
            shutdown_rx.await.ok();
        };
        let (immutable, mutable) = fresh_stores().await;
        let notification_sender: Arc<dyn lore_revision::notification::NotificationSender> =
            Arc::new(lore_server::notification::local::NotificationSender::default());
        let hook_dispatcher = Arc::new(HookDispatcher::empty());

        let (stopped_tx, mut stopped_rx) = tokio::sync::oneshot::channel::<String>();
        // Background server task in a test; LORE_CONTEXT propagation is unnecessary here.
        #[allow(clippy::disallowed_methods)]
        tokio::spawn(async move {
            let outcome = GrpcServerBuilder::new()
                .with_environment(EnvironmentConfig::default())
                .with_feature(FeatureSettings::default())
                .with_immutable_store(immutable.clone(), immutable)
                .with_mutable_store(mutable)
                .with_lock_store(None)
                .with_domain_context(None)
                .with_notification(notification_sender, None)
                .with_hook_dispatcher(hook_dispatcher)
                .with_tls_config(None, None, None)
                .unwrap()
                .with_admin_endpoints(HashMap::new(), vec![])
                .with_http2_config(
                    None,
                    None,
                    Duration::from_secs(30),
                    None,
                    Default::default(),
                    None,
                )
                .with_jwt_verifier(None, false)
                .unwrap()
                .serve_with_listener(listener, signal)
                .await;
            let _ = stopped_tx.send(match outcome {
                Ok(()) => "stopped before the test finished".to_string(),
                Err(error) => format!("failed: {error}"),
            });
        });

        let mut ready = false;
        for _ in 0..50 {
            if let Ok(reason) = stopped_rx.try_recv() {
                panic!("test gRPC server on {addr} {reason}");
            }
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            ready,
            "test gRPC server on {addr} never accepted a connection"
        );

        shutdown_tx
    }

    /// A recording QUIC storage server bound to `udp`, backed by `immutable`/`mutable`.
    fn start_recording_quic_server(
        udp: std::net::UdpSocket,
        immutable: Arc<dyn ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
        log: Log,
    ) -> QuinnServer {
        let (cert_file, pkey_file, _ca) = server_certs().expect("test certificate paths");
        QuinnServer::start(
            QuinnConfigBuilder::new()
                .socket(udp)
                .cert_file(cert_file)
                .pkey_file(pkey_file)
                .stream_handler_factory(Box::new(RecordingHandlerFactory::new(
                    immutable, mutable, log,
                )))
                .build()
                .expect("quinn config"),
        )
        .expect("quinn server start")
    }

    /// A recording QUIC storage server that additionally severs the response to the first
    /// dispatched command of `sever_opcode`, deterministically (see [`SeverResponse`]). Returns
    /// the server and the `Notify` that fires once that command's real mutation has happened and
    /// the response is about to be attempted -- await it, then close the server.
    fn start_severing_quic_server(
        udp: std::net::UdpSocket,
        immutable: Arc<dyn ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
        log: Log,
        sever_opcode: u8,
    ) -> (QuinnServer, Arc<tokio::sync::Notify>) {
        let notify_processed = Arc::new(tokio::sync::Notify::new());
        let sever = SeverResponse {
            opcode: sever_opcode,
            notify_processed: notify_processed.clone(),
            // Comfortably longer than an in-process `QuinnServer::close()` takes, so the
            // connection is provably gone before this returns and the framework attempts the
            // write.
            grace_period: Duration::from_millis(300),
        };
        let (cert_file, pkey_file, _ca) = server_certs().expect("test certificate paths");
        let server = QuinnServer::start(
            QuinnConfigBuilder::new()
                .socket(udp)
                .cert_file(cert_file)
                .pkey_file(pkey_file)
                .stream_handler_factory(Box::new(RecordingHandlerFactory::with_sever(
                    immutable,
                    mutable,
                    log,
                    Some(sever),
                )))
                .build()
                .expect("quinn config"),
        )
        .expect("quinn server start");
        (server, notify_processed)
    }

    /// A recording server that holds the first real error answer for `opcode` until the test
    /// releases it. The returned notifications form a deterministic hand-off: await `answered`,
    /// move the client generation, then notify `release` so the original server answer reaches
    /// the caller.
    fn start_answer_holding_quic_server(
        udp: std::net::UdpSocket,
        immutable: Arc<dyn ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
        log: Log,
        opcode: Command,
    ) -> (
        QuinnServer,
        Arc<tokio::sync::Notify>,
        Arc<tokio::sync::Notify>,
    ) {
        let notify_answered = Arc::new(tokio::sync::Notify::new());
        let release_answer = Arc::new(tokio::sync::Notify::new());
        let hold = HoldAnsweredError {
            opcode: opcode as u8,
            notify_answered: notify_answered.clone(),
            release_answer: release_answer.clone(),
            armed: Arc::new(AtomicBool::new(true)),
        };
        let (cert_file, pkey_file, _ca) = server_certs().expect("test certificate paths");
        let server = QuinnServer::start(
            QuinnConfigBuilder::new()
                .socket(udp)
                .cert_file(cert_file)
                .pkey_file(pkey_file)
                .stream_handler_factory(Box::new(
                    RecordingHandlerFactory::with_answered_error_hold(
                        immutable, mutable, log, hold,
                    ),
                ))
                .build()
                .expect("quinn config"),
        )
        .expect("quinn server start");
        (server, notify_answered, release_answer)
    }

    /// Rebind a UDP socket on the exact port a just-closed QUIC server used. UDP has no TIME_WAIT,
    /// so this should succeed immediately once the old `QuinnServer` is fully dropped; poll briefly
    /// to absorb the OS's own teardown latency.
    async fn rebind_udp(port: u16) -> std::net::UdpSocket {
        for _ in 0..50 {
            if let Ok(udp) = std::net::UdpSocket::bind(("127.0.0.1", port)) {
                return udp;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("could not rebind udp port {port} after closing the original QUIC server");
    }

    /// Gracefully close `server` (so the client observes a clean connection loss rather than
    /// hanging on a dead socket) and hand back a fresh UDP socket bound to the same port.
    async fn replace_quic_server(server: QuinnServer, port: u16) -> std::net::UdpSocket {
        server.close().await;
        drop(server);
        rebind_udp(port).await
    }

    /// A random small payload command through `session`, returning the fragment/address used so
    /// callers can round-trip it.
    fn random_fragment() -> (lore_base::types::Fragment, lore_base::types::Address, Bytes) {
        fragment::generate_random()
    }

    /// Whether the FIRST occurrence of `command` in `log` is preceded by an `Authorize` in the
    /// same log -- i.e. a fresh `session_start` really happened on this connection before the
    /// command was sent, rather than reusing (or replaying) an id from elsewhere.
    ///
    /// Deliberately NOT a raw session-id comparison against the pre-reconnect id. Each server's
    /// `SessionMap` assigns ids independently starting from the same small counter, so a fresh
    /// session on a brand-new connection can legitimately be issued the SAME numeric id an old,
    /// unrelated connection once had -- that is a coincidence, not a replay. The only sound proof
    /// that a command's session was freshly (re)established on ITS OWN connection is ordering:
    /// an `Authorize` recorded on that same connection, before the command.
    fn preceded_by_fresh_authorize(log: &[Observed], command: u8) -> bool {
        let Some(command_index) = log.iter().position(|o| o.opcode == command) else {
            return false;
        };
        log[..command_index]
            .iter()
            .any(|o| o.opcode == Command::Authorize as u8)
    }

    /// A1: reconnecting the SAME `StorageSession` to a fresh QUIC connection on the SAME server
    /// process must not resend the pre-reconnect `session_id`, and the command that follows the
    /// reconnect must succeed. The server hands every newly accepted QUIC connection a fresh
    /// `StorageServiceV4`/`SessionMap` (see `quinn_server.rs::handle_conn`), so even a same-process
    /// reconnect invalidates every session id issued on the prior connection.
    #[tokio::test]
    async fn same_server_reconnect_must_not_replay_the_stale_session_id() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr().unwrap();
                let port = addr.port();
                let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

                let (immutable, mutable) = fresh_stores().await;
                let log_a: Log = Arc::new(StdMutex::new(Vec::new()));
                let server_a = start_recording_quic_server(
                    udp,
                    immutable.clone(),
                    mutable.clone(),
                    log_a.clone(),
                );

                let store = RemoteImmutableStore::new(&format!("lore://127.0.0.1:{port}"), None);
                let partition = random::<RepositoryId>();
                let session = store.session(partition).await?;

                let (fragment1, address1, payload1) = random_fragment();
                session
                    .put(address1, fragment1, Some(payload1))
                    .await
                    .expect("first put, before any reconnect, should succeed");

                let stale_session_id = log_a
                    .lock()
                    .unwrap()
                    .iter()
                    .rev()
                    .find(|o| o.opcode == Command::Put as u8)
                    .expect("the first put must have been observed on the wire")
                    .session_id;
                assert_ne!(
                    stale_session_id, 0,
                    "a resolved session must carry a nonzero server-assigned id"
                );

                // Force the same StorageSession to reconnect: close server A's QUIC listener and
                // rebind a fresh one on the identical port, backed by the SAME stores (this is a
                // reconnect to "the same server", not a failover to an independent one -- see A2
                // for that case).
                let udp2 = replace_quic_server(server_a, port).await;
                let log_b: Log = Arc::new(StdMutex::new(Vec::new()));
                let _server_b =
                    start_recording_quic_server(udp2, immutable, mutable, log_b.clone());

                let (fragment2, address2, payload2) = random_fragment();
                let second_put = session.put(address2, fragment2, Some(payload2)).await;

                // Pre-fix reproduction (recorded verbatim, no longer expected to reproduce):
                // panicked at lore-integration-tests\tests\quic_session_rebind_test.rs:403:17:
                // epoch-N session id 1 was replayed on the wire to the post-reconnect server;
                // observed inbound commands on the new connection: [Observed { opcode: 2,
                // session_id: 1 }] -- no `Authorize` at all before the replayed `Put`.
                let log_b_snapshot = log_b.lock().unwrap().clone();
                assert!(
                    preceded_by_fresh_authorize(&log_b_snapshot, Command::Put as u8),
                    "the post-reconnect Put must be preceded by a fresh Authorize (session_start) \
                     on the new connection, not a reused/replayed id (numeric ids are only unique \
                     within one connection's SessionMap, so a bare id comparison against \
                     {stale_session_id} would be unsound); observed: {log_b_snapshot:?}"
                );

                assert!(
                    second_put.is_ok(),
                    "expected the command issued right after a same-server reconnect to succeed \
                     once the session is rebound, got {second_put:?}"
                );

                Ok(())
            })
            .await
    }

    /// A2: same as A1, but the replacement connection lands on an INDEPENDENT server process (its
    /// own stores, its own `SessionMap`). Proves the epoch-N session id is not just stale but
    /// meaningless off the original process entirely.
    #[tokio::test]
    async fn cross_server_reconnect_must_not_replay_the_stale_session_id() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr().unwrap();
                let port = addr.port();
                let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

                let (immutable_a, mutable_a) = fresh_stores().await;
                let log_a: Log = Arc::new(StdMutex::new(Vec::new()));
                let server_a =
                    start_recording_quic_server(udp, immutable_a.clone(), mutable_a, log_a.clone());

                let store = RemoteImmutableStore::new(&format!("lore://127.0.0.1:{port}"), None);
                let partition = random::<RepositoryId>();
                let session = store.session(partition).await?;

                let (fragment1, address1, payload1) = random_fragment();
                session
                    .put(address1, fragment1, Some(payload1.clone()))
                    .await
                    .expect("first put, against server A, should succeed");

                let stale_session_id = log_a
                    .lock()
                    .unwrap()
                    .iter()
                    .rev()
                    .find(|o| o.opcode == Command::Put as u8)
                    .expect("the first put must have been observed on the wire")
                    .session_id;

                // Replace server A's listener with an independently constructed server B: its own
                // stores, so a store-hit on B's side would prove content genuinely reached it
                // rather than just an id collision.
                let udp2 = replace_quic_server(server_a, port).await;
                let (immutable_b, mutable_b) = fresh_stores().await;
                let log_b: Log = Arc::new(StdMutex::new(Vec::new()));
                let _server_b =
                    start_recording_quic_server(udp2, immutable_b, mutable_b, log_b.clone());

                let (fragment2, address2, payload2) = random_fragment();
                let second_put = session.put(address2, fragment2, Some(payload2)).await;

                // Pre-fix reproduction (recorded verbatim, no longer expected to reproduce):
                // panicked at lore-integration-tests\tests\quic_session_rebind_test.rs:475:17:
                // server A's session id 1 was sent to independent server B; observed inbound
                // commands on B: [Observed { opcode: 2, session_id: 1 }] -- no `Authorize` at all
                // before the replayed `Put`.
                let log_b_snapshot = log_b.lock().unwrap().clone();
                assert!(
                    preceded_by_fresh_authorize(&log_b_snapshot, Command::Put as u8),
                    "the post-failover Put on independent server B must be preceded by its own \
                     fresh Authorize (session_start), not server A's id {stale_session_id} \
                     (numeric ids are only unique within one connection's SessionMap, so a bare \
                     id comparison would be unsound); observed on B: {log_b_snapshot:?}"
                );

                assert!(
                    second_put.is_ok(),
                    "expected the command issued right after failing over to an independent \
                     server to succeed once the session is rebound, got {second_put:?}"
                );

                Ok(())
            })
            .await
    }

    // ── Phase B: post-fix behavior (WP-108 landed 2026-08-30) ──

    /// B1: same-server reconnect creates EXACTLY one replacement `Authorize`/`session_start` on
    /// the new connection before the next command -- not "at least one", not "recorded
    /// somewhere", exactly one.
    #[tokio::test]
    async fn b1_same_server_reconnect_starts_exactly_one_replacement_session() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr().unwrap();
                let port = addr.port();
                let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

                let (immutable, mutable) = fresh_stores().await;
                let log_a: Log = Arc::new(StdMutex::new(Vec::new()));
                let server_a = start_recording_quic_server(
                    udp,
                    immutable.clone(),
                    mutable.clone(),
                    log_a.clone(),
                );

                let store = RemoteImmutableStore::new(&format!("lore://127.0.0.1:{port}"), None);
                let partition = random::<RepositoryId>();
                let session = store.session(partition).await?;

                let (fragment1, address1, payload1) = random_fragment();
                session
                    .put(address1, fragment1, Some(payload1))
                    .await
                    .expect("first put should succeed");

                let udp2 = replace_quic_server(server_a, port).await;
                let log_b: Log = Arc::new(StdMutex::new(Vec::new()));
                let _server_b =
                    start_recording_quic_server(udp2, immutable, mutable, log_b.clone());

                let (fragment2, address2, payload2) = random_fragment();
                session
                    .put(address2, fragment2, Some(payload2))
                    .await
                    .expect("post-reconnect put should succeed");

                let log_b_snapshot = log_b.lock().unwrap().clone();
                let authorize_count = log_b_snapshot
                    .iter()
                    .filter(|o| o.opcode == Command::Authorize as u8)
                    .count();
                assert_eq!(
                    authorize_count, 1,
                    "expected exactly one replacement session_start on the new connection, \
                     observed: {log_b_snapshot:?}"
                );

                Ok(())
            })
            .await
    }

    /// B2: cross-server failover never sends server A's session id to independent server B --
    /// the FIRST command server B ever sees on this connection is an `Authorize`, full stop.
    #[tokio::test]
    async fn b2_cross_server_failover_never_sends_a_bare_command_to_b() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr().unwrap();
                let port = addr.port();
                let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

                let (immutable_a, mutable_a) = fresh_stores().await;
                let log_a: Log = Arc::new(StdMutex::new(Vec::new()));
                let server_a =
                    start_recording_quic_server(udp, immutable_a.clone(), mutable_a, log_a.clone());

                let store = RemoteImmutableStore::new(&format!("lore://127.0.0.1:{port}"), None);
                let partition = random::<RepositoryId>();
                let session = store.session(partition).await?;

                let (fragment1, address1, payload1) = random_fragment();
                session
                    .put(address1, fragment1, Some(payload1))
                    .await
                    .expect("first put against server A should succeed");

                let udp2 = replace_quic_server(server_a, port).await;
                let (immutable_b, mutable_b) = fresh_stores().await;
                let log_b: Log = Arc::new(StdMutex::new(Vec::new()));
                let _server_b =
                    start_recording_quic_server(udp2, immutable_b, mutable_b, log_b.clone());

                let (fragment2, address2, payload2) = random_fragment();
                session
                    .put(address2, fragment2, Some(payload2))
                    .await
                    .expect("post-failover put should succeed");

                let log_b_snapshot = log_b.lock().unwrap().clone();
                assert_eq!(
                    log_b_snapshot.first().map(|o| o.opcode),
                    Some(Command::Authorize as u8),
                    "the first command independent server B ever sees on this connection must \
                     be a fresh Authorize, not a bare reused command; observed: {log_b_snapshot:?}"
                );

                Ok(())
            })
            .await
    }

    /// B3: several concurrent commands on the same `StorageSession`, issued right after a
    /// reconnect, single-flight the replacement `session_start` -- exactly one `Authorize` for
    /// every concurrent command that needed a rebound session, not one per command.
    #[tokio::test]
    async fn b3_concurrent_commands_single_flight_the_replacement_session_start() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr().unwrap();
                let port = addr.port();
                let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

                let (immutable, mutable) = fresh_stores().await;
                let log_a: Log = Arc::new(StdMutex::new(Vec::new()));
                let server_a = start_recording_quic_server(
                    udp,
                    immutable.clone(),
                    mutable.clone(),
                    log_a.clone(),
                );

                let store = RemoteImmutableStore::new(&format!("lore://127.0.0.1:{port}"), None);
                let partition = random::<RepositoryId>();
                let session = store.session(partition).await?;

                let (fragment1, address1, payload1) = random_fragment();
                session
                    .put(address1, fragment1, Some(payload1))
                    .await
                    .expect("first put should succeed");

                let udp2 = replace_quic_server(server_a, port).await;
                let log_b: Log = Arc::new(StdMutex::new(Vec::new()));
                let _server_b =
                    start_recording_quic_server(udp2, immutable, mutable, log_b.clone());

                const CONCURRENT: usize = 5;
                let fragments: Vec<_> = (0..CONCURRENT).map(|_| random_fragment()).collect();
                let mut tasks = tokio::task::JoinSet::new();
                for (fragment, address, payload) in fragments {
                    let session = session.clone();
                    #[allow(clippy::disallowed_methods)]
                    tasks.spawn(async move { session.put(address, fragment, Some(payload)).await });
                }
                let results = tasks.join_all().await;
                for result in &results {
                    assert!(
                        result.is_ok(),
                        "every concurrent post-reconnect put should succeed, got {result:?}"
                    );
                }

                let log_b_snapshot = log_b.lock().unwrap().clone();
                let authorize_count = log_b_snapshot
                    .iter()
                    .filter(|o| o.opcode == Command::Authorize as u8)
                    .count();
                let put_count = log_b_snapshot
                    .iter()
                    .filter(|o| o.opcode == Command::Put as u8)
                    .count();
                assert_eq!(
                    authorize_count, 1,
                    "{CONCURRENT} concurrent commands sharing one StorageSession must single-\
                     flight the replacement session_start to exactly one Authorize, observed: \
                     {log_b_snapshot:?}"
                );
                assert_eq!(
                    put_count, CONCURRENT,
                    "every concurrent put should still have been individually dispatched"
                );

                Ok(())
            })
            .await
    }

    // B4: replacement authorization uses the CURRENT credential and fails closed when it is no
    // longer authorized.
    //
    // NOT-RUN. This harness (like every sibling QUIC integration suite in this crate) is
    // auth-OFF (`jwt_verifier: None` on both the gRPC and QUIC sides), so there is no live
    // authorization decision to force closed. Proving "uses the CURRENT credential" and "fails
    // closed on an expired/unauthorized credential" needs an auth-ON server (JWT issuance,
    // verification, and a way to expire/revoke a credential mid-test) -- infrastructure this
    // crate's other QUIC suites don't build either. Building it is a real addition, not a cheap
    // extension of this file's harness; deferred rather than faked with a harness that cannot
    // fail the way the case requires. `session_start`'s implementation (`StorageClient`) does
    // read `self.credentials.tokens()` fresh at call time rather than caching a token from
    // construction, which is the structural mechanism this case is about -- see
    // `lore-transport/src/quic/storage_service/client.rs`'s `session_start`. No test function.

    /// B5: a safe read recovers across a reconnect with no caller intervention -- one `.get()`
    /// call, no retry loop in the caller, no `invalidate()` call.
    #[tokio::test]
    async fn b5_a_safe_read_recovers_across_reconnect_with_no_caller_intervention() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr().unwrap();
                let port = addr.port();
                let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

                let (immutable, mutable) = fresh_stores().await;
                let log_a: Log = Arc::new(StdMutex::new(Vec::new()));
                let server_a = start_recording_quic_server(
                    udp,
                    immutable.clone(),
                    mutable.clone(),
                    log_a.clone(),
                );

                let store = RemoteImmutableStore::new(&format!("lore://127.0.0.1:{port}"), None);
                let partition = random::<RepositoryId>();
                let session = store.session(partition).await?;

                // Content written before the reconnect, through the SAME backing stores the
                // replacement connection will also serve -- so a successful read after the
                // reconnect proves recovery, not that the content happened to still be reachable
                // some other way.
                let (fragment, address, payload) = random_fragment();
                session
                    .put(address, fragment, Some(payload.clone()))
                    .await
                    .expect("setup put should succeed");

                let udp2 = replace_quic_server(server_a, port).await;
                let _server_b = start_recording_quic_server(
                    udp2,
                    immutable,
                    mutable,
                    Arc::new(StdMutex::new(Vec::new())),
                );

                // One call. No retry, no invalidate(), no special-casing by the caller.
                let (_read_fragment, read_payload) = session
                    .get(&address)
                    .await
                    .expect("a safe read must recover across a reconnect with no caller help");
                assert_eq!(read_payload, payload);

                Ok(())
            })
            .await
    }

    /// B6: session renewal and command retry are bounded, for the clean single-reconnect case.
    ///
    /// CORRECTED (2026-08-31, verified directly against `session.rs`/`quic/client.rs` at tip
    /// `2aa2f40`, not just taken on report): `ATTEMPT_BUDGET` (2) is NOT the caller-visible
    /// system-wide ceiling by itself -- it composes across two layers that both consult it.
    /// `StorageSession::attempt` runs up to `ATTEMPT_BUDGET` outer iterations; each iteration's
    /// `ensure()` can itself cost up to `ATTEMPT_BUDGET` wire messages when the replacement
    /// `session_start` (sent with `session_id == 0`, so it is NOT short-circuited by
    /// `SessionRebindRequired` the way a data command is) needs its own internal reconnect-retry,
    /// plus one more for the data operation itself (which, being session-bearing, can cost only
    /// one dispatch per outer iteration -- a failed one returns `SessionRebindRequired` rather
    /// than redispatching). Worst case: 2 outer iterations x (2 for `session_start` + 1 for the
    /// operation) = 6 wire messages, 2 reconnects. That worst case needs `session_start` itself to
    /// fail once and is NOT what this test forces or observes -- NOT-RUN, a real gap, not silently
    /// dropped. What this test DOES prove, and is still exactly true: the clean single-reconnect
    /// path (reconnect succeeds, replacement `session_start` succeeds on its first try) costs
    /// exactly [`lore_transport::ATTEMPT_BUDGET`] wire commands (one Authorize, one retried
    /// operation) on the replacement connection, not more -- this is the common case, not the
    /// ceiling.
    #[tokio::test]
    async fn b6_one_operation_call_spends_at_most_the_shared_attempt_budget() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr().unwrap();
                let port = addr.port();
                let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

                let (immutable, mutable) = fresh_stores().await;
                let log_a: Log = Arc::new(StdMutex::new(Vec::new()));
                let server_a = start_recording_quic_server(
                    udp,
                    immutable.clone(),
                    mutable.clone(),
                    log_a.clone(),
                );

                let store = RemoteImmutableStore::new(&format!("lore://127.0.0.1:{port}"), None);
                let partition = random::<RepositoryId>();
                let session = store.session(partition).await?;

                let (fragment1, address1, payload1) = random_fragment();
                session
                    .put(address1, fragment1, Some(payload1))
                    .await
                    .expect("first put should succeed");

                let udp2 = replace_quic_server(server_a, port).await;
                let log_b: Log = Arc::new(StdMutex::new(Vec::new()));
                let _server_b =
                    start_recording_quic_server(udp2, immutable, mutable, log_b.clone());

                let (fragment2, address2, payload2) = random_fragment();
                session
                    .put(address2, fragment2, Some(payload2))
                    .await
                    .expect("post-reconnect put should succeed");

                let log_b_snapshot = log_b.lock().unwrap().clone();
                assert_eq!(
                    log_b_snapshot.len(),
                    lore_transport::ATTEMPT_BUDGET as usize,
                    "the CLEAN single-reconnect path (replacement session_start succeeds on its \
                     first try) must dispatch exactly ATTEMPT_BUDGET ({}) wire commands on the \
                     replacement connection (one Authorize, one retried operation) -- this is \
                     NOT the system-wide worst case (that is higher; see this test's doc comment), \
                     only the common-case bound; observed: {log_b_snapshot:?}",
                    lore_transport::ATTEMPT_BUDGET
                );

                Ok(())
            })
            .await
    }

    /// Shared scaffolding for B7/B8/B10/B11: force a real, deterministic "dispatched, response
    /// lost" fault on `target_opcode` and hand back everything a case needs to drive its own
    /// typed operation and verify the aftermath.
    struct SeveredScenario {
        session: Arc<lore_transport::StorageSession>,
        /// Same backing stores the severed connection was using, so a case can verify server-
        /// side state (e.g. a mutable key's value) directly, independent of the dead connection.
        immutable: Arc<dyn ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
        log: Log,
    }

    /// Sets up a session, then arranges for the NEXT dispatch of `target_opcode` to be
    /// deterministically severed: the real mutation happens server-side, but the connection is
    /// closed before the response can reach the client (see [`SeverResponse`]). Returns the
    /// scenario and the `Notify` the caller must await before running its operation (so the
    /// severing task is armed and ready).
    async fn severed_response_scenario(
        target_opcode: Command,
    ) -> (SeveredScenario, Arc<tokio::sync::Notify>, QuinnServer) {
        let (tcp, udp) = bind_matched_pair();
        let addr: SocketAddr = tcp.local_addr().unwrap();
        let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

        let (immutable, mutable) = fresh_stores().await;
        let log: Log = Arc::new(StdMutex::new(Vec::new()));
        let (server, notify_processed) = start_severing_quic_server(
            udp,
            immutable.clone(),
            mutable.clone(),
            log.clone(),
            target_opcode as u8,
        );

        let store = RemoteImmutableStore::new(&format!("lore://127.0.0.1:{}", addr.port()), None);
        let partition = random::<RepositoryId>();
        let session = store.session(partition).await.expect("session establish");

        (
            SeveredScenario {
                session,
                immutable,
                mutable,
                log,
            },
            notify_processed,
            server,
        )
    }

    /// Bound on waiting for the severing wrapper's "processed, about to respond" signal. If the
    /// target opcode's dispatch errors before `run_request_handler` returns `Ok` (e.g. a genuine
    /// server-side rejection unrelated to severing), the sever hook never fires and
    /// `Notify::notified()` would otherwise hang forever -- fail fast with a clear cause instead.
    const SEVER_SIGNAL_TIMEOUT: Duration = Duration::from_secs(10);

    async fn await_severed(notify: &tokio::sync::Notify, opcode: Command) {
        tokio::time::timeout(SEVER_SIGNAL_TIMEOUT, notify.notified())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the severing wrapper never signalled for {opcode} within {SEVER_SIGNAL_TIMEOUT:?} \
                     -- the dispatch likely returned Err before the sever hook could fire (which \
                     only runs on Ok), so this is not the fault under test"
                )
            });
    }

    /// After a severed dispatch resolves to `MutableOutcome::Unknown`, the barrier must hold:
    /// zero epoch-N+1 bytes ever went out, including no replacement `session_start`. Concretely:
    /// the wire log recorded for this connection must contain no entry AFTER the severed
    /// command itself -- if the client had attempted a reconnect+rebind, that would show up as
    /// more entries (it can't succeed against a closed port, but the ATTEMPT would still dispatch
    /// nothing new here since there is nothing to dispatch TO; the absence of a `Disconnected`/
    /// `ReconnectFailed` error and the presence of `MutableOutcome::Unknown` instead is the
    /// stronger proof that no reconnect was ever attempted -- `send_with_reconnect` returns
    /// `Verdict::Unknown` before ever calling into `reconnect_and_retry`).
    fn assert_no_bytes_after_severed_command(log: &[Observed], target_opcode: u8) {
        let last_target = log.iter().rposition(|o| o.opcode == target_opcode);
        assert_eq!(
            last_target,
            Some(log.len() - 1),
            "no wire activity may follow the severed command -- a barrier violation would show \
             up as more entries after it (e.g. a replacement Authorize); observed: {log:?}"
        );
    }

    /// B7: a forced ambiguous CAS. The caller-visible result on the typed path is
    /// `MutableOutcome::Unknown`, and the mutable value did NOT advance twice -- read back after
    /// the fault, it holds exactly the value the single real (server-side) CAS produced, not a
    /// value a second, phantom dispatch would have produced.
    #[tokio::test]
    async fn b7_forced_ambiguous_cas_yields_unknown_and_does_not_advance_twice() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (scenario, notify_processed, server) =
                    severed_response_scenario(Command::MutableCas).await;
                let SeveredScenario {
                    session,
                    mutable,
                    log,
                    ..
                } = scenario;

                let key = random::<Hash>();
                let expected = Hash::default();
                let first_value = random::<Hash>();

                let session_for_cas = session.clone();
                #[allow(clippy::disallowed_methods)]
                let cas_task = tokio::spawn(async move {
                    session_for_cas
                        .mutable_compare_and_swap_outcome(
                            key,
                            expected,
                            first_value,
                            KeyType::Untyped,
                        )
                        .await
                });

                // Deterministic hand-off: wait until the server has genuinely applied the CAS
                // and is about to answer, THEN sever the connection out from under the response.
                await_severed(&notify_processed, Command::MutableCas).await;
                server.close().await;

                let outcome = cas_task
                    .await
                    .expect("cas task should not panic")
                    .expect("a dispatched-then-lost CAS must resolve Ok(Unknown), not Err");
                assert!(
                    outcome.is_unknown(),
                    "expected MutableOutcome::Unknown for a severed CAS response, got {outcome:?}"
                );

                assert_no_bytes_after_severed_command(
                    &log.lock().unwrap(),
                    Command::MutableCas as u8,
                );

                // The real, server-side CAS DID apply exactly once (the fault is only in the
                // client's visibility of the outcome, not in what happened). Read the value back
                // directly against the same backing store the severed connection used, keyed by
                // the session's own partition.
                let partition = session.partition().await?;
                let value = mutable
                    .load(partition, key, KeyType::Untyped)
                    .await
                    .expect("the real CAS must have applied server-side despite the lost response");
                assert_eq!(
                    value, first_value,
                    "the mutable key must hold exactly the single real CAS's value, proving no \
                     second (phantom) dispatch ever applied a different one"
                );

                Ok(())
            })
            .await
    }

    /// B8: a forced ambiguous `PutResolved`. Its mutable-key publication is not replayed as an
    /// immutable put and is not dispatched twice -- the typed result is
    /// `MutableOutcome::Unknown`, and the key resolves to exactly the one address the single
    /// real dispatch published.
    #[tokio::test]
    async fn b8_forced_ambiguous_put_resolved_yields_unknown_and_is_not_redispatched() -> TestResult
    {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (scenario, notify_processed, server) =
                    severed_response_scenario(Command::PutResolved).await;
                let SeveredScenario {
                    session,
                    mutable,
                    log,
                    ..
                } = scenario;

                let (fragment, address, payload) = random_fragment();
                let key = random::<Hash>();

                let session_for_put = session.clone();
                let payload_for_put = payload.clone();
                #[allow(clippy::disallowed_methods)]
                let put_task = tokio::spawn(async move {
                    session_for_put
                        .put_resolved_outcome(&key, address, fragment, Some(payload_for_put))
                        .await
                });

                await_severed(&notify_processed, Command::PutResolved).await;
                server.close().await;

                let outcome = put_task
                    .await
                    .expect("put_resolved task should not panic")
                    .expect("a dispatched-then-lost PutResolved must resolve Ok(Unknown), not Err");
                assert!(
                    outcome.is_unknown(),
                    "expected MutableOutcome::Unknown for a severed PutResolved response, got \
                     {outcome:?}"
                );

                assert_no_bytes_after_severed_command(
                    &log.lock().unwrap(),
                    Command::PutResolved as u8,
                );

                let partition = session.partition().await?;
                let resolved = mutable
                    .load(partition, key, KeyType::Resolve)
                    .await
                    .expect("the real PutResolved must have published the key server-side");
                assert_eq!(
                    resolved, address.hash,
                    "the key must resolve to exactly the one address the single real dispatch \
                     published, proving no second dispatch redid the publication"
                );

                Ok(())
            })
            .await
    }

    // B9: NOT-RUN.
    //
    // The full scenario -- lose the response after a public `Put`'s association commit, perform
    // an intervening obliterate + re-store from an OTHER server/session, reconnect the original
    // client, and assert exactly one epoch-N `Put`, zero epoch-N+1 `Put` bytes, no replacement
    // `session_start` for that command, a typed `OutcomeUnknown`, AND that a lifecycle
    // readback after the obliterate/re-store attributes neither success nor failure to the
    // original attempt -- composes B7/B8's severed-response mechanism with a THIRD independent
    // actor (an obliterate + re-store from a different server/session) racing against the first
    // client's still-pending typed call, all before that call resolves. Building the severed-
    // response half is what B7/B8 above prove is achievable; the obliterate/re-store race on top
    // of it, ordered precisely enough to be non-flaky and to avoid attributing the original
    // attempt's outcome, is a materially larger scenario than time in this pass allowed to build
    // and verify without risking a vacuous or flaky assertion. Deferred, not faked. No test
    // function.

    /// B10: the barrier before any epoch-N+1 reconnect/rebind. Every dispatched `MutableNoReplay`
    /// opcode that loses its response branches to `OutcomeUnknown` with ZERO epoch-N+1 bytes,
    /// including no replacement `session_start`. B7 and B8 above each independently prove this
    /// for CAS and PutResolved via [`assert_no_bytes_after_severed_command`]; this case makes the
    /// same proof the explicit subject for the plain `Put` and `MutableStore` opcodes B7/B8 don't
    /// cover, so the barrier is pinned for a representative read-modify path (`MutableStore`) and
    /// the representative immutable-publication path (`Put`) too, not just the two compound ones.
    #[tokio::test]
    async fn b10_barrier_holds_zero_epoch_bytes_for_put_and_mutable_store() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                for opcode in [Command::Put, Command::MutableStore] {
                    let (scenario, notify_processed, server) =
                        severed_response_scenario(opcode).await;
                    let SeveredScenario { session, log, .. } = scenario;

                    #[allow(clippy::disallowed_methods)]
                    let task: tokio::task::JoinHandle<
                        Result<bool, lore_transport::ProtocolError>,
                    > = match opcode {
                        Command::Put => {
                            let (fragment, address, payload) = random_fragment();
                            let session = session.clone();
                            tokio::spawn(async move {
                                session
                                    .put_outcome(address, fragment, Some(payload))
                                    .await
                                    .map(|outcome| outcome.is_unknown())
                            })
                        }
                        Command::MutableStore => {
                            let key = random::<Hash>();
                            let value = random::<Hash>();
                            let session = session.clone();
                            tokio::spawn(async move {
                                session
                                    .mutable_store_outcome(key, value, KeyType::Untyped)
                                    .await
                                    .map(|outcome| outcome.is_unknown())
                            })
                        }
                        _ => unreachable!("only Put and MutableStore are driven here"),
                    };

                    await_severed(&notify_processed, opcode).await;
                    server.close().await;

                    let is_unknown = task
                        .await
                        .expect("task should not panic")
                        .expect("a dispatched-then-lost mutable command must resolve Ok(Unknown)");
                    assert!(
                        is_unknown,
                        "{opcode} must resolve to MutableOutcome::Unknown when severed"
                    );

                    assert_no_bytes_after_severed_command(&log.lock().unwrap(), opcode as u8);
                }

                Ok(())
            })
            .await
    }

    /// B11: every `MutableNoReplay` opcode returns the typed outcome-unknown after a forced
    /// response loss and is not dispatched a second time. B7 (`MutableCas`) and B8
    /// (`PutResolved`) above cover two of the six with a full double-apply proof; this sweep
    /// covers three of the remaining four (`Put`, `MutableStore`, `Copy`) for the outcome-
    /// unknown + no-redispatch half of the contract (the barrier check duplicates B10 for `Put`/
    /// `MutableStore` on purpose -- it belongs to "every opcode", not just two).
    ///
    /// `Verify` is NOT covered here -- root-caused, not just excluded. Isolated diagnosis: a
    /// `Verify(heal=true)` for a freshly-seeded, uncorrupted fragment (same session, same
    /// connection, right after a real `Put` the wire log confirms succeeded) returns `Err`, not
    /// `Ok`, from the server: `session.verify_outcome(&address, true)` resolves to
    /// `Err(Internal(.. "verify: Failed sending command: Server returned error code 3" ..))` --
    /// `QuicServiceError::Failed`, the generic catch-all `handle_verify`
    /// (`lore-server/src/protocol/storage/verify.rs`) maps every `StoreError` variant it does not
    /// special-case to. The wire log confirms the command genuinely reached the server
    /// (`Observed { opcode: 6 (Verify), session_id: 1 }`, right after the seed `Put`'s `opcode:
    /// 2`), so this is a real dispatched-and-answered error, not a hang or a severing-mechanism
    /// defect -- the severing wrapper's `result.is_ok()` gate correctly never fires because the
    /// real result genuinely is not `Ok`.
    ///
    /// ROOT CAUSE, since confirmed by execution: this harness builds its stores in memory
    /// (`fresh_stores` passes `None::<&str>`), and `LocalImmutableStore::verify_fragment`
    /// refuses a path-less store in its first statement -- `Err(Internal("Cannot verify
    /// fragment: no path to store"))`, at `lore-storage/src/local/immutable_store.rs:4198`.
    /// `handle_verify`'s catch-all maps that to `StoreFailure`, which is the code 3 seen here.
    /// It is identical for `heal=false`, so the heal flag was incidental, and the
    /// `Any::downcast::<LocalImmutableStore>()` candidate is disproven: `immutable_store::create`
    /// returns `LocalImmutableStore::new`'s `Arc<Self>` upcast, so the downcast succeeds and
    /// `verify_fragment` is genuinely reached. Verification reads the fragment's file, so a store
    /// with nowhere to read from cannot do it. That is correct server behaviour, not a transport
    /// or WP-108 defect. Pinned now by `verify_fragment_path_requirement` in `lore-storage`,
    /// which had no coverage before this.
    ///
    /// So `Verify` is uncoverable HERE rather than broken: closing it means giving this harness
    /// path-backed stores, a change to `fresh_stores` and its twelve call sites, not to the
    /// transport. Until then this sweep is honestly three of four.
    ///
    /// `Put`, `MutableStore`, and `Copy` below all correctly resolve `Ok(Unknown)` when severed,
    /// so the severing mechanism itself is sound.
    #[tokio::test]
    async fn b11_every_mutable_no_replay_opcode_yields_unknown_when_severed() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                for opcode in [Command::Put, Command::MutableStore, Command::Copy] {
                    let (scenario, notify_processed, server) =
                        severed_response_scenario(opcode).await;
                    let SeveredScenario {
                        session,
                        immutable,
                        log,
                        ..
                    } = scenario;

                    #[allow(clippy::disallowed_methods)]
                    let task: tokio::task::JoinHandle<
                        Result<bool, lore_transport::ProtocolError>,
                    > = match opcode {
                        Command::Put => {
                            let (fragment, address, payload) = random_fragment();
                            let session = session.clone();
                            tokio::spawn(async move {
                                session
                                    .put_outcome(address, fragment, Some(payload))
                                    .await
                                    .map(|outcome| outcome.is_unknown())
                            })
                        }
                        Command::MutableStore => {
                            let key = random::<Hash>();
                            let value = random::<Hash>();
                            let session = session.clone();
                            tokio::spawn(async move {
                                session
                                    .mutable_store_outcome(key, value, KeyType::Untyped)
                                    .await
                                    .map(|outcome| outcome.is_unknown())
                            })
                        }
                        Command::Copy => {
                            let (fragment, address, payload) = random_fragment();
                            let source_partition = session.partition().await?;
                            session
                                .put(address, fragment, Some(payload))
                                .await
                                .expect("seed put for copy should succeed");
                            let target_context =
                                lore_base::types::Context::from(rand::random::<[u8; 16]>());
                            let session = session.clone();
                            tokio::spawn(async move {
                                session
                                    .copy_outcome(source_partition, address, target_context)
                                    .await
                                    .map(|outcome| outcome.is_unknown())
                            })
                        }
                        Command::Verify => {
                            let (fragment, address, payload) = random_fragment();
                            session
                                .put(address, fragment, Some(payload))
                                .await
                                .expect("seed put for verify should succeed");
                            let session = session.clone();
                            tokio::spawn(async move {
                                let result = session.verify_outcome(&address, true).await;
                                eprintln!("[b11 diagnostic] verify_outcome raw result: {result:?}");
                                result.map(|outcome| outcome.is_unknown())
                            })
                        }
                        _ => unreachable!("only these four opcodes are driven here"),
                    };

                    await_severed(&notify_processed, opcode).await;
                    server.close().await;

                    let is_unknown = task
                        .await
                        .expect("task should not panic")
                        .expect("a dispatched-then-lost mutable command must resolve Ok(Unknown)");
                    assert!(
                        is_unknown,
                        "{opcode} must resolve to MutableOutcome::Unknown when severed"
                    );

                    assert_no_bytes_after_severed_command(&log.lock().unwrap(), opcode as u8);
                    let _ = &immutable; // kept alive for the duration of the loop iteration
                }

                Ok(())
            })
            .await
    }

    /// A real server error answer is never replay authority. The path-less in-memory immutable
    /// store makes `Verify` return the storage service's generic failure after the request has
    /// reached the server. Move the connection generation while that answer is held in flight,
    /// then require the original error and exactly one observed Verify dispatch.
    #[tokio::test]
    async fn answered_mutable_no_replay_error_is_not_redispatched_when_generation_moves()
    -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr().unwrap();
                let port = addr.port();
                let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

                let (immutable, mutable) = fresh_stores().await;
                let log: Log = Arc::new(StdMutex::new(Vec::new()));
                let (_server, notify_answered, release_answer) = start_answer_holding_quic_server(
                    udp,
                    immutable,
                    mutable,
                    log.clone(),
                    Command::Verify,
                );

                let partition = random::<RepositoryId>();
                let connection = lore_revision::protocol::connect(
                    &format!("lore://127.0.0.1:{port}"),
                    "",
                    partition,
                )
                .await?;
                let session = connection.session(partition, "answered-generation").await?;

                // Verify needs a real stored address to reach the path-less-store failure. A
                // missing address would return modeled NotFound, which takes a separate fixed
                // classifier arm and would not exercise the answered generic-error branch.
                let (fragment, address, payload) = random_fragment();
                session
                    .put(address, fragment, Some(payload))
                    .await
                    .expect("seed put should succeed");

                let session_for_verify = session.clone();
                let verify_task = lore_base::lore_spawn!(async move {
                    session_for_verify.verify_outcome(&address, true).await
                });

                tokio::time::timeout(SEVER_SIGNAL_TIMEOUT, notify_answered.notified())
                    .await
                    .expect("server did not produce the expected Verify error answer");
                connection
                    .advance_storage_generation_before_epoch_for_test()
                    .await
                    .expect("QUIC generation seam should be available");
                release_answer.notify_one();

                let error = tokio::time::timeout(SEVER_SIGNAL_TIMEOUT, verify_task)
                    .await
                    .expect("answered Verify must return instead of hanging")
                    .expect("verify task should not panic")
                    .expect_err("the server's real Verify failure must reach the caller");

                let snapshot = log.lock().unwrap().clone();
                let verify_dispatches = snapshot
                    .iter()
                    .filter(|observed| observed.opcode == Command::Verify as u8)
                    .count();
                assert_eq!(
                    verify_dispatches, 1,
                    "an answered MutableNoReplay error must not be redispatched after the \
                     generation moves; observed: {snapshot:?}"
                );
                assert!(
                    snapshot
                        .iter()
                        .any(|observed| observed.opcode == Command::Verify as u8),
                    "the server must have observed the Verify bytes before its answer was held"
                );
                assert!(
                    error.to_string().contains("Server returned error code"),
                    "the original answered server error must reach the caller, got {error:?}"
                );

                Ok(())
            })
            .await
    }

    /// The companion positive control for the retry gate. Pause after the old session id has
    /// resolved but before the QUIC write lock, move the generation, and resume. The first send
    /// must be refused as `NotDispatched`; the session layer then rebinds and performs the one
    /// server-observed MutableStore dispatch.
    #[tokio::test]
    async fn not_dispatched_generation_mover_rebinds_and_retries_once() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr().unwrap();
                let port = addr.port();
                let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

                let (immutable, mutable) = fresh_stores().await;
                let log: Log = Arc::new(StdMutex::new(Vec::new()));
                let _server =
                    start_recording_quic_server(udp, immutable, mutable.clone(), log.clone());

                let partition = random::<RepositoryId>();
                let connection = lore_revision::protocol::connect(
                    &format!("lore://127.0.0.1:{port}"),
                    "",
                    partition,
                )
                .await?;
                let session = connection
                    .session(partition, "not-dispatched-generation")
                    .await?;
                connection
                    .arm_storage_session_send_pause_for_test()
                    .await
                    .expect("QUIC pre-write pause should arm");

                let key = random::<Hash>();
                let value = random::<Hash>();
                let session_for_store = session.clone();
                let store_task = lore_base::lore_spawn!(async move {
                    session_for_store
                        .mutable_store_outcome(key, value, KeyType::Untyped)
                        .await
                });

                tokio::time::timeout(
                    SEVER_SIGNAL_TIMEOUT,
                    connection.wait_for_storage_session_send_pause_for_test(),
                )
                .await
                .expect("MutableStore did not reach the armed pre-write pause")
                .expect("QUIC pre-write pause should be available");
                connection
                    .advance_storage_generation_before_epoch_for_test()
                    .await
                    .expect("QUIC generation seam should be available");
                connection
                    .resume_storage_session_send_for_test()
                    .expect("paused MutableStore should resume");

                let outcome = tokio::time::timeout(SEVER_SIGNAL_TIMEOUT, store_task)
                    .await
                    .expect("the rebound MutableStore must complete")
                    .expect("mutable store task should not panic")
                    .expect("a genuinely NotDispatched command should rebind and retry");
                assert!(
                    !outcome.is_unknown(),
                    "the only server-observed MutableStore dispatch returned Applied"
                );

                let snapshot = log.lock().unwrap().clone();
                let mutable_store_dispatches = snapshot
                    .iter()
                    .filter(|observed| observed.opcode == Command::MutableStore as u8)
                    .count();
                let authorize_dispatches = snapshot
                    .iter()
                    .filter(|observed| observed.opcode == Command::Authorize as u8)
                    .count();
                assert_eq!(
                    mutable_store_dispatches, 1,
                    "the refused NotDispatched attempt must emit no bytes; only the rebound retry \
                     reaches the server, observed: {snapshot:?}"
                );
                assert_eq!(
                    authorize_dispatches, 2,
                    "the generation move must add exactly one replacement session_start before \
                     the one MutableStore dispatch, observed: {snapshot:?}"
                );

                let stored = mutable
                    .load(partition, key, KeyType::Untyped)
                    .await
                    .expect("the rebound MutableStore should apply");
                assert_eq!(stored, value);

                Ok(())
            })
            .await
    }

    /// B14: a caller using the EXISTING (non-`_outcome`) methods is not automatically upgraded.
    /// It still sees the pre-existing error shape (`Disconnected`, not a typed unknown), and
    /// linking the fixed library does not by itself declare any active-active outcome-unknown
    /// capability for callers who haven't opted in.
    #[tokio::test]
    async fn b14_unadopted_caller_sees_the_pre_existing_error_shape() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (scenario, notify_processed, server) =
                    severed_response_scenario(Command::MutableStore).await;
                let SeveredScenario { session, .. } = scenario;

                let key = random::<Hash>();
                let value = random::<Hash>();
                let session_for_store = session.clone();
                #[allow(clippy::disallowed_methods)]
                let task = tokio::spawn(async move {
                    // The plain, non-`_outcome` method -- an unadopted caller's code path.
                    session_for_store
                        .mutable_store(key, value, KeyType::Untyped)
                        .await
                });

                await_severed(&notify_processed, Command::MutableStore).await;
                server.close().await;

                let result = task.await.expect("task should not panic");
                assert!(
                    result.is_err(),
                    "an unadopted caller must still see a plain error, not a typed outcome, got \
                     {result:?}"
                );
                let err = result.unwrap_err();
                assert!(
                    err.is_disconnected(),
                    "the unadopted-caller error shape for a severed mutable dispatch is \
                     Disconnected (StorageClient::map_send_error maps both SessionRebindRequired \
                     and OutcomeUnknown to it) -- got {err:?} instead"
                );

                Ok(())
            })
            .await
    }

    /// B15: gRPC storage stays green, and gRPC's `connection_epoch` is explicitly pinned as a
    /// constant that never changes -- the QUIC epoch/rebind behavior must not leak into a
    /// transport that keeps its own sessions client-side and never expires them by generation.
    #[tokio::test]
    async fn b15_grpc_connection_epoch_is_constant_and_grpc_storage_still_works() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, _udp_unused) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr().unwrap();
                let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

                // `grpc://` scheme, not `lore://` -- routes to GRPCProtocol, never touches QUIC.
                let connection = lore_transport::connect(
                    &format!("grpc://127.0.0.1:{}", addr.port()),
                    "",
                    RepositoryId::default(),
                    1,
                    "",
                    "",
                )
                .await?;
                let storage = connection.storage().await?;

                let epoch_before = storage.connection_epoch();
                assert_eq!(
                    epoch_before, 1,
                    "GRPCStorage::connection_epoch must report the GRPC_STATIC_SESSION_EPOCH \
                     constant"
                );

                // A real round trip still works over gRPC storage.
                let session_id = storage
                    .session_start(random::<RepositoryId>(), "b15-correlation")
                    .await?;
                let (fragment, address, payload) = random_fragment();
                storage
                    .put(session_id, address, fragment, Some(payload.clone()))
                    .await?;
                let (_fragment, got) = storage.get(session_id, &address).await?;
                assert_eq!(got, payload, "gRPC storage put/get must still round-trip");

                let epoch_after = storage.connection_epoch();
                assert_eq!(
                    epoch_after, epoch_before,
                    "the epoch must never move for gRPC storage, whatever traffic crossed it -- \
                     QUIC's per-connection generation has no meaning here"
                );

                Ok(())
            })
            .await
    }

    // B16: sibling sweep. `storage_replay_class` (`lore_transport::replay::storage_replay_class`)
    // is the SOLE construction boundary every `send_*_with_reconnect` call site reads from --
    // `StorageClient::replay_class` (`ServiceClient` impl, `quic/storage_service/client.rs`)
    // delegates to it directly, and every `send_normal_with_reconnect`/
    // `send_high_priority_with_reconnect`/`send_normal_with_reconnect_outcome` call in that same
    // file passes a `Command` variant through to `send_with_reconnect`, which calls
    // `service_client.replay_class(request_type)` -- there is no second, locally-decided
    // classification anywhere in the call sites. So B12's exhaustive match
    // (`lore-transport/tests/replay_contract.rs`) already covers every call site by
    // construction: no call site can bypass `storage_replay_class` to invent its own class, and
    // every one of the 12 `Command` variants is classified there. No additional per-call-site
    // pin is needed. Verified by reading `StorageClient`'s `Storage` impl in full
    // (`quic/storage_service/client.rs`) and confirming every mutating method (`put`,
    // `put_resolved`, `mutable_store`, `mutable_compare_and_swap`, `copy`, `verify`) and its
    // `_outcome` twin route through
    // `send_normal_with_reconnect`/`send_normal_with_reconnect_outcome` with its own dedicated
    // `Command` variant, never a shared or inferred one. No test function: there is nothing left
    // to assert once the call-site sweep confirms this structurally -- B12 already covers it.

    // ── Phase C: INV-EO P0-1/P0-2 -- server-side session-id aliasing across connections ──
    //
    // INV-EO (2026-08-31 independent review) found the rebinding core was NOT sound: the
    // deliberately-open client race window (documented at `session.rs:87-97`, not
    // deterministically reproducible in a test -- see this file's top comment) could hand a
    // STALE numeric session id to a REPLACEMENT connection. That id used to be accepted
    // whenever it happened to exist in the replacement connection's own `SessionMap`, because
    // each accepted QUIC connection's `SessionMap` counter independently restarted at 1, so two
    // live sessions on two DIFFERENT connections routinely got the exact same numeric id.
    //
    // Fixed (2026-08-31) in two independent layers -- see the `lore-transport-client` skill for
    // the full contract:
    //   - SERVER: session ids now come from one process-wide `NEXT_SESSION_ID` sequence,
    //     randomised at start rather than fixed at 1 (`lore-server/src/protocol/storage/
    //     session.rs`), so no two `SessionMap`s ever issue the same id and one loreserver
    //     process's ids are not predictable from another's. Allocation claims the id through
    //     `DashMap`'s vacant-entry API rather than blind-inserting, so a post-wrap collision with
    //     a still-live entry is redrawn rather than silently overwriting it.
    //   - CLIENT: `QuicConnection` records the connection generation each session id was issued
    //     on (`register_session`) and `send_command_tracked` refuses to frame an id whose
    //     generation has moved, at the write boundary, inside the same lock section a reconnect
    //     must take to swap the connection (`QuicConnection::session_is_current`).
    //
    // R1/R2 below reproduce the fully deterministic SERVER-side half specifically: no reconnect,
    // no timing race, two ordinary connections and a hand-framed command, with the client's own
    // write-boundary gate deliberately forced open (see R1's doc comment) so a failure here is
    // proof of the server's own defense, not just the client's. `register_session` itself is
    // `pub(crate)` to `lore-transport` -- marking an arbitrary id current on an arbitrary
    // connection from ANY linking crate would reopen INV-EO P0-1 by another door. This file
    // instead calls `QuicConnection::register_session_for_test`, a `pub` forwarder gated behind
    // `lore-transport`'s `test_seams` cargo feature (enabled for this crate in
    // `lore-integration-tests/Cargo.toml`) -- forging that state deliberately, from this one
    // named door, is how the server half of the fix gets exercised on its own, independent of
    // the client layer it must not depend on. The client gate's own correctness is pinned
    // separately and deterministically in `lore-transport/src/quic/client.rs`'s
    // `quic::client::tests::a_session_id_stops_being_current_once_its_generation_is_replaced`.
    //
    // No test here may assume a session id is small, starts at a fixed value, or is contiguous
    // with another -- `NEXT_SESSION_ID` starts at a random `u32` and is shared with whatever
    // else in this test binary happens to be running concurrently.

    /// A bare QUIC connection to the recording server, with no `StorageSession`/`StorageClient`
    /// wrapping. Gives R1/R2 direct control of the wire framing via [`send_normal`] -- exactly
    /// what is needed to send a session id issued to a DIFFERENT connection, which is what the
    /// documented client race (INV-EO P0-1/P0-2) would emit. Mirrors `StorageClient::connect`'s
    /// own low-level setup (`quic/storage_service/client.rs:129-203`), minus the auth-adapter
    /// and credential plumbing this auth-OFF harness never exercises -- `CertificateSettings`
    /// below is byte-for-byte what `StorageClientAuth::client_certs()`
    /// (`quic/storage_service/auth.rs`) returns, and `lore://` (not `lores://`) means the
    /// server certificate is never validated, exactly as for every other connection in this
    /// file.
    async fn raw_quic_connection(port: u16) -> Arc<QuicConnection> {
        let quinn_connection = raw_quic_connect(
            &EndpointConfig {
                remote_url: format!("lore://127.0.0.1:{port}"),
                default_port: port,
                sni_override: None,
            },
            CertificateSettings {
                custom_ca: None,
                client: None,
            },
            TEST_PROTOCOL_V4,
            TransportConfig {
                max_bytes_bandwidth_per_second: (1024 * 1024 * 1024) / 8,
                expected_rtt_ms: DEFAULT_EXPECTED_RTT_MS,
                congestion_algorithm: CongestionAlgorithm::Bbr,
                initial_cwnd: None,
            },
        )
        .await
        .expect("raw QUIC connect to the recording server");

        let quic = Arc::new(QuicConnection::with_v4(
            quinn_connection,
            MAX_CHUNK_SIZE,
            true,
        ));
        quic.create_initial_stream()
            .await
            .expect("raw QUIC initial stream");
        quic.stream_count
            .store(1, std::sync::atomic::Ordering::Relaxed);
        quic
    }

    /// Send a real `Command::Authorize` (session_start) on `quic`, framed exactly as
    /// `StorageClient::session_start` does (`quic/storage_service/client.rs:473-526`): the byte
    /// layout is action(1=0), partition(16), corr_len(1), corr(N), token_len(2, u16 LE),
    /// token(M). The token is empty because this harness's `auth_url` is always empty (auth is
    /// off), matching production's own
    /// `if !self.auth_url.is_empty() { .. } else { String::new() }` branch. Also mirrors
    /// production's post-fix bookkeeping (`StorageClient::session_start`'s
    /// `self.quic.register_session(session_id, generation)`, `pub(crate)` to `lore-transport` --
    /// reached here through the `test_seams`-gated `register_session_for_test` forwarder
    /// instead): without it, `quic`'s own `sessions` map would stay empty forever and the
    /// client-side write-boundary check (`QuicConnection::session_is_current`, `quic/client.rs`)
    /// would refuse even this connection's own legitimately-issued id on every later send.
    /// Returns the server-assigned session id.
    async fn raw_session_start(
        quic: &Arc<QuicConnection>,
        partition: RepositoryId,
        correlation_id: &str,
    ) -> u32 {
        let corr_bytes = correlation_id.as_bytes();
        let mut payload = BytesMut::with_capacity(1 + 16 + 1 + corr_bytes.len() + 2);
        payload.put_u8(0); // action = start
        payload.extend_from_slice(partition.as_bytes());
        payload.put_u8(corr_bytes.len() as u8);
        payload.extend_from_slice(corr_bytes);
        payload.extend_from_slice(&0u16.to_le_bytes()); // empty token, auth is off
        let payload = payload.freeze();

        // Sampled before the request, exactly as `StorageClient::session_start` does, and for
        // the same reason: a connection replaced mid-call must record the OLDER generation.
        let generation = quic.connection_generation();

        let response = send_normal(
            quic.clone(),
            Command::Authorize as QuicOpCode,
            0,
            true,
            &mut [Bytes::default(), payload],
        )
        .await
        .expect("raw session_start should succeed against an auth-off server");

        assert_eq!(
            response.len(),
            4,
            "session_start response must be a 4-byte little-endian session id, got {} bytes",
            response.len()
        );
        let session_id = u32::from_le_bytes(response[..4].try_into().unwrap());
        quic.register_session_for_test(session_id, generation);
        session_id
    }

    /// R1: connection 1's session id, framed onto connection 2's wire, must not apply a `Put` to
    /// connection 2's repository -- INV-EO P0-1's deterministic SERVER-side half, isolated from
    /// the client-side write-boundary check (`QuicConnection::session_is_current`) so this test
    /// proves what it always proved: the server-side fix (`NEXT_SESSION_ID`, one process-wide
    /// sequence -- `lore-server/src/protocol/storage/session.rs`) independently refuses a
    /// foreign id, not only the client's own bookkeeping.
    ///
    /// The client-side check is real and would ALSO refuse this send outright (`conn2` never
    /// registered `id_a`), which is why this test forces
    /// `conn2.register_session_for_test(id_a, ..)` immediately before sending: that one line
    /// (the `test_seams`-gated forwarder to the `pub(crate)` `register_session`) simulates the
    /// exact state a real client's
    /// bookkeeping would be in right after the documented, non-deterministic race window this
    /// file's top comment describes (the client believes `id_a` is valid to send here) --
    /// isolating the question this test exists to answer: if the client's own gate is somehow
    /// wrong, does the server independently refuse it? `session_is_current`'s own correctness is
    /// a separate, client-only property, pinned deterministically by
    /// `quic::client::tests::a_session_id_stops_being_current_once_its_generation_is_replaced`
    /// in `lore-transport/src/quic/client.rs`, not by this file.
    #[tokio::test]
    async fn r1_a_stale_session_id_is_accepted_on_another_connection_and_writes_the_wrong_repository()
    -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr().unwrap();
                let port = addr.port();
                let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

                let (immutable, mutable) = fresh_stores().await;
                let log: Log = Arc::new(StdMutex::new(Vec::new()));
                let _server =
                    start_recording_quic_server(udp, immutable.clone(), mutable, log.clone());

                let partition_a = random::<RepositoryId>();
                let partition_b = random::<RepositoryId>();
                assert_ne!(
                    partition_a, partition_b,
                    "the two connections must be authorized for genuinely different repositories \
                     for a wrong-repository write to be observable"
                );

                let conn1 = raw_quic_connection(port).await;
                let id_a = raw_session_start(&conn1, partition_a, "r1-conn1").await;

                let conn2 = raw_quic_connection(port).await;
                let id_b = raw_session_start(&conn2, partition_b, "r1-conn2").await;

                // Post-fix: session ids come from one process-wide sequence
                // (`NEXT_SESSION_ID`), so two live sessions on two DIFFERENT connections can
                // never collide any more -- the opposite of the pre-fix precondition this test
                // used to assert. If this ever fires, the server-side allocator has regressed
                // back toward per-connection numbering. Do not additionally assert anything
                // about the MAGNITUDE of either id -- see this file's Phase C header comment
                // (`NEXT_SESSION_ID` starts at a random `u32`).
                assert_ne!(
                    id_a, id_b,
                    "two connections' session ids must never collide once session ids come from \
                     one process-wide sequence (NEXT_SESSION_ID)"
                );

                // Simulate a client whose bookkeeping already (incorrectly) believes id_a is
                // valid to send here -- see the doc comment above. Real production code never
                // does this; `StorageClient::session_start` is the only caller of
                // `register_session`, and it only ever registers the id the SERVER just handed
                // back to THIS call.
                conn2.register_session_for_test(id_a, conn2.connection_generation());

                let (fragment, address, payload) = random_fragment();
                let put_result = send_normal(
                    conn2.clone(),
                    Command::Put as QuicOpCode,
                    id_a,
                    true,
                    &mut [
                        Bytes::default(),
                        Bytes::from_owner(address),
                        Bytes::from_owner(fragment),
                        payload.clone(),
                    ],
                )
                .await;

                // With the client-side gate forced open, the bytes actually left the process
                // this time -- confirm the server genuinely saw them, so a failure below is
                // proof of a SERVER-side refusal, not just an unsent command.
                let log_snapshot = log.lock().unwrap().clone();
                assert_eq!(
                    log_snapshot.last(),
                    Some(&Observed {
                        opcode: Command::Put as u8,
                        session_id: id_a,
                    }),
                    "the server must have received the forged Put carrying connection 1's \
                     session id on connection 2's wire; observed: {log_snapshot:?}"
                );

                // Pre-fix reproduction (recorded verbatim 2026-08-31, before NEXT_SESSION_ID
                // landed): put_result = Ok(b"") -- the forged Put SUCCEEDED; found_in_a =
                // Err(AddressNotFound(..)); found_in_b = Ok(StoreGetData { fragment: Fragment {
                // flags: 262144, size_payload: 32, size_content: 32 }, match_made: MatchFull,
                // partition: <partition_b>, payload: Some(<the 32-byte payload>) }) -- the
                // fragment landed in partition B, connection 2's OWN repository, even though the
                // id sent was the one issued to connection 1.
                // Post-fix (recorded verbatim 2026-08-31, one representative run against the
                // final tree -- NEXT_SESSION_ID's random start means the exact numbers vary run
                // to run, but id_a != id_b always holds): id_a=1058134712, id_b=1058134714,
                // put_result=Err(ServerError(3)), found_in_a=Err(AddressNotFound(..)),
                // found_in_b=Err(AddressNotFound(..)) -- the forged Put reached the server
                // (confirmed by the log assertion above) and was refused; the fragment landed
                // nowhere.
                let found_in_a = immutable.clone().get(partition_a, address).await;
                let found_in_b = immutable.clone().get(partition_b, address).await;

                assert!(
                    put_result.is_err(),
                    "the server's own SessionMap for connection 2 was never given id_a (it \
                     belongs to connection 1's SessionMap under the process-wide sequence), so \
                     the forged Put must be refused server-side even with the client's own gate \
                     forced open; got {put_result:?}"
                );

                assert!(
                    found_in_a.is_err(),
                    "partition A must never see a write it was never party to; got {found_in_a:?}"
                );

                assert!(
                    found_in_b.is_err(),
                    "the forged Put must not have applied anywhere, including connection 2's \
                     own partition B; got {found_in_b:?}"
                );

                Ok(())
            })
            .await
    }

    /// R2: a session_stop framed with connection 1's session id, sent on connection 2's wire,
    /// must not remove connection 2's own live session -- INV-EO P0-2's deterministic SERVER-side
    /// half, isolated from the client-side gate the same way R1 does (see its doc comment for
    /// why forcing `register_session_for_test` here is deliberate, not a bypass of what this
    /// test means to prove).
    #[tokio::test]
    async fn r2_a_stale_session_stop_removes_an_unrelated_live_session() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr().unwrap();
                let port = addr.port();
                let _grpc_shutdown = start_grpc_backend(tcp, addr).await;

                let (immutable, mutable) = fresh_stores().await;
                let log: Log = Arc::new(StdMutex::new(Vec::new()));
                let _server = start_recording_quic_server(udp, immutable, mutable, log.clone());

                let partition_a = random::<RepositoryId>();
                let partition_b = random::<RepositoryId>();

                let conn1 = raw_quic_connection(port).await;
                let id_a = raw_session_start(&conn1, partition_a, "r2-conn1").await;

                let conn2 = raw_quic_connection(port).await;
                let id_b = raw_session_start(&conn2, partition_b, "r2-conn2").await;

                // Post-fix: see R1's comment on the same assertion.
                assert_ne!(
                    id_a, id_b,
                    "two connections' session ids must never collide once session ids come from \
                     one process-wide sequence (NEXT_SESSION_ID)"
                );

                // Simulate a client whose bookkeeping already (incorrectly) believes id_a is
                // valid to send here -- see R1's doc comment for why this is deliberate.
                conn2.register_session_for_test(id_a, conn2.connection_generation());

                // Forge a session_stop carrying connection 1's id on connection 2's wire -- the
                // exact framing `StorageClient::session_stop` uses: action byte 1, no partition,
                // header session id set to the id being stopped
                // (`quic/storage_service/client.rs:528-540`).
                let stop_result = send_normal(
                    conn2.clone(),
                    Command::Authorize as QuicOpCode,
                    id_a,
                    true,
                    &mut [Bytes::default(), Bytes::from_static(&[1u8])],
                )
                .await;

                let log_snapshot = log.lock().unwrap().clone();
                assert_eq!(
                    log_snapshot.last(),
                    Some(&Observed {
                        opcode: Command::Authorize as u8,
                        session_id: id_a,
                    }),
                    "the server must have received the forged stop on connection 2's wire; \
                     observed: {log_snapshot:?}"
                );

                // Pre-fix reproduction (recorded verbatim 2026-08-31, before NEXT_SESSION_ID
                // landed): stop_result = Ok(b"") -- the forged stop SUCCEEDED against connection
                // 2's own entry (`SessionMap::stop` matched on the bare id alone);
                // post_stop_put = Err(ServerError(3)) -- a subsequent Put on connection 2 using
                // its own session id id_b then failed as an unknown session, because the entry
                // the forged stop removed WAS connection 2's own live session.
                //
                // Post-fix: id_a was never issued to connection 2's own SessionMap (it belongs
                // to connection 1's, under the process-wide sequence), so the server's `stop`
                // must find nothing there to remove.
                // Post-fix (recorded verbatim 2026-08-31, one representative run against the
                // final tree): id_a=1058134713, id_b=1058134715,
                // stop_result=Err(ServerError(3)).
                assert!(
                    stop_result.is_err(),
                    "the server's own SessionMap for connection 2 never held id_a, so the \
                     forged stop must be refused server-side, not silently accepted; got \
                     {stop_result:?}"
                );

                let (fragment, address, payload) = random_fragment();
                let post_stop_put = send_normal(
                    conn2.clone(),
                    Command::Put as QuicOpCode,
                    id_b,
                    true,
                    &mut [
                        Bytes::default(),
                        Bytes::from_owner(address),
                        Bytes::from_owner(fragment),
                        payload.clone(),
                    ],
                )
                .await;
                // Recorded verbatim 2026-08-31: post_stop_put=Ok(b"") -- connection 2's own
                // session survived the forged stop.

                assert!(
                    post_stop_put.is_ok(),
                    "a stale session_stop forged from another connection must not remove \
                     connection 2's own live session -- a Put on connection 2's still-live \
                     session should succeed; got {post_stop_put:?}"
                );

                Ok(())
            })
            .await
    }
}
