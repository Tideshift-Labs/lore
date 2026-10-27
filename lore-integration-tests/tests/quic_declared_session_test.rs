// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//
// WP-124 slice 2a: the client declares a managed caller's storage session over QUIC.
//
// [CLIENT]-class: `lore-transport`'s `StorageSession` picks a binding per call. A call inside a
// managed scope (`with_caller_operation`) on a QUIC transport runs on a *declared* session
// (`AuthorizeStart` action 2 plus the capability list); every other call runs on the undeclared
// session (action 0, as before). The declared sessions belong to the scope's
// `CallerOperationContext` and are stopped when its last clone drops.
//
// The server here is the real slice-1 `StorageServiceV4` under the strict policy, wrapped only to
// record what crossed the wire. Live-session state is read from the server's own `SessionMap`
// (via `lore-server`'s `test-util` fields), not inferred from client state.
//
// Reads (Query) are the managed traffic: `reject_managed_quic` still refuses managed QUIC writes
// in slice 2a, so nothing here asserts a managed write is admitted.
#[cfg(all(test, feature = "integration_tests"))]
mod quic_declared_session_tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::time::Instant;

    use async_trait::async_trait;
    use bytes::Bytes;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Address;
    use lore_base::types::Context;
    use lore_base::types::Hash;
    use lore_base::types::KeyType;
    use lore_revision::environment::EnvironmentConfig;
    use lore_revision::fragment;
    use lore_revision::lore::RepositoryId;
    use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
    use lore_server::authnz::repository_catalog::BaselineRepositoryCatalog;
    use lore_server::grpc::caller_capabilities::CallerCapabilityPolicy;
    use lore_server::grpc::server::FeatureSettings;
    use lore_server::grpc::server::GrpcServerBuilder;
    use lore_server::grpc::server::GrpcTimeouts;
    use lore_server::hooks::HookDispatcher;
    use lore_server::protocol::attribute_map::AttributeMap;
    use lore_server::protocol::storage::messages::MessageHandleError;
    use lore_server::protocol::storage::messages::MessageParseError;
    use lore_server::protocol::storage::session::SessionMap;
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
    use lore_server::quic::stream_handler::AdmissionLimits;
    use lore_server::quic::stream_handler::StreamHandler;
    use lore_server::quic::tests::TEST_PROTOCOL_V4;
    use lore_server::quic::tests::server_certs;
    use lore_server::settings::BaselineAccess;
    use lore_storage::ImmutableStore;
    use lore_storage::MutableStore;
    use lore_storage::local::immutable_store::ImmutableStoreCreateOptions;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;
    use lore_telemetry::user_agent_filter::UserAgentFilter;
    use lore_transport::CallerOperationContext;
    use lore_transport::Connection;
    use lore_transport::QuicDeclarationRefused;
    use lore_transport::VolatileAttemptStore;
    use lore_transport::current_caller_operation;
    use lore_transport::error::ProtocolError;
    use lore_transport::is_quic_declaration_refused;
    use lore_transport::quic::QuicOpCode;
    use lore_transport::quic::command_header::CommandHeader;
    use lore_transport::quic::storage_service::Command;
    use lore_transport::session::StorageSession;
    use lore_transport::with_caller_operation;
    use lore_transport::with_optional_caller_operation;
    use rand::random;
    use tracing::Span;

    use crate::common::net_common::bind_matched_pair;
    use crate::setup_execution;

    type TestResult = Result<(), Box<dyn Error>>;

    const ACTION_START: u8 = 0;
    const ACTION_STOP: u8 = 1;
    const ACTION_START_DECLARED: u8 = 2;
    const WAIT: Duration = Duration::from_secs(5);

    // ---------------------------------------------------------------------------------------
    // Server: the real `StorageServiceV4` (strict), wrapped to record the wire.
    // ---------------------------------------------------------------------------------------

    /// How the wrapped server answers an `AuthorizeStart`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Mode {
        /// The slice-1 server, unmodified.
        Real,
        /// A stock server: any `Authorize` action but 0 and 1 is a parse error (status 1).
        Stock,
        /// A slice-1 server that refuses the declaration it was sent (status 200).
        RefuseDeclared200,
        /// A server that fails every action-0 start, so the undeclared path cannot succeed.
        RejectUndeclared,
    }

    /// One inbound command, recorded off its header before it is parsed.
    #[derive(Clone, Copy, Debug)]
    struct Wire {
        opcode: u8,
        session_id: u32,
        /// The first payload byte of an `Authorize`: 0 start, 1 stop, 2 declared start.
        action: Option<u8>,
        /// Which accepted connection carried it.
        connection: usize,
    }

    /// `(arrived, release)`: see [`Probe::hold`].
    type Hold = Arc<StdMutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>>;

    static NEXT_CONNECTION: AtomicUsize = AtomicUsize::new(1);

    /// What a test reads back from the server.
    #[derive(Clone, Default)]
    struct Probe {
        log: Arc<StdMutex<Vec<Wire>>>,
        /// One `SessionMap` per accepted connection.
        maps: Arc<StdMutex<Vec<Arc<SessionMap>>>>,
        /// When set, the next declared `AuthorizeStart` tells `.0` it arrived and waits for `.1`
        /// before the real handler runs, so a test can act while the start is in flight.
        hold: Hold,
        /// As `hold`, for the next `Query` command.
        query_hold: Hold,
    }

    impl Probe {
        fn wire(&self) -> Vec<Wire> {
            self.log.lock().expect("log mutex").clone()
        }

        fn authorize_actions(&self) -> Vec<u8> {
            self.wire()
                .iter()
                .filter(|w| w.opcode == Command::Authorize as u8)
                .filter_map(|w| w.action)
                .collect()
        }

        fn count_action(&self, action: u8) -> usize {
            self.authorize_actions()
                .iter()
                .filter(|a| **a == action)
                .count()
        }

        /// The session id each `Query` arrived under, in arrival order.
        fn query_sessions(&self) -> Vec<u32> {
            self.wire()
                .iter()
                .filter(|w| w.opcode == Command::Query as u8)
                .map(|w| w.session_id)
                .collect()
        }

        fn connections_seen(&self) -> usize {
            let mut seen: Vec<usize> = self.wire().iter().map(|w| w.connection).collect();
            seen.sort_unstable();
            seen.dedup();
            seen.len()
        }

        /// Live sessions across every connection, from the server's own `SessionMap`s.
        fn live(&self) -> usize {
            self.maps
                .lock()
                .expect("maps mutex")
                .iter()
                .map(|map| map.entries.len())
                .sum()
        }

        fn declared_live(&self) -> usize {
            self.maps
                .lock()
                .expect("maps mutex")
                .iter()
                .map(|map| {
                    map.entries
                        .iter()
                        .filter(|entry| entry.value().declared)
                        .count()
                })
                .sum()
        }

        /// `Some(declared)` for a live session id, `None` for one the server does not hold.
        fn declared_of(&self, session_id: u32) -> Option<bool> {
            self.maps
                .lock()
                .expect("maps mutex")
                .iter()
                .find_map(|map| map.get(session_id).map(|entry| entry.declared))
        }
    }

    struct ProbeService {
        inner: StorageServiceV4,
        mode: Mode,
        connection: usize,
        log: Arc<StdMutex<Vec<Wire>>>,
        hold: Hold,
        query_hold: Hold,
    }

    #[async_trait]
    impl QuicService for ProbeService {
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
            let action = (header.cmd == Command::Authorize as u8)
                .then(|| bytes.first().copied())
                .flatten();
            self.log.lock().expect("log mutex").push(Wire {
                opcode: header.cmd,
                session_id: header.session_id,
                action,
                connection: self.connection,
            });
            match (self.mode, action) {
                (Mode::Stock, Some(a)) if a != ACTION_START && a != ACTION_STOP => {
                    Err(MessageParseError::ParseFailure("unrecognized action byte"))
                }
                (Mode::RejectUndeclared, Some(ACTION_START)) => {
                    Err(MessageParseError::ParseFailure("unrecognized action byte"))
                }
                _ => self.inner.parse_request_bytes(header, bytes),
            }
        }

        async fn run_request_handler(
            &self,
            context: Arc<AttributeMap>,
            request: Self::ParsedRequestType,
        ) -> Result<Vec<Bytes>, Self::RequestHandlerError> {
            if self.mode == Mode::RefuseDeclared200
                && let ParsedStorageRequestV4::AuthorizeStart {
                    caller_capabilities: Some(_),
                    ..
                } = &request
            {
                return Err(MessageHandleError::UnsupportedClient);
            }
            if let ParsedStorageRequestV4::AuthorizeStart {
                caller_capabilities: Some(_),
                ..
            } = &request
            {
                let held = self.hold.lock().expect("hold mutex").take();
                if let Some((arrived, release)) = held {
                    arrived.notify_one();
                    release.notified().await;
                }
            }
            if let ParsedStorageRequestV4::StorageCommand { opcode, .. } = &request
                && *opcode == Command::Query as u8
            {
                let held = self.query_hold.lock().expect("hold mutex").take();
                if let Some((arrived, release)) = held {
                    arrived.notify_one();
                    release.notified().await;
                }
            }
            self.inner.run_request_handler(context, request).await
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

    struct ProbeFactory {
        service_store: ServiceStore,
    }

    impl ProbeFactory {
        fn new(
            immutable: Arc<dyn ImmutableStore>,
            mutable: Arc<dyn MutableStore>,
            probe: Probe,
            mode: Mode,
        ) -> Self {
            let mut service_store = ServiceStore::default();
            service_store.add_service(
                TEST_PROTOCOL_V4,
                Box::new(move |context: Arc<AttributeMap>| {
                    // Auth off, strict policy: the slice-1 server as a strict cell runs it, minus
                    // the token, which these tests do not need.
                    let inner = StorageServiceV4::new(
                        Arc::new(None),
                        Arc::new(AllowAllRepositoryAuthorizer),
                        immutable.clone(),
                        immutable.clone(),
                        mutable.clone(),
                        false,
                        Arc::new(UserAgentFilter::default()),
                    )
                    .with_caller_capability_policy(CallerCapabilityPolicy::RequireOutcomeUnknownV1);
                    probe
                        .maps
                        .lock()
                        .expect("maps mutex")
                        .push(inner.session_map.clone());
                    let service = ProbeService {
                        inner,
                        mode,
                        connection: NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed),
                        log: probe.log.clone(),
                        hold: probe.hold.clone(),
                        query_hold: probe.query_hold.clone(),
                    };
                    Box::new(StreamHandler::new(
                        Arc::new(service),
                        context,
                        AdmissionLimits {
                            process_limit: 100,
                            inflight_limit: 800,
                            handler_timeout: None,
                            permit_timeout: None,
                        },
                    )) as Box<dyn StreamDataHandler>
                }),
            );
            Self { service_store }
        }
    }

    impl StreamHandlerFactory for ProbeFactory {
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
        .expect("immutable store");
        let mutable = lore_storage::local::mutable_store::create(
            None::<&str>,
            lore_storage::MutableStoreSettings::default(),
            immutable.clone(),
        )
        .await
        .expect("mutable store");
        (immutable, mutable)
    }

    /// The gRPC half of a `lore://` loopback server: environment resolution and gRPC storage.
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
            let repository_catalog = Arc::new(BaselineRepositoryCatalog::new(
                BaselineAccess::Reachable,
                immutable.clone(),
                mutable.clone(),
            ));
            let outcome = async {
                GrpcServerBuilder::new()
                    .with_environment(EnvironmentConfig::default())
                    .with_feature(FeatureSettings::default())
                    .with_immutable_store(immutable.clone(), immutable)
                    .with_mutable_store(mutable)
                    .with_lock_store(None)
                    .with_domain_context(None)
                    .with_notification(notification_sender, None)
                    .with_hook_dispatcher(hook_dispatcher)
                    .with_tls_config(None, None, None)?
                    .with_admin_endpoints(HashMap::new(), vec![])
                    .with_http2_config(
                        None,
                        None,
                        GrpcTimeouts {
                            request_handler: Duration::from_secs(30),
                            authorization: Duration::from_secs(30),
                        },
                        Default::default(),
                        Default::default(),
                        None,
                    )
                    .with_jwt_verifier(
                        None,
                        false,
                        Arc::new(AllowAllRepositoryAuthorizer),
                        repository_catalog,
                    )?
                    .serve_with_listener(listener, signal)
                    .await
            }
            .await;
            let _ = stopped_tx.send(match outcome {
                Ok(()) => "stopped before the test finished".to_string(),
                Err(error) => format!("failed: {error}"),
            });
        });
        for _ in 0..50 {
            if let Ok(reason) = stopped_rx.try_recv() {
                panic!("test gRPC server on {addr} {reason}");
            }
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return shutdown_tx;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("test gRPC server on {addr} never accepted a connection");
    }

    fn start_quic(
        udp: std::net::UdpSocket,
        mode: Mode,
        probe: Probe,
        stores: (Arc<dyn ImmutableStore>, Arc<dyn MutableStore>),
    ) -> QuinnServer {
        let (cert_file, pkey_file, _ca) = server_certs().expect("test certificate paths");
        QuinnServer::start(
            QuinnConfigBuilder::new()
                .socket(udp)
                .cert_file(cert_file)
                .pkey_file(pkey_file)
                .stream_handler_factory(Box::new(ProbeFactory::new(
                    stores.0, stores.1, probe, mode,
                )))
                .build()
                .expect("quinn config"),
        )
        .expect("quinn server start")
    }

    /// A loopback cell: the gRPC backend `lore://` resolves through, and the probed QUIC server.
    struct Cell {
        port: u16,
        probe: Probe,
        quic: Option<QuinnServer>,
        _grpc: tokio::sync::oneshot::Sender<()>,
    }

    async fn cell(mode: Mode) -> Cell {
        let (tcp, udp) = bind_matched_pair();
        let addr: SocketAddr = tcp.local_addr().expect("local addr");
        let grpc = start_grpc_backend(tcp, addr).await;
        let probe = Probe::default();
        let quic = Some(start_quic(udp, mode, probe.clone(), fresh_stores().await));
        Cell {
            port: addr.port(),
            probe,
            quic,
            _grpc: grpc,
        }
    }

    async fn rebind_udp(port: u16) -> std::net::UdpSocket {
        for _ in 0..50 {
            if let Ok(udp) = std::net::UdpSocket::bind(("127.0.0.1", port)) {
                return udp;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("could not rebind udp port {port}");
    }

    // ---------------------------------------------------------------------------------------
    // Client helpers.
    // ---------------------------------------------------------------------------------------

    async fn in_context<F: Future<Output = TestResult>>(body: F) -> TestResult {
        LORE_CONTEXT
            .scope(setup_execution("test".to_string()), body)
            .await
    }

    async fn connect(scheme: &str, port: u16, partition: RepositoryId) -> Arc<Connection> {
        lore_revision::protocol::connect(&format!("{scheme}://127.0.0.1:{port}"), "", partition)
            .await
            .expect("connect")
    }

    /// A fresh managed scope for `repository`. Reads write no journal rows, so the volatile
    /// store is enough.
    fn managed(repository: RepositoryId) -> CallerOperationContext {
        CallerOperationContext::new(
            uuid::Uuid::now_v7(),
            repository,
            Arc::new(VolatileAttemptStore::default()),
        )
    }

    fn some_address() -> Address {
        fragment::generate_random().1
    }

    /// One read through `session`, inside `scope` when given.
    async fn read(
        session: &StorageSession,
        scope: Option<&CallerOperationContext>,
        address: Address,
    ) -> Result<Bytes, ProtocolError> {
        match scope {
            Some(scope) => with_caller_operation(scope.clone(), session.query(&[address])).await,
            None => session.query(&[address]).await,
        }
    }

    async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The status carried by a `QuicDeclarationRefused` anywhere in the error's source chain.
    fn refusal_status(error: &ProtocolError) -> Option<u32> {
        let mut current: Option<&(dyn Error + 'static)> = Some(error);
        while let Some(source) = current {
            if let Some(refused) = source.downcast_ref::<QuicDeclarationRefused>() {
                return Some(refused.status);
            }
            current = source.source();
        }
        None
    }

    // ---------------------------------------------------------------------------------------
    // 2a. The exact push sequence on ONE StorageSession.
    // ---------------------------------------------------------------------------------------

    /// `push_query` runs outside the managed stage on the same `StorageSession` the stage's
    /// fragment traffic uses: Query outside, a call inside, Query outside again.
    #[tokio::test]
    async fn one_session_runs_undeclared_then_declared_then_undeclared_again() -> TestResult {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection.session(partition, "decl-sequence").await?;
            let address = some_address();

            read(&session, None, address).await?;
            let scope = managed(partition);
            read(&session, Some(&scope), address).await?;
            assert_eq!(scope.declared_session_count(), 1);
            read(&session, None, address).await?;

            let queries = cell.probe.query_sessions();
            assert_eq!(queries.len(), 3, "{:?}", cell.probe.wire());
            assert_eq!(
                queries[0], queries[2],
                "both outside calls share the undeclared session"
            );
            assert_ne!(
                queries[0], queries[1],
                "the inside call has a session of its own"
            );
            assert_eq!(cell.probe.declared_of(queries[0]), Some(false));
            assert_eq!(cell.probe.declared_of(queries[1]), Some(true));

            assert_eq!(
                cell.probe.count_action(ACTION_START),
                1,
                "one undeclared start, never repeated: {:?}",
                cell.probe.authorize_actions()
            );
            assert_eq!(
                cell.probe.count_action(ACTION_START_DECLARED),
                1,
                "one declared start: {:?}",
                cell.probe.authorize_actions()
            );
            Ok(())
        })
        .await
    }

    // ---------------------------------------------------------------------------------------
    // 2b. A declared binding is never used outside a scope, and dies with it.
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_declared_session_is_stopped_when_its_scope_ends_and_never_used_after() -> TestResult
    {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection.session(partition, "decl-never-outside").await?;
            let address = some_address();

            read(&session, None, address).await?;
            let baseline = cell.probe.live();
            assert_eq!(cell.probe.declared_live(), 0);

            let scope = managed(partition);
            read(&session, Some(&scope), address).await?;
            let declared_id = *cell
                .probe
                .query_sessions()
                .last()
                .expect("the inside read reached the server");
            assert_eq!(cell.probe.declared_of(declared_id), Some(true));
            assert_eq!(cell.probe.live(), baseline + 1);

            // Still in scope: a second read reuses the same declared session.
            read(&session, Some(&scope), address).await?;
            assert_eq!(cell.probe.query_sessions().last(), Some(&declared_id));
            assert_eq!(scope.declared_session_count(), 1);

            drop(scope);
            eventually("the declared session to be stopped", || {
                cell.probe.declared_of(declared_id).is_none()
            })
            .await;
            assert_eq!(cell.probe.declared_live(), 0);
            assert_eq!(
                cell.probe.live(),
                baseline,
                "the undeclared session is untouched"
            );
            assert_eq!(
                cell.probe.count_action(ACTION_STOP),
                1,
                "{:?}",
                cell.probe.wire()
            );

            // Outside any scope again: the undeclared session, not the stopped declared one.
            let before = cell.probe.count_action(ACTION_START_DECLARED);
            read(&session, None, address).await?;
            let used = *cell.probe.query_sessions().last().expect("a query");
            assert_ne!(used, declared_id);
            assert_eq!(cell.probe.declared_of(used), Some(false));
            assert_eq!(cell.probe.count_action(ACTION_START_DECLARED), before);
            Ok(())
        })
        .await
    }

    // ---------------------------------------------------------------------------------------
    // 2c. Task locals do not cross a spawn; the scope has to be captured and re-entered.
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_spawned_task_is_declared_only_when_it_re_enters_the_captured_scope() -> TestResult {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection.session(partition, "decl-spawn").await?;
            let address = some_address();
            let scope = managed(partition);

            // Captured before the spawn, entered inside it.
            let with_scope = {
                let session = session.clone();
                let scope = scope.clone();
                let captured =
                    with_caller_operation(scope, async { current_caller_operation() }).await;
                assert!(captured.is_some(), "the scope is visible inside itself");
                lore_base::lore_spawn!(async move {
                    with_optional_caller_operation(captured, async move {
                        session.query(&[address]).await
                    })
                    .await
                })
            };
            with_scope.await??;
            let declared = *cell.probe.query_sessions().last().expect("a query");
            assert_eq!(cell.probe.declared_of(declared), Some(true));

            // Spawned from inside the scope without re-entering it: the task reads no scope.
            let without_scope = {
                let session = session.clone();
                with_caller_operation(scope.clone(), async move {
                    lore_base::lore_spawn!(async move { session.query(&[address]).await }).await
                })
                .await
            };
            without_scope??;
            let plain = *cell.probe.query_sessions().last().expect("a query");
            assert_eq!(cell.probe.declared_of(plain), Some(false));
            assert_ne!(plain, declared);
            assert_eq!(scope.declared_session_count(), 1);
            Ok(())
        })
        .await
    }

    // ---------------------------------------------------------------------------------------
    // 2d. Partition mismatch.
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_write_on_another_partition_is_refused_locally_and_a_read_stays_undeclared()
    -> TestResult {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let managed_repository = random::<RepositoryId>();
            let other = random::<RepositoryId>();
            let connection = connect("lore", cell.port, managed_repository).await;
            let session = connection.session(other, "decl-mismatch").await?;
            let scope = managed(managed_repository);
            let address = some_address();

            // A read in the scope on the other partition runs undeclared.
            read(&session, Some(&scope), address).await?;
            let used = *cell.probe.query_sessions().last().expect("a query");
            assert_eq!(cell.probe.declared_of(used), Some(false));
            assert_eq!(scope.declared_session_count(), 0);
            assert_eq!(cell.probe.count_action(ACTION_START_DECLARED), 0);

            // Every write is refused before it reaches the wire: zero bytes of any kind.
            let wire_before = cell.probe.wire().len();
            let (fragment, write_address, payload) = fragment::generate_random();
            let key = random::<Hash>();
            let value = random::<Hash>();
            let mut errors: Vec<(&str, ProtocolError)> = Vec::new();
            let mut refused = |name: &'static str, result: Result<(), ProtocolError>| {
                errors.push((name, result.expect_err(name)));
            };
            let scoped = scope.clone();
            with_caller_operation(scoped, async {
                refused(
                    "put",
                    session
                        .put(write_address, fragment, Some(payload.clone()))
                        .await,
                );
                refused(
                    "put_resolved",
                    session
                        .put_resolved_outcome(&key, write_address, fragment, Some(payload.clone()))
                        .await
                        .map(|_| ()),
                );
                refused(
                    "copy",
                    session
                        .copy_outcome(other, write_address, random::<Context>())
                        .await
                        .map(|_| ()),
                );
                refused(
                    "mutable_store",
                    session
                        .mutable_store_outcome(key, value, KeyType::Untyped)
                        .await
                        .map(|_| ()),
                );
                refused(
                    "mutable_cas",
                    session
                        .mutable_compare_and_swap_outcome(key, value, value, KeyType::Untyped)
                        .await
                        .map(|_| ()),
                );
                refused(
                    "verify_heal",
                    session
                        .verify_outcome(&write_address, true)
                        .await
                        .map(|_| ()),
                );
            })
            .await;
            assert_eq!(errors.len(), 6);
            for (name, error) in &errors {
                assert!(
                    error
                        .to_string()
                        .contains("managed operation repository mismatch"),
                    "{name}: {error:?}"
                );
            }
            assert_eq!(
                cell.probe.wire().len(),
                wire_before,
                "a refused write must put nothing on the wire: {:?}",
                cell.probe.wire()
            );
            assert_eq!(cell.probe.count_action(ACTION_START_DECLARED), 0);
            Ok(())
        })
        .await
    }

    // ---------------------------------------------------------------------------------------
    // 2e. No session growth across many managed scopes on one process-wide Connection.
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn two_hundred_managed_scopes_leave_the_server_at_its_undeclared_baseline() -> TestResult
    {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection.session(partition, "decl-growth").await?;
            let address = some_address();

            read(&session, None, address).await?;
            let baseline = cell.probe.live();
            assert!(baseline >= 1);

            for round in 0..200 {
                let scope = managed(partition);
                read(&session, Some(&scope), address).await?;
                assert_eq!(scope.declared_session_count(), 1, "round {round}");
                assert!(
                    cell.probe.declared_live() >= 1,
                    "round {round}: the scope's session is live on the server"
                );
                drop(scope);
                let probe = cell.probe.clone();
                eventually(&format!("round {round} to return to baseline"), move || {
                    probe.live() == baseline
                })
                .await;
            }
            assert_eq!(cell.probe.declared_live(), 0);
            assert_eq!(cell.probe.count_action(ACTION_START_DECLARED), 200);
            assert_eq!(cell.probe.count_action(ACTION_START), 1);
            assert_eq!(cell.probe.count_action(ACTION_STOP), 200);
            Ok(())
        })
        .await
    }

    // ---------------------------------------------------------------------------------------
    // 2f. A rebind re-declares.
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_generation_move_re_declares_the_declared_session() -> TestResult {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection.session(partition, "decl-rebind").await?;
            let address = some_address();
            let scope = managed(partition);

            read(&session, Some(&scope), address).await?;
            assert_eq!(cell.probe.count_action(ACTION_START_DECLARED), 1);
            let first = *cell.probe.query_sessions().last().expect("a query");

            connection
                .advance_storage_generation_before_epoch_for_test()
                .await?;
            read(&session, Some(&scope), address).await?;

            assert_eq!(
                cell.probe.count_action(ACTION_START_DECLARED),
                2,
                "the replacement session declares again: {:?}",
                cell.probe.authorize_actions()
            );
            let second = *cell.probe.query_sessions().last().expect("a query");
            assert_ne!(first, second);
            assert_eq!(cell.probe.declared_of(second), Some(true));
            assert_eq!(
                scope.declared_session_count(),
                1,
                "a rebind replaces the id, not the binding"
            );
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn a_restarted_server_gets_a_declared_session_for_the_next_managed_read() -> TestResult {
        in_context(async {
            let mut cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection.session(partition, "decl-restart").await?;
            let address = some_address();
            let scope = managed(partition);

            read(&session, Some(&scope), address).await?;
            assert_eq!(cell.probe.count_action(ACTION_START_DECLARED), 1);

            // Replace the QUIC server on the same port with a fresh one (fresh SessionMaps).
            let old = cell.quic.take().expect("the cell's QUIC server");
            old.close().await;
            drop(old);
            let udp = rebind_udp(cell.port).await;
            let replacement = Probe::default();
            cell.quic = Some(start_quic(
                udp,
                Mode::Real,
                replacement.clone(),
                fresh_stores().await,
            ));

            read(&session, Some(&scope), address).await?;
            assert_eq!(
                replacement.count_action(ACTION_START_DECLARED),
                1,
                "the replacement connection declares again: {:?}",
                replacement.wire()
            );
            let used = *replacement.query_sessions().last().expect("a query");
            assert_eq!(replacement.declared_of(used), Some(true));
            // Outside the scope the same session is undeclared on the replacement server.
            read(&session, None, address).await?;
            let plain = *replacement.query_sessions().last().expect("a query");
            assert_eq!(replacement.declared_of(plain), Some(false));
            Ok(())
        })
        .await
    }

    // ---------------------------------------------------------------------------------------
    // 2g. A server that refuses the declaration: typed, final, no action-0 fallback.
    // ---------------------------------------------------------------------------------------

    async fn refused_declaration(mode: Mode, expected_status: u32) -> TestResult {
        let cell = cell(mode).await;
        let partition = random::<RepositoryId>();
        let connection = connect("lore", cell.port, partition).await;
        let session = connection.session(partition, "decl-refused").await?;
        let address = some_address();

        // The undeclared session works; only the declaration is refused.
        read(&session, None, address).await?;
        let starts_before = cell.probe.count_action(ACTION_START);
        let wire_before = cell.probe.wire().len();

        let scope = managed(partition);
        for attempt in 1..=2 {
            let error = read(&session, Some(&scope), address)
                .await
                .expect_err("the declaration is refused");
            assert!(is_quic_declaration_refused(&error), "{error:?}");
            assert_eq!(refusal_status(&error), Some(expected_status), "{error:?}");
            assert_eq!(
                cell.probe.count_action(ACTION_START_DECLARED),
                attempt,
                "exactly one declared start per call, no retry: {:?}",
                cell.probe.authorize_actions()
            );
        }
        assert_eq!(
            cell.probe.count_action(ACTION_START),
            starts_before,
            "no action-0 fallback: {:?}",
            cell.probe.authorize_actions()
        );
        let after: Vec<Wire> = cell.probe.wire()[wire_before..].to_vec();
        assert!(
            after.iter().all(|w| w.opcode == Command::Authorize as u8),
            "a refused declaration sends no storage command: {after:?}"
        );
        assert_eq!(cell.probe.connections_seen(), 1, "no reconnect loop");
        assert_eq!(cell.probe.declared_live(), 0);

        // The session is not poisoned: an unmanaged call still works.
        read(&session, None, address).await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_stock_server_answering_status_one_is_a_typed_final_refusal() -> TestResult {
        in_context(refused_declaration(Mode::Stock, 1)).await
    }

    #[tokio::test]
    async fn a_server_answering_status_200_is_a_typed_final_refusal() -> TestResult {
        in_context(refused_declaration(Mode::RefuseDeclared200, 200)).await
    }

    /// The marker belongs to the declared start. An undeclared start that fails the same way is
    /// an ordinary error, so a caller cannot mistake it for a declaration refusal.
    #[tokio::test]
    async fn a_failed_undeclared_start_is_not_a_declaration_refusal() -> TestResult {
        in_context(async {
            let cell = cell(Mode::RejectUndeclared).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let error = connection
                .session(partition, "decl-undeclared-fails")
                .await
                .err()
                .expect("the server fails every action-0 start");
            assert!(!is_quic_declaration_refused(&error), "{error:?}");
            assert!(
                error.to_string().contains("Failed sending command"),
                "the action-0 error text is the one it always was: {error}"
            );
            assert_eq!(cell.probe.count_action(ACTION_START_DECLARED), 0);
            Ok(())
        })
        .await
    }

    // ---------------------------------------------------------------------------------------
    // 2h. Disjoint parents; an unmanaged call is never declared.
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn two_parents_get_disjoint_declared_sessions_and_unmanaged_never_does() -> TestResult {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection.session(partition, "decl-parents").await?;
            let address = some_address();
            let parent_a = managed(partition);
            let parent_b = managed(partition);

            read(&session, Some(&parent_a), address).await?;
            read(&session, Some(&parent_b), address).await?;
            read(&session, None, address).await?;
            read(&session, Some(&parent_a), address).await?;

            let q = cell.probe.query_sessions();
            assert_eq!(q.len(), 4);
            let (a, b, plain, a_again) = (q[0], q[1], q[2], q[3]);
            assert_ne!(a, b, "two parents never share a declared session");
            assert_eq!(a, a_again, "a parent keeps its own binding across calls");
            assert_eq!(cell.probe.declared_of(a), Some(true));
            assert_eq!(cell.probe.declared_of(b), Some(true));
            assert_eq!(cell.probe.declared_of(plain), Some(false));
            assert!(![a, b].contains(&plain));
            assert_eq!(parent_a.declared_session_count(), 1);
            assert_eq!(parent_b.declared_session_count(), 1);

            // Ending one parent stops only its session.
            drop(parent_a);
            eventually("parent A's session to stop", || {
                cell.probe.declared_of(a).is_none()
            })
            .await;
            assert_eq!(cell.probe.declared_of(b), Some(true));
            Ok(())
        })
        .await
    }

    /// Concurrent first calls in one scope open one declared session, not one each.
    #[tokio::test]
    async fn concurrent_first_calls_in_one_scope_share_one_declared_session() -> TestResult {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection.session(partition, "decl-concurrent").await?;
            let address = some_address();
            let scope = managed(partition);

            let (a, b, c, d) = tokio::join!(
                read(&session, Some(&scope), address),
                read(&session, Some(&scope), address),
                read(&session, Some(&scope), address),
                read(&session, Some(&scope), address),
            );
            a?;
            b?;
            c?;
            d?;
            assert_eq!(cell.probe.count_action(ACTION_START_DECLARED), 1);
            assert_eq!(scope.declared_session_count(), 1);
            let mut used = cell.probe.query_sessions();
            used.dedup();
            assert_eq!(used.len(), 1, "{used:?}");
            Ok(())
        })
        .await
    }

    // ---------------------------------------------------------------------------------------
    // 2i. No double stop.
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn an_undeclared_session_sends_exactly_one_stop_when_it_drops() -> TestResult {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection.session(partition, "decl-one-stop").await?;
            read(&session, None, some_address()).await?;
            let id = *cell.probe.query_sessions().last().expect("a query");
            assert_eq!(cell.probe.declared_of(id), Some(false));

            drop(session);
            connection.release_session(partition, "decl-one-stop");
            eventually("the undeclared session to stop", || {
                cell.probe.declared_of(id).is_none()
            })
            .await;
            // A second stop would land within a task or two of the first.
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                cell.probe.count_action(ACTION_STOP),
                1,
                "{:?}",
                cell.probe.wire()
            );
            Ok(())
        })
        .await
    }

    /// One undeclared and one declared session in the same process: one stop each.
    #[tokio::test]
    async fn a_declared_and_an_undeclared_session_each_send_one_stop() -> TestResult {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection.session(partition, "decl-two-stops").await?;
            let address = some_address();
            let scope = managed(partition);
            read(&session, None, address).await?;
            read(&session, Some(&scope), address).await?;

            drop(scope);
            eventually("the declared session to stop", || {
                cell.probe.declared_live() == 0
            })
            .await;
            drop(session);
            connection.release_session(partition, "decl-two-stops");
            eventually("both sessions to stop", || cell.probe.live() == 0).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                cell.probe.count_action(ACTION_STOP),
                2,
                "{:?}",
                cell.probe.wire()
            );
            Ok(())
        })
        .await
    }

    // ---------------------------------------------------------------------------------------
    // gRPC managed path: unchanged, no second session.
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_managed_grpc_read_opens_no_declared_session() -> TestResult {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("grpc", cell.port, partition).await;
            let session = connection.session(partition, "decl-grpc").await?;
            let scope = managed(partition);

            read(&session, Some(&scope), some_address()).await?;
            assert_eq!(
                scope.declared_session_count(),
                0,
                "gRPC declares per request and needs no second session"
            );
            assert!(
                cell.probe.wire().is_empty(),
                "gRPC storage never touches QUIC"
            );
            Ok(())
        })
        .await
    }

    // ---------------------------------------------------------------------------------------
    // invalidate inside a scope releases that scope's declared binding.
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn invalidate_in_a_scope_releases_its_declared_session_and_the_next_read_redeclares()
    -> TestResult {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection.session(partition, "decl-invalidate").await?;
            let address = some_address();
            let scope = managed(partition);

            read(&session, Some(&scope), address).await?;
            let first = *cell.probe.query_sessions().last().expect("a query");
            assert_eq!(scope.declared_session_count(), 1);
            assert_eq!(cell.probe.declared_live(), 1);

            with_caller_operation(scope.clone(), session.invalidate()).await;
            assert_eq!(
                scope.declared_session_count(),
                0,
                "invalidate removes the scope's declared binding"
            );
            eventually("the invalidated declared session to be stopped", || {
                cell.probe.declared_of(first).is_none()
            })
            .await;
            assert_eq!(cell.probe.declared_live(), 0);

            read(&session, Some(&scope), address).await?;
            let second = *cell.probe.query_sessions().last().expect("a query");
            assert_ne!(
                first, second,
                "the next read opens a fresh declared session"
            );
            assert_eq!(cell.probe.declared_of(second), Some(true));
            assert_eq!(scope.declared_session_count(), 1);
            assert_eq!(cell.probe.count_action(ACTION_START_DECLARED), 2);

            drop(scope);
            eventually("the scope to release everything", || {
                cell.probe.declared_live() == 0
            })
            .await;
            Ok(())
        })
        .await
    }

    /// `invalidate` lands while the first declared start is still on the wire. The binding's entry
    /// is dropped before it has an id; the start then binds one nobody owns unless the drop waits
    /// for the start to finish and stops what it bound.
    #[tokio::test]
    async fn invalidate_during_an_in_flight_declared_start_orphans_no_session() -> TestResult {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection
                .session(partition, "decl-invalidate-race")
                .await?;
            let address = some_address();
            let scope = managed(partition);

            let arrived = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            *cell.probe.hold.lock().expect("hold mutex") = Some((arrived.clone(), release.clone()));

            let reader = {
                let session = session.clone();
                let scope = scope.clone();
                lore_base::lore_spawn!(async move {
                    with_caller_operation(scope, session.query(&[address])).await
                })
            };
            tokio::time::timeout(WAIT, arrived.notified())
                .await
                .expect("the declared start reached the server");
            assert_eq!(
                cell.probe.declared_live(),
                0,
                "the start is held, not yet applied"
            );

            with_caller_operation(scope.clone(), session.invalidate()).await;
            assert_eq!(scope.declared_session_count(), 0);
            release.notify_one();

            // The read that owned the in-flight start finishes on whatever it bound.
            reader.await??;
            drop(scope);
            eventually("no declared session to remain on the server", || {
                cell.probe.declared_live() == 0
            })
            .await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                cell.probe.declared_live(),
                0,
                "an orphaned declared session: {:?}",
                cell.probe.wire()
            );
            Ok(())
        })
        .await
    }

    /// The declared session outlives `invalidate` while a Query is in flight on it: the stop goes
    /// out when the last holder lets go, after the Query was answered, and only once.
    #[tokio::test]
    async fn invalidate_with_a_query_in_flight_stops_the_declared_session_after_the_answer()
    -> TestResult {
        in_context(async {
            let cell = cell(Mode::Real).await;
            let partition = random::<RepositoryId>();
            let connection = connect("lore", cell.port, partition).await;
            let session = connection.session(partition, "decl-inflight").await?;
            let address = some_address();
            let scope = managed(partition);

            read(&session, Some(&scope), address).await?;
            let declared = *cell.probe.query_sessions().last().expect("a query");
            assert_eq!(cell.probe.declared_of(declared), Some(true));

            let arrived = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            *cell.probe.query_hold.lock().expect("hold mutex") =
                Some((arrived.clone(), release.clone()));
            let reader = {
                let session = session.clone();
                let scope = scope.clone();
                lore_base::lore_spawn!(async move {
                    with_caller_operation(scope, session.query(&[address])).await
                })
            };
            tokio::time::timeout(WAIT, arrived.notified())
                .await
                .expect("the second Query reached the server");
            assert_eq!(cell.probe.query_sessions().last(), Some(&declared));

            with_caller_operation(scope.clone(), session.invalidate()).await;
            assert_eq!(scope.declared_session_count(), 0);
            // The in-flight Query still holds the binding: nothing may stop the session yet.
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                cell.probe.count_action(ACTION_STOP),
                0,
                "{:?}",
                cell.probe.wire()
            );
            assert_eq!(cell.probe.declared_of(declared), Some(true));

            release.notify_one();
            reader.await??;
            eventually("the declared session to be stopped", || {
                cell.probe.declared_of(declared).is_none()
            })
            .await;
            tokio::time::sleep(Duration::from_millis(300)).await;

            let wire = cell.probe.wire();
            let held_query = wire
                .iter()
                .rposition(|w| w.opcode == Command::Query as u8)
                .expect("the held Query");
            let stops: Vec<usize> = wire
                .iter()
                .enumerate()
                .filter(|(_, w)| {
                    w.opcode == Command::Authorize as u8 && w.action == Some(ACTION_STOP)
                })
                .map(|(i, _)| i)
                .collect();
            assert_eq!(stops.len(), 1, "exactly one stop: {wire:?}");
            assert!(
                stops[0] > held_query,
                "the stop follows the Query: {wire:?}"
            );
            Ok(())
        })
        .await
    }
}
