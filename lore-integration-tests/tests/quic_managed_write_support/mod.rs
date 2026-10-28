// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// Shared fixture for the WP-124 slice 4 managed-write proofs: a strict loopback cell (the real
// `StorageServiceV4` under `RequireOutcomeUnknownV1`, wrapped to record the wire and to hold one
// applied `Put` answer) with an optional certificate on each leg. Included by
// `quic_managed_write_proof_test.rs` (the `integration` binary) and `quic_lores_tls_test.rs` (its
// own binary), so each binary uses only part of it.
#![cfg(all(test, feature = "integration_tests"))]
#![allow(dead_code)]
use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_revision::environment::EnvironmentConfig;
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
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::LockOwnership;
use lore_transport::attempt_store::VolatileAttemptStore;
use lore_transport::caller_operation::ManagedAttemptIntent;
use lore_transport::error::ProtocolError;
use lore_transport::outcome::AttemptId;
use lore_transport::quic::QuicOpCode;
use lore_transport::quic::command_header::CommandHeader;
use lore_transport::quic::storage_service::Command;
use tracing::Span;

use crate::common::net_common::bind_matched_pair;
use crate::setup_execution;

pub(crate) type TestResult = Result<(), Box<dyn Error>>;

pub(crate) const ACTION_START: u8 = 0;
pub(crate) const ACTION_START_DECLARED: u8 = 2;
pub(crate) const WAIT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------------------
// Server: the real strict `StorageServiceV4`, wrapped to record the wire and hold one answer.
// ---------------------------------------------------------------------------------------

/// One inbound command, recorded off its header before it is parsed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Wire {
    pub(crate) opcode: u8,
    pub(crate) session_id: u32,
    /// The first payload byte of an `Authorize`: 0 start, 1 stop, 2 declared start.
    pub(crate) action: Option<u8>,
}

/// Withholds the answer to the first `Put` the server applies: once the real `Put` handler has
/// succeeded (the fragment is stored) it tells the test, then sleeps `grace` before returning
/// the answer, so the test can close the server out from under the answer.
#[derive(Clone)]
pub(crate) struct HoldFirstPutAnswer {
    pub(crate) applied: Arc<tokio::sync::Notify>,
    pub(crate) grace: Duration,
    pub(crate) armed: Arc<AtomicBool>,
}

/// What a test reads back from the server.
#[derive(Clone, Default)]
pub(crate) struct Probe {
    pub(crate) log: Arc<StdMutex<Vec<Wire>>>,
    /// One `SessionMap` per accepted connection.
    pub(crate) maps: Arc<StdMutex<Vec<Arc<SessionMap>>>>,
}

impl Probe {
    pub(crate) fn wire(&self) -> Vec<Wire> {
        self.log.lock().expect("log mutex").clone()
    }

    pub(crate) fn count_opcode(&self, opcode: Command) -> usize {
        self.wire()
            .iter()
            .filter(|w| w.opcode == opcode as u8)
            .count()
    }

    pub(crate) fn count_action(&self, action: u8) -> usize {
        self.wire()
            .iter()
            .filter(|w| w.opcode == Command::Authorize as u8 && w.action == Some(action))
            .count()
    }

    /// `Some(declared)` for a live session id, `None` for one the server does not hold.
    pub(crate) fn declared_of(&self, session_id: u32) -> Option<bool> {
        self.maps
            .lock()
            .expect("maps mutex")
            .iter()
            .find_map(|map| map.get(session_id).map(|entry| entry.declared))
    }
}

pub(crate) struct ProbeService {
    inner: StorageServiceV4,
    log: Arc<StdMutex<Vec<Wire>>>,
    hold: Option<HoldFirstPutAnswer>,
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
        });
        self.inner.parse_request_bytes(header, bytes)
    }

    async fn run_request_handler(
        &self,
        context: Arc<AttributeMap>,
        request: Self::ParsedRequestType,
    ) -> Result<Vec<Bytes>, Self::RequestHandlerError> {
        let is_put = matches!(
            &request,
            ParsedStorageRequestV4::StorageCommand { opcode, .. }
                if *opcode == Command::Put as u8
        );
        let result = self.inner.run_request_handler(context, request).await;
        if is_put
            && result.is_ok()
            && let Some(hold) = &self.hold
            && hold.armed.swap(false, Ordering::SeqCst)
        {
            // The real write is done. Let the test close the server, then keep the answer
            // back long enough that the closed connection wins deterministically.
            hold.applied.notify_one();
            tokio::time::sleep(hold.grace).await;
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

pub(crate) struct ProbeFactory {
    service_store: ServiceStore,
}

impl ProbeFactory {
    fn new(
        immutable: Arc<dyn ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
        probe: Probe,
        hold: Option<HoldFirstPutAnswer>,
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
                    log: probe.log.clone(),
                    hold: hold.clone(),
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

pub(crate) async fn fresh_stores() -> (Arc<dyn ImmutableStore>, Arc<dyn MutableStore>) {
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

/// Certificate and key files a server presents.
#[derive(Clone)]
pub(crate) struct TlsFiles {
    pub(crate) cert: PathBuf,
    pub(crate) key: PathBuf,
}

/// The gRPC half of a `lore://` loopback server: environment resolution and gRPC storage.
/// `tls` makes it serve `https`.
pub(crate) async fn start_grpc_backend(
    listener: std::net::TcpListener,
    addr: SocketAddr,
    tls: Option<TlsFiles>,
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
    // The server task carries the test's LORE_CONTEXT, as production tasks do.
    lore_base::lore_spawn!(async move {
        let repository_catalog = Arc::new(BaselineRepositoryCatalog::new(
            BaselineAccess::Reachable,
            immutable.clone(),
            mutable.clone(),
        ));
        let (cert, key) = match tls {
            Some(tls) => (Some(tls.cert), Some(tls.key)),
            None => (None, None),
        };
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
                .with_tls_config(cert, key, None)?
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
    for _ in 0..100 {
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

pub(crate) fn start_quic(
    udp: std::net::UdpSocket,
    stores: (Arc<dyn ImmutableStore>, Arc<dyn MutableStore>),
    probe: Probe,
    hold: Option<HoldFirstPutAnswer>,
    tls: Option<TlsFiles>,
) -> QuinnServer {
    let (cert_file, pkey_file) = if let Some(tls) = tls {
        (tls.cert, tls.key)
    } else {
        let (cert_file, pkey_file, _ca) = server_certs().expect("test certificate paths");
        (cert_file, pkey_file)
    };
    QuinnServer::start(
        QuinnConfigBuilder::new()
            .socket(udp)
            .cert_file(cert_file)
            .pkey_file(pkey_file)
            .stream_handler_factory(Box::new(ProbeFactory::new(stores.0, stores.1, probe, hold)))
            .build()
            .expect("quinn config"),
    )
    .expect("quinn server start")
}

/// A loopback cell: the gRPC backend a `lore(s)://` URL resolves through, and the probed
/// strict QUIC server.
pub(crate) struct Cell {
    pub(crate) port: u16,
    pub(crate) probe: Probe,
    pub(crate) stores: (Arc<dyn ImmutableStore>, Arc<dyn MutableStore>),
    pub(crate) quic: Option<QuinnServer>,
    pub(crate) _grpc: tokio::sync::oneshot::Sender<()>,
}

/// `hold`: withhold the first applied `Put` answer. `grpc_tls` / `quic_tls`: serve TLS on that
/// leg with these files, plain otherwise.
pub(crate) async fn cell(
    hold: Option<HoldFirstPutAnswer>,
    grpc_tls: Option<TlsFiles>,
    quic_tls: Option<TlsFiles>,
) -> Cell {
    let (tcp, udp) = bind_matched_pair();
    let addr: SocketAddr = tcp.local_addr().expect("local addr");
    let grpc = start_grpc_backend(tcp, addr, grpc_tls).await;
    let probe = Probe::default();
    let stores = fresh_stores().await;
    let quic = Some(start_quic(
        udp,
        stores.clone(),
        probe.clone(),
        hold,
        quic_tls,
    ));
    Cell {
        port: addr.port(),
        probe,
        stores,
        quic,
        _grpc: grpc,
    }
}

pub(crate) async fn rebind_udp(port: u16) -> std::net::UdpSocket {
    for _ in 0..100 {
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

pub(crate) async fn in_context<F: Future<Output = TestResult>>(body: F) -> TestResult {
    LORE_CONTEXT
        .scope(setup_execution("test".to_string()), body)
        .await
}

pub(crate) async fn connect(
    scheme: &str,
    port: u16,
    partition: RepositoryId,
) -> Result<Arc<Connection>, ProtocolError> {
    lore_revision::protocol::connect(&format!("{scheme}://127.0.0.1:{port}"), "", partition).await
}

/// An in-memory journal that accepts managed intents and counts every record, so a test can
/// prove an RPC wrote no journal child. `VolatileAttemptStore` alone refuses managed intents.
#[derive(Default)]
pub(crate) struct CountingJournal {
    inner: VolatileAttemptStore,
    pub(crate) records: AtomicUsize,
}

#[async_trait]
impl AttemptStore for CountingJournal {
    async fn record_managed(
        &self,
        record: &AttemptRecord,
        _intent: &ManagedAttemptIntent,
    ) -> Result<(), ProtocolError> {
        self.records.fetch_add(1, Ordering::SeqCst);
        self.inner.record(record).await
    }
    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
        self.records.fetch_add(1, Ordering::SeqCst);
        self.inner.record(record).await
    }
    async fn lookup(&self, id: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
        self.inner.lookup(id).await
    }
    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
        self.inner.unresolved().await
    }
    async fn record_ownership(&self, ownership: &LockOwnership) -> Result<(), ProtocolError> {
        self.inner.record_ownership(ownership).await
    }
    async fn ownership_for(
        &self,
        branch: &Context,
        resource_hash: &Hash,
    ) -> Result<Option<LockOwnership>, ProtocolError> {
        self.inner.ownership_for(branch, resource_hash).await
    }
    async fn clear_ownership(
        &self,
        branch: &Context,
        resource_hash: &Hash,
    ) -> Result<(), ProtocolError> {
        self.inner.clear_ownership(branch, resource_hash).await
    }
    async fn resolve(
        &self,
        id: &AttemptId,
        resolution: AttemptResolution,
    ) -> Result<(), ProtocolError> {
        self.inner.resolve(id, resolution).await
    }
}

pub(crate) fn managed(repository: RepositoryId) -> (CallerOperationContext, Arc<CountingJournal>) {
    let journal = Arc::new(CountingJournal::default());
    (
        CallerOperationContext::new(uuid::Uuid::now_v7(), repository, journal.clone()),
        journal,
    )
}

pub(crate) async fn stored(
    stores: &(Arc<dyn ImmutableStore>, Arc<dyn MutableStore>),
    partition: RepositoryId,
    address: Address,
) -> bool {
    stores.0.clone().get(partition, address).await.is_ok()
}

pub(crate) fn hold_first_put_answer() -> HoldFirstPutAnswer {
    HoldFirstPutAnswer {
        applied: Arc::new(tokio::sync::Notify::new()),
        // Comfortably longer than an in-process `QuinnServer::close()` takes.
        grace: Duration::from_millis(400),
        armed: Arc::new(AtomicBool::new(true)),
    }
}

/// Lose the held `Put`'s answer, then bring a replacement server up at once.
///
/// Waits until the server has applied the held `Put`, runs `before_close` (a test's way to act
/// while the answer is still owed), closes the server, and starts a fresh one on the same port over
/// the same stores. The replacement is up BEFORE the writer's call returns, so a resend of the lost
/// `Put` would reach a live server and show on the returned [`Probe`]; reading the closed server's
/// wire could not show it.
pub(crate) async fn lose_answer_and_restart(
    hold: &HoldFirstPutAnswer,
    server: QuinnServer,
    port: u16,
    stores: &(Arc<dyn ImmutableStore>, Arc<dyn MutableStore>),
    before_close: impl Future<Output = ()>,
) -> (QuinnServer, Probe) {
    tokio::time::timeout(WAIT, hold.applied.notified())
        .await
        .expect("the server never applied a Put to hold; the loss is not the fault under test");
    before_close.await;
    server.close().await;
    drop(server);
    let udp = rebind_udp(port).await;
    let replacement = Probe::default();
    let quic = start_quic(udp, stores.clone(), replacement.clone(), None, None);
    (quic, replacement)
}

/// How long to wait, after a lost answer returned, for a resend to show on the replacement.
pub(crate) const RESEND_SETTLE: Duration = Duration::from_millis(750);
