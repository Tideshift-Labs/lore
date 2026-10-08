// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Proves the `lore-attempt-id` header actually reaches a real server over the wire (WP-120's
//! `AttemptStore` seam), rather than trusting that a `tonic` interceptor runs inside a
//! `tokio::task_local!` scope just because it compiles. Every claim here is checked against a
//! real in-process `tonic` server, following `storage_client.rs`'s test convention -- no mock.
//!
//! `LockService::lock`/`LockService::query` are the vehicle: `Lock` is `GrpcRpc::LockLock`
//! (`MutableNoReplay`, mints an attempt) and `Query` is `GrpcRpc::LockQuery` (`ReadRetryable`,
//! mints none). `DomainOperationReceiptGet` cannot be used for this -- it is `ReadRetryable`
//! too, so it never enters [`with_dispatch_attempt`].
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::LockData;
use lore_base::types::LockResource;
use lore_base::types::RepositoryId;
use lore_proto::lock::AdminLockRequest;
use lore_proto::lock::AdminLockResponse;
use lore_proto::lock::ForceUnlockRequest;
use lore_proto::lock::ForceUnlockResponse;
use lore_proto::lock::LockRequest;
use lore_proto::lock::LockResponse;
use lore_proto::lock::QueryRequest;
use lore_proto::lock::QueryResponse;
use lore_proto::lock::StatusRequest;
use lore_proto::lock::StatusResponse;
use lore_proto::lock::UnlockRequest;
use lore_proto::lock::UnlockResponse;
use lore_proto::lock::lock_service_server::LockService as LockServiceServerTrait;
use lore_proto::lock::lock_service_server::LockServiceServer;
use lore_transport::attempt_store::AcquiredLock;
use lore_transport::attempt_store::FencedLockResource;
use lore_transport::error::ProtocolError;
use lore_transport::grpc::GRPCAuth;
use lore_transport::grpc::GRPCAuthRef;
use lore_transport::grpc::GRPCConnection;
use lore_transport::grpc::RequestLoggerLayer;
use lore_transport::grpc::lock_client;
use lore_transport::grpc::with_reconnect_classified;
use lore_transport::outcome::AttemptId;
use lore_transport::outcome::GrpcRpc;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tower::ServiceBuilder;
use uuid::Uuid;

/// A connection object `with_reconnect_classified` is content to read `.reconnect` from but
/// never actually dials -- every test here either never fails (so `rebuild` is never called)
/// or the `MutableNoReplay` branch, which does not touch `connection` at all. Matches
/// `reconnect_tests::test_connection`'s shape, duplicated rather than shared across modules.
fn dummy_connection() -> GRPCConnection {
    let endpoint = tonic::transport::Endpoint::from_shared("http://127.0.0.1:1".to_string())
        .expect("test endpoint");
    let channel = ServiceBuilder::new()
        .layer(RequestLoggerLayer {})
        .service(endpoint.connect_lazy());
    GRPCConnection::for_test("http://127.0.0.1:1".parse().expect("test url"), channel)
}

fn captured_attempt_id_header(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
    metadata
        .get(lore_transport::outcome::ATTEMPT_ID_METADATA_KEY)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// Implements only `lock` and `query`; the rest of `LockService` is unreachable from this
/// test and returns `Unimplemented` if a regression ever calls one. Optionally fails every
/// `lock` call after capturing its header, to drive the client's `OutcomeUnknown` path.
struct RecordingLockServer {
    seen_attempt_id_headers: Arc<Mutex<Vec<Option<String>>>>,
    fail_lock: bool,
}

#[tonic::async_trait]
impl LockServiceServerTrait for RecordingLockServer {
    async fn lock(&self, request: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
        self.seen_attempt_id_headers
            .lock()
            .unwrap()
            .push(captured_attempt_id_header(request.metadata()));
        if self.fail_lock {
            return Err(Status::unavailable("connection reset"));
        }
        Ok(Response::new(LockResponse { locks: vec![] }))
    }

    async fn query(
        &self,
        request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        self.seen_attempt_id_headers
            .lock()
            .unwrap()
            .push(captured_attempt_id_header(request.metadata()));
        Ok(Response::new(QueryResponse { result: vec![] }))
    }

    async fn status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn unlock(
        &self,
        _request: Request<UnlockRequest>,
    ) -> Result<Response<UnlockResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn admin_lock(
        &self,
        _request: Request<AdminLockRequest>,
    ) -> Result<Response<AdminLockResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn force_unlock(
        &self,
        _request: Request<ForceUnlockRequest>,
    ) -> Result<Response<ForceUnlockResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }
}

/// Stand up a real `LockService` gRPC server on an ephemeral port and a raw
/// `lock_client::LockService` bound to it through the same `AuthzInterceptor` production
/// traffic goes through.
async fn start_recording_lock_server(
    fail_lock: bool,
) -> (lock_client::LockService, Arc<Mutex<Vec<Option<String>>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server = RecordingLockServer {
        seen_attempt_id_headers: seen.clone(),
        fail_lock,
    };

    #[allow(clippy::disallowed_methods)] // Test-local server task.
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(LockServiceServer::new(server))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .expect("connect to test server");
    let channel = ServiceBuilder::new()
        .layer(RequestLoggerLayer {})
        .service(channel);

    let auth: GRPCAuthRef = Arc::new(parking_lot::RwLock::new(GRPCAuth {
        authorization_token: "test-lore-jwt".to_string(),
        ..Default::default()
    }));

    let client = lock_client::LockService::new(channel, RepositoryId::from([0x01u8; 16]), auth);
    (client, seen)
}

fn one_resource() -> Vec<FencedLockResource> {
    vec![FencedLockResource::tokenless(LockResource {
        branch: Context::from([0x02u8; 16]),
        hash: Hash::from([0x55u8; 32]),
        description: "test-resource".to_string(),
    })]
}

/// Priority 1, the one that matters: a `MutableNoReplay` dispatch through
/// `with_reconnect_classified` arrives at a real server carrying `lore-attempt-id`, and the
/// value parses as a UUID.
#[tokio::test]
async fn a_mutating_dispatch_carries_the_attempt_id_header() {
    let (client, seen) = start_recording_lock_server(false).await;
    let connection = dummy_connection();
    let resources = one_resource();

    let result: Result<Vec<AcquiredLock>, ProtocolError> = with_reconnect_classified(
        &connection,
        GrpcRpc::LockLock,
        || async { client.lock(&resources, None).await },
        |_reconnect_id| async { Ok(()) },
    )
    .await;
    assert!(
        result.is_ok(),
        "expected the lock call to succeed: {result:?}"
    );

    let headers = seen.lock().unwrap().clone();
    assert_eq!(
        headers.len(),
        1,
        "expected exactly one request: {headers:?}"
    );
    let header = headers[0]
        .as_ref()
        .expect("a mutating dispatch must carry the lore-attempt-id header");
    Uuid::parse_str(header).expect("the header value must parse as a UUID");
}

/// Priority 2: a read carries no such header. Stamping one would put an identity on the wire
/// for a call the server files no receipt under.
#[tokio::test]
async fn a_read_dispatch_carries_no_attempt_id_header() {
    let (client, seen) = start_recording_lock_server(false).await;
    let connection = dummy_connection();

    let result: Result<Vec<LockData>, ProtocolError> = with_reconnect_classified(
        &connection,
        GrpcRpc::LockQuery,
        || async { client.query(None, None, None).await },
        |_reconnect_id| async { Ok(()) },
    )
    .await;
    assert!(
        result.is_ok(),
        "expected the query call to succeed: {result:?}"
    );

    assert_eq!(
        seen.lock().unwrap().clone(),
        vec![None],
        "a read must never carry an attempt id header"
    );
}

/// Priority 3: the id the server captured must be the exact same one the client names in
/// its `OutcomeUnknown` error when the dispatch then fails. If these could diverge, a
/// reconciler would look the receipt up under an identity the server never persisted.
#[tokio::test]
async fn the_servers_captured_attempt_id_matches_the_clients_outcome_unknown_error() {
    let (client, seen) = start_recording_lock_server(true).await;
    let connection = dummy_connection();
    let resources = one_resource();

    let result: Result<Vec<AcquiredLock>, ProtocolError> = with_reconnect_classified(
        &connection,
        GrpcRpc::LockLock,
        || async { client.lock(&resources, None).await },
        |_reconnect_id| async { Ok(()) },
    )
    .await;

    let error = result.expect_err("an Unavailable status must surface as an error, not a receipt");
    assert!(
        error.is_outcome_unknown(),
        "a MutableNoReplay dispatch losing its channel must become OutcomeUnknown: {error:?}"
    );
    let unknown = error
        .as_outcome_unknown()
        .expect("just asserted is_outcome_unknown");

    let headers = seen.lock().unwrap().clone();
    assert_eq!(headers.len(), 1);
    let server_seen = headers[0]
        .clone()
        .expect("the server must have captured a header before failing the call");

    assert_eq!(
        unknown.attempt_id, server_seen,
        "the id the server persisted must be the exact one the client names in its error"
    );
}

/// Priority 4: two dispatches on the same task get different ids, and neither leaks past its
/// own scope. Pure -- no wire needed, since this is a property of [`with_dispatch_attempt`]
/// itself, not of any one client.
#[tokio::test]
async fn a_dispatch_attempt_scope_does_not_leak_past_its_own_await_and_differs_each_time() {
    assert_eq!(
        lore_transport::outcome::current_dispatch_attempt(),
        None,
        "no attempt should be visible outside any scope"
    );

    let first = AttemptId::new();
    let observed_in_first = lore_transport::outcome::with_dispatch_attempt(first, async {
        lore_transport::outcome::current_dispatch_attempt()
    })
    .await;
    assert_eq!(observed_in_first, Some(first));
    assert_eq!(
        lore_transport::outcome::current_dispatch_attempt(),
        None,
        "the scope must not leak past its own await"
    );

    let second = AttemptId::new();
    let observed_in_second = lore_transport::outcome::with_dispatch_attempt(second, async {
        lore_transport::outcome::current_dispatch_attempt()
    })
    .await;
    assert_eq!(observed_in_second, Some(second));
    assert_ne!(first, second, "two mints must not coincide");
    assert_eq!(lore_transport::outcome::current_dispatch_attempt(), None);
}
