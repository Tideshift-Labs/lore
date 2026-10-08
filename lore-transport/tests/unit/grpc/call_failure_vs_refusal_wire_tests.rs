// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! `with_reconnect_classified` layer (`answer_is_not_settled` above, and `crate::error`'s
//! `From<tonic::Status>` impl underneath it). Before this fix all three funnelled into a
//! decisive `Internal`, which is what let a mid-flight stream reset during a lock release
//! escalate to a force-release on a maybe. See `lore-server/src/grpc/lock_service.rs`'s
//! `handle_lock_error`: no lock handler ever raises `Cancelled` or `DeadlineExceeded` as a
//! refusal, so a status carrying either code, arriving here, always means the call failed rather
//! than being refused.
//!
//! Deliberately a sibling of `attempt_id_wire_tests` with its own double, for the same reason
//! `fenced_lock_token_wire_tests` is: `RecordingLockServer` always answers `Unavailable`, and
//! widening it to answer a caller-scripted status for an unrelated concern would put every test
//! using it at risk of a change made for this one.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

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
use lore_transport::outcome::GrpcRpc;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tower::ServiceBuilder;

/// Matches `attempt_id_wire_tests::dummy_connection`'s shape, duplicated rather than shared
/// across modules per this file's existing convention: every test here either never fails
/// (so `rebuild` is never called) or takes the `MutableNoReplay`/`ReadRetryable` branches,
/// neither of which touches `connection` beyond reading `.reconnect`.
fn dummy_connection() -> GRPCConnection {
    let endpoint = tonic::transport::Endpoint::from_shared("http://127.0.0.1:1".to_string())
        .expect("test endpoint");
    let channel = ServiceBuilder::new()
        .layer(RequestLoggerLayer {})
        .service(endpoint.connect_lazy());
    GRPCConnection::for_test("http://127.0.0.1:1".parse().expect("test url"), channel)
}

fn one_resource() -> Vec<FencedLockResource> {
    vec![FencedLockResource::tokenless(LockResource {
        branch: Context::from([0x02u8; 16]),
        hash: Hash::from([0x77u8; 32]),
        description: "call-failure-vs-refusal-test-resource".to_string(),
    })]
}

/// The status a scripted server answers every call with. `Internal` here is
/// `Status::internal`, exactly what `handle_lock_error` builds for a genuine refusal --
/// decoded off the wire it is sourceless (`Status::from_header_map` always sets
/// `source: None`), so it is the correct shape for the negative control regardless of how
/// `Status::internal` behaves before it round-trips through a real connection.
#[derive(Clone, Copy)]
enum ScriptedFailure {
    Cancelled,
    DeadlineExceeded,
    Internal,
}

impl ScriptedFailure {
    fn status(self) -> Status {
        match self {
            Self::Cancelled => Status::cancelled("mid-flight stream reset"),
            Self::DeadlineExceeded => Status::deadline_exceeded("grpc-timeout expired"),
            Self::Internal => Status::internal("refused: resource locked by another owner"),
        }
    }
}

/// Implements only `lock` and `query`; every call is counted and every call fails with the
/// same scripted status, so a test can assert exactly how many times the server actually ran
/// (proving reissue did or did not happen, not just what the final error looked like).
struct ScriptedLockServer {
    failure: ScriptedFailure,
    lock_calls: Arc<AtomicUsize>,
    query_calls: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl LockServiceServerTrait for ScriptedLockServer {
    async fn lock(&self, _request: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
        self.lock_calls.fetch_add(1, Ordering::Relaxed);
        Err(self.failure.status())
    }

    async fn query(
        &self,
        _request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        self.query_calls.fetch_add(1, Ordering::Relaxed);
        Err(self.failure.status())
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
/// `lock_client::LockService` bound to it, matching `start_recording_lock_server`'s shape.
async fn start_scripted_lock_server(
    failure: ScriptedFailure,
) -> (lock_client::LockService, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let lock_calls = Arc::new(AtomicUsize::new(0));
    let query_calls = Arc::new(AtomicUsize::new(0));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server = ScriptedLockServer {
        failure,
        lock_calls: lock_calls.clone(),
        query_calls: query_calls.clone(),
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
    (client, lock_calls, query_calls)
}

/// A `MutableNoReplay` dispatch (`LockLock`) whose server answers `Cancelled` must become
/// `OutcomeUnknown`, not a decisive `Internal` -- this is the defect under test: before the
/// fix, this path escalated a mid-flight reset to a force-release.
#[tokio::test]
async fn mutable_no_replay_dispatch_with_cancelled_becomes_outcome_unknown() {
    let (client, lock_calls, _query_calls) =
        start_scripted_lock_server(ScriptedFailure::Cancelled).await;
    let connection = dummy_connection();
    let resources = one_resource();

    let result: Result<Vec<AcquiredLock>, ProtocolError> = with_reconnect_classified(
        &connection,
        GrpcRpc::LockLock,
        || async { client.lock(&resources, None).await },
        |_reconnect_id| async { Ok(()) },
    )
    .await;

    let error = result.expect_err("a Cancelled status must surface as an error");
    assert!(
        error.is_outcome_unknown(),
        "a MutableNoReplay dispatch answered with Cancelled must become OutcomeUnknown, not \
         a decisive Internal: {error:?}"
    );
    assert_eq!(lock_calls.load(Ordering::Relaxed), 1);
}

/// Same RPC, `DeadlineExceeded` instead of `Cancelled` -- the second funnelled code.
#[tokio::test]
async fn mutable_no_replay_dispatch_with_deadline_exceeded_becomes_outcome_unknown() {
    let (client, lock_calls, _query_calls) =
        start_scripted_lock_server(ScriptedFailure::DeadlineExceeded).await;
    let connection = dummy_connection();
    let resources = one_resource();

    let result: Result<Vec<AcquiredLock>, ProtocolError> = with_reconnect_classified(
        &connection,
        GrpcRpc::LockLock,
        || async { client.lock(&resources, None).await },
        |_reconnect_id| async { Ok(()) },
    )
    .await;

    let error = result.expect_err("a DeadlineExceeded status must surface as an error");
    assert!(
        error.is_outcome_unknown(),
        "a MutableNoReplay dispatch answered with DeadlineExceeded must become \
         OutcomeUnknown, not a decisive Internal: {error:?}"
    );
    assert_eq!(lock_calls.load(Ordering::Relaxed), 1);
}

/// Load-bearing negative control: a genuine server refusal (`Status::internal`, no funnelled
/// code) must stay decisive. If this test also went `OutcomeUnknown`, the fix would have
/// turned every server refusal into a retryable-looking maybe, defeating the whole point of
/// the split.
#[tokio::test]
async fn mutable_no_replay_dispatch_with_a_plain_internal_refusal_stays_decisive() {
    let (client, lock_calls, _query_calls) =
        start_scripted_lock_server(ScriptedFailure::Internal).await;
    let connection = dummy_connection();
    let resources = one_resource();

    let result: Result<Vec<AcquiredLock>, ProtocolError> = with_reconnect_classified(
        &connection,
        GrpcRpc::LockLock,
        || async { client.lock(&resources, None).await },
        |_reconnect_id| async { Ok(()) },
    )
    .await;

    let error = result.expect_err("an Internal status must surface as an error");
    assert!(
        !error.is_outcome_unknown(),
        "a genuine server refusal must never read as OutcomeUnknown: {error:?}"
    );
    assert!(
        matches!(error, ProtocolError::Internal(_)),
        "a genuine server refusal must stay a decisive Internal: {error:?}"
    );
    assert_eq!(lock_calls.load(Ordering::Relaxed), 1);
}

/// A `ReadRetryable` dispatch (`LockQuery`) answered with `Cancelled` stays a decisive
/// `Internal` and is not reissued -- `with_reconnect` only reconnects on `Disconnected`, so
/// this also pins that a lost-answer marker on a read is never treated as a lost channel.
#[tokio::test]
async fn read_retryable_dispatch_with_cancelled_stays_internal_and_is_not_reissued() {
    let (client, _lock_calls, query_calls) =
        start_scripted_lock_server(ScriptedFailure::Cancelled).await;
    let connection = dummy_connection();

    let result: Result<Vec<LockData>, ProtocolError> = with_reconnect_classified(
        &connection,
        GrpcRpc::LockQuery,
        || async { client.query(None, None, None).await },
        |_reconnect_id| async { Ok(()) },
    )
    .await;

    let error = result.expect_err("a Cancelled status must surface as an error");
    assert!(
        !error.is_outcome_unknown(),
        "a read is not upgraded to OutcomeUnknown even when it carries the lost-answer \
         marker: {error:?}"
    );
    assert!(matches!(error, ProtocolError::Internal(_)));
    assert_eq!(
        query_calls.load(Ordering::Relaxed),
        1,
        "a decisive-looking Internal on a read must not be reissued"
    );
}
