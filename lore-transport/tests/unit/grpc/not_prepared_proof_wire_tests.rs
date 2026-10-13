// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! The not-prepared proof (`lore-not-prepared-attempt-v1`) through a real `LockService` server and
//! `with_reconnect_classified` (Gate 0 campaign c13, 2026-10-13).
//!
//! A fenced cell whose verifier is down refuses `Lock` with `UNAVAILABLE` before it files any
//! receipt. The client used to read that as a lost answer and raise `OutcomeUnknown`, leaving an
//! attempt no reconciliation could ever settle. The server now stamps the request's own attempt id
//! on such a refusal, and the client treats it as decisive only when the proof names this attempt
//! and this process sent the attempt exactly once.
//!
//! Deliberately a sibling of `call_failure_vs_refusal_wire_tests` with its own double: that
//! double answers a status fixed at construction, and this one must echo the id each request
//! carried.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use lore_base::types::Context;
use lore_base::types::Hash;
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
use lore_transport::outcome::ATTEMPT_ID_METADATA_KEY;
use lore_transport::outcome::AttemptId;
use lore_transport::outcome::GrpcRpc;
use lore_transport::outcome::NOT_PREPARED_ATTEMPT_METADATA_KEY;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tower::ServiceBuilder;

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
        branch: Context::from([0x03u8; 16]),
        hash: Hash::from([0x78u8; 32]),
        description: "not-prepared-proof-test-resource".to_string(),
    })]
}

/// What the scripted server stamps on its `UNAVAILABLE` refusal.
#[derive(Clone, Copy)]
enum Proof {
    /// The id the request carried: what a real loreserver sets.
    OwnAttempt,
    /// A fresh unrelated id.
    ForeignAttempt,
    /// No header at all: a load balancer, a proxy, a dropped connection.
    None,
    /// The request's own id, twice.
    OwnAttemptTwice,
    /// A value that is not a UUID.
    Unparseable,
    /// The request's own id, on a decisive code.
    OwnAttemptOnPermissionDenied,
}

struct ProofLockServer {
    proof: Proof,
    lock_calls: Arc<AtomicUsize>,
}

impl ProofLockServer {
    fn refusal(&self, request: &Request<LockRequest>) -> Status {
        let own = request
            .metadata()
            .get(ATTEMPT_ID_METADATA_KEY)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .expect("the dispatch must carry an attempt id");
        let mut status = match self.proof {
            Proof::OwnAttemptOnPermissionDenied => Status::permission_denied("not allowed"),
            _ => Status::unavailable("verifier unavailable"),
        };
        let mut stamp = |value: &str| {
            status.metadata_mut().append(
                NOT_PREPARED_ATTEMPT_METADATA_KEY,
                value.parse().expect("ascii"),
            );
        };
        match self.proof {
            Proof::OwnAttempt | Proof::OwnAttemptOnPermissionDenied => stamp(&own),
            Proof::ForeignAttempt => stamp(&uuid::Uuid::now_v7().to_string()),
            Proof::None => {}
            Proof::OwnAttemptTwice => {
                stamp(&own);
                stamp(&own);
            }
            Proof::Unparseable => stamp("not-a-uuid"),
        }
        status
    }
}

#[tonic::async_trait]
impl LockServiceServerTrait for ProofLockServer {
    async fn lock(&self, request: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
        self.lock_calls.fetch_add(1, Ordering::Relaxed);
        Err(self.refusal(&request))
    }

    async fn query(
        &self,
        _request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
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

async fn start_proof_lock_server(proof: Proof) -> (lock_client::LockService, Arc<AtomicUsize>) {
    let lock_calls = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server = ProofLockServer {
        proof,
        lock_calls: lock_calls.clone(),
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
    (client, lock_calls)
}

/// One `LockLock` dispatch, with the attempt minted by the dispatcher itself.
async fn dispatch_once(
    client: &lock_client::LockService,
) -> Result<Vec<AcquiredLock>, ProtocolError> {
    let connection = dummy_connection();
    let resources = one_resource();
    // Boxed: the dispatcher's future is large enough to trip large_futures in every caller.
    Box::pin(with_reconnect_classified(
        &connection,
        GrpcRpc::LockLock,
        || async { client.lock(&resources, None).await },
        |_reconnect_id| async { Ok(()) },
    ))
    .await
}

/// The defect under test: a refusal proven to precede any receipt is decisive, so the journal can
/// settle the attempt `NotApplied` instead of leaving it for a reconcile that finds no receipt.
#[tokio::test]
async fn an_unavailable_proven_not_prepared_for_this_attempt_is_decisive() {
    let (client, lock_calls) = start_proof_lock_server(Proof::OwnAttempt).await;

    let error = dispatch_once(&client)
        .await
        .expect_err("the refusal must surface as an error");

    assert!(
        !error.is_outcome_unknown(),
        "a refusal proven not-prepared for this very attempt must be decisive: {error:?}"
    );
    assert!(
        matches!(error, ProtocolError::Internal(_)),
        "the decisive shape is Internal wrapping the proof: {error:?}"
    );
    assert_eq!(lock_calls.load(Ordering::Relaxed), 1);
}

/// Negative control: an `UNAVAILABLE` with no proof is a load balancer's shape and stays unknown.
#[tokio::test]
async fn an_unmarked_unavailable_stays_outcome_unknown() {
    let (client, lock_calls) = start_proof_lock_server(Proof::None).await;

    let error = dispatch_once(&client).await.expect_err("must fail");

    assert!(
        error.is_outcome_unknown(),
        "an UNAVAILABLE without the proof must stay OutcomeUnknown: {error:?}"
    );
    assert_eq!(lock_calls.load(Ordering::Relaxed), 1);
}

/// A proof for some other attempt cannot settle this one.
#[tokio::test]
async fn a_proof_naming_a_different_attempt_stays_outcome_unknown() {
    let (client, _lock_calls) = start_proof_lock_server(Proof::ForeignAttempt).await;

    let error = dispatch_once(&client).await.expect_err("must fail");

    assert!(
        error.is_outcome_unknown(),
        "a proof for another attempt must not settle this one: {error:?}"
    );
}

/// Two header values, or one that is not a UUID, are no proof about one attempt.
#[tokio::test]
async fn a_duplicated_or_unparseable_proof_stays_outcome_unknown() {
    for proof in [Proof::OwnAttemptTwice, Proof::Unparseable] {
        let (client, _lock_calls) = start_proof_lock_server(proof).await;

        let error = dispatch_once(&client).await.expect_err("must fail");

        assert!(
            error.is_outcome_unknown(),
            "a malformed proof must give no proof: {error:?}"
        );
    }
}

/// The proof on a code that already maps to a decisive refusal changes nothing: it stays
/// `NotAuthorized`, and is not turned into `Internal` or `OutcomeUnknown`.
#[tokio::test]
async fn a_proof_on_a_decisive_code_keeps_the_usual_variant() {
    let (client, _lock_calls) = start_proof_lock_server(Proof::OwnAttemptOnPermissionDenied).await;

    let error = dispatch_once(&client).await.expect_err("must fail");

    assert!(
        matches!(error, ProtocolError::NotAuthorized(_)),
        "PermissionDenied carrying the proof must stay NotAuthorized: {error:?}"
    );
}

/// One attempt id sent twice is no longer one copy. The first send is refused with a genuine
/// proof and settles; the second is refused with an equally genuine proof and stays unknown,
/// because another copy may have reached a replica that did prepare it.
#[tokio::test]
async fn a_retried_attempt_stays_outcome_unknown_even_with_a_genuine_proof() {
    let (client, lock_calls) = start_proof_lock_server(Proof::OwnAttempt).await;
    let attempt = AttemptId::new();

    let (first, second) = lore_transport::outcome::with_dispatch_attempt(attempt, async {
        let first = dispatch_once(&client).await;
        let second = dispatch_once(&client).await;
        (first, second)
    })
    .await;

    let first = first.expect_err("the first send is refused");
    assert!(
        !first.is_outcome_unknown(),
        "control: the first and only copy so far is proven not prepared: {first:?}"
    );

    let second = second.expect_err("the second send is refused");
    let unknown = second
        .as_outcome_unknown()
        .unwrap_or_else(|| panic!("the second send of one attempt must stay unknown: {second:?}"));
    assert_eq!(
        unknown.attempt_id,
        attempt.to_string(),
        "the unknown outcome must name the shared attempt"
    );
    assert_eq!(lock_calls.load(Ordering::Relaxed), 2);
    assert_eq!(lore_transport::outcome::dispatch_send_count(&attempt), 2);
}

/// The send counter is per attempt: a fresh id starts at zero and counts every stamped request.
#[tokio::test]
async fn the_send_counter_counts_each_copy_of_one_attempt_and_no_other() {
    let (client, _lock_calls) = start_proof_lock_server(Proof::None).await;
    let counted = AttemptId::new();
    let untouched = AttemptId::new();

    assert_eq!(lore_transport::outcome::dispatch_send_count(&counted), 0);
    lore_transport::outcome::with_dispatch_attempt(counted, async {
        let _ = dispatch_once(&client).await;
    })
    .await;
    assert_eq!(lore_transport::outcome::dispatch_send_count(&counted), 1);
    assert_eq!(lore_transport::outcome::dispatch_send_count(&untouched), 0);
}
