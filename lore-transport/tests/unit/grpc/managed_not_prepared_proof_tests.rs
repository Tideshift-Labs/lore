// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! The not-prepared proof (`lore-not-prepared-attempt-v1`) through the MANAGED caller journal.
//!
//! `dispatch_recorded_result` settles the journal record before the outer
//! `with_reconnect_classified` check runs, so it must apply the proof rule itself: a marked
//! refusal settles `NotApplied` only when it names this attempt and the attempt was sent once.
use std::sync::Arc;

use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::LockResource;
use lore_base::types::RepositoryId;
use lore_proto::lock::lock_service_server::LockService as Server;
use lore_proto::lock::lock_service_server::LockServiceServer;
use lore_proto::lock::*;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptState;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::FencedLockResource;
use lore_transport::attempt_store::LockOwnership;
use lore_transport::attempt_store::VolatileAttemptStore;
use lore_transport::caller_operation::CallerOperationContext;
use lore_transport::caller_operation::ManagedAttemptIntent;
use lore_transport::caller_operation::with_caller_operation;
use lore_transport::error::ProtocolError;
use lore_transport::grpc::lock_client::LockService;
use lore_transport::outcome::AttemptId;
use lore_transport::outcome::NOT_PREPARED_ATTEMPT_METADATA_KEY;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use uuid::Uuid;

// Only syntax is tested here; this disposable server does not verify JWT signatures.
const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJmaXh0dXJlLXVzZXIiLCJuYW1lIjoiZml4dHVyZS11c2VyIiwiZXhwIjo0MTAyNDQ0ODAwLCJhdWQiOiJmaXh0dXJlIn0.eA";

/// A volatile journal that also accepts the managed intent and remembers which attempts it saw.
#[derive(Default)]
struct Journal {
    inner: VolatileAttemptStore,
    recorded: parking_lot::Mutex<Vec<AttemptId>>,
}

#[async_trait::async_trait]
impl AttemptStore for Journal {
    async fn record_managed(
        &self,
        record: &AttemptRecord,
        _intent: &ManagedAttemptIntent,
    ) -> Result<(), ProtocolError> {
        self.recorded.lock().push(record.attempt_id);
        self.inner.record(record).await
    }
    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
        self.inner.record(record).await
    }
    async fn lookup(&self, id: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
        self.inner.lookup(id).await
    }
    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
        self.inner.unresolved().await
    }
    async fn resolve(
        &self,
        id: &AttemptId,
        resolution: AttemptResolution,
    ) -> Result<(), ProtocolError> {
        self.inner.resolve(id, resolution).await
    }
    async fn record_ownership(&self, _: &LockOwnership) -> Result<(), ProtocolError> {
        unreachable!()
    }
    async fn ownership_for(
        &self,
        _: &Context,
        _: &Hash,
    ) -> Result<Option<LockOwnership>, ProtocolError> {
        unreachable!()
    }
    async fn clear_ownership(&self, _: &Context, _: &Hash) -> Result<(), ProtocolError> {
        unreachable!()
    }
}

/// Whose attempt id the refusal's proof names.
#[derive(Clone, Copy)]
enum Names {
    /// The id the request carried.
    Request,
    /// A fresh unrelated id.
    Other,
}

struct RefusingServer {
    names: Names,
}

#[tonic::async_trait]
impl Server for RefusingServer {
    async fn unlock(
        &self,
        request: Request<UnlockRequest>,
    ) -> Result<Response<UnlockResponse>, Status> {
        let named = match self.names {
            Names::Request => request
                .metadata()
                .get("lore-attempt-id")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                .expect("the dispatch must carry an attempt id"),
            Names::Other => Uuid::now_v7().to_string(),
        };
        let mut status = Status::unavailable("verifier unavailable");
        status.metadata_mut().insert(
            NOT_PREPARED_ATTEMPT_METADATA_KEY,
            named.parse().expect("ascii"),
        );
        Err(status)
    }
    async fn force_unlock(
        &self,
        _: Request<ForceUnlockRequest>,
    ) -> Result<Response<ForceUnlockResponse>, Status> {
        panic!("unexpected force unlock")
    }
    async fn lock(&self, _: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
        panic!("unexpected lock")
    }
    async fn admin_lock(
        &self,
        _: Request<AdminLockRequest>,
    ) -> Result<Response<AdminLockResponse>, Status> {
        panic!("unexpected admin lock")
    }
    async fn query(&self, _: Request<QueryRequest>) -> Result<Response<QueryResponse>, Status> {
        panic!("unexpected query")
    }
    async fn status(&self, _: Request<StatusRequest>) -> Result<Response<StatusResponse>, Status> {
        panic!("unexpected status")
    }
}

struct Fixture {
    client: LockService,
    journal: Arc<Journal>,
    endpoint: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn resource() -> LockResource {
    LockResource {
        branch: Context::from([0x22; 16]),
        hash: Hash::from([0x33; 32]),
        description: "resource".into(),
    }
}

impl Fixture {
    async fn new(names: Names) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = lore_base::lore_spawn!(async move {
            tonic::transport::Server::builder()
                .add_service(LockServiceServer::new(RefusingServer { names }))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let channel = tonic::transport::Channel::from_shared(endpoint.clone())
            .unwrap()
            .connect()
            .await
            .unwrap();
        let channel = tower::ServiceBuilder::new()
            .layer(lore_transport::grpc::RequestLoggerLayer {})
            .service(channel);
        let auth = Arc::new(parking_lot::RwLock::new(lore_transport::grpc::GRPCAuth {
            authentication_token: TOKEN.into(),
            authorization_token: TOKEN.into(),
            ..Default::default()
        }));
        Self {
            client: LockService::new(channel, RepositoryId::from([0x11; 16]), auth),
            journal: Arc::new(Journal::default()),
            endpoint,
            task,
        }
    }

    /// One managed (journalled) unlock.
    async fn managed_unlock(&self) -> Result<Vec<LockResource>, ProtocolError> {
        let context = CallerOperationContext::new(
            Uuid::now_v7(),
            RepositoryId::from([0x11; 16]),
            self.journal.clone(),
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            with_caller_operation(
                context,
                lore_transport::caller_operation::with_transport_endpoint(
                    self.endpoint.clone(),
                    async {
                        self.client
                            .unlock(&[FencedLockResource::tokenless(resource())])
                            .await
                    },
                ),
            ),
        )
        .await
        .expect("bounded unlock")
    }

    async fn state_of(&self, attempt: &AttemptId) -> AttemptState {
        self.journal
            .lookup(attempt)
            .await
            .unwrap()
            .expect("the attempt must be journalled")
            .state
    }
}

/// The defect under test, through the journal: a refusal proven not-prepared for this attempt,
/// sent once, is decisive and the record settles `NotApplied`.
#[tokio::test]
async fn a_proof_for_this_attempt_sent_once_settles_the_managed_record_not_applied() {
    let f = Fixture::new(Names::Request).await;

    let error = f.managed_unlock().await.unwrap_err();

    assert!(
        !error.is_outcome_unknown(),
        "a proven not-prepared refusal must be decisive: {error:?}"
    );
    let recorded = f.journal.recorded.lock().clone();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        f.state_of(&recorded[0]).await,
        AttemptState::Resolved(AttemptResolution::NotApplied)
    );
    assert!(f.journal.unresolved().await.unwrap().is_empty());
}

/// A proof naming another attempt is no proof for this one: unknown, and the record stays open.
#[tokio::test]
async fn a_proof_naming_another_attempt_leaves_the_managed_record_unresolved() {
    let f = Fixture::new(Names::Other).await;

    let error = f.managed_unlock().await.unwrap_err();

    assert!(
        error.is_outcome_unknown(),
        "a proof for another attempt must not settle this one: {error:?}"
    );
    let recorded = f.journal.recorded.lock().clone();
    assert_eq!(recorded.len(), 1);
    assert_eq!(f.state_of(&recorded[0]).await, AttemptState::Unresolved);
}

/// A second send of one attempt id is not covered by a proof about the first copy. The first
/// copy goes out unmanaged under the same attempt scope (counted, genuinely proven); the managed
/// dispatch is then the second send.
#[tokio::test]
async fn a_second_send_of_the_attempt_leaves_the_managed_record_unresolved() {
    let f = Fixture::new(Names::Request).await;
    let attempt = AttemptId::new();

    let (first, second) = lore_transport::outcome::with_dispatch_attempt(attempt, async {
        let first = f
            .client
            .unlock(&[FencedLockResource::tokenless(resource())])
            .await;
        let second = f.managed_unlock().await;
        (first, second)
    })
    .await;

    let first = first.unwrap_err();
    assert!(
        !first.is_outcome_unknown(),
        "control: the unmanaged first send is a plain refusal: {first:?}"
    );
    let second = second.unwrap_err();
    assert!(
        second.is_outcome_unknown(),
        "the second send of one attempt must stay unknown: {second:?}"
    );
    assert_eq!(*f.journal.recorded.lock(), vec![attempt]);
    assert_eq!(f.state_of(&attempt).await, AttemptState::Unresolved);
    assert_eq!(lore_transport::outcome::dispatch_send_count(&attempt), 2);
}
