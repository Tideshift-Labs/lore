// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Client dispatch proof against a real tonic server; the journal double is not disk proof.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use lore_proto::lore::revision::v1::revision_service_server::RevisionService as Server;
use lore_proto::lore::revision::v1::revision_service_server::RevisionServiceServer;
use lore_proto::lore::revision::v1::*;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use uuid::Uuid;

use super::*;
use crate::attempt_store::AttemptRecord;
use crate::attempt_store::AttemptResolution;
use crate::attempt_store::AttemptStore;
use crate::attempt_store::LockOwnership;
use crate::attempt_store::VolatileAttemptStore;
use crate::caller_operation::CallerOperationContext;
use crate::caller_operation::ManagedAttemptIntent;
use crate::caller_operation::with_caller_operation;
use crate::outcome::AttemptId;

// Only syntax is tested here; this disposable server does not verify JWT signatures.
const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJmaXh0dXJlLXVzZXIiLCJuYW1lIjoiZml4dHVyZS11c2VyIiwiZXhwIjo0MTAyNDQ0ODAwLCJhdWQiOiJmaXh0dXJlIn0.eA";

#[derive(Default)]
struct Journal {
    inner: VolatileAttemptStore,
    intents: parking_lot::Mutex<Vec<(AttemptRecord, ManagedAttemptIntent)>>,
    fail_record: AtomicBool,
    fail_settle: AtomicBool,
}

#[async_trait::async_trait]
impl AttemptStore for Journal {
    async fn record_managed(
        &self,
        record: &AttemptRecord,
        intent: &ManagedAttemptIntent,
    ) -> Result<(), ProtocolError> {
        self.record(record).await?;
        self.intents.lock().push((record.clone(), intent.clone()));
        Ok(())
    }
    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
        if self.fail_record.load(Ordering::SeqCst) {
            return Err(ProtocolError::internal("injected journal failure"));
        }
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
        if self.fail_settle.load(Ordering::SeqCst) {
            return Err(ProtocolError::internal("injected settlement failure"));
        }
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

#[derive(Clone, Copy)]
enum Reply {
    Success,
    Loss,
    Refusal,
    Malformed,
}

struct FixtureServer {
    journal: Arc<Journal>,
    seen: Arc<parking_lot::Mutex<Vec<BranchCreateRequest>>>,
    reply: Reply,
}

#[tonic::async_trait]
impl Server for FixtureServer {
    async fn branch_create(
        &self,
        request: Request<BranchCreateRequest>,
    ) -> Result<Response<BranchCreateResponse>, Status> {
        assert_eq!(
            request
                .metadata()
                .get("lore-caller-capabilities-v1")
                .unwrap(),
            "outcome_unknown_v1"
        );
        assert_eq!(
            request.metadata().get("lore-authn-bearer").unwrap(),
            format!("Bearer {TOKEN}").as_str()
        );
        let id = Uuid::parse_str(
            request
                .metadata()
                .get("lore-attempt-id")
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let recorded = self.journal.intents.lock();
        assert_eq!(recorded.len(), 1, "journal must precede wire dispatch");
        assert_eq!(recorded[0].0.attempt_id.to_string(), id.to_string());
        assert_eq!(recorded[0].1.rpc, "RevisionService.BranchCreate");
        assert_eq!(
            recorded[0].1.canonical_request,
            request.get_ref().encode_to_vec()
        );
        drop(recorded);
        let request = request.into_inner();
        self.seen.lock().push(request.clone());
        match self.reply {
            Reply::Success | Reply::Malformed => Ok(Response::new(BranchCreateResponse {
                branch: Some(model_v1::Branch {
                    id: request.id,
                    name: request.name,
                    creator: "fixture-user".into(),
                    latest: vec![0x35; 32].into(),
                    metadata: vec![
                        0x36;
                        if matches!(self.reply, Reply::Malformed) {
                            31
                        } else {
                            32
                        }
                    ]
                    .into(),
                    ..Default::default()
                }),
            })),
            Reply::Loss => Err(Status::unavailable("response unavailable after dispatch")),
            Reply::Refusal => Err(Status::permission_denied("write refused")),
        }
    }
    async fn branch_delete(
        &self,
        _: Request<BranchDeleteRequest>,
    ) -> Result<Response<BranchDeleteResponse>, Status> {
        panic!("unexpected delete")
    }
    async fn branch_get(
        &self,
        _: Request<BranchGetRequest>,
    ) -> Result<Response<BranchGetResponse>, Status> {
        panic!("unexpected get")
    }
    type BranchListStream = tokio_stream::Empty<Result<revision_v1::BranchListResponse, Status>>;
    async fn branch_list(
        &self,
        _: Request<BranchListRequest>,
    ) -> Result<Response<Self::BranchListStream>, Status> {
        panic!("unexpected list")
    }
    async fn branch_push(
        &self,
        _: Request<BranchPushRequest>,
    ) -> Result<Response<revision_v1::BranchPushResponse>, Status> {
        panic!("unexpected push")
    }
    async fn branch_metadata_get(
        &self,
        _: Request<BranchMetadataGetRequest>,
    ) -> Result<Response<BranchMetadataGetResponse>, Status> {
        panic!("unexpected metadata get")
    }
    async fn branch_metadata_set(
        &self,
        _: Request<BranchMetadataSetRequest>,
    ) -> Result<Response<BranchMetadataSetResponse>, Status> {
        panic!("unexpected metadata set")
    }
    async fn revision_list(
        &self,
        _: Request<RevisionListRequest>,
    ) -> Result<Response<revision_v1::RevisionListResponse>, Status> {
        panic!("unexpected revision list")
    }
}

struct Fixture {
    client: RevisionService,
    journal: Arc<Journal>,
    seen: Arc<parking_lot::Mutex<Vec<BranchCreateRequest>>>,
    endpoint: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new(reply: Reply) -> Self {
        let journal = Arc::new(Journal::default());
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let service = FixtureServer {
            journal: journal.clone(),
            seen: seen.clone(),
            reply,
        };
        let task = lore_base::lore_spawn!(async move {
            tonic::transport::Server::builder()
                .add_service(RevisionServiceServer::new(service))
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
            .layer(crate::grpc::RequestLoggerLayer {})
            .service(channel);
        let auth = Arc::new(parking_lot::RwLock::new(crate::grpc::GRPCAuth {
            authentication_token: TOKEN.into(),
            authorization_token: TOKEN.into(),
            ..Default::default()
        }));
        Self {
            client: RevisionService::new(channel, RepositoryId::from([0x11; 16]), auth),
            journal,
            seen,
            endpoint,
            task,
        }
    }
    async fn create(&self, repository: RepositoryId) -> Result<Hash, ProtocolError> {
        let operation =
            CallerOperationContext::new(Uuid::now_v7(), repository, self.journal.clone());
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            with_caller_operation(
                operation,
                crate::caller_operation::with_transport_endpoint(
                    self.endpoint.clone(),
                    self.client.branch_create(
                        BranchId::from([0x22; 16]),
                        "feature",
                        "category",
                        "foreign",
                        &[],
                    ),
                ),
            ),
        )
        .await
        .expect("bounded branch create")
    }
}

#[tokio::test]
async fn managed_create_records_exact_intent_before_one_dispatch() {
    let fixture = Fixture::new(Reply::Success).await;
    assert_eq!(
        fixture
            .create(RepositoryId::from([0x11; 16]))
            .await
            .unwrap(),
        Hash::from([0x35; 32])
    );
    assert_eq!(fixture.seen.lock().len(), 1);
    let (record, intent) = fixture.journal.intents.lock()[0].clone();
    assert_eq!(intent.authenticated_subject, "fixture-user");
    assert_eq!(
        BranchCreateRequest::decode(intent.canonical_request.as_slice())
            .unwrap()
            .creator
            .as_deref(),
        Some("foreign")
    );
    assert_eq!(
        fixture
            .journal
            .lookup(&record.attempt_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        crate::attempt_store::AttemptState::Resolved(AttemptResolution::Applied)
    );
}

#[tokio::test]
async fn dispatched_failure_never_enters_the_legacy_retry_loop() {
    for reply in [Reply::Loss, Reply::Refusal, Reply::Malformed] {
        let fixture = Fixture::new(reply).await;
        let error = fixture
            .create(RepositoryId::from([0x11; 16]))
            .await
            .unwrap_err();
        assert_eq!(fixture.seen.lock().len(), 1);
        if matches!(reply, Reply::Loss | Reply::Malformed) {
            assert!(error.is_outcome_unknown(), "{error:?}");
            assert_eq!(fixture.journal.unresolved().await.unwrap().len(), 1);
        }
    }
}

#[tokio::test]
async fn failed_pre_dispatch_journaling_or_repository_mismatch_sends_nothing() {
    for wrong_repository in [false, true] {
        let fixture = Fixture::new(Reply::Success).await;
        fixture
            .journal
            .fail_record
            .store(!wrong_repository, Ordering::SeqCst);
        let repository = RepositoryId::from([if wrong_repository { 0x99 } else { 0x11 }; 16]);
        assert!(fixture.create(repository).await.is_err());
        assert!(fixture.seen.lock().is_empty());
        assert!(fixture.journal.intents.lock().is_empty());
    }
}

#[tokio::test]
async fn successful_wire_reply_cannot_hide_failed_journal_settlement() {
    let fixture = Fixture::new(Reply::Success).await;
    fixture.journal.fail_settle.store(true, Ordering::SeqCst);
    assert!(
        fixture
            .create(RepositoryId::from([0x11; 16]))
            .await
            .is_err()
    );
    assert_eq!(fixture.seen.lock().len(), 1);
    assert_eq!(fixture.journal.unresolved().await.unwrap().len(), 1);
}
