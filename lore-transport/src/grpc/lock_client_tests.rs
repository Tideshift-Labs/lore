// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Ordinary-unlock compatibility after actual managed dispatch and settlement.
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use lore_base::types::Hash;
use lore_proto::lock::lock_service_server::LockService as Server;
use lore_proto::lock::lock_service_server::LockServiceServer;
use lore_proto::lock::*;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use uuid::Uuid;

use super::*;
use crate::attempt_store::AttemptRecord;
use crate::attempt_store::AttemptResolution;
use crate::attempt_store::AttemptState;
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
            return Err(ProtocolError::from(Status::not_found(
                "injected journal failure",
            )));
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

struct FixtureServer {
    journal: Arc<Journal>,
    unknown: bool,
    seen: Arc<parking_lot::Mutex<Vec<AttemptId>>>,
}
impl FixtureServer {
    fn answer<T>(&self, request: &Request<T>) -> Status {
        let id = AttemptId::from_uuid(
            Uuid::parse_str(
                request
                    .metadata()
                    .get("lore-attempt-id")
                    .unwrap()
                    .to_str()
                    .unwrap(),
            )
            .unwrap(),
        );
        let recorded = self.journal.intents.lock();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].0.attempt_id, id,
            "journal precedes actual request"
        );
        self.seen.lock().push(id);
        if self.unknown {
            Status::unavailable("answer lost")
        } else {
            Status::not_found("lock absent")
        }
    }
}
#[tonic::async_trait]
impl Server for FixtureServer {
    async fn unlock(
        &self,
        request: Request<UnlockRequest>,
    ) -> Result<Response<UnlockResponse>, Status> {
        Err(self.answer(&request))
    }
    async fn force_unlock(
        &self,
        request: Request<ForceUnlockRequest>,
    ) -> Result<Response<ForceUnlockResponse>, Status> {
        Err(self.answer(&request))
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
    seen: Arc<parking_lot::Mutex<Vec<AttemptId>>>,
    endpoint: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new(unknown: bool) -> Self {
        let journal = Arc::new(Journal::default());
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let service = FixtureServer {
            journal: journal.clone(),
            unknown,
            seen: seen.clone(),
        };
        let task = lore_base::lore_spawn!(async move {
            tonic::transport::Server::builder()
                .add_service(LockServiceServer::new(service))
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
            client: LockService::new(channel, RepositoryId::from([0x11; 16]), auth),
            journal,
            seen,
            endpoint,
            task,
        }
    }
    async fn release(&self, admin: bool) -> Result<Vec<LockResource>, ProtocolError> {
        let context = CallerOperationContext::new(
            Uuid::now_v7(),
            RepositoryId::from([0x11; 16]),
            self.journal.clone(),
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            with_caller_operation(
                context,
                crate::caller_operation::with_transport_endpoint(self.endpoint.clone(), async {
                    let resource = LockResource {
                        branch: Context::from([0x22; 16]),
                        hash: Hash::from([0x33; 32]),
                        description: "resource".into(),
                    };
                    if admin {
                        self.client.force_unlock(&[resource], "other-owner").await
                    } else {
                        self.client
                            .unlock(&[FencedLockResource::tokenless(resource)])
                            .await
                    }
                }),
            ),
        )
        .await
        .expect("bounded release")
    }
}
#[tokio::test]
async fn ordinary_missing_lock_is_empty_only_after_exact_not_applied_settlement() {
    let f = Fixture::new(false).await;
    assert!(f.release(false).await.unwrap().is_empty());
    let (record, intent) = f.journal.intents.lock()[0].clone();
    assert_eq!(intent.rpc, "LockService.Unlock");
    assert_eq!(*f.seen.lock(), vec![record.attempt_id]);
    assert_eq!(
        f.journal
            .lookup(&record.attempt_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        AttemptState::Resolved(AttemptResolution::NotApplied)
    );
    assert!(f.journal.unresolved().await.unwrap().is_empty());
}
#[tokio::test]
async fn ordinary_unlock_unknown_preserves_original_attempt_and_does_not_retry() {
    let f = Fixture::new(true).await;
    let error = f.release(false).await.unwrap_err();
    assert!(error.is_outcome_unknown());
    let record = f.journal.intents.lock()[0].0.clone();
    assert!(format!("{error:?}").contains(&record.attempt_id.to_string()));
    assert_eq!(*f.seen.lock(), vec![record.attempt_id]);
    assert_eq!(
        f.journal.unresolved().await.unwrap()[0].attempt_id,
        record.attempt_id
    );
}
#[tokio::test]
async fn administrative_missing_lock_remains_a_decisive_not_found() {
    let f = Fixture::new(false).await;
    assert!(f.release(true).await.unwrap_err().is_not_found());
    let record = f.journal.intents.lock()[0].0.clone();
    assert_eq!(*f.seen.lock(), vec![record.attempt_id]);
    assert_eq!(
        f.journal
            .lookup(&record.attempt_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        AttemptState::Resolved(AttemptResolution::NotApplied)
    );
}
#[tokio::test]
async fn missing_lock_cannot_hide_failed_journal_settlement() {
    let f = Fixture::new(false).await;
    f.journal.fail_settle.store(true, Ordering::SeqCst);
    let error = f.release(false).await.unwrap_err();
    assert!(error.is_outcome_unknown());
    let attempt = f.journal.intents.lock()[0].0.attempt_id;
    assert!(format!("{error:?}").contains(&attempt.to_string()));
    assert_eq!(*f.seen.lock(), vec![attempt]);
    assert_eq!(f.journal.unresolved().await.unwrap().len(), 1);
}

#[tokio::test]
async fn pre_dispatch_journal_not_found_is_not_reported_as_success() {
    let f = Fixture::new(false).await;
    f.journal.fail_record.store(true, Ordering::SeqCst);
    assert!(f.release(false).await.is_err());
    assert!(f.seen.lock().is_empty());
    assert!(f.journal.intents.lock().is_empty());
}
