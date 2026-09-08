// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] Managed declarations against a real disposable tonic server.

use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use lore_base::types::RepositoryId;
use lore_proto::lore::storage::v1::storage_service_server::StorageService as Service;
use lore_proto::lore::storage::v1::storage_service_server::StorageServiceServer;
use prost::Message;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;
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

type Responses<T> = Pin<Box<dyn futures::Stream<Item = Result<T, Status>> + Send>>;

// The disposable server does not authenticate. This syntactic JWT exercises extraction of
// the exact outgoing credential's namespace, not signature verification.
const FIXTURE_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJmaXh0dXJlLXVzZXIiLCJuYW1lIjoiZml4dHVyZS11c2VyIiwiZXhwIjo0MTAyNDQ0ODAwLCJhdWQiOiJmaXh0dXJlIn0.eA";

#[derive(Default)]
struct Journal {
    inner: VolatileAttemptStore,
    records: parking_lot::Mutex<Vec<AttemptRecord>>,
    intents: parking_lot::Mutex<Vec<ManagedAttemptIntent>>,
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
        assert_eq!(intent.version, 1);
        assert_eq!(intent.repository, record.repository);
        assert_eq!(intent.rpc, record.operation);
        assert!(!intent.canonical_request.is_empty());
        self.record(record).await?;
        self.intents.lock().push(intent.clone());
        Ok(())
    }
    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
        if self.fail_record.load(Ordering::SeqCst) {
            return Err(ProtocolError::internal("injected journal failure"));
        }
        self.inner.record(record).await?;
        self.records.lock().push(record.clone());
        Ok(())
    }
    async fn lookup(&self, id: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
        self.inner.lookup(id).await
    }
    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
        self.inner.unresolved().await
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
}

#[derive(Clone, Copy)]
enum Reply {
    Success,
    Loss,
    Refusal,
    Hold,
    ItemCancelled,
    ItemAborted,
    ItemUnknown(u32, &'static str, &'static str),
}

#[derive(Clone, Debug)]
struct Seen {
    capability: Option<String>,
    attempt: Option<Uuid>,
    journaled_before_body: bool,
}

struct FixtureServer {
    journal: Arc<Journal>,
    seen: Arc<parking_lot::Mutex<Vec<Seen>>>,
    items: Arc<AtomicUsize>,
    reply: Reply,
}

impl FixtureServer {
    fn observe<T>(&self, request: &Request<T>) {
        let capability = request
            .metadata()
            .get("lore-caller-capabilities-v1")
            .map(|v| v.to_str().unwrap().to_owned());
        let attempt = request
            .metadata()
            .get("lore-attempt-id")
            .map(|v| Uuid::parse_str(v.to_str().unwrap()).unwrap());
        let journaled_before_body = attempt.is_some_and(|id| {
            self.journal
                .records
                .lock()
                .iter()
                .any(|r| r.attempt_id.as_uuid() == id)
        });
        self.seen.lock().push(Seen {
            capability,
            attempt,
            journaled_before_body,
        });
    }
}

fn refusal() -> Status {
    let mut status = Status::failed_precondition("the message is deliberately unrelated");
    status.metadata_mut().insert(
        "lore-client-admission-v1",
        "unsupported-client".parse().unwrap(),
    );
    status
}

#[tonic::async_trait]
impl Service for FixtureServer {
    type PutStream = Responses<storage_v1::PutResponse>;
    async fn put(
        &self,
        request: Request<Streaming<storage_v1::PutRequest>>,
    ) -> Result<Response<Self::PutStream>, Status> {
        self.observe(&request);
        if matches!(self.reply, Reply::Refusal) {
            return Err(refusal());
        }
        let attempt = request
            .metadata()
            .get("lore-attempt-id")
            .map(|v| Uuid::parse_str(v.to_str().unwrap()).unwrap());
        let managed = request
            .metadata()
            .contains_key("lore-caller-capabilities-v1");
        let mut requests = request.into_inner();
        let items = self.items.clone();
        let journal = self.journal.clone();
        let reply = self.reply;
        Ok(Response::new(Box::pin(async_stream::stream! {
            while let Some(Ok(item)) = requests.next().await {
                if managed {
                    let index = journal.records.lock().iter().position(|r| Some(r.attempt_id.as_uuid()) == attempt).expect("wire attempt already journaled");
                    let intent = journal.intents.lock()[index].clone();
                    let mut expected = item.clone();
                    expected.payload = expected.payload.map(|_| Bytes::new());
                    assert_eq!(intent.canonical_request, expected.encode_to_vec(), "persisted intent must describe the real wire request");
                }
                items.fetch_add(1, Ordering::SeqCst);
                match reply {
                    Reply::Loss => { yield Err(Status::unavailable("response lost")); return; }
                    Reply::Hold => { std::future::pending::<()>().await; }
                    Reply::ItemCancelled => yield Ok(storage_v1::PutResponse { address: item.address, status: Some(model_v1::ItemStatus { code: 1, message: "decisive per-item cancellation".into(), ..Default::default() }) }),
                    Reply::ItemAborted => yield Ok(storage_v1::PutResponse { address: item.address, status: Some(model_v1::ItemStatus { code: 10, message: "decisive per-item abort".into(), ..Default::default() }) }),
                    Reply::ItemUnknown(version, operation, attempt) => yield Ok(storage_v1::PutResponse { address: item.address, status: Some(model_v1::ItemStatus { code: 0, outcome_unknown_version: version, outcome_unknown_operation: operation.into(), outcome_unknown_attempt: attempt.into(), ..Default::default() }) }),
                    _ => yield Ok(storage_v1::PutResponse { address: item.address, status: None }),
                }
            }
        })))
    }
    type GetStream = Responses<storage_v1::GetResponse>;
    async fn get(
        &self,
        _: Request<Streaming<model_v1::Address>>,
    ) -> Result<Response<Self::GetStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
    type GetMetadataStream = Responses<storage_v1::GetResponse>;
    async fn get_metadata(
        &self,
        _: Request<Streaming<model_v1::Address>>,
    ) -> Result<Response<Self::GetMetadataStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
    type GetResolvedStream = Responses<storage_v1::GetResolvedResponse>;
    async fn get_resolved(
        &self,
        _: Request<Streaming<storage_v1::GetResolvedRequest>>,
    ) -> Result<Response<Self::GetResolvedStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
    type PutResolvedStream = Responses<storage_v1::PutResolvedResponse>;
    async fn put_resolved(
        &self,
        request: Request<Streaming<storage_v1::PutResolvedRequest>>,
    ) -> Result<Response<Self::PutResolvedStream>, Status> {
        self.observe(&request);
        let mut requests = request.into_inner();
        let items = self.items.clone();
        Ok(Response::new(Box::pin(async_stream::stream! {
            if requests.next().await.is_some() {
                items.fetch_add(1, Ordering::SeqCst);
                yield Err(Status::unavailable("resolved put response lost"));
            }
        })))
    }
    type CopyStream = Responses<storage_v1::CopyResponse>;
    async fn copy(
        &self,
        request: Request<Streaming<storage_v1::CopyRequest>>,
    ) -> Result<Response<Self::CopyStream>, Status> {
        self.observe(&request);
        let mut requests = request.into_inner();
        let items = self.items.clone();
        Ok(Response::new(Box::pin(async_stream::stream! {
            if requests.next().await.is_some() {
                items.fetch_add(1, Ordering::SeqCst);
                yield Err(Status::unavailable("copy response lost"));
            }
        })))
    }
    async fn query(
        &self,
        _: Request<storage_v1::QueryRequest>,
    ) -> Result<Response<storage_v1::QueryResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn verify(
        &self,
        request: Request<storage_v1::VerifyRequest>,
    ) -> Result<Response<storage_v1::VerifyResponse>, Status> {
        self.observe(&request);
        self.items.fetch_add(1, Ordering::SeqCst);
        Err(Status::unavailable("verify response lost"))
    }
    async fn mutable_load(
        &self,
        _: Request<storage_v1::MutableLoadRequest>,
    ) -> Result<Response<storage_v1::MutableLoadResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn mutable_store(
        &self,
        request: Request<storage_v1::MutableStoreRequest>,
    ) -> Result<Response<storage_v1::MutableStoreResponse>, Status> {
        self.observe(&request);
        self.items.fetch_add(1, Ordering::SeqCst);
        Err(Status::unavailable("mutable store response lost"))
    }
    async fn mutable_compare_and_swap(
        &self,
        request: Request<storage_v1::MutableCompareAndSwapRequest>,
    ) -> Result<Response<storage_v1::MutableCompareAndSwapResponse>, Status> {
        self.observe(&request);
        self.items.fetch_add(1, Ordering::SeqCst);
        Err(Status::unavailable("CAS response lost"))
    }
}

struct Fixture {
    service: StorageService,
    journal: Arc<Journal>,
    seen: Arc<parking_lot::Mutex<Vec<Seen>>>,
    items: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new(reply: Reply) -> Self {
        let journal = Arc::new(Journal::default());
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let items = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let service = FixtureServer {
            journal: journal.clone(),
            seen: seen.clone(),
            items: items.clone(),
            reply,
        };
        let server = lore_base::lore_spawn!(async move {
            tonic::transport::Server::builder()
                .add_service(StorageServiceServer::new(service))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let channel = tonic::transport::Channel::from_shared(url.clone())
            .unwrap()
            .connect()
            .await
            .unwrap();
        let channel = tower::ServiceBuilder::new()
            .layer(crate::grpc::RequestLoggerLayer {})
            .service(channel);
        let connection = Arc::new(crate::grpc::GRPCConnection::for_test(
            url.parse().unwrap(),
            channel,
        ));
        Self {
            service: StorageService::new(connection),
            journal,
            seen,
            items,
            server,
        }
    }
    fn operation(&self) -> CallerOperationContext {
        CallerOperationContext::new(
            Uuid::now_v7(),
            RepositoryId::from([0x11; 16]),
            self.journal.clone(),
        )
    }
    fn context(&self) -> GrpcSessionContext {
        GrpcSessionContext {
            partition: Partition::from(Context::from([0x11; 16])),
            correlation_id: "adoption-fixture".into(),
            auth_token: FIXTURE_TOKEN.into(),
        }
    }
    async fn put(&self, tag: u8) -> Result<(), ProtocolError> {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.service.put(
                0,
                &self.context(),
                Address::zero_context_hash(Hash::from([tag; 32])),
                Fragment {
                    flags: 0,
                    size_payload: 1,
                    size_content: 1,
                },
                Some(Bytes::from_static(b"x")),
            ),
        )
        .await
        .expect("bounded put")
    }
}

#[tokio::test]
async fn pooled_puts_do_not_leak_adoption_in_either_order() {
    for adopted_first in [false, true] {
        let f = Fixture::new(Reply::Success).await;
        for adopted in [adopted_first, !adopted_first, adopted_first] {
            let result = if adopted {
                with_caller_operation(f.operation(), f.put(1)).await
            } else {
                f.put(1).await
            };
            result.unwrap();
        }
        let seen = f.seen.lock();
        let adopted: Vec<_> = seen.iter().filter(|s| s.capability.is_some()).collect();
        assert_eq!(adopted.len(), if adopted_first { 2 } else { 1 });
        for observation in adopted {
            assert_eq!(
                observation.capability.as_deref(),
                Some("outcome_unknown_v1")
            );
            assert!(observation.journaled_before_body);
        }
        assert!(seen.iter().any(|s| s.capability.is_none()));
        assert_eq!(
            f.journal.records.lock().len(),
            if adopted_first { 2 } else { 1 }
        );
        assert_eq!(f.items.load(Ordering::SeqCst), 3);
    }
}

#[tokio::test]
async fn concurrent_same_address_mutations_have_distinct_journaled_ids() {
    let f = Fixture::new(Reply::Success).await;
    let (a, b, legacy) = tokio::join!(
        with_caller_operation(f.operation(), f.put(2)),
        with_caller_operation(f.operation(), f.put(2)),
        f.put(2)
    );
    a.unwrap();
    b.unwrap();
    legacy.unwrap();
    let seen = f.seen.lock();
    let adopted: Vec<_> = seen.iter().filter(|s| s.capability.is_some()).collect();
    assert_eq!(adopted.len(), 2);
    assert_ne!(adopted[0].attempt, adopted[1].attempt);
    assert!(adopted.iter().all(|s| s.journaled_before_body));
    assert_eq!(f.items.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn every_item_binds_to_the_same_explicit_parent_and_unique_child() {
    let f = Fixture::new(Reply::Success).await;
    let operation = f.operation();
    let parent = operation.parent_id();
    with_caller_operation(operation, async {
        f.put(21).await.unwrap();
        f.put(22).await.unwrap();
    })
    .await;
    let intents = f.journal.intents.lock();
    assert_eq!(intents.len(), 2);
    assert!(intents.iter().all(|intent| intent.parent_id == parent));
    assert_ne!(intents[0].canonical_request, intents[1].canonical_request);
    let seen = f.seen.lock();
    assert_ne!(seen[0].attempt, seen[1].attempt);
    assert_eq!(f.items.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn journal_failure_opens_no_rpc_and_enqueues_no_item() {
    let f = Fixture::new(Reply::Success).await;
    f.journal.fail_record.store(true, Ordering::SeqCst);
    let error = with_caller_operation(f.operation(), f.put(3))
        .await
        .unwrap_err();
    assert!(!error.is_outcome_unknown());
    assert!(f.seen.lock().is_empty());
    assert_eq!(f.items.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn put_response_loss_keeps_attempt_unresolved_without_replay() {
    let f = Fixture::new(Reply::Loss).await;
    let error = with_caller_operation(f.operation(), f.put(4))
        .await
        .unwrap_err();
    assert!(error.is_outcome_unknown(), "{error:?}");
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
    assert_eq!(f.seen.lock().len(), 1);
    assert_eq!(f.journal.unresolved().await.unwrap().len(), 1);
}

#[tokio::test]
async fn settlement_failure_after_success_keeps_unresolved_durable_state() {
    let f = Fixture::new(Reply::Success).await;
    f.journal.fail_settle.store(true, Ordering::SeqCst);
    let error = with_caller_operation(f.operation(), f.put(14))
        .await
        .unwrap_err();
    assert!(error.is_outcome_unknown(), "{error:?}");
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
    assert_eq!(f.journal.unresolved().await.unwrap().len(), 1);
}

#[tokio::test]
async fn exact_admission_refusal_is_decisive_with_no_body_effect() {
    let f = Fixture::new(Reply::Refusal).await;
    let error = with_caller_operation(f.operation(), f.put(5))
        .await
        .unwrap_err();
    assert!(crate::error::is_unsupported_client(&error), "{error:?}");
    assert!(!error.is_outcome_unknown());
    assert_eq!(f.items.load(Ordering::SeqCst), 0);
    assert_eq!(f.seen.lock().len(), 1);
    assert!(f.journal.unresolved().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_correlated_in_band_cancelled_response_is_decisive() {
    let f = Fixture::new(Reply::ItemCancelled).await;
    let error = with_caller_operation(f.operation(), f.put(15))
        .await
        .unwrap_err();
    assert!(
        !error.is_outcome_unknown(),
        "server answered this exact item: {error:?}"
    );
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
    assert!(f.journal.unresolved().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_legacy_store_cannot_implicitly_promise_managed_journaling() {
    let f = Fixture::new(Reply::Success).await;
    let operation = CallerOperationContext::new(
        Uuid::now_v7(),
        RepositoryId::from([0x11; 16]),
        Arc::new(VolatileAttemptStore::new()),
    );
    let error = with_caller_operation(operation, f.put(16))
        .await
        .unwrap_err();
    assert!(!error.is_outcome_unknown());
    assert!(f.seen.lock().is_empty());
    assert_eq!(f.items.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_unmarked_in_band_aborted_response_is_decisive() {
    let f = Fixture::new(Reply::ItemAborted).await;
    let error = with_caller_operation(f.operation(), f.put(16))
        .await
        .unwrap_err();
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
    assert!(f.journal.unresolved().await.unwrap().is_empty());
}

#[test]
fn item_parser_preserves_future_and_incomplete_uncertainty_before_ok() {
    assert!(item_status_error(None).is_none());
    assert!(item_status_error(Some(&model_v1::ItemStatus::ok())).is_none());
    for (version, operation, attempt) in [
        (1, "", ""),
        (77, "", ""),
        (0, "Copy", ""),
        (0, "", "attempt"),
    ] {
        let status = model_v1::ItemStatus {
            code: 0,
            outcome_unknown_version: version,
            outcome_unknown_operation: operation.into(),
            outcome_unknown_attempt: attempt.into(),
            ..Default::default()
        };
        let error = item_status_error(Some(&status)).expect("uncertain item cannot become success");
        assert!(error.is_outcome_unknown(), "{error:?}");
    }
}

#[tokio::test]
async fn future_and_incomplete_wire_markers_keep_the_managed_child_unresolved() {
    for (version, operation, attempt) in [
        (1, "", ""),
        (77, "", ""),
        (0, "Copy", ""),
        (0, "", "foreign-attempt"),
    ] {
        let f = Fixture::new(Reply::ItemUnknown(version, operation, attempt)).await;
        let error = with_caller_operation(f.operation(), f.put(17))
            .await
            .unwrap_err();
        let ProtocolError::OutcomeUnknown(unknown) = error else {
            panic!("marker must preserve semantic uncertainty: {error:?}");
        };
        let pending = f.journal.unresolved().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(unknown.attempt_id, pending[0].attempt_id.to_string());
        assert_eq!(f.items.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn missing_or_malformed_outgoing_namespace_refuses_before_record_or_rpc() {
    for token in ["", "not-a-jwt"] {
        let f = Fixture::new(Reply::Success).await;
        let mut ctx = f.context();
        ctx.auth_token = token.into();
        let error = with_caller_operation(
            f.operation(),
            f.service.put(
                0,
                &ctx,
                Address::zero_context_hash(Hash::from([25; 32])),
                Fragment {
                    flags: 0,
                    size_payload: 1,
                    size_content: 1,
                },
                Some(Bytes::from_static(b"x")),
            ),
        )
        .await
        .unwrap_err();
        assert!(!error.is_outcome_unknown());
        assert!(f.journal.records.lock().is_empty());
        assert!(f.seen.lock().is_empty());
        assert_eq!(f.items.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn journal_names_the_exact_outgoing_credential_namespace_without_bearer_bytes() {
    let f = Fixture::new(Reply::Success).await;
    with_caller_operation(f.operation(), f.put(26))
        .await
        .unwrap();
    let intents = f.journal.intents.lock();
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].verified_issuer, "https://fixture.invalid/issuer");
    assert_eq!(intents[0].authenticated_subject, "fixture-user");
    assert_eq!(intents[0].caller_capabilities, "outcome_unknown_v1");
    assert!(intents[0].endpoint.starts_with("http://127.0.0.1:"));
    assert!(!format!("{:?}", intents[0]).contains(FIXTURE_TOKEN));
}

#[tokio::test]
async fn parent_rejects_principal_rotation_but_allows_same_principal_refresh() {
    const OTHER: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJvdGhlci11c2VyIiwibmFtZSI6ImZpeHR1cmUtdXNlciIsImV4cCI6NDEwMjQ0NDgwMCwiYXVkIjoiZml4dHVyZSJ9.eA";
    const REFRESHED: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJmaXh0dXJlLXVzZXIiLCJuYW1lIjoicmVuYW1lZC11c2VyIiwiZXhwIjo0MTAyNDQ0OTAwLCJhdWQiOiJmaXh0dXJlIn0.eA";
    let f = Fixture::new(Reply::Success).await;
    with_caller_operation(f.operation(), async {
        f.put(27).await.unwrap();
        let mut ctx = f.context();
        ctx.auth_token = OTHER.into();
        let result = f
            .service
            .put(
                0,
                &ctx,
                Address::zero_context_hash(Hash::from([28; 32])),
                Fragment {
                    flags: 0,
                    size_payload: 1,
                    size_content: 1,
                },
                Some(Bytes::from_static(b"x")),
            )
            .await;
        assert!(
            result.is_err(),
            "changing principal under one parent must refuse before dispatch"
        );
        assert_eq!(f.items.load(Ordering::SeqCst), 1);
        assert_eq!(f.journal.records.lock().len(), 1);
        ctx.auth_token = REFRESHED.into();
        f.service
            .put(
                0,
                &ctx,
                Address::zero_context_hash(Hash::from([29; 32])),
                Fragment {
                    flags: 0,
                    size_payload: 1,
                    size_content: 1,
                },
                Some(Bytes::from_static(b"x")),
            )
            .await
            .unwrap();
    })
    .await;
    assert_eq!(f.items.load(Ordering::SeqCst), 2);
    assert_eq!(f.journal.records.lock().len(), 2);
}

#[tokio::test]
async fn cancelling_after_server_reads_item_keeps_attempt_unresolved() {
    let f = Fixture::new(Reply::Hold).await;
    let mut put = Box::pin(with_caller_operation(f.operation(), f.put(6)));
    tokio::select! {
        result = &mut put => panic!("holding server unexpectedly returned {result:?}"),
        _ = tokio::time::timeout(Duration::from_secs(5), async {
            while f.items.load(Ordering::SeqCst) == 0 { tokio::task::yield_now().await; }
        }) => {}
    }
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
    drop(put);
    assert_eq!(f.journal.unresolved().await.unwrap().len(), 1);
}

#[tokio::test]
async fn reconnect_retains_only_the_current_callers_declaration() {
    let f = Fixture::new(Reply::Success).await;
    with_caller_operation(f.operation(), f.put(7))
        .await
        .unwrap();
    let epoch = f.service.connection.reconnect.load(Ordering::SeqCst);
    f.service.connection.reconnect(epoch).await.unwrap();
    f.put(8).await.unwrap();
    with_caller_operation(f.operation(), f.put(9))
        .await
        .unwrap();
    let seen = f.seen.lock();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].capability.as_deref(), Some("outcome_unknown_v1"));
    assert!(seen[1].capability.is_none());
    assert_eq!(seen[2].capability.as_deref(), Some("outcome_unknown_v1"));
    assert_ne!(seen[0].attempt, seen[2].attempt);
    assert!(seen[2].journaled_before_body);
}

#[tokio::test]
async fn healing_verify_response_loss_is_unknown_and_read_verify_records_nothing() {
    let f = Fixture::new(Reply::Loss).await;
    let address = Address::zero_context_hash(Hash::from([10; 32]));
    let ctx = f.context();
    let error = with_caller_operation(f.operation(), f.service.verify(&ctx, &address, true))
        .await
        .unwrap_err();
    assert!(error.is_outcome_unknown(), "{error:?}");
    assert_eq!(f.journal.unresolved().await.unwrap().len(), 1);
    let error = with_caller_operation(f.operation(), f.service.verify(&ctx, &address, false))
        .await
        .unwrap_err();
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert_eq!(f.journal.records.lock().len(), 1);
    assert_eq!(f.items.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn copy_response_loss_is_unknown_and_is_not_resent() {
    let f = Fixture::new(Reply::Loss).await;
    let ctx = f.context();
    let error = with_caller_operation(
        f.operation(),
        f.service.copy(
            0,
            &ctx,
            ctx.partition,
            Address::zero_context_hash(Hash::from([11; 32])),
            Context::from([12; 16]),
        ),
    )
    .await
    .unwrap_err();
    assert!(error.is_outcome_unknown(), "{error:?}");
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
    assert_eq!(f.seen.lock().len(), 1);
    assert_eq!(f.journal.unresolved().await.unwrap().len(), 1);
}

#[tokio::test]
async fn resolved_put_and_mutable_unaries_journal_before_loss_without_replay() {
    for operation in [
        "StorageService.PutResolved",
        "StorageService.MutableStore",
        "StorageService.MutableCompareAndSwap",
    ] {
        let f = Fixture::new(Reply::Loss).await;
        let ctx = f.context();
        let key = Hash::from([31; 32]);
        let value = Hash::from([32; 32]);
        let error = with_caller_operation(f.operation(), async {
            match operation {
                "StorageService.PutResolved" => {
                    f.service
                        .put_resolved(
                            0,
                            &ctx,
                            &key,
                            Address::zero_context_hash(value),
                            Fragment {
                                flags: 0,
                                size_payload: 1,
                                size_content: 1,
                            },
                            Some(Bytes::from_static(b"x")),
                        )
                        .await
                }
                "StorageService.MutableStore" => {
                    f.service
                        .mutable_store(&ctx, key, value, KeyType::Resolve)
                        .await
                }
                _ => f
                    .service
                    .mutable_compare_and_swap(&ctx, key, key, value, KeyType::Resolve)
                    .await
                    .map(|_| ()),
            }
        })
        .await
        .unwrap_err();
        assert!(error.is_outcome_unknown(), "{operation}: {error:?}");
        let unresolved = f.journal.unresolved().await.unwrap();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].operation, operation);
        assert_eq!(f.items.load(Ordering::SeqCst), 1);
        let seen = f.seen.lock();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].journaled_before_body);
        assert_eq!(seen[0].attempt, Some(unresolved[0].attempt_id.as_uuid()));
    }
}
