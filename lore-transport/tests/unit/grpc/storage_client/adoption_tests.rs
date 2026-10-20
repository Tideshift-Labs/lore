// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] Managed declarations against a real disposable tonic server.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_base::types::Partition;
use lore_base::types::RepositoryId;
use lore_proto::lore::model::v1 as model_v1;
use lore_proto::lore::storage::v1 as storage_v1;
use lore_proto::lore::storage::v1::storage_service_server::StorageService as Service;
use lore_proto::lore::storage::v1::storage_service_server::StorageServiceServer;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::LockOwnership;
use lore_transport::attempt_store::VolatileAttemptStore;
use lore_transport::caller_operation::CallerOperationContext;
use lore_transport::caller_operation::ManagedAttemptIntent;
use lore_transport::caller_operation::with_caller_operation;
use lore_transport::error::ProtocolError;
use lore_transport::grpc::storage_client::*;
use lore_transport::outcome::AttemptId;
use prost::Message;
use tokio_stream::StreamExt;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;
use uuid::Uuid;

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
    /// Never return from the first Put open: no response headers, so a client request occupies
    /// the channel. Later opens are answered normally.
    StallOpen,
    /// Answer after this pause. The client channel also admits one request at a time, so the
    /// others queue on the client before the transport takes their message.
    Paced(Duration),
    /// The server serialises Puts on a mutex and answers each after this pause once it holds it.
    Serialized(Duration),
    /// Answer after this pause; the server admits one HTTP/2 stream at a time.
    OneStream(Duration),
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
    gate: Arc<tokio::sync::Mutex<()>>,
    /// Ends the stalled first open (see `Reply::StallOpen`), freeing the client's slot.
    release: Arc<tokio::sync::Notify>,
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
        // Only the first open stalls; a later one is served, so a message that leaks onto a
        // freed slot is read and counted.
        if matches!(self.reply, Reply::StallOpen) && self.seen.lock().len() == 1 {
            self.release.notified().await;
            return Err(Status::unavailable("slot released"));
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
        let gate = self.gate.clone();
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
                    Reply::Serialized(pause) => {
                        let _turn = gate.lock().await;
                        tokio::time::sleep(pause).await;
                        yield Ok(storage_v1::PutResponse { address: item.address, status: None });
                    }
                    Reply::OneStream(pause) => {
                        tokio::time::sleep(pause).await;
                        yield Ok(storage_v1::PutResponse { address: item.address, status: None });
                    }
                    Reply::Paced(pause) => {
                        tokio::time::sleep(pause).await;
                        yield Ok(storage_v1::PutResponse { address: item.address, status: None });
                    }
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
    release: Arc<tokio::sync::Notify>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new(reply: Reply) -> Self {
        Self::with_idle(reply, None).await
    }
    async fn with_idle(reply: Reply, idle: Option<Duration>) -> Self {
        let journal = Arc::new(Journal::default());
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let items = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let service = FixtureServer {
            journal: journal.clone(),
            seen: seen.clone(),
            items: items.clone(),
            reply,
            gate: Arc::default(),
            release: release.clone(),
        };
        let server = lore_base::lore_spawn!(async move {
            tonic::transport::Server::builder()
                .max_concurrent_streams(matches!(reply, Reply::OneStream(_)).then_some(1))
                .add_service(StorageServiceServer::new(service))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let mut endpoint = tonic::transport::Channel::from_shared(url.clone()).unwrap();
        if matches!(reply, Reply::Paced(_) | Reply::StallOpen) {
            endpoint = endpoint.concurrency_limit(1);
        }
        let channel = endpoint.connect().await.unwrap();
        let channel = tower::ServiceBuilder::new()
            .layer(lore_transport::grpc::RequestLoggerLayer {})
            .service(channel);
        let connection = Arc::new(lore_transport::grpc::GRPCConnection::for_test(
            url.parse().unwrap(),
            channel,
        ));
        let service = StorageService::new(connection);
        let service = match idle {
            Some(idle) => service.with_stream_idle_timeout(idle),
            None => service,
        };
        Self {
            service,
            journal,
            seen,
            items,
            release,
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
    #[allow(clippy::unused_self)] // Reads as a method of the fixture beside its siblings.
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
    assert!(
        lore_transport::error::is_unsupported_client(&error),
        "{error:?}"
    );
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
    let epoch = f
        .service
        .connection_for_test()
        .reconnect
        .load(Ordering::SeqCst);
    f.service
        .connection_for_test()
        .reconnect(epoch)
        .await
        .unwrap();
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

/// A managed single-message Put whose answer never comes is bounded by the idle duration and
/// reads as an unknown outcome; the journal keeps the attempt unresolved. Pre-change the put
/// waits forever (the fixture's own 5 s bound then fails the test).
#[tokio::test]
async fn silent_managed_put_is_bounded_unknown_and_stays_unresolved() {
    let f = Fixture::with_idle(Reply::Hold, Some(Duration::from_secs(1))).await;
    let started = std::time::Instant::now();
    let error = with_caller_operation(f.operation(), f.put(40))
        .await
        .unwrap_err();
    assert!(error.is_outcome_unknown(), "{error:?}");
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "must wait out the idle bound, took {:?}",
        started.elapsed()
    );
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
    assert_eq!(f.journal.unresolved().await.unwrap().len(), 1);
}

/// Time spent queued behind other uploads is not idleness: 8 concurrent managed Puts against a
/// server that answers one Put per 300 ms (idle 1 s) all succeed, although the last waits 2.4 s.
/// Measured before the fix: 3 Ok, 5 unknown outcomes.
#[tokio::test]
async fn queued_managed_puts_are_not_cut_by_the_idle_bound() {
    let f = Fixture::with_idle(
        Reply::Paced(Duration::from_millis(300)),
        Some(Duration::from_secs(1)),
    )
    .await;
    let results = futures::future::join_all(
        (0..8u8).map(|tag| with_caller_operation(f.operation(), f.put(50 + tag))),
    )
    .await;
    for result in results {
        result.expect("a queued managed put must succeed");
    }
    assert_eq!(f.items.load(Ordering::SeqCst), 8);
    assert!(f.journal.unresolved().await.unwrap().is_empty());
}

async fn eight_queued_managed_puts(reply: Reply) {
    let f = Fixture::with_idle(reply, Some(Duration::from_secs(1))).await;
    // Warm-up: let the server's SETTINGS (one stream at a time) reach the client first. A burst
    // sent before them is refused by the server with REFUSED_STREAM, which is not queueing.
    // Managed, so its stream closes: a pooled plain Put would hold the only slot.
    with_caller_operation(f.operation(), f.put(59))
        .await
        .unwrap();
    let results = futures::future::join_all(
        (0..8u8).map(|tag| with_caller_operation(f.operation(), f.put(60 + tag))),
    )
    .await;
    for result in results {
        let ok = result.as_ref().is_ok();
        assert!(
            ok,
            "a put queued behind others must succeed: {:?}",
            result.err()
        );
    }
    assert_eq!(f.items.load(Ordering::SeqCst), 9, "warm-up plus eight");
    assert!(f.journal.unresolved().await.unwrap().is_empty());
}

/// The server serialises Puts on a mutex and answers each 300 ms after taking it. The shared
/// progress clock moves with every answer, so the queue is not silence.
#[tokio::test]
async fn server_side_mutex_queue_does_not_cut_managed_puts() {
    eight_queued_managed_puts(Reply::Serialized(Duration::from_millis(300))).await;
}

/// The same with the server admitting one HTTP/2 stream at a time.
#[tokio::test]
async fn single_stream_server_queue_does_not_cut_managed_puts() {
    eight_queued_managed_puts(Reply::OneStream(Duration::from_millis(300))).await;
}

/// No stream slot: the channel admits one request at a time and a stalled open holds it, so a
/// managed Put's message is never taken. After the idle bound the attempt is settled `NotApplied`
/// and the call returns `Disconnected` for the reconnect layer; never Unresolved or an unknown
/// outcome, and never a hang. The server sees no Put message at all.
///
/// A peer that advertises `max_concurrent_streams(0)` behaves the same way: the body is never
/// polled, so the Put is not sent (observed by the third review pass: `Disconnected`, `NotApplied`).
#[tokio::test]
async fn managed_put_with_no_stream_slot_is_not_applied_and_disconnected() {
    let f = Fixture::with_idle(Reply::StallOpen, Some(Duration::from_secs(1))).await;
    // A second service on the same channel, with the default 60 s idle, holds the only slot.
    let blocker = Arc::new(StorageService::new(f.service.connection_for_test().clone()));
    let blocker_ctx = f.context();
    #[allow(clippy::disallowed_methods)] // Test-local slot holder.
    let held = tokio::spawn({
        let blocker = blocker.clone();
        async move {
            let _ = blocker
                .put(
                    0,
                    &blocker_ctx,
                    Address::zero_context_hash(Hash::from([69; 32])),
                    Fragment {
                        flags: 0,
                        size_payload: 1,
                        size_content: 1,
                    },
                    Some(Bytes::from_static(b"x")),
                )
                .await;
        }
    });
    while f.seen.lock().is_empty() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let operation = f.operation();
    let started = std::time::Instant::now();
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        with_caller_operation(
            operation,
            f.service.put(
                0,
                &f.context(),
                Address::zero_context_hash(Hash::from([70; 32])),
                Fragment {
                    flags: 0,
                    size_payload: 1,
                    size_content: 1,
                },
                Some(Bytes::from_static(b"x")),
            ),
        ),
    )
    .await
    .expect("a slot that never comes must not hang the put")
    .unwrap_err();
    assert!(error.is_disconnected(), "{error:?}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(f.journal.unresolved().await.unwrap().is_empty());
    let records = f.journal.records.lock().clone();
    assert_eq!(records.len(), 1);
    let record = f
        .journal
        .lookup(&records[0].attempt_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.state,
        lore_transport::attempt_store::AttemptState::Resolved(AttemptResolution::NotApplied)
    );
    assert_eq!(
        f.items.load(Ordering::SeqCst),
        0,
        "no Put message reached the server"
    );
    assert_eq!(
        f.seen.lock().len(),
        1,
        "only the slot holder's open arrived"
    );
    held.abort();
}

/// One round: the slot is held, a managed Put is abandoned unsent, then the slot is freed.
async fn abandoned_put_round(tag: u8) {
    let f = Fixture::with_idle(Reply::StallOpen, Some(Duration::from_secs(1))).await;
    let blocker = Arc::new(StorageService::new(f.service.connection_for_test().clone()));
    let blocker_ctx = f.context();
    #[allow(clippy::disallowed_methods)] // Test-local slot holder.
    let held = tokio::spawn({
        let blocker = blocker.clone();
        async move {
            let _ = blocker
                .put(
                    0,
                    &blocker_ctx,
                    Address::zero_context_hash(Hash::from([tag; 32])),
                    Fragment {
                        flags: 0,
                        size_payload: 1,
                        size_content: 1,
                    },
                    Some(Bytes::from_static(b"x")),
                )
                .await;
        }
    });
    while f.seen.lock().is_empty() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        with_caller_operation(
            f.operation(),
            f.service.put(
                0,
                &f.context(),
                Address::zero_context_hash(Hash::from([tag.wrapping_add(100); 32])),
                Fragment {
                    flags: 0,
                    size_payload: 1,
                    size_content: 1,
                },
                Some(Bytes::from_static(b"x")),
            ),
        ),
    )
    .await
    .expect("a slot that never comes must not hang the put")
    .unwrap_err();
    assert!(error.is_disconnected(), "round {tag}: {error:?}");
    let records = f.journal.records.lock().clone();
    assert_eq!(records.len(), 1, "round {tag}");
    let record = f
        .journal
        .lookup(&records[0].attempt_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.state,
        lore_transport::attempt_store::AttemptState::Resolved(AttemptResolution::NotApplied),
        "round {tag}"
    );
    // Free the slot: the server ends the stalled open.
    f.release.notify_one();
    let _ = held.await;
    drop(blocker);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        f.items.load(Ordering::SeqCst),
        0,
        "round {tag}: an abandoned put's message reached the server once the slot freed"
    );
    // The slot really is free: a fresh put goes through, and is the only message the server
    // ever read.
    with_caller_operation(f.operation(), f.put(tag.wrapping_add(50)))
        .await
        .unwrap_or_else(|e| panic!("round {tag}: the freed slot did not serve a fresh put: {e:?}"));
    assert_eq!(f.items.load(Ordering::SeqCst), 1, "round {tag}");
    assert!(
        f.journal.unresolved().await.unwrap().is_empty(),
        "round {tag}"
    );
}

/// An abandoned managed Put (settled `NotApplied`, returned `Disconnected`) must never be sent
/// afterwards, when the slot it was queued for finally frees: the reconnect layer may resend it
/// under a fresh attempt, and a leaked original would apply twice. The leak was a race, so the
/// case runs many times at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_managed_put_is_never_sent_when_the_slot_frees() {
    futures::future::join_all((0..10u8).map(abandoned_put_round)).await;
}
