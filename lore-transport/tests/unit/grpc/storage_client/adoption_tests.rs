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
use lore_transport::outcome::GrpcRpc;
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
    /// Count the Put streams open at once (from handler entry to the answer being sent), holding
    /// each for this pause before it answers.
    Gauge(Duration),
    /// Fail the response stream with a stream-fatal status that names its cause.
    Fatal,
    /// End the response stream cleanly without sending any message.
    Ended,
    /// Answer at once, then end the response stream only after this pause, so the trailers reach
    /// the client late.
    LateTrailers(Duration),
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
    /// Put streams open now, and the most that were ever open at once (see `Reply::Gauge`).
    open: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
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
        let open = self.open.clone();
        if matches!(reply, Reply::Gauge(_)) {
            let now = open.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
        }
        Ok(Response::new(Box::pin(async_stream::stream! {
            while let Some(Ok(item)) = requests.next().await {
                if managed {
                    // A fragment Put writes no journal child: its wire attempt id is minted for
                    // correlation only and is never in the journal.
                    assert!(attempt.is_some(), "a managed Put still carries an attempt id");
                    assert!(
                        !journal.records.lock().iter().any(|r| Some(r.attempt_id.as_uuid()) == attempt),
                        "a managed Put must not be journaled"
                    );
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
                    Reply::Gauge(pause) => {
                        tokio::time::sleep(pause).await;
                        open.fetch_sub(1, Ordering::SeqCst);
                        yield Ok(storage_v1::PutResponse { address: item.address, status: None });
                    }
                    Reply::Fatal => { yield Err(Status::internal("disk exploded")); return; }
                    Reply::Ended => { return; }
                    Reply::LateTrailers(pause) => {
                        yield Ok(storage_v1::PutResponse { address: item.address, status: None });
                        tokio::time::sleep(pause).await;
                        return;
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
        if matches!(self.reply, Reply::Refusal) {
            return Err(refusal());
        }
        let mut requests = request.into_inner();
        let items = self.items.clone();
        let reply = self.reply;
        Ok(Response::new(Box::pin(async_stream::stream! {
            if let Some(Ok(item)) = requests.next().await {
                items.fetch_add(1, Ordering::SeqCst);
                match reply {
                    Reply::Success => yield Ok(storage_v1::PutResolvedResponse { request_id: item.request_id, status: None }),
                    Reply::ItemCancelled => yield Ok(storage_v1::PutResolvedResponse { request_id: item.request_id, status: Some(model_v1::ItemStatus { code: 1, message: "decisive per-item cancellation".into(), ..Default::default() }) }),
                    // An answer for some other request is a lost answer, not this one's.
                    Reply::ItemUnknown(..) => yield Ok(storage_v1::PutResolvedResponse { request_id: item.request_id.wrapping_add(1), status: None }),
                    Reply::Ended => {}
                    _ => yield Err(Status::unavailable("resolved put response lost")),
                }
            }
        })))
    }
    type CopyStream = Responses<storage_v1::CopyResponse>;
    async fn copy(
        &self,
        request: Request<Streaming<storage_v1::CopyRequest>>,
    ) -> Result<Response<Self::CopyStream>, Status> {
        self.observe(&request);
        if matches!(self.reply, Reply::Refusal) {
            return Err(refusal());
        }
        let mut requests = request.into_inner();
        let items = self.items.clone();
        let reply = self.reply;
        Ok(Response::new(Box::pin(async_stream::stream! {
            if let Some(Ok(item)) = requests.next().await {
                items.fetch_add(1, Ordering::SeqCst);
                let answer = |address: Option<model_v1::Address>, status: Option<model_v1::ItemStatus>| storage_v1::CopyResponse {
                    source_repository_id: item.source_repository_id.clone(),
                    source_address: address,
                    status,
                };
                match reply {
                    Reply::Success => yield Ok(answer(item.source_address.clone(), None)),
                    Reply::ItemCancelled => yield Ok(answer(item.source_address.clone(), Some(model_v1::ItemStatus { code: 1, message: "decisive per-item cancellation".into(), ..Default::default() }))),
                    // An answer naming another address is a lost answer, not this one's.
                    Reply::ItemUnknown(..) => yield Ok(answer(Some(Address::zero_context_hash(Hash::from([0xEE; 32])).into()), None)),
                    Reply::Ended => {}
                    _ => yield Err(Status::unavailable("copy response lost")),
                }
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
    peak: Arc<AtomicUsize>,
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
        Self::build(reply, idle, None).await
    }
    /// A service whose managed Put budget is `slots`.
    async fn with_slots(reply: Reply, slots: u32) -> Self {
        Self::build(reply, None, Some(slots)).await
    }
    async fn build(reply: Reply, idle: Option<Duration>, slots: Option<u32>) -> Self {
        let peak = Arc::new(AtomicUsize::new(0));
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
            open: Arc::default(),
            peak: peak.clone(),
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
        let service = match slots {
            Some(slots) => service.with_managed_put_slots(slots),
            None => service,
        };
        Self {
            service,
            journal,
            seen,
            items,
            release,
            peak,
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
    /// A Copy of one source address into the fixture's own repository.
    async fn copy(&self, tag: u8) -> Result<(), ProtocolError> {
        let ctx = self.context();
        tokio::time::timeout(
            Duration::from_secs(5),
            self.service.copy(
                0,
                &ctx,
                ctx.partition,
                Address::zero_context_hash(Hash::from([tag; 32])),
                Context::from([0x12; 16]),
            ),
        )
        .await
        .expect("bounded copy")
    }
    /// A `PutResolved` of one key.
    async fn put_resolved(&self, tag: u8) -> Result<(), ProtocolError> {
        let ctx = self.context();
        tokio::time::timeout(
            Duration::from_secs(5),
            self.service.put_resolved(
                0,
                &ctx,
                &Hash::from([tag; 32]),
                Address::zero_context_hash(Hash::from([tag.wrapping_add(1); 32])),
                Fragment {
                    flags: 0,
                    size_payload: 1,
                    size_content: 1,
                },
                Some(Bytes::from_static(b"x")),
            ),
        )
        .await
        .expect("bounded put_resolved")
    }
    /// A managed Put of `len` payload bytes, for the slot weighting.
    async fn put_sized(&self, tag: u8, len: usize) -> Result<(), ProtocolError> {
        let size = u32::try_from(len).unwrap();
        tokio::time::timeout(
            Duration::from_secs(30),
            with_caller_operation(
                self.operation(),
                self.service.put(
                    0,
                    &self.context(),
                    Address::zero_context_hash(Hash::from([tag; 32])),
                    Fragment {
                        flags: 0,
                        size_payload: size,
                        size_content: u64::from(size),
                    },
                    Some(Bytes::from(vec![0u8; len])),
                ),
            ),
        )
        .await
        .expect("bounded sized put")
    }
    /// A still-journaled managed mutation, for the generic journal properties a Put no longer
    /// carries. The fixture server loses its answer, so the call is always an unknown outcome.
    async fn journaled_mutation(
        &self,
        ctx: &GrpcSessionContext,
        tag: u8,
    ) -> Result<(), ProtocolError> {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.service.mutable_store(
                ctx,
                Hash::from([tag; 32]),
                Hash::from([tag.wrapping_add(1); 32]),
                KeyType::Resolve,
            ),
        )
        .await
        .expect("bounded mutable store")
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
            assert!(observation.attempt.is_some());
            assert!(!observation.journaled_before_body);
        }
        assert!(seen.iter().any(|s| s.capability.is_none()));
        assert!(f.journal.records.lock().is_empty());
        assert_eq!(f.items.load(Ordering::SeqCst), 3);
    }
}

#[tokio::test]
async fn concurrent_same_address_puts_have_distinct_unjournaled_ids() {
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
    assert!(adopted.iter().all(|s| s.attempt.is_some()));
    assert!(adopted.iter().all(|s| !s.journaled_before_body));
    assert!(f.journal.records.lock().is_empty());
    assert_eq!(f.items.load(Ordering::SeqCst), 3);
}

/// A managed Put writes nothing to the journal on success, yet still declares the capability and
/// carries a fresh attempt id on every call.
#[tokio::test]
async fn managed_put_records_nothing_but_still_declares_and_mints_an_attempt_id() {
    let f = Fixture::new(Reply::Success).await;
    let operation = f.operation();
    with_caller_operation(operation, async {
        f.put(21).await.unwrap();
        f.put(22).await.unwrap();
        f.put(21).await.unwrap();
    })
    .await;
    assert!(f.journal.records.lock().is_empty());
    assert!(f.journal.intents.lock().is_empty());
    assert!(f.journal.unresolved().await.unwrap().is_empty());
    let seen = f.seen.lock();
    assert_eq!(seen.len(), 3);
    for observation in seen.iter() {
        assert_eq!(
            observation.capability.as_deref(),
            Some("outcome_unknown_v1")
        );
        assert!(observation.attempt.is_some());
    }
    assert_ne!(seen[0].attempt, seen[1].attempt);
    assert_ne!(
        seen[0].attempt, seen[2].attempt,
        "same address, new attempt"
    );
    assert_ne!(seen[1].attempt, seen[2].attempt);
    assert_eq!(f.items.load(Ordering::SeqCst), 3);
}

/// The generic journal properties below used to ride on Put; they now use a still-journaled
/// RPC (`MutableStore`). Every journaled child binds to the one explicit parent.
#[tokio::test]
async fn every_item_binds_to_the_same_explicit_parent_and_unique_child() {
    let f = Fixture::new(Reply::Success).await;
    let operation = f.operation();
    let parent = operation.parent_id();
    let ctx = f.context();
    with_caller_operation(operation, async {
        let _ = f.journaled_mutation(&ctx, 21).await;
        let _ = f.journaled_mutation(&ctx, 22).await;
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
    let ctx = f.context();
    let error = with_caller_operation(f.operation(), f.journaled_mutation(&ctx, 3))
        .await
        .unwrap_err();
    assert!(!error.is_outcome_unknown());
    assert!(f.seen.lock().is_empty());
    assert_eq!(f.items.load(Ordering::SeqCst), 0);
}

/// A journal that fails to record or settle is irrelevant to a Put: it never touches the store.
#[tokio::test]
async fn put_does_not_depend_on_the_journal_working() {
    let f = Fixture::new(Reply::Success).await;
    f.journal.fail_record.store(true, Ordering::SeqCst);
    f.journal.fail_settle.store(true, Ordering::SeqCst);
    with_caller_operation(f.operation(), f.put(14))
        .await
        .unwrap();
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
    assert!(f.journal.records.lock().is_empty());
}

/// A lost answer is a plain retryable failure of the push: not an unknown outcome (which would
/// hold the fence), not `Disconnected` (which the reconnect layer would resend), and the one
/// message is sent exactly once. Nothing is recorded.
#[tokio::test]
async fn put_response_loss_is_a_retryable_internal_error_without_replay_or_journal() {
    let f = Fixture::new(Reply::Loss).await;
    let error = with_caller_operation(f.operation(), f.put(4))
        .await
        .unwrap_err();
    assert!(matches!(error, ProtocolError::Internal(_)), "{error:?}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(!error.is_disconnected(), "{error:?}");
    let text = error.to_string();
    assert!(
        text.contains("StorageService.Put") && text.contains("lost its answer"),
        "{text}"
    );
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
    assert_eq!(f.seen.lock().len(), 1, "exactly one wire request");
    assert!(f.journal.records.lock().is_empty());
    assert!(f.journal.unresolved().await.unwrap().is_empty());
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
    assert_eq!(
        f.seen.lock()[0].capability.as_deref(),
        Some("outcome_unknown_v1")
    );
    assert!(f.journal.records.lock().is_empty());
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
    let ctx = f.context();
    let error = with_caller_operation(operation, f.journaled_mutation(&ctx, 16))
        .await
        .unwrap_err();
    assert!(!error.is_outcome_unknown());
    assert!(f.seen.lock().is_empty());
    assert_eq!(f.items.load(Ordering::SeqCst), 0);
}

/// A managed Put whose session partition differs from the operation's repository is refused
/// before anything is sent or written.
#[tokio::test]
async fn managed_put_for_another_repository_is_refused_with_no_wire_request_or_journal_write() {
    let f = Fixture::new(Reply::Success).await;
    let mut ctx = f.context();
    ctx.partition = Partition::from(Context::from([0x22; 16]));
    let error = with_caller_operation(
        f.operation(),
        f.service.put(
            0,
            &ctx,
            Address::zero_context_hash(Hash::from([71; 32])),
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
    assert!(
        error.to_string().contains("repository mismatch"),
        "{error:?}"
    );
    assert!(!error.is_outcome_unknown());
    assert!(!error.is_disconnected());
    assert!(f.seen.lock().is_empty(), "no wire request");
    assert_eq!(f.items.load(Ordering::SeqCst), 0);
    assert!(f.journal.records.lock().is_empty());
}

/// A Put records nothing, so it does not need a journal that can promise managed journaling.
#[tokio::test]
async fn a_legacy_store_does_not_stop_an_unjournaled_put() {
    let f = Fixture::new(Reply::Success).await;
    let operation = CallerOperationContext::new(
        Uuid::now_v7(),
        RepositoryId::from([0x11; 16]),
        Arc::new(VolatileAttemptStore::new()),
    );
    with_caller_operation(operation, f.put(16)).await.unwrap();
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_unmarked_in_band_aborted_response_is_decisive() {
    let f = Fixture::new(Reply::ItemAborted).await;
    let error = with_caller_operation(f.operation(), f.put(16))
        .await
        .unwrap_err();
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
    assert!(f.journal.records.lock().is_empty());
    assert!(f.journal.unresolved().await.unwrap().is_empty());
}

/// The mapping of a managed Put, Copy or `PutResolved` wire result: every way of losing the answer
/// becomes the same retryable internal error that names its RPC and carries the lost-answer mark,
/// and decisive refusals pass through untouched and unmarked.
#[test]
fn unjournaled_result_maps_lost_answers_and_passes_decisive_errors_through() {
    for rpc in [
        GrpcRpc::StoragePut,
        GrpcRpc::StorageCopy,
        GrpcRpc::StoragePutResolved,
    ] {
        let attempt = AttemptId::new();
        assert!(unjournaled_result(rpc, Ok(()), &attempt).is_ok());
        let lost = [
            lore_transport::outcome::outcome_unknown(rpc.wire_name(), &attempt),
            ProtocolError::from(lore_base::error::Disconnected),
            ProtocolError::from(Status::cancelled("answer lost")),
            ProtocolError::from(Status::deadline_exceeded("answer lost")),
        ];
        for error in lost {
            let shown = format!("{error:?}");
            let mapped = unjournaled_result(rpc, Err(error), &attempt).unwrap_err();
            assert!(
                matches!(mapped, ProtocolError::Internal(_)),
                "{rpc:?}: {shown} -> {mapped:?}"
            );
            assert!(
                !mapped.is_outcome_unknown(),
                "{rpc:?}: {shown} -> {mapped:?}"
            );
            assert!(!mapped.is_disconnected(), "{rpc:?}: {shown} -> {mapped:?}");
            assert!(
                lore_transport::is_unjournaled_answer_lost(&mapped),
                "{rpc:?}: {shown} -> {mapped:?}"
            );
            let text = mapped.to_string();
            assert!(text.contains(rpc.wire_name()), "{text}");
            assert!(
                text.contains(&format!("attempt {attempt} lost its answer")),
                "{text}"
            );
            assert!(text.contains("Pushing again is safe"), "{text}");
        }
        let refused =
            unjournaled_result(rpc, Err(ProtocolError::from(refusal())), &attempt).unwrap_err();
        assert!(
            lore_transport::error::is_unsupported_client(&refused),
            "{rpc:?}: {refused:?}"
        );
        assert!(!lore_transport::is_unjournaled_answer_lost(&refused));
        let denied = unjournaled_result(
            rpc,
            Err(ProtocolError::from(Status::permission_denied("no"))),
            &attempt,
        )
        .unwrap_err();
        assert!(
            matches!(denied, ProtocolError::NotAuthorized(_)),
            "{rpc:?}: {denied:?}"
        );
        assert!(!lore_transport::is_unjournaled_answer_lost(&denied));
    }
}

/// The lost-answer predicate is false for the errors a caller must keep treating as before.
#[test]
fn is_unjournaled_answer_lost_is_false_for_other_errors() {
    let attempt = AttemptId::new();
    for error in [
        lore_transport::outcome::outcome_unknown("StorageService.MutableStore", &attempt),
        ProtocolError::from(lore_base::error::Disconnected),
        ProtocolError::internal("lost its answer. Pushing again is safe"),
        ProtocolError::from(Status::permission_denied("no")),
    ] {
        assert!(
            !lore_transport::is_unjournaled_answer_lost(&error),
            "{error:?}"
        );
    }
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

/// An in-band uncertainty marker on a Put answer is the same lost answer as a dropped stream:
/// a retryable internal error, never an unknown outcome and never a journal child.
#[tokio::test]
async fn future_and_incomplete_wire_markers_on_a_put_are_a_retryable_internal_error() {
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
        assert!(
            matches!(error, ProtocolError::Internal(_)),
            "marker must read as a retryable lost answer: {error:?}"
        );
        assert!(!error.is_outcome_unknown(), "{error:?}");
        assert!(!error.is_disconnected(), "{error:?}");
        assert!(f.journal.records.lock().is_empty());
        assert!(f.journal.unresolved().await.unwrap().is_empty());
        assert_eq!(f.items.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn missing_or_malformed_outgoing_namespace_refuses_before_record_or_rpc() {
    for token in ["", "not-a-jwt"] {
        let f = Fixture::new(Reply::Success).await;
        let mut ctx = f.context();
        ctx.auth_token = token.into();
        let error = with_caller_operation(f.operation(), f.journaled_mutation(&ctx, 25))
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
    let ctx = f.context();
    let _ = with_caller_operation(f.operation(), f.journaled_mutation(&ctx, 26)).await;
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
    // The fixture loses every MutableStore answer, so each accepted call is an unknown outcome;
    // only whether the call was admitted and journaled is under test.
    with_caller_operation(f.operation(), async {
        let mut ctx = f.context();
        let first = f.journaled_mutation(&ctx, 27).await.unwrap_err();
        assert!(first.is_outcome_unknown(), "{first:?}");
        ctx.auth_token = OTHER.into();
        let rotated = f.journaled_mutation(&ctx, 28).await.unwrap_err();
        assert!(
            !rotated.is_outcome_unknown(),
            "changing principal under one parent must refuse before dispatch: {rotated:?}"
        );
        assert_eq!(f.items.load(Ordering::SeqCst), 1);
        assert_eq!(f.journal.records.lock().len(), 1);
        ctx.auth_token = REFRESHED.into();
        let refreshed = f.journaled_mutation(&ctx, 29).await.unwrap_err();
        assert!(refreshed.is_outcome_unknown(), "{refreshed:?}");
    })
    .await;
    assert_eq!(f.items.load(Ordering::SeqCst), 2);
    assert_eq!(f.journal.records.lock().len(), 2);
}

/// A Put abandoned after the server read it leaves nothing behind: no record to settle.
#[tokio::test]
async fn cancelling_a_put_after_server_reads_item_leaves_no_journal_state() {
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
    assert!(f.journal.records.lock().is_empty());
    assert!(f.journal.unresolved().await.unwrap().is_empty());
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
    assert!(f.journal.records.lock().is_empty());
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

/// The managed storage writes that write no journal child.
#[derive(Clone, Copy, Debug)]
enum Unjournaled {
    Copy,
    PutResolved,
}

impl Unjournaled {
    const ALL: [Self; 2] = [Self::Copy, Self::PutResolved];
    fn wire_name(self) -> &'static str {
        match self {
            Self::Copy => "StorageService.Copy",
            Self::PutResolved => "StorageService.PutResolved",
        }
    }
    async fn call(self, f: &Fixture, tag: u8) -> Result<(), ProtocolError> {
        match self {
            Self::Copy => f.copy(tag).await,
            Self::PutResolved => f.put_resolved(tag).await,
        }
    }
}

/// A managed Copy and `PutResolved` write no journal child, exactly as a fragment Put does: on
/// success they still declare the capability and send a fresh attempt id each call, but nothing
/// is recorded and the id is never in the journal.
#[tokio::test]
async fn managed_copy_and_put_resolved_record_nothing_but_still_declare_and_mint_an_attempt_id() {
    for write in Unjournaled::ALL {
        let f = Fixture::new(Reply::Success).await;
        with_caller_operation(f.operation(), async {
            write.call(&f, 41).await.unwrap();
            write.call(&f, 41).await.unwrap();
        })
        .await;
        assert!(f.journal.records.lock().is_empty(), "{write:?}");
        assert!(f.journal.intents.lock().is_empty(), "{write:?}");
        assert!(
            f.journal.unresolved().await.unwrap().is_empty(),
            "{write:?}"
        );
        let seen = f.seen.lock();
        assert_eq!(seen.len(), 2, "{write:?}");
        for observation in seen.iter() {
            assert_eq!(
                observation.capability.as_deref(),
                Some("outcome_unknown_v1"),
                "{write:?}"
            );
            assert!(observation.attempt.is_some(), "{write:?}");
            assert!(!observation.journaled_before_body, "{write:?}");
        }
        assert_ne!(
            seen[0].attempt, seen[1].attempt,
            "{write:?}: fresh id per call"
        );
        assert_eq!(f.items.load(Ordering::SeqCst), 2, "{write:?}");
    }
}

/// A lost answer is a plain retryable failure of the push, marked as an unjournaled lost answer:
/// not an unknown outcome (which would hold the fence), not `Disconnected` (which the reconnect
/// layer would resend). The one message is sent exactly once and nothing is journaled.
#[tokio::test]
async fn managed_copy_and_put_resolved_response_loss_is_a_retryable_internal_error_without_journal()
{
    for write in Unjournaled::ALL {
        let f = Fixture::new(Reply::Loss).await;
        let error = with_caller_operation(f.operation(), write.call(&f, 11))
            .await
            .unwrap_err();
        assert!(
            matches!(error, ProtocolError::Internal(_)),
            "{write:?}: {error:?}"
        );
        assert!(!error.is_outcome_unknown(), "{write:?}: {error:?}");
        assert!(!error.is_disconnected(), "{write:?}: {error:?}");
        assert!(
            lore_transport::is_unjournaled_answer_lost(&error),
            "{write:?}: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains(write.wire_name()), "{write:?}: {text}");
        assert!(text.contains("lost its answer"), "{write:?}: {text}");
        assert!(text.contains("Pushing again is safe"), "{write:?}: {text}");
        assert_eq!(f.items.load(Ordering::SeqCst), 1, "{write:?}");
        {
            let seen = f.seen.lock();
            assert_eq!(seen.len(), 1, "{write:?}: exactly one wire request");
            assert_eq!(
                seen[0].capability.as_deref(),
                Some("outcome_unknown_v1"),
                "{write:?}"
            );
            assert!(seen[0].attempt.is_some(), "{write:?}");
            assert!(!seen[0].journaled_before_body, "{write:?}");
        }
        assert!(f.journal.records.lock().is_empty(), "{write:?}");
        assert!(f.journal.intents.lock().is_empty(), "{write:?}");
        assert!(
            f.journal.unresolved().await.unwrap().is_empty(),
            "{write:?}"
        );
    }
}

/// Every other way the answer goes missing is the same lost answer: a stream that ends silent,
/// and an answer that names another address or request.
#[tokio::test]
async fn managed_copy_and_put_resolved_ended_or_mismatched_answer_is_a_lost_answer() {
    for write in Unjournaled::ALL {
        for reply in [Reply::Ended, Reply::ItemUnknown(0, "", "")] {
            let f = Fixture::new(reply).await;
            let error = with_caller_operation(f.operation(), write.call(&f, 12))
                .await
                .unwrap_err();
            assert!(
                lore_transport::is_unjournaled_answer_lost(&error),
                "{write:?}: {error:?}"
            );
            assert!(!error.is_outcome_unknown(), "{write:?}: {error:?}");
            assert!(!error.is_disconnected(), "{write:?}: {error:?}");
            assert_eq!(f.seen.lock().len(), 1, "{write:?}: no resend");
            assert!(f.journal.records.lock().is_empty(), "{write:?}");
        }
    }
}

/// A decisive refusal stays decisive: it is not the lost-answer mapping, and nothing is journaled.
#[tokio::test]
async fn managed_copy_and_put_resolved_decisive_refusals_are_not_lost_answers() {
    for write in Unjournaled::ALL {
        let f = Fixture::new(Reply::Refusal).await;
        let error = with_caller_operation(f.operation(), write.call(&f, 13))
            .await
            .unwrap_err();
        assert!(
            lore_transport::error::is_unsupported_client(&error),
            "{write:?}: {error:?}"
        );
        assert!(
            !lore_transport::is_unjournaled_answer_lost(&error),
            "{write:?}"
        );
        assert!(!error.is_outcome_unknown(), "{write:?}");
        assert_eq!(f.items.load(Ordering::SeqCst), 0, "{write:?}");
        assert!(f.journal.records.lock().is_empty(), "{write:?}");

        let f = Fixture::new(Reply::ItemCancelled).await;
        let error = with_caller_operation(f.operation(), write.call(&f, 14))
            .await
            .unwrap_err();
        assert!(
            !lore_transport::is_unjournaled_answer_lost(&error),
            "{write:?}: {error:?}"
        );
        assert!(!error.is_outcome_unknown(), "{write:?}: {error:?}");
        assert_eq!(f.items.load(Ordering::SeqCst), 1, "{write:?}");
        assert!(f.journal.records.lock().is_empty(), "{write:?}");
    }
}

/// Neither write depends on the journal working: it never touches the store.
#[tokio::test]
async fn managed_copy_and_put_resolved_do_not_depend_on_the_journal_working() {
    for write in Unjournaled::ALL {
        let f = Fixture::new(Reply::Success).await;
        f.journal.fail_record.store(true, Ordering::SeqCst);
        f.journal.fail_settle.store(true, Ordering::SeqCst);
        with_caller_operation(f.operation(), write.call(&f, 15))
            .await
            .unwrap();
        assert_eq!(f.items.load(Ordering::SeqCst), 1, "{write:?}");
    }
}

/// A managed Copy or `PutResolved` whose session partition differs from the operation's repository
/// is refused before anything is sent.
#[tokio::test]
async fn managed_copy_and_put_resolved_for_another_repository_are_refused_before_the_wire() {
    for write in Unjournaled::ALL {
        let f = Fixture::new(Reply::Success).await;
        let mut ctx = f.context();
        ctx.partition = Partition::from(Context::from([0x22; 16]));
        let error = with_caller_operation(f.operation(), async {
            match write {
                Unjournaled::Copy => {
                    f.service
                        .copy(
                            0,
                            &ctx,
                            ctx.partition,
                            Address::zero_context_hash(Hash::from([72; 32])),
                            Context::from([0x12; 16]),
                        )
                        .await
                }
                Unjournaled::PutResolved => {
                    f.service
                        .put_resolved(
                            0,
                            &ctx,
                            &Hash::from([73; 32]),
                            Address::zero_context_hash(Hash::from([74; 32])),
                            Fragment {
                                flags: 0,
                                size_payload: 1,
                                size_content: 1,
                            },
                            Some(Bytes::from_static(b"x")),
                        )
                        .await
                }
            }
        })
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("repository mismatch"),
            "{write:?}: {error:?}"
        );
        assert!(f.seen.lock().is_empty(), "{write:?}: no wire request");
        assert_eq!(f.items.load(Ordering::SeqCst), 0, "{write:?}");
        assert!(f.journal.records.lock().is_empty(), "{write:?}");
    }
}

#[tokio::test]
async fn mutable_unaries_journal_before_loss_without_replay() {
    for operation in [
        "StorageService.MutableStore",
        "StorageService.MutableCompareAndSwap",
    ] {
        let f = Fixture::new(Reply::Loss).await;
        let ctx = f.context();
        let key = Hash::from([31; 32]);
        let value = Hash::from([32; 32]);
        let error = with_caller_operation(f.operation(), async {
            match operation {
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
/// reads as a retryable lost answer (not an unknown outcome); nothing is journaled. Pre-change
/// the put waits forever (the fixture's own 5 s bound then fails the test).
#[tokio::test]
async fn silent_managed_put_is_bounded_and_reads_as_a_retryable_lost_answer() {
    let f = Fixture::with_idle(Reply::Hold, Some(Duration::from_secs(1))).await;
    let started = std::time::Instant::now();
    let error = with_caller_operation(f.operation(), f.put(40))
        .await
        .unwrap_err();
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(!error.is_disconnected(), "{error:?}");
    assert!(error.to_string().contains("lost its answer"), "{error}");
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "must wait out the idle bound, took {:?}",
        started.elapsed()
    );
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
    assert_eq!(f.seen.lock().len(), 1, "no resend");
    assert!(f.journal.records.lock().is_empty());
    assert!(f.journal.unresolved().await.unwrap().is_empty());
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
    assert!(
        f.journal.records.lock().is_empty(),
        "an unsent Put has no journal child to settle"
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
    assert!(f.journal.records.lock().is_empty(), "round {tag}");
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

/// The managed Put budget bounds the streams open at once: 40 concurrent tiny Puts against a
/// budget of 4 never have more than 4 open, and every one of them succeeds.
#[tokio::test]
async fn managed_puts_in_flight_never_exceed_the_slot_budget() {
    let f = Fixture::with_slots(Reply::Gauge(Duration::from_millis(30)), 4).await;
    let results = futures::future::join_all(
        (0..40u8).map(|tag| with_caller_operation(f.operation(), f.put(100 + tag))),
    )
    .await;
    for result in results {
        result.expect("a Put waiting for a slot must still succeed");
    }
    let peak = f.peak.load(Ordering::SeqCst);
    assert!(peak <= 4, "peak concurrent Put streams was {peak}");
    assert!(
        peak >= 2,
        "the fixture never overlapped Puts ({peak}); the bound is untested"
    );
    assert_eq!(f.items.load(Ordering::SeqCst), 40);
    assert!(f.journal.records.lock().is_empty());
}

/// A Put costs one slot plus one per 64 KiB: with a budget of 4, a 3 * 64 KiB payload costs 4,
/// so those Puts run one at a time.
#[tokio::test]
async fn managed_put_cost_weights_payload_bytes_against_the_budget() {
    let f = Fixture::with_slots(Reply::Gauge(Duration::from_millis(30)), 4).await;
    let results =
        futures::future::join_all((0..6u8).map(|tag| f.put_sized(110 + tag, 3 * 65536))).await;
    for result in results {
        result.expect("a whole-budget Put must complete");
    }
    assert_eq!(f.peak.load(Ordering::SeqCst), 1);
    assert_eq!(f.items.load(Ordering::SeqCst), 6);
}

/// A payload costing more than the whole budget is capped at the budget, so it still runs.
#[tokio::test]
async fn managed_put_larger_than_the_whole_budget_still_completes() {
    let f = Fixture::with_slots(Reply::Gauge(Duration::from_millis(10)), 4).await;
    f.put_sized(120, 10 * 65536)
        .await
        .expect("a Put over the whole budget must be capped, not starved");
    assert_eq!(f.peak.load(Ordering::SeqCst), 1);
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
}

/// A stream-fatal status on the response stream is a lost answer that keeps the server's text,
/// and is still neither an unknown outcome nor a disconnect.
#[tokio::test]
async fn managed_put_stream_failure_keeps_its_cause_in_the_error() {
    let f = Fixture::new(Reply::Fatal).await;
    let error = with_caller_operation(f.operation(), f.put(130))
        .await
        .unwrap_err();
    let text = error.to_string();
    assert!(text.contains("lost its answer"), "{text}");
    assert!(text.contains("disk exploded"), "{text}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(!error.is_disconnected(), "{error:?}");
    assert_eq!(f.seen.lock().len(), 1, "no resend");
    assert!(f.journal.records.lock().is_empty());
}

/// A response stream that ends without a message says so.
#[tokio::test]
async fn managed_put_stream_ending_without_an_answer_says_so() {
    let f = Fixture::new(Reply::Ended).await;
    let error = with_caller_operation(f.operation(), f.put(131))
        .await
        .unwrap_err();
    let text = error.to_string();
    assert!(text.contains("lost its answer"), "{text}");
    assert!(text.contains("ended without an answer"), "{text}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(!error.is_disconnected(), "{error:?}");
    assert_eq!(f.seen.lock().len(), 1, "no resend");
}

/// The wait for a stream's trailers must never outlast the silence bound: a server that answers
/// at once but ends the stream after the idle limit still has its answer kept, not turned into a
/// lost one.
#[tokio::test]
async fn managed_put_answer_is_kept_when_trailers_outlast_the_idle_bound() {
    let f = Fixture::with_idle(
        Reply::LateTrailers(Duration::from_millis(1500)),
        Some(Duration::from_millis(300)),
    )
    .await;
    with_caller_operation(f.operation(), f.put(140))
        .await
        .expect("an answer received before the idle bound must be kept");
    assert_eq!(f.items.load(Ordering::SeqCst), 1);
    assert_eq!(f.seen.lock().len(), 1, "no resend");
}

#[test]
fn managed_put_cost_edge_cases() {
    assert_eq!(managed_put_cost(0, 128), 1);
    assert_eq!(managed_put_cost(65535, 128), 1);
    assert_eq!(managed_put_cost(65536, 128), 2);
    assert_eq!(managed_put_cost(3 * 65536, 128), 4);
    assert_eq!(managed_put_cost(usize::MAX, 128), 128);
    assert_eq!(managed_put_cost(10 * 65536, 4), 4, "capped at the budget");
    assert_eq!(managed_put_cost(0, 1), 1);
}

/// A managed Put used to drop its response stream right after the answer, so h2 reset every
/// stream (`RST_STREAM(CANCEL)`) before the server's trailers arrived. Under concurrency the
/// trailers hit forgotten streams, each counted as an internal reset, and past the h2 limit of
/// 1024 the client sent `GOAWAY` for the whole connection (`too_many_internal_resets`).
///
/// The load is tuned to discriminate: with the Put's stream finish removed it fails on that
/// GOAWAY, and with it every Put completes. The slot budget (512, well above the 50 streams h2
/// remembers) lets enough streams end within a second to outrun that memory; a much larger
/// budget (`100_000`) or a larger burst instead closes the connection for unrelated reasons.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_managed_puts_do_not_trip_the_h2_reset_limit() {
    const PUTS: usize = 10_000;
    let f = Fixture::with_slots(Reply::LateTrailers(Duration::from_millis(30)), 512).await;
    let results = futures::future::join_all((0..PUTS).map(|n| {
        let tag = u8::try_from(n % 256).unwrap();
        f.put_sized(tag, 1)
    }))
    .await;
    let failures: Vec<_> = results.iter().filter_map(|r| r.as_ref().err()).collect();
    // Attempt ids differ per Put; keep only the text after them so causes dedupe.
    let mut causes: Vec<String> = failures
        .iter()
        .map(|error| {
            let text = error.to_string();
            match text.split_once("lost its answer") {
                Some((_, cause)) => cause.to_owned(),
                None => text,
            }
        })
        .collect();
    causes.sort();
    causes.dedup();
    assert!(
        failures.is_empty(),
        "{} of {PUTS} managed Puts failed; distinct causes: {causes:#?}",
        failures.len(),
    );
    assert_eq!(f.items.load(Ordering::SeqCst), PUTS);
}
