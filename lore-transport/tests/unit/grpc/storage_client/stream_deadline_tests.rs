// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] A stream's answer wait is bounded by an idle deadline, and an admission refusal on
//! stream open is decisive for every request that meets it.
//!
//! Two fixtures: a tonic server whose Put/Get behaviour is selectable, and a raw h2 "front" that
//! answers every request trailers-only with the admission marker yet keeps the request body
//! open, as a reverse proxy in front of the real server can.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_proto::lore::model::v1 as model_v1;
use lore_proto::lore::storage::v1 as storage_v1;
use lore_proto::lore::storage::v1::storage_service_server::StorageService as Service;
use lore_proto::lore::storage::v1::storage_service_server::StorageServiceServer;
use lore_transport::error::ProtocolError;
use lore_transport::error::is_unsupported_client;
use lore_transport::grpc::storage_client::*;
use tokio_stream::StreamExt;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

type Responses<T> = Pin<Box<dyn futures::Stream<Item = Result<T, Status>> + Send>>;

const PAYLOAD: &[u8] = b"abcd";

#[derive(Clone, Copy)]
enum PutBehavior {
    /// Open the stream, read every request, never answer.
    Silent,
    /// Fail the open with the exact admission refusal.
    RefuseMarked,
    /// Fail the open with a bare `FailedPrecondition`, no admission marker.
    RefuseBare,
    /// Answer each request after this pause, one at a time.
    Paced(Duration),
    /// Answer the first request, read the second, then end the OPENED stream with the
    /// admission-marker status. The refusal applies only to a failed open, not to this.
    AnswerOneThenEndMarked,
}

#[derive(Clone, Copy)]
enum GetBehavior {
    /// Read the first stream's requests and never answer; answer every later stream.
    SilentFirstStream,
    /// Read every stream's requests and never answer, on every open.
    AllSilent,
}

struct Server {
    put: PutBehavior,
    get: GetBehavior,
    put_opens: Arc<AtomicUsize>,
    get_opens: Arc<AtomicUsize>,
}

fn marked_refusal() -> Status {
    let mut status = Status::failed_precondition("the message is deliberately unrelated");
    status.metadata_mut().insert(
        "lore-client-admission-v1",
        "unsupported-client".parse().unwrap(),
    );
    status
}

#[tonic::async_trait]
impl Service for Server {
    type GetStream = Responses<storage_v1::GetResponse>;
    async fn get(
        &self,
        request: Request<Streaming<model_v1::Address>>,
    ) -> Result<Response<Self::GetStream>, Status> {
        let attempt = self.get_opens.fetch_add(1, Ordering::SeqCst);
        let silent_from = match self.get {
            GetBehavior::SilentFirstStream => 1,
            GetBehavior::AllSilent => usize::MAX,
        };
        let mut requests = request.into_inner();
        let stream = async_stream::stream! {
            if attempt < silent_from {
                while let Some(Ok(_)) = requests.next().await {}
                futures::future::pending::<()>().await;
            }
            while let Some(Ok(address)) = requests.next().await {
                yield Ok(storage_v1::GetResponse {
                    address: Some(address),
                    fragment: Some(model_v1::Fragment {
                        flags: 0,
                        size_payload: PAYLOAD.len() as u32,
                        size_content: PAYLOAD.len() as u64,
                    }),
                    payload: Bytes::from_static(PAYLOAD),
                    status: Some(model_v1::ItemStatus::ok()),
                });
            }
        };
        Ok(Response::new(Box::pin(stream) as Self::GetStream))
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
        request: Request<Streaming<storage_v1::GetResolvedRequest>>,
    ) -> Result<Response<Self::GetResolvedStream>, Status> {
        let mut requests = request.into_inner();
        let stream = async_stream::stream! {
            while let Some(Ok(_)) = requests.next().await {}
            futures::future::pending::<()>().await;
            yield Ok(storage_v1::GetResolvedResponse::default());
        };
        Ok(Response::new(Box::pin(stream) as Self::GetResolvedStream))
    }
    type PutResolvedStream = Responses<storage_v1::PutResolvedResponse>;
    async fn put_resolved(
        &self,
        request: Request<Streaming<storage_v1::PutResolvedRequest>>,
    ) -> Result<Response<Self::PutResolvedStream>, Status> {
        // Shares the Put behaviour: silent, or refused at open with the marker.
        if let PutBehavior::RefuseMarked = self.put {
            return Err(marked_refusal());
        }
        let mut requests = request.into_inner();
        let stream = async_stream::stream! {
            while let Some(Ok(_)) = requests.next().await {}
            futures::future::pending::<()>().await;
            yield Ok(storage_v1::PutResolvedResponse::default());
        };
        Ok(Response::new(Box::pin(stream) as Self::PutResolvedStream))
    }
    type PutStream = Responses<storage_v1::PutResponse>;
    async fn put(
        &self,
        request: Request<Streaming<storage_v1::PutRequest>>,
    ) -> Result<Response<Self::PutStream>, Status> {
        self.put_opens.fetch_add(1, Ordering::SeqCst);
        let behavior = self.put;
        match behavior {
            PutBehavior::RefuseMarked => Err(marked_refusal()),
            PutBehavior::RefuseBare => Err(Status::failed_precondition("no marker here")),
            PutBehavior::Silent | PutBehavior::Paced(_) | PutBehavior::AnswerOneThenEndMarked => {
                let mut requests = request.into_inner();
                let stream = async_stream::stream! {
                    if let PutBehavior::AnswerOneThenEndMarked = behavior {
                        if let Some(Ok(item)) = requests.next().await {
                            yield Ok(storage_v1::PutResponse { address: item.address, status: None });
                        }
                        if let Some(Ok(_)) = requests.next().await {
                            yield Err(marked_refusal());
                        }
                    } else if let PutBehavior::Paced(pause) = behavior {
                        while let Some(Ok(item)) = requests.next().await {
                            tokio::time::sleep(pause).await;
                            yield Ok(storage_v1::PutResponse { address: item.address, status: None });
                        }
                    } else {
                        while let Some(Ok(_)) = requests.next().await {}
                        futures::future::pending::<()>().await;
                        yield Ok(storage_v1::PutResponse::default());
                    }
                };
                Ok(Response::new(Box::pin(stream) as Self::PutStream))
            }
        }
    }
    type CopyStream = Responses<storage_v1::CopyResponse>;
    async fn copy(
        &self,
        _: Request<Streaming<storage_v1::CopyRequest>>,
    ) -> Result<Response<Self::CopyStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn query(
        &self,
        _: Request<storage_v1::QueryRequest>,
    ) -> Result<Response<storage_v1::QueryResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn verify(
        &self,
        _: Request<storage_v1::VerifyRequest>,
    ) -> Result<Response<storage_v1::VerifyResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn mutable_load(
        &self,
        _: Request<storage_v1::MutableLoadRequest>,
    ) -> Result<Response<storage_v1::MutableLoadResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn mutable_store(
        &self,
        _: Request<storage_v1::MutableStoreRequest>,
    ) -> Result<Response<storage_v1::MutableStoreResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn mutable_compare_and_swap(
        &self,
        _: Request<storage_v1::MutableCompareAndSwapRequest>,
    ) -> Result<Response<storage_v1::MutableCompareAndSwapResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

struct Rig {
    service: Arc<StorageService>,
    put_opens: Arc<AtomicUsize>,
    get_opens: Arc<AtomicUsize>,
    url: String,
}

async fn service_at(url: &str, idle: Duration) -> Arc<StorageService> {
    let channel = tonic::transport::Channel::from_shared(url.to_string())
        .unwrap()
        .connect()
        .await
        .expect("connect to test server");
    let channel = tower::ServiceBuilder::new()
        .layer(lore_transport::grpc::RequestLoggerLayer {})
        .service(channel);
    let connection = Arc::new(lore_transport::grpc::GRPCConnection::for_test(
        url.parse().unwrap(),
        channel,
    ));
    Arc::new(StorageService::new(connection).with_stream_idle_timeout(idle))
}

async fn rig(put: PutBehavior, idle: Duration) -> Rig {
    rig_with(put, GetBehavior::SilentFirstStream, idle).await
}

async fn rig_with(put: PutBehavior, get: GetBehavior, idle: Duration) -> Rig {
    let put_opens = Arc::new(AtomicUsize::new(0));
    let get_opens = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server = Server {
        put,
        get,
        put_opens: put_opens.clone(),
        get_opens: get_opens.clone(),
    };
    #[allow(clippy::disallowed_methods)] // Test-local server task.
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(StorageServiceServer::new(server))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let url = format!("http://{addr}");
    Rig {
        service: service_at(&url, idle).await,
        put_opens,
        get_opens,
        url,
    }
}

fn context() -> Arc<GrpcSessionContext> {
    Arc::new(GrpcSessionContext {
        partition: Partition::from(Context::from([0x11u8; 16])),
        correlation_id: "stream-deadline".to_string(),
        auth_token: String::new(),
    })
}

async fn put_one(
    service: Arc<StorageService>,
    ctx: Arc<GrpcSessionContext>,
    tag: u8,
    salt: u8,
) -> Result<(), ProtocolError> {
    let mut hash = [salt; 32];
    hash[0] = tag;
    service
        .put(
            0,
            &ctx,
            Address::zero_context_hash(Hash::from(hash)),
            Fragment {
                flags: 0,
                size_payload: PAYLOAD.len() as u32,
                size_content: PAYLOAD.len() as u64,
            },
            Some(Bytes::from_static(PAYLOAD)),
        )
        .await
}

/// Run `count` concurrent Puts, each bounded by `bound`; a timeout panics, so a hang is a failure.
async fn put_wave(
    service: &Arc<StorageService>,
    ctx: &Arc<GrpcSessionContext>,
    count: u8,
    salt: u8,
    bound: Duration,
) -> Vec<Result<(), ProtocolError>> {
    let mut tasks = Vec::new();
    for tag in 0..count {
        let service = service.clone();
        let ctx = ctx.clone();
        #[allow(clippy::disallowed_methods)] // Test-local concurrent callers.
        tasks.push(tokio::spawn(async move {
            tokio::time::timeout(bound, put_one(service, ctx, tag, salt))
                .await
                .unwrap_or_else(|_| panic!("put {tag} (wave {salt}) hung past {bound:?}"))
        }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.expect("put task panicked"));
    }
    results
}

/// A front that answers every request trailers-only with the admission marker but keeps the
/// request body open and keeps reading it, never resetting the stream.
async fn body_holding_front() -> (String, Arc<AtomicUsize>) {
    draining_front(false).await
}

/// `silent`: send response headers without ending the stream, then never answer: an opened,
/// silent stream. Otherwise the trailers-only admission refusal.
async fn draining_front(silent: bool) -> (String, Arc<AtomicUsize>) {
    let opens = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let counter = opens.clone();
    #[allow(clippy::disallowed_methods)] // Test-local front.
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let counter = counter.clone();
            #[allow(clippy::disallowed_methods)] // Test-local front connection.
            tokio::spawn(async move {
                let Ok(mut conn) = h2::server::handshake(socket).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = conn.accept().await {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let mut response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc");
                    if !silent {
                        response = response
                            .header("grpc-status", "9")
                            .header("grpc-message", "unsupported-client")
                            .header("lore-client-admission-v1", "unsupported-client");
                    }
                    let response = response.body(()).unwrap();
                    if respond.send_response(response, !silent).is_err() {
                        continue;
                    }
                    let mut body = request.into_body();
                    #[allow(clippy::disallowed_methods)] // Test-local request drain.
                    tokio::spawn(async move {
                        let _held = respond;
                        while let Some(Ok(chunk)) = body.data().await {
                            let _ = body.flow_control().release_capacity(chunk.len());
                        }
                        futures::future::pending::<()>().await;
                    });
                }
            });
        }
    });
    (url, opens)
}

/// A front that holds the request body open after a trailers-only refusal used to hang every
/// later Put on the session: the request generator never ended, and queued requests were never
/// failed. Pre-change, the second wave hangs and the per-put timeout fires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn body_holding_front_refusal_never_hangs_a_later_wave() {
    const WAVES: u8 = 4;
    let (url, opens) = body_holding_front().await;
    let service = service_at(&url, Duration::from_secs(30)).await;
    let ctx = context();
    for wave in 0..WAVES {
        for result in put_wave(&service, &ctx, 25, wave, Duration::from_secs(10)).await {
            let err = result.expect_err("a refused put cannot succeed");
            assert!(is_unsupported_client(&err), "wave {wave}: {err:?}");
            assert!(!err.is_outcome_unknown(), "wave {wave}: {err:?}");
            assert!(!err.is_disconnected(), "wave {wave}: {err:?}");
        }
    }
    let seen = opens.load(Ordering::SeqCst);
    assert!(
        (1..=usize::from(WAVES)).contains(&seen),
        "the front must see at most one open per wave, saw {seen} for {WAVES} waves"
    );
}

/// A server that opens the Put stream, reads the request and never answers. Pre-change the put
/// waits forever. The mutation is dispatched, so it is an unknown outcome and is not resent.
#[tokio::test]
async fn silent_put_stream_is_an_unknown_outcome_after_the_idle_bound() {
    let rig = rig(PutBehavior::Silent, Duration::from_secs(1)).await;
    let started = Instant::now();
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        put_one(rig.service.clone(), context(), 1, 1),
    )
    .await
    .expect("idle deadline must end the wait within 5 s")
    .expect_err("a silent stream cannot succeed");
    assert!(err.is_outcome_unknown(), "{err:?}");
    assert!(!is_unsupported_client(&err), "{err:?}");
    assert!(
        format!("{err:?}").contains("no answer from the put stream"),
        "{err:?}"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "must wait out the idle bound, took {:?}",
        started.elapsed()
    );
    assert_eq!(
        rig.put_opens.load(Ordering::SeqCst),
        1,
        "a dispatched put is never reissued"
    );
}

/// A Get whose stream never answers fails after ONE idle wait as a disconnect and discards the
/// stream; the retry belongs to the reconnect layer above (see the `GRPCStorage` cases below).
/// Pre-change it waits forever.
#[tokio::test]
async fn silent_get_stream_fails_as_a_disconnect_after_one_idle_wait() {
    let rig = rig(PutBehavior::Silent, Duration::from_secs(1)).await;
    let address = Address::zero_context_hash(Hash::from([0x22u8; 32]));
    let started = Instant::now();
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        rig.service.get(0, &context(), &address),
    )
    .await
    .expect("idle deadline must end the wait within 5 s")
    .expect_err("a silent first stream cannot answer");
    assert!(err.is_disconnected(), "{err:?}");
    assert!(!err.is_outcome_unknown(), "{err:?}");
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(
        rig.get_opens.load(Ordering::SeqCst),
        1,
        "no stream-level reissue"
    );
}

async fn storage_at(
    url: &str,
    idle: Duration,
) -> (
    lore_transport::grpc::GRPCStorage,
    Arc<lore_transport::grpc::GRPCConnection>,
) {
    let channel = tonic::transport::Channel::from_shared(url.to_string())
        .unwrap()
        .connect()
        .await
        .expect("connect to test server");
    let channel = tower::ServiceBuilder::new()
        .layer(lore_transport::grpc::RequestLoggerLayer {})
        .service(channel);
    let connection = Arc::new(lore_transport::grpc::GRPCConnection::for_test(
        url.parse().unwrap(),
        channel,
    ));
    let storage = lore_transport::grpc::GRPCStorage {
        connection: connection.clone(),
        client: StorageService::new(connection.clone()).with_stream_idle_timeout(idle),
        auth_url: String::new(),
        identity: String::new(),
        credentials: Arc::new(lore_transport::connection::SuppliedCredentials::default()),
        session_counter: std::sync::atomic::AtomicU32::new(1),
        sessions: dashmap::DashMap::new(),
    };
    storage.sessions.insert(0, context());
    (storage, connection)
}

/// Through `GRPCStorage`, a silent first Get stream is recovered by a rebuilt channel: the
/// read succeeds and the connection epoch advanced.
#[tokio::test]
async fn silent_first_get_stream_recovers_through_a_reconnect() {
    use lore_transport::traits::Storage;
    let rig = rig(PutBehavior::Silent, Duration::from_secs(1)).await;
    let (storage, connection) = storage_at(&rig.url, Duration::from_secs(1)).await;
    let epoch = connection.reconnect.load(Ordering::SeqCst);
    let address = Address::zero_context_hash(Hash::from([0x23u8; 32]));
    let (fragment, payload) =
        tokio::time::timeout(Duration::from_secs(10), storage.get(0, &address))
            .await
            .expect("the read must recover within the bound")
            .expect("get must succeed after the reconnect");
    assert_eq!(payload.as_ref(), PAYLOAD);
    assert_eq!(fragment.size_payload, PAYLOAD.len() as u32);
    assert_eq!(connection.reconnect.load(Ordering::SeqCst), epoch + 1);
    assert_eq!(rig.get_opens.load(Ordering::SeqCst), 2);
}

/// The read worst case: every Get stream opens and never answers. Through `GRPCStorage` the
/// operation errors within a few idle waits and opens at most 3 Get streams (it was 8 before).
#[tokio::test]
async fn a_read_that_never_gets_an_answer_is_bounded_by_the_reconnect_budget() {
    use lore_transport::traits::Storage;
    let rig = rig_with(
        PutBehavior::Silent,
        GetBehavior::AllSilent,
        Duration::from_secs(1),
    )
    .await;
    let (storage, _connection) = storage_at(&rig.url, Duration::from_secs(1)).await;
    let address = Address::zero_context_hash(Hash::from([0x24u8; 32]));
    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(15), storage.get(0, &address))
        .await
        .expect("a read must not wait forever on streams that never answer");
    assert!(result.is_err(), "no answer cannot be a fragment");
    let opens = rig.get_opens.load(Ordering::SeqCst);
    assert!(opens <= 3, "get opened {opens} streams");
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "took {:?}",
        started.elapsed()
    );
}

/// A server that answers Put 1, reads Put 2, then ends the OPENED stream with the admission
/// status: the refusal applies only to a failed open, so Put 2 is an unknown outcome.
#[tokio::test]
async fn marker_status_on_an_opened_stream_is_not_a_refusal() {
    let rig = rig(PutBehavior::AnswerOneThenEndMarked, Duration::from_secs(5)).await;
    let ctx = context();
    put_one(rig.service.clone(), ctx.clone(), 1, 7)
        .await
        .expect("put 1 was answered");
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        put_one(rig.service.clone(), ctx, 2, 7),
    )
    .await
    .expect("put 2 must not hang")
    .expect_err("put 2 was read and never answered");
    assert!(err.is_outcome_unknown(), "{err:?}");
    assert!(!is_unsupported_client(&err), "{err:?}");
}

/// A front that opens the stream, drains the body and stays silent: no Put of any wave hangs or
/// succeeds. A Put that dispatched is an unknown outcome within about the idle bound. A Put
/// that finds the previous wave's closed stream was never sent, so it is a `Disconnected`
/// (positive non-dispatch proof; `GRPCStorage` reconnects on it), never a refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_front_never_hangs_and_dispatched_puts_are_unknown() {
    let (url, _opens) = draining_front(true).await;
    let service = service_at(&url, Duration::from_secs(1)).await;
    let ctx = context();
    for wave in 0..3u8 {
        let started = Instant::now();
        let mut unknown = 0;
        for result in put_wave(&service, &ctx, 10, wave, Duration::from_secs(8)).await {
            let err = result.expect_err("a silent front answers nothing");
            assert!(!is_unsupported_client(&err), "wave {wave}: {err:?}");
            if err.is_outcome_unknown() {
                unknown += 1;
            } else {
                assert!(err.is_disconnected(), "wave {wave}: {err:?}");
            }
        }
        assert!(unknown >= 1, "wave {wave}: no put was a dispatched unknown");
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "wave {wave} took {:?}",
            started.elapsed()
        );
    }
}
fn resolved_fragment() -> Fragment {
    Fragment {
        flags: 0,
        size_payload: PAYLOAD.len() as u32,
        size_content: PAYLOAD.len() as u64,
    }
}

async fn put_resolved_one(
    service: Arc<StorageService>,
    ctx: Arc<GrpcSessionContext>,
    tag: u8,
) -> Result<(), ProtocolError> {
    service
        .put_resolved(
            0,
            &ctx,
            &Hash::from([tag; 32]),
            Address::zero_context_hash(Hash::from([tag.wrapping_add(1); 32])),
            resolved_fragment(),
            Some(Bytes::from_static(PAYLOAD)),
        )
        .await
}

/// `PutResolved` on a stream that never answers is an unknown outcome within the bound.
#[tokio::test]
async fn silent_put_resolved_stream_is_an_unknown_outcome() {
    let rig = rig(PutBehavior::Silent, Duration::from_secs(1)).await;
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        put_resolved_one(rig.service.clone(), context(), 9),
    )
    .await
    .expect("idle deadline must end the wait within 5 s")
    .expect_err("a silent stream cannot succeed");
    assert!(err.is_outcome_unknown(), "{err:?}");
}

/// `PutResolved` refused at open with the marker: a concurrent batch gets the decisive refusal
/// and none reads as an unknown outcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn marked_refusal_is_decisive_for_every_concurrent_put_resolved() {
    let rig = rig(PutBehavior::RefuseMarked, Duration::from_secs(30)).await;
    let ctx = context();
    let mut tasks = Vec::new();
    for tag in 0..100u8 {
        let service = rig.service.clone();
        let ctx = ctx.clone();
        #[allow(clippy::disallowed_methods)] // Test-local concurrent callers.
        tasks.push(tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(10), put_resolved_one(service, ctx, tag))
                .await
                .expect("put_resolved hung")
        }));
    }
    for task in tasks {
        let err = task
            .await
            .unwrap()
            .expect_err("a refused put_resolved cannot succeed");
        assert!(is_unsupported_client(&err), "{err:?}");
        assert!(!err.is_outcome_unknown(), "{err:?}");
    }
}

/// `GetResolved` on a stream that never answers errors within the bound. It is a read, so the
/// error is a disconnect for the reconnect layer to act on, not an unknown outcome.
#[tokio::test]
async fn silent_get_resolved_stream_errors_within_the_bound() {
    let rig = rig(PutBehavior::Silent, Duration::from_secs(1)).await;
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        rig.service.get_resolved(
            0,
            &context(),
            &Hash::from([0x30u8; 32]),
            &Context::from([0x11u8; 16]),
            0,
        ),
    )
    .await
    .expect("idle deadline must end the wait within 5 s")
    .expect_err("a silent stream cannot answer");
    assert!(err.is_disconnected(), "{err:?}");
    assert!(!err.is_outcome_unknown(), "{err:?}");
}
/// Deadline is idle time, not age: a server answering steadily keeps every put alive although
/// the whole batch takes longer than the idle bound. Fails if the deadline were absolute from
/// the request (puts 4 and later would be cut at 1 s).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn steady_progress_extends_the_idle_deadline() {
    let idle = Duration::from_secs(1);
    let rig = rig(PutBehavior::Paced(Duration::from_millis(300)), idle).await;
    let started = Instant::now();
    let results = put_wave(&rig.service, &context(), 10, 3, Duration::from_secs(20)).await;
    for result in results {
        result.expect("a put answered on a progressing stream must succeed");
    }
    assert!(
        started.elapsed() > idle,
        "the batch must outlast the idle bound for this test to mean anything, took {:?}",
        started.elapsed()
    );
    assert_eq!(rig.put_opens.load(Ordering::SeqCst), 1);
}

/// A tonic server refusing the open with the admission marker: every concurrent put gets the
/// decisive refusal. Pre-change 25 to 113 of 200 came back as `OutcomeUnknown` (code 248).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn marked_refusal_is_decisive_for_every_concurrent_put() {
    let rig = rig(PutBehavior::RefuseMarked, Duration::from_secs(30)).await;
    let results = put_wave(&rig.service, &context(), 200, 5, Duration::from_secs(10)).await;
    let mut unknown = 0;
    let mut refused = 0;
    for result in results {
        let err = result.expect_err("a refused put cannot succeed");
        if err.is_outcome_unknown() {
            unknown += 1;
        }
        if is_unsupported_client(&err) {
            refused += 1;
        }
    }
    assert_eq!(unknown, 0, "no refused put may read as an unknown outcome");
    assert_eq!(refused, 200, "every put must carry the decisive refusal");
}

/// Without the admission marker a `FailedPrecondition` open failure is not a refusal. Pinned
/// as it behaves today: not decisive-refusal, and it must come back rather than hang.
#[tokio::test]
async fn bare_failed_precondition_is_not_treated_as_a_refusal() {
    let rig = rig(PutBehavior::RefuseBare, Duration::from_secs(30)).await;
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        put_one(rig.service.clone(), context(), 1, 6),
    )
    .await
    .expect("a bare failed-precondition open must not hang");
    let err = result.expect_err("an open failure cannot succeed");
    assert!(!is_unsupported_client(&err), "{err:?}");
    // Today it surfaces as a plain Internal wrapping the status: not a refusal, not an unknown
    // outcome (the server read nothing), not a disconnect.
    assert!(!err.is_outcome_unknown(), "{err:?}");
    assert!(!err.is_disconnected(), "{err:?}");
    assert!(format!("{err:?}").contains("no marker here"), "{err:?}");
}
