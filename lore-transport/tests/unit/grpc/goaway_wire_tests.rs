// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] An h2 `ENHANCE_YOUR_CALM` failure after dispatch is a lost answer, not `SlowDown`.
//!
//! `tonic` maps an h2 error with reason `ENHANCE_YOUR_CALM` to `ResourceExhausted`, the same
//! code a server sends as in-band back-pressure, and attaches the h2/hyper error as the status's
//! source. Before this fix both read as `SlowDown`, the one verdict callers retry, so a Put or a
//! lock the server had already read was sent again (`store_raw_remote_retry`,
//! `remote_put_retry`, `handle_error`). The client's own
//! `GOAWAY(ENHANCE_YOUR_CALM, "too_many_internal_resets")` takes this shape; see
//! `lorehub/docs/learnings/dropping-a-tonic-response-stream-before-trailers-trips-h2-goaway-enhance-your-calm.md`.
//!
//! The fixture is a raw h2 front, because a tonic server cannot reset a stream with a chosen
//! reason. It reads the first request bytes of each stream, so every failure here follows a
//! dispatch. A peer's `RST_STREAM(ENHANCE_YOUR_CALM)` drives the same `tonic` mapping as the
//! client's own GOAWAY and is deterministic; the client GOAWAY itself needs thousands of
//! dropped streams. A peer's GOAWAY followed by a close reads as a disconnect instead, and one
//! case pins that.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::LockResource;
use lore_base::types::Partition;
use lore_base::types::RepositoryId;
use lore_proto::lore::model::v1 as model_v1;
use lore_proto::lore::storage::v1 as storage_v1;
use lore_transport::attempt_store::FencedLockResource;
use lore_transport::attempt_store::VolatileAttemptStore;
use lore_transport::caller_operation::CallerOperationContext;
use lore_transport::caller_operation::with_caller_operation;
use lore_transport::error::ProtocolError;
use lore_transport::grpc::GRPCAuth;
use lore_transport::grpc::GRPCAuthRef;
use lore_transport::grpc::GRPCConnection;
use lore_transport::grpc::RequestLoggerLayer;
use lore_transport::grpc::lock_client;
use lore_transport::grpc::storage_client::GrpcSessionContext;
use lore_transport::grpc::storage_client::StorageService;
use lore_transport::grpc::with_reconnect_classified;
use lore_transport::outcome::GrpcRpc;
use prost::Message as _;
use tower::ServiceBuilder;

const PAYLOAD: &[u8] = b"goaway";

/// What the front does once it has read a stream's first request bytes.
#[derive(Clone, Copy)]
enum Front {
    /// `GOAWAY(ENHANCE_YOUR_CALM)` and a close, on every connection.
    GoAway,
    /// `RST_STREAM(ENHANCE_YOUR_CALM)` on every stream.
    Reset,
    /// A trailers-only `RESOURCE_EXHAUSTED`: the server's own back-pressure, nothing stored.
    InBandSlowDown,
    /// `RST_STREAM` with this reason on the first stream; later streams answer one Get.
    ResetThenServeGet(h2::Reason),
}

struct Rig {
    url: String,
    /// Streams whose request bytes the front read: each one is a dispatch.
    requests: Arc<AtomicUsize>,
}

async fn front(mode: Front) -> Rig {
    let requests = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let counter = requests.clone();
    #[allow(clippy::disallowed_methods)] // Test-local front.
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let counter = counter.clone();
            #[allow(clippy::disallowed_methods)] // Test-local front connection.
            tokio::spawn(serve_connection(socket, mode, counter));
        }
    });
    Rig { url, requests }
}

/// The connection must keep being polled while stream tasks run, so a stream asks for the
/// GOAWAY over a channel rather than sending it itself.
async fn serve_connection(socket: tokio::net::TcpStream, mode: Front, requests: Arc<AtomicUsize>) {
    let Ok(mut conn) = h2::server::handshake(socket).await else {
        return;
    };
    let (shutdown, mut shutdown_requested) = tokio::sync::mpsc::unbounded_channel::<()>();
    loop {
        tokio::select! {
            accepted = conn.accept() => {
                let Some(Ok((request, respond))) = accepted else { return };
                #[allow(clippy::disallowed_methods)] // Test-local stream handler.
                tokio::spawn(serve_stream(
                    request,
                    respond,
                    mode,
                    shutdown.clone(),
                    requests.clone(),
                ));
            }
            Some(()) = shutdown_requested.recv() => {
                conn.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
                while conn.accept().await.is_some() {}
                return;
            }
        }
    }
}

async fn serve_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    mode: Front,
    shutdown: tokio::sync::mpsc::UnboundedSender<()>,
    requests: Arc<AtomicUsize>,
) {
    let mut body = request.into_body();
    let index = match body.data().await {
        Some(Ok(chunk)) => {
            let _ = body.flow_control().release_capacity(chunk.len());
            requests.fetch_add(1, Ordering::SeqCst)
        }
        _ => return,
    };
    match mode {
        Front::GoAway => {
            let _ = shutdown.send(());
        }
        Front::Reset => respond.send_reset(h2::Reason::ENHANCE_YOUR_CALM),
        Front::ResetThenServeGet(reason) if index == 0 => respond.send_reset(reason),
        Front::InBandSlowDown => {
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .header("grpc-status", "8")
                .header("grpc-message", "the server is busy")
                .body(())
                .unwrap();
            let _ = respond.send_response(response, true);
        }
        Front::ResetThenServeGet(_) => {
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            if let Ok(mut send) = respond.send_response(response, false) {
                let _ = send.send_data(get_answer(), false);
                // Held open, as a live Get stream is.
                let _held = (send, body);
                futures::future::pending::<()>().await;
            }
            return;
        }
    }
    // Held, not dropped: a dropped `SendResponse` resets the stream with its own reason, which
    // would race the failure under test.
    let _held = (respond, body);
    futures::future::pending::<()>().await;
}

fn get_address() -> Address {
    Address::zero_context_hash(Hash::from([0x5au8; 32]))
}

/// One length-prefixed gRPC message answering the Get for [`get_address`].
fn get_answer() -> Bytes {
    let message = storage_v1::GetResponse {
        address: Some(get_address().into()),
        fragment: Some(model_v1::Fragment {
            flags: 0,
            size_payload: PAYLOAD.len() as u32,
            size_content: PAYLOAD.len() as u64,
        }),
        payload: Bytes::from_static(PAYLOAD),
        status: Some(model_v1::ItemStatus::ok()),
    }
    .encode_to_vec();
    let mut framed = Vec::with_capacity(message.len() + 5);
    framed.push(0);
    framed.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(&message);
    Bytes::from(framed)
}

async fn channel(url: &str) -> lore_transport::grpc::Channel {
    let channel = tonic::transport::Channel::from_shared(url.to_string())
        .unwrap()
        .connect()
        .await
        .expect("connect to the front");
    ServiceBuilder::new()
        .layer(RequestLoggerLayer {})
        .service(channel)
}

async fn connection(url: &str) -> Arc<GRPCConnection> {
    Arc::new(GRPCConnection::for_test(
        url.parse().unwrap(),
        channel(url).await,
    ))
}

fn session() -> GrpcSessionContext {
    GrpcSessionContext {
        partition: Partition::from(Context::from([0x11u8; 16])),
        correlation_id: "goaway".to_string(),
        auth_token: String::new(),
    }
}

fn operation() -> CallerOperationContext {
    CallerOperationContext::new(
        uuid::Uuid::now_v7(),
        RepositoryId::from([0x11; 16]),
        Arc::new(VolatileAttemptStore::default()),
    )
}

async fn put(service: &StorageService, tag: u8) -> Result<(), ProtocolError> {
    tokio::time::timeout(
        Duration::from_secs(10),
        service.put(
            0,
            &session(),
            Address::zero_context_hash(Hash::from([tag; 32])),
            Fragment {
                flags: 0,
                size_payload: PAYLOAD.len() as u32,
                size_content: PAYLOAD.len() as u64,
            },
            Some(Bytes::from_static(PAYLOAD)),
        ),
    )
    .await
    .expect("a put must not hang")
}

async fn managed_put(front_mode: Front) -> (Result<(), ProtocolError>, usize) {
    let rig = front(front_mode).await;
    let service = StorageService::new(connection(&rig.url).await);
    let result = with_caller_operation(operation(), put(&service, 1)).await;
    (result, rig.requests.load(Ordering::SeqCst))
}

async fn unmanaged_put(front_mode: Front) -> (Result<(), ProtocolError>, usize) {
    let rig = front(front_mode).await;
    let service = StorageService::new(connection(&rig.url).await);
    let result = put(&service, 2).await;
    (result, rig.requests.load(Ordering::SeqCst))
}

/// The managed Put has no journal child, so a lost answer is a retryable push failure: never
/// `SlowDown` (a loop above would resend it), never an unknown outcome (nothing could settle it).
/// Pre-fix: `SlowDown`.
#[tokio::test]
async fn managed_put_lost_to_an_enhance_your_calm_reset_is_a_push_failure_not_slow_down() {
    let (result, requests) = managed_put(Front::Reset).await;
    let err = result.expect_err("a put lost to a reset cannot succeed");
    assert!(!err.is_slow_down(), "{err:?}");
    assert!(!err.is_outcome_unknown(), "{err:?}");
    assert!(!err.is_disconnected(), "{err:?}");
    assert!(format!("{err}").contains("lost its answer"), "{err}");
    assert_eq!(
        requests, 1,
        "the put reached the server once and is not resent"
    );
}

/// The unmanaged Put goes through the stream cache, which knows it dispatched: an unknown
/// outcome, sent once. Pre-fix: `SlowDown`.
#[tokio::test]
async fn unmanaged_put_lost_to_an_enhance_your_calm_reset_is_an_unknown_outcome() {
    let (result, requests) = unmanaged_put(Front::Reset).await;
    let err = result.expect_err("a put lost to a reset cannot succeed");
    assert!(err.is_outcome_unknown(), "{err:?}");
    assert_eq!(requests, 1, "a dispatched put is never reissued");
}

/// Pin, already true before the fix: a peer's GOAWAY followed by a close reaches the client as
/// a dropped connection, not as `ResourceExhausted`, so both Put paths already treat it as lost.
#[tokio::test]
async fn a_peer_goaway_and_close_is_a_lost_put_on_both_paths() {
    let (managed, requests) = managed_put(Front::GoAway).await;
    let managed = managed.expect_err("a put lost to a GOAWAY cannot succeed");
    assert!(!managed.is_slow_down(), "{managed:?}");
    assert!(
        format!("{managed}").contains("lost its answer"),
        "{managed}"
    );
    assert_eq!(requests, 1);
    let (unmanaged, requests) = unmanaged_put(Front::GoAway).await;
    let unmanaged = unmanaged.expect_err("a put lost to a GOAWAY cannot succeed");
    assert!(unmanaged.is_outcome_unknown(), "{unmanaged:?}");
    assert_eq!(requests, 1);
}

/// Negative control: the server's own `RESOURCE_EXHAUSTED` is still `SlowDown`, on both paths,
/// so the callers' back-off still runs for real back-pressure.
#[tokio::test]
async fn in_band_resource_exhausted_is_still_slow_down() {
    let (managed, _) = managed_put(Front::InBandSlowDown).await;
    let managed = managed.expect_err("a refused put cannot succeed");
    assert!(managed.is_slow_down(), "managed: {managed:?}");
    let (unmanaged, _) = unmanaged_put(Front::InBandSlowDown).await;
    let unmanaged = unmanaged.expect_err("a refused put cannot succeed");
    assert!(unmanaged.is_slow_down(), "unmanaged: {unmanaged:?}");
}

/// A lock acquire lost to an `ENHANCE_YOUR_CALM` reset is an unknown outcome and is sent once.
/// Pre-fix, `handle_error` read the `ResourceExhausted` as back-pressure and resent the acquire
/// beneath the replay class until its budget ran out.
#[tokio::test]
async fn lock_acquire_lost_to_an_enhance_your_calm_reset_is_unknown_and_sent_once() {
    let rig = front(Front::Reset).await;
    let auth: GRPCAuthRef = Arc::new(parking_lot::RwLock::new(GRPCAuth {
        authorization_token: "test-lore-jwt".to_string(),
        ..Default::default()
    }));
    let client = lock_client::LockService::new(
        channel(&rig.url).await,
        RepositoryId::from([0x01u8; 16]),
        auth,
    );
    let connection = connection(&rig.url).await;
    let resources = vec![FencedLockResource::tokenless(LockResource {
        branch: Context::from([0x02u8; 16]),
        hash: Hash::from([0x77u8; 32]),
        description: "goaway".to_string(),
    })];
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        // Boxed: the lock future is over 16 KB.
        Box::pin(with_reconnect_classified(
            &connection,
            GrpcRpc::LockLock,
            || async { client.lock(&resources, None).await },
            |_reconnect_id| async { Ok(()) },
        )),
    )
    .await
    .expect("a lost lock answer must not loop");
    let err = result.expect_err("a lock lost to a reset cannot succeed");
    assert!(err.is_outcome_unknown(), "{err:?}");
    assert_eq!(rig.requests.load(Ordering::SeqCst), 1);
}

/// A unary read lost to an `ENHANCE_YOUR_CALM` reset is reissued on a rebuilt channel, as
/// `Disconnected`, within the reconnect bound. Pre-fix, `handle_error` retried it in place as
/// `SlowDown` until its 120 s budget ran out; that in-place retry is gone for mutations, and this
/// pins that reads keep a bounded retry.
#[tokio::test]
async fn lock_query_lost_to_an_enhance_your_calm_reset_reconnects_within_the_bound() {
    let rig = front(Front::Reset).await;
    let auth: GRPCAuthRef = Arc::new(parking_lot::RwLock::new(GRPCAuth {
        authorization_token: "test-lore-jwt".to_string(),
        ..Default::default()
    }));
    let client = lock_client::LockService::new(
        channel(&rig.url).await,
        RepositoryId::from([0x01u8; 16]),
        auth,
    );
    let connection = connection(&rig.url).await;
    let rebuilds = AtomicUsize::new(0);
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        with_reconnect_classified(
            &connection,
            GrpcRpc::LockQuery,
            || async { client.query(None, None, None).await },
            |_reconnect_id| {
                rebuilds.fetch_add(1, Ordering::SeqCst);
                async { Ok(()) }
            },
        ),
    )
    .await
    .expect("a lost read must not loop past the reconnect bound");
    let err = result.expect_err("every stream is reset");
    assert!(err.is_disconnected(), "{err:?}");
    let requests = rig.requests.load(Ordering::SeqCst);
    assert!(requests > 1, "a read must be reissued, sent {requests}");
    assert_eq!(rebuilds.load(Ordering::SeqCst), requests);
}
/// A read lost to an `ENHANCE_YOUR_CALM` reset is reissued and succeeds. Pre-fix it came back
/// as `SlowDown` from the stream cache; this pins that the fix does not instead fail reads.
#[tokio::test]
async fn get_lost_to_an_enhance_your_calm_reset_is_reissued_and_succeeds() {
    get_whose_first_stream_is_reset_succeeds(h2::Reason::ENHANCE_YOUR_CALM).await;
}

/// The stream cache reads every lost answer as no verdict, not only `ENHANCE_YOUR_CALM`: a read
/// whose first stream is reset with `CANCEL` (tonic's `Cancelled`) is reissued too. Pre-fix it
/// came back as a plain `Internal`.
#[tokio::test]
async fn get_lost_to_a_cancel_reset_is_reissued_and_succeeds() {
    get_whose_first_stream_is_reset_succeeds(h2::Reason::CANCEL).await;
}

async fn get_whose_first_stream_is_reset_succeeds(reason: h2::Reason) {
    use lore_transport::traits::Storage;
    let rig = front(Front::ResetThenServeGet(reason)).await;
    let connection = connection(&rig.url).await;
    let storage = lore_transport::grpc::GRPCStorage {
        connection: connection.clone(),
        client: StorageService::new(connection.clone()),
        auth_url: String::new(),
        identity: String::new(),
        credentials: Arc::new(lore_transport::connection::SuppliedCredentials::default()),
        session_counter: std::sync::atomic::AtomicU32::new(1),
        sessions: dashmap::DashMap::new(),
    };
    storage.sessions.insert(0, Arc::new(session()));
    let (fragment, payload) =
        tokio::time::timeout(Duration::from_secs(10), storage.get(0, &get_address()))
            .await
            .expect("the read must recover within the bound")
            .expect("the read must succeed when reissued");
    assert_eq!(payload.as_ref(), PAYLOAD);
    assert_eq!(fragment.size_payload, PAYLOAD.len() as u32);
    assert_eq!(rig.requests.load(Ordering::SeqCst), 2);
}
