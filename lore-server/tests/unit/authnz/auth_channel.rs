// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): `AuthClientAuthorizer` keeps one connection to the
//! auth service and shares it, instead of dialling per `CheckUserPermission`.
//!
//! A fake `UrcAuthApi` on a loopback port counts the TCP connections it
//! accepts, answers in a mode the test sets, and can be stopped and started
//! again on the same port.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use futures::future::join_all;
use lore_base::types::Context as LoreContext;
use lore_base::types::RepositoryId;
use lore_proto::auth::CheckUserPermissionRequest;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::authnz::auth::AUTH_CALL_TIMEOUT;
use lore_server::authnz::auth::AUTH_CONNECT_TIMEOUT;
use lore_server::authnz::auth::AuthChannel;
use lore_server::authnz::repository_authorizer::AuthClientAuthorizer;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::VerifiedToken;
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tonic::codegen::*;

const ALLOW: u8 = 0;
const DENY: u8 = 1;
const UNAUTHENTICATED: u8 = 2;
const UNAVAILABLE: u8 = 3;
const DEADLINE_EXCEEDED: u8 = 4;
const HANG: u8 = 5;

fn repository() -> RepositoryId {
    LoreContext::from_str("0194b726b34e72b0b45550b88a967076")
        .unwrap()
        .into()
}

#[derive(Clone)]
struct FakeAuth {
    mode: Arc<AtomicU8>,
    calls: Arc<AtomicUsize>,
    peers: Peers,
}

/// The client address of each call, in arrival order: tells connections apart.
type Peers = Arc<std::sync::Mutex<Vec<SocketAddr>>>;

impl tonic::server::NamedService for FakeAuth {
    const NAME: &'static str = "epic_urc.UrcAuthApi";
}

struct CheckUserPermission(u8);

impl tonic::server::UnaryService<lore_proto::auth::CheckUserPermissionRequest>
    for CheckUserPermission
{
    type Response = lore_proto::auth::CheckUserPermissionResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(
        &mut self,
        request: tonic::Request<lore_proto::auth::CheckUserPermissionRequest>,
    ) -> Self::Future {
        let mode = self.0;
        Box::pin(async move {
            let resource_id = request
                .into_inner()
                .resource_id
                .into_iter()
                .next()
                .unwrap_or_default();
            match mode {
                ALLOW => Ok(tonic::Response::new(
                    lore_proto::auth::CheckUserPermissionResponse {
                        allowed_resource_permission: vec![lore_proto::auth::ResourcePermission {
                            resource_id,
                            permission: vec!["read".to_string()],
                        }],
                        denied_resource_permission: vec![],
                    },
                )),
                DENY => Err(tonic::Status::permission_denied("fake: denied")),
                UNAUTHENTICATED => Err(tonic::Status::unauthenticated("fake: who")),
                UNAVAILABLE => Err(tonic::Status::unavailable("fake: down")),
                DEADLINE_EXCEEDED => Err(tonic::Status::deadline_exceeded("fake: slow")),
                _ => {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    Err(tonic::Status::internal("fake: woke"))
                }
            }
        })
    }
}

impl<B> Service<http::Request<B>> for FakeAuth
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(peer) = request
            .extensions()
            .get::<tonic::transport::server::TcpConnectInfo>()
            .and_then(tonic::transport::server::TcpConnectInfo::remote_addr)
        {
            self.peers.lock().unwrap().push(peer);
        }
        let method = CheckUserPermission(self.mode.load(Ordering::SeqCst));
        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
        Box::pin(async move { Ok(grpc.unary(method, request).await) })
    }
}

/// A fake auth service that can be stopped and started on one port.
struct FakeServer {
    address: SocketAddr,
    mode: Arc<AtomicU8>,
    calls: Arc<AtomicUsize>,
    accepted: Arc<AtomicUsize>,
    peers: Peers,
    running: Option<(oneshot::Sender<()>, tokio::task::JoinHandle<()>)>,
}

impl FakeServer {
    fn start() -> Self {
        let mut server = FakeServer {
            address: "127.0.0.1:0".parse().unwrap(),
            mode: Arc::new(AtomicU8::new(ALLOW)),
            calls: Arc::new(AtomicUsize::new(0)),
            accepted: Arc::new(AtomicUsize::new(0)),
            peers: Peers::default(),
            running: None,
        };
        server.serve();
        server
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn set_mode(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn serve(&mut self) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.bind(self.address).unwrap();
        let listener = socket.listen(128).unwrap();
        self.address = listener.local_addr().unwrap();
        let accepted = self.accepted.clone();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener).map(move |conn| {
            accepted.fetch_add(1, Ordering::SeqCst);
            conn
        });
        let service = FakeAuth {
            mode: self.mode.clone(),
            calls: self.calls.clone(),
            peers: self.peers.clone(),
        };
        let (stop, stopped) = oneshot::channel::<()>();
        let task = lore_base::lore_spawn!(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await;
        });
        self.running = Some((stop, task));
    }

    /// Stops accepting and closes every connection (graceful shutdown sends
    /// GOAWAY and waits for in-flight calls).
    async fn stop(&mut self) {
        if let Some((stop, task)) = self.running.take() {
            let _ = stop.send(());
            task.await.unwrap();
        }
    }
}

fn identity_claims() -> AuthorizationToken {
    // No `resources` claim: the authorizer must ask the auth service.
    AuthorizationToken::default()
}

async fn check(authorizer: &AuthClientAuthorizer) -> Result<(), tonic::Status> {
    let claims = identity_claims();
    let token = VerifiedToken {
        raw: "identity.jwt",
        claims: &claims,
    };
    authorizer
        .check_repository_access(Some(&token), repository(), None)
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sequential_checks_share_one_connection() {
    let server = FakeServer::start();
    let authorizer = AuthClientAuthorizer::new(server.url());
    for _ in 0..20 {
        check(&authorizer).await.unwrap();
    }
    assert_eq!(server.calls.load(Ordering::SeqCst), 20);
    assert_eq!(
        server.accepted(),
        1,
        "20 sequential checks dialled more than once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_checks_share_one_connection() {
    let server = FakeServer::start();
    let authorizer = AuthClientAuthorizer::new(server.url());
    // The very first calls race to dial: they must wait for one dial, not
    // open one each.
    let results = join_all((0..100).map(|_| check(&authorizer))).await;
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    assert_eq!(server.calls.load(Ordering::SeqCst), 100);
    assert_eq!(
        server.accepted(),
        1,
        "100 concurrent checks dialled more than once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn checks_succeed_after_the_auth_service_restarts() {
    let mut server = FakeServer::start();
    let authorizer = AuthClientAuthorizer::new(server.url());
    check(&authorizer).await.unwrap();
    assert_eq!(server.accepted(), 1);

    server.stop().await;
    // While it is down every check fails, as before, and nothing is cached
    // that would keep failing once it is back.
    let down = check(&authorizer).await.unwrap_err();
    assert_eq!(down.code(), tonic::Code::Internal, "{down:?}");

    server.serve();
    for _ in 0..5 {
        check(&authorizer).await.unwrap();
    }
    assert_eq!(
        server.accepted(),
        2,
        "the restart should cost exactly one new dial"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_never_reached_is_retried_on_the_next_check() {
    // Reserve a port, then close it: the first check finds nothing listening.
    let mut server = FakeServer::start();
    server.stop().await;
    let authorizer = AuthClientAuthorizer::new(server.url());
    let refused = check(&authorizer).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Internal);
    assert_eq!(refused.message(), "Failed to connect to lore auth service");

    server.serve();
    check(&authorizer).await.unwrap();
    assert_eq!(server.accepted(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_mapping_is_unchanged() {
    let server = FakeServer::start();
    let authorizer = AuthClientAuthorizer::new(server.url());
    let cases = [
        (DENY, tonic::Code::PermissionDenied, "Query resource denied"),
        (
            UNAUTHENTICATED,
            tonic::Code::Unauthenticated,
            "Query resource failed - unauthenticated",
        ),
        (UNAVAILABLE, tonic::Code::Internal, ""),
        (DEADLINE_EXCEEDED, tonic::Code::Internal, ""),
    ];
    for (mode, code, message) in cases {
        server.set_mode(mode);
        let status = check(&authorizer).await.unwrap_err();
        assert_eq!(status.code(), code, "mode {mode}: {status:?}");
        if message.is_empty() {
            assert!(
                status
                    .message()
                    .starts_with("Failed to call auth check_user_permission:"),
                "mode {mode}: {status:?}"
            );
        } else {
            assert_eq!(status.message(), message, "mode {mode}");
        }
    }
    // A service-sent denial is an answer, not a broken connection.
    server.set_mode(ALLOW);
    check(&authorizer).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_slow_check_does_not_block_the_next_one() {
    let server = FakeServer::start();
    let authorizer = AuthClientAuthorizer::new(server.url());
    server.set_mode(HANG);
    // The caller gives up (a request deadline above this layer does the same).
    let gave_up = tokio::time::timeout(Duration::from_millis(200), check(&authorizer)).await;
    assert!(gave_up.is_err(), "the hung check should not have answered");

    server.set_mode(ALLOW);
    tokio::time::timeout(Duration::from_secs(10), check(&authorizer))
        .await
        .expect("the next check must not wait behind the abandoned one")
        .unwrap();
    assert_eq!(server.accepted(), 1);
}

fn permission_request() -> tonic::Request<CheckUserPermissionRequest> {
    tonic::Request::new(CheckUserPermissionRequest {
        resource_id: vec![format!("urc-{}", repository())],
        target_user: None,
    })
}

/// Probe A: callers waiting on a dial to an address that never answers all
/// fail within about one connect timeout, not one timeout each in turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn callers_on_a_silent_address_fail_together_within_the_connect_timeout() {
    // TEST-NET style unroutable address: SYNs go unanswered (or the network
    // refuses at once, which also passes).
    let channel = AuthChannel::new("http://10.255.255.1:41339".to_string());
    let started = Instant::now();
    let results = join_all((0..4).map(|_| async {
        let result = channel.client().await.map(|_| ());
        (result, started.elapsed())
    }))
    .await;
    for (result, elapsed) in &results {
        let status = result.as_ref().unwrap_err();
        assert_eq!(status.code(), tonic::Code::Internal, "{status:?}");
        assert!(
            *elapsed < AUTH_CONNECT_TIMEOUT * 2,
            "a caller failed after {elapsed:?}: waiters dialled in turn"
        );
    }
    assert_eq!(channel.dial_attempts(), 1);
}

/// Probe B: fifty first callers to a refused port share one dial and fail
/// together; the failure is not cached, so a call after a restart passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_callers_to_a_refused_port_share_one_dial_and_recover() {
    let mut server = FakeServer::start();
    server.stop().await;
    let channel = AuthChannel::new(server.url());
    let started = Instant::now();
    let results = join_all((0..50).map(|_| channel.client())).await;
    let elapsed = started.elapsed();
    for result in &results {
        let status = result.as_ref().map(|_| ()).unwrap_err();
        assert_eq!(status.code(), tonic::Code::Internal);
        assert_eq!(status.message(), "Failed to connect to lore auth service");
    }
    assert_eq!(channel.dial_attempts(), 1, "the waiters dialled again");
    assert!(
        elapsed < AUTH_CONNECT_TIMEOUT * 2,
        "50 refused callers took {elapsed:?}"
    );

    server.serve();
    let mut client = channel.client().await.unwrap();
    client
        .check_user_permission(permission_request())
        .await
        .unwrap();
    assert_eq!(channel.dial_attempts(), 2);
    assert_eq!(server.accepted(), 1);
}

/// A TCP relay that can cut every connection it carries.
struct Proxy {
    address: SocketAddr,
    upstream: SocketAddr,
    tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Proxy {
    fn start(upstream: SocketAddr) -> Self {
        let mut proxy = Proxy {
            address: "127.0.0.1:0".parse().unwrap(),
            upstream,
            tasks: Arc::default(),
        };
        proxy.serve();
        proxy
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn serve(&mut self) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.bind(self.address).unwrap();
        let listener = socket.listen(128).unwrap();
        self.address = listener.local_addr().unwrap();
        let upstream = self.upstream;
        let tasks = self.tasks.clone();
        let accept = lore_base::lore_spawn!(async move {
            while let Ok((mut down, _)) = listener.accept().await {
                let relay = lore_base::lore_spawn!(async move {
                    if let Ok(mut up) = tokio::net::TcpStream::connect(upstream).await {
                        let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
                    }
                });
                tasks.lock().unwrap().push(relay);
            }
        });
        self.tasks.lock().unwrap().push(accept);
    }

    /// Stops listening and drops every relayed connection.
    async fn cut(&mut self) {
        let tasks: Vec<_> = self.tasks.lock().unwrap().drain(..).collect();
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_cut_mid_call_fails_that_call_and_the_next_redials() {
    let server = FakeServer::start();
    let mut proxy = Proxy::start(server.address);
    let authorizer = AuthClientAuthorizer::new(proxy.url());
    check(&authorizer).await.unwrap();

    server.set_mode(HANG);
    let in_flight = tokio::time::timeout(Duration::from_secs(10), check(&authorizer));
    let cut = async {
        while server.calls.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        proxy.cut().await;
    };
    let (in_flight, ()) = tokio::join!(in_flight, cut);
    let status = in_flight
        .expect("a cut connection must fail its call, not hang it")
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal, "{status:?}");

    proxy.serve();
    server.set_mode(ALLOW);
    check(&authorizer).await.unwrap();
    assert_eq!(server.accepted(), 2, "the next call should redial once");
}

/// A TLS peer that accepts TCP and never answers: the handshake stalls.
fn start_silent_tls_peer() -> (String, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(128).unwrap();
    let address = listener.local_addr().unwrap();
    let task = lore_base::lore_spawn!(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    (format!("https://{address}"), task)
}

/// P5: a dial whose TLS handshake never completes fails every caller
/// sharing it within about the connect timeout, and the next caller dials
/// again rather than joining the stuck dial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_tls_handshake_fails_the_shared_dial_within_the_timeout() {
    let (url, peer) = start_silent_tls_peer();
    let channel = AuthChannel::new(url);
    let bound = AUTH_CONNECT_TIMEOUT + Duration::from_secs(3);
    let started = Instant::now();
    let results = tokio::time::timeout(
        bound * 2,
        join_all((0..4).map(|_| async {
            let result = channel.client().await.map(|_| ());
            (result, started.elapsed())
        })),
    )
    .await
    .expect("callers joined a dial that never ends");
    for (result, elapsed) in &results {
        let status = result.as_ref().unwrap_err();
        assert_eq!(status.message(), "Failed to connect to lore auth service");
        assert!(*elapsed < bound, "a caller failed after {elapsed:?}");
    }
    assert_eq!(channel.dial_attempts(), 1);

    // The stuck dial is gone: the next caller starts its own, and it is
    // bounded the same way.
    let started = Instant::now();
    let next = tokio::time::timeout(bound * 2, channel.client())
        .await
        .expect("the next caller joined the stuck dial");
    assert!(next.is_err());
    assert!(started.elapsed() < bound);
    assert_eq!(channel.dial_attempts(), 2);

    // The peer is fixed (here: it now refuses at once): the next dial sees
    // the change rather than the old stall.
    peer.abort();
    let _ = peer.await;
    let started = Instant::now();
    assert!(channel.client().await.is_err());
    assert!(started.elapsed() < bound);
    assert_eq!(channel.dial_attempts(), 3);
}

/// P2: a caller that joined a dial but resumes only after that channel was
/// discarded and replaced takes the replacement, so its calls run on (and
/// may only discard) the installed channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_follower_takes_the_current_channel() {
    let server = FakeServer::start();
    let channel = AuthChannel::new(server.url());

    let mut late = Box::pin(channel.client());
    assert!(futures::poll!(&mut late).is_pending(), "joined dial 1");

    // Dial 1 lands; a connection failure on it discards it.
    let mut first = channel.client().await.unwrap();
    server.set_mode(UNAVAILABLE);
    first
        .check_user_permission(permission_request())
        .await
        .unwrap_err();
    server.set_mode(ALLOW);
    // Dial 2 replaces it.
    let mut second = channel.client().await.unwrap();
    second
        .check_user_permission(permission_request())
        .await
        .unwrap();
    assert_eq!(channel.dial_attempts(), 2);

    let mut late = late.await.unwrap();
    late.check_user_permission(permission_request())
        .await
        .unwrap();
    let peers = server.peers.lock().unwrap().clone();
    assert_eq!(peers.len(), 3);
    assert_ne!(peers[0], peers[1], "dial 2 should be its own connection");
    assert_eq!(
        peers[2], peers[1],
        "the late follower used the discarded channel"
    );
    assert_eq!(channel.dial_attempts(), 2, "the late follower dialled");
}

/// P1b: a dial every caller abandoned still records its own failure, so the
/// first caller after the service recovers dials afresh and succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_failed_dial_leaves_no_stale_failure() {
    let mut server = FakeServer::start();
    server.stop().await;
    let channel = AuthChannel::new(server.url());
    {
        let mut abandoned = Box::pin(channel.client());
        assert!(futures::poll!(&mut abandoned).is_pending());
    }
    // Let the abandoned dial run to its (refused) end.
    tokio::time::sleep(AUTH_CONNECT_TIMEOUT + Duration::from_secs(1)).await;

    server.serve();
    let mut client = channel
        .client()
        .await
        .expect("the first caller after recovery got a stale failure");
    client
        .check_user_permission(permission_request())
        .await
        .unwrap();
    assert_eq!(channel.dial_attempts(), 2);
}

/// On an established connection, a service that never answers an RPC fails
/// that call within the call timeout, as `Internal`, and the next call
/// redials.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_rpc_the_service_never_answers_times_out_and_the_next_call_redials() {
    let server = FakeServer::start();
    let authorizer = AuthClientAuthorizer::new(server.url());
    check(&authorizer).await.unwrap();

    server.set_mode(HANG);
    let started = Instant::now();
    let status = tokio::time::timeout(AUTH_CALL_TIMEOUT * 3, check(&authorizer))
        .await
        .expect("an unanswered RPC was not bounded")
        .unwrap_err();
    let elapsed = started.elapsed();
    assert!(elapsed >= AUTH_CALL_TIMEOUT, "{elapsed:?}");
    assert!(
        elapsed < AUTH_CALL_TIMEOUT + Duration::from_secs(3),
        "{elapsed:?}"
    );
    assert_eq!(status.code(), tonic::Code::Internal, "{status:?}");
    assert!(
        status
            .message()
            .starts_with("Failed to call auth check_user_permission:"),
        "{status:?}"
    );

    server.set_mode(ALLOW);
    check(&authorizer).await.unwrap();
    assert_eq!(
        server.accepted(),
        2,
        "the timed-out channel should be replaced"
    );
}
