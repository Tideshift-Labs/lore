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
use lore_server::auth::jwt::AuthorizationToken;
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
}

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
    running: Option<(oneshot::Sender<()>, tokio::task::JoinHandle<()>)>,
}

impl FakeServer {
    fn start() -> Self {
        let mut server = FakeServer {
            address: "127.0.0.1:0".parse().unwrap(),
            mode: Arc::new(AtomicU8::new(ALLOW)),
            calls: Arc::new(AtomicUsize::new(0)),
            accepted: Arc::new(AtomicUsize::new(0)),
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
    let started = Instant::now();
    let results = join_all((0..100).map(|_| check(&authorizer))).await;
    // Informational: the in-process cost of 100 concurrent checks on loopback.
    eprintln!(
        "100 concurrent checks took {:?} over {} connection(s)",
        started.elapsed(),
        server.accepted()
    );
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
