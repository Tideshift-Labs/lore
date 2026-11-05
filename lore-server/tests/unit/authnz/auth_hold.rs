// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): the auth outage hold and the shared auth budget.
//!
//! A call or dial that runs out of time starts a hold: for `AUTH_OUTAGE_HOLD`
//! every call fails at once, sending nothing. Only a timeout starts it; a real
//! answer (denial included) and a fast transport error never do.
//!
//! A fake `UrcAuthApi` on an ephemeral loopback port counts the requests it
//! receives and answers in a mode the test sets. These tests run in real time:
//! the stub is real TCP, which paused tokio time would race.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use futures::future::join_all;
use lore_base::types::Context as LoreContext;
use lore_base::types::RepositoryId;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::authnz::auth::AUTH_CONNECT_TIMEOUT;
use lore_server::authnz::auth::AUTH_DEADLINE;
use lore_server::authnz::auth::AUTH_OUTAGE_HOLD;
use lore_server::authnz::auth::AuthChannel;
use lore_server::authnz::auth::auth_unavailable_status;
use lore_server::authnz::auth::is_auth_unavailable;
use lore_server::authnz::auth::with_auth_budget;
use lore_server::authnz::repository_authorizer::AuthClientAuthorizer;
use lore_server::authnz::repository_authorizer::Grants;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::VerifiedToken;
use lore_server::authnz::repository_authorizer::flatten_denial;
use lore_server::grpc::no_repository_access_status;
use lore_server::protocol::storage::messages::MessageHandleError;
use tokio_stream::StreamExt;
use tonic::Code;
use tonic::Status;
use tonic::codegen::*;

const ALLOW: u8 = 0;
const DENY: u8 = 1;
const UNAUTHENTICATED: u8 = 2;
/// Allows, but for a resource that is not the one asked about.
const ALLOW_OTHER_RESOURCE: u8 = 3;
/// Answers an allow after five seconds.
const SLOW_ALLOW: u8 = 4;
const HANG: u8 = 5;
/// Answers an allow after four seconds.
const SLOW_ALLOW_4S: u8 = 6;

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
            let allow = |resource_id: String| {
                Ok(tonic::Response::new(
                    lore_proto::auth::CheckUserPermissionResponse {
                        allowed_resource_permission: vec![lore_proto::auth::ResourcePermission {
                            resource_id,
                            permission: vec!["read".to_string()],
                        }],
                        denied_resource_permission: vec![],
                    },
                ))
            };
            match mode {
                ALLOW => allow(resource_id),
                ALLOW_OTHER_RESOURCE => allow("urc-someone-else".to_string()),
                SLOW_ALLOW_4S => {
                    tokio::time::sleep(Duration::from_secs(4)).await;
                    allow(resource_id)
                }
                SLOW_ALLOW => {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    allow(resource_id)
                }
                DENY => Err(tonic::Status::permission_denied("fake: denied")),
                UNAUTHENTICATED => Err(tonic::Status::unauthenticated("fake: who")),
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

/// A fake auth service. It counts the requests that reach it.
struct Stub {
    address: SocketAddr,
    mode: Arc<AtomicU8>,
    calls: Arc<AtomicUsize>,
}

impl Stub {
    fn start(mode: u8) -> Self {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(128).unwrap();
        let address = listener.local_addr().unwrap();
        let mode = Arc::new(AtomicU8::new(mode));
        let calls = Arc::new(AtomicUsize::new(0));
        let service = FakeAuth {
            mode: mode.clone(),
            calls: calls.clone(),
        };
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener).map(|conn| conn);
        // Runs until the test's runtime goes away.
        lore_base::lore_spawn!(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming)
                .await;
        });
        Stub {
            address,
            mode,
            calls,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn set_mode(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// A loopback URL with nothing listening: a connection is refused at once.
fn closed_port_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{address}")
}

async fn check(authorizer: &AuthClientAuthorizer) -> Result<(), Status> {
    // No `resources` claim: the authorizer must ask the auth service.
    let claims = AuthorizationToken::default();
    let token = VerifiedToken {
        raw: "identity.jwt",
        claims: &claims,
    };
    authorizer
        .check_repository_access(Some(&token), repository(), None)
        .await
}

async fn granted(authorizer: &AuthClientAuthorizer) -> Result<Option<Grants>, Status> {
    let claims = AuthorizationToken::default();
    let token = VerifiedToken {
        raw: "identity.jwt",
        claims: &claims,
    };
    let authorizer: &dyn RepositoryAuthorizer = authorizer;
    // `granted_access` is defined on the trait object.
    <dyn RepositoryAuthorizer>::granted_access(authorizer, Some(&token), repository()).await
}

/// Waits out the rest of a hold that started at `since` (plus a margin).
async fn wait_out_hold(since: Instant) {
    let end = since + AUTH_OUTAGE_HOLD + Duration::from_millis(300);
    tokio::time::sleep(end.saturating_duration_since(Instant::now())).await;
}

fn assert_timeout_bound(elapsed: Duration) {
    assert!(
        elapsed >= AUTH_DEADLINE - Duration::from_millis(300),
        "{elapsed:?}"
    );
    assert!(
        elapsed < AUTH_DEADLINE + Duration::from_secs(2),
        "{elapsed:?}"
    );
}

// A. A timeout starts a hold: the next call fails at once, sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_timeout_starts_a_hold_that_fails_the_next_call_at_once() {
    let stub = Stub::start(HANG);
    let authorizer = AuthClientAuthorizer::new(stub.url());

    let started = Instant::now();
    let first = check(&authorizer).await.unwrap_err();
    assert_timeout_bound(started.elapsed());
    assert!(is_auth_unavailable(&first), "{first:?}");
    assert_eq!(first.code(), Code::Internal);
    assert_eq!(stub.calls(), 1);

    let started = Instant::now();
    let second = check(&authorizer).await.unwrap_err();
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "a held call took {:?}",
        started.elapsed()
    );
    assert!(is_auth_unavailable(&second), "{second:?}");
    assert_eq!(second.code(), Code::Internal);
    assert_eq!(second.message(), first.message());
    assert_eq!(stub.calls(), 1, "a held call reached the auth service");
}

// B. The hold ends: the first call after it sends a real request, and a real
// answer to it is not a hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hold_expires_and_the_next_call_reaches_the_service() {
    let stub = Stub::start(HANG);
    let authorizer = AuthClientAuthorizer::new(stub.url());
    check(&authorizer).await.unwrap_err();
    let held_at = Instant::now();
    assert_eq!(stub.calls(), 1);

    // Inside the hold: nothing sent.
    stub.set_mode(DENY);
    assert!(is_auth_unavailable(&check(&authorizer).await.unwrap_err()));
    assert_eq!(stub.calls(), 1);

    wait_out_hold(held_at).await;
    let status = check(&authorizer).await.unwrap_err();
    assert_eq!(stub.calls(), 2, "the call after the hold sent nothing");
    assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
    assert!(!is_auth_unavailable(&status));
}

// C. Recovery: the first call after the hold succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_call_after_the_hold_succeeds_when_the_service_recovered() {
    let stub = Stub::start(HANG);
    let authorizer = AuthClientAuthorizer::new(stub.url());
    check(&authorizer).await.unwrap_err();
    let held_at = Instant::now();

    stub.set_mode(ALLOW);
    assert!(
        is_auth_unavailable(&check(&authorizer).await.unwrap_err()),
        "the hold should outlast the service's recovery"
    );
    wait_out_hold(held_at).await;
    check(&authorizer).await.unwrap();
    // The service answered, so later calls go straight through.
    check(&authorizer).await.unwrap();
    assert_eq!(stub.calls(), 3);
}

// D. A real answer is never a hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_real_answer_never_starts_a_hold() {
    let cases = [
        (DENY, Code::PermissionDenied),
        (UNAUTHENTICATED, Code::Unauthenticated),
        (ALLOW_OTHER_RESOURCE, Code::PermissionDenied),
    ];
    for (mode, code) in cases {
        let stub = Stub::start(mode);
        let authorizer = AuthClientAuthorizer::new(stub.url());
        for round in 1..=3 {
            let started = Instant::now();
            let status = check(&authorizer).await.unwrap_err();
            assert_eq!(status.code(), code, "mode {mode}: {status:?}");
            assert!(!is_auth_unavailable(&status), "mode {mode}: {status:?}");
            assert_eq!(
                stub.calls(),
                round,
                "mode {mode}: call {round} was fast-failed instead of sent"
            );
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_denial_through_granted_access_stays_permission_denied() {
    let cases = [DENY, UNAUTHENTICATED, ALLOW_OTHER_RESOURCE];
    for mode in cases {
        let stub = Stub::start(mode);
        let authorizer = AuthClientAuthorizer::new(stub.url());
        for round in 1..=2 {
            let status = granted(&authorizer).await.unwrap_err();
            assert_eq!(status.code(), Code::PermissionDenied, "mode {mode}");
            assert_eq!(
                status.message(),
                no_repository_access_status().message(),
                "mode {mode}"
            );
            assert!(!is_auth_unavailable(&status));
            assert_eq!(stub.calls(), round, "mode {mode}: a denial was held");
        }
    }
}

// E. A fast transport error is not a hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_connection_is_not_a_hold() {
    let channel = AuthChannel::new(closed_port_url());
    for attempt in 1..=3 {
        let started = Instant::now();
        let status = channel.client().await.map(|_| ()).unwrap_err();
        // A refusal is not a timeout: it ends well before the connect bound
        // (Windows retries a refused loopback connect for about two seconds).
        assert!(started.elapsed() < AUTH_CONNECT_TIMEOUT);
        assert_eq!(status.code(), Code::Internal, "{status:?}");
        assert_eq!(status.message(), "Failed to connect to lore auth service");
        assert!(!is_auth_unavailable(&status), "{status:?}");
        assert_eq!(
            channel.dial_attempts(),
            attempt,
            "attempt {attempt} was fast-failed instead of dialled"
        );
    }
}

// F. Concurrency: 50 callers time out together, then 50 more fail fast.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifty_concurrent_callers_time_out_together_then_fail_fast() {
    let stub = Stub::start(HANG);
    let authorizer = AuthClientAuthorizer::new(stub.url());

    let started = Instant::now();
    let results = tokio::time::timeout(
        AUTH_DEADLINE * 3,
        join_all((0..50).map(|_| check(&authorizer))),
    )
    .await
    .expect("50 callers on a hung service did not finish: deadlock");
    assert_timeout_bound(started.elapsed());
    for result in &results {
        let status = result.as_ref().unwrap_err();
        assert!(is_auth_unavailable(status), "{status:?}");
        assert_eq!(status.code(), Code::Internal);
    }
    let sent = stub.calls();
    assert!((1..=50).contains(&sent), "{sent}");

    let started = Instant::now();
    let results = join_all((0..50).map(|_| check(&authorizer))).await;
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "held callers took {:?}",
        started.elapsed()
    );
    for result in &results {
        assert!(is_auth_unavailable(result.as_ref().unwrap_err()));
    }
    assert_eq!(stub.calls(), sent, "a held caller reached the service");
}

// G. One budget across calls on a task.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_budget_scope_shares_one_deadline_between_calls() {
    let stub = Stub::start(SLOW_ALLOW);
    let authorizer = AuthClientAuthorizer::new(stub.url());

    let started = Instant::now();
    let second_took = with_auth_budget(async {
        check(&authorizer).await.unwrap();
        let used = started.elapsed();
        assert!(used >= Duration::from_secs(5), "{used:?}");
        stub.set_mode(HANG);
        let second_started = Instant::now();
        let status = check(&authorizer).await.unwrap_err();
        assert!(is_auth_unavailable(&status), "{status:?}");
        second_started.elapsed()
    })
    .await;
    let total = started.elapsed();
    assert!(
        second_took >= Duration::from_millis(2500) && second_took < Duration::from_millis(4500),
        "the second call should get the 3 s left, got {second_took:?}"
    );
    assert_timeout_bound(total);
}

fn permission_request() -> tonic::Request<lore_proto::auth::CheckUserPermissionRequest> {
    tonic::Request::new(lore_proto::auth::CheckUserPermissionRequest {
        resource_id: vec![format!("urc-{}", repository())],
        target_user: None,
    })
}

async fn raw_call(channel: &AuthChannel) -> Result<(), Status> {
    channel
        .client()
        .await?
        .check_user_permission(permission_request())
        .await
        .map(|_| ())
}

// A timeout on a call left with less than AUTH_CONNECT_TIMEOUT of a spent
// budget says nothing about the service: no hold, no discarded channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_timeout_on_a_part_spent_budget_starts_no_hold_and_keeps_the_channel() {
    let stub = Stub::start(SLOW_ALLOW_4S);
    let channel = AuthChannel::new(stub.url());

    let started = Instant::now();
    let second_took = with_auth_budget(async {
        raw_call(&channel).await.unwrap();
        stub.set_mode(HANG);
        let second_started = Instant::now();
        let status = raw_call(&channel).await.unwrap_err();
        assert!(is_auth_unavailable(&status), "{status:?}");
        assert_eq!(status.code(), Code::Internal);
        assert!(
            !status
                .message()
                .contains(&format!("within {AUTH_DEADLINE:?}")),
            "the message should name the shorter allowance: {status:?}"
        );
        assert!(
            status
                .message()
                .contains("did not answer check_user_permission within"),
            "{status:?}"
        );
        second_started.elapsed()
    })
    .await;
    assert!(
        second_took >= Duration::from_millis(3000) && second_took < Duration::from_millis(5000),
        "the second call should get the ~4 s left, got {second_took:?}"
    );
    assert!(started.elapsed() < AUTH_DEADLINE + Duration::from_secs(2));
    assert_eq!(stub.calls(), 2);

    // Outside the scope: not fast-failed (it reaches the service), and the
    // channel was kept, so nothing dialled again.
    stub.set_mode(DENY);
    let began = Instant::now();
    let status = raw_call(&channel).await.unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
    assert!(began.elapsed() < Duration::from_secs(2));
    assert_eq!(stub.calls(), 3, "the call after was fast-failed");
    assert_eq!(channel.dial_attempts(), 1, "the channel was discarded");
}

// A few milliseconds of healthy auth earlier in the scope leave the hung call
// a whole allowance (>= AUTH_CONNECT_TIMEOUT): it runs to near the full
// deadline and its timeout does start a hold, discarding the channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_timeout_after_a_few_ms_of_spent_budget_still_starts_a_hold() {
    let stub = Stub::start(ALLOW);
    let channel = AuthChannel::new(stub.url());

    let started = Instant::now();
    with_auth_budget(async {
        raw_call(&channel).await.unwrap();
        stub.set_mode(HANG);
        let status = raw_call(&channel).await.unwrap_err();
        assert!(is_auth_unavailable(&status), "{status:?}");
    })
    .await;
    assert_timeout_bound(started.elapsed());
    assert_eq!(stub.calls(), 2);

    // Outside the scope the hold fails the call at once, sending nothing.
    let began = Instant::now();
    let status = raw_call(&channel).await.unwrap_err();
    assert!(
        began.elapsed() < Duration::from_millis(100),
        "a held call took {:?}",
        began.elapsed()
    );
    assert!(is_auth_unavailable(&status), "{status:?}");
    assert_eq!(stub.calls(), 2, "a held call reached the auth service");
}

// The Copy shape: in one budget scope a healthy partition-style call on repo
// A is answered at once, then the source check on repo B hangs. The hung call
// still had a whole allowance, so its timeout is a real one: unavailable,
// and a hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hung_source_check_after_a_healthy_partition_call_starts_a_hold() {
    let source: RepositoryId = LoreContext::from_str("0194b726b34e72b0b45550b88a967077")
        .unwrap()
        .into();
    let stub = Stub::start(ALLOW);
    let authorizer = AuthClientAuthorizer::new(stub.url());

    let started = Instant::now();
    with_auth_budget(async {
        granted(&authorizer).await.unwrap();
        stub.set_mode(HANG);
        let claims = AuthorizationToken::default();
        let token = VerifiedToken {
            raw: "identity.jwt",
            claims: &claims,
        };
        let status = authorizer
            .check_repository_access(Some(&token), source, None)
            .await
            .unwrap_err();
        assert!(is_auth_unavailable(&status), "{status:?}");
        assert_eq!(status.code(), Code::Internal);
    })
    .await;
    assert_timeout_bound(started.elapsed());
    let sent = stub.calls();
    assert!(sent >= 2, "{sent}");

    let began = Instant::now();
    let status = check(&authorizer).await.unwrap_err();
    assert!(
        began.elapsed() < Duration::from_millis(100),
        "a held call took {:?}",
        began.elapsed()
    );
    assert!(is_auth_unavailable(&status), "{status:?}");
    assert_eq!(stub.calls(), sent, "a held call reached the auth service");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nested_budget_scope_joins_the_outer_one() {
    let stub = Stub::start(SLOW_ALLOW);
    let authorizer = AuthClientAuthorizer::new(stub.url());

    let started = Instant::now();
    with_auth_budget(async {
        check(&authorizer).await.unwrap();
        stub.set_mode(HANG);
        with_auth_budget(async {
            let status = check(&authorizer).await.unwrap_err();
            assert!(is_auth_unavailable(&status), "{status:?}");
        })
        .await;
    })
    .await;
    assert_timeout_bound(started.elapsed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outside_a_budget_scope_each_call_gets_the_full_deadline() {
    let stub = Stub::start(SLOW_ALLOW);
    let authorizer = AuthClientAuthorizer::new(stub.url());

    check(&authorizer).await.unwrap();
    stub.set_mode(HANG);
    let started = Instant::now();
    let status = check(&authorizer).await.unwrap_err();
    assert!(is_auth_unavailable(&status), "{status:?}");
    assert_timeout_bound(started.elapsed());
}

// H. Mapping. These use authorizers that answer at once.

/// Answers every question with the same result.
struct Fixed {
    enumerate: Result<Option<Grants>, Status>,
    check: Result<(), Status>,
}

#[async_trait]
impl RepositoryAuthorizer for Fixed {
    async fn check_repository_access(
        &self,
        _token: Option<&VerifiedToken<'_>>,
        _repository_id: RepositoryId,
        _action: Option<&str>,
    ) -> Result<(), Status> {
        self.check.clone()
    }

    async fn granted_actions(
        &self,
        _token: Option<&VerifiedToken<'_>>,
        _repository_id: RepositoryId,
    ) -> Result<Option<Grants>, Status> {
        self.enumerate.clone()
    }
}

fn unavailable() -> Status {
    auth_unavailable_status(
        "lore auth service did not answer check_user_permission within 8s".into(),
    )
}

#[test]
fn flatten_denial_passes_a_timeout_on_and_flattens_everything_else() {
    let timeout = unavailable();
    let passed = flatten_denial(timeout.clone());
    assert!(is_auth_unavailable(&passed));
    assert_eq!(passed.code(), Code::Internal);
    assert_eq!(passed.message(), timeout.message());

    for other in [
        Status::permission_denied("Query resource denied"),
        Status::unauthenticated("who"),
        Status::internal("Failed to connect to lore auth service"),
        Status::unavailable("down"),
    ] {
        let flat = flatten_denial(other);
        assert_eq!(flat.code(), Code::PermissionDenied);
        assert_eq!(flat.message(), no_repository_access_status().message());
        assert!(!is_auth_unavailable(&flat));
    }
}

#[test]
fn only_this_modules_marker_makes_an_auth_unavailable_status() {
    assert!(is_auth_unavailable(&unavailable()));
    assert!(!is_auth_unavailable(&Status::internal(
        unavailable().message()
    )));
}

#[test]
fn from_authorization_status_tells_a_timeout_from_a_denial() {
    let timeout = MessageHandleError::from_authorization_status(&unavailable());
    assert!(
        matches!(&timeout, MessageHandleError::AuthUnavailable(message)
            if message == unavailable().message()),
        "{timeout:?}"
    );
    for denial in [
        Status::permission_denied("Query resource denied"),
        Status::internal("Failed to connect to lore auth service"),
    ] {
        let mapped = MessageHandleError::from_authorization_status(&denial);
        assert!(
            matches!(&mapped, MessageHandleError::AuthorizationFailure(message)
                if message == denial.message()),
            "{mapped:?}"
        );
    }
}

#[tokio::test]
async fn granted_access_maps_a_timeout_and_a_denial_apart() {
    let timed_out = Fixed {
        enumerate: Err(unavailable()),
        check: Err(unavailable()),
    };
    let authorizer: &dyn RepositoryAuthorizer = &timed_out;
    let status = authorizer
        .granted_access(None, repository())
        .await
        .unwrap_err();
    assert!(is_auth_unavailable(&status), "{status:?}");
    assert_eq!(status.code(), Code::Internal);

    // The per-question path (no enumeration) is mapped the same way.
    let timed_out = Fixed {
        enumerate: Ok(None),
        check: Err(unavailable()),
    };
    let authorizer: &dyn RepositoryAuthorizer = &timed_out;
    let status = authorizer
        .granted_access(None, repository())
        .await
        .unwrap_err();
    assert!(is_auth_unavailable(&status), "{status:?}");

    let denied = Fixed {
        enumerate: Ok(None),
        check: Err(Status::permission_denied("Query resource denied")),
    };
    let authorizer: &dyn RepositoryAuthorizer = &denied;
    let status = authorizer
        .granted_access(None, repository())
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(status.message(), no_repository_access_status().message());

    let enumerated_denial = Fixed {
        enumerate: Ok(Some(Grants::Denied)),
        check: Ok(()),
    };
    let authorizer: &dyn RepositoryAuthorizer = &enumerated_denial;
    let status = authorizer
        .granted_access(None, repository())
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
    assert!(!is_auth_unavailable(&status));
}

#[tokio::test]
async fn require_action_passes_a_timeout_on_and_a_denial_stays_permission_denied() {
    // The fallback per-action check times out.
    let timed_out = Fixed {
        enumerate: Ok(None),
        check: Err(unavailable()),
    };
    let authorizer: &dyn RepositoryAuthorizer = &timed_out;
    // `granted_access` itself asks reachability first, which also times out.
    let status = authorizer
        .require_action(None, repository(), "write")
        .await
        .unwrap_err();
    assert!(is_auth_unavailable(&status), "{status:?}");

    // A denied fallback check is a plain refusal, not a timeout.
    let denied = Fixed {
        enumerate: Ok(None),
        check: Err(Status::permission_denied("no")),
    };
    let authorizer: &dyn RepositoryAuthorizer = &denied;
    let status = authorizer
        .require_action(None, repository(), "write")
        .await
        .unwrap_err();
    assert!(!is_auth_unavailable(&status), "{status:?}");
    assert_eq!(status.code(), Code::PermissionDenied);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn require_action_on_a_hung_service_fails_within_one_deadline() {
    let stub = Stub::start(HANG);
    let authorizer = AuthClientAuthorizer::new(stub.url());
    let authorizer: &dyn RepositoryAuthorizer = &authorizer;
    let claims = AuthorizationToken::default();
    let token = VerifiedToken {
        raw: "identity.jwt",
        claims: &claims,
    };
    let started = Instant::now();
    let status = authorizer
        .require_action(Some(&token), repository(), "write")
        .await
        .unwrap_err();
    assert!(is_auth_unavailable(&status), "{status:?}");
    assert_timeout_bound(started.elapsed());
}
