// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): HTTP content PUT under the strict caller-capability
//! policy and the graceful-drain gate.
//!
//! Everything runs through the real `create_router` and the real
//! `PUT /v1/repository/{id}/content` route, over a local store. A refused PUT
//! is proved to write nothing by the store's fragment count; every refusal is
//! paired with a case in which the same request is served.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::Method;
use axum::http::Request;
use axum::http::Response;
use axum::http::StatusCode;
use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::drain::DrainState;
use lore_server::grpc::caller_capabilities::ADMISSION_HEADER;
use lore_server::grpc::caller_capabilities::CAPABILITIES_HEADER;
use lore_server::grpc::caller_capabilities::CallerCapabilityPolicy;
use lore_server::grpc::caller_capabilities::REQUIRED_CAPABILITY;
use lore_server::http::server::LoreHttpServerSettings;
use lore_server::http::server::ServerHealth;
use lore_server::http::server::ServerState;
use lore_server::http::server::create_router;
use rand::random;
use tower::ServiceExt;

use crate::store::test_support::test_store_create;

const PAYLOAD: &[u8] = b"content-upload-drain-payload";

struct Harness {
    router: Router,
    repository: Context,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    execution: Arc<lore_revision::interface::ExecutionContext>,
}

async fn harness(policy: CallerCapabilityPolicy, drain: Option<Arc<DrainState>>) -> Harness {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    let state = ServerState {
        immutable_store: immutable_store.clone(),
        mutable_store,
        jwt_verifier: None,
        repository_authorizer: Arc::new(AllowAllRepositoryAuthorizer),
        max_file_size: 1024,
        presign_config: None,
        enforce_write_permission: false,
    };
    let mut health = ServerHealth::new_without_availability(immutable_store.clone());
    health.drain = drain;
    let settings = LoreHttpServerSettings {
        caller_capability_policy: policy,
        ..LoreHttpServerSettings::test_default()
    };
    Harness {
        router: create_router(state, health, &settings),
        repository: random::<Context>(),
        immutable_store,
        execution,
    }
}

impl Harness {
    fn put_request(&self, declared: bool, body: Body) -> Request<Body> {
        let mut request = Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/repository/{}/content", self.repository));
        if declared {
            request = request.header(CAPABILITIES_HEADER, REQUIRED_CAPABILITY);
        }
        request.body(body).expect("request")
    }

    async fn put(&self, declared: bool) -> Response<Body> {
        self.router
            .clone()
            .oneshot(self.put_request(declared, Body::from(Bytes::from_static(PAYLOAD))))
            .await
            .expect("router is infallible")
    }

    async fn fragments(&self) -> usize {
        self.immutable_store
            .clone()
            .fragment_count()
            .await
            .expect("the test store must count fragments")
    }
}

/// Runs `body` inside the harness's execution context, boxed so the future
/// stays small.
async fn scoped<F, Fut>(harness: Harness, body: F)
where
    F: FnOnce(Harness) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let execution = harness.execution.clone();
    Box::pin(LORE_CONTEXT.scope(execution, body(harness))).await;
}

// --- strict caller-capability policy ----------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_policy_refuses_an_undeclared_put_without_writing() {
    scoped(
        harness(CallerCapabilityPolicy::RequireOutcomeUnknownV1, None).await,
        |h| async move {
            let before = h.fragments().await;
            let response = h.put(false).await;
            assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
            assert_eq!(
                response
                    .headers()
                    .get(ADMISSION_HEADER)
                    .map(|v| v.as_bytes()),
                Some(b"unsupported-client".as_slice())
            );
            assert_eq!(h.fragments().await, before, "a refused PUT must not write");
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_policy_serves_a_declared_put() {
    scoped(
        harness(CallerCapabilityPolicy::RequireOutcomeUnknownV1, None).await,
        |h| async move {
            let before = h.fragments().await;
            let response = h.put(true).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(response.headers().get(ADMISSION_HEADER).is_none());
            assert!(
                h.fragments().await > before,
                "positive control: a served PUT stores a fragment"
            );
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_compatible_policy_serves_an_undeclared_put() {
    scoped(
        harness(CallerCapabilityPolicy::default(), None).await,
        |h| async move {
            assert_eq!(h.put(false).await.status(), StatusCode::OK);
        },
    )
    .await;
}

// --- the drain gate ----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draining_node_refuses_a_new_put_with_503_before_any_write() {
    let drain = DrainState::new();
    scoped(
        harness(CallerCapabilityPolicy::default(), Some(drain.clone())).await,
        |h| async move {
            let before = h.fragments().await;
            drain.begin_drain();

            let response = h.put(true).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::RETRY_AFTER)
                    .map(|v| v.as_bytes()),
                Some(b"1".as_slice())
            );
            assert_eq!(h.fragments().await, before, "a refused PUT must not write");
            assert_eq!(drain.active_rpc_requests(), 0, "a refusal is not counted");
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_node_serves_a_put_and_leaves_the_count_at_zero() {
    let drain = DrainState::new();
    scoped(
        harness(CallerCapabilityPolicy::default(), Some(drain.clone())).await,
        |h| async move {
            let before = h.fragments().await;
            assert_eq!(h.put(true).await.status(), StatusCode::OK);
            assert!(h.fragments().await > before);
            assert_eq!(drain.active_rpc_requests(), 0);
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_lame_duck_period_still_serves_a_put() {
    let drain = DrainState::new();
    scoped(
        harness(CallerCapabilityPolicy::default(), Some(drain.clone())).await,
        |h| async move {
            drain.begin_lame_duck();
            assert!(drain.is_draining() && drain.is_lame_duck());

            let before = h.fragments().await;
            assert_eq!(h.put(true).await.status(), StatusCode::OK);
            assert!(h.fragments().await > before, "a lame-duck PUT is served");
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_closes_when_the_lame_duck_period_ends() {
    let drain = DrainState::new();
    scoped(
        harness(CallerCapabilityPolicy::default(), Some(drain.clone())).await,
        |h| async move {
            drain.begin_lame_duck();
            drain.end_lame_duck();

            assert_eq!(h.put(true).await.status(), StatusCode::SERVICE_UNAVAILABLE);
        },
    )
    .await;
}

/// The drain gate sits outside capability admission, as the gRPC drain layer
/// sits outside the gRPC admission layer: a draining node says "go elsewhere"
/// to every PUT, declared or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_drain_refusal_precedes_the_capability_refusal() {
    let drain = DrainState::new();
    scoped(
        harness(
            CallerCapabilityPolicy::RequireOutcomeUnknownV1,
            Some(drain.clone()),
        )
        .await,
        |h| async move {
            drain.begin_drain();

            let response = h.put(false).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(response.headers().get(ADMISSION_HEADER).is_none());
        },
    )
    .await;
}

/// Only a PUT is gated and counted: reads and the drain status stay up through
/// a drain, so a deploy controller can poll it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_status_stays_readable_and_uncounted_while_draining() {
    let drain = DrainState::new();
    scoped(
        harness(CallerCapabilityPolicy::default(), Some(drain.clone())).await,
        |h| async move {
            drain.begin_drain();

            let response = h
                .router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/drain_status")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("router is infallible");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(drain.active_rpc_requests(), 0);
        },
    )
    .await;
}

/// Polls `condition` for up to five seconds, driving `pending` meanwhile. A
/// completed `pending` before the condition holds is a failure.
async fn wait_until_in_flight<F, T>(
    drain: &DrainState,
    pending: &mut std::pin::Pin<&mut F>,
    expected: u64,
) where
    F: std::future::Future<Output = T>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while drain.active_rpc_requests() != expected {
        assert!(
            tokio::time::Instant::now() < deadline,
            "active_rpc_requests never reached {expected}, now {}",
            drain.active_rpc_requests()
        );
        tokio::select! {
            _ = &mut *pending => panic!("the PUT finished before its body was complete"),
            () = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
}

/// An in-flight PUT counts as public RPC work for its whole life, a drain that
/// begins mid-request does not cut it off, and the count is released when it
/// ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_in_flight_put_is_counted_survives_a_drain_and_is_released() {
    let drain = DrainState::new();
    scoped(
        harness(CallerCapabilityPolicy::default(), Some(drain.clone())).await,
        |h| async move {
            let before = h.fragments().await;
            let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(4);
            let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(receiver));
            let call = h.router.clone().oneshot(h.put_request(true, body));
            tokio::pin!(call);

            // The handler is blocked reading the body we have not finished.
            sender
                .send(Ok(Bytes::from_static(&PAYLOAD[..4])))
                .await
                .expect("body open");
            wait_until_in_flight(&drain, &mut call, 1).await;
            assert!(!drain.is_drained());

            // A drain that starts now does not cut the request off.
            drain.begin_drain();
            assert!(
                !drain.is_drained(),
                "a node with a PUT in flight is not drained"
            );

            sender
                .send(Ok(Bytes::from_static(&PAYLOAD[4..])))
                .await
                .expect("body open");
            drop(sender);
            let response = call.await.expect("router is infallible");
            assert_eq!(response.status(), StatusCode::OK);
            assert!(h.fragments().await > before, "the admitted PUT completed");

            // Released once the response is done.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while drain.active_rpc_requests() != 0 {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the count was never released"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(drain.is_drained());
        },
    )
    .await;
}

/// The guard releases on a failed request too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_put_releases_the_count() {
    let drain = DrainState::new();
    scoped(
        harness(
            CallerCapabilityPolicy::RequireOutcomeUnknownV1,
            Some(drain.clone()),
        )
        .await,
        |h| async move {
            // Admitted by the drain gate, refused by capability admission.
            assert_eq!(h.put(false).await.status(), StatusCode::PRECONDITION_FAILED);
            assert_eq!(drain.active_rpc_requests(), 0);
        },
    )
    .await;
}
