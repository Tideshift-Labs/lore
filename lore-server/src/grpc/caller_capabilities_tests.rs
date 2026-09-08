// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::Ready;
use std::future::ready;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use http::HeaderValue;

use super::*;

#[path = "caller_read_repairs_tests.rs"]
pub(crate) mod read_repairs;

fn headers(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CAPABILITIES_HEADER, HeaderValue::from_str(value).unwrap());
    headers
}

fn refused(status: Status) {
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(status.message(), "unsupported client capability");
    assert_eq!(
        status.metadata().get_all(ADMISSION_HEADER).iter().count(),
        1
    );
    assert_eq!(
        status.metadata().get(ADMISSION_HEADER).unwrap(),
        "unsupported-client"
    );
}

#[test]
fn grammar_accepts_only_bounded_sorted_unique_ascii_tokens() {
    assert!(!declares_outcome_unknown(&HeaderMap::new()).unwrap());
    for value in ["outcome_unknown_v1", "a,outcome_unknown_v1,z"] {
        assert!(declares_outcome_unknown(&headers(value)).unwrap());
    }
    assert!(!declares_outcome_unknown(&headers("other_capability")).unwrap());
    for value in [
        "",
        " outcome_unknown_v1",
        "outcome_unknown_v1 ",
        "a,,outcome_unknown_v1",
        "outcome_unknown_v1,",
        "outcome_unknown_v1,outcome_unknown_v1",
        "z,outcome_unknown_v1",
        "Outcome_unknown_v1",
        "0foo",
        "outcome-unknown-v1",
    ] {
        refused(declares_outcome_unknown(&headers(value)).unwrap_err());
    }
    assert!(!declares_outcome_unknown(&headers(&"a".repeat(64))).unwrap());
    refused(declares_outcome_unknown(&headers(&"a".repeat(65))).unwrap_err());
    let sixteen = (0..16)
        .map(|i| format!("a{i:02}"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(!declares_outcome_unknown(&headers(&sixteen)).unwrap());
    refused(declares_outcome_unknown(&headers(&format!("{sixteen},a16"))).unwrap_err());
    let mut duplicate = headers(REQUIRED_CAPABILITY);
    duplicate.append(
        CAPABILITIES_HEADER,
        HeaderValue::from_static(REQUIRED_CAPABILITY),
    );
    refused(declares_outcome_unknown(&duplicate).unwrap_err());
    let mut non_ascii = HeaderMap::new();
    non_ascii.insert(
        CAPABILITIES_HEADER,
        HeaderValue::from_bytes(&[0xff]).unwrap(),
    );
    refused(declares_outcome_unknown(&non_ascii).unwrap_err());
    let mut maximum = (0..16)
        .map(|i| format!("a{i:02}{}", "x".repeat(60)))
        .collect::<Vec<_>>();
    maximum[15].push('x');
    let value = maximum.join(",");
    assert_eq!(value.len(), 1024);
    assert!(!declares_outcome_unknown(&headers(&value)).unwrap());
    maximum[14].push('x');
    refused(declares_outcome_unknown(&headers(&maximum.join(","))).unwrap_err());
}

#[test]
fn required_mode_checks_mutations_and_unknown_paths_without_jwt_exemption() {
    let mut auth = HeaderMap::new();
    auth.insert(
        "authorization",
        HeaderValue::from_static("Bearer service-account-token"),
    );
    let mut declared = headers(REQUIRED_CAPABILITY);
    declared.insert(
        "lore-attempt-id",
        HeaderValue::from_str(&uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    for (path, class) in RPC_INVENTORY {
        match class {
            RpcClass::Read => {
                admit(CallerCapabilityPolicy::RequireOutcomeUnknownV1, path, &auth).unwrap()
            }
            RpcClass::Mutation => {
                refused(
                    admit(CallerCapabilityPolicy::RequireOutcomeUnknownV1, path, &auth)
                        .unwrap_err(),
                );
                let admitted = admit(
                    CallerCapabilityPolicy::RequireOutcomeUnknownV1,
                    path,
                    &declared,
                );
                if [
                    "/urc.rpc.RevisionService/BranchCreate",
                    "/urc.rpc.RevisionService/BranchDelete",
                    "/lore.revision.v1.RevisionService/BranchCreate",
                    "/lore.revision.v1.RevisionService/BranchDelete",
                ]
                .contains(path)
                {
                    refused(admitted.unwrap_err());
                } else {
                    admitted.unwrap();
                }
            }
        }
    }
    refused(
        admit(
            CallerCapabilityPolicy::RequireOutcomeUnknownV1,
            "/unknown/Write",
            &headers(REQUIRED_CAPABILITY),
        )
        .unwrap_err(),
    );
    admit(
        CallerCapabilityPolicy::CompatibleSingleReplica,
        "/unknown/Write",
        &headers("malformed,"),
    )
    .unwrap();
    for path in [
        "/urc.rpc.StorageService/Verify",
        "/urc.rpc.StorageService/MutableCompareAndSwap",
    ] {
        assert_eq!(classify_rpc(path), Some(RpcClass::Mutation));
    }
}

#[test]
fn governed_repository_lifecycle_requires_attempt_identity_after_capability() {
    for path in [
        "/urc.rpc.RepositoryService/RepositoryCreate",
        "/urc.rpc.RepositoryService/RepositoryDelete",
        "/lore.repository.v1.RepositoryService/RepositoryCreate",
        "/lore.repository.v1.RepositoryService/RepositoryDelete",
    ] {
        for attempt in [
            None,
            Some("invalid"),
            Some("00000000-0000-0000-0000-000000000000"),
        ] {
            let mut declaration = headers(REQUIRED_CAPABILITY);
            if let Some(attempt) = attempt {
                declaration.insert("lore-attempt-id", HeaderValue::from_str(attempt).unwrap());
            }
            let error = admit(
                CallerCapabilityPolicy::RequireOutcomeUnknownV1,
                path,
                &declaration,
            )
            .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument, "{path}");
        }
    }
}

#[derive(Clone)]
struct Handler(Arc<AtomicUsize>);
impl<B> Service<Request<B>> for Handler {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Request<B>) -> Self::Future {
        self.0.fetch_add(1, Ordering::SeqCst);
        ready(Ok(Response::new(Body::empty())))
    }
}

struct UnreadBody;
impl http_body::Body for UnreadBody {
    type Data = bytes::Bytes;
    type Error = Infallible;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        panic!("refused request body must not be polled")
    }
}

#[tokio::test]
async fn layer_refuses_before_handler_or_stream_body_and_has_positive_control() {
    let called = Arc::new(AtomicUsize::new(0));
    let mut service = CallerCapabilityLayer::new(CallerCapabilityPolicy::RequireOutcomeUnknownV1)
        .layer(Handler(called.clone()));
    let request = Request::builder()
        .uri("/urc.rpc.StorageService/Put")
        .body(UnreadBody)
        .unwrap();
    let response = service.call(request).await.unwrap();
    assert_eq!(response.headers().get("grpc-status").unwrap(), "9");
    assert_eq!(
        response.headers().get_all(ADMISSION_HEADER).iter().count(),
        1
    );
    assert_eq!(
        response.headers().get(ADMISSION_HEADER).unwrap(),
        "unsupported-client"
    );
    assert_eq!(called.load(Ordering::SeqCst), 0);
    let request = Request::builder()
        .uri("/urc.rpc.StorageService/Put")
        .header(CAPABILITIES_HEADER, REQUIRED_CAPABILITY)
        .body(UnreadBody)
        .unwrap();
    service.call(request).await.unwrap();
    assert_eq!(called.load(Ordering::SeqCst), 1);
}

fn proto_methods(source: &str) -> BTreeSet<String> {
    let mut package = "";
    let mut service = "";
    let mut methods = BTreeSet::new();
    for line in source.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("package ") {
            package = rest.trim_end_matches(';');
        }
        if let Some(rest) = line.strip_prefix("service ") {
            service = rest.split_whitespace().next().unwrap();
        }
        if let Some(rest) = line.strip_prefix("rpc ") {
            let method = rest.split(['(', ' ']).next().unwrap();
            methods.insert(format!("/{package}.{service}/{method}"));
        }
    }
    methods
}

#[test]
fn inventory_matches_every_method_in_registered_proto_services() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut declared = BTreeSet::new();
    for file in [
        "src/legacy/proto/storage.proto",
        "src/legacy/proto/repository.proto",
        "src/legacy/proto/revision.proto",
        "../lore-proto/proto/admin.proto",
        "../lore-proto/proto/lock.proto",
        "../lore-proto/proto/environment.proto",
        "../lore-proto/proto/notification.proto",
        "../lore-proto/proto/lore_notification.proto",
        "../lore-proto/proto/lore/domain/v1/domain_operation.proto",
        "../lore-proto/proto/lore/environment/v1/environment.proto",
        "../lore-proto/proto/lore/repository/v1/repository.proto",
        "../lore-proto/proto/lore/revision/v1/revision.proto",
        "../lore-proto/proto/lore/storage/v1/storage.proto",
        "../lore-proto/proto/lore/thin_client/v1/thin_client.proto",
    ] {
        for method in proto_methods(&std::fs::read_to_string(root.join(file)).unwrap()) {
            // These declarations are not mounted public services; required mode
            // forbids forwarded ingress separately during startup validation.
            if method.starts_with("/urc.notification.")
                || method.starts_with("/lore.repository.v1.ForwardedRepositoryService/")
                || method.starts_with("/lore.revision.v1.ForwardedRevisionService/")
            {
                assert_eq!(classify_rpc(&method), None);
            } else {
                declared.insert(method);
            }
        }
    }
    let actual: BTreeSet<_> = RPC_INVENTORY
        .iter()
        .map(|(path, _)| path.to_string())
        .collect();
    assert_eq!(
        actual.len(),
        RPC_INVENTORY.len(),
        "duplicate classification entries"
    );
    assert_eq!(actual, declared);
    assert!(
        actual.len() > 70,
        "service inventory must not become vacuous"
    );
}

fn guarded_settings() -> crate::settings::Settings {
    let mut settings: crate::settings::Settings =
        toml::from_str(include_str!("../../config/default.toml")).unwrap();
    settings
        .server
        .grpc
        .as_mut()
        .unwrap()
        .caller_capability_policy = CallerCapabilityPolicy::RequireOutcomeUnknownV1;
    settings.server.quic.as_mut().unwrap().enabled = false;
    settings.server.auth =
        Some(toml::from_str("[jwk]\nendpoint = 'http://jwks/.well-known/jwks.json'").unwrap());
    settings
}

#[test]
fn required_policy_refuses_unguarded_transports_and_missing_auth() {
    validate_settings(&guarded_settings()).unwrap();
    for change in 0..6 {
        let mut settings = guarded_settings();
        match change {
            0 => settings.server.auth = None,
            1 => settings.server.quic.as_mut().unwrap().enabled = true,
            2 => settings.server.quic_internal.as_mut().unwrap().enabled = true,
            3 => settings.server.grpc_internal.as_mut().unwrap().enabled = true,
            4 => settings.immutable_store.mode = "remote".into(),
            5 => settings.mutable_store.mode = "remote".into(),
            _ => unreachable!(),
        }
        assert!(
            validate_settings(&settings).is_err(),
            "unsafe setting {change}"
        );
        settings
            .server
            .grpc
            .as_mut()
            .unwrap()
            .caller_capability_policy = CallerCapabilityPolicy::CompatibleSingleReplica;
        validate_settings(&settings).unwrap();
    }
}

#[tokio::test]
async fn http_put_gate_refuses_before_handler_and_body_with_positive_control() {
    use axum::Router;
    use axum::middleware;
    use axum::routing::put;
    use tower::ServiceExt;
    let called = Arc::new(AtomicUsize::new(0));
    let count = called.clone();
    let router = Router::new()
        .route(
            "/content",
            put(move || {
                count.fetch_add(1, Ordering::SeqCst);
                async { "accepted" }
            }),
        )
        .layer(middleware::from_fn_with_state(
            CallerCapabilityPolicy::RequireOutcomeUnknownV1,
            crate::http::server::caller_capability_admission,
        ));
    let refused = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/content")
                .body(axum::body::Body::new(UnreadBody))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), http::StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        refused.headers().get(ADMISSION_HEADER).unwrap(),
        "unsupported-client"
    );
    assert_eq!(called.load(Ordering::SeqCst), 0);
    let accepted = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/content")
                .header(CAPABILITIES_HEADER, REQUIRED_CAPABILITY)
                .body(axum::body::Body::new(UnreadBody))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), http::StatusCode::OK);
    assert_eq!(called.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn readiness_reports_the_frozen_policy_and_contract() {
    for (policy, label, required) in [
        (
            CallerCapabilityPolicy::CompatibleSingleReplica,
            "compatible_single_replica",
            false,
        ),
        (
            CallerCapabilityPolicy::RequireOutcomeUnknownV1,
            "require_outcome_unknown_v1",
            true,
        ),
    ] {
        let axum::Json(value) =
            crate::http::server::caller_capability_readiness(axum::extract::State(policy)).await;
        assert_eq!(value["policy"], label);
        assert_eq!(value["contract"], "grpc-caller-capability-admission-v1");
        let features = value["features"].as_array().unwrap();
        assert!(features.contains(&serde_json::json!("outcome_unknown_v1")));
        assert_eq!(
            features.contains(&serde_json::json!("requires_outcome_unknown_v1")),
            required
        );
        assert_eq!(
            admit(policy, "/urc.rpc.StorageService/Put", &HeaderMap::new()).is_err(),
            required
        );
    }
}

#[test]
fn required_postgres_serving_policy_requires_the_actual_coordinated_route() {
    for postgres in [false, true] {
        for coordinated in [false, true] {
            let required = validate_serving_fragment_route(
                CallerCapabilityPolicy::RequireOutcomeUnknownV1,
                postgres,
                coordinated,
            );
            assert_eq!(
                required.is_ok(),
                !postgres || coordinated,
                "postgres={postgres} coordinated={coordinated}"
            );
            validate_serving_fragment_route(
                CallerCapabilityPolicy::CompatibleSingleReplica,
                postgres,
                coordinated,
            )
            .unwrap();
        }
    }
}
