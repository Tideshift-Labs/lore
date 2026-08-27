// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use lore_object_dispatch::DispatchMetricRecorder;
use lore_object_dispatch::DispatchRpc;
use lore_object_dispatch::SERVICE_CONFIG_REVISION;
use lore_object_dispatch::SOURCE_DARK_STATUS_MESSAGE;
use lore_object_dispatch::ServiceConfig;
use lore_object_dispatch::ServiceConfigError;
use lore_object_dispatch::ServiceServerError;
use lore_object_dispatch::SourceDarkObjectStoreDispatchService;
use lore_object_dispatch::config::LISTEN_ADDR_ENV;
use lore_object_dispatch::config::SERVICE_CONFIG_REVISION_ENV;
use lore_object_dispatch::serve_prebound;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestQueryV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultFetchV1;
use lore_proto::lore::object_dispatch::v1::ReservePutRequestV1;
use lore_proto::lore::object_dispatch::v1::UploadPutChunkV1;
use lore_proto::lore::object_dispatch::v1::object_store_dispatch_service_client::ObjectStoreDispatchServiceClient;
use lore_proto::lore::object_dispatch::v1::object_store_dispatch_service_server::ObjectStoreDispatchService;
use lore_proto::lore::object_dispatch::v1::object_store_dispatch_service_server::ObjectStoreDispatchServiceServer;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tonic::Code;
use tonic::Request;
use tonic::Status;
use tonic::transport::Server;

const REVISION: &str = "object-store-dispatch-service-shell-v1";
const ADDRESS: &str = "127.0.0.1:50051";
const RPC_TIMEOUT: Duration = Duration::from_secs(2);

fn config_vars(address: &str) -> [(&'static str, &str); 2] {
    [
        (SERVICE_CONFIG_REVISION_ENV, REVISION),
        (LISTEN_ADDR_ENV, address),
    ]
}

fn assert_source_dark(status: Status) {
    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(status.message(), SOURCE_DARK_STATUS_MESSAGE);
    assert!(status.details().is_empty());
}

#[derive(Default)]
struct RecordingMetrics {
    calls: Mutex<Vec<DispatchRpc>>,
}

impl DispatchMetricRecorder for RecordingMetrics {
    fn record_source_dark_rejection(&self, rpc: DispatchRpc) {
        self.calls
            .lock()
            .expect("test metric recorder mutex must remain healthy")
            .push(rpc);
    }
}

#[test]
fn service_config_accepts_only_the_exact_required_surface() {
    let config = ServiceConfig::from_prefixed_vars(config_vars(ADDRESS))
        .expect("exact shell configuration must parse");

    assert_eq!(config.service_config_revision(), SERVICE_CONFIG_REVISION);
    assert_eq!(config.listen_addr().to_string(), ADDRESS);
}

#[test]
fn service_config_has_no_implicit_defaults() {
    assert_eq!(
        ServiceConfig::from_prefixed_vars(std::iter::empty::<(&str, &str)>()),
        Err(ServiceConfigError::MissingRevision)
    );
    assert_eq!(
        ServiceConfig::from_prefixed_vars([(SERVICE_CONFIG_REVISION_ENV, REVISION)]),
        Err(ServiceConfigError::MissingListenAddress)
    );
}

#[test]
fn service_config_rejects_changed_revision() {
    let vars = [
        (
            SERVICE_CONFIG_REVISION_ENV,
            "object-store-dispatch-service-shell-v2",
        ),
        (LISTEN_ADDR_ENV, ADDRESS),
    ];

    assert_eq!(
        ServiceConfig::from_prefixed_vars(vars),
        Err(ServiceConfigError::RevisionMismatch)
    );
}

#[test]
fn service_config_rejects_unknown_object_dispatch_keys() {
    let vars = [
        (SERVICE_CONFIG_REVISION_ENV, REVISION),
        (LISTEN_ADDR_ENV, ADDRESS),
        (
            "LORE_OBJECT_DISPATCH_CONTINUITY_DATABASE_URL",
            "postgresql://must-not-be-consumed",
        ),
    ];

    assert_eq!(
        ServiceConfig::from_prefixed_vars(vars),
        Err(ServiceConfigError::UnknownVariable)
    );
}

#[cfg(unix)]
#[test]
fn service_config_rejects_bytewise_prefixed_nonunicode_key() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let mut key = b"LORE_OBJECT_DISPATCH_".to_vec();
    key.push(0xff);

    assert_eq!(
        ServiceConfig::from_prefixed_vars([(OsString::from_vec(key), OsString::from("value"))]),
        Err(ServiceConfigError::NonUnicodeKey)
    );
}

#[test]
fn service_config_ignores_unrelated_environment_keys() {
    let vars = [
        (SERVICE_CONFIG_REVISION_ENV, REVISION),
        (LISTEN_ADDR_ENV, ADDRESS),
        ("UNRELATED_SECRET", "must-not-be-read"),
    ];

    assert!(ServiceConfig::from_prefixed_vars(vars).is_ok());
}

#[test]
fn service_config_rejects_duplicate_keys() {
    let vars = [
        (SERVICE_CONFIG_REVISION_ENV, REVISION),
        (SERVICE_CONFIG_REVISION_ENV, REVISION),
        (LISTEN_ADDR_ENV, ADDRESS),
    ];

    assert_eq!(
        ServiceConfig::from_prefixed_vars(vars),
        Err(ServiceConfigError::DuplicateVariable)
    );
}

#[test]
fn service_config_rejects_non_loopback_or_zero_port_listeners() {
    for address in ["0.0.0.0:50051", "192.0.2.1:50051", "127.0.0.1:0"] {
        assert_eq!(
            ServiceConfig::from_prefixed_vars(config_vars(address)),
            Err(ServiceConfigError::UnsafeListenAddress),
            "address {address} must stay unavailable to the source-dark shell"
        );
    }
}

#[test]
fn service_config_rejects_malformed_listener() {
    assert_eq!(
        ServiceConfig::from_prefixed_vars(config_vars("localhost:50051")),
        Err(ServiceConfigError::InvalidListenAddress)
    );
}

#[test]
fn service_config_debug_contains_only_validated_nonsecret_values() {
    let config = ServiceConfig::from_prefixed_vars(config_vars(ADDRESS))
        .expect("exact shell configuration must parse");

    assert_eq!(
        format!("{config:?}"),
        "ServiceConfig { service_config_revision: \"object-store-dispatch-service-shell-v1\", listen_addr: 127.0.0.1:50051 }"
    );
}

#[tokio::test]
async fn direct_unary_and_fetch_handlers_return_one_redacted_status() {
    lore_base::runtime::LORE_CONTEXT
        .scope(Arc::new(()), async {
            let service = SourceDarkObjectStoreDispatchService::new();

            assert_source_dark(
                service
                    .reserve_put(Request::new(ReservePutRequestV1::default()))
                    .await
                    .expect_err("ReservePut must stay source-dark"),
            );
            assert_source_dark(
                service
                    .submit(Request::new(ObjectStoreRequestV1::default()))
                    .await
                    .expect_err("Submit must stay source-dark"),
            );
            assert_source_dark(
                service
                    .get_request(Request::new(ObjectStoreRequestQueryV1::default()))
                    .await
                    .expect_err("GetRequest must stay source-dark"),
            );
            let fetch_status = match service
                .fetch_result(Request::new(ObjectStoreResultFetchV1::default()))
                .await
            {
                Ok(_) => panic!("FetchResult must fail before returning a stream"),
                Err(status) => status,
            };
            assert_source_dark(fetch_status);
            assert_source_dark(
                service
                    .acknowledge_result(Request::new(ObjectStoreResultAckV1::default()))
                    .await
                    .expect_err("AcknowledgeResult must stay source-dark"),
            );
            assert_source_dark(
                service
                    .discard_result(Request::new(ObjectStoreResultDiscardV1::default()))
                    .await
                    .expect_err("DiscardResult must stay source-dark"),
            );
        })
        .await;
}

#[test]
fn generated_server_accepts_the_source_dark_service() {
    fn generated_server<T: ObjectStoreDispatchService>(service: T) {
        let _server = ObjectStoreDispatchServiceServer::new(service);
    }

    generated_server(SourceDarkObjectStoreDispatchService::new());
}

#[tokio::test]
async fn prebound_server_keeps_all_seven_rpc_paths_source_dark_and_shuts_down() {
    lore_base::runtime::LORE_CONTEXT
        .scope(Arc::new(()), async {
            let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener must bind");
            let address = listener
                .local_addr()
                .expect("listener must expose its address");
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let server = lore_base::lore_spawn!(async move {
                serve_prebound(listener, async move {
                    let _ = shutdown_rx.await;
                })
                .await
            });
            let mut client = ObjectStoreDispatchServiceClient::connect(format!("http://{address}"))
                .await
                .expect("pre-bound source-dark server must accept a client");

            assert_source_dark(
                client
                    .reserve_put(ReservePutRequestV1::default())
                    .await
                    .expect_err("ReservePut must stay source-dark"),
            );
            let upload = timeout(
                RPC_TIMEOUT,
                client.upload_put(tokio_stream::pending::<UploadPutChunkV1>()),
            )
            .await
            .expect("UploadPut must return before polling a request frame")
            .expect_err("UploadPut must stay source-dark");
            assert_source_dark(upload);
            assert_source_dark(
                client
                    .submit(ObjectStoreRequestV1::default())
                    .await
                    .expect_err("Submit must stay source-dark"),
            );
            assert_source_dark(
                client
                    .get_request(ObjectStoreRequestQueryV1::default())
                    .await
                    .expect_err("GetRequest must stay source-dark"),
            );
            assert_source_dark(
                client
                    .fetch_result(ObjectStoreResultFetchV1::default())
                    .await
                    .expect_err("FetchResult must fail before returning a stream"),
            );
            assert_source_dark(
                client
                    .acknowledge_result(ObjectStoreResultAckV1::default())
                    .await
                    .expect_err("AcknowledgeResult must stay source-dark"),
            );
            assert_source_dark(
                client
                    .discard_result(ObjectStoreResultDiscardV1::default())
                    .await
                    .expect_err("DiscardResult must stay source-dark"),
            );

            shutdown_tx
                .send(())
                .expect("server shutdown receiver must remain live");
            timeout(RPC_TIMEOUT, server)
                .await
                .expect("graceful shutdown must be bounded")
                .expect("server task must not panic")
                .expect("server must shut down cleanly");
        })
        .await;
}

#[tokio::test]
async fn prebound_server_rejects_an_unsafe_listener_before_serving() {
    lore_base::runtime::LORE_CONTEXT
        .scope(Arc::new(()), async {
            let listener = TcpListener::bind("0.0.0.0:0").expect("wildcard listener must bind");

            assert_eq!(
                serve_prebound(listener, std::future::pending()).await,
                Err(ServiceServerError::UnsafeListener)
            );
        })
        .await;
}

#[tokio::test]
async fn metric_recorder_observes_each_closed_rpc_value_exactly_once() {
    lore_base::runtime::LORE_CONTEXT
        .scope(Arc::new(()), async {
            let recorder = Arc::new(RecordingMetrics::default());
            let service =
                SourceDarkObjectStoreDispatchService::with_metric_recorder(recorder.clone());
            let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener must bind");
            let address = listener
                .local_addr()
                .expect("listener must expose its address");
            listener
                .set_nonblocking(true)
                .expect("test listener must become nonblocking");
            let listener = tokio::net::TcpListener::from_std(listener)
                .expect("Tokio must adopt the pre-bound listener");
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let server = lore_base::lore_spawn!(async move {
                Server::builder()
                    .add_service(ObjectStoreDispatchServiceServer::new(service))
                    .serve_with_incoming_shutdown(
                        tokio_stream::wrappers::TcpListenerStream::new(listener),
                        async move {
                            let _ = shutdown_rx.await;
                        },
                    )
                    .await
            });
            let mut client = ObjectStoreDispatchServiceClient::connect(format!("http://{address}"))
                .await
                .expect("instrumented source-dark server must accept a client");

            assert_source_dark(
                client
                    .reserve_put(ReservePutRequestV1::default())
                    .await
                    .expect_err("ReservePut must stay source-dark"),
            );
            assert_source_dark(
                timeout(
                    RPC_TIMEOUT,
                    client.upload_put(tokio_stream::pending::<UploadPutChunkV1>()),
                )
                .await
                .expect("UploadPut must return before polling a request frame")
                .expect_err("UploadPut must stay source-dark"),
            );
            assert_source_dark(
                client
                    .submit(ObjectStoreRequestV1::default())
                    .await
                    .expect_err("Submit must stay source-dark"),
            );
            assert_source_dark(
                client
                    .get_request(ObjectStoreRequestQueryV1::default())
                    .await
                    .expect_err("GetRequest must stay source-dark"),
            );
            assert_source_dark(
                client
                    .fetch_result(ObjectStoreResultFetchV1::default())
                    .await
                    .expect_err("FetchResult must fail before returning a stream"),
            );
            assert_source_dark(
                client
                    .acknowledge_result(ObjectStoreResultAckV1::default())
                    .await
                    .expect_err("AcknowledgeResult must stay source-dark"),
            );
            assert_source_dark(
                client
                    .discard_result(ObjectStoreResultDiscardV1::default())
                    .await
                    .expect_err("DiscardResult must stay source-dark"),
            );

            shutdown_tx
                .send(())
                .expect("metric server shutdown receiver must remain live");
            timeout(RPC_TIMEOUT, server)
                .await
                .expect("metric server shutdown must be bounded")
                .expect("metric server task must not panic")
                .expect("metric server must shut down cleanly");

            assert_eq!(
                *recorder
                    .calls
                    .lock()
                    .expect("test metric recorder mutex must remain healthy"),
                DispatchRpc::ALL
            );
            assert_eq!(
                DispatchRpc::ALL.map(DispatchRpc::metric_label),
                [
                    "ReservePut",
                    "UploadPut",
                    "Submit",
                    "GetRequest",
                    "FetchResult",
                    "AcknowledgeResult",
                    "DiscardResult",
                ]
            );

            let server_source = std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server.rs"),
            )
            .expect("server source must be readable by its source-contract test");
            let metrics_source = std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("src/metrics.rs"),
            )
            .expect("metrics source must be readable by its source-contract test");
            for forbidden in [
                "GrpcMetricsLayer",
                "UserAgentFilter",
                "user_agent",
                "http.route",
                "request.uri",
            ] {
                assert!(
                    !server_source.contains(forbidden) && !metrics_source.contains(forbidden),
                    "closed dispatch metrics must not accept arbitrary surface {forbidden}"
                );
            }
            assert_eq!(
                metrics_source.matches("KeyValue::new(").count(),
                3,
                "default metric emission must have exactly three closed labels"
            );
            assert!(metrics_source.contains(r#"KeyValue::new("rpc.method", rpc.metric_label())"#));
            assert!(
                metrics_source.contains(r#"KeyValue::new("rpc.grpc.status_code", "Unavailable")"#)
            );
            assert!(metrics_source.contains(r#"KeyValue::new("outcome", "source_dark")"#));
        })
        .await;
}

#[test]
fn source_dark_service_has_no_authority_or_effect_dependencies() {
    let service_source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service.rs"))
            .expect("service source must be readable by its source-contract test");
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("crate manifest must be readable by its source-contract test");

    for forbidden in [
        "crate::continuity",
        "crate::schema",
        "std::fs",
        "tokio_postgres",
        "aws_sdk",
        "lore_aws",
        "lore_postgres",
    ] {
        assert!(
            !service_source.contains(forbidden),
            "source-dark service must not depend on {forbidden}"
        );
    }
    for forbidden_dependency in ["aws-sdk-", "lore-aws", "lore-postgres"] {
        assert!(
            !manifest.contains(forbidden_dependency),
            "source-dark service manifest must not add {forbidden_dependency}"
        );
    }
}

#[test]
fn dockerfile_builds_a_nonroot_source_dark_runtime_image() {
    let dockerfile =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Dockerfile"))
            .expect("Dockerfile must be readable by its source-contract test");
    let uppercase = dockerfile.to_ascii_uppercase();

    let base_images = dockerfile
        .lines()
        .filter(|line| line.starts_with("FROM "))
        .collect::<Vec<_>>();
    assert_eq!(
        base_images.len(),
        2,
        "the image must use separate build and runtime stages"
    );
    for base_image in base_images {
        let digest = base_image
            .split("@sha256:")
            .nth(1)
            .and_then(|tail| tail.split_whitespace().next())
            .expect("every base image must be pinned by SHA-256 digest");
        assert_eq!(digest.len(), 64, "base-image digest must contain 32 bytes");
        assert!(
            digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "base-image digest must be hexadecimal"
        );
    }
    assert!(dockerfile.contains("cargo build --release --locked --bin lore-object-dispatch"));
    assert!(dockerfile.contains("COPY --from=builder /build/lore-object-dispatch-bin"));
    assert!(dockerfile.contains("groupadd --gid 10001 object-dispatch"));
    assert!(dockerfile.contains(
        "useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin object-dispatch"
    ));
    assert!(dockerfile.contains("USER 10001:10001"));
    assert!(dockerfile.contains(
        "ENV LORE_OBJECT_DISPATCH_SERVICE_CONFIG_REVISION=object-store-dispatch-service-shell-v1"
    ));
    assert!(dockerfile.contains("ENV LORE_OBJECT_DISPATCH_LISTEN_ADDR=127.0.0.1:50051"));
    assert!(dockerfile.contains("ENTRYPOINT [\"lore-object-dispatch\"]"));
    assert!(!uppercase.contains("HEALTHCHECK"));
    for forbidden in [
        "LORE_OBJECT_DISPATCH_CONTINUITY_",
        "AWS_ACCESS_KEY",
        "AWS_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "HEALTHCHECK",
    ] {
        assert!(
            !uppercase.contains(forbidden),
            "runtime image must not carry source-dark authority surface {forbidden}"
        );
    }

    let dockerignore = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate must live directly below the workspace root")
            .join(".dockerignore"),
    )
    .expect("workspace .dockerignore must be readable by its source-contract test");
    for required_ignore in [
        ".git/",
        "**/.git/",
        ".env",
        ".env.*",
        "**/.env",
        "**/.env.*",
        "**/*.crt",
        "**/*.key",
        "**/*.pem",
        "**/*.p12",
        "**/*.pfx",
    ] {
        assert!(
            dockerignore.lines().any(|line| line == required_ignore),
            "Docker build context must exclude {required_ignore}"
        );
    }
}
