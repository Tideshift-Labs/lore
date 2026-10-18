// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-120: the production public-QUIC wiring carries the configured caller-capability policy.
//!
//! `async_main` reads the policy with `quic_caller_capability_policy` and hands it to
//! `QuicPublicStreamHandler::new`, which must apply it to BOTH storage services it mounts
//! (`urc/0.2` and `lore-storage/0.4`). A site that forgot the builder call would silently fall
//! back to the compatible default, so these tests drive a real QUIC Put through each ALPN of a
//! handler built by the production constructor.

use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use lore_revision::fragment;
use lore_revision::lore::RepositoryId;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::grpc::caller_capabilities::CallerCapabilityPolicy;
use lore_server::protocol::storage::put::Put;
use lore_server::quic::quinn::QuinnConfigBuilder;
use lore_server::quic::quinn::QuinnServer;
use lore_server::quic::stream_handler::AdmissionLimits;
use lore_server::quic::tests::server_certs;
use lore_server::server::QuicPublicStreamHandler;
use lore_server::server::quic_caller_capability_policy;
use lore_storage::ImmutableStore;
use lore_telemetry::user_agent_filter::UserAgentFilter;
use lore_transport::Storage;
use lore_transport::SuppliedCredentials;
use lore_transport::quic::QuicClientError;
use lore_transport::quic::QuicServiceError;
use lore_transport::quic::client::CertificateSettings;
use lore_transport::quic::client::CongestionAlgorithm;
use lore_transport::quic::client::DEFAULT_EXPECTED_RTT_MS;
use lore_transport::quic::client::EndpointConfig;
use lore_transport::quic::client::QuicConnection;
use lore_transport::quic::client::TransportConfig;
use lore_transport::quic::client::send_normal;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::MAX_CHUNK_SIZE;
use lore_transport::quic::storage_service::client::StorageClient;
use rand::random;
use zerocopy::IntoBytes;

use crate::store::test_support::test_store_create;

const STRICT: CallerCapabilityPolicy = CallerCapabilityPolicy::RequireOutcomeUnknownV1;
const COMPATIBLE: CallerCapabilityPolicy = CallerCapabilityPolicy::CompatibleSingleReplica;
const UNSUPPORTED_CLIENT: u32 = QuicServiceError::ImplementationReserved as u32;

fn settings_with(policy: Option<CallerCapabilityPolicy>) -> lore_server::settings::Settings {
    let mut settings: lore_server::settings::Settings =
        toml::from_str(include_str!("../../../config/default.toml")).unwrap();
    match policy {
        Some(policy) => {
            settings
                .server
                .grpc
                .as_mut()
                .expect("default.toml carries [server.grpc]")
                .caller_capability_policy = policy;
        }
        None => settings.server.grpc = None,
    }
    settings
}

#[test]
fn the_quic_policy_is_read_from_the_grpc_setting() {
    assert_eq!(
        quic_caller_capability_policy(&settings_with(Some(STRICT))),
        STRICT
    );
    assert_eq!(
        quic_caller_capability_policy(&settings_with(Some(COMPATIBLE))),
        COMPATIBLE
    );
    // No gRPC section: the compatible default, the same one gRPC itself would use.
    assert_eq!(
        quic_caller_capability_policy(&settings_with(None)),
        COMPATIBLE
    );
}

/// A real QUIC listener whose factory is the production `QuicPublicStreamHandler`.
fn start_public_quic(
    immutable: Arc<dyn ImmutableStore>,
    mutable: Arc<dyn lore_storage::MutableStore>,
    policy: CallerCapabilityPolicy,
) -> (QuinnServer, u16) {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    let port = udp.local_addr().expect("udp address").port();
    let (cert_file, pkey_file, _ca) = server_certs().expect("test certificate paths");
    let handler = QuicPublicStreamHandler::new(
        immutable.clone(),
        immutable,
        mutable,
        None,
        false,
        Arc::new(AllowAllRepositoryAuthorizer),
        AdmissionLimits {
            process_limit: 100,
            inflight_limit: 800,
            handler_timeout: None,
            permit_timeout: None,
        },
        Arc::new(UserAgentFilter::default()),
        policy,
    );
    let server = QuinnServer::start(
        QuinnConfigBuilder::new()
            .socket(udp)
            .cert_file(cert_file)
            .pkey_file(pkey_file)
            .stream_handler_factory(Box::new(handler))
            .build()
            .expect("quinn config"),
    )
    .expect("quinn server start");
    (server, port)
}

/// A `lore-storage/0.4` Put through the stock QUIC storage client.
async fn put_v4(
    port: u16,
    partition: RepositoryId,
) -> (Result<(), String>, lore_base::types::Address) {
    let client = StorageClient::connect(
        Weak::new(),
        &format!("lore://127.0.0.1:{port}"),
        "127.0.0.1".to_string(),
        "",
        "wp120-wiring",
        partition,
        &Arc::new(SuppliedCredentials::default()),
        None,
    )
    .await
    .expect("connect lore-storage/0.4");
    let session_id = client
        .session_start(partition, "wp120-wiring")
        .await
        .expect("session start");
    let (fragment, address, payload) = fragment::generate_random();
    let result = client
        .put(session_id, address, fragment, Some(payload))
        .await
        .map_err(|error| format!("{error:?}"));
    (result, address)
}

/// A `urc/0.2` Put, hand-framed: the legacy protocol carries no session id, so Connect binds
/// the connection's repository and the Put follows on session 0.
async fn put_urc02(
    port: u16,
    partition: RepositoryId,
) -> (Result<Bytes, QuicClientError>, lore_base::types::Address) {
    let quinn = lore_transport::quic::client::connect(
        &EndpointConfig {
            remote_url: format!("lore://127.0.0.1:{port}"),
            default_port: port,
            sni_override: None,
        },
        CertificateSettings {
            custom_ca: None,
            client: None,
        },
        "urc/0.2",
        TransportConfig {
            max_bytes_bandwidth_per_second: (1024 * 1024 * 1024) / 8,
            expected_rtt_ms: DEFAULT_EXPECTED_RTT_MS,
            congestion_algorithm: CongestionAlgorithm::Bbr,
            initial_cwnd: None,
        },
    )
    .await
    .expect("connect urc/0.2");
    let quic = Arc::new(QuicConnection::new(quinn, MAX_CHUNK_SIZE));
    quic.create_initial_stream().await.expect("initial stream");
    quic.stream_count.store(1, Ordering::Relaxed);

    send_normal(
        quic.clone(),
        Command::Authorize as u8,
        0,
        false,
        &mut [
            Bytes::default(),
            Bytes::copy_from_slice(partition.as_bytes()),
        ],
    )
    .await
    .expect("urc/0.2 Connect must succeed with auth off");

    let (fragment, address, payload) = fragment::generate_random();
    let put = Put {
        address,
        fragment,
        payload: Some(payload),
    };
    let result = send_normal(
        quic,
        Command::Put as u8,
        0,
        false,
        &mut [Bytes::default(), put.to_bytes()],
    )
    .await;
    (result, address)
}

async fn stored(
    immutable: &Arc<dyn ImmutableStore>,
    partition: RepositoryId,
    address: lore_base::types::Address,
) -> bool {
    immutable.clone().get(partition, address).await.is_ok()
}

#[tokio::test]
async fn the_production_public_quic_handler_applies_strict_to_both_storage_protocols() {
    let (immutable, mutable, execution) = test_store_create().await.expect("stores");
    lore_base::runtime::LORE_CONTEXT
        .scope(execution, async move {
            let (_server, port) = start_public_quic(immutable.clone(), mutable, STRICT);
            let partition = random::<RepositoryId>();

            let (result, address) = put_v4(port, partition).await;
            let error = result.expect_err("strict lore-storage/0.4 must refuse a stock Put");
            assert!(
                error.contains(&UNSUPPORTED_CLIENT.to_string()),
                "lore-storage/0.4 refusal must carry storage status 200: {error}"
            );
            assert!(!stored(&immutable, partition, address).await);

            let (result, address) = put_urc02(port, partition).await;
            match result {
                Err(QuicClientError::ServerError(code)) => assert_eq!(
                    code, UNSUPPORTED_CLIENT,
                    "urc/0.2 refusal must be storage status 200"
                ),
                other => panic!("strict urc/0.2 must refuse a stock Put with 200, got {other:?}"),
            }
            assert!(!stored(&immutable, partition, address).await);
        })
        .await;
}

/// Positive control: the same handler built with the compatible policy stores both Puts.
#[tokio::test]
async fn the_production_public_quic_handler_stays_compatible_when_configured_so() {
    let (immutable, mutable, execution) = test_store_create().await.expect("stores");
    lore_base::runtime::LORE_CONTEXT
        .scope(execution, async move {
            let (_server, port) = start_public_quic(immutable.clone(), mutable, COMPATIBLE);
            let partition = random::<RepositoryId>();

            let (result, address) = put_v4(port, partition).await;
            result.expect("compatible lore-storage/0.4 must store a stock Put");
            assert!(stored(&immutable, partition, address).await);

            let (result, address) = put_urc02(port, partition).await;
            result.expect("compatible urc/0.2 must store a stock Put");
            assert!(stored(&immutable, partition, address).await);
        })
        .await;
}
