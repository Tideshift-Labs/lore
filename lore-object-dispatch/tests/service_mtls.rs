// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use lore_object_dispatch::AuthenticatedRequestContext;
use lore_object_dispatch::AuthorityValidationError;
use lore_object_dispatch::AuthorizedCallerEntry;
use lore_object_dispatch::AuthorizedCallerRegistry;
use lore_object_dispatch::CallerAuthenticationError;
use lore_object_dispatch::CellAllocationState;
use lore_object_dispatch::CurrentCellAdmission;
use lore_object_dispatch::CurrentCellAllocation;
use lore_object_dispatch::DispatchMetricRecorder;
use lore_object_dispatch::DispatchRpc;
use lore_object_dispatch::SOURCE_DARK_STATUS_MESSAGE;
use lore_object_dispatch::ServiceServerError;
use lore_object_dispatch::ServiceTlsConfig;
use lore_object_dispatch::SourceDarkObjectStoreDispatchService;
use lore_object_dispatch::SubmittedAuthority;
use lore_object_dispatch::serve_prebound_with_tls;
use lore_object_dispatch::validate_request_authority;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestQueryV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultFetchV1;
use lore_proto::lore::object_dispatch::v1::ReservePutRequestV1;
use lore_proto::lore::object_dispatch::v1::UploadPutChunkV1;
use lore_proto::lore::object_dispatch::v1::object_store_dispatch_service_client::ObjectStoreDispatchServiceClient;
use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::Issuer;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;
use rcgen::date_time_ymd;
use rcgen::string::Ia5String;
use rustls::pki_types::CertificateDer;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tonic::Code;
use tonic::Status;
use tonic::transport::Certificate;
use tonic::transport::Channel;
use tonic::transport::ClientTlsConfig;
use tonic::transport::Endpoint;
use tonic::transport::Identity;

const REGISTERED_SAN: &str = "spiffe://lorehub/object-dispatch/service-a";
const SECOND_SAN: &str = "spiffe://lorehub/object-dispatch/service-b";
const RPC_TIMEOUT: Duration = Duration::from_secs(2);

struct TestIdentity {
    certificate_pem: String,
    private_key_pem: String,
    certificate_der: Vec<u8>,
}

struct TestPki {
    ca_pem: String,
    server: TestIdentity,
    registered_client: TestIdentity,
    unregistered_client: TestIdentity,
    no_uri_san_client: TestIdentity,
    malformed_uri_san_client: TestIdentity,
    ambiguous_client: TestIdentity,
    expired_client: TestIdentity,
}

fn issue_identity(
    issuer: &Issuer<'_, KeyPair>,
    dns_names: Vec<String>,
    uri_sans: &[&str],
    usage: ExtendedKeyUsagePurpose,
    expired: bool,
) -> TestIdentity {
    let key = KeyPair::generate().expect("test leaf key generation must succeed");
    let mut params = CertificateParams::new(dns_names).expect("test leaf parameters must be valid");
    params.extended_key_usages = vec![usage];
    params.subject_alt_names.extend(
        uri_sans
            .iter()
            .map(|san| SanType::URI(Ia5String::try_from(*san).expect("test URI SAN must be IA5"))),
    );
    if expired {
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(2001, 1, 1);
    }
    let certificate = params
        .signed_by(&key, issuer)
        .expect("test leaf certificate generation must succeed");
    TestIdentity {
        certificate_pem: certificate.pem(),
        private_key_pem: key.serialize_pem(),
        certificate_der: certificate.der().to_vec(),
    }
}

fn test_pki() -> TestPki {
    let ca_key = KeyPair::generate().expect("test CA key generation must succeed");
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).expect("test CA parameters must be valid");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_certificate = ca_params
        .self_signed(&ca_key)
        .expect("test CA certificate generation must succeed");
    let ca_pem = ca_certificate.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    TestPki {
        ca_pem,
        server: issue_identity(
            &issuer,
            vec!["localhost".to_string()],
            &[],
            ExtendedKeyUsagePurpose::ServerAuth,
            false,
        ),
        registered_client: issue_identity(
            &issuer,
            vec![],
            &[REGISTERED_SAN],
            ExtendedKeyUsagePurpose::ClientAuth,
            false,
        ),
        unregistered_client: issue_identity(
            &issuer,
            vec![],
            &["spiffe://lorehub/object-dispatch/unregistered"],
            ExtendedKeyUsagePurpose::ClientAuth,
            false,
        ),
        no_uri_san_client: issue_identity(
            &issuer,
            vec!["client.example".to_string()],
            &[],
            ExtendedKeyUsagePurpose::ClientAuth,
            false,
        ),
        malformed_uri_san_client: issue_identity(
            &issuer,
            vec![],
            &["not-a-uri"],
            ExtendedKeyUsagePurpose::ClientAuth,
            false,
        ),
        ambiguous_client: issue_identity(
            &issuer,
            vec![],
            &[REGISTERED_SAN, SECOND_SAN],
            ExtendedKeyUsagePurpose::ClientAuth,
            false,
        ),
        expired_client: issue_identity(
            &issuer,
            vec![],
            &[REGISTERED_SAN],
            ExtendedKeyUsagePurpose::ClientAuth,
            true,
        ),
    }
}

fn registry() -> AuthorizedCallerRegistry {
    AuthorizedCallerRegistry::new(vec![AuthorizedCallerEntry {
        uri_san: REGISTERED_SAN.to_string(),
        service_instance_id: "service-a".to_string(),
        provider_boundary_id: "boundary-a".to_string(),
        allowed_cell_ids: vec!["cell-a".to_string(), "cell-b".to_string()],
    }])
    .expect("exact test caller registry must be valid")
}

fn tls_config(pki: &TestPki) -> ServiceTlsConfig {
    ServiceTlsConfig::from_pem(
        pki.server.certificate_pem.as_bytes().to_vec(),
        pki.server.private_key_pem.as_bytes().to_vec(),
        pki.ca_pem.as_bytes().to_vec(),
    )
    .expect("test server TLS material must be valid")
}

fn client_tls(pki: &TestPki, identity: Option<&TestIdentity>) -> ClientTlsConfig {
    let mut tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(Certificate::from_pem(pki.ca_pem.as_bytes()));
    if let Some(identity) = identity {
        tls = tls.identity(Identity::from_pem(
            identity.certificate_pem.as_bytes(),
            identity.private_key_pem.as_bytes(),
        ));
    }
    tls
}

async fn connect(
    address: std::net::SocketAddr,
    tls: ClientTlsConfig,
) -> Result<ObjectStoreDispatchServiceClient<Channel>, tonic::transport::Error> {
    let channel = Endpoint::from_shared(format!("https://{address}"))
        .expect("test endpoint URI must be valid")
        .tls_config(tls)?
        .connect()
        .await?;
    Ok(ObjectStoreDispatchServiceClient::new(channel))
}

#[derive(Default)]
struct RecordingMetrics {
    calls: Mutex<Vec<DispatchRpc>>,
}

#[derive(Clone, Copy, Debug)]
enum ClientFixture {
    None,
    Unregistered,
    NoUriSan,
    MalformedUriSan,
    Ambiguous,
    Expired,
    WrongCa,
}

async fn rejected_client_result(
    fixture: ClientFixture,
    caller_registry: AuthorizedCallerRegistry,
) -> (Result<Status, tonic::transport::Error>, Vec<DispatchRpc>) {
    let pki = test_pki();
    let wrong_pki = test_pki();
    let recorder = Arc::new(RecordingMetrics::default());
    let service = SourceDarkObjectStoreDispatchService::with_metric_recorder(recorder.clone());
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener must bind");
    let address = listener
        .local_addr()
        .expect("listener must expose its address");
    let server_tls = tls_config(&pki);
    let client_identity = match fixture {
        ClientFixture::None => None,
        ClientFixture::Unregistered => Some(&pki.unregistered_client),
        ClientFixture::NoUriSan => Some(&pki.no_uri_san_client),
        ClientFixture::MalformedUriSan => Some(&pki.malformed_uri_san_client),
        ClientFixture::Ambiguous => Some(&pki.ambiguous_client),
        ClientFixture::Expired => Some(&pki.expired_client),
        ClientFixture::WrongCa => Some(&wrong_pki.registered_client),
    };
    let client_tls = client_tls(&pki, client_identity);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = lore_base::lore_spawn!(async move {
        serve_prebound_with_tls(listener, service, server_tls, caller_registry, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    let result = match connect(address, client_tls).await {
        Ok(mut client) => Ok(client
            .reserve_put(ReservePutRequestV1::default())
            .await
            .expect_err("unauthorized client must not reach the source-dark handler")),
        Err(error) => Err(error),
    };
    shutdown_tx
        .send(())
        .expect("server shutdown receiver must remain live");
    timeout(RPC_TIMEOUT, server)
        .await
        .expect("rejection server shutdown must be bounded")
        .expect("rejection server task must not panic")
        .expect("rejection server must shut down cleanly");
    let calls = recorder
        .calls
        .lock()
        .expect("test metric recorder mutex must remain healthy")
        .clone();
    (result, calls)
}

impl DispatchMetricRecorder for RecordingMetrics {
    fn record_source_dark_rejection(&self, rpc: DispatchRpc) {
        self.calls
            .lock()
            .expect("test metric recorder mutex must remain healthy")
            .push(rpc);
    }
}

fn assert_source_dark(status: Status) {
    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(status.message(), SOURCE_DARK_STATUS_MESSAGE);
    assert!(status.details().is_empty());
}

fn authenticated_context() -> AuthenticatedRequestContext {
    let pki = test_pki();
    let certificates = [CertificateDer::from(
        pki.registered_client.certificate_der.clone(),
    )];
    let caller = registry()
        .authenticate_peer_certs(Some(&certificates))
        .expect("registered URI SAN must resolve to one caller");
    AuthenticatedRequestContext {
        caller,
        tenant_id: "tenant-a".to_string(),
    }
}

fn authority_fixture() -> (
    SubmittedAuthority,
    AuthenticatedRequestContext,
    CurrentCellAllocation,
    CurrentCellAdmission,
) {
    (
        SubmittedAuthority {
            protocol_revision: "protocol-v1".to_string(),
            policy_revision: "policy-v1".to_string(),
            provider_boundary_id: "boundary-a".to_string(),
            authenticated_cell_id: "cell-a".to_string(),
            authenticated_tenant_id: "tenant-a".to_string(),
            allocation_revision: "allocation-v7".to_string(),
            allocation_fence: 11,
            cell_admission_id: "admission-a".to_string(),
            cell_admission_fence: 12,
        },
        authenticated_context(),
        CurrentCellAllocation {
            provider_boundary_id: "boundary-a".to_string(),
            cell_id: "cell-a".to_string(),
            allocation_revision: "allocation-v7".to_string(),
            allocation_fence: 11,
            hard_expiry_unix_ms: 1_001,
            state: CellAllocationState::Active,
        },
        CurrentCellAdmission {
            provider_boundary_id: "boundary-a".to_string(),
            cell_id: "cell-a".to_string(),
            tenant_id: "tenant-a".to_string(),
            cell_admission_id: "admission-a".to_string(),
            cell_admission_fence: 12,
        },
    )
}

fn validate_fixture(
    submitted: &SubmittedAuthority,
    authenticated: &AuthenticatedRequestContext,
    allocation: &CurrentCellAllocation,
    admission: &CurrentCellAdmission,
    now: i64,
) -> Result<(), AuthorityValidationError> {
    validate_request_authority(
        submitted,
        authenticated,
        allocation,
        admission,
        "protocol-v1",
        "policy-v1",
        now,
    )
}

#[tokio::test]
async fn registered_uri_san_reaches_all_seven_source_dark_handlers() {
    lore_base::runtime::LORE_CONTEXT
        .scope(Arc::new(()), async {
            let pki = test_pki();
            let recorder = Arc::new(RecordingMetrics::default());
            let service =
                SourceDarkObjectStoreDispatchService::with_metric_recorder(recorder.clone());
            let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener must bind");
            let address = listener
                .local_addr()
                .expect("listener must expose its address");
            let server_tls = tls_config(&pki);
            let client_tls = client_tls(&pki, Some(&pki.registered_client));
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let server = lore_base::lore_spawn!(async move {
                serve_prebound_with_tls(listener, service, server_tls, registry(), async move {
                    let _ = shutdown_rx.await;
                })
                .await
            });
            let mut client = connect(address, client_tls)
                .await
                .expect("registered client certificate must complete mTLS");

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
                .expect("UploadPut must reject before polling a request frame")
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
                .expect("server shutdown receiver must remain live");
            timeout(RPC_TIMEOUT, server)
                .await
                .expect("mTLS server shutdown must be bounded")
                .expect("mTLS server task must not panic")
                .expect("mTLS server must shut down cleanly");
            assert_eq!(
                *recorder
                    .calls
                    .lock()
                    .expect("test metric recorder mutex must remain healthy"),
                DispatchRpc::ALL
            );
        })
        .await;
}

#[tokio::test]
async fn missing_untrusted_and_expired_client_certificates_fail_at_tls() {
    lore_base::runtime::LORE_CONTEXT
        .scope(Arc::new(()), async {
            for fixture in [
                ClientFixture::None,
                ClientFixture::WrongCa,
                ClientFixture::Expired,
            ] {
                let (result, calls) = rejected_client_result(fixture, registry()).await;
                if let Ok(status) = result {
                    assert_eq!(
                        status.code(),
                        Code::Unknown,
                        "invalid client identity {fixture:?} must fail in transport"
                    );
                    assert_eq!(status.message(), "transport error");
                }
                assert!(calls.is_empty(), "TLS failures must not reach a handler");
            }
        })
        .await;
}

#[tokio::test]
async fn unregistered_missing_and_ambiguous_uri_sans_fail_before_handlers() {
    lore_base::runtime::LORE_CONTEXT
        .scope(Arc::new(()), async {
            let ambiguous_registry = AuthorizedCallerRegistry::new(vec![
                AuthorizedCallerEntry {
                    uri_san: REGISTERED_SAN.to_string(),
                    service_instance_id: "service-a".to_string(),
                    provider_boundary_id: "boundary-a".to_string(),
                    allowed_cell_ids: vec!["cell-a".to_string()],
                },
                AuthorizedCallerEntry {
                    uri_san: SECOND_SAN.to_string(),
                    service_instance_id: "service-b".to_string(),
                    provider_boundary_id: "boundary-a".to_string(),
                    allowed_cell_ids: vec!["cell-b".to_string()],
                },
            ])
            .expect("two distinct registry entries must be valid");
            for (fixture, caller_registry) in [
                (ClientFixture::Unregistered, registry()),
                (ClientFixture::NoUriSan, registry()),
                (ClientFixture::MalformedUriSan, registry()),
                (ClientFixture::Ambiguous, ambiguous_registry),
            ] {
                let (result, calls) = rejected_client_result(fixture, caller_registry).await;
                let status = result.expect("trusted certificate must complete the TLS handshake");
                assert_eq!(status.code(), Code::Unauthenticated);
                assert!(status.details().is_empty());
                for secret in [REGISTERED_SAN, SECOND_SAN, "boundary-a", "cell-a"] {
                    assert!(
                        !status.message().contains(secret),
                        "authentication failure must not disclose {secret}"
                    );
                }
                assert!(
                    calls.is_empty(),
                    "interceptor failures must not reach a handler"
                );
            }
        })
        .await;
}

#[test]
fn caller_registry_rejects_duplicate_and_unbounded_entries() {
    let valid = AuthorizedCallerEntry {
        uri_san: REGISTERED_SAN.to_string(),
        service_instance_id: "service-a".to_string(),
        provider_boundary_id: "boundary-a".to_string(),
        allowed_cell_ids: vec!["cell-a".to_string()],
    };

    assert!(AuthorizedCallerRegistry::new(vec![valid.clone(), valid.clone()]).is_err());

    let mut duplicate_cell = valid.clone();
    duplicate_cell.allowed_cell_ids.push("cell-a".to_string());
    assert!(AuthorizedCallerRegistry::new(vec![duplicate_cell]).is_err());

    for invalid in [
        AuthorizedCallerEntry {
            uri_san: String::new(),
            ..valid.clone()
        },
        AuthorizedCallerEntry {
            service_instance_id: String::new(),
            ..valid.clone()
        },
        AuthorizedCallerEntry {
            provider_boundary_id: String::new(),
            ..valid.clone()
        },
        AuthorizedCallerEntry {
            allowed_cell_ids: vec![],
            ..valid
        },
    ] {
        assert!(AuthorizedCallerRegistry::new(vec![invalid]).is_err());
    }

    for invalid in [
        AuthorizedCallerEntry {
            uri_san: "not-a-uri".to_string(),
            service_instance_id: "service-a".to_string(),
            provider_boundary_id: "boundary-a".to_string(),
            allowed_cell_ids: vec!["cell-a".to_string()],
        },
        AuthorizedCallerEntry {
            uri_san: format!("spiffe:{}", "x".repeat(2_049)),
            service_instance_id: "service-a".to_string(),
            provider_boundary_id: "boundary-a".to_string(),
            allowed_cell_ids: vec!["cell-a".to_string()],
        },
        AuthorizedCallerEntry {
            uri_san: REGISTERED_SAN.to_string(),
            service_instance_id: "s".repeat(257),
            provider_boundary_id: "boundary-a".to_string(),
            allowed_cell_ids: vec!["cell-a".to_string()],
        },
        AuthorizedCallerEntry {
            uri_san: REGISTERED_SAN.to_string(),
            service_instance_id: "service-a".to_string(),
            provider_boundary_id: "boundary-a".to_string(),
            allowed_cell_ids: (0..4_097).map(|index| format!("cell-{index}")).collect(),
        },
    ] {
        assert!(AuthorizedCallerRegistry::new(vec![invalid]).is_err());
    }
}

#[test]
fn missing_and_malformed_leaf_certificates_fail_closed_in_the_registry() {
    assert_eq!(
        registry().authenticate_peer_certs(None),
        Err(CallerAuthenticationError::MissingCertificate)
    );
    let malformed = [CertificateDer::from(vec![0x30, 0x01, 0xff])];
    assert_eq!(
        registry().authenticate_peer_certs(Some(&malformed)),
        Err(CallerAuthenticationError::MalformedCertificate)
    );
}

#[test]
fn registered_caller_maps_exactly_one_service_boundary_and_sorted_cell_set() {
    let context = authenticated_context();
    let pki = test_pki();

    assert_eq!(context.caller.service_instance_id(), "service-a");
    assert_eq!(context.caller.provider_boundary_id(), "boundary-a");
    assert_eq!(context.caller.allowed_cell_ids(), ["cell-a", "cell-b"]);
    assert!(context.caller.allows_cell("cell-a"));
    assert!(!context.caller.allows_cell("cell-c"));
    let debug = format!("{:?} {:?}", registry(), context.caller);
    for secret in [REGISTERED_SAN, "service-a", "boundary-a", "cell-a"] {
        assert!(!debug.contains(secret), "Debug must redact {secret}");
    }
    let tls_debug = format!("{:?}", tls_config(&pki));
    assert_eq!(
        tls_debug,
        "ServiceTlsConfig { server_identity: \"[REDACTED]\", client_ca: \"[REDACTED]\" }"
    );
    assert!(!tls_debug.contains("BEGIN CERTIFICATE"));
    assert!(!tls_debug.contains("PRIVATE KEY"));
}

#[test]
fn exact_allocation_and_admission_authority_accepts_only_before_expiry() {
    let (submitted, authenticated, allocation, admission) = authority_fixture();

    assert_eq!(
        validate_fixture(&submitted, &authenticated, &allocation, &admission, 1_000),
        Ok(())
    );
    assert_eq!(
        validate_fixture(&submitted, &authenticated, &allocation, &admission, 1_001),
        Err(AuthorityValidationError::AllocationExpired)
    );
    assert_eq!(
        validate_fixture(&submitted, &authenticated, &allocation, &admission, 1_002),
        Err(AuthorityValidationError::AllocationExpired)
    );
}

#[test]
fn request_and_caller_scope_mismatches_fail_closed() {
    let (submitted, authenticated, allocation, admission) = authority_fixture();
    let mut cases = Vec::new();

    let mut changed = submitted.clone();
    changed.protocol_revision = "protocol-v2".to_string();
    cases.push((changed, AuthorityValidationError::ProtocolRevisionMismatch));
    let mut changed = submitted.clone();
    changed.policy_revision = "policy-v2".to_string();
    cases.push((changed, AuthorityValidationError::PolicyRevisionMismatch));
    let mut changed = submitted.clone();
    changed.provider_boundary_id = "boundary-b".to_string();
    cases.push((changed, AuthorityValidationError::CallerBoundaryMismatch));
    let mut changed = submitted.clone();
    changed.authenticated_cell_id = "cell-c".to_string();
    cases.push((changed, AuthorityValidationError::CallerCellNotAllowed));
    let mut changed = submitted.clone();
    changed.authenticated_tenant_id = "tenant-b".to_string();
    cases.push((
        changed,
        AuthorityValidationError::AuthenticatedTenantMismatch,
    ));

    for (changed, expected) in cases {
        assert_eq!(
            validate_fixture(&changed, &authenticated, &allocation, &admission, 1_000),
            Err(expected)
        );
    }
}

#[test]
fn allocation_and_admission_component_mismatches_fail_independently() {
    let (submitted, authenticated, allocation, admission) = authority_fixture();

    let mut changed_allocation = allocation.clone();
    changed_allocation.provider_boundary_id = "boundary-b".to_string();
    assert_eq!(
        validate_fixture(
            &submitted,
            &authenticated,
            &changed_allocation,
            &admission,
            1_000
        ),
        Err(AuthorityValidationError::AllocationScopeMismatch)
    );
    let mut changed_allocation = allocation.clone();
    changed_allocation.cell_id = "cell-b".to_string();
    assert_eq!(
        validate_fixture(
            &submitted,
            &authenticated,
            &changed_allocation,
            &admission,
            1_000
        ),
        Err(AuthorityValidationError::AllocationScopeMismatch)
    );
    for state in [CellAllocationState::Prepared, CellAllocationState::Sealed] {
        let mut changed_allocation = allocation.clone();
        changed_allocation.state = state;
        assert_eq!(
            validate_fixture(
                &submitted,
                &authenticated,
                &changed_allocation,
                &admission,
                1_000
            ),
            Err(AuthorityValidationError::AllocationNotActive)
        );
    }
    let mut changed_allocation = allocation.clone();
    changed_allocation.allocation_revision = "allocation-v8".to_string();
    assert_eq!(
        validate_fixture(
            &submitted,
            &authenticated,
            &changed_allocation,
            &admission,
            1_000
        ),
        Err(AuthorityValidationError::AllocationRevisionMismatch)
    );
    let mut changed_allocation = allocation.clone();
    changed_allocation.allocation_fence += 1;
    assert_eq!(
        validate_fixture(
            &submitted,
            &authenticated,
            &changed_allocation,
            &admission,
            1_000
        ),
        Err(AuthorityValidationError::AllocationFenceMismatch)
    );

    for field in ["boundary", "cell", "tenant"] {
        let mut changed_admission = admission.clone();
        match field {
            "boundary" => changed_admission.provider_boundary_id = "boundary-b".to_string(),
            "cell" => changed_admission.cell_id = "cell-b".to_string(),
            "tenant" => changed_admission.tenant_id = "tenant-b".to_string(),
            _ => unreachable!("closed test field inventory"),
        }
        assert_eq!(
            validate_fixture(
                &submitted,
                &authenticated,
                &allocation,
                &changed_admission,
                1_000
            ),
            Err(AuthorityValidationError::AdmissionScopeMismatch)
        );
    }
    let mut changed_admission = admission.clone();
    changed_admission.cell_admission_id = "admission-b".to_string();
    assert_eq!(
        validate_fixture(
            &submitted,
            &authenticated,
            &allocation,
            &changed_admission,
            1_000
        ),
        Err(AuthorityValidationError::AdmissionIdMismatch)
    );
    let mut changed_admission = admission.clone();
    changed_admission.cell_admission_fence += 1;
    assert_eq!(
        validate_fixture(
            &submitted,
            &authenticated,
            &allocation,
            &changed_admission,
            1_000
        ),
        Err(AuthorityValidationError::AdmissionFenceMismatch)
    );
}

#[test]
fn authority_rejects_zero_fences_and_unbounded_or_noncanonical_values() {
    let (submitted, authenticated, allocation, admission) = authority_fixture();

    let mut changed = submitted.clone();
    changed.allocation_fence = 0;
    assert_eq!(
        validate_fixture(&changed, &authenticated, &allocation, &admission, 1_000),
        Err(AuthorityValidationError::InvalidCanonicalInput)
    );
    let mut changed = submitted.clone();
    changed.cell_admission_fence = 0;
    assert_eq!(
        validate_fixture(&changed, &authenticated, &allocation, &admission, 1_000),
        Err(AuthorityValidationError::InvalidCanonicalInput)
    );
    let mut changed = submitted.clone();
    changed.allocation_revision = "r".repeat(257);
    assert_eq!(
        validate_fixture(&changed, &authenticated, &allocation, &admission, 1_000),
        Err(AuthorityValidationError::InvalidCanonicalInput)
    );
    let mut changed_allocation = allocation.clone();
    changed_allocation.allocation_fence = 0;
    assert_eq!(
        validate_fixture(
            &submitted,
            &authenticated,
            &changed_allocation,
            &admission,
            1_000,
        ),
        Err(AuthorityValidationError::InvalidCanonicalInput)
    );
    let mut changed_admission = admission.clone();
    changed_admission.cell_admission_fence = 0;
    assert_eq!(
        validate_fixture(
            &submitted,
            &authenticated,
            &allocation,
            &changed_admission,
            1_000,
        ),
        Err(AuthorityValidationError::InvalidCanonicalInput)
    );
    let mut changed_allocation = allocation.clone();
    changed_allocation.hard_expiry_unix_ms = -1;
    assert_eq!(
        validate_fixture(
            &submitted,
            &authenticated,
            &changed_allocation,
            &admission,
            1_000,
        ),
        Err(AuthorityValidationError::InvalidCanonicalInput)
    );
    let mut changed = submitted;
    changed.cell_admission_id = "invalid id with spaces".to_string();
    assert_eq!(
        validate_fixture(&changed, &authenticated, &allocation, &admission, 1_000),
        Err(AuthorityValidationError::InvalidCanonicalInput)
    );
}

#[test]
fn authority_rejects_negative_database_time_and_decomposed_revisions() {
    let (submitted, authenticated, allocation, admission) = authority_fixture();
    assert_eq!(
        validate_fixture(&submitted, &authenticated, &allocation, &admission, -1),
        Err(AuthorityValidationError::InvalidCanonicalInput)
    );

    let decomposed = "re\u{301}vision".to_string();
    let mut changed = submitted.clone();
    changed.protocol_revision = decomposed.clone();
    assert_eq!(
        validate_fixture(&changed, &authenticated, &allocation, &admission, 1_000),
        Err(AuthorityValidationError::InvalidCanonicalInput)
    );
    let mut changed = submitted.clone();
    changed.policy_revision = decomposed.clone();
    assert_eq!(
        validate_fixture(&changed, &authenticated, &allocation, &admission, 1_000),
        Err(AuthorityValidationError::InvalidCanonicalInput)
    );
    let mut changed = submitted.clone();
    changed.allocation_revision = decomposed.clone();
    assert_eq!(
        validate_fixture(&changed, &authenticated, &allocation, &admission, 1_000),
        Err(AuthorityValidationError::InvalidCanonicalInput)
    );
    let mut changed_allocation = allocation.clone();
    changed_allocation.allocation_revision = decomposed;
    assert_eq!(
        validate_fixture(
            &submitted,
            &authenticated,
            &changed_allocation,
            &admission,
            1_000,
        ),
        Err(AuthorityValidationError::InvalidCanonicalInput)
    );
}

#[tokio::test]
async fn prebound_mtls_server_rejects_a_nonloopback_listener() {
    lore_base::runtime::LORE_CONTEXT
        .scope(Arc::new(()), async {
            let pki = test_pki();
            let listener = TcpListener::bind("0.0.0.0:0").expect("wildcard listener must bind");

            assert_eq!(
                serve_prebound_with_tls(
                    listener,
                    SourceDarkObjectStoreDispatchService::new(),
                    tls_config(&pki),
                    registry(),
                    std::future::pending(),
                )
                .await,
                Err(ServiceServerError::UnsafeListener)
            );
        })
        .await;
}

async fn assert_prebound_tls_configuration_rejected(tls: ServiceTlsConfig) {
    use std::error::Error as _;

    let recorder = Arc::new(RecordingMetrics::default());
    let service = SourceDarkObjectStoreDispatchService::with_metric_recorder(recorder.clone());
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener must bind");
    let address = listener
        .local_addr()
        .expect("listener must expose its address");
    let error = timeout(
        RPC_TIMEOUT,
        serve_prebound_with_tls(listener, service, tls, registry(), std::future::pending()),
    )
    .await
    .expect("invalid TLS configuration must fail before serving")
    .expect_err("invalid TLS configuration must fail closed");

    assert!(matches!(error, ServiceServerError::TlsConfiguration(_)));
    assert!(error.source().is_some());
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("BEGIN CERTIFICATE"));
    assert!(!rendered.contains("PRIVATE KEY"));
    assert!(
        recorder
            .calls
            .lock()
            .expect("test metric recorder mutex must remain healthy")
            .is_empty(),
        "TLS configuration failure must not reach a handler"
    );
    TcpListener::bind(address)
        .expect("TLS configuration failure must release the prebound listener immediately");
}

#[tokio::test]
async fn malformed_pem_and_mismatched_server_key_fail_before_serving() {
    lore_base::runtime::LORE_CONTEXT
        .scope(Arc::new(()), async {
            let malformed = ServiceTlsConfig::from_pem(
                b"not-a-certificate".to_vec(),
                b"not-a-private-key".to_vec(),
                b"not-a-client-ca".to_vec(),
            )
            .expect("nonempty malformed material reaches the TLS parser");
            assert_prebound_tls_configuration_rejected(malformed).await;

            let pki = test_pki();
            let other_pki = test_pki();
            let mismatched = ServiceTlsConfig::from_pem(
                pki.server.certificate_pem.as_bytes().to_vec(),
                other_pki.server.private_key_pem.as_bytes().to_vec(),
                pki.ca_pem.as_bytes().to_vec(),
            )
            .expect("nonempty mismatched material reaches the TLS parser");
            assert_prebound_tls_configuration_rejected(mismatched).await;
        })
        .await;
}

#[test]
fn mtls_and_authority_slice_adds_no_effectful_backend_or_readiness_dependency() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        std::fs::read_to_string(root.join("Cargo.toml")).expect("crate manifest must be readable");
    for dependency in ["aws-sdk-", "lore-aws", "lore-postgres"] {
        assert!(
            !manifest.contains(dependency),
            "source-dark mTLS slice must not add {dependency}"
        );
    }
    for file in ["auth.rs", "authority.rs", "server.rs"] {
        let source = std::fs::read_to_string(root.join("src").join(file))
            .expect("source contract input must be readable");
        for forbidden in [
            "crate::continuity",
            "crate::schema",
            "tokio_postgres",
            "aws_sdk",
            "provider_client",
            "spool",
            "health_check",
            "readiness",
        ] {
            assert!(
                !source.contains(forbidden),
                "source-dark {file} must not depend on {forbidden}"
            );
        }
    }
}
