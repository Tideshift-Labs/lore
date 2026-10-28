// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-120 strict caller admission on QUIC (`admit_quic`).
//!
//! `urc/0.2` has no capability declaration, and a `lore-storage/0.4` session opened with
//! `AuthorizeStart` action 0 declares nothing, so under `require_outcome_unknown_v1` those
//! undeclared callers can read but not write: every mutation is refused with storage status 200
//! (`unsupported-client`) before write authorization and before any store call.
//! `compatible_single_replica` is unchanged. WP-124: a `lore-storage/0.4` session opened with
//! action 2 and `outcome_unknown_v1` is declared, and its mutations pass admission and then
//! face write authorization as usual, so a managed caller writes over QUIC. Each command is driven through both storage protocols
//! under both policies (and declared/undeclared on v4), against stores that count every call
//! they receive.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use bytes::Bytes;
use bytes::BytesMut;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_base::types::Partition;
use lore_revision::fragment;
use lore_revision::lore::RepositoryId;
use lore_server::auth::jwk::JWKService;
use lore_server::auth::jwk::JWKServiceError;
use lore_server::auth::jwt::DEFAULT_IDENTITY_CLAIM;
use lore_server::auth::jwt::JwtVerifier;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::grpc::caller_capabilities::ADMISSION_HEADER;
use lore_server::grpc::caller_capabilities::CAPABILITIES_HEADER;
use lore_server::grpc::caller_capabilities::CallerCapabilityPolicy;
use lore_server::grpc::caller_capabilities::admit_quic;
use lore_server::grpc::caller_capabilities::declares_outcome_unknown;
use lore_server::grpc::caller_capabilities::parse_capability_list;
use lore_server::protocol::attribute_map::AttributeMap;
use lore_server::protocol::storage::messages::MessageHandleError;
use lore_server::protocol::storage::put::Put;
use lore_server::protocol::storage::verify::Verify;
use lore_server::quic::QuicService;
use lore_server::quic::storage_service::ParsedStorageRequest;
use lore_server::quic::storage_service::StorageService;
use lore_server::quic::storage_service::parse_message_for_opcode;
use lore_server::quic::storage_service::parse_message_for_opcode_v4;
use lore_server::quic::storage_service_v4::ParsedStorageRequestV4;
use lore_server::quic::storage_service_v4::StorageServiceV4;
use lore_storage::ImmutableStore;
use lore_storage::KeyValueStream;
use lore_storage::MutableStore;
use lore_storage::StoreError;
use lore_storage::StoreGetData;
use lore_storage::StoreMatchResult;
use lore_storage::StoreObliterateStats;
use lore_storage::immutable_store::CopyBehavior;
use lore_telemetry::user_agent_filter::UserAgentFilter;
use lore_transport::quic::QuicErrorStatus;
use lore_transport::quic::QuicServiceError;
use lore_transport::quic::storage_service::Command;
use rand::random;
use zerocopy::IntoBytes;

use crate::store::test_support::test_store_create;

const STRICT: CallerCapabilityPolicy = CallerCapabilityPolicy::RequireOutcomeUnknownV1;
const COMPATIBLE: CallerCapabilityPolicy = CallerCapabilityPolicy::CompatibleSingleReplica;

/// Every QUIC storage command a client can send, with `Verify` split by its heal flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmd {
    Put,
    PutResolved,
    Copy,
    MutableStore,
    MutableCas,
    VerifyHeal,
    Get,
    GetMetadata,
    GetResolved,
    Query,
    MutableLoad,
    VerifyNoHeal,
}

/// Refused under the strict policy.
const MUTATIONS: [Cmd; 6] = [
    Cmd::Put,
    Cmd::PutResolved,
    Cmd::Copy,
    Cmd::MutableStore,
    Cmd::MutableCas,
    Cmd::VerifyHeal,
];

/// Admitted under the strict policy.
const READS: [Cmd; 6] = [
    Cmd::Get,
    Cmd::GetMetadata,
    Cmd::GetResolved,
    Cmd::Query,
    Cmd::MutableLoad,
    Cmd::VerifyNoHeal,
];

impl Cmd {
    fn opcode(self) -> u8 {
        (match self {
            Cmd::Put => Command::Put,
            Cmd::PutResolved => Command::PutResolved,
            Cmd::Copy => Command::Copy,
            Cmd::MutableStore => Command::MutableStore,
            Cmd::MutableCas => Command::MutableCas,
            Cmd::VerifyHeal | Cmd::VerifyNoHeal => Command::Verify,
            Cmd::Get => Command::Get,
            Cmd::GetMetadata => Command::GetMetadata,
            Cmd::GetResolved => Command::GetResolved,
            Cmd::Query => Command::Query,
            Cmd::MutableLoad => Command::MutableLoad,
        }) as u8
    }

    /// `Verify` is served from the local store, which the counting wrappers cannot stand in
    /// for (the handler downcasts to the concrete local store). `GetResolved`/`PutResolved` are
    /// v4-only: urc/0.2 answers them `NotImplemented` without a store call. Every other command,
    /// once admitted, reaches a counted store.
    fn reaches_counted_store(self, protocol: Protocol) -> bool {
        match self {
            Cmd::VerifyHeal | Cmd::VerifyNoHeal => false,
            Cmd::GetResolved | Cmd::PutResolved => matches!(protocol, Protocol::V4),
            _ => true,
        }
    }

    /// The wire payload for this command. `v4` selects the lore-storage/0.4 `Copy` layout
    /// (80 bytes, with a target context); urc/0.2 uses the 64-byte one.
    fn payload(self, repository: RepositoryId, v4: bool) -> Bytes {
        let key = Hash::hash_buffer(b"wp120-quic-admission-key");
        let value = Hash::hash_buffer(b"wp120-quic-admission-value");
        let address = Address {
            hash: Hash::hash_buffer(b"wp120-quic-admission-address"),
            context: Context::default(),
        };
        let mut bytes = BytesMut::new();
        match self {
            Cmd::Put => {
                let (fragment, address, payload) = fragment::generate_random();
                return Put {
                    address,
                    fragment,
                    payload: Some(payload),
                }
                .to_bytes();
            }
            Cmd::PutResolved => {
                let (fragment, address, payload) = fragment::generate_random();
                bytes.extend_from_slice(key.as_bytes());
                bytes.extend_from_slice(address.as_bytes());
                bytes.extend_from_slice(fragment.as_bytes());
                bytes.extend_from_slice(&payload);
            }
            Cmd::Copy => {
                bytes.extend_from_slice(repository.as_bytes());
                bytes.extend_from_slice(address.hash.as_bytes());
                bytes.extend_from_slice(address.context.as_bytes());
                if v4 {
                    bytes.extend_from_slice(Context::default().as_bytes());
                }
            }
            Cmd::MutableStore => {
                bytes.extend_from_slice(key.as_bytes());
                bytes.extend_from_slice(value.as_bytes());
                bytes.extend_from_slice(&[KeyType::Untyped as u8]);
            }
            Cmd::MutableCas => {
                bytes.extend_from_slice(key.as_bytes());
                bytes.extend_from_slice(Hash::default().as_bytes());
                bytes.extend_from_slice(value.as_bytes());
                bytes.extend_from_slice(&[KeyType::Untyped as u8]);
            }
            Cmd::VerifyHeal | Cmd::VerifyNoHeal => {
                let mut wire = vec![0u8; size_of::<Verify>()];
                wire[..size_of::<Address>()].copy_from_slice(address.as_bytes());
                wire[std::mem::offset_of!(Verify, heal)] = u8::from(self == Cmd::VerifyHeal);
                bytes.extend_from_slice(&wire);
            }
            Cmd::Get | Cmd::GetMetadata | Cmd::Query => {
                bytes.extend_from_slice(address.as_bytes());
            }
            Cmd::GetResolved => {
                bytes.extend_from_slice(key.as_bytes());
                bytes.extend_from_slice(Context::default().as_bytes());
                bytes.extend_from_slice(&0u32.to_le_bytes());
            }
            Cmd::MutableLoad => {
                bytes.extend_from_slice(key.as_bytes());
                bytes.extend_from_slice(&[KeyType::Untyped as u8]);
            }
        }
        bytes.freeze()
    }

    fn parsed(self, repository: RepositoryId, v4: bool) -> ParsedStorageRequest {
        let payload = self.payload(repository, v4);
        if v4 {
            parse_message_for_opcode_v4(self.opcode(), payload)
        } else {
            parse_message_for_opcode(self.opcode(), payload)
        }
        .unwrap_or_else(|error| panic!("{self:?} payload must parse: {error:?}"))
    }
}

/// Counts every call into the wrapped immutable store.
struct CountingImmutableStore {
    inner: Arc<dyn ImmutableStore>,
    calls: Arc<AtomicUsize>,
}

impl CountingImmutableStore {
    fn hit(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl ImmutableStore for CountingImmutableStore {
    async fn get(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
    ) -> Result<StoreGetData, StoreError> {
        self.hit();
        self.inner.clone().get(partition, address).await
    }

    async fn query(
        self: Arc<Self>,
        partition: Partition,
        addresses: &[Address],
        results: &mut [StoreMatchResult],
    ) -> Result<(), StoreError> {
        self.hit();
        self.inner
            .clone()
            .query(partition, addresses, results)
            .await
    }

    async fn get_metadata(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
    ) -> Result<StoreGetData, StoreError> {
        self.hit();
        self.inner.clone().get_metadata(partition, address).await
    }

    async fn put(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
        force: bool,
    ) -> Result<(), StoreError> {
        self.hit();
        self.inner
            .clone()
            .put(partition, address, fragment, payload, force)
            .await
    }

    async fn obliterate(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        stats: Arc<StoreObliterateStats>,
    ) -> Result<(), StoreError> {
        self.hit();
        self.inner
            .clone()
            .obliterate(partition, address, stats)
            .await
    }

    async fn evict(
        self: Arc<Self>,
        max_capacity: usize,
        sync_data: bool,
        sink: Option<lore_storage::gc_event::GcEventSinkRef>,
    ) -> Result<usize, StoreError> {
        self.hit();
        self.inner
            .clone()
            .evict(max_capacity, sync_data, sink)
            .await
    }

    async fn compact(
        self: Arc<Self>,
        max_size: usize,
        at: Option<usize>,
        sync_data: bool,
        sink: Option<lore_storage::gc_event::GcEventSinkRef>,
    ) -> Result<Option<usize>, StoreError> {
        self.hit();
        self.inner
            .clone()
            .compact(max_size, at, sync_data, sink)
            .await
    }

    async fn compact_resume_at(self: Arc<Self>) -> Option<usize> {
        self.inner.clone().compact_resume_at().await
    }

    fn max_query_batch(&self) -> Option<usize> {
        self.inner.max_query_batch()
    }

    async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
        self.hit();
        self.inner.clone().flush(sync_data).await
    }

    async fn verify(self: Arc<Self>, heal: bool) -> Result<(), StoreError> {
        self.hit();
        self.inner.clone().verify(heal).await
    }

    async fn copy(
        self: Arc<Self>,
        source_partition: Partition,
        source_address: Address,
        destination_partition: Partition,
        destination_context: Context,
        behavior: CopyBehavior,
    ) -> Result<(), StoreError> {
        self.hit();
        self.inner
            .clone()
            .copy(
                source_partition,
                source_address,
                destination_partition,
                destination_context,
                behavior,
            )
            .await
    }
}

/// Counts every call into the wrapped mutable store.
struct CountingMutableStore {
    inner: Arc<dyn MutableStore>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl MutableStore for CountingMutableStore {
    async fn load(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.clone().load(partition, key, key_type).await
    }

    async fn store(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .clone()
            .store(partition, key, value, key_type)
            .await
    }

    async fn compare_and_swap(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .clone()
            .compare_and_swap(partition, key, expected, value, key_type)
            .await
    }

    async fn list(
        self: Arc<Self>,
        partition: Partition,
        key_type: KeyType,
    ) -> Result<KeyValueStream, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.clone().list(partition, key_type).await
    }

    async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.clone().flush(sync_data).await
    }
}

/// Counted immutable and mutable stores, plus the uncounted real local store `Verify` needs.
struct Stores {
    immutable: Arc<dyn ImmutableStore>,
    local: Arc<dyn ImmutableStore>,
    mutable: Arc<dyn MutableStore>,
    calls: Arc<AtomicUsize>,
}

impl Stores {
    async fn new() -> Self {
        let (immutable, mutable, _execution) =
            test_store_create().await.expect("Failed to create stores");
        let calls = Arc::new(AtomicUsize::new(0));
        Self {
            immutable: Arc::new(CountingImmutableStore {
                inner: immutable.clone(),
                calls: calls.clone(),
            }),
            local: immutable,
            mutable: Arc::new(CountingMutableStore {
                inner: mutable,
                calls: calls.clone(),
            }),
            calls,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// A `JWKService` that must never be called: the tests seed sessions/contexts directly, so only
/// `jwt_verifier.is_some()` matters for the write gate.
#[derive(Debug)]
struct UnusedJwkService;

#[async_trait]
impl JWKService for UnusedJwkService {
    async fn get_key(
        &self,
        _kid: &str,
    ) -> Result<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm), JWKServiceError> {
        unreachable!("sessions are seeded directly; no token is verified")
    }

    fn get_cached_key(
        &self,
        _kid: &str,
    ) -> Option<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)> {
        unreachable!("sessions are seeded directly; no token is verified")
    }

    async fn refresh_key(
        &self,
        _kid: &str,
    ) -> Result<Option<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)>, JWKServiceError> {
        unreachable!("sessions are seeded directly; no token is verified")
    }
}

fn verifier_present() -> Arc<Option<JwtVerifier>> {
    Arc::new(Some(JwtVerifier {
        jwk_service: Arc::new(UnusedJwkService),
        jwt_issuer: None,
        jwt_audience: None,
        jwt_typ: None,
        identity_claim: DEFAULT_IDENTITY_CLAIM.to_string(),
    }))
}

/// Which storage protocol a case drives.
#[derive(Clone, Copy, Debug)]
enum Protocol {
    V4,
    Legacy,
}

/// The service under test plus the repository its session/connection is bound to.
enum Service {
    V4(StorageServiceV4, u32),
    Legacy(StorageService, Arc<AttributeMap>),
}

/// Build a service of `protocol` under `policy`. `auth` puts a verifier in place with write
/// enforcement on, and binds a caller holding `read` only (v4) or no token at all (legacy):
/// a caller with no write grant.
fn service(
    protocol: Protocol,
    policy: CallerCapabilityPolicy,
    stores: &Stores,
    repository: RepositoryId,
    auth: bool,
) -> Service {
    let verifier = if auth {
        verifier_present()
    } else {
        Arc::new(None)
    };
    match protocol {
        Protocol::V4 => {
            let service = StorageServiceV4::new(
                verifier,
                Arc::new(AllowAllRepositoryAuthorizer),
                stores.immutable.clone(),
                stores.local.clone(),
                stores.mutable.clone(),
                auth,
                Arc::new(UserAgentFilter::default()),
            )
            .with_caller_capability_policy(policy);
            let (session_id, _) = service
                .session_map
                .start(
                    repository,
                    "corr".into(),
                    "user".into(),
                    vec!["read".into()],
                    None,
                    None,
                    false,
                )
                .expect("seed session");
            Service::V4(service, session_id)
        }
        Protocol::Legacy => {
            let service = StorageService::new(
                verifier,
                Arc::new(AllowAllRepositoryAuthorizer),
                stores.immutable.clone(),
                stores.local.clone(),
                stores.mutable.clone(),
                auth,
            )
            .with_caller_capability_policy(policy);
            let context = Arc::new(AttributeMap::default());
            context.insert(repository);
            Service::Legacy(service, context)
        }
    }
}

impl Service {
    async fn run(
        &self,
        cmd: Cmd,
        repository: RepositoryId,
    ) -> Result<Vec<Bytes>, MessageHandleError> {
        match self {
            Service::V4(service, session_id) => {
                service
                    .run_request_handler(
                        AttributeMap::default().into(),
                        ParsedStorageRequestV4::StorageCommand {
                            session_id: *session_id,
                            opcode: cmd.opcode(),
                            payload: cmd.payload(repository, true),
                        },
                    )
                    .await
            }
            Service::Legacy(service, context) => {
                service
                    .run_request_handler(context.clone(), cmd.parsed(repository, false))
                    .await
            }
        }
    }

    fn wire_code(&self, error: &MessageHandleError) -> (QuicErrorStatus, &'static str, bool) {
        let info = match self {
            Service::V4(service, _) => service.transform_protocol_error(error),
            Service::Legacy(service, _) => service.transform_protocol_error(error),
        };
        (
            info.response_error_code,
            info.message_handle_label,
            info.is_internal_error,
        )
    }
}

/// Storage status 200 is the `unsupported-client` refusal, and nothing else that a client
/// would retry or treat as an unknown outcome.
fn assert_unsupported_client_on_the_wire(
    service: &Service,
    error: &MessageHandleError,
    case: &str,
) {
    assert!(
        matches!(error, MessageHandleError::UnsupportedClient),
        "{case}: expected UnsupportedClient, got {error:?}"
    );
    let (code, label, internal) = service.wire_code(error);
    assert_eq!(code, 200, "{case}: storage status");
    assert_eq!(
        code,
        QuicServiceError::ImplementationReserved as QuicErrorStatus,
        "{case}: 200 is the first service-reserved code"
    );
    assert_ne!(
        code,
        QuicServiceError::SlowDown as QuicErrorStatus,
        "{case}"
    );
    assert_ne!(
        code,
        QuicServiceError::OutcomeUnknown as QuicErrorStatus,
        "{case}"
    );
    assert_eq!(label, "UnsupportedClient", "{case}: metrics label");
    assert!(!internal, "{case}: a refusal is not an internal error");
}

#[test]
fn admit_quic_classifies_every_request_variant() {
    let repository = random::<RepositoryId>();
    for cmd in MUTATIONS {
        for v4 in [true, false] {
            let request = cmd.parsed(repository, v4);
            // Undeclared rows: the pre-WP-124 behaviour, unchanged.
            assert!(
                matches!(
                    admit_quic(STRICT, &request, false),
                    Err(MessageHandleError::UnsupportedClient)
                ),
                "strict must refuse {cmd:?} (v4={v4}) when undeclared"
            );
            assert!(
                admit_quic(COMPATIBLE, &request, false).is_ok(),
                "compatible must admit {cmd:?} (v4={v4})"
            );
            // Declared rows: every mutation is admitted; compatible is indifferent.
            assert!(
                admit_quic(STRICT, &request, true).is_ok(),
                "strict must admit {cmd:?} (v4={v4}) when declared"
            );
            assert!(
                admit_quic(COMPATIBLE, &request, true).is_ok(),
                "compatible must admit {cmd:?} (v4={v4}) when declared"
            );
        }
    }
    for cmd in READS {
        for v4 in [true, false] {
            let request = cmd.parsed(repository, v4);
            for declared in [false, true] {
                assert!(
                    admit_quic(STRICT, &request, declared).is_ok(),
                    "strict must admit {cmd:?} (v4={v4}, declared={declared})"
                );
                assert!(admit_quic(COMPATIBLE, &request, declared).is_ok());
            }
        }
    }
    // Connection setup on the legacy protocol stays admitted, or no read could ever run.
    let connect = parse_message_for_opcode(Command::Authorize as u8, Bytes::from(vec![0u8; 16]))
        .expect("Connect parses");
    let correlate = parse_message_for_opcode(5, Bytes::from_static(b"wp120-correlation-id"))
        .expect("Correlate parses");
    for request in [connect, correlate] {
        assert!(matches!(
            request,
            ParsedStorageRequest::Connect(_) | ParsedStorageRequest::Correlate(_)
        ));
        for declared in [false, true] {
            assert!(
                admit_quic(STRICT, &request, declared).is_ok(),
                "{request:?}"
            );
            assert!(
                admit_quic(COMPATIBLE, &request, declared).is_ok(),
                "{request:?}"
            );
        }
    }
}
#[tokio::test]
async fn strict_refuses_every_quic_mutation_with_200_and_no_store_call() {
    for protocol in [Protocol::V4, Protocol::Legacy] {
        for cmd in MUTATIONS {
            let case = format!("{protocol:?} {cmd:?}");
            let stores = Stores::new().await;
            let repository = random::<RepositoryId>();
            let service = service(protocol, STRICT, &stores, repository, false);
            let error = service
                .run(cmd, repository)
                .await
                .expect_err(&format!("{case}: strict must refuse"));
            assert_unsupported_client_on_the_wire(&service, &error, &case);
            assert_eq!(
                stores.calls(),
                0,
                "{case}: a refused mutation touched a store"
            );
        }
    }
}

#[tokio::test]
async fn strict_admits_every_quic_read() {
    for protocol in [Protocol::V4, Protocol::Legacy] {
        for cmd in READS {
            let case = format!("{protocol:?} {cmd:?}");
            let stores = Stores::new().await;
            let repository = random::<RepositoryId>();
            let service = service(protocol, STRICT, &stores, repository, false);
            let result = service.run(cmd, repository).await;
            assert!(
                !matches!(result, Err(MessageHandleError::UnsupportedClient)),
                "{case}: strict must admit a read, got {result:?}"
            );
            if cmd.reaches_counted_store(protocol) {
                assert!(
                    stores.calls() > 0,
                    "{case}: an admitted read never reached the store"
                );
            }
        }
    }
}

#[tokio::test]
async fn compatible_admits_every_quic_command() {
    for protocol in [Protocol::V4, Protocol::Legacy] {
        for cmd in MUTATIONS.into_iter().chain(READS) {
            let case = format!("{protocol:?} {cmd:?}");
            let stores = Stores::new().await;
            let repository = random::<RepositoryId>();
            let service = service(protocol, COMPATIBLE, &stores, repository, false);
            let result = service.run(cmd, repository).await;
            assert!(
                !matches!(result, Err(MessageHandleError::UnsupportedClient)),
                "{case}: compatible must not refuse, got {result:?}"
            );
            if cmd.reaches_counted_store(protocol) {
                assert!(
                    stores.calls() > 0,
                    "{case}: an admitted command never reached the store"
                );
            }
        }
    }
}

/// The contract order: caller admission runs before write authorization. A caller with no
/// write grant is told `unsupported-client` under strict, and the positive control proves the
/// same caller is refused by the write gate (`NotAuthorized`) under compatible.
#[tokio::test]
async fn strict_admission_runs_before_the_write_permission_gate() {
    for protocol in [Protocol::V4, Protocol::Legacy] {
        for cmd in MUTATIONS {
            let case = format!("{protocol:?} {cmd:?}");

            let stores = Stores::new().await;
            let repository = random::<RepositoryId>();
            let strict = service(protocol, STRICT, &stores, repository, true);
            let error = strict
                .run(cmd, repository)
                .await
                .expect_err(&format!("{case}: strict must refuse"));
            assert_unsupported_client_on_the_wire(&strict, &error, &case);
            assert_eq!(stores.calls(), 0, "{case}");

            let stores = Stores::new().await;
            let compatible = service(protocol, COMPATIBLE, &stores, repository, true);
            let error = compatible.run(cmd, repository).await.expect_err(&format!(
                "{case}: the write gate must refuse a read-only caller"
            ));
            assert!(
                matches!(error, MessageHandleError::AuthorizationFailure(_)),
                "{case}: expected AuthorizationFailure under compatible, got {error:?}"
            );
            let (code, _, _) = compatible.wire_code(&error);
            assert_eq!(
                code,
                QuicServiceError::NotAuthorized as QuicErrorStatus,
                "{case}"
            );
            assert_eq!(stores.calls(), 0, "{case}");
        }
    }
}

/// `new` keeps the compatible default, so an unconfigured service is unchanged.
#[tokio::test]
async fn services_built_without_a_policy_stay_compatible() {
    let stores = Stores::new().await;
    let repository = random::<RepositoryId>();
    let v4 = StorageServiceV4::new(
        Arc::new(None),
        Arc::new(AllowAllRepositoryAuthorizer),
        stores.immutable.clone(),
        stores.local.clone(),
        stores.mutable.clone(),
        false,
        Arc::new(UserAgentFilter::default()),
    );
    let (session_id, _) = v4
        .session_map
        .start(
            repository,
            "corr".into(),
            "user".into(),
            vec![],
            None,
            None,
            false,
        )
        .expect("seed session");
    v4.run_request_handler(
        AttributeMap::default().into(),
        ParsedStorageRequestV4::StorageCommand {
            session_id,
            opcode: Cmd::Put.opcode(),
            payload: Cmd::Put.payload(repository, true),
        },
    )
    .await
    .expect("a default-built v4 service admits Put");

    let legacy = StorageService::new(
        Arc::new(None),
        Arc::new(AllowAllRepositoryAuthorizer),
        stores.immutable.clone(),
        stores.local.clone(),
        stores.mutable.clone(),
        false,
    );
    let context = Arc::new(AttributeMap::default());
    context.insert(repository);
    legacy
        .run_request_handler(context, Cmd::Put.parsed(repository, false))
        .await
        .expect("a default-built legacy service admits Put");
}

/// On gRPC the same refusal is the admission layer's own answer: `FAILED_PRECONDITION` with
/// the `unsupported-client` header.
#[test]
fn unsupported_client_maps_to_the_grpc_admission_refusal() {
    let status = lore_server::grpc::map_message_handle_error_to_status(
        &MessageHandleError::UnsupportedClient,
        None,
        None,
    );
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(status.message(), "unsupported client capability");
    assert_eq!(
        status.metadata().get(ADMISSION_HEADER).unwrap(),
        "unsupported-client"
    );
    assert!(
        status
            .metadata()
            .get(lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_KEY)
            .is_none(),
        "a refusal is a confirmed non-effect, never an unknown outcome"
    );
}

// ---- WP-124 slice 1: declared v4 sessions ----------------------------------------------------

/// A `lore-storage/0.4` service whose seeded session is `declared` and holds `write` or only
/// `read`. `auth` puts a verifier in place with write enforcement on (so `write` matters).
fn declared_v4_service(
    policy: CallerCapabilityPolicy,
    stores: &Stores,
    repository: RepositoryId,
    auth: bool,
    declared: bool,
    write: bool,
) -> Service {
    let verifier = if auth {
        verifier_present()
    } else {
        Arc::new(None)
    };
    let service = StorageServiceV4::new(
        verifier,
        Arc::new(AllowAllRepositoryAuthorizer),
        stores.immutable.clone(),
        stores.local.clone(),
        stores.mutable.clone(),
        auth,
        Arc::new(UserAgentFilter::default()),
    )
    .with_caller_capability_policy(policy);
    let permissions = if write {
        vec!["read".into(), "write".into()]
    } else {
        vec!["read".into()]
    };
    let (session_id, _) = service
        .session_map
        .start(
            repository,
            "corr".into(),
            "user".into(),
            permissions,
            None,
            None,
            declared,
        )
        .expect("seed session");
    Service::V4(service, session_id)
}

/// The full table through the v4 harness: every command x policy x declared/undeclared. Only
/// a strict policy with an undeclared session refuses a mutation, with 200 and no store call;
/// every other cell is admitted and, where the command reaches a counted store, reaches it.
///
/// Mutation probe (a), dropping the declared arm of `admit_quic`, turns the strict + declared
/// mutation rows red.
#[tokio::test]
async fn v4_admission_table_command_by_policy_by_declaration() {
    for policy in [STRICT, COMPATIBLE] {
        for declared in [false, true] {
            for cmd in MUTATIONS.into_iter().chain(READS) {
                let case = format!("{policy:?} declared={declared} {cmd:?}");
                let stores = Stores::new().await;
                let repository = random::<RepositoryId>();
                let service =
                    declared_v4_service(policy, &stores, repository, false, declared, false);
                let result = service.run(cmd, repository).await;
                let refused = policy == STRICT && !declared && MUTATIONS.contains(&cmd);
                if refused {
                    let error = result.expect_err(&format!("{case}: must be refused"));
                    assert_unsupported_client_on_the_wire(&service, &error, &case);
                    assert_eq!(
                        stores.calls(),
                        0,
                        "{case}: a refused mutation touched a store"
                    );
                } else {
                    assert!(
                        !matches!(result, Err(MessageHandleError::UnsupportedClient)),
                        "{case}: must be admitted, got {result:?}"
                    );
                    if cmd.reaches_counted_store(Protocol::V4) {
                        assert!(stores.calls() > 0, "{case}: never reached the store");
                    }
                }
            }
        }
    }
}

/// Declared + strict + `write` grant: the mutation passes admission and the write gate, and the
/// store is called exactly once.
#[tokio::test]
async fn strict_declared_session_with_write_reaches_the_store_once() {
    for cmd in [Cmd::Put, Cmd::MutableStore, Cmd::MutableCas] {
        let case = format!("{cmd:?}");
        let stores = Stores::new().await;
        let repository = random::<RepositoryId>();
        let service = declared_v4_service(STRICT, &stores, repository, true, true, true);
        let result = service.run(cmd, repository).await;
        assert!(
            result.is_ok(),
            "{case}: expected the write to succeed, got {result:?}"
        );
        assert_eq!(stores.calls(), 1, "{case}: exactly one store call");
    }
    // Every other mutation also clears both gates (whatever the store then answers).
    for cmd in MUTATIONS {
        let case = format!("{cmd:?}");
        let stores = Stores::new().await;
        let repository = random::<RepositoryId>();
        let service = declared_v4_service(STRICT, &stores, repository, true, true, true);
        let result = service.run(cmd, repository).await;
        assert!(
            !matches!(
                result,
                Err(MessageHandleError::UnsupportedClient
                    | MessageHandleError::AuthorizationFailure(_))
            ),
            "{case}: a declared session with write must clear admission and the write gate, got {result:?}"
        );
    }
}

/// The contract order: admission, then write authorization. A declared session without the
/// `write` grant passes admission and is then refused by the write gate with `NotAuthorized`
/// (2), not by admission with 200, and no store is touched.
///
/// Mutation probe (b), swapping `admit_quic` and `require_write`, turns
/// `strict_admission_runs_before_the_write_permission_gate` red (undeclared, expects 200). This
/// test pins the other half of the pair: declared must see the write gate's answer.
#[tokio::test]
async fn strict_declared_session_without_write_is_not_authorized_not_unsupported() {
    for cmd in MUTATIONS {
        let case = format!("{cmd:?}");
        let stores = Stores::new().await;
        let repository = random::<RepositoryId>();
        let service = declared_v4_service(STRICT, &stores, repository, true, true, false);
        let error = service
            .run(cmd, repository)
            .await
            .expect_err(&format!("{case}: the write gate must refuse"));
        assert!(
            matches!(error, MessageHandleError::AuthorizationFailure(_)),
            "{case}: expected AuthorizationFailure, got {error:?}"
        );
        let (code, _, _) = service.wire_code(&error);
        assert_eq!(
            code,
            QuicServiceError::NotAuthorized as QuicErrorStatus,
            "{case}"
        );
        assert_eq!(code, 2, "{case}");
        assert_eq!(stores.calls(), 0, "{case}");
    }
}

/// The undeclared counterpart of the case above, side by side on the same service shape: no
/// `write` grant, strict, undeclared is still 200. Declaration changes the answer, nothing else.
#[tokio::test]
async fn strict_undeclared_session_without_write_is_still_200() {
    for cmd in MUTATIONS {
        let case = format!("{cmd:?}");
        let stores = Stores::new().await;
        let repository = random::<RepositoryId>();
        let service = declared_v4_service(STRICT, &stores, repository, true, false, false);
        let error = service
            .run(cmd, repository)
            .await
            .expect_err(&format!("{case}: must be refused"));
        assert_unsupported_client_on_the_wire(&service, &error, &case);
        assert_eq!(stores.calls(), 0, "{case}");
    }
}

/// The real path end to end: the declaration made in `AuthorizeStart` decides the session's
/// writes. Action 2 with `outcome_unknown_v1` writes; action 0 and a valid list without the
/// token are refused with 200; sessions of one service do not share a declaration.
#[tokio::test]
async fn the_authorize_start_declaration_decides_the_sessions_writes() {
    let stores = Stores::new().await;
    let repository = random::<RepositoryId>();
    let service = StorageServiceV4::new(
        Arc::new(None),
        Arc::new(AllowAllRepositoryAuthorizer),
        stores.immutable.clone(),
        stores.local.clone(),
        stores.mutable.clone(),
        false,
        Arc::new(UserAgentFilter::default()),
    )
    .with_caller_capability_policy(STRICT);

    let open = |caps: Option<&'static str>| {
        let service = &service;
        async move {
            let response = service
                .run_request_handler(
                    AttributeMap::default().into(),
                    ParsedStorageRequestV4::AuthorizeStart {
                        repository,
                        correlation_id: "corr".into(),
                        auth_token: vec![],
                        caller_capabilities: caps.map(str::to_string),
                    },
                )
                .await
                .expect("the session must open");
            u32::from_le_bytes(response[0][..4].try_into().unwrap())
        }
    };
    let put = |session_id: u32| {
        let service = &service;
        async move {
            service
                .run_request_handler(
                    AttributeMap::default().into(),
                    ParsedStorageRequestV4::StorageCommand {
                        session_id,
                        opcode: Cmd::Put.opcode(),
                        payload: Cmd::Put.payload(repository, true),
                    },
                )
                .await
        }
    };

    // Opened in an order that would expose a declaration leaking between sessions.
    let plain = open(None).await;
    let declared = open(Some("outcome_unknown_v1")).await;
    let other_caps = open(Some("other_capability")).await;
    let declared_with_extras = open(Some("a,outcome_unknown_v1,z")).await;

    for (name, session_id) in [("action 0", plain), ("other capability", other_caps)] {
        let error = put(session_id).await.expect_err(name);
        assert!(
            matches!(error, MessageHandleError::UnsupportedClient),
            "{name}: {error:?}"
        );
        assert_eq!(stores.calls(), 0, "{name}");
    }
    for (name, session_id) in [
        ("declared", declared),
        ("declared with extras", declared_with_extras),
    ] {
        let before = stores.calls();
        put(session_id)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(stores.calls(), before + 1, "{name}");
    }
    // The undeclared session is still refused after the declared ones wrote.
    let error = put(plain).await.expect_err("still undeclared");
    assert!(matches!(error, MessageHandleError::UnsupportedClient));
}

/// `urc/0.2` has no declaration carrier: strict writes stay 200 with zero store calls, with auth
/// off and with a verifier and write enforcement on. Pinned in source too, because no behaviour
/// can tell `false` from a hard-coded `true` that no legacy request could ever change.
#[tokio::test]
async fn legacy_urc02_writes_stay_refused_under_strict() {
    for auth in [false, true] {
        for cmd in MUTATIONS {
            let case = format!("auth={auth} {cmd:?}");
            let stores = Stores::new().await;
            let repository = random::<RepositoryId>();
            let service = service(Protocol::Legacy, STRICT, &stores, repository, auth);
            let error = service
                .run(cmd, repository)
                .await
                .expect_err(&format!("{case}: must be refused"));
            assert_unsupported_client_on_the_wire(&service, &error, &case);
            assert_eq!(stores.calls(), 0, "{case}");
        }
    }
}

#[test]
fn legacy_urc02_admits_with_declared_false_only() {
    let source: String = include_str!("../../../../src/quic/storage_service.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
        .split_whitespace()
        .collect();
    let calls: Vec<_> = source.match_indices("admit_quic(").collect();
    assert_eq!(
        calls.len(),
        1,
        "urc/0.2 has exactly one admission call site"
    );
    assert!(
        source.contains("admit_quic(self.caller_capability_policy,&request,false)"),
        "urc/0.2 has no sessions and must always admit as undeclared"
    );
}

// ---- grammar parity: one table, two entry points ---------------------------------------------

/// The header path (`declares_outcome_unknown`) and the QUIC path (`parse_capability_list`)
/// must accept and refuse the same strings and answer the same bool.
#[test]
fn the_header_and_quic_paths_share_one_grammar() {
    let sixteen_of = |len: usize| -> String {
        (0..16)
            .map(|i| format!("a{i:02}{}", "x".repeat(len - 3)))
            .collect::<Vec<_>>()
            .join(",")
    };
    let seventeen = (0..17)
        .map(|i| format!("a{i:02}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut at_cap = (0..16)
        .map(|i| format!("a{i:02}{}", "x".repeat(60)))
        .collect::<Vec<_>>();
    at_cap[15].push('x');
    let at_cap = at_cap.join(",");
    assert_eq!(at_cap.len(), 1024);
    let over_cap = sixteen_of(64);
    assert_eq!(over_cap.len(), 1039);

    // (value, Some(declared) when accepted, None when refused)
    let table: Vec<(String, Option<bool>)> = vec![
        ("outcome_unknown_v1".into(), Some(true)),
        ("a,outcome_unknown_v1,z".into(), Some(true)),
        ("other_capability".into(), Some(false)),
        ("a,b".into(), Some(false)),
        ("a".repeat(64), Some(false)),
        (at_cap, Some(false)),
        (
            (0..16)
                .map(|i| format!("a{i:02}"))
                .collect::<Vec<_>>()
                .join(","),
            Some(false),
        ),
        // refused
        (String::new(), None),
        ("z,outcome_unknown_v1".into(), None),
        ("outcome_unknown_v1,outcome_unknown_v1".into(), None),
        ("a,,b".into(), None),
        ("a,".into(), None),
        (",a".into(), None),
        (" outcome_unknown_v1".into(), None),
        ("outcome_unknown_v1 ".into(), None),
        ("a".repeat(65), None),
        (seventeen, None),
        (over_cap, None),
        ("Outcome_unknown_v1".into(), None),
        ("OUTCOME_UNKNOWN_V1".into(), None),
        ("0foo".into(), None),
        ("_foo".into(), None),
        ("outcome-unknown-v1".into(), None),
        ("caf\u{e9}".into(), None),
    ];
    for (value, expected) in &table {
        let quic = parse_capability_list(value);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            CAPABILITIES_HEADER,
            http::HeaderValue::from_str(value).expect("a visible-ASCII-or-opaque header value"),
        );
        let header = declares_outcome_unknown(&headers);
        if let Some(declared) = expected {
            assert_eq!(quic, Ok(*declared), "parse_capability_list({value:?})");
            assert_eq!(
                header.as_ref().ok(),
                Some(declared),
                "declares_outcome_unknown({value:?})"
            );
        } else {
            assert!(
                quic.is_err(),
                "parse_capability_list({value:?}) must refuse"
            );
            assert!(
                header.is_err(),
                "declares_outcome_unknown({value:?}) must refuse"
            );
        }
    }
}

// WP-124 slice 5b: the token-expiry re-check, driven through the harness above.
mod session_expiry;
