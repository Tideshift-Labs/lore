// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): the generic mutable RPCs refuse a client write to a
//! server-owned (CR-029 domain) key type.
//!
//! The seven RPCs (v0 and v1 gRPC `MutableStore` and `MutableCompareAndSwap`,
//! and the `urc/0.2` and `lore-storage/0.4` QUIC `MutableStore` and
//! `MutableCas`) all reach the store through `handle_mutable_store` or
//! `handle_mutable_cas`. Each transport is driven through the same table by the
//! [`Transport`] trait, over a plain local mutable store: the refusal is
//! store-independent, so it must hold with no Postgres and no enforcement.
//!
//! Every refusal case asserts two things: the wire answer, and that the store
//! saw no write (a counting wrapper plus a read-back of a pre-seeded value).
//! Every transport also carries a positive control, so a harness that cannot
//! write at all cannot read as a pass.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use bytes::Bytes;
use bytes::BytesMut;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_base::types::Partition;
use lore_proto::lore::storage::v1 as storage_v1;
use lore_proto::lore::storage::v1::storage_service_server::StorageService as StorageServiceV1;
use lore_revision::lore::RepositoryId;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::auth::jwt::ResourcePermission;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::grpc::storage_service::LoreStorageService;
use lore_server::legacy::rpc::storage_service_server::StorageService as StorageServiceV0;
use lore_server::protocol::attribute_map::AttributeMap;
use lore_server::protocol::storage::messages::MessageHandleError;
use lore_server::protocol::storage::requests;
use lore_server::quic::QuicService;
use lore_server::quic::storage_service::ParsedStorageRequest;
use lore_server::quic::storage_service::StorageService as QuicStorageServiceV02;
use lore_server::quic::storage_service_v4::ParsedStorageRequestV4;
use lore_server::quic::storage_service_v4::StorageServiceV4;
use lore_telemetry::user_agent_filter::UserAgentFilter;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use lore_transport::quic::QuicErrorStatus;
use lore_transport::quic::QuicServiceError;
use lore_transport::quic::storage_service::Command;
use rand::random;
use tonic::Code;
use tonic::Request;
use tonic::Status;
use zerocopy::IntoBytes;

use crate::store::test_support::test_store_create;

/// The server-owned set: `lore_postgres::domain::bypass::is_domain_owned`.
const REFUSED: [KeyType; 6] = [
    KeyType::RepositoryId,
    KeyType::RepositoryMetadata,
    KeyType::BranchId,
    KeyType::BranchMetadata,
    KeyType::BranchLatestPointer,
    KeyType::Instance,
];

/// The key types a client may still write through the generic RPCs.
const ALLOWED: [KeyType; 2] = [KeyType::Resolve, KeyType::Untyped];

/// A mutable store that counts the writes that reach it.
struct RecordingStore {
    inner: Arc<dyn lore_storage::MutableStore>,
    writes: Arc<AtomicUsize>,
}

#[async_trait]
impl lore_storage::MutableStore for RecordingStore {
    async fn load(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        key_type: KeyType,
    ) -> Result<Hash, lore_storage::StoreError> {
        self.inner.clone().load(partition, key, key_type).await
    }

    async fn store(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), lore_storage::StoreError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
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
    ) -> Result<Hash, lore_storage::StoreError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .clone()
            .compare_and_swap(partition, key, expected, value, key_type)
            .await
    }

    async fn list(
        self: Arc<Self>,
        partition: Partition,
        key_type: KeyType,
    ) -> Result<lore_storage::KeyValueStream, lore_storage::StoreError> {
        self.inner.clone().list(partition, key_type).await
    }

    async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), lore_storage::StoreError> {
        self.inner.clone().flush(sync_data).await
    }
}

/// One local store pair, with the mutable side wrapped in a write counter.
/// `inner` reads and seeds without touching the counter.
struct Fixture {
    immutable: Arc<dyn lore_storage::ImmutableStore>,
    inner: Arc<dyn lore_storage::MutableStore>,
    recording: Arc<dyn lore_storage::MutableStore>,
    writes: Arc<AtomicUsize>,
    execution: Arc<lore_revision::interface::ExecutionContext>,
    repository: RepositoryId,
}

async fn fixture() -> Fixture {
    let (immutable, inner, execution) = test_store_create().await.expect("stores");
    let writes = Arc::new(AtomicUsize::new(0));
    let recording: Arc<dyn lore_storage::MutableStore> = Arc::new(RecordingStore {
        inner: inner.clone(),
        writes: writes.clone(),
    });
    Fixture {
        immutable,
        inner,
        recording,
        writes,
        execution,
        repository: random::<RepositoryId>(),
    }
}

/// What a transport reports for a refused write: its own status code and the
/// text it carries.
struct Refusal {
    wire: String,
    text: String,
}

/// One transport's `MutableStore` and `MutableCas`, over a [`Fixture`].
#[async_trait]
trait Transport: Send + Sync {
    async fn store(
        &self,
        f: &Fixture,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), Refusal>;

    async fn cas(
        &self,
        f: &Fixture,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), Refusal>;

    /// Asserts the transport's own refusal shape for `key_type`.
    fn assert_refusal(&self, refusal: &Refusal, key_type: KeyType);
}

fn assert_text_names(refusal: &Refusal, key_type: KeyType) {
    assert!(
        refusal.text.contains(&format!("{key_type:?}")),
        "the refusal must name {key_type:?}, got {:?}",
        refusal.text
    );
    assert!(
        refusal.text.contains("domain-owned"),
        "the refusal must say the key type is domain-owned, got {:?}",
        refusal.text
    );
}

async fn refuses_store<T: Transport>(transport: T) {
    let f = fixture().await;
    Box::pin(LORE_CONTEXT.scope(f.execution.clone(), async {
        for key_type in REFUSED {
            let key = random::<Hash>();
            let initial = random::<Hash>();
            f.inner
                .clone()
                .store(f.repository, key, initial, key_type)
                .await
                .expect("seed");
            let before = f.writes.load(Ordering::SeqCst);

            let refusal = transport
                .store(&f, key, random::<Hash>(), key_type)
                .await
                .expect_err(&format!("{key_type:?} must be refused"));
            transport.assert_refusal(&refusal, key_type);

            assert_eq!(
                f.writes.load(Ordering::SeqCst),
                before,
                "{key_type:?}: a refused store must not reach the store"
            );
            assert_eq!(
                f.inner
                    .clone()
                    .load(f.repository, key, key_type)
                    .await
                    .expect("read back"),
                initial,
                "{key_type:?}: the stored value must be unchanged"
            );
        }
    }))
    .await;
}

async fn refuses_cas<T: Transport>(transport: T) {
    let f = fixture().await;
    Box::pin(LORE_CONTEXT.scope(f.execution.clone(), async {
        for key_type in REFUSED {
            let key = random::<Hash>();
            let initial = random::<Hash>();
            f.inner
                .clone()
                .store(f.repository, key, initial, key_type)
                .await
                .expect("seed");
            let before = f.writes.load(Ordering::SeqCst);

            // A correct `expected`: only the refusal can stop this swap.
            let refusal = transport
                .cas(&f, key, initial, random::<Hash>(), key_type)
                .await
                .expect_err(&format!("{key_type:?} must be refused"));
            transport.assert_refusal(&refusal, key_type);

            assert_eq!(
                f.writes.load(Ordering::SeqCst),
                before,
                "{key_type:?}: a refused swap must not reach the store"
            );
            assert_eq!(
                f.inner
                    .clone()
                    .load(f.repository, key, key_type)
                    .await
                    .expect("read back"),
                initial,
                "{key_type:?}: the stored value must be unchanged"
            );
        }
    }))
    .await;
}

async fn allows_store<T: Transport>(transport: T) {
    let f = fixture().await;
    Box::pin(LORE_CONTEXT.scope(f.execution.clone(), async {
        for key_type in ALLOWED {
            let key = random::<Hash>();
            let value = random::<Hash>();
            let before = f.writes.load(Ordering::SeqCst);

            transport
                .store(&f, key, value, key_type)
                .await
                .unwrap_or_else(|refusal| {
                    panic!("{key_type:?} must be writable: {}", refusal.text)
                });

            assert_eq!(
                f.writes.load(Ordering::SeqCst),
                before + 1,
                "{key_type:?}: an accepted store reaches the store once"
            );
            assert_eq!(
                f.inner
                    .clone()
                    .load(f.repository, key, key_type)
                    .await
                    .expect("read back"),
                value,
                "{key_type:?}: the write must land"
            );
        }
    }))
    .await;
}

async fn allows_cas<T: Transport>(transport: T) {
    let f = fixture().await;
    Box::pin(LORE_CONTEXT.scope(f.execution.clone(), async {
        for key_type in ALLOWED {
            let key = random::<Hash>();
            let initial = random::<Hash>();
            let value = random::<Hash>();
            f.inner
                .clone()
                .store(f.repository, key, initial, key_type)
                .await
                .expect("seed");
            let before = f.writes.load(Ordering::SeqCst);

            transport
                .cas(&f, key, initial, value, key_type)
                .await
                .unwrap_or_else(|refusal| {
                    panic!("{key_type:?} must be swappable: {}", refusal.text)
                });

            assert_eq!(
                f.writes.load(Ordering::SeqCst),
                before + 1,
                "{key_type:?}: an accepted swap reaches the store once"
            );
            assert_eq!(
                f.inner
                    .clone()
                    .load(f.repository, key, key_type)
                    .await
                    .expect("read back"),
                value,
                "{key_type:?}: the swap must land"
            );
        }
    }))
    .await;
}

macro_rules! transport_suite {
    ($name:ident, $transport:expr) => {
        mod $name {
            use super::*;

            #[tokio::test]
            async fn refuses_every_domain_key_on_mutable_store() {
                refuses_store($transport).await;
            }

            #[tokio::test]
            async fn refuses_every_domain_key_on_mutable_cas() {
                refuses_cas($transport).await;
            }

            #[tokio::test]
            async fn still_writes_resolve_and_untyped_through_mutable_store() {
                allows_store($transport).await;
            }

            #[tokio::test]
            async fn still_swaps_resolve_and_untyped_through_mutable_cas() {
                allows_cas($transport).await;
            }
        }
    };
}

// ---------------------------------------------------------------------------
// gRPC: v0 (`urc.rpc`) and v1 (`lore.storage.v1`), both on `LoreStorageService`.
// A write-granted token with enforcement on, so the refusal is proved to sit
// behind the permission gate and not to replace it.
// ---------------------------------------------------------------------------

fn with_write_token<T>(inner: T, repository: RepositoryId, permissions: &[&str]) -> Request<T> {
    let mut request = Request::new(inner);
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
    );
    request.extensions_mut().insert(AuthorizationToken {
        user_id: "test-user".into(),
        resources: Some(vec![ResourcePermission {
            resource_id: format!("urc-{repository}"),
            permission: permissions.iter().map(|p| (*p).to_string()).collect(),
        }]),
        ..Default::default()
    });
    request
}

fn grpc_service(f: &Fixture) -> LoreStorageService {
    LoreStorageService::new(
        f.immutable.clone(),
        f.immutable.clone(),
        f.recording.clone(),
        Arc::new(AllowAllRepositoryAuthorizer),
        true,
    )
}

fn grpc_refusal(status: &Status) -> Refusal {
    Refusal {
        wire: format!("{:?}", status.code()),
        text: status.message().to_string(),
    }
}

fn assert_grpc_refusal(refusal: &Refusal, key_type: KeyType) {
    assert_eq!(
        refusal.wire,
        format!("{:?}", Code::PermissionDenied),
        "{key_type:?}: gRPC must answer PermissionDenied"
    );
    assert_text_names(refusal, key_type);
}

#[derive(Clone, Copy)]
struct GrpcV0;

#[async_trait]
impl Transport for GrpcV0 {
    async fn store(
        &self,
        f: &Fixture,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), Refusal> {
        let request = lore_proto::MutableStoreRequest {
            key: Bytes::copy_from_slice(key.as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
            key_type: key_type as u32,
        };
        StorageServiceV0::mutable_store(
            &grpc_service(f),
            with_write_token(request, f.repository, &["read", "write"]),
        )
        .await
        .map(|_| ())
        .map_err(|status| grpc_refusal(&status))
    }

    async fn cas(
        &self,
        f: &Fixture,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), Refusal> {
        let request = lore_proto::MutableCompareAndSwapRequest {
            key: Bytes::copy_from_slice(key.as_bytes()),
            expected: Bytes::copy_from_slice(expected.as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
            key_type: key_type as u32,
        };
        StorageServiceV0::mutable_compare_and_swap(
            &grpc_service(f),
            with_write_token(request, f.repository, &["read", "write"]),
        )
        .await
        .map(|_| ())
        .map_err(|status| grpc_refusal(&status))
    }

    fn assert_refusal(&self, refusal: &Refusal, key_type: KeyType) {
        assert_grpc_refusal(refusal, key_type);
    }
}

transport_suite!(grpc_v0, GrpcV0);

#[derive(Clone, Copy)]
struct GrpcV1;

#[async_trait]
impl Transport for GrpcV1 {
    async fn store(
        &self,
        f: &Fixture,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), Refusal> {
        let request = storage_v1::MutableStoreRequest {
            key: Bytes::copy_from_slice(key.as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
            key_type: key_type as u32,
        };
        StorageServiceV1::mutable_store(
            &grpc_service(f),
            with_write_token(request, f.repository, &["read", "write"]),
        )
        .await
        .map(|_| ())
        .map_err(|status| grpc_refusal(&status))
    }

    async fn cas(
        &self,
        f: &Fixture,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), Refusal> {
        let request = storage_v1::MutableCompareAndSwapRequest {
            key: Bytes::copy_from_slice(key.as_bytes()),
            expected: Bytes::copy_from_slice(expected.as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
            key_type: key_type as u32,
        };
        StorageServiceV1::mutable_compare_and_swap(
            &grpc_service(f),
            with_write_token(request, f.repository, &["read", "write"]),
        )
        .await
        .map(|_| ())
        .map_err(|status| grpc_refusal(&status))
    }

    fn assert_refusal(&self, refusal: &Refusal, key_type: KeyType) {
        assert_grpc_refusal(refusal, key_type);
    }
}

transport_suite!(grpc_v1, GrpcV1);

/// The refusal sits behind the write-permission gate: a read-only caller is
/// told it lacks `write`, not that the key type is server-owned, on both
/// generations.
#[tokio::test]
async fn a_read_only_token_meets_the_permission_gate_before_the_key_refusal() {
    let f = fixture().await;
    Box::pin(LORE_CONTEXT.scope(f.execution.clone(), async {
        let key = random::<Hash>();
        let store_v1 = storage_v1::MutableStoreRequest {
            key: Bytes::copy_from_slice(key.as_bytes()),
            value: Bytes::copy_from_slice(random::<Hash>().as_bytes()),
            key_type: KeyType::BranchLatestPointer as u32,
        };
        let status = StorageServiceV1::mutable_store(
            &grpc_service(&f),
            with_write_token(store_v1, f.repository, &["read"]),
        )
        .await
        .expect_err("a read-only token must be denied");
        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(
            !status.message().contains("domain-owned"),
            "v1: the permission gate answers first, got {:?}",
            status.message()
        );

        let store_v0 = lore_proto::MutableStoreRequest {
            key: Bytes::copy_from_slice(key.as_bytes()),
            value: Bytes::copy_from_slice(random::<Hash>().as_bytes()),
            key_type: KeyType::BranchLatestPointer as u32,
        };
        let status = StorageServiceV0::mutable_store(
            &grpc_service(&f),
            with_write_token(store_v0, f.repository, &["read"]),
        )
        .await
        .expect_err("a read-only token must be denied");
        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(
            !status.message().contains("domain-owned"),
            "v0: the permission gate answers first, got {:?}",
            status.message()
        );
        assert_eq!(f.writes.load(Ordering::SeqCst), 0);
    }))
    .await;
}

// ---------------------------------------------------------------------------
// QUIC: urc/0.2 and lore-storage/0.4. Auth off (no verifier), so the only
// thing between the command and the store is the refusal.
// ---------------------------------------------------------------------------

/// The wire status a QUIC refusal must carry: the generic failure. Not
/// `NotAuthorized` (that is the permission gate) and not 200
/// (`ImplementationReserved`, the unsupported-client refusal).
fn quic_refusal(
    error: &MessageHandleError,
    info: &lore_server::quic::ProtocolErrorInfo,
) -> Refusal {
    assert!(
        !info.is_internal_error,
        "a refused domain key is not a server fault"
    );
    Refusal {
        wire: format!("{}", info.response_error_code),
        text: error.to_string(),
    }
}

fn assert_quic_refusal(refusal: &Refusal, key_type: KeyType) {
    assert_eq!(
        refusal.wire,
        format!("{}", QuicServiceError::Failed as QuicErrorStatus),
        "{key_type:?}: QUIC must answer the generic failure status"
    );
    assert_ne!(
        refusal.wire,
        format!("{}", QuicServiceError::NotAuthorized as QuicErrorStatus)
    );
    assert_ne!(
        refusal.wire,
        format!(
            "{}",
            QuicServiceError::ImplementationReserved as QuicErrorStatus
        )
    );
    assert_text_names(refusal, key_type);
}

#[derive(Clone, Copy)]
struct QuicV02;

impl QuicV02 {
    async fn run(f: &Fixture, request: ParsedStorageRequest) -> Result<(), Refusal> {
        let service = QuicStorageServiceV02::new(
            Arc::new(None),
            Arc::new(AllowAllRepositoryAuthorizer),
            f.immutable.clone(),
            f.immutable.clone(),
            f.recording.clone(),
            false,
        );
        let context = Arc::new(AttributeMap::default());
        context.insert(f.repository);
        service
            .run_request_handler(context, request)
            .await
            .map(|_| ())
            .map_err(|error| quic_refusal(&error, &service.transform_protocol_error(&error)))
    }
}

#[async_trait]
impl Transport for QuicV02 {
    async fn store(
        &self,
        f: &Fixture,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), Refusal> {
        Self::run(
            f,
            ParsedStorageRequest::MutableStoreOp(requests::MutableStoreOp {
                key,
                value,
                key_type,
            }),
        )
        .await
    }

    async fn cas(
        &self,
        f: &Fixture,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), Refusal> {
        Self::run(
            f,
            ParsedStorageRequest::MutableCas(requests::MutableCas {
                key,
                expected,
                value,
                key_type,
            }),
        )
        .await
    }

    fn assert_refusal(&self, refusal: &Refusal, key_type: KeyType) {
        assert_quic_refusal(refusal, key_type);
    }
}

transport_suite!(quic_urc_0_2, QuicV02);

#[derive(Clone, Copy)]
struct QuicV04;

impl QuicV04 {
    async fn run(f: &Fixture, opcode: Command, payload: Bytes) -> Result<(), Refusal> {
        let service = StorageServiceV4::new(
            Arc::new(None),
            Arc::new(AllowAllRepositoryAuthorizer),
            f.immutable.clone(),
            f.immutable.clone(),
            f.recording.clone(),
            false,
            Arc::new(UserAgentFilter::default()),
        );
        let (session_id, _) = service
            .session_map
            .start(
                f.repository,
                "corr".into(),
                "user".into(),
                vec![],
                None,
                None,
            )
            .expect("seed session");
        service
            .run_request_handler(
                AttributeMap::default().into(),
                ParsedStorageRequestV4::StorageCommand {
                    session_id,
                    opcode: opcode as u8,
                    payload,
                },
            )
            .await
            .map(|_| ())
            .map_err(|error| quic_refusal(&error, &service.transform_protocol_error(&error)))
    }
}

#[async_trait]
impl Transport for QuicV04 {
    async fn store(
        &self,
        f: &Fixture,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), Refusal> {
        let mut payload = BytesMut::new();
        payload.extend_from_slice(key.as_bytes());
        payload.extend_from_slice(value.as_bytes());
        payload.extend_from_slice(&[key_type as u8]);
        Self::run(f, Command::MutableStore, payload.freeze()).await
    }

    async fn cas(
        &self,
        f: &Fixture,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), Refusal> {
        let mut payload = BytesMut::new();
        payload.extend_from_slice(key.as_bytes());
        payload.extend_from_slice(expected.as_bytes());
        payload.extend_from_slice(value.as_bytes());
        payload.extend_from_slice(&[key_type as u8]);
        Self::run(f, Command::MutableCas, payload.freeze()).await
    }

    fn assert_refusal(&self, refusal: &Refusal, key_type: KeyType) {
        assert_quic_refusal(refusal, key_type);
    }
}

transport_suite!(quic_lore_storage_0_4, QuicV04);

// ---------------------------------------------------------------------------
// The shared handler layer and the status mappings.
// ---------------------------------------------------------------------------

mod shared_handlers {
    use lore_server::protocol::storage::mutable_cas::handle_mutable_cas;
    use lore_server::protocol::storage::mutable_store_handler::handle_mutable_store;
    use lore_server::protocol::storage::mutable_store_handler::refuse_domain_key;

    use super::*;

    #[test]
    fn the_refused_set_is_exactly_the_domain_owned_set() {
        for key_type in REFUSED {
            assert!(
                matches!(
                    refuse_domain_key(key_type),
                    Err(MessageHandleError::DomainKeyRefused(refused)) if refused == key_type
                ),
                "{key_type:?}"
            );
        }
        for key_type in ALLOWED {
            assert!(refuse_domain_key(key_type).is_ok(), "{key_type:?}");
        }
    }

    #[test]
    fn the_error_text_names_the_key_type() {
        let text = MessageHandleError::DomainKeyRefused(KeyType::BranchLatestPointer).to_string();
        assert!(text.contains("BranchLatestPointer"), "{text}");
        assert!(text.contains("domain-owned"), "{text}");
    }

    #[test]
    fn the_status_mapping_is_permission_denied_and_not_an_internal_error() {
        let error = MessageHandleError::DomainKeyRefused(KeyType::Instance);
        let status = lore_server::grpc::map_message_handle_error_to_status(&error, None, None);
        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(
            status.message().contains("Instance"),
            "{}",
            status.message()
        );
        assert!(!lore_server::quic::storage_service::is_internal_error(
            &error
        ));
        assert_eq!(
            lore_server::quic::storage_service::message_handle_error_to_label(&error),
            "DomainKeyRefused"
        );
    }

    /// The handlers refuse first, before the store sees anything.
    #[tokio::test]
    async fn the_handlers_refuse_before_touching_the_store() {
        let f = fixture().await;
        Box::pin(LORE_CONTEXT.scope(f.execution.clone(), async {
            for key_type in REFUSED {
                let error = handle_mutable_store(
                    random::<Hash>(),
                    random::<Hash>(),
                    key_type,
                    f.repository,
                    String::new(),
                    String::new(),
                    f.recording.clone(),
                )
                .await
                .expect_err("store must be refused");
                assert!(
                    matches!(&error, MessageHandleError::DomainKeyRefused(k) if *k == key_type),
                    "{key_type:?}: {error:?}"
                );

                let error = handle_mutable_cas(
                    random::<Hash>(),
                    random::<Hash>(),
                    random::<Hash>(),
                    key_type,
                    f.repository,
                    String::new(),
                    String::new(),
                    f.recording.clone(),
                )
                .await
                .expect_err("swap must be refused");
                assert!(
                    matches!(&error, MessageHandleError::DomainKeyRefused(k) if *k == key_type),
                    "{key_type:?}: {error:?}"
                );
            }
            assert_eq!(f.writes.load(Ordering::SeqCst), 0);
        }))
        .await;
    }
}
