// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::KeyType;
use lore_base::types::RepositoryId;
use lore_proto::RepositoryMetadataSetRequest;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::domain::test_support::context as build_domain_context;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_KEY;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_V1_LEN;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
use lore_server::grpc::domain_operation_metadata::OPERATION_ID_KEY;
use lore_server::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
use lore_server::grpc::domain_operation_metadata::PREPARE_TOKEN_LEN;
use lore_server::grpc::handlers::repository_metadata_set::*;
use tonic::Code;
use tonic::Request;
use tonic::Status;
use tonic::metadata::BinaryMetadataValue;
use uuid::Uuid;

use crate::store::test_support::test_store_create;

const REPOSITORY_ID: [u8; 16] = [1u8; 16];

/// Panics on every method. Used as the mutable store for the
/// admission-short-circuit test below: any call at all is proof the gate
/// did not run before the handler body, so the panic message names the
/// property under test rather than a generic "not implemented".
struct PanicOnAnyCallMutableStore;

#[async_trait::async_trait]
impl lore_storage::MutableStore for PanicOnAnyCallMutableStore {
    async fn load(
        self: Arc<Self>,
        _partition: lore_storage::Partition,
        _key: lore_base::types::Hash,
        _key_type: KeyType,
    ) -> Result<lore_base::types::Hash, lore_storage::StoreError> {
        panic!("admission must short-circuit before any mutable-store access")
    }

    async fn store(
        self: Arc<Self>,
        _partition: lore_storage::Partition,
        _key: lore_base::types::Hash,
        _value: lore_base::types::Hash,
        _key_type: KeyType,
    ) -> Result<(), lore_storage::StoreError> {
        panic!("admission must short-circuit before any mutable-store access")
    }

    async fn compare_and_swap(
        self: Arc<Self>,
        _partition: lore_storage::Partition,
        _key: lore_base::types::Hash,
        _expected: lore_base::types::Hash,
        _value: lore_base::types::Hash,
        _key_type: KeyType,
    ) -> Result<lore_base::types::Hash, lore_storage::StoreError> {
        panic!("admission must short-circuit before any mutable-store access")
    }

    async fn list(
        self: Arc<Self>,
        _partition: lore_storage::Partition,
        _key_type: KeyType,
    ) -> Result<lore_storage::KeyValueStream, lore_storage::StoreError> {
        panic!("admission must short-circuit before any mutable-store access")
    }

    async fn flush(self: Arc<Self>, _sync_data: bool) -> Result<(), lore_storage::StoreError> {
        panic!("admission must short-circuit before any mutable-store access")
    }
}

// WP-116 Part 2 wired this site, so valid carriage is no longer refused.
// The test is kept and inverted rather than deleted, because the property
// it really guards outlived the refusal: a governed request must never
// reach the **ungoverned** mutable store. That store now writes through the
// domain coordinator's projection inside one transaction, and a stray
// direct call would be a second, unfenced writer to the same row.
//
// `PanicOnAnyCallMutableStore` is what enforces it: any call panics. The
// request stops earlier still, in metadata-blob validation, which is why
// the code is `InvalidArgument` — the zero expected hash and the all-ones
// proposed hash name no real blob. `Unimplemented` here would mean the site
// had regressed back behind its guard.
#[tokio::test]
async fn valid_carriage_with_a_coordinator_present_is_admitted_and_never_touches_the_ungoverned_store()
 {
    let (immutable, _, _) = test_store_create().await.unwrap();
    let domain_context = Arc::new(build_domain_context(false));

    let mut request = Request::new(RepositoryMetadataSetRequest {
        repository_id: REPOSITORY_ID.to_vec().into(),
        expected_hash: vec![0u8; 32].into(),
        new_hash: vec![1u8; 32].into(),
    });
    insert_valid_domain_operation_headers(&mut request);
    request
        .extensions_mut()
        .insert(AuthorizationToken::default());

    let err = handler(
        request,
        Arc::new(AllowAllRepositoryAuthorizer),
        immutable,
        Arc::new(PanicOnAnyCallMutableStore),
        Some(&domain_context),
    )
    .await
    .unwrap_err();

    assert_ne!(
        err.code(),
        Code::Unimplemented,
        "this site is wired; a refusal would mean it regressed behind its guard"
    );
    assert_eq!(err.code(), Code::InvalidArgument);
}

/// Attach a well-formed set of the three CR-029 domain-operation headers,
/// so `admit_at_entry` sees carriage rather than the legacy absence
/// carve-out. Exact header contents don't matter here: this handler-level
/// pin only needs the no-coordinator path (`admit_at_entry(None, ..)`),
/// which decides before ever inspecting the token or scope.
fn insert_valid_domain_operation_headers<T>(request: &mut Request<T>) {
    let metadata = request.metadata_mut();
    metadata.insert_bin(
        OPERATION_ID_KEY,
        BinaryMetadataValue::from_bytes(Uuid::now_v7().as_bytes()),
    );
    let mut fingerprint = vec![FINGERPRINT_VERSION_V1];
    fingerprint.extend(std::iter::repeat_n(0xAB, FINGERPRINT_V1_LEN));
    metadata.insert_bin(
        FINGERPRINT_KEY,
        BinaryMetadataValue::from_bytes(&fingerprint),
    );
    metadata.insert_bin(
        PREPARE_TOKEN_KEY,
        BinaryMetadataValue::from_bytes(&[0xCDu8; PREPARE_TOKEN_LEN]),
    );
}

/// FORK-LOCAL (Tideshift, CR-029): panics if asked anything. Proof that
/// the admission gate decides before any authorization side effect.
struct PanicOnAnyCallAuthorizer;

#[async_trait::async_trait]
impl RepositoryAuthorizer for PanicOnAnyCallAuthorizer {
    async fn check_repository_access(
        &self,
        _token: Option<&lore_server::authnz::repository_authorizer::VerifiedToken<'_>>,
        _repository_id: RepositoryId,
        _action: Option<&str>,
    ) -> Result<(), Status> {
        panic!("admission must decide before any authorization side effect")
    }
}

/// Denies every request.
struct DenyAllRepositoryAuthorizer;

#[async_trait::async_trait]
impl RepositoryAuthorizer for DenyAllRepositoryAuthorizer {
    async fn check_repository_access(
        &self,
        token: Option<&lore_server::authnz::repository_authorizer::VerifiedToken<'_>>,
        repository_id: RepositoryId,
        _action: Option<&str>,
    ) -> Result<(), Status> {
        // FORK-LOCAL (Tideshift, CR-011): the check is asked about the
        // BODY repository id, with no token on this tokenless request.
        assert!(token.is_none());
        assert_eq!(repository_id, RepositoryId::from(REPOSITORY_ID));
        Err(Status::permission_denied("denied"))
    }
}

/// Permits, recording that the handler asked with `action: None`.
#[derive(Default)]
struct RecordingPermitAuthorizer {
    called_with_action_none: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl RepositoryAuthorizer for RecordingPermitAuthorizer {
    async fn check_repository_access(
        &self,
        _token: Option<&lore_server::authnz::repository_authorizer::VerifiedToken<'_>>,
        _repository_id: RepositoryId,
        action: Option<&str>,
    ) -> Result<(), Status> {
        self.called_with_action_none
            .store(action.is_none(), std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

async fn seed_metadata_blob(
    immutable: Arc<dyn lore_storage::ImmutableStore>,
    mutable: Arc<dyn lore_storage::MutableStore>,
) -> lore_base::types::Hash {
    let repo_ctx = Arc::new(RepositoryContext::new_server_context(
        immutable,
        mutable,
        Context::from(REPOSITORY_ID).into(),
    ));
    lore_revision::repository::metadata_store(
        repo_ctx,
        RepositoryMetadata {
            name: "test".to_string(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

// CR-029 R-BLOCK-2: a caller that supplies domain-operation carriage
// against a cell with no coordinator must be refused, never silently
// ignored. `PanicOnAnyCallAuthorizer` is the proof of "refused" over
// "ignored": the gate must decide before any authorization side effect.
#[tokio::test]
async fn carriage_with_no_domain_context_is_refused_before_any_authorization_side_effect() {
    let (immutable, mutable, _) = test_store_create().await.unwrap();
    let mut request = Request::new(RepositoryMetadataSetRequest {
        repository_id: REPOSITORY_ID.to_vec().into(),
        expected_hash: vec![0u8; 32].into(),
        new_hash: vec![1u8; 32].into(),
    });
    insert_valid_domain_operation_headers(&mut request);

    let err = handler(
        request,
        Arc::new(PanicOnAnyCallAuthorizer),
        immutable,
        mutable,
        None,
    )
    .await
    .unwrap_err();

    assert_eq!(err.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn no_auth_configured_allows_operation() {
    let (immutable, mutable, execution) = test_store_create().await.unwrap();
    LORE_CONTEXT
        .scope(execution, async move {
            let hash = seed_metadata_blob(immutable.clone(), mutable.clone()).await;
            let request = Request::new(RepositoryMetadataSetRequest {
                repository_id: REPOSITORY_ID.to_vec().into(),
                expected_hash: vec![0u8; 32].into(),
                new_hash: hash.into(),
            });
            handler(
                request,
                Arc::new(AllowAllRepositoryAuthorizer),
                immutable,
                mutable,
                None,
            )
            .await
            .unwrap();
        })
        .await;
}

#[tokio::test]
async fn auth_configured_no_access_returns_permission_denied() {
    let (immutable, mutable, _) = test_store_create().await.unwrap();
    let request = Request::new(RepositoryMetadataSetRequest {
        repository_id: REPOSITORY_ID.to_vec().into(),
        expected_hash: vec![0u8; 32].into(),
        new_hash: vec![1u8; 32].into(),
    });
    let err = handler(
        request,
        Arc::new(DenyAllRepositoryAuthorizer),
        immutable,
        mutable,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), "Unauthorized");
}

#[tokio::test]
async fn auth_configured_with_access_allows_operation() {
    let (immutable, mutable, execution) = test_store_create().await.unwrap();
    LORE_CONTEXT
        .scope(execution, async move {
            let hash = seed_metadata_blob(immutable.clone(), mutable.clone()).await;
            let authorizer = Arc::new(RecordingPermitAuthorizer::default());
            let request = Request::new(RepositoryMetadataSetRequest {
                repository_id: REPOSITORY_ID.to_vec().into(),
                expected_hash: vec![0u8; 32].into(),
                new_hash: hash.into(),
            });
            handler(request, authorizer.clone(), immutable, mutable, None)
                .await
                .unwrap();
            assert!(
                authorizer
                    .called_with_action_none
                    .load(std::sync::atomic::Ordering::SeqCst)
            );
        })
        .await;
}
