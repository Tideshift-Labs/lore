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

/// Permits, recording the action of every question the handler asked.
#[derive(Default)]
struct RecordingPermitAuthorizer {
    actions: std::sync::Mutex<Vec<Option<String>>>,
}

#[async_trait::async_trait]
impl RepositoryAuthorizer for RecordingPermitAuthorizer {
    async fn check_repository_access(
        &self,
        _token: Option<&lore_server::authnz::repository_authorizer::VerifiedToken<'_>>,
        _repository_id: RepositoryId,
        action: Option<&str>,
    ) -> Result<(), Status> {
        self.actions.lock().unwrap().push(action.map(str::to_owned));
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
            // Reachability first, then the admin action, on an authorizer
            // that cannot enumerate grants.
            assert_eq!(
                *authorizer.actions.lock().unwrap(),
                vec![None, Some("admin".to_owned())]
            );
        })
        .await;
}

// FORK-LOCAL (Tideshift): repository metadata is an admin act. A token that
// reaches the repository with any other grant is refused before the CAS.
mod admin_required {
    use std::sync::Arc;

    use lore_base::types::Hash;
    use lore_base::types::RepositoryId;
    use lore_proto::RepositoryMetadataSetRequest;
    use lore_revision::repository;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::RepositoryMetadata;
    use lore_server::auth::jwt::AuthorizationToken;
    use lore_server::auth::jwt::ResourcePermission;
    use lore_server::authnz::repository_authorizer::AuthClientAuthorizer;
    use lore_server::authnz::repository_authorizer::RawToken;
    use lore_server::authnz::resource_grants_authorizer::ResourceGrantsAuthorizer;
    use lore_server::grpc::handlers::repository_metadata_set::handler;
    use tonic::Code;
    use tonic::Request;
    use tonic::Status;

    use crate::grpc::handlers::repository_query::authz_test_support::new_test_stores;
    use crate::grpc::handlers::repository_query::authz_test_support::seed_repository_metadata;
    use crate::grpc::handlers::repository_query::authz_test_support::start_stub_auth_server_granting;

    fn claim_token(resource_id: String, permissions: &[&str]) -> AuthorizationToken {
        AuthorizationToken {
            resources: Some(vec![ResourcePermission {
                resource_id,
                permission: permissions.iter().map(|p| p.to_string()).collect(),
            }]),
            ..Default::default()
        }
    }

    /// One CAS carrying `token` (claim token) or an identity token answered
    /// online by a stub granting `online` (when `token` is `None`). Returns
    /// the result, the pointer afterwards, the original and the update.
    async fn set_metadata(
        seed: u8,
        token: Option<Box<dyn FnOnce(RepositoryId) -> AuthorizationToken>>,
        online: &[&str],
    ) -> (Result<bool, Status>, Hash, Hash, Hash) {
        let repository_id = RepositoryId::from([seed; 16]);
        let (immutable, mutable) = new_test_stores().await;
        let original = seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            "acme",
            "original",
        )
        .await;
        let updated = repository::metadata_store(
            Arc::new(RepositoryContext::new_server_context(
                immutable.clone(),
                mutable.clone(),
                repository_id,
            )),
            RepositoryMetadata {
                name: "acme".to_string(),
                description: "updated description".to_string(),
                default_branch: Default::default(),
                default_branch_name: "main".to_string(),
                creator: "alice".to_string(),
                created: 0,
            },
        )
        .await
        .expect("serialize updated metadata");

        let mut request = Request::new(RepositoryMetadataSetRequest {
            repository_id: repository_id.into(),
            expected_hash: original.into(),
            new_hash: updated.into(),
        });
        // A claim token is answered in place, so its URL is never dialled.
        let auth_url = if let Some(token) = token {
            request.extensions_mut().insert(token(repository_id));
            "http://127.0.0.1:1".to_string()
        } else {
            request
                .extensions_mut()
                .insert(AuthorizationToken::default());
            start_stub_auth_server_granting(repository_id, online).await
        };
        request
            .extensions_mut()
            .insert(RawToken("test-token".into()));

        let result = handler(
            request,
            Arc::new(AuthClientAuthorizer::new(auth_url)),
            immutable.clone(),
            mutable.clone(),
            None,
        )
        .await
        .map(|response| response.into_inner().success);

        let current = repository::metadata_hash(Arc::new(RepositoryContext::new_server_context(
            immutable,
            mutable,
            repository_id,
        )))
        .await
        .expect("metadata must still be readable");
        (result, current, original, updated)
    }

    fn scoped(
        permissions: &'static [&'static str],
    ) -> Option<Box<dyn FnOnce(RepositoryId) -> AuthorizationToken>> {
        Some(Box::new(move |id| {
            claim_token(format!("urc-{id}"), permissions)
        }))
    }

    #[tokio::test]
    async fn a_viewer_token_is_refused_and_does_not_cas() {
        let (result, current, original, _) = set_metadata(50, scoped(&["read"]), &[]).await;
        let err = result.expect_err("a read grant must not set repository metadata");
        assert_eq!(err.code(), Code::PermissionDenied);
        assert_eq!(
            current, original,
            "a refused request must not perform the CAS"
        );
    }

    #[tokio::test]
    async fn a_write_token_without_admin_is_refused_and_does_not_cas() {
        let (result, current, original, _) =
            set_metadata(51, scoped(&["read", "write"]), &[]).await;
        let err = result.expect_err("a write grant must not set repository metadata");
        assert_eq!(err.code(), Code::PermissionDenied);
        assert_eq!(
            current, original,
            "a refused request must not perform the CAS"
        );
    }

    #[tokio::test]
    async fn an_admin_token_sets_metadata() {
        let (result, current, _, updated) =
            set_metadata(52, scoped(&["read", "write", "admin"]), &[]).await;
        assert!(result.expect("an admin grant sets metadata"));
        assert_eq!(current, updated);
    }

    #[tokio::test]
    async fn a_service_account_with_wildcard_admin_sets_metadata() {
        let token = Box::new(|_| AuthorizationToken {
            is_service_account: Some(true),
            ..claim_token("urc-*".into(), &["admin"])
        });
        let (result, current, _, updated) = set_metadata(53, Some(token), &[]).await;
        assert!(result.expect("a wildcard admin service token sets metadata"));
        assert_eq!(current, updated);
    }

    #[tokio::test]
    async fn a_service_account_is_not_exempt_from_the_admin_requirement() {
        let token = Box::new(|_| AuthorizationToken {
            is_service_account: Some(true),
            ..claim_token("urc-*".into(), &["read", "write"])
        });
        let (result, current, original, _) = set_metadata(54, Some(token), &[]).await;
        let err = result.expect_err("no service-account bypass exists for this RPC");
        assert_eq!(err.code(), Code::PermissionDenied);
        assert_eq!(current, original);
    }

    #[tokio::test]
    async fn an_identity_token_without_online_admin_is_refused_and_does_not_cas() {
        let (result, current, original, _) = set_metadata(55, None, &["read", "write"]).await;
        let err = result.expect_err("an online read + write answer must not set metadata");
        assert_eq!(err.code(), Code::PermissionDenied);
        assert_eq!(
            current, original,
            "a refused request must not perform the CAS"
        );
    }

    #[tokio::test]
    async fn an_identity_token_with_online_admin_sets_metadata() {
        let (result, current, _, updated) =
            set_metadata(56, None, &["read", "write", "admin"]).await;
        assert!(result.expect("an online admin answer sets metadata"));
        assert_eq!(current, updated);
    }

    /// One CAS under the `ResourceGrantsAuthorizer` tier, the one Lorehub
    /// cells run, with a token granting `permissions` on the repository.
    async fn set_metadata_resource_grants(
        seed: u8,
        permissions: &[&str],
    ) -> (Result<bool, Status>, Hash, Hash, Hash) {
        let repository_id = RepositoryId::from([seed; 16]);
        let (immutable, mutable) = new_test_stores().await;
        let original = seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            "acme",
            "original",
        )
        .await;
        let updated = repository::metadata_store(
            Arc::new(RepositoryContext::new_server_context(
                immutable.clone(),
                mutable.clone(),
                repository_id,
            )),
            RepositoryMetadata {
                name: "acme".to_string(),
                description: "updated description".to_string(),
                default_branch: Default::default(),
                default_branch_name: "main".to_string(),
                creator: "alice".to_string(),
                created: 0,
            },
        )
        .await
        .expect("serialize updated metadata");

        let mut request = Request::new(RepositoryMetadataSetRequest {
            repository_id: repository_id.into(),
            expected_hash: original.into(),
            new_hash: updated.into(),
        });
        request
            .extensions_mut()
            .insert(claim_token(format!("urc-{repository_id}"), permissions));
        request
            .extensions_mut()
            .insert(RawToken("test-token".into()));

        let authorizer = ResourceGrantsAuthorizer::new(
            "resources".to_string(),
            "resource_id".to_string(),
            None,
            "urc-{id}".to_string(),
            "urc-*".to_string(),
        );
        let result = handler(
            request,
            Arc::new(authorizer),
            immutable.clone(),
            mutable.clone(),
            None,
        )
        .await
        .map(|response| response.into_inner().success);

        let current = repository::metadata_hash(Arc::new(RepositoryContext::new_server_context(
            immutable,
            mutable,
            repository_id,
        )))
        .await
        .expect("metadata must still be readable");
        (result, current, original, updated)
    }

    #[tokio::test]
    async fn resource_grants_tier_refuses_viewer_and_write_only_without_a_cas() {
        for (seed, permissions) in [(60u8, &["read"][..]), (61, &["read", "write"][..])] {
            let (result, current, original, _) =
                set_metadata_resource_grants(seed, permissions).await;
            let err = result.expect_err("a non-admin grant must not set repository metadata");
            assert_eq!(err.code(), Code::PermissionDenied, "{permissions:?}");
            assert_eq!(
                current, original,
                "a refused request must not perform the CAS ({permissions:?})"
            );
        }
    }

    #[tokio::test]
    async fn resource_grants_tier_admin_sets_metadata() {
        let (result, current, _, updated) =
            set_metadata_resource_grants(62, &["read", "write", "admin"]).await;
        assert!(result.expect("an admin grant sets metadata"));
        assert_eq!(current, updated);
    }
}
