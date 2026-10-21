// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT

use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::KeyType;
use lore_proto::lore::repository::v1::RepositoryMetadataSetRequest;
use lore_revision::metadata::Metadata;
use lore_revision::repository::RepositoryContext;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use tonic::Request;
use tonic::Status;
mod auth_guard {
    use lore_base::types::RepositoryId;
    use lore_revision::repository::RepositoryMetadata;
    use lore_server::auth::jwt::AuthorizationToken;
    use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
    use lore_server::domain::test_support::context as build_domain_context;
    use lore_server::grpc::domain_operation_metadata::FINGERPRINT_KEY;
    use lore_server::grpc::domain_operation_metadata::FINGERPRINT_V1_LEN;
    use lore_server::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
    use lore_server::grpc::domain_operation_metadata::OPERATION_ID_KEY;
    use lore_server::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
    use lore_server::grpc::domain_operation_metadata::PREPARE_TOKEN_LEN;
    use lore_server::grpc::repository::v1::repository_metadata_set::*;
    use tonic::Code;
    use tonic::metadata::BinaryMetadataValue;
    use uuid::Uuid;

    use super::*;
    use crate::store::test_support::test_store_create;

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
            // FORK-LOCAL (Tideshift, CR-011): asked about the BODY id,
            // with no token on this tokenless request.
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

    const REPOSITORY_ID: [u8; 16] = [1u8; 16];

    /// Attach a well-formed set of the three CR-029 domain-operation
    /// headers, so `admit_at_entry` sees carriage rather than the legacy
    /// absence carve-out. Exact header contents don't matter here: this
    /// handler-level pin only needs the no-coordinator path
    /// (`admit_at_entry(None, ..)`), which decides before ever inspecting
    /// the token or scope.
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

    /// Panics on every method. Used as the mutable store for the
    /// admission-short-circuit test below: any call at all is proof the
    /// gate did not run before the handler body, so the panic message
    /// names the property under test rather than a generic "not
    /// implemented".
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

    // WP-116 Part 2 wired this site, so valid carriage is no longer
    // refused. The test is kept and inverted rather than deleted, because
    // the property it really guards outlived the refusal: a governed
    // request must never reach the **ungoverned** mutable store. That
    // store now writes through the domain coordinator's projection inside
    // one transaction, and a stray direct call would be a second,
    // unfenced writer to the same row.
    //
    // `PanicOnAnyCallMutableStore` is what enforces it: any call panics.
    // The request stops earlier still, in metadata-blob validation, which
    // is why the code is `InvalidArgument` — the zero expected hash and
    // the all-ones proposed hash name no real blob. `Unimplemented` here
    // would mean the site had regressed back behind its guard.
    #[tokio::test]
    async fn valid_carriage_with_a_coordinator_present_is_admitted_and_never_touches_the_ungoverned_store()
     {
        let (immutable, _, _) = test_store_create().await.unwrap();
        let domain_context = Arc::new(build_domain_context(false));

        let mut request = Request::new(RepositoryMetadataSetRequest {
            id: REPOSITORY_ID.to_vec().into(),
            expected: vec![0u8; 32].into(),
            updated: vec![1u8; 32].into(),
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

    /// Writes a valid metadata blob to the immutable store and returns its
    /// hash. `metadata_set` can then use that hash as `updated`.
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
    // ignored. `PanicOnAnyCallAuthorizer` is the proof of "refused"
    // over "ignored": the gate must decide before any authorization side
    // effect.
    #[tokio::test]
    async fn carriage_with_no_domain_context_is_refused_before_any_authorization_side_effect() {
        let (immutable, mutable, _) = test_store_create().await.unwrap();
        let mut request = Request::new(RepositoryMetadataSetRequest {
            id: REPOSITORY_ID.to_vec().into(),
            expected: vec![0u8; 32].into(),
            updated: vec![1u8; 32].into(),
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
                    id: REPOSITORY_ID.to_vec().into(),
                    expected: vec![0u8; 32].into(),
                    updated: hash.into(),
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
            id: REPOSITORY_ID.to_vec().into(),
            expected: vec![0u8; 32].into(),
            updated: vec![1u8; 32].into(),
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
                    id: REPOSITORY_ID.to_vec().into(),
                    expected: vec![0u8; 32].into(),
                    updated: hash.into(),
                });
                handler(request, authorizer.clone(), immutable, mutable, None)
                    .await
                    .unwrap();
                // Reachability first, then the admin action, on an
                // authorizer that cannot enumerate grants.
                assert_eq!(
                    *authorizer.actions.lock().unwrap(),
                    vec![None, Some("admin".to_owned())]
                );
            })
            .await;
    }
}

mod validate_read_only_fields {
    use lore_base::types::Context;
    use lore_revision::repository;
    use lore_server::grpc::repository::v1::repository_metadata_set::validate_read_only_fields;

    use super::*;

    /// Build a metadata blob with every read-only key populated to a
    /// known value so individual tests can mutate exactly one field
    /// and assert the rejection is attributable to that mutation.
    fn baseline() -> Metadata {
        let mut metadata = Metadata::new();
        metadata.set_string(repository::NAME, "repo").unwrap();
        metadata
            .set_context(repository::DEFAULT_BRANCH, Context::default())
            .unwrap();
        metadata
            .set_string(repository::DEFAULT_BRANCH_NAME, "main")
            .unwrap();
        metadata.set_string(repository::CREATOR, "alice").unwrap();
        metadata.set_u64(repository::CREATED, 100).unwrap();
        metadata
    }

    #[test]
    fn accepts_unchanged_read_only_fields_with_writable_change() {
        let current = baseline();
        let mut proposed = baseline();
        proposed
            .set_string(repository::DESCRIPTION, "edited description")
            .unwrap();
        validate_read_only_fields(&current, &proposed)
            .expect("description is writable, all read-only fields unchanged");
    }

    #[test]
    fn rejects_name_modification() {
        let current = baseline();
        let mut proposed = baseline();
        proposed.set_string(repository::NAME, "renamed").unwrap();
        let err = validate_read_only_fields(&current, &proposed)
            .expect_err("mutating name must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains(repository::NAME));
    }

    #[test]
    fn rejects_creator_modification() {
        let current = baseline();
        let mut proposed = baseline();
        proposed.set_string(repository::CREATOR, "mallory").unwrap();
        let err = validate_read_only_fields(&current, &proposed)
            .expect_err("mutating creator must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains(repository::CREATOR));
    }

    #[test]
    fn rejects_default_branch_modification() {
        let current = baseline();
        let mut proposed = baseline();
        proposed
            .set_context(repository::DEFAULT_BRANCH, Context::from([1u8; 16]))
            .unwrap();
        let err = validate_read_only_fields(&current, &proposed)
            .expect_err("mutating default-branch must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains(repository::DEFAULT_BRANCH));
    }

    #[test]
    fn rejects_default_branch_name_modification() {
        let current = baseline();
        let mut proposed = baseline();
        proposed
            .set_string(repository::DEFAULT_BRANCH_NAME, "trunk")
            .unwrap();
        let err = validate_read_only_fields(&current, &proposed)
            .expect_err("mutating default-branch-name must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains(repository::DEFAULT_BRANCH_NAME));
    }

    #[test]
    fn rejects_created_modification() {
        let current = baseline();
        let mut proposed = baseline();
        proposed.set_u64(repository::CREATED, 200).unwrap();
        let err = validate_read_only_fields(&current, &proposed)
            .expect_err("mutating created must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains(repository::CREATED));
    }

    #[test]
    fn rejects_read_only_key_removal() {
        let current = baseline();
        let mut proposed = baseline();
        assert!(proposed.remove_key(repository::CREATOR));
        let err = validate_read_only_fields(&current, &proposed)
            .expect_err("removing a read-only key must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains(repository::CREATOR));
        assert!(err.message().contains("remove"));
    }

    #[test]
    fn accepts_setting_read_only_keys_when_current_is_empty() {
        // CAS-from-zero path: `expected` was Hash::default(), so the
        // server passes an empty `current` Metadata. Every key in
        // proposed is being set for the first time and must be
        // allowed.
        let current = Metadata::new();
        let proposed = baseline();
        validate_read_only_fields(&current, &proposed)
            .expect("first-time write of read-only keys must be allowed");
    }

    #[test]
    fn ignores_read_only_keys_absent_from_both() {
        // No read-only key is present in either blob; the validator
        // must not invent rejections.
        let current = Metadata::new();
        let proposed = Metadata::new();
        validate_read_only_fields(&current, &proposed).expect("absence on both sides is a no-op");
    }

    #[test]
    fn type_mismatch_on_read_only_key_is_rejected() {
        // Same key, same logical value, different MetadataType: the
        // validator compares (bytes, type) and must catch this.
        let mut current = Metadata::new();
        current.set_string(repository::CREATED, "100").unwrap();
        let mut proposed = Metadata::new();
        proposed.set_u64(repository::CREATED, 100).unwrap();
        let err = validate_read_only_fields(&current, &proposed)
            .expect_err("type change on a read-only key must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains(repository::CREATED));
    }
}

mod authorization {
    use std::sync::Arc;

    use lore_base::types::Hash;
    use lore_proto::lore::repository::v1::RepositoryMetadataSetRequest;
    use lore_revision::lore::RepositoryId;
    use lore_revision::repository;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::RepositoryMetadata;
    use lore_server::auth::jwt::AuthorizationToken;
    use lore_server::auth::jwt::ResourcePermission;
    use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
    use lore_server::authnz::repository_authorizer::AuthClientAuthorizer;
    use lore_server::authnz::repository_authorizer::RawToken;
    use lore_server::grpc::repository::v1::repository_metadata_set::handler;
    use tonic::Request;

    use crate::grpc::handlers::repository_query::authz_test_support::new_test_stores;
    use crate::grpc::handlers::repository_query::authz_test_support::seed_repository_metadata;
    use crate::grpc::handlers::repository_query::authz_test_support::start_stub_auth_server;
    use crate::grpc::handlers::repository_query::authz_test_support::start_stub_auth_server_granting;

    fn request_for(
        repository_id: RepositoryId,
        expected: Hash,
        updated: Hash,
    ) -> Request<RepositoryMetadataSetRequest> {
        let mut request = Request::new(RepositoryMetadataSetRequest {
            id: repository_id.into(),
            expected: expected.into(),
            updated: updated.into(),
        });
        request
            .metadata_mut()
            .insert("authorization", "Bearer test-token".parse().unwrap());
        // The verified halves the interceptor would insert: an identity
        // token (no `resources` claim), so the online check is asked.
        request
            .extensions_mut()
            .insert(AuthorizationToken::default());
        request
            .extensions_mut()
            .insert(RawToken("test-token".into()));
        request
    }

    /// Serializes an updated metadata blob for `repository_id` that
    /// keeps every read-only field identical to what
    /// `seed_repository_metadata` wrote (only `description` changes),
    /// so a CAS against it is well-formed and would land if the
    /// handler ever reached the CAS.
    async fn build_valid_update(
        immutable: Arc<dyn lore_storage::ImmutableStore>,
        mutable: Arc<dyn lore_storage::MutableStore>,
        repository_id: RepositoryId,
    ) -> Hash {
        let repository = Arc::new(RepositoryContext::new_server_context(
            immutable,
            mutable,
            repository_id,
        ));
        repository::metadata_store(
            repository,
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
        .expect("serialize updated metadata")
    }

    #[tokio::test]
    async fn denies_metadata_set_for_a_repository_the_caller_is_not_authorized_for_and_does_not_cas()
     {
        let caller_authorized_repo = RepositoryId::from([31u8; 16]);
        let target_repo = RepositoryId::from([32u8; 16]);
        let (immutable, mutable) = new_test_stores().await;
        let original_hash = seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            target_repo,
            "victim",
            "original",
        )
        .await;
        // Well-formed update that WOULD succeed if the CAS were reached.
        let updated = build_valid_update(immutable.clone(), mutable.clone(), target_repo).await;
        let auth_url = start_stub_auth_server(caller_authorized_repo).await;

        let result = handler(
            request_for(target_repo, original_hash, updated),
            Arc::new(AuthClientAuthorizer::new(auth_url)),
            immutable.clone(),
            mutable.clone(),
            None,
        )
        .await;

        let err = result.expect_err("caller is not authorized for the target repository");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        // Prove the CAS never ran: the published pointer is still the
        // original, despite the update above being one that would have
        // landed had the handler reached the store.
        let repository = Arc::new(RepositoryContext::new_server_context(
            immutable,
            mutable,
            target_repo,
        ));
        let current = repository::metadata_hash(repository)
            .await
            .expect("metadata must still be readable");
        assert_eq!(
            current, original_hash,
            "a denied request must not perform the CAS"
        );
    }

    #[tokio::test]
    async fn accepts_metadata_set_for_the_callers_own_repository() {
        let repository_id = RepositoryId::from([33u8; 16]);
        let (immutable, mutable) = new_test_stores().await;
        let expected = seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            "acme",
            "original",
        )
        .await;
        let updated = build_valid_update(immutable.clone(), mutable.clone(), repository_id).await;
        let auth_url =
            start_stub_auth_server_granting(repository_id, &["read", "write", "admin"]).await;

        let response = handler(
            request_for(repository_id, expected, updated),
            Arc::new(AuthClientAuthorizer::new(auth_url)),
            immutable,
            mutable,
            None,
        )
        .await
        .expect("a legitimate client CAS-writing its own repository must be unaffected");

        // v1 signals CAS hit/miss in-band: success means
        // response.metadata == request.updated.
        assert_eq!(Hash::from(response.into_inner().metadata), updated);
    }

    #[tokio::test]
    async fn auth_off_allows_cas_without_an_authorization_check() {
        let repository_id = RepositoryId::from([34u8; 16]);
        let (immutable, mutable) = new_test_stores().await;
        let expected = seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            "acme",
            "original",
        )
        .await;
        let updated = build_valid_update(immutable.clone(), mutable.clone(), repository_id).await;

        let response = handler(
            request_for(repository_id, expected, updated),
            Arc::new(AllowAllRepositoryAuthorizer),
            immutable,
            mutable,
            None,
        )
        .await
        .expect("auth-off must leave behavior unchanged");

        assert_eq!(Hash::from(response.into_inner().metadata), updated);
    }

    // FORK-LOCAL (Tideshift): repository metadata is an admin act. A token
    // that reaches the repository with any other grant is refused before
    // the CAS.

    /// A request carrying an exchanged access token whose `resources` claim
    /// holds `token`'s grants, as the Lorehub mint issues it.
    fn request_with_token(
        repository_id: RepositoryId,
        expected: Hash,
        updated: Hash,
        token: AuthorizationToken,
    ) -> Request<RepositoryMetadataSetRequest> {
        let mut request = Request::new(RepositoryMetadataSetRequest {
            id: repository_id.into(),
            expected: expected.into(),
            updated: updated.into(),
        });
        request.extensions_mut().insert(token);
        request
            .extensions_mut()
            .insert(RawToken("test-token".into()));
        request
    }

    fn claim_token(resource_id: String, permissions: &[&str]) -> AuthorizationToken {
        AuthorizationToken {
            resources: Some(vec![ResourcePermission {
                resource_id,
                permission: permissions.iter().map(|p| p.to_string()).collect(),
            }]),
            ..Default::default()
        }
    }

    /// Runs one CAS with `token` against a seeded repository under the
    /// claim-answering `AuthClient` authorizer, and returns the result plus
    /// the pointer afterwards and the update it tried to publish.
    async fn set_with_claim_token(
        seed: u8,
        token: impl FnOnce(RepositoryId) -> AuthorizationToken,
    ) -> (Result<Hash, tonic::Status>, Hash, Hash, Hash) {
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
        let updated = build_valid_update(immutable.clone(), mutable.clone(), repository_id).await;
        // A claim token is answered in place, so this URL is never dialled.
        let authorizer = Arc::new(AuthClientAuthorizer::new("http://127.0.0.1:1".into()));

        let result = handler(
            request_with_token(repository_id, original, updated, token(repository_id)),
            authorizer,
            immutable.clone(),
            mutable.clone(),
            None,
        )
        .await
        .map(|response| Hash::from(response.into_inner().metadata));

        let repository = Arc::new(RepositoryContext::new_server_context(
            immutable,
            mutable,
            repository_id,
        ));
        let current = repository::metadata_hash(repository)
            .await
            .expect("metadata must still be readable");
        (result, current, original, updated)
    }

    #[tokio::test]
    async fn a_viewer_token_is_refused_and_does_not_cas() {
        let (result, current, original, _) =
            set_with_claim_token(40, |id| claim_token(format!("urc-{id}"), &["read"])).await;
        let err = result.expect_err("a read grant must not set repository metadata");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            current, original,
            "a refused request must not perform the CAS"
        );
    }

    #[tokio::test]
    async fn a_write_token_without_admin_is_refused_and_does_not_cas() {
        let (result, current, original, _) = set_with_claim_token(41, |id| {
            claim_token(format!("urc-{id}"), &["read", "write"])
        })
        .await;
        let err = result.expect_err("a write grant must not set repository metadata");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            current, original,
            "a refused request must not perform the CAS"
        );
    }

    #[tokio::test]
    async fn an_admin_token_sets_metadata() {
        let (result, current, _, updated) = set_with_claim_token(42, |id| {
            claim_token(format!("urc-{id}"), &["read", "write", "admin"])
        })
        .await;
        assert_eq!(result.expect("an admin grant sets metadata"), updated);
        assert_eq!(current, updated);
    }

    #[tokio::test]
    async fn a_service_account_with_wildcard_admin_sets_metadata() {
        let (result, current, _, updated) = set_with_claim_token(43, |_| AuthorizationToken {
            is_service_account: Some(true),
            ..claim_token("urc-*".into(), &["admin"])
        })
        .await;
        assert_eq!(
            result.expect("a wildcard admin service token sets metadata"),
            updated
        );
        assert_eq!(current, updated);
    }

    #[tokio::test]
    async fn a_service_account_is_not_exempt_from_the_admin_requirement() {
        let (result, current, original, _) = set_with_claim_token(44, |_| AuthorizationToken {
            is_service_account: Some(true),
            ..claim_token("urc-*".into(), &["read", "write"])
        })
        .await;
        let err = result.expect_err("no service-account bypass exists for this RPC");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(current, original);
    }

    /// An identity token (no `resources` claim) is checked online. The auth
    /// service answering `read` + `write` reaches the repository but does not
    /// grant `admin`.
    #[tokio::test]
    async fn an_identity_token_without_online_admin_is_refused_and_does_not_cas() {
        let repository_id = RepositoryId::from([45u8; 16]);
        let (immutable, mutable) = new_test_stores().await;
        let original = seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            "acme",
            "original",
        )
        .await;
        let updated = build_valid_update(immutable.clone(), mutable.clone(), repository_id).await;
        let auth_url = start_stub_auth_server(repository_id).await;

        let err = handler(
            request_for(repository_id, original, updated),
            Arc::new(AuthClientAuthorizer::new(auth_url)),
            immutable.clone(),
            mutable.clone(),
            None,
        )
        .await
        .expect_err("an online read + write answer must not set repository metadata");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let repository = Arc::new(RepositoryContext::new_server_context(
            immutable,
            mutable,
            repository_id,
        ));
        let current = repository::metadata_hash(repository)
            .await
            .expect("metadata must still be readable");
        assert_eq!(
            current, original,
            "a refused request must not perform the CAS"
        );
    }
}
