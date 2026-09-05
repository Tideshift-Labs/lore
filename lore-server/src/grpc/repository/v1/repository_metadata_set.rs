// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_postgres::domain::coordinator::ProjectionWrite;
use lore_postgres::domain::outbox::builders as outbox_builders;
use lore_proto::lore::repository::v1::RepositoryMetadataSetRequest;
use lore_proto::lore::repository::v1::RepositoryMetadataSetResponse;
use lore_revision::metadata::Metadata;
use lore_revision::metadata::MetadataType;
use lore_revision::metadata::repository::READ_ONLY_KEYS;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_storage::hash;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::domain::DomainContext;
use crate::domain::GovernedMetadataCas;
use crate::domain::GovernedScope;
use crate::domain::MetadataCasFamily;
use crate::domain::MetadataCasOutcome;
use crate::domain::admit_at_entry;
use crate::domain_intent::CanonicalIntent;
use crate::domain_intent::canonical_intent_digest;
use crate::grpc::extract_authorization_header;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_authorization_optional;
use crate::grpc::get_user_id;
use crate::grpc::get_write_token;
use crate::grpc::no_repository_access_status;
use crate::grpc::warn_error_to_status;
use crate::util::setup_execution;

/// `lore.repository.v1.RepositoryService.RepositoryMetadataSet` handler.
///
/// Compare-and-swap update of the repository metadata pointer.
/// Validates that the proposed metadata blob (a) preserves all read-only
/// fields and (b) references only existing immutable blobs for any
/// Address-typed entries, then performs a CAS on the mutable store.
///
/// CAS hit / miss is signalled in-band by comparing
/// `response.metadata` to `request.updated`; the gRPC status is always
/// `Ok` unless an internal failure prevents the CAS from being attempted
/// at all.
#[tracing::instrument(name = "RepositoryMetadataSet::v1::handle", skip_all)]
pub async fn handler(
    request: Request<RepositoryMetadataSetRequest>,
    authorizer: Arc<dyn RepositoryAuthorizer>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<RepositoryMetadataSetResponse>, Status> {
    // Captured before `into_inner` consumes the request: the domain-operation
    // headers and the verified principal both live outside the message body.
    let request_metadata = request.metadata().clone();
    let request_authorization = get_authorization_optional(request.extensions());
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let authorization = extract_authorization_header(&request);
    let req = request.into_inner();

    // CR-029 R-BLOCK-2: the one shared reader of the domain-operation headers,
    // at handler entry, before any handler logic or authorization side effect.
    let admitted = admit_at_entry(
        domain_context,
        &request_metadata,
        request_authorization.as_ref(),
        GovernedScope::TargetRepository {
            repository_id: &req.id,
        },
    )?;

    let repository_id: Context = req.id.into();
    if repository_id == Context::default() {
        return Err(Status::invalid_argument("Missing repository id"));
    }

    // Same family and same digest as v0: CR-029 freezes one canonical intent
    // per semantic operation, not one per wire shape, so v0 and v1 of the same
    // CAS must produce identical 32 bytes for identical values.
    //
    // After the empty/default check, per INTENT-02-LORE; see the v0 handler.
    let governed = match admitted {
        Some(admitted) => {
            let digest = canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
                repository_id: repository_id.data(),
                expected_hash: &req.expected,
                new_hash: &req.updated,
            })
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
            GovernedMetadataCas::prepare(
                domain_context,
                Some(admitted),
                MetadataCasFamily::Repository,
                digest,
            )
            .await?
        }
        None => None,
    };

    let expected: Hash = req.expected.into();
    let updated: Hash = req.updated.into();

    let execution = setup_execution(module_path!(), correlation_id, user_id);
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository_id.into(),
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            authorizer
                .check_repository_access(authorization, repository_id.into())
                .await
                .map_err(|_err| no_repository_access_status())?;

            let current_metadata = if !expected.is_zero() {
                Metadata::deserialize(repository.clone(), expected)
                    .await
                    .map_err(|err| {
                        warn_error_to_status(&err, |err| {
                            Status::invalid_argument(format!(
                                "failed to deserialize current metadata: {err}"
                            ))
                        })
                    })?
            } else {
                Metadata::new()
            };

            let proposed_metadata = Metadata::deserialize(repository.clone(), updated)
                .await
                .map_err(|err| {
                    warn_error_to_status(&err, |err| {
                        Status::invalid_argument(format!(
                            "failed to deserialize proposed metadata: {err}"
                        ))
                    })
                })?;

            validate_read_only_fields(&current_metadata, &proposed_metadata)?;
            validate_binary_blobs(repository.clone(), &proposed_metadata).await?;

            let metadata_key = hash::hash_function_arg(
                repository::SALT_LORE,
                repository::METADATA,
                hex::encode(repository_id.data()).as_str(),
            );
            let previous = match &governed {
                Some(governed) => {
                    let event = match governed.cell_id() {
                        Some(cell_id) => Some(
                            outbox_builders::repository_metadata_changed(
                                cell_id,
                                repository_id.data(),
                                expected.as_ref(),
                                updated.as_ref(),
                            )
                            .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?,
                        ),
                        None => None,
                    };
                    let projection = ProjectionWrite {
                        partition: repository_id.data().to_vec(),
                        key_type: KeyType::RepositoryMetadata as i16,
                        key: metadata_key.as_ref().to_vec(),
                        value: Some(updated.as_ref().to_vec()),
                    };
                    match governed
                        .commit(
                            repository_id.data(),
                            None,
                            expected.as_ref(),
                            updated.as_ref(),
                            projection,
                            event,
                        )
                        .await?
                    {
                        MetadataCasOutcome::Applied => expected,
                        MetadataCasOutcome::Lost(observed) => Hash::from(observed.as_slice()),
                    }
                }
                None => {
                    let write_token = get_write_token();
                    repository
                        .write_mutable_store(&write_token)
                        .compare_and_swap(
                            repository_id.into(),
                            metadata_key,
                            expected,
                            updated,
                            KeyType::RepositoryMetadata,
                        )
                        .await
                        .map_err(|err| {
                            warn_error_to_status(&err, |err| {
                                Status::internal(format!("failed to update metadata: {err}"))
                            })
                        })?
                }
            };

            let metadata = if previous == expected {
                updated
            } else {
                previous
            };
            Ok(Response::new(RepositoryMetadataSetResponse {
                metadata: metadata.into(),
            }))
        })
        .await
}

/// Reject a proposed metadata blob that mutates a read-only field.
fn validate_read_only_fields(current: &Metadata, proposed: &Metadata) -> Result<(), Status> {
    for key in READ_ONLY_KEYS {
        let current_value = current.get_typed(key);
        let proposed_value = proposed.get_typed(key);

        match (current_value, proposed_value) {
            (Ok((current_bytes, current_type)), Ok((proposed_bytes, proposed_type))) => {
                if current_type != proposed_type || current_bytes != proposed_bytes {
                    return Err(Status::invalid_argument(format!(
                        "cannot modify read-only key '{key}'"
                    )));
                }
            }
            (Ok(_), Err(_)) => {
                return Err(Status::invalid_argument(format!(
                    "cannot remove read-only key '{key}'"
                )));
            }
            (Err(_), Ok(_) | Err(_)) => {}
        }
    }
    Ok(())
}

/// Reject a proposed metadata blob that references an Address that is not
/// currently addressable in CAS.
async fn validate_binary_blobs(
    repo: Arc<RepositoryContext>,
    proposed: &Metadata,
) -> Result<(), Status> {
    let mut addresses = vec![];
    proposed.walk(
        |_key_slice: &[u8], value_slice: &[u8], value_type: MetadataType| {
            if value_type == MetadataType::Address
                && value_slice.len() == std::mem::size_of::<Address>()
            {
                let address: Address = value_slice.into();
                addresses.push(address);
            }
        },
    );

    for address in addresses {
        let options = lore_revision::immutable::read_options_from_repository(&repo).with_cache();
        if lore_revision::immutable::read(repo.clone(), address, None, options)
            .await
            .is_err()
        {
            return Err(Status::not_found(format!(
                "binary blob not found: {address}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    mod auth_guard {
        use lore_base::types::RepositoryId;
        use lore_revision::repository::RepositoryMetadata;
        use tonic::Code;
        use tonic::metadata::BinaryMetadataValue;
        use uuid::Uuid;

        use super::super::*;
        use crate::auth::jwt::AuthorizationToken;
        use crate::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
        use crate::domain::test_support::context as build_domain_context;
        use crate::grpc::domain_operation_metadata::FINGERPRINT_KEY;
        use crate::grpc::domain_operation_metadata::FINGERPRINT_V1_LEN;
        use crate::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
        use crate::grpc::domain_operation_metadata::OPERATION_ID_KEY;
        use crate::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
        use crate::grpc::domain_operation_metadata::PREPARE_TOKEN_LEN;
        use crate::store::test_store_create;

        mockall::mock! {
            pub Authorizer {}

            #[async_trait::async_trait]
            impl RepositoryAuthorizer for Authorizer {
                async fn check_repository_access(
                    &self,
                    authorization: Option<String>,
                    repository_id: RepositoryId,
                ) -> Result<(), Status>;
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

            async fn flush(
                self: Arc<Self>,
                _sync_data: bool,
            ) -> Result<(), lore_storage::StoreError> {
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
        // ignored. `.times(0)` on the authorizer is the proof of "refused"
        // over "ignored": the gate must decide before any authorization side
        // effect.
        #[tokio::test]
        async fn carriage_with_no_domain_context_is_refused_before_any_authorization_side_effect() {
            let (immutable, mutable, _) = test_store_create().await.unwrap();
            let mut mock = MockAuthorizer::new();
            mock.expect_check_repository_access().times(0);

            let mut request = Request::new(RepositoryMetadataSetRequest {
                id: REPOSITORY_ID.to_vec().into(),
                expected: vec![0u8; 32].into(),
                updated: vec![1u8; 32].into(),
            });
            insert_valid_domain_operation_headers(&mut request);

            let err = handler(request, Arc::new(mock), immutable, mutable, None)
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
            let mut mock = MockAuthorizer::new();
            mock.expect_check_repository_access()
                .withf(|authorization, repository_id| {
                    authorization.is_none() && repository_id == &RepositoryId::from(REPOSITORY_ID)
                })
                .times(1)
                .returning(|_, _| Err(Status::permission_denied("denied")));
            let request = Request::new(RepositoryMetadataSetRequest {
                id: REPOSITORY_ID.to_vec().into(),
                expected: vec![0u8; 32].into(),
                updated: vec![1u8; 32].into(),
            });
            let err = handler(request, Arc::new(mock), immutable, mutable, None)
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
                    let mut mock = MockAuthorizer::new();
                    mock.expect_check_repository_access()
                        .returning(|_, _| Ok(()));
                    let request = Request::new(RepositoryMetadataSetRequest {
                        id: REPOSITORY_ID.to_vec().into(),
                        expected: vec![0u8; 32].into(),
                        updated: hash.into(),
                    });
                    handler(request, Arc::new(mock), immutable, mutable, None)
                        .await
                        .unwrap();
                })
                .await;
        }
    }

    mod validate_read_only_fields {
        use lore_base::types::Context;
        use lore_revision::repository;

        use super::super::validate_read_only_fields;
        use super::super::*;

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
            validate_read_only_fields(&current, &proposed)
                .expect("absence on both sides is a no-op");
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
        use tonic::Request;

        use super::super::handler;
        use crate::authnz::repository_authorizer::repository_authorizer;
        use crate::grpc::handlers::repository_query::authz_test_support::new_test_stores;
        use crate::grpc::handlers::repository_query::authz_test_support::seed_repository_metadata;
        use crate::grpc::handlers::repository_query::authz_test_support::start_stub_auth_server;

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
                repository_authorizer(Some(auth_url)),
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
            let updated =
                build_valid_update(immutable.clone(), mutable.clone(), repository_id).await;
            let auth_url = start_stub_auth_server(repository_id).await;

            let response = handler(
                request_for(repository_id, expected, updated),
                repository_authorizer(Some(auth_url)),
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
            let updated =
                build_valid_update(immutable.clone(), mutable.clone(), repository_id).await;

            let response = handler(
                request_for(repository_id, expected, updated),
                repository_authorizer(None),
                immutable,
                mutable,
                None,
            )
            .await
            .expect("auth-off must leave behavior unchanged");

            assert_eq!(Hash::from(response.into_inner().metadata), updated);
        }
    }
}
