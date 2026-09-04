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
use lore_proto::RepositoryMetadataSetRequest;
use lore_proto::RepositoryMetadataSetResponse;
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

/// Validate that read-only fields have not been changed between the current and proposed
/// metadata blobs.
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

/// Validate that all Address-typed values in the proposed metadata blob reference existing
/// blobs in the immutable store.
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

#[tracing::instrument(name = "RepositoryMetadataSet::handle", skip_all)]
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
            repository_id: &req.repository_id,
        },
    )?;

    let repository_id: Context = req.repository_id.into();
    if repository_id == Context::default() {
        return Err(Status::invalid_argument("Missing repository ID"));
    }

    // The digest is recomputed here from the exact validated wire values, never
    // taken from the body: CR-029's canonical-intent contract makes Lore the
    // second independent computation of the platform's 32 bytes, and a
    // handler-supplied digest would defeat the point.
    //
    // It sits after the empty/default check and after admission, satisfying two
    // rules at once: R-BLOCK-2 keeps `admit_at_entry` at handler entry, while
    // INTENT-02-LORE allows the intent module to be called "only after wire,
    // frozen text-limit, empty/default, and principal validation". An all-zero
    // identity is exactly the empty/default case — it is 16 bytes, so the
    // canonical encoder accepts it, and hashing it would mint a binding for a
    // request that is about to be refused.
    let governed = match admitted {
        Some(admitted) => {
            let digest = canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
                repository_id: repository_id.data(),
                expected_hash: &req.expected_hash,
                new_hash: &req.new_hash,
            })
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
            GovernedMetadataCas::prepare(
                domain_context,
                Some(admitted),
                "lore.RepositoryService/RepositoryMetadataSet",
                digest,
            )?
        }
        None => None,
    };

    let expected_hash: Hash = req.expected_hash.into();
    let new_hash: Hash = req.new_hash.into();

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

            // Deserialize current and proposed blobs for validation
            let current_metadata = if !expected_hash.is_zero() {
                Metadata::deserialize(repository.clone(), expected_hash)
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

            let proposed_metadata = Metadata::deserialize(repository.clone(), new_hash)
                .await
                .map_err(|err| {
                    warn_error_to_status(&err, |err| {
                        Status::invalid_argument(format!(
                            "failed to deserialize proposed metadata: {err}"
                        ))
                    })
                })?;

            // Validate read-only fields are unchanged
            validate_read_only_fields(&current_metadata, &proposed_metadata)?;

            // Validate binary blob references exist
            validate_binary_blobs(repository.clone(), &proposed_metadata).await?;

            // Perform compare-and-swap
            let metadata_key = hash::hash_function_arg(
                repository::SALT_LORE,
                repository::METADATA,
                hex::encode(repository_id.data()).as_str(),
            );
            // The governed path replaces the direct store CAS with one domain
            // transaction that swaps the pointer, writes the same
            // `lore_mutable` projection row the direct path would have written,
            // and appends the classified event, all or nothing. The in-band CAS
            // miss is preserved exactly: a loss is still a successful RPC
            // carrying the pointer that was there.
            let previous = match &governed {
                Some(governed) => {
                    let event = match governed.cell_id() {
                        Some(cell_id) => Some(
                            outbox_builders::repository_metadata_changed(
                                cell_id,
                                repository_id.data(),
                                expected_hash.as_ref(),
                                new_hash.as_ref(),
                            )
                            .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?,
                        ),
                        None => None,
                    };
                    let projection = ProjectionWrite {
                        partition: repository_id.data().to_vec(),
                        key_type: KeyType::RepositoryMetadata as i16,
                        key: metadata_key.as_ref().to_vec(),
                        value: Some(new_hash.as_ref().to_vec()),
                    };
                    match governed
                        .commit(
                            repository_id.data(),
                            None,
                            expected_hash.as_ref(),
                            new_hash.as_ref(),
                            projection,
                            event,
                        )
                        .await?
                    {
                        MetadataCasOutcome::Applied => expected_hash,
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
                            expected_hash,
                            new_hash,
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

            if previous == expected_hash {
                Ok(Response::new(RepositoryMetadataSetResponse {
                    success: true,
                    current_hash: new_hash.into(),
                }))
            } else {
                Ok(Response::new(RepositoryMetadataSetResponse {
                    success: false,
                    current_hash: previous.into(),
                }))
            }
        })
        .await
}

#[cfg(test)]
mod tests {
    use lore_base::types::RepositoryId;
    use lore_revision::repository::RepositoryMetadata;
    use tonic::Code;
    use tonic::metadata::BinaryMetadataValue;
    use uuid::Uuid;

    use super::*;
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
    // ignored. `.times(0)` on the authorizer is the proof of "refused" over
    // "ignored": the gate must decide before any authorization side effect.
    #[tokio::test]
    async fn carriage_with_no_domain_context_is_refused_before_any_authorization_side_effect() {
        let (immutable, mutable, _) = test_store_create().await.unwrap();
        let mut mock = MockAuthorizer::new();
        mock.expect_check_repository_access().times(0);

        let mut request = Request::new(RepositoryMetadataSetRequest {
            repository_id: REPOSITORY_ID.to_vec().into(),
            expected_hash: vec![0u8; 32].into(),
            new_hash: vec![1u8; 32].into(),
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
        let mut mock = MockAuthorizer::new();
        mock.expect_check_repository_access()
            .withf(|authorization, repository_id| {
                authorization.is_none() && repository_id == &RepositoryId::from(REPOSITORY_ID)
            })
            .times(1)
            .returning(|_, _| Err(Status::permission_denied("denied")));
        let request = Request::new(RepositoryMetadataSetRequest {
            repository_id: REPOSITORY_ID.to_vec().into(),
            expected_hash: vec![0u8; 32].into(),
            new_hash: vec![1u8; 32].into(),
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
                    repository_id: REPOSITORY_ID.to_vec().into(),
                    expected_hash: vec![0u8; 32].into(),
                    new_hash: hash.into(),
                });
                handler(request, Arc::new(mock), immutable, mutable, None)
                    .await
                    .unwrap();
            })
            .await;
    }
}
