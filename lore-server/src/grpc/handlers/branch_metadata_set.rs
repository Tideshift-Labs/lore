// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Hash;
use lore_postgres::domain::coordinator::ProjectionWrite;
use lore_postgres::domain::outbox::builders as outbox_builders;
use lore_proto::BranchMetadataSetRequest;
use lore_proto::BranchMetadataSetResponse;
use lore_revision::branch;
use lore_revision::lore::BranchId;
use lore_revision::metadata::Metadata;
use lore_revision::metadata::MetadataType;
use lore_revision::metadata::branch::READ_ONLY_KEYS;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::domain::DomainContext;
use crate::domain::GovernedMetadataCas;
use crate::domain::GovernedScope;
use crate::domain::MetadataCasFamily;
use crate::domain::MetadataCasOutcome;
use crate::domain::admit_at_entry;
use crate::domain_intent::CanonicalIntent;
use crate::domain_intent::canonical_intent_digest;
use crate::grpc::FilterSlowDownExt;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_repository;
use crate::grpc::get_user_id;
use crate::grpc::get_write_token;
use crate::grpc::require_permission;
use crate::grpc::warn_error_to_status;
use crate::util::setup_execution;

/// Validate that read-only fields have not been changed between the current and proposed
/// metadata blobs.
pub(crate) fn validate_read_only_fields(
    current: &Metadata,
    proposed: &Metadata,
) -> Result<(), Status> {
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
pub(crate) async fn validate_binary_blobs(
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

#[tracing::instrument(name = "BranchMetadataSet::handle", skip_all)]
pub async fn handler(
    request: Request<BranchMetadataSetRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    enforce_write_permission: bool,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<BranchMetadataSetResponse>, Status> {
    let request_metadata = request.metadata().clone();
    let request_authorization = crate::grpc::get_authorization_optional(request.extensions());
    let repository_id = get_repository(request.metadata())?;
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    // Capture the auth token before the request is consumed; the
    // PROTECT-set gate below needs it once both metadata blobs are
    // deserialized.
    let extensions = request.extensions().clone();
    let req = request.into_inner();

    // CR-029 R-BLOCK-2: the one shared reader of the domain-operation headers,
    // at handler entry, before any handler logic or authorization side effect.
    let admitted = admit_at_entry(
        domain_context,
        &request_metadata,
        request_authorization.as_ref(),
        GovernedScope::TargetRepository {
            repository_id: repository_id.data(),
        },
    )?;

    let branch_id = BranchId::from(req.branch_id);
    if branch_id == BranchId::default() {
        return Err(Status::invalid_argument("Missing branch ID"));
    }

    // Recomputed from the exact validated wire values, never taken from the
    // body. v0 and v1 of this CAS share one frozen intent family, so identical
    // values must produce identical bytes on both entry points.
    //
    // After the empty/default check, per INTENT-02-LORE; see the v0 repository
    // handler for the full reasoning.
    let governed = match admitted {
        Some(admitted) => {
            let digest = canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
                repository_id: repository_id.data(),
                branch_id: branch_id.as_ref(),
                expected_hash: &req.expected_hash,
                new_hash: &req.new_hash,
            })
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
            GovernedMetadataCas::prepare(
                domain_context,
                Some(admitted),
                MetadataCasFamily::Branch,
                digest,
            )
            .await?
        }
        None => None,
    };

    let expected_hash: Hash = req.expected_hash.into();
    let new_hash: Hash = req.new_hash.into();

    let execution = setup_execution(module_path!(), correlation_id, user_id);
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository_id,
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            // Deserialize current and proposed blobs for validation
            let current_metadata = if !expected_hash.is_zero() {
                Metadata::deserialize(repository.clone(), expected_hash)
                    .await
                    .filter_slow_down()?
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

            // Enforce write authorization. Toggling the PROTECT bit
            // requires `admin` (branch protection is an admin act); any
            // other metadata write requires `write`. No-op when auth is
            // OFF or the flag is disabled.
            let protect_changed = current_metadata
                .get_bool(branch::PROTECT)
                .unwrap_or_default()
                != proposed_metadata
                    .get_bool(branch::PROTECT)
                    .unwrap_or_default();
            let required_permission = if protect_changed { "admin" } else { "write" };
            require_permission(
                &extensions,
                repository_id,
                required_permission,
                enforce_write_permission,
            )?;

            // Validate read-only fields are unchanged
            validate_read_only_fields(&current_metadata, &proposed_metadata)?;

            // Validate binary blob references exist
            validate_binary_blobs(repository.clone(), &proposed_metadata).await?;

            // Perform compare-and-swap
            let (metadata_key, key_type) = branch::mutable_key(
                repository::SALT_LORE,
                branch::METADATA,
                repository_id,
                branch_id,
            );
            // The governed path swaps the pointer, writes the same projection
            // row, and appends the classified event in one transaction. The
            // classification is not always `branch.metadata_changed`: the
            // PROTECT bit travels inside this same CAS, and CR-032 pins
            // `branch.protection_changed` as its own kind. `protect_changed` is
            // already computed above for the admin-permission gate, so the two
            // decisions cannot drift apart.
            //
            // PIN(WP-116): a CAS that moves the PROTECT bit AND other metadata
            // in one write is classified as the protection change, because that
            // is the transition with the stricter authorization and the named
            // consumer. The pinned set's second open question is whether these
            // two kinds stay distinct at all; if they merge, this branch
            // collapses rather than changing meaning.
            let previous = match &governed {
                Some(governed) => {
                    let event =
                        match governed.cell_id() {
                            Some(cell_id) => {
                                // Read before the transaction, so the name and tip
                                // are a preflight observation. They go in the
                                // payload only; the aggregate version is resolved
                                // by the coordinator from what it commits.
                                let branch = governed
                                    .branch_snapshot(repository_id.data(), branch_id.as_ref())
                                    .await?
                                    .ok_or_else(|| {
                                        Status::not_found(format!("Branch {branch_id} not found"))
                                    })?;
                                let built = if protect_changed {
                                    outbox_builders::branch_protection_changed(
                                        cell_id,
                                        repository_id.data(),
                                        branch_id.as_ref(),
                                        &branch.name,
                                        &branch.latest_hash,
                                        expected_hash.as_ref(),
                                        new_hash.as_ref(),
                                        proposed_metadata
                                            .get_bool(branch::PROTECT)
                                            .unwrap_or_default(),
                                    )
                                } else {
                                    outbox_builders::branch_metadata_changed(
                                        cell_id,
                                        repository_id.data(),
                                        branch_id.as_ref(),
                                        &branch.name,
                                        &branch.latest_hash,
                                        expected_hash.as_ref(),
                                        new_hash.as_ref(),
                                    )
                                };
                                Some(built.map_err(|error| {
                                    crate::grpc::map_domain_error_to_status(&error)
                                })?)
                            }
                            None => None,
                        };
                    let projection = ProjectionWrite {
                        partition: repository_id.data().to_vec(),
                        key_type: key_type as i16,
                        key: metadata_key.as_ref().to_vec(),
                        value: Some(new_hash.as_ref().to_vec()),
                    };
                    match governed
                        .commit(
                            repository_id.data(),
                            Some(branch_id.as_ref()),
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
                            repository_id,
                            metadata_key,
                            expected_hash,
                            new_hash,
                            key_type,
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
                Ok(Response::new(BranchMetadataSetResponse {
                    success: true,
                    current_hash: new_hash.into(),
                }))
            } else {
                Ok(Response::new(BranchMetadataSetResponse {
                    success: false,
                    current_hash: previous.into(),
                }))
            }
        })
        .await
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Hash;
    use lore_proto::BranchMetadataSetRequest;
    use lore_revision::branch;
    use lore_revision::lore::BranchId;
    use lore_revision::lore::RepositoryId;
    use lore_revision::metadata::Metadata;
    use lore_revision::repository::RepositoryContext;
    use lore_transport::grpc::REPOSITORY_ID_KEY;
    use rand::random;
    use tonic::Request;

    use super::*;
    use crate::grpc::get_write_token;
    use crate::store::test_store_create;

    fn make_request(
        repository: RepositoryId,
        branch: BranchId,
        expected_hash: Hash,
        new_hash: Hash,
    ) -> Request<BranchMetadataSetRequest> {
        let mut request = Request::new(BranchMetadataSetRequest {
            branch_id: branch.into(),
            expected_hash: expected_hash.into(),
            new_hash: new_hash.into(),
        });
        request.metadata_mut().insert_bin(
            REPOSITORY_ID_KEY,
            tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
        );
        request
    }

    #[tokio::test]
    #[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
    async fn enforcing_cell_rejects_before_legacy_metadata_cas_body() {
        let Some(domain) = crate::domain::test_support::configured_enforcing_context().await else {
            panic!("LORE_TEST_PG_URL must be set; a skipped live case is NOT RUN, never a pass");
        };
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, _) = test_store_create().await.expect("test stores");
        let error = handler(
            make_request(
                repository,
                BranchId::default(),
                Hash::default(),
                Hash::default(),
            ),
            immutable_store,
            mutable_store,
            false,
            Some(&domain),
        )
        .await
        .expect_err("enforcement must reject missing operation carriage at entry");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    /// Create a branch and return its metadata hash.
    async fn create_branch(repository: Arc<RepositoryContext>, branch_id: BranchId) -> Hash {
        let write_token = get_write_token();
        branch::create(
            repository.clone(),
            &write_token,
            branch_id,
            "test-branch",
            branch::default_category(),
            "creator",
            1,
            vec![],
            false,
            false,
        )
        .await
        .expect("Failed to create branch");

        branch::metadata_hash(repository, branch_id)
            .await
            .expect("Failed to load metadata hash")
    }

    /// Serialize a metadata blob and return its hash.
    async fn serialize_metadata(repository: Arc<RepositoryContext>, metadata: &Metadata) -> Hash {
        metadata
            .serialize(repository)
            .await
            .expect("Failed to serialize metadata")
    }

    #[tokio::test]
    async fn set_custom_key_succeeds() {
        let repository_id = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository_id,
            ));

            let current_hash = create_branch(repository.clone(), branch_id).await;

            // Build proposed metadata with the same read-only fields plus a custom key
            let mut proposed = Metadata::deserialize(repository.clone(), current_hash)
                .await
                .expect("deserialize");
            proposed
                .set_string("custom-key", "custom-value")
                .expect("set custom key");
            let new_hash = serialize_metadata(repository.clone(), &proposed).await;

            let request = make_request(repository_id, branch_id, current_hash, new_hash);
            let response = handler(request, immutable_store, mutable_store, false, None)
                .await
                .expect("Handler failed");

            let inner = response.into_inner();
            assert!(inner.success);
            assert_eq!(Hash::from(inner.current_hash), new_hash);
        }))
        .await;
    }

    #[tokio::test]
    async fn rejects_modification_of_read_only_name() {
        let repository_id = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository_id,
            ));

            let current_hash = create_branch(repository.clone(), branch_id).await;

            let mut proposed = Metadata::deserialize(repository.clone(), current_hash)
                .await
                .expect("deserialize");
            proposed
                .set_string(branch::NAME, "renamed-branch")
                .expect("set name");
            let new_hash = serialize_metadata(repository.clone(), &proposed).await;

            let request = make_request(repository_id, branch_id, current_hash, new_hash);
            let result = handler(request, immutable_store, mutable_store, false, None).await;

            assert!(result.is_err());
            let status = result.unwrap_err();
            assert_eq!(status.code(), tonic::Code::InvalidArgument);
            assert!(status.message().contains("name"));
        }))
        .await;
    }

    #[tokio::test]
    async fn rejects_removal_of_read_only_creator() {
        let repository_id = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository_id,
            ));

            let current_hash = create_branch(repository.clone(), branch_id).await;

            let mut proposed = Metadata::deserialize(repository.clone(), current_hash)
                .await
                .expect("deserialize");
            proposed.remove_key(branch::CREATOR);
            let new_hash = serialize_metadata(repository.clone(), &proposed).await;

            let request = make_request(repository_id, branch_id, current_hash, new_hash);
            let result = handler(request, immutable_store, mutable_store, false, None).await;

            assert!(result.is_err());
            let status = result.unwrap_err();
            assert_eq!(status.code(), tonic::Code::InvalidArgument);
            assert!(status.message().contains("creator"));
        }))
        .await;
    }

    #[tokio::test]
    async fn allows_modification_of_protect_field() {
        let repository_id = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository_id,
            ));

            let current_hash = create_branch(repository.clone(), branch_id).await;

            let mut proposed = Metadata::deserialize(repository.clone(), current_hash)
                .await
                .expect("deserialize");
            proposed
                .set_bool(branch::PROTECT, true)
                .expect("set protect");
            let new_hash = serialize_metadata(repository.clone(), &proposed).await;

            let request = make_request(repository_id, branch_id, current_hash, new_hash);
            let response = handler(request, immutable_store, mutable_store, false, None)
                .await
                .expect("Handler failed — protect should be writable");

            assert!(response.into_inner().success);
        }))
        .await;
    }

    #[tokio::test]
    async fn cas_fails_on_stale_expected_hash() {
        let repository_id = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository_id,
            ));

            let current_hash = create_branch(repository.clone(), branch_id).await;

            // Build a valid proposed metadata with a custom key
            let mut proposed = Metadata::deserialize(repository.clone(), current_hash)
                .await
                .expect("deserialize");
            proposed.set_string("key", "value").expect("set custom key");
            let new_hash = serialize_metadata(repository.clone(), &proposed).await;

            // Use a bogus expected hash
            let stale_hash = Hash::from(random::<[u8; 32]>());
            let request = make_request(repository_id, branch_id, stale_hash, new_hash);
            let result = handler(request, immutable_store, mutable_store, false, None).await;

            // CAS should fail because expected_hash doesn't match (it can't be deserialized)
            assert!(result.is_err());
        }))
        .await;
    }

    #[tokio::test]
    async fn rejects_missing_branch_id() {
        let repository_id = random::<RepositoryId>();

        let (immutable_store, mutable_store, _execution) =
            test_store_create().await.expect("Failed to create stores");

        let request = make_request(
            repository_id,
            BranchId::default(),
            Hash::default(),
            Hash::default(),
        );
        let result = handler(request, immutable_store, mutable_store, false, None).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn rejects_modification_of_read_only_category() {
        let repository_id = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository_id,
            ));

            let current_hash = create_branch(repository.clone(), branch_id).await;

            let mut proposed = Metadata::deserialize(repository.clone(), current_hash)
                .await
                .expect("deserialize");
            proposed
                .set_string(branch::CATEGORY, "changed-category")
                .expect("set category");
            let new_hash = serialize_metadata(repository.clone(), &proposed).await;

            let request = make_request(repository_id, branch_id, current_hash, new_hash);
            let result = handler(request, immutable_store, mutable_store, false, None).await;

            assert!(result.is_err());
            let status = result.unwrap_err();
            assert_eq!(status.code(), tonic::Code::InvalidArgument);
            assert!(status.message().contains("category"));
        }))
        .await;
    }
}
