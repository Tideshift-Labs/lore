// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::KeyType;
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

use crate::grpc::extract_correlation_id;
use crate::grpc::get_user_id;
use crate::grpc::get_write_token;
use crate::grpc::handlers::repository_query::check_repository_query_authorization;
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
    proposed
        .walk(
            |_key_slice: &[u8], value_slice: &[u8], value_type: MetadataType| {
                if value_type == MetadataType::Address
                    && value_slice.len() == std::mem::size_of::<Address>()
                {
                    let address: Address = value_slice.into();
                    addresses.push(address);
                }
            },
        )
        .map_err(|err| {
            warn_error_to_status(&err, |err| {
                Status::internal(format!("failed to walk proposed metadata: {err}"))
            })
        })?;

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
    auth_url: Option<String>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
) -> Result<Response<RepositoryMetadataSetResponse>, Status> {
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let authorization = request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string());
    let req = request.into_inner();

    let repository_id: Context = req.repository_id.into();
    if repository_id == Context::default() {
        return Err(Status::invalid_argument("Missing repository ID"));
    }

    // Scope the CAS to the caller's repository — see RepositoryMetadataGet.
    // RepositoryService rides the authn-only interceptor (UCS-13506), so the
    // body repository id carries no upstream authorization; re-check it before
    // any mutation. Auth-OFF (no auth_url) leaves behavior unchanged.
    if let Some(auth_url) = auth_url {
        check_repository_query_authorization(auth_url, authorization, repository_id.into()).await?;
    }

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
            let write_token = get_write_token();
            let previous = repository
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
                })?;

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
    use std::sync::Arc;

    use lore_base::types::Hash;
    use lore_proto::RepositoryMetadataSetRequest;
    use lore_revision::lore::RepositoryId;
    use lore_revision::repository;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::RepositoryMetadata;
    use tonic::Request;

    use super::handler;
    use crate::grpc::handlers::repository_query::authz_test_support::new_test_stores;
    use crate::grpc::handlers::repository_query::authz_test_support::seed_repository_metadata;
    use crate::grpc::handlers::repository_query::authz_test_support::start_stub_auth_server;

    fn request_for(
        repository_id: RepositoryId,
        expected_hash: Hash,
        new_hash: Hash,
    ) -> Request<RepositoryMetadataSetRequest> {
        let mut request = Request::new(RepositoryMetadataSetRequest {
            repository_id: repository_id.into(),
            expected_hash: expected_hash.into(),
            new_hash: new_hash.into(),
        });
        request
            .metadata_mut()
            .insert("authorization", "Bearer test-token".parse().unwrap());
        request
    }

    /// Serializes an updated metadata blob for `repository_id` that keeps
    /// every read-only field identical to what `seed_repository_metadata`
    /// wrote (only `description` changes), so a CAS against it is
    /// well-formed and would land if the handler ever reached the CAS.
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
        let caller_authorized_repo = RepositoryId::from([21u8; 16]);
        let target_repo = RepositoryId::from([22u8; 16]);
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
        let new_hash = build_valid_update(immutable.clone(), mutable.clone(), target_repo).await;
        let auth_url = start_stub_auth_server(caller_authorized_repo).await;

        let result = handler(
            request_for(target_repo, original_hash, new_hash),
            Some(auth_url),
            immutable.clone(),
            mutable.clone(),
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
        let repository_id = RepositoryId::from([23u8; 16]);
        let (immutable, mutable) = new_test_stores().await;
        let expected_hash = seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            "acme",
            "original",
        )
        .await;
        let new_hash = build_valid_update(immutable.clone(), mutable.clone(), repository_id).await;
        let auth_url = start_stub_auth_server(repository_id).await;

        let response = handler(
            request_for(repository_id, expected_hash, new_hash),
            Some(auth_url),
            immutable,
            mutable,
        )
        .await
        .expect("a legitimate client CAS-writing its own repository must be unaffected");

        let body = response.into_inner();
        assert!(body.success, "CAS on the caller's own repository must land");
        assert_eq!(Hash::from(body.current_hash), new_hash);
    }

    #[tokio::test]
    async fn auth_off_allows_cas_without_an_authorization_check() {
        let repository_id = RepositoryId::from([24u8; 16]);
        let (immutable, mutable) = new_test_stores().await;
        let expected_hash = seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            "acme",
            "original",
        )
        .await;
        let new_hash = build_valid_update(immutable.clone(), mutable.clone(), repository_id).await;

        // No stub auth server is started: with auth_url = None, none should
        // be needed.
        let response = handler(
            request_for(repository_id, expected_hash, new_hash),
            None,
            immutable,
            mutable,
        )
        .await
        .expect("auth-off must leave behavior unchanged");

        let body = response.into_inner();
        assert!(body.success);
        assert_eq!(Hash::from(body.current_hash), new_hash);
    }
}
