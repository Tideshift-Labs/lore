// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::str::FromStr;
use std::sync::Arc;

use lore_base::error::RepositoryNotFound;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_error_set::prelude::*;
use lore_proto::lore::repository::v1::RepositoryGetRequest;
use lore_proto::lore::repository::v1::RepositoryGetResponse;
use lore_proto::lore::repository::v1::repository_get_request::Query;
use lore_revision::lore::RepositoryId;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryError;
use lore_revision::repository::RepositoryMetadata;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;
use tracing::info;
use tracing::warn;

use super::record::build_repository;
use crate::grpc::extract_authorization_header;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_user_id;
use crate::grpc::handlers::repository_query::check_repository_query_authorization;
use crate::util::setup_execution;

/// `lore.repository.v1.RepositoryService.RepositoryGet` handler.
///
/// Resolves a repository by id or by name and returns the full
/// `Repository` record. Honors auth when the environment configures an
/// auth-service URL. Self-heals stale or missing name → id mappings the
/// same way the legacy `RepositoryQuery` handler does.
#[tracing::instrument(name = "RepositoryGet::v1::handle", skip_all)]
pub async fn handler(
    request: Request<RepositoryGetRequest>,
    auth_url: Option<String>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
) -> Result<Response<RepositoryGetResponse>, Status> {
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let authorization = extract_authorization_header(&request);
    let req = request.into_inner();

    let Some(query) = req.query else {
        return Err(Status::invalid_argument(
            "RepositoryGetRequest.query must be set (id or name)",
        ));
    };

    let execution = setup_execution(module_path!(), correlation_id, user_id);

    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        RepositoryId::default(),
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            let (id, metadata, metadata_hash) = match query {
                Query::Id(id) => {
                    let id: RepositoryId = Context::from(id).into();
                    debug!(%id, "Get repository by id");
                    let (metadata, metadata_hash) =
                        repository_load_id(repository.clone(), id, auth_url, authorization)
                            .await
                            .map_err(|_err| {
                                Status::not_found(format!("Repository {id} not found"))
                            })?;
                    (id, metadata, metadata_hash)
                }
                Query::Name(name) => {
                    debug!(name, "Get repository by name");
                    let (id, metadata, metadata_hash) = repository_load_name(
                        repository.clone(),
                        name.as_str(),
                        auth_url,
                        authorization,
                    )
                    .await
                    .map_err(|_err| Status::not_found(format!("Repository {name} not found")))?;
                    (id, metadata, metadata_hash)
                }
            };
            debug!(%id, "Repository get response");
            Ok(Response::new(RepositoryGetResponse {
                repository: Some(build_repository(id, &metadata, metadata_hash)),
            }))
        })
        .await
}

/// Resolve a repository by id, returning its metadata blob plus the
/// metadata pointer hash. Performs the same authz check + name-mapping
/// repair the legacy v0 handler does.
#[allow(clippy::map_err_ignore)]
pub(super) async fn repository_load_id(
    repository: Arc<RepositoryContext>,
    id: RepositoryId,
    auth_url: Option<String>,
    authorization: Option<String>,
) -> Result<(RepositoryMetadata, Hash), RepositoryError> {
    if let Some(auth_url) = auth_url {
        check_repository_query_authorization(auth_url, authorization, id)
            .await
            .map_err(|status| {
                debug!(%id, "User authorization failed: {status}");
                RepositoryError::from(RepositoryNotFound {
                    repository: id.to_string(),
                })
            })?;
    }

    let repository = Arc::new(repository.to_server_context(id));
    let metadata_hash = repository::metadata_hash(repository.clone())
        .await
        .forward_with::<RepositoryError, _>(|| {
            format!("Repository {id} metadata hash not found")
        })?;
    let metadata = repository::metadata(repository.clone(), metadata_hash)
        .await
        .forward_with::<RepositoryError, _>(|| format!("Repository {id} metadata not found"))?;

    let name_repository = Arc::new(repository.to_server_context(RepositoryId::default()));
    match repository::id_from_name(name_repository, &metadata.name).await {
        Ok(resolved_id) if resolved_id != id => {
            warn!(
                "Repository {} name {} maps to different repository {}, returning not found",
                id, metadata.name, resolved_id
            );
            return Err(RepositoryError::from(RepositoryNotFound {
                repository: id.to_string(),
            }));
        }
        Err(_) => {
            info!(
                "Repairing missing name -> ID mapping: {} -> {}",
                metadata.name, id
            );
            let _ = repository::store_name_to_id(repository.clone(), &metadata.name, id)
                .await
                .inspect_err(|err| warn!("Failed to repair name -> ID mapping: {err}"));
        }
        Ok(_) => {}
    }

    Ok((metadata, metadata_hash))
}

/// Resolve a repository by name. Falls through to id lookup when the
/// caller passed a parseable `RepositoryId` as the name. Self-heals a
/// stale name → id mapping by deleting it when the metadata's name
/// disagrees.
#[allow(clippy::map_err_ignore)]
pub(super) async fn repository_load_name(
    repository: Arc<RepositoryContext>,
    name: &str,
    auth_url: Option<String>,
    authorization: Option<String>,
) -> Result<(RepositoryId, RepositoryMetadata, Hash), RepositoryError> {
    if let Ok(id) = RepositoryId::from_str(name) {
        let (metadata, metadata_hash) =
            repository_load_id(repository, id, auth_url, authorization).await?;
        return Ok((id, metadata, metadata_hash));
    }

    let name_repository = Arc::new(repository.to_server_context(RepositoryId::default()));
    let id = repository::id_from_name(name_repository, name).await?;

    if let Some(auth_url) = auth_url {
        check_repository_query_authorization(auth_url, authorization, id)
            .await
            .map_err(|status| {
                debug!(%id, "User authorization failed: {status}");
                RepositoryError::from(RepositoryNotFound {
                    repository: name.to_string(),
                })
            })?;
    }

    let repository = Arc::new(repository.to_server_context(id));
    let metadata_hash = repository::metadata_hash(repository.clone())
        .await
        .forward_with::<RepositoryError, _>(|| {
            format!("Repository {name} metadata hash not found")
        })?;
    let metadata = repository::metadata(repository.clone(), metadata_hash)
        .await
        .forward_with::<RepositoryError, _>(|| format!("Repository {name} metadata not found"))?;

    if metadata.name != name {
        warn!(
            "Stale name -> ID mapping: {} maps to {} but metadata name is {}, deleting mapping",
            name, id, metadata.name
        );
        let _ = repository::delete_name_to_id(repository.clone(), name)
            .await
            .inspect_err(|err| warn!("Failed to delete stale name -> ID mapping: {err}"));
        return Err(RepositoryError::from(RepositoryNotFound {
            repository: name.to_string(),
        }));
    }

    Ok((id, metadata, metadata_hash))
}

#[cfg(test)]
mod tests {
    use lore_storage::KeyValueStream;
    use lore_storage::MutableStore;
    use lore_storage::Partition;
    use lore_storage::StoreError;

    use super::*;
    use crate::grpc::handlers::repository_query::authz_test_support::new_test_stores;
    use crate::grpc::handlers::repository_query::authz_test_support::seed_repository_metadata;

    /// Wraps a real `MutableStore`, delegating every method except `store()`,
    /// which always fails once wrapped. Mirrors the self-heal write's actual
    /// failure mode under CR-029 enforcement (the domain-key bypass guard
    /// rejects a `RepositoryId`-typed write on the generic mutable path —
    /// see `lore-postgres/tests/domain_bypass.rs`) without depending on a
    /// live Postgres store.
    struct FailStoreWritesMutableStore {
        inner: Arc<dyn MutableStore>,
    }

    #[async_trait::async_trait]
    impl MutableStore for FailStoreWritesMutableStore {
        async fn load(
            self: Arc<Self>,
            partition: Partition,
            key: Hash,
            key_type: lore_base::types::KeyType,
        ) -> Result<Hash, StoreError> {
            self.inner.clone().load(partition, key, key_type).await
        }

        async fn store(
            self: Arc<Self>,
            _partition: Partition,
            _key: Hash,
            _value: Hash,
            _key_type: lore_base::types::KeyType,
        ) -> Result<(), StoreError> {
            Err(StoreError::internal(
                "simulated domain-key bypass guard rejection",
            ))
        }

        async fn compare_and_swap(
            self: Arc<Self>,
            partition: Partition,
            key: Hash,
            expected: Hash,
            value: Hash,
            key_type: lore_base::types::KeyType,
        ) -> Result<Hash, StoreError> {
            self.inner
                .clone()
                .compare_and_swap(partition, key, expected, value, key_type)
                .await
        }

        async fn list(
            self: Arc<Self>,
            partition: Partition,
            key_type: lore_base::types::KeyType,
        ) -> Result<KeyValueStream, StoreError> {
            self.inner.clone().list(partition, key_type).await
        }

        async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
            self.inner.clone().flush(sync_data).await
        }
    }

    // CR-029, self-heal writer pin (companion to `lore-postgres/tests/
    // domain_bypass.rs`, which proves the guard itself rejects the write —
    // this proves the call site at line 147 swallows that rejection rather
    // than propagating it). The reviewer's defence for leaving this handler
    // ungated is that a missing name -> ID mapping is repaired best-effort;
    // if a future cleanup ever turns the `let _ = ...` into a `?`, this test
    // must go red.
    #[tokio::test]
    async fn missing_name_mapping_repair_failure_does_not_fail_the_get() {
        let (immutable, mutable) = new_test_stores().await;
        let repository_id: RepositoryId = Context::from([9u8; 16]).into();
        let metadata_hash = seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            "my-repo",
            "a description",
        )
        .await;

        let faulty_mutable: Arc<dyn MutableStore> =
            Arc::new(FailStoreWritesMutableStore { inner: mutable });
        let repository = Arc::new(RepositoryContext::new_server_context(
            immutable,
            faulty_mutable,
            repository_id,
        ));

        let (metadata, hash) = repository_load_id(repository, repository_id, None, None)
            .await
            .expect("a failed name-mapping repair must not fail the get");

        assert_eq!(metadata.name, "my-repo");
        assert_eq!(hash, metadata_hash);
    }
}
