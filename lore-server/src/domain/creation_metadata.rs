// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The admitted create handler's private metadata-upload context.
use std::sync::Arc;

use lore_postgres::store::immutable_store::PostgresImmutableStore;
use lore_postgres::store::immutable_store::creation_metadata::CreationMetadataStore;
use lore_revision::repository::RepositoryContext;
use tonic::Status;

use super::GovernedRepositoryCreate;

pub(crate) struct CreationMetadataContext {
    pub repository: Arc<RepositoryContext>,
    pub uploads: Arc<CreationMetadataStore>,
}

impl GovernedRepositoryCreate {
    /// Called after the create claim's authorization callback, never from a storage RPC.
    pub(crate) fn metadata_upload_context(
        &self,
        repository: &Arc<RepositoryContext>,
    ) -> Result<Option<CreationMetadataContext>, Status> {
        let Some(coordinator) = self.domain.fragment_coordinator() else {
            return Ok(None);
        };
        // Enabled Postgres serving composition supplies this concrete store directly. Refuse a
        // wrapping or foreign store instead of silently falling back to an ungoverned upload.
        let raw: Arc<dyn std::any::Any + Send + Sync> = repository.immutable_store();
        let store = Arc::downcast::<PostgresImmutableStore>(raw).map_err(|_| {
            Status::failed_precondition(
                "coordinated create requires the configured Postgres immutable store",
            )
        })?;
        let uploads = store
            .creation_metadata_store(*repository.id.data(), coordinator)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        let mutable = repository.try_mutable_store_arc().ok_or_else(|| {
            Status::failed_precondition("repository creation context is not writable")
        })?;
        let context = Arc::new(RepositoryContext::new_server_context(
            uploads.clone(),
            mutable,
            repository.id,
        ));
        Ok(Some(CreationMetadataContext {
            repository: context,
            uploads,
        }))
    }
}
