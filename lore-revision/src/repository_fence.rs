// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Shared worktree admission for managed workflows and ordinary local writes.
use std::future::Future;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use lore_base::fs::lock::FSLock;
use lore_transport::AttemptStore;
use lore_transport::ProtocolError;
use uuid::Uuid;

use crate::attempt_store::ManagedParent;
use crate::attempt_store::RepositoryAttemptStore;

/// Stable before and after repository initialization; never part of repository content.
pub const WORKFLOW_DIRECTORY: &str = ".lore-workflow";

pub fn is_workflow_path(path: &str) -> bool {
    path.split(['/', '\\'])
        .any(|part| part.eq_ignore_ascii_case(WORKFLOW_DIRECTORY))
}

tokio::task_local! { static ACTIVE_WORKTREE: PathBuf; }

/// Owns exclusion until all nested calls and durable settlement have ended.
pub struct RepositoryMutationGuard {
    root: PathBuf,
    _lock: Option<FSLock>,
    store: Arc<RepositoryAttemptStore>,
    legacy_stores: Vec<(&'static str, Arc<RepositoryAttemptStore>)>,
}

impl RepositoryMutationGuard {
    pub async fn acquire(root: &Path) -> Result<Self, ProtocolError> {
        Self::open(root, false).await
    }

    /// Recovery holds the same process exclusion but is allowed to inspect unresolved parents.
    pub async fn recover(root: &Path) -> Result<Self, ProtocolError> {
        Self::open(root, true).await
    }

    async fn open(root: &Path, recovery: bool) -> Result<Self, ProtocolError> {
        let root = std::fs::canonicalize(root)
            .map_err(|error| ProtocolError::internal(error.to_string()))?;
        let dot = root.join(WORKFLOW_DIRECTORY);
        std::fs::create_dir_all(&dot)
            .map_err(|error| ProtocolError::internal(error.to_string()))?;
        let nested = ACTIVE_WORKTREE
            .try_with(|active| active == &root)
            .unwrap_or(false);
        let lock = if nested {
            None
        } else {
            Some(
                FSLock::acquire_file_lock(dot.join("workflow-admission"))
                    .await
                    .map_err(|error| ProtocolError::internal(error.to_string()))?,
            )
        };
        let store = Arc::new(RepositoryAttemptStore::in_directory(dot));
        // Discover existing legacy evidence while holding the same admission lock.
        // Recovery must see every store that ordinary admission consults.
        let legacy_stores: Vec<_> = [".lore", ".urc"]
            .into_iter()
            .filter_map(|source| {
                let directory = root.join(source);
                directory.is_dir().then(|| {
                    (
                        source,
                        Arc::new(RepositoryAttemptStore::in_directory(directory)),
                    )
                })
            })
            .collect();
        if !nested
            && !recovery
            && (store
                .managed_parents()
                .await?
                .iter()
                .any(|parent| !parent.complete)
                || !store.unresolved().await?.is_empty())
        {
            return Err(ProtocolError::internal(
                "repository has an unresolved workflow; inspect operation status",
            ));
        }
        if !nested && !recovery {
            for (_, legacy) in &legacy_stores {
                if legacy
                    .managed_parents()
                    .await?
                    .iter()
                    .any(|parent| !parent.complete)
                    || !legacy.unresolved().await?.is_empty()
                {
                    return Err(ProtocolError::internal(
                        "repository has unresolved legacy attempts; inspect operation status",
                    ));
                }
            }
        }
        Ok(Self {
            root,
            _lock: lock,
            store,
            legacy_stores,
        })
    }

    pub fn store(&self) -> Arc<RepositoryAttemptStore> {
        self.store.clone()
    }

    /// All stores consulted by admission, with their original on-disk source.
    /// Legacy records stay in place; their namespaces are never reconstructed.
    pub fn recovery_stores(&self) -> Vec<(&'static str, Arc<RepositoryAttemptStore>)> {
        let mut stores = vec![(WORKFLOW_DIRECTORY, self.store.clone())];
        stores.extend(self.legacy_stores.iter().cloned());
        stores
    }

    pub async fn begin(
        &self,
        id: Uuid,
        operation: String,
        normalized_intent: String,
    ) -> Result<Arc<RepositoryAttemptStore>, ProtocolError> {
        self.store
            .begin_parent(ManagedParent {
                version: 1,
                id: id.to_string(),
                root: self.root.to_string_lossy().into_owned(),
                operation,
                normalized_intent,
                namespace: None,
                complete: false,
                parent_uncertainty_code: None,
                body_completed: false,
            })
            .await?;
        Ok(self.store.clone())
    }

    pub fn run<F: Future>(&self, future: F) -> impl Future<Output = F::Output> {
        ACTIVE_WORKTREE.scope(self.root.clone(), future)
    }

    pub async fn finish(&self, parent: Uuid) -> Result<(), ProtocolError> {
        self.store.finish_parent(parent).await
    }
}
