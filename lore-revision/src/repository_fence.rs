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
    path.split(['/', '\\']).any(|part| {
        part.eq_ignore_ascii_case(WORKFLOW_DIRECTORY)
            || part.eq_ignore_ascii_case(crate::attempt_store::BOOTSTRAP_LOCK_FILE)
            // Windows names are case-insensitive; aliases of our lowercase UUID must stay
            // excluded too. Parsing still rejects malformed and non-UUID lookalikes.
            || crate::attempt_store::is_directory_temporary(&part.to_ascii_lowercase())
    })
}

tokio::task_local! { static ACTIVE_WORKTREE: PathBuf; }

/// Whether a store blocks write admission after it settles what needs no server answer.
/// The caller holds the exclusive admission lock, so no open parent has a live body.
async fn blocks_admission(store: &RepositoryAttemptStore) -> Result<bool, ProtocolError> {
    async fn blocked(store: &RepositoryAttemptStore) -> Result<bool, ProtocolError> {
        Ok(store
            .admission_parents()
            .await?
            .iter()
            .any(|parent| !parent.complete)
            || !store.unresolved().await?.is_empty())
    }
    if !blocked(store).await? {
        return Ok(false);
    }
    if !store.settle_receiptless().await? {
        return Ok(true);
    }
    blocked(store).await
}

/// Owns exclusion until all nested calls and durable settlement have ended.
pub struct RepositoryMutationGuard {
    root: PathBuf,
    lock: Option<FSLock>,
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
        crate::attempt_store::ensure_directory(&dot).await?;
        let nested = ACTIVE_WORKTREE
            .try_with(|active| active == &root)
            .unwrap_or(false);
        let lock = if nested {
            None
        } else {
            Some(
                FSLock::acquire_file_lock(dot.join("workflow-admission"), false)
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
        if !nested && !recovery && blocks_admission(&store).await? {
            return Err(ProtocolError::internal(
                "repository has an unresolved workflow; inspect operation status",
            ));
        }
        if !nested && !recovery {
            for (_, legacy) in &legacy_stores {
                if blocks_admission(legacy).await? {
                    return Err(ProtocolError::internal(
                        "repository has unresolved legacy attempts; inspect operation status",
                    ));
                }
            }
        }
        Ok(Self {
            root,
            lock,
            store,
            legacy_stores,
        })
    }

    /// Settles what needs no server answer in every admission store (see
    /// `RepositoryAttemptStore::settle_receiptless`). Refused inside a nested fence: it holds no
    /// lock, and the open parent there is the running caller's own.
    pub async fn settle_receiptless(&self) -> Result<(), ProtocolError> {
        if self.lock.is_none() {
            return Err(ProtocolError::internal(
                "cannot settle blockers inside a running managed workflow",
            ));
        }
        for (source, store) in self.recovery_stores() {
            store.settle_receiptless().await.map_err(|error| {
                ProtocolError::internal(format!("{source}: cannot settle blockers: {error}"))
            })?;
        }
        Ok(())
    }

    /// The canonical worktree root this guard admits.
    pub fn root(&self) -> &Path {
        &self.root
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
