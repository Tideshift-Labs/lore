// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Shared worktree admission for managed workflows and ordinary local writes.
use std::future::Future;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use lore_base::fs::lock::FSLock;
use lore_transport::AttemptState;
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

/// The refusal for a blocked admission. It keeps the internal error code and names each blocker,
/// whether Lore can still settle it, and the only exit when it cannot. Acknowledging an attempt
/// (`AdjudicatedUnknown`) is not an exit: correctness stays unresolved and the latch, keyed on
/// this working copy's path, stays in place.
async fn admission_refusal(store: &RepositoryAttemptStore, headline: &str) -> ProtocolError {
    ProtocolError::internal(admission_refusal_text(store, headline).await)
}

#[lore_macro::test_pub]
async fn admission_refusal_text(store: &RepositoryAttemptStore, headline: &str) -> String {
    let mut lines = vec![format!(
        "{headline}; writes to this working copy are blocked."
    )];
    let mut unsettleable = false;
    // An open parent that recorded an uncertainty code, or never proved its body finished, can
    // never complete: `reconcile_parent` refuses it even after every child settles. Admission ran
    // `settle_receiptless` first, so any such parent still open here is one of those.
    let open_parents = match store.admission_parents().await {
        Ok(parents) => {
            let open: Vec<_> = parents
                .into_iter()
                .filter(|parent| !parent.complete)
                .collect();
            unsettleable |= open
                .iter()
                .any(|parent| parent.parent_uncertainty_code.is_some() || !parent.body_completed);
            open
        }
        Err(error) => {
            lines.push(format!("Cannot list the blocking workflows: {error}"));
            Vec::new()
        }
    };
    let mut has_children = false;
    match store.unresolved().await {
        Ok(children) => {
            has_children = !children.is_empty();
            for child in children {
                // Reconcile can settle a child only through a receipt reader, and only when the
                // child's recorded namespace can be recovered to ask the server.
                let reason =
                    if !lore_transport::caller_operation::has_receipt_reader(&child.operation) {
                        Some(" Lore cannot settle it: this operation has no receipt to read.")
                    } else if store.recovery_context(&child.attempt_id).await.is_err() {
                        Some(
                            " Lore cannot settle it: its recorded server namespace cannot be \
                             recovered.",
                        )
                    } else {
                        None
                    };
                unsettleable |= reason.is_some();
                let mut line = format!(
                    "Attempt {} ({}): the outcome is unknown.",
                    child.attempt_id, child.operation
                );
                line.push_str(reason.unwrap_or(
                    " It can settle only if the server holds a receipt for it: run `lore \
                     operation reconcile`, or retry later.",
                ));
                if child.state == AttemptState::AdjudicatedUnknown {
                    line.push_str(" It was acknowledged; acknowledging does not unblock writes.");
                }
                lines.push(line);
            }
        }
        Err(error) => lines.push(format!("Cannot list the blocking attempts: {error}")),
    }
    // Name every open parent that can never finish, even beside settleable children: settling
    // them would still leave this parent, and so the block, in place.
    for parent in &open_parents {
        let line = if parent.parent_uncertainty_code.is_some() {
            format!(
                "Workflow {} ({}) cannot finish: it recorded an uncertain outcome.",
                parent.id, parent.operation
            )
        } else if !parent.body_completed {
            format!(
                "Workflow {} ({}) cannot finish: it never recorded that its steps completed.",
                parent.id, parent.operation
            )
        } else if !has_children {
            format!(
                "Workflow {} ({}) did not finish.",
                parent.id, parent.operation
            )
        } else {
            continue;
        };
        lines.push(line);
    }
    lines.push(
        if unsettleable {
            "To keep writing, clone the repository again into a new folder."
        } else {
            "If it stays blocked, clone the repository again into a new folder to keep writing."
        }
        .to_owned(),
    );
    // A fresh clone holds no lock tokens, but `lock release --force` with no paths queries the
    // caller's own locks and, on a fenced cell, escalates to the self force-release the server
    // admits for a caller's own rows (`is_self_force_unlock`).
    lines.push(
        "Locks you hold stay held after you clone again. To release them, run `lore lock \
         release --force` in the new folder (add `--branch <name>` for another branch)."
            .to_owned(),
    );
    lines.push("Run `lore operation status` for detail.".to_owned());
    lines.join("\n")
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
            return Err(admission_refusal(&store, "repository has an unresolved workflow").await);
        }
        if !nested && !recovery {
            for (_, legacy) in &legacy_stores {
                if blocks_admission(legacy).await? {
                    return Err(admission_refusal(
                        legacy,
                        "repository has unresolved legacy attempts",
                    )
                    .await);
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

    /// FORK-LOCAL (Tideshift): whether this guard holds the admission lock itself, so no managed
    /// workflow body can be live on the worktree. False for a guard nested in a running workflow.
    pub fn holds_admission_lock(&self) -> bool {
        self.lock.is_some()
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
