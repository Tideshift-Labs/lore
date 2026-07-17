// Copyright 2026 Khurram Virani
// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT

//! Push-time advisory-lock enforcement (CR-019, naive present-tense model).
//!
//! Lore locks are advisory by design: the storage/push/merge paths never
//! consult them, so a client that ignores the lock protocol (e.g. the stock
//! `lore` CLI, or any tool bypassing Lorehub's own clients) can push a change
//! to a file another user has locked. This guard makes an **opt-in** server
//! check: on push, diff the pushed revision against the branch's current tip
//! and, if any changed path is locked on that branch by a *different* user,
//! reject the push.
//!
//! Deliberately naive (present-tense) for a first cut: it answers "is a changed
//! file locked by someone else *right now*", not the causal question the
//! upstream successor-locks LEP targets (has this branch seen every prior edit).
//! It is gated behind `[feature] enforce_locks_on_push` (default **off**), so
//! enabling it is an explicit operator choice after live verification.

use std::collections::HashMap;
use std::sync::Arc;

use lore_base::types::Hash;
use lore_revision::branch::load_latest;
use lore_revision::change::NodeChange;
use lore_revision::diff::diff_revision_paths;
use lore_revision::lock::LockQuery;
use lore_revision::lock::LockStore;
use lore_revision::lock::util::assemble_resource_for_path;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::repository::RepositoryContext;
use lore_revision::state::State;
use lore_revision::util::collect_stream::collect_stream_with_summary;
use tonic::Status;
use tracing::debug;
use tracing::warn;

/// A single lock that blocks the push: the changed path and who holds the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockConflict {
    pub path: String,
    pub owner: String,
}

/// Enforce advisory locks against a push. Returns `Ok(())` when the push is
/// clear; returns a `permission_denied` `Status` naming the first blocking lock
/// when a changed path is locked by another user on this branch.
///
/// `new_revision` is the revision being pushed; the prior branch tip is loaded
/// here (before `push()` advances it). A push that creates the branch (no prior
/// tip) diffs against the empty tree, so a brand-new file locked by someone else
/// would still be caught.
pub async fn enforce_push_locks(
    repository: Arc<RepositoryContext>,
    lock_store: &Arc<dyn LockStore>,
    branch: BranchId,
    new_revision: Hash,
    pusher_user_id: &str,
) -> Result<(), Status> {
    let repository_id = repository.id;
    let conflicts = collect_push_lock_conflicts(
        repository,
        lock_store,
        repository_id,
        branch,
        new_revision,
        pusher_user_id,
    )
    .await?;

    if let Some(first) = conflicts.first() {
        warn!(
            path = %first.path,
            owner = %first.owner,
            conflict_count = conflicts.len(),
            "Rejecting push: changed path is locked by another user",
        );
        return Err(Status::permission_denied(format!(
            "push blocked: {} file(s) changed are locked by another user; \
             e.g. '{}' is locked by {}",
            conflicts.len(),
            first.path,
            first.owner,
        )));
    }

    Ok(())
}

/// The pure core: compute the set of changed paths on this push that are locked
/// by a different user. Split out from `enforce_push_locks` so the conflict
/// computation is unit-testable without the tonic `Status` mapping.
pub(crate) async fn collect_push_lock_conflicts(
    repository: Arc<RepositoryContext>,
    lock_store: &Arc<dyn LockStore>,
    repository_id: RepositoryId,
    branch: BranchId,
    new_revision: Hash,
    pusher_user_id: &str,
) -> Result<Vec<LockConflict>, Status> {
    // Locks held by OTHERS on this branch, keyed by resource hash. If nobody
    // else holds a lock on this branch, there is nothing to enforce — skip the
    // (potentially expensive) revision diff entirely.
    let other_locks =
        others_locks_by_hash(lock_store, repository_id, branch, pusher_user_id).await?;
    if other_locks.is_empty() {
        debug!(%branch, "No foreign locks on branch; skipping push-lock diff");
        return Ok(Vec::new());
    }

    let prior_tip = load_latest(repository.clone(), branch)
        .await
        .map_err(|err| {
            warn!(error = %err, "Failed to load branch tip for push-lock check");
            Status::internal("failed to load branch tip for lock check")
        })?;

    let changed_paths = changed_paths(repository, prior_tip, new_revision).await?;

    let mut conflicts = Vec::new();
    for path in changed_paths {
        let resource = assemble_resource_for_path(&path, branch);
        if let Some(owner) = other_locks.get(&resource.hash) {
            conflicts.push(LockConflict {
                path,
                owner: owner.clone(),
            });
        }
    }
    Ok(conflicts)
}

/// Map of `resource.hash -> owner` for every lock on `branch` held by a user
/// other than `pusher_user_id`.
async fn others_locks_by_hash(
    lock_store: &Arc<dyn LockStore>,
    repository_id: RepositoryId,
    branch: BranchId,
    pusher_user_id: &str,
) -> Result<HashMap<Hash, String>, Status> {
    let locks = lock_store
        .query_locks(LockQuery::RepositoryBranch(repository_id, branch))
        .await
        .map_err(|err| {
            warn!(error = %err, "Failed to query locks for push-lock check");
            Status::internal("failed to query locks for lock check")
        })?;

    Ok(locks
        .into_iter()
        .filter(|lock| lock.owner != pusher_user_id)
        .map(|lock| (lock.resource.hash, lock.owner))
        .collect())
}

/// The set of file paths that differ between `source` and `target` revisions.
async fn changed_paths(
    repository: Arc<RepositoryContext>,
    source: Hash,
    target: Hash,
) -> Result<Vec<String>, Status> {
    let state_source = State::deserialize(repository.clone(), source)
        .await
        .map_err(|err| {
            warn!(error = %err, "Failed to deserialize source state for push-lock check");
            Status::internal("failed to read source revision for lock check")
        })?;
    let state_target = State::deserialize(repository.clone(), target)
        .await
        .map_err(|err| {
            warn!(error = %err, "Failed to deserialize target state for push-lock check");
            Status::internal("failed to read target revision for lock check")
        })?;

    let (_, changes): (_, Vec<NodeChange>) = collect_stream_with_summary(|tx| {
        diff_revision_paths(repository.clone(), state_source, state_target, None, tx)
    })
    .await
    .map_err(|err| {
        warn!(error = %err, "Failed to diff revisions for push-lock check");
        Status::internal("failed to diff revisions for lock check")
    })?;

    let mut paths = Vec::with_capacity(changes.len());
    for change in changes {
        // The path in the target tree. A rename also carries `from_path` (the
        // old path) — both endpoints are "changed" for lock purposes, since a
        // lock is on either the source or destination path.
        paths.push(change.path.as_str().to_string());
        if let Some(from_path) = change.from_path {
            let from = from_path.as_str().to_string();
            if from != change.path.as_str() {
                paths.push(from);
            }
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use lore_revision::lore::BranchId;
    use lore_revision::lore::RepositoryId;
    use rand::random;

    use super::*;
    use crate::lock::store::LocalLockStore;

    async fn store_with_lock(
        owner: &str,
        path: &str,
        branch: BranchId,
        repository: RepositoryId,
    ) -> Arc<dyn LockStore> {
        let store = LocalLockStore::default();
        let resource = assemble_resource_for_path(path, branch);
        store
            .lock_resources(owner, repository, std::slice::from_ref(&resource))
            .await
            .expect("acquire lock");
        Arc::new(store)
    }

    #[tokio::test]
    async fn others_locks_excludes_the_pusher_and_recomputes_the_client_hash() {
        let repository: RepositoryId = random();
        let branch: BranchId = random();
        let path = "Art/Hero.uasset";
        let lock_store = store_with_lock("alice", path, branch, repository).await;

        // A different user (bob) sees alice's lock, keyed by the SAME hash the
        // client used to acquire it — proving the server-side recompute matches.
        let others = others_locks_by_hash(&lock_store, repository, branch, "bob")
            .await
            .expect("query others' locks");
        let expected_hash = assemble_resource_for_path(path, branch).hash;
        assert_eq!(
            others.get(&expected_hash).map(String::as_str),
            Some("alice")
        );

        // The lock holder (alice) pushing her own change sees no foreign lock.
        let self_view = others_locks_by_hash(&lock_store, repository, branch, "alice")
            .await
            .expect("query self locks");
        assert!(
            self_view.is_empty(),
            "a pusher's own lock must not block their push"
        );
    }

    #[tokio::test]
    async fn others_locks_are_scoped_to_the_branch() {
        let repository: RepositoryId = random();
        let branch: BranchId = random();
        let other_branch: BranchId = random();
        let lock_store = store_with_lock("alice", "Art/Hero.uasset", branch, repository).await;

        // The lock is on `branch`; a query for a different branch sees nothing
        // (locks are branch-scoped — the cross-branch case is a client concern).
        let on_other = others_locks_by_hash(&lock_store, repository, other_branch, "bob")
            .await
            .expect("query other branch");
        assert!(on_other.is_empty());
    }
}
