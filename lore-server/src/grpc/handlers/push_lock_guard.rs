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

/// Map an internal engine error to a `Status::internal` that fails the push
/// closed, logging via the house `warn_mapped_error_status` convention.
fn to_internal<E: std::error::Error>(error: &E, message: &'static str) -> Status {
    let status = Status::internal(message);
    crate::grpc::warn_mapped_error_status(error, &status);
    status
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
        .map_err(|err| to_internal(&err, "failed to load branch tip for lock check"))?;

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
        .map_err(|err| to_internal(&err, "failed to query locks for lock check"))?;

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
        .map_err(|err| to_internal(&err, "failed to read source revision for lock check"))?;
    let state_target = State::deserialize(repository.clone(), target)
        .await
        .map_err(|err| to_internal(&err, "failed to read target revision for lock check"))?;

    let (_, changes): (_, Vec<NodeChange>) = collect_stream_with_summary(|tx| {
        diff_revision_paths(repository.clone(), state_source, state_target, None, tx)
    })
    .await
    .map_err(|err| to_internal(&err, "failed to diff revisions for lock check"))?;

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
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Address;
    use lore_base::types::Context;
    use lore_revision::branch;
    use lore_revision::lore::BranchId;
    use lore_revision::lore::RepositoryId;
    use lore_revision::node::Node;
    use lore_revision::node::NodeFlags;
    use lore_revision::node::ROOT_NODE;
    use lore_revision::state;
    use lore_storage::hash::hash_string;
    use rand::random;

    use super::*;
    use crate::grpc::get_write_token;
    use crate::grpc::handlers::branch_push;
    use crate::lock::store::LocalLockStore;
    use crate::store::test_store_create;

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

    /// Creates a fresh branch with no revision pushed yet — `load_latest`
    /// returns a zero hash for it (see `branch::load_latest`), mirroring a
    /// brand-new branch about to receive its first push.
    async fn create_root_branch(repository: &Arc<RepositoryContext>, name: &str) -> BranchId {
        let write_token = get_write_token();
        branch::create(
            repository.clone(),
            &write_token,
            BranchId::from(uuid::Uuid::now_v7()),
            name,
            branch::default_category(),
            "test-creator",
            1,
            vec![],
            false,
            false,
        )
        .await
        .expect("create root branch")
    }

    /// Serializes a revision with a single root-level File node at `file_name`
    /// and returns its hash. Does NOT push/advance the branch tip — mirrors
    /// the production flow, where `enforce_push_locks` diffs the about-to-be
    /// pushed revision against the branch's *current* tip, before `push()`
    /// ever runs.
    async fn serialize_file_revision(
        repository: &Arc<RepositoryContext>,
        parent: Hash,
        revision_number: u64,
        file_name: &str,
    ) -> Hash {
        serialize_file_revision_with_context(
            repository,
            parent,
            revision_number,
            file_name,
            Context::default(),
        )
        .await
    }

    /// Like `serialize_file_revision`, but lets the caller pin the file's
    /// `address.context` — the node identity `detect_and_coalesce_moves`
    /// matches on to fold an add/delete pair into a rename. A non-zero,
    /// shared context across two revisions is what makes a path change
    /// look like a rename rather than an unrelated delete + add.
    async fn serialize_file_revision_with_context(
        repository: &Arc<RepositoryContext>,
        parent: Hash,
        revision_number: u64,
        file_name: &str,
        context: Context,
    ) -> Hash {
        let write_token = get_write_token();
        let state = state::State::new();
        state.set_parent_self(parent);
        state.set_revision_number(revision_number);
        let node = Node {
            flags: NodeFlags::File.bits(),
            name_hash: hash_string(file_name),
            address: Address {
                hash: Hash::default(),
                context,
            },
            ..Default::default()
        };
        state
            .node_add(repository.clone(), ROOT_NODE, node, file_name)
            .await
            .expect("node_add");
        state
            .serialize(repository.clone(), &write_token)
            .await
            .expect("serialize state")
    }

    /// Serializes an empty (no files) revision and returns its hash.
    async fn serialize_empty_revision(
        repository: &Arc<RepositoryContext>,
        parent: Hash,
        revision_number: u64,
    ) -> Hash {
        let write_token = get_write_token();
        let state = state::State::new();
        state.set_parent_self(parent);
        state.set_revision_number(revision_number);
        state
            .serialize(repository.clone(), &write_token)
            .await
            .expect("serialize state")
    }

    /// Pushes `revision` to `branch`, actually advancing the branch tip —
    /// used to establish a real "prior tip" for `collect_push_lock_conflicts`
    /// to load via `load_latest`.
    async fn push_revision(
        repository: &Arc<RepositoryContext>,
        branch_id: BranchId,
        revision: Hash,
    ) -> Hash {
        branch_push::push(
            repository.clone(),
            branch_id,
            revision,
            true,
            true,
            false,
            branch::DEFAULT_HISTORY_STEP_SIZE,
            crate::grpc::server::RevisionListAcceleration::default(),
        )
        .await
        .expect("push")
        .revision
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

    /// `collect_push_lock_conflicts` — the handler-seam gate itself, not just
    /// `others_locks_by_hash`. Real repo fixture: a fresh branch, a pushed
    /// revision establishing the branch tip, then a second (not-yet-pushed)
    /// revision that changes a file locked by another user.
    mod collect_push_lock_conflicts_tests {
        use super::*;

        #[tokio::test]
        async fn changed_path_locked_by_another_user_is_a_conflict() {
            let (immutable_store, mutable_store, execution) =
                test_store_create().await.expect("Failed to create stores");
            let repository_id: RepositoryId = random();

            Box::pin(LORE_CONTEXT.scope(execution, async move {
                let repository = Arc::new(RepositoryContext::new_server_context(
                    immutable_store,
                    mutable_store,
                    repository_id,
                ));
                let branch_id = create_root_branch(&repository, "main").await;

                // Establish a real prior tip: an empty revision, actually pushed.
                let root = serialize_empty_revision(&repository, Hash::default(), 1).await;
                push_revision(&repository, branch_id, root).await;

                let path = "hero.uasset";
                let lock_store = store_with_lock("alice", path, branch_id, repository_id).await;

                // The next revision (not yet pushed) adds the locked file.
                let new_revision = serialize_file_revision(&repository, root, 2, path).await;

                let conflicts = collect_push_lock_conflicts(
                    repository.clone(),
                    &lock_store,
                    repository_id,
                    branch_id,
                    new_revision,
                    "bob",
                )
                .await
                .expect("collect conflicts");

                assert_eq!(conflicts.len(), 1);
                assert_eq!(conflicts[0].path, path);
                assert_eq!(conflicts[0].owner, "alice");
            }))
            .await;
        }

        #[tokio::test]
        async fn self_lock_is_not_a_conflict() {
            let (immutable_store, mutable_store, execution) =
                test_store_create().await.expect("Failed to create stores");
            let repository_id: RepositoryId = random();

            Box::pin(LORE_CONTEXT.scope(execution, async move {
                let repository = Arc::new(RepositoryContext::new_server_context(
                    immutable_store,
                    mutable_store,
                    repository_id,
                ));
                let branch_id = create_root_branch(&repository, "main").await;

                let root = serialize_empty_revision(&repository, Hash::default(), 1).await;
                push_revision(&repository, branch_id, root).await;

                let path = "hero.uasset";
                // The pusher (alice) holds her own lock on the file she's changing.
                let lock_store = store_with_lock("alice", path, branch_id, repository_id).await;
                let new_revision = serialize_file_revision(&repository, root, 2, path).await;

                let conflicts = collect_push_lock_conflicts(
                    repository.clone(),
                    &lock_store,
                    repository_id,
                    branch_id,
                    new_revision,
                    "alice",
                )
                .await
                .expect("collect conflicts");

                assert!(
                    conflicts.is_empty(),
                    "a pusher's own lock must not block their own push"
                );
            }))
            .await;
        }

        #[tokio::test]
        async fn no_foreign_lock_short_circuits_without_diffing() {
            let (immutable_store, mutable_store, execution) =
                test_store_create().await.expect("Failed to create stores");
            let repository_id: RepositoryId = random();

            Box::pin(LORE_CONTEXT.scope(execution, async move {
                let repository = Arc::new(RepositoryContext::new_server_context(
                    immutable_store,
                    mutable_store,
                    repository_id,
                ));
                let branch_id = create_root_branch(&repository, "main").await;
                let root = serialize_empty_revision(&repository, Hash::default(), 1).await;
                push_revision(&repository, branch_id, root).await;

                // No locks at all on this branch.
                let lock_store: Arc<dyn LockStore> = Arc::new(LocalLockStore::default());

                // A revision hash that was never serialized — if
                // `collect_push_lock_conflicts` attempted the diff anyway, this
                // would fail to deserialize and surface as an `Err`, not an
                // empty `Ok`. Proves the empty-foreign-locks short-circuit
                // really does skip the (potentially expensive) diff.
                let bogus_revision = Hash::hash_buffer(b"never serialized");

                let conflicts = collect_push_lock_conflicts(
                    repository.clone(),
                    &lock_store,
                    repository_id,
                    branch_id,
                    bogus_revision,
                    "bob",
                )
                .await
                .expect("no foreign locks should short-circuit to Ok, not attempt a diff");

                assert!(conflicts.is_empty());
            }))
            .await;
        }

        #[tokio::test]
        async fn changed_path_not_locked_is_not_a_conflict() {
            let (immutable_store, mutable_store, execution) =
                test_store_create().await.expect("Failed to create stores");
            let repository_id: RepositoryId = random();

            Box::pin(LORE_CONTEXT.scope(execution, async move {
                let repository = Arc::new(RepositoryContext::new_server_context(
                    immutable_store,
                    mutable_store,
                    repository_id,
                ));
                let branch_id = create_root_branch(&repository, "main").await;
                let root = serialize_empty_revision(&repository, Hash::default(), 1).await;
                push_revision(&repository, branch_id, root).await;

                // A foreign lock exists on this branch, but on a path the push
                // never touches — must not block.
                let lock_store =
                    store_with_lock("alice", "unrelated.uasset", branch_id, repository_id).await;
                let new_revision =
                    serialize_file_revision(&repository, root, 2, "hero.uasset").await;

                let conflicts = collect_push_lock_conflicts(
                    repository.clone(),
                    &lock_store,
                    repository_id,
                    branch_id,
                    new_revision,
                    "bob",
                )
                .await
                .expect("collect conflicts");

                assert!(
                    conflicts.is_empty(),
                    "a lock on an untouched path must not block the push"
                );
            }))
            .await;
        }

        #[tokio::test]
        async fn branch_creation_with_locked_new_file_is_a_conflict() {
            let (immutable_store, mutable_store, execution) =
                test_store_create().await.expect("Failed to create stores");
            let repository_id: RepositoryId = random();

            Box::pin(LORE_CONTEXT.scope(execution, async move {
                let repository = Arc::new(RepositoryContext::new_server_context(
                    immutable_store,
                    mutable_store,
                    repository_id,
                ));
                // Freshly created branch — no revision pushed yet, so
                // `load_latest` returns a zero hash and the diff is against
                // the empty tree (see `branch::load_latest`).
                let branch_id = create_root_branch(&repository, "main").await;

                let path = "hero.uasset";
                let lock_store = store_with_lock("alice", path, branch_id, repository_id).await;

                let first_revision =
                    serialize_file_revision(&repository, Hash::default(), 1, path).await;

                let conflicts = collect_push_lock_conflicts(
                    repository.clone(),
                    &lock_store,
                    repository_id,
                    branch_id,
                    first_revision,
                    "bob",
                )
                .await
                .expect("collect conflicts");

                assert_eq!(conflicts.len(), 1);
                assert_eq!(conflicts[0].path, path);
                assert_eq!(conflicts[0].owner, "alice");
            }))
            .await;
        }

        #[tokio::test]
        async fn rename_counts_both_endpoints_as_changed() {
            let (immutable_store, mutable_store, execution) =
                test_store_create().await.expect("Failed to create stores");
            let repository_id: RepositoryId = random();

            Box::pin(LORE_CONTEXT.scope(execution, async move {
                let repository = Arc::new(RepositoryContext::new_server_context(
                    immutable_store,
                    mutable_store,
                    repository_id,
                ));
                let branch_id = create_root_branch(&repository, "main").await;

                let old_path = "old.uasset";
                let new_path = "new.uasset";
                // Same non-zero node context at both paths is what
                // `detect_and_coalesce_moves` matches on to fold an add/delete
                // pair into a single rename (`NodeChange::from_path`).
                let file_context: Context = random();

                let root = serialize_file_revision_with_context(
                    &repository,
                    Hash::default(),
                    1,
                    old_path,
                    file_context,
                )
                .await;
                push_revision(&repository, branch_id, root).await;

                // Lock is on the OLD path — the file that "disappears" from the
                // tree but must still be recognized as touched by the rename.
                let lock_store = store_with_lock("alice", old_path, branch_id, repository_id).await;

                let renamed = serialize_file_revision_with_context(
                    &repository,
                    root,
                    2,
                    new_path,
                    file_context,
                )
                .await;

                let conflicts = collect_push_lock_conflicts(
                    repository.clone(),
                    &lock_store,
                    repository_id,
                    branch_id,
                    renamed,
                    "bob",
                )
                .await
                .expect("collect conflicts");

                assert_eq!(conflicts.len(), 1);
                assert_eq!(conflicts[0].path, old_path);
                assert_eq!(conflicts[0].owner, "alice");
            }))
            .await;
        }
    }
}
