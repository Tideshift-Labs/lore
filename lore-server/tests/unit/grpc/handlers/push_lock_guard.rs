// Copyright 2026 Khurram Virani
// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_postgres::domain::locks::VerifiedLockOwner;
use lore_revision::branch;
use lore_revision::lock::LockStore;
use lore_revision::lock::util::assemble_resource_for_path;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::node::Node;
use lore_revision::node::NodeFlags;
use lore_revision::node::ROOT_NODE;
use lore_revision::repository::RepositoryContext;
use lore_revision::state;
use lore_server::grpc::get_write_token;
use lore_server::grpc::handlers::branch_push;
use lore_server::grpc::handlers::push_lock_guard::*;
use lore_server::lock::store::LocalLockStore;
use lore_storage::hash::hash_string;
use rand::random;

use crate::store::test_support::test_store_create;

/// The issuer this cell's verifier is configured to accept.
const ISSUER_A: &str = "https://issuer-a.example";
/// A second issuer the same cell would accept with no issuer policy set.
const ISSUER_B: &str = "https://issuer-b.example";

fn owner(issuer: &str, subject: &str) -> VerifiedLockOwner {
    VerifiedLockOwner {
        verified_issuer: issuer.to_owned(),
        authenticated_subject: subject.to_owned(),
    }
}

fn pinned() -> LockOwnerIssuerPolicy {
    LockOwnerIssuerPolicy::Pinned(ISSUER_A.to_owned())
}

/// FORK-LOCAL (Tideshift, merge decision D3): `jwt_issuer` became a list
/// at v0.10.0. Only exactly one non-empty issuer pins; none, an empty
/// string, or a two-issuer cutover list is unprovable (fail closed).
#[test]
fn issuer_policy_pins_only_exactly_one_non_empty_issuer() {
    let one = vec![ISSUER_A.to_owned()];
    assert_eq!(
        LockOwnerIssuerPolicy::from_configured_issuers(Some(one.as_slice())),
        pinned()
    );
    let two = vec![ISSUER_A.to_owned(), ISSUER_B.to_owned()];
    let empty_entry = vec![String::new()];
    let none: Vec<String> = Vec::new();
    for issuers in [
        Some(two.as_slice()),
        Some(empty_entry.as_slice()),
        Some(none.as_slice()),
        None,
    ] {
        assert_eq!(
            LockOwnerIssuerPolicy::from_configured_issuers(issuers),
            LockOwnerIssuerPolicy::Unprovable,
            "{issuers:?}"
        );
    }
}

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
        lore_server::grpc::server::RevisionListAcceleration::default(),
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
    let others = others_locks_by_hash(
        &lock_store,
        repository,
        branch,
        &owner(ISSUER_A, "bob"),
        &pinned(),
    )
    .await
    .expect("query others' locks");
    let expected_hash = assemble_resource_for_path(path, branch).hash;
    assert_eq!(
        others.get(&expected_hash).map(String::as_str),
        Some("alice")
    );

    // The lock holder (alice) pushing her own change sees no foreign lock.
    let self_view = others_locks_by_hash(
        &lock_store,
        repository,
        branch,
        &owner(ISSUER_A, "alice"),
        &pinned(),
    )
    .await
    .expect("query self locks");
    assert!(
        self_view.is_empty(),
        "a pusher's own lock must not block their push"
    );
}

/// CR-030's named fail-open regression: the guard compared bare subjects,
/// so `mallory` authenticated by issuer B counted as the owner of a lock
/// `mallory` acquired under issuer A, and pushed straight over it.
#[tokio::test]
async fn same_subject_under_a_different_issuer_stays_foreign() {
    let repository: RepositoryId = random();
    let branch: BranchId = random();
    let path = "Art/Hero.uasset";
    let lock_store = store_with_lock("mallory", path, branch, repository).await;
    let expected_hash = assemble_resource_for_path(path, branch).hash;

    let foreign_issuer = others_locks_by_hash(
        &lock_store,
        repository,
        branch,
        &owner(ISSUER_B, "mallory"),
        &pinned(),
    )
    .await
    .expect("query with a foreign issuer");
    assert_eq!(
        foreign_issuer.get(&expected_hash).map(String::as_str),
        Some("mallory"),
        "the same subject under another issuer is another owner, not the lock holder"
    );

    // The genuine holder, under the pinned issuer, still owns it.
    let holder = others_locks_by_hash(
        &lock_store,
        repository,
        branch,
        &owner(ISSUER_A, "mallory"),
        &pinned(),
    )
    .await
    .expect("query as the genuine holder");
    assert!(holder.is_empty());
}

/// With no issuer policy the cell accepts any issuer its JWK service can
/// verify, so a stored subject proves nothing. Fail closed: every lock on
/// a changed path blocks, including one the pusher believes is their own.
#[tokio::test]
async fn an_unprovable_issuer_policy_leaves_every_lock_foreign() {
    let repository: RepositoryId = random();
    let branch: BranchId = random();
    let path = "Art/Hero.uasset";
    let lock_store = store_with_lock("alice", path, branch, repository).await;

    let view = others_locks_by_hash(
        &lock_store,
        repository,
        branch,
        &owner(ISSUER_A, "alice"),
        &LockOwnerIssuerPolicy::Unprovable,
    )
    .await
    .expect("query without an issuer policy");
    assert_eq!(
        view.get(&assemble_resource_for_path(path, branch).hash)
            .map(String::as_str),
        Some("alice"),
        "an unprovable owner pair must not be read as the pusher's own lock"
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
    let on_other = others_locks_by_hash(
        &lock_store,
        repository,
        other_branch,
        &owner(ISSUER_A, "bob"),
        &pinned(),
    )
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
                &owner(ISSUER_A, "bob"),
                &pinned(),
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
                &owner(ISSUER_A, "alice"),
                &pinned(),
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
                &owner(ISSUER_A, "bob"),
                &pinned(),
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
            let new_revision = serialize_file_revision(&repository, root, 2, "hero.uasset").await;

            let conflicts = collect_push_lock_conflicts(
                repository.clone(),
                &lock_store,
                repository_id,
                branch_id,
                new_revision,
                &owner(ISSUER_A, "bob"),
                &pinned(),
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
                &owner(ISSUER_A, "bob"),
                &pinned(),
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

            let renamed =
                serialize_file_revision_with_context(&repository, root, 2, new_path, file_context)
                    .await;

            let conflicts = collect_push_lock_conflicts(
                repository.clone(),
                &lock_store,
                repository_id,
                branch_id,
                renamed,
                &owner(ISSUER_A, "bob"),
                &pinned(),
            )
            .await
            .expect("collect conflicts");

            assert_eq!(conflicts.len(), 1);
            assert_eq!(conflicts[0].path, old_path);
            assert_eq!(conflicts[0].owner, "alice");
        }))
        .await;
    }

    /// The same discriminating case, end to end through the handler seam:
    /// `mallory` under issuer B must not push over the lock `mallory`
    /// acquired under issuer A, and the genuine holder still may.
    #[tokio::test]
    async fn same_subject_under_a_different_issuer_cannot_push_over_the_lock() {
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
            let lock_store = store_with_lock("mallory", path, branch_id, repository_id).await;
            let new_revision = serialize_file_revision(&repository, root, 2, path).await;

            let foreign = collect_push_lock_conflicts(
                repository.clone(),
                &lock_store,
                repository_id,
                branch_id,
                new_revision,
                &owner(ISSUER_B, "mallory"),
                &pinned(),
            )
            .await
            .expect("collect conflicts");
            assert_eq!(foreign.len(), 1);
            assert_eq!(foreign[0].path, path);

            let holder = collect_push_lock_conflicts(
                repository.clone(),
                &lock_store,
                repository_id,
                branch_id,
                new_revision,
                &owner(ISSUER_A, "mallory"),
                &pinned(),
            )
            .await
            .expect("collect conflicts");
            assert!(
                holder.is_empty(),
                "the genuine holder must still push over their own lock"
            );
        }))
        .await;
    }
}
