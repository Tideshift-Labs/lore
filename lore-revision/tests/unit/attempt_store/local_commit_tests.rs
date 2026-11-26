// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] The journal's local commit evidence: `record_local_commit_child`,
//! `unresolved_local_commits` and `close_parents_without_effect`.
#![allow(clippy::disallowed_methods)] // Isolated temporary journal fixtures only.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use lore_base::types::Hash;
use lore_base::types::RepositoryId;
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_revision::local_commit_evidence::LocalCommitEvidence;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptId;
use lore_transport::AttemptRecord;
use lore_transport::AttemptResolution;
use lore_transport::AttemptState;
use lore_transport::AttemptStore;
use uuid::Uuid;

const COMMIT: &str = "RevisionService.CommitLocal";

fn worktree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".lore")).unwrap();
    dir
}

fn evidence() -> LocalCommitEvidence {
    LocalCommitEvidence {
        branch: Hash::from([1; 32]),
        current: Hash::from([2; 32]),
        branch_latest: Hash::from([3; 32]),
        staged: Hash::from([4; 32]),
        committing: Hash::default(),
    }
}

/// An open parent in a fresh worktree, with the fence that began it.
async fn open_parent(dir: &Path) -> (RepositoryMutationGuard, Arc<RepositoryAttemptStore>, Uuid) {
    let guard = RepositoryMutationGuard::acquire(dir).await.unwrap();
    let parent = Uuid::now_v7();
    let store = guard
        .begin(parent, "commit".into(), "fixture".into())
        .await
        .unwrap();
    (guard, store, parent)
}

async fn local_child(store: &RepositoryAttemptStore, parent: Uuid) -> AttemptId {
    let attempt = AttemptId::new();
    store
        .record_local_commit_child(
            parent,
            attempt,
            COMMIT.into(),
            b"intent".to_vec(),
            evidence(),
        )
        .await
        .unwrap();
    attempt
}

async fn plain_child(store: &RepositoryAttemptStore, parent: Uuid) -> AttemptId {
    let attempt = AttemptId::new();
    store
        .record_workflow_child(
            parent,
            attempt,
            "RevisionService.BranchPush".into(),
            vec![1],
        )
        .await
        .unwrap();
    attempt
}

/// The journal's file for the child `attempt`, wherever its generation put it.
fn child_file(root: &Path, attempt: &AttemptId) -> PathBuf {
    let name = format!("{attempt}.json");
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path.file_name().is_some_and(|found| *found == *name) {
                return path;
            }
        }
    }
    panic!("no journal file for {attempt}");
}

async fn parent_state(store: &RepositoryAttemptStore, parent: Uuid) -> (bool, bool) {
    let parents = store.managed_parents().await.unwrap();
    let parent = parents
        .iter()
        .find(|held| held.id == parent.to_string())
        .unwrap();
    (parent.complete, parent.body_completed)
}

#[tokio::test]
async fn evidence_survives_a_reopen_of_the_journal() {
    let dir = worktree();
    let (guard, store, parent) = open_parent(dir.path()).await;
    let attempt = local_child(&store, parent).await;
    drop(store);
    drop(guard);

    let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    assert_eq!(
        recovery.store().unresolved_local_commits().await.unwrap(),
        vec![(attempt, COMMIT.to_string(), evidence())]
    );
}

/// A child an older build wrote has no `local` member: it loads, and is not a local commit. A
/// child without evidence writes none.
#[tokio::test]
async fn a_child_json_without_local_still_loads() {
    let dir = worktree();
    let (guard, store, parent) = open_parent(dir.path()).await;
    let plain = plain_child(&store, parent).await;
    let local = local_child(&store, parent).await;

    let plain_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(child_file(dir.path(), &plain)).unwrap()).unwrap();
    assert!(plain_json.get("local").is_none(), "{plain_json}");

    let path = child_file(dir.path(), &local);
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(json.get("local").is_some(), "{json}");
    json.as_object_mut().unwrap().remove("local");
    std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    drop(store);
    drop(guard);

    let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    let store = recovery.store();
    let unresolved = store.unresolved().await.unwrap();
    assert_eq!(unresolved.len(), 2);
    assert!(unresolved.iter().any(|record| record.attempt_id == local));
    assert!(store.unresolved_local_commits().await.unwrap().is_empty());
}

/// `record` re-journals a child (here, its settled outcome) without dropping its evidence.
#[tokio::test]
async fn record_keeps_the_evidence_of_an_existing_child() {
    let dir = worktree();
    let (_guard, store, parent) = open_parent(dir.path()).await;
    let attempt = local_child(&store, parent).await;
    let rerecord = |state| AttemptRecord {
        attempt_id: attempt,
        state,
        operation: COMMIT.into(),
        repository: RepositoryId::from([0u8; 16]),
        recorded_at_unix_millis: 42,
        receipt: None,
    };

    store
        .record(&rerecord(AttemptState::Unresolved))
        .await
        .unwrap();
    assert_eq!(
        store.unresolved_local_commits().await.unwrap(),
        vec![(attempt, COMMIT.to_string(), evidence())],
        "an unresolved re-record keeps the evidence"
    );

    store
        .record(&rerecord(AttemptState::Resolved(
            AttemptResolution::NotApplied,
        )))
        .await
        .unwrap();
    assert!(store.unresolved_local_commits().await.unwrap().is_empty());
    // Only a child that still has its evidence lets the parent close as unaffected.
    assert!(store.close_parents_without_effect().await.unwrap());
    assert_eq!(parent_state(&store, parent).await, (true, true));
}

#[tokio::test]
async fn unresolved_local_commits_lists_only_unresolved_local_children() {
    let dir = worktree();
    let (_guard, store, parent) = open_parent(dir.path()).await;
    let open = local_child(&store, parent).await;
    let settled = local_child(&store, parent).await;
    store
        .resolve(&settled, AttemptResolution::NotApplied)
        .await
        .unwrap();
    let _not_local = plain_child(&store, parent).await;

    assert_eq!(
        store.unresolved_local_commits().await.unwrap(),
        vec![(open, COMMIT.to_string(), evidence())]
    );
}

#[tokio::test]
async fn a_parent_whose_only_child_is_a_local_commit_that_did_not_apply_closes() {
    let dir = worktree();
    let (_guard, store, parent) = open_parent(dir.path()).await;
    let attempt = local_child(&store, parent).await;
    assert!(
        !store.close_parents_without_effect().await.unwrap(),
        "an unresolved local child keeps its parent open"
    );
    store
        .resolve(&attempt, AttemptResolution::NotApplied)
        .await
        .unwrap();
    assert!(store.close_parents_without_effect().await.unwrap());
    assert_eq!(parent_state(&store, parent).await, (true, true));
    assert!(
        !store.close_parents_without_effect().await.unwrap(),
        "nothing is left to close"
    );
}

#[tokio::test]
async fn an_applied_local_commit_keeps_its_parent_open() {
    let dir = worktree();
    let (_guard, store, parent) = open_parent(dir.path()).await;
    let attempt = local_child(&store, parent).await;
    store
        .resolve(&attempt, AttemptResolution::Applied)
        .await
        .unwrap();
    assert!(!store.close_parents_without_effect().await.unwrap());
    assert_eq!(parent_state(&store, parent).await, (false, false));
}

#[tokio::test]
async fn an_uncertainty_code_keeps_the_parent_open() {
    let dir = worktree();
    let (_guard, store, parent) = open_parent(dir.path()).await;
    let attempt = local_child(&store, parent).await;
    store
        .resolve(&attempt, AttemptResolution::NotApplied)
        .await
        .unwrap();
    store.mark_parent_uncertain(parent, 249).await.unwrap();
    assert!(!store.close_parents_without_effect().await.unwrap());
    assert_eq!(parent_state(&store, parent).await, (false, false));
}

/// Every child must be settled `NotApplied`: an Applied or an unresolved sibling keeps the parent.
#[tokio::test]
async fn an_applied_or_unresolved_sibling_keeps_the_parent_open() {
    for sibling in [Some(AttemptResolution::Applied), None] {
        let dir = worktree();
        let (_guard, store, parent) = open_parent(dir.path()).await;
        let local = local_child(&store, parent).await;
        store
            .resolve(&local, AttemptResolution::NotApplied)
            .await
            .unwrap();
        let other = plain_child(&store, parent).await;
        if let Some(resolution) = sibling {
            store.resolve(&other, resolution).await.unwrap();
        }
        assert!(
            !store.close_parents_without_effect().await.unwrap(),
            "{sibling:?}"
        );
        assert_eq!(
            parent_state(&store, parent).await,
            (false, false),
            "{sibling:?}"
        );
    }
}

/// A root orphan intent is a claim on a server answer no child settles.
#[tokio::test]
async fn an_orphan_intent_keeps_the_parent_open() {
    let dir = worktree();
    let (_guard, store, parent) = open_parent(dir.path()).await;
    let attempt = local_child(&store, parent).await;
    store
        .resolve(&attempt, AttemptResolution::NotApplied)
        .await
        .unwrap();

    let root = store.path().unwrap().to_path_buf();
    let bytes = std::fs::read(&root).unwrap();
    // Byte 0 is the format version, not part of the JSON body.
    let mut document: serde_json::Value = serde_json::from_slice(&bytes[1..]).unwrap();
    let orphans = document
        .get_mut("managed")
        .and_then(serde_json::Value::as_array_mut)
        .expect("the root has a managed list");
    orphans.push(serde_json::json!({
        "attempt": Uuid::from_u128(7).to_string(),
        "parent": parent.to_string(),
        "rpc": "StorageService.Put",
        "canonical_request": [8, 1],
    }));
    let mut rewritten = vec![bytes[0]];
    rewritten.extend(serde_json::to_vec(&document).unwrap());
    std::fs::write(&root, rewritten).unwrap();

    assert!(!store.close_parents_without_effect().await.unwrap());
    assert_eq!(parent_state(&store, parent).await, (false, false));
}

/// Without a local child there is no evidence that nothing happened: settled non-local children
/// and childless parents are other recovery paths' business.
#[tokio::test]
async fn a_parent_without_a_local_child_stays_open() {
    let dir = worktree();
    let (_guard, store, parent) = open_parent(dir.path()).await;
    assert!(!store.close_parents_without_effect().await.unwrap());
    let plain = plain_child(&store, parent).await;
    store
        .resolve(&plain, AttemptResolution::NotApplied)
        .await
        .unwrap();
    assert!(!store.close_parents_without_effect().await.unwrap());
    assert_eq!(parent_state(&store, parent).await, (false, false));
}
