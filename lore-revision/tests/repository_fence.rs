// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] Durable same-worktree admission, including separate process lifetimes.
#![allow(clippy::disallowed_methods)] // Only this suite's temp directories and child processes.

use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use lore_base::types::RepositoryId;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptId;
use lore_transport::AttemptRecord;
use lore_transport::AttemptResolution;
use lore_transport::AttemptState;
use lore_transport::AttemptStore;
use lore_transport::caller_operation::ManagedAttemptIntent;
use uuid::Uuid;

fn worktree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".lore")).unwrap();
    dir
}

#[tokio::test]
async fn recovery_exposes_existing_legacy_journals_without_creating_missing_directories() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".urc")).unwrap();
    let legacy =
        lore_revision::attempt_store::RepositoryAttemptStore::in_directory(dir.path().join(".urc"));
    let (child, _) = record(Uuid::now_v7());
    legacy.record(&child).await.unwrap();
    assert!(RepositoryMutationGuard::acquire(dir.path()).await.is_err());
    let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    let stores = recovery.recovery_stores();
    assert_eq!(
        stores.iter().map(|(source, _)| *source).collect::<Vec<_>>(),
        vec![".lore-workflow", ".urc"]
    );
    assert!(stores[0].1.unresolved().await.unwrap().is_empty());
    assert_eq!(stores[1].1.unresolved().await.unwrap(), vec![child]);
    assert!(!dir.path().join(".lore").exists());
    // Recovery owns the same admission lock, including while inspecting a legacy store.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            RepositoryMutationGuard::recover(dir.path())
        )
        .await
        .is_err()
    );
    drop(stores);
    drop(recovery);
    tokio::time::timeout(
        Duration::from_secs(3),
        RepositoryMutationGuard::recover(dir.path()),
    )
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test]
async fn settled_children_cannot_clear_missing_body_proof_or_explicit_parent_uncertainty() {
    for uncertain in [false, true] {
        let dir = worktree();
        let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
        let parent = Uuid::now_v7();
        let store = guard
            .begin(parent, "push".into(), "branch".into())
            .await
            .unwrap();
        let (child, intent) = record(parent);
        store.record_managed(&child, &intent).await.unwrap();
        store
            .resolve(&child.attempt_id, AttemptResolution::Applied)
            .await
            .unwrap();
        if uncertain {
            store.mark_parent_uncertain(parent, 249).await.unwrap();
            assert!(store.complete_parent_body(parent).await.is_err());
        }
        drop(store);
        drop(guard);
        let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
        let reopened = recovery.store();
        assert!(reopened.unresolved().await.unwrap().is_empty());
        assert!(reopened.reconcile_parent(parent).await.is_err());
        assert!(recovery.finish(parent).await.is_err());
        let parents = reopened.managed_parents().await.unwrap();
        assert_eq!(parents.len(), 1);
        assert!(!parents[0].complete);
        assert!(!parents[0].body_completed);
        assert_eq!(parents[0].parent_uncertainty_code, uncertain.then_some(249));
        drop(recovery);
        assert!(RepositoryMutationGuard::acquire(dir.path()).await.is_err());
    }
}

#[tokio::test]
async fn preinit_parent_keeps_the_same_journal_after_repository_creation() {
    let dir = tempfile::tempdir().unwrap();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(parent, "clone".into(), "destination".into())
        .await
        .unwrap();
    // A pending child keeps the parent open; a childless crashed parent is now closed instead.
    let pending = AttemptId::new();
    store
        .record_workflow_child(
            parent,
            pending,
            "RevisionService.BranchPush".into(),
            b"nonsecret intent".to_vec(),
        )
        .await
        .unwrap();
    let path = store.path().unwrap().to_path_buf();
    assert_eq!(
        path.parent().unwrap(),
        std::fs::canonicalize(dir.path())
            .unwrap()
            .join(".lore-workflow")
    );
    assert!(!dir.path().join(".lore").exists());
    std::fs::create_dir(dir.path().join(".lore")).unwrap();
    drop(store);
    drop(guard);
    assert!(RepositoryMutationGuard::acquire(dir.path()).await.is_err());
    let recovered = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    assert_eq!(recovered.store().path().unwrap(), path);
    assert_eq!(
        recovered.store().managed_parents().await.unwrap()[0].id,
        parent.to_string()
    );
    recovered
        .store()
        .resolve(&pending, AttemptResolution::Applied)
        .await
        .unwrap();
    recovered
        .store()
        .complete_parent_body(parent)
        .await
        .unwrap();
    recovered.finish(parent).await.unwrap();
    drop(recovered);
    RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
}

#[tokio::test]
async fn lexical_alias_nested_admission_shares_the_canonical_root() {
    let dir = worktree();
    std::fs::create_dir(dir.path().join("child")).unwrap();
    let alias = dir.path().join("child").join("..");
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let parent = Uuid::now_v7();
    guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        guard.run(async {
            let nested = RepositoryMutationGuard::acquire(&alias).await.unwrap();
            assert_eq!(nested.store().path(), guard.store().path());
            assert_eq!(
                nested.store().managed_parents().await.unwrap()[0].id,
                parent.to_string()
            );
        }),
    )
    .await
    .expect("canonical alias must reuse admission");
    guard.store().complete_parent_body(parent).await.unwrap();
    guard.finish(parent).await.unwrap();
}

#[test]
fn workflow_path_detection_uses_complete_components_for_both_separators() {
    for path in [
        ".lore-workflow",
        ".lore-workflow/journal",
        "dir/.LORE-WORKFLOW/journal",
        "dir\\.lore-workflow\\journal",
    ] {
        assert!(
            lore_revision::repository_fence::is_workflow_path(path),
            "{path}"
        );
    }
    for path in [
        ".lore-workflow-backup/journal",
        "dir/my.lore-workflow",
        "workflow/journal",
    ] {
        assert!(
            !lore_revision::repository_fence::is_workflow_path(path),
            "{path}"
        );
    }
}

/// A generic journaled child. `MutableStore` stays journaled; a fragment `Put`, `Copy` and
/// `PutResolved` no longer are, so none of them is the vehicle for the generic journal properties
/// below.
fn record(parent: Uuid) -> (AttemptRecord, ManagedAttemptIntent) {
    record_for(parent, "StorageService.MutableStore")
}

/// The child an older build wrote for every fragment Put in a managed operation.
fn legacy_put_record(parent: Uuid) -> (AttemptRecord, ManagedAttemptIntent) {
    record_for(parent, "StorageService.Put")
}

/// Every storage write an older build journaled and this one no longer does.
const LEGACY_UNJOURNALED: [&str; 3] = [
    "StorageService.Put",
    "StorageService.Copy",
    "StorageService.PutResolved",
];

fn record_for(parent: Uuid, rpc: &str) -> (AttemptRecord, ManagedAttemptIntent) {
    let repository = RepositoryId::from([1; 16]);
    let rpc = rpc.to_owned();
    (
        AttemptRecord {
            attempt_id: AttemptId::new(),
            state: AttemptState::Unresolved,
            operation: rpc.clone(),
            repository,
            recorded_at_unix_millis: 1,
            receipt: None,
        },
        ManagedAttemptIntent {
            version: 1,
            parent_id: parent,
            repository,
            rpc,
            canonical_request: vec![8, 1],
            endpoint: "https://fixture.invalid/".into(),
            verified_issuer: "https://fixture.invalid/issuer".into(),
            authenticated_subject: "alice".into(),
            caller_capabilities: "outcome_unknown_v1".into(),
        },
    )
}

/// Journals written before fragment Puts stopped being journaled can hold unresolved `Put`
/// children. They must still load (read with `recover`, before any acquire). The next plain
/// acquire settles the Put `NotApplied` with no receipt read and closes the parent, because a
/// parent whose only children are settled Puts moved nothing and is owed no answer.
#[tokio::test]
async fn an_older_builds_lone_put_child_still_loads_then_acquire_settles_and_closes_it() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let (child, intent) = legacy_put_record(parent);
    store.record_managed(&child, &intent).await.unwrap();
    store.complete_parent_body(parent).await.unwrap();
    assert!(guard.finish(parent).await.is_err(), "unresolved child");
    drop(store);
    drop(guard);

    // The old journal loads under `recover`, which settles nothing, so the Put is still listed.
    let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    let store = recovery.store();
    for parents in [
        store.managed_parents().await.unwrap(),
        store.admission_parents().await.unwrap(),
    ] {
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].id, parent.to_string());
        assert!(parents[0].body_completed);
        assert!(!parents[0].complete);
    }
    assert_eq!(store.unresolved().await.unwrap(), vec![child.clone()]);
    assert_eq!(
        store.unresolved().await.unwrap()[0].operation,
        "StorageService.Put"
    );
    store
        .recovery_context(&child.attempt_id)
        .await
        .expect("the recorded namespace survives for the operator");
    drop(store);
    drop(recovery);

    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard.store();
    assert!(store.unresolved().await.unwrap().is_empty());
    assert_eq!(
        store
            .lookup(&child.attempt_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        AttemptState::Resolved(AttemptResolution::NotApplied)
    );
    assert!(store.managed_parents().await.unwrap()[0].complete);
    guard
        .begin(Uuid::now_v7(), "push".into(), "branch".into())
        .await
        .unwrap();
}

/// A Put-only parent whose body never completed (a crash mid-upload in an old build) closes too.
#[tokio::test]
async fn put_only_parent_with_an_unfinished_body_is_closed_by_acquire() {
    for settled in [false, true] {
        let dir = worktree();
        let parent = Uuid::now_v7();
        let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
        let store = guard
            .begin(parent, "push".into(), "branch".into())
            .await
            .unwrap();
        let (put, intent) = legacy_put_record(parent);
        store.record_managed(&put, &intent).await.unwrap();
        if settled {
            store
                .resolve(&put.attempt_id, AttemptResolution::Applied)
                .await
                .unwrap();
        }
        drop(store);
        drop(guard);

        let guard = RepositoryMutationGuard::acquire(dir.path())
            .await
            .unwrap_or_else(|error| panic!("settled={settled}: {error}"));
        let parents = guard.store().managed_parents().await.unwrap();
        assert!(
            parents[0].complete && parents[0].body_completed,
            "{settled}"
        );
        assert!(guard.store().unresolved().await.unwrap().is_empty());
    }
}

/// A Put beside an unresolved `BranchPush`: the Put settles but the parent still waits on the
/// push receipt, so acquire refuses.
#[tokio::test]
async fn put_beside_an_unresolved_branch_push_settles_the_put_but_still_blocks() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let (put, put_intent) = legacy_put_record(parent);
    store.record_managed(&put, &put_intent).await.unwrap();
    let (push, push_intent) = record_for(parent, "RevisionService.BranchPush");
    store.record_managed(&push, &push_intent).await.unwrap();
    store.complete_parent_body(parent).await.unwrap();
    drop(store);
    drop(guard);

    assert!(RepositoryMutationGuard::acquire(dir.path()).await.is_err());
    let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    let store = recovery.store();
    assert_eq!(store.unresolved().await.unwrap(), vec![push]);
    assert_eq!(
        store.lookup(&put.attempt_id).await.unwrap().unwrap().state,
        AttemptState::Resolved(AttemptResolution::NotApplied)
    );
    assert!(!store.managed_parents().await.unwrap()[0].complete);
}

/// A Put plus a settled non-Put child with the body unfinished is a partial composite: the
/// settled child is evidence something may have happened, so acquire refuses.
#[tokio::test]
async fn put_beside_a_settled_non_put_child_with_no_body_proof_still_blocks() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let (put, put_intent) = legacy_put_record(parent);
    store.record_managed(&put, &put_intent).await.unwrap();
    let local = AttemptId::new();
    store
        .record_workflow_child(parent, local, "local commit".into(), b"intent".to_vec())
        .await
        .unwrap();
    store
        .resolve(&local, AttemptResolution::Applied)
        .await
        .unwrap();
    drop(store);
    drop(guard);

    assert!(RepositoryMutationGuard::acquire(dir.path()).await.is_err());
    let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    let parents = recovery.store().managed_parents().await.unwrap();
    assert!(!parents[0].complete);
    assert!(!parents[0].body_completed);
}

/// Copy and `PutResolved` stopped being journaled after Put did. An older build's unresolved child
/// of any of the three settles `NotApplied` at the next acquire with no receipt read, and a parent
/// whose only children are such settled writes closes.
#[tokio::test]
async fn an_older_builds_lone_unjournaled_write_child_is_settled_and_closed_by_acquire() {
    for rpc in LEGACY_UNJOURNALED {
        for body_completed in [false, true] {
            let dir = worktree();
            let parent = Uuid::now_v7();
            let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
            let store = guard
                .begin(parent, "push".into(), "branch".into())
                .await
                .unwrap();
            let (child, intent) = record_for(parent, rpc);
            store.record_managed(&child, &intent).await.unwrap();
            if body_completed {
                store.complete_parent_body(parent).await.unwrap();
            }
            drop(store);
            drop(guard);

            // `recover` settles nothing, so the old journal still lists the child.
            let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
            assert_eq!(
                recovery.store().unresolved().await.unwrap(),
                vec![child.clone()],
                "{rpc} body_completed={body_completed}"
            );
            drop(recovery);

            let guard = RepositoryMutationGuard::acquire(dir.path())
                .await
                .unwrap_or_else(|error| panic!("{rpc} body_completed={body_completed}: {error}"));
            let store = guard.store();
            assert!(store.unresolved().await.unwrap().is_empty(), "{rpc}");
            assert_eq!(
                store
                    .lookup(&child.attempt_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .state,
                AttemptState::Resolved(AttemptResolution::NotApplied),
                "{rpc} body_completed={body_completed}"
            );
            let parents = store.managed_parents().await.unwrap();
            assert!(
                parents[0].complete && parents[0].body_completed,
                "{rpc} body_completed={body_completed}"
            );
            guard
                .begin(Uuid::now_v7(), "push".into(), "branch".into())
                .await
                .unwrap();
        }
    }
}

/// One parent holding an unresolved child of each legacy write closes together.
#[tokio::test]
async fn a_parent_of_mixed_legacy_put_copy_and_put_resolved_children_closes() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let mut children = Vec::new();
    for rpc in LEGACY_UNJOURNALED {
        let (child, intent) = record_for(parent, rpc);
        store.record_managed(&child, &intent).await.unwrap();
        children.push(child);
    }
    drop(store);
    drop(guard);

    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    for child in &children {
        assert_eq!(
            guard
                .store()
                .lookup(&child.attempt_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            AttemptState::Resolved(AttemptResolution::NotApplied),
            "{}",
            child.operation
        );
    }
    assert!(guard.store().managed_parents().await.unwrap()[0].complete);
}

/// A legacy Copy or `PutResolved` beside an unresolved `BranchPush`: the write settles but the
/// parent still waits on the push receipt, so acquire refuses.
#[tokio::test]
async fn legacy_copy_or_put_resolved_beside_an_unresolved_branch_push_settles_but_still_blocks() {
    for rpc in ["StorageService.Copy", "StorageService.PutResolved"] {
        let dir = worktree();
        let parent = Uuid::now_v7();
        let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
        let store = guard
            .begin(parent, "push".into(), "branch".into())
            .await
            .unwrap();
        let (write, write_intent) = record_for(parent, rpc);
        store.record_managed(&write, &write_intent).await.unwrap();
        let (push, push_intent) = record_for(parent, "RevisionService.BranchPush");
        store.record_managed(&push, &push_intent).await.unwrap();
        store.complete_parent_body(parent).await.unwrap();
        drop(store);
        drop(guard);

        assert!(
            RepositoryMutationGuard::acquire(dir.path()).await.is_err(),
            "{rpc}"
        );
        let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
        let store = recovery.store();
        assert_eq!(store.unresolved().await.unwrap(), vec![push], "{rpc}");
        assert_eq!(
            store
                .lookup(&write.attempt_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            AttemptState::Resolved(AttemptResolution::NotApplied),
            "{rpc}"
        );
        assert!(!store.managed_parents().await.unwrap()[0].complete, "{rpc}");
    }
}

/// A legacy Copy or `PutResolved` plus a settled non-write child with the body unfinished is a
/// partial composite: the settled child is evidence something may have happened.
#[tokio::test]
async fn legacy_copy_or_put_resolved_beside_a_settled_other_child_with_no_body_proof_still_blocks()
{
    for rpc in ["StorageService.Copy", "StorageService.PutResolved"] {
        let dir = worktree();
        let parent = Uuid::now_v7();
        let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
        let store = guard
            .begin(parent, "push".into(), "branch".into())
            .await
            .unwrap();
        let (write, write_intent) = record_for(parent, rpc);
        store.record_managed(&write, &write_intent).await.unwrap();
        let (other, other_intent) = record(parent);
        store.record_managed(&other, &other_intent).await.unwrap();
        store
            .resolve(&other.attempt_id, AttemptResolution::Applied)
            .await
            .unwrap();
        drop(store);
        drop(guard);

        assert!(
            RepositoryMutationGuard::acquire(dir.path()).await.is_err(),
            "{rpc}"
        );
        let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
        let parents = recovery.store().managed_parents().await.unwrap();
        assert!(!parents[0].complete, "{rpc}");
        assert!(!parents[0].body_completed, "{rpc}");
    }
}

/// A journaled child that merely resembles a legacy write is not one: it keeps its claim.
#[tokio::test]
async fn a_near_miss_rpc_name_is_not_settled_as_a_legacy_write() {
    for rpc in [
        "StorageService.Copy2",
        "StorageService.PutResolve",
        "StorageService.Verify",
    ] {
        let dir = worktree();
        let parent = Uuid::now_v7();
        let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
        let store = guard
            .begin(parent, "push".into(), "branch".into())
            .await
            .unwrap();
        let (child, intent) = record_for(parent, rpc);
        store.record_managed(&child, &intent).await.unwrap();
        store.complete_parent_body(parent).await.unwrap();
        drop(store);
        drop(guard);

        assert!(
            RepositoryMutationGuard::acquire(dir.path()).await.is_err(),
            "{rpc}"
        );
        let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
        assert_eq!(
            recovery.store().unresolved().await.unwrap(),
            vec![child],
            "{rpc}"
        );
    }
}

/// `finish_parent` prunes and re-validates settled history; a journal full of settled old `Put`
/// children must neither fail that nor stop the next parent from starting.
#[tokio::test]
async fn settled_old_put_children_do_not_break_finish_or_the_next_parent() {
    let dir = worktree();
    for round in 0..3 {
        let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
        let parent = Uuid::now_v7();
        let store = guard
            .begin(parent, "push".into(), "branch".into())
            .await
            .unwrap();
        for _ in 0..4 {
            let (child, intent) = legacy_put_record(parent);
            store.record_managed(&child, &intent).await.unwrap();
            store
                .resolve(&child.attempt_id, AttemptResolution::NotApplied)
                .await
                .unwrap();
        }
        let (copy, intent) = record(parent);
        store.record_managed(&copy, &intent).await.unwrap();
        store
            .resolve(&copy.attempt_id, AttemptResolution::Applied)
            .await
            .unwrap();
        store.complete_parent_body(parent).await.unwrap();
        guard.finish(parent).await.unwrap();
        assert!(
            store
                .managed_parents()
                .await
                .unwrap()
                .iter()
                .all(|p| p.complete),
            "round {round}"
        );
        assert!(store.unresolved().await.unwrap().is_empty());
        drop(store);
        drop(guard);
    }
    RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
}

#[tokio::test]
async fn non_rpc_workflow_child_survives_reopen_and_requires_a_positive_settlement() {
    let dir = tempfile::tempdir().unwrap();
    let parent = Uuid::now_v7();
    let child = AttemptId::new();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(parent, "create remote".into(), "repository".into())
        .await
        .unwrap();
    assert!(
        store.reconcile_parent(parent).await.is_err(),
        "absence of children is not proof of completion"
    );
    store
        .record_workflow_child(
            parent,
            child,
            "platform repository create".into(),
            b"nonsecret intent".to_vec(),
        )
        .await
        .unwrap();
    assert!(
        store
            .record_workflow_child(parent, child, "duplicate".into(), vec![])
            .await
            .is_err()
    );
    drop(store);
    drop(guard);
    assert!(RepositoryMutationGuard::acquire(dir.path()).await.is_err());
    let recovered = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    let store = recovered.store();
    let pending = store.unresolved().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].attempt_id, child);
    assert_eq!(pending[0].operation, "platform repository create");
    assert!(store.reconcile_parent(parent).await.is_err());
    store
        .resolve(&child, AttemptResolution::Applied)
        .await
        .unwrap();
    assert!(store.reconcile_parent(parent).await.is_err());
    store.complete_parent_body(parent).await.unwrap();
    store.reconcile_parent(parent).await.unwrap();
    drop(store);
    drop(recovered);
    RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
}

#[tokio::test]
async fn prebound_namespace_survives_reopen_and_rejects_each_changed_identity_field() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let (_, intent) = record(parent);
    let binding = lore_transport::CallerRecoveryContext {
        repository: intent.repository,
        endpoint: intent.endpoint.clone(),
        verified_issuer: intent.verified_issuer.clone(),
        authenticated_subject: intent.authenticated_subject.clone(),
        caller_capabilities: intent.caller_capabilities.clone(),
    };
    store.bind_parent_namespace(parent, &binding).await.unwrap();
    drop(store);
    drop(guard);
    let recovered = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    let store = recovered.store();
    store.bind_parent_namespace(parent, &binding).await.unwrap();
    for field in 0..5 {
        let mut changed = binding.clone();
        match field {
            0 => changed.repository = RepositoryId::from([2; 16]),
            1 => changed.endpoint.push_str("other"),
            2 => changed.verified_issuer.push_str("other"),
            3 => changed.authenticated_subject.push_str("other"),
            4 => changed.caller_capabilities.push_str("other"),
            _ => unreachable!(),
        }
        assert!(
            store.bind_parent_namespace(parent, &changed).await.is_err(),
            "field {field}"
        );
        assert!(store.unresolved().await.unwrap().is_empty());
        store.bind_parent_namespace(parent, &binding).await.unwrap();
    }
    let (child, mut changed_intent) = record(parent);
    changed_intent.authenticated_subject = "different subject".into();
    assert!(store.record_managed(&child, &changed_intent).await.is_err());
    assert!(store.lookup(&child.attempt_id).await.unwrap().is_none());
    store.record_managed(&child, &intent).await.unwrap();
    assert_eq!(
        store.recovery_context(&child.attempt_id).await.unwrap(),
        binding
    );
}

#[tokio::test]
async fn unresolved_parent_survives_reopen_and_other_worktrees_remain_independent() {
    let dir = worktree();
    let other = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(parent, "desktop commit".into(), "selected paths".into())
        .await
        .unwrap();
    store
        .record_workflow_child(
            parent,
            AttemptId::new(),
            "RevisionService.BranchPush".into(),
            b"nonsecret intent".to_vec(),
        )
        .await
        .unwrap();
    drop(store);
    drop(guard);
    assert!(RepositoryMutationGuard::acquire(dir.path()).await.is_err());
    let independent = RepositoryMutationGuard::acquire(other.path())
        .await
        .unwrap();
    drop(independent);
    let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    let parents = recovery.store().managed_parents().await.unwrap();
    assert_eq!(parents.len(), 1);
    assert_eq!(parents[0].id, parent.to_string());
    assert!(!parents[0].complete);
}

#[tokio::test]
async fn same_parent_nested_calls_do_not_reacquire_the_process_lock() {
    let dir = worktree();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let parent = Uuid::now_v7();
    guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        guard.run(async {
            let nested = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
            assert_eq!(nested.store().managed_parents().await.unwrap().len(), 1);
        }),
    )
    .await
    .expect("nested admission must not deadlock");
    guard.store().complete_parent_body(parent).await.unwrap();
    guard.finish(parent).await.unwrap();
    drop(guard);
    RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
}

#[tokio::test]
async fn managed_child_reopens_with_exact_namespace_and_blocks_finish_until_resolved() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let (child, intent) = record(parent);
    store.record_managed(&child, &intent).await.unwrap();
    assert!(guard.finish(parent).await.is_err());
    drop(store);
    drop(guard);
    let reopened = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    assert_eq!(
        reopened.store().lookup(&child.attempt_id).await.unwrap(),
        Some(child.clone())
    );
    let namespace = reopened
        .store()
        .recovery_context(&child.attempt_id)
        .await
        .unwrap();
    assert_eq!(namespace.repository, intent.repository);
    assert_eq!(namespace.endpoint, intent.endpoint);
    assert_eq!(namespace.verified_issuer, intent.verified_issuer);
    assert_eq!(
        namespace.authenticated_subject,
        intent.authenticated_subject
    );
    reopened
        .store()
        .resolve(&child.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    assert!(reopened.finish(parent).await.is_err());
    reopened.store().complete_parent_body(parent).await.unwrap();
    reopened.finish(parent).await.unwrap();
    drop(reopened);
    RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
}

#[tokio::test]
async fn reconstructed_parent_refuses_changed_namespace_without_adding_a_child() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let (first, intent) = record(parent);
    store.record_managed(&first, &intent).await.unwrap();
    drop(store);
    drop(guard);
    let reopened = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    let (second, mut changed) = record(parent);
    changed.authenticated_subject = "bob".into();
    assert!(
        reopened
            .store()
            .record_managed(&second, &changed)
            .await
            .is_err()
    );
    assert!(
        reopened
            .store()
            .lookup(&second.attempt_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(reopened.store().unresolved().await.unwrap(), vec![first]);
}

#[tokio::test]
async fn corrupt_journal_is_preserved_and_refuses_new_admission() {
    let dir = worktree();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(Uuid::now_v7(), "commit".into(), "paths".into())
        .await
        .unwrap();
    let path = store.path().unwrap().to_path_buf();
    drop(store);
    drop(guard);
    for bytes in [vec![], vec![255, b'{', b'}'], vec![1, b'{']] {
        std::fs::write(&path, &bytes).unwrap();
        assert!(RepositoryMutationGuard::acquire(dir.path()).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

/// Crash right after `begin`: no child was recorded, so nothing was dispatched and the parent
/// has nothing to reconcile. The next acquire settles it instead of blocking.
#[tokio::test]
async fn childless_parent_after_a_crash_is_closed_by_the_next_acquire() {
    for bound in [false, true] {
        let dir = worktree();
        let parent = Uuid::now_v7();
        let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
        let store = guard
            .begin(parent, "push".into(), "branch".into())
            .await
            .unwrap();
        if bound {
            let (_, intent) = record(parent);
            let binding = lore_transport::CallerRecoveryContext {
                repository: intent.repository,
                endpoint: intent.endpoint.clone(),
                verified_issuer: intent.verified_issuer.clone(),
                authenticated_subject: intent.authenticated_subject.clone(),
                caller_capabilities: intent.caller_capabilities.clone(),
            };
            store.bind_parent_namespace(parent, &binding).await.unwrap();
        }
        drop(store);
        drop(guard);

        let guard = RepositoryMutationGuard::acquire(dir.path())
            .await
            .unwrap_or_else(|error| panic!("bound={bound}: {error}"));
        let parents = guard.store().managed_parents().await.unwrap();
        assert_eq!(parents.len(), 1, "bound={bound}");
        assert!(parents[0].complete, "bound={bound}");
        assert!(parents[0].body_completed, "bound={bound}");
        guard
            .begin(Uuid::now_v7(), "push".into(), "branch".into())
            .await
            .unwrap_or_else(|error| panic!("bound={bound}: {error}"));
    }
}

/// A partial composite: a settled child but the body never finished. Neither acquire nor
/// `settle_receiptless` may close it.
#[tokio::test]
async fn parent_with_a_settled_child_and_no_body_proof_is_not_closed() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let (child, intent) = record(parent);
    store.record_managed(&child, &intent).await.unwrap();
    store
        .resolve(&child.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    drop(store);
    drop(guard);

    assert!(RepositoryMutationGuard::acquire(dir.path()).await.is_err());
    let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    assert!(!recovery.store().settle_receiptless().await.unwrap());
    let parents = recovery.store().managed_parents().await.unwrap();
    assert!(!parents[0].complete);
    assert!(!parents[0].body_completed);
    drop(recovery);
    assert!(RepositoryMutationGuard::acquire(dir.path()).await.is_err());
}

/// A childless parent flagged uncertain is not proof of "nothing dispatched"; it stays blocked.
#[tokio::test]
async fn childless_parent_with_an_uncertainty_code_still_blocks_acquire() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let store = guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    store.mark_parent_uncertain(parent, 249).await.unwrap();
    drop(store);
    drop(guard);

    assert!(RepositoryMutationGuard::acquire(dir.path()).await.is_err());
    let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    assert!(!recovery.store().settle_receiptless().await.unwrap());
    let parents = recovery.store().managed_parents().await.unwrap();
    assert!(!parents[0].complete);
    assert_eq!(parents[0].parent_uncertainty_code, Some(249));
}

/// The legacy `.lore` and `.urc` stores get the same settlement at acquire.
#[tokio::test]
async fn childless_parent_in_a_legacy_store_is_closed_by_acquire() {
    for source in [".lore", ".urc"] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(source)).unwrap();
        let legacy = lore_revision::attempt_store::RepositoryAttemptStore::in_directory(
            dir.path().join(source),
        );
        let parent = Uuid::now_v7();
        legacy
            .begin_parent(lore_revision::attempt_store::ManagedParent {
                version: 1,
                id: parent.to_string(),
                root: "fixture".into(),
                operation: "push".into(),
                normalized_intent: "fixture".into(),
                namespace: None,
                complete: false,
                parent_uncertainty_code: None,
                body_completed: false,
            })
            .await
            .unwrap();
        assert!(!legacy.managed_parents().await.unwrap()[0].complete);

        RepositoryMutationGuard::acquire(dir.path())
            .await
            .unwrap_or_else(|error| panic!("{source}: {error}"));
        let parents = legacy.managed_parents().await.unwrap();
        assert!(parents[0].complete, "{source}");
        assert!(parents[0].body_completed, "{source}");
    }
}

/// Ids of the parents still open in the workflow journal, read without taking the lock.
fn open_parents(root: &Path) -> Vec<(String, bool)> {
    let bytes = std::fs::read(
        std::fs::canonicalize(root)
            .unwrap()
            .join(".lore-workflow")
            .join("attempts"),
    )
    .unwrap();
    let document: serde_json::Value = serde_json::from_slice(&bytes[1..]).unwrap();
    document["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|parent| {
            (
                parent["id"].as_str().unwrap().to_owned(),
                parent["complete"].as_bool().unwrap(),
            )
        })
        .collect()
}

/// A live holder in another process owns its open parent: a second process waits on the
/// admission lock and must not settle it. Once the holder dies, the next acquire may.
#[test]
fn a_live_holder_in_another_process_keeps_its_childless_or_put_only_parent_open() {
    for mode in ["hold-childless", "hold-put"] {
        let dir = worktree();
        std::fs::write(dir.path().join("go"), b"go").unwrap();
        let mut holder = child(dir.path(), "holder", mode);
        wait_for(&dir.path().join("holder.result"));
        let waiter = child(dir.path(), "waiter", "begin");
        wait_for(&dir.path().join("waiter.ready"));
        std::thread::sleep(Duration::from_millis(2500));
        assert!(
            !dir.path().join("waiter.result").exists(),
            "{mode}: acquire must wait for the live holder"
        );
        assert_eq!(open_parents(dir.path()).len(), 1, "{mode}");
        assert!(
            !open_parents(dir.path())[0].1,
            "{mode}: holder's parent open"
        );

        holder.0.kill().unwrap();
        holder.0.wait().unwrap();
        wait_child(waiter);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("waiter.result")).unwrap(),
            "admitted",
            "{mode}"
        );
        let parents = open_parents(dir.path());
        assert_eq!(parents.len(), 2, "{mode}");
        assert_eq!(
            parents.iter().filter(|(_, complete)| *complete).count(),
            1,
            "{mode}: the dead holder's parent closed, the waiter's own is open"
        );
    }
}

/// Same process, another task: a second acquire waits while the first guard is held, and the
/// holder's childless parent is still open when it finishes normally.
#[tokio::test]
async fn a_second_acquire_waits_for_the_holder_and_never_closes_its_open_parent() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let mut second = Box::pin(RepositoryMutationGuard::acquire(dir.path()));
    assert!(
        tokio::time::timeout(Duration::from_secs(2), &mut second)
            .await
            .is_err(),
        "second acquire must wait for the holder"
    );
    let parents = guard.store().managed_parents().await.unwrap();
    assert!(!parents[0].complete);
    assert!(!parents[0].body_completed);
    guard.store().complete_parent_body(parent).await.unwrap();
    guard.finish(parent).await.unwrap();
    drop(guard);
    second.await.unwrap();
}

/// A nested fence holds no lock and the open parent is its running caller's own: neither a
/// nested acquire nor a nested recover may settle it.
#[tokio::test]
async fn nested_fences_settle_nothing_and_refuse_settle_receiptless() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    guard
        .run(async {
            let nested = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
            let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
            for fence in [&nested, &recovery] {
                assert!(fence.settle_receiptless().await.is_err());
                let parents = fence.store().managed_parents().await.unwrap();
                assert_eq!(parents.len(), 1);
                assert!(!parents[0].complete);
                assert!(!parents[0].body_completed);
            }
        })
        .await;
    guard.store().complete_parent_body(parent).await.unwrap();
    guard.finish(parent).await.unwrap();
}

/// Settling a legacy store must keep the lock ownership it holds.
#[tokio::test]
async fn settling_a_legacy_store_keeps_its_lock_ownership() {
    use lore_base::types::Context;
    use lore_base::types::Hash;
    use lore_transport::attempt_store::LockOwnership;
    use lore_transport::attempt_store::OwnershipToken;

    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".lore")).unwrap();
    let legacy = lore_revision::attempt_store::RepositoryAttemptStore::in_directory(
        dir.path().join(".lore"),
    );
    let branch = Context::from([0x11u8; 16]);
    let resource = Hash::from([0x22u8; 32]);
    let ownership = LockOwnership {
        attempt_id: AttemptId::new(),
        branch,
        resource_hash: resource,
        token: OwnershipToken::from_wire(&[0xAB; OwnershipToken::LEN])
            .unwrap()
            .unwrap(),
    };
    legacy.record_ownership(&ownership).await.unwrap();
    legacy
        .begin_parent(lore_revision::attempt_store::ManagedParent {
            version: 1,
            id: Uuid::now_v7().to_string(),
            root: "fixture".into(),
            operation: "push".into(),
            normalized_intent: "fixture".into(),
            namespace: None,
            complete: false,
            parent_uncertainty_code: None,
            body_completed: false,
        })
        .await
        .unwrap();

    RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    assert!(legacy.managed_parents().await.unwrap()[0].complete);
    assert_eq!(
        legacy.ownership_for(&branch, &resource).await.unwrap(),
        Some(ownership)
    );
}

struct TestChild(std::process::Child);

impl Drop for TestChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn child(root: &Path, name: &str, mode: &str) -> TestChild {
    TestChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "process_worker", "--nocapture"])
            .env("LORE_FENCE_TEST_ROOT", root)
            .env("LORE_FENCE_TEST_NAME", name)
            .env("LORE_FENCE_TEST_MODE", mode)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

fn wait_for(path: &Path) {
    let started = Instant::now();
    while !path.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "child failed to create {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_child(mut process: TestChild) {
    let started = Instant::now();
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success(), "child exit: {status}");
            return;
        }
        if started.elapsed() > Duration::from_secs(10) {
            panic!("fence test child hung");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn separate_process_cannot_admit_another_parent_after_process_exit() {
    let dir = worktree();
    std::fs::write(dir.path().join("go"), b"go").unwrap();
    wait_child(child(dir.path(), "first", "begin"));
    wait_child(child(dir.path(), "second", "begin"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("first.result")).unwrap(),
        "admitted"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("second.result")).unwrap(),
        "refused"
    );
}

#[test]
fn two_processes_start_together_and_only_one_admits_a_parent() {
    let dir = worktree();
    let a = child(dir.path(), "a", "begin");
    let b = child(dir.path(), "b", "begin");
    wait_for(&dir.path().join("a.ready"));
    wait_for(&dir.path().join("b.ready"));
    std::fs::write(dir.path().join("go"), b"go").unwrap();
    wait_child(a);
    wait_child(b);
    let mut outcomes = vec![
        std::fs::read_to_string(dir.path().join("a.result")).unwrap(),
        std::fs::read_to_string(dir.path().join("b.result")).unwrap(),
    ];
    outcomes.sort();
    assert_eq!(outcomes, ["admitted", "refused"]);
}

#[test]
fn killing_the_holder_releases_the_os_lock_but_preserves_the_durable_fence() {
    let dir = worktree();
    std::fs::write(dir.path().join("go"), b"go").unwrap();
    let mut holder = child(dir.path(), "holder", "hold");
    wait_for(&dir.path().join("holder.result"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("holder.result")).unwrap(),
        "admitted"
    );
    holder.0.kill().unwrap();
    holder.0.wait().unwrap();
    wait_child(child(dir.path(), "after-crash", "begin"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("after-crash.result")).unwrap(),
        "refused"
    );
}

#[test]
#[ignore = "subprocess helper; parent tests supply isolated fixture paths"]
fn process_worker() {
    let root =
        std::path::PathBuf::from(std::env::var_os("LORE_FENCE_TEST_ROOT").expect("test root"));
    let name = std::env::var("LORE_FENCE_TEST_NAME").unwrap();
    let mode = std::env::var("LORE_FENCE_TEST_MODE").unwrap();
    std::fs::write(root.join(format!("{name}.ready")), b"ready").unwrap();
    wait_for(&root.join("go"));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        match RepositoryMutationGuard::acquire(&root).await {
            Ok(guard) => {
                let parent = Uuid::now_v7();
                let store = guard
                    .begin(parent, "child process".into(), "fixture intent".into())
                    .await
                    .unwrap();
                match mode.as_str() {
                    // The holder's parent is open with no child, or with only a Put.
                    "hold-childless" => {}
                    "hold-put" => {
                        let (put, intent) = legacy_put_record(parent);
                        store.record_managed(&put, &intent).await.unwrap();
                    }
                    // An unresolved child keeps the parent open across the process exit.
                    _ => store
                        .record_workflow_child(
                            parent,
                            AttemptId::new(),
                            "RevisionService.BranchPush".into(),
                            b"nonsecret intent".to_vec(),
                        )
                        .await
                        .unwrap(),
                }
                std::fs::write(root.join(format!("{name}.result")), b"admitted").unwrap();
                if mode.starts_with("hold") {
                    std::future::pending::<()>().await;
                }
            }
            Err(_) => {
                std::fs::write(root.join(format!("{name}.result")), b"refused").unwrap();
            }
        }
    });
}
