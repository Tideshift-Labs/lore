// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] `recovery::admit_with`: a crash-blocked repository reconciles itself before refusing.
#![allow(clippy::disallowed_methods)] // Isolated temporary journal fixtures only.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use lore::recovery::admit_with;
use lore_base::types::RepositoryId;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptId;
use lore_transport::AttemptRecord;
use lore_transport::AttemptResolution;
use lore_transport::AttemptState;
use lore_transport::AttemptStore;
use lore_transport::DomainAttemptReceipt;
use lore_transport::DomainReceiptOutcome;
use lore_transport::DomainReceiptState;
use lore_transport::caller_operation::ManagedAttemptIntent;
use uuid::Uuid;

/// A throwaway worktree removed on drop (this crate has no `tempfile` dev-dependency).
struct Worktree(std::path::PathBuf);

impl Worktree {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Worktree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn worktree() -> Worktree {
    let dir = std::env::temp_dir().join(format!("lore-recovery-test-{}", Uuid::now_v7()));
    std::fs::create_dir_all(dir.join(".lore")).unwrap();
    Worktree(dir)
}

fn record(parent: Uuid, rpc: &str) -> (AttemptRecord, ManagedAttemptIntent) {
    let repository = RepositoryId::from([1; 16]);
    (
        AttemptRecord {
            attempt_id: AttemptId::new(),
            state: AttemptState::Unresolved,
            operation: rpc.into(),
            repository,
            recorded_at_unix_millis: 1,
            receipt: None,
        },
        ManagedAttemptIntent {
            version: 1,
            parent_id: parent,
            repository,
            rpc: rpc.into(),
            canonical_request: vec![8, 1],
            endpoint: "https://fixture.invalid/".into(),
            verified_issuer: "https://fixture.invalid/issuer".into(),
            authenticated_subject: "alice".into(),
            caller_capabilities: "outcome_unknown_v1".into(),
        },
    )
}

/// Leaves a crashed parent with one unresolved child of `rpc` and the body completed.
async fn crash_with_child(dir: &std::path::Path, rpc: &str) -> (Uuid, AttemptRecord) {
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir).await.unwrap();
    let store = guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let (child, intent) = record(parent, rpc);
    store.record_managed(&child, &intent).await.unwrap();
    store.complete_parent_body(parent).await.unwrap();
    (parent, child)
}

#[tokio::test]
async fn a_lone_old_put_child_is_settled_by_a_plain_acquire_with_no_lookup() {
    let dir = worktree();
    let (parent, child) = crash_with_child(dir.path(), "StorageService.Put").await;
    // The old journal still loads, and `recover` settles nothing: the Put is listed unresolved.
    {
        let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
        assert_eq!(
            recovery.store().unresolved().await.unwrap(),
            vec![child.clone()]
        );
    }

    let calls = AtomicUsize::new(0);
    let guard = admit_with(dir.path(), |_, _| {
        calls.fetch_add(1, Ordering::SeqCst);
        async { panic!("a legacy fragment Put has no receipt and must never be looked up") }
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
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
    let parents = store.managed_parents().await.unwrap();
    assert_eq!(parents[0].id, parent.to_string());
    assert!(parents[0].complete);
    guard
        .begin(Uuid::now_v7(), "push".into(), "branch".into())
        .await
        .unwrap();
}

/// Copy and `PutResolved` stopped being journaled after Put did: an older build's unresolved child
/// of either is settled by a plain acquire with no lookup, exactly as a Put is.
#[tokio::test]
async fn a_lone_old_copy_or_put_resolved_child_is_settled_by_a_plain_acquire_with_no_lookup() {
    for rpc in ["StorageService.Copy", "StorageService.PutResolved"] {
        let dir = worktree();
        let (parent, child) = crash_with_child(dir.path(), rpc).await;
        {
            let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
            assert_eq!(
                recovery.store().unresolved().await.unwrap(),
                vec![child.clone()],
                "{rpc}"
            );
        }

        let calls = AtomicUsize::new(0);
        let guard = admit_with(dir.path(), |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                panic!("a legacy Copy or PutResolved has no receipt and must never be looked up")
            }
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0, "{rpc}");
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
            "{rpc}"
        );
        let parents = store.managed_parents().await.unwrap();
        assert_eq!(parents[0].id, parent.to_string());
        assert!(parents[0].complete, "{rpc}");
        guard
            .begin(Uuid::now_v7(), "push".into(), "branch".into())
            .await
            .unwrap();
    }
}

/// A legacy Copy or `PutResolved` beside an unresolved `BranchPush` settles, but the parent stays
/// blocked on the push, and only the push is ever looked up.
#[tokio::test]
async fn a_legacy_copy_or_put_resolved_beside_a_branch_push_looks_up_only_the_push() {
    for rpc in ["StorageService.Copy", "StorageService.PutResolved"] {
        let dir = worktree();
        let parent = Uuid::now_v7();
        let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
        let store = guard
            .begin(parent, "push".into(), "branch".into())
            .await
            .unwrap();
        let (write, write_intent) = record(parent, rpc);
        store.record_managed(&write, &write_intent).await.unwrap();
        let (push, push_intent) = record(parent, "RevisionService.BranchPush");
        store.record_managed(&push, &push_intent).await.unwrap();
        store.complete_parent_body(parent).await.unwrap();
        drop(store);
        drop(guard);

        let looked_up = parking_lot::Mutex::new(Vec::new());
        let error = admit_with(dir.path(), |_, attempt| {
            looked_up.lock().push(attempt);
            async {
                Ok(DomainAttemptReceipt {
                    method: String::new(),
                    state: DomainReceiptState::NotFound,
                    acquired_locks: Vec::new(),
                })
            }
        })
        .await
        .err()
        .expect("an undecided push receipt keeps admission refused");
        assert_eq!(*looked_up.lock(), vec![push.attempt_id], "{rpc}");
        assert!(
            error.to_string().contains(&push.attempt_id.to_string()),
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
    }
}

#[tokio::test]
async fn a_nondecisive_branch_push_receipt_still_refuses_and_names_the_child() {
    let dir = worktree();
    let (_, child) = crash_with_child(dir.path(), "RevisionService.BranchPush").await;
    assert!(RepositoryMutationGuard::acquire(dir.path()).await.is_err());

    let calls = AtomicUsize::new(0);
    let error = admit_with(dir.path(), |_, attempt| {
        calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(attempt, child.attempt_id);
        async {
            Ok(DomainAttemptReceipt {
                method: String::new(),
                state: DomainReceiptState::NotFound,
                acquired_locks: Vec::new(),
            })
        }
    })
    .await
    .err()
    .expect("a receipt that decides nothing must keep admission refused");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let message = error.to_string();
    assert!(message.contains(&child.attempt_id.to_string()), "{message}");
    assert!(message.contains("nondecisive"), "{message}");

    let recovery = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
    assert_eq!(
        recovery.store().unresolved().await.unwrap(),
        vec![child.clone()]
    );
}

#[tokio::test]
async fn a_committed_applied_branch_push_receipt_settles_the_child_and_admits() {
    let dir = worktree();
    let (_, child) = crash_with_child(dir.path(), "RevisionService.BranchPush").await;

    let calls = AtomicUsize::new(0);
    let guard = admit_with(dir.path(), |_, attempt| {
        calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(attempt, child.attempt_id);
        async {
            Ok(DomainAttemptReceipt {
                method: "branch.push".into(),
                state: DomainReceiptState::Committed {
                    outcome: DomainReceiptOutcome::Applied,
                    from_future_marker: false,
                },
                acquired_locks: Vec::new(),
            })
        }
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let store = guard.store();
    assert!(store.unresolved().await.unwrap().is_empty());
    assert_eq!(
        store
            .lookup(&child.attempt_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        AttemptState::Resolved(AttemptResolution::Applied)
    );
}

#[tokio::test]
async fn an_unblocked_repository_admits_without_any_lookup() {
    let dir = worktree();
    admit_with(dir.path(), |_, _| async {
        panic!("nothing is blocked, so nothing may be looked up")
    })
    .await
    .unwrap();
}

/// `reconcile` on a nested fence (no admission lock, the open parent is its caller's own)
/// refuses and leaves that parent open.
#[tokio::test]
async fn reconcile_on_a_nested_fence_errors_and_leaves_the_open_parent() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    guard
        .run(async {
            let nested = RepositoryMutationGuard::recover(dir.path()).await.unwrap();
            let result = lore::recovery::reconcile(&nested, |_, _| async {
                panic!("a nested reconcile must not look anything up")
            })
            .await;
            assert!(result.is_err());
            let parents = nested.store().managed_parents().await.unwrap();
            assert_eq!(parents.len(), 1);
            assert!(!parents[0].complete);
        })
        .await;
    guard.store().complete_parent_body(parent).await.unwrap();
    guard.finish(parent).await.unwrap();
}

/// A nested `admit_with` (inside a running workflow's `run`) admits through the nested fence,
/// looks nothing up, and settles nothing: the caller's own open parent stays open.
#[tokio::test]
async fn a_nested_admit_with_admits_without_lookup_and_leaves_the_open_parent() {
    let dir = worktree();
    let parent = Uuid::now_v7();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let calls = AtomicUsize::new(0);
    guard
        .run(async {
            let nested = admit_with(dir.path(), |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { panic!("a nested admit must not look anything up") }
            })
            .await
            .unwrap();
            let parents = nested.store().managed_parents().await.unwrap();
            assert_eq!(parents.len(), 1);
            assert!(!parents[0].complete);
            assert!(!parents[0].body_completed);
        })
        .await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let parents = guard.store().managed_parents().await.unwrap();
    assert!(!parents[0].complete);
    assert!(!parents[0].body_completed);
    guard.store().complete_parent_body(parent).await.unwrap();
    guard.finish(parent).await.unwrap();
}
