// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
#![allow(clippy::disallowed_methods)] // Isolated temporary journal fixtures only.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use lore_revision::attempt_store::ManagedParent;
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_transport::AttemptId;
use lore_transport::AttemptRecord;
use lore_transport::AttemptState;
use lore_transport::DomainAttemptReceipt;
use lore_transport::DomainReceiptOutcome;
use lore_transport::DomainReceiptState;
use lore_transport::caller_operation::ManagedAttemptIntent;

use super::*;

fn child(method: &str) -> AttemptRecord {
    AttemptRecord {
        attempt_id: AttemptId::new(),
        state: AttemptState::Unresolved,
        operation: method.into(),
        repository: "01010101010101010101010101010101".parse().unwrap(),
        recorded_at_unix_millis: 1,
        receipt: None,
    }
}

async fn managed_child(store: &RepositoryAttemptStore, method: &str) -> (Uuid, AttemptRecord) {
    let parent = Uuid::now_v7();
    store
        .begin_parent(ManagedParent {
            version: 1,
            id: parent.to_string(),
            root: "fixture".into(),
            operation: "lock-release".into(),
            normalized_intent: "fixture".into(),
            namespace: None,
            complete: false,
            parent_uncertainty_code: None,
            body_completed: false,
        })
        .await
        .unwrap();
    let record = child(method);
    store
        .record_managed(
            &record,
            &ManagedAttemptIntent {
                version: 1,
                parent_id: parent,
                repository: record.repository,
                rpc: method.into(),
                canonical_request: vec![8, 1],
                endpoint: "grpcs://original.invalid/".into(),
                verified_issuer: "original-issuer".into(),
                authenticated_subject: "original-subject".into(),
                caller_capabilities: "outcome_unknown_v1".into(),
            },
        )
        .await
        .unwrap();
    store.complete_parent_body(parent).await.unwrap();
    (parent, record)
}

#[tokio::test]
async fn branch_create_reconciliation_requires_exact_receipt_method_and_original_namespace() {
    for method in ["branch.create", "branch_create", "branch.push"] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join(".lore")).unwrap();
        let store = RepositoryAttemptStore::in_directory(directory.path().join(".lore"));
        let (parent, record) = managed_child(&store, "RevisionService.BranchCreate").await;
        let expected_namespace = store.recovery_context(&record.attempt_id).await.unwrap();
        let guard = RepositoryMutationGuard::recover(directory.path())
            .await
            .unwrap();
        let calls = AtomicUsize::new(0);
        let result = reconcile_stores(&guard, |opened, attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            let expected_namespace = expected_namespace.clone();
            let expected_attempt = record.attempt_id;
            async move {
                assert_eq!(attempt, expected_attempt);
                assert_eq!(
                    opened.recovery_context(&attempt).await.unwrap(),
                    expected_namespace
                );
                Ok(DomainAttemptReceipt {
                    method: method.into(),
                    state: DomainReceiptState::Committed {
                        outcome: DomainReceiptOutcome::Applied,
                        from_future_marker: false,
                    },
                })
            }
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(guard);
        let reopened = RepositoryAttemptStore::in_directory(directory.path().join(".lore"));
        let parents = reopened.managed_parents().await.unwrap();
        assert_eq!(parents[0].id, parent.to_string());
        if method == "branch.create" {
            result.unwrap();
            assert!(reopened.unresolved().await.unwrap().is_empty());
            assert!(parents[0].complete);
        } else {
            assert!(result.is_err());
            assert_eq!(reopened.unresolved().await.unwrap(), vec![record]);
            assert!(!parents[0].complete);
        }
    }
}

#[tokio::test]
async fn status_exposes_legacy_only_blockers_and_reconcile_never_guesses_namespace() {
    for source in [".lore", ".urc"] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join(source)).unwrap();
        let legacy = RepositoryAttemptStore::in_directory(directory.path().join(source));
        let record = child("LockService.Unlock");
        legacy.record(&record).await.unwrap();
        assert!(
            RepositoryMutationGuard::acquire(directory.path())
                .await
                .is_err()
        );
        let guard = RepositoryMutationGuard::recover(directory.path())
            .await
            .unwrap();
        let lines = status_lines(&guard).await.unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains(source) && line.contains(&record.attempt_id.to_string()))
        );
        let calls = AtomicUsize::new(0);
        let error = reconcile_stores(&guard, |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { panic!("a legacy attempt without namespace must never dispatch") }
        })
        .await
        .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(error.to_string().contains(source));
        assert_eq!(legacy.unresolved().await.unwrap(), vec![record]);
        drop(guard);
        assert!(
            RepositoryMutationGuard::acquire(directory.path())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn exact_legacy_force_unlock_receipt_settles_original_child_and_parent() {
    for outcome in [
        DomainReceiptOutcome::Applied,
        DomainReceiptOutcome::NotApplied {
            reason_version: 1,
            reason: "denied".into(),
        },
    ] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join(".urc")).unwrap();
        let legacy = RepositoryAttemptStore::in_directory(directory.path().join(".urc"));
        let (parent, record) = managed_child(&legacy, "LockService.ForceUnlock").await;
        let expected_namespace = legacy.recovery_context(&record.attempt_id).await.unwrap();
        let guard = RepositoryMutationGuard::recover(directory.path())
            .await
            .unwrap();
        let lines = status_lines(&guard).await.unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains(".urc") && line.contains(&parent.to_string()))
        );
        let calls = AtomicUsize::new(0);
        reconcile_stores(&guard, |store, attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            let outcome = outcome.clone();
            let expected_namespace = expected_namespace.clone();
            let expected_attempt = record.attempt_id;
            async move {
                assert_eq!(attempt, expected_attempt);
                assert_eq!(
                    store.recovery_context(&attempt).await.unwrap(),
                    expected_namespace
                );
                Ok(DomainAttemptReceipt {
                    method: "lock.force_release".into(),
                    state: DomainReceiptState::Committed {
                        outcome,
                        from_future_marker: false,
                    },
                })
            }
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(legacy.unresolved().await.unwrap().is_empty());
        assert!(legacy.managed_parents().await.unwrap()[0].complete);
        assert!(status_lines(&guard).await.unwrap().is_empty());
        drop(guard);
        RepositoryMutationGuard::acquire(directory.path())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn wrong_method_or_nonattributive_force_unlock_receipt_keeps_parent_blocked() {
    for (method, state) in [
        (
            "lock.release",
            DomainReceiptState::Committed {
                outcome: DomainReceiptOutcome::Applied,
                from_future_marker: false,
            },
        ),
        ("lock.force_release", DomainReceiptState::NotFound),
        (
            "lock.force_release",
            DomainReceiptState::Prepared {
                prepared_at_unix_millis: 1,
                hard_expires_at_unix_millis: 2,
            },
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let guard = RepositoryMutationGuard::recover(directory.path())
            .await
            .unwrap();
        let store = guard.store();
        let (_, record) = managed_child(&store, "LockService.ForceUnlock").await;
        let calls = AtomicUsize::new(0);
        assert!(
            reconcile_stores(&guard, |_, attempt| {
                assert_eq!(attempt, record.attempt_id);
                calls.fetch_add(1, Ordering::SeqCst);
                let state = state.clone();
                async move {
                    Ok(DomainAttemptReceipt {
                        method: method.into(),
                        state,
                    })
                }
            })
            .await
            .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.unresolved().await.unwrap(), vec![record]);
        assert!(!store.managed_parents().await.unwrap()[0].complete);
    }
}

#[tokio::test]
async fn unsupported_admin_lock_is_not_silently_added_to_recovery_scope() {
    let directory = tempfile::tempdir().unwrap();
    let guard = RepositoryMutationGuard::recover(directory.path())
        .await
        .unwrap();
    let store = guard.store();
    let (_, record) = managed_child(&store, "LockService.AdminLock").await;
    assert!(
        reconcile_stores(&guard, |_, _| async {
            panic!("unsupported method must never dispatch")
        })
        .await
        .is_err()
    );
    assert_eq!(store.unresolved().await.unwrap(), vec![record]);
}
