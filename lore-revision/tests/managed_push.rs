// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] Real durable journals across explicit repository push stages.
#![allow(clippy::disallowed_methods)] // This suite's owned temporary worktrees only.
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use lore_base::types::RepositoryId;
use lore_error_set::FfiError;
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_revision::managed_push::ManagedPushObserver;
use lore_revision::managed_push::ManagedPushRunner;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptId;
use lore_transport::AttemptRecord;
use lore_transport::AttemptResolution;
use lore_transport::AttemptState;
use lore_transport::AttemptStore;
use lore_transport::ProtocolError;
use lore_transport::caller_operation::ManagedAttemptIntent;
use uuid::Uuid;

fn worktree() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join(".lore")).unwrap();
    directory
}

async fn record_stage(repository: RepositoryId) -> (Uuid, AttemptId) {
    let context = lore_transport::current_caller_operation().expect("stage context before polling");
    assert_eq!(context.repository(), repository);
    let parent = context.parent_id();
    let attempt = AttemptId::new();
    let rpc = "RevisionService.BranchPush".to_owned();
    context
        .attempts()
        .record_managed(
            &AttemptRecord {
                attempt_id: attempt,
                state: AttemptState::Unresolved,
                operation: rpc.clone(),
                repository,
                recorded_at_unix_millis: 1,
                receipt: None,
            },
            &ManagedAttemptIntent {
                version: 1,
                parent_id: parent,
                repository,
                rpc,
                canonical_request: vec![8, 1],
                endpoint: format!("https://{repository}.fixture.invalid/"),
                verified_issuer: "https://fixture.invalid/issuer".into(),
                authenticated_subject: "alice".into(),
                caller_capabilities: "outcome_unknown_v1".into(),
            },
        )
        .await
        .unwrap();
    (parent, attempt)
}

#[tokio::test]
async fn root_link_and_resumed_root_have_distinct_frozen_stage_namespaces() {
    let directory = worktree();
    let guard = Arc::new(
        RepositoryMutationGuard::acquire(directory.path())
            .await
            .unwrap(),
    );
    let runner = ManagedPushRunner::new(guard.clone(), None);
    let repositories = [
        RepositoryId::from([1; 16]),
        RepositoryId::from([2; 16]),
        RepositoryId::from([1; 16]),
    ];
    let mut identities = Vec::new();
    for repository in repositories {
        let identity = runner
            .run_stage(repository, "test mutation", async {
                let (parent, attempt) = record_stage(repository).await;
                lore_transport::current_caller_operation()
                    .unwrap()
                    .attempts()
                    .resolve(&attempt, AttemptResolution::Applied)
                    .await?;
                Ok::<_, ProtocolError>((parent, attempt))
            })
            .await
            .unwrap();
        identities.push(identity);
        assert!(lore_transport::current_caller_operation().is_none());
    }
    assert_eq!(
        identities
            .iter()
            .map(|(parent, _)| parent)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    let parents = guard.store().managed_parents().await.unwrap();
    assert_eq!(parents.len(), 3);
    for ((parent, attempt), repository) in identities.iter().zip(repositories) {
        let stored = parents
            .iter()
            .find(|stored| stored.id == parent.to_string())
            .unwrap();
        assert!(stored.complete && stored.body_completed);
        assert!(stored.parent_uncertainty_code.is_none());
        assert_eq!(
            stored.namespace.as_ref().unwrap().repository,
            repository.to_string()
        );
        assert_eq!(
            guard
                .store()
                .recovery_context(attempt)
                .await
                .unwrap()
                .repository,
            repository
        );
    }
    assert!(guard.store().unresolved().await.unwrap().is_empty());
}

#[tokio::test]
async fn link_unknown_retains_original_attempt_blocks_later_stage_and_recovers_target_namespace() {
    let directory = worktree();
    let root = RepositoryId::from([1; 16]);
    let link = RepositoryId::from([2; 16]);
    let guard = Arc::new(
        RepositoryMutationGuard::acquire(directory.path())
            .await
            .unwrap(),
    );
    let runner = ManagedPushRunner::new(guard.clone(), None);
    runner
        .run_stage(root, "root before link", async {
            let (_, attempt) = record_stage(root).await;
            guard
                .store()
                .resolve(&attempt, AttemptResolution::Applied)
                .await?;
            Ok::<_, ProtocolError>(())
        })
        .await
        .unwrap();
    let mut original = None;
    let result = runner
        .run_stage(link, "link mutation", async {
            let identity = record_stage(link).await;
            original = Some(identity);
            Err::<(), _>(lore_transport::outcome::outcome_unknown(
                "RevisionService.BranchPush",
                &identity.1,
            ))
        })
        .await;
    let error = result.unwrap_err();
    let (parent, attempt) = original.unwrap();
    assert_eq!(error.ffi_code(), 193);
    let attempt_text = attempt.to_string();
    assert_eq!(
        error.outcome_identity(),
        Some(("RevisionService.BranchPush", attempt_text.as_str()))
    );
    let later_polled = AtomicBool::new(false);
    assert!(
        runner
            .run_stage(root, "root resume", async {
                later_polled.store(true, Ordering::SeqCst);
                Ok::<_, ProtocolError>(())
            })
            .await
            .is_err()
    );
    assert!(!later_polled.load(Ordering::SeqCst));
    assert_eq!(guard.store().managed_parents().await.unwrap().len(), 2);
    drop(runner);
    drop(guard);
    assert!(
        RepositoryMutationGuard::acquire(directory.path())
            .await
            .is_err()
    );
    let recovery = RepositoryMutationGuard::recover(directory.path())
        .await
        .unwrap();
    let pending = recovery.store().unresolved().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].attempt_id, attempt);
    assert_eq!(pending[0].repository, link);
    let context = recovery.store().recovery_context(&attempt).await.unwrap();
    assert_eq!(context.repository, link);
    assert_eq!(context.endpoint, format!("https://{link}.fixture.invalid/"));
    assert!(recovery.store().reconcile_parent(parent).await.is_err());
    recovery
        .store()
        .resolve(&attempt, AttemptResolution::Applied)
        .await
        .unwrap();
    recovery.store().reconcile_parent(parent).await.unwrap();
    drop(recovery);
    RepositoryMutationGuard::acquire(directory.path())
        .await
        .unwrap();
}

struct FailingObserver(u8);

#[async_trait::async_trait]
impl ManagedPushObserver for FailingObserver {
    async fn begin_stage(
        &self,
        _: Uuid,
        _: RepositoryId,
        shared: Arc<RepositoryAttemptStore>,
        _: &str,
    ) -> Result<Arc<dyn AttemptStore>, ProtocolError> {
        if self.0 == 0 {
            return Err(ProtocolError::internal("observer begin failed"));
        }
        Ok(shared)
    }
    async fn complete_stage_body(&self, _: Uuid, _: i32) -> Result<(), ProtocolError> {
        if self.0 == 1 {
            return Err(ProtocolError::internal("observer body failed"));
        }
        Ok(())
    }
    async fn finish_stage(&self, _: Uuid) -> Result<(), ProtocolError> {
        if self.0 == 2 {
            return Err(ProtocolError::internal("observer finish failed"));
        }
        Ok(())
    }
}

#[tokio::test]
async fn observer_failure_preserves_durable_blocker_at_every_hook() {
    for failed_hook in 0..3 {
        let directory = worktree();
        let repository = RepositoryId::from([4; 16]);
        let guard = Arc::new(
            RepositoryMutationGuard::acquire(directory.path())
                .await
                .unwrap(),
        );
        let runner =
            ManagedPushRunner::new(guard.clone(), Some(Arc::new(FailingObserver(failed_hook))));
        let polled = AtomicBool::new(false);
        let result = runner
            .run_stage(repository, "observer failure", async {
                polled.store(true, Ordering::SeqCst);
                let (_, attempt) = record_stage(repository).await;
                guard
                    .store()
                    .resolve(&attempt, AttemptResolution::Applied)
                    .await?;
                Ok::<_, ProtocolError>(())
            })
            .await;
        assert!(result.is_err());
        assert_eq!(polled.load(Ordering::SeqCst), failed_hook != 0);
        let parents = guard.store().managed_parents().await.unwrap();
        assert_eq!(parents.len(), 1);
        assert!(
            !parents[0].complete,
            "hook {failed_hook} lost its durable blocker"
        );
        drop(runner);
        drop(guard);
        assert!(
            RepositoryMutationGuard::acquire(directory.path())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn cancelled_stage_keeps_body_unproven_and_stops_later_stages() {
    let directory = worktree();
    let repository = RepositoryId::from([3; 16]);
    let guard = Arc::new(
        RepositoryMutationGuard::acquire(directory.path())
            .await
            .unwrap(),
    );
    let runner = ManagedPushRunner::new(guard.clone(), None);
    let started = tokio::sync::Notify::new();
    let mut stage = Box::pin(runner.run_stage(repository, "cancelled", async {
        record_stage(repository).await;
        started.notify_one();
        std::future::pending::<Result<(), ProtocolError>>().await
    }));
    tokio::select! {
        _ = &mut stage => panic!("stage must remain pending"),
        _ = started.notified() => {}
    }
    drop(stage);
    assert!(
        runner
            .run_stage(repository, "later", async { Ok::<_, ProtocolError>(()) })
            .await
            .is_err()
    );
    let parents = guard.store().managed_parents().await.unwrap();
    assert_eq!(parents.len(), 1);
    assert!(!parents[0].complete && !parents[0].body_completed);
    drop(runner);
    drop(guard);
    assert!(
        RepositoryMutationGuard::acquire(directory.path())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn observer_body_failure_cannot_replace_unknown_attempt_with_decisive_error() {
    let directory = worktree();
    let repository = RepositoryId::from([5; 16]);
    let guard = Arc::new(
        RepositoryMutationGuard::acquire(directory.path())
            .await
            .unwrap(),
    );
    let runner = ManagedPushRunner::new(guard.clone(), Some(Arc::new(FailingObserver(1))));
    let mut original = None;
    let error = runner
        .run_stage(repository, "unknown with observer failure", async {
            let (parent, attempt) = record_stage(repository).await;
            original = Some((parent, attempt));
            Err::<(), _>(lore_transport::outcome::outcome_unknown(
                "RevisionService.BranchPush",
                &attempt,
            ))
        })
        .await
        .unwrap_err();
    let (parent, attempt) = original.unwrap();
    let text = attempt.to_string();
    assert_eq!(error.ffi_code(), 193);
    assert_eq!(
        error.outcome_identity(),
        Some(("RevisionService.BranchPush", text.as_str()))
    );
    assert_eq!(
        guard.store().unresolved().await.unwrap()[0].attempt_id,
        attempt
    );
    let parents = guard.store().managed_parents().await.unwrap();
    assert_eq!(parents[0].id, parent.to_string());
    assert!(parents[0].body_completed && !parents[0].complete);
    assert!(
        runner
            .run_stage(repository, "later", async { Ok::<_, ProtocolError>(()) })
            .await
            .is_err()
    );
}
