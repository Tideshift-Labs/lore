// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] The daemon owns admitted work after its forwarding receiver disappears.
#![allow(clippy::disallowed_methods)] // Only this test's isolated worktree.

use std::sync::Arc;
use std::time::Duration;

use lore_revision::managed_push::ManagedPushRunner;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptId;
use lore_transport::AttemptRecord;
use lore_transport::AttemptResolution;
use lore_transport::AttemptState;
use lore_transport::AttemptStore;
use lore_transport::ProtocolError;
use lore_transport::caller_operation::ManagedAttemptIntent;
use tokio::sync::oneshot;

use super::SerializationType;
use super::spawn_command;

struct ReleaseStage(Option<oneshot::Sender<()>>);

impl Drop for ReleaseStage {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[tokio::test]
async fn disconnected_forwarder_keeps_original_stage_fenced_until_daemon_settles() {
    let root = tempfile::tempdir().unwrap().keep();
    std::fs::create_dir(root.join(".lore")).unwrap();
    crate::eprintln!("Service lifecycle fixture: {}", root.display());
    let guard = Arc::new(RepositoryMutationGuard::acquire(&root).await.unwrap());
    let store = guard.store();
    let (entered_sender, entered) = oneshot::channel();
    let (release_sender, released) = oneshot::channel();
    let release = ReleaseStage(Some(release_sender));
    let (receiver, mut task) =
        spawn_command(SerializationType::Json, move |_callback| async move {
            let repository = [7; 16].into();
            let runner = ManagedPushRunner::new(guard, None);
            runner
                .run_stage(repository, "held daemon mutation", async move {
                    let context = lore_transport::current_caller_operation().unwrap();
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
                                endpoint: "https://fixture.invalid/".into(),
                                verified_issuer: "https://fixture.invalid/issuer".into(),
                                authenticated_subject: "alice".into(),
                                caller_capabilities: "outcome_unknown_v1".into(),
                            },
                        )
                        .await?;
                    entered_sender.send((parent, attempt)).unwrap();
                    released.await.unwrap();
                    context
                        .attempts()
                        .resolve(&attempt, AttemptResolution::Applied)
                        .await?;
                    Ok::<_, ProtocolError>(())
                })
                .await
                .unwrap();
            0
        });

    // Collect failures before asserting, so every normal failure releases and joins the daemon.
    let held = async {
        let (parent, attempt) = tokio::time::timeout(Duration::from_secs(5), entered)
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string())?;
        drop(receiver);
        let blocked = tokio::time::timeout(
            Duration::from_millis(100),
            RepositoryMutationGuard::acquire(&root),
        )
        .await
        .is_err();
        let parents = store
            .managed_parents()
            .await
            .map_err(|error| error.to_string())?;
        let unresolved = store
            .unresolved()
            .await
            .map_err(|error| error.to_string())?;
        Ok::<_, String>((
            parent,
            attempt,
            blocked,
            parents,
            unresolved,
            task.is_finished(),
        ))
    }
    .await;
    drop(release);
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task).await;
    if joined.is_err() {
        task.abort();
        let _ = task.await;
        panic!("daemon did not finish after stage release");
    }
    joined.unwrap().unwrap();
    let (parent, attempt, blocked, parents, unresolved, finished_while_held) = held.unwrap();
    assert!(
        blocked,
        "receiver loss must not release the daemon's write fence"
    );
    assert!(!finished_while_held);
    assert_eq!(parents.len(), 1);
    assert_eq!(parents[0].id, parent.to_string());
    assert!(!parents[0].complete && !parents[0].body_completed);
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].attempt_id, attempt);
    assert_eq!(unresolved[0].state, AttemptState::Unresolved);

    let parents = store.managed_parents().await.unwrap();
    assert_eq!(parents.len(), 1);
    assert_eq!(parents[0].id, parent.to_string());
    assert!(parents[0].complete && parents[0].body_completed);
    assert!(parents[0].parent_uncertainty_code.is_none());
    assert_eq!(
        store.lookup(&attempt).await.unwrap().unwrap().state,
        AttemptState::Resolved(AttemptResolution::Applied)
    );
    assert!(store.unresolved().await.unwrap().is_empty());
    let next = tokio::time::timeout(
        Duration::from_secs(3),
        RepositoryMutationGuard::acquire(&root),
    )
    .await
    .unwrap()
    .unwrap();
    drop(next);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
