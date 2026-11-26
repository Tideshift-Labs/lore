// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] A managed parent left open by a local commit whose outcome was lost settles from the
//! working copy's own anchors, with no network: the next write command admits itself (commit did
//! not apply), or stays refused (commit applied, the parent still owed its body), and `reconcile`
//! settles the same way. Real repository, real `lore::file::stage` through `call.rs`.
#![allow(clippy::disallowed_methods)] // Fixtures write in their own temporary directories.

use std::path::PathBuf;
use std::sync::Arc;

use lore::file::LoreFileStageArgs;
use lore::repository::LoreRepositoryCreateArgs;
use lore::revision::LoreRevisionCommitArgs;
use lore_base::runtime::LORE_CONTEXT;
use lore_revision::exact_selection::ExactSelectionOptions;
use lore_revision::exact_selection::ExpectedFileAction;
use lore_revision::exact_selection::FileMetadataSelection;
use lore_revision::exact_selection::SelectedFile;
use lore_revision::interface::ExecutionContext;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreGlobalArgs;
use lore_revision::interface::LoreString;
use lore_revision::local_commit_evidence::LocalCommitEvidence;
use lore_revision::relay::EventDispatcher;
use lore_revision::repository;
use lore_revision::repository::LoreSharedStoreMode;
use lore_revision::repository::RepositoryAccess;
use lore_revision::repository::RepositoryWriteToken;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptId;
use lore_transport::AttemptResolution;
use lore_transport::AttemptState;
use lore_transport::AttemptStore;
use uuid::Uuid;

use crate::test_util::TempDir;

const COMMIT: &str = "RevisionService.CommitLocal";

struct Rig {
    _dir: TempDir,
    root: PathBuf,
    globals: LoreGlobalArgs,
}

impl Rig {
    /// An offline repository with one committed file.
    async fn new() -> Rig {
        let rig = Rig::empty().await;
        assert_eq!(rig.stage("base.txt").await, 0);
        let commit = LoreRevisionCommitArgs {
            message: "base".into(),
            ..Default::default()
        };
        assert_eq!(
            lore::revision::commit(rig.globals.clone(), commit, None).await,
            0
        );
        rig
    }

    /// An offline repository with no revision yet: its branch has no latest.
    async fn empty() -> Rig {
        let dir = TempDir::new("lore-local-commit-recovery-");
        let root = dir.path().to_path_buf();
        let globals = LoreGlobalArgs {
            repository_path: root.as_path().into(),
            offline: 1,
            identity: "local-commit-recovery-test".into(),
            ..Default::default()
        };
        let create = LoreRepositoryCreateArgs {
            repository_url: format!("lore://localhost/{}", Uuid::now_v7()).into(),
            id: LoreString::default(),
            description: LoreString::default(),
            use_shared_store: LoreSharedStoreMode::Disabled,
            shared_store_path: LoreString::default(),
            vfs: Default::default(),
        };
        assert_eq!(
            lore::repository::create(globals.clone(), create, None).await,
            0
        );
        Rig {
            _dir: dir,
            root,
            globals,
        }
    }

    /// Writes `name` and stages it through the facade: a write command through `call.rs`.
    async fn stage(&self, name: &str) -> i32 {
        std::fs::write(self.root.join(name), name.as_bytes()).expect("write fixture file");
        let args = LoreFileStageArgs {
            paths: LoreArray::from_vec(vec![LoreString::from(self.root.join(name).as_path())]),
            case_change: 0,
            scan: 0,
        };
        lore::file::stage(self.globals.clone(), args, None).await
    }

    fn execution(&self) -> Arc<ExecutionContext> {
        Arc::new(ExecutionContext::new_client_with_user_id(
            self.globals.clone(),
            EventDispatcher::new(None),
            "local-commit-recovery-test".to_string(),
        ))
    }

    /// The anchors a journalled local commit would record, read as recovery reads them.
    async fn evidence(&self) -> LocalCommitEvidence {
        let root = self.root.clone();
        LORE_CONTEXT
            .scope(self.execution(), async move {
                let repository = repository::load_and_connect(&root, RepositoryAccess::ReadOnly)
                    .await
                    .expect("open the fixture repository");
                let evidence = lore_revision::local_commit_evidence::capture(&repository)
                    .await
                    .expect("capture the anchors");
                drop(repository);
                repository::repository_release(&root);
                evidence
            })
            .await
    }

    /// Commits `name` as a revision through the facade (exact selection): the local commit whose
    /// answer a crash then loses. Run before the parent opens, or the fence refuses it.
    async fn commit_file(&self, name: &str) {
        // The bytes whose content hash the selection names (as the exact-selection facade test).
        std::fs::write(self.root.join(name), b"facade bytes\n").expect("write fixture file");
        let options = ExactSelectionOptions {
            message: format!("commit {name}"),
            files: vec![SelectedFile {
                path: name.to_string(),
                expected_effective_action: ExpectedFileAction::Add,
                source_hash: Some("0d53bad53f9f2a053fdf0faa5c07a205".to_string()),
                file_metadata: FileMetadataSelection::Unchanged,
            }],
            revision_metadata: Vec::new(),
            stats: false,
        };
        let result = lore::revision::commit_exact_selection(self.globals.clone(), options, None)
            .await
            .expect("the exact-selection commit");
        assert!(!result.revision.is_zero());
    }

    /// Points the anchor at a branch the store does not hold, so the anchors cannot be read.
    async fn break_the_branch_anchor(&self) {
        let root = self.root.clone();
        LORE_CONTEXT
            .scope(self.execution(), async move {
                let token = RepositoryWriteToken::acquire(&root).await;
                let repository = repository::load_and_connect_with_token(
                    &root,
                    RepositoryAccess::ReadWrite,
                    Some(token.share()),
                )
                .await
                .expect("open the fixture repository");
                lore_revision::instance::store_current_anchor_branch(
                    &repository,
                    lore_base::types::Context::from(Uuid::now_v7()),
                )
                .await
                .expect("store the anchor branch");
                repository
                    .flush(Default::default())
                    .await
                    .expect("flush the anchor");
                drop(repository);
                repository::repository_release(&root);
            })
            .await;
    }

    /// A parent opened for a local commit with `evidence`, its body never completed and its child
    /// unresolved: what a crash (or a failure the caller could not classify) leaves.
    async fn leave_open_parent(&self, attempt: AttemptId, evidence: LocalCommitEvidence) -> Uuid {
        let guard = RepositoryMutationGuard::acquire(&self.root)
            .await
            .expect("an unblocked repository admits");
        let parent = Uuid::now_v7();
        let store = guard
            .begin(parent, "commit".into(), "fixture".into())
            .await
            .expect("a parent begins");
        store
            .record_local_commit_child(parent, attempt, COMMIT.into(), b"intent".to_vec(), evidence)
            .await
            .expect("the local commit child records");
        parent
    }

    async fn child_state(&self, attempt: &AttemptId) -> AttemptState {
        let recovery = RepositoryMutationGuard::recover(&self.root)
            .await
            .expect("recovery opens the fence");
        recovery
            .store()
            .lookup(attempt)
            .await
            .expect("lookup")
            .expect("the child is journalled")
            .state
    }

    async fn parent_complete(&self, parent: Uuid) -> bool {
        let recovery = RepositoryMutationGuard::recover(&self.root)
            .await
            .expect("recovery opens the fence");
        recovery
            .store()
            .managed_parents()
            .await
            .expect("parents")
            .iter()
            .find(|held| held.id == parent.to_string())
            .expect("the parent is journalled")
            .complete
    }

    async fn refused(&self) -> bool {
        RepositoryMutationGuard::acquire(&self.root).await.is_err()
    }
}

/// The crash came before the commit moved an anchor: the next ordinary write admits itself, the
/// child settles `NotApplied` and the parent is complete.
#[tokio::test]
async fn a_write_after_a_commit_that_never_applied_is_admitted_and_closes_the_parent() {
    let rig = Rig::new().await;
    let attempt = AttemptId::new();
    let evidence = rig.evidence().await;
    let parent = rig.leave_open_parent(attempt, evidence).await;
    assert!(rig.refused().await, "the open parent blocks writes");

    assert_eq!(rig.stage("next.txt").await, 0, "the write is admitted");

    assert_eq!(
        rig.child_state(&attempt).await,
        AttemptState::Resolved(AttemptResolution::NotApplied)
    );
    assert!(rig.parent_complete(parent).await);
    assert!(!rig.refused().await);
}

/// The commit DID apply before the answer was lost, but only the unchanged anchors are proof: a
/// moved current is unknown, so the child stays unresolved, the parent open and writes refused.
#[tokio::test]
async fn a_write_after_an_applied_commit_stays_refused_and_unresolved() {
    let rig = Rig::new().await;
    let attempt = AttemptId::new();
    let evidence = rig.evidence().await;
    rig.commit_file("applied.txt").await;
    let parent = rig.leave_open_parent(attempt, evidence).await;
    assert!(rig.refused().await);

    assert_ne!(rig.stage("next.txt").await, 0, "the write is still refused");

    assert_eq!(rig.child_state(&attempt).await, AttemptState::Unresolved);
    assert!(!rig.parent_complete(parent).await);
    assert!(rig.refused().await);
}

/// An anchor that cannot be read is an error, never "unchanged": the child stays unresolved and
/// the write stays refused.
#[tokio::test]
async fn a_read_error_leaves_the_child_unresolved_and_the_write_refused() {
    let rig = Rig::new().await;
    let attempt = AttemptId::new();
    let evidence = rig.evidence().await;
    let parent = rig.leave_open_parent(attempt, evidence).await;
    rig.break_the_branch_anchor().await;
    assert_ne!(rig.stage("next.txt").await, 0);

    assert_eq!(rig.child_state(&attempt).await, AttemptState::Unresolved);
    assert!(!rig.parent_complete(parent).await);
    assert!(rig.refused().await);
}

/// `lore operation reconcile` settles the same way, reading no receipt.
#[tokio::test]
async fn reconcile_settles_a_local_commit_from_the_anchors() {
    let rig = Rig::new().await;
    let attempt = AttemptId::new();
    let evidence = rig.evidence().await;
    let parent = rig.leave_open_parent(attempt, evidence).await;

    let result = LORE_CONTEXT
        .scope(rig.execution(), async {
            let fence = RepositoryMutationGuard::recover(&rig.root).await.unwrap();
            lore::recovery::reconcile(&fence, |_, _| async {
                panic!("a local commit has no receipt to read")
            })
            .await
        })
        .await;
    result.expect("reconcile settles the local commit");

    assert_eq!(
        rig.child_state(&attempt).await,
        AttemptState::Resolved(AttemptResolution::NotApplied)
    );
    assert!(rig.parent_complete(parent).await);
    assert!(!rig.refused().await);
}

/// Without a command's execution context the working copy cannot be opened: nothing settles, and
/// the refusal stands.
#[tokio::test]
async fn settling_without_an_execution_context_changes_nothing() {
    let rig = Rig::new().await;
    let attempt = AttemptId::new();
    let evidence = rig.evidence().await;
    let parent = rig.leave_open_parent(attempt, evidence).await;

    let fence = RepositoryMutationGuard::recover(&rig.root).await.unwrap();
    assert!(!lore::recovery::settle_local_commits(&fence).await.unwrap());
    drop(fence);

    assert_eq!(rig.child_state(&attempt).await, AttemptState::Unresolved);
    assert!(!rig.parent_complete(parent).await);
    assert!(rig.refused().await);

    // With the context the same fence settles it.
    let settled = LORE_CONTEXT
        .scope(rig.execution(), async {
            let fence = RepositoryMutationGuard::recover(&rig.root).await.unwrap();
            lore::recovery::settle_local_commits(&fence).await.unwrap()
        })
        .await;
    assert!(settled);
    assert!(rig.parent_complete(parent).await);
}

/// Inside a running workflow the unresolved child may be the body's own, mid-commit, its anchors
/// not yet moved: settling there is an error and settles nothing, though the same evidence
/// settles `NotApplied` under the admission lock (`reconcile_settles_...`).
#[tokio::test]
async fn settling_inside_a_running_workflow_errors_and_settles_nothing() {
    let rig = Rig::new().await;
    let attempt = AttemptId::new();
    let evidence = rig.evidence().await;
    let outer = RepositoryMutationGuard::acquire(&rig.root).await.unwrap();
    let parent = Uuid::now_v7();
    let store = outer
        .begin(parent, "commit".into(), "fixture".into())
        .await
        .unwrap();
    store
        .record_local_commit_child(parent, attempt, COMMIT.into(), b"intent".to_vec(), evidence)
        .await
        .unwrap();

    let result = LORE_CONTEXT
        .scope(
            rig.execution(),
            outer.run(async {
                let nested = RepositoryMutationGuard::recover(&rig.root).await.unwrap();
                assert!(!nested.holds_admission_lock());
                lore::recovery::settle_local_commits(&nested).await
            }),
        )
        .await;
    assert!(result.is_err(), "{result:?}");

    let parents = store.managed_parents().await.unwrap();
    assert!(!parents[0].complete);
    assert_eq!(
        store.lookup(&attempt).await.unwrap().unwrap().state,
        AttemptState::Unresolved
    );
}

/// Admission settles from the anchors without the network even where the caller is online: the
/// repository has no revision (its branch latest is not found, the read that can fall back to a
/// remote) and its remote is a port nothing listens on.
#[tokio::test]
async fn admission_settlement_stays_offline_for_an_online_caller() {
    let rig = Rig::empty().await;
    let attempt = AttemptId::new();
    let evidence = rig.evidence().await;
    assert!(evidence.current.is_zero() && evidence.branch_latest.is_zero());
    let parent = rig.leave_open_parent(attempt, evidence).await;
    assert!(rig.refused().await);

    let mut online = rig.globals.clone();
    online.offline = 0;
    let execution = Arc::new(ExecutionContext::new_client_with_user_id(
        online,
        EventDispatcher::new(None),
        "local-commit-recovery-test".to_string(),
    ));
    let guard = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        lore::recovery::acquire_settling_local_commits(&rig.root, &execution),
    )
    .await
    .expect("settling must not wait on a remote")
    .expect("an unreachable remote does not refuse admission");
    drop(guard);

    assert_eq!(
        rig.child_state(&attempt).await,
        AttemptState::Resolved(AttemptResolution::NotApplied)
    );
    assert!(rig.parent_complete(parent).await);
}

/// The facade the desktop calls reads the same anchors as `capture`, with no execution context
/// of its own caller and no network.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_facade_reads_the_working_copy_anchors() {
    let rig = Rig::new().await;
    let expected = rig.evidence().await;
    let captured = lore::recovery::capture_local_commit_evidence(&rig.root)
        .await
        .expect("the facade captures offline");
    assert_eq!(captured, expected);
}

/// The embedder facade settles a never-applied local commit outside any command, with no caller
/// context.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_embedder_facade_settles_a_never_applied_commit() {
    let rig = Rig::new().await;
    let attempt = AttemptId::new();
    let evidence = rig.evidence().await;
    let parent = rig.leave_open_parent(attempt, evidence).await;
    assert!(rig.refused().await);

    assert!(
        lore::recovery::settle_local_commits_at(&rig.root)
            .await
            .expect("the facade settles")
    );
    assert_eq!(
        rig.child_state(&attempt).await,
        AttemptState::Resolved(AttemptResolution::NotApplied)
    );
    assert!(rig.parent_complete(parent).await);
    assert!(!rig.refused().await);
    assert!(
        !lore::recovery::settle_local_commits_at(&rig.root)
            .await
            .expect("a second pass finds nothing"),
    );
}
