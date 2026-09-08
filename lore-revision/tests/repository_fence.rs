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
            store.mark_parent_uncertain(parent, 194).await.unwrap();
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
        assert_eq!(parents[0].parent_uncertainty_code, uncertain.then_some(194));
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

fn record(parent: Uuid) -> (AttemptRecord, ManagedAttemptIntent) {
    let repository = RepositoryId::from([1; 16]);
    let rpc = "StorageService.Put".to_owned();
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
    guard
        .begin(parent, "desktop commit".into(), "selected paths".into())
        .await
        .unwrap();
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
                guard
                    .begin(
                        Uuid::now_v7(),
                        "child process".into(),
                        "fixture intent".into(),
                    )
                    .await
                    .unwrap();
                std::fs::write(root.join(format!("{name}.result")), b"admitted").unwrap();
                if mode == "hold" {
                    std::future::pending::<()>().await;
                }
            }
            Err(_) => {
                std::fs::write(root.join(format!("{name}.result")), b"refused").unwrap();
            }
        }
    });
}
