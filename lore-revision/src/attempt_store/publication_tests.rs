// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

#![allow(clippy::disallowed_methods)]

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use super::persistence::PublicationPoint;
use super::persistence::install_publication_probe;
use super::*;

fn record(index: u128, state: AttemptState) -> AttemptRecord {
    AttemptRecord {
        attempt_id: AttemptId::from_uuid(Uuid::from_u128(index)),
        state,
        operation: "Storage.Put".into(),
        repository: RepositoryId::from([0x41; 16]),
        recorded_at_unix_millis: 1_000,
        receipt: None,
    }
}

fn points() -> [PublicationPoint; 4] {
    [
        PublicationPoint::AfterWrite,
        PublicationPoint::AfterSync,
        PublicationPoint::BeforeRename,
        PublicationPoint::AfterRename,
    ]
}

fn legacy(path: &Path) -> Vec<u8> {
    let document = serde_json::json!({"attempts":[{
        "attempt_id":record(1, AttemptState::Unresolved).attempt_id.to_string(),
        "state":{"state":"unresolved"}, "operation":"Storage.Put",
        "repository":RepositoryId::from([0x41;16]).to_string(), "recorded_at_unix_millis":1000
    }]});
    let mut bytes = vec![1];
    bytes.extend(serde_json::to_vec(&document).unwrap());
    std::fs::write(path.join("attempts"), &bytes).unwrap();
    bytes
}

fn fail(fired: &AtomicBool) -> Result<(), ProtocolError> {
    fired.store(true, Ordering::SeqCst);
    Err(ProtocolError::internal(
        "injected journal publication failure",
    ))
}

fn assert_injected(result: Result<(), ProtocolError>, fired: &AtomicBool) {
    assert!(fired.load(Ordering::SeqCst), "publication hook did not run");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("injected journal publication failure")
    );
}

// On Unix these hooks bracket the actual rename -> directory sync boundary. Windows' native
// move already uses WRITE_THROUGH, so its hook run proves the simulated failure/retry protocol,
// not an observed Windows directory-fsync failure or a power-loss guarantee.
#[tokio::test]
async fn visible_root_with_failed_directory_barrier_cannot_acknowledge_a_retry() {
    let dir = tempfile::tempdir().unwrap();
    legacy(dir.path());
    let root = dir.path().join("attempts");
    let directory = dir.path().to_path_buf();
    let armed = Arc::new(AtomicBool::new(false));
    let failures = Arc::new(AtomicUsize::new(0));
    let visible = armed.clone();
    let counter = failures.clone();
    let probe =
        install_publication_probe(dir.path().to_path_buf(), move |point, _, destination| {
            if point == PublicationPoint::AfterRenameBeforeDirectorySync && destination == root {
                assert!(
                    root.is_file(),
                    "selected root rename must already be visible"
                );
                visible.store(true, Ordering::SeqCst);
            }
            if point == PublicationPoint::BeforeDirectorySync
                && destination == directory
                && visible.load(Ordering::SeqCst)
            {
                counter.fetch_add(1, Ordering::SeqCst);
                return Err(ProtocolError::internal(
                    "injected directory barrier failure",
                ));
            }
            Ok(())
        });
    let first = RepositoryAttemptStore::in_directory(dir.path());
    assert!(
        first
            .lookup(&record(1, AttemptState::Unresolved).attempt_id)
            .await
            .unwrap_err()
            .to_string()
            .contains("injected directory barrier failure")
    );
    assert!(armed.load(Ordering::SeqCst));
    assert_eq!(std::fs::read(dir.path().join("attempts")).unwrap()[0], 2);
    let initial_failures = failures.load(Ordering::SeqCst);
    assert!(initial_failures > 0);
    drop(first);

    let reopened = RepositoryAttemptStore::in_directory(dir.path());
    assert!(
        reopened
            .record(&record(2, AttemptState::Unresolved))
            .await
            .unwrap_err()
            .to_string()
            .contains("injected directory barrier failure")
    );
    assert!(
        failures.load(Ordering::SeqCst) > initial_failures,
        "fresh-store retry must revisit the barrier for the already visible root"
    );
    drop(reopened);
    assert_barrier_retry_fails_in_fresh_process(dir.path());
    drop(probe);

    let repaired = RepositoryAttemptStore::in_directory(dir.path());
    repaired
        .record(&record(2, AttemptState::Unresolved))
        .await
        .unwrap();
    drop(repaired);
    let reopened = RepositoryAttemptStore::in_directory(dir.path());
    for index in [1, 2] {
        assert_eq!(
            reopened
                .lookup(&record(index, AttemptState::Unresolved).attempt_id)
                .await
                .unwrap(),
            Some(record(index, AttemptState::Unresolved))
        );
    }
}

#[tokio::test]
async fn visible_ancestor_with_failed_directory_barrier_cannot_acknowledge_a_retry() {
    let dir = tempfile::tempdir().unwrap();
    let ancestor = dir.path().join("unfinished-ancestor");
    let journal = ancestor.join("journal");
    let barrier_directory = dir.path().to_path_buf();
    let armed = Arc::new(AtomicBool::new(false));
    let failures = Arc::new(AtomicUsize::new(0));
    let visible = armed.clone();
    let counter = failures.clone();
    let published = ancestor.clone();
    let probe =
        install_publication_probe(dir.path().to_path_buf(), move |point, _, destination| {
            if point == PublicationPoint::AfterRenameBeforeDirectorySync && destination == published
            {
                assert!(
                    published.is_dir(),
                    "selected ancestor rename must already be visible"
                );
                visible.store(true, Ordering::SeqCst);
            }
            if point == PublicationPoint::BeforeDirectorySync
                && destination == barrier_directory
                && visible.load(Ordering::SeqCst)
            {
                counter.fetch_add(1, Ordering::SeqCst);
                return Err(ProtocolError::internal(
                    "injected directory barrier failure",
                ));
            }
            Ok(())
        });
    let first = RepositoryAttemptStore::in_directory(&journal);
    assert!(
        first
            .record(&record(1, AttemptState::Unresolved))
            .await
            .unwrap_err()
            .to_string()
            .contains("injected directory barrier failure")
    );
    assert!(ancestor.is_dir());
    assert!(armed.load(Ordering::SeqCst));
    let initial_failures = failures.load(Ordering::SeqCst);
    assert!(initial_failures > 0);
    drop(first);

    let reopened = RepositoryAttemptStore::in_directory(&journal);
    assert!(
        reopened
            .record(&record(1, AttemptState::Unresolved))
            .await
            .unwrap_err()
            .to_string()
            .contains("injected directory barrier failure")
    );
    assert!(
        failures.load(Ordering::SeqCst) > initial_failures,
        "existing ancestor must not bypass its failed publication barrier"
    );
    drop(reopened);
    drop(probe);

    let repaired = RepositoryAttemptStore::in_directory(&journal);
    repaired
        .record(&record(1, AttemptState::Unresolved))
        .await
        .unwrap();
    drop(repaired);
    let reopened = RepositoryAttemptStore::in_directory(&journal);
    assert_eq!(
        reopened
            .lookup(&record(1, AttemptState::Unresolved).attempt_id)
            .await
            .unwrap(),
        Some(record(1, AttemptState::Unresolved))
    );
}

#[tokio::test]
async fn orphan_plain_record_root_failure_requires_exact_intent_retry() {
    for mismatch in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let pending = record(1, AttemptState::Unresolved);
        let parent_id = Uuid::from_u128(100);
        let document = StoredDocument {
            parents: vec![ManagedParent {
                version: 1,
                id: parent_id.to_string(),
                root: "fixture".into(),
                operation: "compact".into(),
                normalized_intent: "fixture".into(),
                namespace: None,
                complete: false,
                parent_uncertainty_code: None,
                body_completed: false,
            }],
            managed: vec![StoredManagedIntent {
                attempt: pending.attempt_id.to_string(),
                parent: parent_id.to_string(),
                rpc: "Storage.Put".into(),
                canonical_request: vec![8, 1],
            }],
            ..StoredDocument::default()
        };
        let mut bytes = vec![1];
        bytes.extend(serde_json::to_vec(&document).unwrap());
        let root = dir.path().join("attempts");
        std::fs::write(&root, bytes).unwrap();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        assert_eq!(store.lookup(&pending.attempt_id).await.unwrap(), None);
        let before = std::fs::read(&root).unwrap();
        let fired = Arc::new(AtomicBool::new(false));
        let signal = fired.clone();
        let probe =
            install_publication_probe(dir.path().to_path_buf(), move |point, _, destination| {
                if point == PublicationPoint::BeforeRename && destination == root {
                    fail(&signal)
                } else {
                    Ok(())
                }
            });
        assert_injected(store.record(&pending).await, &fired);
        drop(probe);
        drop(store);
        assert_eq!(std::fs::read(dir.path().join("attempts")).unwrap(), before);
        let reopened = RepositoryAttemptStore::in_directory(dir.path());
        assert!(
            reopened.managed_parents().await.is_err(),
            "root/child duplicate must fence admission"
        );
        if mismatch {
            let document: StoredDocument = serde_json::from_slice(&before[1..]).unwrap();
            let path = dir
                .path()
                .join(format!("attempts-v2-{}", document.generation.unwrap()))
                .join("pending")
                .join(format!("{}.json", pending.attempt_id));
            let mut child: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            child["managed"]["canonical_request"] = serde_json::json!([9, 9]);
            let changed = serde_json::to_vec(&child).unwrap();
            std::fs::write(&path, &changed).unwrap();
            assert!(reopened.record(&pending).await.is_err());
            assert_eq!(std::fs::read(&path).unwrap(), changed);
            assert_eq!(std::fs::read(dir.path().join("attempts")).unwrap(), before);
        } else {
            reopened.record(&pending).await.unwrap();
            assert_eq!(reopened.managed_parents().await.unwrap().len(), 1);
            assert_eq!(
                reopened.lookup(&pending.attempt_id).await.unwrap(),
                Some(pending)
            );
        }
    }
}

#[tokio::test]
async fn migration_root_publication_errors_preserve_recoverable_authority() {
    for point in points() {
        let dir = tempfile::tempdir().unwrap();
        let original = legacy(dir.path());
        let fired = Arc::new(AtomicBool::new(false));
        let signal = fired.clone();
        let root = dir.path().join("attempts");
        let probe =
            install_publication_probe(dir.path().to_path_buf(), move |stage, _, destination| {
                if stage == point && destination == root {
                    fail(&signal)
                } else {
                    Ok(())
                }
            });
        let store = RepositoryAttemptStore::in_directory(dir.path());
        assert_injected(
            store
                .lookup(&record(1, AttemptState::Unresolved).attempt_id)
                .await
                .map(|_| ()),
            &fired,
        );
        let bytes = std::fs::read(dir.path().join("attempts")).unwrap();
        if point == PublicationPoint::AfterRename {
            assert_eq!(bytes[0], 2);
        } else {
            assert_eq!(bytes, original);
        }
        drop(probe);
        drop(store);
        let reopened = RepositoryAttemptStore::in_directory(dir.path());
        assert_eq!(
            reopened
                .lookup(&record(1, AttemptState::Unresolved).attempt_id)
                .await
                .unwrap(),
            Some(record(1, AttemptState::Unresolved))
        );
    }
}

#[tokio::test]
async fn child_record_publication_errors_do_not_acknowledge_missing_intent() {
    for point in points() {
        let dir = tempfile::tempdir().unwrap();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        store
            .record(&record(1, AttemptState::Unresolved))
            .await
            .unwrap();
        let next = record(2, AttemptState::Unresolved);
        let name = format!("{}.json", next.attempt_id);
        let fired = Arc::new(AtomicBool::new(false));
        let signal = fired.clone();
        let probe =
            install_publication_probe(dir.path().to_path_buf(), move |stage, _, destination| {
                if stage == point
                    && destination
                        .file_name()
                        .is_some_and(|file| file == name.as_str())
                {
                    fail(&signal)
                } else {
                    Ok(())
                }
            });
        assert_injected(store.record(&next).await, &fired);
        drop(probe);
        drop(store);
        let reopened = RepositoryAttemptStore::in_directory(dir.path());
        assert_eq!(
            reopened.lookup(&next.attempt_id).await.unwrap(),
            (point == PublicationPoint::AfterRename).then_some(next)
        );
        assert_eq!(
            reopened
                .lookup(&record(1, AttemptState::Unresolved).attempt_id)
                .await
                .unwrap(),
            Some(record(1, AttemptState::Unresolved))
        );
    }
}

#[tokio::test]
async fn settlement_publication_errors_preserve_prior_or_terminal_evidence() {
    for point in points() {
        let dir = tempfile::tempdir().unwrap();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        let pending = record(1, AttemptState::Unresolved);
        store.record(&pending).await.unwrap();
        let name = format!("{}.json", pending.attempt_id);
        let fired = Arc::new(AtomicBool::new(false));
        let signal = fired.clone();
        let probe =
            install_publication_probe(dir.path().to_path_buf(), move |stage, _, destination| {
                if stage == point
                    && destination
                        .file_name()
                        .is_some_and(|file| file == name.as_str())
                    && destination
                        .parent()
                        .is_some_and(|parent| parent.ends_with("pending"))
                {
                    fail(&signal)
                } else {
                    Ok(())
                }
            });
        assert_injected(
            store
                .resolve(&pending.attempt_id, AttemptResolution::Applied)
                .await,
            &fired,
        );
        drop(probe);
        drop(store);
        let reopened = RepositoryAttemptStore::in_directory(dir.path());
        let expected = if point == PublicationPoint::AfterRename {
            record(1, AttemptState::Resolved(AttemptResolution::Applied))
        } else {
            pending.clone()
        };
        assert_eq!(
            reopened.lookup(&pending.attempt_id).await.unwrap(),
            Some(expected)
        );
        assert_eq!(
            reopened.unresolved().await.unwrap().len(),
            usize::from(point != PublicationPoint::AfterRename)
        );
    }
}

#[tokio::test]
async fn settlement_directory_move_errors_retain_terminal_evidence() {
    for point in [
        PublicationPoint::BeforeRename,
        PublicationPoint::AfterRename,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        let pending = record(1, AttemptState::Unresolved);
        store.record(&pending).await.unwrap();
        let fired = Arc::new(AtomicBool::new(false));
        let signal = fired.clone();
        let probe = install_publication_probe(
            dir.path().to_path_buf(),
            move |stage, source, destination| {
                if stage == point
                    && source
                        .parent()
                        .is_some_and(|parent| parent.ends_with("pending"))
                    && destination
                        .parent()
                        .is_some_and(|parent| parent.ends_with("settled"))
                {
                    fail(&signal)
                } else {
                    Ok(())
                }
            },
        );
        assert_injected(
            store
                .resolve(&pending.attempt_id, AttemptResolution::Applied)
                .await,
            &fired,
        );
        drop(probe);
        drop(store);
        let reopened = RepositoryAttemptStore::in_directory(dir.path());
        assert_eq!(
            reopened.lookup(&pending.attempt_id).await.unwrap(),
            Some(record(
                1,
                AttemptState::Resolved(AttemptResolution::Applied)
            ))
        );
        assert!(reopened.unresolved().await.unwrap().is_empty());
    }
}

#[test]
fn process_exit_inside_publication_leaves_recoverable_disk_state() {
    for mode in ["migration-before", "migration-after", "resolve-after"] {
        let dir = tempfile::tempdir().unwrap();
        let original = legacy(dir.path());
        if mode == "resolve-after" {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let store = RepositoryAttemptStore::in_directory(dir.path());
                store
                    .lookup(&record(1, AttemptState::Unresolved).attempt_id)
                    .await
                    .unwrap();
            });
        }
        let log = std::fs::File::create(dir.path().join("worker.log")).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "attempt_store::publication_tests::crash_worker",
                "--nocapture",
            ])
            .env("LORE_JOURNAL_PUBLICATION_ROOT", dir.path())
            .env("LORE_JOURNAL_PUBLICATION_MODE", mode)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut child = TestProcess(child);
        let started = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(20),
                "publication worker hung"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(
            status.code(),
            Some(77),
            "child must exit from the publication hook"
        );
        if mode == "migration-before" {
            assert_eq!(
                std::fs::read(dir.path().join("attempts")).unwrap(),
                original
            );
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let store = RepositoryAttemptStore::in_directory(dir.path());
            let expected = if mode == "resolve-after" {
                AttemptState::Resolved(AttemptResolution::Applied)
            } else {
                AttemptState::Unresolved
            };
            assert_eq!(
                store
                    .lookup(&record(1, AttemptState::Unresolved).attempt_id)
                    .await
                    .unwrap(),
                Some(record(1, expected))
            );
        });
    }
}

struct TestProcess(std::process::Child);

fn assert_barrier_retry_fails_in_fresh_process(root: &Path) {
    let log = std::fs::File::create(root.join("retry-worker.log")).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "attempt_store::publication_tests::crash_worker",
            "--nocapture",
        ])
        .env("LORE_JOURNAL_PUBLICATION_ROOT", root)
        .env("LORE_JOURNAL_PUBLICATION_MODE", "barrier-retry")
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let mut child = TestProcess(child);
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "fresh-process barrier retry failed: {status}"
            );
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "barrier retry worker hung"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
#[ignore = "publication crash subprocess helper; parent test supplies isolated root and mode"]
fn crash_worker() {
    let root =
        PathBuf::from(std::env::var_os("LORE_JOURNAL_PUBLICATION_ROOT").expect("fixture root"));
    let mode = std::env::var("LORE_JOURNAL_PUBLICATION_MODE").unwrap();
    if mode == "barrier-retry" {
        let directory = root.clone();
        let fired = Arc::new(AtomicBool::new(false));
        let signal = fired.clone();
        let _probe = install_publication_probe(root.clone(), move |point, _, destination| {
            if point == PublicationPoint::BeforeDirectorySync && destination == directory {
                signal.store(true, Ordering::SeqCst);
                return Err(ProtocolError::internal(
                    "injected directory barrier failure",
                ));
            }
            Ok(())
        });
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let store = RepositoryAttemptStore::in_directory(root);
            let error = store
                .record(&record(2, AttemptState::Unresolved))
                .await
                .unwrap_err();
            assert!(
                fired.load(Ordering::SeqCst),
                "new process must retry the directory barrier"
            );
            assert!(
                error
                    .to_string()
                    .contains("injected directory barrier failure")
            );
        });
        return;
    }
    assert!(["migration-before", "migration-after", "resolve-after"].contains(&mode.as_str()));
    let root_file = root.join("attempts");
    let selection = mode.clone();
    let _probe = install_publication_probe(root.clone(), move |stage, _, destination| {
        let selected = match selection.as_str() {
            "migration-before" => stage == PublicationPoint::AfterSync && destination == root_file,
            "migration-after" => stage == PublicationPoint::AfterRename && destination == root_file,
            "resolve-after" => {
                stage == PublicationPoint::AfterRename
                    && destination
                        .parent()
                        .is_some_and(|parent| parent.ends_with("pending"))
            }
            _ => false,
        };
        if selected {
            std::process::exit(77);
        }
        Ok(())
    });
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let store = RepositoryAttemptStore::in_directory(root);
        if mode == "resolve-after" {
            store
                .resolve(
                    &record(1, AttemptState::Unresolved).attempt_id,
                    AttemptResolution::Applied,
                )
                .await
                .unwrap();
        } else {
            store
                .lookup(&record(1, AttemptState::Unresolved).attempt_id)
                .await
                .unwrap();
        }
        panic!("publication hook was never reached");
    });
}
