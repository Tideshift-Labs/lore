// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use super::*;

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn spawn(root: &Path, index: u128, mode: &str) -> OwnedChild {
    let log = std::fs::File::create(root.join(format!("worker-{index}.log"))).unwrap();
    OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "process::worker", "--nocapture"])
            .env("LORE_JOURNAL_V2_ROOT", root)
            .env("LORE_JOURNAL_V2_INDEX", index.to_string())
            .env("LORE_JOURNAL_V2_MODE", mode)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    )
}

fn wait_for(path: &Path) {
    let started = Instant::now();
    while !path.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "child did not publish {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_success(child: &mut OwnedChild) {
    let started = Instant::now();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "journal worker exited {status}");
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "journal worker hung"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn concurrent_processes_preserve_both_managed_children() {
    let dir = tempfile::tempdir().unwrap();
    drop(runtime().block_on(migrated(dir.path())));
    let mut first = spawn(dir.path(), 7, "settle-exit");
    let mut second = spawn(dir.path(), 8, "settle-exit");
    wait_for(&dir.path().join("ready-7"));
    wait_for(&dir.path().join("ready-8"));
    std::fs::write(dir.path().join("go"), b"go").unwrap();
    wait_success(&mut first);
    wait_success(&mut second);
    runtime().block_on(async {
        let store = RepositoryAttemptStore::in_directory(dir.path());
        for index in [7, 8] {
            assert_eq!(
                store.lookup(&id(index)).await.unwrap(),
                Some(record(
                    index,
                    AttemptState::Resolved(AttemptResolution::Applied)
                ))
            );
            assert_eq!(
                store
                    .recovery_context(&id(index))
                    .await
                    .unwrap()
                    .authenticated_subject,
                "subject"
            );
        }
        assert_eq!(store.unresolved().await.unwrap().len(), 2);
    });
}

#[test]
fn killed_process_preserves_acknowledged_pending_child() {
    kill_after_acknowledgment("record-hold", AttemptState::Unresolved);
}

#[test]
fn killed_process_preserves_acknowledged_settlement() {
    kill_after_acknowledgment(
        "settle-hold",
        AttemptState::Resolved(AttemptResolution::Applied),
    );
}

fn kill_after_acknowledgment(mode: &str, expected: AttemptState) {
    let dir = tempfile::tempdir().unwrap();
    drop(runtime().block_on(migrated(dir.path())));
    let mut child = spawn(dir.path(), 7, mode);
    wait_for(&dir.path().join("ready-7"));
    std::fs::write(dir.path().join("go"), b"go").unwrap();
    wait_for(&dir.path().join("ack-7"));
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    runtime().block_on(async {
        let store = RepositoryAttemptStore::in_directory(dir.path());
        assert_eq!(
            store.lookup(&id(7)).await.unwrap(),
            Some(record(7, expected.clone()))
        );
        assert_eq!(
            store
                .recovery_context(&id(7))
                .await
                .unwrap()
                .authenticated_subject,
            "subject"
        );
        assert_eq!(
            store
                .unresolved()
                .await
                .unwrap()
                .iter()
                .any(|record| record.attempt_id == id(7)),
            expected == AttemptState::Unresolved
        );
    });
}

#[test]
#[ignore = "subprocess helper; process tests supply an isolated root and start barrier"]
fn worker() {
    let root = PathBuf::from(std::env::var_os("LORE_JOURNAL_V2_ROOT").expect("fixture root"));
    let index: u128 = std::env::var("LORE_JOURNAL_V2_INDEX")
        .unwrap()
        .parse()
        .unwrap();
    let mode = std::env::var("LORE_JOURNAL_V2_MODE").unwrap();
    assert!(["record-hold", "settle-hold", "settle-exit"].contains(&mode.as_str()));
    std::fs::write(root.join(format!("ready-{index}")), b"ready").unwrap();
    wait_for(&root.join("go"));
    runtime().block_on(async {
        let store = RepositoryAttemptStore::in_directory(&root);
        store
            .record_managed(&record(index, AttemptState::Unresolved), &intent(index))
            .await
            .unwrap();
        if mode != "record-hold" {
            store
                .resolve(&id(index), AttemptResolution::Applied)
                .await
                .unwrap();
        }
        std::fs::write(root.join(format!("ack-{index}")), b"acknowledged").unwrap();
        if mode != "settle-exit" {
            std::future::pending::<()>().await;
        }
    });
}
