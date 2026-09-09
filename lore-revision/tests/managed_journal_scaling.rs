// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::time::Instant;

use lore_base::types::RepositoryId;
use lore_revision::attempt_store::ManagedParent;
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptState;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::caller_operation::CallerRecoveryContext;
use lore_transport::caller_operation::ManagedAttemptIntent;
use lore_transport::outcome::AttemptId;
use uuid::Uuid;

fn binding() -> CallerRecoveryContext {
    CallerRecoveryContext {
        repository: RepositoryId::from([0x41; 16]),
        endpoint: "https://journal-scaling.invalid:443".into(),
        verified_issuer: "journal-scaling-issuer".into(),
        authenticated_subject: "journal-scaling-subject".into(),
        caller_capabilities: "read,write".into(),
    }
}

async fn begin(store: &RepositoryAttemptStore) -> Uuid {
    let parent = Uuid::now_v7();
    store
        .begin_parent(ManagedParent {
            version: 1,
            id: parent.to_string(),
            root: "journal-scaling".into(),
            operation: "compact".into(),
            normalized_intent: "journal-scaling".into(),
            namespace: None,
            complete: false,
            parent_uncertainty_code: None,
            body_completed: false,
        })
        .await
        .unwrap();
    store
        .bind_parent_namespace(parent, &binding())
        .await
        .unwrap();
    parent
}

fn child(parent: Uuid) -> (AttemptRecord, ManagedAttemptIntent) {
    let binding = binding();
    let record = AttemptRecord {
        attempt_id: AttemptId::new(),
        state: AttemptState::Unresolved,
        operation: "Storage.Put".into(),
        repository: binding.repository,
        recorded_at_unix_millis: 1_000,
        receipt: None,
    };
    let intent = ManagedAttemptIntent {
        version: 1,
        parent_id: parent,
        repository: binding.repository,
        rpc: record.operation.clone(),
        // Fixed-size opaque intent: this measures the journal, not transport serialization.
        canonical_request: vec![0x42; 64],
        endpoint: binding.endpoint,
        verified_issuer: binding.verified_issuer,
        authenticated_subject: binding.authenticated_subject,
        caller_capabilities: binding.caller_capabilities,
    };
    (record, intent)
}

fn directory_bytes(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            if metadata.is_dir() {
                directory_bytes(&entry.path())
            } else {
                metadata.len()
            }
        })
        .sum()
}

// Run with --release -- --ignored --exact managed_storage_put_scaling --nocapture.
// LORE_MANAGED_JOURNAL_SIZES selects a comma-separated subset of 1..=4000; default 1000,2000,4000.
// No time threshold: record/resolve and reopen verification have separate descriptive timings.
#[tokio::test]
#[ignore = "real durable journal scaling measurement; opt in with --ignored --nocapture"]
async fn managed_storage_put_scaling() {
    let sizes =
        std::env::var("LORE_MANAGED_JOURNAL_SIZES").unwrap_or_else(|_| "1000,2000,4000".into());
    let sizes: Vec<usize> = sizes
        .split(',')
        .map(|value| value.trim().parse().expect("sizes must be integers"))
        .collect();
    assert!(!sizes.is_empty() && sizes.len() <= 3);
    assert!(sizes.iter().all(|size| (1..=4000).contains(size)));
    for count in sizes {
        let dir = tempfile::tempdir().unwrap();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        let parent = begin(&store).await;
        let records: Vec<_> = (0..count).map(|_| child(parent)).collect();
        let started = Instant::now();
        for (record, intent) in &records {
            store.record_managed(record, intent).await.unwrap();
            store
                .resolve(&record.attempt_id, AttemptResolution::Applied)
                .await
                .unwrap();
        }
        let write_elapsed = started.elapsed();
        let retained_bytes = directory_bytes(dir.path());
        eprintln!(
            "managed_journal children={count} record_resolve_ms={:.3} retained_bytes={retained_bytes} profile={}",
            write_elapsed.as_secs_f64() * 1000.0,
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
        );
        drop(store);

        let started = Instant::now();
        let reopened = RepositoryAttemptStore::in_directory(dir.path());
        assert!(reopened.unresolved().await.unwrap().is_empty());
        for (record, _) in &records {
            let mut expected = record.clone();
            expected.state = AttemptState::Resolved(AttemptResolution::Applied);
            assert_eq!(
                reopened.lookup(&record.attempt_id).await.unwrap(),
                Some(expected)
            );
            assert_eq!(
                reopened.recovery_context(&record.attempt_id).await.unwrap(),
                binding()
            );
        }
        reopened.complete_parent_body(parent).await.unwrap();
        reopened.finish_parent(parent).await.unwrap();
        drop(reopened);
        let reopened = RepositoryAttemptStore::in_directory(dir.path());
        let parents = reopened.managed_parents().await.unwrap();
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].id, parent.to_string());
        assert!(parents[0].complete && parents[0].body_completed);
        eprintln!(
            "managed_journal children={count} reopen_verify_ms={:.3} verified_applied={count}",
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
}

#[tokio::test]
async fn unresolved_excludes_each_settled_managed_child() {
    let dir = tempfile::tempdir().unwrap();
    let store = RepositoryAttemptStore::in_directory(dir.path());
    let parent = begin(&store).await;
    let children: Vec<_> = (0..3).map(|_| child(parent)).collect();
    for (record, intent) in &children {
        store.record_managed(record, intent).await.unwrap();
    }
    assert_eq!(store.unresolved().await.unwrap().len(), children.len());
    for (index, (record, _)) in children.iter().enumerate() {
        store
            .resolve(&record.attempt_id, AttemptResolution::Applied)
            .await
            .unwrap();
        let unresolved = store.unresolved().await.unwrap();
        let remaining = &children[index + 1..];
        assert_eq!(unresolved.len(), remaining.len());
        for (pending, _) in remaining {
            assert!(
                unresolved.contains(pending),
                "unsettled child must remain visible"
            );
        }
    }
    drop(store);
    let reopened = RepositoryAttemptStore::in_directory(dir.path());
    assert!(reopened.unresolved().await.unwrap().is_empty());
    for (mut record, _) in children {
        record.state = AttemptState::Resolved(AttemptResolution::Applied);
        assert_eq!(
            reopened.lookup(&record.attempt_id).await.unwrap(),
            Some(record)
        );
    }
}

#[tokio::test]
async fn pending_managed_child_blocks_completion_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let store = RepositoryAttemptStore::in_directory(dir.path());
    let parent = begin(&store).await;
    let (applied, applied_intent) = child(parent);
    let (pending, pending_intent) = child(parent);
    store
        .record_managed(&applied, &applied_intent)
        .await
        .unwrap();
    store
        .resolve(&applied.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    store
        .record_managed(&pending, &pending_intent)
        .await
        .unwrap();
    store.complete_parent_body(parent).await.unwrap();
    drop(store);

    let reopened = RepositoryAttemptStore::in_directory(dir.path());
    assert_eq!(reopened.unresolved().await.unwrap(), vec![pending.clone()]);
    assert!(reopened.finish_parent(parent).await.is_err());
    assert!(!reopened.managed_parents().await.unwrap()[0].complete);
    assert_eq!(
        reopened
            .recovery_context(&pending.attempt_id)
            .await
            .unwrap(),
        binding()
    );
    reopened
        .resolve(&pending.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    reopened.finish_parent(parent).await.unwrap();
    drop(reopened);
    let reopened = RepositoryAttemptStore::in_directory(dir.path());
    assert!(reopened.managed_parents().await.unwrap()[0].complete);
    assert_eq!(
        reopened
            .lookup(&pending.attempt_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        AttemptState::Resolved(AttemptResolution::Applied)
    );
}
