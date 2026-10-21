// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

// Tests corrupt journal files directly, as managed_journal_v2.rs does.
#![allow(clippy::disallowed_methods)]

use std::path::Path;
use std::time::Instant;

use lore_base::types::RepositoryId;
use lore_revision::attempt_store::ManagedParent;
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_revision::attempt_store::phase_diagnostics;
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

/// One full parent cycle on `store`: begin, bind, one managed child recorded then settled,
/// body complete, finish. Every call leaves one more settled child in the journal.
async fn full_cycle(store: &RepositoryAttemptStore) -> Uuid {
    let parent = begin(store).await;
    let (record, intent) = child(parent);
    store.record_managed(&record, &intent).await.unwrap();
    store
        .resolve(&record.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    store.complete_parent_body(parent).await.unwrap();
    store.finish_parent(parent).await.unwrap();
    parent
}

fn counter(probe: &phase_diagnostics::Probe, phase: &'static str) -> usize {
    probe.snapshot().get(phase).map_or(0, |metric| metric.count)
}

/// Per-cycle `(child_read, child_parse)` deltas. `fresh_store` builds a new store instance (and so
/// an empty settled-validation cache) for every cycle, which is the pre-cache cost shape.
async fn cycle_reads(cycles: usize, fresh_store: bool) -> Vec<(usize, usize)> {
    let dir = tempfile::tempdir().unwrap();
    let probe = phase_diagnostics::Probe::install(dir.path().to_path_buf());
    let shared = RepositoryAttemptStore::in_directory(dir.path());
    let mut deltas = Vec::with_capacity(cycles);
    for _ in 0..cycles {
        let (reads, parses) = (
            counter(&probe, "child_read"),
            counter(&probe, "child_parse"),
        );
        if fresh_store {
            full_cycle(&RepositoryAttemptStore::in_directory(dir.path())).await;
        } else {
            full_cycle(&shared).await;
        }
        deltas.push((
            counter(&probe, "child_read") - reads,
            counter(&probe, "child_parse") - parses,
        ));
    }
    deltas
}

fn window_sum(deltas: &[(usize, usize)], range: std::ops::Range<usize>) -> (usize, usize) {
    deltas[range]
        .iter()
        .fold((0, 0), |sum, delta| (sum.0 + delta.0, sum.1 + delta.1))
}

/// Cycle count for the cached-store scaling test; the default keeps debug runs short.
fn scaling_cycles() -> usize {
    std::env::var("LORE_MANAGED_JOURNAL_CYCLES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(400)
}

// One store instance: settled-history validation must cost the same at cycle 900 as at cycle 0.
#[tokio::test]
async fn parent_cycle_child_reads_stay_flat_on_one_store_instance() {
    let cycles = scaling_cycles();
    assert!(
        cycles >= 300,
        "need disjoint first and last 100-cycle windows"
    );
    let deltas = cycle_reads(cycles, false).await;
    let first = window_sum(&deltas, 0..100);
    let last = window_sum(&deltas, cycles - 100..cycles);
    eprintln!(
        "cached store cycles={cycles} first100(read,parse)={first:?} last100(read,parse)={last:?} \
         max_cycle_read={:?}",
        deltas.iter().map(|delta| delta.0).max()
    );
    // Positive control: the probe observed child reads at all, so a zero cannot pass as "flat".
    assert!(first.0 > 0 && first.1 > 0, "probe saw no child reads");
    // Growth with history would multiply the last window by roughly cycles/100.
    assert!(
        last.0 <= first.0 + first.0 / 10,
        "child_read grew with history: first100={first:?} last100={last:?}"
    );
    assert!(
        last.1 <= first.1 + first.1 / 10,
        "child_parse grew with history: first100={first:?} last100={last:?}"
    );
}

// Discrimination control: a fresh instance per cycle has an empty cache, so it must show the
// per-parent full-history cost the cache removes. Fewer cycles: this shape is O(n^2).
#[tokio::test]
async fn parent_cycle_child_reads_grow_with_a_fresh_store_instance_per_cycle() {
    let cycles = 300;
    let deltas = cycle_reads(cycles, true).await;
    let first = window_sum(&deltas, 0..100);
    let last = window_sum(&deltas, cycles - 100..cycles);
    eprintln!(
        "fresh store cycles={cycles} first100(read,parse)={first:?} last100(read,parse)={last:?}"
    );
    assert!(first.0 > 0, "probe saw no child reads");
    assert!(
        last.0 > first.0 * 2 && last.1 > first.1 * 2,
        "fresh-instance control did not grow: first100={first:?} last100={last:?}"
    );
}

fn settled_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(settled_files(&path));
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
            && path
                .parent()
                .is_some_and(|parent| parent.ends_with("settled"))
        {
            found.push(path);
        }
    }
    found.sort();
    found
}

fn assert_protocol_error<T>(result: Result<T, impl std::fmt::Debug>, reason: &str) {
    match result {
        Ok(_) => panic!("expected failure containing {reason:?}, got success"),
        Err(error) => {
            let text = format!("{error:?}");
            assert!(text.contains(reason), "expected {reason:?} in {text}");
        }
    }
}

// Cached entries must be revalidated when the file changes underneath the same instance.
#[tokio::test]
async fn cached_settled_child_torn_in_place_blocks_begin_and_finish() {
    let dir = tempfile::tempdir().unwrap();
    let store = RepositoryAttemptStore::in_directory(dir.path());
    full_cycle(&store).await;
    let second = full_cycle(&store).await; // begin_parent has cached the first cycle's child.
    let files = settled_files(dir.path());
    assert_eq!(files.len(), 2, "both settled children must be on disk");
    std::fs::write(&files[0], b"torn").unwrap();

    let next = Uuid::now_v7();
    let parent = ManagedParent {
        version: 1,
        id: next.to_string(),
        root: "journal-scaling".into(),
        operation: "compact".into(),
        normalized_intent: "journal-scaling".into(),
        namespace: None,
        complete: false,
        parent_uncertainty_code: None,
        body_completed: false,
    };
    assert_protocol_error(store.begin_parent(parent).await, "parse child");
    assert_protocol_error(store.finish_parent(second).await, "parse child");
}

#[tokio::test]
async fn cached_settled_child_rewritten_with_wrong_identity_blocks_begin_and_finish() {
    let dir = tempfile::tempdir().unwrap();
    let store = RepositoryAttemptStore::in_directory(dir.path());
    full_cycle(&store).await;
    let second = full_cycle(&store).await;
    let files = settled_files(dir.path());
    assert_eq!(files.len(), 2);
    let original = std::fs::read(&files[0]).unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(&original).unwrap();
    body["attempt"]["attempt_id"] = serde_json::json!(Uuid::from_u128(9).to_string());
    // Pretty-printing guarantees a different length from the compact original.
    let rewritten = serde_json::to_vec_pretty(&body).unwrap();
    assert_ne!(rewritten.len(), original.len());
    std::fs::write(&files[0], rewritten).unwrap();

    let parent = ManagedParent {
        version: 1,
        id: Uuid::now_v7().to_string(),
        root: "journal-scaling".into(),
        operation: "compact".into(),
        normalized_intent: "journal-scaling".into(),
        namespace: None,
        complete: false,
        parent_uncertainty_code: None,
        body_completed: false,
    };
    assert_protocol_error(
        store.begin_parent(parent).await,
        "invalid journal child version or identity",
    );
    assert_protocol_error(
        store.finish_parent(second).await,
        "invalid journal child version or identity",
    );
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
