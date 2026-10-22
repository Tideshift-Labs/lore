// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! `RepositoryAttemptStore::finish_parent` prunes expired settled history and refreshes the
//! admission marker over what remains, in one root write. [CLIENT]-class: `lore-revision` ships
//! into user workstations.
//!
//! Recovery (`reconcile_parent`, `managed_parents`) never prunes and never writes a marker; these
//! tests also pin that a journal pruned at any point still loads and recovers as before.

// Tests build, corrupt and re-time journal files directly, as admission_marker.rs does.
#![allow(clippy::disallowed_methods)]

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::SystemTime;

use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::RepositoryId;
use lore_revision::attempt_store::ManagedParent;
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_revision::attempt_store::persistence::PublicationPoint;
use lore_revision::attempt_store::persistence::install_publication_probe;
use lore_revision::attempt_store::phase_diagnostics;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptState;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::LockOwnership;
use lore_transport::attempt_store::OwnershipToken;
use lore_transport::caller_operation::CallerRecoveryContext;
use lore_transport::caller_operation::ManagedAttemptIntent;
use lore_transport::error::ProtocolError;
use lore_transport::outcome::AttemptId;
use serde_json::Value;
use uuid::Uuid;

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

// ---------------------------------------------------------------------------
// Fixtures (same shapes as admission_marker.rs)
// ---------------------------------------------------------------------------

fn binding() -> CallerRecoveryContext {
    CallerRecoveryContext {
        repository: RepositoryId::from([0x43; 16]),
        endpoint: "https://attempt-prune.invalid:443".into(),
        verified_issuer: "prune-issuer".into(),
        authenticated_subject: "prune-subject".into(),
        caller_capabilities: "read,write".into(),
    }
}

/// A `UUIDv7` whose embedded timestamp is `age` ago.
fn v7_aged(age: Duration) -> Uuid {
    let created = SystemTime::now()
        .checked_sub(age)
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    Uuid::new_v7(uuid::Timestamp::from_unix(
        uuid::NoContext,
        created.as_secs(),
        created.subsec_nanos(),
    ))
}

fn parent_with(id: Uuid) -> ManagedParent {
    ManagedParent {
        version: 1,
        id: id.to_string(),
        root: "attempt-prune".into(),
        operation: "compact".into(),
        normalized_intent: "attempt-prune".into(),
        namespace: None,
        complete: false,
        parent_uncertainty_code: None,
        body_completed: false,
    }
}

async fn begin_as(store: &RepositoryAttemptStore, id: Uuid) -> Uuid {
    store.begin_parent(parent_with(id)).await.unwrap();
    store.bind_parent_namespace(id, &binding()).await.unwrap();
    id
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
        canonical_request: vec![0x42; 64],
        endpoint: binding.endpoint,
        verified_issuer: binding.verified_issuer,
        authenticated_subject: binding.authenticated_subject,
        caller_capabilities: binding.caller_capabilities,
    };
    (record, intent)
}

/// One settled child of `parent`; returns its attempt id.
async fn settle_child(store: &RepositoryAttemptStore, parent: Uuid) -> String {
    let (record, intent) = child(parent);
    store.record_managed(&record, &intent).await.unwrap();
    store
        .resolve(&record.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    record.attempt_id.to_string()
}

/// A completed parent with `children` settled children.
async fn finished(store: &RepositoryAttemptStore, id: Uuid, children: usize) -> Vec<String> {
    begin_as(store, id).await;
    let mut ids = Vec::new();
    for _ in 0..children {
        ids.push(settle_child(store, id).await);
    }
    store.complete_parent_body(id).await.unwrap();
    store.finish_parent(id).await.unwrap();
    ids
}

struct Journal {
    _dir: tempfile::TempDir,
    path: PathBuf,
    probe: phase_diagnostics::Probe,
    store: RepositoryAttemptStore,
}

fn journal() -> Journal {
    let dir = tempfile::tempdir().unwrap();
    let path = std::fs::canonicalize(dir.path()).unwrap();
    Journal {
        probe: phase_diagnostics::Probe::install(path.clone()),
        store: RepositoryAttemptStore::in_directory(&path),
        path,
        _dir: dir,
    }
}

fn counter(probe: &phase_diagnostics::Probe, phase: &'static str) -> usize {
    probe.snapshot().get(phase).map_or(0, |metric| metric.count)
}

fn read_root(path: &Path) -> Value {
    let bytes = std::fs::read(path.join("attempts")).unwrap();
    assert_eq!(bytes[0], 2, "root version byte must stay 2");
    serde_json::from_slice(&bytes[1..]).unwrap()
}

fn write_root(path: &Path, root: &Value) {
    let mut bytes = vec![2];
    bytes.extend(serde_json::to_vec(root).unwrap());
    std::fs::write(path.join("attempts"), bytes).unwrap();
}

fn marker(path: &Path) -> Option<Value> {
    read_root(path).get("validated").cloned()
}

fn pruned(path: &Path) -> (u64, u64) {
    let root = read_root(path);
    let summary = &root["pruned"];
    (
        summary["children"].as_u64().unwrap_or(0),
        summary["parents"].as_u64().unwrap_or(0),
    )
}

fn root_parent_ids(path: &Path) -> Vec<String> {
    read_root(path)["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|parent| parent["id"].as_str().unwrap().to_owned())
        .collect()
}

fn generation_dir(path: &Path) -> PathBuf {
    let root = read_root(path);
    path.join(format!(
        "attempts-v2-{}",
        root["generation"].as_str().unwrap()
    ))
}

fn settled_path(path: &Path, attempt: &str) -> PathBuf {
    generation_dir(path)
        .join("settled")
        .join(format!("{attempt}.json"))
}

fn settled_exists(path: &Path, attempt: &str) -> bool {
    settled_path(path, attempt).exists()
}

fn settled_count(path: &Path) -> usize {
    std::fs::read_dir(generation_dir(path).join("settled"))
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|ext| ext == "json")
        })
        .count()
}

fn set_mtime(path: &Path, time: SystemTime) {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(time)
        .unwrap();
}

/// Moves settled children's modification time past the retention window.
fn age(path: &Path, attempts: &[String]) {
    let old = SystemTime::now().checked_sub(DAY * 8).unwrap();
    for attempt in attempts {
        set_mtime(&settled_path(path, attempt), old);
    }
}

/// Finishes a fresh recent parent with one child, which is what triggers pruning.
async fn trigger(journal: &Journal) -> (Uuid, String) {
    let id = Uuid::now_v7();
    let children = finished(&journal.store, id, 1).await;
    (id, children[0].clone())
}

// ---------------------------------------------------------------------------
// Pruning
// ---------------------------------------------------------------------------

#[tokio::test]
async fn old_children_of_a_complete_parent_are_removed_and_recent_ones_kept() {
    let journal = journal();
    let expired_parent = Uuid::now_v7();
    let expired = finished(&journal.store, expired_parent, 3).await;
    let recent = finished(&journal.store, Uuid::now_v7(), 2).await;
    age(&journal.path, &expired);
    assert_eq!(pruned(&journal.path), (0, 0));
    let prunes = counter(&journal.probe, "settled_prune");

    let (_, current_child) = trigger(&journal).await;

    for attempt in &expired {
        assert!(!settled_exists(&journal.path, attempt), "{attempt} expired");
    }
    for attempt in recent.iter().chain([&current_child]) {
        assert!(settled_exists(&journal.path, attempt), "{attempt} kept");
    }
    assert_eq!(pruned(&journal.path), (3, 0));
    assert!(
        root_parent_ids(&journal.path).contains(&expired_parent.to_string()),
        "a recent parent stays even with no children"
    );
    assert!(counter(&journal.probe, "settled_prune") > prunes);
}

#[tokio::test]
async fn children_of_the_parent_being_finished_are_kept_even_when_old() {
    let journal = journal();
    let id = begin_as(&journal.store, Uuid::now_v7()).await;
    let first = settle_child(&journal.store, id).await;
    let second = settle_child(&journal.store, id).await;
    journal.store.complete_parent_body(id).await.unwrap();
    age(&journal.path, &[first.clone(), second.clone()]);

    journal.store.finish_parent(id).await.unwrap();

    assert!(settled_exists(&journal.path, &first));
    assert!(settled_exists(&journal.path, &second));
    assert_eq!(pruned(&journal.path), (0, 0));
    assert!(root_parent_ids(&journal.path).contains(&id.to_string()));
    journal.store.managed_parents().await.unwrap();
}

#[tokio::test]
async fn children_of_an_incomplete_parent_are_never_pruned() {
    // `begin_parent` refuses a second open parent, so the open one is made by a root edit that
    // flips a finished parent back to incomplete just before the trigger finishes.
    let journal = journal();
    let reopened = Uuid::now_v7();
    let children = finished(&journal.store, reopened, 2).await;
    age(&journal.path, &children);
    let id = begin_as(&journal.store, Uuid::now_v7()).await;
    let current_child = settle_child(&journal.store, id).await;
    journal.store.complete_parent_body(id).await.unwrap();
    let mut root = read_root(&journal.path);
    let entry = root["parents"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|parent| parent["id"] == reopened.to_string())
        .unwrap();
    entry["complete"] = Value::Bool(false);
    write_root(&journal.path, &root);

    journal.store.finish_parent(id).await.unwrap();

    for attempt in &children {
        assert!(settled_exists(&journal.path, attempt), "{attempt} kept");
    }
    assert!(settled_exists(&journal.path, &current_child));
    assert_eq!(pruned(&journal.path), (0, 0));
    assert!(root_parent_ids(&journal.path).contains(&reopened.to_string()));
}

#[tokio::test]
async fn ownership_rows_survive_pruning() {
    let journal = journal();
    let branch = Context::from([0x11u8; 16]);
    let resource = Hash::from([0x22u8; 32]);
    let ownership = LockOwnership {
        attempt_id: AttemptId::new(),
        branch,
        resource_hash: resource,
        token: OwnershipToken::from_wire(&[0xAB; OwnershipToken::LEN])
            .unwrap()
            .unwrap(),
    };
    journal.store.record_ownership(&ownership).await.unwrap();
    let old_parent = v7_aged(DAY * 30);
    let expired = finished(&journal.store, old_parent, 2).await;
    age(&journal.path, &expired);

    trigger(&journal).await;

    assert!(!settled_exists(&journal.path, &expired[0]));
    assert_eq!(pruned(&journal.path), (2, 0), "the parent lags one call");
    trigger(&journal).await;
    assert_eq!(pruned(&journal.path), (2, 1));
    let held = journal
        .store
        .ownership_for_batch(&[(branch, resource)])
        .await
        .unwrap();
    assert_eq!(held, vec![Some(ownership.clone())]);
    assert_eq!(
        journal
            .store
            .ownership_for(&branch, &resource)
            .await
            .unwrap(),
        Some(ownership)
    );
}

#[tokio::test]
async fn parents_are_removed_only_when_old_v7_complete_and_unreferenced() {
    let journal = journal();
    let store = &journal.store;
    // Old v7, complete, every child expired: the only parent that leaves.
    let old = v7_aged(DAY * 30);
    let old_children = finished(store, old, 2).await;
    // Not a v7: no creation time, never pruned (its children still go).
    let not_v7 = Uuid::new_v4();
    let not_v7_children = finished(store, not_v7, 1).await;
    // Recent v7: kept (its children still go).
    let recent = Uuid::now_v7();
    let recent_children = finished(store, recent, 1).await;
    // Old v7 but one recent child outlives the pruning: referenced, kept.
    let referenced = v7_aged(DAY * 30);
    let referenced_children = finished(store, referenced, 2).await;
    age(&journal.path, &old_children);
    age(&journal.path, &not_v7_children);
    age(&journal.path, &recent_children);
    age(&journal.path, &referenced_children[..1]);

    let (current, _) = trigger(&journal).await;

    // Finish N deleted the children; their parent lags and is still named.
    let parents = root_parent_ids(&journal.path);
    assert!(
        parents.contains(&old.to_string()),
        "old parent lags one call"
    );
    assert!(!settled_exists(&journal.path, &old_children[0]));
    assert_eq!(pruned(&journal.path), (5, 0));

    // Finish N+1 removes it, and only it.
    let (next, _) = trigger(&journal).await;
    let parents = root_parent_ids(&journal.path);
    assert!(!parents.contains(&old.to_string()), "old parent pruned");
    for kept in [not_v7, recent, referenced, current, next] {
        assert!(parents.contains(&kept.to_string()), "{kept} kept");
    }
    assert!(!settled_exists(&journal.path, &referenced_children[0]));
    assert!(settled_exists(&journal.path, &referenced_children[1]));
    assert_eq!(pruned(&journal.path), (5, 1));

    // After pruning, the full scan passes and a fresh store loads.
    let fresh = RepositoryAttemptStore::in_directory(&journal.path);
    let managed = fresh.managed_parents().await.unwrap();
    assert_eq!(managed.len(), parents.len());
    fresh.admission_parents().await.unwrap();
}

#[tokio::test]
async fn one_finish_removes_at_most_1024_expired_children() {
    let journal = journal();
    let id = begin_as(&journal.store, Uuid::now_v7()).await;
    let mut expired = Vec::new();
    for _ in 0..1025 {
        expired.push(settle_child(&journal.store, id).await);
    }
    journal.store.complete_parent_body(id).await.unwrap();
    journal.store.finish_parent(id).await.unwrap();
    age(&journal.path, &expired);

    let (_, _) = trigger(&journal).await;
    assert_eq!(pruned(&journal.path).0, 1024);
    assert_eq!(settled_count(&journal.path), 1 + 1);

    trigger(&journal).await;
    assert_eq!(pruned(&journal.path).0, 1025, "the backlog drains");
    assert_eq!(settled_count(&journal.path), 2);
    journal.store.managed_parents().await.unwrap();
}

// ---------------------------------------------------------------------------
// Crash safety
// ---------------------------------------------------------------------------

/// Everything a restarted process does with the journal.
async fn assert_journal_still_works(path: &Path, open: Uuid, listed: &[Uuid]) {
    let fresh = RepositoryAttemptStore::in_directory(path);
    fresh.admission_parents().await.unwrap();
    let managed = fresh.managed_parents().await.unwrap();
    for id in listed {
        assert!(
            managed.iter().any(|parent| parent.id == id.to_string()),
            "{id} is still named by the root"
        );
    }
    fresh.reconcile_parent(open).await.unwrap();
    let next = begin_as(&fresh, Uuid::now_v7()).await;
    let (record, intent) = child(next);
    fresh.record_managed(&record, &intent).await.unwrap();
    fresh
        .resolve(&record.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    fresh.complete_parent_body(next).await.unwrap();
    fresh.finish_parent(next).await.unwrap();
    fresh.managed_parents().await.unwrap();
}

#[tokio::test]
async fn root_write_failing_after_the_deletions_leaves_a_journal_that_still_works() {
    let journal = journal();
    let old_parent = v7_aged(DAY * 30);
    let expired = finished(&journal.store, old_parent, 2).await;
    age(&journal.path, &expired);
    let open = begin_as(&journal.store, Uuid::now_v7()).await;
    settle_child(&journal.store, open).await;
    journal.store.complete_parent_body(open).await.unwrap();
    let before = std::fs::read(journal.path.join("attempts")).unwrap();

    let root = journal.path.join("attempts");
    let fired = Arc::new(AtomicBool::new(false));
    let probe = {
        let fired = fired.clone();
        install_publication_probe(journal.path.clone(), move |point, _, destination| {
            if point == PublicationPoint::BeforeRename && destination == root {
                fired.store(true, Ordering::SeqCst);
                Err(ProtocolError::internal("injected root publication failure"))
            } else {
                Ok(())
            }
        })
    };
    assert!(journal.store.finish_parent(open).await.is_err());
    drop(probe);

    assert!(
        fired.load(Ordering::SeqCst),
        "the root write must be reached"
    );
    for attempt in &expired {
        assert!(!settled_exists(&journal.path, attempt), "deleted first");
    }
    assert_eq!(
        std::fs::read(journal.path.join("attempts")).unwrap(),
        before,
        "the failed write left the root unchanged"
    );
    // The root still names the parent whose children are gone.
    assert!(root_parent_ids(&journal.path).contains(&old_parent.to_string()));
    assert_journal_still_works(&journal.path, open, &[old_parent]).await;
}

#[tokio::test]
async fn children_deleted_by_hand_with_the_root_unchanged_leave_a_journal_that_still_works() {
    let journal = journal();
    let old_parent = v7_aged(DAY * 30);
    let expired = finished(&journal.store, old_parent, 2).await;
    let open = begin_as(&journal.store, Uuid::now_v7()).await;
    settle_child(&journal.store, open).await;
    journal.store.complete_parent_body(open).await.unwrap();
    for attempt in &expired {
        std::fs::remove_file(settled_path(&journal.path, attempt)).unwrap();
    }
    let before = std::fs::read(journal.path.join("attempts")).unwrap();

    // A restarted process, as after a crash between the deletions and the root write.
    assert_journal_still_works(&journal.path, open, &[old_parent]).await;
    assert!(
        std::fs::read(journal.path.join("attempts")).unwrap() != before,
        "the follow-up work rewrote the root"
    );
}

// ---------------------------------------------------------------------------
// Marker refresh
// ---------------------------------------------------------------------------

async fn admit_parses(journal: &Journal) -> usize {
    let before = counter(&journal.probe, "child_parse");
    journal.store.admission_parents().await.unwrap();
    counter(&journal.probe, "child_parse") - before
}

#[tokio::test]
async fn admission_after_finish_parses_no_settled_child_and_the_marker_matches_admission() {
    let journal = journal();
    finished(&journal.store, Uuid::now_v7(), 3).await;
    finished(&journal.store, Uuid::now_v7(), 2).await;
    let written = marker(&journal.path).expect("finish_parent records the marker");
    let before = std::fs::read(journal.path.join("attempts")).unwrap();

    assert_eq!(admit_parses(&journal).await, 0, "a marker hit");
    assert_eq!(
        std::fs::read(journal.path.join("attempts")).unwrap(),
        before,
        "a hit does not rewrite the root"
    );

    // Dropping the marker forces the scan that computes it from disk: the same value.
    let mut root = read_root(&journal.path);
    root.as_object_mut().unwrap().remove("validated");
    write_root(&journal.path, &root);
    assert_eq!(admit_parses(&journal).await, 5, "a full scan");
    assert_eq!(marker(&journal.path), Some(written));
    assert_eq!(admit_parses(&journal).await, 0);
}

#[tokio::test]
async fn marker_after_a_pruning_finish_matches_the_remaining_settled_history() {
    let journal = journal();
    let expired = finished(&journal.store, Uuid::now_v7(), 3).await;
    finished(&journal.store, Uuid::now_v7(), 1).await;
    age(&journal.path, &expired);
    trigger(&journal).await;
    assert_eq!(pruned(&journal.path).0, 3);
    let written = marker(&journal.path).expect("marker");

    assert_eq!(
        admit_parses(&journal).await,
        0,
        "the marker covers the survivors"
    );

    let mut root = read_root(&journal.path);
    root.as_object_mut().unwrap().remove("validated");
    write_root(&journal.path, &root);
    assert_eq!(admit_parses(&journal).await, 2);
    assert_eq!(marker(&journal.path), Some(written));
}

#[tokio::test]
async fn marker_still_invalidates_on_a_later_settled_change() {
    let journal = journal();
    let children = finished(&journal.store, Uuid::now_v7(), 2).await;
    let written = marker(&journal.path).unwrap();
    assert_eq!(admit_parses(&journal).await, 0);

    set_mtime(
        &settled_path(&journal.path, &children[0]),
        SystemTime::now().checked_sub(DAY).unwrap(),
    );

    assert_eq!(
        admit_parses(&journal).await,
        2,
        "a changed child forces a full scan"
    );
    assert_ne!(marker(&journal.path), Some(written));
    assert_eq!(admit_parses(&journal).await, 0);
}

#[tokio::test]
async fn recovery_scan_still_parses_every_settled_child_after_finish() {
    let journal = journal();
    finished(&journal.store, Uuid::now_v7(), 3).await;
    finished(&journal.store, Uuid::now_v7(), 2).await;
    let before = counter(&journal.probe, "child_parse");

    journal.store.managed_parents().await.unwrap();

    assert_eq!(counter(&journal.probe, "child_parse") - before, 5);
}

#[tokio::test]
async fn reconcile_parent_neither_prunes_nor_records_a_marker() {
    let journal = journal();
    let expired = finished(&journal.store, v7_aged(DAY * 30), 2).await;
    age(&journal.path, &expired);
    let open = begin_as(&journal.store, Uuid::now_v7()).await;
    settle_child(&journal.store, open).await;
    journal.store.complete_parent_body(open).await.unwrap();
    let mut root = read_root(&journal.path);
    root.as_object_mut().unwrap().remove("validated");
    write_root(&journal.path, &root);

    journal.store.reconcile_parent(open).await.unwrap();

    for attempt in &expired {
        assert!(
            settled_exists(&journal.path, attempt),
            "recovery never prunes"
        );
    }
    assert_eq!(pruned(&journal.path), (0, 0));
    assert!(
        marker(&journal.path).is_none(),
        "recovery records no marker"
    );
}

// ---------------------------------------------------------------------------
// Parent lag, resurrection, other references, unmanaged children, failed deletes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_restored_child_keeps_its_parent_and_the_journal_still_works() {
    let journal = journal();
    let old_parent = v7_aged(DAY * 30);
    let expired = finished(&journal.store, old_parent, 2).await;
    age(&journal.path, &expired);
    let aside = journal.path.join("aside.json");
    std::fs::copy(settled_path(&journal.path, &expired[0]), &aside).unwrap();

    trigger(&journal).await;
    assert!(!settled_exists(&journal.path, &expired[0]));
    assert!(root_parent_ids(&journal.path).contains(&old_parent.to_string()));

    // A deletion that did not survive a crash: the child comes back.
    std::fs::copy(&aside, settled_path(&journal.path, &expired[0])).unwrap();
    trigger(&journal).await;

    assert!(
        root_parent_ids(&journal.path).contains(&old_parent.to_string()),
        "the restored child's parent must stay"
    );
    let fresh = RepositoryAttemptStore::in_directory(&journal.path);
    fresh.admission_parents().await.unwrap();
    fresh.managed_parents().await.unwrap();
    let next = begin_as(&fresh, Uuid::now_v7()).await;
    assert!(root_parent_ids(&journal.path).contains(&next.to_string()));
}

#[tokio::test]
async fn a_legacy_managed_intent_keeps_its_parent() {
    let journal = journal();
    let old_parent = v7_aged(DAY * 30);
    let expired = finished(&journal.store, old_parent, 1).await;
    age(&journal.path, &expired);
    let mut root = read_root(&journal.path);
    root["managed"] = serde_json::json!([{
        "attempt": Uuid::new_v4().to_string(),
        "parent": old_parent.to_string(),
        "rpc": "Storage.Put",
        "canonical_request": [8, 1],
    }]);
    write_root(&journal.path, &root);

    trigger(&journal).await;
    trigger(&journal).await;

    assert!(!settled_exists(&journal.path, &expired[0]));
    assert!(
        root_parent_ids(&journal.path).contains(&old_parent.to_string()),
        "a legacy root intent names the parent"
    );
    assert_eq!(pruned(&journal.path).1, 0);
}

#[tokio::test]
async fn an_old_unmanaged_settled_child_is_pruned_by_age_alone() {
    let journal = journal();
    let record = AttemptRecord {
        attempt_id: AttemptId::new(),
        state: AttemptState::Unresolved,
        operation: "Storage.Put".into(),
        repository: binding().repository,
        recorded_at_unix_millis: 1_000,
        receipt: None,
    };
    journal.store.record(&record).await.unwrap();
    journal
        .store
        .resolve(&record.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    let attempt = record.attempt_id.to_string();
    assert!(settled_exists(&journal.path, &attempt));
    assert!(
        journal
            .store
            .lookup(&record.attempt_id)
            .await
            .unwrap()
            .is_some()
    );
    age(&journal.path, std::slice::from_ref(&attempt));

    trigger(&journal).await;

    assert!(!settled_exists(&journal.path, &attempt));
    assert_eq!(pruned(&journal.path), (1, 0));
    assert!(
        journal
            .store
            .lookup(&record.attempt_id)
            .await
            .unwrap()
            .is_none()
    );
    journal.store.managed_parents().await.unwrap();
}

// A delete that fails (here, a sharing violation) keeps that child; the call goes on with the
// others and fails nothing.
#[cfg(windows)]
fn hold_open(path: &Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt;

    // FILE_SHARE_READ only: no FILE_SHARE_DELETE, so removing the file fails.
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(path)
        .unwrap()
}

#[cfg(windows)]
#[tokio::test]
async fn a_failed_delete_keeps_the_child_and_prunes_its_siblings_in_the_same_call() {
    let journal = journal();
    let old_parent = v7_aged(DAY * 30);
    let expired = finished(&journal.store, old_parent, 3).await;
    age(&journal.path, &expired);
    let held = hold_open(&settled_path(&journal.path, &expired[1]));

    let (_, current_child) = trigger(&journal).await;

    assert!(
        settled_exists(&journal.path, &expired[1]),
        "the held child stays"
    );
    assert!(!settled_exists(&journal.path, &expired[0]));
    assert!(!settled_exists(&journal.path, &expired[2]));
    assert!(settled_exists(&journal.path, &current_child));
    assert_eq!(pruned(&journal.path), (2, 0));
    assert!(root_parent_ids(&journal.path).contains(&old_parent.to_string()));
    drop(held);

    let fresh = RepositoryAttemptStore::in_directory(&journal.path);
    fresh.admission_parents().await.unwrap();
    fresh.managed_parents().await.unwrap();
    // Once released, a later finish deletes it, and the parent follows on the call after.
    trigger(&journal).await;
    assert!(!settled_exists(&journal.path, &expired[1]));
    trigger(&journal).await;
    assert!(!root_parent_ids(&journal.path).contains(&old_parent.to_string()));
}

#[cfg(windows)]
#[tokio::test]
async fn a_child_held_across_three_finishes_never_stops_its_siblings_being_pruned() {
    let journal = journal();
    let old_parent = v7_aged(DAY * 30);
    let first = finished(&journal.store, old_parent, 1).await;
    age(&journal.path, &first);
    let held = hold_open(&settled_path(&journal.path, &first[0]));
    let mut total = 0u64;
    for round in 0..3 {
        let batch = finished(&journal.store, Uuid::now_v7(), 2).await;
        age(&journal.path, &batch);
        trigger(&journal).await;
        total += 2;
        for attempt in &batch {
            assert!(!settled_exists(&journal.path, attempt), "round {round}");
        }
        assert!(settled_exists(&journal.path, &first[0]), "round {round}");
        assert_eq!(pruned(&journal.path).0, total, "round {round}");
    }
    drop(held);
    journal.store.managed_parents().await.unwrap();
}
// ---------------------------------------------------------------------------
// Seeded `begin_parent`: a fresh store per push (the CLI shape)
// ---------------------------------------------------------------------------

fn now_millis() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn full_scan_millis(path: &Path) -> Option<i64> {
    read_root(path)["pruned"]["full_scan_unix_millis"].as_i64()
}

/// Sets (or, with `None`, removes) the root's last-full-scan time, keeping every other field.
fn set_full_scan(path: &Path, millis: Option<i64>) {
    let mut root = read_root(path);
    let object = root.as_object_mut().unwrap();
    let summary = object
        .entry("pruned")
        .or_insert_with(|| serde_json::json!({"children": 0, "parents": 0}))
        .as_object_mut()
        .unwrap();
    match millis {
        Some(millis) => summary.insert("full_scan_unix_millis".into(), millis.into()),
        None => summary.remove("full_scan_unix_millis"),
    };
    write_root(path, &root);
}

/// After a hand edit: one full admission scan rewrites the marker over what is on disk, and the
/// last-full-scan time is made recent, so the next `begin_parent` is a candidate for seeding.
async fn settle_hand_edit(path: &Path) {
    RepositoryAttemptStore::in_directory(path)
        .admission_parents()
        .await
        .unwrap();
    set_full_scan(path, Some(now_millis()));
}

struct Push {
    begin_parses: usize,
    finish_parses: usize,
    child: String,
}

/// One CLI push on a brand-new store instance: begin, one child, finish.
async fn push(journal: &Journal) -> Push {
    let store = RepositoryAttemptStore::in_directory(&journal.path);
    let id = Uuid::now_v7();
    let parses = || counter(&journal.probe, "child_parse");
    let before = parses();
    store.begin_parent(parent_with(id)).await.unwrap();
    let begin_parses = parses() - before;
    store.bind_parent_namespace(id, &binding()).await.unwrap();
    let child = settle_child(&store, id).await;
    store.complete_parent_body(id).await.unwrap();
    let before = parses();
    store.finish_parent(id).await.unwrap();
    Push {
        begin_parses,
        finish_parses: parses() - before,
        child,
    }
}

/// A journal of `cycles` finished recent parents (one child each) over fresh stores.
async fn pushed_journal(cycles: usize) -> Journal {
    let journal = journal();
    for _ in 0..cycles {
        push(&journal).await;
    }
    journal
}

#[tokio::test]
async fn a_push_on_a_fresh_store_parses_no_settled_child_at_begin_or_finish() {
    let journal = pushed_journal(4).await;
    assert!(
        full_scan_millis(&journal.path).is_some(),
        "an earlier begin scanned in full"
    );

    let seen = push(&journal).await;

    assert_eq!(seen.begin_parses, 0, "begin trusts the marker");
    assert!(
        seen.finish_parses <= 1,
        "finish parses at most its own new child, got {}",
        seen.finish_parses
    );
    assert!(settled_exists(&journal.path, &seen.child));
    // The cost does not grow with history.
    let again = push(&journal).await;
    assert_eq!(again.begin_parses, 0);
    assert!(again.finish_parses <= 1);
}

#[tokio::test]
async fn a_stale_future_or_missing_full_scan_time_makes_begin_parse_in_full() {
    for (label, time) in [
        (
            "older than 24 hours",
            Some(now_millis() - 25 * 60 * 60 * 1000),
        ),
        ("in the future", Some(now_millis() + 60 * 60 * 1000)),
        ("missing", None),
    ] {
        let journal = pushed_journal(3).await;
        set_full_scan(&journal.path, time);
        let settled = settled_count(&journal.path);
        assert_eq!(settled, 3);

        let seen = push(&journal).await;

        assert_eq!(
            seen.begin_parses, settled,
            "{label}: begin parses every child"
        );
        let recorded = full_scan_millis(&journal.path).expect("the full scan time is recorded");
        assert!(
            (now_millis() - recorded).abs() < 60 * 60 * 1000,
            "{label}: time refreshed"
        );
        // Refreshed, so the next push seeds again.
        assert_eq!(push(&journal).await.begin_parses, 0, "{label}");
    }
}

/// `count` extra complete `UUIDv7` parents, 30 days old, copied from a real row.
async fn add_old_parents(path: &Path, count: usize) {
    let mut root = read_root(path);
    let template = root["parents"][0].clone();
    let parents = root["parents"].as_array_mut().unwrap();
    for _ in 0..count {
        let mut parent = template.clone();
        parent["id"] = v7_aged(DAY * 30).to_string().into();
        parents.push(parent);
    }
    write_root(path, &root);
    settle_hand_edit(path).await;
}

#[tokio::test]
async fn begin_parses_in_full_at_256_old_complete_parents_but_not_at_255() {
    let seeded = pushed_journal(2).await;
    add_old_parents(&seeded.path, 255).await;
    let seen = push(&seeded).await;
    assert_eq!(
        seen.begin_parses, 0,
        "255 old parents are below the threshold"
    );

    let full = pushed_journal(2).await;
    add_old_parents(&full.path, 256).await;
    let settled = settled_count(&full.path);
    let seen = push(&full).await;
    assert_eq!(
        seen.begin_parses, settled,
        "256 old parents force a full parse"
    );
}

#[tokio::test]
async fn a_seeded_begin_prunes_old_children_but_removes_no_parent_until_a_full_parse() {
    let journal = journal();
    let old_parent = v7_aged(DAY * 30);
    let mut store = RepositoryAttemptStore::in_directory(&journal.path);
    let expired = finished(&store, old_parent, 3).await;
    store = RepositoryAttemptStore::in_directory(&journal.path);
    let recent = finished(&store, Uuid::now_v7(), 1).await;
    age(&journal.path, &expired);
    settle_hand_edit(&journal.path).await;

    // Seeded push: nothing is parsed at begin, yet the old children of the complete parent go.
    let seeded = push(&journal).await;
    assert_eq!(seeded.begin_parses, 0);
    assert!(
        seeded.finish_parses >= expired.len(),
        "finish parses each candidate to learn its parent"
    );
    for attempt in &expired {
        assert!(!settled_exists(&journal.path, attempt), "{attempt} pruned");
    }
    assert!(settled_exists(&journal.path, &recent[0]));
    assert_eq!(pruned(&journal.path).0, 3);

    // The old parent is now unreferenced, but an Unknown parent is listed: it must stay.
    assert!(root_parent_ids(&journal.path).contains(&old_parent.to_string()));
    let second = push(&journal).await;
    assert_eq!(second.begin_parses, 0);
    assert!(
        root_parent_ids(&journal.path).contains(&old_parent.to_string()),
        "a seeded begin lets finish remove no parent"
    );
    assert_eq!(pruned(&journal.path).1, 0);

    // A full parse resolves every parent; the old one leaves (once, after at most one lag call).
    for _ in 0..2 {
        if !root_parent_ids(&journal.path).contains(&old_parent.to_string()) {
            break;
        }
        set_full_scan(&journal.path, None);
        let full = push(&journal).await;
        assert!(full.begin_parses > 0, "a full parse");
    }
    assert!(!root_parent_ids(&journal.path).contains(&old_parent.to_string()));
    assert_eq!(pruned(&journal.path).1, 1);
    let fresh = RepositoryAttemptStore::in_directory(&journal.path);
    fresh.managed_parents().await.unwrap();
    fresh.admission_parents().await.unwrap();
}

#[tokio::test]
async fn a_seeded_candidate_that_fails_to_parse_is_kept_and_the_marker_is_withheld() {
    let journal = journal();
    let old_parent = v7_aged(DAY * 30);
    let expired = finished(&journal.store, old_parent, 2).await;
    finished(&journal.store, Uuid::now_v7(), 1).await;
    age(&journal.path, &expired);
    settle_hand_edit(&journal.path).await;

    // Same length and mtime, so the marker still matches; only the bound parent is wrong.
    let victim = settled_path(&journal.path, &expired[0]);
    let modified = std::fs::metadata(&victim).unwrap().modified().unwrap();
    let original = std::fs::read(&victim).unwrap();
    let mut body: Value = serde_json::from_slice(&original).unwrap();
    body["managed"]["parent"] = Uuid::now_v7().to_string().into();
    let rewritten = serde_json::to_vec(&body).unwrap();
    assert_eq!(rewritten.len(), original.len(), "fixture must keep length");
    std::fs::write(&victim, rewritten).unwrap();
    set_mtime(&victim, modified);

    let seen = push(&journal).await;

    assert_eq!(seen.begin_parses, 0, "begin was seeded");
    assert!(
        settled_exists(&journal.path, &expired[0]),
        "the damaged child is kept"
    );
    assert!(
        !settled_exists(&journal.path, &expired[1]),
        "its healthy sibling goes"
    );
    assert!(
        marker(&journal.path).is_none(),
        "no marker over a damaged child"
    );
    let result = RepositoryAttemptStore::in_directory(&journal.path)
        .admission_parents()
        .await;
    match result {
        Ok(parents) => panic!("admission must fail closed, got {} parents", parents.len()),
        Err(error) => {
            let text = format!("{error:?}");
            assert!(text.contains("invalid managed child binding"), "{text}");
        }
    }
}

// Regression: a damaged seeded candidate must leave the per-instance cache, or a repeat
// `finish_parent` on the same instance would trust it again once the failure cap stopped pruning
// before reaching it, and write a marker over it.
#[cfg(windows)]
#[tokio::test]
async fn a_repeat_finish_on_the_same_instance_does_not_trust_an_evicted_damaged_child() {
    let journal = journal();
    let old_parent = v7_aged(DAY * 30);
    let expired = finished(&journal.store, old_parent, 2).await;
    finished(&journal.store, Uuid::now_v7(), 1).await;
    age(&journal.path, &expired);
    settle_hand_edit(&journal.path).await;

    // Same length and mtime, so the marker still matches; only the bound parent is wrong.
    let victim = settled_path(&journal.path, &expired[0]);
    let modified = std::fs::metadata(&victim).unwrap().modified().unwrap();
    let original = std::fs::read(&victim).unwrap();
    let mut body: Value = serde_json::from_slice(&original).unwrap();
    body["managed"]["parent"] = Uuid::now_v7().to_string().into();
    let rewritten = serde_json::to_vec(&body).unwrap();
    assert_eq!(rewritten.len(), original.len(), "fixture must keep length");
    std::fs::write(&victim, rewritten).unwrap();
    set_mtime(&victim, modified);

    let healthy: Value =
        serde_json::from_slice(&std::fs::read(settled_path(&journal.path, &expired[1])).unwrap())
            .unwrap();
    // One instance throughout: seeded begin, first finish.
    let store = RepositoryAttemptStore::in_directory(&journal.path);
    let id = Uuid::now_v7();
    store.begin_parent(parent_with(id)).await.unwrap();
    store.bind_parent_namespace(id, &binding()).await.unwrap();
    settle_child(&store, id).await;
    store.complete_parent_body(id).await.unwrap();
    store.finish_parent(id).await.unwrap();
    assert!(
        marker(&journal.path).is_none(),
        "first finish withholds the marker"
    );
    assert!(settled_exists(&journal.path, &expired[0]));

    // Eight old children of the old parent that sort before the damaged one and cannot be
    // deleted: the failure cap is spent before pruning would reach the damaged child again.
    let mut held = Vec::new();
    let mut extras = Vec::new();
    for index in 1..=8u128 {
        let attempt = Uuid::from_u128(index).to_string();
        let mut body = healthy.clone();
        body["attempt"]["attempt_id"] = attempt.clone().into();
        body["managed"]["attempt"] = attempt.clone().into();
        let path = settled_path(&journal.path, &attempt);
        std::fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
        extras.push(attempt);
    }
    age(&journal.path, &extras);
    for attempt in &extras {
        held.push(hold_open(&settled_path(&journal.path, attempt)));
    }

    // Positive control: every extra is a valid child, so the failure below cannot come from one.
    for attempt in &extras {
        let found = store
            .lookup(&AttemptId::from_uuid(Uuid::parse_str(attempt).unwrap()))
            .await
            .unwrap();
        assert!(found.is_some(), "extra {attempt} must be a valid child");
    }

    let repeat = store.finish_parent(id).await;

    let error = format!(
        "{:?}",
        repeat.expect_err("the evicted damaged child must be parsed again")
    );
    assert!(error.contains("invalid managed child binding"), "{error}");
    assert!(
        marker(&journal.path).is_none(),
        "no marker over a damaged child"
    );
    drop(held);
    let admission = RepositoryAttemptStore::in_directory(&journal.path)
        .admission_parents()
        .await;
    assert!(admission.is_err(), "a fresh store must fail closed too");
}
