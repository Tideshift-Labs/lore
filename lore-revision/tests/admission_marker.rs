// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! Settled-history admission marker: `RepositoryAttemptStore::admission_parents` skips the full
//! settled-child scan when the root's `validated` marker matches `settled_fingerprint`.
//!
//! The probe's `child_parse` count tells the two paths apart. A child file that exists is parsed
//! exactly once per scan, so a full scan parses every pending and settled child on disk, while a
//! marker hit parses only the pending ones.

// Tests build, corrupt and re-time journal files directly, as managed_journal_scaling.rs does.
#![allow(clippy::disallowed_methods)]

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Instant;

use lore_base::types::RepositoryId;
use lore_revision::attempt_store::ManagedParent;
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_revision::attempt_store::StoredAttempt;
use lore_revision::attempt_store::StoredManagedIntent;
use lore_revision::attempt_store::StoredOwnership;
use lore_revision::attempt_store::persistence::PublicationPoint;
use lore_revision::attempt_store::persistence::install_publication_probe;
use lore_revision::attempt_store::phase_diagnostics;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptState;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::caller_operation::CallerRecoveryContext;
use lore_transport::caller_operation::ManagedAttemptIntent;
use lore_transport::error::ProtocolError;
use lore_transport::outcome::AttemptId;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixture helpers (same shapes as managed_journal_scaling.rs / managed_journal_v2.rs)
// ---------------------------------------------------------------------------

fn binding() -> CallerRecoveryContext {
    CallerRecoveryContext {
        repository: RepositoryId::from([0x41; 16]),
        endpoint: "https://admission-marker.invalid:443".into(),
        verified_issuer: "admission-issuer".into(),
        authenticated_subject: "admission-subject".into(),
        caller_capabilities: "read,write".into(),
    }
}

fn next_parent() -> ManagedParent {
    ManagedParent {
        version: 1,
        id: Uuid::now_v7().to_string(),
        root: "admission-marker".into(),
        operation: "compact".into(),
        normalized_intent: "admission-marker".into(),
        namespace: None,
        complete: false,
        parent_uncertainty_code: None,
        body_completed: false,
    }
}

async fn begin(store: &RepositoryAttemptStore) -> Uuid {
    let parent = next_parent();
    let id = Uuid::parse_str(&parent.id).unwrap();
    store.begin_parent(parent).await.unwrap();
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

/// One completed parent with one settled child.
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

/// A journal directory, a store over it and a probe counting its child reads. The path is
/// canonical because the repository fence canonicalizes, and probes match by path prefix.
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

/// `cycles` completed parents, one settled child each.
async fn completed(cycles: usize) -> Journal {
    let journal = journal();
    for _ in 0..cycles {
        full_cycle(&journal.store).await;
    }
    journal
}

fn counter(probe: &phase_diagnostics::Probe, phase: &'static str) -> usize {
    probe.snapshot().get(phase).map_or(0, |metric| metric.count)
}

struct Observed {
    result: Result<Vec<ManagedParent>, ProtocolError>,
    reads: usize,
    parses: usize,
}

async fn admit(journal: &Journal) -> Observed {
    let (reads, parses) = (
        counter(&journal.probe, "child_read"),
        counter(&journal.probe, "child_parse"),
    );
    let result = journal.store.admission_parents().await;
    Observed {
        result,
        reads: counter(&journal.probe, "child_read") - reads,
        parses: counter(&journal.probe, "child_parse") - parses,
    }
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

fn root_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path.join("attempts")).unwrap()
}

fn marker(path: &Path) -> Option<Value> {
    read_root(path).get("validated").cloned()
}

fn generation_dir(path: &Path) -> PathBuf {
    let root = read_root(path);
    path.join(format!(
        "attempts-v2-{}",
        root["generation"].as_str().unwrap()
    ))
}

fn json_files(directory: &Path) -> Vec<PathBuf> {
    let mut files: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    files
}

fn settled_files(path: &Path) -> Vec<PathBuf> {
    json_files(&generation_dir(path).join("settled"))
}

fn pending_files(path: &Path) -> Vec<PathBuf> {
    json_files(&generation_dir(path).join("pending"))
}

fn set_mtime(path: &Path, time: std::time::SystemTime) {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(time)
        .unwrap();
}

fn same_length_wrong_identity(original: &[u8]) -> Vec<u8> {
    let mut body: Value = serde_json::from_slice(original).unwrap();
    let id = body["attempt"]["attempt_id"].as_str().unwrap().to_owned();
    let mut digits: Vec<char> = id.chars().collect();
    let last = digits.len() - 1;
    digits[last] = if digits[last] == '0' { '1' } else { '0' };
    body["attempt"]["attempt_id"] = json!(digits.into_iter().collect::<String>());
    let rewritten = serde_json::to_vec(&body).unwrap();
    assert_eq!(rewritten.len(), original.len(), "fixture must keep length");
    assert_ne!(rewritten, original);
    rewritten
}

fn assert_error_contains<T: std::fmt::Debug>(result: Result<T, ProtocolError>, reason: &str) {
    match result {
        Ok(value) => panic!("expected failure containing {reason:?}, got {value:?}"),
        Err(error) => {
            let text = format!("{error:?}");
            assert!(text.contains(reason), "expected {reason:?} in {text}");
        }
    }
}

/// Admission is a marker hit: only pending children are parsed.
async fn assert_hit(journal: &Journal) {
    let pending = pending_files(&journal.path).len();
    let before = root_bytes(&journal.path);
    let seen = admit(journal).await;
    seen.result.unwrap();
    assert_eq!(
        seen.parses, pending,
        "marker hit must parse only the {pending} pending children"
    );
    assert_eq!(
        root_bytes(&journal.path),
        before,
        "a marker hit must not rewrite the root"
    );
}

/// Admission scanned every child on disk and rewrote the marker; the admission after it is a
/// marker hit. `expect_marker` is the marker the rewrite must produce, or `None` when it must
/// merely differ from `before`.
async fn assert_rescans(journal: &Journal, before: Option<Value>, expect_marker: Option<Value>) {
    let total = pending_files(&journal.path).len() + settled_files(&journal.path).len();
    assert!(total > 0, "fixture has no children, so a scan is invisible");
    let seen = admit(journal).await;
    seen.result.unwrap();
    assert_eq!(
        seen.parses, total,
        "full scan must parse all {total} children on disk"
    );
    assert!(seen.reads >= total, "full scan must read every child");
    let after = marker(&journal.path).expect("a passing scan must write the marker");
    match expect_marker {
        Some(expected) => assert_eq!(after, expected),
        None => assert_ne!(Some(&after), before.as_ref(), "marker must change"),
    }
    assert_hit(journal).await;
}

/// Primes the marker and returns it.
async fn prime(journal: &Journal) -> Value {
    admit(journal).await.result.unwrap();
    marker(&journal.path).expect("first admission must write the marker")
}

// ---------------------------------------------------------------------------
// 1. Marker hit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn second_admission_reads_no_settled_children() {
    let journal = completed(3).await;
    assert!(
        marker(&journal.path).is_none(),
        "journal writers never create the marker"
    );
    let first = admit(&journal).await;
    let parents = first.result.unwrap();
    assert_eq!(first.parses, 3, "first admission scans every settled child");
    assert!(first.reads >= 3);
    let written = marker(&journal.path).expect("marker written with the root");
    assert_eq!(written["version"], json!(1));
    let fingerprint = written["fingerprint"].as_str().unwrap();
    assert_eq!(fingerprint.len(), 64);
    assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        std::fs::read(journal.path.join("attempts")).unwrap()[0],
        2,
        "root version byte stays 2"
    );

    let second = admit(&journal).await;
    assert_eq!(second.result.unwrap().len(), parents.len());
    assert_eq!((second.reads, second.parses), (0, 0));
    assert_eq!(marker(&journal.path), Some(written));
}

#[tokio::test]
async fn marker_hit_still_validates_pending_children() {
    let journal = journal();
    let parent = begin(&journal.store).await;
    let (settled, settled_intent) = child(parent);
    let (pending, pending_intent) = child(parent);
    for (record, intent) in [(&settled, &settled_intent), (&pending, &pending_intent)] {
        journal.store.record_managed(record, intent).await.unwrap();
    }
    journal
        .store
        .resolve(&settled.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    prime(&journal).await;
    assert_hit(&journal).await;
    std::fs::write(&pending_files(&journal.path)[0], b"torn").unwrap();
    assert_error_contains(admit(&journal).await.result, "parse child");
}

// ---------------------------------------------------------------------------
// 2. Invalidation: every fingerprint input, one test each
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalidated_by_settled_add() {
    let journal = journal();
    let parent = begin(&journal.store).await;
    let (first, first_intent) = child(parent);
    let (second, second_intent) = child(parent);
    journal
        .store
        .record_managed(&first, &first_intent)
        .await
        .unwrap();
    journal
        .store
        .record_managed(&second, &second_intent)
        .await
        .unwrap();
    journal
        .store
        .resolve(&first.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    let before = prime(&journal).await;
    assert_hit(&journal).await;
    // Parents and generation are untouched; only the settled set grows.
    journal
        .store
        .resolve(&second.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    assert_eq!(settled_files(&journal.path).len(), 2);
    assert_rescans(&journal, Some(before), None).await;
}

#[tokio::test]
async fn invalidated_by_settled_child_moved_to_pending() {
    let journal = completed(3).await;
    let before = prime(&journal).await;
    let victim = settled_files(&journal.path)[0].clone();
    std::fs::rename(
        &victim,
        generation_dir(&journal.path)
            .join("pending")
            .join(victim.file_name().unwrap()),
    )
    .unwrap();
    assert_rescans(&journal, Some(before), None).await;
}

#[tokio::test]
async fn invalidated_by_settled_child_removed() {
    let journal = completed(3).await;
    let before = prime(&journal).await;
    std::fs::remove_file(&settled_files(&journal.path)[0]).unwrap();
    assert_rescans(&journal, Some(before), None).await;
}

#[tokio::test]
async fn invalidated_by_settled_rewrite_that_changes_length() {
    let journal = completed(3).await;
    let before = prime(&journal).await;
    let victim = settled_files(&journal.path)[0].clone();
    let original = std::fs::read(&victim).unwrap();
    let body: Value = serde_json::from_slice(&original).unwrap();
    let pretty = serde_json::to_vec_pretty(&body).unwrap();
    assert_ne!(pretty.len(), original.len());
    std::fs::write(&victim, pretty).unwrap();
    assert_rescans(&journal, Some(before), None).await;
}

#[tokio::test]
async fn invalidated_by_settled_rewrite_that_changes_only_mtime() {
    let journal = completed(3).await;
    let before = prime(&journal).await;
    let victim = settled_files(&journal.path)[0].clone();
    let modified = std::fs::metadata(&victim).unwrap().modified().unwrap();
    // Identical bytes and name; only the modification time moves.
    set_mtime(&victim, modified + std::time::Duration::from_secs(10));
    assert_rescans(&journal, Some(before), None).await;
}

#[tokio::test]
async fn invalidated_by_parent_added() {
    let journal = completed(3).await;
    let before = prime(&journal).await;
    journal.store.begin_parent(next_parent()).await.unwrap();
    // begin_parent rewrites the root and carries the stale marker along.
    assert_eq!(marker(&journal.path), Some(before.clone()));
    assert_rescans(&journal, Some(before), None).await;
}

#[tokio::test]
async fn invalidated_by_parent_removed() {
    let journal = completed(3).await;
    journal.store.begin_parent(next_parent()).await.unwrap();
    let before = prime(&journal).await;
    assert_hit(&journal).await;
    let mut root = read_root(&journal.path);
    let parents = root["parents"].as_array_mut().unwrap();
    assert_eq!(parents.len(), 4);
    parents.pop(); // the childless parent: removing it leaves a valid journal
    write_root(&journal.path, &root);
    assert_eq!(marker(&journal.path), Some(before.clone()));
    assert_rescans(&journal, Some(before), None).await;
}

// Same parent count as before, so only the parent identity itself can invalidate the marker.
#[tokio::test]
async fn invalidated_by_parent_id_replaced_at_the_same_count() {
    let journal = completed(3).await;
    let before = prime(&journal).await;
    assert_hit(&journal).await;
    let mut root = read_root(&journal.path);
    let owner = root["parents"][0]["id"].as_str().unwrap().to_owned();
    // The replaced parent owns a settled child, so a full scan must reject the binding.
    let child = settled_files(&journal.path)
        .into_iter()
        .map(|path| serde_json::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap())
        .find(|child| child["managed"]["parent"] == owner.as_str())
        .expect("first parent owns a settled child");
    assert_eq!(child["managed"]["parent"], owner.as_str());
    root["parents"][0]["id"] = json!(Uuid::from_u128(4242).to_string());
    assert_eq!(root["parents"].as_array().unwrap().len(), 3);
    write_root(&journal.path, &root);
    assert_eq!(marker(&journal.path), Some(before.clone()));
    let seen = admit(&journal).await;
    assert_error_contains(seen.result, "invalid managed child binding");
    assert!(seen.parses > 0, "the full scan must have run");
}

#[tokio::test]
async fn invalidated_by_generation_change() {
    let journal = completed(3).await;
    let before = prime(&journal).await;
    let old = generation_dir(&journal.path);
    let replacement = Uuid::from_u128(777).to_string();
    let new = journal.path.join(format!("attempts-v2-{replacement}"));
    copy_directory(&old, &new);
    let mut root = read_root(&journal.path);
    root["generation"] = json!(replacement);
    write_root(&journal.path, &root);
    assert_eq!(marker(&journal.path), Some(before.clone()));
    assert_rescans(&journal, Some(before), None).await;
}

fn copy_directory(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_directory(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A migrated v1 journal with five children and one orphan legacy intent row (attempt 6).
fn legacy_root() -> Value {
    let id = |index: u128| AttemptId::from_uuid(Uuid::from_u128(index)).to_string();
    let repository = RepositoryId::from([0x41; 16]).to_string();
    let states = [
        json!({"state":"unresolved"}),
        json!({"state":"adjudicated_unknown"}),
        json!({"state":"resolved","resolution":"applied"}),
        json!({"state":"resolved","resolution":"not_applied"}),
        json!({"state":"resolved","resolution":"conflicted"}),
    ];
    let attempts: Vec<_> = states
        .into_iter()
        .enumerate()
        .map(|(i, state)| {
            let index = i as u128 + 1;
            json!({"attempt_id":id(index),"state":state,"operation":"Storage.Put",
                "repository":repository,"recorded_at_unix_millis":index as i64})
        })
        .collect();
    let parent = Uuid::from_u128(100).to_string();
    let managed: Vec<_> = (1..=6)
        .map(|index| {
            json!({"attempt":id(index),"parent":parent,"rpc":"Storage.Put","canonical_request":[8,1]})
        })
        .collect();
    json!({
        "parents":[{"version":1,"id":parent,"root":"fixture","operation":"compact",
            "normalized_intent":"fixture","namespace":{"repository":repository,
                "endpoint":"https://journal.invalid","issuer":"issuer","subject":"subject",
                "capabilities":"capabilities-0"},"complete":false,"body_completed":true}],
        "attempts":attempts,"managed":managed
    })
}

async fn migrated_legacy() -> Journal {
    let journal = journal();
    let mut bytes = vec![1];
    bytes.extend(serde_json::to_vec(&legacy_root()).unwrap());
    std::fs::write(journal.path.join("attempts"), bytes).unwrap();
    // Any journal operation migrates v1 to a v2 generation.
    assert!(
        journal
            .store
            .lookup(&AttemptId::from_uuid(Uuid::from_u128(3)))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        read_root(&journal.path)["managed"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    journal
}

#[tokio::test]
async fn invalidated_by_legacy_intent_change() {
    let journal = migrated_legacy().await;
    let before = prime(&journal).await;
    assert_hit(&journal).await;
    let mut root = read_root(&journal.path);
    // The orphan intent row is the only legacy managed intent left after migration.
    root["managed"] = json!([]);
    write_root(&journal.path, &root);
    assert_eq!(marker(&journal.path), Some(before.clone()));
    assert_rescans(&journal, Some(before), None).await;
}

#[tokio::test]
async fn invalidated_by_legacy_intent_added() {
    let journal = migrated_legacy().await;
    let before = prime(&journal).await;
    let mut root = read_root(&journal.path);
    let mut row = root["managed"][0].clone();
    row["attempt"] = json!(AttemptId::from_uuid(Uuid::from_u128(7)).to_string());
    root["managed"].as_array_mut().unwrap().push(row);
    write_root(&journal.path, &root);
    assert_rescans(&journal, Some(before), None).await;
}

// Same legacy-intent count as before: only the row identity can invalidate the marker.
#[tokio::test]
async fn invalidated_by_legacy_intent_attempt_replaced_at_the_same_count() {
    let journal = migrated_legacy().await;
    let before = prime(&journal).await;
    assert_hit(&journal).await;
    let mut root = read_root(&journal.path);
    root["managed"][0]["attempt"] = json!(AttemptId::from_uuid(Uuid::from_u128(8)).to_string());
    assert_eq!(root["managed"].as_array().unwrap().len(), 1);
    write_root(&journal.path, &root);
    assert_eq!(marker(&journal.path), Some(before.clone()));
    assert_rescans(&journal, Some(before), None).await;
}

#[tokio::test]
async fn invalidated_by_legacy_intent_parent_replaced_at_the_same_count() {
    let journal = migrated_legacy().await;
    let before = prime(&journal).await;
    assert_hit(&journal).await;
    let mut root = read_root(&journal.path);
    root["managed"][0]["parent"] = json!(Uuid::from_u128(4343).to_string());
    assert_eq!(root["managed"].as_array().unwrap().len(), 1);
    write_root(&journal.path, &root);
    assert_eq!(marker(&journal.path), Some(before.clone()));
    assert_rescans(&journal, Some(before), None).await;
}

async fn assert_marker_edit_rescans(edit: impl FnOnce(&mut Value)) {
    let journal = completed(3).await;
    let original = prime(&journal).await;
    assert_hit(&journal).await;
    let mut root = read_root(&journal.path);
    edit(&mut root);
    write_root(&journal.path, &root);
    // Children are unchanged, so the rewrite must restore the exact original marker.
    assert_rescans(&journal, None, Some(original)).await;
}

#[tokio::test]
async fn rescans_when_the_marker_field_is_missing() {
    assert_marker_edit_rescans(|root| {
        assert!(root.as_object_mut().unwrap().remove("validated").is_some());
    })
    .await;
}

#[tokio::test]
async fn rescans_when_the_marker_version_is_unknown() {
    assert_marker_edit_rescans(|root| root["validated"]["version"] = json!(2)).await;
}

#[tokio::test]
async fn rescans_when_the_marker_fingerprint_is_garbage() {
    assert_marker_edit_rescans(|root| root["validated"]["fingerprint"] = json!("not-a-hash")).await;
}

// ---------------------------------------------------------------------------
// 3. Corruption after the marker
// ---------------------------------------------------------------------------

#[tokio::test]
async fn torn_settled_child_after_marker_fails_admission() {
    let journal = completed(3).await;
    let primed = prime(&journal).await;
    assert_hit(&journal).await;
    std::fs::write(&settled_files(&journal.path)[0], b"torn").unwrap();
    let before = root_bytes(&journal.path);
    assert_error_contains(admit(&journal).await.result, "parse child");
    assert_eq!(
        root_bytes(&journal.path),
        before,
        "a failed scan must not write a marker"
    );
    assert_eq!(marker(&journal.path), Some(primed));
}

#[tokio::test]
async fn torn_settled_child_after_marker_closes_the_fence() {
    let root = tempfile::tempdir().unwrap();
    let journal = root.path().join(".lore-workflow");
    std::fs::create_dir(&journal).unwrap();
    let store = RepositoryAttemptStore::in_directory(&journal);
    for _ in 0..3 {
        full_cycle(&store).await;
    }
    drop(RepositoryMutationGuard::acquire(root.path()).await.unwrap());
    assert!(marker(&journal).is_some());
    std::fs::write(&settled_files(&journal)[0], b"torn").unwrap();
    assert!(RepositoryMutationGuard::acquire(root.path()).await.is_err());
}

// DOCUMENTED RESIDUAL: a rewrite that keeps name, length and mtime is invisible to admission
// until a full scan; managed_parents (recovery, `lore operation status`) always scans in full.
#[tokio::test]
async fn residual_same_length_same_mtime_rewrite_passes_admission_but_not_managed_parents() {
    let journal = completed(3).await;
    prime(&journal).await;
    let victim = settled_files(&journal.path)[0].clone();
    let original = std::fs::read(&victim).unwrap();
    let modified = std::fs::metadata(&victim).unwrap().modified().unwrap();
    std::fs::write(&victim, same_length_wrong_identity(&original)).unwrap();
    set_mtime(&victim, modified);
    let metadata = std::fs::metadata(&victim).unwrap();
    assert_eq!(metadata.modified().unwrap(), modified);
    assert_eq!(metadata.len() as usize, original.len());

    let seen = admit(&journal).await;
    seen.result.unwrap();
    assert_eq!(seen.parses, 0, "admission trusts the marker (the residual)");

    // A fresh store has no settled-child cache, so this is a genuine full scan.
    let fresh = RepositoryAttemptStore::in_directory(&journal.path);
    assert_error_contains(
        fresh.managed_parents().await,
        "invalid journal child version or identity",
    );
}

// ---------------------------------------------------------------------------
// 4. Crash safety
// ---------------------------------------------------------------------------

fn injected_root_write_failure(
    path: &Path,
    fired: &Arc<AtomicBool>,
) -> lore_revision::attempt_store::persistence::PublicationProbe {
    let root = path.join("attempts");
    let fired = fired.clone();
    install_publication_probe(path.to_path_buf(), move |point, _, destination| {
        if point == PublicationPoint::BeforeRename && destination == root {
            fired.store(true, Ordering::SeqCst);
            Err(ProtocolError::internal("injected root publication failure"))
        } else {
            Ok(())
        }
    })
}

#[tokio::test]
async fn failed_marker_write_is_best_effort_and_the_next_admission_scans_and_writes_it() {
    let journal = completed(3).await;
    let before = root_bytes(&journal.path);
    let fired = Arc::new(AtomicBool::new(false));
    let probe = injected_root_write_failure(&journal.path, &fired);
    let seen = admit(&journal).await;
    seen.result.unwrap();
    assert!(
        fired.load(Ordering::SeqCst),
        "the root write must be reached"
    );
    assert_eq!(seen.parses, 3, "the scan finished before the marker write");
    assert_eq!(root_bytes(&journal.path), before, "root unchanged");
    assert!(marker(&journal.path).is_none());
    drop(probe);

    assert_rescans(&journal, None, None).await;
}

// The publication already happened when this point fails: the call errors, but the marker is
// on disk and describes the state the full scan validated, so the next admission is a hit.
#[tokio::test]
async fn marker_write_failing_after_rename_admits_and_the_published_marker_is_trusted() {
    let journal = completed(3).await;
    let root = journal.path.join("attempts");
    let fired = Arc::new(AtomicBool::new(false));
    let probe = {
        let fired = fired.clone();
        install_publication_probe(journal.path.clone(), move |point, _, destination| {
            if point == PublicationPoint::AfterRenameBeforeDirectorySync && destination == root {
                fired.store(true, Ordering::SeqCst);
                Err(ProtocolError::internal("injected post-rename failure"))
            } else {
                Ok(())
            }
        })
    };
    let seen = admit(&journal).await;
    seen.result.unwrap();
    assert!(
        fired.load(Ordering::SeqCst),
        "the root write must be reached"
    );
    assert_eq!(seen.parses, 3, "the scan finished before the marker write");
    assert!(marker(&journal.path).is_some(), "the rename published it");
    drop(probe);
    assert_hit(&journal).await;
}

// A root the process cannot replace must not refuse admission once the full scan passed; the
// marker just stays absent. Windows only: the read-only attribute blocks a rename-replace there,
// while Unix rename permission belongs to the directory, not the file.
#[cfg(windows)]
#[tokio::test]
async fn read_only_root_admits_after_a_full_scan_and_never_gets_a_marker() {
    let journal = completed(3).await;
    let root = journal.path.join("attempts");
    let original = std::fs::metadata(&root).unwrap().permissions();
    let mut permissions = original.clone();
    permissions.set_readonly(true);
    std::fs::set_permissions(&root, permissions).unwrap();
    let first = admit(&journal).await;
    let second = admit(&journal).await;
    let writable = std::fs::metadata(&root).unwrap().permissions();
    std::fs::set_permissions(&root, original).unwrap();
    first.result.unwrap();
    second.result.unwrap();
    assert_eq!(first.parses, 3, "first admission scans in full");
    assert_eq!(
        second.parses, 3,
        "no marker was recorded, so it scans again"
    );
    assert!(
        writable.readonly(),
        "the root stayed read-only during admission"
    );
    assert!(marker(&journal.path).is_none());
    // Once writable again, the next admission records the marker.
    assert_rescans(&journal, None, None).await;
}

#[tokio::test]
async fn settled_add_after_marker_with_no_root_write_rescans_in_full_after_restart() {
    let journal = journal();
    let parent = begin(&journal.store).await;
    let (first, first_intent) = child(parent);
    let (second, second_intent) = child(parent);
    for (record, intent) in [(&first, &first_intent), (&second, &second_intent)] {
        journal.store.record_managed(record, intent).await.unwrap();
    }
    journal
        .store
        .resolve(&first.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    let stale = prime(&journal).await;
    // The process "crashes" right after a settled child lands, before any root write.
    journal
        .store
        .resolve(&second.attempt_id, AttemptResolution::Applied)
        .await
        .unwrap();
    assert_eq!(marker(&journal.path), Some(stale.clone()));

    // Restart: a new store instance. The first retry also fails to publish the root, so the
    // stale marker survives; the retry after that must still scan in full.
    let restarted = Journal {
        store: RepositoryAttemptStore::in_directory(&journal.path),
        ..journal
    };
    let fired = Arc::new(AtomicBool::new(false));
    let probe = injected_root_write_failure(&restarted.path, &fired);
    let seen = admit(&restarted).await;
    seen.result.unwrap();
    assert!(
        fired.load(Ordering::SeqCst),
        "the root write must be reached"
    );
    assert_eq!(seen.parses, 2, "stale marker must not suppress the scan");
    assert_eq!(marker(&restarted.path), Some(stale.clone()));
    drop(probe);

    assert_rescans(&restarted, Some(stale), None).await;
}

// ---------------------------------------------------------------------------
// 5. Old-format compatibility
// ---------------------------------------------------------------------------

#[tokio::test]
async fn root_without_the_field_loads_and_admits_with_a_full_scan() {
    let journal = completed(3).await;
    assert!(
        read_root(&journal.path)
            .as_object()
            .unwrap()
            .get("validated")
            .is_none(),
        "a root nobody admitted must not carry the field at all"
    );
    assert_rescans(&journal, None, None).await;
}

/// The `StoredDocument` definition at commit 03ce00a4 (`git show
/// 03ce00a4:lore-revision/src/attempt_store.rs`), before the `validated` field existed. It has
/// no `deny_unknown_fields`, which is the whole compatibility argument for an additive field.
#[derive(Debug, Default, Deserialize, Serialize)]
struct PreChangeStoredDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generation: Option<String>,
    #[serde(default)]
    parents: Vec<ManagedParent>,
    #[serde(default)]
    managed: Vec<StoredManagedIntent>,
    #[serde(default)]
    attempts: Vec<StoredAttempt>,
    #[serde(default)]
    ownership: Vec<StoredOwnership>,
}

#[tokio::test]
async fn pre_change_reader_parses_a_marked_root_and_its_rewrite_forces_a_full_scan() {
    let journal = completed(3).await;
    let marked = prime(&journal).await;
    let bytes = root_bytes(&journal.path);
    assert_eq!(bytes[0], 2);

    // The old build reads the new root: the unknown field is ignored.
    let old: PreChangeStoredDocument = serde_json::from_slice(&bytes[1..]).unwrap();
    assert_eq!(old.parents.len(), 3);
    assert_eq!(
        old.generation.as_deref(),
        read_root(&journal.path)["generation"].as_str()
    );

    // ... and writes its next root without it, exactly as the old build would.
    let mut rewritten = vec![bytes[0]];
    rewritten.extend(serde_json::to_vec(&old).unwrap());
    assert!(
        !String::from_utf8_lossy(&rewritten).contains("validated"),
        "the old build cannot carry the marker"
    );
    std::fs::write(journal.path.join("attempts"), rewritten).unwrap();
    assert!(marker(&journal.path).is_none());

    // The new build sees the marker missing and scans in full, restoring the same marker.
    assert_rescans(&journal, None, Some(marked)).await;
}

// ---------------------------------------------------------------------------
// Fence: both the main and the legacy store use marker admission
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fence_acquire_uses_marker_admission_for_main_and_legacy_journals() {
    let root = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(root.path()).unwrap();
    let probe = phase_diagnostics::Probe::install(canonical.clone());
    for directory in [".lore-workflow", ".lore"] {
        let path = canonical.join(directory);
        std::fs::create_dir(&path).unwrap();
        let store = RepositoryAttemptStore::in_directory(&path);
        for _ in 0..2 {
            full_cycle(&store).await;
        }
    }
    let parses = |probe: &phase_diagnostics::Probe| counter(probe, "child_parse");
    let before = parses(&probe);
    drop(RepositoryMutationGuard::acquire(&canonical).await.unwrap());
    let first = parses(&probe) - before;
    assert!(first >= 4, "first acquire scans 2 + 2 settled children");
    for directory in [".lore-workflow", ".lore"] {
        assert!(marker(&canonical.join(directory)).is_some(), "{directory}");
    }
    let before = parses(&probe);
    drop(RepositoryMutationGuard::acquire(&canonical).await.unwrap());
    assert_eq!(parses(&probe) - before, 0, "second acquire is a marker hit");
}

// ---------------------------------------------------------------------------
// 6. Measurement (descriptive; no threshold)
// ---------------------------------------------------------------------------

// Run with: cargo test -j 4 -p lore-revision --features test-util --release --test
// admission_marker -- --ignored --nocapture admission_cost_with_1000_completed_parents
// LORE_ADMISSION_PARENTS overrides the count.
#[tokio::test]
#[ignore = "descriptive timing measurement; opt in with --ignored --nocapture"]
async fn admission_cost_with_1000_completed_parents() {
    let count: usize = std::env::var("LORE_ADMISSION_PARENTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1000);
    let worktree = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(worktree.path()).unwrap();
    let path = root.join(".lore-workflow");
    std::fs::create_dir(&path).unwrap();
    let probe = phase_diagnostics::Probe::install(root.clone());
    let builder = RepositoryAttemptStore::in_directory(&path);
    let started = Instant::now();
    for _ in 0..count {
        full_cycle(&builder).await;
    }
    eprintln!(
        "admission_cost parents={count} build_ms={:.1} profile={}",
        started.elapsed().as_secs_f64() * 1000.0,
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    drop(builder);

    let measure = |label: &'static str, started: Instant, before: (usize, usize)| {
        eprintln!(
            "admission_cost {label}: ms={:.3} child_read={} child_parse={}",
            started.elapsed().as_secs_f64() * 1000.0,
            counter(&probe, "child_read") - before.0,
            counter(&probe, "child_parse") - before.1,
        );
    };
    let snapshot = || {
        (
            counter(&probe, "child_read"),
            counter(&probe, "child_parse"),
        )
    };

    let store = RepositoryAttemptStore::in_directory(&path);
    let (at, begun) = (snapshot(), Instant::now());
    assert_eq!(store.managed_parents().await.unwrap().len(), count);
    measure("a managed_parents (old admission cost)", begun, at);

    // (d) fence on the same worktree, which has no marker yet.
    let (at, begun) = (snapshot(), Instant::now());
    drop(RepositoryMutationGuard::acquire(&root).await.unwrap());
    measure("d1 fence acquire first (full + marker write)", begun, at);
    let (at, begun) = (snapshot(), Instant::now());
    drop(RepositoryMutationGuard::acquire(&root).await.unwrap());
    measure("d2 fence acquire second (marker hit)", begun, at);

    // (b)/(c) need an unmarked root again.
    let mut document = read_root(&path);
    assert!(
        document
            .as_object_mut()
            .unwrap()
            .remove("validated")
            .is_some()
    );
    write_root(&path, &document);
    let store = RepositoryAttemptStore::in_directory(&path);
    let (at, begun) = (snapshot(), Instant::now());
    store.admission_parents().await.unwrap();
    measure("b admission_parents first (full + marker write)", begun, at);
    let (at, begun) = (snapshot(), Instant::now());
    store.admission_parents().await.unwrap();
    measure("c admission_parents second (marker hit)", begun, at);
}
