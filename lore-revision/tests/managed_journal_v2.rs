// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

// Raw writes below construct crash/migration fixtures only inside fresh temporary directories.
#![allow(clippy::disallowed_methods)]

use std::path::Path;
use std::path::PathBuf;

use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::RepositoryId;
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptState;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::caller_operation::ManagedAttemptIntent;
use lore_transport::outcome::AttemptId;
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;

#[path = "managed_journal_v2/process.rs"]
mod process;

fn parent() -> Uuid {
    Uuid::from_u128(100)
}

fn id(index: u128) -> AttemptId {
    AttemptId::from_uuid(Uuid::from_u128(index))
}

fn repository() -> RepositoryId {
    RepositoryId::from([0x41; 16])
}

fn record(index: u128, state: AttemptState) -> AttemptRecord {
    AttemptRecord {
        attempt_id: id(index),
        state,
        operation: "Storage.Put".into(),
        repository: repository(),
        recorded_at_unix_millis: i64::try_from(index).unwrap(),
        receipt: None,
    }
}

fn intent(index: u128) -> ManagedAttemptIntent {
    ManagedAttemptIntent {
        version: 1,
        parent_id: parent(),
        repository: repository(),
        rpc: "Storage.Put".into(),
        canonical_request: vec![8, 1],
        endpoint: "https://journal.invalid".into(),
        verified_issuer: "issuer".into(),
        authenticated_subject: "subject".into(),
        caller_capabilities: format!("capabilities-{}", index / 100),
    }
}

fn legacy() -> Value {
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
            json!({"attempt_id":id(index).to_string(),"state":state,"operation":"Storage.Put",
            "repository":repository().to_string(),"recorded_at_unix_millis":index as i64})
        })
        .collect();
    let managed: Vec<_> = (1..=6)
        .map(|index| {
            json!({
                "attempt":id(index).to_string(),"parent":parent().to_string(),"rpc":"Storage.Put",
                "canonical_request":[8,1]
            })
        })
        .collect();
    json!({
        "parents":[{"version":1,"id":parent().to_string(),"root":"fixture","operation":"compact",
            "normalized_intent":"fixture","namespace":{"repository":repository().to_string(),
                "endpoint":"https://journal.invalid","issuer":"issuer","subject":"subject",
                "capabilities":"capabilities-0"},"complete":false,"body_completed":true}],
        "attempts":attempts,"managed":managed,
        "ownership":[{"attempt_id":id(3).to_string(),"branch":Context::from([0x11;16]).to_string(),
            "resource":Hash::from([0x22;32]).to_string(),"token":hex::encode([0x33;32])}]
    })
}

fn write_root(path: &Path, version: u8, body: &Value) -> Vec<u8> {
    let mut bytes = vec![version];
    bytes.extend(serde_json::to_vec(body).unwrap());
    std::fs::write(path.join("attempts"), &bytes).unwrap();
    bytes
}

fn generation(path: &Path) -> PathBuf {
    let bytes = std::fs::read(path.join("attempts")).unwrap();
    assert_eq!(bytes[0], 2);
    let root: Value = serde_json::from_slice(&bytes[1..]).unwrap();
    let generation = root["generation"].as_str().unwrap();
    Uuid::parse_str(generation).unwrap();
    path.join(format!("attempts-v2-{generation}"))
}

async fn migrated(path: &Path) -> RepositoryAttemptStore {
    write_root(path, 1, &legacy());
    let store = RepositoryAttemptStore::in_directory(path);
    assert_eq!(
        store.lookup(&id(3)).await.unwrap(),
        Some(record(
            3,
            AttemptState::Resolved(AttemptResolution::Applied)
        ))
    );
    generation(path);
    store
}

#[tokio::test]
async fn migration_preserves_every_state_namespace_token_and_orphan_intent() {
    let dir = tempfile::tempdir().unwrap();
    let store = migrated(dir.path()).await;
    drop(store);
    let store = RepositoryAttemptStore::in_directory(dir.path());
    let expected_states = [
        AttemptState::Unresolved,
        AttemptState::AdjudicatedUnknown,
        AttemptState::Resolved(AttemptResolution::Applied),
        AttemptState::Resolved(AttemptResolution::NotApplied),
        AttemptState::Resolved(AttemptResolution::Conflicted),
    ];
    for (index, state) in expected_states.into_iter().enumerate() {
        let index = index as u128 + 1;
        assert_eq!(
            store.lookup(&id(index)).await.unwrap(),
            Some(record(index, state))
        );
        let context = store.recovery_context(&id(index)).await.unwrap();
        assert_eq!(context.repository, repository());
        assert_eq!(context.endpoint, "https://journal.invalid");
        assert_eq!(context.verified_issuer, "issuer");
        assert_eq!(context.authenticated_subject, "subject");
        assert_eq!(context.caller_capabilities, "capabilities-0");
    }
    assert_eq!(
        store.unresolved().await.unwrap(),
        vec![
            record(1, AttemptState::Unresolved),
            record(2, AttemptState::AdjudicatedUnknown)
        ]
    );
    let token = store
        .ownership_for(&Context::from([0x11; 16]), &Hash::from([0x22; 32]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(token.attempt_id, id(3));
    assert_eq!(token.token.as_bytes().as_ref(), &[0x33; 32]);
    assert_eq!(store.lookup(&id(6)).await.unwrap(), None);
    assert!(
        store
            .record_managed(&record(6, AttemptState::Unresolved), &intent(6))
            .await
            .is_err(),
        "intent-only legacy child cannot be upgraded into a fresh dispatch"
    );
    assert_eq!(store.lookup(&id(6)).await.unwrap(), None);
}

#[tokio::test]
async fn duplicate_legacy_attempt_ids_fail_without_switching_root() {
    let dir = tempfile::tempdir().unwrap();
    let mut document = legacy();
    let duplicate = document["attempts"][0].clone();
    document["attempts"].as_array_mut().unwrap().push(duplicate);
    let original = write_root(dir.path(), 1, &document);
    let store = RepositoryAttemptStore::in_directory(dir.path());
    assert!(
        store
            .resolve(&id(3), AttemptResolution::Applied)
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(dir.path().join("attempts")).unwrap(),
        original
    );
}

#[tokio::test]
async fn migration_preserves_full_receipt_identity() {
    let dir = tempfile::tempdir().unwrap();
    let mut document = legacy();
    document["attempts"][0]["receipt"] = json!({
        "org_uuid":Uuid::from_u128(201).to_string(),
        "initiating_principal_namespace":"010203", "operation_id":Uuid::from_u128(202).to_string(),
        "method":"RevisionService.BranchPush", "scope":"040506", "fingerprint_version":1,
        "fingerprint":hex::encode([0x11;32]), "canonical_intent_digest":hex::encode([0x22;32]),
        "authorization_revision":7, "consumed_ticket_sha256":hex::encode([0x33;32])
    });
    write_root(dir.path(), 1, &document);
    let store = RepositoryAttemptStore::in_directory(dir.path());
    let expected = lore_transport::domain_receipt::DomainReceiptQuery {
        org_uuid: Uuid::from_u128(201),
        initiating_principal_namespace: bytes::Bytes::from_static(&[1, 2, 3]),
        operation_id: Uuid::from_u128(202),
        method: "RevisionService.BranchPush".into(),
        scope: bytes::Bytes::from_static(&[4, 5, 6]),
        fingerprint_version: 1,
        fingerprint: bytes::Bytes::from(vec![0x11; 32]),
        canonical_intent_digest: bytes::Bytes::from(vec![0x22; 32]),
        authorization_revision: 7,
        consumed_ticket_sha256: bytes::Bytes::from(vec![0x33; 32]),
    };
    assert_eq!(
        store.lookup(&id(1)).await.unwrap().unwrap().receipt,
        Some(expected.clone())
    );
    generation(dir.path());
    drop(store);
    let store = RepositoryAttemptStore::in_directory(dir.path());
    assert_eq!(
        store.lookup(&id(1)).await.unwrap().unwrap().receipt,
        Some(expected)
    );
}

#[tokio::test]
async fn settled_managed_attempt_cannot_be_dispatched_again() {
    let dir = tempfile::tempdir().unwrap();
    let store = migrated(dir.path()).await;
    assert!(
        store
            .record_managed(&record(3, AttemptState::Unresolved), &intent(3))
            .await
            .is_err()
    );
    drop(store);
    let store = RepositoryAttemptStore::in_directory(dir.path());
    assert_eq!(
        store.lookup(&id(3)).await.unwrap(),
        Some(record(
            3,
            AttemptState::Resolved(AttemptResolution::Applied)
        ))
    );
}

#[tokio::test]
async fn duplicate_legacy_managed_ids_fail_without_switching_root() {
    let dir = tempfile::tempdir().unwrap();
    let mut document = legacy();
    let duplicate = document["managed"][0].clone();
    document["managed"].as_array_mut().unwrap().push(duplicate);
    let original = write_root(dir.path(), 1, &document);
    let store = RepositoryAttemptStore::in_directory(dir.path());
    assert!(store.lookup(&id(1)).await.is_err());
    assert_eq!(
        std::fs::read(dir.path().join("attempts")).unwrap(),
        original
    );
}

#[tokio::test]
async fn legacy_uppercase_uuid_aliases_reopen_with_canonical_identities() {
    let dir = tempfile::tempdir().unwrap();
    let mut document = legacy();
    let attempt = id(0xabcdef);
    let parent = Uuid::from_u128(0xfedcba);
    document["attempts"][0]["attempt_id"] = json!(attempt.to_string().to_uppercase());
    document["parents"][0]["id"] = json!(parent.to_string().to_uppercase());
    for child in document["managed"].as_array_mut().unwrap() {
        child["parent"] = json!(parent.to_string().to_uppercase());
    }
    document["managed"][0]["attempt"] = json!(attempt.to_string().to_uppercase());
    document["ownership"][0]["attempt_id"] = json!(attempt.to_string().to_uppercase());
    write_root(dir.path(), 1, &document);
    let store = RepositoryAttemptStore::in_directory(dir.path());
    assert_eq!(
        store.lookup(&attempt).await.unwrap().unwrap().attempt_id,
        attempt
    );
    generation(dir.path());
    drop(store);
    let store = RepositoryAttemptStore::in_directory(dir.path());
    assert_eq!(
        store.managed_parents().await.unwrap()[0].id,
        parent.to_string()
    );
    assert_eq!(
        store
            .recovery_context(&attempt)
            .await
            .unwrap()
            .authenticated_subject,
        "subject"
    );
    assert_eq!(
        store
            .ownership_for(&Context::from([0x11; 16]), &Hash::from([0x22; 32]))
            .await
            .unwrap()
            .unwrap()
            .attempt_id,
        attempt
    );
}

#[tokio::test]
async fn legacy_case_alias_duplicates_preserve_original_root() {
    for managed_duplicate in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut document = legacy();
        let identity = id(0xabcdef).to_string();
        document["attempts"][0]["attempt_id"] = json!(identity);
        document["managed"][0]["attempt"] = json!(identity);
        let (array, field) = if managed_duplicate {
            ("managed", "attempt")
        } else {
            ("attempts", "attempt_id")
        };
        let mut duplicate = document[array][0].clone();
        duplicate[field] = json!(identity.to_uppercase());
        document[array].as_array_mut().unwrap().push(duplicate);
        let original = write_root(dir.path(), 1, &document);
        let store = RepositoryAttemptStore::in_directory(dir.path());
        assert!(store.lookup(&id(0xabcdef)).await.is_err());
        assert_eq!(
            std::fs::read(dir.path().join("attempts")).unwrap(),
            original
        );
    }
}

#[tokio::test]
async fn unsupported_or_corrupt_legacy_roots_remain_unchanged() {
    for original in [vec![], vec![1, b'{'], vec![255, b'{', b'}']] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("attempts"), &original).unwrap();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        assert!(store.unresolved().await.is_err());
        assert_eq!(
            std::fs::read(dir.path().join("attempts")).unwrap(),
            original
        );
        assert_eq!(
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter(|entry| entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("attempts-v2-"))
                .count(),
            0,
            "bad roots must fail before creating a generation"
        );
    }
}

#[tokio::test]
async fn unpublished_generation_does_not_replace_legacy_authority() {
    let dir = tempfile::tempdir().unwrap();
    let abandoned = dir
        .path()
        .join(format!("attempts-v2-{}", Uuid::from_u128(999)));
    std::fs::create_dir_all(abandoned.join("pending")).unwrap();
    std::fs::write(
        abandoned.join("pending").join(format!("{}.json", id(1))),
        b"torn",
    )
    .unwrap();
    let store = migrated(dir.path()).await;
    assert_ne!(generation(dir.path()), abandoned);
    assert_eq!(
        store.lookup(&id(1)).await.unwrap(),
        Some(record(1, AttemptState::Unresolved))
    );
    assert_eq!(store.unresolved().await.unwrap().len(), 2);
}

#[tokio::test]
async fn terminal_pending_crash_residue_is_not_reported_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    drop(migrated(dir.path()).await);
    let generation = generation(dir.path());
    let name = format!("{}.json", id(3));
    std::fs::rename(
        generation.join("settled").join(&name),
        generation.join("pending").join(&name),
    )
    .unwrap();
    let store = RepositoryAttemptStore::in_directory(dir.path());
    assert_eq!(
        store.unresolved().await.unwrap(),
        vec![
            record(1, AttemptState::Unresolved),
            record(2, AttemptState::AdjudicatedUnknown)
        ]
    );
    assert_eq!(
        store.lookup(&id(3)).await.unwrap(),
        Some(record(
            3,
            AttemptState::Resolved(AttemptResolution::Applied)
        ))
    );
}

#[tokio::test]
async fn duplicate_pending_and_settled_child_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    drop(migrated(dir.path()).await);
    let generation = generation(dir.path());
    let name = format!("{}.json", id(1));
    std::fs::copy(
        generation.join("pending").join(&name),
        generation.join("settled").join(&name),
    )
    .unwrap();
    let store = RepositoryAttemptStore::in_directory(dir.path());
    assert!(store.lookup(&id(1)).await.is_err());
    assert!(store.managed_parents().await.is_err());
    assert!(store.finish_parent(parent()).await.is_err());
}

#[tokio::test]
async fn child_filename_identity_and_version_are_checked_on_reopen() {
    for corrupt_version in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        drop(migrated(dir.path()).await);
        let path = generation(dir.path())
            .join("pending")
            .join(format!("{}.json", id(1)));
        let mut child: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        if corrupt_version {
            child["version"] = json!(255);
        } else {
            child["attempt"]["attempt_id"] = json!(id(9).to_string());
        }
        std::fs::write(&path, serde_json::to_vec(&child).unwrap()).unwrap();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        assert!(store.lookup(&id(1)).await.is_err());
        assert!(store.unresolved().await.is_err());
    }
}

#[tokio::test]
async fn corrupt_settled_child_prevents_parent_completion() {
    let dir = tempfile::tempdir().unwrap();
    let store = migrated(dir.path()).await;
    for index in [1, 2] {
        store
            .resolve(&id(index), AttemptResolution::Applied)
            .await
            .unwrap();
    }
    drop(store);
    std::fs::write(
        generation(dir.path())
            .join("settled")
            .join(format!("{}.json", id(3))),
        b"torn",
    )
    .unwrap();
    let store = RepositoryAttemptStore::in_directory(dir.path());
    assert!(store.managed_parents().await.is_err());
    assert!(store.finish_parent(parent()).await.is_err());
}

#[tokio::test]
async fn ordinary_worktree_admission_rejects_corrupt_settled_history() {
    let dir = tempfile::tempdir().unwrap();
    let journal = dir.path().join(".lore-workflow");
    std::fs::create_dir(&journal).unwrap();
    let store = migrated(&journal).await;
    for index in [1, 2] {
        store
            .resolve(&id(index), AttemptResolution::Applied)
            .await
            .unwrap();
    }
    store.finish_parent(parent()).await.unwrap();
    drop(store);
    // Establish admission actually succeeds before corrupting its previously settled history.
    drop(
        lore_revision::repository_fence::RepositoryMutationGuard::acquire(dir.path())
            .await
            .unwrap(),
    );
    std::fs::write(
        generation(&journal)
            .join("settled")
            .join(format!("{}.json", id(3))),
        b"torn",
    )
    .unwrap();
    assert!(
        lore_revision::repository_fence::RepositoryMutationGuard::acquire(dir.path())
            .await
            .is_err()
    );
}

#[test]
fn bootstrap_reservations_match_exact_names_and_leave_lookalikes_visible() {
    use lore_revision::repository_fence::is_workflow_path;
    let temporary = format!(
        ".lore-workflow.directory.{}.~loretemp",
        Uuid::from_u128(123)
    );
    for path in [
        ".lore-workflow.bootstrap.lock".to_owned(),
        ".lore-workflow.directory.AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA.~loretemp".to_owned(),
        temporary.clone(),
        format!("nested/{temporary}/child"),
        format!("nested\\{temporary}\\child"),
    ] {
        assert!(is_workflow_path(&path), "reserved artifact: {path}");
    }
    for path in [
        ".lore-workflow.bootstrap.lock.backup".to_owned(),
        ".lore-workflow.directory.not-a-uuid.~loretemp".to_owned(),
        format!("{temporary}.backup"),
        format!("prefix{temporary}"),
    ] {
        assert!(
            !is_workflow_path(&path),
            "lookalike must remain visible: {path}"
        );
    }
}

#[tokio::test]
async fn settled_to_unresolved_rerecord_retains_managed_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let store = migrated(dir.path()).await;
    store
        .record(&record(3, AttemptState::Unresolved))
        .await
        .unwrap();
    drop(store);
    let store = RepositoryAttemptStore::in_directory(dir.path());
    assert!(
        store
            .unresolved()
            .await
            .unwrap()
            .contains(&record(3, AttemptState::Unresolved))
    );
    assert_eq!(
        store
            .recovery_context(&id(3))
            .await
            .unwrap()
            .authenticated_subject,
        "subject"
    );
    store
        .resolve(&id(3), AttemptResolution::NotApplied)
        .await
        .unwrap();
    assert!(
        !store
            .unresolved()
            .await
            .unwrap()
            .iter()
            .any(|record| record.attempt_id == id(3))
    );
    assert_eq!(
        store.lookup(&id(3)).await.unwrap(),
        Some(record(
            3,
            AttemptState::Resolved(AttemptResolution::NotApplied)
        ))
    );
}
