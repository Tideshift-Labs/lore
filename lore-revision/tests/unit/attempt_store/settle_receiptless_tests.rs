// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! `settle_receiptless` must not close a parent that a root orphan intent still claims.
#![allow(clippy::disallowed_methods)]

use lore_revision::attempt_store::ManagedParent;
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_revision::attempt_store::StoredDocument;
use lore_revision::attempt_store::StoredManagedIntent;
use uuid::Uuid;

#[tokio::test]
async fn a_root_orphan_intent_keeps_its_parent_open() {
    let dir = tempfile::tempdir().unwrap();
    let parent_id = Uuid::from_u128(100);
    let document = StoredDocument {
        parents: vec![ManagedParent {
            version: 1,
            id: parent_id.to_string(),
            root: "fixture".into(),
            operation: "push".into(),
            normalized_intent: "fixture".into(),
            namespace: None,
            complete: false,
            parent_uncertainty_code: None,
            body_completed: false,
        }],
        managed: vec![StoredManagedIntent {
            attempt: Uuid::from_u128(1).to_string(),
            parent: parent_id.to_string(),
            rpc: "StorageService.Put".into(),
            canonical_request: vec![8, 1],
        }],
        ..StoredDocument::default()
    };
    let mut bytes = vec![1];
    bytes.extend(serde_json::to_vec(&document).unwrap());
    std::fs::write(dir.path().join("attempts"), bytes).unwrap();

    let store = RepositoryAttemptStore::in_directory(dir.path());
    assert!(!store.settle_receiptless().await.unwrap());
    let parents = store.managed_parents().await.unwrap();
    assert_eq!(parents.len(), 1);
    assert!(!parents[0].complete);
    assert!(!parents[0].body_completed);
}
