// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Integration tests for the Postgres mutable (branch-tip CAS) store (CR-007).
//!
//! Gated on `LORE_TEST_PG_URL`; skipped when unset. Isolated by a random
//! `Partition` since `lore_mutable` is shared.

use std::sync::Arc;

use lore_base::types::KeyType;
use lore_postgres::store::mutable_store::PostgresMutableStore;
use lore_storage::Hash;
use lore_storage::MutableStore;
use lore_storage::Partition;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

#[tokio::test]
async fn mutable_cas_lifecycle() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping Postgres mutable-store test");
        return;
    };
    let store = Arc::new(
        PostgresMutableStore::connect(&url, 5, None)
            .await
            .expect("connect + schema"),
    );

    let part: Partition = rand::random();
    let key: Hash = rand::random();
    let kt = KeyType::RepositoryId;
    let v1: Hash = rand::random();
    let v2: Hash = rand::random();

    // Absent → AddressNotFound.
    assert!(store.clone().load(part, key, kt).await.is_err());

    // store + load.
    store
        .clone()
        .store(part, key, v1, kt)
        .await
        .expect("store v1");
    assert_eq!(
        store.clone().load(part, key, kt).await.expect("load v1"),
        v1
    );

    // CAS with matching expected → swaps, returns expected.
    let prev = store
        .clone()
        .compare_and_swap(part, key, v1, v2, kt)
        .await
        .expect("cas v1->v2");
    assert_eq!(prev, v1);
    assert_eq!(
        store.clone().load(part, key, kt).await.expect("load v2"),
        v2
    );

    // CAS with stale expected → no swap, returns the actual current value.
    let v3: Hash = rand::random();
    let got = store
        .clone()
        .compare_and_swap(part, key, v1, v3, kt)
        .await
        .expect("cas stale");
    assert_eq!(got, v2, "stale CAS returns current");
    assert_eq!(
        store
            .clone()
            .load(part, key, kt)
            .await
            .expect("load unchanged"),
        v2,
        "stale CAS must not modify"
    );

    // store(null) removes the key.
    store
        .clone()
        .store(part, key, Hash::default(), kt)
        .await
        .expect("store null removes");
    assert!(store.clone().load(part, key, kt).await.is_err());

    // CAS on an absent key inserts and reports success (returns expected).
    let v4: Hash = rand::random();
    let exp_absent: Hash = rand::random();
    let r = store
        .clone()
        .compare_and_swap(part, key, exp_absent, v4, kt)
        .await
        .expect("cas absent");
    assert_eq!(r, exp_absent);
    assert_eq!(
        store.clone().load(part, key, kt).await.expect("load v4"),
        v4
    );

    // list by (partition, key_type) → both keys.
    let key2: Hash = rand::random();
    let v5: Hash = rand::random();
    store
        .clone()
        .store(part, key2, v5, kt)
        .await
        .expect("store key2");
    let mut rx = store.clone().list(part, kt).await.expect("list").channel();
    let mut items = Vec::new();
    while let Some(kv) = rx.recv().await {
        items.push(kv);
    }
    assert_eq!(
        items.len(),
        2,
        "list returns both keys for the partition+type"
    );
}
