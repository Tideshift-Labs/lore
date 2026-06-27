// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Concurrency integration tests for the Postgres stores (CR-007).
//!
//! (a) Racing CAS: exactly one concurrent `compare_and_swap` wins; no lost updates.
//! (b) Batch lock atomicity: a batch that conflicts on any resource rolls back entirely,
//!     leaving no partial lock state.
//!
//! Gated on `LORE_TEST_PG_URL`; skipped when unset. Uses `#[serial]` to avoid
//! cross-test interference on the shared tables.

use std::sync::Arc;

use lore_base::types::KeyType;
use lore_base::types::LockResource;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::lock_store::PostgresLockStore;
use lore_postgres::store::mutable_store::PostgresMutableStore;
use lore_revision::lock::LockStore;
use lore_revision::lore::RepositoryId;
use lore_storage::Hash;
use lore_storage::MutableStore;
use lore_storage::Partition;
use serial_test::serial;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

fn resource(desc: &str) -> LockResource {
    LockResource {
        branch: rand::random(),
        hash: rand::random(),
        description: desc.to_string(),
    }
}

/// (a) Racing CAS — no lost update.
///
/// Seeds a key with `v0`, then races two concurrent `compare_and_swap` calls
/// against the same `(partition, key)`. The CAS semantics:
/// - On success the callee returns `expected` (`v0`).
/// - On failure the callee returns the ACTUAL current value (≠ the caller's
///   expected), so the caller can detect the loss.
///
/// Exactly one task must receive `v0` back (the winner). The other must receive
/// a value ≠ `v0`. The final `load` must equal the winner's proposed value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn racing_cas_no_lost_update() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping racing-CAS concurrency test");
        return;
    };

    let store = Arc::new(
        PostgresMutableStore::connect(&url, 5, &TlsConfig::default())
            .await
            .expect("connect + schema"),
    );

    let part: Partition = rand::random();
    let key: Hash = rand::random();
    let kt = KeyType::RepositoryId;
    let v0: Hash = rand::random();
    let value1: Hash = rand::random();
    let value2: Hash = rand::random();

    // Seed the key with v0 so both tasks see it as the current value.
    store
        .clone()
        .store(part, key, v0, kt)
        .await
        .expect("seed v0");

    // Both tasks call CAS concurrently against v0; exactly one can succeed at
    // the DB level (atomic INSERT … ON CONFLICT … WHERE existing.value = expected).
    let store1 = store.clone();
    let store2 = store.clone();
    let (r1, r2) = tokio::join!(
        async move { store1.compare_and_swap(part, key, v0, value1, kt).await },
        async move { store2.compare_and_swap(part, key, v0, value2, kt).await },
    );

    let r1 = r1.expect("task1 CAS must not error");
    let r2 = r2.expect("task2 CAS must not error");

    // Exactly one task gets v0 back (success); the other gets the new current
    // value (the winner's proposed value).
    let task1_won = r1 == v0;
    let task2_won = r2 == v0;
    assert!(
        task1_won ^ task2_won,
        "exactly one CAS must win — both winning would mean a lost update; \
         task1_returned={r1:?} task2_returned={r2:?} v0={v0:?}"
    );

    let (winner_value, loser_return) = if task1_won {
        (value1, r2)
    } else {
        (value2, r1)
    };

    // The loser's return is the new current value set by the winner, not v0.
    assert_ne!(
        loser_return, v0,
        "loser must return the winner's new value, not the original v0"
    );

    // The final stored value is exactly the winner's proposed value.
    let final_val = store.clone().load(part, key, kt).await.expect("final load");
    assert_eq!(
        final_val, winner_value,
        "final stored value must equal the winner's proposed value — no update lost"
    );
}

/// (b) Batch lock is all-or-nothing.
///
/// Alice holds r1. Bob's batch `[r2, r1]` must fail because r1 is held. The
/// transaction must roll back entirely — r2 must NOT be left locked by a
/// partial insert.
#[tokio::test]
#[serial]
async fn batch_lock_all_or_nothing() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping batch-lock atomicity test");
        return;
    };

    let store = PostgresLockStore::connect(&url, 5, &TlsConfig::default())
        .await
        .expect("connect + schema");

    let repo: RepositoryId = rand::random();
    let r1 = resource("concurrency/r1");
    let r2 = resource("concurrency/r2");

    // Alice acquires r1.
    let locked = store
        .lock_resources("alice", repo, std::slice::from_ref(&r1))
        .await
        .expect("alice acquires r1");
    assert_eq!(locked.len(), 1, "alice must hold exactly r1");

    // Bob tries to acquire [r2, r1]. r2 is free; r1 is held by alice.
    // The whole batch must fail because r1 cannot be acquired.
    let batch_result = store
        .lock_resources("bob", repo, &[r2.clone(), r1.clone()])
        .await;
    assert!(
        batch_result.is_err(),
        "bob's batch must fail because r1 is already held by alice"
    );

    // The batch transaction rolled back — r2 must NOT be left locked by bob.
    let r2_status = store
        .check_locks_status(repo, std::slice::from_ref(&r2))
        .await
        .expect("status r2");
    assert!(
        r2_status.is_empty(),
        "r2 must not be locked after the failed batch — the partial insert must have rolled back"
    );

    // r1 must still be held by alice and not corrupted.
    let r1_status = store
        .check_locks_status(repo, std::slice::from_ref(&r1))
        .await
        .expect("status r1");
    assert_eq!(r1_status.len(), 1, "r1 must still be locked");
    assert_eq!(
        r1_status[0].owner, "alice",
        "r1 must still be owned by alice after bob's failed batch"
    );
}
