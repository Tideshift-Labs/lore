// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Concurrency integration tests for the Postgres stores (CR-007).
//!
//! (a) Racing CAS: exactly one concurrent `compare_and_swap` wins; no lost updates.
//! (b) CAS outcome selection shares the per-key writer lock; no false success after a miss.
//! (c) Batch lock atomicity: a batch that conflicts on any resource rolls back entirely,
//!     leaving no partial lock state.
//!
//! Gated on `LORE_TEST_PG_URL` and honestly `#[ignore]`d when the live service
//! tier is not requested. Uses `#[serial]` to avoid cross-test interference on
//! the shared tables.

use std::sync::Arc;
use std::time::Duration;

use lore_base::types::KeyType;
use lore_base::types::LockResource;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use lore_postgres::store::lock_store::PostgresLockStore;
use lore_postgres::store::mutable_store::PostgresMutableStore;
use lore_revision::lock::LockError;
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
#[ignore = "needs live Postgres env; run with -- --ignored"]
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
    // the DB level under the per-key transactional advisory lock.
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

/// (b) A failed CAS cannot report success after an interleaving writer.
///
/// Hold the exact advisory lock used by mutable writers, queue a CAS behind it,
/// then install a value different from the CAS expectation before releasing the
/// lock. The CAS must remain blocked, then return the intervening value without
/// installing its proposal. The old two-statement CAS did not take this lock
/// and could report `expected` after an outcome-select race.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs live Postgres env; run with -- --ignored"]
#[serial]
async fn cas_outcome_is_serialized_with_interleaving_writer() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping CAS outcome serialization test");
        return;
    };

    let tls = TlsConfig::default();
    let store = Arc::new(
        PostgresMutableStore::connect(&url, 5, &tls)
            .await
            .expect("connect + schema"),
    );
    let pool = build_pool(&url, 2, &tls).expect("build coordination pool");

    let partition: Partition = rand::random();
    let key: Hash = rand::random();
    let key_type = KeyType::RepositoryId;
    let expected: Hash = rand::random();
    let proposed: Hash = rand::random();
    let intervening: Hash = rand::random();
    store
        .clone()
        .store(partition, key, expected, key_type)
        .await
        .expect("seed expected value");

    let mut client = pool.get().await.expect("checkout coordination client");
    let tx = client.transaction().await.expect("start coordination tx");
    let partition_bytes = partition.data();
    let key_bytes = key.data();
    let key_type_id = key_type as i16;
    tx.execute(
        "SELECT pg_advisory_xact_lock( \
             hashtextextended( \
                 encode($1, 'hex') || ':' || $2::smallint::text || ':' || encode($3, 'hex'), \
                 0 \
             ) \
         )",
        &[
            &partition_bytes.as_slice(),
            &key_type_id,
            &key_bytes.as_slice(),
        ],
    )
    .await
    .expect("hold mutable writer lock");

    let mut cas = lore_base::lore_spawn!({
        let store = store.clone();
        async move {
            store
                .compare_and_swap(partition, key, expected, proposed, key_type)
                .await
        }
    });

    tx.execute(
        "UPDATE lore_mutable SET value = $4 \
         WHERE partition = $1 AND key_type = $2 AND key = $3",
        &[
            &partition_bytes.as_slice(),
            &key_type_id,
            &key_bytes.as_slice(),
            &intervening.data().as_slice(),
        ],
    )
    .await
    .expect("install intervening value");
    assert!(
        tokio::time::timeout(Duration::from_millis(250), &mut cas)
            .await
            .is_err(),
        "CAS must wait for the per-key writer transaction to release its lock"
    );
    tx.commit().await.expect("release mutable writer lock");

    let returned = tokio::time::timeout(Duration::from_secs(5), cas)
        .await
        .expect("CAS must finish after lock release")
        .expect("CAS task must not panic")
        .expect("CAS must not fail");
    assert_eq!(
        returned, intervening,
        "failed CAS must return the value observed at its locked linearization point"
    );
    assert_eq!(
        store
            .clone()
            .load(partition, key, key_type)
            .await
            .expect("load after failed CAS"),
        intervening,
        "failed CAS must not install its proposed value"
    );
}

/// (c) Batch lock is all-or-nothing.
///
/// Alice holds r1. Bob's batch `[r2, r1]` must fail because r1 is held. The
/// transaction must roll back entirely — r2 must NOT be left locked by a
/// partial insert.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
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
    let batch_err = store
        .lock_resources("bob", repo, &[r2.clone(), r1.clone()])
        .await
        .unwrap_err();
    assert!(
        matches!(batch_err, LockError::LockNotOwned(_)),
        "expected LockNotOwned for bob's batch conflict, got {batch_err:?}"
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
