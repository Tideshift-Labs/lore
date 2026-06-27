// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Integration tests for the Postgres lock store (CR-007).
//!
//! Gated on `LORE_TEST_PG_URL` (e.g. `postgres://postgres:test@localhost:5433/lore`);
//! skipped when unset so the default `cargo test` needs no database. Each test
//! isolates by a random `RepositoryId` since the `lore_locks` table is shared.

use lore_base::types::LockResource;
use lore_postgres::store::lock_store::PostgresLockStore;
use lore_revision::lock::LockQuery;
use lore_revision::lock::LockStore;
use lore_revision::lore::RepositoryId;

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

#[tokio::test]
async fn lock_lifecycle() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping Postgres lock-store test");
        return;
    };
    let store = PostgresLockStore::connect(&url, 5, None)
        .await
        .expect("connect + schema");

    let repo: RepositoryId = rand::random();
    let r1 = resource("file/a.txt");
    let r2 = resource("file/b.txt");

    // Acquire by alice → exactly one new lock.
    let locked = store
        .lock_resources("alice", repo, std::slice::from_ref(&r1))
        .await
        .expect("alice acquires r1");
    assert_eq!(locked.len(), 1);
    assert_eq!(locked[0].owner, "alice");
    assert_eq!(locked[0].resource.description, "file/a.txt");

    // Idempotent re-acquire by alice → no new lock (same-owner skip).
    let again = store
        .lock_resources("alice", repo, std::slice::from_ref(&r1))
        .await
        .expect("alice re-acquires r1 idempotently");
    assert!(again.is_empty());

    // Conflict: bob cannot take r1.
    assert!(
        store
            .lock_resources("bob", repo, std::slice::from_ref(&r1))
            .await
            .is_err()
    );

    // Batch atomicity: bob acquires [r2 (free), r1 (held)] → whole batch fails,
    // and r2 must NOT be left locked (transaction rolled back).
    assert!(
        store
            .lock_resources("bob", repo, &[r2.clone(), r1.clone()])
            .await
            .is_err()
    );
    let r2_status = store
        .check_locks_status(repo, std::slice::from_ref(&r2))
        .await
        .expect("status r2");
    assert!(r2_status.is_empty(), "r2 should have rolled back");

    // Query by repository → only r1.
    let all = store
        .query_locks(LockQuery::Repository(repo))
        .await
        .expect("query repo");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].resource.description, "file/a.txt");

    // Point status for r1 → present.
    let st = store
        .check_locks_status(repo, std::slice::from_ref(&r1))
        .await
        .expect("status r1");
    assert_eq!(st.len(), 1);

    // bob's owner-checked unlock of r1 → rejected.
    assert!(
        store
            .unlock_resources("bob", true, repo, std::slice::from_ref(&r1))
            .await
            .is_err()
    );

    // Owner-checked unlock of a non-existent lock (r2) → rejected.
    assert!(
        store
            .unlock_resources("alice", true, repo, std::slice::from_ref(&r2))
            .await
            .is_err()
    );

    // Force unlock (validate_user = false) of r1 by bob → succeeds.
    let freed = store
        .unlock_resources("bob", false, repo, std::slice::from_ref(&r1))
        .await
        .expect("force unlock r1");
    assert_eq!(freed.len(), 1);

    // r1 is gone.
    let gone = store
        .check_locks_status(repo, std::slice::from_ref(&r1))
        .await
        .expect("status r1 after unlock");
    assert!(gone.is_empty());
}
