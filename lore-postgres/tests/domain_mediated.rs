// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Tests for invariants in CR-029's mediated-proof schema
//! (`lore-postgres/src/domain/schema_mediated.rs`) that are deliberately
//! **not** expressible as a single-table CHECK or a catalog exclusion
//! constraint, and so are enforced in code rather than by the schema:
//!
//! - the fence-or-tombstone exchange: `lore_domain_operation_dispatch_possibility_fences`
//!   and `lore_domain_operation_reserve_release_tombstones` share the full
//!   receipt key, and only the Phase 1 transaction may delete a fence — it
//!   must insert the matching tombstone in that same transaction. A
//!   cross-table CHECK cannot express "at most one of these two rows exists
//!   for this key", so what's tested here is the atomicity the code depends
//!   on: the delete-and-insert either both happen or neither does.
//! - prune-range non-overlap: the module docs say plainly that this is
//!   enforced by the namespace row lock in code, not by a GiST `EXCLUDE`
//!   (which would need `CREATE EXTENSION btree_gist`, unavailable to
//!   boot-time DDL on a managed cell database), with the unique indexes on
//!   `start_sequence`/`end_sequence` as a catalog backstop that only catches
//!   an *exact* duplicated bound. This file proves that backstop's real
//!   shape — including its limit: two ranges that overlap without sharing an
//!   exact bound are **not** caught by the catalog alone, which is exactly
//!   why the namespace-lock discipline is load-bearing. There is no
//!   merge/insert application function in this crate yet (`schema_mediated.rs`
//!   is DDL and constants only) to drive a true concurrent-merge test
//!   against; that is real coverage owed once that code lands, not something
//!   this file can fake without testing a test-authored reimplementation
//!   instead of production code.
//!
//! Gated on `LORE_TEST_PG_URL`; skipped when unset. Isolated per test by
//! random receipt keys/epochs since the tables are shared.

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::error::SqlState;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn connect_domain_store(url: &str) -> PostgresDomainStore {
    PostgresDomainStore::connect(url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store")
}

async fn pg_client(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect for direct test setup");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

/// One full receipt key, fresh and random for each test.
struct Key {
    verified_issuer: String,
    authenticated_subject: String,
    tenant_scope_key: [u8; 8],
    operation_id: [u8; 16],
}

fn fresh_key() -> Key {
    Key {
        verified_issuer: format!(
            "https://issuer.example/wp116-mediated/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "svc:wp116-mediated-test".to_string(),
        tenant_scope_key: rand::random(),
        operation_id: rand::random(),
    }
}

async fn insert_fence(
    client: &tokio_postgres::Client,
    key: &Key,
) -> Result<(), tokio_postgres::Error> {
    let scope: [u8; 8] = rand::random();
    let fingerprint: [u8; 32] = rand::random();
    let canonical_intent_digest: [u8; 32] = rand::random();
    let authorization_id: [u8; 16] = rand::random();
    let verification_nonce: [u8; 32] = rand::random();
    let bound_fields_digest: [u8; 32] = rand::random();
    let consumed_ticket_sha256: [u8; 32] = rand::random();
    let expected_claim_identity_digest: [u8; 32] = rand::random();
    client
        .execute(
            "INSERT INTO lore_domain_operation_dispatch_possibility_fences (
                verified_issuer, authenticated_subject, tenant_scope_key, operation_id,
                method, scope, fingerprint_version, fingerprint, canonical_intent_digest,
                authorization_id, authorization_revision, verification_nonce,
                bound_fields_digest, consumed_ticket_sha256, expected_claim_identity_digest,
                created_revision, created_at, safe_prune_after
            ) VALUES ($1, $2, $3, $4, 'lore.domain.v1.test/Method', $5, 1, $6, $7,
                      $8, 0, $9, $10, $11, $12, 0, clock_timestamp(),
                      clock_timestamp() + interval '1 day')",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key.as_slice(),
                &key.operation_id.as_slice(),
                &scope.as_slice(),
                &fingerprint.as_slice(),
                &canonical_intent_digest.as_slice(),
                &authorization_id.as_slice(),
                &verification_nonce.as_slice(),
                &bound_fields_digest.as_slice(),
                &consumed_ticket_sha256.as_slice(),
                &expected_claim_identity_digest.as_slice(),
            ],
        )
        .await
        .map(|_| ())
}

async fn delete_fence(
    tx: &tokio_postgres::Transaction<'_>,
    key: &Key,
) -> Result<u64, tokio_postgres::Error> {
    tx.execute(
        "DELETE FROM lore_domain_operation_dispatch_possibility_fences
          WHERE verified_issuer = $1 AND authenticated_subject = $2
            AND tenant_scope_key = $3 AND operation_id = $4",
        &[
            &key.verified_issuer,
            &key.authenticated_subject,
            &key.tenant_scope_key.as_slice(),
            &key.operation_id.as_slice(),
        ],
    )
    .await
}

async fn insert_tombstone(
    tx: &tokio_postgres::Transaction<'_>,
    key: &Key,
) -> Result<u64, tokio_postgres::Error> {
    let scope: [u8; 8] = rand::random();
    let fingerprint: [u8; 32] = rand::random();
    let authorization_id: [u8; 16] = rand::random();
    let claim_id: [u8; 16] = rand::random();
    let reserve_charge_nonce: [u8; 32] = rand::random();
    let tombstone_reservation_nonce: [u8; 32] = rand::random();
    let terminal_ack_digest: [u8; 32] = rand::random();
    let receipt_prune_digest: [u8; 32] = rand::random();
    let fence_prune_digest: [u8; 32] = rand::random();
    let phase1_response = b"phase1-response".as_slice();
    let tombstone_digest: [u8; 32] = rand::random();
    tx.execute(
        "INSERT INTO lore_domain_operation_reserve_release_tombstones (
            verified_issuer, authenticated_subject, tenant_scope_key, operation_id,
            method, scope, fingerprint_version, fingerprint,
            authorization_id, authorization_revision, claim_id, claim_revision,
            reserve_charge_revision, reserve_charge_nonce,
            tombstone_reservation_revision, tombstone_reservation_nonce,
            terminal_ack_digest, receipt_prune_digest, fence_prune_digest, phase1_response,
            created_at, compact_after, final_prune_after, tombstone_digest
        ) VALUES ($1, $2, $3, $4, 'lore.domain.v1.test/Method', $5, 1, $6,
                  $7, 0, $8, 0, 0, $9, 0, $10, $11, $12, $13, $14,
                  clock_timestamp(), clock_timestamp() + interval '1 day',
                  clock_timestamp() + interval '2 days', $15)",
        &[
            &key.verified_issuer,
            &key.authenticated_subject,
            &key.tenant_scope_key.as_slice(),
            &key.operation_id.as_slice(),
            &scope.as_slice(),
            &fingerprint.as_slice(),
            &authorization_id.as_slice(),
            &claim_id.as_slice(),
            &reserve_charge_nonce.as_slice(),
            &tombstone_reservation_nonce.as_slice(),
            &terminal_ack_digest.as_slice(),
            &receipt_prune_digest.as_slice(),
            &fence_prune_digest.as_slice(),
            &phase1_response,
            &tombstone_digest.as_slice(),
        ],
    )
    .await
}

async fn fence_exists(client: &tokio_postgres::Client, key: &Key) -> bool {
    client
        .query_opt(
            "SELECT 1 FROM lore_domain_operation_dispatch_possibility_fences
              WHERE verified_issuer = $1 AND authenticated_subject = $2
                AND tenant_scope_key = $3 AND operation_id = $4",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key.as_slice(),
                &key.operation_id.as_slice(),
            ],
        )
        .await
        .expect("query fence existence")
        .is_some()
}

async fn tombstone_exists(client: &tokio_postgres::Client, key: &Key) -> bool {
    client
        .query_opt(
            "SELECT 1 FROM lore_domain_operation_reserve_release_tombstones
              WHERE verified_issuer = $1 AND authenticated_subject = $2
                AND tenant_scope_key = $3 AND operation_id = $4",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key.as_slice(),
                &key.operation_id.as_slice(),
            ],
        )
        .await
        .expect("query tombstone existence")
        .is_some()
}

/// The Phase 1 replace pattern: delete the fence and insert the matching
/// tombstone in one transaction. After commit, exactly the tombstone remains.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn fence_delete_and_tombstone_insert_commit_together() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping fence-to-tombstone exchange test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let key = fresh_key();

    insert_fence(&client, &key).await.expect("seed fence");
    assert!(fence_exists(&client, &key).await);
    assert!(!tombstone_exists(&client, &key).await);

    let tx = client.transaction().await.expect("begin exchange tx");
    let deleted = delete_fence(&tx, &key).await.expect("delete fence");
    assert_eq!(deleted, 1, "exactly the seeded fence row must be deleted");
    insert_tombstone(&tx, &key)
        .await
        .expect("insert the matching tombstone in the same transaction");
    tx.commit().await.expect("commit the exchange");

    assert!(
        !fence_exists(&client, &key).await,
        "the fence must be gone after the exchange"
    );
    assert!(
        tombstone_exists(&client, &key).await,
        "the matching tombstone must exist"
    );
}

/// The exchange is atomic: if the transaction that deletes the fence and
/// inserts the tombstone is rolled back, the fence must survive untouched and
/// no tombstone must exist — no partial state from an interrupted exchange.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn fence_delete_and_tombstone_insert_roll_back_together() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping fence-to-tombstone rollback test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let key = fresh_key();

    insert_fence(&client, &key).await.expect("seed fence");

    let tx = client.transaction().await.expect("begin exchange tx");
    delete_fence(&tx, &key)
        .await
        .expect("delete fence inside the transaction");
    insert_tombstone(&tx, &key)
        .await
        .expect("insert tombstone inside the transaction");
    tx.rollback().await.expect("roll back the exchange");

    assert!(
        fence_exists(&client, &key).await,
        "a rolled-back exchange must leave the original fence untouched"
    );
    assert!(
        !tombstone_exists(&client, &key).await,
        "a rolled-back exchange must not leave a tombstone behind"
    );
}

async fn insert_prune_range(
    client: &tokio_postgres::Client,
    key: &Key,
    epoch: &[u8],
    start_sequence: i64,
    end_sequence: i64,
) -> Result<(), tokio_postgres::Error> {
    let interval_digest: [u8; 32] = rand::random();
    let sequence_count = end_sequence - start_sequence + 1;
    client
        .execute(
            "INSERT INTO lore_domain_tombstone_marker_prune_ranges (
                verified_issuer, authenticated_subject, tenant_scope_key, epoch,
                protocol_revision, quota_revision, marker_interval_schema_revision,
                start_sequence, end_sequence, sequence_count, generation,
                created_at_ms, row_charge, byte_charge, interval_digest
            ) VALUES ($1, $2, $3, $4, 1, 1, 3, $5, $6, $7, $6, 0, 1, 0, $8)",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key.as_slice(),
                &epoch,
                &start_sequence,
                &end_sequence,
                &sequence_count,
                &interval_digest.as_slice(),
            ],
        )
        .await
        .map(|_| ())
}

/// The documented backstop: an *exact* duplicated `start_sequence` collides
/// on the primary key, and an exact duplicated `end_sequence` collides on
/// `lore_domain_prune_ranges_end`. Positive controls first (two genuinely
/// disjoint ranges must both be accepted), matching the "a negative control
/// alone doesn't prove the positive path" rule.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prune_range_catalog_backstop_catches_an_exact_duplicated_bound() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping prune-range backstop test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let key = fresh_key();
    let epoch: [u8; 16] = rand::random();

    insert_prune_range(&client, &key, &epoch, 1, 10)
        .await
        .expect("first range must be accepted");
    insert_prune_range(&client, &key, &epoch, 11, 20)
        .await
        .expect("a disjoint adjacent range must be accepted");
    insert_prune_range(&client, &key, &epoch, 31, 40)
        .await
        .expect("a second disjoint range must be accepted");

    // Exact duplicated start_sequence -> primary key violation.
    let err = insert_prune_range(&client, &key, &epoch, 1, 30)
        .await
        .expect_err("a duplicated start_sequence must collide on the primary key");
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::UNIQUE_VIOLATION);
    assert_eq!(
        db_err.constraint(),
        Some("lore_domain_tombstone_marker_prune_ranges_pkey")
    );

    // Exact duplicated end_sequence (40, shared with [31, 40]), different
    // start_sequence (25) so the primary key and bounds CHECK are untouched —
    // isolates the dedicated end_sequence unique index.
    let err = insert_prune_range(&client, &key, &epoch, 25, 40)
        .await
        .expect_err("a duplicated end_sequence must collide on its dedicated unique index");
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::UNIQUE_VIOLATION);
    assert_eq!(db_err.constraint(), Some("lore_domain_prune_ranges_end"));
}

/// The catalog's real limit, proven rather than merely asserted in a comment:
/// two ranges that overlap **without** sharing an exact `start_sequence` or
/// `end_sequence` are not rejected by anything in the schema. This is the
/// precise reason the namespace row lock (code, not catalog) is load-bearing
/// for true non-overlap — there is no merge/insert function in this crate
/// yet to test that discipline against.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prune_range_catalog_alone_does_not_catch_general_overlap() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping prune-range general-overlap test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let key = fresh_key();
    let epoch: [u8; 16] = rand::random();

    insert_prune_range(&client, &key, &epoch, 1, 10)
        .await
        .expect("first range must be accepted");
    // [5, 15] overlaps [1, 10] on 5..=10 but shares neither exact bound.
    insert_prune_range(&client, &key, &epoch, 5, 15)
        .await
        .expect(
            "the schema alone does not catch a general overlap with no shared exact bound; \
             true non-overlap depends on code-level namespace-lock discipline that does not \
             exist yet in this crate — this is documented, expected-red-by-design evidence, \
             not a passing correctness guarantee",
        );
}
