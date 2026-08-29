// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032 outbox-base conformance tests (F-032-2; WP-116 Phase 2).
//!
//! Covers the transaction-local [`lore_postgres::domain::outbox::append`] API
//! and the schema constraints it relies on: the 64 KiB payload bound, the
//! `(cell_id, idempotency_key)` unique retry, the `pending`/`broker_accepted`/
//! `consumer_safe` state enum, atomic append-then-rollback, and schema-state
//! survival across a repeated bootstrap.
//!
//! Gated on `LORE_TEST_PG_URL`; skipped when unset. Isolated per test by
//! random cell/repository/aggregate identities since the table is shared.

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::outbox::OutboxEvent;
use lore_postgres::domain::outbox::append;
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

fn fresh_event<'a>(
    cell_id: &'a str,
    repository_id: &'a [u8],
    aggregate_id: &'a [u8],
    aggregate_version: &'a [u8],
    payload: &'a [u8],
) -> OutboxEvent<'a> {
    OutboxEvent {
        cell_id,
        repository_id,
        repository_generation: 1,
        event_kind: "branch.pushed",
        aggregate_kind: "branch",
        aggregate_id,
        aggregate_version,
        payload_schema_version: 1,
        payload,
    }
}

/// Payload over the frozen 64 KiB cap must be rejected before any SQL runs
/// (`append`'s own `validate`), and the cap itself is a schema CHECK too —
/// prove both by going one byte over via a raw insert that bypasses
/// `append`'s pre-check.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn payload_over_64_kib_is_rejected_by_append_and_by_the_schema_check() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping outbox payload-bound test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let repository_id: [u8; 16] = rand::random();
    let cell_id = format!("cell-{:016x}", rand::random::<u64>());
    let aggregate_id: [u8; 16] = rand::random();

    let oversized = vec![0u8; 64 * 1024 + 1];
    let tx = client.transaction().await.expect("begin tx");
    let event = fresh_event(&cell_id, &repository_id, &aggregate_id, b"v1", &oversized);
    let err = append(&tx, &event)
        .await
        .expect_err("append must reject a payload over the frozen 64 KiB cap");
    assert!(
        matches!(err, lore_postgres::domain::DomainError::InvalidInput(_)),
        "expected InvalidInput, got {err:?}"
    );
    tx.rollback().await.expect("rollback after rejected append");

    // The schema CHECK is the backstop for any writer that bypasses `append`.
    let tx = client.transaction().await.expect("begin raw-insert tx");
    let event_id = uuid::Uuid::new_v4();
    let raw_err = tx
        .execute(
            "INSERT INTO lore_outbox_events (
                event_id, cell_id, idempotency_key, repository_id, repository_generation,
                event_kind, aggregate_kind, aggregate_id, aggregate_version,
                payload_schema_version, payload, state, created_at, available_at
            ) VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, $7,
                      'pending', clock_timestamp(), clock_timestamp())",
            &[
                &event_id,
                &cell_id,
                &rand::random::<[u8; 32]>().as_slice(),
                &repository_id.as_slice(),
                &aggregate_id.as_slice(),
                &b"v1".as_slice(),
                &oversized.as_slice(),
            ],
        )
        .await
        .expect_err("raw insert over the payload cap must be rejected by the CHECK constraint");
    let db_err = raw_err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::CHECK_VIOLATION);
    tx.rollback().await.expect("rollback raw-insert tx");
}

/// `(cell_id, idempotency_key)` is unique: an exact mutation retry (identical
/// cell, event kind, repository, aggregate identity/version) must find the
/// original row and its stable `event_id` rather than creating a duplicate,
/// even when the payload bytes differ between the two calls.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn exact_key_retry_after_commit_returns_the_original_event_id() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping outbox exact-retry test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let repository_id: [u8; 16] = rand::random();
    let cell_id = format!("cell-{:016x}", rand::random::<u64>());
    let aggregate_id: [u8; 16] = rand::random();

    let tx = client.transaction().await.expect("begin first tx");
    let first_event = fresh_event(&cell_id, &repository_id, &aggregate_id, b"v1", b"{}");
    let first = append(&tx, &first_event)
        .await
        .expect("first append must succeed");
    assert!(first.created, "first append must report created=true");
    tx.commit().await.expect("commit first append");

    // Exact retry: identical identity tuple, different payload bytes.
    let tx = client.transaction().await.expect("begin retry tx");
    let retry_event = fresh_event(
        &cell_id,
        &repository_id,
        &aggregate_id,
        b"v1",
        b"{\"different\":true}",
    );
    let retry = append(&tx, &retry_event)
        .await
        .expect("exact retry append must succeed");
    tx.commit().await.expect("commit retry append");

    assert!(!retry.created, "exact retry must report created=false");
    assert_eq!(
        retry.event_id, first.event_id,
        "exact retry must return the original stable event_id"
    );
    assert_eq!(retry.idempotency_key, first.idempotency_key);

    let row_count: i64 = client
        .query_one(
            "SELECT count(*) FROM lore_outbox_events WHERE cell_id = $1 AND idempotency_key = $2",
            &[&cell_id, &first.idempotency_key.as_slice()],
        )
        .await
        .expect("count rows for this idempotency key")
        .get(0);
    assert_eq!(row_count, 1, "exact retry must not create a second row");
}

/// A different aggregate version (a genuinely new mutation, not a retry of
/// the same one) must get its own row and its own `event_id`.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn different_aggregate_version_creates_a_new_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping outbox different-version test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let repository_id: [u8; 16] = rand::random();
    let cell_id = format!("cell-{:016x}", rand::random::<u64>());
    let aggregate_id: [u8; 16] = rand::random();

    let tx = client.transaction().await.expect("begin tx v1");
    let v1 = fresh_event(&cell_id, &repository_id, &aggregate_id, b"v1", b"{}");
    let first = append(&tx, &v1).await.expect("append v1");
    tx.commit().await.expect("commit v1");

    let tx = client.transaction().await.expect("begin tx v2");
    let v2 = fresh_event(&cell_id, &repository_id, &aggregate_id, b"v2", b"{}");
    let second = append(&tx, &v2).await.expect("append v2");
    tx.commit().await.expect("commit v2");

    assert!(
        second.created,
        "a distinct aggregate version must create a new row"
    );
    assert_ne!(second.event_id, first.event_id);
    assert_ne!(second.idempotency_key, first.idempotency_key);
}

/// The `state` enum admits exactly `pending`, `broker_accepted`, and
/// `consumer_safe`; anything else is rejected by the CHECK constraint.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn state_enum_admits_exactly_the_three_frozen_values() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping outbox state-enum test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let repository_id: [u8; 16] = rand::random();

    for state in ["pending", "broker_accepted", "consumer_safe"] {
        let cell_id = format!("cell-{:016x}", rand::random::<u64>());
        let aggregate_id: [u8; 16] = rand::random();
        client
            .execute(
                "INSERT INTO lore_outbox_events (
                    event_id, cell_id, idempotency_key, repository_id, repository_generation,
                    event_kind, aggregate_kind, aggregate_id, aggregate_version,
                    payload_schema_version, payload, state, created_at, available_at
                ) VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, 'v1', 1, '{}',
                          $6, clock_timestamp(), clock_timestamp())",
                &[
                    &uuid::Uuid::new_v4(),
                    &cell_id,
                    &rand::random::<[u8; 32]>().as_slice(),
                    &repository_id.as_slice(),
                    &aggregate_id.as_slice(),
                    &state,
                ],
            )
            .await
            .unwrap_or_else(|e| {
                panic!("state {state:?} must be accepted by the CHECK constraint: {e}")
            });
    }

    let cell_id = format!("cell-{:016x}", rand::random::<u64>());
    let aggregate_id: [u8; 16] = rand::random();
    let err = client
        .execute(
            "INSERT INTO lore_outbox_events (
                event_id, cell_id, idempotency_key, repository_id, repository_generation,
                event_kind, aggregate_kind, aggregate_id, aggregate_version,
                payload_schema_version, payload, state, created_at, available_at
            ) VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, 'v1', 1, '{}',
                      'bogus_state', clock_timestamp(), clock_timestamp())",
            &[
                &uuid::Uuid::new_v4(),
                &cell_id,
                &rand::random::<[u8; 32]>().as_slice(),
                &repository_id.as_slice(),
                &aggregate_id.as_slice(),
            ],
        )
        .await
        .expect_err("an out-of-enum state value must be rejected");
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::CHECK_VIOLATION);
}

/// Appending inside a transaction that then rolls back must leave no row:
/// the whole point of the transaction-local API is that the event commits or
/// rolls back with the mutation that caused it.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn append_inside_a_rolled_back_transaction_leaves_no_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping outbox atomic-rollback test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let repository_id: [u8; 16] = rand::random();
    let cell_id = format!("cell-{:016x}", rand::random::<u64>());
    let aggregate_id: [u8; 16] = rand::random();

    let tx = client.transaction().await.expect("begin tx");
    let event = fresh_event(&cell_id, &repository_id, &aggregate_id, b"v1", b"{}");
    let appended = append(&tx, &event).await.expect("append must succeed");
    tx.rollback()
        .await
        .expect("rollback the mutation transaction");

    let row_count: i64 = client
        .query_one(
            "SELECT count(*) FROM lore_outbox_events WHERE event_id = $1",
            &[&appended.event_id],
        )
        .await
        .expect("count rows for the rolled-back event_id")
        .get(0);
    assert_eq!(row_count, 0, "a rolled-back append must leave no row");
}

/// Restart/bootstrap (reconnecting `PostgresDomainStore`) must leave the
/// outbox schema-state row intact rather than resetting its compatibility
/// floors or cutover marker.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn restart_leaves_the_outbox_schema_state_row_intact() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping outbox restart test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;

    let before = client
        .query_one(
            "SELECT migration_version, producer_compat_floor, relay_compat_floor, \
                    consumer_compat_floor, cutover_at \
             FROM lore_outbox_schema_state WHERE id = 1",
            &[],
        )
        .await
        .expect("read outbox schema state before restart");

    // Simulate a second replica/process booting against the same database.
    connect_domain_store(&url).await;

    let after = client
        .query_one(
            "SELECT migration_version, producer_compat_floor, relay_compat_floor, \
                    consumer_compat_floor, cutover_at \
             FROM lore_outbox_schema_state WHERE id = 1",
            &[],
        )
        .await
        .expect("read outbox schema state after restart");

    let before_version: i64 = before.get("migration_version");
    let after_version: i64 = after.get("migration_version");
    assert_eq!(before_version, after_version);
    let before_floor: i32 = before.get("producer_compat_floor");
    let after_floor: i32 = after.get("producer_compat_floor");
    assert_eq!(before_floor, after_floor);
    let before_cutover: Option<std::time::SystemTime> = before.get("cutover_at");
    let after_cutover: Option<std::time::SystemTime> = after.get("cutover_at");
    assert_eq!(before_cutover, after_cutover);
}
