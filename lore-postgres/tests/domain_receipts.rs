// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Receipt state-machine CHECK-constraint tests for
//! `lore_domain_operation_receipts` (CR-029, WP-116 Phase 2).
//!
//! Gated on `LORE_TEST_PG_URL`; skipped when unset. Isolated per test by
//! random receipt keys since the table is shared.

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

/// One receipt row with fresh random identity each call, overridable on the
/// fields the state-machine constraints actually gate. Fields not relevant to
/// a given constraint use a valid default so only the field under test can be
/// blamed for a rejection.
async fn insert_receipt(
    client: &tokio_postgres::Client,
    state: i16,
    consume_token: Option<&[u8]>,
    outcome: Option<i16>,
    not_applied_reason_version: Option<i32>,
    not_applied_reason: Option<&str>,
) -> Result<(), tokio_postgres::Error> {
    let verified_issuer = format!(
        "https://issuer.example/wp116-test/{:016x}",
        rand::random::<u64>()
    );
    let authenticated_subject = "svc:wp116-test";
    let tenant_scope_key: [u8; 8] = rand::random();
    let operation_id: [u8; 16] = rand::random();
    let scope: [u8; 8] = rand::random();
    let fingerprint: [u8; 32] = rand::random();
    let canonical_intent_digest: [u8; 32] = rand::random();

    let committed_at_expr = if state == 1 {
        "clock_timestamp()"
    } else {
        "NULL"
    };
    let full_result_expiry_expr = if state == 1 {
        "clock_timestamp() + interval '30 days'"
    } else {
        "NULL"
    };
    let compact_expiry_expr = if state == 1 {
        "clock_timestamp() + interval '365 days'"
    } else {
        "NULL"
    };

    let sql = format!(
        "INSERT INTO lore_domain_operation_receipts (
            verified_issuer, authenticated_subject, tenant_scope_key, operation_id,
            method, scope, fingerprint_version, fingerprint, canonical_intent_digest,
            state, consume_token, outcome, not_applied_reason_version, not_applied_reason,
            uuid_timestamp, prepared_at, hard_expires_at, committed_at,
            full_result_expires_at, compact_expires_at
        ) VALUES (
            $1, $2, $3, $4,
            $5, $6, $7, $8, $9,
            $10, $11, $12, $13, $14,
            clock_timestamp(), clock_timestamp(), clock_timestamp() + interval '15 minutes',
            {committed_at_expr}, {full_result_expiry_expr}, {compact_expiry_expr}
        )"
    );

    client
        .execute(
            &sql,
            &[
                &verified_issuer,
                &authenticated_subject,
                &tenant_scope_key.as_slice(),
                &operation_id.as_slice(),
                &"lore.domain.v1.test/Method",
                &scope.as_slice(),
                &1i32,
                &fingerprint.as_slice(),
                &canonical_intent_digest.as_slice(),
                &state,
                &consume_token,
                &outcome,
                &not_applied_reason_version,
                &not_applied_reason,
            ],
        )
        .await
        .map(|_| ())
}

fn assert_check_violation(err: &tokio_postgres::Error, expected_constraint: &str) {
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(
        db_err.code(),
        &SqlState::CHECK_VIOLATION,
        "expected SQLSTATE 23514 (check_violation), got {:?}: {db_err}",
        db_err.code()
    );
    assert_eq!(
        db_err.constraint(),
        Some(expected_constraint),
        "expected the {expected_constraint} constraint to fire, got {:?}: {db_err}",
        db_err.constraint()
    );
}

/// Positive controls: the three legal row shapes (PREPARED, COMMITTED
/// APPLIED, COMMITTED NOT_APPLIED) must all be accepted. Kept alongside the
/// negative cases below so a constraint that is simply too strict (rejecting
/// everything) cannot masquerade as "the negative cases all pass" — see the
/// testing guide's note that a negative control alone doesn't prove the
/// positive path.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn receipt_state_shape_accepts_the_three_legal_row_shapes() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping receipt legal-shape test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;

    let token: [u8; 32] = rand::random();
    insert_receipt(&client, 0, Some(&token), None, None, None)
        .await
        .expect("PREPARED with a consume token and no outcome must be accepted");

    insert_receipt(&client, 1, None, Some(0), None, None)
        .await
        .expect("COMMITTED APPLIED with no reason must be accepted");

    insert_receipt(
        &client,
        1,
        None,
        Some(1),
        Some(1),
        Some("stale precondition"),
    )
    .await
    .expect("COMMITTED NOT_APPLIED with a versioned reason must be accepted");
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn receipt_state_shape_rejects_prepared_with_an_outcome() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping receipt PREPARED-with-outcome test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let token: [u8; 32] = rand::random();

    let err = insert_receipt(&client, 0, Some(&token), Some(0), None, None)
        .await
        .expect_err("PREPARED with a non-null outcome must be rejected");
    assert_check_violation(&err, "lore_domain_operation_receipts_state_shape");
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn receipt_state_shape_rejects_prepared_with_a_null_consume_token() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping receipt PREPARED-null-token test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;

    let err = insert_receipt(&client, 0, None, None, None, None)
        .await
        .expect_err("PREPARED with a null consume token must be rejected");
    assert_check_violation(&err, "lore_domain_operation_receipts_state_shape");
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn receipt_state_shape_rejects_committed_with_a_non_null_consume_token() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping receipt COMMITTED-with-token test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let token: [u8; 32] = rand::random();

    let err = insert_receipt(&client, 1, Some(&token), Some(0), None, None)
        .await
        .expect_err("COMMITTED with a non-null consume token must be rejected");
    assert_check_violation(&err, "lore_domain_operation_receipts_state_shape");
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn receipt_not_applied_reason_constraint_requires_a_reason() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping receipt NOT_APPLIED-missing-reason test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;

    let err = insert_receipt(&client, 1, None, Some(1), None, None)
        .await
        .expect_err("COMMITTED NOT_APPLIED with a null reason/version must be rejected");
    assert_check_violation(&err, "lore_domain_operation_receipts_not_applied_reason");
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn receipt_applied_reason_constraint_forbids_a_reason() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping receipt APPLIED-with-reason test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;

    let err = insert_receipt(
        &client,
        1,
        None,
        Some(0),
        Some(1),
        Some("should not be here"),
    )
    .await
    .expect_err("COMMITTED APPLIED with a non-null reason must be rejected");
    assert_check_violation(&err, "lore_domain_operation_receipts_applied_reason");
}
