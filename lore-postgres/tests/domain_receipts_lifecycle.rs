// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Integration tests for the domain operation receipt state machine
//! (`lore-postgres/src/domain/receipts.rs`): `prepare`, `consume`,
//! `commit_terminal`, and `receipt_get`. These are the admission gate for
//! every governed mutation.
//!
//! `receipts.rs`'s own `#[cfg(test)]` module already covers the pure
//! `classify`/`uuid_v7_timestamp` boundary math offline. What's tested here is
//! the async, database-backed state machine built on top of it: which rows
//! get written for each temporal class, retry/mismatch semantics, single-use
//! consumption, hard-TTL expiry, and terminal immutability.
//!
//! Gated on `LORE_TEST_PG_URL`; skipped when unset. Isolated per test by a
//! random `(verified_issuer, tenant_scope_key)` pair, since the future-reject
//! quota is namespaced by exactly that tuple and must not leak between tests.

use std::time::Duration;
use std::time::SystemTime;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PREPARED_HARD_TTL_EXPIRED_V1;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::ReceiptLookup;
use lore_postgres::domain::receipts::UUID_FUTURE_HORIZON_EXCEEDED_V1;
use lore_postgres::domain::receipts::UUID_TIME_OUT_OF_RANGE_V1;
use lore_postgres::domain::receipts::admission_clock;
use lore_postgres::domain::receipts::commit_terminal;
use lore_postgres::domain::receipts::consume;
use lore_postgres::domain::receipts::prepare;
use lore_postgres::domain::receipts::receipt_get;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;
use tokio_postgres::Transaction;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn connect_domain_store(url: &str) -> PostgresDomainStore {
    PostgresDomainStore::connect(url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store")
}

async fn pg_client(url: &str) -> Client {
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

/// A UUIDv7 carrying exactly `ts` as its embedded timestamp, so a test can
/// place an operation ID at a precise offset from a captured admission clock
/// without sleeping.
fn uuid_v7_at(ts: SystemTime) -> Uuid {
    let since_epoch = ts
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("timestamp must be after the Unix epoch");
    Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        since_epoch.as_secs(),
        since_epoch.subsec_nanos(),
    ))
}

fn fresh_key(tenant_scope_key: Vec<u8>, operation_id: Uuid) -> ReceiptKey {
    ReceiptKey {
        verified_issuer: format!(
            "https://issuer.example/wp116-receipts/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "svc:wp116-receipts-test".to_string(),
        tenant_scope_key,
        operation_id,
    }
}

/// A key with an independent, random tenant namespace — the right choice for
/// any test that isn't specifically exercising the shared-namespace quota,
/// since it can never collide with another test's quota state.
fn isolated_key(operation_id: Uuid) -> ReceiptKey {
    fresh_key(rand::random::<[u8; 8]>().to_vec(), operation_id)
}

/// A new operation under the exact same quota namespace
/// `(verified_issuer, authenticated_subject, tenant_scope_key)` as `base` —
/// the future-reject quota is keyed by that triple with no `operation_id`,
/// so a quota test must reuse it exactly rather than calling [`fresh_key`]
/// again, which mints an unrelated random `verified_issuer` every time.
fn same_namespace_key(base: &ReceiptKey, operation_id: Uuid) -> ReceiptKey {
    ReceiptKey {
        verified_issuer: base.verified_issuer.clone(),
        authenticated_subject: base.authenticated_subject.clone(),
        tenant_scope_key: base.tenant_scope_key.clone(),
        operation_id,
    }
}

fn binding(method: &str) -> OperationBinding {
    OperationBinding {
        method: method.to_string(),
        scope: rand::random::<[u8; 8]>().to_vec(),
        fingerprint_version: 1,
        fingerprint: rand::random::<[u8; 32]>().to_vec(),
        canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

async fn receipt_row_count(client: &Client, key: &ReceiptKey) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM lore_domain_operation_receipts
              WHERE verified_issuer = $1 AND authenticated_subject = $2
                AND tenant_scope_key = $3 AND operation_id = $4",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("count receipt rows")
        .get(0)
}

async fn future_rejection_row_count(client: &Client, key: &ReceiptKey) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM lore_domain_operation_future_rejections
              WHERE verified_issuer = $1 AND authenticated_subject = $2
                AND tenant_scope_key = $3 AND operation_id = $4",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("count future-rejection rows")
        .get(0)
}

async fn quota_counts(client: &Client, key: &ReceiptKey) -> Option<(i64, i64)> {
    client
        .query_opt(
            "SELECT retained_count, bucket_count FROM lore_domain_operation_future_reject_quotas
              WHERE verified_issuer = $1 AND authenticated_subject = $2 AND tenant_scope_key = $3",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
            ],
        )
        .await
        .expect("read quota row")
        .map(|row| (row.get(0), row.get(1)))
}

struct PersistedReceipt {
    state: i16,
    consume_token: Option<Vec<u8>>,
    outcome: Option<i16>,
    not_applied_reason: Option<String>,
}

async fn fetch_receipt(client: &Client, key: &ReceiptKey) -> PersistedReceipt {
    let row = client
        .query_one(
            "SELECT state, consume_token, outcome, not_applied_reason
               FROM lore_domain_operation_receipts
              WHERE verified_issuer = $1 AND authenticated_subject = $2
                AND tenant_scope_key = $3 AND operation_id = $4",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("fetch persisted receipt row");
    PersistedReceipt {
        state: row.get("state"),
        consume_token: row.get("consume_token"),
        outcome: row.get("outcome"),
        not_applied_reason: row.get("not_applied_reason"),
    }
}

/// Force a `PREPARED` row into the past relative to its own `hard_expires_at`,
/// without sleeping, so hard-TTL expiry can be exercised deterministically.
async fn age_past_hard_ttl(client: &Client, key: &ReceiptKey) {
    client
        .execute(
            "UPDATE lore_domain_operation_receipts
                SET hard_expires_at = clock_timestamp() - interval '1 second'
              WHERE verified_issuer = $1 AND authenticated_subject = $2
                AND tenant_scope_key = $3 AND operation_id = $4",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("age the row past its hard TTL");
}

async fn capture_clock(client: &mut Client) -> SystemTime {
    let tx: Transaction<'_> = client.transaction().await.expect("begin clock-read tx");
    let clock = admission_clock(&tx).await.expect("read admission clock");
    tx.rollback()
        .await
        .expect("roll back the read-only clock tx");
    clock
}

// ─── PostgresDomainStore wrapper seam ───────────────────────────────────────

/// The coordinator wrapper must expose the same authoritative database clock
/// used by receipt admission, bounded by samples from an independent
/// connection rather than the process clock.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn coordinator_clock_get_samples_the_database_clock() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping coordinator clock test");
        return;
    };
    let store = connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;

    let before = capture_clock(&mut client).await;
    let sampled = store
        .domain_operation_clock_get()
        .await
        .expect("coordinator clock sample");
    let after = capture_clock(&mut client).await;

    assert!(
        before <= sampled && sampled <= after,
        "coordinator sample {sampled:?} must be bounded by independent DB samples {before:?}..={after:?}"
    );
}

/// Exercise prepare and lookup through the public coordinator trait, not the
/// lower-level receipt functions used by the rest of this suite. A successful
/// wrapper commit must be visible on a separate connection, exact prepare
/// replay must return the original token, and a changed binding must remain a
/// nonmutating mismatch.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn coordinator_prepare_commit_is_visible_and_receipt_get_replays_it() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping coordinator receipt wrapper test");
        return;
    };
    let store = connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let original = binding("lore.domain.v1.test/CoordinatorWrapper");

    let first = store
        .domain_operation_prepare(&key, &original, None)
        .await
        .expect("coordinator prepare");
    let PrepareResult::Prepared {
        token: first_token,
        hard_expires_at: first_expiry,
    } = first
    else {
        panic!("expected Prepared, got {first:?}");
    };

    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(persisted.state, 0, "separate connection sees PREPARED");
    assert_eq!(
        persisted.consume_token.as_deref(),
        Some(first_token.as_slice()),
        "separate connection sees the committed token"
    );

    let lookup = store
        .domain_operation_receipt_get(&key, &original)
        .await
        .expect("coordinator receipt lookup");
    let ReceiptLookup::Prepared {
        prepared_at,
        hard_expires_at,
    } = lookup
    else {
        panic!("expected Prepared lookup, got {lookup:?}");
    };
    assert!(prepared_at <= hard_expires_at);
    assert_eq!(hard_expires_at, first_expiry);

    let retry = store
        .domain_operation_prepare(&key, &original, None)
        .await
        .expect("exact coordinator prepare retry");
    assert!(matches!(
        retry,
        PrepareResult::Prepared { token, .. } if token == first_token
    ));

    let mut changed = original.clone();
    changed.fingerprint[0] ^= 0xFF;
    let mismatch = store
        .domain_operation_prepare(&key, &changed, None)
        .await
        .expect("mismatched coordinator prepare");
    assert_eq!(mismatch, PrepareResult::Mismatch);
    let unchanged = fetch_receipt(&client, &key).await;
    assert_eq!(unchanged.consume_token, persisted.consume_token);
}

// ─── the five temporal classes ──────────────────────────────────────────────

/// A stale UUID (older than the 365-day horizon) must be non-attributive:
/// `ExpiredOrUnknown`, with no row of any kind — not a receipt, not a future
/// marker, not a quota allocation.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_stale_is_expired_or_unknown_and_writes_nothing() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping stale-prepare test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let uuid_ts = clock - Duration::from_secs(366 * 24 * 60 * 60);
    let key = isolated_key(uuid_v7_at(uuid_ts));
    let b = binding("lore.domain.v1.test/Stale");

    let tx = client.transaction().await.expect("begin tx");
    let result = prepare(&tx, &key, &b, None)
        .await
        .expect("prepare must not error");
    tx.commit().await.expect("commit");

    assert_eq!(result, PrepareResult::ExpiredOrUnknown);
    assert_eq!(receipt_row_count(&client, &key).await, 0, "no receipt row");
    assert_eq!(
        future_rejection_row_count(&client, &key).await,
        0,
        "no future-rejection marker"
    );
    assert!(
        quota_counts(&client, &key).await.is_none(),
        "no quota row allocated for a stale, non-attributive attempt"
    );
}

/// An admissible UUID must prepare and persist a `PREPARED` row carrying the
/// returned consume token and expiry.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_admissible_persists_a_prepared_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping admissible-prepare test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/Admissible");

    let tx = client.transaction().await.expect("begin tx");
    let result = prepare(&tx, &key, &b, None)
        .await
        .expect("prepare must not error");
    tx.commit().await.expect("commit");

    let PrepareResult::Prepared { token, .. } = result else {
        panic!("expected Prepared, got {result:?}");
    };
    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(persisted.state, 0, "state must be PREPARED");
    assert_eq!(persisted.consume_token.as_deref(), Some(token.as_slice()));
    assert!(persisted.outcome.is_none());
}

/// A receipt-bearing future UUID must commit a real, attributable `NOT_APPLIED`
/// receipt with no domain mutation — a real row, not a compact marker.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_receipt_bearing_future_commits_a_real_not_applied_receipt() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping receipt-bearing-future test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let uuid_ts = clock + Duration::from_secs(6 * 60);
    let key = isolated_key(uuid_v7_at(uuid_ts));
    let b = binding("lore.domain.v1.test/ReceiptBearingFuture");

    let tx = client.transaction().await.expect("begin tx");
    let result = prepare(&tx, &key, &b, None)
        .await
        .expect("prepare must not error");
    tx.commit().await.expect("commit");

    assert_eq!(
        result,
        PrepareResult::Committed(DomainOutcome::NotApplied {
            reason_version: 1,
            reason: UUID_TIME_OUT_OF_RANGE_V1.to_string(),
        })
    );
    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(persisted.state, 1, "state must be COMMITTED");
    assert_eq!(persisted.outcome, Some(1), "outcome must be NOT_APPLIED");
    assert_eq!(
        persisted.not_applied_reason.as_deref(),
        Some(UUID_TIME_OUT_OF_RANGE_V1)
    );
    assert_eq!(
        future_rejection_row_count(&client, &key).await,
        0,
        "a receipt-bearing future rejection is an ordinary receipt, not a compact marker"
    );
}

/// A beyond-horizon UUID must create a compact future-rejection marker and
/// bump its namespace quota, with no ordinary receipt row at all.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_beyond_horizon_creates_a_compact_marker_and_no_ordinary_receipt() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping beyond-horizon test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let uuid_ts = clock + Duration::from_secs(25 * 60 * 60);
    let key = isolated_key(uuid_v7_at(uuid_ts));
    let b = binding("lore.domain.v1.test/BeyondHorizon");

    let tx = client.transaction().await.expect("begin tx");
    let result = prepare(&tx, &key, &b, None)
        .await
        .expect("prepare must not error");
    tx.commit().await.expect("commit");

    assert_eq!(
        result,
        PrepareResult::Committed(DomainOutcome::NotApplied {
            reason_version: 1,
            reason: UUID_FUTURE_HORIZON_EXCEEDED_V1.to_string(),
        })
    );
    assert_eq!(
        receipt_row_count(&client, &key).await,
        0,
        "no ordinary receipt row"
    );
    assert_eq!(
        future_rejection_row_count(&client, &key).await,
        1,
        "exactly one marker"
    );
    let (retained, bucket) = quota_counts(&client, &key)
        .await
        .expect("quota row must exist");
    assert_eq!((retained, bucket), (1, 1), "quota bumped by exactly one");
}

// ─── exact retry and mismatch ────────────────────────────────────────────────

/// An exact retry (identical key and binding) must return the same token as
/// the original `Prepared` result rather than minting a new one.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_exact_retry_returns_the_same_token() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping exact-retry test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/ExactRetry");

    let tx = client.transaction().await.expect("begin first tx");
    let first = prepare(&tx, &key, &b, None).await.expect("first prepare");
    tx.commit().await.expect("commit first");
    let PrepareResult::Prepared {
        token: first_token, ..
    } = first
    else {
        panic!("expected Prepared, got {first:?}");
    };

    let tx = client.transaction().await.expect("begin retry tx");
    let retry = prepare(&tx, &key, &b, None).await.expect("retry prepare");
    tx.commit().await.expect("commit retry");
    let PrepareResult::Prepared {
        token: retry_token, ..
    } = retry
    else {
        panic!("expected Prepared on retry, got {retry:?}");
    };

    assert_eq!(
        first_token, retry_token,
        "an exact retry must return the original token"
    );
}

/// A retry that changes exactly one of method/scope/fingerprint_version/
/// fingerprint must return `Mismatch` and must not touch the stored row.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_retry_with_a_changed_binding_field_returns_mismatch_and_mutates_nothing() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping binding-mismatch test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;

    for field in ["method", "scope", "fingerprint_version", "fingerprint"] {
        let clock = capture_clock(&mut client).await;
        let key = isolated_key(uuid_v7_at(clock));
        let original = binding("lore.domain.v1.test/MismatchOriginal");

        let tx = client.transaction().await.expect("begin original tx");
        let first = prepare(&tx, &key, &original, None)
            .await
            .expect("original prepare");
        tx.commit().await.expect("commit original");
        let PrepareResult::Prepared {
            token: original_token,
            ..
        } = first
        else {
            panic!("expected Prepared, got {first:?}");
        };

        let mut changed = original.clone();
        match field {
            "method" => changed.method.push_str("-changed"),
            "scope" => changed.scope[0] ^= 0xFF,
            "fingerprint_version" => changed.fingerprint_version += 1,
            "fingerprint" => changed.fingerprint[0] ^= 0xFF,
            _ => unreachable!(),
        }

        let tx = client.transaction().await.expect("begin mismatch tx");
        let result = prepare(&tx, &key, &changed, None)
            .await
            .expect("mismatched prepare must not error");
        tx.commit().await.expect("commit mismatch attempt");

        assert_eq!(
            result,
            PrepareResult::Mismatch,
            "changed {field} must return Mismatch"
        );
        let persisted = fetch_receipt(&client, &key).await;
        assert_eq!(persisted.state, 0, "row must remain PREPARED for {field}");
        assert_eq!(
            persisted.consume_token.as_deref(),
            Some(original_token.as_slice()),
            "the original token must be untouched for {field}"
        );
    }
}

// ─── consume ─────────────────────────────────────────────────────────────────

/// Once a mutation transaction consumes and commits a receipt, the row is
/// terminal — a later `consume` with the same token must return `None`
/// because the row is no longer `PREPARED`, not because the token itself
/// stops matching.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn consume_is_single_use_once_the_receipt_is_terminal() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping single-use consume test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/ConsumeSingleUse");

    let tx = client.transaction().await.expect("begin prepare tx");
    let prepared = prepare(&tx, &key, &b, None).await.expect("prepare");
    tx.commit().await.expect("commit prepare");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("expected Prepared, got {prepared:?}");
    };

    let tx = client.transaction().await.expect("begin consume+commit tx");
    let admission = consume(&tx, &key, &b, &token)
        .await
        .expect("consume must not error")
        .expect("first consume must succeed");
    commit_terminal(
        &tx,
        &key,
        &DomainOutcome::Applied,
        None,
        admission.admission_clock,
    )
    .await
    .expect("commit_terminal");
    tx.commit().await.expect("commit the mutation transaction");

    let tx = client.transaction().await.expect("begin second consume tx");
    let second = consume(&tx, &key, &b, &token)
        .await
        .expect("second consume must not error");
    tx.rollback()
        .await
        .expect("roll back read-only second attempt");

    assert!(
        second.is_none(),
        "consume must return None once the receipt is terminal"
    );
}

/// A token is scoped to its exact key and binding: presenting it against a
/// different key, or the right key with a different binding, must return
/// `None` in every case, never distinguishing which part mismatched.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn consume_rejects_a_token_presented_for_the_wrong_key_or_binding() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping wrong-key/binding consume test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key_a = isolated_key(uuid_v7_at(clock));
    let binding_a = binding("lore.domain.v1.test/ConsumeScopeA");

    let tx = client.transaction().await.expect("begin prepare tx");
    let prepared = prepare(&tx, &key_a, &binding_a, None)
        .await
        .expect("prepare");
    tx.commit().await.expect("commit prepare");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("expected Prepared, got {prepared:?}");
    };

    // Wrong key entirely (a key that was never prepared).
    let key_b = isolated_key(uuid_v7_at(clock));
    let tx = client.transaction().await.expect("begin wrong-key tx");
    let result = consume(&tx, &key_b, &binding_a, &token)
        .await
        .expect("consume must not error");
    tx.rollback().await.expect("rollback");
    assert!(
        result.is_none(),
        "a token for key_a must not consume against key_b"
    );

    // Right key, wrong binding.
    let wrong_binding = binding("lore.domain.v1.test/ConsumeScopeWrong");
    let tx = client.transaction().await.expect("begin wrong-binding tx");
    let result = consume(&tx, &key_a, &wrong_binding, &token)
        .await
        .expect("consume must not error");
    tx.rollback().await.expect("rollback");
    assert!(
        result.is_none(),
        "the right key with the wrong binding must not consume"
    );

    // Right key and binding, wrong token.
    let mut wrong_token = token;
    wrong_token[0] ^= 0xFF;
    let tx = client.transaction().await.expect("begin wrong-token tx");
    let result = consume(&tx, &key_a, &binding_a, &wrong_token)
        .await
        .expect("consume must not error");
    tx.rollback().await.expect("rollback");
    assert!(
        result.is_none(),
        "the right key and binding with the wrong token must not consume"
    );

    // Sanity: the original token against the original key/binding still works.
    let tx = client.transaction().await.expect("begin correct tx");
    let result = consume(&tx, &key_a, &binding_a, &token)
        .await
        .expect("consume must not error");
    tx.rollback()
        .await
        .expect("rollback (do not actually terminalize)");
    assert!(
        result.is_some(),
        "the original token/key/binding combination must still consume"
    );
}

/// The canonical intent digest is part of the immutable operation binding.
/// A caller that changes only this field must not read or consume the prepared
/// row, and the failed attempts must leave the original token usable.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn consume_and_receipt_get_reject_changed_canonical_intent() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping canonical-intent binding test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let original = binding("lore.domain.v1.test/CanonicalIntent");

    let tx = client.transaction().await.expect("begin prepare tx");
    let prepared = prepare(&tx, &key, &original, None).await.expect("prepare");
    tx.commit().await.expect("commit prepare");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("expected Prepared, got {prepared:?}");
    };

    let mut changed = original.clone();
    changed.canonical_intent_digest[0] ^= 0xff;

    let tx = client
        .transaction()
        .await
        .expect("begin mismatched lookup tx");
    let lookup = receipt_get(&tx, &key, &changed)
        .await
        .expect("mismatched lookup must not error");
    tx.rollback().await.expect("rollback lookup");
    assert_eq!(
        lookup,
        ReceiptLookup::Mismatch,
        "changed canonical intent must not read the prepared receipt"
    );

    let tx = client
        .transaction()
        .await
        .expect("begin mismatched consume tx");
    let consumed = consume(&tx, &key, &changed, &token)
        .await
        .expect("mismatched consume must not error");
    tx.rollback().await.expect("rollback mismatched consume");
    assert!(
        consumed.is_none(),
        "changed canonical intent must not consume the prepared receipt"
    );

    let tx = client
        .transaction()
        .await
        .expect("begin exact consume control tx");
    let exact = consume(&tx, &key, &original, &token)
        .await
        .expect("exact consume must not error");
    tx.rollback().await.expect("rollback exact consume control");
    assert!(
        exact.is_some(),
        "mismatched lookup and consume must leave the original token usable"
    );
}

// ─── hard-TTL expiry ─────────────────────────────────────────────────────────

/// `prepare` against a row already past its hard TTL must terminalize it to
/// `NOT_APPLIED(PREPARED_HARD_TTL_EXPIRED_V1)` rather than returning stale
/// `Prepared` state or minting a second row.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_expires_a_past_ttl_prepared_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping prepare-driven TTL expiry test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/PrepareExpiry");

    let tx = client.transaction().await.expect("begin prepare tx");
    prepare(&tx, &key, &b, None).await.expect("prepare");
    tx.commit().await.expect("commit prepare");
    age_past_hard_ttl(&client, &key).await;

    let tx = client.transaction().await.expect("begin second-touch tx");
    let result = prepare(&tx, &key, &b, None)
        .await
        .expect("prepare must not error");
    tx.commit().await.expect("commit");

    assert_eq!(
        result,
        PrepareResult::Committed(DomainOutcome::NotApplied {
            reason_version: 1,
            reason: PREPARED_HARD_TTL_EXPIRED_V1.to_string(),
        })
    );
    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(persisted.state, 1, "expiry must terminalize the row");
}

/// `consume` against a row already past its hard TTL must terminalize it the
/// same way and return `None`, never a live admission.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn consume_expires_a_past_ttl_prepared_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping consume-driven TTL expiry test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/ConsumeExpiry");

    let tx = client.transaction().await.expect("begin prepare tx");
    let prepared = prepare(&tx, &key, &b, None).await.expect("prepare");
    tx.commit().await.expect("commit prepare");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("expected Prepared, got {prepared:?}");
    };
    age_past_hard_ttl(&client, &key).await;

    let tx = client.transaction().await.expect("begin consume tx");
    let result = consume(&tx, &key, &b, &token)
        .await
        .expect("consume must not error");
    tx.commit().await.expect("commit");

    assert!(
        result.is_none(),
        "consume of a past-TTL row must return None"
    );
    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(
        persisted.state, 1,
        "consume-driven expiry must terminalize the row"
    );
    assert_eq!(
        persisted.not_applied_reason.as_deref(),
        Some(PREPARED_HARD_TTL_EXPIRED_V1)
    );
}

/// `receipt_get`'s own doc comment for [`PREPARED_HARD_TTL_EXPIRED_V1`]-style
/// expiry (`expire_prepared`'s comment: "Every prepare, get, and consume
/// touch performs this same transition") claims lookup also drives expiry.
/// This pins the currently-observed behavior so a fix or a contract
/// correction shows up as a diff here rather than silently.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn receipt_get_of_a_past_ttl_prepared_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping receipt_get TTL-expiry test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/GetExpiry");

    let tx = client.transaction().await.expect("begin prepare tx");
    prepare(&tx, &key, &b, None).await.expect("prepare");
    tx.commit().await.expect("commit prepare");
    age_past_hard_ttl(&client, &key).await;

    let tx = client.transaction().await.expect("begin get tx");
    let looked_up = receipt_get(&tx, &key, &b)
        .await
        .expect("receipt_get must not error");
    tx.commit().await.expect("commit");

    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(
        (looked_up, persisted.state),
        (
            ReceiptLookup::Committed {
                outcome: DomainOutcome::NotApplied {
                    reason_version: 1,
                    reason: PREPARED_HARD_TTL_EXPIRED_V1.to_string(),
                },
                from_future_marker: false,
            },
            1
        ),
        "receipt_get is documented (expire_prepared's comment) to drive hard-TTL expiry \
         the same way prepare/consume do; if this assertion fails, receipt_get returned \
         Prepared{{..}} over the still-PREPARED row instead — receipt_get's own function body \
         never checks clock against hard_expires_at for the PREPARED branch, unlike prepare \
         and consume, so this is expected to currently FAIL as a genuine implementation gap, \
         not a test defect. Report exact vs actual to the main session rather than loosening \
         this assertion."
    );
}

// ─── terminal immutability ───────────────────────────────────────────────────

/// A terminal row is immutable: a second `commit_terminal` against an
/// already-committed row must error rather than silently overwrite it.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn commit_terminal_against_an_already_committed_row_errors() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping terminal-immutability test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/TerminalImmutable");

    let tx = client.transaction().await.expect("begin prepare tx");
    prepare(&tx, &key, &b, None).await.expect("prepare");
    let admission_clock_value = admission_clock(&tx).await.expect("read clock");
    commit_terminal(
        &tx,
        &key,
        &DomainOutcome::Applied,
        None,
        admission_clock_value,
    )
    .await
    .expect("first commit_terminal must succeed");
    tx.commit().await.expect("commit first terminalization");

    let tx = client
        .transaction()
        .await
        .expect("begin second commit_terminal tx");
    let second_clock = admission_clock(&tx).await.expect("read clock");
    let err = commit_terminal(
        &tx,
        &key,
        &DomainOutcome::NotApplied {
            reason_version: 1,
            reason: "SHOULD_NEVER_APPLY".to_string(),
        },
        None,
        second_clock,
    )
    .await
    .expect_err("a second commit_terminal against an already-terminal row must error");
    tx.rollback()
        .await
        .expect("rollback the rejected second attempt");

    assert!(
        matches!(&err, DomainError::Internal(msg) if msg.contains("must never be rewritten")),
        "expected an Internal error naming immutability, got {err:?}"
    );
    let persisted = fetch_receipt(&client, &key).await;
    assert_eq!(
        persisted.outcome,
        Some(0),
        "the original APPLIED outcome must be untouched"
    );
}

// ─── receipt_get never returns the token ────────────────────────────────────

/// `ReceiptLookup::Prepared` structurally carries only `prepared_at` and
/// `hard_expires_at` — there is no field for the token, so a caller cannot
/// obtain it through this path even by accident. Destructuring only the
/// documented fields here is itself part of the proof: this would not
/// compile if the variant carried a third field.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn receipt_get_of_a_prepared_row_carries_no_token() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping receipt_get token-shape test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/GetNoToken");

    let tx = client.transaction().await.expect("begin prepare tx");
    prepare(&tx, &key, &b, None).await.expect("prepare");
    tx.commit().await.expect("commit prepare");

    let tx = client.transaction().await.expect("begin get tx");
    let looked_up = receipt_get(&tx, &key, &b)
        .await
        .expect("receipt_get must not error");
    tx.commit().await.expect("commit");

    let ReceiptLookup::Prepared {
        prepared_at: _,
        hard_expires_at: _,
    } = looked_up
    else {
        panic!("expected Prepared, got {looked_up:?}");
    };
}

// ─── future-marker binding scoping ───────────────────────────────────────────

/// A future-rejection marker created under one binding must not answer a
/// lookup made with a *different* binding — that would resolve one operation
/// with another operation's stored result, which CR-029 forbids for every
/// other receipt path. `prepare` and `receipt_get` both consult
/// `load_future_marker(tx, key)` for a hit under the same `operation_id`
/// (shared with any other caller who reuses this UUID with different
/// content), so this must fail closed exactly like the ordinary-receipt
/// mismatch path does.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_of_a_future_marker_under_a_different_binding_must_return_mismatch() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping future-marker binding-scope test (prepare)");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let uuid_ts = clock + Duration::from_secs(25 * 60 * 60);
    let key = isolated_key(uuid_v7_at(uuid_ts));
    let binding_a = binding("lore.domain.v1.test/FutureMarkerA");

    let tx = client.transaction().await.expect("begin first tx");
    let first = prepare(&tx, &key, &binding_a, None)
        .await
        .expect("first prepare");
    tx.commit().await.expect("commit first");
    assert!(matches!(
        first,
        PrepareResult::Committed(DomainOutcome::NotApplied { .. })
    ));

    let binding_b = binding("lore.domain.v1.test/FutureMarkerB");
    let tx = client.transaction().await.expect("begin second tx");
    let second = prepare(&tx, &key, &binding_b, None)
        .await
        .expect("second prepare");
    tx.commit().await.expect("commit second");

    assert_eq!(
        second,
        PrepareResult::Mismatch,
        "a future marker under binding_a must not answer a prepare under binding_b with \
         binding_a's outcome — that would resolve one operation with another operation's \
         stored result. `load_future_marker` compares the stored method/scope/\
         fingerprint_version/fingerprint against the caller's binding and returns \
         FutureMarker::Mismatch on any difference before FutureMarker::Exact can apply."
    );
}

/// Same invariant, `receipt_get` side: a lookup under a different binding
/// must not resolve to the marker's outcome either.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn receipt_get_of_a_future_marker_under_a_different_binding_must_return_mismatch() {
    let Some(url) = pg_url() else {
        eprintln!(
            "LORE_TEST_PG_URL unset; skipping future-marker binding-scope test (receipt_get)"
        );
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let uuid_ts = clock + Duration::from_secs(25 * 60 * 60);
    let key = isolated_key(uuid_v7_at(uuid_ts));
    let binding_a = binding("lore.domain.v1.test/FutureMarkerGetA");

    let tx = client.transaction().await.expect("begin prepare tx");
    prepare(&tx, &key, &binding_a, None).await.expect("prepare");
    tx.commit().await.expect("commit prepare");

    let binding_b = binding("lore.domain.v1.test/FutureMarkerGetB");
    let tx = client.transaction().await.expect("begin get tx");
    let looked_up = receipt_get(&tx, &key, &binding_b)
        .await
        .expect("receipt_get must not error");
    tx.commit().await.expect("commit");

    assert_eq!(
        looked_up,
        ReceiptLookup::Mismatch,
        "receipt_get must not resolve a future marker stored under binding_a to a lookup \
         made with binding_b; see the companion prepare-side test for the shared \
         `load_future_marker` binding check this exercises"
    );
}

// ─── future-rejection quota ──────────────────────────────────────────────────

/// At the 1,024-retained-marker limit, prepare must return `CapacityExhausted`
/// and must not write a marker for the new operation or bump the quota
/// further.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn beyond_horizon_prepare_at_retained_quota_limit_is_capacity_exhausted() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping retained-quota-limit test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let tenant_scope: Vec<u8> = rand::random::<[u8; 8]>().to_vec();
    let issuer_key = fresh_key(
        tenant_scope.clone(),
        uuid_v7_at(clock + Duration::from_secs(25 * 60 * 60)),
    );
    let b = binding("lore.domain.v1.test/QuotaRetainedSeed");

    // Seed the quota row for real via one successful marker admission.
    let tx = client.transaction().await.expect("begin seed tx");
    prepare(&tx, &issuer_key, &b, None)
        .await
        .expect("seed prepare");
    tx.commit().await.expect("commit seed");

    client
        .execute(
            "UPDATE lore_domain_operation_future_reject_quotas
                SET retained_count = 1024
              WHERE verified_issuer = $1 AND authenticated_subject = $2 AND tenant_scope_key = $3",
            &[
                &issuer_key.verified_issuer,
                &issuer_key.authenticated_subject,
                &tenant_scope,
            ],
        )
        .await
        .expect("force retained_count to the limit");

    let clock2 = capture_clock(&mut client).await;
    let new_operation_key = same_namespace_key(
        &issuer_key,
        uuid_v7_at(clock2 + Duration::from_secs(25 * 60 * 60)),
    );
    let tx = client.transaction().await.expect("begin exhausted tx");
    let result = prepare(
        &tx,
        &new_operation_key,
        &binding("lore.domain.v1.test/QuotaRetainedNew"),
        None,
    )
    .await
    .expect("prepare must not error");
    tx.commit().await.expect("commit");

    assert_eq!(result, PrepareResult::CapacityExhausted);
    assert_eq!(
        future_rejection_row_count(&client, &new_operation_key).await,
        0,
        "no marker written for the rejected operation"
    );
    let (retained, _bucket) = quota_counts(&client, &new_operation_key)
        .await
        .expect("quota row still exists");
    assert_eq!(
        retained, 1024,
        "retained_count must not have been incremented past the limit"
    );
}

/// At the 64-per-hour limit, the same admission backpressure applies.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn beyond_horizon_prepare_at_hourly_quota_limit_is_capacity_exhausted() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping hourly-quota-limit test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let tenant_scope: Vec<u8> = rand::random::<[u8; 8]>().to_vec();
    let seed_key = fresh_key(
        tenant_scope.clone(),
        uuid_v7_at(clock + Duration::from_secs(25 * 60 * 60)),
    );

    let tx = client.transaction().await.expect("begin seed tx");
    prepare(
        &tx,
        &seed_key,
        &binding("lore.domain.v1.test/QuotaHourlySeed"),
        None,
    )
    .await
    .expect("seed prepare");
    tx.commit().await.expect("commit seed");

    client
        .execute(
            "UPDATE lore_domain_operation_future_reject_quotas
                SET bucket_count = 64
              WHERE verified_issuer = $1 AND authenticated_subject = $2 AND tenant_scope_key = $3",
            &[
                &seed_key.verified_issuer,
                &seed_key.authenticated_subject,
                &tenant_scope,
            ],
        )
        .await
        .expect("force bucket_count to the limit");

    let clock2 = capture_clock(&mut client).await;
    let new_operation_key = same_namespace_key(
        &seed_key,
        uuid_v7_at(clock2 + Duration::from_secs(25 * 60 * 60)),
    );
    let tx = client.transaction().await.expect("begin exhausted tx");
    let result = prepare(
        &tx,
        &new_operation_key,
        &binding("lore.domain.v1.test/QuotaHourlyNew"),
        None,
    )
    .await
    .expect("prepare must not error");
    tx.commit().await.expect("commit");

    assert_eq!(result, PrepareResult::CapacityExhausted);
    assert_eq!(
        future_rejection_row_count(&client, &new_operation_key).await,
        0
    );
    let (_retained, bucket) = quota_counts(&client, &new_operation_key)
        .await
        .expect("quota row still exists");
    assert_eq!(
        bucket, 64,
        "bucket_count must not have been incremented past the hourly limit"
    );
}

/// `AuthorizationWitness` is accepted end to end by `prepare`: passing one
/// must not error and must not change the observable `Prepared` outcome. The
/// witness fields themselves are internal/server-only evidence, not part of
/// this public contract, so this is a smoke test of the plumbing rather than
/// a field-by-field pin.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn prepare_accepts_an_authorization_witness() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping authorization-witness test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let clock = capture_clock(&mut client).await;
    let key = isolated_key(uuid_v7_at(clock));
    let b = binding("lore.domain.v1.test/WithWitness");
    let witness = AuthorizationWitness {
        authorization_id: rand::random::<[u8; 16]>().to_vec(),
        authorization_revision: 1,
        verification_nonce: rand::random::<[u8; 32]>().to_vec(),
        bound_fields_digest: rand::random::<[u8; 32]>().to_vec(),
        consumed_ticket_sha256: rand::random::<[u8; 32]>().to_vec(),
    };

    let tx = client.transaction().await.expect("begin tx");
    let result = prepare(&tx, &key, &b, Some(&witness))
        .await
        .expect("prepare with a witness must not error");
    tx.commit().await.expect("commit");

    assert!(matches!(result, PrepareResult::Prepared { .. }));
}

/// Two concurrent `prepare` calls against the identical beyond-horizon key
/// must not double-count the future-reject quota: `insert_future_marker`'s
/// `INSERT ... ON CONFLICT DO NOTHING` on the marker row means the loser's
/// insert affects zero rows, and the increment must be gated on that rather
/// than running unconditionally after every attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn concurrent_duplicate_future_marker_prepares_do_not_double_count_the_quota() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping concurrent-duplicate-marker test");
        return;
    };
    connect_domain_store(&url).await;
    let clock = capture_clock(&mut pg_client(&url).await).await;
    let uuid_ts = clock + Duration::from_secs(25 * 60 * 60);
    let key = isolated_key(uuid_v7_at(uuid_ts));
    let b = binding("lore.domain.v1.test/ConcurrentDuplicateMarker");

    let mut client_a = pg_client(&url).await;
    let mut client_b = pg_client(&url).await;
    let key_a = key.clone();
    let key_b = key.clone();
    let binding_a = b.clone();
    let binding_b = b.clone();

    let (result_a, result_b) = tokio::join!(
        async {
            let tx = client_a.transaction().await.expect("begin tx a");
            let r = prepare(&tx, &key_a, &binding_a, None)
                .await
                .expect("prepare a");
            tx.commit().await.expect("commit a");
            r
        },
        async {
            let tx = client_b.transaction().await.expect("begin tx b");
            let r = prepare(&tx, &key_b, &binding_b, None)
                .await
                .expect("prepare b");
            tx.commit().await.expect("commit b");
            r
        },
    );

    let expected = PrepareResult::Committed(DomainOutcome::NotApplied {
        reason_version: 1,
        reason: UUID_FUTURE_HORIZON_EXCEEDED_V1.to_string(),
    });
    assert_eq!(
        result_a, expected,
        "both concurrent callers see the same decisive outcome"
    );
    assert_eq!(result_b, expected);

    let client = pg_client(&url).await;
    assert_eq!(
        future_rejection_row_count(&client, &key).await,
        1,
        "exactly one marker row despite two concurrent attempts"
    );
    let (retained, bucket) = quota_counts(&client, &key)
        .await
        .expect("quota row must exist");
    assert_eq!(
        (retained, bucket),
        (1, 1),
        "the quota must be incremented exactly once, not once per attempt"
    );
}
