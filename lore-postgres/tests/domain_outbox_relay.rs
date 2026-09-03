// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-119 Step A: relay claim, publication-CAS, dead-letter, and
//! epoch-reset-requeue proof for `lore-postgres/src/domain/outbox/relay.rs`
//! (CR-032's `SCHEMA-119` extension).
//!
//! Real Postgres only, `#[ignore]`. This run gets ONE shared database (not one
//! per case the way the fragment-lifecycle live runner does), so every case
//! acquires its own [`case_namespace::CaseNamespace`] schema -- load-bearing
//! isolation here, not decorative, since `claim_batch`/`backlog`/
//! `admission_check`/`requeue_unsafe_for_epoch_reset` all scan
//! `lore_outbox_events` table-wide with no `cell_id` filter.
//!
//! Two connection kinds are needed, matching `relay.rs`'s own mixed surface:
//! `claim_batch`/`dead_letter`/`requeue_dead_letter`/
//! `requeue_unsafe_for_epoch_reset` take `&mut deadpool_postgres::Client`
//! (they open their own internal transaction); `record_broker_accepted`/
//! `release_for_retry`/`mark_obsolete`/`lookup_by_idempotency_key`/`backlog`/
//! `admission_check` take `&impl tokio_postgres::GenericClient`, satisfied
//! directly by a raw `tokio_postgres::Client` (a `deadpool_postgres::Client`
//! does not implement that trait -- it carries its own separate copy -- so
//! this file uses the same raw-`NoTls` pattern `domain_outbox.rs` already
//! established rather than fighting deref coercion through the pool wrapper).

#[path = "common/case_namespace.rs"]
mod case_namespace;

use std::time::Duration;
use std::time::SystemTime;

use case_namespace::CaseNamespace;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::outbox::OutboxEvent;
use lore_postgres::domain::outbox::append;
use lore_postgres::domain::outbox::relay::BrokerAcceptanceRecord;
use lore_postgres::domain::outbox::relay::CasOutcome;
use lore_postgres::domain::outbox::relay::DeadLetterOutcome;
use lore_postgres::domain::outbox::relay::MAX_CLAIM_BATCH;
use lore_postgres::domain::outbox::relay::MAX_EPOCH_RESET_BATCH;
use lore_postgres::domain::outbox::relay::claim_batch;
use lore_postgres::domain::outbox::relay::dead_letter;
use lore_postgres::domain::outbox::relay::lookup_by_idempotency_key;
use lore_postgres::domain::outbox::relay::mark_obsolete;
use lore_postgres::domain::outbox::relay::record_broker_accepted;
use lore_postgres::domain::outbox::relay::release_for_retry;
use lore_postgres::domain::outbox::relay::renew_claim;
use lore_postgres::domain::outbox::relay::requeue_dead_letter;
use lore_postgres::domain::outbox::relay::requeue_unsafe_for_epoch_reset;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use tokio_postgres::Client;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn connect_domain_store(url: &str) -> PostgresDomainStore {
    PostgresDomainStore::connect(url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store")
}

/// A raw `NoTls` connection, for the functions bound on `tokio_postgres::GenericClient`.
async fn pg_client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect for direct test access");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

/// A `deadpool_postgres::Client`, for the functions that open their own
/// internal transaction (`claim_batch`, `dead_letter`, `requeue_dead_letter`,
/// `requeue_unsafe_for_epoch_reset`).
async fn deadpool_client(url: &str) -> deadpool_postgres::Client {
    let pool = build_pool(url, 4, &TlsConfig::default()).expect("build deadpool pool");
    pool.get().await.expect("checkout deadpool connection")
}

fn rand_repository_id() -> [u8; 16] {
    rand::random()
}

fn rand_cell_id() -> String {
    format!("cell-{:016x}", rand::random::<u64>())
}

/// Append one pending row via the real production `append()` path so every
/// case here exercises the actual write path, not a hand-poked row.
async fn append_pending(
    client: &mut Client,
    cell_id: &str,
    repository_id: &[u8],
    event_kind: &str,
    aggregate_kind: &str,
    aggregate_id: &[u8],
    ordinal: u64,
) -> Uuid {
    let version = AggregateVersion::ordinal_only(ordinal).encode();
    let tx = client.transaction().await.expect("begin append tx");
    let event = OutboxEvent {
        cell_id,
        repository_id,
        repository_generation: 1,
        event_kind,
        aggregate_kind,
        aggregate_id,
        aggregate_version: &version,
        payload_schema_version: 1,
        payload: b"{}",
    };
    let appended = append(&tx, &event).await.expect("append pending event");
    tx.commit().await.expect("commit append");
    appended.event_id
}

async fn append_n_pending(
    client: &mut Client,
    cell_id: &str,
    repository_id: &[u8],
    n: u64,
) -> Vec<Uuid> {
    let mut ids = Vec::with_capacity(n as usize);
    for i in 0..n {
        let aggregate_id: [u8; 16] = rand::random();
        ids.push(
            append_pending(
                client,
                cell_id,
                repository_id,
                "branch.pushed",
                "branch",
                &aggregate_id,
                i + 1,
            )
            .await,
        );
    }
    ids
}

/// Read the relay-relevant columns of one row by `event_id`, or `None` if it
/// is not (or no longer) in `lore_outbox_events`.
struct RowSnapshot {
    state: String,
    available_at: SystemTime,
    claim_generation: i64,
    claim_owner: Option<String>,
    claim_expires_at: Option<SystemTime>,
    attempt_count: i32,
    last_error_class: Option<String>,
    stream_identity: Option<String>,
    stream_epoch: Option<i64>,
    broker_sequence: Option<i64>,
    gateway_response_id: Option<String>,
    publisher_contract_version: Option<i32>,
    broker_accepted_at: Option<SystemTime>,
    idempotency_key: Vec<u8>,
}

async fn snapshot(client: &Client, event_id: Uuid) -> Option<RowSnapshot> {
    let row = client
        .query_opt(
            "SELECT state, available_at, claim_generation, claim_owner, claim_expires_at, \
                    attempt_count, last_error_class, stream_identity, stream_epoch, \
                    broker_sequence, gateway_response_id, publisher_contract_version, \
                    broker_accepted_at, idempotency_key \
             FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("snapshot query");
    row.map(|r| RowSnapshot {
        state: r.get("state"),
        available_at: r.get("available_at"),
        claim_generation: r.get("claim_generation"),
        claim_owner: r.get("claim_owner"),
        claim_expires_at: r.get("claim_expires_at"),
        attempt_count: r.get("attempt_count"),
        last_error_class: r.get("last_error_class"),
        stream_identity: r.get("stream_identity"),
        stream_epoch: r.get("stream_epoch"),
        broker_sequence: r.get("broker_sequence"),
        gateway_response_id: r.get("gateway_response_id"),
        publisher_contract_version: r.get("publisher_contract_version"),
        broker_accepted_at: r.get("broker_accepted_at"),
        idempotency_key: r.get("idempotency_key"),
    })
}

fn assert_snapshots_equal(before: &RowSnapshot, after: &RowSnapshot, context: &str) {
    assert_eq!(before.state, after.state, "{context}: state changed");
    assert_eq!(
        before.available_at, after.available_at,
        "{context}: available_at changed"
    );
    assert_eq!(
        before.claim_generation, after.claim_generation,
        "{context}: claim_generation changed"
    );
    assert_eq!(
        before.claim_owner, after.claim_owner,
        "{context}: claim_owner changed"
    );
    assert_eq!(
        before.claim_expires_at, after.claim_expires_at,
        "{context}: claim_expires_at changed"
    );
    assert_eq!(
        before.attempt_count, after.attempt_count,
        "{context}: attempt_count changed"
    );
    assert_eq!(
        before.last_error_class, after.last_error_class,
        "{context}: last_error_class changed"
    );
    assert_eq!(
        before.stream_identity, after.stream_identity,
        "{context}: stream_identity changed"
    );
    assert_eq!(
        before.stream_epoch, after.stream_epoch,
        "{context}: stream_epoch changed"
    );
    assert_eq!(
        before.broker_sequence, after.broker_sequence,
        "{context}: broker_sequence changed"
    );
    assert_eq!(
        before.gateway_response_id, after.gateway_response_id,
        "{context}: gateway_response_id changed"
    );
    assert_eq!(
        before.publisher_contract_version, after.publisher_contract_version,
        "{context}: publisher_contract_version changed"
    );
    assert_eq!(
        before.broker_accepted_at, after.broker_accepted_at,
        "{context}: broker_accepted_at changed"
    );
    assert_eq!(
        before.idempotency_key, after.idempotency_key,
        "{context}: idempotency_key changed"
    );
}

fn sample_acceptance(
    stream_identity: &str,
    stream_epoch: i64,
    broker_sequence: i64,
) -> BrokerAcceptanceRecord {
    BrokerAcceptanceRecord {
        stream_identity: stream_identity.to_owned(),
        stream_epoch,
        broker_sequence,
        gateway_response_id: format!("resp-{:016x}", rand::random::<u64>()),
        publisher_contract_version: 1,
    }
}

// ---------------------------------------------------------------------------
// claim_batch
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn claim_batch_respects_the_limit_and_orders_by_available_at_then_event_id() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "claim-limit-order").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let ids = append_n_pending(&mut raw, &cell_id, &repository_id, 5).await;

    let claimed = claim_batch(&mut pool_client, "worker-limit", 3, Duration::from_secs(30))
        .await
        .expect("claim batch");
    assert_eq!(
        claimed.len(),
        3,
        "must claim exactly `limit` rows when more are eligible"
    );
    let claimed_ids: Vec<Uuid> = claimed.iter().map(|c| c.event.event_id).collect();
    // Every claimed id must be one of the five inserted, and the append order
    // (ascending ordinal / insertion order) is also ascending `available_at`
    // (both stamped by `clock_timestamp()` in insertion order), so the first
    // three appended must be the three claimed.
    assert_eq!(claimed_ids, ids[..3].to_vec());

    let claimed_again = claim_batch(
        &mut pool_client,
        "worker-limit",
        100,
        Duration::from_secs(30),
    )
    .await
    .expect("claim remaining");
    assert_eq!(
        claimed_again.len(),
        2,
        "the two unclaimed rows remain eligible"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn claim_batch_rejects_a_limit_over_the_cr_032_bound() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "claim-limit-bound").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let err = claim_batch(
        &mut pool_client,
        "worker-a",
        MAX_CLAIM_BATCH + 1,
        Duration::from_secs(30),
    )
    .await
    .expect_err("a limit above 100 must be rejected");
    assert!(matches!(err, DomainError::InvalidInput(_)));

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn claim_stamps_lease_and_increasing_generation_and_fences_a_second_claimant_until_expiry() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "claim-fence-expiry").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;

    let first = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("first claim");
    assert_eq!(first.len(), 1);
    assert_eq!(
        first[0].claim_generation, 1,
        "the first claim must stamp generation 1"
    );

    // Unexpired claim: a second claimer over the whole eligible set must not
    // receive this row.
    let second = claim_batch(&mut pool_client, "worker-b", 10, Duration::from_secs(30))
        .await
        .expect("second claim attempt while unexpired");
    assert!(
        second.is_empty(),
        "an unexpired claim must not be handed to a second claimant"
    );

    // Force-expire the lease and reclaim.
    raw.execute(
        "UPDATE lore_outbox_events SET claim_expires_at = clock_timestamp() - interval '1 second' \
         WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("force-expire the lease");

    let reclaimed = claim_batch(&mut pool_client, "worker-b", 10, Duration::from_secs(30))
        .await
        .expect("reclaim after expiry");
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].event.event_id, event_id);
    assert_eq!(
        reclaimed[0].claim_generation, 2,
        "a reclaim must strictly increase the claim generation"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn two_concurrent_claimers_over_two_hundred_rows_never_receive_the_same_event_id() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    // Deterministic barrier: `tokio::join!` genuinely interleaves two
    // I/O-bound futures on plain `#[tokio::test]` (no `tokio::spawn`
    // required), so no sleep is used to force interleaving. Repeated 5 times
    // with a fresh 200-row batch each time for confidence; each repetition
    // gets its own namespace so a batch from one repetition cannot leak into
    // another's claim scan.
    const REPETITIONS: usize = 5;
    const ROW_COUNT: u64 = 200;
    const HALF: usize = 100;

    for repetition in 0..REPETITIONS {
        let namespace =
            CaseNamespace::acquire(&base_url, &format!("claim-race-{repetition}")).await;
        let url = namespace.pg_url().to_owned();
        connect_domain_store(&url).await;
        let mut raw = pg_client(&url).await;
        let repository_id = rand_repository_id();
        let cell_id = rand_cell_id();
        let ids = append_n_pending(&mut raw, &cell_id, &repository_id, ROW_COUNT).await;

        let mut client_a = deadpool_client(&url).await;
        let mut client_b = deadpool_client(&url).await;
        let (claimed_a, claimed_b) = tokio::join!(
            claim_batch(&mut client_a, "racer-a", HALF, Duration::from_secs(30)),
            claim_batch(&mut client_b, "racer-b", HALF, Duration::from_secs(30)),
        );
        let claimed_a = claimed_a.expect("racer-a claim");
        let claimed_b = claimed_b.expect("racer-b claim");

        let mut ids_a: Vec<Uuid> = claimed_a.iter().map(|c| c.event.event_id).collect();
        let mut ids_b: Vec<Uuid> = claimed_b.iter().map(|c| c.event.event_id).collect();
        assert_eq!(
            ids_a.len() + ids_b.len(),
            ROW_COUNT as usize,
            "repetition {repetition}: two claimers of {HALF} each over {ROW_COUNT} pending rows \
             must together claim every row exactly once"
        );
        ids_a.sort();
        ids_b.sort();
        let overlap: Vec<&Uuid> = ids_a.iter().filter(|id| ids_b.contains(id)).collect();
        assert!(
            overlap.is_empty(),
            "repetition {repetition}: claimers must never receive the same event_id, overlap={overlap:?}"
        );
        let mut all_claimed = ids_a.clone();
        all_claimed.extend(ids_b.clone());
        all_claimed.sort();
        let mut expected = ids.clone();
        expected.sort();
        assert_eq!(
            all_claimed, expected,
            "repetition {repetition}: the union of both claims must cover every inserted row"
        );

        namespace.release().await;
    }
}

// ---------------------------------------------------------------------------
// record_broker_accepted (publication CAS)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn record_broker_accepted_applies_with_the_current_generation_and_sets_publication_fields() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "accept-applies").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;
    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    let generation = claimed[0].claim_generation;

    let acceptance = sample_acceptance("DURABLE-cell-a", 8, 42);
    let outcome = record_broker_accepted(&raw, event_id, generation, &acceptance)
        .await
        .expect("record broker acceptance");
    assert_eq!(outcome, CasOutcome::Applied);

    let row = snapshot(&raw, event_id)
        .await
        .expect("row must still exist");
    assert_eq!(row.state, "broker_accepted");
    assert_eq!(row.stream_identity.as_deref(), Some("DURABLE-cell-a"));
    assert_eq!(row.stream_epoch, Some(8));
    assert_eq!(row.broker_sequence, Some(42));
    assert_eq!(
        row.gateway_response_id,
        Some(acceptance.gateway_response_id.clone())
    );
    assert_eq!(row.publisher_contract_version, Some(1));
    assert!(row.broker_accepted_at.is_some());
    assert!(
        row.claim_owner.is_none() && row.claim_expires_at.is_none(),
        "the lease must be cleared once the row is no longer pending"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn record_broker_accepted_with_a_stale_generation_returns_stale_claim_and_leaves_the_row_unchanged()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "accept-stale").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;
    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    let current_generation = claimed[0].claim_generation;
    let stale_generation = current_generation - 1;

    let before = snapshot(&raw, event_id).await.expect("row before");
    let acceptance = sample_acceptance("DURABLE-cell-a", 8, 42);
    let outcome = record_broker_accepted(&raw, event_id, stale_generation, &acceptance)
        .await
        .expect("record with stale generation");
    assert_eq!(
        outcome,
        CasOutcome::StaleClaim {
            current_claim_generation: current_generation
        }
    );
    let after = snapshot(&raw, event_id).await.expect("row after");
    assert_snapshots_equal(
        &before,
        &after,
        "record_broker_accepted with a stale generation",
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn record_broker_accepted_on_an_already_accepted_row_is_already_accepted_and_publication_fields_are_unchanged()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "accept-dup").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;
    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    let generation = claimed[0].claim_generation;

    let first_acceptance = sample_acceptance("DURABLE-cell-a", 8, 42);
    assert_eq!(
        record_broker_accepted(&raw, event_id, generation, &first_acceptance)
            .await
            .expect("first acceptance"),
        CasOutcome::Applied
    );

    // A duplicate acknowledgement retry, same claim generation (the row is
    // already past `pending`), with DIFFERENT publication details -- this
    // must not overwrite the original.
    let duplicate_acceptance = sample_acceptance("DURABLE-cell-b", 9, 999);
    let outcome = record_broker_accepted(&raw, event_id, generation, &duplicate_acceptance)
        .await
        .expect("duplicate acceptance");
    assert_eq!(outcome, CasOutcome::AlreadyAccepted);

    let row = snapshot(&raw, event_id).await.expect("row after duplicate");
    assert_eq!(
        row.stream_identity.as_deref(),
        Some("DURABLE-cell-a"),
        "the ORIGINAL acceptance's publication fields must survive a duplicate ack"
    );
    assert_eq!(row.stream_epoch, Some(8));
    assert_eq!(row.broker_sequence, Some(42));

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// release_for_retry (CAS)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn release_for_retry_increments_attempt_count_sets_available_at_and_clears_the_claim() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "release-retry").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;
    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    assert_eq!(claimed[0].attempt_count, 0);
    let generation = claimed[0].claim_generation;

    let next_attempt_at = SystemTime::now() + Duration::from_secs(5);
    let outcome = release_for_retry(
        &raw,
        event_id,
        generation,
        "TRANSPORT_TIMEOUT_V1",
        next_attempt_at,
    )
    .await
    .expect("release for retry");
    assert_eq!(outcome, CasOutcome::Applied);

    let row = snapshot(&raw, event_id).await.expect("row after release");
    assert_eq!(row.state, "pending");
    assert_eq!(row.attempt_count, 1);
    assert_eq!(
        row.last_error_class.as_deref(),
        Some("TRANSPORT_TIMEOUT_V1")
    );
    assert!(row.claim_owner.is_none() && row.claim_expires_at.is_none());
    let delta = row
        .available_at
        .duration_since(next_attempt_at)
        .or_else(|e| Ok::<_, std::time::SystemTimeError>(e.duration()))
        .expect("comparable durations");
    assert!(
        delta < Duration::from_millis(500),
        "available_at must be set to the requested next_attempt_at, delta={delta:?}"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn release_for_retry_with_a_stale_generation_is_a_no_op() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "release-stale").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;
    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    let stale_generation = claimed[0].claim_generation - 1;

    let before = snapshot(&raw, event_id).await.expect("before");
    let outcome = release_for_retry(
        &raw,
        event_id,
        stale_generation,
        "TRANSPORT_TIMEOUT_V1",
        SystemTime::now(),
    )
    .await
    .expect("release with stale generation");
    assert!(matches!(outcome, CasOutcome::StaleClaim { .. }));
    let after = snapshot(&raw, event_id).await.expect("after");
    assert_snapshots_equal(&before, &after, "release_for_retry with a stale generation");

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// dead_letter / requeue_dead_letter / mark_obsolete
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn dead_letter_moves_the_exact_identity_and_payload_to_dead_letters_as_parked() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "dead-letter-move").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "repository.obliterated",
        "repository",
        &aggregate_id,
        1,
    )
    .await;
    let before_key = snapshot(&raw, event_id)
        .await
        .expect("row before")
        .idempotency_key;

    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    let generation = claimed[0].claim_generation;

    let outcome = dead_letter(
        &mut pool_client,
        event_id,
        generation,
        "UNSUPPORTED_SCHEMA_V1",
    )
    .await
    .expect("dead letter");
    assert_eq!(outcome, CasOutcome::Applied);

    assert!(
        snapshot(&raw, event_id).await.is_none(),
        "a dead-lettered row must leave lore_outbox_events"
    );

    let dl = raw
        .query_one(
            "SELECT cell_id, idempotency_key, repository_id, repository_generation, \
                    event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                    payload_schema_version, payload, disposition, terminal_class, \
                    first_failed_at, last_failed_at \
             FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("dead letter row must exist");
    let dl_cell_id: String = dl.get("cell_id");
    let dl_key: Vec<u8> = dl.get("idempotency_key");
    let dl_repository_id: Vec<u8> = dl.get("repository_id");
    let dl_aggregate_id: Vec<u8> = dl.get("aggregate_id");
    let dl_disposition: String = dl.get("disposition");
    let dl_terminal_class: String = dl.get("terminal_class");
    let first_failed_at: std::time::SystemTime = dl.get("first_failed_at");
    let last_failed_at: std::time::SystemTime = dl.get("last_failed_at");

    assert_eq!(dl_cell_id, cell_id);
    assert_eq!(dl_key, before_key);
    assert_eq!(dl_repository_id, repository_id.to_vec());
    assert_eq!(dl_aggregate_id, aggregate_id.to_vec());
    assert_eq!(dl_disposition, "parked");
    assert_eq!(dl_terminal_class, "UNSUPPORTED_SCHEMA_V1");
    assert_eq!(
        first_failed_at, last_failed_at,
        "the first dead-letter of a row must set first_failed_at == last_failed_at"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn dead_letter_with_a_stale_generation_is_a_no_op() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "dead-letter-stale").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;
    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    let stale_generation = claimed[0].claim_generation - 1;

    let before = snapshot(&raw, event_id).await.expect("before");
    let outcome = dead_letter(
        &mut pool_client,
        event_id,
        stale_generation,
        "UNSUPPORTED_SCHEMA_V1",
    )
    .await
    .expect("dead letter with stale generation");
    assert!(matches!(outcome, CasOutcome::StaleClaim { .. }));
    let after = snapshot(&raw, event_id)
        .await
        .expect("row must still be present");
    assert_snapshots_equal(&before, &after, "dead_letter with a stale generation");

    let dl_count: i64 = raw
        .query_one(
            "SELECT count(*) FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("dead letter count query")
        .get(0);
    assert_eq!(
        dl_count, 0,
        "a stale-generation dead-letter must not create a dead-letter row"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn requeue_dead_letter_returns_the_row_with_original_keys_and_marks_the_evidence_requeued() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "requeue-dl").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;
    let before_key = snapshot(&raw, event_id)
        .await
        .expect("before")
        .idempotency_key;
    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    let generation_at_dead_letter = claimed[0].claim_generation;
    dead_letter(
        &mut pool_client,
        event_id,
        generation_at_dead_letter,
        "TERMINAL_V1",
    )
    .await
    .expect("dead letter");

    let outcome = requeue_dead_letter(
        &mut pool_client,
        event_id,
        "operator verified stale scope",
        "alice@ops",
    )
    .await
    .expect("requeue");
    assert_eq!(outcome, DeadLetterOutcome::Applied);

    let row = snapshot(&raw, event_id)
        .await
        .expect("row must be back in lore_outbox_events");
    assert_eq!(row.state, "pending");
    // NOT reset to 0: reinstated at the dead letter's stored generation PLUS
    // ONE, strictly above every generation any worker holding the old claim
    // could still present -- resetting to 0 would make the fence reusable.
    assert_eq!(row.claim_generation, generation_at_dead_letter + 1);
    assert_eq!(row.attempt_count, 0);
    assert_eq!(
        row.idempotency_key, before_key,
        "the ORIGINAL idempotency_key must be preserved"
    );
    assert!(
        row.stream_identity.is_none(),
        "publication fields must be cleared on reinstatement"
    );

    let dl_disposition: String = raw
        .query_one(
            "SELECT disposition FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("dead letter evidence row must remain")
        .get("disposition");
    assert_eq!(
        dl_disposition, "requeued",
        "the evidence row is retained, not deleted"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn requeue_dead_letter_when_a_live_row_with_the_same_keys_exists_returns_event_still_present()
{
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "requeue-collision").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;
    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    dead_letter(
        &mut pool_client,
        event_id,
        claimed[0].claim_generation,
        "TERMINAL_V1",
    )
    .await
    .expect("dead letter");

    // A retry of the SAME logical mutation (identical identity tuple) after
    // the original was dead-lettered gets a fresh event_id but the SAME
    // idempotency_key, because the original row no longer exists to collide
    // with.
    let new_event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;
    assert_ne!(
        new_event_id, event_id,
        "the retry must mint a fresh event_id"
    );

    let outcome = requeue_dead_letter(
        &mut pool_client,
        event_id,
        "operator attempted requeue",
        "bob@ops",
    )
    .await
    .expect("requeue against a colliding live row");
    assert_eq!(outcome, DeadLetterOutcome::EventStillPresent);

    // Nothing must have changed: the live row is the retry's, the dead letter
    // is still parked.
    let live = snapshot(&raw, new_event_id)
        .await
        .expect("the retry's row must be untouched");
    assert_eq!(live.state, "pending");
    let dl_disposition: String = raw
        .query_one(
            "SELECT disposition FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("dead letter row")
        .get("disposition");
    assert_eq!(
        dl_disposition, "parked",
        "a rejected requeue must not change the disposition"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn mark_obsolete_records_reason_and_actor_and_never_deletes_the_dead_letter_row() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "mark-obsolete").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;
    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    dead_letter(
        &mut pool_client,
        event_id,
        claimed[0].claim_generation,
        "TERMINAL_V1",
    )
    .await
    .expect("dead letter");

    let outcome = mark_obsolete(
        &raw,
        event_id,
        "verified the aggregate was deleted before this event could apply",
        "carol@ops",
    )
    .await
    .expect("mark obsolete");
    assert_eq!(outcome, DeadLetterOutcome::Applied);

    let row = raw
        .query_one(
            "SELECT disposition, disposition_reason, disposition_actor, terminal_class \
             FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("dead letter row must still exist");
    let disposition: String = row.get("disposition");
    let reason: Option<String> = row.get("disposition_reason");
    let actor: Option<String> = row.get("disposition_actor");
    let terminal_class: String = row.get("terminal_class");
    assert_eq!(disposition, "obsolete");
    assert_eq!(actor.as_deref(), Some("carol@ops"));
    assert!(reason.is_some());
    assert_eq!(
        terminal_class, "TERMINAL_V1",
        "the original evidence must be preserved"
    );

    // Re-marking an already-obsolete row must be refused, not silently reapplied.
    let second = mark_obsolete(&raw, event_id, "second attempt", "dave@ops")
        .await
        .expect("second mark obsolete call");
    assert_eq!(
        second,
        DeadLetterOutcome::NotParked {
            disposition: "obsolete".to_owned()
        }
    );

    let missing = mark_obsolete(&raw, Uuid::new_v4(), "reason", "actor")
        .await
        .expect("mark obsolete on a nonexistent event");
    assert_eq!(missing, DeadLetterOutcome::NotFound);

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// requeue_unsafe_for_epoch_reset
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn epoch_reset_requeues_only_the_matching_stream_and_old_epoch_with_original_keys() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "epoch-reset-scope").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;
    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();

    async fn accept_at(
        raw: &mut Client,
        pool_client: &mut deadpool_postgres::Client,
        cell_id: &str,
        repository_id: &[u8],
        stream_identity: &str,
        stream_epoch: i64,
    ) -> (Uuid, [u8; 32]) {
        let aggregate_id: [u8; 16] = rand::random();
        let event_id = append_pending(
            raw,
            cell_id,
            repository_id,
            "branch.pushed",
            "branch",
            &aggregate_id,
            1,
        )
        .await;
        let before_key: Vec<u8> = snapshot(raw, event_id).await.expect("row").idempotency_key;
        let claimed = claim_batch(pool_client, "worker-a", 10, Duration::from_secs(30))
            .await
            .expect("claim")
            .into_iter()
            .find(|c| c.event.event_id == event_id)
            .expect("claimed the row just inserted");
        let acceptance = sample_acceptance(stream_identity, stream_epoch, 1);
        record_broker_accepted(raw, event_id, claimed.claim_generation, &acceptance)
            .await
            .expect("accept");
        (event_id, before_key.try_into().expect("32-byte key"))
    }

    let matching: Vec<(Uuid, [u8; 32])> = {
        let mut v = Vec::new();
        for _ in 0..3 {
            v.push(
                accept_at(
                    &mut raw,
                    &mut pool_client,
                    &cell_id,
                    &repository_id,
                    "s1",
                    5,
                )
                .await,
            );
        }
        v
    };
    let (other_epoch_id, _) = accept_at(
        &mut raw,
        &mut pool_client,
        &cell_id,
        &repository_id,
        "s1",
        6,
    )
    .await;
    let (other_stream_id, _) = accept_at(
        &mut raw,
        &mut pool_client,
        &cell_id,
        &repository_id,
        "s2",
        5,
    )
    .await;

    let requeued = requeue_unsafe_for_epoch_reset(&mut pool_client, "s1", 5)
        .await
        .expect("epoch reset requeue");
    assert_eq!(requeued, 3);

    for (event_id, key) in &matching {
        let row = snapshot(&raw, *event_id)
            .await
            .expect("requeued row must exist");
        assert_eq!(row.state, "pending");
        assert!(row.stream_identity.is_none());
        assert!(row.broker_accepted_at.is_none());
        assert_eq!(&row.idempotency_key[..], key.as_slice());
    }

    let other_epoch_row = snapshot(&raw, other_epoch_id).await.expect("row");
    assert_eq!(
        other_epoch_row.state, "broker_accepted",
        "a different epoch must be untouched"
    );
    let other_stream_row = snapshot(&raw, other_stream_id).await.expect("row");
    assert_eq!(
        other_stream_row.state, "broker_accepted",
        "a different stream identity must be untouched"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn epoch_reset_is_bounded_per_transaction_and_the_cursor_continues_across_batches() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "epoch-reset-batching").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    // Bulk-seed rows directly in `broker_accepted` state (bypassing
    // claim/accept for speed -- this test's own concern is the requeue
    // function's batching/cursor behavior, not the claim/accept path, which
    // has its own dedicated cases above).
    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let total: i64 = MAX_EPOCH_RESET_BATCH as i64 + 500;
    raw.execute(
        "INSERT INTO lore_outbox_events ( \
             event_id, cell_id, idempotency_key, repository_id, repository_generation, \
             event_kind, aggregate_kind, aggregate_id, aggregate_version, \
             payload_schema_version, payload, state, created_at, available_at, \
             claim_generation, stream_identity, stream_epoch, broker_sequence, \
             gateway_response_id, publisher_contract_version, broker_accepted_at \
         ) \
         SELECT gen_random_uuid(), $1, decode(md5(g::text), 'hex') || decode(md5(g::text || 'x'), 'hex'), \
                $2, 1, 'branch.pushed', 'branch', decode(lpad(to_hex(g), 32, '0'), 'hex'), \
                decode(lpad(to_hex(1000000000 + g), 16, '0'), 'hex'), \
                1, '{}', 'broker_accepted', clock_timestamp(), clock_timestamp(), \
                1, 's1', 7, g, 'resp-' || g::text, 1, clock_timestamp() \
         FROM generate_series(1, $3::bigint) AS g",
        &[&cell_id, &repository_id.as_slice(), &total],
    )
    .await
    .expect("bulk seed broker_accepted rows");

    let requeued = requeue_unsafe_for_epoch_reset(&mut pool_client, "s1", 7)
        .await
        .expect("bounded epoch reset requeue");
    assert_eq!(
        requeued, total as u64,
        "the cursor must continue past the first {MAX_EPOCH_RESET_BATCH}-row batch and drain the rest"
    );

    let remaining_accepted: i64 = raw
        .query_one(
            "SELECT count(*) FROM lore_outbox_events WHERE cell_id = $1 AND state = 'broker_accepted'",
            &[&cell_id],
        )
        .await
        .expect("count remaining")
        .get(0);
    assert_eq!(remaining_accepted, 0);
    let now_pending: i64 = raw
        .query_one(
            "SELECT count(*) FROM lore_outbox_events WHERE cell_id = $1 AND state = 'pending'",
            &[&cell_id],
        )
        .await
        .expect("count pending")
        .get(0);
    assert_eq!(now_pending, total);

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Partial-index EXPLAIN proof (behavior 9 of the WP-119 Step A brief)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn the_claim_query_and_epoch_reset_query_use_their_partial_indexes() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "explain-partial-idx").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let raw = pg_client(&url).await;

    // The exact predicate `claim_batch` runs, minus `FOR UPDATE SKIP LOCKED`
    // (EXPLAIN without ANALYZE does not execute row locking, and the literal
    // predicate shape is what is under test here, not the lock semantics
    // already proven live above).
    let plan_rows = raw
        .query(
            "EXPLAIN SELECT event_id FROM lore_outbox_events \
             WHERE state = 'pending' \
               AND available_at <= clock_timestamp() \
               AND (claim_expires_at IS NULL OR claim_expires_at <= clock_timestamp()) \
             ORDER BY available_at, event_id \
             LIMIT 100",
            &[],
        )
        .await
        .expect("explain claim query");
    let plan_text: String = plan_rows
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        plan_text.contains("lore_outbox_events_pending_available"),
        "the claim query must use its partial index; got plan:\n{plan_text}"
    );

    let plan_rows = raw
        .query(
            "EXPLAIN SELECT event_id FROM lore_outbox_events \
             WHERE state = 'broker_accepted' \
               AND stream_identity = 'placeholder' \
               AND stream_epoch = 1 \
               AND event_id > '00000000-0000-0000-0000-000000000000' \
             ORDER BY event_id \
             LIMIT 1000",
            &[],
        )
        .await
        .expect("explain epoch reset query");
    let plan_text: String = plan_rows
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        plan_text.contains("lore_outbox_events_accepted_stream"),
        "the epoch-reset query must use its partial index; got plan:\n{plan_text}"
    );

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Regression cases for the reviewer-found generation-reuse defects (fix round
// after the schema/relay.rs changes that added the dead-letter
// `claim_generation`/`dead_letter_count`/`previous_disposition_*` columns).
// Each proves a stale fence is refused, not merely that the happy path works.
// ---------------------------------------------------------------------------

/// Regression (a): a worker's claim generation from BEFORE a dead-letter/
/// requeue cycle must not be reusable afterward. `requeue_dead_letter`
/// reinstates at `claim_generation + 1`, strictly above the generation the
/// original worker held, specifically so this can never apply.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_stale_generation_from_before_a_requeue_cannot_apply_after_a_second_claim() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "gen-not-reusable").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;

    let claimed_a = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("worker-a claim");
    let generation_a = claimed_a[0].claim_generation;
    dead_letter(&mut pool_client, event_id, generation_a, "TERMINAL_V1")
        .await
        .expect("dead letter");
    requeue_dead_letter(&mut pool_client, event_id, "operator retry", "ops@example")
        .await
        .expect("requeue");

    let claimed_b = claim_batch(&mut pool_client, "worker-b", 10, Duration::from_secs(30))
        .await
        .expect("worker-b claim");
    let generation_b = claimed_b[0].claim_generation;
    assert!(
        generation_b > generation_a,
        "worker-b's generation ({generation_b}) must be strictly greater than worker-a's \
         pre-requeue generation ({generation_a})"
    );

    let before = snapshot(&raw, event_id)
        .await
        .expect("row before A's stale ack");
    let acceptance = sample_acceptance("DURABLE-gen-reuse", 1, 1);
    // Revert-check: against the pre-fix behavior (reinstate at generation 0),
    // `generation_a` (1, the first-ever claim) would equal the reinstated
    // generation and this call would incorrectly apply.
    let outcome = record_broker_accepted(&raw, event_id, generation_a, &acceptance)
        .await
        .expect("worker-a's stale acknowledgement attempt");
    assert!(
        matches!(outcome, CasOutcome::StaleClaim { .. }),
        "worker-a's pre-requeue generation must never apply again, got {outcome:?}"
    );
    let after = snapshot(&raw, event_id)
        .await
        .expect("row after A's stale ack");
    assert_snapshots_equal(
        &before,
        &after,
        "worker-a's stale post-requeue acknowledgement",
    );

    namespace.release().await;
}

/// Regression (b): an acknowledgement carrying a claim generation from before
/// an epoch reset must not apply after the reset, even without a dead worker
/// -- `requeue_unsafe_for_epoch_reset` now bumps `claim_generation` on every
/// row it requeues for exactly this reason.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_stale_epoch_acknowledgement_cannot_apply_after_an_epoch_reset() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "gen-not-reusable-epoch").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;

    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    let generation = claimed[0].claim_generation;
    let acceptance = sample_acceptance("s1", 7, 1);
    record_broker_accepted(&raw, event_id, generation, &acceptance)
        .await
        .expect("initial acceptance under epoch 7");

    let requeued = requeue_unsafe_for_epoch_reset(&mut pool_client, "s1", 7)
        .await
        .expect("epoch reset");
    assert_eq!(requeued, 1);

    // The gateway's in-flight response for the OLD epoch/generation arrives
    // late, after the reset. It must not apply.
    let stale_acceptance = sample_acceptance("s1", 7, 1);
    let outcome = record_broker_accepted(&raw, event_id, generation, &stale_acceptance)
        .await
        .expect("stale post-reset acknowledgement attempt");
    assert!(
        matches!(outcome, CasOutcome::StaleClaim { .. }),
        "a pre-reset generation must never apply after the epoch reset, got {outcome:?}"
    );

    let row = snapshot(&raw, event_id).await.expect("row after stale ack");
    assert_eq!(row.state, "pending");
    assert!(row.stream_identity.is_none());
    assert!(row.stream_epoch.is_none());
    assert!(row.broker_sequence.is_none());
    assert!(row.gateway_response_id.is_none());
    assert!(row.publisher_contract_version.is_none());
    assert!(row.broker_accepted_at.is_none());

    namespace.release().await;
}

/// Regression (c): dead-lettering an event a SECOND time (after it was
/// requeued and failed terminally again) must preserve the original
/// `first_failed_at`, count the cycle, and retain the prior operator
/// decision in `previous_disposition_*` rather than overwriting it.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn dead_letter_after_requeue_preserves_first_failed_at_and_records_previous_disposition() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "redelivery-audit-trail").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;

    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    dead_letter(
        &mut pool_client,
        event_id,
        claimed[0].claim_generation,
        "TERMINAL_V1",
    )
    .await
    .expect("first dead letter");
    let first_failed_at: std::time::SystemTime = raw
        .query_one(
            "SELECT first_failed_at FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("read first_failed_at")
        .get("first_failed_at");

    requeue_dead_letter(&mut pool_client, event_id, "op says retry", "kv")
        .await
        .expect("requeue");

    let claimed_again = claim_batch(&mut pool_client, "worker-b", 10, Duration::from_secs(30))
        .await
        .expect("claim after requeue");
    dead_letter(
        &mut pool_client,
        event_id,
        claimed_again[0].claim_generation,
        "TERMINAL_V1",
    )
    .await
    .expect("second dead letter");

    let row = raw
        .query_one(
            "SELECT first_failed_at, dead_letter_count, disposition, disposition_reason, \
                    disposition_at, disposition_actor, previous_disposition, \
                    previous_disposition_reason, previous_disposition_actor \
             FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("read dead letter row after second dead-letter");

    let row_first_failed_at: std::time::SystemTime = row.get("first_failed_at");
    let dead_letter_count: i32 = row.get("dead_letter_count");
    let disposition: String = row.get("disposition");
    let disposition_reason: Option<String> = row.get("disposition_reason");
    let disposition_at: Option<std::time::SystemTime> = row.get("disposition_at");
    let disposition_actor: Option<String> = row.get("disposition_actor");
    let previous_disposition: Option<String> = row.get("previous_disposition");
    let previous_disposition_reason: Option<String> = row.get("previous_disposition_reason");
    let previous_disposition_actor: Option<String> = row.get("previous_disposition_actor");

    assert_eq!(
        row_first_failed_at, first_failed_at,
        "first_failed_at must survive a second dead-letter cycle"
    );
    assert_eq!(dead_letter_count, 2);
    assert_eq!(disposition, "parked");
    assert!(disposition_reason.is_none());
    assert!(disposition_at.is_none());
    assert!(disposition_actor.is_none());
    assert_eq!(previous_disposition.as_deref(), Some("requeued"));
    assert_eq!(
        previous_disposition_reason.as_deref(),
        Some("op says retry")
    );
    assert_eq!(previous_disposition_actor.as_deref(), Some("kv"));

    namespace.release().await;
}

// Regression (d), requested: prove `requeue_unsafe_for_epoch_reset`'s loop
// does not stop early when a batch is concurrently drained (a row moved to
// `consumer_safe` or another epoch mid-reset). NOT WRITTEN: reaching that
// interleaving deterministically needs a barrier between the function's
// SELECT and its UPDATE in the same batch iteration, and `relay.rs` has no
// `failpoint!` anchor there today (its five anchors are `outbox.claim.
// after_select`, `outbox.claim.before_commit`, `outbox.accept.before_update`,
// `outbox.accept.after_update`, and `outbox.dead_letter.
// between_copy_and_delete` -- none inside `requeue_unsafe_for_epoch_reset`).
// A `tokio::join!` race without that anchor cannot guarantee the second
// connection's write lands inside the exact SELECT-to-UPDATE window, so it
// would not fail against a version of the loop that DID stop early -- would
// not be discriminating -- and is skipped per this file's own instruction
// not to write a version that cannot fail. Adding the anchor is a `relay.rs`
// change, not a test-file one.

// ---------------------------------------------------------------------------
// Gap-fill: lookup_by_idempotency_key, renew_claim, requeue_dead_letter's
// NotParked/NotFound outcomes.
// ---------------------------------------------------------------------------

/// INV-FL R-SHOULD-1: `lookup_by_idempotency_key` round-trips a pending row,
/// reflects the acceptance once one is recorded, and returns `None` for a key
/// that was never appended.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn lookup_by_idempotency_key_round_trips_pending_then_accepted_and_none_for_unknown() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "lookup-round-trip").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let version = AggregateVersion::ordinal_only(1).encode();
    let tx = raw.transaction().await.expect("begin append tx");
    let event = OutboxEvent {
        cell_id: &cell_id,
        repository_id: &repository_id,
        repository_generation: 1,
        event_kind: "branch.pushed",
        aggregate_kind: "branch",
        aggregate_id: &aggregate_id,
        aggregate_version: &version,
        payload_schema_version: 1,
        payload: b"{}",
    };
    let appended = append(&tx, &event).await.expect("append");
    tx.commit().await.expect("commit append");

    let unknown_key: [u8; 32] = rand::random();
    assert!(
        lookup_by_idempotency_key(&raw, &cell_id, &unknown_key)
            .await
            .expect("lookup unknown key")
            .is_none(),
        "an unknown idempotency_key must return None"
    );

    let pending_row = lookup_by_idempotency_key(&raw, &cell_id, &appended.idempotency_key)
        .await
        .expect("lookup pending row")
        .expect("row must be found");
    assert_eq!(pending_row.event.event_id, appended.event_id);
    assert_eq!(pending_row.state, "pending");
    assert!(pending_row.acceptance.is_none());

    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    let acceptance = sample_acceptance("DURABLE-lookup", 3, 9);
    record_broker_accepted(
        &raw,
        appended.event_id,
        claimed[0].claim_generation,
        &acceptance,
    )
    .await
    .expect("accept");

    let accepted_row = lookup_by_idempotency_key(&raw, &cell_id, &appended.idempotency_key)
        .await
        .expect("lookup accepted row")
        .expect("row must still be found");
    assert_eq!(accepted_row.state, "broker_accepted");
    let found_acceptance = accepted_row
        .acceptance
        .expect("acceptance must be populated once broker_accepted");
    assert_eq!(found_acceptance.stream_identity, "DURABLE-lookup");
    assert_eq!(found_acceptance.stream_epoch, 3);
    assert_eq!(found_acceptance.broker_sequence, 9);

    namespace.release().await;
}

/// `renew_claim` extends a lease when the caller's owner and generation both
/// match, and refuses (`StaleClaim`) when the owner differs even at the
/// current generation -- two workers cannot both believe they hold one claim.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn renew_claim_applies_for_the_owning_worker_and_refuses_a_different_owner_at_the_same_generation()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "renew-claim").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;
    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    let generation = claimed[0].claim_generation;
    let expiry_before = claimed[0].claim_expires_at;

    // A different owner at the SAME generation must be refused -- the schema
    // cannot express two owners for one generation, so this is the only place
    // that invariant is checked.
    let wrong_owner_outcome = renew_claim(
        &raw,
        event_id,
        generation,
        "worker-b",
        Duration::from_secs(30),
    )
    .await
    .expect("renew attempt by the wrong owner");
    assert!(
        matches!(wrong_owner_outcome, CasOutcome::StaleClaim { .. }),
        "a different owner at the same generation must be refused, got {wrong_owner_outcome:?}"
    );
    let unchanged = snapshot(&raw, event_id)
        .await
        .expect("row after wrong-owner renew attempt");
    assert_eq!(
        unchanged.claim_expires_at,
        Some(expiry_before),
        "a refused renewal must not extend the lease"
    );

    let right_owner_outcome = renew_claim(
        &raw,
        event_id,
        generation,
        "worker-a",
        Duration::from_secs(60),
    )
    .await
    .expect("renew attempt by the owning worker");
    assert_eq!(right_owner_outcome, CasOutcome::Applied);
    let renewed = snapshot(&raw, event_id)
        .await
        .expect("row after right-owner renew");
    assert!(
        renewed.claim_expires_at.expect("lease still set") > expiry_before,
        "the owning worker's renewal must extend the lease"
    );
    assert_eq!(
        renewed.claim_generation, generation,
        "renew_claim must not itself change the generation"
    );

    namespace.release().await;
}

/// `requeue_dead_letter`'s CAS failure paths: a non-parked disposition
/// returns `NotParked`, and an unknown `event_id` returns `NotFound`.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn requeue_dead_letter_returns_not_parked_or_not_found_as_appropriate() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "requeue-not-parked").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let repository_id = rand_repository_id();
    let cell_id = rand_cell_id();
    let aggregate_id: [u8; 16] = rand::random();
    let event_id = append_pending(
        &mut raw,
        &cell_id,
        &repository_id,
        "branch.pushed",
        "branch",
        &aggregate_id,
        1,
    )
    .await;
    let claimed = claim_batch(&mut pool_client, "worker-a", 10, Duration::from_secs(30))
        .await
        .expect("claim");
    dead_letter(
        &mut pool_client,
        event_id,
        claimed[0].claim_generation,
        "TERMINAL_V1",
    )
    .await
    .expect("dead letter");
    mark_obsolete(&raw, event_id, "authoritative proof it's unnecessary", "kv")
        .await
        .expect("mark obsolete");

    let not_parked = requeue_dead_letter(&mut pool_client, event_id, "attempted requeue", "kv")
        .await
        .expect("requeue against an obsolete row");
    assert_eq!(
        not_parked,
        DeadLetterOutcome::NotParked {
            disposition: "obsolete".to_owned()
        }
    );

    let not_found = requeue_dead_letter(&mut pool_client, Uuid::new_v4(), "reason", "actor")
        .await
        .expect("requeue against an unknown event_id");
    assert_eq!(not_found, DeadLetterOutcome::NotFound);

    namespace.release().await;
}
