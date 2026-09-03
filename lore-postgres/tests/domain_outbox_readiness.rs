// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-119 Step A: outbox backlog and admission proof
//! (`lore-postgres/src/domain/outbox/relay.rs`'s `backlog`/`admission_check`;
//! CR-032 "Lag, readiness, and backpressure" -- the local-Postgres-only half.
//! Consumer readiness/checkpoint-projection admission is WP-119 Step C's, out
//! of scope here).
//!
//! Real Postgres only, `#[ignore]`. `backlog`/`admission_check` scan
//! `lore_outbox_events` table-wide with no `cell_id` filter, so each case
//! gets its own [`case_namespace::CaseNamespace`] schema -- load-bearing
//! isolation, not decorative, given this run shares one database across every
//! case in this suite.
//!
//! Rows are seeded with an explicit, controlled `created_at`/`available_at`
//! via a raw INSERT (not `append()`, which always stamps
//! `clock_timestamp()`), because the age assertions below need to control the
//! seed precisely rather than sleeping for real minutes.

#[path = "common/case_namespace.rs"]
mod case_namespace;

use std::time::Duration;

use case_namespace::CaseNamespace;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::outbox::relay::AdmissionLimits;
use lore_postgres::domain::outbox::relay::AdmissionRejection;
use lore_postgres::domain::outbox::relay::AdmissionVerdict;
use lore_postgres::domain::outbox::relay::admission_check;
use lore_postgres::domain::outbox::relay::backlog;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;

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
        .expect("connect for direct test access");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

/// Insert one pending row with an explicit `created_at`/`available_at` and
/// payload size, bypassing `append()` so the age/byte assertions below are
/// exact rather than approximate.
async fn seed_pending(
    client: &Client,
    cell_id: &str,
    age: Duration,
    payload_len: usize,
) -> uuid::Uuid {
    let event_id = uuid::Uuid::new_v4();
    let repository_id: [u8; 16] = rand::random();
    let aggregate_id: [u8; 16] = rand::random();
    let version = AggregateVersion::ordinal_only(1).encode();
    let payload = vec![0u8; payload_len];
    let age_secs = age.as_secs_f64();
    client
        .execute(
            "INSERT INTO lore_outbox_events ( \
                 event_id, cell_id, idempotency_key, repository_id, repository_generation, \
                 event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                 payload_schema_version, payload, state, created_at, available_at \
             ) VALUES ( \
                 $1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, $7, 'pending', \
                 clock_timestamp() - ($8::double precision * interval '1 second'), \
                 clock_timestamp() - ($8::double precision * interval '1 second') \
             )",
            &[
                &event_id,
                &cell_id,
                &rand::random::<[u8; 32]>().as_slice(),
                &repository_id.as_slice(),
                &aggregate_id.as_slice(),
                &version.as_slice(),
                &payload.as_slice(),
                &age_secs,
            ],
        )
        .await
        .expect("seed pending row");
    event_id
}

async fn seed_claimed(client: &Client, cell_id: &str) -> uuid::Uuid {
    let event_id = seed_pending(client, cell_id, Duration::ZERO, 8).await;
    client
        .execute(
            "UPDATE lore_outbox_events SET \
                 claim_owner = 'probe-worker', \
                 claim_expires_at = clock_timestamp() + interval '30 seconds' \
             WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("mark row claimed");
    event_id
}

async fn seed_dead_letter(client: &Client, cell_id: &str) -> uuid::Uuid {
    let event_id = uuid::Uuid::new_v4();
    let repository_id: [u8; 16] = rand::random();
    let aggregate_id: [u8; 16] = rand::random();
    let version = AggregateVersion::ordinal_only(1).encode();
    client
        .execute(
            "INSERT INTO lore_outbox_dead_letters ( \
                 event_id, cell_id, idempotency_key, repository_id, repository_generation, \
                 event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                 payload_schema_version, payload, created_at, attempt_count, \
                 claim_generation, terminal_class, first_failed_at, last_failed_at, disposition \
             ) VALUES ( \
                 $1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{}', \
                 clock_timestamp(), 3, 1, 'TERMINAL_V1', clock_timestamp(), clock_timestamp(), 'parked' \
             )",
            &[
                &event_id,
                &cell_id,
                &rand::random::<[u8; 32]>().as_slice(),
                &repository_id.as_slice(),
                &aggregate_id.as_slice(),
                &version.as_slice(),
            ],
        )
        .await
        .expect("seed dead letter row");
    event_id
}

// ---------------------------------------------------------------------------
// OutboxBacklog
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn backlog_counts_and_oldest_age_match_seeded_rows() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "backlog-counts").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let cell_id = format!("cell-{:016x}", rand::random::<u64>());

    // Three explicitly-pending rows: ages 0s, 30s, 120s -- oldest must be
    // ~120s. `seed_claimed` (8-byte payload) ALSO leaves `state = 'pending'`
    // -- claiming only sets `claim_owner`/`claim_expires_at`, matching
    // `relay.rs`'s real `claim_batch` -- so it counts toward `pending_count`
    // AND `claimed_count` at once; that overlap is `backlog()`'s real,
    // intentional behavior (`pending_count` has no `claim_expires_at`
    // filter), not a test bug.
    seed_pending(&client, &cell_id, Duration::from_secs(0), 100).await;
    seed_pending(&client, &cell_id, Duration::from_secs(30), 100).await;
    seed_pending(&client, &cell_id, Duration::from_secs(120), 250).await;
    seed_claimed(&client, &cell_id).await;
    seed_dead_letter(&client, &cell_id).await;

    let result = backlog(&client).await.expect("backlog");
    // NOTE: backlog() is not scoped by cell_id, so these assertions rely on
    // the namespace's fresh schema being the only source of rows -- exactly
    // the isolation CaseNamespace exists to provide.
    assert_eq!(
        result.pending_count, 4,
        "3 explicit pending rows plus the still-pending claimed row"
    );
    assert_eq!(result.pending_bytes, 100 + 100 + 250 + 8);
    assert_eq!(result.claimed_count, 1);
    assert_eq!(result.dead_letter_count, 1);
    let oldest = result
        .oldest_pending_age
        .expect("must report an oldest age when pending rows exist");
    assert!(
        oldest >= Duration::from_secs(115) && oldest <= Duration::from_secs(130),
        "oldest_pending_age must reflect the ~120s-old row, got {oldest:?}"
    );
    assert!(!result.saturated());

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn backlog_reports_no_oldest_age_when_there_are_no_pending_rows() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "backlog-empty").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;

    let result = backlog(&client)
        .await
        .expect("backlog on an empty namespace");
    assert_eq!(result.pending_count, 0);
    assert_eq!(result.pending_bytes, 0);
    assert!(result.oldest_pending_age.is_none());
    assert_eq!(result.claimed_count, 0);
    assert_eq!(result.dead_letter_count, 0);

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// admission_check
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn admission_check_is_open_when_every_limit_is_comfortably_unmet() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "admission-open").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let cell_id = format!("cell-{:016x}", rand::random::<u64>());
    seed_pending(&client, &cell_id, Duration::from_secs(1), 100).await;

    let verdict = admission_check(&client, &AdmissionLimits::default())
        .await
        .expect("admission check");
    assert_eq!(verdict, AdmissionVerdict::Admit);

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn admission_check_closes_on_oldest_pending_age() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "admission-age").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let cell_id = format!("cell-{:016x}", rand::random::<u64>());
    seed_pending(&client, &cell_id, Duration::from_secs(600), 100).await;

    let limits = AdmissionLimits {
        max_oldest_pending_age: Duration::from_secs(300),
        ..AdmissionLimits::default()
    };
    let verdict = admission_check(&client, &limits)
        .await
        .expect("admission check");
    match verdict {
        AdmissionVerdict::Reject(AdmissionRejection::OldestPendingAge { observed, limit }) => {
            assert_eq!(limit, Duration::from_secs(300));
            assert!(observed > limit);
        }
        other => panic!("expected an OldestPendingAge rejection, got {other:?}"),
    }

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn admission_check_closes_on_pending_row_count() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "admission-rows").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let cell_id = format!("cell-{:016x}", rand::random::<u64>());
    for _ in 0..5 {
        seed_pending(&client, &cell_id, Duration::from_secs(1), 10).await;
    }

    let limits = AdmissionLimits {
        max_pending_rows: 4,
        ..AdmissionLimits::default()
    };
    let verdict = admission_check(&client, &limits)
        .await
        .expect("admission check");
    match verdict {
        AdmissionVerdict::Reject(AdmissionRejection::PendingRows { observed, limit }) => {
            assert_eq!(limit, 4);
            assert!(observed > limit);
        }
        other => panic!("expected a PendingRows rejection, got {other:?}"),
    }

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn admission_check_closes_on_pending_payload_bytes() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "admission-bytes").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let cell_id = format!("cell-{:016x}", rand::random::<u64>());
    seed_pending(&client, &cell_id, Duration::from_secs(1), 10_000).await;

    let limits = AdmissionLimits {
        max_pending_bytes: 5_000,
        ..AdmissionLimits::default()
    };
    let verdict = admission_check(&client, &limits)
        .await
        .expect("admission check");
    match verdict {
        AdmissionVerdict::Reject(AdmissionRejection::PendingBytes { observed, limit }) => {
            assert_eq!(limit, 5_000);
            assert!(observed > limit);
        }
        other => panic!("expected a PendingBytes rejection, got {other:?}"),
    }

    namespace.release().await;
}

/// CR-032: "It must not query live broker lag, gateway health, or a receiver
/// over the network inside the mutation transaction." Verified structurally
/// rather than at runtime: this non-generic wrapper compiles only if
/// `admission_check` accepts EXACTLY a Postgres client reference and a plain
/// `&AdmissionLimits` data struct -- there is no third parameter slot for a
/// gateway/broker handle, and argument-position `impl GenericClient` cannot
/// silently admit a network type here because every other call site in this
/// file already monomorphizes it against `tokio_postgres::Client`. A
/// signature change that added a network dependency would be a visible diff
/// to this wrapper, not a thing a runtime probe could catch better.
async fn _admission_check_takes_only_a_postgres_client_and_plain_limits(
    client: &tokio_postgres::Client,
    limits: &AdmissionLimits,
) -> Result<AdmissionVerdict, lore_postgres::domain::DomainError> {
    admission_check(client, limits).await
}

/// With zero pending rows, `admission_check` must return `Admit` via its own
/// age short-circuit -- source (`relay.rs`'s `admission_check`) returns
/// early on `age_secs == None` before running the row/byte count probes at
/// all. Distinct from `admission_check_is_open_when_every_limit_is_
/// comfortably_unmet`, which seeds one row and so exercises the age check
/// with a real (small) value rather than the `None` branch.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn admission_check_is_open_with_zero_pending_rows_via_the_age_short_circuit() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "admission-zero-rows").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;

    let pending_count: i64 = client
        .query_one(
            "SELECT count(*) FROM lore_outbox_events WHERE state = 'pending'",
            &[],
        )
        .await
        .expect("count pending rows")
        .get(0);
    assert_eq!(
        pending_count, 0,
        "this case's whole point depends on zero pending rows"
    );

    let verdict = admission_check(&client, &AdmissionLimits::default())
        .await
        .expect("admission check with no pending rows");
    assert_eq!(verdict, AdmissionVerdict::Admit);

    namespace.release().await;
}
