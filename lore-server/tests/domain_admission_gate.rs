// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-119 Phase 8: CR-032's required-event admission gate, wired into
//! `DomainContext::admit` (`lore-server/src/domain.rs`).
//!
//! `OutboxAdmission`'s own probe/cache contract (`refresh`/`current`) is
//! proven directly against `lore-postgres::domain::outbox::relay::admission_check`
//! by `lore-postgres/tests/domain_outbox_readiness.rs`. This file proves the
//! **choke point** instead: that `DomainContext::admit` actually consults the
//! attached gate, refuses a closed cached verdict with `RESOURCE_EXHAUSTED`
//! and bounded `RetryInfo`, admits an open one, and behaves exactly as before
//! WP-119 when no gate is attached at all.
//!
//! # Structural proof that `admit` performs no database call
//!
//! `DomainContext::admit` and `OutboxAdmission::refuse_if_closed`/`current`
//! are plain (non-`async`) functions, so calling them cannot itself await
//! anything. The tests below make that a checked property rather than an
//! implementation detail taken on faith: the async setup (connecting,
//! seeding, and running `OutboxAdmission::refresh`, which IS the database
//! probe) runs inside a short-lived `tokio::runtime::Runtime` that is
//! dropped before `admit` is ever called. `admit` is then invoked from a
//! plain `#[test]` with no Tokio runtime active at all -- if it needed one
//! (a pool `.get()`, a query, anything async), the call would panic with "no
//! reactor running" rather than quietly succeed. It doesn't panic, which is
//! the proof.

use std::sync::Arc;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::outbox::relay::AdmissionLimits;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::domain::DomainContext;
use lore_server::domain::GovernedScope;
use lore_server::event_relay::OutboxAdmission;
use lore_server::event_relay::admission::ADMISSION_RETRY_DELAY;
use lore_server::event_relay::retry_info::decode_retry_delay;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_KEY;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_V1_LEN;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
use lore_server::grpc::domain_operation_metadata::OPERATION_ID_KEY;
use lore_server::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
use lore_server::grpc::domain_operation_metadata::PREPARE_TOKEN_LEN;
use tokio_postgres::Client;
use tonic::Code;
use tonic::metadata::BinaryMetadataValue;
use tonic::metadata::MetadataMap;
use uuid::Uuid;

fn pg_url() -> String {
    std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; an unconfigured live case is NOT RUN")
}

fn token() -> AuthorizationToken {
    AuthorizationToken {
        issuer: "https://issuer.example/p119-admission".to_string(),
        user_id: "p119-admission-tester".to_string(),
        is_service_account: None,
        ..Default::default()
    }
}

fn scope() -> GovernedScope<'static> {
    GovernedScope::TargetRepository {
        repository_id: &[0x37u8; 16],
    }
}

/// A carriage-complete request for a non-mediated `TargetRepository` scope:
/// operation id, fingerprint, and prepare token, no mediated-scope header.
fn carriage() -> MetadataMap {
    let mut metadata = MetadataMap::new();
    metadata.insert_bin(
        OPERATION_ID_KEY,
        BinaryMetadataValue::from_bytes(Uuid::now_v7().as_bytes()),
    );
    let mut fingerprint = vec![FINGERPRINT_VERSION_V1];
    fingerprint.extend(std::iter::repeat_n(0x24, FINGERPRINT_V1_LEN));
    metadata.insert_bin(
        FINGERPRINT_KEY,
        BinaryMetadataValue::from_bytes(&fingerprint),
    );
    metadata.insert_bin(
        PREPARE_TOKEN_KEY,
        BinaryMetadataValue::from_bytes(&[0x61u8; PREPARE_TOKEN_LEN]),
    );
    metadata
}

async fn pg_client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect direct assertion client");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

/// Insert one pending row with an explicit age, matching the schema shape
/// `lore-postgres/tests/domain_outbox_readiness.rs`'s `seed_pending` pins.
async fn seed_pending_row(client: &Client, cell_id: &str) {
    let event_id = Uuid::new_v4();
    let repository_id: [u8; 16] = rand::random();
    let aggregate_id: [u8; 16] = rand::random();
    let version = AggregateVersion::ordinal_only(1).encode();
    client
        .execute(
            "INSERT INTO lore_outbox_events ( \
                 event_id, cell_id, idempotency_key, repository_id, repository_generation, \
                 event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                 payload_schema_version, payload, state, created_at, available_at \
             ) VALUES ( \
                 $1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{}', 'pending', \
                 clock_timestamp(), clock_timestamp() \
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
        .expect("seed pending row");
}

/// Sets up a connected domain store plus an `OutboxAdmission` bound to its
/// own small pool on the same database, inside a short-lived runtime that is
/// dropped before returning -- see the module doc's structural-proof note.
fn build_context_with_refreshed_admission(
    limits: AdmissionLimits,
    seed_row: bool,
) -> DomainContext {
    let url = pg_url();
    let runtime = tokio::runtime::Runtime::new().expect("build a throwaway async runtime");
    let (store, admission) = runtime.block_on(async {
        let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
            .await
            .expect("connect domain store; also bootstraps the outbox schema");
        if seed_row {
            let client = pg_client(&url).await;
            seed_pending_row(&client, "p119-admission-cell").await;
        }
        let pool = build_pool(&url, 2, &TlsConfig::default()).expect("build admission pool");
        let admission = OutboxAdmission::new(pool, limits);
        admission
            .refresh()
            .await
            .expect("admission probe must succeed against a reachable database");
        (store, admission)
    });
    drop(runtime);

    let context = DomainContext::new(Arc::new(store), true);
    context
        .attach_admission(Arc::new(admission))
        .unwrap_or_else(|_| panic!("attach_admission must succeed on a fresh context"));
    context
}

/// Happy path negative: a closed cached verdict (one pending row over a
/// zero-row limit) refuses the governed mutation with `RESOURCE_EXHAUSTED`
/// and a bounded `RetryInfo`, with `admit` called from a plain `#[test]`
/// carrying no active Tokio runtime.
#[test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
fn admit_refuses_with_resource_exhausted_and_bounded_retry_info_when_the_cached_verdict_is_closed()
{
    let limits = AdmissionLimits {
        max_pending_rows: 0,
        ..AdmissionLimits::default()
    };
    let context = build_context_with_refreshed_admission(limits, true);

    let error = context
        .admit(&carriage(), Some(&token()), scope())
        .expect_err("a closed cached verdict must refuse the governed mutation");

    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_eq!(
        decode_retry_delay(error.details()),
        Some(ADMISSION_RETRY_DELAY),
        "a closed admission rejection must carry a bounded RetryInfo"
    );
}

/// Happy path positive: an open cached verdict (generous limits, one row
/// well within them) admits exactly as an ungoverned cell would.
#[test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
fn admit_admits_when_the_cached_verdict_is_open() {
    let context = build_context_with_refreshed_admission(AdmissionLimits::default(), true);

    let admitted = context
        .admit(&carriage(), Some(&token()), scope())
        .expect("an open cached verdict must not refuse the mutation")
        .expect("carriage-complete metadata must be admitted, not the legacy None path");

    // Sanity: the admitted operation actually carries the request's identity,
    // not some default -- guards against a vacuous "it returned Ok" pass.
    assert_ne!(admitted.key.tenant_scope_key, Vec::<u8>::new());
}

/// Before the first probe the gate is open (module doc's documented
/// invariant): attaching a fresh, never-refreshed `OutboxAdmission` must not
/// itself refuse anything.
#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn admit_admits_when_the_admission_gate_has_never_been_refreshed() {
    let url = pg_url();
    let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store");
    let pool = build_pool(&url, 2, &TlsConfig::default()).expect("build admission pool");
    // Deliberately never call `.refresh()`.
    let admission = OutboxAdmission::new(pool, AdmissionLimits::default());

    let context = DomainContext::new(Arc::new(store), true);
    context
        .attach_admission(Arc::new(admission))
        .unwrap_or_else(|_| panic!("attach_admission must succeed on a fresh context"));

    context
        .admit(&carriage(), Some(&token()), scope())
        .expect("a never-refreshed gate must not refuse")
        .expect("carriage-complete metadata must be admitted");
}

/// The no-relay legacy carve-out: a `DomainContext` with no admission gate
/// attached at all (every cell before WP-119 Phase 8, and every cell today
/// with `[outbox_relay] enabled = false`) admits exactly as it always did.
#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn admit_admits_unchanged_when_no_admission_gate_is_attached() {
    let url = pg_url();
    let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store");
    let context = DomainContext::new(Arc::new(store), true);
    assert!(
        context.admission().is_none(),
        "a context nobody attached a gate to must report none"
    );

    context
        .admit(&carriage(), Some(&token()), scope())
        .expect("no gate attached must never refuse on admission grounds")
        .expect("carriage-complete metadata must be admitted");
}
