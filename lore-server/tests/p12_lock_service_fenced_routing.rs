// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! CR-032 / WP-119 Part L2: `LoreLockService`'s fenced-routing gate.
//!
//! `PostgresLockCoordinator::acquire_or_renew`/`release`/`force_release` build
//! and append their pinned `lock_namespace` outbox event once a caller
//! supplies `outbox_cell_id` (proved against real Postgres in
//! `lore-postgres/tests/domain_lock_fencing.rs`). Nothing in this file
//! repeats that. This file proves the two states of the gate a step further
//! out, at the gRPC entry point that decides whether the coordinator is ever
//! reached at all:
//!
//! - a server built with a `fenced_coordinator` (`with_fenced_coordinator`)
//!   unconditionally refuses `Lock`/`Unlock`/`AdminLock` with
//!   `FAILED_PRECONDITION` -- see `lock_service.rs`'s own
//!   `fenced_public_mutation_unavailable` doc comment and
//!   `lore-postgres/tests/domain_lock_fencing.rs`'s
//!   `arming_is_refused_until_the_public_mutation_contract_exists` for why:
//!   the public wire carries neither a `GovernedOperation` nor a per-resource
//!   ownership token, both WP-120 contract gaps. This is **not** the
//!   "fencing_enabled" schema-state flag `enable_fencing_for_component_fixture`
//!   arms in that file -- the gRPC gate reads only whether a coordinator was
//!   wired into the server at all, independent of that flag; and
//! - a server built with no `fenced_coordinator` (the legacy default) routes
//!   through `store::lock_store::PostgresLockStore`, which succeeds and
//!   appends no CR-032 outbox row, because that store has no fence, no
//!   generation, and no domain transaction to append inside
//!   (`lock_store.rs`'s own `BLOCKED(WP-117)` comment).
//!
//! Real Postgres end to end for both arms, rather than a mock, so the "zero
//! rows" half is checked against `lore_outbox_events` itself, not inferred
//! from a mock never being asked to record one.

use std::sync::Arc;
use std::time::Duration;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::lock_store::PostgresLockStore;
use lore_proto::LockService;
use lore_proto::lock::LockRequest;
use lore_proto::lock::Resource;
use lore_proto::lock::UnlockRequest;
use lore_server::grpc::lock_service::LoreLockService;
use lore_server::hooks::HookDispatcher;
use lore_server::notification::local::NotificationSender;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use tokio_postgres::Client;
use tonic::Code;
use tonic::Request;
use tonic::metadata::BinaryMetadataValue;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect direct assertion client");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });
    client
}

fn one_resource() -> Resource {
    Resource {
        branch: rand::random::<[u8; 16]>().to_vec().into(),
        hash: rand::random::<[u8; 32]>().to_vec().into(),
        description: "/Game/wp119-lock-service.uasset".to_owned(),
    }
}

fn request_with_repository<T>(body: T, repository_id: &[u8; 16]) -> Request<T> {
    let mut request = Request::new(body);
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        BinaryMetadataValue::from_bytes(repository_id),
    );
    request
}

async fn outbox_row_count(client: &Client, repository_id: &[u8]) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM lore_outbox_events WHERE repository_id = $1",
            &[&repository_id],
        )
        .await
        .expect("count outbox rows for repository")
        .get(0)
}

/// A server wired with a `fenced_coordinator` unconditionally refuses `Lock`
/// and `Unlock` with `FAILED_PRECONDITION` and appends no outbox row, because
/// the refusal happens before the request ever reaches a store.
#[tokio::test]
#[ignore = "needs live Postgres env (LORE_TEST_PG_URL); run with -- --ignored"]
async fn armed_fenced_coordinator_refuses_lock_and_unlock_and_appends_nothing() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let domain_store = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
        .await
        .expect("connect domain store");
    let coordinator = domain_store.lock_coordinator();
    coordinator
        .bootstrap()
        .await
        .expect("install fenced lock schema");
    // Constructed against the same database purely to satisfy
    // `LoreLockService::new`'s required `Arc<dyn LockStore>` parameter; the
    // armed gate below refuses before this store is ever called.
    let lock_store = PostgresLockStore::connect(&url, 4, &TlsConfig::default())
        .await
        .expect("connect legacy lock store");
    let db = client(&url).await;
    let repository_id: [u8; 16] = rand::random();

    let service = LoreLockService::new(
        Arc::new(lock_store),
        Arc::new(NotificationSender::default()),
        Arc::new(HookDispatcher::empty()),
        Duration::from_secs(60),
        false,
    )
    .with_fenced_coordinator(Some(Arc::new(coordinator)));

    let lock_status = service
        .lock(request_with_repository(
            LockRequest {
                resources: vec![one_resource()],
            },
            &repository_id,
        ))
        .await
        .expect_err("an armed server must refuse Lock");
    assert_eq!(lock_status.code(), Code::FailedPrecondition);

    let unlock_status = service
        .unlock(request_with_repository(
            UnlockRequest {
                resources: vec![one_resource()],
            },
            &repository_id,
        ))
        .await
        .expect_err("an armed server must refuse Unlock");
    assert_eq!(unlock_status.code(), Code::FailedPrecondition);

    assert_eq!(
        outbox_row_count(&db, &repository_id).await,
        0,
        "a refused-before-any-store-call request must append nothing"
    );
}

/// A server with no `fenced_coordinator` (the legacy default) routes through
/// `PostgresLockStore` end to end: `Lock` succeeds and appends no CR-032
/// outbox row, because that store has no fence, no generation, and no domain
/// transaction to append inside.
#[tokio::test]
#[ignore = "needs live Postgres env (LORE_TEST_PG_URL); run with -- --ignored"]
async fn unarmed_legacy_route_succeeds_and_appends_nothing() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    // Only `lore_outbox_events` needs to exist for the assertion below; the
    // domain store itself plays no part in this test's Lock/Unlock flow,
    // which routes through the separate legacy `PostgresLockStore`.
    PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
        .await
        .expect("install outbox schema for the zero-row assertion");
    let lock_store = PostgresLockStore::connect(&url, 4, &TlsConfig::default())
        .await
        .expect("connect legacy lock store");
    let db = client(&url).await;
    let repository_id: [u8; 16] = rand::random();

    let service = LoreLockService::new(
        Arc::new(lock_store),
        Arc::new(NotificationSender::default()),
        Arc::new(HookDispatcher::empty()),
        Duration::from_secs(60),
        false,
    );

    let response = service
        .lock(request_with_repository(
            LockRequest {
                resources: vec![one_resource()],
            },
            &repository_id,
        ))
        .await
        .expect("an unarmed server must route Lock through the legacy store");
    assert_eq!(response.into_inner().locks.len(), 1);

    assert_eq!(
        outbox_row_count(&db, &repository_id).await,
        0,
        "the legacy lock_store path has no fence, no generation, and no domain transaction \
         to append an outbox row inside"
    );
}
