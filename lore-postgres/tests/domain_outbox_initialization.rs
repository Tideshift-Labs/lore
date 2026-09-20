// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! SERVER-only clean initialization. Each ignored case requires an empty database.
//! This tier attests database transitions. The operator tier proves provider namespace checks.

use async_trait::async_trait;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::backfill::BranchFacts;
use lore_postgres::domain::backfill::DomainBackfill;
use lore_postgres::domain::backfill::DomainBackfillSource;
use lore_postgres::domain::backfill::OrphanKey;
use lore_postgres::domain::backfill::RepositoryFacts;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::fragments::initialization::CleanCellInitialization;
use lore_postgres::domain::locks::BackfillIssuerMap;
use lore_postgres::domain::outbox::initialization::FreshEventInitialization;
use lore_postgres::domain::outbox::initialization::FreshEventInitializationOutcome;
use lore_postgres::domain::outbox::initialization::initialize_empty;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use tokio_postgres::Client;

fn input(sequence: i64) -> FreshEventInitialization {
    FreshEventInitialization::new("test-cell".into(), "test-stream".into(), 1, sequence).unwrap()
}

#[test]
fn event_initialization_input_rejects_invalid_identity_epoch_and_observation() {
    for (cell, stream, epoch, sequence) in [
        ("Bad Cell", "stream", 1, 0),
        ("cell", "", 1, 0),
        ("cell", "stream", 0, 0),
        ("cell", "stream", 1, -1),
        ("cell", "bad\nstream", 1, 0),
    ] {
        assert!(matches!(
            FreshEventInitialization::new(cell.into(), stream.into(), epoch, sequence),
            Err(DomainError::InvalidInput(_))
        ));
    }
    input(0);
    input(100);
}

async fn armed() -> (lore_postgres::pool::Pool, Client) {
    let (url, store, direct) = fixture(true).await;
    store
        .fragment_coordinator()
        .initialize_empty(&fragment_input())
        .await
        .unwrap();
    (build_pool(&url, 4, &TlsConfig::default()).unwrap(), direct)
}

async fn event_state(client: &Client) -> String {
    client.query_one("SELECT json_build_array((SELECT row_to_json(s) FROM lore_outbox_schema_state s),(SELECT json_agg(r) FROM lore_outbox_fresh_initialization r),(SELECT json_agg(m) FROM lore_outbox_membership_state m))::text",&[]).await.unwrap().get(0)
}

async fn publish_stage_policy(direct: &Client) {
    direct.batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_maintenance;
        SELECT stage_policy_publish_v1('test-cell','event-init-policy',decode(repeat('ab',32),'hex'),1048576,100,1048576,100,60000,4102444800000);
        RESET SESSION AUTHORIZATION;").await.unwrap();
}

#[tokio::test]
#[ignore = "owned empty PostgreSQL fixture required"]
async fn fresh_event_initialization_accepts_published_stage_policy_and_exact_zero_usage() {
    let (pool, direct) = armed().await;
    publish_stage_policy(&direct).await;
    let policy: String = direct
        .query_one(
            "SELECT row_to_json(p)::text FROM lore_fragment_stage_policy p",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        initialize_empty(&pool, &input(0)).await.unwrap(),
        FreshEventInitializationOutcome::Initialized
    );
    assert_eq!(
        direct
            .query_one(
                "SELECT row_to_json(p)::text FROM lore_fragment_stage_policy p",
                &[]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        policy
    );
    let row = direct.query_one("SELECT count(*),bool_and(singleton AND live_bytes=0 AND live_files=0 AND metadata_bytes=0 AND metadata_rows=0) FROM lore_fragment_stage_usage", &[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert!(row.get::<_, bool>(1));
    assert_eq!(
        initialize_empty(&pool, &input(0)).await.unwrap(),
        FreshEventInitializationOutcome::AlreadyInitialized
    );
}

#[tokio::test]
#[ignore = "owned empty PostgreSQL fixture required"]
async fn fresh_event_initialization_refuses_used_or_missing_stage_usage() {
    let (pool, direct) = armed().await;
    publish_stage_policy(&direct).await;
    for column in [
        "live_bytes",
        "live_files",
        "metadata_bytes",
        "metadata_rows",
    ] {
        direct
            .batch_execute(&format!("UPDATE lore_fragment_stage_usage SET {column}=1"))
            .await
            .unwrap();
        let before = event_state(&direct).await;
        let error = initialize_empty(&pool, &input(0)).await.unwrap_err();
        assert!(
            matches!(error, DomainError::NotReady(_)),
            "{column}: {error:?}"
        );
        assert!(error.to_string().contains("stage counters"), "{error:?}");
        assert_eq!(event_state(&direct).await, before);
        assert_eq!(
            direct
                .query_one(
                    &format!("SELECT {column} FROM lore_fragment_stage_usage"),
                    &[]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        direct
            .batch_execute(&format!("UPDATE lore_fragment_stage_usage SET {column}=0"))
            .await
            .unwrap();
    }
    direct
        .batch_execute("DELETE FROM lore_fragment_stage_usage")
        .await
        .unwrap();
    let before = event_state(&direct).await;
    let error = initialize_empty(&pool, &input(0)).await.unwrap_err();
    assert!(matches!(error, DomainError::NotReady(_)), "{error:?}");
    assert!(error.to_string().contains("stage counters"), "{error:?}");
    assert_eq!(event_state(&direct).await, before);
    assert_eq!(
        direct
            .query_one("SELECT count(*) FROM lore_fragment_stage_usage", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    direct
        .batch_execute("INSERT INTO lore_fragment_stage_usage(singleton) VALUES(true)")
        .await
        .unwrap();
    assert_eq!(
        initialize_empty(&pool, &input(0)).await.unwrap(),
        FreshEventInitializationOutcome::Initialized
    );
}

#[tokio::test]
#[ignore = "owned empty PostgreSQL fixture required"]
async fn fresh_event_initialization_refuses_retained_stage_custody() {
    let (pool, direct) = armed().await;
    publish_stage_policy(&direct).await;
    let url = std::env::var("LORE_TEST_PG_URL").unwrap();
    let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .unwrap();
    let coordinator = store.fragment_coordinator();
    let orphan = coordinator
        .begin_stage_cleanup(&[0x42; 32], 71)
        .await
        .unwrap()
        .unwrap();
    coordinator.commit_stage_cleanup(&orphan).await.unwrap();
    let before = event_state(&direct).await;
    let error = initialize_empty(&pool, &input(0)).await.unwrap_err();
    assert!(matches!(error, DomainError::NotReady(_)), "{error:?}");
    assert!(
        error.to_string().contains("lore_fragment_stage_custody"),
        "{error:?}"
    );
    assert_eq!(event_state(&direct).await, before);
    assert_eq!(
        direct
            .query_one("SELECT count(*) FROM lore_fragment_stage_custody", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
}

#[tokio::test]
#[ignore = "owned empty PostgreSQL fixture required"]
async fn fresh_event_initialization_is_atomic_repeatable_and_not_receiver_readiness() {
    let (pool, mut direct) = armed().await;
    assert_eq!(
        initialize_empty(&pool, &input(0)).await.unwrap(),
        FreshEventInitializationOutcome::Initialized
    );
    let repository = [1u8; 16];
    let aggregate = [2u8; 16];
    let version =
        lore_postgres::domain::outbox::version::AggregateVersion::ordinal_only(1).encode();
    let tx = direct.transaction().await.unwrap();
    lore_postgres::domain::outbox::append(
        &tx,
        &lore_postgres::domain::outbox::OutboxEvent {
            cell_id: "test-cell",
            repository_id: &repository,
            repository_generation: 1,
            event_kind: "branch.pushed",
            aggregate_kind: "branch",
            aggregate_id: &aggregate,
            aggregate_version: &version,
            payload_schema_version: 1,
            payload: b"{}",
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let before = event_state(&direct).await;
    assert_eq!(
        initialize_empty(&pool, &input(11)).await.unwrap(),
        FreshEventInitializationOutcome::AlreadyInitialized
    );
    assert_eq!(event_state(&direct).await, before);
    let ready: i64 = direct
        .query_one("SELECT count(*) FROM lore_outbox_receiver_membership", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(ready, 0, "initialization must not invent ready receivers");
}

#[tokio::test]
#[ignore = "owned empty PostgreSQL fixture required"]
async fn fresh_event_initialization_refuses_unarmed_retained_or_populated_state() {
    let (url, store, direct) = fixture(false).await;
    let pool = build_pool(&url, 4, &TlsConfig::default()).unwrap();
    assert!(matches!(
        initialize_empty(&pool, &input(0)).await,
        Err(DomainError::NotReady(_))
    ));
    drop(store);
    drop(pool);
    drop(direct);
    let (pool, direct) = armed().await;
    let before = event_state(&direct).await;
    assert!(matches!(
        initialize_empty(&pool, &input(1)).await,
        Err(DomainError::NotReady(_))
    ));
    assert_eq!(event_state(&direct).await, before);
    direct.batch_execute("CREATE TABLE lore_unexpected_retained (id integer); INSERT INTO lore_unexpected_retained VALUES (1)").await.unwrap();
    let error = initialize_empty(&pool, &input(0)).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("populated table lore_unexpected_retained")
    );
    assert_eq!(event_state(&direct).await, before);
}

#[tokio::test]
#[ignore = "owned empty PostgreSQL fixture required"]
async fn fresh_event_initialization_refuses_receipt_placement_and_contract_drift() {
    let (pool, direct) = armed().await;
    initialize_empty(&pool, &input(0)).await.unwrap();
    let before = event_state(&direct).await;
    let wrong =
        FreshEventInitialization::new("other-cell".into(), "test-stream".into(), 1, 0).unwrap();
    assert!(matches!(
        initialize_empty(&pool, &wrong).await,
        Err(DomainError::NotReady(_))
    ));
    assert_eq!(event_state(&direct).await, before);
    direct
        .batch_execute("UPDATE lore_outbox_membership_state SET current_placement_revision=2")
        .await
        .unwrap();
    assert!(matches!(
        initialize_empty(&pool, &input(0)).await,
        Err(DomainError::NotReady(_))
    ));
    direct
        .batch_execute("UPDATE lore_outbox_membership_state SET current_placement_revision=1")
        .await
        .unwrap();
    for (stream, epoch) in [("other-stream", 1), ("test-stream", 2)] {
        let wrong =
            FreshEventInitialization::new("test-cell".into(), stream.into(), epoch, 0).unwrap();
        assert!(matches!(
            initialize_empty(&pool, &wrong).await,
            Err(DomainError::NotReady(_))
        ));
        assert_eq!(event_state(&direct).await, before);
    }
    direct
        .batch_execute("UPDATE lore_domain_lock_schema_state SET fencing_enabled=false")
        .await
        .unwrap();
    assert!(matches!(
        initialize_empty(&pool, &input(0)).await,
        Err(DomainError::NotReady(_))
    ));
    direct.batch_execute("UPDATE lore_domain_lock_schema_state SET fencing_enabled=true; UPDATE lore_outbox_schema_state SET producer_compat_floor=999").await.unwrap();
    assert!(matches!(
        initialize_empty(&pool, &input(0)).await,
        Err(DomainError::NotReady(_))
    ));
}

#[tokio::test]
#[ignore = "owned empty PostgreSQL fixture required"]
async fn fresh_event_initialization_observes_a_contending_writer_before_stamping() {
    let (pool, direct) = armed().await;
    direct
        .batch_execute("CREATE TABLE lore_contending_retained (id integer)")
        .await
        .unwrap();
    direct
        .batch_execute("BEGIN; INSERT INTO lore_contending_retained VALUES (1)")
        .await
        .unwrap();
    let before = event_state(&direct).await;
    let observer = pool.get().await.unwrap();
    let input = input(0);
    let (result, ()) = tokio::join!(initialize_empty(&pool, &input), async {
        tokio::time::timeout(std::time::Duration::from_secs(4),async {
            loop {
                let waiting:bool=observer.query_one("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'LOCK TABLE %')",&[]).await.unwrap().get(0);
                if waiting { break; }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await.expect("database must attest initializer waiting on writer");
        direct.batch_execute("COMMIT").await.unwrap();
    });
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("populated table lore_contending_retained")
    );
    assert_eq!(event_state(&direct).await, before);
}

#[tokio::test]
#[ignore = "owned empty PostgreSQL fixture required"]
async fn fresh_event_initialization_refuses_lost_provenance() {
    let (pool, direct) = armed().await;
    initialize_empty(&pool, &input(0)).await.unwrap();
    direct
        .batch_execute("UPDATE lore_outbox_schema_state SET cutover_at=NULL")
        .await
        .unwrap();
    let before = event_state(&direct).await;
    assert!(matches!(
        initialize_empty(&pool, &input(0)).await,
        Err(DomainError::NotReady(_))
    ));
    assert_eq!(event_state(&direct).await, before);
    direct.batch_execute("UPDATE lore_outbox_schema_state SET cutover_at=(SELECT initialized_at FROM lore_outbox_fresh_initialization); DELETE FROM lore_outbox_fresh_initialization").await.unwrap();
    let before = event_state(&direct).await;
    assert!(matches!(
        initialize_empty(&pool, &input(0)).await,
        Err(DomainError::NotReady(_))
    ));
    assert_eq!(event_state(&direct).await, before);
}

#[tokio::test]
#[ignore = "owned empty PostgreSQL fixture required"]
async fn fresh_event_initialization_requires_membership_record_and_permanent_fences() {
    let (pool, direct) = armed().await;
    // Deliberate administrative corruption only inside this owned disposable database.
    direct.batch_execute("ALTER TABLE lore_fragment_membership_protocol DISABLE TRIGGER lore_membership_protocol_permanent; DELETE FROM lore_fragment_membership_protocol; ALTER TABLE lore_fragment_membership_protocol ENABLE ALWAYS TRIGGER lore_membership_protocol_permanent").await.unwrap();
    let before = event_state(&direct).await;
    assert!(
        initialize_empty(&pool, &input(0))
            .await
            .unwrap_err()
            .to_string()
            .contains("membership")
    );
    assert_eq!(event_state(&direct).await, before);
    direct
        .batch_execute("INSERT INTO lore_fragment_membership_protocol VALUES (1,1)")
        .await
        .unwrap();
    initialize_empty(&pool, &input(0)).await.unwrap();
    direct
        .batch_execute("ALTER TABLE lore_mutable DISABLE TRIGGER lore_membership_writer_fence")
        .await
        .unwrap();
    let before = event_state(&direct).await;
    assert!(
        initialize_empty(&pool, &input(0))
            .await
            .unwrap_err()
            .to_string()
            .contains("membership")
    );
    assert_eq!(event_state(&direct).await, before);
}

async fn client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .unwrap();
    lore_base::lore_spawn!(async move {
        connection.await.unwrap();
    });
    client
}

// The metadata source is synthetic at this crate boundary. Its emptiness is checked against
// the actual database before the supported domain/lock transitions are invoked.
struct EmptySource;

#[async_trait]
impl DomainBackfillSource for EmptySource {
    async fn list_repositories(&self) -> Result<Vec<RepositoryFacts>, DomainError> {
        Ok(vec![])
    }
    async fn list_branches(&self, _: &[u8]) -> Result<Vec<BranchFacts>, DomainError> {
        unreachable!()
    }
    async fn snapshot_token(&self, _: &[u8]) -> Result<Vec<u8>, DomainError> {
        unreachable!()
    }
    async fn orphan_projection_keys(&self) -> Result<Vec<OrphanKey>, DomainError> {
        Ok(vec![])
    }
}

async fn fixture(arm: bool) -> (String, PostgresDomainStore, Client) {
    let url = std::env::var("LORE_TEST_PG_URL").expect("isolated empty PostgreSQL required");
    let direct = client(&url).await;
    // Bootstrap grants procedure access only to roles that already exist.
    direct.batch_execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance; END IF; END $$;").await.unwrap();
    direct
        .batch_execute(include_str!("../migrations/0001_init.sql"))
        .await
        .unwrap();
    let store = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
        .await
        .unwrap();
    store.lock_coordinator().bootstrap().await.unwrap();
    store.fragment_coordinator().bootstrap().await.unwrap();
    if arm {
        assert_eq!(direct.query_one("SELECT (SELECT count(*) FROM lore_mutable) + (SELECT count(*) FROM lore_domain_repositories)", &[]).await.unwrap().get::<_, i64>(0), 0);
        let pool = build_pool(&url, 2, &TlsConfig::default()).unwrap();
        let backfill = DomainBackfill::new(&pool, &EmptySource);
        assert_eq!(backfill.run().await.unwrap(), 0);
        let verified = backfill.verify().await.unwrap();
        assert!(verified.passed());
        backfill.complete(&verified).await.unwrap();
        store
            .lock_coordinator()
            .backfill(&BackfillIssuerMap::new())
            .await
            .unwrap();
        store
            .lock_coordinator()
            .enable_fencing(false)
            .await
            .unwrap();
        store.enable_enforcement().await.unwrap();
    }
    (url, store, direct)
}

fn fragment_input() -> CleanCellInitialization {
    CleanCellInitialization::new(
        "local-test-empty-namespace".into(),
        "scoped-writer-v1".into(),
    )
    .unwrap()
}
