// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! SERVER-only clean initialization. Each ignored case requires an empty database.
//! This tier attests database transitions. The operator tier proves provider namespace checks.

use std::time::Duration;

use async_trait::async_trait;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::backfill::BranchFacts;
use lore_postgres::domain::backfill::DomainBackfill;
use lore_postgres::domain::backfill::DomainBackfillSource;
use lore_postgres::domain::backfill::OrphanKey;
use lore_postgres::domain::backfill::RepositoryFacts;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::fragments::initialization::CleanCellInitialization;
use lore_postgres::domain::fragments::initialization::CleanCellInitializationOutcome;
use lore_postgres::domain::locks::BackfillIssuerMap;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use tokio::time::timeout;
use tokio_postgres::Client;
use tokio_postgres::IsolationLevel;

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

fn input() -> CleanCellInitialization {
    CleanCellInitialization::new(
        "local-test-empty-namespace".into(),
        "scoped-writer-v1".into(),
    )
    .unwrap()
}

async fn state(direct: &Client) -> String {
    direct
        .query_one(
            "SELECT row_to_json(s)::text FROM lore_fragment_schema_state s",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

async fn assert_dark(store: &PostgresDomainStore) {
    let coordinator = store.fragment_coordinator();
    let readiness = coordinator.readiness().await.unwrap();
    assert!(!readiness.clean_initialized);
    assert!(!readiness.lifecycle_enabled);
    assert!(!readiness.ready_for_lifecycle());
    assert!(!coordinator.push_membership_enabled().await.unwrap());
}

#[test]
fn clean_initialization_identity_rejects_empty_values() {
    assert!(CleanCellInitialization::new(String::new(), "writer".into()).is_err());
    assert!(CleanCellInitialization::new("namespace".into(), String::new()).is_err());
    assert!(CleanCellInitialization::new("namespace".into(), "writer".into()).is_ok());
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn empty_initialization_establishes_readiness_without_claiming_backfill() {
    let (_, store, direct) = fixture(true).await;
    let usage = direct.query_one("SELECT count(*), bool_and(singleton AND live_bytes=0 AND live_files=0 AND metadata_bytes=0 AND metadata_rows=0) FROM lore_fragment_stage_usage", &[]).await.unwrap();
    assert_eq!(usage.get::<_, i64>(0), 1);
    assert!(usage.get::<_, bool>(1));
    assert_dark(&store).await;
    let coordinator = store.fragment_coordinator();
    assert_eq!(
        coordinator.initialize_empty(&input()).await.unwrap(),
        CleanCellInitializationOutcome::Initialized
    );
    let readiness = coordinator.readiness().await.unwrap();
    assert!(readiness.clean_initialized);
    assert!(readiness.lifecycle_enabled);
    assert!(readiness.ready_for_lifecycle());
    assert!(coordinator.push_membership_enabled().await.unwrap());
    let row = direct.query_one("SELECT backfill_state, backfill_version, backfill_cursor, verified_fragments FROM lore_fragment_schema_state", &[]).await.unwrap();
    assert_eq!(row.get::<_, i16>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(2), None);
    assert_eq!(row.get::<_, i64>(3), 0);
    let before = state(&direct).await;
    assert_eq!(
        coordinator.initialize_empty(&input()).await.unwrap(),
        CleanCellInitializationOutcome::AlreadyInitialized
    );
    assert_eq!(
        state(&direct).await,
        before,
        "rerun must preserve durable initialization evidence"
    );
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn used_or_missing_stage_counter_seed_refuses_clean_initialization() {
    let (_, store, direct) = fixture(true).await;
    let coordinator = store.fragment_coordinator();
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
        let before = state(&direct).await;
        let error = coordinator.initialize_empty(&input()).await.unwrap_err();
        assert!(
            matches!(error, DomainError::NotReady(_)),
            "{column}: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("used counter seed lore_fragment_stage_usage"),
            "{error:?}"
        );
        assert_eq!(state(&direct).await, before);
        assert_dark(&store).await;
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
    let before = state(&direct).await;
    let error = coordinator.initialize_empty(&input()).await.unwrap_err();
    assert!(matches!(error, DomainError::NotReady(_)), "{error:?}");
    assert!(
        error
            .to_string()
            .contains("used counter seed lore_fragment_stage_usage"),
        "{error:?}"
    );
    assert_eq!(state(&direct).await, before);
    assert_dark(&store).await;
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
        coordinator.initialize_empty(&input()).await.unwrap(),
        CleanCellInitializationOutcome::Initialized
    );
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn missing_domain_and_lock_prerequisites_leave_initialization_dark() {
    let (_, store, direct) = fixture(false).await;
    let before = state(&direct).await;
    let error = store
        .fragment_coordinator()
        .initialize_empty(&input())
        .await
        .unwrap_err();
    assert!(matches!(error, DomainError::NotReady(_)), "{error:?}");
    assert!(error.to_string().contains("domain and lock cutover"));
    assert_eq!(state(&direct).await, before);
    assert_dark(&store).await;
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn every_legacy_store_residue_refuses_without_erasing_data() {
    let (_, store, direct) = fixture(true).await;
    for (table, insert) in [
        (
            "lore_fragments",
            "INSERT INTO lore_fragments VALUES ('\\x01','\\x02','\\x03')",
        ),
        (
            "lore_fragment_state",
            "INSERT INTO lore_fragment_state VALUES ('\\x01',256)",
        ),
        (
            "lore_fragment_metering",
            "INSERT INTO lore_fragment_metering VALUES ('\\x01',0,0,0)",
        ),
        (
            "lore_mutable",
            "INSERT INTO lore_mutable VALUES ('\\x01',0,'\\x02','\\x03')",
        ),
        (
            "lore_locks",
            "INSERT INTO lore_locks (repository,branch,hash,owner,description,locked_at) VALUES (decode(repeat('01',16),'hex'),decode(repeat('02',16),'hex'),'\\x03','owner','old',0)",
        ),
    ] {
        direct.batch_execute(insert).await.unwrap();
        let before = state(&direct).await;
        let error = store
            .fragment_coordinator()
            .initialize_empty(&input())
            .await
            .unwrap_err();
        assert!(
            matches!(error, DomainError::NotReady(_)),
            "{table}: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains(&format!("populated table {table}")),
            "{error:?}"
        );
        assert_eq!(state(&direct).await, before);
        assert_eq!(
            direct
                .query_one(&format!("SELECT count(*) FROM {table}"), &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        assert_dark(&store).await;
        direct
            .batch_execute(&format!("DELETE FROM {table}"))
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .fragment_coordinator()
            .initialize_empty(&input())
            .await
            .unwrap(),
        CleanCellInitializationOutcome::Initialized
    );
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn used_global_proof_counter_seed_cannot_be_mistaken_for_empty_schema() {
    let (_, store, direct) = fixture(true).await;
    direct
        .batch_execute("UPDATE lore_domain_proof_global_counters SET counter_revision=1")
        .await
        .unwrap();
    let error = store
        .fragment_coordinator()
        .initialize_empty(&input())
        .await
        .unwrap_err();
    assert!(matches!(error, DomainError::NotReady(_)), "{error:?}");
    assert!(error.to_string().contains("counter seed"), "{error:?}");
    assert_eq!(
        direct
            .query_one(
                "SELECT counter_revision FROM lore_domain_proof_global_counters",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_dark(&store).await;
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn lifecycle_tombstone_residue_is_not_an_empty_cell() {
    let (_, store, direct) = fixture(true).await;
    direct.batch_execute("INSERT INTO lore_fragment_lifecycle (hash,current_epoch,state,last_fence) VALUES ('\\x01',1,8,1)").await.unwrap();
    let error = store
        .fragment_coordinator()
        .initialize_empty(&input())
        .await
        .unwrap_err();
    assert!(matches!(error, DomainError::NotReady(_)), "{error:?}");
    assert!(
        error
            .to_string()
            .contains("populated table lore_fragment_lifecycle"),
        "{error:?}"
    );
    assert_eq!(
        direct
            .query_one("SELECT state FROM lore_fragment_lifecycle", &[])
            .await
            .unwrap()
            .get::<_, i16>(0),
        8
    );
    assert_dark(&store).await;
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn unverified_backfill_cursor_cannot_be_relabelled_as_clean_initialization() {
    let (_, store, _) = fixture(true).await;
    let coordinator = store.fragment_coordinator();
    coordinator.advance_backfill_cursor(1).await.unwrap();
    let error = coordinator.initialize_empty(&input()).await.unwrap_err();
    assert!(matches!(error, DomainError::NotReady(_)), "{error:?}");
    assert!(error.to_string().contains("migration state"), "{error:?}");
    assert_dark(&store).await;
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn exact_rerun_preserves_later_data_but_rejects_changed_identity_and_damaged_fences() {
    let (_, store, direct) = fixture(true).await;
    let coordinator = store.fragment_coordinator();
    coordinator.initialize_empty(&input()).await.unwrap();
    direct.batch_execute("INSERT INTO lore_fragment_lifecycle (hash,current_epoch,state,last_fence) VALUES ('\\x01',1,8,nextval('lore_fragment_fence_seq'))").await.unwrap();
    let before = state(&direct).await;
    assert_eq!(
        coordinator.initialize_empty(&input()).await.unwrap(),
        CleanCellInitializationOutcome::AlreadyInitialized
    );
    for changed in [
        CleanCellInitialization::new("another-namespace".into(), "scoped-writer-v1".into())
            .unwrap(),
        CleanCellInitialization::new("local-test-empty-namespace".into(), "another-writer".into())
            .unwrap(),
    ] {
        assert!(coordinator.initialize_empty(&changed).await.is_err());
        assert_eq!(state(&direct).await, before);
    }
    direct
        .batch_execute("ALTER TABLE lore_fragments DISABLE TRIGGER lore_membership_writer_fence")
        .await
        .unwrap();
    assert!(
        coordinator.initialize_empty(&input()).await.is_err(),
        "exact rerun must attest installed fences"
    );
    assert_eq!(
        direct
            .query_one("SELECT count(*) FROM lore_fragment_lifecycle", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn preexisting_repeatable_read_snapshot_and_prepared_writer_are_fenced() {
    let (url, store, _) = fixture(true).await;
    let mut old = client(&url).await;
    let prepared = old
        .prepare("INSERT INTO lore_fragments VALUES ('\\x01','\\x02','\\x03')")
        .await
        .unwrap();
    let tx = old
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .start()
        .await
        .unwrap();
    // Establish a snapshot without retaining a table read lock which the offline
    // initializer must drain. The later protocol query independently proves staleness.
    assert!(
        !tx.query_one("SELECT txid_current_snapshot()::text", &[])
            .await
            .unwrap()
            .get::<_, String>(0)
            .is_empty()
    );
    store
        .fragment_coordinator()
        .initialize_empty(&input())
        .await
        .unwrap();
    assert_eq!(
        tx.query_one(
            "SELECT count(*) FROM lore_fragment_membership_protocol",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0,
        "snapshot must actually predate initialization"
    );
    let error = tx.execute(&prepared, &[]).await.unwrap_err();
    let db = error.as_db_error().unwrap();
    assert_eq!(db.code().code(), "55000");
    assert_eq!(db.message(), "membership_writer_protocol_required");
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn clean_readiness_refuses_a_disabled_permanent_legacy_fence() {
    let (_, store, direct) = fixture(true).await;
    let coordinator = store.fragment_coordinator();
    coordinator.initialize_empty(&input()).await.unwrap();
    assert!(coordinator.readiness().await.unwrap().ready_for_lifecycle());
    direct
        .batch_execute("ALTER TABLE lore_fragment_state DISABLE TRIGGER lore_clean_legacy_fence")
        .await
        .unwrap();
    let error = coordinator.readiness().await.unwrap_err();
    assert!(matches!(error, DomainError::NotReady(_)), "{error:?}");
    assert!(error.to_string().contains("permanent fence"));
    assert!(coordinator.initialize_empty(&input()).await.is_err());
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn initialized_cell_excludes_legacy_state_writes_and_readiness_rollback() {
    let (_, store, direct) = fixture(true).await;
    store
        .fragment_coordinator()
        .initialize_empty(&input())
        .await
        .unwrap();
    let before = state(&direct).await;
    for sql in [
        "INSERT INTO lore_fragment_state VALUES ('\\x01',0)",
        "INSERT INTO lore_fragment_metering VALUES ('\\x01',0,0,0)",
        "TRUNCATE lore_fragment_state",
        "TRUNCATE lore_fragment_metering",
        "DELETE FROM lore_fragment_schema_state",
        "TRUNCATE lore_fragment_schema_state",
        "UPDATE lore_fragment_schema_state SET lifecycle_enabled=false",
    ] {
        let error = direct.batch_execute(sql).await.unwrap_err();
        let db = error.as_db_error().unwrap();
        assert_eq!(db.code().code(), "55000", "{sql}: {error:?}");
        assert_eq!(db.message(), "clean_initialization_permanent_fence");
        assert_eq!(state(&direct).await, before);
    }
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn commit_failure_rolls_back_readiness_and_membership_fences_together() {
    let (_, store, direct) = fixture(true).await;
    direct.batch_execute("CREATE SEQUENCE test_commit_attempt;
        CREATE TABLE test_commit_barrier (marker boolean);
        CREATE FUNCTION enqueue_clean_init_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO test_commit_barrier VALUES (true); RETURN NEW; END $$;
        CREATE TRIGGER enqueue_clean_init_commit AFTER UPDATE ON lore_fragment_schema_state FOR EACH ROW EXECUTE FUNCTION enqueue_clean_init_commit();
        CREATE FUNCTION reject_clean_init_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('test_commit_attempt'); RAISE EXCEPTION 'test_clean_init_commit_failure'; END $$;
        CREATE CONSTRAINT TRIGGER reject_clean_init_commit AFTER INSERT ON test_commit_barrier DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_clean_init_commit()")
        .await.unwrap();
    let before = state(&direct).await;
    let error = store
        .fragment_coordinator()
        .initialize_empty(&input())
        .await
        .unwrap_err();
    assert!(matches!(error, DomainError::OutcomeUnknown(_)), "{error:?}");
    // Sequence increments survive rollback and prove the deferred trigger ran at COMMIT.
    assert!(
        direct
            .query_one("SELECT is_called FROM test_commit_attempt", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert_eq!(state(&direct).await, before);
    assert_dark(&store).await;
    assert_eq!(direct.query_one("SELECT count(*) FROM pg_trigger WHERE tgname IN ('lore_membership_writer_fence','lore_membership_truncate_fence')", &[]).await.unwrap().get::<_, i64>(0), 0);
    direct.batch_execute("DROP TRIGGER enqueue_clean_init_commit ON lore_fragment_schema_state; DROP FUNCTION enqueue_clean_init_commit(); DROP TABLE test_commit_barrier; DROP FUNCTION reject_clean_init_commit()").await.unwrap();
    assert_eq!(
        store
            .fragment_coordinator()
            .initialize_empty(&input())
            .await
            .unwrap(),
        CleanCellInitializationOutcome::Initialized
    );
}

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn cancellation_while_waiting_for_prior_writers_leaves_a_safe_rerun() {
    let (url, store, direct) = fixture(true).await;
    let mut old = client(&url).await;
    let tx = old.transaction().await.unwrap();
    tx.batch_execute("LOCK TABLE lore_fragments IN ROW EXCLUSIVE MODE")
        .await
        .unwrap();
    let pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let coordinator = store.fragment_coordinator();
    let request = input();
    let initialize = coordinator.initialize_empty(&request);
    tokio::pin!(initialize);
    let observed = async {
        timeout(Duration::from_secs(10), async {
            loop {
                let blocked: bool = direct.query_one("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) AND wait_event_type='Lock')", &[&pid]).await.unwrap().get(0);
                if blocked { return; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("initializer must visibly wait for old writer table lock");
    };
    tokio::select! {
        result = &mut initialize => panic!("initializer escaped the old writer: {result:?}"),
        () = observed => {},
    }
    // Cancel the backend, not merely the Future: PostgreSQL may continue a sent query after
    // a Rust future is dropped. The initializer must observe cancellation and roll back.
    direct.execute("SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) AND wait_event_type='Lock'", &[&pid]).await.unwrap();
    assert!(
        timeout(Duration::from_secs(10), initialize)
            .await
            .unwrap()
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert_dark(&store).await;
    assert_eq!(
        coordinator.initialize_empty(&request).await.unwrap(),
        CleanCellInitializationOutcome::Initialized
    );
}

#[path = "common/clean_init_commit_proxy.rs"]
mod commit_proxy;

#[tokio::test]
#[ignore = "isolated empty PostgreSQL required"]
async fn committed_initialization_with_lost_ack_is_reconciled_by_exact_rerun() {
    let (url, store, direct) = fixture(true).await;
    let parsed: tokio_postgres::Config = url.parse().unwrap();
    let host = match &parsed.get_hosts()[0] {
        tokio_postgres::config::Host::Tcp(host) => host.clone(),
        #[cfg(unix)]
        tokio_postgres::config::Host::Unix(_) => panic!("TCP fixture required"),
    };
    let port = parsed.get_ports().first().copied().unwrap_or(5432);
    let proxy = commit_proxy::LostCommitProxy::start(format!("{host}:{port}")).await;
    let proxy_url = format!(
        "postgresql://postgres@127.0.0.1:{}/{}?sslmode=disable",
        proxy.port,
        parsed.get_dbname().unwrap()
    );
    let proxied = PostgresDomainStore::connect(&proxy_url, 1, &TlsConfig::default())
        .await
        .unwrap();
    // Arm only after pool/bootstrap commits finish. The next COMMIT belongs to initialize_empty.
    proxy.drop_next_commit_response();
    let error = timeout(
        Duration::from_secs(15),
        proxied.fragment_coordinator().initialize_empty(&input()),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        proxy.fault_fired(),
        "proxy must have observed PostgreSQL's committed response"
    );
    assert!(matches!(error, DomainError::OutcomeUnknown(_)), "{error:?}");
    // Independent original connection proves the commit landed; no row state is hand-patched.
    let readiness = store.fragment_coordinator().readiness().await.unwrap();
    assert!(readiness.clean_initialized && readiness.ready_for_lifecycle());
    assert!(
        store
            .fragment_coordinator()
            .push_membership_enabled()
            .await
            .unwrap()
    );
    let before = state(&direct).await;
    assert_eq!(
        store
            .fragment_coordinator()
            .initialize_empty(&input())
            .await
            .unwrap(),
        CleanCellInitializationOutcome::AlreadyInitialized
    );
    assert_eq!(
        state(&direct).await,
        before,
        "rerun must adopt exact durable commit evidence"
    );
    assert_eq!(
        proxied
            .fragment_coordinator()
            .initialize_empty(&input())
            .await
            .unwrap(),
        CleanCellInitializationOutcome::AlreadyInitialized,
        "lost connection pool must reconnect and adopt committed state"
    );
}
