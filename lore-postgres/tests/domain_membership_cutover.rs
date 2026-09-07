// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Database writer cutover. Each ignored case needs its own empty PostgreSQL database.

use std::time::Duration;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::BranchPushCommitInput;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::ProjectionWrite;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::fragments::CommitVerdict;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use tokio::time::timeout;
use tokio_postgres::Client;
use tokio_postgres::IsolationLevel;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

const REPOSITORY: [u8; 16] = [1; 16];
const HASH: [u8; 32] = [2; 32];
const CONTEXT: [u8; 16] = [3; 16];
const LEGACY_INSERT: &str = "INSERT INTO lore_fragments VALUES ('\\x02', '\\x01', '\\x03')";
const ASSOCIATION_INSERT: &str = "INSERT INTO lore_fragment_associations (hash, repository_id, context, association_epoch, state, repository_generation) VALUES ('\\x02', decode(repeat('01',16),'hex'), '\\x03', 1, 0, 1)";
const MUTABLE_INSERT: &str = "INSERT INTO lore_mutable VALUES ('\\x01', 3, '\\x03', '\\x02')";

async fn client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .unwrap();
    lore_base::lore_spawn!(async move {
        connection.await.unwrap();
    });
    client
}

async fn fixture() -> (String, PostgresDomainStore, Client) {
    let url = std::env::var("LORE_TEST_PG_URL").expect("isolated PostgreSQL required");
    let direct = client(&url).await;
    direct
        .batch_execute(include_str!("../migrations/0001_init.sql"))
        .await
        .unwrap();
    let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .unwrap();
    direct.execute("INSERT INTO lore_domain_repositories (repository_id,state,generation,name,metadata_hash,default_branch_id,creation_fingerprint_version,creation_fingerprint,created_at) VALUES ($1,0,1,'cutover',$2,$1,1,$2,clock_timestamp())", &[&REPOSITORY.as_slice(), &HASH.as_slice()]).await.unwrap();
    direct.execute("INSERT INTO lore_domain_branches (repository_id,branch_id,repository_generation,state,generation,name,metadata_hash,latest_hash,creation_fingerprint_version,creation_fingerprint,created_at) VALUES ($1,$1,1,0,1,'main',$2,$2,1,$2,clock_timestamp())", &[&REPOSITORY.as_slice(), &HASH.as_slice()]).await.unwrap();
    ready(&direct).await;
    (url, store, direct)
}

async fn ready(direct: &Client) {
    // This fixture models completed prerequisite maintenance, without provider traffic.
    direct.batch_execute("UPDATE lore_domain_schema_state SET backfill_state=3, cutover_at=clock_timestamp(), enforcement_enabled = true;
        UPDATE lore_domain_lock_schema_state SET backfill_state=2, cutover_at=clock_timestamp(), sequence_headroom_fence=1, fencing_enabled=true;
        UPDATE lore_fragment_schema_state SET backfill_state=3, residue_classified=true,
        cutover_at=clock_timestamp(), sequence_headroom_fence=1, lifecycle_enabled=true,
        write_capability=1, provider_write_authority_revision='cutover-test',
        write_claims_required_at=clock_timestamp()").await.unwrap();
}

fn refused(error: tokio_postgres::Error) {
    let error = error.as_db_error().expect("database refusal");
    assert_eq!(error.code().code(), "55000");
    assert_eq!(error.message(), "membership_writer_protocol_required");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn activation_drains_an_old_writer_before_committing_the_protocol() {
    let (url, store, observer) = fixture().await;
    let mut old = client(&url).await;
    let tx = old.transaction().await.unwrap();
    tx.batch_execute(LEGACY_INSERT).await.unwrap();
    let old_pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let coordinator = store.fragment_coordinator();
    let activate = coordinator.activate_push_membership();
    let observe = async {
        timeout(Duration::from_secs(10), async {
            loop {
                let blocked: bool = observer.query_one("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) AND wait_event_type='Lock')", &[&old_pid]).await.unwrap().get(0);
                if blocked { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("activation must visibly wait for old DML");
        let active: bool = observer
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM lore_fragment_membership_protocol)",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(!active);
        tx.commit().await.unwrap();
    };
    let (activated, ()) = timeout(Duration::from_secs(15), async {
        tokio::join!(activate, observe)
    })
    .await
    .unwrap();
    activated.unwrap();
    assert!(coordinator.push_membership_enabled().await.unwrap());
    refused(
        old.batch_execute("DELETE FROM lore_fragments")
            .await
            .unwrap_err(),
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn old_snapshots_and_cached_statements_cannot_write_after_activation() {
    let (url, store, _) = fixture().await;
    let mut old = client(&url).await;
    let mut old_publication = client(&url).await;
    let publication = old_publication
        .prepare("UPDATE lore_domain_branches SET latest_hash=decode(repeat('09',32),'hex')")
        .await
        .unwrap();
    let publication_tx = old_publication
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .start()
        .await
        .unwrap();
    assert_eq!(
        publication_tx
            .query_one(
                "SELECT count(*) FROM lore_fragment_membership_protocol",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    // Prepare outside the transaction, so no table lock blocks activation.
    let prepared = old.prepare(LEGACY_INSERT).await.unwrap();
    let tx = old
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .start()
        .await
        .unwrap();
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM lore_fragment_membership_protocol",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    store
        .fragment_coordinator()
        .activate_push_membership()
        .await
        .unwrap();
    let stale_count: i64 = tx
        .query_one(
            "SELECT count(*) FROM lore_fragment_membership_protocol",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stale_count, 0, "this must actually be a stale snapshot");
    refused(tx.execute(&prepared, &[]).await.unwrap_err());
    tx.rollback().await.unwrap();
    refused(old.execute(&prepared, &[]).await.unwrap_err());
    assert_eq!(
        publication_tx
            .query_one(
                "SELECT count(*) FROM lore_fragment_membership_protocol",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    refused(publication_tx.execute(&publication, &[]).await.unwrap_err());
    publication_tx.rollback().await.unwrap();
    assert_eq!(
        old_publication
            .query_one("SELECT latest_hash FROM lore_domain_branches", &[])
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0),
        HASH
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn unmarked_legacy_association_and_publication_writes_are_denied() {
    let (_, store, direct) = fixture().await;
    direct.batch_execute(LEGACY_INSERT).await.unwrap();
    direct.batch_execute(ASSOCIATION_INSERT).await.unwrap();
    direct.batch_execute(MUTABLE_INSERT).await.unwrap();
    store
        .fragment_coordinator()
        .activate_push_membership()
        .await
        .unwrap();
    for sql in [
        "INSERT INTO lore_fragments VALUES ('\\x04','\\x01','\\x03')",
        "UPDATE lore_fragments SET context='\\x04'",
        "DELETE FROM lore_fragments",
        "INSERT INTO lore_fragment_associations (hash,repository_id,context,association_epoch,state,repository_generation) VALUES ('\\x04',decode(repeat('01',16),'hex'),'\\x03',1,0,1)",
        "UPDATE lore_fragment_associations SET state=1",
        "DELETE FROM lore_fragment_associations",
        "INSERT INTO lore_mutable VALUES ('\\x01',3,'\\x04','\\x02')",
        "UPDATE lore_mutable SET value='\\x04'",
        "DELETE FROM lore_mutable",
        "UPDATE lore_domain_branches SET latest_hash=decode(repeat('04',32),'hex')",
        "TRUNCATE lore_fragments",
        "TRUNCATE lore_fragment_associations",
        "TRUNCATE lore_mutable",
        "TRUNCATE lore_domain_branches CASCADE",
    ] {
        refused(direct.batch_execute(sql).await.unwrap_err());
    }
    direct
        .batch_execute("INSERT INTO lore_mutable VALUES ('\\x01',0,'\\x03','\\x02')")
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn upgraded_associations_advance_counters_and_transaction_markers_do_not_leak() {
    let (url, store, _) = fixture().await;
    let coordinator = store.fragment_coordinator();
    coordinator.activate_push_membership().await.unwrap();
    assert_eq!(
        coordinator
            .create_association(&HASH, &REPOSITORY, &CONTEXT)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    let before = coordinator
        .capture_push_witness(&REPOSITORY)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.content_membership_invalidation_generation, 0);
    assert_eq!(
        coordinator
            .tombstone_association(&HASH, &REPOSITORY, &CONTEXT)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    let after = coordinator
        .capture_push_witness(&REPOSITORY)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.content_membership_invalidation_generation, 1);
    assert_eq!(
        after.content_association_generation,
        before.content_association_generation + 1
    );
    // A one-connection pool proves reuse of the same backend after SET LOCAL.
    let pool = build_pool(&url, 1, &TlsConfig::default()).unwrap();
    let mut connection = pool.get().await.unwrap();
    let pid: i32 = connection
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let tx = connection.transaction().await.unwrap();
    tx.batch_execute("SELECT set_config('lore.membership_writer_protocol','1',true); SELECT set_config('lore.membership_publication_protocol','1',true)").await.unwrap();
    tx.commit().await.unwrap();
    drop(connection);
    let reused = pool.get().await.unwrap();
    assert_eq!(
        reused
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get::<_, i32>(0),
        pid
    );
    refused(reused.batch_execute(ASSOCIATION_INSERT).await.unwrap_err());
    refused(reused.batch_execute(MUTABLE_INSERT).await.unwrap_err());
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn rollback_cannot_remove_the_protocol_and_damaged_fences_refuse_readiness() {
    let (_, store, direct) = fixture().await;
    let coordinator = store.fragment_coordinator();
    coordinator.activate_push_membership().await.unwrap();
    direct.batch_execute("UPDATE lore_domain_schema_state SET enforcement_enabled=false; UPDATE lore_fragment_schema_state SET lifecycle_enabled=false").await.unwrap();
    for sql in [
        "DELETE FROM lore_fragment_membership_protocol",
        "UPDATE lore_fragment_membership_protocol SET revision=1",
        "TRUNCATE lore_fragment_membership_protocol",
        LEGACY_INSERT,
    ] {
        refused(direct.batch_execute(sql).await.unwrap_err());
    }
    assert!(coordinator.push_membership_enabled().await.unwrap());
    direct
        .batch_execute("ALTER TABLE lore_fragments DISABLE TRIGGER lore_membership_writer_fence")
        .await
        .unwrap();
    assert_eq!(
        coordinator.push_membership_enabled().await,
        Err(DomainError::Internal(
            "membership protocol fence is missing or disabled".to_owned()
        ))
    );
    direct.batch_execute("CREATE OR REPLACE TRIGGER lore_membership_writer_fence BEFORE INSERT ON lore_fragments FOR EACH ROW EXECUTE FUNCTION lore_membership_writer_guard(); ALTER TABLE lore_fragments ENABLE ALWAYS TRIGGER lore_membership_writer_fence").await.unwrap();
    assert_eq!(
        coordinator.push_membership_enabled().await,
        Err(DomainError::Internal(
            "membership protocol fence is missing or disabled".to_owned()
        )),
        "an INSERT-only fence does not protect old DELETE writers"
    );
    direct.batch_execute("CREATE OR REPLACE TRIGGER lore_membership_writer_fence BEFORE INSERT OR UPDATE OR DELETE ON lore_fragments FOR EACH ROW EXECUTE FUNCTION lore_membership_writer_guard(); ALTER TABLE lore_fragments ENABLE ALWAYS TRIGGER lore_membership_writer_fence; DROP TRIGGER lore_membership_protocol_permanent ON lore_fragment_membership_protocol").await.unwrap();
    assert_eq!(
        coordinator.push_membership_enabled().await,
        Err(DomainError::Internal(
            "membership protocol fence is missing or disabled".to_owned()
        )),
        "the permanent protocol record needs its own fence"
    );
    direct.batch_execute("CREATE TRIGGER lore_membership_protocol_permanent BEFORE UPDATE OR DELETE ON lore_fragment_membership_protocol FOR EACH ROW EXECUTE FUNCTION lore_membership_writer_guard(); ALTER TABLE lore_fragment_membership_protocol ENABLE ALWAYS TRIGGER lore_membership_protocol_permanent").await.unwrap();
    assert!(coordinator.push_membership_enabled().await.unwrap());
    direct.batch_execute("CREATE OR REPLACE TRIGGER lore_membership_writer_fence BEFORE INSERT OR UPDATE OF state OR DELETE ON lore_fragment_associations FOR EACH ROW EXECUTE FUNCTION lore_membership_writer_guard(); ALTER TABLE lore_fragment_associations ENABLE ALWAYS TRIGGER lore_membership_writer_fence").await.unwrap();
    let narrowed = direct.query_one("SELECT tgtype, tgattr <> ''::int2vector FROM pg_trigger WHERE tgrelid='lore_fragment_associations'::regclass AND tgname='lore_membership_writer_fence'", &[]).await.unwrap();
    assert_eq!(
        narrowed.get::<_, i16>(0),
        31,
        "column restrictions leave the event mask unchanged"
    );
    assert!(
        narrowed.get::<_, bool>(1),
        "the fixture must restrict UPDATE to named columns"
    );
    assert_eq!(
        coordinator.push_membership_enabled().await,
        Err(DomainError::Internal(
            "membership protocol fence is missing or disabled".to_owned()
        )),
        "UPDATE OF state leaves an association epoch replacement unprotected"
    );
    direct.batch_execute("CREATE OR REPLACE TRIGGER lore_membership_writer_fence BEFORE INSERT OR UPDATE OR DELETE ON lore_fragment_associations FOR EACH ROW EXECUTE FUNCTION lore_membership_writer_guard(); ALTER TABLE lore_fragment_associations ENABLE ALWAYS TRIGGER lore_membership_writer_fence").await.unwrap();
    assert!(coordinator.push_membership_enabled().await.unwrap());
    direct
        .batch_execute("DROP TRIGGER lore_membership_truncate_fence ON lore_fragment_associations")
        .await
        .unwrap();
    assert_eq!(
        coordinator.push_membership_enabled().await,
        Err(DomainError::Internal(
            "membership protocol fence is missing or disabled".to_owned()
        ))
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn installed_fences_with_missing_protocol_evidence_fail_closed() {
    let (_, store, direct) = fixture().await;
    let coordinator = store.fragment_coordinator();
    coordinator.activate_push_membership().await.unwrap();
    // Administrator damage injection, not an authorized rollback path.
    direct.batch_execute("ALTER TABLE lore_fragment_membership_protocol DISABLE TRIGGER lore_membership_protocol_permanent; DELETE FROM lore_fragment_membership_protocol; ALTER TABLE lore_fragment_membership_protocol ENABLE ALWAYS TRIGGER lore_membership_protocol_permanent").await.unwrap();
    assert_eq!(
        coordinator.push_membership_enabled().await,
        Err(DomainError::Internal(
            "membership fences exist without the protocol record".to_owned()
        )),
        "an empty record must not report the pre-install dark state"
    );
    direct
        .batch_execute("DROP TABLE lore_fragment_membership_protocol")
        .await
        .unwrap();
    assert_eq!(
        coordinator.push_membership_enabled().await,
        Err(DomainError::Internal(
            "membership fences exist without the protocol record".to_owned()
        )),
        "remaining fences with no record table must not report dark"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn activation_requires_all_readiness_prerequisites() {
    let (_, store, direct) = fixture().await;
    let coordinator = store.fragment_coordinator();
    for sql in [
        "UPDATE lore_domain_schema_state SET enforcement_enabled=false",
        "UPDATE lore_domain_lock_schema_state SET fencing_enabled=false",
        "UPDATE lore_fragment_schema_state SET lifecycle_enabled=false",
        "UPDATE lore_fragment_schema_state SET write_capability=0, provider_write_authority_revision=NULL, write_claims_required_at=NULL",
    ] {
        ready(&direct).await;
        direct.batch_execute(sql).await.unwrap();
        assert!(coordinator.activate_push_membership().await.is_err());
        assert!(!coordinator.push_membership_enabled().await.unwrap());
    }
    ready(&direct).await;
    coordinator.activate_push_membership().await.unwrap();
    assert!(coordinator.push_membership_enabled().await.unwrap());
}

async fn admitted(store: &PostgresDomainStore) -> GovernedOperation {
    let clock = store
        .domain_operation_clock_get()
        .await
        .unwrap()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap();
    let key = ReceiptKey {
        verified_issuer: "https://cutover.test".to_owned(),
        authenticated_subject: "cutover".to_owned(),
        tenant_scope_key: Uuid::now_v7().as_bytes().to_vec(),
        operation_id: Uuid::new_v7(Timestamp::from_unix(
            NoContext,
            clock.as_secs(),
            clock.subsec_nanos(),
        )),
    };
    let binding = OperationBinding {
        method: "branch_push_commit".to_owned(),
        scope: REPOSITORY.to_vec(),
        fingerprint_version: 1,
        fingerprint: HASH.to_vec(),
        canonical_intent_digest: HASH.to_vec(),
    };
    let PrepareResult::Prepared { token, .. } = store
        .domain_operation_prepare(&key, &binding, None, None)
        .await
        .unwrap()
    else {
        panic!("prepare refused");
    };
    GovernedOperation {
        key,
        binding,
        prepare_token: token,
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn final_push_requires_a_witness_and_validated_publication_still_commits() {
    let (_, store, direct) = fixture().await;
    let coordinator = store.fragment_coordinator();
    coordinator.activate_push_membership().await.unwrap();
    let locks = store
        .lock_coordinator()
        .capture_push_witness(&REPOSITORY, &REPOSITORY)
        .await
        .unwrap();
    let mut input = BranchPushCommitInput {
        fragment_witness: None,
        repository_id: REPOSITORY.to_vec(),
        branch_id: REPOSITORY.to_vec(),
        expected_repository_generation: 1,
        expected_branch_generation: 1,
        expected_repository_lock_generation: locks.repository_lock_generation,
        expected_branch_lock_generation: locks.branch_lock_generation,
        expected_branch_lock_namespace_last_applied_fence: locks
            .branch_lock_namespace_last_applied_fence,
        expected_latest_hash: HASH.to_vec(),
        new_latest_hash: vec![9; 32],
        projection: vec![ProjectionWrite {
            partition: REPOSITORY.to_vec(),
            key_type: 3,
            key: CONTEXT.to_vec(),
            value: Some(vec![9; 32]),
        }],
        event: None,
    };
    let operation = admitted(&store).await;
    assert_eq!(
        store
            .branch_push_commit(&operation, &input)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::NotApplied {
            reason_version: 1,
            reason: lore_postgres::domain::fragments::REQUIRED_FRAGMENT_PROOF_UNAVAILABLE
                .to_owned()
        }
    );
    assert_eq!(
        direct
            .query_one("SELECT latest_hash FROM lore_domain_branches", &[])
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0),
        HASH
    );
    assert_eq!(
        direct
            .query_one("SELECT count(*) FROM lore_mutable", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    input.fragment_witness = coordinator.capture_push_witness(&REPOSITORY).await.unwrap();
    assert_eq!(
        store
            .branch_push_commit(&admitted(&store).await, &input)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    assert_eq!(
        direct
            .query_one("SELECT latest_hash FROM lore_domain_branches", &[])
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0),
        vec![9; 32]
    );
    assert_eq!(
        direct
            .query_one("SELECT value FROM lore_mutable WHERE key_type=3", &[])
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0),
        vec![9; 32]
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn real_repeatable_read_push_started_before_activation_cannot_publish_without_a_witness() {
    let (url, store, observer) = fixture().await;
    let separator = if url.contains('?') { '&' } else { '?' };
    let rr_url = format!(
        "{url}{separator}options=-c%20default_transaction_isolation%3Drepeatable%5C%20read"
    );
    let rr_probe = client(&rr_url).await;
    assert_eq!(
        rr_probe
            .query_one("SHOW default_transaction_isolation", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "repeatable read"
    );
    let rr_store = PostgresDomainStore::connect(&rr_url, 1, &TlsConfig::default())
        .await
        .unwrap();
    let locks = store
        .lock_coordinator()
        .capture_push_witness(&REPOSITORY, &REPOSITORY)
        .await
        .unwrap();
    let input = BranchPushCommitInput {
        fragment_witness: None,
        repository_id: REPOSITORY.to_vec(),
        branch_id: REPOSITORY.to_vec(),
        expected_repository_generation: 1,
        expected_branch_generation: 1,
        expected_repository_lock_generation: locks.repository_lock_generation,
        expected_branch_lock_generation: locks.branch_lock_generation,
        expected_branch_lock_namespace_last_applied_fence: locks
            .branch_lock_namespace_last_applied_fence,
        expected_latest_hash: HASH.to_vec(),
        new_latest_hash: vec![9; 32],
        projection: vec![ProjectionWrite {
            partition: REPOSITORY.to_vec(),
            key_type: 3,
            key: CONTEXT.to_vec(),
            value: Some(vec![9; 32]),
        }],
        event: None,
    };
    let operation = admitted(&store).await;
    let mut blocker = client(&url).await;
    let tx = blocker.transaction().await.unwrap();
    // A lock only. Updating this tuple would cause a serialization error and mask the fence.
    tx.query_one("SELECT state FROM lore_domain_operation_receipts WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4 FOR UPDATE", &[&operation.key.verified_issuer, &operation.key.authenticated_subject, &operation.key.tenant_scope_key, &operation.key.operation_id.as_bytes().as_slice()]).await.unwrap();
    let blocker_pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let push = rr_store.branch_push_commit(&operation, &input);
    let activate = async {
        timeout(Duration::from_secs(10), async {
            loop {
                let blocked: bool = observer.query_one("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND wait_event_type='Lock')", &[&blocker_pid]).await.unwrap().get(0);
                if blocked { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("real Rust push must hold its old snapshot while blocked on the receipt");
        store
            .fragment_coordinator()
            .activate_push_membership()
            .await
            .unwrap();
        tx.commit().await.unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(15), async {
        tokio::join!(push, activate)
    })
    .await
    .unwrap();
    let error = result.expect_err("old-snapshot Rust publication must hit the persistent fence");
    assert_eq!(
        error,
        DomainError::Internal("branch tip publish: db error".to_owned()),
        "must reach the publication fence, not an earlier serialization or readiness error"
    );
    assert_eq!(
        observer
            .query_one("SELECT latest_hash FROM lore_domain_branches", &[])
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0),
        HASH
    );
    assert_eq!(
        observer
            .query_one("SELECT count(*) FROM lore_mutable", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        observer
            .query_one("SELECT count(*) FROM lore_outbox_events", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        observer
            .query_one("SELECT state FROM lore_domain_operation_receipts", &[])
            .await
            .unwrap()
            .get::<_, i16>(0),
        0,
        "failed transaction must leave the prepared receipt intact"
    );
}
