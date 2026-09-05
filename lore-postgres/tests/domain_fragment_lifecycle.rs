// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Real-Postgres proof for WP-118 Phases 2 and 3's fragment lifecycle
//! coordinator (`lore-postgres/src/domain/fragments/`).
//!
//! Every case is `#[ignore]` and is executed by `run-fragment-lifecycle-live.ps1`,
//! which gives each exact case a fresh PostgreSQL 16 database. The pure-logic
//! parts (witness matching, key distinctness, readiness fail-closed, state and
//! diagnostic round trips, the mask partition) are already pinned offline in
//! `states.rs`, `masks.rs`, and `coordinator.rs`'s own `mod tests` — this file
//! is exclusively the real-database tier: resolver agreement, the no-held-
//! connection proof, cross-instance racing, stale-witness fencing, generation
//! fanout atomicity, and readiness against real schema damage.

#[path = "common/case_namespace.rs"]
mod case_namespace;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Deref;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::fragments::BeginOutcome;
use lore_postgres::domain::fragments::CommitVerdict;
use lore_postgres::domain::fragments::EpochAuthority;
use lore_postgres::domain::fragments::EpochWitness;
use lore_postgres::domain::fragments::FragmentLifecycleReadiness;
use lore_postgres::domain::fragments::FragmentManifest;
use lore_postgres::domain::fragments::FragmentObliterateBegin;
use lore_postgres::domain::fragments::FragmentObliteratePhase;
use lore_postgres::domain::fragments::FragmentQueryRequest;
use lore_postgres::domain::fragments::FragmentResolution;
use lore_postgres::domain::fragments::FragmentVerdict;
use lore_postgres::domain::fragments::FragmentWriteCapability;
use lore_postgres::domain::fragments::FragmentWriteCapabilityCutover;
use lore_postgres::domain::fragments::FragmentWriteClaimInput;
use lore_postgres::domain::fragments::FragmentWriteClaimPruneBatch;
use lore_postgres::domain::fragments::FragmentWriteClaimPruneReport;
use lore_postgres::domain::fragments::FragmentWriteClaimState;
use lore_postgres::domain::fragments::FragmentWriteSettlement;
use lore_postgres::domain::fragments::IoObservation;
use lore_postgres::domain::fragments::MAX_FRAGMENT_BACKFILL_CURSOR_BATCH;
use lore_postgres::domain::fragments::MAX_LIFECYCLE_GENERATION_FANOUT;
use lore_postgres::domain::fragments::MAX_PUSH_FRAGMENT_REVALIDATIONS;
use lore_postgres::domain::fragments::MissingDiagnostic;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::domain::fragments::PushWitnessVerdict;
use lore_postgres::domain::fragments::REQUIRED_FRAGMENT_CHANGED;
use lore_postgres::domain::fragments::REQUIRED_FRAGMENT_REVALIDATION_LIMIT;
use lore_postgres::domain::fragments::RequiredFragment;
use lore_postgres::domain::fragments::STAGED_LEASE_ALREADY_RELEASED;
use lore_postgres::domain::fragments::STAGED_LEASE_MEMBER_NOT_STAGED;
use lore_postgres::domain::fragments::STAGED_LEASE_MEMBER_SET_MISMATCH;
use lore_postgres::domain::fragments::StagedReaderLease;
use lore_postgres::domain::fragments::coordinator::DirectWriteKind;
use lore_postgres::domain::fragments::coordinator::FragmentIntent;
use lore_postgres::domain::fragments::read_fragment_write_capability;
use lore_postgres::domain::fragments::schema;
use lore_postgres::domain::fragments::states::FragmentLifecycleState;
use lore_postgres::domain::lock_order::LockClass;
use lore_postgres::domain::lock_order::LockSequence;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use tokio::time::timeout;
use tokio_postgres::Client;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

const TEST_PROVIDER_WRITE_AUTHORITY_REVISION: &str = "write-claims-v1";

fn write_claim() -> FragmentWriteClaimInput {
    FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        [0xA5; 32],
        1,
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .expect("valid test write claim")
}

struct TestDomainStore(PostgresDomainStore);

impl Deref for TestDomainStore {
    type Target = PostgresDomainStore;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TestDomainStore {
    fn fragment_coordinator(&self) -> TestFragmentCoordinator {
        TestFragmentCoordinator(self.0.fragment_coordinator())
    }
}

#[derive(Clone)]
struct TestFragmentCoordinator(PostgresFragmentCoordinator);

impl Deref for TestFragmentCoordinator {
    type Target = PostgresFragmentCoordinator;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TestFragmentCoordinator {
    async fn begin_direct_write(
        &self,
        hash: &[u8],
        legacy_object_key: &str,
    ) -> Result<BeginOutcome, DomainError> {
        self.0
            .begin_direct_write(hash, legacy_object_key, write_claim())
            .await
    }

    async fn claim_repair(&self, hash: &[u8]) -> Result<BeginOutcome, DomainError> {
        self.0.claim_repair(hash, write_claim()).await
    }

    async fn commit_remote(
        &self,
        intent: &FragmentIntent,
        observation: IoObservation,
    ) -> Result<CommitVerdict, DomainError> {
        let claim = intent.write_claim().ok_or_else(|| {
            DomainError::InvalidInput("test remote intent has no write claim".to_owned())
        })?;
        self.0.authorize_write_claim(claim).await?;
        self.0
            .commit_remote(intent, observation, FragmentWriteSettlement::Decisive)
            .await
    }

    async fn commit_repair(
        &self,
        intent: &FragmentIntent,
        observation: IoObservation,
    ) -> Result<CommitVerdict, DomainError> {
        let claim = intent.write_claim().ok_or_else(|| {
            DomainError::InvalidInput("test repair intent has no write claim".to_owned())
        })?;
        self.0.authorize_write_claim(claim).await?;
        self.0
            .commit_repair(intent, observation, FragmentWriteSettlement::Decisive)
            .await
    }

    async fn begin_obliterate(
        &self,
        hash: &[u8],
        repository_id: &[u8],
        context: &[u8],
    ) -> Result<FragmentObliterateBegin, DomainError> {
        self.0
            .begin_obliterate(
                hash,
                repository_id,
                context,
                TEST_PROVIDER_WRITE_AUTHORITY_REVISION,
            )
            .await
    }
}

async fn enable_write_claims(url: &str, coordinator: &TestFragmentCoordinator) {
    let direct = client(url).await;
    direct
        .execute(
            "UPDATE lore_fragment_schema_state \
                SET backfill_state = $1, cutover_at = clock_timestamp(), \
                    residue_classified = true, sequence_headroom_fence = 1 \
              WHERE id = 1",
            &[&schema::BACKFILL_CUTOVER],
        )
        .await
        .expect("stage lifecycle cutover preconditions");
    coordinator
        .enable_lifecycle()
        .await
        .expect("enable lifecycle before coordinated obliterate");
    coordinator
        .require_write_claims(
            &FragmentWriteCapabilityCutover::new(TEST_PROVIDER_WRITE_AUTHORITY_REVISION)
                .expect("valid test provider write-authority revision"),
        )
        .await
        .expect("enable write claims for coordinated obliterate");
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn normal_direct_write_uses_legacy_key_and_missing_reoffer_uses_repair_epoch_key() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let hash = rand::random::<[u8; 32]>();
    let legacy_key = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let normal_claim = write_claim();
    let BeginOutcome::Admitted(first) = coordinator
        .0
        .begin_direct_write(&hash, &legacy_key, normal_claim.clone())
        .await
        .expect("begin ordinary direct write")
    else {
        panic!("fresh hash must admit its ordinary direct write");
    };
    assert_eq!(first.object_key, legacy_key);
    assert_eq!(first.direct_write_kind(), Some(DirectWriteKind::Normal));

    let assertion_client = client(&url).await;
    let persisted_normal = assertion_client
        .query_one(
            "SELECT current_epoch, state, last_fence, active_operation \
             FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash.as_slice()],
        )
        .await
        .expect("read persisted normal intent");
    assert_eq!(
        persisted_normal.get::<_, i16>("state"),
        FragmentLifecycleState::PreparingRemote.bits()
    );
    assert_eq!(
        persisted_normal.get::<_, Vec<u8>>("active_operation"),
        b"wp118-direct-v1N"
    );

    assertion_client
        .execute(
            "UPDATE lore_fragment_lifecycle SET active_operation = NULL WHERE hash = $1",
            &[&hash.as_slice()],
        )
        .await
        .expect("remove persisted lineage token");
    let missing_token = coordinator
        .0
        .begin_direct_write(&hash, &legacy_key, normal_claim.clone())
        .await
        .expect_err("a PreparingRemote head with no lineage token must fail closed");
    assert_eq!(
        missing_token,
        DomainError::NotReady("PreparingRemote head has no direct-write lineage token".to_owned())
    );

    assertion_client
        .execute(
            "UPDATE lore_fragment_lifecycle SET active_operation = $2 WHERE hash = $1",
            &[&hash.as_slice(), &b"wp118-direct-v1X".as_slice()],
        )
        .await
        .expect("install unknown persisted lineage token");
    let unknown_token = coordinator
        .0
        .begin_direct_write(&hash, &legacy_key, normal_claim.clone())
        .await
        .expect_err("a PreparingRemote head with an unknown lineage token must fail closed");
    assert_eq!(
        unknown_token,
        DomainError::NotReady(
            "PreparingRemote head has an unknown direct-write lineage token".to_owned()
        )
    );

    assertion_client
        .execute(
            "UPDATE lore_fragment_lifecycle SET active_operation = $2 WHERE hash = $1",
            &[&hash.as_slice(), &b"wp118-direct-v1N".as_slice()],
        )
        .await
        .expect("restore normal persisted lineage token");

    let restarted = store_with_pool(&url, 8).await.fragment_coordinator();
    let BeginOutcome::Admitted(normal_retry) = restarted
        .0
        .begin_direct_write(&hash, &legacy_key, normal_claim)
        .await
        .expect("resume ordinary direct write after restart")
    else {
        panic!("PreparingRemote normal write must resume");
    };
    assert_eq!(normal_retry.epoch, first.epoch);
    assert_eq!(normal_retry.fence, first.fence);
    assert_eq!(normal_retry.object_key, first.object_key);
    assert_eq!(
        normal_retry.direct_write_kind(),
        Some(DirectWriteKind::Normal)
    );
    assert_eq!(
        restarted
            .commit_remote(&first, IoObservation::Unusable(MissingDiagnostic::Absent))
            .await
            .expect("publish Missing observation"),
        CommitVerdict::Published
    );

    let repair_claim = write_claim();
    let BeginOutcome::Admitted(repair) = coordinator
        .0
        .begin_direct_write(&hash, &legacy_key, repair_claim.clone())
        .await
        .expect("re-offer Missing fragment")
    else {
        panic!("Missing head must admit a repair successor");
    };
    assert_ne!(repair.object_key, legacy_key);
    assert_eq!(repair.object_key, format!("{legacy_key}.r{}", repair.epoch));
    assert_eq!(repair.direct_write_kind(), Some(DirectWriteKind::Repair));

    let persisted_repair = assertion_client
        .query_one(
            "SELECT current_epoch, state, last_fence, active_operation \
             FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash.as_slice()],
        )
        .await
        .expect("read persisted repair intent");
    assert_eq!(
        persisted_repair.get::<_, i16>("state"),
        FragmentLifecycleState::PreparingRemote.bits()
    );
    assert_eq!(
        persisted_repair.get::<_, i64>("current_epoch"),
        repair.epoch
    );
    assert_eq!(persisted_repair.get::<_, i64>("last_fence"), repair.fence);
    assert_eq!(
        persisted_repair.get::<_, Vec<u8>>("active_operation"),
        b"wp118-direct-v1R"
    );

    let repaired_restart = store_with_pool(&url, 8).await.fragment_coordinator();
    let BeginOutcome::Admitted(repair_retry) = repaired_restart
        .0
        .begin_direct_write(&hash, &legacy_key, repair_claim)
        .await
        .expect("resume repair after restart")
    else {
        panic!("PreparingRemote repair must resume");
    };
    assert_eq!(repair_retry.epoch, repair.epoch);
    assert_eq!(repair_retry.fence, repair.fence);
    assert_eq!(repair_retry.object_key, repair.object_key);
    assert_ne!(repair_retry.object_key, legacy_key);
    assert_eq!(
        repair_retry.direct_write_kind(),
        Some(DirectWriteKind::Repair)
    );
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn payload_free_coordinated_preflight_distinguishes_exact_readable_from_new_publication() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository = create_repository(&store).await;
    let context = random_context();
    let readable_hash = random_hash();
    let object_key = readable_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&readable_hash, &object_key)
        .await
        .expect("begin readable fixture")
    else {
        panic!("fresh fixture must admit");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(&object_key, 0x41, EpochAuthority::Remote)),
            )
            .await
            .expect("publish readable fixture"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&readable_hash, &repository, &context)
            .await
            .expect("associate readable fixture"),
        CommitVerdict::Published
    );

    let new_hash = random_hash();
    let resolved = coordinator
        .resolve(
            &repository,
            &context,
            &[readable_hash.clone(), new_hash.clone()],
        )
        .await
        .expect("resolve payload-free preflight matrix");
    expect_readable(&resolved[0]);
    expect_absent(&resolved[1]);
    assert!(matches!(
        coordinator
            .begin_direct_write(&readable_hash, &object_key)
            .await
            .expect("deduplicate readable fixture"),
        BeginOutcome::AlreadyReadable(_)
    ));
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn durable_write_claims_bind_replay_authorize_settle_and_expiry_to_database_state() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let key = legacy_key(&hash);
    let logical_request_id = [0x11; 16];
    let attempt_id = [0x22; 16];
    let body_blake3 = [0x33; 32];
    let input = FragmentWriteClaimInput::new(
        logical_request_id,
        attempt_id,
        body_blake3,
        262_144,
        Duration::from_millis(500),
        Duration::from_millis(250),
    )
    .expect("valid exact claim binding");

    let BeginOutcome::Admitted(intent) = coordinator
        .0
        .begin_direct_write(&hash, &key, input.clone())
        .await
        .expect("prepare durable write claim")
    else {
        panic!("fresh direct write must prepare its claim");
    };
    let claim = intent.write_claim().expect("direct intent claim");
    assert_eq!(claim.logical_request_id(), &logical_request_id);
    assert_eq!(claim.attempt_id(), &attempt_id);
    assert_eq!(claim.hash(), hash.as_slice());
    assert_eq!(claim.epoch(), intent.epoch);
    assert_eq!(claim.fence(), intent.fence);
    assert_eq!(claim.authority(), EpochAuthority::Remote);
    assert_eq!(claim.object_key(), key);
    assert_eq!(claim.body_blake3(), &body_blake3);
    assert_eq!(claim.body_size(), 262_144);
    assert!(claim.send_not_after() < claim.hard_not_after());
    let no_send_publish = coordinator
        .0
        .commit_remote(
            &intent,
            IoObservation::Unusable(MissingDiagnostic::Absent),
            FragmentWriteSettlement::NoSend,
        )
        .await
        .expect_err("NoSend can settle but can never publish an observation");
    assert_eq!(
        no_send_publish,
        DomainError::InvalidInput("a no-send claim cannot publish a remote observation".to_owned())
    );

    let row = direct
        .query_one(
            "SELECT state, prepared_at, send_not_after, hard_not_after, \
                    prepared_at <= clock_timestamp(), send_not_after > prepared_at, \
                    hard_not_after > send_not_after \
               FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[&logical_request_id.as_slice(), &attempt_id.as_slice()],
        )
        .await
        .expect("read prepared claim");
    assert_eq!(
        row.get::<_, i16>("state"),
        FragmentWriteClaimState::Prepared.bits()
    );
    assert!(row.get::<_, bool>(4));
    assert!(row.get::<_, bool>(5));
    assert!(row.get::<_, bool>(6));

    let BeginOutcome::Admitted(replayed) = coordinator
        .0
        .begin_direct_write(&hash, &key, input.clone())
        .await
        .expect("replay exact prepared claim")
    else {
        panic!("exact prepared replay must remain admitted");
    };
    assert_eq!(replayed.write_claim(), intent.write_claim());

    let mismatched = FragmentWriteClaimInput::new(
        logical_request_id,
        attempt_id,
        [0x44; 32],
        262_144,
        Duration::from_millis(500),
        Duration::from_millis(250),
    )
    .expect("valid but differently bound claim");
    let error = coordinator
        .0
        .begin_direct_write(&hash, &key, mismatched)
        .await
        .expect_err("same attempt identity with a changed body hash must fail");
    assert!(
        error
            .to_string()
            .contains("reused with a different binding")
    );

    assert!(matches!(
        coordinator
            .0
            .begin_direct_write(&hash, &key, write_claim())
            .await
            .expect("inspect prepared barrier"),
        BeginOutcome::WriteClaimBlocked { .. }
    ));
    let authorized = coordinator
        .authorize_write_claim(claim)
        .await
        .expect("authorize exact prepared claim");
    assert!(!authorized.send_budget().is_zero());
    assert!(authorized.send_budget() <= Duration::from_millis(500));
    assert!(matches!(
        coordinator
            .0
            .begin_direct_write(&hash, &key, write_claim())
            .await
            .expect("inspect Sending barrier"),
        BeginOutcome::WriteClaimBlocked { .. }
    ));
    coordinator
        .settle_write_claim(claim, FragmentWriteSettlement::Ambiguous)
        .await
        .expect("settle ambiguous provider outcome");
    assert_eq!(
        direct
            .query_one(
                "SELECT state FROM lore_fragment_write_claims \
                  WHERE logical_request_id = $1 AND attempt_id = $2",
                &[&logical_request_id.as_slice(), &attempt_id.as_slice()],
            )
            .await
            .expect("read settled claim")
            .get::<_, i16>(0),
        FragmentWriteClaimState::Ambiguous.bits()
    );
    assert!(matches!(
        coordinator
            .0
            .begin_direct_write(&hash, &key, write_claim())
            .await
            .expect("inspect Ambiguous barrier"),
        BeginOutcome::WriteClaimBlocked { .. }
    ));

    tokio::time::sleep(Duration::from_millis(850)).await;
    let BeginOutcome::Admitted(after_expiry) = coordinator
        .0
        .begin_direct_write(&hash, &key, write_claim())
        .await
        .expect("hard-expired ambiguity no longer blocks")
    else {
        panic!("a new attempt must be admitted after the database hard expiry");
    };
    coordinator
        .settle_write_claim(
            after_expiry.write_claim().expect("replacement claim"),
            FragmentWriteSettlement::NoSend,
        )
        .await
        .expect("NoSend replacement settlement");
    assert!(matches!(
        coordinator
            .0
            .begin_direct_write(&hash, &key, write_claim())
            .await
            .expect("NoSend is nonblocking"),
        BeginOutcome::Admitted(_)
    ));
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn write_claim_head_lock_precedes_claim_insert_and_moved_lineage_refuses_send() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let hash = random_hash();
    let key = legacy_key(&hash);
    let BeginOutcome::Admitted(seed) = coordinator.begin_direct_write(&hash, &key).await.unwrap()
    else {
        panic!("fresh seed must admit");
    };
    assert_eq!(
        coordinator
            .commit_remote(&seed, IoObservation::Unusable(MissingDiagnostic::Absent))
            .await
            .expect("seed Missing head"),
        CommitVerdict::Published
    );

    let mut locker = own_transaction_client(&url).await;
    let tx = locker.transaction().await.expect("head-lock transaction");
    tx.query_one(
        "SELECT hash FROM lore_fragment_lifecycle WHERE hash = $1 FOR UPDATE",
        &[&hash.as_slice()],
    )
    .await
    .expect("lock exact lifecycle head");
    let blocked_request = *Uuid::now_v7().as_bytes();
    let blocked_attempt = *Uuid::now_v7().as_bytes();
    let blocked_input = FragmentWriteClaimInput::new(
        blocked_request,
        blocked_attempt,
        [0x66; 32],
        1,
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .expect("blocked attempt fixture");
    let racing = coordinator.clone();
    let racing_hash = hash.clone();
    let begin = lore_base::lore_spawn!(async move {
        racing
            .0
            .begin_direct_write(&racing_hash, &legacy_key(&racing_hash), blocked_input)
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let observer = client(&url).await;
    assert_eq!(
        observer
            .query_one(
                "SELECT count(*) FROM lore_fragment_write_claims \
                  WHERE logical_request_id = $1 AND attempt_id = $2",
                &[&blocked_request.as_slice(), &blocked_attempt.as_slice()],
            )
            .await
            .expect("claim visibility while head locked")
            .get::<_, i64>(0),
        0,
        "claim insertion must not overtake the lifecycle-head lock"
    );
    tx.commit().await.expect("release lifecycle head lock");
    let BeginOutcome::Admitted(repair) = begin
        .await
        .expect("join blocked begin")
        .expect("begin after head unlock")
    else {
        panic!("Missing head must admit a repair after the lock releases");
    };

    observer
        .execute(
            "UPDATE lore_fragment_lifecycle SET state = $2 WHERE hash = $1",
            &[
                &hash.as_slice(),
                &FragmentLifecycleState::DeletingChildren.bits(),
            ],
        )
        .await
        .expect("simulate the Phase 6B head-first deletion transition");
    let error = coordinator
        .authorize_write_claim(repair.write_claim().expect("repair claim"))
        .await
        .expect_err("a moved/deleting lineage must refuse authorization");
    assert!(error.to_string().contains("fragment_write_lineage_moved"));
    assert_eq!(
        observer
            .query_one(
                "SELECT state FROM lore_fragment_write_claims \
                  WHERE logical_request_id = $1 AND attempt_id = $2",
                &[&blocked_request.as_slice(), &blocked_attempt.as_slice()],
            )
            .await
            .expect("read refused claim state")
            .get::<_, i16>(0),
        FragmentWriteClaimState::NoSend.bits(),
        "lineage refusal must durably prevent a later send"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn write_claim_acl_denies_public_and_retains_owner_access() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let _store = store(&url).await;
    let direct = client(&url).await;
    let public_dml: bool = direct
        .query_one(
            "SELECT EXISTS ( \
                 SELECT 1 FROM pg_class AS c, \
                    LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) AS acl \
                  WHERE c.oid = 'lore_fragment_write_claims'::regclass \
                    AND acl.grantee = 0 \
                    AND acl.privilege_type = ANY($1::text[]) \
             )",
            &[&["SELECT", "INSERT", "UPDATE", "DELETE"].as_slice()],
        )
        .await
        .expect("inspect PUBLIC table ACL")
        .get(0);
    assert!(!public_dml, "PUBLIC must have no write-claim DML privilege");
    let owner_dml: bool = direct
        .query_one(
            "SELECT has_table_privilege( \
                 current_user, 'lore_fragment_write_claims', 'SELECT,INSERT,UPDATE,DELETE' \
             )",
            &[],
        )
        .await
        .expect("inspect owner table ACL")
        .get(0);
    assert!(owner_dml, "the schema owner must retain claim-table access");
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn write_capability_cutover_is_exact_idempotent_and_database_attested() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let pool = build_pool(&url, 2, &TlsConfig::default()).expect("build capability pool");

    let initial = read_fragment_write_capability(&pool)
        .await
        .expect("read optional capability");
    assert!(initial.provisioned);
    assert_eq!(initial.schema_version, schema::FRAGMENT_SCHEMA_VERSION);
    assert_eq!(initial.write_capability, FragmentWriteCapability::Optional);

    for invalid in [String::new(), "bad revision".to_owned(), "x".repeat(65)] {
        assert!(FragmentWriteCapabilityCutover::new(&invalid).is_err());
    }
    let cutover = FragmentWriteCapabilityCutover::new("write-claims-v1")
        .expect("canonical write-authority revision");
    let not_ready = coordinator
        .require_write_claims(&cutover)
        .await
        .expect_err("cutover before lifecycle readiness must fail");
    assert!(matches!(not_ready, DomainError::NotReady(_)));

    direct
        .execute(
            "UPDATE lore_fragment_schema_state \
                SET backfill_state = $1, cutover_at = clock_timestamp(), \
                    residue_classified = true, sequence_headroom_fence = 1 \
              WHERE id = 1",
            &[&schema::BACKFILL_CUTOVER],
        )
        .await
        .expect("stage lifecycle cutover preconditions");
    coordinator
        .enable_lifecycle()
        .await
        .expect("enable lifecycle before claims-required cutover");
    coordinator
        .require_write_claims(&cutover)
        .await
        .expect("persist claims-required capability");
    coordinator
        .require_write_claims(&cutover)
        .await
        .expect("exact cutover replay must be idempotent");

    let required = read_fragment_write_capability(&pool)
        .await
        .expect("read claims-required capability");
    assert_eq!(required.schema_version, schema::FRAGMENT_SCHEMA_VERSION);
    assert_eq!(
        required.write_capability,
        FragmentWriteCapability::ClaimsRequired {
            provider_write_authority_revision: "write-claims-v1".to_owned(),
        }
    );
    let mismatch = coordinator
        .require_write_claims(
            &FragmentWriteCapabilityCutover::new("write-claims-v2")
                .expect("second canonical revision"),
        )
        .await
        .expect_err("a different revision must not rewrite the cutover");
    assert!(matches!(
        mismatch,
        DomainError::PreconditionRejected { ref reason, .. }
            if reason == "fragment_write_authority_revision_mismatch"
    ));
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn claim_inventory_and_prune_preserve_cleanup_targets_and_bound_terminal_deletion() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    let ambiguous_hash = random_hash();
    let ambiguous_key = legacy_key(&ambiguous_hash);
    let ambiguous_input = FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        [0x31; 32],
        31,
        Duration::from_millis(50),
        Duration::from_millis(100),
    )
    .expect("short ambiguous claim");
    let BeginOutcome::Admitted(ambiguous_intent) = coordinator
        .0
        .begin_direct_write(&ambiguous_hash, &ambiguous_key, ambiguous_input)
        .await
        .expect("prepare ambiguous predecessor")
    else {
        panic!("fresh ambiguous predecessor must admit");
    };
    let ambiguous_claim = ambiguous_intent
        .write_claim()
        .expect("ambiguous predecessor claim");
    coordinator
        .authorize_write_claim(ambiguous_claim)
        .await
        .expect("authorize ambiguous predecessor");
    coordinator
        .0
        .commit_remote(
            &ambiguous_intent,
            IoObservation::Unusable(MissingDiagnostic::Absent),
            FragmentWriteSettlement::Ambiguous,
        )
        .await
        .expect("publish Missing while retaining ambiguous predecessor");
    tokio::time::sleep(Duration::from_millis(170)).await;

    let BeginOutcome::Admitted(repair_intent) = coordinator
        .0
        .begin_direct_write(&ambiguous_hash, &ambiguous_key, write_claim())
        .await
        .expect("repair after Missing remains legitimate")
    else {
        panic!("repair after Missing must allocate a successor");
    };
    assert_ne!(repair_intent.object_key, ambiguous_key);
    coordinator
        .settle_write_claim(
            repair_intent.write_claim().expect("repair claim"),
            FragmentWriteSettlement::NoSend,
        )
        .await
        .expect("settle unused repair");
    tokio::time::sleep(Duration::from_millis(5)).await;
    let old_row = direct
        .query_one(
            "SELECT epoch, fence, object_key, state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &ambiguous_claim.logical_request_id().as_slice(),
                &ambiguous_claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read old ambiguous cleanup target");
    assert_eq!(old_row.get::<_, i64>(0), ambiguous_claim.epoch());
    assert_eq!(old_row.get::<_, i64>(1), ambiguous_claim.fence());
    assert_eq!(old_row.get::<_, String>(2), ambiguous_key);
    assert_eq!(
        old_row.get::<_, i16>(3),
        FragmentWriteClaimState::Ambiguous.bits()
    );

    let pruned = coordinator
        .prune_terminal_write_claims(
            FragmentWriteClaimPruneBatch::new(1, Duration::from_millis(1))
                .expect("bounded prune batch"),
        )
        .await
        .expect("prune one terminal claim");
    // The ambiguous predecessor's hard horizon has already passed (its windows
    // were 50/150 ms and the sleep above is 170 ms), so it is neither an
    // eligible candidate nor an active barrier: the batch is one candidate and
    // it is pruned, with nothing skipped on either counter.
    assert_eq!(
        pruned,
        FragmentWriteClaimPruneReport {
            examined: 1,
            pruned: 1,
            skipped_blocked: 0,
            skipped_missing_evidence: 0,
        },
        "the NoSend repair is the sole eligible row"
    );
    let ambiguous_survives: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &ambiguous_claim.logical_request_id().as_slice(),
                &ambiguous_claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("count old ambiguous target after prune")
        .get(0);
    assert_eq!(ambiguous_survives, 1);

    let decisive_hash = random_hash();
    let decisive_key = legacy_key(&decisive_hash);
    let decisive_input = FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        [0x52; 32],
        52,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect("decisive claim");
    let BeginOutcome::Admitted(decisive_intent) = coordinator
        .0
        .begin_direct_write(&decisive_hash, &decisive_key, decisive_input)
        .await
        .expect("prepare decisive publication")
    else {
        panic!("fresh decisive publication must admit");
    };
    let decisive_claim = decisive_intent
        .write_claim()
        .expect("decisive publication claim");
    coordinator
        .authorize_write_claim(decisive_claim)
        .await
        .expect("authorize decisive publication");
    coordinator
        .0
        .commit_remote(
            &decisive_intent,
            IoObservation::Valid(manifest(&decisive_key, 0x52, EpochAuthority::Remote)),
            FragmentWriteSettlement::Decisive,
        )
        .await
        .expect("publish decisive provider evidence");
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(
        coordinator
            .prune_terminal_write_claims(
                FragmentWriteClaimPruneBatch::new(1, Duration::from_millis(1))
                    .expect("single decisive prune"),
            )
            .await
            .expect("prune decisive claim with durable evidence"),
        FragmentWriteClaimPruneReport {
            examined: 1,
            pruned: 1,
            skipped_blocked: 0,
            skipped_missing_evidence: 0,
        }
    );
    let epoch_evidence = direct
        .query_one(
            "SELECT provider_body_blake3, provider_body_size, provider_claim_fence \
               FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&decisive_hash, &decisive_intent.epoch],
        )
        .await
        .expect("read durable decisive epoch evidence");
    assert_eq!(epoch_evidence.get::<_, Vec<u8>>(0), vec![0x52; 32]);
    assert_eq!(epoch_evidence.get::<_, i64>(1), 52);
    assert_eq!(epoch_evidence.get::<_, i64>(2), decisive_claim.fence());
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn obliterate_retains_an_old_ambiguous_target_across_missing_repair_and_new_epoch() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();
    let legacy = legacy_key(&hash);

    let input = FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        [0xB1; 32],
        17,
        Duration::from_millis(40),
        Duration::from_millis(60),
    )
    .expect("short ambiguous claim");
    let BeginOutcome::Admitted(first) = coordinator
        .0
        .begin_direct_write(&hash, &legacy, input)
        .await
        .expect("begin first publication")
    else {
        panic!("fresh hash must admit");
    };
    let old_claim = first.write_claim().expect("first claim").clone();
    coordinator
        .authorize_write_claim(&old_claim)
        .await
        .expect("authorize ambiguous write");
    assert_eq!(
        coordinator
            .0
            .commit_remote(
                &first,
                IoObservation::Unusable(MissingDiagnostic::Absent),
                FragmentWriteSettlement::Ambiguous,
            )
            .await
            .expect("publish Missing while retaining ambiguous target"),
        CommitVerdict::Published
    );
    tokio::time::sleep(Duration::from_millis(120)).await;

    let BeginOutcome::Admitted(repair) = coordinator
        .begin_direct_write(&hash, &legacy)
        .await
        .expect("begin repair")
    else {
        panic!("Missing head must admit repair");
    };
    let repair_key = repair.object_key.clone();
    assert_ne!(repair_key, legacy);
    assert_eq!(
        coordinator
            .commit_remote(
                &repair,
                IoObservation::Valid(manifest(&repair_key, 0xB2, EpochAuthority::Remote,)),
            )
            .await
            .expect("publish repair"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .expect("associate repaired fragment"),
        CommitVerdict::Published
    );
    enable_write_claims(&url, &coordinator).await;

    let FragmentObliterateBegin::Ready(deleting) = coordinator
        .begin_obliterate(&hash, &repository, &context)
        .await
        .expect("begin exact deletion after repair")
    else {
        panic!("last association must own deletion");
    };
    assert_eq!(deleting.phase(), FragmentObliteratePhase::Children);
    assert!(
        deleting
            .purge_targets()
            .iter()
            .any(|target| target.object_key() == legacy
                && target.epoch() == old_claim.epoch()
                && target.provider_claim_fence() == Some(old_claim.fence())
                && target.provider_body_blake3() == Some(old_claim.body_blake3())
                && target.provider_body_size() == Some(old_claim.body_size())),
        "the old ambiguous legacy-key target must survive into deletion inventory"
    );
    assert!(
        deleting
            .purge_targets()
            .iter()
            .any(|target| target.object_key() == repair_key && target.epoch() == repair.epoch),
        "the repaired current epoch must remain an independent exact target"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn unexpired_ambiguous_claim_blocks_exact_obliterate_before_children_can_advance() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();
    let key = legacy_key(&hash);
    let input = FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        [0xB3; 32],
        19,
        Duration::from_secs(30),
        Duration::from_secs(30),
    )
    .expect("unexpired ambiguous claim");
    let BeginOutcome::Admitted(publication) = coordinator
        .0
        .begin_direct_write(&hash, &key, input)
        .await
        .expect("begin publication")
    else {
        panic!("fresh hash must admit");
    };
    let claim = publication
        .write_claim()
        .expect("durable write claim")
        .clone();
    coordinator
        .authorize_write_claim(&claim)
        .await
        .expect("authorize ambiguous send");
    assert_eq!(
        coordinator
            .0
            .commit_remote(
                &publication,
                IoObservation::Unusable(MissingDiagnostic::Absent),
                FragmentWriteSettlement::Ambiguous,
            )
            .await
            .expect("publish Missing with ambiguous settlement"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .expect("associate Missing lineage"),
        CommitVerdict::Published
    );
    enable_write_claims(&url, &coordinator).await;

    let FragmentObliterateBegin::Blocked {
        intent,
        blocked_until,
    } = coordinator
        .begin_obliterate(&hash, &repository, &context)
        .await
        .expect("begin exact obliterate")
    else {
        panic!("an unexpired ambiguous claim must block exact deletion");
    };
    assert_eq!(blocked_until, claim.hard_not_after());
    assert_eq!(intent.phase(), FragmentObliteratePhase::Children);
    let state: i16 = client(&url)
        .await
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash.as_slice()],
        )
        .await
        .expect("read blocked obliterate head")
        .get(0);
    assert_eq!(state, FragmentLifecycleState::DeletingChildren.bits());
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn prune_normalizes_expired_prepared_to_targetless_no_send_and_honors_batch_limit() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let key = legacy_key(&hash);
    let input = FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        [0x71; 32],
        71,
        Duration::from_millis(40),
        Duration::from_millis(200),
    )
    .expect("short prepared claim");
    let BeginOutcome::Admitted(intent) = coordinator
        .0
        .begin_direct_write(&hash, &key, input)
        .await
        .expect("prepare expiring claim")
    else {
        panic!("fresh prepared claim must admit");
    };
    let prepared = intent.write_claim().expect("prepared claim");

    let prepared_epoch = prepared.epoch();
    let prepared_fence = prepared.fence();
    let remote_authority = EpochAuthority::Remote.bits();
    let no_send_state = FragmentWriteClaimState::NoSend.bits();
    for seed in [0x81_u8, 0x82_u8] {
        let logical_request_id = vec![seed; 16];
        let attempt_id = vec![seed.wrapping_add(1); 16];
        let body_blake3 = vec![seed; 32];
        let body_size = i64::from(seed);
        direct
            .execute(
                "INSERT INTO lore_fragment_write_claims ( \
                    logical_request_id, attempt_id, hash, epoch, fence, authority, object_key, \
                    body_blake3, body_size, state, send_not_after, hard_not_after, prepared_at, settled_at \
                 ) VALUES ( \
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                    clock_timestamp() - interval '2 seconds', \
                    clock_timestamp() - interval '1 second', \
                    clock_timestamp() - interval '3 seconds', \
                    clock_timestamp() - interval '1 second' \
                 )",
                &[
                    &logical_request_id,
                    &attempt_id,
                    &hash,
                    &prepared_epoch,
                    &prepared_fence,
                    &remote_authority,
                    &key,
                    &body_blake3,
                    &body_size,
                    &no_send_state,
                ],
            )
            .await
            .expect("insert old targetless NoSend candidate");
    }
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        coordinator
            .prune_terminal_write_claims(
                FragmentWriteClaimPruneBatch::new(1, Duration::from_millis(1))
                    .expect("single-row prune batch"),
            )
            .await
            .expect("bounded prune and inventory normalization"),
        FragmentWriteClaimPruneReport {
            examined: 1,
            pruned: 1,
            skipped_blocked: 0,
            skipped_missing_evidence: 0,
        },
        "LIMIT 1 must examine and delete exactly one terminal candidate"
    );
    let prepared_state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &prepared.logical_request_id().as_slice(),
                &prepared.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read normalized prepared claim")
        .get(0);
    assert_eq!(prepared_state, FragmentWriteClaimState::NoSend.bits());
    let first_synthetic_request = vec![0x81_u8; 16];
    let second_synthetic_request = vec![0x82_u8; 16];
    let synthetic_remaining: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_fragment_write_claims \
              WHERE hash = $1 AND logical_request_id IN ($2, $3)",
            &[&hash, &first_synthetic_request, &second_synthetic_request],
        )
        .await
        .expect("count bounded synthetic survivors")
        .get(0);
    assert_eq!(synthetic_remaining, 1);
}

// ---------------------------------------------------------------------------
// WP-118 prune-fix shared fixtures.
//
// Every prune case below needs the same two ingredients: a hash whose terminal
// claim carries real durable epoch evidence (so it is eligible on the plan
// query's own decisive terms, and only the barrier or the batch can keep it
// out), and synthetic sibling rows on that same hash. Building the second by
// hand from the first's stored evidence keeps the synthetic rows honest — they
// satisfy the same EXISTS clause a real row does, rather than being waved
// through.
// ---------------------------------------------------------------------------

/// One hash's durable claim evidence, copied so a synthetic sibling row can
/// satisfy the plan query's decisive EXISTS clause against the same epoch.
struct ClaimEvidence {
    epoch: i64,
    fence: i64,
    authority: i16,
    object_key: String,
    body_blake3: Vec<u8>,
    body_size: i64,
}

/// Publish one decisive provider write on a fresh hash, then age its terminal
/// claim well past any short prune retention so it is an eligible candidate.
async fn aged_decisive_publication(
    coordinator: &TestFragmentCoordinator,
    direct: &Client,
    seed: u8,
) -> Vec<u8> {
    let hash = random_hash();
    let key = legacy_key(&hash);
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &key)
        .await
        .expect("begin a decisive publication")
    else {
        panic!("a fresh hash must admit its direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(&key, seed, EpochAuthority::Remote)),
            )
            .await
            .expect("publish decisive provider evidence"),
        CommitVerdict::Published
    );
    direct
        .execute(
            "UPDATE lore_fragment_write_claims \
                SET settled_at = clock_timestamp() - interval '10 seconds' \
              WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("age the decisive claim past retention");
    hash
}

async fn claim_evidence(direct: &Client, hash: &[u8]) -> ClaimEvidence {
    let row = direct
        .query_one(
            "SELECT epoch, fence, authority, object_key, body_blake3, body_size \
               FROM lore_fragment_write_claims WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read the hash's durable claim evidence");
    ClaimEvidence {
        epoch: row.get("epoch"),
        fence: row.get("fence"),
        authority: row.get("authority"),
        object_key: row.get("object_key"),
        body_blake3: row.get("body_blake3"),
        body_size: row.get("body_size"),
    }
}

/// Insert one aged terminal claim sharing `hash`'s durable epoch evidence.
///
/// `authorized_at` is set on both arms: the state CHECK requires it for
/// Decisive and permits it for NoSend, so one statement serves both.
async fn insert_aged_terminal_claim(
    direct: &Client,
    hash: &[u8],
    evidence: &ClaimEvidence,
    seed: u8,
    state: FragmentWriteClaimState,
) -> (Vec<u8>, Vec<u8>) {
    let logical_request_id = vec![seed; 16];
    let attempt_id = vec![seed.wrapping_add(1); 16];
    direct
        .execute(
            "INSERT INTO lore_fragment_write_claims ( \
                logical_request_id, attempt_id, hash, epoch, fence, authority, object_key, \
                body_blake3, body_size, state, send_not_after, hard_not_after, prepared_at, \
                authorized_at, settled_at \
             ) VALUES ( \
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                clock_timestamp() - interval '11 seconds', \
                clock_timestamp() - interval '10 seconds', \
                clock_timestamp() - interval '12 seconds', \
                clock_timestamp() - interval '11 seconds', \
                clock_timestamp() - interval '9 seconds' \
             )",
            &[
                &logical_request_id,
                &attempt_id,
                &hash,
                &evidence.epoch,
                &evidence.fence,
                &evidence.authority,
                &evidence.object_key,
                &evidence.body_blake3,
                &evidence.body_size,
                &state.bits(),
            ],
        )
        .await
        .expect("insert an aged terminal claim");
    (logical_request_id, attempt_id)
}

/// Insert one unexpired `Prepared` claim: a live send barrier on `hash` whose
/// send horizon is an hour out, so it blocks for the whole case and cannot be
/// settled out by `write_claim_barrier_for_prune`'s own normalization.
async fn insert_live_send_barrier(
    direct: &Client,
    hash: &[u8],
    evidence: &ClaimEvidence,
    seed: u8,
) -> (Vec<u8>, Vec<u8>) {
    let logical_request_id = vec![seed; 16];
    let attempt_id = vec![seed.wrapping_add(1); 16];
    direct
        .execute(
            "INSERT INTO lore_fragment_write_claims ( \
                logical_request_id, attempt_id, hash, epoch, fence, authority, object_key, \
                body_blake3, body_size, state, send_not_after, hard_not_after, prepared_at \
             ) VALUES ( \
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                clock_timestamp() + interval '1 hour', \
                clock_timestamp() + interval '2 hours', \
                clock_timestamp() \
             )",
            &[
                &logical_request_id,
                &attempt_id,
                &hash,
                &evidence.epoch,
                &evidence.fence,
                &evidence.authority,
                &evidence.object_key,
                &vec![seed; 32],
                &7_i64,
                &FragmentWriteClaimState::Prepared.bits(),
            ],
        )
        .await
        .expect("insert a live send barrier");
    (logical_request_id, attempt_id)
}

async fn claim_row_count(direct: &Client, logical_request_id: &[u8], attempt_id: &[u8]) -> i64 {
    direct
        .query_one(
            "SELECT count(*) FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[&logical_request_id, &attempt_id],
        )
        .await
        .expect("count one claim row")
        .get(0)
}

/// WP-118: one blocked hash must not own the whole prune batch.
///
/// Before the plan query gained its anti-join against active claims, the batch
/// was selected by `settled_at` order alone. The oldest terminal rows therefore
/// won every slot of the `LIMIT` on every pass; the loop then skipped each of
/// them because the hash still carried a live send barrier, and younger
/// prunable rows on every other hash were never reached. Measured before the
/// fix: 256 of 256 slots to a single blocked hash, and 196 consecutive passes
/// in which nothing at all was deleted. A hash under continuous write traffic
/// regenerates those claims indefinitely, so the batch never self-clears.
///
/// This is the smallest live reproduction: two aged Decisive rows on a blocked
/// hash, a younger Decisive row on a prunable one, and a batch limit exactly
/// the size of the blocked pair. Against the pre-fix plan query the pass
/// reports `examined: 2, pruned: 0, skipped_blocked: 2` and the prunable row
/// survives; with the anti-join the blocked hash is not planned at all.
///
/// The ordering is deliberately left as-is and is not what fixes this —
/// selection is. Ordering by `settled_at` is still correct: oldest-first is the
/// retention order a prune wants, once the rows it cannot delete are out of the
/// candidate set.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_blocked_hash_does_not_occupy_the_prune_batch_and_starve_a_younger_prunable_hash() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    // The blocked hash: one real decisive publication, so its claim carries
    // durable epoch evidence and is genuinely eligible on the plan query's own
    // terms. Only the barrier stops it being deleted.
    let blocked_hash = aged_decisive_publication(&coordinator, &direct, 0x91).await;
    let evidence = claim_evidence(&direct, &blocked_hash).await;

    // A second aged terminal row on the same hash, sharing the first's exact
    // epoch evidence so it satisfies the plan query's decisive EXISTS clause
    // too. Two rows is what makes this head-of-line occupancy rather than a
    // single unlucky candidate: they fill the whole batch between them.
    insert_aged_terminal_claim(
        &direct,
        &blocked_hash,
        &evidence,
        0x93,
        FragmentWriteClaimState::Decisive,
    )
    .await;
    insert_live_send_barrier(&direct, &blocked_hash, &evidence, 0x95).await;

    // The prunable hash: a younger terminal row on a hash with no barrier at
    // all. It sorts last, so it is exactly what the pre-fix batch never reached.
    let prunable_hash = random_hash();
    let prunable_key = legacy_key(&prunable_hash);
    let BeginOutcome::Admitted(prunable_intent) = coordinator
        .begin_direct_write(&prunable_hash, &prunable_key)
        .await
        .expect("prepare the prunable hash's publication")
    else {
        panic!("a fresh hash must admit its direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &prunable_intent,
                IoObservation::Valid(manifest(&prunable_key, 0x98, EpochAuthority::Remote)),
            )
            .await
            .expect("publish the prunable hash's decisive evidence"),
        CommitVerdict::Published
    );
    let prunable_claim = prunable_intent
        .write_claim()
        .expect("prunable publication claim");
    tokio::time::sleep(Duration::from_millis(5)).await;

    // A batch exactly the size of the blocked pair. Pre-fix the two blocked
    // rows sort first and take both slots.
    let report = coordinator
        .prune_terminal_write_claims(
            FragmentWriteClaimPruneBatch::new(2, Duration::from_millis(1))
                .expect("two-slot prune batch"),
        )
        .await
        .expect("prune past a blocked hash in one pass");
    assert_eq!(
        report,
        FragmentWriteClaimPruneReport {
            examined: 1,
            pruned: 1,
            skipped_blocked: 0,
            skipped_missing_evidence: 0,
        },
        "the blocked hash must be excluded by the plan, not skipped inside the batch"
    );

    let prunable_remaining = claim_row_count(
        &direct,
        prunable_claim.logical_request_id().as_slice(),
        prunable_claim.attempt_id().as_slice(),
    )
    .await;
    assert_eq!(
        prunable_remaining, 0,
        "the younger prunable row must be reached in this single pass"
    );

    // The blocked hash keeps all three rows: the anti-join is a selection
    // filter, not a licence to delete past a live barrier.
    let blocked_remaining: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_fragment_write_claims WHERE hash = $1",
            &[&blocked_hash],
        )
        .await
        .expect("count the blocked hash's survivors")
        .get(0);
    assert_eq!(blocked_remaining, 3);
    // No assertion here that the barrier row is still `Prepared`. Once the hash
    // is excluded from the plan, `write_claim_barrier_for_prune` never runs
    // against it, so such an assertion could not discriminate any
    // implementation. The Prepared normalization contract is exercised where it
    // is reachable, by
    // `prune_normalizes_expired_prepared_to_targetless_no_send_and_honors_batch_limit`
    // and, under a live barrier, by
    // `a_barriered_hash_still_yields_its_no_send_claims_while_its_decisive_claims_stay_excluded`.
}

/// WP-118: the head-locked barrier re-check, not the anti-join, is the safety
/// gate — and this is the only case that executes it.
///
/// The plan query's anti-join runs unlocked on a pooled connection, so it is
/// advisory: a hash can gain an active claim between the plan and the head
/// lock. `write_claim_barrier_for_prune` is what actually refuses the delete,
/// and it is the reason `prune_terminal_write_claims` may read claim rows
/// without `FOR UPDATE` at all. Nothing exercised it before this case.
///
/// Deterministic interleaving, not timing, and no failpoint — the same method
/// as `a_concurrent_create_association_landing_between_the_plan_and_the_head_lock_is_refused_with_zero_mutation`.
/// An external transaction takes the hash's lifecycle row `FOR UPDATE` and
/// inserts the barrier claim **in that same uncommitted transaction**. The
/// prune's plan query runs on a different, pooled connection and cannot see an
/// uncommitted row, so the hash *is* planned; the loop then parks at
/// `lock_fragment_head`. Releasing the external transaction lets the loop
/// through, and by then the barrier claim is durably committed.
///
/// `examined: 1` is load-bearing alongside `skipped_blocked: 1`: together they
/// prove the plan admitted the candidate and the locked re-check alone refused
/// it. Were the interleaving to collapse — the insert committing before the
/// plan ran — the anti-join would exclude the hash and `examined` would be 0,
/// so this case cannot pass by accidentally proving the advisory filter instead.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn the_head_locked_barrier_recheck_refuses_a_claim_the_unlocked_plan_query_admitted() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    let hash = aged_decisive_publication(&coordinator, &direct, 0xb1).await;
    let evidence = claim_evidence(&direct, &hash).await;
    let target = direct
        .query_one(
            "SELECT logical_request_id, attempt_id FROM lore_fragment_write_claims \
              WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read the candidate's identity");
    let target_request: Vec<u8> = target.get("logical_request_id");
    let target_attempt: Vec<u8> = target.get("attempt_id");

    let mut lock_client = own_transaction_client(&url).await;
    let lock_tx = lock_client
        .transaction()
        .await
        .expect("open the external head-lock transaction");
    lock_tx
        .execute(
            "SELECT 1 FROM lore_fragment_lifecycle WHERE hash = $1 FOR UPDATE",
            &[&hash],
        )
        .await
        .expect("lock the lifecycle head externally");
    lock_tx
        .execute(
            "INSERT INTO lore_fragment_write_claims ( \
                logical_request_id, attempt_id, hash, epoch, fence, authority, object_key, \
                body_blake3, body_size, state, send_not_after, hard_not_after, prepared_at \
             ) VALUES ( \
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                clock_timestamp() + interval '1 hour', \
                clock_timestamp() + interval '2 hours', \
                clock_timestamp() \
             )",
            &[
                &vec![0xb3_u8; 16],
                &vec![0xb4_u8; 16],
                &hash,
                &evidence.epoch,
                &evidence.fence,
                &evidence.authority,
                &evidence.object_key,
                &vec![0xb5_u8; 32],
                &7_i64,
                &FragmentWriteClaimState::Prepared.bits(),
            ],
        )
        .await
        .expect("insert the racing barrier inside the uncommitted transaction");

    let prune = coordinator.prune_terminal_write_claims(
        FragmentWriteClaimPruneBatch::new(4, Duration::from_millis(1))
            .expect("bounded racing prune batch"),
    );
    let release = async {
        tokio::time::sleep(Duration::from_millis(150)).await;
        lock_tx
            .commit()
            .await
            .expect("release the external head lock");
    };
    let (report, ()) = tokio::join!(prune, release);

    assert_eq!(
        report.expect("racing prune pass"),
        FragmentWriteClaimPruneReport {
            examined: 1,
            pruned: 0,
            skipped_blocked: 1,
            skipped_missing_evidence: 0,
        },
        "the unlocked plan admitted this candidate; only the head-locked \
         barrier re-check may refuse it"
    );
    assert_eq!(
        claim_row_count(&direct, &target_request, &target_attempt).await,
        1,
        "a barrier observed under the head lock must leave the claim in place"
    );
}

/// WP-118: both ways a prune candidate can lose its evidence between the
/// unlocked plan and the head lock, and neither may delete anything.
///
/// No case asserted `skipped_missing_evidence` non-zero before this one, so
/// both arms that feed it were unexecuted.
///
/// Phase A is the natural race: the candidate's own claim row is deleted by a
/// competitor holding the head lock. Same two-connection interleaving as the
/// barrier case, with a `DELETE` in place of the insert — `examined: 1` again
/// proves the plan admitted the row before it vanished.
///
/// Phase B is the headless candidate, and it needs no concurrency at all. A
/// claim whose hash has no `lore_fragment_lifecycle` row offers no head lock to
/// take, so the premise that lets the barrier probe read without `FOR UPDATE`
/// is simply false there. The loop must stop rather than inherit a lock it
/// never acquired. This arm is discriminating on its own: proceeding on
/// `lock_fragment_head`'s `None` deletes the row and reports `pruned: 1`.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_candidate_that_loses_its_row_or_its_head_between_plan_and_lock_deletes_nothing() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    // Phase A: the claim row is deleted under the head lock while the prune is
    // parked on that same lock.
    let raced_hash = aged_decisive_publication(&coordinator, &direct, 0xc1).await;
    let mut lock_client = own_transaction_client(&url).await;
    let lock_tx = lock_client
        .transaction()
        .await
        .expect("open the external head-lock transaction");
    lock_tx
        .execute(
            "SELECT 1 FROM lore_fragment_lifecycle WHERE hash = $1 FOR UPDATE",
            &[&raced_hash],
        )
        .await
        .expect("lock the lifecycle head externally");
    lock_tx
        .execute(
            "DELETE FROM lore_fragment_write_claims WHERE hash = $1",
            &[&raced_hash],
        )
        .await
        .expect("delete the candidate inside the uncommitted transaction");

    let prune = coordinator.prune_terminal_write_claims(
        FragmentWriteClaimPruneBatch::new(4, Duration::from_millis(1))
            .expect("bounded racing prune batch"),
    );
    let release = async {
        tokio::time::sleep(Duration::from_millis(150)).await;
        lock_tx
            .commit()
            .await
            .expect("release the external head lock");
    };
    let (raced_report, ()) = tokio::join!(prune, release);
    assert_eq!(
        raced_report.expect("racing prune pass"),
        FragmentWriteClaimPruneReport {
            examined: 1,
            pruned: 0,
            skipped_blocked: 0,
            skipped_missing_evidence: 1,
        },
        "a candidate whose row moved under the head lock is missing evidence, \
         not a silent loss"
    );

    // Phase B: a terminal claim on a hash that has no lifecycle head at all.
    //
    // Phase B's `examined: 1` only means what it says while phase A's row is
    // really gone, so assert that rather than inheriting it. Without this pin a
    // phase A that stopped deleting would silently make phase B's expectation
    // wrong instead of failing.
    let claims_before_phase_b: i64 = direct
        .query_one("SELECT count(*) FROM lore_fragment_write_claims", &[])
        .await
        .expect("count claims left by phase A")
        .get(0);
    assert_eq!(
        claims_before_phase_b, 0,
        "phase A must leave no claim row, or phase B's batch is not what it claims"
    );

    let headless_hash = random_hash();
    let headless_request = vec![0xc5_u8; 16];
    let headless_attempt = vec![0xc6_u8; 16];
    direct
        .execute(
            "INSERT INTO lore_fragment_write_claims ( \
                logical_request_id, attempt_id, hash, epoch, fence, authority, object_key, \
                body_blake3, body_size, state, send_not_after, hard_not_after, prepared_at, \
                settled_at \
             ) VALUES ( \
                $1, $2, $3, 1, 1, $4, $5, $6, 7, $7, \
                clock_timestamp() - interval '11 seconds', \
                clock_timestamp() - interval '10 seconds', \
                clock_timestamp() - interval '12 seconds', \
                clock_timestamp() - interval '9 seconds' \
             )",
            &[
                &headless_request,
                &headless_attempt,
                &headless_hash,
                &EpochAuthority::Remote.bits(),
                &legacy_key(&headless_hash),
                &vec![0xc7_u8; 32],
                &FragmentWriteClaimState::NoSend.bits(),
            ],
        )
        .await
        .expect("insert a terminal claim on a headless hash");
    let headless_head: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&headless_hash],
        )
        .await
        .expect("confirm the headless hash has no lifecycle row")
        .get(0);
    assert_eq!(headless_head, 0);

    let headless_report = coordinator
        .prune_terminal_write_claims(
            FragmentWriteClaimPruneBatch::new(4, Duration::from_millis(1))
                .expect("bounded headless prune batch"),
        )
        .await
        .expect("headless prune pass");
    assert_eq!(
        headless_report,
        FragmentWriteClaimPruneReport {
            examined: 1,
            pruned: 0,
            skipped_blocked: 0,
            skipped_missing_evidence: 1,
        },
        "with no head row there is no lock to serialise on, so the loop must stop"
    );
    assert_eq!(
        claim_row_count(&direct, &headless_request, &headless_attempt).await,
        1,
        "a headless candidate must survive, not be deleted without a head lock"
    );
}

/// WP-118: the third `skipped_missing_evidence` feeder — the delete's own CAS
/// refusing a plan that went stale under the lock.
///
/// The plan query reads unlocked on a pooled connection, so every candidate it
/// hands the loop is a *claim* about eligibility, not a fact. Each delete
/// re-states the full eligibility predicate — identity, state, and the
/// retention window — and a zero-row result means the plan was stale. That
/// feeder had no executed coverage: the sibling case above reaches
/// `skipped_missing_evidence` through the Decisive arm's `locked` guard, which
/// returns before any delete runs.
///
/// The lever here is the retention window, because it is the only clause a
/// surviving NoSend row can fall foul of — NoSend is terminal, so no transition
/// moves its state, and identity is immutable. It is also the clause worth
/// pinning: a delete that trusted the plan's retention check instead of
/// re-stating its own would delete a row that is no longer eligible, and the
/// row surviving is what proves it did not. The row moving out of the window
/// under the head lock stands in for any way the plan's premise can lapse; the
/// property under test is that the delete re-checks rather than trusts.
///
/// Deterministic: the retention window is five seconds and the external
/// transaction resets `settled_at` to the database clock, so the row is outside
/// the window by seconds, not milliseconds, when the delete re-evaluates.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_candidate_that_leaves_the_retention_window_under_the_head_lock_is_refused_by_its_delete()
{
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    // A real publication supplies the lifecycle head the loop requires; its own
    // claim is then cleared so the synthetic NoSend row is the only candidate.
    let hash = aged_decisive_publication(&coordinator, &direct, 0xe1).await;
    let evidence = claim_evidence(&direct, &hash).await;
    direct
        .execute(
            "DELETE FROM lore_fragment_write_claims WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("clear the publication's own claim");
    let (candidate_request, candidate_attempt) = insert_aged_terminal_claim(
        &direct,
        &hash,
        &evidence,
        0xe3,
        FragmentWriteClaimState::NoSend,
    )
    .await;
    let claims_before: i64 = direct
        .query_one("SELECT count(*) FROM lore_fragment_write_claims", &[])
        .await
        .expect("count claims before the pass")
        .get(0);
    assert_eq!(
        claims_before, 1,
        "the synthetic NoSend row must be the only candidate in this batch"
    );

    let mut lock_client = own_transaction_client(&url).await;
    let lock_tx = lock_client
        .transaction()
        .await
        .expect("open the external head-lock transaction");
    lock_tx
        .execute(
            "SELECT 1 FROM lore_fragment_lifecycle WHERE hash = $1 FOR UPDATE",
            &[&hash],
        )
        .await
        .expect("lock the lifecycle head externally");
    lock_tx
        .execute(
            "UPDATE lore_fragment_write_claims SET settled_at = clock_timestamp() \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[&candidate_request, &candidate_attempt],
        )
        .await
        .expect("move the candidate back inside retention while holding the head");

    let prune = coordinator.prune_terminal_write_claims(
        FragmentWriteClaimPruneBatch::new(4, Duration::from_secs(5))
            .expect("five-second retention prune batch"),
    );
    let release = async {
        tokio::time::sleep(Duration::from_millis(150)).await;
        lock_tx
            .commit()
            .await
            .expect("release the external head lock");
    };
    let (report, ()) = tokio::join!(prune, release);

    assert_eq!(
        report.expect("stale-plan prune pass"),
        FragmentWriteClaimPruneReport {
            examined: 1,
            pruned: 0,
            skipped_blocked: 0,
            skipped_missing_evidence: 1,
        },
        "a delete whose own retention re-check fails is missing evidence, not a prune"
    );
    assert_eq!(
        claim_row_count(&direct, &candidate_request, &candidate_attempt).await,
        1,
        "a row back inside the retention window must survive its own delete"
    );
}

/// WP-118: the anti-join must be exactly as strict as the loop it feeds, and no
/// stricter.
///
/// The loop exempts `NoSend` from the barrier: a NoSend claim records that no
/// provider send occurred, so it names no cleanup target and another claim
/// being in flight on the hash has no bearing on it. A hash-wide anti-join
/// spanning both arms therefore contradicted the loop — it stopped *selecting*
/// NoSend rows on a barriered hash that the loop would happily have pruned,
/// making the exemption near-dead code and letting a hot hash accumulate NoSend
/// claims forever. Measured on the shipped form: 256 hot NoSend rows selected;
/// on the hash-wide form, 0.
///
/// So the anti-join sits inside the Decisive arm. `NoSend` needs only age;
/// `Decisive` needs age, exact epoch evidence, and no barrier. This case
/// asserts both halves against one barriered hash in a single pass, which is
/// what makes it fail against the hash-wide placement rather than merely
/// looking different.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_barriered_hash_still_yields_its_no_send_claims_while_its_decisive_claims_stay_excluded()
{
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    // One hot hash: a real aged Decisive claim, a live send barrier, and three
    // aged NoSend rows of the kind continuous write traffic leaves behind.
    let hash = aged_decisive_publication(&coordinator, &direct, 0xd1).await;
    let evidence = claim_evidence(&direct, &hash).await;
    let decisive = direct
        .query_one(
            "SELECT logical_request_id, attempt_id FROM lore_fragment_write_claims \
              WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read the decisive claim's identity");
    let decisive_request: Vec<u8> = decisive.get("logical_request_id");
    let decisive_attempt: Vec<u8> = decisive.get("attempt_id");
    let (barrier_request, barrier_attempt) =
        insert_live_send_barrier(&direct, &hash, &evidence, 0xd3).await;

    let mut no_send_rows = Vec::new();
    for seed in [0xd5_u8, 0xd7_u8, 0xd9_u8] {
        no_send_rows.push(
            insert_aged_terminal_claim(
                &direct,
                &hash,
                &evidence,
                seed,
                FragmentWriteClaimState::NoSend,
            )
            .await,
        );
    }

    // A batch with room for every terminal row on the hash, so what is left
    // behind is a selection decision rather than a `LIMIT`.
    let report = coordinator
        .prune_terminal_write_claims(
            FragmentWriteClaimPruneBatch::new(4, Duration::from_millis(1))
                .expect("four-slot prune batch"),
        )
        .await
        .expect("prune a barriered hash's NoSend claims");
    assert_eq!(
        report,
        FragmentWriteClaimPruneReport {
            examined: 3,
            pruned: 3,
            skipped_blocked: 0,
            skipped_missing_evidence: 0,
        },
        "a live barrier must not withhold NoSend claims from the plan"
    );

    for (request, attempt) in &no_send_rows {
        assert_eq!(
            claim_row_count(&direct, request, attempt).await,
            0,
            "every aged NoSend row on the barriered hash must be pruned"
        );
    }
    assert_eq!(
        claim_row_count(&direct, &decisive_request, &decisive_attempt).await,
        1,
        "the barriered Decisive claim must stay excluded in the same pass"
    );
    // Reachable here, unlike in the plan-excluded case above: the loop really
    // does run the barrier probe against this hash for each NoSend candidate,
    // so an unexpired Prepared row surviving as Prepared is a discriminating
    // observation rather than a vacuous one.
    let barrier_state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[&barrier_request, &barrier_attempt],
        )
        .await
        .expect("read the live send barrier after the pass")
        .get(0);
    assert_eq!(
        barrier_state,
        FragmentWriteClaimState::Prepared.bits(),
        "an unexpired Prepared claim must not be normalized to NoSend"
    );
}

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn lifecycle_metering_rebuild_is_exact_removes_stale_rows_and_is_idempotent() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    let remote = random_hash();
    let missing = random_hash();
    let deleting_children = random_hash();
    let deleting_payload = random_hash();
    let preparing = random_hash();
    let tombstoned = random_hash();
    let purged = random_hash();
    let mismatched_readable = random_hash();
    let fixtures = [
        (&remote, FragmentLifecycleState::Remote, 0_i16, true),
        (&missing, FragmentLifecycleState::Missing, 0_i16, false),
        (
            &deleting_children,
            FragmentLifecycleState::DeletingChildren,
            0_i16,
            false,
        ),
        (
            &deleting_payload,
            FragmentLifecycleState::DeletingPayload,
            0_i16,
            false,
        ),
        (
            &preparing,
            FragmentLifecycleState::PreparingRemote,
            0_i16,
            false,
        ),
        (
            &tombstoned,
            FragmentLifecycleState::Tombstoned,
            0_i16,
            false,
        ),
        (&purged, FragmentLifecycleState::Missing, 2_i16, false),
        (
            &mismatched_readable,
            FragmentLifecycleState::Remote,
            0_i16,
            true,
        ),
    ];

    for (ordinal, (hash, state, disposition, readable)) in fixtures.iter().enumerate() {
        let epoch = i64::try_from(ordinal + 1).expect("small fixture ordinal");
        let seed = u8::try_from(ordinal + 1).expect("small fixture ordinal");
        let epoch_manifest = vec![seed; 32];
        let head_manifest = readable.then(|| {
            if *hash == &mismatched_readable {
                vec![0xFE; 32]
            } else {
                epoch_manifest.clone()
            }
        });
        direct
            .execute(
                "INSERT INTO lore_fragment_epochs (hash, epoch, authority, object_key, \
                     manifest_id, size_payload, size_content, decoded_hash, payload_flags, \
                     fence, disposition) \
                 VALUES ($1, $2, 2, $3, $4, $5, $6, $7, $8, $9, $10)",
                &[
                    hash,
                    &epoch,
                    &legacy_key(hash),
                    &epoch_manifest,
                    &(100_i64 + epoch),
                    &(200_i64 + epoch),
                    &vec![seed.wrapping_add(1); 32],
                    &i64::from(seed),
                    &epoch,
                    disposition,
                ],
            )
            .await
            .expect("insert authoritative epoch fixture");
        direct
            .execute(
                "INSERT INTO lore_fragment_lifecycle \
                     (hash, current_epoch, state, manifest_id, last_fence) \
                 VALUES ($1, $2, $3, $4, $5)",
                &[hash, &epoch, &state.bits(), &head_manifest, &epoch],
            )
            .await
            .expect("insert lifecycle head fixture");
        direct
            .execute(
                "INSERT INTO lore_fragment_lifecycle_metering \
                     (hash, epoch, payload_flags, size_payload, size_content, authority) \
                 VALUES ($1, 99, 0, 1, 1, 1)",
                &[hash],
            )
            .await
            .expect("insert deliberately stale projection fixture");
    }
    let orphan = random_hash();
    direct
        .execute(
            "INSERT INTO lore_fragment_lifecycle_metering \
                 (hash, epoch, payload_flags, size_payload, size_content, authority) \
             VALUES ($1, 99, 0, 1, 1, 1)",
            &[&orphan],
        )
        .await
        .expect("insert orphan projection row");

    let rebuilt = coordinator
        .rebuild_metering_projection()
        .await
        .expect("rebuild exact lifecycle projection");
    assert_eq!(rebuilt, 4);
    let rows = direct
        .query(
            "SELECT hash, epoch, payload_flags, size_payload, size_content, authority \
               FROM lore_fragment_lifecycle_metering ORDER BY hash",
            &[],
        )
        .await
        .expect("read rebuilt projection");
    assert_eq!(rows.len(), 4);
    for expected_hash in [&remote, &missing, &deleting_children, &deleting_payload] {
        let row = rows
            .iter()
            .find(|row| row.get::<_, Vec<u8>>("hash") == *expected_hash)
            .expect("eligible lifecycle row must be projected");
        let ordinal = fixtures
            .iter()
            .position(|(hash, _, _, _)| *hash == expected_hash)
            .expect("eligible hash fixture ordinal");
        let epoch = i64::try_from(ordinal + 1).expect("small fixture ordinal");
        assert_eq!(row.get::<_, i64>("epoch"), epoch);
        assert_eq!(row.get::<_, i64>("payload_flags"), epoch);
        assert_eq!(row.get::<_, i64>("size_payload"), 100 + epoch);
        assert_eq!(row.get::<_, i64>("size_content"), 200 + epoch);
        assert_eq!(row.get::<_, i16>("authority"), 2);
    }
    for excluded in [
        &preparing,
        &tombstoned,
        &purged,
        &mismatched_readable,
        &orphan,
    ] {
        assert!(
            rows.iter()
                .all(|row| row.get::<_, Vec<u8>>("hash") != *excluded),
            "ineligible or orphan row survived the rebuild"
        );
    }

    assert_eq!(
        coordinator
            .rebuild_metering_projection()
            .await
            .expect("repeat exact lifecycle projection rebuild"),
        4,
        "an idempotent rebuild returns the same authoritative count"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn lifecycle_metering_rebuild_serializes_behind_an_inflight_epoch_writer_without_deadlock() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let hash = random_hash();
    let initial_manifest = vec![0x31_u8; 32];
    let direct = client(&url).await;
    direct
        .execute(
            "INSERT INTO lore_fragment_epochs \
                 (hash, epoch, authority, object_key, manifest_id, size_payload, \
                  size_content, decoded_hash, payload_flags, fence, disposition) \
             VALUES ($1, 1, 2, $2, $3, 10, 11, $4, 0, 1, 0)",
            &[
                &hash,
                &legacy_key(&hash),
                &initial_manifest,
                &vec![0x32_u8; 32],
            ],
        )
        .await
        .expect("insert initial epoch");
    direct
        .execute(
            "INSERT INTO lore_fragment_lifecycle \
                 (hash, current_epoch, state, manifest_id, last_fence) \
             VALUES ($1, 1, 7, NULL, 1)",
            &[&hash],
        )
        .await
        .expect("insert initial Missing head");

    let mut writer = own_transaction_client(&url).await;
    let writer_tx = writer.transaction().await.expect("writer transaction");
    writer_tx
        .query_one(
            "SELECT hash FROM lore_fragment_lifecycle WHERE hash = $1 FOR UPDATE",
            &[&hash],
        )
        .await
        .expect("writer locks lifecycle head before epoch mutation");
    writer_tx
        .execute(
            "INSERT INTO lore_fragment_epochs \
                 (hash, epoch, authority, object_key, manifest_id, size_payload, \
                  size_content, decoded_hash, payload_flags, fence, disposition) \
             VALUES ($1, 2, 2, $2, $3, 20, 21, $4, 0, 2, 0)",
            &[
                &hash,
                &format!("{}.r2", legacy_key(&hash)),
                &vec![0x41_u8; 32],
                &vec![0x42_u8; 32],
            ],
        )
        .await
        .expect("writer inserts successor epoch while retaining head lock");

    let rebuilding = coordinator.clone();
    let rebuild =
        lore_base::lore_spawn!(async move { rebuilding.rebuild_metering_projection().await });
    let observer = client(&url).await;
    timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = observer
                .query_one(
                    "SELECT EXISTS ( \
                         SELECT 1 FROM pg_stat_activity \
                          WHERE datname = current_database() \
                            AND pid <> pg_backend_pid() \
                            AND wait_event_type = 'Lock' \
                            AND query LIKE '%LOCK TABLE lore_fragment_lifecycle IN EXCLUSIVE MODE%' \
                     )",
                    &[],
                )
                .await
                .expect("observe blocked rebuild")
                .get(0);
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("rebuild must block first on the lifecycle EXCLUSIVE lock");

    let (rebuilt, ()) = timeout(Duration::from_secs(5), async {
        writer_tx
            .execute(
                "UPDATE lore_fragment_lifecycle \
                    SET current_epoch = 2, last_fence = 2, updated_at = clock_timestamp() \
                  WHERE hash = $1",
                &[&hash],
            )
            .await
            .expect("writer advances lifecycle head");
        writer_tx
            .commit()
            .await
            .expect("writer commits successor epoch");
        let rebuilt = rebuild
            .await
            .expect("join rebuilding task")
            .expect("rebuild after writer commit");
        (rebuilt, ())
    })
    .await
    .expect("writer and rebuild must serialize without a table-lock deadlock");
    assert_eq!(rebuilt, 1);
    assert_eq!(
        observer
            .query_one(
                "SELECT epoch FROM lore_fragment_lifecycle_metering WHERE hash = $1",
                &[&hash],
            )
            .await
            .expect("read serialized projection")
            .get::<_, i64>(0),
        2,
        "rebuild must project the committed successor, never a partial epoch/head snapshot"
    );
}

/// Connect and install SCHEMA-118 through the isolated component fixture.
/// Production never calls `bootstrap()` (it is migration-owned), so this is a
/// test-only shortcut, exactly like `PostgresLockCoordinator::bootstrap()`.
async fn store(url: &str) -> TestDomainStore {
    store_with_pool(url, 8).await
}

async fn store_with_pool(url: &str, pool_max: u32) -> TestDomainStore {
    let store = PostgresDomainStore::connect(url, pool_max, &TlsConfig::default())
        .await
        .expect("connect domain store");
    store
        .fragment_coordinator()
        .bootstrap()
        .await
        .expect("install isolated SCHEMA-118 fixture");
    TestDomainStore(store)
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

fn uuid_v7_at(time: SystemTime) -> Uuid {
    let elapsed = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("test timestamp follows epoch");
    Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        elapsed.as_secs(),
        elapsed.subsec_nanos(),
    ))
}

/// PostgreSQL `timestamptz` is microsecond-precision; a `SystemTime` with a
/// sub-microsecond remainder (Windows' `SystemTime::now()` is 100 ns
/// resolution) would silently lose precision on a round trip through the
/// database, breaking an exact deadline-equality assertion for a reason that
/// has nothing to do with the coordinator's own logic. Truncate before using
/// a deadline in an assertion that reads it back from a stored row.
fn microsecond_deadline(offset: Duration) -> SystemTime {
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("test timestamp follows epoch");
    let micros =
        u64::try_from(since_epoch.as_micros()).expect("test timestamp fits in u64 microseconds");
    SystemTime::UNIX_EPOCH + Duration::from_micros(micros) + offset
}

fn binding(method: &str) -> OperationBinding {
    OperationBinding {
        method: method.to_owned(),
        scope: rand::random::<[u8; 16]>().to_vec(),
        fingerprint_version: 1,
        fingerprint: rand::random::<[u8; 32]>().to_vec(),
        canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

/// Prepare one admissible receipt for a CR-029 domain-level operation (e.g.
/// `PostgresDomainStore::begin_obliterate`, the repository-generation fence).
/// The fragment coordinator's own begin/commit pairs take no `GovernedOperation`
/// at all -- they are not receipted CR-029 mutations -- so this helper exists
/// only for the CR-029 domain-store calls this file makes to move a
/// repository's generation.
async fn prepare_operation(store: &PostgresDomainStore, method: &str) -> GovernedOperation {
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("read receipt database clock");
    let key = ReceiptKey {
        verified_issuer: format!(
            "https://issuer.example/wp118/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "svc:wp118-fragment-test".to_owned(),
        tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
        operation_id: uuid_v7_at(clock),
    };
    let op_binding = binding(method);
    let prepared = store
        .domain_operation_prepare(&key, &op_binding, None, None)
        .await
        .expect("prepare domain operation");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("an admissible domain operation must prepare, got {prepared:?}");
    };
    GovernedOperation {
        key,
        binding: op_binding,
        prepare_token: token,
    }
}

async fn create_repository(store: &PostgresDomainStore) -> [u8; 16] {
    let repository_id: [u8; 16] = rand::random();
    let branch_id: [u8; 16] = rand::random();
    let operation = prepare_operation(store, "lore.domain.v1.test/FragmentRepositoryCreate").await;
    let input = RepositoryCreateInput {
        repository_id: repository_id.to_vec(),
        name: format!("wp118-fragment-{:016x}", rand::random::<u64>()),
        metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_id: branch_id.to_vec(),
        default_branch_name: "main".to_owned(),
        default_branch_metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_latest_hash: rand::random::<[u8; 32]>().to_vec(),
        creation_fingerprint: rand::random::<[u8; 32]>().to_vec(),
        creation_fingerprint_version: 1,
        projection: Vec::new(),
        events: Vec::new(),
    };
    let result = store
        .repository_create(&operation, &input)
        .await
        .expect("create repository fixture");
    assert_eq!(result.outcome, DomainOutcome::Applied);
    repository_id
}

fn random_hash() -> Vec<u8> {
    rand::random::<[u8; 32]>().to_vec()
}

fn legacy_key(hash: &[u8]) -> String {
    hash.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn staged_key(hash: &[u8], epoch: i64) -> String {
    format!("{}.s{epoch}", legacy_key(hash))
}

fn random_context() -> Vec<u8> {
    rand::random::<[u8; 16]>().to_vec()
}

fn manifest(object_key: &str, seed: u8, authority: EpochAuthority) -> FragmentManifest {
    FragmentManifest {
        authority,
        object_key: object_key.to_owned(),
        manifest_id: vec![seed; 32],
        size_payload: 128,
        size_content: 128,
        decoded_hash: vec![seed.wrapping_add(1); 32],
        payload_flags: 0,
    }
}

fn expect_readable(resolution: &FragmentResolution) -> (&EpochWitness, &FragmentManifest, i64) {
    match &resolution.verdict {
        FragmentVerdict::Readable {
            witness,
            manifest,
            association_epoch,
        } => (witness, manifest, *association_epoch),
        FragmentVerdict::Absent => panic!(
            "expected Readable for hash {:02x?}, got Absent",
            resolution.hash
        ),
    }
}

fn expect_absent(resolution: &FragmentResolution) {
    assert!(
        matches!(resolution.verdict, FragmentVerdict::Absent),
        "expected Absent for hash {:02x?}, got {:?}",
        resolution.hash,
        resolution.verdict
    );
}

/// Item 1: the batched resolver must return the identical verdict for a given
/// (hash, repository, context) whichever caller shape asks. A batched request
/// repeating the same hash mimics two simultaneous callers; a single-hash
/// request mimics `get`/`get_metadata`.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn resolver_returns_the_identical_verdict_whether_asked_singly_or_batched() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();

    let readable_hash = random_hash();
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&readable_hash, &legacy_key(&readable_hash))
        .await
        .expect("begin readable")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    let published_manifest = manifest("resolver-agreement/readable", 0x60, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_remote(&intent, IoObservation::Valid(published_manifest.clone()))
            .await
            .expect("commit readable"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&readable_hash, &repository_id, &context)
            .await
            .expect("associate readable"),
        CommitVerdict::Published
    );

    let absent_hash = random_hash(); // never written at all

    let batched = coordinator
        .resolve(
            &repository_id,
            &context,
            &[
                readable_hash.clone(),
                absent_hash.clone(),
                readable_hash.clone(),
            ],
        )
        .await
        .expect("batched resolve");
    let single_readable = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&readable_hash),
        )
        .await
        .expect("single readable resolve");
    let single_absent = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&absent_hash))
        .await
        .expect("single absent resolve");

    assert_eq!(batched.len(), 3);
    assert_eq!(
        batched[0], batched[2],
        "two batched requests for the same hash must agree"
    );
    assert_eq!(
        batched[0], single_readable[0],
        "a batched and a single-hash request for the same hash must agree"
    );
    assert_eq!(
        batched[1], single_absent[0],
        "a batched and a single-hash request for the same absent hash must agree"
    );

    let (witness, resolved_manifest, association_epoch) = expect_readable(&batched[0]);
    assert_eq!(resolved_manifest, &published_manifest);
    assert_eq!(witness.hash, readable_hash);
    assert!(association_epoch >= 1);
    expect_absent(&batched[1]);
}

/// Item 2, corrected against the reviewed contract: `resolve`'s
/// repository-generation clause is `<=`, not `=` (an ordinary metadata CAS
/// bumping `lore_domain_repositories.generation` must not fence an existing
/// association — equality would make every fragment in a repository
/// permanently `Absent` the moment anyone touched its metadata). The real
/// permanent fence is a repository tombstone, checked via `r.state`, and a
/// tombstoned association is the other independent fence.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn stale_association_rejection_comes_from_repository_tombstone_not_generation_drift() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let context = random_context();

    // An ordinary repository generation bump (CR-029's own
    // repository-obliteration fence is a convenient generation-only bump that
    // leaves the repository live) must NOT fence an existing association.
    let repository_id = create_repository(&store).await;
    let hash = random_hash();
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    let published = manifest("generation-drift/key", 0x70, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_remote(&intent, IoObservation::Valid(published.clone()))
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let bump_op = prepare_operation(&store, "lore.domain.v1.test/FragmentGenerationDrift").await;
    let bumped = store
        .begin_obliterate(&bump_op, &repository_id, None)
        .await
        .expect("begin_obliterate must not error");
    assert_eq!(bumped.outcome, DomainOutcome::Applied);

    let after_bump = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve after generation drift");
    let (_, resolved_manifest, _) = expect_readable(&after_bump[0]);
    assert_eq!(
        resolved_manifest, &published,
        "an ordinary repository generation bump must not fence an existing association"
    );

    // The real permanent fence is a repository tombstone.
    let delete_op =
        prepare_operation(&store, "lore.domain.v1.test/FragmentRepositoryTombstone").await;
    let deleted = store
        .repository_delete(
            &delete_op,
            &RepositoryDeleteInput {
                repository_id: repository_id.to_vec(),
                expected_generation: None,
                delete_proof: rand::random::<[u8; 32]>().to_vec(),
                projection: Vec::new(),
                events: Vec::new(),
            },
        )
        .await
        .expect("repository_delete must not error");
    assert_eq!(deleted.outcome, DomainOutcome::Applied);

    let after_tombstone = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve after repository tombstone");
    expect_absent(&after_tombstone[0]);

    // Half 2: a tombstoned association, independent of repository state.
    let repository_id_2 = create_repository(&store).await;
    let hash_2 = random_hash();
    let BeginOutcome::Admitted(intent_2) = coordinator
        .begin_direct_write(&hash_2, &legacy_key(&hash_2))
        .await
        .expect("begin 2")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent_2,
                IoObservation::Valid(manifest(
                    "tombstoned-association/key",
                    0x71,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit 2"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash_2, &repository_id_2, &context)
            .await
            .expect("associate 2"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .tombstone_association(&hash_2, &repository_id_2, &context)
            .await
            .expect("tombstone"),
        CommitVerdict::Published
    );

    let after_tombstone = coordinator
        .resolve(&repository_id_2, &context, std::slice::from_ref(&hash_2))
        .await
        .expect("resolve after tombstone");
    expect_absent(&after_tombstone[0]);
}

/// Item 3: a positive read needs a live association AND a readable current
/// epoch/manifest. Each missing half independently yields absent; both
/// present yields readable.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_positive_read_requires_both_a_live_association_and_a_readable_current_epoch() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();

    // Case A: a live association, but the head is not readable (Missing).
    let missing_hash = random_hash();
    let BeginOutcome::Admitted(intent_a) = coordinator
        .begin_direct_write(&missing_hash, &legacy_key(&missing_hash))
        .await
        .expect("begin missing")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent_a,
                IoObservation::Unusable(MissingDiagnostic::Truncated)
            )
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&missing_hash, &repository_id, &context)
            .await
            .expect("associate missing"),
        CommitVerdict::Published
    );

    // Case B: a readable head, but no association at all.
    let unassociated_hash = random_hash();
    let BeginOutcome::Admitted(intent_b) = coordinator
        .begin_direct_write(&unassociated_hash, &legacy_key(&unassociated_hash))
        .await
        .expect("begin unassociated")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent_b,
                IoObservation::Valid(manifest(
                    "half-unassociated/key",
                    0x80,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit unassociated"),
        CommitVerdict::Published
    );

    // Positive control: both halves present.
    let positive_hash = random_hash();
    let BeginOutcome::Admitted(intent_c) = coordinator
        .begin_direct_write(&positive_hash, &legacy_key(&positive_hash))
        .await
        .expect("begin positive")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent_c,
                IoObservation::Valid(manifest("half-both/key", 0x81, EpochAuthority::Remote))
            )
            .await
            .expect("commit positive"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&positive_hash, &repository_id, &context)
            .await
            .expect("associate positive"),
        CommitVerdict::Published
    );

    let resolved = coordinator
        .resolve(
            &repository_id,
            &context,
            &[
                missing_hash.clone(),
                unassociated_hash.clone(),
                positive_hash.clone(),
            ],
        )
        .await
        .expect("batch resolve");
    expect_absent(&resolved[0]);
    expect_absent(&resolved[1]);
    expect_readable(&resolved[2]);
}

/// Item 4, the discriminating case: a coordinator built on a **one-connection
/// pool** must not hold that connection across its caller's I/O phase.
/// `begin_direct_write` returns an owned [`FragmentIntent`] that borrows no
/// transaction, connection, or lock; this proves that structurally rather than
/// by source reading, by racing a second real pool operation during a real
/// await that stands in for blocked provider I/O, bounded by a timeout so a
/// held connection fails the test instead of hanging it.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_blocked_io_phase_does_not_hold_the_one_connection_pool() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store_with_pool(&url, 1).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin on a one-connection pool")
    else {
        panic!("a fresh hash must admit a direct write");
    };

    // The "I/O phase": sleep while holding the returned intent, standing in
    // for a blocked provider PUT. Concurrently, a second real coordinator
    // operation on the SAME one-connection pool must still complete: if
    // `begin_direct_write` had left a transaction or checked-out connection
    // open, the pool would have zero connections free and this would hang
    // until the bounded timeout below fires.
    let io_phase = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "one-connection/direct",
                    0x01,
                    EpochAuthority::Remote,
                )),
            )
            .await
    };
    let second_operation = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        timeout(
            Duration::from_secs(5),
            coordinator.resolve(&repository_id, &context, std::slice::from_ref(&hash)),
        )
        .await
    };

    let (commit_result, second_result) = tokio::join!(io_phase, second_operation);
    assert_eq!(
        commit_result.expect("commit must not error"),
        CommitVerdict::Published
    );
    let second_result = second_result.expect(
        "a second coordinator operation must complete within 5s on a one-connection pool; \
         a timeout means begin_direct_write's caller is still holding the sole connection \
         during its I/O phase",
    );
    second_result.expect("resolve must not error");
}

/// Item 5: two independently constructed coordinators (separate pools, same
/// database) racing the same fresh head. Exactly one must publish; the loser
/// is fenced.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn two_independently_constructed_coordinators_race_one_fresh_head_and_exactly_one_wins() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store_a = store(&url).await;
    let store_b = store_with_pool(&url, 8).await; // separate connect/pool; bootstrap is idempotent
    let coordinator_a = store_a.fragment_coordinator();
    let coordinator_b = store_b.fragment_coordinator();
    let repository_id = create_repository(&store_a).await;
    let context = random_context();
    let hash = random_hash();

    async fn race_attempt(
        coordinator: TestFragmentCoordinator,
        hash: Vec<u8>,
        manifest: FragmentManifest,
    ) -> bool {
        match coordinator
            .begin_direct_write(&hash, &legacy_key(&hash))
            .await
            .expect("begin must not error")
        {
            BeginOutcome::AlreadyReadable(_)
            | BeginOutcome::Fenced(_)
            | BeginOutcome::WriteClaimBlocked { .. } => false,
            BeginOutcome::Admitted(intent) => match coordinator
                .commit_remote(&intent, IoObservation::Valid(manifest))
                .await
            {
                Ok(CommitVerdict::Published) => true,
                Ok(CommitVerdict::Fenced | CommitVerdict::Abandoned) => false,
                Err(DomainError::PreconditionRejected { ref reason, .. })
                    if reason == "fragment_write_lineage_moved" =>
                {
                    false
                }
                result => panic!("race commit had an unrelated outcome: {result:?}"),
            },
        }
    }

    let (a_won, b_won) = tokio::join!(
        race_attempt(
            coordinator_a.clone(),
            hash.clone(),
            manifest("race/a", 0xA1, EpochAuthority::Remote),
        ),
        race_attempt(
            coordinator_b.clone(),
            hash.clone(),
            manifest("race/b", 0xB2, EpochAuthority::Remote),
        ),
    );
    assert_eq!(
        usize::from(a_won) + usize::from(b_won),
        1,
        "exactly one of two independently constructed coordinators must publish \
         against one shared head: a_won={a_won} b_won={b_won}"
    );

    assert_eq!(
        coordinator_a
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate the winner"),
        CommitVerdict::Published
    );
    let resolved = coordinator_a
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve winner");
    let (_, resolved_manifest, _) = expect_readable(&resolved[0]);
    assert!(
        resolved_manifest.object_key == "race/a" || resolved_manifest.object_key == "race/b",
        "published manifest must be exactly one contender's, not a merge: {resolved_manifest:?}"
    );
    assert_eq!(a_won, resolved_manifest.object_key == "race/a");
    assert_eq!(b_won, resolved_manifest.object_key == "race/b");
}

/// A direct-write retry against a persisted PreparingRemote head reuses the
/// exact witness. Once one copy commits, the late copy is fenced and cannot
/// publish a second epoch row.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_replayed_direct_write_reuses_exact_claim_and_terminal_attempt_cannot_publish_twice() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    let replay_claim = write_claim();
    let BeginOutcome::Admitted(first_intent) = coordinator
        .0
        .begin_direct_write(&hash, &legacy_key(&hash), replay_claim.clone())
        .await
        .expect("begin direct write")
    else {
        panic!("a fresh hash must admit a direct write");
    };

    let restarted = store_with_pool(&url, 8).await.fragment_coordinator();
    let BeginOutcome::Admitted(replayed_intent) = restarted
        .0
        .begin_direct_write(&hash, &legacy_key(&hash), replay_claim)
        .await
        .expect("replay persisted direct write")
    else {
        panic!("PreparingRemote must replay as admitted");
    };
    assert_eq!(replayed_intent.epoch, first_intent.epoch);
    assert_eq!(replayed_intent.fence, first_intent.fence);
    assert_eq!(replayed_intent.object_key, first_intent.object_key);
    assert_eq!(
        replayed_intent.direct_write_kind(),
        first_intent.direct_write_kind()
    );

    let winner_manifest = manifest("competing-write/winner", 0x10, EpochAuthority::Remote);
    assert_eq!(
        restarted
            .commit_remote(&replayed_intent, IoObservation::Valid(winner_manifest))
            .await
            .expect("replayed commit"),
        CommitVerdict::Published
    );

    let stale_manifest = manifest("competing-write/stale", 0x20, EpochAuthority::Remote);
    let late = coordinator
        .0
        .commit_remote(
            &first_intent,
            IoObservation::Valid(stale_manifest),
            FragmentWriteSettlement::Decisive,
        )
        .await
        .expect("the stale publication is fenced before claim settlement");
    assert_eq!(late, CommitVerdict::Fenced);

    let epoch_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &first_intent.epoch],
        )
        .await
        .expect("count stale epoch rows")
        .get(0);
    assert_eq!(
        epoch_rows, 1,
        "replay and terminal-attempt refusal must leave exactly one published epoch row"
    );
}

/// An exact-association obliterate cannot capture an unassociated preparing
/// write, so a foreign request is a no-op and cannot fence its later commit.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_foreign_obliterate_cannot_fence_an_unassociated_preparing_write() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let repository_id = create_repository(&store).await;
    let context = random_context();

    let BeginOutcome::Admitted(stale_intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin stale")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    coordinator
        .authorize_write_claim(stale_intent.write_claim().expect("stale claim"))
        .await
        .expect("authorize before the simulated provider I/O gap");

    assert!(matches!(
        coordinator
            .begin_obliterate(&hash, &repository_id, &context)
            .await
            .expect("foreign obliterate begin"),
        FragmentObliterateBegin::NoOp
    ));

    let stale_manifest = manifest("competing-obliterate/stale", 0x30, EpochAuthority::Remote);
    let late = coordinator
        .0
        .commit_remote(
            &stale_intent,
            IoObservation::Valid(stale_manifest),
            FragmentWriteSettlement::Decisive,
        )
        .await
        .expect("uncontested late commit must not error");
    assert_eq!(
        late,
        CommitVerdict::Published,
        "a foreign obliterate must not capture or fence an unassociated write"
    );

    let epoch_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &stale_intent.epoch],
        )
        .await
        .expect("count stale epoch rows")
        .get(0);
    assert_eq!(epoch_rows, 1);

    let state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head state")
        .get(0);
    assert_eq!(
        state,
        FragmentLifecycleState::Remote.bits(),
        "the foreign no-op must leave the preparing write free to publish"
    );
}

/// Item 6c: a competing repair independently turns a late commit into
/// `Fenced` with zero mutation.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_prepared_repair_blocks_a_competitor_and_no_send_attempt_cannot_publish_late() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    // Get the head to Missing first.
    let BeginOutcome::Admitted(setup_intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin setup")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &setup_intent,
                IoObservation::Unusable(MissingDiagnostic::Absent)
            )
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );

    let BeginOutcome::Admitted(stale_repair) = coordinator
        .claim_repair(&hash)
        .await
        .expect("begin stale repair")
    else {
        panic!("a Missing head must admit a repair claim");
    };

    assert!(matches!(
        coordinator
            .claim_repair(&hash)
            .await
            .expect("inspect prepared repair barrier"),
        BeginOutcome::WriteClaimBlocked { .. }
    ));
    coordinator
        .settle_write_claim(
            stale_repair.write_claim().expect("stale repair claim"),
            FragmentWriteSettlement::NoSend,
        )
        .await
        .expect("settle the attempt that never sent");

    // NoSend is terminal and nonblocking, so the later repair can now obtain
    // its own exact claim and publish.
    let BeginOutcome::Admitted(winning_repair) = coordinator
        .claim_repair(&hash)
        .await
        .expect("begin winning repair")
    else {
        panic!("a second claim must admit after NoSend settlement");
    };
    let winner_manifest = manifest("competing-repair/winner", 0x40, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_repair(&winning_repair, IoObservation::Valid(winner_manifest))
            .await
            .expect("winner repair commit"),
        CommitVerdict::Published
    );

    let stale_manifest = manifest("competing-repair/stale", 0x50, EpochAuthority::Remote);
    let late = coordinator
        .0
        .commit_repair(
            &stale_repair,
            IoObservation::Valid(stale_manifest),
            FragmentWriteSettlement::Decisive,
        )
        .await
        .expect_err("a NoSend attempt must not publish late");
    assert!(matches!(
        late,
        DomainError::PreconditionRejected { ref reason, .. }
            if reason == "fragment_write_claim_invalid_settlement"
    ));

    let epoch_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &stale_repair.epoch],
        )
        .await
        .expect("count stale epoch rows")
        .get(0);
    assert_eq!(
        epoch_rows, 1,
        "the winning attempt publishes the shared repair lineage exactly once"
    );
}

/// Item 8: a readable/unreadable transition must bump `fragment_lifecycle_generation`
/// for every live-associated repository atomically. This also proves item 7's
/// lock-order claim for a real coordinator transaction: `bump_lifecycle_generation`
/// is reached only after `lock_fragment_head` has already entered
/// `LockClass::Fragments`, so this is the real multi-row transaction F-032-3's
/// order applies to.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_readable_to_unreadable_transition_bumps_every_live_associated_repository_atomically() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let context = random_context();

    let repository_ids = [
        create_repository(&store).await,
        create_repository(&store).await,
        create_repository(&store).await,
    ];

    let hash = random_hash();
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin fanout fragment")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest("fanout/key", 0x90, EpochAuthority::Remote))
            )
            .await
            .expect("commit fanout fragment"),
        CommitVerdict::Published
    );
    for repository_id in &repository_ids {
        assert_eq!(
            coordinator
                .create_association(&hash, repository_id, &context)
                .await
                .expect("associate fanout repo"),
            CommitVerdict::Published
        );
    }

    for repository_id in &repository_ids {
        let witness = coordinator
            .capture_push_witness(repository_id)
            .await
            .expect("capture witness before")
            .expect("repository must exist");
        assert_eq!(witness.fragment_lifecycle_generation, 1);
    }

    let resolved = coordinator
        .resolve(&repository_ids[0], &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve to capture epoch witness");
    let (epoch_witness, ..) = expect_readable(&resolved[0]);
    let epoch_witness = epoch_witness.clone();

    let verdict = coordinator
        .mark_missing(&epoch_witness, MissingDiagnostic::Absent)
        .await
        .expect(
            "mark_missing must not error: a readable/unreadable transition with a live \
             multi-repository fanout must bump every associated repository atomically",
        );
    assert_eq!(verdict, CommitVerdict::Published);

    for repository_id in &repository_ids {
        let witness = coordinator
            .capture_push_witness(repository_id)
            .await
            .expect("capture witness after")
            .expect("repository must exist");
        assert_eq!(
            witness.fragment_lifecycle_generation, 2,
            "every repository with a live association must move together, not partially"
        );
    }
}

/// Item 8 (concurrency half): two readable-to-unreadable transitions over an
/// OVERLAPPING repository fanout must not deadlock, bounded by a watchdog so a
/// real deadlock fails the test instead of hanging the suite.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn two_concurrent_transitions_over_an_overlapping_fanout_do_not_deadlock() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let context = random_context();

    let repo_1 = create_repository(&store).await;
    let repo_2 = create_repository(&store).await;
    let repo_3 = create_repository(&store).await;

    async fn publish(coordinator: &TestFragmentCoordinator, key: &str, seed: u8) -> Vec<u8> {
        let hash = random_hash();
        let BeginOutcome::Admitted(intent) = coordinator
            .begin_direct_write(&hash, &legacy_key(&hash))
            .await
            .expect("begin overlap fragment")
        else {
            panic!("a fresh hash must admit a direct write");
        };
        assert_eq!(
            coordinator
                .commit_remote(
                    &intent,
                    IoObservation::Valid(manifest(key, seed, EpochAuthority::Remote))
                )
                .await
                .expect("commit overlap fragment"),
            CommitVerdict::Published
        );
        hash
    }

    let hash_x = publish(&coordinator, "overlap/x", 0xA0).await;
    let hash_y = publish(&coordinator, "overlap/y", 0xA1).await;

    for repository_id in [&repo_1, &repo_2] {
        assert_eq!(
            coordinator
                .create_association(&hash_x, repository_id, &context)
                .await
                .expect("associate x"),
            CommitVerdict::Published
        );
    }
    // repo_2 is shared between x's and y's fanout on purpose: this is the
    // overlap the sorted-order rule exists to make deadlock-free.
    for repository_id in [&repo_2, &repo_3] {
        assert_eq!(
            coordinator
                .create_association(&hash_y, repository_id, &context)
                .await
                .expect("associate y"),
            CommitVerdict::Published
        );
    }

    let resolved_x = coordinator
        .resolve(&repo_1, &context, std::slice::from_ref(&hash_x))
        .await
        .expect("resolve x");
    let (witness_x, ..) = expect_readable(&resolved_x[0]);
    let witness_x = witness_x.clone();
    let resolved_y = coordinator
        .resolve(&repo_2, &context, std::slice::from_ref(&hash_y))
        .await
        .expect("resolve y");
    let (witness_y, ..) = expect_readable(&resolved_y[0]);
    let witness_y = witness_y.clone();

    let coordinator_x = coordinator.clone();
    let coordinator_y = coordinator.clone();
    let (result_x, result_y) = tokio::join!(
        timeout(
            Duration::from_secs(10),
            coordinator_x.mark_missing(&witness_x, MissingDiagnostic::Absent)
        ),
        timeout(
            Duration::from_secs(10),
            coordinator_y.mark_missing(&witness_y, MissingDiagnostic::Absent)
        ),
    );
    let result_x = result_x
        .expect("mark_missing(x) must not deadlock past a 10s watchdog")
        .expect("mark_missing(x) must not error");
    let result_y = result_y
        .expect("mark_missing(y) must not deadlock past a 10s watchdog")
        .expect("mark_missing(y) must not error");
    assert_eq!(result_x, CommitVerdict::Published);
    assert_eq!(result_y, CommitVerdict::Published);

    // repo_1 and repo_3 are each associated with exactly one of the two
    // transitioning fragments, so each moves once (1 -> 2). repo_2 is
    // associated with BOTH x and y, so it legitimately receives one bump per
    // independent transition (1 -> 3) -- not a partial or doubled fanout, but
    // two genuinely separate lifecycle transitions that happen to share a
    // repository.
    for (repository_id, expected_generation) in [(&repo_1, 2i64), (&repo_2, 3i64), (&repo_3, 2i64)]
    {
        let witness = coordinator
            .capture_push_witness(repository_id)
            .await
            .expect("capture witness")
            .expect("repository must exist");
        assert_eq!(
            witness.fragment_lifecycle_generation, expected_generation,
            "repository {repository_id:02x?} must reflect exactly the transitions of the \
             fragments it is associated with, no more and no less"
        );
    }
}

/// Reviewer gap: repair on a `Missing` fragment that HAS a live association
/// must bump that repository's fanout, exercising `commit_repair`'s
/// Missing-to-Remote transition through the real fanout-locking path (a repair
/// with zero associations never reaches it).
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_repair_on_a_missing_fragment_with_a_live_association_bumps_its_repository_fanout() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(setup) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin setup")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(&setup, IoObservation::Unusable(MissingDiagnostic::Absent))
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate missing fragment"),
        CommitVerdict::Published
    );

    let before = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture before")
        .expect("repository must exist");

    let BeginOutcome::Admitted(repair_intent) =
        coordinator.claim_repair(&hash).await.expect("claim repair")
    else {
        panic!("a Missing head must admit a repair claim");
    };
    let repaired_manifest = manifest(
        "repair-with-association/repaired",
        0x60,
        EpochAuthority::Remote,
    );
    assert_eq!(
        coordinator
            .commit_repair(
                &repair_intent,
                IoObservation::Valid(repaired_manifest.clone())
            )
            .await
            .expect("commit repair"),
        CommitVerdict::Published
    );

    let after = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture after")
        .expect("repository must exist");
    assert_eq!(
        after.fragment_lifecycle_generation,
        before.fragment_lifecycle_generation + 1,
        "Missing-to-Remote via repair is a readable transition and must bump the \
         associated repository exactly once"
    );

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve repaired fragment");
    let (_, resolved_manifest, _) = expect_readable(&resolved[0]);
    assert_eq!(resolved_manifest, &repaired_manifest);
}

/// Reviewer gap: obliterate on a readable fragment that HAS a live association
/// must bump that repository's fanout and remove the association, exercising
/// `begin_obliterate`'s fanout-locking path (zero associations never reach
/// it).
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn an_obliterate_on_a_readable_fragment_with_a_live_association_bumps_its_repository_fanout()
{
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();
    enable_write_claims(&url, &coordinator).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(&legacy_key(&hash), 0x61, EpochAuthority::Remote))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let before = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture before")
        .expect("repository must exist");
    assert_eq!(before.fragment_lifecycle_generation, 1);

    let FragmentObliterateBegin::Ready(obliterate_intent) = coordinator
        .begin_obliterate(&hash, &repository_id, &context)
        .await
        .expect("begin obliterate on a readable, associated fragment")
    else {
        panic!("the sole live association must own coordinated obliterate");
    };
    assert_eq!(obliterate_intent.phase(), FragmentObliteratePhase::Children);

    let after = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture after")
        .expect("repository must exist");
    assert_eq!(
        after.fragment_lifecycle_generation, 2,
        "moving a readable head into the deletion sequence is a readable-to-unreadable \
         transition and must bump the associated repository"
    );

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve during obliteration");
    expect_absent(&resolved[0]);
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn exact_obliterate_is_foreign_safe_and_retires_only_one_shared_association() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_a = create_repository(&store).await;
    let repository_b = create_repository(&store).await;
    let foreign_repository = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();
    enable_write_claims(&url, &coordinator).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("fresh hash must admit");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(&legacy_key(&hash), 0xA1, EpochAuthority::Remote,)),
            )
            .await
            .expect("publish"),
        CommitVerdict::Published
    );
    for repository in [&repository_a, &repository_b] {
        assert_eq!(
            coordinator
                .create_association(&hash, repository, &context)
                .await
                .expect("associate"),
            CommitVerdict::Published
        );
    }

    assert!(matches!(
        coordinator
            .begin_obliterate(&hash, &foreign_repository, &context)
            .await
            .expect("foreign request"),
        FragmentObliterateBegin::NoOp
    ));
    assert!(matches!(
        coordinator
            .begin_obliterate(&hash, &repository_a, &context)
            .await
            .expect("retire A"),
        FragmentObliterateBegin::AssociationOnly
    ));

    let a = coordinator
        .resolve(&repository_a, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve retired A");
    expect_absent(&a[0]);
    let b = coordinator
        .resolve(&repository_b, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve surviving B");
    expect_readable(&b[0]);

    let FragmentObliterateBegin::Ready(last) = coordinator
        .begin_obliterate(&hash, &repository_b, &context)
        .await
        .expect("last association owns physical deletion")
    else {
        panic!("the last live association must own physical deletion");
    };
    assert_eq!(last.phase(), FragmentObliteratePhase::Children);
    assert_eq!(last.ownership().repository_id(), repository_b);
    assert_eq!(last.ownership().context(), context);
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn obliterate_requires_claims_cutover_and_exact_provider_authority_revision() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("fresh hash must admit");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(&legacy_key(&hash), 0xA2, EpochAuthority::Remote,)),
            )
            .await
            .expect("publish"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let optional = coordinator
        .0
        .begin_obliterate(
            &hash,
            &repository,
            &context,
            TEST_PROVIDER_WRITE_AUTHORITY_REVISION,
        )
        .await
        .expect_err("Optional write capability must refuse physical deletion");
    assert!(matches!(optional, DomainError::NotReady(_)));

    enable_write_claims(&url, &coordinator).await;
    let wrong_revision = coordinator
        .0
        .begin_obliterate(&hash, &repository, &context, "write-claims-v2")
        .await
        .expect_err("a mismatched provider authority revision must refuse");
    assert!(matches!(wrong_revision, DomainError::NotReady(_)));

    let FragmentObliterateBegin::Ready(intent) = coordinator
        .0
        .begin_obliterate(
            &hash,
            &repository,
            &context,
            TEST_PROVIDER_WRITE_AUTHORITY_REVISION,
        )
        .await
        .expect("exact revision")
    else {
        panic!("the exact revision must admit the owning deletion");
    };
    assert_eq!(
        intent.provider_write_authority_revision(),
        TEST_PROVIDER_WRITE_AUTHORITY_REVISION
    );
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn missing_without_epoch_evidence_still_enters_safe_exact_deletion() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();
    enable_write_claims(&url, &coordinator).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin failed first publication")
    else {
        panic!("fresh hash must admit");
    };
    assert_eq!(
        coordinator
            .commit_remote(&intent, IoObservation::Unusable(MissingDiagnostic::Absent))
            .await
            .expect("publish Missing"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .expect("associate Missing head"),
        CommitVerdict::Published
    );

    let FragmentObliterateBegin::Ready(deleting) = coordinator
        .begin_obliterate(&hash, &repository, &context)
        .await
        .expect("Missing head without epoch evidence must remain deletable")
    else {
        panic!("the sole association must own Missing deletion");
    };
    assert_eq!(deleting.phase(), FragmentObliteratePhase::Children);
    assert!(deleting.current().is_none());
    assert!(
        deleting
            .purge_targets()
            .iter()
            .any(|target| target.object_key() == legacy_key(&hash))
    );
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn noncanonical_epoch_object_key_is_refused_before_delete_ownership_is_published() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();
    enable_write_claims(&url, &coordinator).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("fresh hash must admit");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "canonical-before-tamper",
                    0xA3,
                    EpochAuthority::Remote,
                )),
            )
            .await
            .expect("publish"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );
    direct
        .execute(
            "UPDATE lore_fragment_epochs SET object_key = $3 WHERE hash = $1 AND epoch = $2",
            &[&hash, &intent.epoch, &"prefix-neighbor-not-owned"],
        )
        .await
        .expect("tamper object key fixture");

    let result = coordinator
        .begin_obliterate(&hash, &repository, &context)
        .await;
    assert!(
        matches!(
            result,
            Err(DomainError::InvalidInput(_) | DomainError::NotReady(_))
        ),
        "a noncanonical durable key must be rejected before it can become DeleteExact: {result:?}"
    );
    let state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after refusal")
        .get(0);
    assert_eq!(state, FragmentLifecycleState::Remote.bits());
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn noncanonical_claim_object_key_is_refused_before_delete_ownership_is_published() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();
    let legacy = legacy_key(&hash);
    enable_write_claims(&url, &coordinator).await;

    let short_claim = FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        [0xC1; 32],
        1,
        Duration::from_millis(20),
        Duration::from_millis(30),
    )
    .expect("short claim");
    let BeginOutcome::Admitted(intent) = coordinator
        .0
        .begin_direct_write(&hash, &legacy, short_claim)
        .await
        .expect("begin failed publication")
    else {
        panic!("fresh hash must admit");
    };
    let claim = intent.write_claim().expect("durable claim");
    coordinator
        .authorize_write_claim(claim)
        .await
        .expect("authorize ambiguous publication");
    assert_eq!(
        coordinator
            .0
            .commit_remote(
                &intent,
                IoObservation::Unusable(MissingDiagnostic::Absent),
                FragmentWriteSettlement::Ambiguous,
            )
            .await
            .expect("publish Missing"),
        CommitVerdict::Published
    );
    direct
        .execute(
            "UPDATE lore_fragment_write_claims SET object_key = $3 \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
                &"prefix-neighbor-not-owned",
            ],
        )
        .await
        .expect("tamper claim key fixture");
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .expect("associate Missing head"),
        CommitVerdict::Published
    );

    let result = coordinator
        .begin_obliterate(&hash, &repository, &context)
        .await;
    assert!(
        matches!(
            result,
            Err(DomainError::InvalidInput(_) | DomainError::NotReady(_))
        ),
        "a noncanonical claim key must be rejected before DeleteExact: {result:?}"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn missing_without_epoch_evidence_reconstructs_the_exact_staged_cleanup_target() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();
    enable_write_claims(&url, &coordinator).await;

    let BeginOutcome::Admitted(stage) = coordinator
        .begin_stage(&hash)
        .await
        .expect("begin failed staging")
    else {
        panic!("fresh hash must admit staging");
    };
    assert_eq!(
        coordinator
            .commit_staged(&stage, IoObservation::Unusable(MissingDiagnostic::Absent))
            .await
            .expect("publish Missing from staging"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .expect("associate Missing head"),
        CommitVerdict::Published
    );

    let FragmentObliterateBegin::Ready(deleting) = coordinator
        .begin_obliterate(&hash, &repository, &context)
        .await
        .expect("resume staged-origin Missing deletion")
    else {
        panic!("sole association must own deletion");
    };
    let current = deleting
        .current()
        .expect("staged fallback remains the exact child-discovery representation");
    assert!(current.manifest().is_none());
    assert_eq!(deleting.purge_targets().len(), 1);
    let target = &deleting.purge_targets()[0];
    assert_eq!(target.authority(), EpochAuthority::Staged);
    assert_eq!(target.epoch(), stage.epoch);
    assert_eq!(target.object_key(), staged_key(&hash, stage.epoch));
}

/// Reviewer gap: `readiness().unresolved_rows` must stay zero for a live
/// `Preparing` head (no epoch row yet by construction) and for a `Missing`
/// head committed by a failed first write. Neither is damage; both are
/// ordinary in-flight or terminal states the resolver's join already handles.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn readiness_reports_zero_unresolved_rows_for_a_preparing_head_and_a_missing_head() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();

    let preparing_hash = random_hash();
    let BeginOutcome::Admitted(_preparing_intent) = coordinator
        .begin_direct_write(&preparing_hash, &legacy_key(&preparing_hash))
        .await
        .expect("begin preparing")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    let readiness_with_preparing = coordinator
        .readiness()
        .await
        .expect("readiness with a Preparing head");
    assert_eq!(
        readiness_with_preparing.unresolved_rows, 0,
        "a Preparing head with no epoch row yet must not count as damage"
    );

    let missing_hash = random_hash();
    let BeginOutcome::Admitted(missing_intent) = coordinator
        .begin_direct_write(&missing_hash, &legacy_key(&missing_hash))
        .await
        .expect("begin missing")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &missing_intent,
                IoObservation::Unusable(MissingDiagnostic::Absent)
            )
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );
    let readiness_with_missing = coordinator
        .readiness()
        .await
        .expect("readiness with a Missing head");
    assert_eq!(
        readiness_with_missing.unresolved_rows, 0,
        "a Missing head from a failed first write must not count as damage"
    );
}

/// Reviewer gap: a promotion round trip must allocate a NEW epoch (not
/// republish the staged one) and must publish under `Remote` authority.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_promotion_round_trip_allocates_a_new_epoch_and_publishes_under_remote_authority() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    let staged_epoch = stage_intent.epoch;
    let staged_manifest = manifest("promotion/staged", 0x80, EpochAuthority::Staged);
    assert_eq!(
        coordinator
            .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest))
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );

    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash)
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    assert_ne!(
        promotion_intent.epoch, staged_epoch,
        "promotion must allocate a NEW epoch, not republish the staged one"
    );
    let remote_manifest = manifest("promotion/remote", 0x81, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_promotion(
                &promotion_intent,
                IoObservation::Valid(remote_manifest.clone())
            )
            .await
            .expect("commit promotion"),
        CommitVerdict::Published
    );
    assert_eq!(remote_manifest.authority, EpochAuthority::Remote);

    let head_row = direct
        .query_one(
            "SELECT current_epoch, state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head");
    let current_epoch: i64 = head_row.get(0);
    let state: i16 = head_row.get(1);
    assert_eq!(current_epoch, promotion_intent.epoch);
    assert_eq!(state, FragmentLifecycleState::Remote.bits());

    let epoch_row = direct
        .query_one(
            "SELECT authority, object_key FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &promotion_intent.epoch],
        )
        .await
        .expect("read published epoch row");
    let authority: i16 = epoch_row.get(0);
    assert_eq!(
        authority,
        EpochAuthority::Remote.bits(),
        "the published epoch row must record Remote authority, not Staged"
    );
}

/// Item 9: an absent SCHEMA-118 is a routing answer (the cell boots on the
/// legacy route); a partially installed one is refused, never routed around.
/// Mirrors `domain_lock_fencing.rs`'s
/// `an_absent_schema_routes_legacy_but_a_partial_one_is_refused` for SCHEMA-117.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn an_absent_fragment_schema_routes_legacy_but_a_partial_one_is_refused() {
    let Some(base_url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    // WP-118 Phase 9 proof-of-use for `CaseNamespace`. This case is the one in
    // this file that discriminates on the namespace actually taking effect: it
    // damages the schema through a plain `tokio_postgres` client and observes
    // the damage through the store's own pool, so the two connection paths must
    // resolve the same schema or every "must be refused" assertion below fails.
    // The rest of the case is unchanged.
    let namespace =
        case_namespace::CaseNamespace::acquire(&base_url, "absent-fragment-schema").await;
    let url = namespace.pg_url().to_owned();

    // Deliberately not the bootstrapping `store()` helper: this case needs the
    // state a booting cell actually finds before any migration has run.
    let bare = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
        .await
        .expect("connect domain store without SCHEMA-118");
    let readiness = bare
        .fragment_coordinator()
        .readiness()
        .await
        .expect("an unmigrated database must answer, not error");
    assert_eq!(readiness, FragmentLifecycleReadiness::not_provisioned());

    // `connect` has now run `ensure_schema`, so the CR-029 domain relations
    // exist. Prove they landed in the case namespace rather than in `public`:
    // without the `search_path` override they would be in `public`, so the
    // first assertion fails if the namespace is not in effect. The second is
    // the isolation claim; under the live runner it is near-vacuous because the
    // containing database is fresh, and it is load-bearing only for a harness
    // (WP-109's) that shares one database across cases.
    assert_eq!(
        namespace
            .schemas_containing("lore_domain_repositories")
            .await,
        vec![namespace.schema_name().to_owned()],
        "the domain schema must be installed in the case namespace alone"
    );

    bare.fragment_coordinator()
        .bootstrap()
        .await
        .expect("install SCHEMA-118");
    let direct = client(&url).await;

    // One relation missing: partially installed.
    direct
        .execute("DROP TABLE lore_fragment_staged_lease_members", &[])
        .await
        .expect("drop one fenced relation");
    assert!(
        matches!(
            bare.fragment_coordinator().readiness().await,
            Err(DomainError::NotReady(_))
        ),
        "a half-installed SCHEMA-118 must be refused, never reported as unprovisioned"
    );

    // All relations present, singleton state row gone: also incomplete.
    bare.fragment_coordinator()
        .bootstrap()
        .await
        .expect("reinstall SCHEMA-118");
    direct
        .execute("DELETE FROM lore_fragment_schema_state WHERE id = 1", &[])
        .await
        .expect("remove the singleton schema-state row");
    assert!(
        matches!(
            bare.fragment_coordinator().readiness().await,
            Err(DomainError::NotReady(_))
        ),
        "a missing singleton schema-state row must be refused, not reported as unprovisioned"
    );

    // A provisioned schema missing its repository generation columns: these
    // are part of SCHEMA-118's own DDL (an ALTER TABLE on the CR-029 table),
    // so their absence is damage specific to how this schema installs, not
    // covered by the relation-presence probe at all.
    bare.fragment_coordinator()
        .bootstrap()
        .await
        .expect("reinstall SCHEMA-118 and its schema-state row");
    bare.fragment_coordinator()
        .readiness()
        .await
        .expect("a fully installed schema must answer");
    direct
        .execute(
            "ALTER TABLE lore_domain_repositories DROP COLUMN content_association_generation",
            &[],
        )
        .await
        .expect("drop one repository generation column");
    assert!(
        matches!(
            bare.fragment_coordinator().readiness().await,
            Err(DomainError::NotReady(_))
        ),
        "a provisioned schema missing its repository generation columns must be refused, \
         never reported as ready"
    );

    // Drop the pooled and direct connections before the namespace so nothing is
    // still holding a relation in the schema being dropped.
    drop(direct);
    drop(bare);
    namespace.release().await;
}

// ---------------------------------------------------------------------------
// INV-EF P1-2 / P1-3: six previously-untested public entry points, all
// closable inside Phases 2-3.
// ---------------------------------------------------------------------------

/// Open a caller-owned transaction on a fresh connection pool. This coordinator
/// deliberately does not expose its own pool, and `revalidate_push_witness` is
/// the one method that borrows the caller's `Transaction` rather than owning
/// one -- a real push transaction supplies it, so a test does too.
async fn own_transaction_client(url: &str) -> deadpool_postgres::Client {
    let pool = build_pool(url, 4, &TlsConfig::default()).expect("build push-witness pool");
    pool.get().await.expect("checkout push-witness connection")
}

/// P1-2 item 1a: `revalidate_push_witness`'s `Unchanged` verdict, reached when
/// neither per-repository scalar moved between preflight capture and the final
/// push transaction. The fast path reads no fragment row at all, so an empty
/// `required` slice is enough to prove it.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_reports_unchanged_when_neither_scalar_moved() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &[])
        .await
        .expect("revalidate must not error");
    assert_eq!(verdict, PushWitnessVerdict::Unchanged);
}

/// P1-2 item 1b: `FallbackSatisfied`. The lifecycle scalar moves via a
/// bystander fragment's readable-to-unreadable transition; the two required
/// fragments are untouched and still readable at their captured epoch, so the
/// bounded fallback revalidates and satisfies the push.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_is_satisfied_by_the_fallback_when_the_lifecycle_scalar_moved_and_required_fragments_are_still_readable()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();

    // Two required fragments, published and associated BEFORE capture, so
    // their association does not itself move the content-association scalar
    // after the witness is taken.
    let mut required = Vec::new();
    for seed in 0u8..2 {
        let hash = random_hash();
        let key = format!("push-fallback/required-{seed}");
        let BeginOutcome::Admitted(intent) = coordinator
            .begin_direct_write(&hash, &legacy_key(&hash))
            .await
            .expect("begin required fragment")
        else {
            panic!("a fresh hash must admit a direct write");
        };
        assert_eq!(
            coordinator
                .commit_remote(
                    &intent,
                    IoObservation::Valid(manifest(&key, 0xD0 + seed, EpochAuthority::Remote))
                )
                .await
                .expect("commit required fragment"),
            CommitVerdict::Published
        );
        assert_eq!(
            coordinator
                .create_association(&hash, &repository_id, &context)
                .await
                .expect("associate required fragment"),
            CommitVerdict::Published
        );
        required.push(RequiredFragment {
            hash,
            epoch: intent.epoch,
        });
    }

    // A bystander fragment, also associated before capture, whose later
    // transition is the only thing that moves the lifecycle scalar.
    let bystander_hash = random_hash();
    let BeginOutcome::Admitted(bystander_intent) = coordinator
        .begin_direct_write(&bystander_hash, &legacy_key(&bystander_hash))
        .await
        .expect("begin bystander")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &bystander_intent,
                IoObservation::Valid(manifest(
                    "push-fallback/bystander",
                    0xD9,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit bystander"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&bystander_hash, &repository_id, &context)
            .await
            .expect("associate bystander"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    let resolved_bystander = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&bystander_hash),
        )
        .await
        .expect("resolve bystander");
    let (bystander_witness, ..) = expect_readable(&resolved_bystander[0]);
    let bystander_witness = bystander_witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&bystander_witness, MissingDiagnostic::Absent)
            .await
            .expect("mark bystander missing"),
        CommitVerdict::Published
    );

    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::FallbackSatisfied { revalidated: 2 }
    );
}

/// P1-2 item 1c (first `Aborted` shape): a required fragment that has become
/// unreadable (here, `Missing`) since preflight.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_aborts_when_a_required_fragment_is_no_longer_readable() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest("push-abort/removed", 0xD1, EpochAuthority::Remote))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    let required_epoch = intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve before removal");
    let (witness, ..) = expect_readable(&resolved[0]);
    let witness = witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&witness, MissingDiagnostic::Absent)
            .await
            .expect("mark missing"),
        CommitVerdict::Published
    );

    let required = vec![RequiredFragment {
        hash,
        epoch: required_epoch,
    }];
    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::Aborted {
            reason: REQUIRED_FRAGMENT_CHANGED
        }
    );
}

/// P1-2 item 1c (second `Aborted` shape): a required fragment whose epoch
/// advanced (a repair successor) since preflight, even though it is still
/// readable.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_aborts_when_a_required_fragments_epoch_advanced() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "push-abort/repaired",
                    0xD2,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    let original_epoch = intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve before repair");
    let (witness, ..) = expect_readable(&resolved[0]);
    let witness = witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&witness, MissingDiagnostic::Absent)
            .await
            .expect("mark missing"),
        CommitVerdict::Published
    );
    let BeginOutcome::Admitted(repair_intent) =
        coordinator.claim_repair(&hash).await.expect("claim repair")
    else {
        panic!("a Missing head must admit a repair claim");
    };
    assert_eq!(
        coordinator
            .commit_repair(
                &repair_intent,
                IoObservation::Valid(manifest(
                    "push-abort/repaired-successor",
                    0xD3,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit repair"),
        CommitVerdict::Published
    );

    // `required` still names the ORIGINAL (now stale) epoch.
    let required = vec![RequiredFragment {
        hash,
        epoch: original_epoch,
    }];
    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::Aborted {
            reason: REQUIRED_FRAGMENT_CHANGED
        }
    );
}

/// P1-2 item 1d: the 4,097-synthetic-fragment refusal. `MAX_PUSH_FRAGMENT_REVALIDATIONS`
/// is a count check on the caller's slice, reachable with fabricated hashes
/// that were never inserted -- this is the case INV-EF's own record wrongly
/// attributed to needing real upload traffic. Proven behaviorally (`Aborted`)
/// and structurally: the refusal happens before `LockClass::Fragments` is
/// ever entered.
///
/// **No push-witness before/after comparison here on purpose.**
/// `revalidate_push_witness` has no code path, in this or any other verdict,
/// that writes to `lore_domain_repositories` -- it only ever reads that table
/// and, past the count check, takes `FOR UPDATE` locks on
/// `lore_fragment_lifecycle`. A witness-unchanged assertion would therefore
/// hold no matter what this function did, which is the same
/// cannot-fail-regardless-of-behavior shape INV-EF's own P2-11 flagged
/// elsewhere -- caught here by a reviewer pass rather than shipped. The
/// `LockClass::Repository` re-entry below is the one proof that actually
/// discriminates: it could not succeed if `Fragments` had already been
/// entered.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_refuses_over_the_revalidation_limit_before_locking_any_fragment_row()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest("push-abort/limit", 0xD4, EpochAuthority::Remote))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    // Move the lifecycle scalar so the call reaches the count check rather
    // than short-circuiting on `Unchanged`.
    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve before mark missing");
    let (witness, ..) = expect_readable(&resolved[0]);
    let witness = witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&witness, MissingDiagnostic::Absent)
            .await
            .expect("mark missing"),
        CommitVerdict::Published
    );

    // 4,097 synthetic RequiredFragment values: fabricated hashes, never
    // inserted anywhere, one over the frozen limit.
    let required: Vec<RequiredFragment> = (0..=MAX_PUSH_FRAGMENT_REVALIDATIONS)
        .map(|_| RequiredFragment {
            hash: random_hash(),
            epoch: 1,
        })
        .collect();
    assert_eq!(required.len(), MAX_PUSH_FRAGMENT_REVALIDATIONS + 1);

    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::Aborted {
            reason: REQUIRED_FRAGMENT_REVALIDATION_LIMIT
        }
    );

    // Structural proof: the count check runs BEFORE any fragment row is
    // locked. `LockClass::Fragments` (position 4) is later than
    // `LockClass::Repository` (position 1); if the refusal had already
    // entered Fragments, re-entering Repository here would be rejected as a
    // lock-order inversion.
    sequence.enter(LockClass::Repository).expect(
        "the revalidation-limit refusal must return before locking any fragment row; if \
         LockClass::Fragments had been entered, this would be a lock-order violation",
    );
    drop(tx); // never committed; the function made no writes to roll back
}

/// CR-031:266 (INV-EF P2-2): a required fragment promoted from `Staged` to a
/// `Remote` epoch that is semantically equivalent -- same `decoded_hash`,
/// `size_content`, `size_payload`, and `payload_flags` -- must satisfy the
/// push fallback even though its epoch genuinely advanced and its
/// `object_key`/`manifest_id` changed (deliberately not compared).
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_accepts_a_required_fragment_promoted_to_a_semantically_equivalent_epoch()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();

    // The required fragment: staged, then associated BEFORE capture, so its
    // association does not itself move the content-association scalar after
    // the witness is taken.
    let hash = random_hash();
    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    let staged_manifest = manifest("equivalent-epoch/staged", 0xC0, EpochAuthority::Staged);
    assert_eq!(
        coordinator
            .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest.clone()))
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    let original_epoch = stage_intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    // A bystander, also associated before capture, whose later transition is
    // the only thing that moves the lifecycle scalar (a Staged->Remote
    // promotion crosses no readability boundary and moves nothing on its own).
    let bystander_hash = random_hash();
    let BeginOutcome::Admitted(bystander_intent) = coordinator
        .begin_direct_write(&bystander_hash, &legacy_key(&bystander_hash))
        .await
        .expect("begin bystander")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &bystander_intent,
                IoObservation::Valid(manifest(
                    "equivalent-epoch/bystander",
                    0xC9,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit bystander"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&bystander_hash, &repository_id, &context)
            .await
            .expect("associate bystander"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    // Promote the required fragment: a NEW epoch, a different `object_key`
    // and `manifest_id`, but identical decoded_hash/size_content/size_payload/
    // payload_flags.
    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash)
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    assert_ne!(
        promotion_intent.epoch, original_epoch,
        "promotion must allocate a new epoch, not republish the staged one"
    );
    let mut promoted_manifest = staged_manifest.clone();
    promoted_manifest.authority = EpochAuthority::Remote;
    promoted_manifest.object_key = "equivalent-epoch/promoted".to_owned();
    promoted_manifest.manifest_id = vec![0xCA; 32];
    assert_ne!(
        promoted_manifest.manifest_id, staged_manifest.manifest_id,
        "the successor manifest id must genuinely differ from the staged one"
    );
    assert_eq!(
        coordinator
            .commit_promotion(&promotion_intent, IoObservation::Valid(promoted_manifest))
            .await
            .expect("commit promotion"),
        CommitVerdict::Published
    );

    // Move the lifecycle scalar so the call reaches the fallback rather than
    // short-circuiting on `Unchanged`.
    let resolved_bystander = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&bystander_hash),
        )
        .await
        .expect("resolve bystander");
    let (bystander_witness, ..) = expect_readable(&resolved_bystander[0]);
    let bystander_witness = bystander_witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&bystander_witness, MissingDiagnostic::Absent)
            .await
            .expect("mark bystander missing"),
        CommitVerdict::Published
    );

    // The epoch really did advance -- this is what stops the case from
    // silently degenerating into the exact-match path.
    let current_epoch: i64 = direct
        .query_one(
            "SELECT current_epoch FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read current epoch after promotion")
        .get(0);
    assert_ne!(
        current_epoch, original_epoch,
        "the required fragment's current epoch must have genuinely advanced"
    );
    assert_eq!(current_epoch, promotion_intent.epoch);

    let required = vec![RequiredFragment {
        hash,
        epoch: original_epoch,
    }];
    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::FallbackSatisfied { revalidated: 1 }
    );
}

/// CR-031:266's equivalence allowance is narrow: a successor epoch whose
/// manifest differs in `decoded_hash` or `payload_flags` describes different
/// content and must abort, even though the head is still readable and
/// `size_content`/`size_payload` are unchanged.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_aborts_when_the_new_epoch_describes_different_content() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();

    async fn stage_and_associate(
        coordinator: &PostgresFragmentCoordinator,
        repository_id: &[u8],
        context: &[u8],
        key_prefix: &str,
        seed: u8,
    ) -> (Vec<u8>, i64, FragmentManifest) {
        let hash = random_hash();
        let BeginOutcome::Admitted(stage_intent) =
            coordinator.begin_stage(&hash).await.expect("begin stage")
        else {
            panic!("a fresh hash must admit a stage begin");
        };
        let staged_manifest = manifest(
            &format!("{key_prefix}/staged"),
            seed,
            EpochAuthority::Staged,
        );
        assert_eq!(
            coordinator
                .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest.clone()))
                .await
                .expect("commit staged"),
            CommitVerdict::Published
        );
        assert_eq!(
            coordinator
                .create_association(&hash, repository_id, context)
                .await
                .expect("associate"),
            CommitVerdict::Published
        );
        (hash, stage_intent.epoch, staged_manifest)
    }

    let (hash_a, original_epoch_a, staged_manifest_a) = stage_and_associate(
        &coordinator,
        &repository_id,
        &context,
        "content-changed/hash",
        0xE0,
    )
    .await;
    let (hash_b, original_epoch_b, staged_manifest_b) = stage_and_associate(
        &coordinator,
        &repository_id,
        &context,
        "content-changed/flags",
        0xE1,
    )
    .await;

    let bystander_hash = random_hash();
    let BeginOutcome::Admitted(bystander_intent) = coordinator
        .begin_direct_write(&bystander_hash, &legacy_key(&bystander_hash))
        .await
        .expect("begin bystander")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &bystander_intent,
                IoObservation::Valid(manifest(
                    "content-changed/bystander",
                    0xE9,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit bystander"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&bystander_hash, &repository_id, &context)
            .await
            .expect("associate bystander"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    // A: promote with a different decoded_hash.
    let BeginOutcome::Admitted(promotion_a) = coordinator
        .begin_promotion(&hash_a)
        .await
        .expect("begin promotion a")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    let mut promoted_a = staged_manifest_a.clone();
    promoted_a.authority = EpochAuthority::Remote;
    promoted_a.object_key = "content-changed/promoted-hash".to_owned();
    promoted_a.manifest_id = vec![0xEA; 32];
    promoted_a.decoded_hash = vec![0xFF; 32];
    assert_ne!(promoted_a.decoded_hash, staged_manifest_a.decoded_hash);
    assert_eq!(
        coordinator
            .commit_promotion(&promotion_a, IoObservation::Valid(promoted_a))
            .await
            .expect("commit promotion a"),
        CommitVerdict::Published
    );

    // B: promote with a different payload_flags.
    let BeginOutcome::Admitted(promotion_b) = coordinator
        .begin_promotion(&hash_b)
        .await
        .expect("begin promotion b")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    let mut promoted_b = staged_manifest_b.clone();
    promoted_b.authority = EpochAuthority::Remote;
    promoted_b.object_key = "content-changed/promoted-flags".to_owned();
    promoted_b.manifest_id = vec![0xEB; 32];
    promoted_b.payload_flags = staged_manifest_b.payload_flags ^ 0x01;
    assert_ne!(promoted_b.payload_flags, staged_manifest_b.payload_flags);
    assert_eq!(
        coordinator
            .commit_promotion(&promotion_b, IoObservation::Valid(promoted_b))
            .await
            .expect("commit promotion b"),
        CommitVerdict::Published
    );

    // Move the lifecycle scalar so both revalidations below reach the
    // fallback branch rather than short-circuiting on `Unchanged`.
    let resolved_bystander = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&bystander_hash),
        )
        .await
        .expect("resolve bystander");
    let (bystander_witness, ..) = expect_readable(&resolved_bystander[0]);
    let bystander_witness = bystander_witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&bystander_witness, MissingDiagnostic::Absent)
            .await
            .expect("mark bystander missing"),
        CommitVerdict::Published
    );

    for (hash, original_epoch, label) in [
        (hash_a, original_epoch_a, "decoded_hash"),
        (hash_b, original_epoch_b, "payload_flags"),
    ] {
        let current_epoch: i64 = direct
            .query_one(
                "SELECT current_epoch FROM lore_fragment_lifecycle WHERE hash = $1",
                &[&hash],
            )
            .await
            .expect("read current epoch after promotion")
            .get(0);
        assert_ne!(
            current_epoch, original_epoch,
            "{label}: the epoch must have genuinely advanced, or this case would silently \
             degenerate into the exact-match path"
        );

        let required = vec![RequiredFragment {
            hash,
            epoch: original_epoch,
        }];
        let mut tx_client = own_transaction_client(&url).await;
        let tx = tx_client
            .transaction()
            .await
            .expect("open push-witness transaction");
        let mut sequence = LockSequence::new();

        let verdict = coordinator
            .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
            .await
            .expect("revalidate must not error");
        assert_eq!(
            verdict,
            PushWitnessVerdict::Aborted {
                reason: REQUIRED_FRAGMENT_CHANGED
            },
            "{label} divergence must abort the push, not fall through the equivalence allowance"
        );
    }
}

/// P1-2 item 2: `acquire_staged_leases`/`release_staged_lease` round trip over
/// a **batch** of several staged fragments -- one lease row covering many
/// members is the whole design point, not one lease per fragment.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_and_release_round_trip_a_batch_with_a_monotonic_reader_fence() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    let mut members = Vec::new();
    for seed in 0u8..3 {
        let hash = random_hash();
        let BeginOutcome::Admitted(intent) =
            coordinator.begin_stage(&hash).await.expect("begin stage")
        else {
            panic!("a fresh hash must admit a stage begin");
        };
        let staged_manifest = manifest(
            &format!("staged-lease/member-{seed}"),
            0xE0 + seed,
            EpochAuthority::Staged,
        );
        assert_eq!(
            coordinator
                .commit_staged(&intent, IoObservation::Valid(staged_manifest))
                .await
                .expect("commit staged member"),
            CommitVerdict::Published
        );
        members.push((hash, intent.epoch));
    }

    let lease_id_a = rand::random::<[u8; 16]>().to_vec();
    let deadline = SystemTime::now() + Duration::from_secs(60);
    let lease_a = coordinator
        .acquire_staged_leases(&lease_id_a, &members, deadline)
        .await
        .expect("acquire lease a");
    assert_eq!(lease_a.lease_id, lease_id_a);
    assert_eq!(lease_a.members, members);

    let member_count: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_lease_members WHERE lease_id = $1",
            &[&lease_id_a],
        )
        .await
        .expect("count lease members")
        .get(0);
    assert_eq!(
        member_count,
        members.len() as i64,
        "every batched member must land"
    );

    let lease_row = direct
        .query_one(
            "SELECT reader_fence, terminal FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_a],
        )
        .await
        .expect("read lease row");
    let stored_fence: i64 = lease_row.get(0);
    let terminal: bool = lease_row.get(1);
    assert_eq!(stored_fence, lease_a.reader_fence);
    assert!(!terminal, "a fresh lease must not start terminal");

    // Monotonic reader fence: a second lease, over one member, gets a
    // strictly greater fence.
    let lease_id_b = rand::random::<[u8; 16]>().to_vec();
    let lease_b = coordinator
        .acquire_staged_leases(&lease_id_b, &members[..1], deadline)
        .await
        .expect("acquire lease b");
    assert!(
        lease_b.reader_fence > lease_a.reader_fence,
        "reader fences must be monotonic: a={} b={}",
        lease_a.reader_fence,
        lease_b.reader_fence
    );

    coordinator
        .release_staged_lease(&lease_id_a)
        .await
        .expect("release lease a");
    let released_terminal: bool = direct
        .query_one(
            "SELECT terminal FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_a],
        )
        .await
        .expect("read released lease terminal flag")
        .get(0);
    assert!(released_terminal, "release must flip terminal");

    // Releasing lease A must not affect lease B.
    let lease_b_terminal: bool = direct
        .query_one(
            "SELECT terminal FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_b],
        )
        .await
        .expect("read lease b terminal flag")
        .get(0);
    assert!(!lease_b_terminal);
}

/// INV-EF P2-6: a `lease_id` whose length is not [`schema::STAGED_LEASE_ID_LEN`]
/// must be refused as [`DomainError::InvalidInput`] before any database work,
/// on both `acquire_staged_leases` and `release_staged_lease`.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_refuses_a_lease_id_that_is_not_the_schema_length() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let deadline = microsecond_deadline(Duration::from_secs(60));

    let short_id: Vec<u8> = vec![0u8; schema::STAGED_LEASE_ID_LEN - 1];
    let long_id: Vec<u8> = vec![0u8; schema::STAGED_LEASE_ID_LEN + 1];

    for bad_id in [short_id.clone(), long_id.clone()] {
        let result = coordinator
            .acquire_staged_leases(&bad_id, &[], deadline)
            .await;
        assert!(
            matches!(result, Err(DomainError::InvalidInput(_))),
            "expected InvalidInput for a {}-byte lease id, got {:?}",
            bad_id.len(),
            result
        );
        let lease_rows: i64 = direct
            .query_one(
                "SELECT count(*)::bigint FROM lore_fragment_staged_leases WHERE lease_id = $1",
                &[&bad_id],
            )
            .await
            .expect("count lease rows for a wrong-length id")
            .get(0);
        assert_eq!(
            lease_rows, 0,
            "a wrong-length lease id must be refused before any database write"
        );
    }

    // `release_staged_lease` carries the same guard.
    let release_result = coordinator.release_staged_lease(&short_id).await;
    assert!(
        matches!(release_result, Err(DomainError::InvalidInput(_))),
        "expected InvalidInput from release_staged_lease for a wrong-length id, got {:?}",
        release_result
    );
}

/// INV-EF P2-5: every member of an `acquire_staged_leases` batch must name a
/// row in `lore_fragment_epochs` carrying [`schema::AUTHORITY_STAGED`] -- a
/// `Remote` epoch and a fabricated `(hash, epoch)` naming nothing are both
/// refused, and an all-staged batch still succeeds.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_refuses_a_member_that_is_not_a_staged_epoch() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let deadline = microsecond_deadline(Duration::from_secs(60));

    fn assert_member_not_staged(result: &Result<StagedReaderLease, DomainError>) {
        match result {
            Err(DomainError::PreconditionRejected {
                reason,
                reason_version,
            }) => {
                assert_eq!(reason, STAGED_LEASE_MEMBER_NOT_STAGED);
                assert_eq!(*reason_version, 1);
            }
            other => panic!("expected STAGED_LEASE_MEMBER_NOT_STAGED, got {other:?}"),
        }
    }

    let staged_hash = random_hash();
    let BeginOutcome::Admitted(stage_intent) = coordinator
        .begin_stage(&staged_hash)
        .await
        .expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage_intent,
                IoObservation::Valid(manifest(
                    "staged-lease-scope/staged",
                    0x11,
                    EpochAuthority::Staged
                ))
            )
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    let staged_member = (staged_hash, stage_intent.epoch);

    let remote_hash = random_hash();
    let BeginOutcome::Admitted(remote_intent) = coordinator
        .begin_direct_write(&remote_hash, &legacy_key(&remote_hash))
        .await
        .expect("begin remote")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &remote_intent,
                IoObservation::Valid(manifest(
                    "staged-lease-scope/remote",
                    0x12,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit remote"),
        CommitVerdict::Published
    );
    let remote_member = (remote_hash, remote_intent.epoch);

    let fabricated_member = (random_hash(), 1i64);

    let lease_id_remote = rand::random::<[u8; 16]>().to_vec();
    let remote_result = coordinator
        .acquire_staged_leases(
            &lease_id_remote,
            &[staged_member.clone(), remote_member],
            deadline,
        )
        .await;
    assert_member_not_staged(&remote_result);
    let remote_lease_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_remote],
        )
        .await
        .expect("count lease rows after a Remote-member refusal")
        .get(0);
    assert_eq!(remote_lease_rows, 0);
    let remote_member_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_lease_members WHERE lease_id = $1",
            &[&lease_id_remote],
        )
        .await
        .expect("count member rows after a Remote-member refusal")
        .get(0);
    assert_eq!(remote_member_rows, 0);

    let lease_id_fabricated = rand::random::<[u8; 16]>().to_vec();
    let fabricated_result = coordinator
        .acquire_staged_leases(
            &lease_id_fabricated,
            &[staged_member.clone(), fabricated_member],
            deadline,
        )
        .await;
    assert_member_not_staged(&fabricated_result);
    let fabricated_lease_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_fabricated],
        )
        .await
        .expect("count lease rows after a fabricated-member refusal")
        .get(0);
    assert_eq!(fabricated_lease_rows, 0);
    let fabricated_member_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_lease_members WHERE lease_id = $1",
            &[&lease_id_fabricated],
        )
        .await
        .expect("count member rows after a fabricated-member refusal")
        .get(0);
    assert_eq!(fabricated_member_rows, 0);

    let lease_id_ok = rand::random::<[u8; 16]>().to_vec();
    let ok_lease = coordinator
        .acquire_staged_leases(&lease_id_ok, std::slice::from_ref(&staged_member), deadline)
        .await
        .expect("an all-staged batch must acquire");
    assert_eq!(ok_lease.members, vec![staged_member.clone()]);
    // The returned struct alone cannot fail here -- `StagedReaderLease.members`
    // is copied straight back from the input in `acquire_staged_leases`'s
    // success arm, so it would read correct even if zero member rows had been
    // written. Read the persisted row directly, the same way the refusal legs
    // above prove a NON-write.
    let ok_member_rows: Vec<(Vec<u8>, i64)> = direct
        .query(
            "SELECT hash, epoch FROM lore_fragment_staged_lease_members WHERE lease_id = $1",
            &[&lease_id_ok],
        )
        .await
        .expect("read persisted members for the all-staged batch")
        .into_iter()
        .map(|row| (row.get("hash"), row.get("epoch")))
        .collect();
    assert_eq!(
        ok_member_rows,
        vec![staged_member],
        "the all-staged batch must actually persist its member row, not just echo the input"
    );
}

/// INV-EF P2-6: a duplicate `lease_id` faithfully replays the existing lease
/// (same fence, same deadline, order-independent member set) rather than
/// colliding on a bare primary key; a genuinely different member set or an
/// already-released lease are each refused with their own reason code.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_duplicate_staged_lease_id_replays_the_existing_lease_and_refuses_a_different_batch() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    let mut members = Vec::new();
    for seed in 0u8..2 {
        let hash = random_hash();
        let BeginOutcome::Admitted(intent) =
            coordinator.begin_stage(&hash).await.expect("begin stage")
        else {
            panic!("a fresh hash must admit a stage begin");
        };
        assert_eq!(
            coordinator
                .commit_staged(
                    &intent,
                    IoObservation::Valid(manifest(
                        &format!("duplicate-lease/member-{seed}"),
                        0x30 + seed,
                        EpochAuthority::Staged
                    ))
                )
                .await
                .expect("commit staged member"),
            CommitVerdict::Published
        );
        members.push((hash, intent.epoch));
    }
    let extra_hash = random_hash();
    let BeginOutcome::Admitted(extra_intent) = coordinator
        .begin_stage(&extra_hash)
        .await
        .expect("begin stage extra")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &extra_intent,
                IoObservation::Valid(manifest(
                    "duplicate-lease/extra",
                    0x32,
                    EpochAuthority::Staged
                ))
            )
            .await
            .expect("commit staged extra"),
        CommitVerdict::Published
    );

    let lease_id = rand::random::<[u8; 16]>().to_vec();
    let first_deadline = microsecond_deadline(Duration::from_secs(60));
    let first_lease = coordinator
        .acquire_staged_leases(&lease_id, &members, first_deadline)
        .await
        .expect("acquire first lease");

    // Re-acquire the SAME id with the same members in a DIFFERENT order and a
    // LATER deadline: a replay allocates no second fence and never extends.
    let mut reordered = members.clone();
    reordered.reverse();
    let later_deadline = microsecond_deadline(Duration::from_secs(3600));
    let replay = coordinator
        .acquire_staged_leases(&lease_id, &reordered, later_deadline)
        .await
        .expect("a faithful replay must succeed");
    assert_eq!(
        replay.reader_fence, first_lease.reader_fence,
        "a replay must not allocate a second reader fence"
    );
    assert_eq!(
        replay.deadline, first_lease.deadline,
        "a replay must not extend the deadline"
    );

    let stored_row = direct
        .query_one(
            "SELECT reader_fence, deadline FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id],
        )
        .await
        .expect("read stored lease row after replay");
    let stored_fence: i64 = stored_row.get(0);
    let stored_deadline: SystemTime = stored_row.get(1);
    assert_eq!(stored_fence, first_lease.reader_fence);
    assert_eq!(stored_deadline, first_lease.deadline);

    // A duplicate id over a DIFFERENT member set is an id collision, not a
    // retry.
    let mut different_members = members.clone();
    different_members.push((extra_hash, extra_intent.epoch));
    let mismatch_result = coordinator
        .acquire_staged_leases(&lease_id, &different_members, first_deadline)
        .await;
    match mismatch_result {
        Err(DomainError::PreconditionRejected {
            reason,
            reason_version,
        }) => {
            assert_eq!(reason, STAGED_LEASE_MEMBER_SET_MISMATCH);
            assert_eq!(reason_version, 1);
        }
        other => panic!("expected STAGED_LEASE_MEMBER_SET_MISMATCH, got {other:?}"),
    }

    // A duplicate id over an already-released lease must not be resurrected.
    coordinator
        .release_staged_lease(&lease_id)
        .await
        .expect("release lease");
    let released_result = coordinator
        .acquire_staged_leases(&lease_id, &members, first_deadline)
        .await;
    match released_result {
        Err(DomainError::PreconditionRejected {
            reason,
            reason_version,
        }) => {
            assert_eq!(reason, STAGED_LEASE_ALREADY_RELEASED);
            assert_eq!(reason_version, 1);
        }
        other => panic!("expected STAGED_LEASE_ALREADY_RELEASED, got {other:?}"),
    }
}

/// The children-phase commit never claims physical purge: it advances to
/// `DeletingPayload` while retaining epoch disposition and metering until
/// exact purge proofs are supplied by the immutable-store route.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn commit_obliterate_children_retains_payload_evidence_until_exact_purge_proof() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    enable_write_claims(&url, &coordinator).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(&legacy_key(&hash), 0xF0, EpochAuthority::Remote))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );
    let published_epoch = intent.epoch;

    let metering_before: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_lifecycle_metering WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("count metering before")
        .get(0);
    assert_eq!(
        metering_before, 1,
        "a published fragment has a metering row"
    );

    let FragmentObliterateBegin::Ready(obliterate_intent) = coordinator
        .begin_obliterate(&hash, &repository_id, &context)
        .await
        .expect("begin obliterate")
    else {
        panic!("the sole association must own obliterate");
    };
    assert_eq!(
        coordinator
            .commit_obliterate_children(&obliterate_intent)
            .await
            .expect("commit child discovery"),
        CommitVerdict::Published
    );

    let head_row = direct
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after obliterate");
    let state: i16 = head_row.get(0);
    assert_eq!(state, FragmentLifecycleState::DeletingPayload.bits());

    let disposition: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &published_epoch],
        )
        .await
        .expect("read published epoch disposition")
        .get(0);
    assert_eq!(disposition, schema::DISPOSITION_CURRENT_ELIGIBLE);

    let metering_after: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_lifecycle_metering WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("count metering after")
        .get(0);
    assert_eq!(
        metering_after, 1,
        "metering must remain until exact payload purge proof is committed"
    );
}

/// A retry while `DeletingChildren` recovers the exact durable ownership
/// fence. Once either copy advances the phase, the other children commit is
/// fenced and cannot mutate the payload phase.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn obliterate_retry_recovers_exact_ownership_and_late_children_commit_is_fenced() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    enable_write_claims(&url, &coordinator).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(&legacy_key(&hash), 0xF1, EpochAuthority::Remote))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let FragmentObliterateBegin::Ready(first_intent) = coordinator
        .begin_obliterate(&hash, &repository_id, &context)
        .await
        .expect("begin obliterate")
    else {
        panic!("the sole association must own obliterate");
    };
    let FragmentObliterateBegin::Ready(replayed_intent) = coordinator
        .begin_obliterate(&hash, &repository_id, &context)
        .await
        .expect("retry obliterate")
    else {
        panic!("the owning retry must recover its children-phase intent");
    };
    assert_eq!(first_intent.ownership(), replayed_intent.ownership());
    assert_eq!(first_intent.phase(), FragmentObliteratePhase::Children);
    assert_eq!(
        first_intent.purge_targets(),
        replayed_intent.purge_targets()
    );

    assert_eq!(
        coordinator
            .commit_obliterate_children(&replayed_intent)
            .await
            .expect("commit replayed children intent"),
        CommitVerdict::Published
    );

    let head_after_win = direct
        .query_one(
            "SELECT state, last_fence FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after winner");
    let state_after_win: i16 = head_after_win.get(0);
    let last_fence_after_win: i64 = head_after_win.get(1);
    assert_eq!(
        state_after_win,
        FragmentLifecycleState::DeletingPayload.bits()
    );

    let stale_result = coordinator
        .commit_obliterate_children(&first_intent)
        .await
        .expect("late duplicate children commit must not error");
    assert_eq!(
        stale_result,
        CommitVerdict::Fenced,
        "a children-phase intent cannot commit after payload phase begins"
    );

    let head_after_stale = direct
        .query_one(
            "SELECT state, last_fence FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after stale attempt");
    let state_after_stale: i16 = head_after_stale.get(0);
    let last_fence_after_stale: i64 = head_after_stale.get(1);
    assert_eq!(
        state_after_stale, state_after_win,
        "a fenced duplicate must leave the payload phase unchanged"
    );
    assert_eq!(
        last_fence_after_stale, last_fence_after_win,
        "a fenced duplicate must not move the durable ownership fence"
    );
}

/// P1-2 item 4: `enable_lifecycle` refuses with the typed `DomainError::NotReady`
/// on a cell that has not completed backfill and cutover, and succeeds once
/// the schema-state row genuinely satisfies cutover, residue classification,
/// and sequence headroom.
///
/// SCHEMA-118's Phase 2/3 surface has no coordinator method that advances
/// `backfill_state`/`cutover_at`/`residue_classified` -- that orchestrator is
/// a later phase, unlike SCHEMA-117's sibling in `domain/locks/coordinator.rs`.
/// The positive precondition is staged with the same direct-SQL technique this
/// file's own `an_absent_fragment_schema_routes_legacy_but_a_partial_one_is_refused`
/// already uses to stage schema-damage preconditions -- exercising the real
/// row `enable_lifecycle` reads and writes, not a hand-built
/// `FragmentLifecycleReadiness` fixture (that shape is already pinned by
/// `readiness_fails_closed_on_each_missing_precondition` in this crate's own
/// `mod tests`).
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn enable_lifecycle_refuses_on_a_not_ready_cell_and_succeeds_once_ready() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    // A freshly bootstrapped cell (a real write: `bootstrap()`'s INSERT) has
    // not backfilled or cut over.
    let refusal = coordinator.enable_lifecycle().await;
    assert!(
        matches!(refusal, Err(DomainError::NotReady(_))),
        "expected the typed NotReady error, got {refusal:?}"
    );

    direct
        .execute(
            "UPDATE lore_fragment_schema_state \
                SET backfill_state = $1, cutover_at = clock_timestamp(), \
                    residue_classified = true, sequence_headroom_fence = 1 \
              WHERE id = 1",
            &[&schema::BACKFILL_CUTOVER],
        )
        .await
        .expect("stage the cutover precondition");

    coordinator
        .enable_lifecycle()
        .await
        .expect("enable_lifecycle must succeed once every precondition holds");

    let enabled: bool = direct
        .query_one(
            "SELECT lifecycle_enabled FROM lore_fragment_schema_state WHERE id = 1",
            &[],
        )
        .await
        .expect("read lifecycle_enabled")
        .get(0);
    assert!(enabled);
}

/// P2-1 (reviewer follow-up): the newer-schema diagnostic was moved ahead of
/// the general `ready_for_lifecycle()` verdict specifically so it becomes
/// reachable -- behind that verdict it was dead code, since
/// `ready_for_lifecycle()` already folds the same upper bound in. Stages a
/// cell that is otherwise fully ready (cutover, residue, headroom all
/// satisfied) except `schema_version` is one past what this binary compiles
/// against, and asserts the specific "roll the binary forward" diagnostic
/// fires -- not just any `NotReady`, which the general verdict would also
/// produce and which would leave the reordering unfalsifiable.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn enable_lifecycle_refuses_with_the_roll_forward_diagnostic_when_schema_version_exceeds_the_binary()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    direct
        .execute(
            "UPDATE lore_fragment_schema_state \
                SET backfill_state = $1, cutover_at = clock_timestamp(), \
                    residue_classified = true, sequence_headroom_fence = 1, \
                    schema_version = $2 \
              WHERE id = 1",
            &[
                &schema::BACKFILL_CUTOVER,
                &(schema::FRAGMENT_SCHEMA_VERSION + 1),
            ],
        )
        .await
        .expect("stage an otherwise-ready cell one schema version ahead of the binary");

    let refusal = coordinator
        .enable_lifecycle()
        .await
        .expect_err("a cell ahead of the binary must refuse, not silently enable");
    let DomainError::NotReady(message) = refusal else {
        panic!("expected the typed NotReady error, got {refusal:?}");
    };
    assert!(
        message.contains("roll the binary forward"),
        "an otherwise-ready cell one schema version ahead of the binary must surface the \
         roll-forward diagnostic specifically, not the general readiness dump: {message:?}"
    );

    let enabled: bool = direct
        .query_one(
            "SELECT lifecycle_enabled FROM lore_fragment_schema_state WHERE id = 1",
            &[],
        )
        .await
        .expect("read lifecycle_enabled")
        .get(0);
    assert!(
        !enabled,
        "a refused enable_lifecycle must not flip the flag"
    );
}

/// P1-2 item 5: a promotion whose I/O comes back `Unusable` must leave the
/// head `Staged` and still readable, must not commit `Missing`, and must not
/// move any repository's `fragment_lifecycle_generation` -- the actual bug
/// this path was added to fix (a transient provider error demoting a good
/// staged fragment).
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn abandon_promotion_leaves_the_head_staged_and_readable_and_moves_no_repository_lifecycle_generation()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    let staged_manifest = manifest("abandon-promotion/staged", 0xA5, EpochAuthority::Staged);
    assert_eq!(
        coordinator
            .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest.clone()))
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate staged fragment"),
        CommitVerdict::Published
    );

    let witness_before = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness before promotion")
        .expect("repository must exist");

    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash)
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    let verdict = coordinator
        .commit_promotion(
            &promotion_intent,
            IoObservation::Unusable(MissingDiagnostic::Truncated),
        )
        .await
        .expect("commit promotion must not error");
    assert_eq!(verdict, CommitVerdict::Abandoned);
    assert!(verdict.left_representation_intact());

    let head_row = direct
        .query_one(
            "SELECT current_epoch, state, manifest_id FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after abandon");
    let current_epoch: i64 = head_row.get(0);
    let state: i16 = head_row.get(1);
    let manifest_id: Option<Vec<u8>> = head_row.get(2);
    assert_eq!(
        state,
        FragmentLifecycleState::Staged.bits(),
        "an abandoned promotion must leave the head Staged, not Missing"
    );
    assert_eq!(
        current_epoch, stage_intent.epoch,
        "the head must still name the staged epoch, not the abandoned promotion epoch"
    );
    assert_eq!(
        manifest_id,
        Some(staged_manifest.manifest_id.clone()),
        "the staged manifest must survive an abandoned promotion untouched"
    );

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve after abandoned promotion");
    let (_, resolved_manifest, _) = expect_readable(&resolved[0]);
    assert_eq!(
        resolved_manifest, &staged_manifest,
        "the fragment must remain readable under its original staged representation"
    );

    let witness_after = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness after promotion abandon")
        .expect("repository must exist");
    assert_eq!(
        witness_after, witness_before,
        "an abandoned promotion must move neither push-witness scalar for the associated \
         repository"
    );
}

/// P1-2 item 6 / P1-3: nothing else reads `lore_fragment_epochs.disposition`.
/// A successful repair publishing a greater epoch must quarantine the
/// predecessor epoch and leave the successor `DISPOSITION_CURRENT_ELIGIBLE`.
/// WP-118's acceptance line claimed this was tested; it was not, and this is
/// the test that makes the corrected line true.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_successful_repair_quarantines_the_predecessor_epoch_and_marks_the_successor_current_eligible()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin predecessor")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "quarantine/predecessor",
                    0xB0,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit predecessor"),
        CommitVerdict::Published
    );
    let predecessor_epoch = intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let predecessor_disposition_before: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &predecessor_epoch],
        )
        .await
        .expect("read predecessor disposition before repair")
        .get(0);
    assert_eq!(
        predecessor_disposition_before,
        schema::DISPOSITION_CURRENT_ELIGIBLE,
        "a freshly published epoch is current-eligible until superseded"
    );

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve before repair");
    let (witness, ..) = expect_readable(&resolved[0]);
    let witness = witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&witness, MissingDiagnostic::Absent)
            .await
            .expect("mark missing"),
        CommitVerdict::Published
    );

    let BeginOutcome::Admitted(repair_intent) =
        coordinator.claim_repair(&hash).await.expect("claim repair")
    else {
        panic!("a Missing head must admit a repair claim");
    };
    let successor_epoch = repair_intent.epoch;
    assert!(
        successor_epoch > predecessor_epoch,
        "epochs are allocated from a monotonic sequence"
    );
    assert_eq!(
        coordinator
            .commit_repair(
                &repair_intent,
                IoObservation::Valid(manifest(
                    "quarantine/successor",
                    0xB1,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit repair"),
        CommitVerdict::Published
    );

    let predecessor_disposition_after: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &predecessor_epoch],
        )
        .await
        .expect("read predecessor disposition after repair")
        .get(0);
    assert_eq!(
        predecessor_disposition_after,
        schema::DISPOSITION_QUARANTINED,
        "the predecessor epoch must be quarantined once a greater epoch publishes"
    );

    let successor_disposition: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &successor_epoch],
        )
        .await
        .expect("read successor disposition")
        .get(0);
    assert_eq!(
        successor_disposition,
        schema::DISPOSITION_CURRENT_ELIGIBLE,
        "the successor epoch must be current-eligible"
    );
}

// ---------------------------------------------------------------------------
// Phase 5 guarded copy association.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn query_matches_distinguish_exact_context_partition_and_unreadable_rows_in_one_batch() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let exact_context = random_context();
    let other_context = random_context();
    let readable_hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&readable_hash, &legacy_key(&readable_hash))
        .await
        .expect("begin readable")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "query-matches/readable",
                    0xa0,
                    EpochAuthority::Remote,
                )),
            )
            .await
            .expect("commit readable"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&readable_hash, &repository_id, &exact_context)
            .await
            .expect("associate readable"),
        CommitVerdict::Published
    );

    let missing_hash = random_hash();
    let BeginOutcome::Admitted(missing_intent) = coordinator
        .begin_direct_write(&missing_hash, &legacy_key(&missing_hash))
        .await
        .expect("begin missing")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &missing_intent,
                IoObservation::Unusable(MissingDiagnostic::Absent),
            )
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&missing_hash, &repository_id, &exact_context)
            .await
            .expect("associate missing for diagnostic retention"),
        CommitVerdict::Published
    );

    let absent_hash = random_hash();
    let requested = vec![
        FragmentQueryRequest {
            hash: readable_hash.clone(),
            context: exact_context.clone(),
        },
        FragmentQueryRequest {
            hash: readable_hash.clone(),
            context: other_context,
        },
        FragmentQueryRequest {
            hash: missing_hash.clone(),
            context: exact_context.clone(),
        },
        FragmentQueryRequest {
            hash: absent_hash.clone(),
            context: exact_context,
        },
    ];
    let matches = coordinator
        .resolve_query_matches(&repository_id, &requested)
        .await
        .expect("resolve query matches");

    assert_eq!(
        matches.len(),
        requested.len(),
        "batch cardinality must be exact"
    );
    assert_eq!(matches[0].hash, readable_hash);
    assert!(
        matches[0].exact_context_readable,
        "exact context is MatchFull"
    );
    assert!(matches[0].partition_readable);
    assert_eq!(matches[1].hash, readable_hash);
    assert!(!matches[1].exact_context_readable);
    assert!(
        matches[1].partition_readable,
        "same repository and readable hash in another context is MatchPartition"
    );
    assert_eq!(matches[2].hash, missing_hash);
    assert!(!matches[2].exact_context_readable);
    assert!(
        !matches[2].partition_readable,
        "an association alone cannot make a Missing head partition-readable"
    );
    assert_eq!(matches[3].hash, absent_hash);
    assert!(!matches[3].exact_context_readable);
    assert!(!matches[3].partition_readable);
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn guarded_association_requires_the_exact_readable_witness() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let source_context = random_context();
    let destination_context = random_context();
    let stale_context = random_context();
    let missing_context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin readable")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "guarded-association/readable",
                    0xa1,
                    EpochAuthority::Remote,
                )),
            )
            .await
            .expect("commit readable"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &source_context)
            .await
            .expect("associate source context"),
        CommitVerdict::Published
    );

    let resolution = coordinator
        .resolve(&repository_id, &source_context, std::slice::from_ref(&hash))
        .await
        .expect("resolve readable witness");
    let (witness, _, _) = expect_readable(&resolution[0]);
    let witness = witness.clone();

    assert_eq!(
        coordinator
            .create_association_if_current(&witness, &repository_id, &destination_context)
            .await
            .expect("guarded association"),
        CommitVerdict::Published,
        "the exact readable witness must insert and bump atomically"
    );

    let mut stale = witness.clone();
    stale.fence += 1;
    assert_eq!(
        coordinator
            .create_association_if_current(&stale, &repository_id, &stale_context)
            .await
            .expect("stale guarded association"),
        CommitVerdict::Fenced
    );

    assert_eq!(
        coordinator
            .mark_missing(&witness, MissingDiagnostic::Absent)
            .await
            .expect("mark missing"),
        CommitVerdict::Published
    );
    let missing_row = direct
        .query_one(
            "SELECT current_epoch, state, manifest_id, last_fence \
               FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read exact Missing witness");
    let missing_witness = EpochWitness {
        hash: hash.clone(),
        epoch: missing_row.get("current_epoch"),
        state: FragmentLifecycleState::from_bits(missing_row.get("state"))
            .expect("stored Missing state must decode"),
        manifest_id: missing_row.get("manifest_id"),
        fence: missing_row.get("last_fence"),
    };
    assert_eq!(missing_witness.state, FragmentLifecycleState::Missing);
    assert_eq!(
        coordinator
            .create_association_if_current(&missing_witness, &repository_id, &missing_context)
            .await
            .expect("missing guarded association"),
        CommitVerdict::Fenced,
        "Missing is never admissible even when the witness exactly matches it"
    );

    let forbidden_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_associations \
              WHERE hash = $1 AND repository_id = $2 AND context = ANY($3::bytea[])",
            &[
                &hash,
                &repository_id.as_slice(),
                &vec![stale_context, missing_context],
            ],
        )
        .await
        .expect("count refused association rows")
        .get(0);
    assert_eq!(
        forbidden_rows, 0,
        "stale and Missing refusals must leave no association residue"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn guarded_association_cannot_race_mark_missing_into_a_successful_residue() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let source_context = random_context();
    let racing_context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin readable")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "guarded-association/race",
                    0xa2,
                    EpochAuthority::Remote,
                )),
            )
            .await
            .expect("commit readable"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &source_context)
            .await
            .expect("associate source context"),
        CommitVerdict::Published
    );
    let resolution = coordinator
        .resolve(&repository_id, &source_context, std::slice::from_ref(&hash))
        .await
        .expect("resolve readable witness");
    let (witness, _, _) = expect_readable(&resolution[0]);
    let witness = witness.clone();

    let mut lock_client = own_transaction_client(&url).await;
    let lock_tx = lock_client
        .transaction()
        .await
        .expect("open external repository-lock transaction");
    lock_tx
        .execute(
            "SELECT 1 FROM lore_domain_repositories WHERE repository_id = $1 FOR UPDATE",
            &[&repository_id.as_slice()],
        )
        .await
        .expect("lock repository externally");

    let mark_missing = coordinator.mark_missing(&witness, MissingDiagnostic::Absent);
    let guarded = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        coordinator
            .create_association_if_current(&witness, &repository_id, &racing_context)
            .await
    };
    let release = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        lock_tx
            .commit()
            .await
            .expect("release external repository lock");
    };
    let (missing_result, guarded_result, ()) = tokio::join!(mark_missing, guarded, release);

    assert_eq!(
        missing_result.expect("mark missing race result"),
        CommitVerdict::Published
    );
    assert_eq!(
        guarded_result.expect("guarded association race result"),
        CommitVerdict::Fenced,
        "the later guarded insert must recheck after taking repository then head locks"
    );
    let residue: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_associations \
              WHERE hash = $1 AND repository_id = $2 AND context = $3",
            &[&hash, &repository_id.as_slice(), &racing_context],
        )
        .await
        .expect("count racing association residue")
        .get(0);
    assert_eq!(residue, 0, "a fenced racing insert must leave no row");
}

// ---------------------------------------------------------------------------
// INV-EF P1-1 regression: begin_obliterate's fanout race (fixed at 76033cb).
// ---------------------------------------------------------------------------

/// P1-1: a `create_association` landing between `begin_obliterate`'s unlocked
/// plan read and its head lock must not be silently tombstoned by a
/// transaction that never locked its repository row and moved no scalar for
/// it. `confirm_lifecycle_fanout` now runs unconditionally (not just
/// `if was_readable`) and detects the growth, so the whole obliterate
/// transaction refuses with retryable `Contention` and mutates nothing.
///
/// Deterministic interleaving, not timing: repository R is already
/// associated (so it IS in the planned fanout, giving `lock_lifecycle_fanout`
/// something to block on), and this test holds R's row locked externally for
/// exactly as long as it takes the racing `create_association` -- to a
/// DIFFERENT repository, R2, outside the plan -- to commit. `begin_obliterate`
/// cannot pass R until that external lock releases, and by then R2's
/// association, and the head lock `create_association` itself took and
/// released, are already durably committed -- so `begin_obliterate` resumes
/// straight into the window the finding describes.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_concurrent_create_association_landing_between_the_plan_and_the_head_lock_is_refused_with_zero_mutation()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_r = create_repository(&store).await;
    let repository_r2 = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();
    enable_write_claims(&url, &coordinator).await;

    // A non-readable head: Missing, from a failed first write.
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(&intent, IoObservation::Unusable(MissingDiagnostic::Absent))
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );
    // R is associated BEFORE the race, so it is in begin_obliterate's planned
    // fanout and its lock_lifecycle_fanout loop must take R's row lock.
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_r, &context)
            .await
            .expect("associate R"),
        CommitVerdict::Published
    );

    let witness_r_before = coordinator
        .capture_push_witness(&repository_r)
        .await
        .expect("capture R witness before")
        .expect("repository R must exist");
    let witness_r2_before = coordinator
        .capture_push_witness(&repository_r2)
        .await
        .expect("capture R2 witness before")
        .expect("repository R2 must exist");

    // Hold R's row lock externally, on its own connection/transaction, so
    // begin_obliterate's lock_lifecycle_fanout blocks on it deterministically.
    let mut lock_client = own_transaction_client(&url).await;
    let lock_tx = lock_client
        .transaction()
        .await
        .expect("open external repository-lock transaction");
    lock_tx
        .execute(
            "SELECT 1 FROM lore_domain_repositories WHERE repository_id = $1 FOR UPDATE",
            &[&repository_r.as_slice()],
        )
        .await
        .expect("lock repository R externally");

    let obliterate_task = async {
        coordinator
            .begin_obliterate(&hash, &repository_r, &context)
            .await
    };
    let race_task = async {
        // begin_obliterate is blocked on R's external lock regardless of this
        // delay -- it exists only to give it a moment to actually reach and
        // start waiting on R before the race proceeds.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            coordinator
                .create_association(&hash, &repository_r2, &context)
                .await
                .expect("racing create_association must not error"),
            CommitVerdict::Published,
            "the racing association to R2 (outside the plan) must land"
        );
        // R2's association -- and the head lock create_association itself
        // took and released -- are now durably committed. Only now release
        // R, letting begin_obliterate resume straight into the window.
        lock_tx
            .commit()
            .await
            .expect("release the external repository lock");
    };
    let (obliterate_result, ()) = tokio::join!(obliterate_task, race_task);

    let error = obliterate_result.expect_err(
        "a fanout that grew between the plan and the head lock must refuse, not silently \
         tombstone the racing association",
    );
    assert!(
        matches!(error, DomainError::Contention(_)),
        "expected Contention, got {error:?}"
    );
    assert!(error.is_retryable(), "Contention must be retryable");

    // Zero mutation: the whole obliterate transaction rolled back.
    let head_state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after the refused obliterate")
        .get(0);
    assert_eq!(
        head_state,
        FragmentLifecycleState::Missing.bits(),
        "a refused obliterate must not move the head out of Missing"
    );

    let r2_association_state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_associations \
              WHERE hash = $1 AND repository_id = $2 AND context = $3",
            &[&hash, &repository_r2.as_slice(), &context],
        )
        .await
        .expect("read R2's association state")
        .get(0);
    assert_eq!(
        r2_association_state,
        schema::ASSOCIATION_LIVE,
        "the racing association must not have been silently tombstoned"
    );

    let witness_r_after = coordinator
        .capture_push_witness(&repository_r)
        .await
        .expect("capture R witness after")
        .expect("repository R must exist");
    let witness_r2_after = coordinator
        .capture_push_witness(&repository_r2)
        .await
        .expect("capture R2 witness after")
        .expect("repository R2 must exist");
    assert_eq!(
        witness_r_after, witness_r_before,
        "R's scalars must be exactly as they were: it was never locked by the refused \
         obliterate and moved nothing attributable to it"
    );
    // R2's own `create_association` legitimately bumps its association scalar
    // by one -- that mutation is real and expected. What must NOT have
    // happened is a second movement from the refused obliterate (which would
    // show as +2, or any lifecycle-scalar movement at all).
    assert_eq!(
        witness_r2_after.content_association_generation,
        witness_r2_before.content_association_generation + 1,
        "R2's association scalar must move exactly once, from its own successful \
         create_association -- not a second time from a tombstone that never happened"
    );
    assert_eq!(
        witness_r2_after.fragment_lifecycle_generation,
        witness_r2_before.fragment_lifecycle_generation,
        "R2's lifecycle scalar must not move: the refused obliterate rolled back entirely"
    );
}

/// With two live associations, exact obliterate retires only the requested
/// association and leaves the shared non-readable head available to the peer.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn exact_obliterate_of_a_shared_non_readable_head_retires_only_the_requested_association() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_a = create_repository(&store).await;
    let repository_b = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(&intent, IoObservation::Unusable(MissingDiagnostic::Absent))
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );
    for repository_id in [&repository_a, &repository_b] {
        assert_eq!(
            coordinator
                .create_association(&hash, repository_id, &context)
                .await
                .expect("associate"),
            CommitVerdict::Published
        );
    }

    let before_a = coordinator
        .capture_push_witness(&repository_a)
        .await
        .expect("capture A before")
        .expect("repository A must exist");
    let before_b = coordinator
        .capture_push_witness(&repository_b)
        .await
        .expect("capture B before")
        .expect("repository B must exist");

    assert!(matches!(
        coordinator
            .begin_obliterate(&hash, &repository_a, &context)
            .await
            .expect("retire exact association on shared Missing head"),
        FragmentObliterateBegin::AssociationOnly
    ));

    let after_a = coordinator
        .capture_push_witness(&repository_a)
        .await
        .expect("capture A after")
        .expect("repository A must exist");
    let after_b = coordinator
        .capture_push_witness(&repository_b)
        .await
        .expect("capture B after")
        .expect("repository B must exist");

    assert_eq!(
        after_a.content_association_generation,
        before_a.content_association_generation + 1
    );
    assert_eq!(
        after_b.content_association_generation,
        before_b.content_association_generation
    );
    assert_eq!(
        after_a.fragment_lifecycle_generation,
        before_a.fragment_lifecycle_generation
    );
    assert_eq!(
        after_b.fragment_lifecycle_generation,
        before_b.fragment_lifecycle_generation
    );

    let remaining = coordinator
        .resolve(&repository_b, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve surviving association");
    expect_absent(&remaining[0]);
}

// ---------------------------------------------------------------------------
// WP-118 pre-Phase-5 hardening review: STAGED_LEASE_MEMBER_NOT_STAGED's
// disposition clause, validate_lease_members, and equivalent_epochs' all-or-
// nothing rule over a real multi-fragment batch.
// ---------------------------------------------------------------------------

/// A staged epoch awaiting exact purge remains current-eligible, but its
/// deleting head must refuse any new reader lease before physical cleanup.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_refuses_a_staged_member_awaiting_exact_payload_purge() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let deadline = microsecond_deadline(Duration::from_secs(60));
    enable_write_claims(&url, &coordinator).await;

    let hash = random_hash();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage_intent,
                IoObservation::Valid(manifest(
                    &staged_key(&hash, stage_intent.epoch),
                    0x90,
                    EpochAuthority::Staged
                ))
            )
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    let staged_epoch = stage_intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate staged fragment"),
        CommitVerdict::Published
    );

    let FragmentObliterateBegin::Ready(obliterate_intent) = coordinator
        .begin_obliterate(&hash, &repository_id, &context)
        .await
        .expect("begin obliterate")
    else {
        panic!("the sole association must own staged obliterate");
    };
    assert_eq!(
        coordinator
            .commit_obliterate_children(&obliterate_intent)
            .await
            .expect("commit child discovery"),
        CommitVerdict::Published
    );

    let staged_disposition: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &staged_epoch],
        )
        .await
        .expect("read staged epoch disposition after obliterate")
        .get(0);
    assert_eq!(
        staged_disposition,
        schema::DISPOSITION_CURRENT_ELIGIBLE,
        "child discovery cannot claim that staged bytes were purged"
    );
    let head_state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after obliterate")
        .get(0);
    assert_eq!(
        head_state,
        FragmentLifecycleState::DeletingPayload.bits(),
        "the head must remain deleting until staged cleanup yields an exact proof"
    );

    let lease_id = rand::random::<[u8; 16]>().to_vec();
    let result = coordinator
        .acquire_staged_leases(&lease_id, &[(hash, staged_epoch)], deadline)
        .await;
    match result {
        Err(DomainError::PreconditionRejected {
            reason,
            reason_version,
        }) => {
            assert_eq!(reason, STAGED_LEASE_MEMBER_NOT_STAGED);
            assert_eq!(reason_version, 1);
        }
        other => panic!(
            "expected STAGED_LEASE_MEMBER_NOT_STAGED while staged payload purge is pending, got {other:?}"
        ),
    }
}

/// Reviewer finding A1's other half: a `Staged` epoch that has been
/// quarantined by a later promotion (its successor now `Remote`, itself
/// still `DISPOSITION_QUARANTINED`, never `DISPOSITION_PURGED`) must still be
/// admitted. This is what stops the disposition clause from over-correcting
/// into refusing every superseded staged epoch, not only purged ones -- a
/// reader still mid-hydration against a quarantined staged epoch is exactly
/// what the lease protects.
///
/// **Which guard this pins, post-hardening-review**: both of
/// `lock_lease_member_heads`'s checks agree to admit here, and this case
/// cannot tell them apart on its own -- the head is `Remote` (readable, so
/// neither Tombstoned nor deleting) AND the epoch is QUARANTINED (never
/// PURGED). It exists to prove the new head check does not over-correct into
/// refusing a promoted fragment's superseded staged predecessor, the same way
/// the older disposition-only guard already had to avoid doing.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_admits_a_quarantined_staged_member() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let deadline = microsecond_deadline(Duration::from_secs(60));

    let hash = random_hash();
    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage_intent,
                IoObservation::Valid(manifest(
                    "quarantined-staged-member/staged",
                    0x91,
                    EpochAuthority::Staged
                ))
            )
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    let staged_epoch = stage_intent.epoch;

    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash)
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    assert_eq!(
        coordinator
            .commit_promotion(
                &promotion_intent,
                IoObservation::Valid(manifest(
                    "quarantined-staged-member/promoted",
                    0x92,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit promotion"),
        CommitVerdict::Published
    );

    // Confirm the staged epoch really is quarantined now -- not purged, and
    // not (still) current-eligible -- so this case cannot silently degenerate
    // into "any disposition is fine" or coincide with the purged case above.
    let disposition: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &staged_epoch],
        )
        .await
        .expect("read staged epoch disposition after promotion")
        .get(0);
    assert_eq!(
        disposition,
        schema::DISPOSITION_QUARANTINED,
        "the staged predecessor epoch must be quarantined once its promotion publishes"
    );

    let lease_id = rand::random::<[u8; 16]>().to_vec();
    let lease = coordinator
        .acquire_staged_leases(&lease_id, &[(hash.clone(), staged_epoch)], deadline)
        .await
        .expect("a quarantined staged epoch behind a readable head remains leasable");
    assert_eq!(lease.members, vec![(hash, staged_epoch)]);
}

/// P1-A: the exact independent-review sequence -- stage, promote, obliterate.
/// `commit_obliterate` purges only the epoch that was current when
/// `begin_obliterate` ran, which by then is the PROMOTED epoch, not the
/// staged predecessor -- so the staged epoch's own disposition stays
/// QUARANTINED, never PURGED. The epoch-disposition guard alone would
/// therefore admit this lease; only `lock_lease_member_heads`'s Tombstoned-
/// head check refuses it. The disposition assertion below is what makes this
/// case prove the head check specifically, rather than merely re-running
/// `acquire_staged_leases_refuses_a_purged_staged_member` under a different
/// name.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_refuses_a_member_whose_fragment_was_obliterated_after_promotion() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let deadline = microsecond_deadline(Duration::from_secs(60));
    enable_write_claims(&url, &coordinator).await;

    let hash = random_hash();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage_intent,
                IoObservation::Valid(manifest(
                    &staged_key(&hash, stage_intent.epoch),
                    0x93,
                    EpochAuthority::Staged
                ))
            )
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    let staged_epoch = stage_intent.epoch;

    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash)
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    assert_eq!(
        coordinator
            .commit_promotion(
                &promotion_intent,
                IoObservation::Valid(manifest(&legacy_key(&hash), 0x94, EpochAuthority::Remote))
            )
            .await
            .expect("commit promotion"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate promoted fragment"),
        CommitVerdict::Published
    );

    let FragmentObliterateBegin::Ready(obliterate_intent) = coordinator
        .begin_obliterate(&hash, &repository_id, &context)
        .await
        .expect("begin obliterate")
    else {
        panic!("the sole association must own promoted obliterate");
    };
    assert_eq!(
        coordinator
            .commit_obliterate_children(&obliterate_intent)
            .await
            .expect("commit child discovery"),
        CommitVerdict::Published
    );

    // Prove the shape this case actually exercises BEFORE calling
    // acquire_staged_leases: the staged epoch's disposition is still
    // QUARANTINED, not PURGED, and the head is Tombstoned. If the disposition
    // guard alone were asked, it would admit this lease.
    let staged_disposition: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &staged_epoch],
        )
        .await
        .expect("read staged epoch disposition after obliterate")
        .get(0);
    assert_eq!(
        staged_disposition,
        schema::DISPOSITION_QUARANTINED,
        "the staged predecessor epoch must remain QUARANTINED -- obliterate purges only the \
         epoch that was current when it began, which by then is the promoted one, not this one"
    );
    let head_state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after obliterate")
        .get(0);
    assert_eq!(
        head_state,
        FragmentLifecycleState::DeletingPayload.bits(),
        "the head must refuse leases while awaiting exact payload purge"
    );

    let lease_id = rand::random::<[u8; 16]>().to_vec();
    let result = coordinator
        .acquire_staged_leases(&lease_id, &[(hash.clone(), staged_epoch)], deadline)
        .await;
    match result {
        Err(DomainError::PreconditionRejected {
            reason,
            reason_version,
        }) => {
            assert_eq!(reason, STAGED_LEASE_MEMBER_NOT_STAGED);
            assert_eq!(reason_version, 1);
        }
        other => panic!(
            "expected STAGED_LEASE_MEMBER_NOT_STAGED for a staged epoch behind a tombstoned \
             head, got {other:?}"
        ),
    }

    let lease_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id],
        )
        .await
        .expect("count lease rows")
        .get(0);
    assert_eq!(lease_rows, 0, "a refused lease must persist no lease row");
    let member_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_lease_members WHERE lease_id = $1",
            &[&lease_id],
        )
        .await
        .expect("count lease member rows")
        .get(0);
    assert_eq!(member_rows, 0, "a refused lease must persist no member row");
}

/// P1-A's mid-flight half: `begin_obliterate` alone (no children commit)
/// leaves the head `DeletingChildren`. The head check in
/// `lock_lease_member_heads` refuses on `state.is_deleting()`, a separate
/// branch from the `Tombstoned` equality check the sibling cases exercise --
/// this is the only case in the file that reaches it.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_refuses_a_member_whose_head_is_mid_deletion() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let deadline = microsecond_deadline(Duration::from_secs(60));
    enable_write_claims(&url, &coordinator).await;

    let hash = random_hash();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage_intent,
                IoObservation::Valid(manifest(
                    &staged_key(&hash, stage_intent.epoch),
                    0x95,
                    EpochAuthority::Staged
                ))
            )
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    let staged_epoch = stage_intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate staged fragment"),
        CommitVerdict::Published
    );

    let FragmentObliterateBegin::Ready(_obliterate_intent) = coordinator
        .begin_obliterate(&hash, &repository_id, &context)
        .await
        .expect("begin obliterate")
    else {
        panic!("the sole association must own staged obliterate");
    };
    // Deliberately no commit_obliterate: the head must be DeletingPayload, not
    // yet Tombstoned, so this case reaches `is_deleting()` rather than the
    // `Tombstoned` equality check the sibling cases above exercise.
    let head_state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after begin_obliterate")
        .get(0);
    assert_eq!(
        head_state,
        FragmentLifecycleState::DeletingChildren.bits(),
        "begin_obliterate alone must leave the head in child discovery"
    );

    let lease_id = rand::random::<[u8; 16]>().to_vec();
    let result = coordinator
        .acquire_staged_leases(&lease_id, &[(hash, staged_epoch)], deadline)
        .await;
    match result {
        Err(DomainError::PreconditionRejected {
            reason,
            reason_version,
        }) => {
            assert_eq!(reason, STAGED_LEASE_MEMBER_NOT_STAGED);
            assert_eq!(reason_version, 1);
        }
        other => panic!(
            "expected STAGED_LEASE_MEMBER_NOT_STAGED for a staged epoch behind a mid-deletion \
             head, got {other:?}"
        ),
    }
}

/// P1-B, made deterministic: before `lock_lease_member_heads`, the scope
/// check inside `acquire_staged_leases` was an unlocked `SELECT` at READ
/// COMMITTED with no head lock at all, so a concurrent `commit_obliterate`
/// could purge the epoch between the check passing and the lease row
/// landing. `lock_lease_member_heads`'s `FOR SHARE` closes that by
/// serialising against whatever holds the head row's lock -- proved here by
/// holding an external `FOR UPDATE` on the head and showing
/// `acquire_staged_leases` genuinely blocks on it (a `tokio::time::timeout`
/// elapses) rather than returning immediately, which is exactly what it did
/// before the `FOR SHARE` was added.
///
/// The coordinator's own pool (`store()`, `pool_max` 8) and the external
/// lock holder's pool (`own_transaction_client`, its own separate `pool_max`
/// 4) are two disjoint, multi-connection pools. That is deliberate: if the
/// blocked `acquire_staged_leases` call and the external lock shared a
/// single-connection pool, a timeout here could mean nothing more than "the
/// pool had no free connection to hand out" -- indistinguishable from the
/// row-lock wait this test means to prove. With two separate
/// more-than-one-connection pools, the only thing left that can make the
/// call wait is the head's row lock itself.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_waits_for_a_concurrently_locked_head() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let deadline = microsecond_deadline(Duration::from_secs(60));

    let hash = random_hash();
    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage_intent,
                IoObservation::Valid(manifest(
                    "head-lock-wait/staged",
                    0x96,
                    EpochAuthority::Staged
                ))
            )
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    let staged_epoch = stage_intent.epoch;

    // Hold the head's row lock externally, on a wholly separate pool and
    // connection from the coordinator's own.
    let mut lock_client = own_transaction_client(&url).await;
    let lock_tx = lock_client
        .transaction()
        .await
        .expect("open external head-lock transaction");
    lock_tx
        .execute(
            "SELECT 1 FROM lore_fragment_lifecycle WHERE hash = $1 FOR UPDATE",
            &[&hash.as_slice()],
        )
        .await
        .expect("lock the head externally");

    let lease_id = rand::random::<[u8; 16]>().to_vec();
    let members = vec![(hash.clone(), staged_epoch)];
    let blocked = timeout(
        Duration::from_secs(2),
        coordinator.acquire_staged_leases(&lease_id, &members, deadline),
    )
    .await;
    assert!(
        blocked.is_err(),
        "acquire_staged_leases must block on the externally held head lock rather than return \
         immediately -- without lock_lease_member_heads's FOR SHARE this returns right away"
    );

    // Release the external lock and confirm the very same acquire now
    // succeeds promptly.
    lock_tx
        .commit()
        .await
        .expect("release the external head lock");

    let lease = timeout(
        Duration::from_secs(5),
        coordinator.acquire_staged_leases(&lease_id, &members, deadline),
    )
    .await
    .expect("acquire_staged_leases must complete promptly once the head lock is released")
    .expect("a staged member with no purged/tombstoned head must admit a lease");
    assert_eq!(lease.members, members);
}

/// `validate_lease_members` runs before any database work: a batch repeating
/// one hash at two epochs, and an empty batch, are both refused as
/// [`DomainError::InvalidInput`] with zero rows written. Neither epoch here
/// needs to be real -- the refusal is purely about the shape of the input
/// tuples, which is exactly what makes it a pure, DB-independent guard.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_refuses_a_duplicate_hash_batch_and_an_empty_batch() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let deadline = microsecond_deadline(Duration::from_secs(60));

    let hash = random_hash();
    let duplicate_hash_batch = vec![(hash.clone(), 1i64), (hash, 2i64)];
    let lease_id_duplicate = rand::random::<[u8; 16]>().to_vec();
    let duplicate_result = coordinator
        .acquire_staged_leases(&lease_id_duplicate, &duplicate_hash_batch, deadline)
        .await;
    assert!(
        matches!(duplicate_result, Err(DomainError::InvalidInput(_))),
        "expected InvalidInput for a duplicate-hash batch, got {duplicate_result:?}"
    );
    let duplicate_lease_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_duplicate],
        )
        .await
        .expect("count lease rows for a duplicate-hash batch")
        .get(0);
    assert_eq!(
        duplicate_lease_rows, 0,
        "a duplicate-hash batch must be refused before any database write"
    );

    let lease_id_empty = rand::random::<[u8; 16]>().to_vec();
    let empty_result = coordinator
        .acquire_staged_leases(&lease_id_empty, &[], deadline)
        .await;
    assert!(
        matches!(empty_result, Err(DomainError::InvalidInput(_))),
        "expected InvalidInput for an empty batch, got {empty_result:?}"
    );
    let empty_lease_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_empty],
        )
        .await
        .expect("count lease rows for an empty batch")
        .get(0);
    assert_eq!(
        empty_lease_rows, 0,
        "an empty batch must be refused before any database write"
    );
}

/// A required fragment whose CAPTURED epoch was never published for that hash
/// at all (not merely superseded) must abort, even though the head is
/// genuinely readable at some other epoch. `equivalent_epochs` joins
/// `lore_fragment_epochs` on the captured epoch; when that row does not
/// exist, the join drops the pair, `matched` falls short of `divergent.len()`,
/// and the all-or-nothing rule aborts the whole push.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_aborts_when_the_captured_epoch_was_never_published() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();

    let hash = random_hash();
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "captured-epoch-missing/key",
                    0x93,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    let real_epoch = intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    // Move the lifecycle scalar via a bystander so the call reaches the
    // fallback rather than short-circuiting on `Unchanged`.
    let bystander_hash = random_hash();
    let BeginOutcome::Admitted(bystander_intent) = coordinator
        .begin_direct_write(&bystander_hash, &legacy_key(&bystander_hash))
        .await
        .expect("begin bystander")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &bystander_intent,
                IoObservation::Valid(manifest(
                    "captured-epoch-missing/bystander",
                    0x94,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit bystander"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&bystander_hash, &repository_id, &context)
            .await
            .expect("associate bystander"),
        CommitVerdict::Published
    );
    let resolved_bystander = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&bystander_hash),
        )
        .await
        .expect("resolve bystander");
    let (bystander_witness, ..) = expect_readable(&resolved_bystander[0]);
    let bystander_witness = bystander_witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&bystander_witness, MissingDiagnostic::Absent)
            .await
            .expect("mark bystander missing"),
        CommitVerdict::Published
    );

    // A captured epoch guaranteed never published for this hash: far outside
    // any value this test's own fence sequence could reach, and distinct from
    // the real current epoch.
    let never_published_epoch = real_epoch + 1_000_000_000;
    assert_ne!(never_published_epoch, real_epoch);
    let required = vec![RequiredFragment {
        hash,
        epoch: never_published_epoch,
    }];

    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();
    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::Aborted {
            reason: REQUIRED_FRAGMENT_CHANGED
        }
    );
}

/// `equivalent_epochs`' all-or-nothing rule (`matched == divergent.len()`)
/// cannot be discriminated by a one-element `required` slice -- both branches
/// of the boolean collapse to the same answer at `len() == 1`. A genuine
/// two-fragment batch is required: two fragments both promoted equivalently
/// pins the exact `revalidated: 2` count, and swapping one of them for a
/// non-equivalent promotion must abort the WHOLE push, not just the one
/// fragment that diverged.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_all_or_nothing_over_a_mixed_divergent_batch() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();

    async fn stage_and_associate(
        coordinator: &PostgresFragmentCoordinator,
        repository_id: &[u8],
        context: &[u8],
        key_prefix: &str,
        seed: u8,
    ) -> (Vec<u8>, i64, FragmentManifest) {
        let hash = random_hash();
        let BeginOutcome::Admitted(stage_intent) =
            coordinator.begin_stage(&hash).await.expect("begin stage")
        else {
            panic!("a fresh hash must admit a stage begin");
        };
        let staged_manifest = manifest(
            &format!("{key_prefix}/staged"),
            seed,
            EpochAuthority::Staged,
        );
        assert_eq!(
            coordinator
                .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest.clone()))
                .await
                .expect("commit staged"),
            CommitVerdict::Published
        );
        assert_eq!(
            coordinator
                .create_association(&hash, repository_id, context)
                .await
                .expect("associate"),
            CommitVerdict::Published
        );
        (hash, stage_intent.epoch, staged_manifest)
    }

    let (hash_a, original_epoch_a, staged_manifest_a) = stage_and_associate(
        &coordinator,
        &repository_id,
        &context,
        "mixed-batch/a-equivalent",
        0xA0,
    )
    .await;
    let (hash_b, original_epoch_b, staged_manifest_b) = stage_and_associate(
        &coordinator,
        &repository_id,
        &context,
        "mixed-batch/b-equivalent",
        0xA1,
    )
    .await;
    let (hash_c, original_epoch_c, staged_manifest_c) = stage_and_associate(
        &coordinator,
        &repository_id,
        &context,
        "mixed-batch/c-divergent",
        0xA2,
    )
    .await;

    let bystander_hash = random_hash();
    let BeginOutcome::Admitted(bystander_intent) = coordinator
        .begin_direct_write(&bystander_hash, &legacy_key(&bystander_hash))
        .await
        .expect("begin bystander")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &bystander_intent,
                IoObservation::Valid(manifest(
                    "mixed-batch/bystander",
                    0xA9,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit bystander"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&bystander_hash, &repository_id, &context)
            .await
            .expect("associate bystander"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    // A and B: promote equivalently (identical decoded_hash/size_content/
    // size_payload/payload_flags; different object_key and manifest_id).
    for (hash, staged_manifest, key) in [
        (&hash_a, &staged_manifest_a, "mixed-batch/a-promoted"),
        (&hash_b, &staged_manifest_b, "mixed-batch/b-promoted"),
    ] {
        let BeginOutcome::Admitted(promotion_intent) = coordinator
            .begin_promotion(hash)
            .await
            .expect("begin promotion")
        else {
            panic!("a Staged head must admit begin_promotion");
        };
        let mut promoted = staged_manifest.clone();
        promoted.authority = EpochAuthority::Remote;
        promoted.object_key = key.to_owned();
        promoted.manifest_id = vec![0xAF; 32];
        assert_eq!(
            coordinator
                .commit_promotion(&promotion_intent, IoObservation::Valid(promoted))
                .await
                .expect("commit promotion"),
            CommitVerdict::Published
        );
    }

    // C: promote with a different decoded_hash -- genuinely different content.
    let BeginOutcome::Admitted(promotion_c) = coordinator
        .begin_promotion(&hash_c)
        .await
        .expect("begin promotion c")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    let mut promoted_c = staged_manifest_c.clone();
    promoted_c.authority = EpochAuthority::Remote;
    promoted_c.object_key = "mixed-batch/c-promoted".to_owned();
    promoted_c.manifest_id = vec![0xCA; 32];
    promoted_c.decoded_hash = vec![0xFF; 32];
    assert_ne!(promoted_c.decoded_hash, staged_manifest_c.decoded_hash);
    assert_eq!(
        coordinator
            .commit_promotion(&promotion_c, IoObservation::Valid(promoted_c))
            .await
            .expect("commit promotion c"),
        CommitVerdict::Published
    );

    // Move the lifecycle scalar so both revalidations below reach the
    // fallback branch rather than short-circuiting on `Unchanged`.
    let resolved_bystander = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&bystander_hash),
        )
        .await
        .expect("resolve bystander");
    let (bystander_witness, ..) = expect_readable(&resolved_bystander[0]);
    let bystander_witness = bystander_witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&bystander_witness, MissingDiagnostic::Absent)
            .await
            .expect("mark bystander missing"),
        CommitVerdict::Published
    );

    // Every epoch really did advance -- this is what stops the case from
    // silently degenerating into an exact-match path for any of the three.
    for (hash, original_epoch, label) in [
        (&hash_a, original_epoch_a, "a"),
        (&hash_b, original_epoch_b, "b"),
        (&hash_c, original_epoch_c, "c"),
    ] {
        let current_epoch: i64 = direct
            .query_one(
                "SELECT current_epoch FROM lore_fragment_lifecycle WHERE hash = $1",
                &[hash],
            )
            .await
            .expect("read current epoch after promotion")
            .get(0);
        assert_ne!(
            current_epoch, original_epoch,
            "{label}: the epoch must have genuinely advanced"
        );
    }

    // Part 1: two REQUIRED fragments, both promoted equivalently -- the
    // fallback's exact revalidated count is pinned at 2, not just some
    // positive number, or the length of an incidentally-1-element slice.
    let both_equivalent = vec![
        RequiredFragment {
            hash: hash_a.clone(),
            epoch: original_epoch_a,
        },
        RequiredFragment {
            hash: hash_b.clone(),
            epoch: original_epoch_b,
        },
    ];
    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();
    let verdict = coordinator
        .revalidate_push_witness(
            &tx,
            &mut sequence,
            &repository_id,
            captured,
            &both_equivalent,
        )
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::FallbackSatisfied { revalidated: 2 }
    );
    // Neither `tx` nor `tx_client` was ever committed, so `tx`'s `FOR UPDATE`
    // lock on hash_a's and hash_b's rows is still held until dropped. Part 2
    // below re-locks hash_a in a SEPARATE transaction on a separate pool --
    // without an explicit drop here, shadowing `tx`/`tx_client` with new `let`
    // bindings does not free them (Rust drops shadowed values at end of
    // scope, not at shadowing), and Part 2 would block forever waiting on a
    // lock this same test still holds. Revert-checked: removing these two
    // `drop`s reproduces the hang deterministically.
    drop(tx);
    drop(tx_client);

    // Part 2: swap B for C (non-equivalent). One equivalent member and one
    // non-equivalent member in the SAME batch must abort the whole push, not
    // just skip the bad one.
    let mixed = vec![
        RequiredFragment {
            hash: hash_a,
            epoch: original_epoch_a,
        },
        RequiredFragment {
            hash: hash_c,
            epoch: original_epoch_c,
        },
    ];
    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();
    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &mixed)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::Aborted {
            reason: REQUIRED_FRAGMENT_CHANGED
        },
        "one non-equivalent member in an otherwise-equivalent batch must abort the whole push"
    );
}

/// P2-C (WP-118 hardening review): every existing `revalidate_push_witness`
/// case associates its fragments BEFORE capturing the witness, so the
/// association scalar never moves in any of them --
/// `an_association_move_outranks_a_lifecycle_move` (`coordinator.rs`'s own
/// `mod tests`) pins the precedence offline against `classify_push_witness`
/// directly, but nothing end-to-end proves it against the real
/// `revalidate_push_witness` path until this case. Move BOTH scalars for the
/// SAME required fragment: after capture, tombstone and recreate its
/// association (association scalar, membership unchanged) and promote it to
/// a content-equivalent successor epoch, alongside a bystander transition
/// that moves the lifecycle scalar too. If the precedence were wrong --
/// lifecycle checked first, or the two conditions merged into "was there any
/// change" -- this would reach the fallback, see the required fragment
/// readable at an equivalent epoch, and wrongly satisfy the push against an
/// association set that (momentarily) did not contain it.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_aborts_when_the_association_set_moved_even_though_a_required_fragment_is_equivalent()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();

    // The required fragment: staged, then associated BEFORE capture, exactly
    // like the existing equivalent-epoch case -- its own create_association
    // here does not move the scalar this test cares about after capture.
    let hash = random_hash();
    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    let staged_manifest = manifest("assoc-move/staged", 0xD0, EpochAuthority::Staged);
    assert_eq!(
        coordinator
            .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest.clone()))
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    let original_epoch = stage_intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate required fragment"),
        CommitVerdict::Published
    );

    // A bystander whose readable-to-Missing transition is what moves the
    // lifecycle scalar -- an equivalent promotion alone (Staged->Remote, both
    // readable) crosses no readability boundary and moves nothing on its own.
    let bystander_hash = random_hash();
    let BeginOutcome::Admitted(bystander_intent) = coordinator
        .begin_direct_write(&bystander_hash, &legacy_key(&bystander_hash))
        .await
        .expect("begin bystander")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &bystander_intent,
                IoObservation::Valid(manifest(
                    "assoc-move/bystander",
                    0xD9,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit bystander"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&bystander_hash, &repository_id, &context)
            .await
            .expect("associate bystander"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    // Move the association scalar: tombstone and recreate the required
    // fragment's own association. Membership ends up exactly as it was
    // (still live, same hash/repository/context) -- only the scalar moves,
    // which is precisely the shape a lifecycle-only check would miss.
    assert_eq!(
        coordinator
            .tombstone_association(&hash, &repository_id, &context)
            .await
            .expect("tombstone required fragment association"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("recreate required fragment association"),
        CommitVerdict::Published
    );

    // Promote the required fragment to a NEW epoch that is content-equivalent
    // to the one preflight captured -- if the fallback were ever reached, the
    // CR-031:266 equivalence allowance would accept it.
    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash)
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    assert_ne!(
        promotion_intent.epoch, original_epoch,
        "promotion must allocate a new epoch, not republish the staged one"
    );
    let mut promoted_manifest = staged_manifest.clone();
    promoted_manifest.authority = EpochAuthority::Remote;
    promoted_manifest.object_key = "assoc-move/promoted".to_owned();
    promoted_manifest.manifest_id = vec![0xDA; 32];
    assert_eq!(
        coordinator
            .commit_promotion(&promotion_intent, IoObservation::Valid(promoted_manifest))
            .await
            .expect("commit promotion"),
        CommitVerdict::Published
    );

    // Move the lifecycle scalar via the bystander.
    let resolved_bystander = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&bystander_hash),
        )
        .await
        .expect("resolve bystander");
    let (bystander_witness, ..) = expect_readable(&resolved_bystander[0]);
    let bystander_witness = bystander_witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&bystander_witness, MissingDiagnostic::Absent)
            .await
            .expect("mark bystander missing"),
        CommitVerdict::Published
    );

    // Prove, by direct SQL, that BOTH scalars actually moved -- otherwise
    // this case silently degenerates into the existing lifecycle-only path
    // and proves nothing about the precedence.
    let scalars_row = direct
        .query_one(
            "SELECT content_association_generation, fragment_lifecycle_generation \
               FROM lore_domain_repositories WHERE repository_id = $1",
            &[&repository_id.as_slice()],
        )
        .await
        .expect("read repository scalars after the moves");
    let current_association: i64 = scalars_row.get(0);
    let current_lifecycle: i64 = scalars_row.get(1);
    assert_ne!(
        current_association, captured.content_association_generation,
        "the association scalar must have genuinely moved"
    );
    assert_ne!(
        current_lifecycle, captured.fragment_lifecycle_generation,
        "the lifecycle scalar must have genuinely moved too -- otherwise this case cannot \
         distinguish an association move from a lifecycle-only one"
    );

    // The required fragment really is readable at a content-equivalent
    // successor epoch -- the exact shape the equivalence allowance accepts.
    let current_epoch: i64 = direct
        .query_one(
            "SELECT current_epoch FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read current epoch after promotion")
        .get(0);
    assert_eq!(current_epoch, promotion_intent.epoch);
    assert_ne!(
        current_epoch, original_epoch,
        "the required fragment's current epoch must have genuinely advanced"
    );

    let required = vec![RequiredFragment {
        hash: hash.clone(),
        epoch: original_epoch,
    }];
    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();
    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::Aborted {
            reason: REQUIRED_FRAGMENT_CHANGED
        },
        "an association move must abort even though the required fragment is readable at a \
         content-equivalent epoch -- association precedence must outrank the equivalence \
         allowance"
    );
}

// ---------------------------------------------------------------------------
// WP-118 Phase 7: CR-031's two sustained-upload-traffic push cases, the
// shared-hash fanout cost characterization (INV-EF P2-7), and the copy path's
// association-generation bump.
// ---------------------------------------------------------------------------

/// CR-031's normative window: the uploaders stay busy for at least this long.
const SUSTAINED_UPLOAD_WINDOW: Duration = Duration::from_secs(10);

/// CR-031's suite watchdog for both sustained-traffic cases.
const SUSTAINED_SUITE_WATCHDOG: Duration = Duration::from_secs(30);

/// CR-031 fixes the push count for both sustained-traffic cases.
const SUSTAINED_PUSH_COUNT: usize = 100;

/// CR-031 fixes three disjoint uploaders for both sustained-traffic cases.
const SUSTAINED_UPLOADER_COUNT: usize = 3;

/// Hashes each uploader cycles through. Small enough that every hash is
/// revisited many times inside the window, so the traffic is genuinely
/// sustained rather than one burst.
const UPLOADER_HASHES_EACH: usize = 4;

/// Fragments each simulated push requires. Well under
/// [`MAX_PUSH_FRAGMENT_REVALIDATIONS`], which is what CR-031's shape specifies.
const PUSH_REQUIRED_FRAGMENTS: usize = 16;

/// Spacing between pushes, so the 100 pushes spread across the sustained
/// window instead of finishing in a burst before the uploaders warm up.
const PUSH_INTERVAL: Duration = Duration::from_millis(60);

/// Publish one fresh readable `Remote` fragment and return its hash.
///
/// The published manifest carries the **intent's own** `object_key`, not a
/// caller-supplied label. Several older fixtures in this file publish a
/// descriptive string instead, which leaves the epoch row holding a key that
/// does not match the one the intent was admitted at. That is harmless for a
/// case that never deletes -- nothing on the publication path compares them --
/// but `begin_obliterate` does reject a noncanonical epoch key
/// (`noncanonical_epoch_object_key_is_refused_before_delete_ownership_is_published`),
/// so a fixture built that way silently cannot be obliterated later. Taking the
/// key from the intent keeps every fragment these Phase 7 cases publish
/// canonical and reusable; `seed` still varies the manifest identity bytes.
async fn publish_remote_fragment(coordinator: &TestFragmentCoordinator, seed: u8) -> Vec<u8> {
    let hash = random_hash();
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin publication")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(&intent.object_key, seed, EpochAuthority::Remote)),
            )
            .await
            .expect("commit publication"),
        CommitVerdict::Published
    );
    hash
}

/// What kind of traffic one uploader generates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploaderTraffic {
    /// Fresh publications that associate nothing, plus readable/unreadable
    /// cycling of the uploader's own already-associated hashes. Moves only
    /// `fragment_lifecycle_generation` on the repository.
    LifecycleOnly,
    /// What a real bulk upload through `store/immutable_store.rs` does: every
    /// fresh publication is also associated into the repository, so
    /// `content_association_generation` moves and
    /// `fragment_lifecycle_generation` does not.
    PublishAndAssociate,
}

/// What one uploader actually achieved inside the window.
///
/// Counted rather than assumed, so a run where the traffic never got going is
/// visible in the printed regime block instead of hiding behind a green tick.
#[derive(Debug, Clone)]
struct UploaderTally {
    label: &'static str,
    publications: usize,
    associations: usize,
    transitions: usize,
    elapsed: Duration,
}

impl UploaderTally {
    fn publications_per_second(&self) -> f64 {
        self.publications as f64 / self.elapsed.as_secs_f64()
    }
}

/// One push attempt's verdict plus the wall-clock window over which a
/// concurrent scalar move could have invalidated it.
///
/// `window` spans from the moment preflight's `capture_push_witness` returns to
/// the moment `revalidate_push_witness` returns, so it includes the final
/// transaction's own repository and branch lock acquisition. That is the
/// interval a competing uploader has to move a scalar in.
#[derive(Debug, Clone)]
struct PushSample {
    verdict: PushWitnessVerdict,
    window: Duration,
}

/// Summarise a run of push samples for the printed regime block.
fn summarize_pushes(samples: &[PushSample]) -> String {
    let unchanged = samples
        .iter()
        .filter(|sample| sample.verdict == PushWitnessVerdict::Unchanged)
        .count();
    let mut fallback = 0usize;
    let mut revalidated_counts: BTreeSet<usize> = BTreeSet::new();
    let mut aborted: BTreeMap<&'static str, usize> = BTreeMap::new();
    for sample in samples {
        match &sample.verdict {
            PushWitnessVerdict::Unchanged => {}
            PushWitnessVerdict::FallbackSatisfied { revalidated } => {
                fallback += 1;
                revalidated_counts.insert(*revalidated);
            }
            PushWitnessVerdict::Aborted { reason } => {
                *aborted.entry(reason).or_default() += 1;
            }
        }
    }
    let mut windows: Vec<u128> = samples
        .iter()
        .map(|sample| sample.window.as_micros())
        .collect();
    windows.sort_unstable();
    let median = windows[windows.len() / 2];
    let aborted_total: usize = aborted.values().sum();
    format!(
        "pushes={} unchanged={unchanged} fallback_satisfied={fallback} aborted={aborted_total} \
         aborted_reasons={aborted:?} revalidated_counts={revalidated_counts:?} \
         window_us_min={} window_us_median={median} window_us_max={}",
        samples.len(),
        windows[0],
        windows[windows.len() - 1]
    )
}

/// One uploader's sustained traffic against `repository_id`, over its own
/// disjoint hash set, until `deadline`.
///
/// Under [`UploaderTraffic::LifecycleOnly`] each iteration does three real
/// things: publishes a brand-new fragment (pure upload volume, associated with
/// nothing), drives one of its own already-associated fragments readable to
/// unreadable, and re-uploads it unreadable to readable through the repair
/// path. Those two transitions move `fragment_lifecycle_generation`, the
/// scalar the bounded push fallback exists to survive.
///
/// Under [`UploaderTraffic::PublishAndAssociate`] each iteration publishes a
/// fresh fragment and associates it into the repository, which is what a real
/// bulk upload does, and moves `content_association_generation` instead.
///
/// Returns a counted [`UploaderTally`] rather than a bare number, so a caller
/// can report the achieved rate instead of assuming the traffic was real.
async fn run_sustained_uploader(
    coordinator: &TestFragmentCoordinator,
    repository_id: &[u8],
    context: &[u8],
    hashes: &[Vec<u8>],
    label: &'static str,
    traffic: UploaderTraffic,
    deadline: Instant,
) -> UploaderTally {
    let started = Instant::now();
    let mut tally = UploaderTally {
        label,
        publications: 0,
        associations: 0,
        transitions: 0,
        elapsed: Duration::ZERO,
    };
    let mut seed = 0x10u8;
    while Instant::now() < deadline {
        for hash in hashes {
            if Instant::now() >= deadline {
                break;
            }
            seed = seed.wrapping_add(1);
            let fresh = publish_remote_fragment(coordinator, seed).await;
            tally.publications += 1;

            if traffic == UploaderTraffic::PublishAndAssociate {
                assert_eq!(
                    coordinator
                        .create_association(&fresh, repository_id, context)
                        .await
                        .expect("uploader create_association must not error"),
                    CommitVerdict::Published
                );
                tally.associations += 1;
                continue;
            }

            let resolved = coordinator
                .resolve(repository_id, context, std::slice::from_ref(hash))
                .await
                .expect("uploader resolves its own fragment");
            let (witness, ..) = expect_readable(&resolved[0]);
            let witness = witness.clone();
            assert_eq!(
                coordinator
                    .mark_missing(&witness, MissingDiagnostic::Absent)
                    .await
                    .expect("uploader mark_missing must not error"),
                CommitVerdict::Published,
                "an uploader owns its own disjoint hashes, so nothing can fence it"
            );
            tally.transitions += 1;

            let BeginOutcome::Admitted(repair) = coordinator
                .claim_repair(hash)
                .await
                .expect("uploader claims a repair")
            else {
                panic!("a Missing head the uploader owns must admit a repair claim");
            };
            seed = seed.wrapping_add(1);
            assert_eq!(
                coordinator
                    .commit_repair(
                        &repair,
                        IoObservation::Valid(manifest(
                            &repair.object_key,
                            seed,
                            EpochAuthority::Remote
                        )),
                    )
                    .await
                    .expect("uploader commit_repair must not error"),
                CommitVerdict::Published
            );
            tally.transitions += 1;
        }
    }
    tally.elapsed = started.elapsed();
    tally
}

/// Run one coordinator-level final push transaction and return its verdict
/// together with the window a concurrent scalar move had to invalidate it.
///
/// `FINAL-PUSH-118` is owned by WP-116 and is not built, so this is the
/// coordinator-level equivalent of the real handler: capture the witness
/// outside any transaction (preflight), then open the final transaction and
/// take its locks in F-032-3 order (repository, branch, then the fragment rows
/// `revalidate_push_witness` takes for itself) and revalidate inside it. The
/// verdict is taken from that single call: nothing here retries, so a returned
/// `Aborted` is a push that did not commit on its first final-transaction
/// attempt.
async fn run_final_push_transaction(
    coordinator: &TestFragmentCoordinator,
    pool: &deadpool_postgres::Pool,
    repository_id: &[u8],
    required: &[RequiredFragment],
) -> PushSample {
    let captured = coordinator
        .capture_push_witness(repository_id)
        .await
        .expect("preflight witness capture must not error")
        .expect("the pushing repository must exist");
    let window_start = Instant::now();

    let mut push_client = pool.get().await.expect("checkout final-push connection");
    let tx = push_client
        .transaction()
        .await
        .expect("open final-push transaction");
    let mut sequence = LockSequence::new();
    sequence
        .enter(LockClass::Repository)
        .expect("repository is the final push's first class");
    tx.execute(
        "SELECT 1 FROM lore_domain_repositories WHERE repository_id = $1 FOR UPDATE",
        &[&repository_id],
    )
    .await
    .expect("final push locks its repository row");
    sequence
        .enter(LockClass::Branch)
        .expect("branch follows repository");
    tx.execute(
        "SELECT 1 FROM lore_domain_branches WHERE repository_id = $1 ORDER BY branch_id FOR UPDATE",
        &[&repository_id],
    )
    .await
    .expect("final push locks its branch rows");

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, repository_id, captured, required)
        .await
        .expect("revalidate_push_witness must not error");
    let window = window_start.elapsed();
    tx.commit()
        .await
        .expect("commit the final-push transaction");
    PushSample { verdict, window }
}

/// After an aborted push, how long until one commits on a first attempt again.
///
/// CR-031's remedy for a known-no-commit abort is "wait for a quiet scalar and
/// take a fresh fast-path preflight". This measures exactly that: repeat the
/// whole preflight-plus-final-transaction cycle until one returns something
/// other than `Aborted`, and report how long it took and how many attempts it
/// cost. Returns `None` if `budget` expires first, which is itself the answer.
async fn wait_for_a_first_attempt_commit(
    coordinator: &TestFragmentCoordinator,
    pool: &deadpool_postgres::Pool,
    repository_id: &[u8],
    required: &[RequiredFragment],
    budget: Duration,
) -> Option<(Duration, usize)> {
    let started = Instant::now();
    let mut attempts = 0usize;
    while started.elapsed() < budget {
        attempts += 1;
        let sample = run_final_push_transaction(coordinator, pool, repository_id, required).await;
        if !matches!(sample.verdict, PushWitnessVerdict::Aborted { .. }) {
            return Some((started.elapsed(), attempts));
        }
    }
    None
}

/// Publish `count` readable fragments, associate each with `repository_id`
/// under `context`, and return the exact required set a preflight would.
async fn required_set(
    coordinator: &TestFragmentCoordinator,
    repository_id: &[u8],
    context: &[u8],
    count: usize,
) -> Vec<RequiredFragment> {
    let mut hashes = Vec::with_capacity(count);
    for index in 0..count {
        let seed = u8::try_from(index % 200).expect("required-set seed fits in u8");
        let hash = publish_remote_fragment(coordinator, seed).await;
        assert_eq!(
            coordinator
                .create_association(&hash, repository_id, context)
                .await
                .expect("associate a required fragment"),
            CommitVerdict::Published
        );
        hashes.push(hash);
    }
    let resolved = coordinator
        .resolve(repository_id, context, &hashes)
        .await
        .expect("resolve the required set");
    resolved
        .iter()
        .map(|resolution| {
            let (witness, ..) = expect_readable(resolution);
            RequiredFragment {
                hash: resolution.hash.clone(),
                epoch: witness.epoch,
            }
        })
        .collect()
}

/// Publish and associate one uploader's own disjoint hash set.
async fn uploader_hash_set(
    coordinator: &TestFragmentCoordinator,
    repository_id: &[u8],
    context: &[u8],
) -> Vec<Vec<u8>> {
    let mut hashes = Vec::with_capacity(UPLOADER_HASHES_EACH);
    for index in 0..UPLOADER_HASHES_EACH {
        let seed = u8::try_from(index).expect("uploader seed fits in u8");
        let hash = publish_remote_fragment(coordinator, seed).await;
        assert_eq!(
            coordinator
                .create_association(&hash, repository_id, context)
                .await
                .expect("associate an uploader fragment"),
            CommitVerdict::Published
        );
        hashes.push(hash);
    }
    hashes
}

/// Three disjoint same-repository uploaders active for at least ten seconds,
/// 100 pushes whose required sets are at most
/// `MAX_PUSH_FRAGMENT_REVALIDATIONS` fragments, each committing on its
/// **first** final-transaction attempt with no fallback-induced `ABORTED`,
/// under a 30-second suite watchdog.
///
/// # This is NOT CR-031's `same_repo_bulk_upload_does_not_starve_branch_push`
///
/// That name is the CR's normative acceptance test, and it is deliberately
/// **not implemented**, because it is unsatisfiable against the frozen
/// contract: a real bulk upload creates associations, and the association arm
/// admits no fallback. Nothing in this file may wear that name while testing
/// something narrower. What stands in its place is
/// [`characterize_same_repo_association_traffic_push_aborts`], which runs the
/// literal scenario as a measurement of what the push path actually returns.
///
/// This case covers the neighbouring property that *is* satisfiable and that
/// nothing else pins: the bounded fallback carrying a push through sustained
/// same-repository **lifecycle** churn.
///
/// # What the uploader traffic deliberately is, and is not
///
/// The uploaders move the pushing repository's **lifecycle** scalar: they
/// publish fresh fragments and drive their own disjoint, already-associated
/// hashes readable to unreadable to readable. That is the exact contention the
/// bounded fallback was added for, and every push here must therefore reach
/// `Unchanged` or `FallbackSatisfied`.
///
/// They deliberately do **not** create new associations in the pushing
/// repository, and this case does not cover that traffic. `create_association`
/// and `create_association_if_current` both move
/// `content_association_generation`, and `classify_push_witness` gives
/// `AssociationMoved` precedence over `LifecycleOnly` and admits no fallback
/// for it (CR-031:258-267 grants the bounded fallback only for a changed
/// lifecycle scalar). A same-repository uploader that creates associations
/// therefore aborts a push whose preflight predates it, by contract rather than
/// by defect. Read this green as covering lifecycle-scalar contention only;
/// association-creating same-repository traffic is measured separately by
/// [`characterize_same_repo_association_traffic_push_aborts`], which is a
/// characterization rather than an acceptance case.
///
/// # Timing regime
///
/// This runs against a local disposable PostgreSQL with no object store, so it
/// is a different timing regime from production, not a scaled model of one.
/// Both sides move: with no provider I/O the uploader cycle is faster (more
/// scalar movement per second, harsher for the push), and the push's own
/// capture-to-revalidate window is also shorter (fewer chances to be
/// invalidated). Which effect dominates depends on the ratio between the two,
/// and **nobody has measured it** -- so do not read this tier as either
/// conservative or optimistic relative to a deployed cell. The case prints the
/// achieved uploader rate, both scalars' movement, the verdict distribution,
/// and the observed push window precisely so the regime a given run was
/// produced in is on the record instead of being described.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn same_repo_lifecycle_traffic_does_not_starve_branch_push() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store_with_pool(&url, 16).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;

    let push_context = random_context();
    let required = required_set(
        &coordinator,
        &repository_id,
        &push_context,
        PUSH_REQUIRED_FRAGMENTS,
    )
    .await;
    assert_eq!(required.len(), PUSH_REQUIRED_FRAGMENTS);
    assert!(
        required.len() <= MAX_PUSH_FRAGMENT_REVALIDATIONS,
        "CR-031's shape requires the push's required set to sit under the bound"
    );

    let labels = [
        "same-repo/uploader-a",
        "same-repo/uploader-b",
        "same-repo/uploader-c",
    ];
    let mut uploader_contexts = Vec::with_capacity(SUSTAINED_UPLOADER_COUNT);
    let mut uploader_hashes = Vec::with_capacity(SUSTAINED_UPLOADER_COUNT);
    for _ in 0..SUSTAINED_UPLOADER_COUNT {
        let context = random_context();
        let hashes = uploader_hash_set(&coordinator, &repository_id, &context).await;
        uploader_contexts.push(context);
        uploader_hashes.push(hashes);
    }

    let push_pool = build_pool(&url, 4, &TlsConfig::default()).expect("build final-push pool");
    let before = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness before the window")
        .expect("the pushing repository must exist");

    let deadline = Instant::now() + SUSTAINED_UPLOAD_WINDOW;
    let pushes = async {
        let mut verdicts = Vec::with_capacity(SUSTAINED_PUSH_COUNT);
        for _ in 0..SUSTAINED_PUSH_COUNT {
            verdicts.push(
                run_final_push_transaction(&coordinator, &push_pool, &repository_id, &required)
                    .await,
            );
            tokio::time::sleep(PUSH_INTERVAL).await;
        }
        verdicts
    };

    let (samples, tally_a, tally_b, tally_c) = timeout(SUSTAINED_SUITE_WATCHDOG, async {
        tokio::join!(
            pushes,
            run_sustained_uploader(
                &coordinator,
                &repository_id,
                &uploader_contexts[0],
                &uploader_hashes[0],
                labels[0],
                UploaderTraffic::LifecycleOnly,
                deadline,
            ),
            run_sustained_uploader(
                &coordinator,
                &repository_id,
                &uploader_contexts[1],
                &uploader_hashes[1],
                labels[1],
                UploaderTraffic::LifecycleOnly,
                deadline,
            ),
            run_sustained_uploader(
                &coordinator,
                &repository_id,
                &uploader_contexts[2],
                &uploader_hashes[2],
                labels[2],
                UploaderTraffic::LifecycleOnly,
                deadline,
            ),
        )
    })
    .await
    .expect("the sustained same-repository suite must finish inside its 30s watchdog");

    let after = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness after the window")
        .expect("the pushing repository must exist");
    let tallies = [tally_a, tally_b, tally_c];
    let association_moves =
        after.content_association_generation - before.content_association_generation;
    let lifecycle_moves =
        after.fragment_lifecycle_generation - before.fragment_lifecycle_generation;

    // The regime this evidence was produced in, printed before any assertion
    // can abort the run. A run where the scalars barely moved never exercised
    // the contention this case claims to, and that must be visible in the
    // numbers rather than inferred from a green tick.
    println!(
        "WP118-P7-SAME-REPO regime uploader_traffic=LifecycleOnly window_s={} \
         association_moves={association_moves} lifecycle_moves={lifecycle_moves}",
        SUSTAINED_UPLOAD_WINDOW.as_secs()
    );
    let mut total_publications = 0usize;
    for tally in &tallies {
        total_publications += tally.publications;
        println!(
            "WP118-P7-SAME-REPO uploader label={} publications={} publications_per_s={:.1} \
             transitions={} associations={} elapsed_ms={}",
            tally.label,
            tally.publications,
            tally.publications_per_second(),
            tally.transitions,
            tally.associations,
            tally.elapsed.as_millis()
        );
    }
    println!(
        "WP118-P7-SAME-REPO uploaders_total publications={total_publications} \
         publications_per_s={:.1}",
        total_publications as f64 / SUSTAINED_UPLOAD_WINDOW.as_secs_f64()
    );
    println!("WP118-P7-SAME-REPO {}", summarize_pushes(&samples));

    // The traffic must have been real. Without these the whole case could pass
    // vacuously on an all-`Unchanged` run against idle uploaders.
    for tally in &tallies {
        assert!(
            tally.transitions >= 2,
            "{} must have completed real readability transitions inside the window, got {}",
            tally.label,
            tally.transitions
        );
    }
    assert!(
        lifecycle_moves > 0,
        "the pushing repository's lifecycle scalar must actually have moved during the window; \
         at zero movement this case proves nothing about the bounded fallback however green it is"
    );
    assert_eq!(
        association_moves, 0,
        "no uploader creates or retires an association under LifecycleOnly traffic, so the \
         association scalar must be exactly where it started -- if this moves, the case is \
         measuring different traffic than its doc comment claims"
    );
    assert_eq!(
        lifecycle_moves,
        i64::try_from(tallies.iter().map(|tally| tally.transitions).sum::<usize>())
            .expect("transition count fits in i64"),
        "every uploader transition is a readability crossing on a fragment associated with the \
         pushing repository, so each must move its lifecycle scalar exactly once"
    );

    assert_eq!(samples.len(), SUSTAINED_PUSH_COUNT);
    let aborted: Vec<&PushWitnessVerdict> = samples
        .iter()
        .map(|sample| &sample.verdict)
        .filter(|verdict| matches!(verdict, PushWitnessVerdict::Aborted { .. }))
        .collect();
    assert!(
        aborted.is_empty(),
        "CR-031 requires all {SUSTAINED_PUSH_COUNT} pushes to commit on the first \
         final-transaction attempt with no fallback-induced ABORTED; {} aborted: {aborted:?}",
        aborted.len()
    );
    let fallbacks = samples
        .iter()
        .filter(|sample| matches!(sample.verdict, PushWitnessVerdict::FallbackSatisfied { .. }))
        .count();
    assert!(
        fallbacks >= 1,
        "at least one push must have raced a lifecycle bump into its own preflight window and \
         been carried by the bounded fallback; {SUSTAINED_PUSH_COUNT} `Unchanged` verdicts would \
         mean this case never exercised the fallback at all"
    );
    for sample in &samples {
        if let PushWitnessVerdict::FallbackSatisfied { revalidated } = &sample.verdict {
            assert_eq!(
                *revalidated, PUSH_REQUIRED_FRAGMENTS,
                "the fallback must revalidate the exact required set, no subset"
            );
        }
    }
}

/// CR-031's `cross_repo_bulk_upload_does_not_abort_unrelated_push`: the same
/// sustained shape with the three uploaders in *different* repositories from
/// the pushing one.
///
/// Every push must reach the **unchanged fast path** (`Unchanged`, meaning no
/// fragment row is read at all). This is the case the 2026-08-29 probe measured
/// at the uncontended floor; this pins that it stays there rather than
/// re-measuring latency.
///
/// The timing-regime caveat on
/// [`same_repo_lifecycle_traffic_does_not_starve_branch_push`] applies here too: this
/// is a different regime from production in both directions at once, and which
/// dominates is unmeasured. The printed rate, scalar movement, verdict
/// distribution, and push window record the regime this run was produced in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn cross_repo_bulk_upload_does_not_abort_unrelated_push() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store_with_pool(&url, 16).await;
    let coordinator = store.fragment_coordinator();
    let pushing_repository = create_repository(&store).await;

    let push_context = random_context();
    let required = required_set(
        &coordinator,
        &pushing_repository,
        &push_context,
        PUSH_REQUIRED_FRAGMENTS,
    )
    .await;

    let labels = [
        "cross-repo/uploader-a",
        "cross-repo/uploader-b",
        "cross-repo/uploader-c",
    ];
    let mut uploader_repositories = Vec::with_capacity(SUSTAINED_UPLOADER_COUNT);
    let mut uploader_contexts = Vec::with_capacity(SUSTAINED_UPLOADER_COUNT);
    let mut uploader_hashes = Vec::with_capacity(SUSTAINED_UPLOADER_COUNT);
    for _ in 0..SUSTAINED_UPLOADER_COUNT {
        let repository = create_repository(&store).await;
        let context = random_context();
        let hashes = uploader_hash_set(&coordinator, &repository, &context).await;
        uploader_repositories.push(repository);
        uploader_contexts.push(context);
        uploader_hashes.push(hashes);
    }

    let push_pool = build_pool(&url, 4, &TlsConfig::default()).expect("build final-push pool");
    let before = coordinator
        .capture_push_witness(&pushing_repository)
        .await
        .expect("capture witness before the window")
        .expect("the pushing repository must exist");
    let mut uploader_before = Vec::with_capacity(SUSTAINED_UPLOADER_COUNT);
    for repository in &uploader_repositories {
        uploader_before.push(
            coordinator
                .capture_push_witness(repository)
                .await
                .expect("capture uploader witness before")
                .expect("an uploader repository must exist"),
        );
    }

    let deadline = Instant::now() + SUSTAINED_UPLOAD_WINDOW;
    let pushes = async {
        let mut verdicts = Vec::with_capacity(SUSTAINED_PUSH_COUNT);
        for _ in 0..SUSTAINED_PUSH_COUNT {
            verdicts.push(
                run_final_push_transaction(
                    &coordinator,
                    &push_pool,
                    &pushing_repository,
                    &required,
                )
                .await,
            );
            tokio::time::sleep(PUSH_INTERVAL).await;
        }
        verdicts
    };

    let (samples, tally_a, tally_b, tally_c) = timeout(SUSTAINED_SUITE_WATCHDOG, async {
        tokio::join!(
            pushes,
            run_sustained_uploader(
                &coordinator,
                &uploader_repositories[0],
                &uploader_contexts[0],
                &uploader_hashes[0],
                labels[0],
                UploaderTraffic::LifecycleOnly,
                deadline,
            ),
            run_sustained_uploader(
                &coordinator,
                &uploader_repositories[1],
                &uploader_contexts[1],
                &uploader_hashes[1],
                labels[1],
                UploaderTraffic::LifecycleOnly,
                deadline,
            ),
            run_sustained_uploader(
                &coordinator,
                &uploader_repositories[2],
                &uploader_contexts[2],
                &uploader_hashes[2],
                labels[2],
                UploaderTraffic::LifecycleOnly,
                deadline,
            ),
        )
    })
    .await
    .expect("the sustained cross-repository suite must finish inside its 30s watchdog");

    let after = coordinator
        .capture_push_witness(&pushing_repository)
        .await
        .expect("capture witness after the window")
        .expect("the pushing repository must exist");
    let tallies = [tally_a, tally_b, tally_c];

    // The regime, printed before any assertion can abort the run.
    println!(
        "WP118-P7-CROSS-REPO regime uploader_traffic=LifecycleOnly window_s={} \
         pushing_repo_association_moves={} pushing_repo_lifecycle_moves={}",
        SUSTAINED_UPLOAD_WINDOW.as_secs(),
        after.content_association_generation - before.content_association_generation,
        after.fragment_lifecycle_generation - before.fragment_lifecycle_generation
    );
    let mut total_publications = 0usize;
    let mut uploader_after = Vec::with_capacity(SUSTAINED_UPLOADER_COUNT);
    for (index, tally) in tallies.iter().enumerate() {
        total_publications += tally.publications;
        let observed = coordinator
            .capture_push_witness(&uploader_repositories[index])
            .await
            .expect("capture uploader witness after")
            .expect("an uploader repository must exist");
        println!(
            "WP118-P7-CROSS-REPO uploader label={} publications={} publications_per_s={:.1} \
             transitions={} own_association_moves={} own_lifecycle_moves={} elapsed_ms={}",
            tally.label,
            tally.publications,
            tally.publications_per_second(),
            tally.transitions,
            observed.content_association_generation
                - uploader_before[index].content_association_generation,
            observed.fragment_lifecycle_generation
                - uploader_before[index].fragment_lifecycle_generation,
            tally.elapsed.as_millis()
        );
        uploader_after.push(observed);
    }
    println!(
        "WP118-P7-CROSS-REPO uploaders_total publications={total_publications} \
         publications_per_s={:.1}",
        total_publications as f64 / SUSTAINED_UPLOAD_WINDOW.as_secs_f64()
    );
    println!("WP118-P7-CROSS-REPO {}", summarize_pushes(&samples));

    // The named property first, so a break to per-repository isolation fails
    // on the claim this case exists to make rather than on a support check.
    assert_eq!(
        after, before,
        "cross-repository upload traffic must move neither of the pushing repository's scalars"
    );

    assert_eq!(samples.len(), SUSTAINED_PUSH_COUNT);
    for sample in &samples {
        assert_eq!(
            sample.verdict,
            PushWitnessVerdict::Unchanged,
            "every cross-repository push must reach the unchanged fast path, reading no fragment \
             row at all"
        );
    }

    // Support: the uploaders were real, and each one's own repository absorbed
    // exactly its own transitions. Without this the stillness above could be
    // the stillness of an idle cell.
    for (index, tally) in tallies.iter().enumerate() {
        assert!(
            tally.transitions >= 2,
            "{} must have completed real readability transitions inside the window, got {}",
            tally.label,
            tally.transitions
        );
        assert_eq!(
            uploader_after[index].fragment_lifecycle_generation
                - uploader_before[index].fragment_lifecycle_generation,
            i64::try_from(tally.transitions).expect("transition count fits in i64"),
            "{}'s own repository must absorb every one of its transitions",
            tally.label
        );
    }
}

/// Fanout sizes the cost characterization measures. The largest is the
/// admission bound itself, so the table covers the whole admissible range.
const FANOUT_MEASUREMENT_SIZES: [usize; 4] = [1, 64, 512, MAX_LIFECYCLE_GENERATION_FANOUT];

/// A deliberately generous liveness bound, not a performance gate.
///
/// The only failure this can express is "the operation did not finish", which
/// is the no-deadlock claim the measurement makes. It sits far above any
/// plausible honest duration for one bounded transaction against a local
/// disposable PostgreSQL, so a slow rig, a cold cache, or a busy Docker host
/// cannot turn a measurement into a flake. Do not tighten it into a threshold:
/// the numbers this case prints are the output, and no assertion here claims
/// any particular one of them.
const FANOUT_LIVENESS_BOUND: Duration = Duration::from_secs(120);

/// Count the live association rows for one exact `(hash, repository, context)`,
/// read directly rather than inferred from a `CommitVerdict`.
///
/// A `Published` verdict is the coordinator's own account of what it did. A
/// generation bump that was not atomic with the row it is supposed to accompany
/// would still satisfy every scalar assertion, so the row itself has to be
/// looked at.
async fn live_association_rows(
    direct: &Client,
    hash: &[u8],
    repository_id: &[u8],
    context: &[u8],
) -> i64 {
    direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_associations \
              WHERE hash = $1 AND repository_id = $2 AND context = $3 AND state = $4",
            &[&hash, &repository_id, &context, &schema::ASSOCIATION_LIVE],
        )
        .await
        .expect("count live association rows")
        .get(0)
}

/// Count the live associations a lifecycle transition on `hash` fans out to,
/// read independently of the coordinator's own planning query.
async fn live_fanout_rows(direct: &Client, hash: &[u8]) -> i64 {
    direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_associations \
              WHERE hash = $1 AND state = $2",
            &[&hash, &schema::ASSOCIATION_LIVE],
        )
        .await
        .expect("count the live fanout")
        .get(0)
}

/// CR-031's shared-hash fanout **cost characterization**. This is a
/// measurement, not a pass/fail threshold.
///
/// For increasing fanout sizes N it reports, for a hash live-associated with N
/// repositories:
///
/// * a readable-to-unreadable transition (`mark_missing`), which plans, locks,
///   and *writes* all N repository rows;
/// * a `Staged`-to-`Remote` promotion (`commit_promotion`), which crosses no
///   readability boundary and therefore writes none of them, yet still plans
///   and locks the full fanout unconditionally in `commit_publication`. That is
///   WP-118's deferred **P2-7**: N row locks it never uses. This case exists to
///   measure what those locks cost.
///
/// The only assertions are a generous liveness bound (see
/// [`FANOUT_LIVENESS_BOUND`]), the expected verdict, the fanout width read
/// independently of the coordinator, and the generation movement that proves
/// each measured call did the work its timing is attributed to. No timing
/// threshold is asserted, because none has been derived from anything.
///
/// # Explicitly out of scope
///
/// This measures **the cost at a given N**. It does **not** measure real
/// shared-hash *distribution* -- how large N actually gets in production. That
/// needs a real staging cell and is guarded-stopped. `coordinator.rs`'s
/// `MAX_LIFECYCLE_GENERATION_FANOUT` already records that its value "is a
/// bound, not a measurement" and that staging measurement should replace it.
/// Nothing here replaces it, and a green run of this case must not be read as
/// having done so.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn shared_hash_fanout_transition_and_promotion_cost_is_measured_at_increasing_fanout() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store_with_pool(&url, 8).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let context = random_context();

    let largest = FANOUT_MEASUREMENT_SIZES
        .iter()
        .copied()
        .max()
        .expect("the measurement table is non-empty");

    let repository_setup_start = Instant::now();
    let mut repositories = Vec::with_capacity(largest);
    for _ in 0..largest {
        repositories.push(create_repository(&store).await);
    }
    let repository_setup_ms = repository_setup_start.elapsed().as_millis();

    println!("WP118-P7-FANOUT setup repositories={largest} elapsed_ms={repository_setup_ms}");
    println!(
        "WP118-P7-FANOUT | n | transition_ms | promotion_ms | association_setup_ms | \
         transition_scalar_delta | promotion_scalar_delta"
    );

    for size in FANOUT_MEASUREMENT_SIZES {
        let sampled = [0usize, size - 1];
        let association_start = Instant::now();

        let transition_hash = publish_remote_fragment(&coordinator, 0x30).await;
        let promotion_hash = random_hash();
        let BeginOutcome::Admitted(stage_intent) = coordinator
            .begin_stage(&promotion_hash)
            .await
            .expect("begin the promotion fixture's stage")
        else {
            panic!("a fresh hash must admit a stage begin");
        };
        assert_eq!(
            coordinator
                .commit_staged(
                    &stage_intent,
                    IoObservation::Valid(manifest(
                        &staged_key(&promotion_hash, stage_intent.epoch),
                        0x31,
                        EpochAuthority::Staged,
                    )),
                )
                .await
                .expect("commit the promotion fixture's staged epoch"),
            CommitVerdict::Published
        );

        for repository_id in &repositories[..size] {
            for hash in [&transition_hash, &promotion_hash] {
                assert_eq!(
                    coordinator
                        .create_association(hash, repository_id, &context)
                        .await
                        .expect("associate a fanout fixture"),
                    CommitVerdict::Published
                );
            }
        }
        let association_setup_ms = association_start.elapsed().as_millis();

        for hash in [&transition_hash, &promotion_hash] {
            assert_eq!(
                live_fanout_rows(&direct, hash).await,
                i64::try_from(size).expect("fanout size fits in i64"),
                "the measured fanout must actually be N rows wide"
            );
        }

        // --- readable -> unreadable, which writes all N repository rows ---
        let resolved = coordinator
            .resolve(
                &repositories[0],
                &context,
                std::slice::from_ref(&transition_hash),
            )
            .await
            .expect("resolve the transition fixture");
        let (witness, ..) = expect_readable(&resolved[0]);
        let witness = witness.clone();

        let mut transition_before = Vec::with_capacity(sampled.len());
        for index in sampled {
            transition_before.push(
                coordinator
                    .capture_push_witness(&repositories[index])
                    .await
                    .expect("capture a sampled witness")
                    .expect("a fanout repository must exist"),
            );
        }
        let transition_start = Instant::now();
        let transition_verdict = timeout(
            FANOUT_LIVENESS_BOUND,
            coordinator.mark_missing(&witness, MissingDiagnostic::Absent),
        )
        .await
        .expect("a readable-to-unreadable transition must not deadlock")
        .expect("mark_missing must not error");
        let transition_ms = transition_start.elapsed().as_millis();
        assert_eq!(transition_verdict, CommitVerdict::Published);

        let mut transition_delta = 0i64;
        for (offset, index) in sampled.iter().copied().enumerate() {
            let after = coordinator
                .capture_push_witness(&repositories[index])
                .await
                .expect("capture a sampled witness")
                .expect("a fanout repository must exist");
            transition_delta = after.fragment_lifecycle_generation
                - transition_before[offset].fragment_lifecycle_generation;
            assert_eq!(
                transition_delta, 1,
                "a readability crossing must move every repository in the fanout exactly once, \
                 so the timing above is the cost of real work"
            );
        }

        // --- Staged -> Remote, which crosses nothing and writes none of them ---
        let BeginOutcome::Admitted(promotion_intent) = coordinator
            .begin_promotion(&promotion_hash)
            .await
            .expect("begin the promotion")
        else {
            panic!("a Staged head must admit begin_promotion");
        };
        let mut promotion_before = Vec::with_capacity(sampled.len());
        for index in sampled {
            promotion_before.push(
                coordinator
                    .capture_push_witness(&repositories[index])
                    .await
                    .expect("capture a sampled witness")
                    .expect("a fanout repository must exist"),
            );
        }
        let promotion_start = Instant::now();
        let promotion_verdict = timeout(
            FANOUT_LIVENESS_BOUND,
            coordinator.commit_promotion(
                &promotion_intent,
                IoObservation::Valid(manifest(
                    &legacy_key(&promotion_hash),
                    0x32,
                    EpochAuthority::Remote,
                )),
            ),
        )
        .await
        .expect("a non-crossing promotion must not deadlock")
        .expect("commit_promotion must not error");
        let promotion_ms = promotion_start.elapsed().as_millis();
        assert_eq!(promotion_verdict, CommitVerdict::Published);

        let mut promotion_delta = 0i64;
        for (offset, index) in sampled.iter().copied().enumerate() {
            let after = coordinator
                .capture_push_witness(&repositories[index])
                .await
                .expect("capture a sampled witness")
                .expect("a fanout repository must exist");
            promotion_delta = after.fragment_lifecycle_generation
                - promotion_before[offset].fragment_lifecycle_generation;
            assert_eq!(
                promotion_delta, 0,
                "a Staged-to-Remote promotion crosses no readability boundary, so it must write \
                 no lifecycle scalar -- the whole point of P2-7 is that it locks the fanout it \
                 does not write"
            );
        }

        println!(
            "WP118-P7-FANOUT | {size} | {transition_ms} | {promotion_ms} | \
             {association_setup_ms} | {transition_delta} | {promotion_delta}"
        );
    }
}

/// CR-031 requires create, **copy**, and tombstone to increment
/// `content_association_generation`. Create and tombstone are each already
/// pinned by a case that reads the scalar; the copy path
/// (`create_association_if_current`, reached from the immutable store's
/// already-readable publication and copy-on-write paths) had cases asserting
/// only its verdicts, so its `bump_association_generation` call was unpinned.
///
/// This closes that gap in both directions: an admitted copy moves the
/// association scalar exactly once and the lifecycle scalar not at all, and a
/// fenced copy moves neither.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn create_association_if_current_bumps_the_association_generation_on_every_admitted_copy() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let source_context = random_context();
    let copy_context = random_context();
    let fenced_context = random_context();

    let hash = publish_remote_fragment(&coordinator, 0x70).await;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &source_context)
            .await
            .expect("associate the source context"),
        CommitVerdict::Published
    );

    let resolved = coordinator
        .resolve(&repository_id, &source_context, std::slice::from_ref(&hash))
        .await
        .expect("resolve the readable witness");
    let (witness, ..) = expect_readable(&resolved[0]);
    let witness = witness.clone();

    let before = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture before the copy")
        .expect("the repository must exist");

    assert_eq!(
        coordinator
            .create_association_if_current(&witness, &repository_id, &copy_context)
            .await
            .expect("guarded copy association"),
        CommitVerdict::Published
    );

    let after_copy = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture after the copy")
        .expect("the repository must exist");
    assert_eq!(
        after_copy.content_association_generation,
        before.content_association_generation + 1,
        "the copy path must move the association scalar exactly once, atomically with its insert \
         -- CR-031 requires create, copy, and tombstone to increment it alike"
    );
    assert_eq!(
        after_copy.fragment_lifecycle_generation, before.fragment_lifecycle_generation,
        "a copy crosses no readability boundary and must move no lifecycle scalar"
    );
    assert_eq!(
        live_association_rows(&direct, &hash, &repository_id, &copy_context).await,
        1,
        "the scalar bump must be accompanied by the association row it is atomic with"
    );

    // A replayed copy into the *same* context still moves the scalar. The
    // insert is `ON CONFLICT ... DO UPDATE`, and the bump is unconditional, so
    // a retried copy-on-write publication re-arms every concurrent push's
    // witness. That direction is the safe one -- a spurious bump costs a
    // conservative abort, a missed one would let a push commit against a
    // membership change it never revalidated -- so pin it, or a later
    // "optimisation" that skips the bump when the row already existed would
    // land silently.
    assert_eq!(
        coordinator
            .create_association_if_current(&witness, &repository_id, &copy_context)
            .await
            .expect("replayed guarded copy association"),
        CommitVerdict::Published
    );
    let after_replay = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture after the replayed copy")
        .expect("the repository must exist");
    assert_eq!(
        after_replay.content_association_generation,
        after_copy.content_association_generation + 1,
        "a replayed copy is still an association write and must move the scalar again"
    );
    assert_eq!(
        live_association_rows(&direct, &hash, &repository_id, &copy_context).await,
        1,
        "the replay upserts the existing row rather than adding a second one"
    );

    // A stale witness is refused. Deliberately NOT paired with a
    // scalar-unchanged assertion: the fenced arm returns before `tx.commit()`,
    // so the transaction rolls back and *no* implementation of this shape could
    // move the scalar here. Such an assertion would pass against every possible
    // body and prove nothing (INV-EF P2-11). The residue proof that does
    // discriminate already lives in
    // `guarded_association_requires_the_exact_readable_witness`.
    let mut stale = witness.clone();
    stale.fence += 1;
    assert_eq!(
        coordinator
            .create_association_if_current(&stale, &repository_id, &fenced_context)
            .await
            .expect("stale guarded copy association"),
        CommitVerdict::Fenced
    );
}

/// Budget for the post-abort recovery measurement. Generous: the number it
/// produces is the output, and running out is itself a reportable answer.
const QUIET_SCALAR_WAIT_BUDGET: Duration = Duration::from_secs(20);

/// **Characterization, not acceptance.** CR-031's literal
/// `same_repo_bulk_upload_does_not_starve_branch_push` shape -- three
/// same-repository uploaders doing what a real bulk upload does, which includes
/// creating associations -- and a measurement of what the push path actually
/// returns under it.
///
/// This case exists because that literal shape is unsatisfiable against the
/// frozen contract, and an owner deciding between amending the test spec and
/// narrowing the association check needs measured evidence rather than an
/// argument. The chain, all verified in source:
///
/// * a real upload ends in `create_association` (`store/immutable_store.rs`) or
///   `create_association_if_current`, and both call
///   `bump_association_generation` unconditionally;
/// * that moves `content_association_generation` on the uploaded-into
///   repository;
/// * `classify_push_witness` returns `AssociationMoved`, which outranks
///   `LifecycleOnly` and returns `Aborted { required_fragment_changed }` with no
///   fallback -- CR-031's F-031-3 grants the bounded fallback only for a changed
///   *lifecycle* scalar.
///
/// So a same-repository push racing genuine upload traffic aborts, while
/// CR-031's own acceptance text requires zero fallback-induced `ABORTED` under
/// exactly that traffic. The over-strictness *is* the starvation the CR says
/// must not happen.
///
/// **The precedence is deliberate and is not a defect to fix from here.**
/// `revalidate_push_witness`'s own comment records that association precedence
/// is what keeps obliterate-then-recreate out of reach of the
/// semantically-equivalent-epoch allowance. Loosening it is a frozen-contract
/// decision with a real safety rationale behind it, and it belongs to the CR's
/// owner.
///
/// # What is asserted, and what is only reported
///
/// The only assertion is that **at least one** push aborted with exactly
/// `REQUIRED_FRAGMENT_CHANGED`. That cannot flake upward: the mechanism is
/// deterministic given any association bump inside any push's window, and the
/// case fails loudly if the traffic never got going. Everything else -- the
/// abort rate, how many pushes commit first-attempt, and how long a push must
/// wait for a quiet association scalar -- is printed, not asserted, because a
/// rate measured on this rig is a property of this rig's timing regime.
///
/// The timing-regime caveat on
/// [`same_repo_lifecycle_traffic_does_not_starve_branch_push`] applies in full: with
/// no object-store latency the uploaders cycle faster *and* the push window is
/// shorter, the two push the abort rate in opposite directions, and which one
/// dominates has not been measured. Do not read the printed rate as a
/// production estimate in either direction.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn characterize_same_repo_association_traffic_push_aborts() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store_with_pool(&url, 16).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;

    let push_context = random_context();
    let required = required_set(
        &coordinator,
        &repository_id,
        &push_context,
        PUSH_REQUIRED_FRAGMENTS,
    )
    .await;

    let labels = [
        "assoc-characterization/uploader-a",
        "assoc-characterization/uploader-b",
        "assoc-characterization/uploader-c",
    ];
    let mut uploader_contexts = Vec::with_capacity(SUSTAINED_UPLOADER_COUNT);
    for _ in 0..SUSTAINED_UPLOADER_COUNT {
        uploader_contexts.push(random_context());
    }
    // PublishAndAssociate needs no pre-seeded hash set: every iteration mints a
    // fresh hash and associates it, which is exactly a bulk upload of new
    // content. One placeholder entry drives the loop.
    let placeholder = vec![random_hash()];

    let push_pool = build_pool(&url, 4, &TlsConfig::default()).expect("build final-push pool");
    let before = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness before the window")
        .expect("the pushing repository must exist");

    let deadline = Instant::now() + SUSTAINED_UPLOAD_WINDOW;
    let pushes = async {
        let mut samples = Vec::with_capacity(SUSTAINED_PUSH_COUNT);
        for _ in 0..SUSTAINED_PUSH_COUNT {
            samples.push(
                run_final_push_transaction(&coordinator, &push_pool, &repository_id, &required)
                    .await,
            );
            tokio::time::sleep(PUSH_INTERVAL).await;
        }
        samples
    };

    let (samples, tally_a, tally_b, tally_c) = timeout(SUSTAINED_SUITE_WATCHDOG, async {
        tokio::join!(
            pushes,
            run_sustained_uploader(
                &coordinator,
                &repository_id,
                &uploader_contexts[0],
                &placeholder,
                labels[0],
                UploaderTraffic::PublishAndAssociate,
                deadline,
            ),
            run_sustained_uploader(
                &coordinator,
                &repository_id,
                &uploader_contexts[1],
                &placeholder,
                labels[1],
                UploaderTraffic::PublishAndAssociate,
                deadline,
            ),
            run_sustained_uploader(
                &coordinator,
                &repository_id,
                &uploader_contexts[2],
                &placeholder,
                labels[2],
                UploaderTraffic::PublishAndAssociate,
                deadline,
            ),
        )
    })
    .await
    .expect("the association-traffic characterization must finish inside its 30s watchdog");

    let after = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness after the window")
        .expect("the pushing repository must exist");
    let tallies = [tally_a, tally_b, tally_c];
    let association_moves =
        after.content_association_generation - before.content_association_generation;
    let lifecycle_moves =
        after.fragment_lifecycle_generation - before.fragment_lifecycle_generation;

    println!(
        "WP118-P7-ASSOC-CHAR regime uploader_traffic=PublishAndAssociate window_s={} \
         association_moves={association_moves} lifecycle_moves={lifecycle_moves}",
        SUSTAINED_UPLOAD_WINDOW.as_secs()
    );
    let mut total_publications = 0usize;
    for tally in &tallies {
        total_publications += tally.publications;
        println!(
            "WP118-P7-ASSOC-CHAR uploader label={} publications={} publications_per_s={:.1} \
             associations={} elapsed_ms={}",
            tally.label,
            tally.publications,
            tally.publications_per_second(),
            tally.associations,
            tally.elapsed.as_millis()
        );
    }
    println!(
        "WP118-P7-ASSOC-CHAR uploaders_total publications={total_publications} \
         publications_per_s={:.1}",
        total_publications as f64 / SUSTAINED_UPLOAD_WINDOW.as_secs_f64()
    );
    println!("WP118-P7-ASSOC-CHAR {}", summarize_pushes(&samples));

    // Attribution note, because this filter does NOT by itself prove which arm
    // fired. `REQUIRED_FRAGMENT_CHANGED` is emitted by five arms of
    // `revalidate_push_witness` (`coordinator.rs:3129`, `:3148`, `:3211`,
    // `:3217`, `:3230`) -- an absent repository row, the association-moved
    // precedence, a required fragment whose row vanished, one that is no longer
    // readable, and a non-equivalent epoch. The attribution to the
    // association arm is INDIRECT and rests on the two assertions below:
    // `lifecycle_moves == 0` rules out every readability-driven arm (no
    // fragment this repository is associated with crossed the boundary, and
    // the required set is never touched by the uploaders), and the repository
    // demonstrably exists. Do not read this filter as direct proof of the arm.
    let aborted = samples
        .iter()
        .filter(|sample| {
            matches!(
                &sample.verdict,
                PushWitnessVerdict::Aborted { reason } if *reason == REQUIRED_FRAGMENT_CHANGED
            )
        })
        .count();
    let committed = samples.len() - aborted;
    println!(
        "WP118-P7-ASSOC-CHAR outcome aborted={aborted}/{} first_attempt_commits={committed}",
        samples.len()
    );

    // With the uploaders now stopped the association scalar is quiet, so this
    // measures CR-031's own stated remedy for a known-no-commit abort: wait for
    // a quiet scalar and take a fresh preflight.
    match wait_for_a_first_attempt_commit(
        &coordinator,
        &push_pool,
        &repository_id,
        &required,
        QUIET_SCALAR_WAIT_BUDGET,
    )
    .await
    {
        Some((waited, attempts)) => println!(
            "WP118-P7-ASSOC-CHAR quiet_scalar_recovery attempts={attempts} waited_us={} \
             (uploaders stopped)",
            waited.as_micros()
        ),
        None => println!(
            "WP118-P7-ASSOC-CHAR quiet_scalar_recovery NONE within budget_s={} (uploaders stopped)",
            QUIET_SCALAR_WAIT_BUDGET.as_secs()
        ),
    }

    // The traffic must have been real, or the measurement above is of nothing.
    for tally in &tallies {
        assert!(
            tally.associations >= 2,
            "{} must have completed real associating publications inside the window, got {}",
            tally.label,
            tally.associations
        );
    }
    assert_eq!(
        association_moves,
        i64::try_from(
            tallies
                .iter()
                .map(|tally| tally.associations)
                .sum::<usize>()
        )
        .expect("association count fits in i64"),
        "each associating publication moves the repository's association scalar exactly once"
    );
    assert_eq!(
        lifecycle_moves, 0,
        "PublishAndAssociate traffic publishes fresh hashes that are readable before they are \
         associated, so it crosses no readability boundary for this repository -- a nonzero \
         lifecycle movement would mean this case is measuring mixed traffic and its attribution \
         of the aborts to the association scalar would not hold"
    );

    // Non-vacuity pin, and it is load-bearing rather than decorative. Under
    // the current contract an association-moved witness NEVER reaches the
    // bounded fallback, so the fallback count must be zero. Without this,
    // loosening the association precedence -- the exact change this case exists
    // to inform -- would turn most of these aborts into `FallbackSatisfied`
    // while leaving a handful of aborts from other causes, and the case would
    // survive the very change it was written to characterize.
    assert_eq!(
        samples
            .iter()
            .filter(|sample| matches!(sample.verdict, PushWitnessVerdict::FallbackSatisfied { .. }))
            .count(),
        0,
        "an association-moved witness must never reach the bounded fallback under the current \
         contract; a nonzero count here means the precedence changed and this characterization \
         is stale, not passing"
    );

    // The finding itself. Given any association bump landing inside any of 100
    // push windows this is deterministic; if it ever fails, either the traffic
    // stopped or the association precedence changed, and both are things the
    // owner needs to know.
    assert!(
        aborted >= 1,
        "the association-precedence starvation must be observable: with {association_moves} \
         association bumps against {} pushes, at least one push must have aborted with \
         `{REQUIRED_FRAGMENT_CHANGED}`. Zero aborts means either the uploaders never contended \
         or the contract changed",
        samples.len()
    );
}

// ---------------------------------------------------------------------------
// WP-118 backfill cursor (`advance_backfill_cursor`)
//
// **These cases are not Phase 8.** Phase 8 is WP-118's rollout gate and it
// remains stopped on a real staging cell. `advance_backfill_cursor` exists
// because WP-109's Phase 2 races include a schema backfill and WP-118's path
// had no code a deterministic barrier could sit inside; it moves a cursor and a
// counter on one singleton row and nothing else. A live `backfill_state` of
// `BACKFILL_RUNNING` means this cursor moved. It does **not** mean a backfill
// ran, and nothing below should be read as evidence that one did.
// ---------------------------------------------------------------------------

/// The legacy CR-007 key space the cursor reads. `store/immutable_store.rs`
/// owns and self-bootstraps these tables in production; a coordinator-only
/// fixture has never constructed them, which is exactly the absence the
/// cursor's `to_regclass` probe exists to classify.
const BACKFILL_LEGACY_SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS lore_fragments (
    hash       bytea NOT NULL,
    repository bytea NOT NULL,
    context    bytea NOT NULL,
    PRIMARY KEY (hash, repository, context)
);
CREATE TABLE IF NOT EXISTS lore_fragment_state (
    hash  bytea  NOT NULL PRIMARY KEY,
    state bigint NOT NULL CHECK (state IN (0, 1, 256, 512))
);
CREATE TABLE IF NOT EXISTS lore_fragment_metering (
    hash          bytea  NOT NULL PRIMARY KEY,
    payload_flags bigint NOT NULL CHECK (payload_flags >= 0 AND payload_flags <= 4294967295),
    size_payload bigint NOT NULL CHECK (size_payload >= 0),
    size_content bigint NOT NULL CHECK (size_content >= 0)
);
";

/// Every relation whose contents must be unchanged by a cursor advance, plus
/// the one relation that may change.
///
/// `lore_domain_schema_state` is here for a specific reason and must not be
/// dropped as an unrelated table. It is WP-116's singleton, and
/// `domain/backfill.rs` writes an almost identical statement against it --
/// `UPDATE ... SET backfill_state = $1 ... WHERE id = 1 AND backfill_state IN
/// ($3, $1)` -- over columns of the same names. Two near-identical singletons
/// carrying two near-identical statements is exactly the shape a copy-paste
/// onto the wrong table takes, and a "nothing else changed" assertion that
/// omits the nearest miss cannot see the one defect it most needs to.
///
/// It is listed ahead of `lore_fragment_schema_state` deliberately: the
/// comparison loop below reports the first relation that moved, so a
/// mistargeted write names `lore_domain_schema_state` rather than failing on
/// the intended row having stayed still.
const BACKFILL_WATCHED_RELATIONS: [&str; 14] = [
    "lore_fragment_lifecycle",
    "lore_fragment_epochs",
    "lore_fragment_associations",
    "lore_fragment_lifecycle_metering",
    "lore_fragment_write_claims",
    "lore_fragment_staged_leases",
    "lore_fragment_staged_lease_members",
    "lore_domain_repositories",
    "lore_domain_branches",
    "lore_domain_schema_state",
    "lore_fragments",
    "lore_fragment_state",
    "lore_fragment_metering",
    "lore_fragment_schema_state",
];

/// One digest per watched relation, over every row rendered as text.
///
/// `t::text` renders every column including timestamps, so any write to any row
/// of any watched relation moves that relation's digest. `ORDER BY t::text`
/// makes the digest independent of physical row order.
async fn backfill_snapshot(direct: &Client) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for relation in BACKFILL_WATCHED_RELATIONS {
        let digest: String = direct
            .query_one(
                &format!(
                    "SELECT coalesce(md5(string_agg(t::text, '|' ORDER BY t::text)), 'empty') \
                       FROM {relation} t"
                ),
                &[],
            )
            .await
            .unwrap_or_else(|error| panic!("snapshot {relation}: {error}"))
            .get(0);
        out.push((relation.to_owned(), digest));
    }
    out
}

/// The singleton schema-state row as `column=value` lines, so a diff names the
/// exact columns that moved rather than only that the row changed.
async fn backfill_schema_state_columns(direct: &Client) -> Vec<String> {
    let rendered: String = direct
        .query_one(
            "SELECT string_agg(pair.key || '=' || coalesce(pair.value, '<null>'), \
                               chr(10) ORDER BY pair.key) \
               FROM lore_fragment_schema_state t, jsonb_each_text(to_jsonb(t)) AS pair",
            &[],
        )
        .await
        .expect("render schema state row")
        .get(0);
    rendered.lines().map(str::to_owned).collect()
}

/// The durable cursor position as the row itself holds it.
async fn stored_backfill_cursor(direct: &Client) -> Option<Vec<u8>> {
    direct
        .query_one(
            "SELECT backfill_cursor FROM lore_fragment_schema_state WHERE id = 1",
            &[],
        )
        .await
        .expect("read stored cursor")
        .get(0)
}

/// Fill every watched lifecycle relation with rows a cursor advance must not
/// touch, so "unchanged" is a real claim rather than a statement about empty
/// tables.
async fn seed_backfill_lifecycle_rows(direct: &Client) {
    let hash: Vec<u8> = vec![0x11; 32];
    let manifest: Vec<u8> = vec![0x22; 32];
    let repository: Vec<u8> = vec![0x33; 16];
    let lease: Vec<u8> = vec![0x44; 16];
    let request: Vec<u8> = vec![0x55; 16];
    let attempt: Vec<u8> = vec![0x66; 16];

    direct
        .execute(
            "INSERT INTO lore_domain_repositories \
                 (repository_id, state, generation, name, metadata_hash, \
                  default_branch_id, creation_fingerprint_version, \
                  creation_fingerprint, created_at) \
             VALUES ($1, 0, 1, 'wp118-backfill-cursor', $2, $3, 1, $2, \
                     clock_timestamp())",
            &[&repository, &manifest, &lease],
        )
        .await
        .expect("seed repository");
    direct
        .execute(
            "INSERT INTO lore_domain_branches \
                 (repository_id, branch_id, repository_generation, state, generation, \
                  name, metadata_hash, latest_hash, creation_fingerprint_version, \
                  creation_fingerprint, created_at) \
             VALUES ($1, $2, 1, 0, 1, 'wp118-backfill-cursor-branch', $3, $3, 1, $3, \
                     clock_timestamp())",
            &[&repository, &lease, &manifest],
        )
        .await
        .expect("seed branch");
    direct
        .execute(
            "INSERT INTO lore_fragment_lifecycle \
                 (hash, current_epoch, state, manifest_id, last_fence) \
             VALUES ($1, 1, 3, $2, 1)",
            &[&hash, &manifest],
        )
        .await
        .expect("seed lifecycle head");
    direct
        .execute(
            "INSERT INTO lore_fragment_epochs \
                 (hash, epoch, authority, object_key, manifest_id, size_payload, \
                  size_content, decoded_hash, payload_flags, fence) \
             VALUES ($1, 1, 1, 'backfill-cursor-object-key', $2, 10, 10, $2, 0, 1)",
            &[&hash, &manifest],
        )
        .await
        .expect("seed epoch");
    direct
        .execute(
            "INSERT INTO lore_fragment_associations \
                 (hash, repository_id, context, association_epoch, state, \
                  repository_generation) \
             VALUES ($1, $2, $3, 1, 0, 1)",
            &[&hash, &repository, &b"backfill-cursor-context".to_vec()],
        )
        .await
        .expect("seed association");
    direct
        .execute(
            "INSERT INTO lore_fragment_lifecycle_metering \
                 (hash, epoch, payload_flags, size_payload, size_content, authority) \
             VALUES ($1, 1, 0, 10, 10, 1)",
            &[&hash],
        )
        .await
        .expect("seed lifecycle metering");
    direct
        .execute(
            "INSERT INTO lore_fragment_write_claims \
                 (logical_request_id, attempt_id, hash, epoch, fence, authority, \
                  object_key, body_blake3, body_size, state, send_not_after, \
                  hard_not_after, prepared_at) \
             VALUES ($1, $2, $3, 1, 1, 2, 'backfill-cursor-object-key', $4, 10, 0, \
                     clock_timestamp() + interval '1 hour', \
                     clock_timestamp() + interval '2 hours', clock_timestamp())",
            &[&request, &attempt, &hash, &manifest],
        )
        .await
        .expect("seed write claim");
    direct
        .execute(
            "INSERT INTO lore_fragment_staged_leases (lease_id, reader_fence, deadline) \
             VALUES ($1, 1, clock_timestamp() + interval '1 hour')",
            &[&lease],
        )
        .await
        .expect("seed staged lease");
    direct
        .execute(
            "INSERT INTO lore_fragment_staged_lease_members (lease_id, hash, epoch) \
             VALUES ($1, $2, 1)",
            &[&lease, &hash],
        )
        .await
        .expect("seed staged lease member");
}

/// Install the legacy key space and seed `count` candidate keys, ascending by
/// primary key, so the cursor has somewhere to go and a known order to go in.
async fn seed_legacy_backfill_candidates(direct: &Client, count: u8) -> Vec<Vec<u8>> {
    direct
        .batch_execute(BACKFILL_LEGACY_SCHEMA)
        .await
        .expect("install legacy fragment schema");
    let mut hashes = Vec::new();
    for index in 1..=count {
        let hash = vec![index; 32];
        direct
            .execute(
                "INSERT INTO lore_fragment_state (hash, state) VALUES ($1, 1)",
                &[&hash],
            )
            .await
            .expect("seed legacy candidate");
        direct
            .execute(
                "INSERT INTO lore_fragments (hash, repository, context) \
                 VALUES ($1, $2, $3)",
                &[&hash, &vec![0x77u8; 16], &b"legacy-context".to_vec()],
            )
            .await
            .expect("seed legacy association");
        direct
            .execute(
                "INSERT INTO lore_fragment_metering \
                     (hash, payload_flags, size_payload, size_content) \
                 VALUES ($1, 0, 10, 10)",
                &[&hash],
            )
            .await
            .expect("seed legacy metering");
        hashes.push(hash);
    }
    hashes
}

/// The guarded stop survives a moved cursor, and it is held twice over: by the
/// typed readiness/enable gates and, independently, by the DDL.
///
/// A cell whose cursor has moved sits at `BACKFILL_RUNNING`. It must still be
/// unable to reach `BACKFILL_CUTOVER`, to report itself ready for lifecycle
/// routing, or to have `lifecycle_enabled` written -- and the refusals must
/// name the observed state rather than fail generically. This is what keeps a
/// cursor mechanism from reading as rollout progress it is not.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn backfill_cursor_advance_cannot_reach_cutover_readiness_or_the_enable_gate() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hashes = seed_legacy_backfill_candidates(&direct, 5).await;

    let before = coordinator.readiness().await.expect("readiness before");
    assert_eq!(before.backfill_state, schema::BACKFILL_NOT_STARTED);
    assert!(!before.ready_for_lifecycle());

    let advance = coordinator
        .advance_backfill_cursor(3)
        .await
        .expect("advance cursor");
    assert_eq!(advance.examined, 3, "batch limit bounds the pass");
    assert_eq!(advance.cursor.as_deref(), Some(hashes[2].as_slice()));
    assert!(!advance.exhausted, "a full batch proves nothing either way");

    let row = direct
        .query_one(
            "SELECT backfill_state, backfill_cursor, verified_fragments, cutover_at, \
                    lifecycle_enabled \
               FROM lore_fragment_schema_state WHERE id = 1",
            &[],
        )
        .await
        .expect("read schema state");
    let state: i16 = row.get("backfill_state");
    let cursor: Option<Vec<u8>> = row.get("backfill_cursor");
    let verified: i64 = row.get("verified_fragments");
    let cutover: Option<SystemTime> = row.get("cutover_at");
    let enabled: bool = row.get("lifecycle_enabled");
    assert_eq!(state, schema::BACKFILL_RUNNING);
    assert_ne!(state, schema::BACKFILL_CUTOVER);
    assert_eq!(cursor.as_deref(), Some(hashes[2].as_slice()));
    assert_eq!(verified, 0, "the cursor claims no verification");
    assert!(cutover.is_none());
    assert!(!enabled);

    // The readiness gate refuses, and names the backfill state as the reason.
    let after = coordinator.readiness().await.expect("readiness after");
    assert_eq!(after.backfill_state, schema::BACKFILL_RUNNING);
    assert!(!after.cutover_at_present);
    assert!(
        !after.ready_for_lifecycle(),
        "a moved cursor must not make a cell ready for lifecycle routing"
    );

    // The enable gate refuses, and for the stated reason rather than any error.
    match coordinator.enable_lifecycle().await {
        Err(DomainError::NotReady(message)) => {
            assert!(
                message.contains(&format!("backfill_state={}", schema::BACKFILL_RUNNING)),
                "refusal must name the observed backfill state: {message}"
            );
            assert!(
                message.contains("requires a completed backfill"),
                "refusal must be the completed-backfill gate: {message}"
            );
        }
        other => panic!("enable_lifecycle must refuse with NotReady, got {other:?}"),
    }

    // The DDL refuses independently of the typed gate: a cutover marker or an
    // enabled flag at a non-cutover state is unrepresentable, not merely
    // unwritten.
    let marker = direct
        .execute(
            "UPDATE lore_fragment_schema_state SET cutover_at = clock_timestamp() WHERE id = 1",
            &[],
        )
        .await
        .expect_err("a cutover marker at BACKFILL_RUNNING must be rejected");
    let marker_db = marker.as_db_error().expect("a database error");
    assert_eq!(
        marker_db.code().code(),
        "23514",
        "must be a CHECK violation"
    );
    assert_eq!(
        marker_db.constraint(),
        Some("lore_fragment_schema_cutover_shape"),
        "must be the cutover-shape constraint"
    );

    let enable = direct
        .execute(
            "UPDATE lore_fragment_schema_state SET lifecycle_enabled = true WHERE id = 1",
            &[],
        )
        .await
        .expect_err("enabling lifecycle at BACKFILL_RUNNING must be rejected");
    let enable_db = enable.as_db_error().expect("a database error");
    assert_eq!(
        enable_db.code().code(),
        "23514",
        "must be a CHECK violation"
    );
    // `lore_fragment_schema_enable_shape` also forbids this row, but
    // `lore_fragment_schema_cutover_shape`'s non-cutover arm already pins
    // `lifecycle_enabled = false`, and PostgreSQL reports the first constraint
    // that fails. The enable-shape name here is what a source read predicts and
    // it is wrong against a real PostgreSQL 16: the guarded stop is held twice
    // over at this state, and the cutover-shape arm is what a caller hits.
    assert_eq!(
        enable_db.constraint(),
        Some("lore_fragment_schema_cutover_shape"),
        "the cutover-shape arm is what forbids an enabled flag at a non-cutover state"
    );

    // A cell already past this window refuses rather than silently no-opping.
    direct
        .execute(
            "UPDATE lore_fragment_schema_state SET backfill_state = $1 WHERE id = 1",
            &[&schema::BACKFILL_VERIFIED],
        )
        .await
        .expect("stage a verified cell");
    match coordinator.advance_backfill_cursor(3).await {
        Err(DomainError::NotReady(message)) => assert!(
            message.contains("NOT_STARTED or RUNNING"),
            "refusal must name the required window: {message}"
        ),
        other => panic!("a verified cell must refuse the cursor, got {other:?}"),
    }
}

/// The write set is exactly three columns of one singleton row.
///
/// Run against a database holding live rows in every other fragment relation,
/// so "byte-identical" is a claim about real rows. The non-empty guard below is
/// not decorative: it fired on the implementation's first run, and without it a
/// fixture that silently seeded nothing would report a vacuous pass.
///
/// `verified_fragments` is deliberately NOT in the write set. Nothing here
/// verifies a fragment, so the counter named for verification must not move --
/// this pins three columns, not four.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn backfill_cursor_advance_writes_only_three_columns_of_the_schema_state_row() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    seed_legacy_backfill_candidates(&direct, 4).await;
    seed_backfill_lifecycle_rows(&direct).await;

    // Every watched relation must actually hold rows, or "unchanged" is vacuous.
    for relation in BACKFILL_WATCHED_RELATIONS {
        let count: i64 = direct
            .query_one(&format!("SELECT count(*)::bigint FROM {relation}"), &[])
            .await
            .unwrap_or_else(|error| panic!("count {relation}: {error}"))
            .get(0);
        assert!(
            count > 0,
            "{relation} must hold at least one row or this case proves nothing"
        );
    }

    let before = backfill_snapshot(&direct).await;
    let before_columns = backfill_schema_state_columns(&direct).await;
    // A distinguishable clock gap, so `updated_at` genuinely moves.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let advance = coordinator
        .advance_backfill_cursor(2)
        .await
        .expect("advance cursor");
    assert_eq!(advance.examined, 2);

    let after = backfill_snapshot(&direct).await;
    let after_columns = backfill_schema_state_columns(&direct).await;

    for ((relation, before_digest), (_, after_digest)) in before.iter().zip(after.iter()) {
        if relation == "lore_fragment_schema_state" {
            assert_ne!(
                before_digest, after_digest,
                "the schema-state row must have changed, or this case raced nothing"
            );
        } else {
            assert_eq!(
                before_digest, after_digest,
                "{relation} must be byte-identical across a cursor advance"
            );
        }
    }

    let moved: Vec<&String> = after_columns
        .iter()
        .filter(|line| !before_columns.contains(line))
        .collect();
    let mut moved_names: Vec<&str> = moved
        .iter()
        .map(|line| line.split('=').next().unwrap_or(line))
        .collect();
    moved_names.sort_unstable();
    assert_eq!(
        moved_names,
        vec!["backfill_cursor", "backfill_state", "updated_at"],
        "exactly three columns of the singleton row may move; got {moved:?}"
    );
}

/// Both refusals that precede any candidate read: the batch bound, and a
/// database with no legacy key space.
///
/// The accepted upper boundary is exercised too, so the range guard is pinned
/// as inclusive rather than only as "large values are rejected" -- `1..=MAX`
/// and `1..MAX` are indistinguishable without it.
///
/// The legacy-absence arm is why `to_regclass` is probed at all: a
/// coordinator-only fixture never constructed `lore_fragment_state`, and the
/// caller must see a typed `NotReady` naming the missing key space rather than
/// a raw `42P01` out of the candidate scan, which would read as damage.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn backfill_cursor_refuses_an_out_of_range_batch_and_a_database_with_no_legacy_key_space() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    for rejected in [0, MAX_FRAGMENT_BACKFILL_CURSOR_BATCH + 1, u32::MAX] {
        match coordinator.advance_backfill_cursor(rejected).await {
            Err(DomainError::InvalidInput(message)) => assert!(
                message.contains(&format!(
                    "between 1 and {MAX_FRAGMENT_BACKFILL_CURSOR_BATCH}"
                )),
                "batch {rejected} must be refused naming the bound: {message}"
            ),
            other => panic!("batch {rejected} must be InvalidInput, got {other:?}"),
        }
    }

    // Both accepted boundaries clear the range guard and reach the next one.
    // Without this the case could not tell an inclusive bound from an exclusive
    // one, since every value it rejects is outside both.
    for accepted in [1, MAX_FRAGMENT_BACKFILL_CURSOR_BATCH] {
        match coordinator.advance_backfill_cursor(accepted).await {
            Err(DomainError::NotReady(message)) => {
                assert!(
                    message.contains("lore_fragment_state"),
                    "an absent legacy key space must be named: {message}"
                );
                assert!(
                    !message.contains("42P01"),
                    "the absence must be classified, not a raw relation-missing SQLSTATE: \
                     {message}"
                );
            }
            other => panic!(
                "batch {accepted} must clear the range guard and refuse on the absent legacy \
                 key space, got {other:?}"
            ),
        }
    }

    // A refusal leaves the cell where it was. The method's UPDATE is reachable
    // on the accepting path, so this discriminates against an implementation
    // that stamped RUNNING before checking its prerequisites.
    let row = direct
        .query_one(
            "SELECT backfill_state, backfill_cursor FROM lore_fragment_schema_state WHERE id = 1",
            &[],
        )
        .await
        .expect("read schema state");
    let state: i16 = row.get("backfill_state");
    let cursor: Option<Vec<u8>> = row.get("backfill_cursor");
    assert_eq!(
        state,
        schema::BACKFILL_NOT_STARTED,
        "a refused pass must not move the backfill state"
    );
    assert!(
        cursor.is_none(),
        "a refused pass must not stamp a cursor position"
    );

    // Install the key space and change nothing else about the call: the same
    // batch that was refused now advances, proving the refusal was the absent
    // table and not the batch value.
    seed_legacy_backfill_candidates(&direct, 1).await;
    let advance = coordinator
        .advance_backfill_cursor(1)
        .await
        .expect("the same batch advances once the legacy key space exists");
    assert_eq!(advance.examined, 1);
}

/// The cursor is resumable and monotonic: each pass starts strictly after the
/// stored position, and an empty pass never regresses it to `NULL`.
///
/// The exact per-pass cursor values are what discriminate. A `hash >= $1` scan
/// instead of `hash > $1` re-reads the previous pass's last key and lands the
/// cursor a key short on every subsequent pass, while still reporting a full
/// batch -- indistinguishable from correct behaviour on counts alone.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn backfill_cursor_resumes_strictly_after_its_stored_position_and_never_regresses_to_null() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hashes = seed_legacy_backfill_candidates(&direct, 5).await;

    let first = coordinator
        .advance_backfill_cursor(2)
        .await
        .expect("first pass");
    assert_eq!(first.examined, 2);
    assert_eq!(first.cursor.as_deref(), Some(hashes[1].as_slice()));
    assert!(!first.exhausted);
    assert_eq!(
        stored_backfill_cursor(&direct).await.as_deref(),
        Some(hashes[1].as_slice()),
        "the returned position must be the durable one"
    );

    // Strictly after: a `>=` scan would return hashes[1]..=hashes[2] here and
    // leave the cursor at hashes[2], one key short.
    let second = coordinator
        .advance_backfill_cursor(2)
        .await
        .expect("second pass");
    assert_eq!(second.examined, 2);
    assert_eq!(
        second.cursor.as_deref(),
        Some(hashes[3].as_slice()),
        "the second pass must start strictly after the stored position"
    );
    assert!(!second.exhausted);

    // The short batch is the only evidence the key space ran out.
    let third = coordinator
        .advance_backfill_cursor(2)
        .await
        .expect("third pass");
    assert_eq!(third.examined, 1, "one key remains");
    assert_eq!(third.cursor.as_deref(), Some(hashes[4].as_slice()));
    assert!(
        third.exhausted,
        "a short batch is what reports the key space ran out"
    );

    // The COALESCE arm: an empty pass reads nothing and must leave the durable
    // position where it was, both in the returned value and in the row.
    let empty = coordinator
        .advance_backfill_cursor(2)
        .await
        .expect("empty pass");
    assert_eq!(empty.examined, 0);
    assert!(empty.exhausted);
    assert_eq!(
        empty.cursor.as_deref(),
        Some(hashes[4].as_slice()),
        "an empty pass reports the retained position, not None"
    );
    assert_eq!(
        stored_backfill_cursor(&direct).await.as_deref(),
        Some(hashes[4].as_slice()),
        "an empty batch must never move the durable cursor back to NULL"
    );

    // Every key was read exactly once across the passes: 2 + 2 + 1 + 0 == 5.
    assert_eq!(
        first.examined + second.examined + third.examined + empty.examined,
        u64::try_from(hashes.len()).expect("candidate count fits u64"),
        "a resumable cursor reads each legacy key exactly once"
    );
}

/// Backends in this case's database currently blocked on a lock, excluding the
/// observing backend itself.
///
/// This is what makes the contention deterministic rather than timed: the
/// blocker is not released until the database itself reports both advances
/// parked, so neither can have completed before the other started.
async fn backfill_lock_waiters(observer: &Client) -> i64 {
    observer
        .query_one(
            "SELECT count(*)::bigint FROM pg_stat_activity \
              WHERE datname = current_database() \
                AND wait_event_type = 'Lock' \
                AND pid <> pg_backend_pid()",
            &[],
        )
        .await
        .expect("count lock waiters")
        .get(0)
}

/// Two replicas contending the singleton cursor row serialise on its
/// `FOR UPDATE` and both advance, each resuming strictly after the other.
///
/// This is the `backfill.advance.locked` anchor's own stated scenario, driven
/// without the failpoint mechanism. The property is the corrected one: the row
/// lock does not pick a winner and make the loser no-op -- it orders them, so
/// the second pass reads the position the first committed and continues from
/// there. Two equal cursors would mean both read the same starting position and
/// redid the same batch, which is what dropping the `FOR UPDATE` produces.
///
/// A third connection holds the row while both calls park, and the release
/// waits on `pg_stat_activity` reporting two blocked backends rather than on a
/// sleep, so the contention is established by the database rather than assumed
/// from timing.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn two_concurrent_cursor_advances_serialise_and_each_resumes_after_the_other() {
    let Some(url) = pg_url() else {
        panic!("runner must provide LORE_TEST_PG_URL");
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let observer = client(&url).await;
    let mut blocker = client(&url).await;
    let hashes = seed_legacy_backfill_candidates(&direct, 4).await;

    let blocking = blocker
        .transaction()
        .await
        .expect("open the blocking transaction");
    blocking
        .query_one(
            "SELECT id FROM lore_fragment_schema_state WHERE id = 1 FOR UPDATE",
            &[],
        )
        .await
        .expect("hold the singleton schema-state row");

    let (first, second) = timeout(Duration::from_secs(60), async {
        let release = async {
            while backfill_lock_waiters(&observer).await < 2 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            blocking
                .commit()
                .await
                .expect("release the singleton schema-state row");
        };
        let (first, second, ()) = tokio::join!(
            coordinator.advance_backfill_cursor(2),
            coordinator.advance_backfill_cursor(2),
            release
        );
        (
            first.expect("first advance"),
            second.expect("second advance"),
        )
    })
    .await
    .expect(
        "both advances must park on the held row and then complete; a timeout here means \
         either they never contended or they deadlocked",
    );

    // Neither call no-ops. A serialising lock orders the passes; it does not
    // discard one of them.
    assert_eq!(first.examined, 2, "neither contending pass may no-op");
    assert_eq!(second.examined, 2, "neither contending pass may no-op");

    // The discriminating assertion. Under the `FOR UPDATE` one pass takes
    // hashes[0..=1] and the other resumes at hashes[2..=3]; without it both
    // read the same NULL starting cursor and both land on hashes[1].
    let mut positions = [first.cursor.clone(), second.cursor.clone()];
    positions.sort();
    assert_eq!(
        positions,
        [Some(hashes[1].clone()), Some(hashes[3].clone())],
        "serialised passes must take disjoint halves of the key space; two equal positions \
         mean both read the same starting cursor and duplicated the batch"
    );

    assert_eq!(
        stored_backfill_cursor(&direct).await.as_deref(),
        Some(hashes[3].as_slice()),
        "the durable position after both passes is the later one"
    );

    // Both passes were full, so neither may claim the key space ran out even
    // though it did: `exhausted` is derived from the batch being short, and
    // 2 + 2 consumed exactly the 4 seeded keys.
    assert!(!first.exhausted);
    assert!(!second.exhausted);
}

// ---------------------------------------------------------------------------
// CR-032 / WP-119 Part F: fragment-lifecycle and association outbox summaries.
//
// `PostgresFragmentCoordinator::with_outbox_cell_id` stamps the trusted cell
// id the coordinator's own internal `append_lifecycle_summaries`/
// `append_association_summary` need to append anything; a coordinator built
// with `None` (every other test in this file) performs every lifecycle
// mutation and appends nothing, which is exercised implicitly throughout the
// rest of the suite and not repeated here.

fn outbox_cell_id() -> String {
    format!("wp119-fragment-{:08x}", rand::random::<u32>())
}

impl TestDomainStore {
    fn fragment_coordinator_with_cell_id(&self, cell_id: &str) -> TestFragmentCoordinator {
        TestFragmentCoordinator(
            self.0
                .fragment_coordinator()
                .with_outbox_cell_id(Some(cell_id.to_owned())),
        )
    }
}

async fn outbox_row_count_for_repository(client: &Client, repository_id: &[u8]) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM lore_outbox_events WHERE repository_id = $1",
            &[&repository_id],
        )
        .await
        .expect("count outbox rows for repository")
        .get(0)
}

struct FragmentOutboxRow {
    event_kind: String,
    aggregate_kind: String,
    aggregate_id: Vec<u8>,
    aggregate_version: Vec<u8>,
}

/// All outbox rows for a repository, ordered by `created_at` ascending -- see
/// `domain_outbox_producers.rs`'s `all_outbox_rows_for_repository` for why
/// `created_at` (not `event_id`) carries the ordering signal here.
///
/// `event_kind` is a secondary sort key: `created_at` is `clock_timestamp()`,
/// microsecond-precision, and `begin_obliterate`'s owned arm appends its
/// association and lifecycle summaries in one transaction close enough
/// together to tie at that resolution. Without the tiebreak, a case asserting
/// on row position (not just on the set of rows present) is ordering-
/// dependent on a tie it cannot control and will flake.
async fn all_outbox_rows_for_repository(
    client: &Client,
    repository_id: &[u8],
) -> Vec<FragmentOutboxRow> {
    client
        .query(
            "SELECT event_kind, aggregate_kind, aggregate_id, aggregate_version \
             FROM lore_outbox_events WHERE repository_id = $1 \
             ORDER BY created_at ASC, event_kind ASC",
            &[&repository_id],
        )
        .await
        .expect("query outbox rows for repository")
        .into_iter()
        .map(|row| FragmentOutboxRow {
            event_kind: row.get("event_kind"),
            aggregate_kind: row.get("aggregate_kind"),
            aggregate_id: row.get("aggregate_id"),
            aggregate_version: row.get("aggregate_version"),
        })
        .collect()
}

async fn one_outbox_row_for_repository(client: &Client, repository_id: &[u8]) -> FragmentOutboxRow {
    let rows = all_outbox_rows_for_repository(client, repository_id).await;
    assert_eq!(
        rows.len(),
        1,
        "expected exactly one outbox row for the repository, got {}: kinds {:?}",
        rows.len(),
        rows.iter().map(|r| &r.event_kind).collect::<Vec<_>>()
    );
    rows.into_iter().next().expect("one row")
}

/// F1: a fragment shared by three associations in one repository crosses
/// readability once and commits exactly one `fragment.lifecycle_generation_advanced`
/// row for that repository -- not one row per associated fragment. A second,
/// independent crossing commits a second row with `ordinal + 1`.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_readability_crossing_commits_exactly_one_lifecycle_summary_row_not_one_per_fragment() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let cell_id = outbox_cell_id();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator_with_cell_id(&cell_id);
    let db = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();

    // Three distinct fragments, all associated with the one repository under
    // test. Only the first two are ever marked missing below; the third
    // proves the repository's row count does not scale with how many
    // fragments it happens to have associated.
    let mut hashes = Vec::with_capacity(3);
    for seed in 0u8..3 {
        let hash = random_hash();
        let BeginOutcome::Admitted(intent) = coordinator
            .begin_direct_write(&hash, &legacy_key(&hash))
            .await
            .expect("begin fragment")
        else {
            panic!("a fresh hash must admit a direct write");
        };
        assert_eq!(
            coordinator
                .commit_remote(
                    &intent,
                    IoObservation::Valid(manifest(
                        "f1-summary/key",
                        0x10 + seed,
                        EpochAuthority::Remote
                    ))
                )
                .await
                .expect("commit fragment"),
            CommitVerdict::Published
        );
        assert_eq!(
            coordinator
                .create_association(&hash, &repository_id, &context)
                .await
                .expect("associate fragment"),
            CommitVerdict::Published
        );
        hashes.push(hash);
    }
    // Every association above is content-association traffic, not lifecycle
    // traffic, and it stamps its own `association.generation_advanced` rows;
    // clear those out of the way so the assertions below are unambiguous
    // about which kind they are counting.
    let baseline_generation = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture baseline witness")
        .expect("repository must exist")
        .fragment_lifecycle_generation;

    let resolved = coordinator
        .resolve(&repository_id, &context, &hashes[..1])
        .await
        .expect("resolve first fragment to capture its epoch witness");
    let (epoch_witness, ..) = expect_readable(&resolved[0]);
    let first_witness = epoch_witness.clone();

    coordinator
        .mark_missing(&first_witness, MissingDiagnostic::Absent)
        .await
        .expect("first crossing must succeed");

    let after_first = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness after first crossing")
        .expect("repository must exist")
        .fragment_lifecycle_generation;
    assert_eq!(
        after_first,
        baseline_generation + 1,
        "one crossing must advance the generation by exactly one"
    );

    let rows_after_first = all_outbox_rows_for_repository(&db, &repository_id)
        .await
        .into_iter()
        .filter(|row| row.event_kind == "fragment.lifecycle_generation_advanced")
        .collect::<Vec<_>>();
    assert_eq!(
        rows_after_first.len(),
        1,
        "the repository has three associated fragments but only one crossed; it must own \
         exactly one lifecycle-summary row, not three"
    );
    assert_eq!(rows_after_first[0].aggregate_kind, "fragment_lifecycle");
    assert_eq!(rows_after_first[0].aggregate_id, repository_id.to_vec());
    let decoded = AggregateVersion::decode(&rows_after_first[0].aggregate_version).expect("decode");
    assert_eq!(
        decoded.ordinal,
        u64::try_from(after_first).expect("fits u64")
    );
    assert!(
        decoded.identity.is_empty(),
        "fragment_lifecycle aggregate identity is empty per PIN-4"
    );

    // A second, independent crossing on the second (still-readable) fragment.
    let resolved = coordinator
        .resolve(&repository_id, &context, &hashes[1..2])
        .await
        .expect("resolve second fragment to capture its epoch witness");
    let (epoch_witness, ..) = expect_readable(&resolved[0]);
    let second_witness = epoch_witness.clone();
    coordinator
        .mark_missing(&second_witness, MissingDiagnostic::Absent)
        .await
        .expect("second crossing must succeed");

    let after_second = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness after second crossing")
        .expect("repository must exist")
        .fragment_lifecycle_generation;
    assert_eq!(after_second, baseline_generation + 2);

    let rows_after_second = all_outbox_rows_for_repository(&db, &repository_id)
        .await
        .into_iter()
        .filter(|row| row.event_kind == "fragment.lifecycle_generation_advanced")
        .collect::<Vec<_>>();
    assert_eq!(
        rows_after_second.len(),
        2,
        "a second, independent crossing must add a second row rather than replace the first"
    );
    let second_decoded =
        AggregateVersion::decode(&rows_after_second[1].aggregate_version).expect("decode");
    assert_eq!(
        second_decoded.ordinal,
        decoded.ordinal + 1,
        "the second crossing's ordinal must be exactly the first's plus one"
    );
}

/// F1 (negative control): a `Staged` -> `Remote` promotion moves no repository
/// scalar (CR-032: "unchanged readability: No by default") and must append no
/// lifecycle-summary row, even though it is a real committed transition on an
/// associated fragment.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_promotion_with_unchanged_readability_appends_no_lifecycle_summary_row() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let cell_id = outbox_cell_id();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator_with_cell_id(&cell_id);
    let db = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage_intent,
                IoObservation::Valid(manifest(
                    "f1-promotion/staged",
                    0x20,
                    EpochAuthority::Staged
                ))
            )
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate staged fragment"),
        CommitVerdict::Published
    );
    let before = outbox_row_count_for_repository(&db, &repository_id).await;

    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash)
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    let verdict = coordinator
        .commit_promotion(
            &promotion_intent,
            IoObservation::Valid(manifest(
                "f1-promotion/remote",
                0x21,
                EpochAuthority::Remote,
            )),
        )
        .await
        .expect("commit promotion must not error");
    assert_eq!(verdict, CommitVerdict::Published);

    let after = outbox_row_count_for_repository(&db, &repository_id).await;
    assert_eq!(
        after, before,
        "a Staged -> Remote promotion crosses no readability boundary and must append nothing"
    );
}

/// F2: `create_association` commits exactly one `association.generation_advanced`
/// row per epoch move, with the pinned identity (the association epoch, as an
/// 8-byte big-endian value) and ordinal (the committed
/// `content_association_generation`).
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn create_association_commits_one_association_generation_advanced_row_per_epoch_move() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let cell_id = outbox_cell_id();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator_with_cell_id(&cell_id);
    let db = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context_a = random_context();
    let context_b = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin fragment")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest("f2-association/key", 0x30, EpochAuthority::Remote))
            )
            .await
            .expect("commit fragment"),
        CommitVerdict::Published
    );

    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context_a)
            .await
            .expect("first association"),
        CommitVerdict::Published
    );
    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );
    let first_row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(first_row.event_kind, "association.generation_advanced");
    assert_eq!(first_row.aggregate_kind, "association");
    assert_eq!(first_row.aggregate_id, repository_id.to_vec());
    let first_decoded = AggregateVersion::decode(&first_row.aggregate_version).expect("decode");
    assert_eq!(
        first_decoded.identity.len(),
        8,
        "association identity is the 8-byte big-endian association_epoch"
    );

    // A second, distinct association on the same repository (different
    // context) is a second epoch move and must commit a second row, with the
    // ordinal advancing by exactly one and a different epoch identity.
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context_b)
            .await
            .expect("second association"),
        CommitVerdict::Published
    );
    let rows = all_outbox_rows_for_repository(&db, &repository_id)
        .await
        .into_iter()
        .filter(|row| row.event_kind == "association.generation_advanced")
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    let second_decoded = AggregateVersion::decode(&rows[1].aggregate_version).expect("decode");
    assert_eq!(
        second_decoded.ordinal,
        first_decoded.ordinal + 1,
        "a second epoch move must advance the ordinal by exactly one"
    );
    assert_ne!(
        second_decoded.identity, first_decoded.identity,
        "two distinct association_epoch fence values must not collide"
    );
}

// ---------------------------------------------------------------------------
// F-032-3 lock order: write-claim settlement (`LockClass::Fragments`) must
// run BEFORE the outbox append (`LockClass::OutboxInsert`) inside
// `commit_publication`. `LockSequence` only catches an inversion when a
// claim is actually present on the committing transaction, so both cases
// below need a real write claim (via `claim_repair`) together with a real
// readability crossing on an associated repository -- an empty fanout would
// never enter `OutboxInsert` at all, making the ordering unobservable.
// ---------------------------------------------------------------------------

/// The `IoObservation::Valid` arm (unreadable -> readable): claim settlement
/// before the append. A reversed order would return `Err` from
/// `LockSequence::enter`'s downward-move refusal; this test's success is
/// itself part of the proof.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn commit_publication_valid_arm_settles_the_write_claim_before_appending_the_summary() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let cell_id = outbox_cell_id();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator_with_cell_id(&cell_id);
    let db = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash))
        .await
        .expect("begin fragment")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest("f-order-valid/key", 0x40, EpochAuthority::Remote))
            )
            .await
            .expect("commit initial fragment"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate fragment"),
        CommitVerdict::Published
    );

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve to capture epoch witness");
    let (epoch_witness, ..) = expect_readable(&resolved[0]);
    let witness = epoch_witness.clone();
    coordinator
        .mark_missing(&witness, MissingDiagnostic::Absent)
        .await
        .expect("mark missing to reach an unreadable head");
    let before = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness before repair")
        .expect("repository must exist")
        .fragment_lifecycle_generation;
    let rows_before_repair = outbox_row_count_for_repository(&db, &repository_id).await;

    // A repair over the now-Missing head: `claim_repair` carries a real
    // write claim, and `commit_remote`'s wrapper authorizes + settles it
    // (`FragmentWriteSettlement::Decisive`) as part of this exact commit.
    let BeginOutcome::Admitted(repair_intent) = coordinator
        .claim_repair(&hash)
        .await
        .expect("claim repair over a Missing head")
    else {
        panic!("a Missing head must admit a claimed repair");
    };
    let verdict = coordinator
        .commit_remote(
            &repair_intent,
            IoObservation::Valid(manifest(
                "f-order-valid/repaired",
                0x41,
                EpochAuthority::Remote,
            )),
        )
        .await
        .expect(
            "the Valid arm must settle the write claim before appending the outbox row; a \
             reversed order would fail here with a lock-order violation",
        );
    assert_eq!(verdict, CommitVerdict::Published);

    let after = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness after repair")
        .expect("repository must exist")
        .fragment_lifecycle_generation;
    assert_eq!(
        after,
        before + 1,
        "the repair crosses Missing back to readable and must move the generation once"
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        rows_before_repair + 1,
        "the repair's crossing must append exactly one new row on top of the ones already \
         there (the mark_missing crossing above already owns one)"
    );
}

// The `IoObservation::Unusable` ("publication missing") arm's claim-before-
// append ordering does NOT get an equivalent test here. Structural finding,
// confirmed empirically against real Postgres before writing anything
// further: every admission path that can produce a non-`None` write claim
// (`begin_direct_write`, `begin_stage`, `claim_repair`) either short-circuits
// to `BeginOutcome::AlreadyReadable` with no claim at all when the current
// head is already readable, or requires the opposite (`claim_repair`'s
// `require_missing` refuses with `BeginOutcome::Fenced` unless the head is
// already `Missing` or a resuming `PreparingRemote` repair lineage -- both
// non-readable). Every admitted intent therefore carries a head state of
// `PreparingStage`/`PreparingRemote` at BEGIN time, which is what
// `commit_publication` reads back at COMMIT time too (a concurrent mutation
// in between would move `last_fence` and hit the earlier `Fenced` branch
// first). So `was_readable` is always `false` whenever `write_claim` is
// `Some` -- the "Missing arm, claim present, was_readable = true" case this
// ordering pin asks for cannot be constructed through any public admission
// path. Flagged back rather than built as a vacuous or misleading pass;
// `commit_publication_valid_arm_...` above is the reachable half.
