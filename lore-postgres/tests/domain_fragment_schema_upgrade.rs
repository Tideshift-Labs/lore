// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-039: real-Postgres proof for `PostgresFragmentCoordinator::upgrade_clean_schema`.
//!
//! Every case is `#[ignore]` and executed by `run-fragment-schema-upgrade-live.ps1`,
//! which gives each exact case a fresh PostgreSQL 16 database. No MinIO/S3 is
//! required: the upgrade is offline and database-only (no provider I/O).
//!
//! The seam fixture ([`revision4_clean_cell`]) follows CR-039's own test-spec
//! guidance: initialize a real clean cell through the production
//! `initialize_empty` API (reaching revision 6), then, as the fixture owner
//! with the permanent fence disabled, drop the revision-5/6 objects and roll
//! `schema_version` back to 4. The fixture asserts its own resulting catalog
//! shape before returning, so every case here starts from a database that
//! provably matches a real `dae71dfc` clean cell, not merely "some database
//! missing a few tables".
//!
//! Assertions in the happy-path case independently re-derive the two
//! invariants `upgrade_clean_schema`'s own `verify_upgraded` checks (every
//! schema-state column but `schema_version` is unchanged; every fragment
//! trigger's definition and enablement is unchanged) from this file's own
//! SQL, rather than trusting the coordinator's return value alone -- so a
//! regression that weakened either internal check would still be caught here.

#[path = "common/drain_candidate.rs"]
mod drain_candidate;

#[path = "common/stage_policy.rs"]
mod stage_policy;

use async_trait::async_trait;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::backfill::BranchFacts;
use lore_postgres::domain::backfill::DomainBackfill;
use lore_postgres::domain::backfill::DomainBackfillSource;
use lore_postgres::domain::backfill::OrphanKey;
use lore_postgres::domain::backfill::RepositoryFacts;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::fragments::BeginOutcome;
use lore_postgres::domain::fragments::CommitVerdict;
use lore_postgres::domain::fragments::EpochAuthority;
use lore_postgres::domain::fragments::FragmentManifest;
use lore_postgres::domain::fragments::FragmentWriteClaimInput;
use lore_postgres::domain::fragments::FragmentWriteSettlement;
use lore_postgres::domain::fragments::IoObservation;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::domain::fragments::StageReservationInput;
use lore_postgres::domain::fragments::initialization::CleanCellInitialization;
use lore_postgres::domain::fragments::initialization::CleanCellInitializationOutcome;
use lore_postgres::domain::fragments::schema;
use lore_postgres::domain::fragments::stage_rotation_schema::STAGE_POLICY_ROTATION_SCHEMA;
use lore_postgres::domain::fragments::stage_schema::STAGE_CUSTODY_SCHEMA;
use lore_postgres::domain::fragments::upgrade::FragmentSchemaUpgradeOutcome;
use lore_postgres::domain::locks::BackfillIssuerMap;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use tokio_postgres::Client;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Shared plumbing. Duplicated rather than imported from a sibling test file:
// this crate builds one `[[test]]` binary per file (`autotests = true` here),
// so each target is its own compiled binary and cannot share code except via
// the `common/` `#[path]` modules above.
// ---------------------------------------------------------------------------

fn pg_url() -> String {
    std::env::var("LORE_TEST_PG_URL").expect("runner must set LORE_TEST_PG_URL")
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

fn random_hash() -> Vec<u8> {
    rand::random::<[u8; 32]>().to_vec()
}

fn legacy_key(hash: &[u8]) -> String {
    hash.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
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

fn write_claim() -> FragmentWriteClaimInput {
    FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        rand::random::<[u8; 32]>(),
        1,
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
    )
    .expect("valid test write claim")
}

fn uuid_v7_at(time: std::time::SystemTime) -> Uuid {
    let elapsed = time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("test timestamp follows epoch");
    Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        elapsed.as_secs(),
        elapsed.subsec_nanos(),
    ))
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

async fn prepare_operation(store: &PostgresDomainStore, method: &str) -> GovernedOperation {
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("read receipt database clock");
    let key = ReceiptKey {
        verified_issuer: format!(
            "https://issuer.example/cr-039-schema-upgrade/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "svc:cr-039-schema-upgrade-test".to_owned(),
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

/// Create a repository whose `metadata_hash`/`default_branch_metadata_hash`
/// are two already-published Remote fragments. Once lifecycle is enabled
/// (true for every clean-initialized cell), `repository_create` requires an
/// exact [`lore_postgres::domain::fragments::EpochWitness`] for each distinct
/// metadata hash -- this is what `metadata_witnesses_required` refuses
/// without. `bind_creation_metadata` associates both hashes to the new
/// repository at the zero context internally.
async fn create_repository(
    store: &PostgresDomainStore,
    metadata_witness: lore_postgres::domain::fragments::EpochWitness,
    branch_witness: lore_postgres::domain::fragments::EpochWitness,
) -> [u8; 16] {
    let repository_id: [u8; 16] = rand::random();
    let branch_id: [u8; 16] = rand::random();
    let operation =
        prepare_operation(store, "lore.domain.v1.test/SchemaUpgradeRepositoryCreate").await;
    let input = RepositoryCreateInput {
        metadata_hash: metadata_witness.hash.clone(),
        default_branch_metadata_hash: branch_witness.hash.clone(),
        metadata_witnesses: vec![metadata_witness, branch_witness],
        repository_id: repository_id.to_vec(),
        name: format!("cr039-schema-upgrade-{:016x}", rand::random::<u64>()),
        default_branch_id: branch_id.to_vec(),
        default_branch_name: "main".to_owned(),
        // A fresh repository's initial branch is empty: the CAS check that
        // validates this input requires all-zero bytes here.
        default_branch_latest_hash: vec![0u8; 32],
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

// ---------------------------------------------------------------------------
// The revision-4 clean-cell seam fixture.
// ---------------------------------------------------------------------------

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

/// Build a real clean cell through the production cutover and
/// `initialize_empty` path, reaching revision 6. Installs the legacy
/// `lore_mutable`/CR-007 tables `DomainBackfill` reads from first, the same
/// prerequisite `domain_fragment_clean_init.rs` needs.
async fn revision6_clean_cell(url: &str) -> (PostgresDomainStore, Client) {
    let direct = client(url).await;
    direct
        .batch_execute(include_str!("../migrations/0001_init.sql"))
        .await
        .unwrap();
    let store = PostgresDomainStore::connect(url, 8, &TlsConfig::default())
        .await
        .unwrap();
    store.lock_coordinator().bootstrap().await.unwrap();
    store.fragment_coordinator().bootstrap().await.unwrap();

    let pool = build_pool(url, 2, &TlsConfig::default()).unwrap();
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

    let coordinator = store.fragment_coordinator();
    let input = CleanCellInitialization::new(
        "cr-039-fixture-namespace".into(),
        "cr-039-fixture-writer-v1".into(),
    )
    .unwrap();
    assert_eq!(
        coordinator.initialize_empty(&input).await.unwrap(),
        CleanCellInitializationOutcome::Initialized
    );
    (store, direct)
}

/// [`revision6_clean_cell`], then downgraded in place to the exact
/// revision-4 shape a `dae71dfc` cell has: as the fixture owner, with the
/// permanent fence disabled, drop the stage-5/6 objects and roll
/// `schema_version` back. Asserts the resulting catalog before returning.
async fn revision4_clean_cell(url: &str) -> (PostgresDomainStore, Client) {
    let (store, direct) = revision6_clean_cell(url).await;
    direct
        .batch_execute(
            "ALTER TABLE lore_fragment_schema_state DISABLE TRIGGER lore_clean_state_permanent; \
             DROP TABLE IF EXISTS lore_fragment_stage_custody, lore_fragment_stage_usage, \
                 lore_fragment_stage_policy CASCADE; \
             DROP FUNCTION IF EXISTS stage_policy_publish_v1, stage_policy_verify_v1, \
                 stage_policy_rotate_v1; \
             DROP INDEX IF EXISTS lore_fragment_stage_custody_cleanup, \
                 lore_fragment_stage_drain_recovery; \
             UPDATE lore_fragment_schema_state SET schema_version = 4, updated_at = clock_timestamp() \
                 WHERE id = 1; \
             ALTER TABLE lore_fragment_schema_state ENABLE ALWAYS TRIGGER lore_clean_state_permanent;",
        )
        .await
        .unwrap();
    assert_pre_stage_catalog(&direct).await;
    (store, direct)
}

/// A store whose fragment schema reached revision 6 by ordinary bootstrap,
/// but was never clean-initialized. Used only for the non-clean refusal case.
async fn store_without_clean_init(url: &str) -> PostgresDomainStore {
    // The legacy `lore_fragment_state`/`lore_fragment_metering` tables must
    // exist too: `upgrade_clean_schema`'s NOWAIT lock step locks them
    // unconditionally, before it reaches the clean-record check this case
    // means to exercise.
    client(url)
        .await
        .batch_execute(include_str!("../migrations/0001_init.sql"))
        .await
        .unwrap();
    let store = PostgresDomainStore::connect(url, 8, &TlsConfig::default())
        .await
        .unwrap();
    store.fragment_coordinator().bootstrap().await.unwrap();
    store
}

async fn assert_pre_stage_catalog(direct: &Client) {
    let pre_stage: [&str; 8] = [
        "lore_fragment_lifecycle",
        "lore_fragment_epochs",
        "lore_fragment_associations",
        "lore_fragment_lifecycle_metering",
        "lore_fragment_write_claims",
        "lore_fragment_staged_leases",
        "lore_fragment_staged_lease_members",
        "lore_fragment_schema_state",
    ];
    let stage: [&str; 3] = [
        "lore_fragment_stage_policy",
        "lore_fragment_stage_usage",
        "lore_fragment_stage_custody",
    ];
    let stage_indexes: [&str; 2] = [
        "lore_fragment_stage_custody_cleanup",
        "lore_fragment_stage_drain_recovery",
    ];
    let row = direct
        .query_one(
            "SELECT \
               (SELECT count(*) FROM unnest($1::text[]) r WHERE to_regclass(r) IS NOT NULL)::bigint, \
               (SELECT count(*) FROM unnest($2::text[]) r WHERE to_regclass(r) IS NOT NULL)::bigint, \
               (SELECT count(*) FROM unnest($3::text[]) r WHERE to_regclass(r) IS NOT NULL)::bigint, \
               (SELECT schema_version FROM lore_fragment_schema_state WHERE id = 1)",
            &[&pre_stage.as_slice(), &stage.as_slice(), &stage_indexes.as_slice()],
        )
        .await
        .unwrap();
    assert_eq!(
        row.get::<_, i64>(0),
        pre_stage.len() as i64,
        "a real dae71dfc cell has all 8 pre-stage fragment relations"
    );
    assert_eq!(
        row.get::<_, i64>(1),
        0,
        "a real dae71dfc cell has none of the stage-5/6 relations"
    );
    assert_eq!(
        row.get::<_, i64>(2),
        0,
        "a real dae71dfc cell has neither stage-5 partial index, including the one on \
         lore_fragment_lifecycle that a bare stage-table drop does not remove"
    );
    assert_eq!(row.get::<_, i64>(3), 4);
}

/// `schema_version` plus every other column of the singleton, as the same
/// canonical jsonb `verify_upgraded` compares -- computed independently here
/// so this file does not merely trust the coordinator's internal check.
async fn schema_state_snapshot(direct: &Client) -> (i64, String) {
    let row = direct
        .query_one(
            "SELECT schema_version, (to_jsonb(s) - 'schema_version')::text \
               FROM lore_fragment_schema_state s WHERE id = 1",
            &[],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

/// Every non-internal trigger on a fragment relation, with its enablement --
/// the same shape `verify_upgraded` compares, computed independently here.
async fn fragment_trigger_snapshot(direct: &Client) -> String {
    direct
        .query_one(
            "SELECT COALESCE(string_agg(format('%s/%s/%s/%s/%s', t.tgrelid::regclass, t.tgname, \
                        t.tgenabled, t.tgtype, t.tgfoid::regprocedure), ',' \
                        ORDER BY t.tgrelid::regclass::text, t.tgname), '') \
               FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
              WHERE NOT t.tgisinternal AND starts_with(c.relname, 'lore_fragment')",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

/// Advance the fence sequence past any fixed fence value (`1`) a raw test
/// insert below sets. `clean_readiness_holds`'s sequence-headroom check is a
/// strict `>`, and a fresh clean cell leaves the sequence at `last_value = 1,
/// is_called = false` -- so a raw row carrying the schema's minimum legal
/// `last_fence`/`fence`/`reader_fence` (also `1`, by CHECK) sits exactly on
/// that boundary and trips readiness for an unrelated reason.
async fn advance_fence_sequence(direct: &Client) {
    direct
        .execute("SELECT nextval('lore_fragment_fence_seq')", &[])
        .await
        .unwrap();
    direct
        .execute("SELECT nextval('lore_fragment_fence_seq')", &[])
        .await
        .unwrap();
}

async fn assert_refused(coordinator: &PostgresFragmentCoordinator, needle: &str) {
    match coordinator.upgrade_clean_schema().await {
        Err(DomainError::NotReady(message)) => assert!(
            message.contains(needle),
            "expected a refusal mentioning {needle:?}, got {message:?}"
        ),
        other => panic!("expected Err(NotReady(..) containing {needle:?}), got {other:?}"),
    }
}

fn swap_database(url: &str, database: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (url, None),
    };
    let prefix = base
        .rsplit_once('/')
        .expect("test fixture url must name a database")
        .0;
    match query {
        Some(query) => format!("{prefix}/{database}?{query}"),
        None => format!("{prefix}/{database}"),
    }
}

async fn create_sibling_database(url: &str) -> String {
    let direct = client(url).await;
    let name = format!("cr039_fresh_{:016x}", rand::random::<u64>());
    direct
        .execute(&format!("CREATE DATABASE {name}"), &[])
        .await
        .unwrap();
    name
}

/// A comparable fingerprint of everything CR-039's test spec asks the
/// fresh-vs-upgraded diff to cover: relations' columns, constraints,
/// indexes, the three stage functions' bodies, triggers, and grants.
async fn fragment_catalog_fingerprint(direct: &Client) -> String {
    let relations = schema::FRAGMENT_SCHEMA_RELATIONS.as_slice();
    let functions: [&str; 3] = [
        "stage_policy_publish_v1",
        "stage_policy_verify_v1",
        "stage_policy_rotate_v1",
    ];
    let columns: String = direct
        .query_one(
            "SELECT COALESCE(string_agg(format('%s.%s:%s:%s:%s', c.relname, a.attname, \
                    format_type(a.atttypid, a.atttypmod), a.attnotnull, a.atthasdef), ',' \
                    ORDER BY c.relname, a.attnum), '') \
               FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid \
              WHERE c.relname = ANY($1) AND a.attnum > 0 AND NOT a.attisdropped",
            &[&relations],
        )
        .await
        .unwrap()
        .get(0);
    let constraints: String = direct
        .query_one(
            "SELECT COALESCE(string_agg(format('%s:%s:%s', conrelid::regclass, conname, \
                    pg_get_constraintdef(oid)), ',' ORDER BY conrelid::regclass::text, conname), '') \
               FROM pg_constraint WHERE conrelid::regclass::text = ANY($1)",
            &[&relations],
        )
        .await
        .unwrap()
        .get(0);
    let indexes: String = direct
        .query_one(
            "SELECT COALESCE(string_agg(format('%s:%s', indexname, indexdef), ',' ORDER BY indexname), '') \
               FROM pg_indexes WHERE tablename = ANY($1)",
            &[&relations],
        )
        .await
        .unwrap()
        .get(0);
    let functions: String = direct
        .query_one(
            "SELECT COALESCE(string_agg(format('%s:%s', proname, prosrc), ',' ORDER BY proname), '') \
               FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
              WHERE n.nspname = current_schema() AND proname = ANY($1)",
            &[&functions.as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    let triggers = fragment_trigger_snapshot(direct).await;
    let grants: String = direct
        .query_one(
            "SELECT COALESCE(string_agg(format('%s:%s:%s:%s', table_name, grantee, privilege_type, \
                    is_grantable), ',' ORDER BY table_name, grantee, privilege_type), '') \
               FROM information_schema.role_table_grants WHERE table_name = ANY($1)",
            &[&relations],
        )
        .await
        .unwrap()
        .get(0);
    format!("{columns}|{constraints}|{indexes}|{functions}|{triggers}|{grants}")
}

// ---------------------------------------------------------------------------
// Seam.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn revision_4_seam_fixture_matches_a_real_pre_stage_clean_cell() {
    let url = pg_url();
    let (_store, direct) = revision4_clean_cell(&url).await;
    // `revision4_clean_cell` already asserts the pre-stage relation/version
    // shape; this pins the clean-record fields WP-122's DDL never touches, so
    // the fixture is provably a real clean cell and not merely a database
    // missing a few tables.
    let row = direct
        .query_one(
            "SELECT backfill_state, lifecycle_enabled, write_capability, \
                    (clean_initialized_at IS NOT NULL) AS clean \
               FROM lore_fragment_schema_state WHERE id = 1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i16>(0), schema::BACKFILL_NOT_STARTED);
    assert!(row.get::<_, bool>(1));
    assert_eq!(
        row.get::<_, i16>(2),
        schema::WRITE_CAPABILITY_CLAIMS_REQUIRED
    );
    assert!(row.get::<_, bool>(3));
}

// ---------------------------------------------------------------------------
// Happy path, and the discriminating re-derivation of the internal proof.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn happy_path_upgrades_a_seeded_clean_cell_then_runs_a_real_stage_drain_and_promotion() {
    let url = pg_url();
    let (store, direct) = revision4_clean_cell(&url).await;
    let coordinator = store.fragment_coordinator();

    // Seed one repository and two Remote heads BEFORE the upgrade, so a
    // regression that touches pre-existing revision-4 data is caught. The
    // repository's own metadata_hash/default_branch_metadata_hash ARE two of
    // the Remote heads: once lifecycle is enabled, repository_create requires
    // an exact epoch witness for each, so this publishes them first.
    let mut hashes = Vec::new();
    let mut witnesses = Vec::new();
    for seed in [0x11u8, 0x22u8] {
        let hash = random_hash();
        let BeginOutcome::Admitted(intent) = coordinator
            .begin_direct_write(&hash, &legacy_key(&hash), write_claim())
            .await
            .expect("begin direct write on a fresh hash")
        else {
            panic!("a fresh hash must admit a direct write");
        };
        let claim = intent.write_claim().expect("direct write claim").clone();
        coordinator.authorize_write_claim(&claim).await.unwrap();
        let published = manifest(&intent.object_key, seed, EpochAuthority::Remote);
        assert_eq!(
            coordinator
                .commit_remote(
                    &intent,
                    IoObservation::Valid(published),
                    FragmentWriteSettlement::Decisive
                )
                .await
                .unwrap(),
            CommitVerdict::Published
        );
        let witness = coordinator
            .capture_current_readable_epoch_for_authority(&hash, EpochAuthority::Remote)
            .await
            .unwrap()
            .expect("just-published head");
        hashes.push(hash);
        witnesses.push(witness);
    }
    let repository = create_repository(&store, witnesses[0].clone(), witnesses[1].clone()).await;
    // `bind_creation_metadata` associates both metadata hashes to the new
    // repository at the zero context, not one this test chooses.
    let zero_context = vec![0u8; 16];
    let seeded: Vec<(Vec<u8>, Vec<u8>)> = hashes
        .into_iter()
        .map(|hash| (hash, zero_context.clone()))
        .collect();

    let state_before = schema_state_snapshot(&direct).await;
    let triggers_before = fragment_trigger_snapshot(&direct).await;

    assert_eq!(
        coordinator.upgrade_clean_schema().await.unwrap(),
        FragmentSchemaUpgradeOutcome::Upgraded { from_version: 4 }
    );

    // Discriminating re-derivation: catches a regression that widens what the
    // upgrade may touch, or that forgets to re-enable the permanent fence.
    let (version_after, rest_after) = schema_state_snapshot(&direct).await;
    assert_eq!(version_after, schema::FRAGMENT_SCHEMA_VERSION);
    assert_eq!(
        rest_after, state_before.1,
        "only schema_version may have changed"
    );
    assert_eq!(
        fragment_trigger_snapshot(&direct).await,
        triggers_before,
        "no trigger definition or enablement may have changed"
    );
    let fence_enabled: String = direct
        .query_one(
            "SELECT tgenabled::text FROM pg_trigger WHERE tgname = 'lore_clean_state_permanent'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        fence_enabled, "A",
        "the permanent fence must be re-enabled ALWAYS"
    );

    assert!(coordinator.readiness().await.unwrap().ready_for_lifecycle());

    for (hash, context) in &seeded {
        let resolution = coordinator
            .resolve(&repository, context, std::slice::from_ref(hash))
            .await
            .unwrap();
        assert!(
            resolution[0].verdict.is_readable(),
            "pre-upgrade head {hash:?} must stay readable"
        );
    }

    // A REAL write-behind stage, drain and promotion through the coordinator:
    // proves the newly installed stage objects actually work, not just exist.
    stage_policy::initialize(&url, &coordinator).await;
    let staged_hash = random_hash();
    let BeginOutcome::Admitted(stage_intent) = coordinator
        .begin_stage(
            &staged_hash,
            StageReservationInput {
                size_payload: 128,
                original_flags: 0,
            },
        )
        .await
        .expect("begin stage on a fresh hash")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    let staged_manifest = manifest("cr039-upgrade-proof/staged", 0x33, EpochAuthority::Staged);
    assert_eq!(
        coordinator
            .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest))
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    let usage = coordinator.observe_stage().await.unwrap();
    assert_eq!(usage.resident_files, 1);

    let candidate = drain_candidate::candidate(&coordinator, &staged_hash).await;
    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&candidate, write_claim())
        .await
        .expect("begin promotion of the drained candidate")
    else {
        panic!("a Staged head must admit promotion");
    };
    let promotion_claim = promotion_intent
        .write_claim()
        .expect("promotion claim")
        .clone();
    coordinator
        .authorize_write_claim(&promotion_claim)
        .await
        .unwrap();
    let remote_manifest = manifest("cr039-upgrade-proof/remote", 0x34, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_promotion(
                &promotion_intent,
                IoObservation::Valid(remote_manifest),
                FragmentWriteSettlement::Decisive
            )
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    // No association was ever created for this hash, so readiness is checked
    // directly against the lifecycle head rather than through `resolve`
    // (which is association-scoped).
    let state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&staged_hash],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        state,
        lore_postgres::domain::fragments::FragmentLifecycleState::Remote.bits()
    );
}

// ---------------------------------------------------------------------------
// Resume.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn rerun_after_success_reports_already_current_and_writes_nothing_further() {
    let url = pg_url();
    let (store, direct) = revision4_clean_cell(&url).await;
    let coordinator = store.fragment_coordinator();
    assert_eq!(
        coordinator.upgrade_clean_schema().await.unwrap(),
        FragmentSchemaUpgradeOutcome::Upgraded { from_version: 4 }
    );
    let before = schema_state_snapshot(&direct).await;
    assert_eq!(
        coordinator.upgrade_clean_schema().await.unwrap(),
        FragmentSchemaUpgradeOutcome::AlreadyCurrent
    );
    let after = schema_state_snapshot(&direct).await;
    assert_eq!(before, after);
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn an_aborted_upgrade_transaction_leaves_the_cell_at_exact_revision_4_and_a_rerun_upgrades() {
    let url = pg_url();
    let (store, direct) = revision4_clean_cell(&url).await;
    let coordinator = store.fragment_coordinator();
    let before = schema_state_snapshot(&direct).await;

    // Simulate a crash between the DDL and the commit: run the identical
    // steps the upgrade performs, on their own connection and transaction,
    // then abandon it without committing (a dropped `Transaction` rolls
    // back). CR-039 relies on Postgres's transactional DDL to make an
    // interrupted upgrade safe; this pins that it still holds.
    let mut aborting = client(&url).await;
    let tx = aborting.transaction().await.unwrap();
    tx.batch_execute(
        "ALTER TABLE lore_fragment_schema_state DISABLE TRIGGER lore_clean_state_permanent",
    )
    .await
    .unwrap();
    tx.batch_execute(STAGE_CUSTODY_SCHEMA).await.unwrap();
    tx.batch_execute(STAGE_POLICY_ROTATION_SCHEMA)
        .await
        .unwrap();
    drop(tx);

    let after_abort = schema_state_snapshot(&direct).await;
    assert_eq!(
        before, after_abort,
        "an abandoned transaction must leave the cell untouched"
    );
    let stage_present: bool = direct
        .query_one(
            "SELECT to_regclass('lore_fragment_stage_policy') IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        !stage_present,
        "a rolled-back transaction must not leave stage objects behind"
    );

    assert_eq!(
        coordinator.upgrade_clean_schema().await.unwrap(),
        FragmentSchemaUpgradeOutcome::Upgraded { from_version: 4 }
    );
}

// ---------------------------------------------------------------------------
// Refusals, each by its own named reason.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn a_revision_5_catalog_is_refused_as_an_unknown_state() {
    let url = pg_url();
    let (store, direct) = revision4_clean_cell(&url).await;
    let coordinator = store.fragment_coordinator();
    direct
        .batch_execute(&format!(
            "ALTER TABLE lore_fragment_schema_state DISABLE TRIGGER lore_clean_state_permanent; \
             {STAGE_CUSTODY_SCHEMA} \
             UPDATE lore_fragment_schema_state SET schema_version = 5 WHERE id = 1; \
             ALTER TABLE lore_fragment_schema_state ENABLE ALWAYS TRIGGER lore_clean_state_permanent;"
        ))
        .await
        .unwrap();
    assert_refused(&coordinator, "unknown catalog state").await;
    let (version, _) = schema_state_snapshot(&direct).await;
    assert_eq!(
        version, 5,
        "a refused upgrade must not touch the recorded version"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn a_partial_stage_table_is_refused_as_an_unknown_state() {
    let url = pg_url();
    let (store, direct) = revision4_clean_cell(&url).await;
    let coordinator = store.fragment_coordinator();
    direct
        .batch_execute(
            "ALTER TABLE lore_fragment_schema_state DISABLE TRIGGER lore_clean_state_permanent; \
             CREATE TABLE lore_fragment_stage_policy (id smallint PRIMARY KEY); \
             ALTER TABLE lore_fragment_schema_state ENABLE ALWAYS TRIGGER lore_clean_state_permanent;",
        )
        .await
        .unwrap();
    assert_refused(&coordinator, "unknown catalog state").await;
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn a_staged_lifecycle_head_is_refused_by_name() {
    let url = pg_url();
    let (store, direct) = revision4_clean_cell(&url).await;
    let coordinator = store.fragment_coordinator();
    let hash = random_hash();
    let manifest_id = vec![7u8; 32];
    advance_fence_sequence(&direct).await;
    // A readable head (state 3, Staged) must have a matching epoch row or
    // `clean_readiness_holds` refuses first with a different message; this
    // insert satisfies that so the case actually reaches `refuse_staged_work`.
    direct
        .execute(
            "INSERT INTO lore_fragment_epochs (hash, epoch, authority, object_key, manifest_id, \
                    size_payload, size_content, decoded_hash, payload_flags, fence) \
             VALUES ($1, 1, 1, 'cr039-test/staged-key', $2, 128, 128, $3, 0, 1)",
            &[&hash, &manifest_id, &vec![8u8; 32]],
        )
        .await
        .unwrap();
    direct
        .execute(
            "INSERT INTO lore_fragment_lifecycle (hash, current_epoch, state, manifest_id, last_fence) \
             VALUES ($1, 1, 3, $2, 1)",
            &[&hash, &manifest_id],
        )
        .await
        .unwrap();
    assert_refused(&coordinator, "PreparingStage/Staged lifecycle head").await;
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn a_preparingstage_lifecycle_head_is_refused_by_name() {
    let url = pg_url();
    let (store, direct) = revision4_clean_cell(&url).await;
    let coordinator = store.fragment_coordinator();
    let hash = random_hash();
    advance_fence_sequence(&direct).await;
    direct
        .execute(
            "INSERT INTO lore_fragment_lifecycle (hash, current_epoch, state, last_fence) VALUES ($1, 1, 1, 1)",
            &[&hash],
        )
        .await
        .unwrap();
    assert_refused(&coordinator, "PreparingStage/Staged lifecycle head").await;
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn a_non_terminal_staged_reader_lease_is_refused_by_name() {
    let url = pg_url();
    let (store, direct) = revision4_clean_cell(&url).await;
    let coordinator = store.fragment_coordinator();
    advance_fence_sequence(&direct).await;
    direct
        .execute(
            "INSERT INTO lore_fragment_staged_leases (lease_id, reader_fence, deadline) \
             VALUES ($1, 1, clock_timestamp() + interval '1 hour')",
            &[&vec![9u8; 16]],
        )
        .await
        .unwrap();
    assert_refused(&coordinator, "non-terminal staged-reader lease").await;
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn a_disabled_fence_is_refused_by_name() {
    let url = pg_url();
    let (store, direct) = revision4_clean_cell(&url).await;
    let coordinator = store.fragment_coordinator();
    direct
        .execute(
            "ALTER TABLE lore_fragment_schema_state DISABLE TRIGGER lore_clean_state_permanent",
            &[],
        )
        .await
        .unwrap();
    assert_refused(&coordinator, "permanent fence missing or disabled").await;
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn a_non_clean_cell_is_refused_by_name() {
    let url = pg_url();
    let store = store_without_clean_init(&url).await;
    let coordinator = store.fragment_coordinator();
    assert_refused(&coordinator, "supports only a clean-initialized cell").await;
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn a_database_identity_mismatch_is_refused_by_name() {
    let url = pg_url();
    let (store, direct) = revision4_clean_cell(&url).await;
    let coordinator = store.fragment_coordinator();
    direct
        .batch_execute(
            "ALTER TABLE lore_fragment_schema_state DISABLE TRIGGER lore_clean_state_permanent; \
             UPDATE lore_fragment_schema_state SET database_identity = 'wrong-identity' WHERE id = 1; \
             ALTER TABLE lore_fragment_schema_state ENABLE ALWAYS TRIGGER lore_clean_state_permanent;",
        )
        .await
        .unwrap();
    assert_refused(&coordinator, "database identity mismatch").await;
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn a_live_lock_holder_refuses_with_contention_not_a_wait() {
    let url = pg_url();
    let (store, _direct) = revision4_clean_cell(&url).await;
    let coordinator = store.fragment_coordinator();
    let mut holder = client(&url).await;
    let tx = holder.transaction().await.unwrap();
    tx.batch_execute("LOCK TABLE lore_fragment_lifecycle IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let outcome = coordinator.upgrade_clean_schema().await;
    assert!(
        matches!(outcome, Err(DomainError::Contention(_))),
        "expected Contention while a live session holds a fragment table, got {outcome:?}"
    );
    tx.rollback().await.unwrap();
}

// ---------------------------------------------------------------------------
// Bootstrap.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn bootstrap_on_a_revision_4_clean_cell_returns_the_remedy_and_writes_nothing() {
    let url = pg_url();
    let (store, direct) = revision4_clean_cell(&url).await;
    let before = schema_state_snapshot(&direct).await;
    let stage_present_before: bool = direct
        .query_one(
            "SELECT to_regclass('lore_fragment_stage_policy') IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!stage_present_before);

    let error = store.fragment_coordinator().bootstrap().await.unwrap_err();
    let DomainError::NotReady(message) = error else {
        panic!("expected NotReady, got {error:?}")
    };
    assert!(message.contains("upgrade-fragments --confirm-replicas-stopped"));
    assert!(message.contains("revision 4"));

    let after = schema_state_snapshot(&direct).await;
    assert_eq!(before, after);
    let stage_present_after: bool = direct
        .query_one(
            "SELECT to_regclass('lore_fragment_stage_policy') IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!stage_present_after);
}

// ---------------------------------------------------------------------------
// Fresh == upgraded.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-schema-upgrade-live.ps1"]
async fn a_fresh_cell_and_an_upgraded_cell_have_an_identical_fragment_catalog() {
    let url = pg_url();
    let (store, direct) = revision4_clean_cell(&url).await;
    let coordinator = store.fragment_coordinator();
    assert_eq!(
        coordinator.upgrade_clean_schema().await.unwrap(),
        FragmentSchemaUpgradeOutcome::Upgraded { from_version: 4 }
    );
    let upgraded_fingerprint = fragment_catalog_fingerprint(&direct).await;

    let fresh_db = create_sibling_database(&url).await;
    let fresh_url = swap_database(&url, &fresh_db);
    // A plain `bootstrap()` alone is not the comparison CR-039 needs: the
    // clean-record triggers (`lore_clean_state_permanent` and its five
    // siblings) are installed only by `initialize_empty`, not by bootstrap,
    // so an upgraded cell (which went through clean-init before the
    // downgrade) would trivially mismatch a merely-bootstrapped one on
    // triggers alone. The fair comparison is clean cell vs clean cell.
    let (_fresh_store, fresh_direct) = revision6_clean_cell(&fresh_url).await;
    let fresh_fingerprint = fragment_catalog_fingerprint(&fresh_direct).await;

    // A raw `assert_eq!` on these strings produces an unreadable full-catalog
    // dump on failure; report the first differing byte and its context
    // instead, since that is what a real regression needs.
    if upgraded_fingerprint != fresh_fingerprint {
        fn boundary(s: &str, mut idx: usize) -> usize {
            idx = idx.min(s.len());
            while idx > 0 && !s.is_char_boundary(idx) {
                idx -= 1;
            }
            idx
        }
        let mismatch = upgraded_fingerprint
            .bytes()
            .zip(fresh_fingerprint.bytes())
            .position(|(a, b)| a != b)
            .unwrap_or(upgraded_fingerprint.len().min(fresh_fingerprint.len()));
        let window = 150;
        let u_start = boundary(&upgraded_fingerprint, mismatch.saturating_sub(window));
        let u_end = boundary(&upgraded_fingerprint, mismatch + window);
        let f_start = boundary(&fresh_fingerprint, mismatch.saturating_sub(window));
        let f_end = boundary(&fresh_fingerprint, mismatch + window);
        panic!(
            "fragment catalog fingerprints diverge at byte {mismatch} (upgraded len {}, fresh len \
             {})\nupgraded: ...{}...\nfresh:    ...{}...",
            upgraded_fingerprint.len(),
            fresh_fingerprint.len(),
            &upgraded_fingerprint[u_start..u_end],
            &fresh_fingerprint[f_start..f_end]
        );
    }
}
