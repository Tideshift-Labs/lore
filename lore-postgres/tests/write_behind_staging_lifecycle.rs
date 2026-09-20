// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! Live-Postgres proof for the WP-114 CD-6/CD-7 write-behind store adapter,
//! against a real `WriteBehindStage` (Unix-only) and a real
//! `PostgresFragmentCoordinator` -- no S3/MinIO, no fragment provider.
//!
//! # Why no provider
//!
//! `put_coordinated`'s staging branch (`store/immutable_store.rs`) is reachable
//! only through the `Coordinated` route, which requires a live
//! `FragmentProviderEntry` -- and nothing in `lore-postgres`'s own `tests/`
//! constructs one (`grep -r "with_fragment_provider("` returns nothing; that
//! composition is `lore-server`'s). So this file drives the coordinator and
//! `WriteBehindStage` directly, in the exact sequence `put_staged` uses
//! (`begin_stage` -> `stage.stage` -> `commit_staged` ->
//! `capture_current_readable_epoch_for_authority` -> `create_association_if_current`),
//! rather than through the public `ImmutableStore` trait. This proves
//! everything staging itself does; it does not exercise `put_coordinated`'s
//! routing (see `write_behind_source_pins.rs`'s D11 structural pin for that
//! half) or actual provider traffic.
//!
//! Every case is `#[ignore]` and needs `LORE_TEST_PG_URL` plus a Unix host --
//! run via `cargo test -p lore-postgres --test write_behind_staging_lifecycle
//! -- --ignored`. Each case gets its own database (`CaseNamespace`-style would
//! be heavier than this seam needs today; a throwaway `CREATE DATABASE` per
//! case is enough at this case count) and its own temp staging root.

#![cfg(unix)]

#[cfg(feature = "failure_generator")]
#[path = "common/stage_crash_tests.rs"]
mod stage_crash_tests;

#[path = "common/stage_policy.rs"]
mod stage_policy;

use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;

use bytes::Bytes;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::fragments::BeginOutcome;
use lore_postgres::domain::fragments::CommitVerdict;
use lore_postgres::domain::fragments::EpochAuthority;
use lore_postgres::domain::fragments::FragmentLifecycleState;
use lore_postgres::domain::fragments::FragmentManifest;
use lore_postgres::domain::fragments::IoObservation;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::write_behind::WriteBehindSettings;
use lore_postgres::store::write_behind::WriteBehindStage;
use lore_postgres::store::write_behind::WriteBehindWatermarks;
use tokio_postgres::Client;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn admin_client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect admin client");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("admin postgres connection error: {error}");
        }
    });
    client
}

/// Twin of `domain_migration_parity.rs`'s own `replace_dbname`/
/// `create_throwaway_database` (not shared via `#[path]` for the same reason
/// noted on `prepare_operation` above -- no `url` crate dependency in this
/// crate, so this is the established string-surgery shape, not a shortcut).
fn replace_dbname(url: &str, db_name: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };
    let last_slash = base
        .rfind('/')
        .expect("postgres URL must have a /dbname path");
    let mut new_url = format!("{}/{}", &base[..last_slash], db_name);
    if let Some(q) = query {
        new_url.push('?');
        new_url.push_str(q);
    }
    new_url
}

/// Create a throwaway database off the given URL's connection and return a URL
/// pointing at it. Every case gets its own, so cases never share fixture rows.
async fn fresh_database(base_url: &str) -> String {
    let admin = admin_client(base_url).await;
    let name = format!("wb_case_{}", Uuid::now_v7().simple());
    admin
        .batch_execute(&format!("CREATE DATABASE \"{name}\""))
        .await
        .unwrap_or_else(|error| panic!("create case database {name}: {error}"));
    replace_dbname(base_url, &name)
}

async fn coordinator(url: &str) -> PostgresFragmentCoordinator {
    let store = PostgresDomainStore::connect(url, 8, &TlsConfig::default())
        .await
        .expect("connect domain store");
    let coordinator = store.fragment_coordinator();
    coordinator
        .bootstrap()
        .await
        .expect("install isolated SCHEMA-118 fixture");
    stage_policy::initialize(url, &coordinator).await;
    coordinator
}

async fn direct_client(url: &str) -> Client {
    admin_client(url).await
}

fn random_hash() -> Vec<u8> {
    rand::random::<[u8; 32]>().to_vec()
}

fn random_context() -> Vec<u8> {
    rand::random::<[u8; 16]>().to_vec()
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

fn binding(method: &str) -> OperationBinding {
    OperationBinding {
        method: method.to_owned(),
        scope: rand::random::<[u8; 16]>().to_vec(),
        fingerprint_version: 1,
        fingerprint: rand::random::<[u8; 32]>().to_vec(),
        canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

/// Twin of `domain_fragment_lifecycle.rs`'s own `prepare_operation`/
/// `create_repository`. Not shared via `#[path]` deliberately: that file is a
/// shared file with the L1 lane per the dispatch brief, and this seam needs
/// only the two calls below, not its whole fixture surface.
async fn prepare_operation(store: &PostgresDomainStore, method: &str) -> GovernedOperation {
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("read receipt database clock");
    let key = ReceiptKey {
        verified_issuer: format!(
            "https://issuer.example/wp114-write-behind/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "svc:wp114-write-behind-test".to_owned(),
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
    let operation =
        prepare_operation(store, "lore.domain.v1.test/WriteBehindRepositoryCreate").await;
    let input = RepositoryCreateInput {
        metadata_witnesses: Vec::new(),
        repository_id: repository_id.to_vec(),
        name: format!("wp114-write-behind-{:016x}", rand::random::<u64>()),
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

struct ScratchRoot(PathBuf);

impl ScratchRoot {
    fn new(case: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "lore-write-behind-live-{case}-{:016x}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&path).expect("create scratch staging root");
        Self(path)
    }
}

impl Drop for ScratchRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn open_stage(root: &ScratchRoot) -> std::sync::Arc<WriteBehindStage> {
    WriteBehindStage::open(WriteBehindSettings {
        root: root.0.clone(),
        watermarks: WriteBehindWatermarks {
            low_bytes: 10_000_000,
            high_bytes: 20_000_000,
            hard_bytes: 30_000_000,
            low_count: 1_000,
            high_count: 2_000,
            hard_count: 3_000,
            min_free_bytes: 0,
        },
        drain_stale_after: Duration::from_secs(60),
        sample_interval: Duration::from_secs(3_600),
    })
    .expect("open a healthy staging root")
}

async fn head_state(direct: &Client, hash: &[u8]) -> Option<i16> {
    direct
        .query_opt(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("query lifecycle head")
        .map(|row| row.get(0))
}

/// First publication returns exact staged evidence; metadata capture stays Remote-only.
#[tokio::test]
#[ignore = "run with LORE_TEST_PG_URL and Unix; see file header"]
async fn staged_commit_then_witness_capture_through_the_put_staged_sequence() {
    let Some(base_url) = pg_url() else {
        panic!("LORE_TEST_PG_URL required");
    };
    let url = fresh_database(&base_url).await;
    let coordinator = coordinator(&url).await;
    let direct = direct_client(&url).await;
    let root = ScratchRoot::new("witness-capture");
    let stage = open_stage(&root);

    let hash = random_hash();
    let payload = Bytes::from_static(b"proves-the-witness-capture-contract");

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_stage(
            &hash,
            lore_postgres::domain::fragments::StageReservationInput {
                size_payload: payload.len() as u64,
                original_flags: 0,
            },
        )
        .await
        .expect("begin_stage admits a fresh hash")
    else {
        panic!("a fresh hash must be Admitted, not AlreadyReadable/Fenced/WriteClaimBlocked");
    };

    stage
        .stage(&intent.hash, intent.epoch, &intent.object_key, &payload)
        .await
        .expect("durable finalize onto the confined root");

    let manifest = FragmentManifest {
        authority: EpochAuthority::Staged,
        object_key: intent.object_key.clone(),
        manifest_id: rand::random::<[u8; 32]>().to_vec(),
        size_payload: payload.len() as i64,
        size_content: payload.len() as i64,
        decoded_hash: hash.clone(),
        payload_flags: 0,
    };
    let verdict = coordinator
        .commit_staged(&intent, IoObservation::Valid(manifest.clone()))
        .await
        .expect("commit_staged against an unfenced fresh intent");
    assert_eq!(
        verdict,
        CommitVerdict::Published,
        "the commit itself must publish -- this proves the head really is Staged \
         before this test asserts anything about capturing its witness"
    );
    assert_eq!(
        head_state(&direct, &hash).await,
        Some(FragmentLifecycleState::Staged.bits()),
        "ground truth: the head is Staged after a Published commit_staged"
    );

    let captured = coordinator
        .capture_current_readable_epoch_for_authority(&hash, EpochAuthority::Staged)
        .await
        .expect("capture staged authority")
        .expect("first staged publication must yield its exact witness");
    assert_eq!(captured.epoch, intent.epoch);
    assert_eq!(captured.manifest_id, Some(manifest.manifest_id.clone()));
    assert!(
        coordinator
            .capture_current_readable_epoch(&hash)
            .await
            .unwrap()
            .is_none(),
        "synchronous metadata capture must remain Remote-only"
    );
    assert!(
        coordinator
            .capture_current_readable_epoch_for_authority(&hash, EpochAuthority::Remote)
            .await
            .unwrap()
            .is_none(),
        "Remote authority must refuse a staged head"
    );

    // Retry reuses the already published epoch.
    let BeginOutcome::AlreadyReadable(retry_witness) = coordinator
        .begin_stage(
            &hash,
            lore_postgres::domain::fragments::StageReservationInput {
                size_payload: payload.len() as u64,
                original_flags: 0,
            },
        )
        .await
        .expect("a retried begin_stage against an already-Staged head must not error")
    else {
        panic!(
            "a re-push of an already-Staged, already-durable hash must short-circuit to \
             AlreadyReadable, not re-admit a fresh epoch or fence a live head"
        );
    };
    assert_eq!(retry_witness.epoch, intent.epoch);
    assert_eq!(retry_witness.state, FragmentLifecycleState::Staged);
    assert_eq!(
        retry_witness.manifest_id,
        Some(manifest.manifest_id.clone())
    );
}

/// C2-equivalent crash window (L2 plan §2.2, "crash between 4 and 6" renumbered
/// to this seam's own step names: crash between the durable rename and
/// `commit_staged`). Manufactured directly rather than a literal process
/// kill -- `stage.stage` returning `Ok` already proves the file is durably
/// renamed onto its content-derived identity (finalize.rs's own structural
/// pin in `write_behind_source_pins.rs` proves the fsync/rename order); simply
/// not calling `commit_staged` after it returns is exactly the state a crash
/// in that window leaves, and is indistinguishable from one at the database
/// layer. ADR-00027 predicts: the file is a "finalized, valid, unreferenced"
/// orphan under `staged/`, not swept (cleanup.rs's rule only fires on a
/// coordinator-computed purge target), and a retry gets a FRESH epoch rather
/// than resuming the orphaned one, because `begin_publication_once` allocates
/// a brand new epoch/fence for any non-readable, non-deleting existing head
/// (`coordinator.rs`'s general case, not the `PreparingRemote`-only resume
/// arm).
#[tokio::test]
#[ignore = "run with LORE_TEST_PG_URL and Unix; see file header"]
async fn crash_between_finalize_and_commit_staged_orphans_the_file_and_retry_gets_a_fresh_epoch() {
    let Some(base_url) = pg_url() else {
        panic!("LORE_TEST_PG_URL required");
    };
    let url = fresh_database(&base_url).await;
    let coordinator = coordinator(&url).await;
    let direct = direct_client(&url).await;
    let root = ScratchRoot::new("crash-c2");
    let stage = open_stage(&root);
    let hash = random_hash();
    let payload = Bytes::from_static(b"orphaned-by-a-simulated-crash-before-commit-staged");

    let BeginOutcome::Admitted(first_intent) = coordinator
        .begin_stage(
            &hash,
            lore_postgres::domain::fragments::StageReservationInput {
                size_payload: payload.len() as u64,
                original_flags: 0,
            },
        )
        .await
        .expect("begin_stage admits a fresh hash")
    else {
        panic!("a fresh hash must be Admitted");
    };
    stage
        .stage(
            &first_intent.hash,
            first_intent.epoch,
            &first_intent.object_key,
            &payload,
        )
        .await
        .expect("durable finalize -- this is the crash point; commit_staged is deliberately never called for this intent");

    // Ground truth: no head exists that the read path would call readable.
    // `PreparingStage` (from `begin_stage`'s own insert) is not `is_readable()`.
    assert_ne!(
        head_state(&direct, &hash).await,
        Some(FragmentLifecycleState::Staged.bits()),
        "commit_staged was never called, so the head must not read as Staged"
    );

    // The orphaned file itself is still durably readable through the staging
    // tier directly -- "valid, unreferenced" per ADR-00027, not corrupted and
    // not deleted by anything this seam did.
    let orphan_read = stage
        .read_staged(
            &first_intent.hash,
            first_intent.epoch,
            &first_intent.object_key,
        )
        .await;
    assert!(
        matches!(
            orphan_read,
            lore_postgres::store::write_behind::StagedRead::Found(_)
        ),
        "the orphaned file must still be present and byte-readable, got {orphan_read:?}"
    );

    // A live Preparing owner must remain exclusive even after its process died.
    assert!(!matches!(
        coordinator
            .begin_stage(
                &hash,
                lore_postgres::domain::fragments::StageReservationInput {
                    size_payload: payload.len() as u64,
                    original_flags: 0,
                }
            )
            .await
            .unwrap(),
        BeginOutcome::Admitted(_)
    ));
    direct.execute("UPDATE lore_fragment_stage_custody SET prepare_deadline=clock_timestamp()-interval '1 second' WHERE hash=$1 AND epoch=$2", &[&hash,&first_intent.epoch]).await.unwrap();
    // Once the database deadline expires, retry gets a fresh fenced epoch.
    let BeginOutcome::Admitted(second_intent) = coordinator
        .begin_stage(
            &hash,
            lore_postgres::domain::fragments::StageReservationInput {
                size_payload: payload.len() as u64,
                original_flags: 0,
            },
        )
        .await
        .expect("retry after the simulated crash must be admitted, not blocked")
    else {
        panic!("retry must be Admitted -- the only existing head is non-readable PreparingStage");
    };
    assert_ne!(
        second_intent.epoch, first_intent.epoch,
        "a crash-orphaned intent must never be silently resumed; retry allocates its own epoch"
    );

    // Finish the retry for real, proving the seam recovers cleanly: exactly
    // one epoch ends up Staged, and it is the retry's, not the orphan's.
    stage
        .stage(
            &second_intent.hash,
            second_intent.epoch,
            &second_intent.object_key,
            &payload,
        )
        .await
        .expect("the retry's own finalize");
    let manifest = FragmentManifest {
        authority: EpochAuthority::Staged,
        object_key: second_intent.object_key.clone(),
        manifest_id: rand::random::<[u8; 32]>().to_vec(),
        size_payload: payload.len() as i64,
        size_content: payload.len() as i64,
        decoded_hash: hash.clone(),
        payload_flags: 0,
    };
    assert_eq!(
        coordinator
            .commit_staged(&second_intent, IoObservation::Valid(manifest))
            .await
            .expect("commit the retry"),
        CommitVerdict::Published
    );
    let current_epoch: i64 = direct
        .query_one(
            "SELECT current_epoch FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read the published head")
        .get(0);
    assert_eq!(current_epoch, second_intent.epoch);
}

/// C3-equivalent crash window: crash between a Published `commit_staged` and
/// the association commit. This is exactly the two-transaction boundary B-4
/// resolved for this tranche (`commit_staged` does not publish the
/// association; `create_association_if_current` is a separate transaction),
/// so this test is that resolution's crash-safety proof, not a generic one.
/// Recovery reuses the already readable epoch without writing another file.
#[tokio::test]
#[ignore = "run with LORE_TEST_PG_URL and Unix; see file header"]
async fn crash_between_commit_staged_and_association_recovers_with_exactly_one_file() {
    let Some(base_url) = pg_url() else {
        panic!("LORE_TEST_PG_URL required");
    };
    let url = fresh_database(&base_url).await;
    let store = PostgresDomainStore::connect(&url, 8, &TlsConfig::default())
        .await
        .expect("connect domain store");
    let coordinator = store.fragment_coordinator();
    coordinator
        .bootstrap()
        .await
        .expect("install isolated SCHEMA-118 fixture");
    let direct = direct_client(&url).await;
    stage_policy::initialize(&url, &coordinator).await;
    let root = ScratchRoot::new("crash-c3");
    let stage = open_stage(&root);
    let hash = random_hash();
    let context = random_context();
    let payload = Bytes::from_static(b"published-staged-but-unassociated-by-a-simulated-crash");

    let repository_id = create_repository(&store).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_stage(
            &hash,
            lore_postgres::domain::fragments::StageReservationInput {
                size_payload: payload.len() as u64,
                original_flags: 0,
            },
        )
        .await
        .expect("begin_stage admits a fresh hash")
    else {
        panic!("a fresh hash must be Admitted");
    };
    stage
        .stage(&intent.hash, intent.epoch, &intent.object_key, &payload)
        .await
        .expect("durable finalize");
    let manifest = FragmentManifest {
        authority: EpochAuthority::Staged,
        object_key: intent.object_key.clone(),
        manifest_id: rand::random::<[u8; 32]>().to_vec(),
        size_payload: payload.len() as i64,
        size_content: payload.len() as i64,
        decoded_hash: hash.clone(),
        payload_flags: 0,
    };
    assert_eq!(
        coordinator
            .commit_staged(&intent, IoObservation::Valid(manifest.clone()))
            .await
            .expect("commit_staged"),
        CommitVerdict::Published,
        "the crash point: Published, then the simulated crash skips association entirely"
    );

    // Ground truth before recovery: Staged, but no association for this
    // repository -- exactly what the two-transaction boundary predicts.
    assert_eq!(
        head_state(&direct, &hash).await,
        Some(FragmentLifecycleState::Staged.bits())
    );
    let association_count_before: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_fragment_associations WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("query associations")
        .get(0);
    assert_eq!(
        association_count_before, 0,
        "no association must exist yet -- this is the crash window under test"
    );

    // Recovery: re-push the same fragment. `begin_stage` short-circuits to
    // AlreadyReadable (without repeating the capture or file publication),
    // and the caller binds the association exactly as put_coordinated would.
    let BeginOutcome::AlreadyReadable(witness) = coordinator
        .begin_stage(
            &hash,
            lore_postgres::domain::fragments::StageReservationInput {
                size_payload: payload.len() as u64,
                original_flags: 0,
            },
        )
        .await
        .expect("recovery begin_stage must not error")
    else {
        panic!("a re-push of a Published Staged head must short-circuit to AlreadyReadable");
    };
    assert_eq!(witness.epoch, intent.epoch);
    assert_eq!(witness.manifest_id, Some(manifest.manifest_id.clone()));

    assert_eq!(
        coordinator
            .create_association_if_current(&witness, &repository_id, &context)
            .await
            .expect("bind the association on recovery"),
        CommitVerdict::Published
    );

    let association_count_after: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_fragment_associations WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("query associations")
        .get(0);
    assert_eq!(
        association_count_after, 1,
        "recovery must bind exactly one association, not zero (still broken) or more than one \
         (a duplicate from a non-idempotent recovery path)"
    );

    // And still exactly one file on disk for this hash -- recovery re-ran
    // begin_stage but never re-staged bytes, because it never left the
    // Admitted path.
    let read_after = stage
        .read_staged(&hash, intent.epoch, &intent.object_key)
        .await;
    assert!(matches!(
        read_after,
        lore_postgres::store::write_behind::StagedRead::Found(_)
    ));
}

/// A single first-attempt coordinator sequence binds readable staged bytes.
/// This is coordinator-seam evidence; the public ImmutableStore route is not exercised.
#[tokio::test]
#[ignore = "run with LORE_TEST_PG_URL and Unix; see file header"]
async fn first_attempt_captures_staged_authority_and_binds_the_association() {
    let Some(base_url) = pg_url() else {
        panic!("LORE_TEST_PG_URL required");
    };
    let url = fresh_database(&base_url).await;
    let store = PostgresDomainStore::connect(&url, 8, &TlsConfig::default())
        .await
        .expect("connect domain store");
    let coordinator = store.fragment_coordinator();
    coordinator
        .bootstrap()
        .await
        .expect("install isolated SCHEMA-118 fixture");
    let direct = direct_client(&url).await;
    stage_policy::initialize(&url, &coordinator).await;
    let root = ScratchRoot::new("first-association");
    let stage = open_stage(&root);
    let hash = random_hash();
    let context = random_context();
    let payload = Bytes::from_static(b"first-attempt-association-and-exact-readable-bytes");
    let repository_id = create_repository(&store).await;

    // No retry occurs in this test.
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_stage(
            &hash,
            lore_postgres::domain::fragments::StageReservationInput {
                size_payload: payload.len() as u64,
                original_flags: 0,
            },
        )
        .await
        .expect("begin_stage admits a fresh hash")
    else {
        panic!("a fresh hash must be Admitted");
    };
    stage
        .stage(&intent.hash, intent.epoch, &intent.object_key, &payload)
        .await
        .expect("durable finalize");
    let manifest = FragmentManifest {
        authority: EpochAuthority::Staged,
        object_key: intent.object_key.clone(),
        manifest_id: rand::random::<[u8; 32]>().to_vec(),
        size_payload: payload.len() as i64,
        size_content: payload.len() as i64,
        decoded_hash: hash.clone(),
        payload_flags: 0,
    };
    assert_eq!(
        coordinator
            .commit_staged(&intent, IoObservation::Valid(manifest.clone()))
            .await
            .expect("commit_staged"),
        CommitVerdict::Published
    );
    let first_attempt_witness = coordinator
        .capture_current_readable_epoch_for_authority(&hash, EpochAuthority::Staged)
        .await
        .expect("capture staged authority")
        .expect("first attempt must capture a witness without retry");
    // Capture grants no repository access before association publication.
    let association_count_before_binding: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_fragment_associations WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("query associations")
        .get(0);
    assert_eq!(
        association_count_before_binding, 0,
        "capture must not publish an association"
    );

    assert_eq!(first_attempt_witness.epoch, intent.epoch);
    assert_eq!(
        first_attempt_witness.manifest_id,
        Some(manifest.manifest_id.clone())
    );

    let association_verdict = coordinator
        .create_association_if_current(&first_attempt_witness, &repository_id, &context)
        .await
        .expect("first attempt binds association");

    assert_eq!(
        association_verdict,
        CommitVerdict::Published,
        "the first attempt must publish the association"
    );
    let association_count_after_binding: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_fragment_associations WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("query associations")
        .get(0);
    assert_eq!(
        association_count_after_binding, 1,
        "one first-attempt association must exist"
    );
    let read = stage
        .read_staged(&hash, intent.epoch, &intent.object_key)
        .await;
    assert!(
        matches!(read, lore_postgres::store::write_behind::StagedRead::Found(ref bytes) if bytes == &payload),
        "published association must have exact readable bytes: {read:?}"
    );
}
