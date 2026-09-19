// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Real-Postgres proof for the L1 seam (WP-114/WP-115 write-behind tranche):
//! the durable promotion send claim in the fragments coordinator.
//!
//! Every case is `#[ignore]` and is executed by
//! `run-fragment-lifecycle-live.ps1`, which gives each exact case a fresh
//! PostgreSQL 16 database. Offline pins (DDL, `FragmentWriteClaimKind`,
//! the `ready_for_lifecycle` schema-version-4 guardrail) live in
//! `fragment_write_claim_schema.rs`.
//!
//! # API surface (confirmed against the landed implementation and frozen by
//! # the dispatching session)
//!
//! ```text
//! begin_promotion(&self, hash: &[u8], claim: FragmentWriteClaimInput) -> Result<BeginOutcome, DomainError>
//! commit_promotion(&self, intent: &FragmentIntent, observation: IoObservation, settlement: FragmentWriteSettlement) -> Result<CommitVerdict, DomainError>
//! ```
//!
//! No `FragmentPromotionClaimInput` wrapper exists. This file originally
//! guessed that from the plan's own text (the staged source witness is
//! captured from the locked head, not supplied by the caller, so a wrapper
//! would have nothing to wrap) and the ruling confirmed it independently.
//!
//! # A contract question this file raised, now resolved
//!
//! Plan section 4c recommended restricting the new hash-wide promotion
//! barrier to `kind = 1` (Promotion) rows. The fresh reviewer's required case
//! 1 (below) demands the opposite: an object-key barrier blocking *every*
//! claim kind at the shared `legacy_hash_key`, both directions -- and per the
//! ruling this is intentional, not a bug: the hazard is two live conditional
//! PUTs at one key, not two promotions, so the discriminator is `object_key`,
//! not `kind`. The shipped `write_claim_barrier_locked` is a union of the
//! lineage-scoped predicate (still needed for a `PreparingRemote` resume) and
//! an object-key predicate that is not gated by kind. This file tests that
//! shipped shape.
//!
//! # abandon_promotion: settlement is decided by the claim, not the caller
//!
//! `commit_promotion`'s `settlement` argument is IGNORED on the
//! `IoObservation::Unusable` (abandon) path. Abandon settles by the claim's
//! own durable state: `Sending -> Ambiguous`, `Prepared -> NoSend`, and a
//! claim already terminal is left alone. A case asserting one settlement
//! unconditionally on every abandon path is wrong; this file covers both
//! reachable transitions as distinct cases.

use std::time::Duration;
use std::time::SystemTime;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::fragments::BeginOutcome;
use lore_postgres::domain::fragments::CommitVerdict;
use lore_postgres::domain::fragments::EpochAuthority;
use lore_postgres::domain::fragments::FragmentManifest;
use lore_postgres::domain::fragments::FragmentObliterateBegin;
use lore_postgres::domain::fragments::FragmentObliteratePhase;
use lore_postgres::domain::fragments::FragmentPurgeTarget;
use lore_postgres::domain::fragments::FragmentWriteCapabilityCutover;
use lore_postgres::domain::fragments::FragmentWriteClaim;
use lore_postgres::domain::fragments::FragmentWriteClaimInput;
use lore_postgres::domain::fragments::FragmentWriteClaimState;
use lore_postgres::domain::fragments::FragmentWriteSettlement;
use lore_postgres::domain::fragments::IoObservation;
use lore_postgres::domain::fragments::MissingDiagnostic;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::domain::fragments::schema;
use lore_postgres::domain::fragments::states::FragmentLifecycleState;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

const TEST_PROVIDER_WRITE_AUTHORITY_REVISION: &str = "write-claims-v1";

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn authority_capture_requires_exact_current_eligible_epoch_evidence() {
    let url = pg_url().expect("runner must set LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    for authority in [EpochAuthority::Staged, EpochAuthority::Remote] {
        let hash = random_hash();
        assert!(
            coordinator
                .capture_current_readable_epoch_for_authority(&hash, authority)
                .await
                .unwrap()
                .is_none(),
            "absent head"
        );
        let (epoch, manifest) = stage_hash(&coordinator, &hash, 0x53).await;
        // Relabel both sides together for the Remote capture fixture. No I/O
        // behavior is claimed here; this test isolates SQL evidence matching.
        direct
            .execute(
                "UPDATE lore_fragment_lifecycle SET state=$2 WHERE hash=$1",
                &[&hash, &authority.readable_state().bits()],
            )
            .await
            .unwrap();
        direct
            .execute(
                "UPDATE lore_fragment_epochs SET authority=$2 WHERE hash=$1",
                &[&hash, &authority.bits()],
            )
            .await
            .unwrap();
        let positive = coordinator
            .capture_current_readable_epoch_for_authority(&hash, authority)
            .await
            .unwrap()
            .expect("matching current evidence");
        assert_eq!(positive.epoch, epoch);
        assert_eq!(positive.manifest_id, Some(manifest.manifest_id.clone()));
        let opposite = if authority == EpochAuthority::Staged {
            EpochAuthority::Remote
        } else {
            EpochAuthority::Staged
        };
        assert!(
            coordinator
                .capture_current_readable_epoch_for_authority(&hash, opposite)
                .await
                .unwrap()
                .is_none(),
            "wrong head authority"
        );
        assert_eq!(
            coordinator
                .capture_current_readable_epoch(&hash)
                .await
                .unwrap()
                .is_some(),
            authority == EpochAuthority::Remote,
            "metadata helper remains Remote-only"
        );

        for (damage, restore) in [
            (
                "UPDATE lore_fragment_epochs SET epoch=epoch+100000 WHERE hash=$1",
                "UPDATE lore_fragment_epochs SET epoch=epoch-100000 WHERE hash=$1",
            ),
            (
                "UPDATE lore_fragment_epochs SET manifest_id=decode(repeat('ff',32),'hex') WHERE hash=$1",
                "UPDATE lore_fragment_epochs SET manifest_id=(SELECT manifest_id FROM lore_fragment_lifecycle WHERE hash=$1) WHERE hash=$1",
            ),
            (
                "UPDATE lore_fragment_epochs SET authority=3-authority WHERE hash=$1",
                "UPDATE lore_fragment_epochs SET authority=3-authority WHERE hash=$1",
            ),
            (
                "UPDATE lore_fragment_epochs SET disposition=1 WHERE hash=$1",
                "UPDATE lore_fragment_epochs SET disposition=0 WHERE hash=$1",
            ),
            (
                "UPDATE lore_fragment_epochs SET disposition=2 WHERE hash=$1",
                "UPDATE lore_fragment_epochs SET disposition=0 WHERE hash=$1",
            ),
        ] {
            direct
                .execute(damage, &[&hash])
                .await
                .expect("damage isolated epoch evidence");
            assert!(
                coordinator
                    .capture_current_readable_epoch_for_authority(&hash, authority)
                    .await
                    .unwrap()
                    .is_none(),
                "must refuse {authority:?}: {damage}"
            );
            direct
                .execute(restore, &[&hash])
                .await
                .expect("restore evidence");
            assert!(
                coordinator
                    .capture_current_readable_epoch_for_authority(&hash, authority)
                    .await
                    .unwrap()
                    .is_some(),
                "control after {damage}"
            );
        }
        direct
            .execute("DELETE FROM lore_fragment_epochs WHERE hash=$1", &[&hash])
            .await
            .unwrap();
        assert!(
            coordinator
                .capture_current_readable_epoch_for_authority(&hash, authority)
                .await
                .unwrap()
                .is_none(),
            "missing epoch row"
        );
        direct
            .execute(
                "UPDATE lore_fragment_lifecycle SET state=$2,manifest_id=NULL WHERE hash=$1",
                &[&hash, &FragmentLifecycleState::Missing.bits()],
            )
            .await
            .unwrap();
        assert!(
            coordinator
                .capture_current_readable_epoch_for_authority(&hash, authority)
                .await
                .unwrap()
                .is_none(),
            "unreadable head"
        );
    }
}

// ---------------------------------------------------------------------------
// Helpers (self-contained: this file is its own compiled test binary, so
// these deliberately mirror rather than share `domain_fragment_lifecycle.rs`'s
// helpers of the same name).
// ---------------------------------------------------------------------------

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn store(url: &str) -> PostgresDomainStore {
    let store = PostgresDomainStore::connect(url, 8, &TlsConfig::default())
        .await
        .expect("connect domain store");
    store
        .fragment_coordinator()
        .bootstrap()
        .await
        .expect("install isolated SCHEMA-118 fixture");
    store
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

/// A fresh write-claim input, generous deadlines by default so a case only
/// races the clock deliberately.
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

/// A write-claim input with a short send window and late-effect bound, so a
/// case can wait it out in real time rather than needing a clock-mocking
/// seam this coordinator deliberately has none of (every deadline is a
/// database-clock read).
fn short_lived_write_claim() -> FragmentWriteClaimInput {
    FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        [0x5A; 32],
        1,
        Duration::from_millis(1),
        Duration::from_millis(1),
    )
    .expect("valid short-lived test write claim")
}

/// Stage and publish a hash so its head is `Staged` and eligible for
/// promotion. Returns the staged epoch and manifest.
async fn stage_hash(
    coordinator: &PostgresFragmentCoordinator,
    hash: &[u8],
    seed: u8,
) -> (i64, FragmentManifest) {
    let BeginOutcome::Admitted(stage_intent) = coordinator
        .begin_stage(hash)
        .await
        .expect("begin stage on a fresh hash")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    let staged_manifest = manifest("promotion-claim/staged", seed, EpochAuthority::Staged);
    assert_eq!(
        coordinator
            .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest.clone()))
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    (stage_intent.epoch, staged_manifest)
}

/// Directly insert one write-claim row, bypassing the coordinator's own
/// admission path. Used only to construct a fixture the ordinary API cannot
/// reach quickly (a claim of a chosen kind/state sitting at a chosen object
/// key), exactly like this suite's siblings raw-insert lifecycle/epoch rows.
#[allow(clippy::too_many_arguments)]
async fn insert_raw_claim(
    direct: &Client,
    hash: &[u8],
    epoch: i64,
    fence: i64,
    object_key: &str,
    kind: i16,
    state: i16,
) {
    assert_eq!(
        kind, 0,
        "promotion fixtures must use begin_promotion to bind source evidence"
    );
    let logical_request_id = rand::random::<[u8; 16]>();
    let attempt_id = rand::random::<[u8; 16]>();
    let hard_not_after = SystemTime::now() + Duration::from_secs(3600);
    let send_not_after = SystemTime::now() + Duration::from_secs(1800);
    let (authorized_at, settled_at): (Option<SystemTime>, Option<SystemTime>) = match state {
        0 => (None, None),
        1 => (Some(SystemTime::now()), None),
        _ => (Some(SystemTime::now()), Some(SystemTime::now())),
    };
    direct
        .execute(
            "INSERT INTO lore_fragment_write_claims ( \
                 logical_request_id, attempt_id, hash, epoch, fence, authority, object_key, \
                 body_blake3, body_size, state, send_not_after, hard_not_after, prepared_at, \
                 authorized_at, settled_at, kind \
             ) VALUES ($1, $2, $3, $4, $5, 2, $6, $7, 1, $8, $9, $10, clock_timestamp(), \
                       $11, $12, $13)",
            &[
                &logical_request_id.as_slice(),
                &attempt_id.as_slice(),
                &hash,
                &epoch,
                &fence,
                &object_key,
                &vec![0xEE_u8; 32],
                &state,
                &send_not_after,
                &hard_not_after,
                &authorized_at,
                &settled_at,
                &kind,
            ],
        )
        .await
        .expect("insert raw write-claim fixture (needs the `kind` column landed)");
}

fn random_context() -> Vec<u8> {
    rand::random::<[u8; 16]>().to_vec()
}

/// A write-claim input with a short send window but a long late-effect
/// bound, decoupling the two horizons. The union barrier's per-state split
/// blocks a `Prepared` claim on `send_not_after` alone, so this is what makes
/// "past its send window but nowhere near its hard deadline" reachable.
fn short_send_long_late_effect_write_claim() -> FragmentWriteClaimInput {
    FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        [0xC1; 32],
        1,
        Duration::from_millis(50),
        Duration::from_secs(60),
    )
    .expect("valid short-send-window test write claim")
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

/// Prepare one admissible receipt for a CR-029 domain-level operation.
/// Mirrors `domain_fragment_lifecycle.rs`'s helper of the same name -- this
/// file is its own compiled test binary, so the two cannot share code.
async fn prepare_operation(store: &PostgresDomainStore, method: &str) -> GovernedOperation {
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("read receipt database clock");
    let key = ReceiptKey {
        verified_issuer: format!(
            "https://issuer.example/l1-promotion-claim/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "svc:l1-promotion-claim-test".to_owned(),
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
        prepare_operation(store, "lore.domain.v1.test/PromotionClaimRepositoryCreate").await;
    let input = RepositoryCreateInput {
        metadata_witnesses: Vec::new(),
        repository_id: repository_id.to_vec(),
        name: format!("wp115-promotion-claim-{:016x}", rand::random::<u64>()),
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

/// Stage the destructive-write-claims cutover this coordinator's obliterate
/// path requires. Mirrors `domain_fragment_lifecycle.rs`'s helper of the
/// same name.
async fn enable_write_claims(url: &str, coordinator: &PostgresFragmentCoordinator) {
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

// ---------------------------------------------------------------------------
// Plan case 6: admission happy path.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn promotion_admission_carries_a_durable_claim_and_leaves_the_head_staged() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    let (staged_epoch, staged_manifest) = stage_hash(&coordinator, &hash, 0x10).await;

    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion on a Staged head")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    assert_ne!(
        promotion_intent.epoch, staged_epoch,
        "promotion must allocate a new successor epoch"
    );
    let claim = promotion_intent.write_claim().expect(
        "promotion intent must carry a durable write claim -- write_claim: None must be gone",
    );
    assert_eq!(claim.epoch(), promotion_intent.epoch);

    let head_row = direct
        .query_one(
            "SELECT current_epoch, state, manifest_id FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after promotion admission");
    let current_epoch: i64 = head_row.get(0);
    let state: i16 = head_row.get(1);
    let manifest_id: Option<Vec<u8>> = head_row.get(2);
    assert_eq!(
        current_epoch, staged_epoch,
        "the head must still name the staged epoch; only commit moves it"
    );
    assert_eq!(
        state,
        FragmentLifecycleState::Staged.bits(),
        "the head must stay Staged while the upload runs"
    );
    assert_eq!(manifest_id, Some(staged_manifest.manifest_id.clone()));

    let claim_row = direct
        .query_one(
            "SELECT state, kind, epoch FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read the durable claim row");
    let claim_state: i16 = claim_row.get(0);
    let kind: i16 = claim_row.get(1);
    assert_eq!(claim_state, FragmentWriteClaimState::Prepared.bits());
    assert_eq!(kind, 1, "a promotion claim's kind must be Promotion (1)");
}

// ---------------------------------------------------------------------------
// Plan case 7: admission refusals for every non-Staged head shape.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn promotion_admission_is_fenced_for_every_non_staged_head_shape() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    for (label, state) in [
        ("Remote", FragmentLifecycleState::Remote),
        ("Missing", FragmentLifecycleState::Missing),
        ("PreparingStage", FragmentLifecycleState::PreparingStage),
        ("PreparingRemote", FragmentLifecycleState::PreparingRemote),
        ("DeletingChildren", FragmentLifecycleState::DeletingChildren),
        ("DeletingPayload", FragmentLifecycleState::DeletingPayload),
        ("Tombstoned", FragmentLifecycleState::Tombstoned),
    ] {
        let hash = random_hash();
        let manifest_id = state.is_readable().then(|| vec![0x22_u8; 32]);
        direct
            .execute(
                "INSERT INTO lore_fragment_lifecycle \
                     (hash, current_epoch, state, manifest_id, last_fence) \
                 VALUES ($1, 1, $2, $3, 1)",
                &[&hash, &state.bits(), &manifest_id],
            )
            .await
            .unwrap_or_else(|error| panic!("insert {label} head fixture: {error}"));
        let outcome = coordinator
            .begin_promotion(&hash, write_claim())
            .await
            .unwrap_or_else(|error| {
                panic!("begin_promotion on {label} head must not error: {error}")
            });
        assert!(
            matches!(outcome, BeginOutcome::Fenced(_)),
            "a {label} head must refuse promotion as Fenced, got {outcome:?}"
        );
    }

    let absent_hash = random_hash();
    let outcome = coordinator
        .begin_promotion(&absent_hash, write_claim())
        .await;
    let matches_expected = matches!(
        &outcome,
        Err(DomainError::PreconditionRejected { reason, .. }) if reason == "fragment_head_absent"
    );
    assert!(
        matches_expected,
        "an absent head must be PreconditionRejected(fragment_head_absent), got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// Reviewer case 1: the object-key barrier discriminator, both directions,
// plus the repair-successor exemption the plan itself calls out.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn an_ambiguous_direct_write_claim_at_the_legacy_key_blocks_promotion_admission() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    stage_hash(&coordinator, &hash, 0x11).await;
    // A direct-write claim (kind 0) at the legacy key, at a DIFFERENT
    // epoch/fence than anything promotion would allocate -- the whole point
    // of the object-key barrier is that the old lineage-scoped
    // (hash, epoch, fence) filter would miss this, because both promotion
    // and direct writes always allocate fresh epoch/fence.
    insert_raw_claim(&direct, &hash, 9001, 9001, &legacy_key(&hash), 0, 3).await;

    let outcome = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin_promotion must not error, only refuse admission");
    assert!(
        matches!(outcome, BeginOutcome::WriteClaimBlocked { .. }),
        "a live Ambiguous direct-write claim at the shared legacy key must block promotion \
         admission, got {outcome:?}"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn an_ambiguous_promotion_claim_at_the_legacy_key_blocks_direct_write_admission() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    stage_hash(&coordinator, &hash, 0x51).await;
    let BeginOutcome::Admitted(promotion) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("admit promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = promotion.write_claim().expect("promotion claim");
    coordinator
        .authorize_write_claim(claim)
        .await
        .expect("authorize promotion");
    coordinator
        .settle_write_claim(claim, FragmentWriteSettlement::Ambiguous)
        .await
        .expect("settle outcome-unknown promotion");

    // Synthetic lineage relocation isolates the object-key barrier. The
    // promotion claim itself was produced by the public API, including its
    // mandatory source epoch and manifest. This is not a reachable workflow.
    direct
        .execute(
            "UPDATE lore_fragment_lifecycle SET state=$2, manifest_id=NULL, active_operation=$3 WHERE hash=$1",
            &[&hash, &FragmentLifecycleState::PreparingRemote.bits(), &b"wp118-direct-v1N".as_slice()],
        )
        .await
        .expect("place head on ordinary direct-resume lineage");

    let outcome = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash), write_claim())
        .await
        .expect("begin_direct_write must not error, only refuse admission");
    assert!(
        matches!(outcome, BeginOutcome::WriteClaimBlocked { .. }),
        "a live Ambiguous promotion claim at the shared legacy key must block direct-write \
         admission, got {outcome:?}"
    );

    direct
        .execute(
            "UPDATE lore_fragment_lifecycle SET state=$2, active_operation=NULL WHERE hash=$1",
            &[&hash, &FragmentLifecycleState::Missing.bits()],
        )
        .await
        .expect("move to Missing repair fixture");
    let BeginOutcome::Admitted(repair) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash), write_claim())
        .await
        .expect("repair successor")
    else {
        panic!("Missing repair must bypass the legacy-key claim");
    };
    assert_ne!(repair.object_key, legacy_key(&hash));
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_repair_successor_is_not_blocked_by_a_live_claim_at_the_legacy_key() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    direct
        .execute(
            "INSERT INTO lore_fragment_lifecycle (hash, current_epoch, state, manifest_id, last_fence) \
             VALUES ($1, 1, $2, NULL, 1)",
            &[&hash, &FragmentLifecycleState::Missing.bits()],
        )
        .await
        .expect("insert Missing head fixture");
    // A live claim at the legacy key -- but a repair successor writes
    // `repair_epoch_key`, a different object entirely, and must not be
    // blocked by a barrier scoped to a key it never touches.
    insert_raw_claim(&direct, &hash, 9003, 9003, &legacy_key(&hash), 0, 3).await;

    let outcome = coordinator
        .claim_repair(&hash, write_claim())
        .await
        .expect("claim_repair must not error");
    assert!(
        matches!(outcome, BeginOutcome::Admitted(_)),
        "a repair successor at repair_epoch_key must not be blocked by a claim at the legacy \
         key, got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// Reviewer case 2: direct-write admission regression -- the generalized
// barrier must not newly block the ordinary, uncontended happy path.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn ordinary_direct_write_admission_is_unaffected_by_the_object_key_barrier() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash), write_claim())
        .await
        .expect("begin_direct_write on a fresh hash must not error")
    else {
        panic!("a fresh hash with no interfering claim must admit an ordinary direct write");
    };
    let claim = intent
        .write_claim()
        .expect("direct write intent carries a claim");
    coordinator
        .authorize_write_claim(claim)
        .await
        .expect("authorize the uncontended claim");
    let published_manifest = manifest(&intent.object_key, 0x12, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(published_manifest),
                FragmentWriteSettlement::Decisive
            )
            .await
            .expect("commit the uncontended direct write"),
        CommitVerdict::Published
    );
}

// ---------------------------------------------------------------------------
// Plan case 8 + reviewer case 5: exclusivity, and takeover stamps a NEW
// fence once the barrier clears.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_second_promotion_is_blocked_until_the_first_claims_hard_not_after_then_takeover_stamps_a_new_fence()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    stage_hash(&coordinator, &hash, 0x13).await;

    let BeginOutcome::Admitted(first) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("first begin_promotion")
    else {
        panic!("first promotion attempt must admit");
    };

    // A concurrent (still-live) second attempt must be blocked, not admitted:
    // two live conditional PUTs to one key would double-charge budget and
    // walk past the outcome-unknown latch.
    let blocked = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("second begin_promotion while the first is still live must not error");
    assert!(
        matches!(blocked, BeginOutcome::WriteClaimBlocked { .. }),
        "a concurrent promotion attempt on the same hash must be blocked, got {blocked:?}"
    );

    // Move the database-clock horizons past deterministically after proving
    // the live barrier. A 1 ms claim can expire before that assertion runs.
    direct.execute(
        "UPDATE lore_fragment_write_claims SET prepared_at=clock_timestamp()-interval '3 seconds', \
         send_not_after=clock_timestamp()-interval '2 seconds', \
         hard_not_after=clock_timestamp()-interval '1 second' WHERE hash=$1",
        &[&hash],
    ).await.expect("expire claim horizons");

    let BeginOutcome::Admitted(second) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("takeover begin_promotion after the barrier clears")
    else {
        panic!("a cleared barrier must admit the takeover attempt");
    };
    assert_ne!(
        second.fence, first.fence,
        "takeover must stamp a NEW fence -- fence is the ownership recheck \
         commit_publication uses to detect a competing writer"
    );
}

// ---------------------------------------------------------------------------
// Plan case 9: authorization negatives. Every one settles NoSend and refuses
// with fragment_write_lineage_moved.
// ---------------------------------------------------------------------------

async fn assert_authorization_refused_as_lineage_moved(
    coordinator: &PostgresFragmentCoordinator,
    direct: &Client,
    claim: &lore_postgres::domain::fragments::coordinator::FragmentWriteClaim,
) {
    let outcome = coordinator.authorize_write_claim(claim).await;
    assert!(
        matches!(
            outcome,
            Err(DomainError::PreconditionRejected { ref reason, .. })
                if reason == "fragment_write_lineage_moved"
        ),
        "expected fragment_write_lineage_moved, got {outcome:?}"
    );
    let row = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read claim after refused authorization");
    let state: i16 = row.get(0);
    assert_eq!(
        state,
        FragmentWriteClaimState::NoSend.bits(),
        "a lineage-moved refusal must settle the claim NoSend, confirmed non-send"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn authorization_refuses_when_the_staged_epoch_moved_under_the_claim() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x14).await;
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim");

    direct
        .execute(
            "UPDATE lore_fragment_lifecycle SET current_epoch = current_epoch + 100 WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("simulate the staged epoch moving under the claim");

    assert_authorization_refused_as_lineage_moved(&coordinator, &direct, claim).await;
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn authorization_refuses_when_the_staged_manifest_was_replaced() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x15).await;
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim");

    direct
        .execute(
            "UPDATE lore_fragment_lifecycle SET manifest_id = $2 WHERE hash = $1",
            &[&hash, &vec![0xFE_u8; 32]],
        )
        .await
        .expect("simulate the staged manifest being replaced (e.g. by a repair)");

    assert_authorization_refused_as_lineage_moved(&coordinator, &direct, claim).await;
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn authorization_refuses_when_the_fence_moved() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x16).await;
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim");

    direct
        .execute(
            "UPDATE lore_fragment_lifecycle SET last_fence = last_fence + 1 WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("simulate the fence moving under the claim");

    assert_authorization_refused_as_lineage_moved(&coordinator, &direct, claim).await;
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn authorization_refuses_when_the_promotion_token_was_cleared() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x17).await;
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim");

    direct
        .execute(
            "UPDATE lore_fragment_lifecycle SET active_operation = NULL WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("simulate the promotion ownership token being cleared");

    assert_authorization_refused_as_lineage_moved(&coordinator, &direct, claim).await;
}

// ---------------------------------------------------------------------------
// Reviewer case 3: attempt-identity reuse with a different witness must be
// rejected by the durable equality check, never by trusting the caller.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn reusing_an_attempt_identity_against_a_moved_staged_witness_is_rejected() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x18).await;

    // Leave the claim unauthorized (still Prepared, unexpired) so its
    // identity is eligible to replay.
    let claim_input = write_claim();
    let BeginOutcome::Admitted(first) = coordinator
        .begin_promotion(&hash, claim_input.clone())
        .await
        .expect("first begin_promotion")
    else {
        panic!("Staged head must admit the first promotion attempt");
    };
    let first_claim = first
        .write_claim()
        .expect("first promotion intent carries a claim");

    // Move the staged witness the claim was admitted against, without
    // touching the fence or active_operation this time -- distinct from the
    // authorization-negative cases above, which don't reuse the attempt
    // identity at all.
    direct
        .execute(
            "UPDATE lore_fragment_lifecycle SET current_epoch = current_epoch + 200, \
                 manifest_id = $2 WHERE hash = $1",
            &[&hash, &vec![0xCD_u8; 32]],
        )
        .await
        .expect("simulate the staged witness moving under the still-Prepared claim");

    let replay = coordinator.begin_promotion(&hash, claim_input).await;
    assert!(
        matches!(replay, Err(DomainError::InvalidInput(ref message))
            if message.contains("reused with a different binding")),
        "reusing the attempt identity against a moved witness must be rejected by the durable \
         equality check, got {replay:?}"
    );
    let row = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &first_claim.logical_request_id().as_slice(),
                &first_claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read the original claim row");
    let state: i16 = row.get(0);
    assert_eq!(
        state,
        FragmentWriteClaimState::Prepared.bits(),
        "a rejected replay must not mutate the original durable claim row"
    );
}

// ---------------------------------------------------------------------------
// Plan case 10: send-deadline expiry at authorization settles NoSend, never
// Ambiguous.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn authorization_after_the_send_deadline_settles_no_send_not_ambiguous() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x19).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, short_lived_write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim");

    tokio::time::sleep(Duration::from_millis(30)).await;

    let outcome = coordinator.authorize_write_claim(claim).await;
    assert!(
        matches!(
            outcome,
            Err(DomainError::PreconditionRejected { ref reason, .. })
                if reason == "fragment_write_send_deadline_expired"
        ),
        "expected fragment_write_send_deadline_expired, got {outcome:?}"
    );
    let row = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read claim after expired authorization");
    let state: i16 = row.get(0);
    assert_eq!(
        state,
        FragmentWriteClaimState::NoSend.bits(),
        "an expired send deadline must settle NoSend, never Ambiguous"
    );
}

// ---------------------------------------------------------------------------
// Reviewer case 6: the latch outlives the lease. The barrier ROW must still
// be seen after settlement, and there is no lease to erase it -- it is a
// pure database-clock predicate.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn an_ambiguous_settlement_leaves_the_barrier_row_visible_and_blocks_a_fresh_promotion() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x1A).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim");
    coordinator
        .authorize_write_claim(claim)
        .await
        .expect("authorize before settling Ambiguous");
    coordinator
        .settle_write_claim(claim, FragmentWriteSettlement::Ambiguous)
        .await
        .expect("settle the claim Ambiguous (uncertain provider outcome)");

    // Prove the barrier ROW is still seen -- not merely that a fresh
    // admission is refused. There is no worker lease modeled anywhere near
    // this table; nothing writes lore_fragment_write_claims on lease expiry,
    // because there is no lease row to expire. This is the predicate the
    // outcome-unknown latch actually rests on.
    let row = direct
        .query_one(
            "SELECT state, hard_not_after > clock_timestamp() AS still_live \
               FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("the settled claim row must still be visible");
    let state: i16 = row.get(0);
    let still_live: bool = row.get(1);
    assert_eq!(state, FragmentWriteClaimState::Ambiguous.bits());
    assert!(
        still_live,
        "the barrier row's hard_not_after must still be ahead of the clock right after settlement"
    );

    let blocked = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("a fresh promotion attempt must not error, only be refused");
    assert!(
        matches!(blocked, BeginOutcome::WriteClaimBlocked { .. }),
        "an Ambiguous claim must block a fresh promotion attempt regardless of any worker \
         lease, got {blocked:?}"
    );
}

// ---------------------------------------------------------------------------
// Highest-risk case flagged by review: the union barrier's per-state horizon
// split means a Prepared claim past its OWN send window no longer blocks
// admission (mirroring write_claim_barrier_for_prune's split), which opens a
// window between "barrier relaxed" and "claim formally settled". Pin that
// this window can never let two live conditional PUTs land at one key -- the
// claim that stopped blocking admission must itself be structurally unable
// to reach Sending once past its send window.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_prepared_claim_past_its_send_window_no_longer_blocks_admission_but_can_never_itself_send()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x30).await;

    // Claim A: send window closes at ~50ms, hard deadline nowhere near --
    // decoupled deliberately, so "past send_not_after" is reached while
    // hard_not_after (what the OLD lineage-only barrier, and this barrier's
    // Sending/Ambiguous arm, would gate on) is still far in the future.
    let BeginOutcome::Admitted(intent_a) = coordinator
        .begin_promotion(&hash, short_send_long_late_effect_write_claim())
        .await
        .expect("begin first promotion")
    else {
        panic!("Staged head must admit the first promotion attempt");
    };
    let claim_a = intent_a.write_claim().expect("claim A").clone();

    tokio::time::sleep(Duration::from_millis(150)).await;

    // The barrier's Prepared arm judges claim A by send_not_after, which has
    // now passed -- so a fresh attempt must be admitted, not blocked, even
    // though claim A's hard_not_after is still roughly a minute out and
    // claim A itself is still sitting Prepared, unsettled, in the database.
    let BeginOutcome::Admitted(intent_b) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin second promotion once claim A's send window has closed")
    else {
        panic!(
            "a Prepared claim past its own send_not_after must not block a fresh promotion \
             attempt, even with its hard_not_after still far in the future"
        );
    };
    let claim_b = intent_b.write_claim().expect("claim B").clone();
    assert_ne!(
        intent_a.fence, intent_b.fence,
        "the takeover must stamp a new fence"
    );

    // Claim B proceeds normally -- the relaxation did not admit a second live
    // sender alongside a still-viable claim A.
    coordinator
        .authorize_write_claim(&claim_b)
        .await
        .expect("claim B must authorize normally");

    // THE PIN. Claim A, past its own send window, must never itself reach
    // Sending: attempting to authorize it now must be refused and must
    // settle it NoSend (or leave it in whatever refused-but-non-Sending state
    // it already reached) -- never Sending, which is the only state that
    // would let it issue a live conditional PUT at the object key claim B
    // just used. This is what makes the barrier's relaxation safe: the
    // barrier stopped counting claim A, but claim A is separately
    // self-defusing at authorize time.
    let claim_a_outcome = coordinator.authorize_write_claim(&claim_a).await;
    assert!(
        claim_a_outcome.is_err(),
        "claim A must never authorize successfully once admission has moved past it, got \
         {claim_a_outcome:?}"
    );
    let row = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim_a.logical_request_id().as_slice(),
                &claim_a.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read claim A after the refused late authorization attempt");
    let claim_a_state: i16 = row.get(0);
    assert_ne!(
        claim_a_state,
        FragmentWriteClaimState::Sending.bits(),
        "claim A must never reach Sending once its send window has closed -- this is the \
         property that rules out two live conditional PUTs at one key"
    );
}

// ---------------------------------------------------------------------------
// commit_promotion must refuse a NoSend settlement on a Valid observation,
// exactly as commit_remote/commit_repair already do -- a confirmed non-send
// cannot publish a representation.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn commit_promotion_refuses_a_no_send_settlement_on_a_valid_observation() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x31).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim").clone();
    coordinator
        .authorize_write_claim(&claim)
        .await
        .expect("authorize");

    let remote_manifest = manifest(
        "promotion-claim/no-send-refused",
        0x32,
        EpochAuthority::Remote,
    );
    let outcome = coordinator
        .commit_promotion(
            &intent,
            IoObservation::Valid(remote_manifest),
            FragmentWriteSettlement::NoSend,
        )
        .await;
    assert!(
        matches!(outcome, Err(DomainError::InvalidInput(ref message))
            if message.contains("no-send claim cannot publish a promotion observation")),
        "a confirmed non-send must not be able to publish a Valid promotion observation, got \
         {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// Plan case 13: publication happy path.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn decisive_promotion_publishes_with_provider_evidence_and_quarantines_the_predecessor() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let (staged_epoch, _staged_manifest) = stage_hash(&coordinator, &hash, 0x1B).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim").clone();
    coordinator
        .authorize_write_claim(&claim)
        .await
        .expect("authorize");
    let remote_manifest = manifest("promotion-claim/remote", 0x1C, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_promotion(
                &intent,
                IoObservation::Valid(remote_manifest.clone()),
                FragmentWriteSettlement::Decisive,
            )
            .await
            .expect("commit promotion"),
        CommitVerdict::Published
    );

    let epoch_row = direct
        .query_one(
            "SELECT authority, provider_body_blake3, provider_body_size, provider_claim_fence \
               FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &intent.epoch],
        )
        .await
        .expect("read the published epoch row");
    let authority: i16 = epoch_row.get(0);
    let provider_body_blake3: Option<Vec<u8>> = epoch_row.get(1);
    let provider_body_size: Option<i64> = epoch_row.get(2);
    let provider_claim_fence: Option<i64> = epoch_row.get(3);
    assert_eq!(authority, EpochAuthority::Remote.bits());
    assert_eq!(
        provider_body_blake3.as_deref(),
        Some(claim.body_blake3().as_slice()),
        "the published epoch must carry the claim's exact body digest as evidence"
    );
    assert_eq!(provider_body_size, Some(claim.body_size() as i64));
    assert_eq!(provider_claim_fence, Some(claim.fence()));

    let predecessor_disposition: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &staged_epoch],
        )
        .await
        .expect("read the quarantined predecessor")
        .get(0);
    assert_eq!(
        predecessor_disposition, 1,
        "the staged predecessor epoch must be quarantined (disposition 1), never revived"
    );

    let head_row = direct
        .query_one(
            "SELECT active_operation FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after publication");
    let active_operation: Option<Vec<u8>> = head_row.get(0);
    assert!(
        active_operation.is_none(),
        "a published promotion must clear the ownership token"
    );

    let claim_row = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read claim after publication");
    let claim_state: i16 = claim_row.get(0);
    assert_eq!(claim_state, FragmentWriteClaimState::Decisive.bits());
}

// ---------------------------------------------------------------------------
// Plan case 14: fenced publication (commit_promotion's own Valid-observation
// path, distinct from abandon_promotion below).
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_fence_moved_between_begin_and_commit_leaves_staged_bytes_readable_and_settles_the_claim()
{
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let (staged_epoch, staged_manifest) = stage_hash(&coordinator, &hash, 0x1D).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim").clone();
    coordinator
        .authorize_write_claim(&claim)
        .await
        .expect("authorize");

    direct
        .execute(
            "UPDATE lore_fragment_lifecycle SET last_fence = last_fence + 1 WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("simulate the fence moving between authorization and commit");

    let remote_manifest = manifest(
        "promotion-claim/remote-fenced",
        0x1E,
        EpochAuthority::Remote,
    );
    let verdict = coordinator
        .commit_promotion(
            &intent,
            IoObservation::Valid(remote_manifest),
            FragmentWriteSettlement::Decisive,
        )
        .await
        .expect("commit promotion must not error, only report Fenced");
    assert_eq!(verdict, CommitVerdict::Fenced);
    assert!(verdict.left_representation_intact());

    let head_row = direct
        .query_one(
            "SELECT current_epoch, state, manifest_id FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after fenced commit");
    let current_epoch: i64 = head_row.get(0);
    let state: i16 = head_row.get(1);
    let manifest_id: Option<Vec<u8>> = head_row.get(2);
    assert_eq!(
        current_epoch, staged_epoch,
        "staged bytes must remain readable"
    );
    assert_eq!(state, FragmentLifecycleState::Staged.bits());
    assert_eq!(manifest_id, Some(staged_manifest.manifest_id.clone()));

    let claim_row = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read claim after fenced commit");
    let claim_state: i16 = claim_row.get(0);
    assert_eq!(
        claim_state,
        FragmentWriteClaimState::Decisive.bits(),
        "a fenced commit must still settle the claim rather than leave it Sending forever"
    );
}

// ---------------------------------------------------------------------------
// Reviewer case 4: abandon_promotion's two Fenced early-return arms.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn abandon_promotion_settles_ambiguous_and_leaves_staged_bytes_readable_when_the_fence_moved()
{
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let (staged_epoch, staged_manifest) = stage_hash(&coordinator, &hash, 0x1F).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim").clone();
    coordinator
        .authorize_write_claim(&claim)
        .await
        .expect("authorize");

    direct
        .execute(
            "UPDATE lore_fragment_lifecycle SET last_fence = last_fence + 1 WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("simulate the fence moving between begin and abandon");

    // Unusable observation routes commit_promotion into abandon_promotion.
    // The settlement argument here is IGNORED on this path -- abandon settles
    // by the claim's own durable state. The claim was authorized above (so it
    // is Sending), and Sending settles Ambiguous; passing NoSend here would
    // settle exactly the same way, which the sibling case below proves.
    let verdict = coordinator
        .commit_promotion(
            &intent,
            IoObservation::Unusable(MissingDiagnostic::Truncated),
            FragmentWriteSettlement::NoSend,
        )
        .await
        .expect("commit promotion (unusable, fenced) must not error");
    assert_eq!(verdict, CommitVerdict::Fenced);

    let head_row = direct
        .query_one(
            "SELECT current_epoch, state, manifest_id FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after fenced abandon");
    let current_epoch: i64 = head_row.get(0);
    let state: i16 = head_row.get(1);
    let manifest_id: Option<Vec<u8>> = head_row.get(2);
    assert_eq!(
        current_epoch, staged_epoch,
        "staged bytes must remain readable"
    );
    assert_eq!(state, FragmentLifecycleState::Staged.bits());
    assert_eq!(manifest_id, Some(staged_manifest.manifest_id.clone()));

    let claim_row = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read claim after fenced abandon");
    let claim_state: i16 = claim_row.get(0);
    assert_eq!(
        claim_state,
        FragmentWriteClaimState::Ambiguous.bits(),
        "an authorized (Sending) claim's fenced abandon must settle Ambiguous regardless of the \
         (ignored) caller-supplied settlement, or the outcome-unknown latch never closes"
    );
}

/// The sibling of the case above: a claim abandoned while still `Prepared`
/// (never authorized) settles `NoSend`, not `Ambiguous` -- `Prepared ->
/// Ambiguous` is not a legal transition, and widening it would let a
/// fragment that provably never sent hold a barrier at its object key until
/// the hard deadline.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn abandon_promotion_settles_no_send_when_the_claim_was_never_authorized() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let (staged_epoch, staged_manifest) = stage_hash(&coordinator, &hash, 0x33).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim").clone();
    // Deliberately not authorized: the claim stays Prepared.

    let verdict = coordinator
        .commit_promotion(
            &intent,
            IoObservation::Unusable(MissingDiagnostic::InvalidStructure),
            FragmentWriteSettlement::Ambiguous,
        )
        .await
        .expect("commit promotion (unusable, never authorized) must not error");
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
    assert_eq!(current_epoch, staged_epoch);
    assert_eq!(state, FragmentLifecycleState::Staged.bits());
    assert_eq!(manifest_id, Some(staged_manifest.manifest_id.clone()));

    let claim_row = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read claim after abandon");
    let claim_state: i16 = claim_row.get(0);
    assert_eq!(
        claim_state,
        FragmentWriteClaimState::NoSend.bits(),
        "a never-authorized (Prepared) claim's abandon must settle NoSend, not Ambiguous -- \
         Prepared -> Ambiguous is not a legal transition, and the caller's settlement argument \
         is ignored on this path"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn abandon_promotion_reports_fenced_when_the_head_is_gone() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x20).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim").clone();
    coordinator
        .authorize_write_claim(&claim)
        .await
        .expect("authorize");

    // Synthetic: drive the "no head at all" arm directly. A head cannot
    // physically vanish through the coordinator's own obliterate sequence
    // mid-promotion in one step; this proves the code path defends the
    // invariant regardless of how the row went missing.
    direct
        .execute(
            "DELETE FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("simulate the head row being gone");

    // Settlement argument ignored on this path; the claim was authorized
    // above (Sending), so it settles Ambiguous regardless of what is passed.
    let verdict = coordinator
        .commit_promotion(
            &intent,
            IoObservation::Unusable(MissingDiagnostic::Absent),
            FragmentWriteSettlement::NoSend,
        )
        .await
        .expect("commit promotion (unusable, headless) must not error");
    assert_eq!(verdict, CommitVerdict::Fenced);

    let claim_row = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read claim after the headless fenced abandon");
    let claim_state: i16 = claim_row.get(0);
    assert_eq!(
        claim_state,
        FragmentWriteClaimState::Ambiguous.bits(),
        "the headless arm must still settle the claim even with no head left to update"
    );
}

// ---------------------------------------------------------------------------
// Plan case 15: abandon_promotion happy path (no fence move).
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn abandon_promotion_leaves_the_head_staged_with_its_manifest_and_settles_the_claim() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let (staged_epoch, staged_manifest) = stage_hash(&coordinator, &hash, 0x21).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim").clone();
    coordinator
        .authorize_write_claim(&claim)
        .await
        .expect("authorize");

    // Settlement argument ignored on this path; the claim was authorized
    // above (Sending), so it settles Ambiguous regardless of what is passed.
    let verdict = coordinator
        .commit_promotion(
            &intent,
            IoObservation::Unusable(MissingDiagnostic::Corrupt),
            FragmentWriteSettlement::NoSend,
        )
        .await
        .expect("commit promotion (unusable) must not error");
    assert_eq!(verdict, CommitVerdict::Abandoned);
    assert!(verdict.left_representation_intact());

    let head_row = direct
        .query_one(
            "SELECT current_epoch, state, manifest_id, active_operation \
               FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after abandon");
    let current_epoch: i64 = head_row.get(0);
    let state: i16 = head_row.get(1);
    let manifest_id: Option<Vec<u8>> = head_row.get(2);
    let active_operation: Option<Vec<u8>> = head_row.get(3);
    assert_eq!(current_epoch, staged_epoch);
    assert_eq!(state, FragmentLifecycleState::Staged.bits());
    assert_eq!(manifest_id, Some(staged_manifest.manifest_id.clone()));
    assert!(
        active_operation.is_none(),
        "an abandoned promotion must clear the ownership token so a later attempt can proceed"
    );

    let claim_row = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read claim after abandon");
    let claim_state: i16 = claim_row.get(0);
    assert_eq!(
        claim_state,
        FragmentWriteClaimState::Ambiguous.bits(),
        "an authorized (Sending) claim settles Ambiguous on abandon, ignoring the passed-in \
         (NoSend) settlement argument"
    );
}

// ---------------------------------------------------------------------------
// Case 16 (owner-ruled D10 NARROW): a promotion send claim contributes a
// cleanup target only as unpublished residue. Obliterate's ordinary
// current-epoch Remote purge path is unchanged for a promoted object --
// there is no RETAINED_REMOTE disposition and no promotion-only target
// shape. Nothing in `write_claim_inventory_locked` or
// `capture_obliterate_intent_locked` reads `kind`, so this proves the narrow
// reading holds in code, not only in the ruling.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_decisive_promotion_claim_contributes_a_cleanup_target_exactly_like_a_direct_write_claim_d10_narrow()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let hash = random_hash();
    let legacy = legacy_key(&hash);

    stage_hash(&coordinator, &hash, 0x34).await;
    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let promotion_claim = promotion_intent
        .write_claim()
        .expect("promotion claim")
        .clone();
    coordinator
        .authorize_write_claim(&promotion_claim)
        .await
        .expect("authorize");
    let remote_manifest = manifest(&legacy, 0x35, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_promotion(
                &promotion_intent,
                IoObservation::Valid(remote_manifest),
                FragmentWriteSettlement::Decisive,
            )
            .await
            .expect("commit promotion"),
        CommitVerdict::Published
    );

    let repository = create_repository(&store).await;
    let context = random_context();
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .expect("associate the promoted fragment"),
        CommitVerdict::Published
    );
    enable_write_claims(&url, &coordinator).await;

    let FragmentObliterateBegin::Ready(deleting) = coordinator
        .begin_obliterate(
            &hash,
            &repository,
            &context,
            TEST_PROVIDER_WRITE_AUTHORITY_REVISION,
        )
        .await
        .expect("begin exact deletion of the sole association")
    else {
        panic!("the last association must own deletion and admit immediately");
    };
    assert_eq!(deleting.phase(), FragmentObliteratePhase::Children);

    // The promoted current-epoch representation surfaces through the
    // ORDINARY current-epoch Remote purge path -- `current()` -- identically
    // to a direct write's: same Remote authority, same legacy_hash_key.
    // Nothing here names promotion specially.
    let current = deleting
        .current()
        .expect("a Remote head has a current representation to purge");
    assert_eq!(current.target().object_key(), legacy);
    assert_eq!(current.target().epoch(), promotion_intent.epoch);
    assert_eq!(current.target().authority(), EpochAuthority::Remote);

    // The Decisive promotion claim itself also surfaces through the SAME
    // kind-blind write-claim inventory a Decisive direct-write claim would --
    // proving no special-casing by kind exists anywhere in this path. This is
    // the "unpublished residue" contribution D10 NARROW describes; nothing
    // marks it as permanently retained.
    assert!(
        deleting
            .purge_targets()
            .iter()
            .any(|target| target.object_key() == legacy
                && target.epoch() == promotion_intent.epoch
                && target.authority() == EpochAuthority::Remote
                && target.provider_claim_fence() == Some(promotion_claim.fence())
                && target.provider_body_blake3() == Some(promotion_claim.body_blake3())
                && target.provider_body_size() == Some(promotion_claim.body_size())),
        "a Decisive promotion claim must contribute a cleanup target exactly like a Decisive \
         direct-write claim would -- D10 NARROW: no RETAINED_REMOTE disposition, no \
         promotion-only target shape, purge_targets={:?}",
        deleting.purge_targets()
    );
}

// ---------------------------------------------------------------------------
// The lineage-refusal arm must settle by the claim's DURABLE state.
//
// Every other lineage-refusal case in this suite (and in
// `domain_fragment_lifecycle.rs`) enters the arm from `Prepared`, which is the
// one state for which a confirmed `NoSend` is correct. That is why the defect
// survived. This case is the only one that enters it from `Sending`.
// ---------------------------------------------------------------------------

/// A claim that already authorized, whose head fence then moved, must settle
/// `Ambiguous` -- never a confirmed `NoSend`.
///
/// A `Sending` claim may have a live conditional PUT in flight. Recording it as
/// a confirmed non-send erases the outcome-unknown latch and drops the
/// unpublished-residue cleanup target the deletion barrier still needs. The
/// assertion is on durable state alone: no wall-clock margin, deliberately, so
/// this case cannot join the two takeover/deadline cases in flaking under load.
///
/// The fence bump below is a fixture standing in for a barrier-blind fence
/// stamp, not a proof of one. `begin_obliterate` against a live unexpired
/// promotion claim is now pinned directly by the three cases at the end of this
/// file.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_sending_claim_refused_for_moved_lineage_settles_ambiguous_not_confirmed_no_send() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x36).await;

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion")
    else {
        panic!("Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim").clone();

    // Authorization commits, so from here the claim is `Sending` and its send
    // may have had an effect no later reader can rule out.
    coordinator
        .authorize_write_claim(&claim)
        .await
        .expect("authorize the promotion claim");
    let authorized: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read the claim after authorization")
        .get(0);
    assert_eq!(
        authorized,
        FragmentWriteClaimState::Sending.bits(),
        "the case is meaningless unless the claim really reached Sending"
    );

    // The head fence moves under the live claim, exactly as a barrier-blind
    // fence stamp would leave it. The claim is untouched and still Sending.
    direct
        .execute(
            "UPDATE lore_fragment_lifecycle SET last_fence = last_fence + 1 WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("move the head fence under the live claim");

    let refusal = coordinator.authorize_write_claim(&claim).await;
    assert!(
        matches!(
            refusal,
            Err(DomainError::PreconditionRejected { ref reason, .. })
                if reason == "fragment_write_lineage_moved"
        ),
        "a moved head fence must refuse the claim as lineage-moved, got {refusal:?}"
    );

    let settled: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read the claim after the lineage refusal")
        .get(0);
    assert_ne!(
        settled,
        FragmentWriteClaimState::NoSend.bits(),
        "THE PIN: a claim that already authorized must never be recorded as a CONFIRMED \
         non-send -- that erases the outcome-unknown latch and drops the unpublished-residue \
         cleanup target with it"
    );
    assert_eq!(
        settled,
        FragmentWriteClaimState::Ambiguous.bits(),
        "the durable-state mapping is Sending -> Ambiguous, so the barrier holds until \
         hard_not_after and the residue stays a cleanup target"
    );
}

// ---------------------------------------------------------------------------
// `begin_obliterate` against a hash carrying a LIVE UNEXPIRED promotion claim.
//
// This was unpinned in BOTH directions: nothing said the deletion waits for the
// claim, and nothing said it does not. These three cases pin the CURRENT
// behavior only. No source under `lore-postgres/src/` was changed for them.
//
// What the implementation actually does (read off
// `domain/fragments/coordinator.rs`): `begin_obliterate` does not consult
// `write_claim_barrier_locked` -- the admission barrier -- but it does take the
// whole hash's claim inventory under `FOR UPDATE` via
// `write_claim_inventory_locked`, which is kind-blind. A live claim therefore
// reaches the obliterate path as a BARRIER (`blocked_until`), never as a
// cleanup target, and the association tombstone plus the head transition to
// `DeletingChildren` commit ANYWAY. So the deletion takes durable ownership at
// once and reports a deadline; it does not defer taking ownership.
//
// That matches ruling D10-A in both halves: promotion joins the deletion-barrier
// inventory, and it never authorizes deleting the promoted bare-hash object --
// a live claim contributes no target at all, and a settled one contributes one
// only as unpublished residue.
//
// Case 3 is the negative control. Without it, cases 1 and 2 could not
// distinguish "the live claim blocked the deletion" from "an obliterate on a
// Staged head is always Blocked".
// ---------------------------------------------------------------------------

/// Stage a hash whose staged epoch sits at the CANONICAL staged object key.
///
/// `stage_hash` publishes at a fixed literal key, which is fine for every case
/// that never obliterates a `Staged` head. These cases do, and
/// `validate_purge_target_key` refuses a `Staged` target whose key is not
/// `<hex>.s<epoch>` -- so the intent capture would fail on the fixture rather
/// than on the behavior under test. Returns the staged epoch.
async fn stage_hash_at_canonical_staged_key(
    coordinator: &PostgresFragmentCoordinator,
    hash: &[u8],
    seed: u8,
) -> i64 {
    let BeginOutcome::Admitted(stage_intent) = coordinator
        .begin_stage(hash)
        .await
        .expect("begin stage on a fresh hash")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    let epoch = stage_intent.epoch;
    let key = format!("{}.s{epoch}", legacy_key(hash));
    assert_eq!(
        coordinator
            .commit_staged(
                &stage_intent,
                IoObservation::Valid(manifest(&key, seed, EpochAuthority::Staged)),
            )
            .await
            .expect("commit staged at the canonical staged key"),
        CommitVerdict::Published
    );
    epoch
}

/// The bare-hash key is absent from the capture -- and the capture is not
/// empty.
///
/// `all(|t| t.object_key() != legacy)` is true of an empty slice, so on its own
/// it cannot tell "promotion contributed nothing" from "the whole capture
/// failed". The staged current representation must be there, at the canonical
/// staged key, for the absence to mean anything.
fn assert_non_vacuous_no_legacy_target(targets: &[FragmentPurgeTarget], hash: &[u8], legacy: &str) {
    let staged = format!("{}.s", legacy_key(hash));
    assert!(
        targets
            .iter()
            .any(|target| target.authority() == EpochAuthority::Staged
                && target.object_key().starts_with(&staged)),
        "the capture must carry the staged current representation, or the legacy-key absence \
         below is vacuous; purge_targets={targets:?}"
    );
    assert!(
        targets.iter().all(|target| target.object_key() != legacy),
        "no cleanup target may name the bare-hash key -- promotion never authorizes deleting \
         the promoted bare-hash object (D10-A); purge_targets={targets:?}"
    );
}

/// Read one claim's durable state, so every assertion below is about the row
/// rather than about a value the coordinator handed back.
async fn claim_state(direct: &Client, claim: &FragmentWriteClaim) -> i16 {
    direct
        .query_one(
            "SELECT state FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2",
            &[
                &claim.logical_request_id().as_slice(),
                &claim.attempt_id().as_slice(),
            ],
        )
        .await
        .expect("read the claim row")
        .get(0)
}

/// Stage a hash, associate it, enable write claims, and admit one promotion.
/// Returns everything the three cases below assert against.
async fn promotion_in_flight(
    url: &str,
    store: &PostgresDomainStore,
    coordinator: &PostgresFragmentCoordinator,
    hash: &[u8],
    seed: u8,
    claim_input: FragmentWriteClaimInput,
) -> ([u8; 16], Vec<u8>, FragmentWriteClaim) {
    stage_hash_at_canonical_staged_key(coordinator, hash, seed).await;
    let repository = create_repository(store).await;
    let context = random_context();
    assert_eq!(
        coordinator
            .create_association(hash, &repository, &context)
            .await
            .expect("associate the staged fragment"),
        CommitVerdict::Published
    );
    enable_write_claims(url, coordinator).await;
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_promotion(hash, claim_input)
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit promotion");
    };
    let claim = intent.write_claim().expect("promotion claim").clone();
    (repository, context, claim)
}

/// A `Prepared` promotion claim still inside its send window makes
/// `begin_obliterate` report `Blocked` until that claim's `send_not_after` --
/// while still committing the association tombstone and the head transition,
/// and while leaving the claim row untouched.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn begin_obliterate_is_blocked_by_a_live_prepared_promotion_claim_but_still_takes_ownership()
{
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let (repository, context, claim) = promotion_in_flight(
        &url,
        &store,
        &coordinator,
        &hash,
        0x40,
        // Generous deadlines: this case must not race the clock.
        write_claim(),
    )
    .await;
    assert_eq!(
        claim_state(&direct, &claim).await,
        FragmentWriteClaimState::Prepared.bits(),
        "the case is meaningless unless the claim is Prepared and unexpired"
    );

    let begun = coordinator
        .begin_obliterate(
            &hash,
            &repository,
            &context,
            TEST_PROVIDER_WRITE_AUTHORITY_REVISION,
        )
        .await
        .expect("begin obliterate must not error with a live claim present");
    let FragmentObliterateBegin::Blocked {
        intent,
        blocked_until,
    } = begun
    else {
        panic!("a live unexpired Prepared promotion claim must report Blocked, got {begun:?}");
    };
    assert!(
        blocked_until >= claim.send_not_after(),
        "the barrier deadline must be at least the live claim's send_not_after; \
         blocked_until={blocked_until:?} send_not_after={:?}",
        claim.send_not_after()
    );
    assert_eq!(intent.phase(), FragmentObliteratePhase::Children);

    // D10-A, the half that is easy to lose: a LIVE claim is a barrier, not a
    // licence. Nothing in the intent names the bare-hash key the promotion
    // would have published to. Asserted against a NON-EMPTY target set -- the
    // staged current representation is there, so "no legacy key" is a real
    // absence rather than an empty list passing an `all`.
    let legacy = legacy_key(&hash);
    assert_non_vacuous_no_legacy_target(intent.purge_targets(), &hash, &legacy);

    // Ownership is taken regardless of the barrier: both rows moved.
    let head_state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read the head")
        .get(0);
    assert_eq!(
        head_state,
        FragmentLifecycleState::DeletingChildren.bits(),
        "Blocked still commits the head transition -- the deletion owns the hash now"
    );
    let association_state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_associations \
              WHERE hash = $1 AND repository_id = $2 AND context = $3",
            &[&hash, &repository.as_slice(), &context],
        )
        .await
        .expect("read the association")
        .get(0);
    assert_eq!(
        association_state,
        schema::ASSOCIATION_TOMBSTONED,
        "Blocked still commits the association tombstone"
    );

    // The claim itself is not settled by the obliterate. It is settled by the
    // promotion worker's own next call, which now finds a head it cannot match.
    assert_eq!(
        claim_state(&direct, &claim).await,
        FragmentWriteClaimState::Prepared.bits(),
        "begin_obliterate must not settle a LIVE claim; only an expired Prepared claim is \
         settled by the inventory sweep"
    );
    let refusal = coordinator.authorize_write_claim(&claim).await;
    assert!(
        matches!(
            refusal,
            Err(DomainError::PreconditionRejected { ref reason, .. })
                if reason == "fragment_write_lineage_moved"
        ),
        "the promotion must be fenced by the head the obliterate left behind, got {refusal:?}"
    );
    assert_eq!(
        claim_state(&direct, &claim).await,
        FragmentWriteClaimState::NoSend.bits(),
        "a Prepared claim refused for moved lineage is a CONFIRMED non-send"
    );
}

/// The same shape one state later: a claim that already authorized is
/// `Sending`, so the barrier runs to `hard_not_after`, not `send_not_after`.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn begin_obliterate_is_blocked_by_a_sending_promotion_claim_until_its_hard_deadline() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let (repository, context, claim) =
        promotion_in_flight(&url, &store, &coordinator, &hash, 0x41, write_claim()).await;
    coordinator
        .authorize_write_claim(&claim)
        .await
        .expect("authorize the promotion claim");
    assert_eq!(
        claim_state(&direct, &claim).await,
        FragmentWriteClaimState::Sending.bits(),
        "the case is meaningless unless the claim really reached Sending"
    );

    let begun = coordinator
        .begin_obliterate(
            &hash,
            &repository,
            &context,
            TEST_PROVIDER_WRITE_AUTHORITY_REVISION,
        )
        .await
        .expect("begin obliterate must not error with a Sending claim present");
    let FragmentObliterateBegin::Blocked {
        intent,
        blocked_until,
    } = begun
    else {
        panic!("a live unexpired Sending promotion claim must report Blocked, got {begun:?}");
    };
    assert!(
        blocked_until >= claim.hard_not_after(),
        "a Sending claim's barrier runs to hard_not_after, not send_not_after; \
         blocked_until={blocked_until:?} hard_not_after={:?}",
        claim.hard_not_after()
    );
    // An UNEXPIRED Sending claim is a barrier, not residue: it must contribute
    // no cleanup target while its late effect can still land.
    let legacy = legacy_key(&hash);
    assert_non_vacuous_no_legacy_target(intent.purge_targets(), &hash, &legacy);
    assert_eq!(
        claim_state(&direct, &claim).await,
        FragmentWriteClaimState::Sending.bits(),
        "begin_obliterate must leave a live Sending claim exactly where it found it"
    );
}

/// NEGATIVE CONTROL. The same fixture with a claim whose send window has
/// already closed is NOT blocked -- so the two cases above measure the claim's
/// liveness, not merely "obliterate on a Staged head".
///
/// It also pins the inventory's write side: the expired `Prepared` claim is
/// settled to a confirmed `NoSend` by `begin_obliterate` itself.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn begin_obliterate_is_not_blocked_once_the_promotion_claims_send_window_has_closed() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let (repository, context, claim) = promotion_in_flight(
        &url,
        &store,
        &coordinator,
        &hash,
        0x42,
        // 50 ms send window, 60 s hard bound: the claim can never send again,
        // but its row is nowhere near its late-effect deadline. That is the
        // shape that isolates `send_not_after` as the thing being measured.
        short_send_long_late_effect_write_claim(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        claim_state(&direct, &claim).await,
        FragmentWriteClaimState::Prepared.bits(),
        "nothing should have settled the claim before the obliterate runs"
    );

    let begun = coordinator
        .begin_obliterate(
            &hash,
            &repository,
            &context,
            TEST_PROVIDER_WRITE_AUTHORITY_REVISION,
        )
        .await
        .expect("begin obliterate must not error");
    let FragmentObliterateBegin::Ready(intent) = begun else {
        panic!(
            "a Prepared claim past its send window must NOT block the deletion, got {begun:?} \
             -- if this is Blocked the two cases above prove nothing about claim liveness"
        );
    };
    assert_eq!(intent.phase(), FragmentObliteratePhase::Children);
    // A claim that never authorized leaves no residue at the bare-hash key.
    let legacy = legacy_key(&hash);
    assert_non_vacuous_no_legacy_target(intent.purge_targets(), &hash, &legacy);
    assert_eq!(
        claim_state(&direct, &claim).await,
        FragmentWriteClaimState::NoSend.bits(),
        "the obliterate's own inventory sweep settles an expired Prepared claim to a \
         CONFIRMED non-send"
    );
}
