// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Stage custody tombstone lifetime. A released custody row whose epoch no
//! later cleanup can reach is deleted and gives its metadata row back; only a
//! row that still guards a late residue file stays as a 256-byte tombstone.
//!
//! Every case reads the ledger back from the tables and checks it against the
//! custody rows (`stage_invariant`), so a leaked row or a double refund fails
//! whichever path produced it.

#[path = "common/drain_candidate.rs"]
mod drain_candidate;
#[path = "common/stage_invariant.rs"]
mod stage_invariant;
#[path = "common/stage_policy.rs"]
mod stage_policy;

use std::time::Duration;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::fragments::BeginOutcome;
use lore_postgres::domain::fragments::CommitVerdict;
use lore_postgres::domain::fragments::EpochAuthority;
use lore_postgres::domain::fragments::FragmentManifest;
use lore_postgres::domain::fragments::FragmentWriteClaimInput;
use lore_postgres::domain::fragments::FragmentWriteSettlement;
use lore_postgres::domain::fragments::IoObservation;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::domain::fragments::STAGE_TOMBSTONE_REBUILD_SQL;
use lore_postgres::domain::fragments::StageReservationInput;
use lore_postgres::domain::fragments::coordinator::is_stage_custody_key_taken;
use lore_postgres::domain::fragments::schema;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;
use uuid::Uuid;

/// What an orphan reclaim charges: `MAX_FRAGMENT_WRITE_CLAIM_BODY_BYTES`, the
/// largest payload a claim can carry (pinned here as a literal on purpose).
const ORPHAN_CHARGE: i64 = 262_144;

struct Env {
    url: String,
    store: PostgresDomainStore,
    coordinator: PostgresFragmentCoordinator,
    direct: Client,
}

async fn env_with_metadata_rows(max_metadata_rows: i64) -> Env {
    let url = std::env::var("LORE_TEST_PG_URL").expect("owned disposable PostgreSQL required");
    let store = PostgresDomainStore::connect(&url, 8, &TlsConfig::default())
        .await
        .unwrap();
    let coordinator = store.fragment_coordinator();
    coordinator.bootstrap().await.unwrap();
    stage_policy::initialize_with_limits(
        &url,
        &coordinator,
        1_073_741_824,
        100_000,
        1_073_741_824,
        max_metadata_rows,
    )
    .await;
    let (direct, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });
    Env {
        url,
        store,
        coordinator,
        direct,
    }
}

async fn env() -> Env {
    env_with_metadata_rows(100_000).await
}

fn input() -> StageReservationInput {
    StageReservationInput {
        size_payload: 128,
        original_flags: 0,
    }
}

fn claim() -> FragmentWriteClaimInput {
    FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        [0xA5; 32],
        1,
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .unwrap()
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

/// `(live_bytes, live_files, metadata_bytes, metadata_rows)`.
async fn usage(coordinator: &PostgresFragmentCoordinator) -> (i64, i64, i64, i64) {
    let observed = coordinator.observe_stage().await.unwrap();
    (
        observed.resident_bytes,
        observed.resident_files,
        observed.metadata_bytes,
        observed.metadata_rows,
    )
}

async fn custody_rows(direct: &Client, hash: &[u8], epoch: i64) -> i64 {
    direct
        .query_one(
            "SELECT count(*) FROM lore_fragment_stage_custody WHERE hash=$1 AND epoch=$2",
            &[&hash, &epoch],
        )
        .await
        .unwrap()
        .get(0)
}

async fn epoch_disposition(direct: &Client, hash: &[u8], epoch: i64) -> Option<i16> {
    direct
        .query_opt(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash=$1 AND epoch=$2 AND authority=1",
            &[&hash, &epoch],
        )
        .await
        .unwrap()
        .map(|row| row.get(0))
}

/// Stage a fragment and promote it, so its staged epoch is quarantined behind a
/// readable `Remote` head. Returns the staged epoch.
async fn stage_and_promote(coordinator: &PostgresFragmentCoordinator, hash: &[u8; 32]) -> i64 {
    let BeginOutcome::Admitted(stage) = coordinator.begin_stage(hash, input()).await.unwrap()
    else {
        panic!("a fresh hash admits a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage,
                IoObservation::Valid(manifest(&stage.object_key, 0x91, EpochAuthority::Staged)),
            )
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    let candidate = drain_candidate::candidate(coordinator, hash).await;
    let BeginOutcome::Admitted(promotion) = coordinator
        .begin_promotion(&candidate, claim())
        .await
        .unwrap()
    else {
        panic!("a staged head admits a promotion");
    };
    let write_claim = promotion.write_claim().unwrap().clone();
    coordinator
        .authorize_write_claim(&write_claim)
        .await
        .unwrap();
    assert_eq!(
        coordinator
            .commit_promotion(
                &promotion,
                IoObservation::Valid(manifest(
                    &promotion.object_key,
                    0x92,
                    EpochAuthority::Remote,
                )),
                FragmentWriteSettlement::Decisive,
            )
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    stage.epoch
}

/// Clean one staged epoch: seal, then record the unlink as done.
async fn clean(coordinator: &PostgresFragmentCoordinator, hash: &[u8], epoch: i64) {
    let intent = coordinator
        .begin_stage_cleanup(hash, epoch)
        .await
        .unwrap()
        .expect("cleanup is authorized");
    assert_eq!(intent.target().epoch(), epoch);
    coordinator.commit_stage_cleanup(&intent).await.unwrap();
}

/// Run the full predecessor path: the release has a PURGED staged epoch, so the
/// custody row is redundant and goes away. Returns the staged epoch.
async fn purged_predecessor(coordinator: &PostgresFragmentCoordinator, hash: &[u8; 32]) -> i64 {
    let epoch = stage_and_promote(coordinator, hash).await;
    clean(coordinator, hash, epoch).await;
    epoch
}

/// A tombstone that must stay: the head is still at the withdrawn epoch and no
/// epochs row exists, so a late file for it has no other cleanup authority.
async fn kept_tombstone(coordinator: &PostgresFragmentCoordinator, hash: &[u8; 32]) -> i64 {
    let BeginOutcome::Admitted(stage) = coordinator.begin_stage(hash, input()).await.unwrap()
    else {
        panic!("a fresh hash admits a stage begin");
    };
    assert!(coordinator.withdraw_stage(&stage).await.unwrap());
    clean(coordinator, hash, stage.epoch).await;
    stage.epoch
}

/// The pre-fix shape: a state=3 custody row for a PURGED staged epoch, counted
/// in the usage ledger. The fixed release never leaves one behind.
async fn reinstate_legacy_tombstone(direct: &Client, hash: &[u8], epoch: i64) {
    assert_eq!(custody_rows(direct, hash, epoch).await, 0);
    direct
        .execute(
            "INSERT INTO lore_fragment_stage_custody \
             (hash,epoch,operation_fence,original_flags,size_payload,prepare_deadline,state,metadata_bytes,purged_at) \
             VALUES($1,$2,nextval('lore_fragment_fence_seq'),NULL,0,clock_timestamp(),3,256,clock_timestamp())",
            &[&hash, &epoch],
        )
        .await
        .unwrap();
    direct
        .execute(
            "UPDATE lore_fragment_stage_usage SET metadata_bytes=metadata_bytes+256, \
             metadata_rows=metadata_rows+1 WHERE singleton",
            &[],
        )
        .await
        .unwrap();
}

/// Remove a live custody row by hand and give back its ledger charge, the way a
/// manual repair would, so the invariant keeps holding.
async fn remove_live_custody_by_hand(direct: &Client, hash: &[u8], epoch: i64) {
    let removed = direct
        .execute(
            "DELETE FROM lore_fragment_stage_custody WHERE hash=$1 AND epoch=$2 AND state<>3",
            &[&hash, &epoch],
        )
        .await
        .unwrap();
    assert_eq!(removed, 1);
    direct
        .execute(
            "UPDATE lore_fragment_stage_usage SET live_bytes=live_bytes-128, live_files=live_files-1, \
             metadata_bytes=metadata_bytes-1024, metadata_rows=metadata_rows-1 WHERE singleton",
            &[],
        )
        .await
        .unwrap();
}

/// Guardrail. With room for four metadata rows, six or more promote-and-clean
/// rounds must still leave room for a new stage. Before the fix every round kept
/// a tombstone, so the fifth reservation was refused (`stage capacity exhausted`)
/// and this case failed inside the loop.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn cleaned_predecessors_do_not_consume_the_metadata_row_budget() {
    let env = env_with_metadata_rows(4).await;
    for round in 0..8u8 {
        let hash = [0x30 + round; 32];
        let epoch = stage_and_promote(&env.coordinator, &hash).await;
        assert_eq!(
            usage(&env.coordinator).await,
            (128, 1, 1024, 1),
            "round {round}: only the live reservation holds a row"
        );
        clean(&env.coordinator, &hash, epoch).await;
        assert_eq!(
            usage(&env.coordinator).await,
            (0, 0, 0, 0),
            "round {round}: a redundant release gives the whole row back"
        );
        assert_eq!(custody_rows(&env.direct, &hash, epoch).await, 0);
        assert_eq!(
            epoch_disposition(&env.direct, &hash, epoch).await,
            Some(schema::DISPOSITION_PURGED)
        );
        stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;
    }
    assert!(
        matches!(
            env.coordinator
                .begin_stage(&[0x7f; 32], input())
                .await
                .unwrap(),
            BeginOutcome::Admitted(_)
        ),
        "the budget is still open after more rounds than max_metadata_rows"
    );
    let observed = env.coordinator.observe_stage().await.unwrap();
    assert!(!observed.metadata_full);
    assert_eq!(observed.kept_tombstones, 0);
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;
}

/// Guardrail for the orphan branch. Reclaiming files that have no head and no
/// epoch row charged a fresh row each time and kept it; past `max_metadata_rows`
/// the reclaim itself was refused.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn orphan_reclaims_cycle_past_max_metadata_rows() {
    let env = env_with_metadata_rows(4).await;
    for round in 0..8u8 {
        let hash = [0xA0 + round; 32];
        let epoch = 9000 + i64::from(round);
        let cleanup = env
            .coordinator
            .begin_stage_cleanup(&hash, epoch)
            .await
            .unwrap()
            .expect("an orphan with no head and no epoch is reclaimed");
        assert_eq!(
            usage(&env.coordinator).await,
            (ORPHAN_CHARGE, 1, 1024, 1),
            "round {round}: the reclaim holds one full charge"
        );
        env.coordinator
            .commit_stage_cleanup(&cleanup)
            .await
            .unwrap();
        env.coordinator
            .commit_stage_cleanup(&cleanup)
            .await
            .unwrap();
        assert_eq!(usage(&env.coordinator).await, (0, 0, 0, 0), "round {round}");
        assert_eq!(custody_rows(&env.direct, &hash, epoch).await, 0);
        stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;
    }
    assert!(matches!(
        env.coordinator
            .begin_stage(&[0x7e; 32], input())
            .await
            .unwrap(),
        BeginOutcome::Admitted(_)
    ));
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;
}

/// A late file for an epoch whose custody row was already deleted is cleaned
/// with a fresh charge, and the release gives that charge back.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn late_residue_of_a_purged_epoch_is_reauthorized_with_a_balanced_fresh_charge() {
    let env = env().await;
    let hash = [0x41; 32];
    let epoch = purged_predecessor(&env.coordinator, &hash).await;
    assert_eq!(usage(&env.coordinator).await, (0, 0, 0, 0));
    assert_eq!(custody_rows(&env.direct, &hash, epoch).await, 0);
    let before = env.coordinator.observe_stage().await.unwrap();

    let retry = env
        .coordinator
        .begin_stage_cleanup(&hash, epoch)
        .await
        .unwrap()
        .expect("a PURGED staged epoch with a late file is re-authorized");
    assert_eq!(retry.target().epoch(), epoch);
    assert_eq!(retry.target().authority(), EpochAuthority::Staged);
    let held = env.coordinator.observe_stage().await.unwrap();
    // The bytes of a PURGED epoch were charged once and given back: the fresh
    // reserve takes a file slot and a metadata row, and no bytes.
    assert_eq!((held.resident_bytes, held.resident_files), (0, 1));
    assert_eq!((held.metadata_bytes, held.metadata_rows), (1024, 1));
    assert_eq!(held.charged_bytes, before.charged_bytes);
    assert_eq!(held.charged_files, before.charged_files + 1);
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;

    env.coordinator.commit_stage_cleanup(&retry).await.unwrap();
    env.coordinator.commit_stage_cleanup(&retry).await.unwrap();
    let after = env.coordinator.observe_stage().await.unwrap();
    assert_eq!(
        (
            after.resident_bytes,
            after.resident_files,
            after.metadata_bytes,
            after.metadata_rows
        ),
        (0, 0, 0, 0),
        "the release returns live and metadata counters to their prior values"
    );
    assert_eq!(
        (after.charged_bytes, after.charged_files),
        (held.charged_bytes, held.charged_files),
        "the charged counters keep the fresh charge and never fall"
    );
    assert_eq!(custody_rows(&env.direct, &hash, epoch).await, 0);
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;
}

/// An expired preparation leaves the head at its epoch with no epochs row, so
/// the tombstone is the only cleanup authority for a late file. It stays, a late
/// file is cleaned through it, and no second charge is made.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn expired_preparation_keeps_its_tombstone_and_late_residue_reuses_it() {
    let env = env().await;
    let hash = [0x42; 32];
    let BeginOutcome::Admitted(stage) = env.coordinator.begin_stage(&hash, input()).await.unwrap()
    else {
        panic!("a fresh hash admits a stage begin");
    };
    env.direct
        .execute(
            "UPDATE lore_fragment_stage_custody SET prepare_deadline=clock_timestamp()-interval '1 second' \
             WHERE hash=$1 AND epoch=$2",
            &[&hash.as_slice(), &stage.epoch],
        )
        .await
        .unwrap();
    let first = env
        .coordinator
        .begin_stage_cleanup(&hash, stage.epoch)
        .await
        .unwrap()
        .expect("an expired preparation is reclaimed");
    env.coordinator.commit_stage_cleanup(&first).await.unwrap();
    let kept = env.coordinator.observe_stage().await.unwrap();
    assert_eq!(
        (
            kept.resident_bytes,
            kept.resident_files,
            kept.metadata_bytes,
            kept.metadata_rows
        ),
        (0, 0, 256, 1),
        "the head still names this epoch, so the row stays as a tombstone"
    );
    assert_eq!(kept.kept_tombstones, 1);
    assert_eq!(
        epoch_disposition(&env.direct, &hash, stage.epoch).await,
        None
    );
    assert_eq!(custody_rows(&env.direct, &hash, stage.epoch).await, 1);
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;

    let late = env
        .coordinator
        .begin_stage_cleanup(&hash, stage.epoch)
        .await
        .unwrap()
        .expect("the kept tombstone retains cleanup authority");
    assert_eq!(late.target().epoch(), stage.epoch);
    env.coordinator.commit_stage_cleanup(&late).await.unwrap();
    env.coordinator.commit_stage_cleanup(&late).await.unwrap();
    let after = env.coordinator.observe_stage().await.unwrap();
    assert_eq!(
        (
            after.resident_bytes,
            after.resident_files,
            after.metadata_bytes,
            after.metadata_rows,
            after.kept_tombstones
        ),
        (0, 0, 256, 1, 1)
    );
    assert_eq!(
        (after.charged_bytes, after.charged_files),
        (kept.charged_bytes, kept.charged_files),
        "a late file cleaned through the tombstone makes no second charge"
    );
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;
}

/// Re-authorizing a missing custody row is for a PURGED epoch only. A quarantined
/// or current-eligible staged epoch whose custody row is gone was not cleaned, so
/// nothing authorizes unlinking its file.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn only_a_purged_epoch_is_reauthorized_when_its_custody_row_is_missing() {
    let env = env().await;

    let quarantined = [0x43; 32];
    let epoch = stage_and_promote(&env.coordinator, &quarantined).await;
    assert_eq!(
        epoch_disposition(&env.direct, &quarantined, epoch).await,
        Some(schema::DISPOSITION_QUARANTINED)
    );
    remove_live_custody_by_hand(&env.direct, &quarantined, epoch).await;
    assert!(
        env.coordinator
            .begin_stage_cleanup(&quarantined, epoch)
            .await
            .unwrap()
            .is_none(),
        "a QUARANTINED epoch is not authorized by a missing row"
    );
    assert_eq!(custody_rows(&env.direct, &quarantined, epoch).await, 0);
    assert_eq!(usage(&env.coordinator).await, (0, 0, 0, 0));

    let eligible = [0x44; 32];
    let epoch = stage_and_promote(&env.coordinator, &eligible).await;
    env.direct
        .execute(
            "UPDATE lore_fragment_epochs SET disposition=$3 WHERE hash=$1 AND epoch=$2 AND authority=1",
            &[
                &eligible.as_slice(),
                &epoch,
                &schema::DISPOSITION_CURRENT_ELIGIBLE,
            ],
        )
        .await
        .unwrap();
    remove_live_custody_by_hand(&env.direct, &eligible, epoch).await;
    assert!(
        env.coordinator
            .begin_stage_cleanup(&eligible, epoch)
            .await
            .unwrap()
            .is_none(),
        "a disposition 0 epoch is not authorized by a missing row"
    );
    assert_eq!(custody_rows(&env.direct, &eligible, epoch).await, 0);
    assert_eq!(usage(&env.coordinator).await, (0, 0, 0, 0));
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;
}

/// Two replicas, one residue key. One reservation is made, and the refund is
/// given once, whether the callers begin together and commit together or race
/// the whole begin-and-commit sequence.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn two_replicas_racing_one_residue_key_reserve_once_and_refund_once() {
    let first = env().await;
    let second_store = PostgresDomainStore::connect(&first.url, 8, &TlsConfig::default())
        .await
        .unwrap();
    let second = second_store.fragment_coordinator();
    let a = &first.coordinator;
    let b = &second;

    // Phase one: both begin before either commits, so the second sees the first's
    // reservation. Exactly one reservation is made.
    for key in 0..6u8 {
        let hash = [0x50 + key; 32];
        let epoch = purged_predecessor(a, &hash).await;
        let before = a.observe_stage().await.unwrap();
        let (left, right) = tokio::join!(
            a.begin_stage_cleanup(&hash, epoch),
            b.begin_stage_cleanup(&hash, epoch)
        );
        let left = left.unwrap().expect("first replica is granted");
        let right = right.unwrap().expect("second replica is granted");
        let held = a.observe_stage().await.unwrap();
        assert_eq!(
            (held.resident_files, held.metadata_rows),
            (1, 1),
            "key {key}: one reservation overall"
        );
        assert_eq!(held.charged_files, before.charged_files + 1);
        assert_eq!(
            held.charged_bytes, before.charged_bytes,
            "a purged epoch's reclaim charges no bytes"
        );
        let (left, right) = tokio::join!(
            a.commit_stage_cleanup(&left),
            b.commit_stage_cleanup(&right)
        );
        left.unwrap();
        right.unwrap();
        let after = a.observe_stage().await.unwrap();
        assert_eq!(
            (
                after.resident_bytes,
                after.resident_files,
                after.metadata_bytes,
                after.metadata_rows
            ),
            (0, 0, 0, 0),
            "key {key}: refunded once, never below zero"
        );
        assert_eq!(
            (after.charged_bytes, after.charged_files),
            (held.charged_bytes, held.charged_files)
        );
        stage_invariant::assert_stage_ledger_matches_custody(&first.url).await;
    }

    // Phase two: each replica runs the whole sequence. The interleaving is free,
    // so a late commit may meet a deleted row or a fresh reservation. The charge
    // count may be one or two, and the ledger must balance either way.
    for key in 0..6u8 {
        let hash = [0x60 + key; 32];
        let epoch = purged_predecessor(a, &hash).await;
        let before = a.observe_stage().await.unwrap();
        let (left, right) = tokio::join!(
            async {
                let intent = a.begin_stage_cleanup(&hash, epoch).await?.expect("granted");
                a.commit_stage_cleanup(&intent).await
            },
            async {
                let intent = b.begin_stage_cleanup(&hash, epoch).await?.expect("granted");
                b.commit_stage_cleanup(&intent).await
            }
        );
        left.unwrap();
        right.unwrap();
        let after = a.observe_stage().await.unwrap();
        assert_eq!(
            (
                after.resident_bytes,
                after.resident_files,
                after.metadata_bytes,
                after.metadata_rows
            ),
            (0, 0, 0, 0),
            "key {key}"
        );
        let charged = after.charged_files - before.charged_files;
        assert!((1..=2).contains(&charged), "key {key}: charged {charged}");
        assert_eq!(after.charged_bytes, before.charged_bytes);
        stage_invariant::assert_stage_ledger_matches_custody(&first.url).await;
    }
    drop(second_store);
}

/// Legacy tombstones for PURGED staged epochs are compacted; tombstones that
/// still guard a late file are not; the cursor walks to the end.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn sweep_compacts_legacy_tombstones_keeps_guarding_ones_and_walks_to_the_end() {
    let env = env().await;
    let c = &env.coordinator;
    // Order by hash: K10 L11 K12 L13 K14 L15.
    let mut kept = Vec::new();
    let mut legacy = Vec::new();
    for byte in [0x10u8, 0x12, 0x14] {
        let hash = [byte; 32];
        kept.push((hash, kept_tombstone(c, &hash).await));
    }
    for byte in [0x11u8, 0x13, 0x15] {
        let hash = [byte; 32];
        let epoch = purged_predecessor(c, &hash).await;
        reinstate_legacy_tombstone(&env.direct, &hash, epoch).await;
        legacy.push((hash, epoch));
    }
    assert_eq!(usage(c).await, (0, 0, 6 * 256, 6));
    assert_eq!(c.observe_stage().await.unwrap().kept_tombstones, 6);
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;

    for bad in [0u32, 257] {
        assert!(
            matches!(
                c.compact_stage_tombstones(None, bad).await,
                Err(DomainError::InvalidInput(_))
            ),
            "limit {bad} is outside 1..=256"
        );
    }
    assert_eq!(usage(c).await, (0, 0, 6 * 256, 6));

    let mut cursor: Option<(Vec<u8>, i64)> = None;
    let (mut examined, mut compacted, mut passes) = (0, 0, 0);
    let mut seen: Vec<(Vec<u8>, i64)> = Vec::new();
    loop {
        let after = cursor
            .as_ref()
            .map(|(hash, epoch)| (hash.as_slice(), *epoch));
        let sweep = c.compact_stage_tombstones(after, 2).await.unwrap();
        passes += 1;
        assert!(passes <= 5, "the cursor must reach the end");
        examined += sweep.examined;
        compacted += sweep.compacted;
        if sweep.examined == 0 {
            break;
        }
        let Some(last) = sweep.last else { break };
        if let Some(previous) = seen.last() {
            assert!(last > *previous, "the cursor only moves forward");
        }
        seen.push(last.clone());
        cursor = Some(last);
    }
    assert_eq!(examined, 6, "every tombstone was examined once");
    assert_eq!(compacted, 3, "only the three legacy rows were compacted");
    assert_eq!(usage(c).await, (0, 0, 3 * 256, 3));
    for (hash, epoch) in &legacy {
        assert_eq!(custody_rows(&env.direct, hash, *epoch).await, 0);
    }
    for (hash, epoch) in &kept {
        assert_eq!(custody_rows(&env.direct, hash, *epoch).await, 1);
    }
    assert_eq!(c.observe_stage().await.unwrap().kept_tombstones, 3);
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;

    let again = c.compact_stage_tombstones(None, 256).await.unwrap();
    assert_eq!((again.examined, again.compacted), (3, 0));
    assert_eq!(usage(c).await, (0, 0, 3 * 256, 3));
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;

    // A kept tombstone is still the authority for its late file.
    let (hash, epoch) = kept[0];
    clean(c, &hash, epoch).await;
    assert_eq!(usage(c).await, (0, 0, 3 * 256, 3));
}

/// Two replicas sweep the same rows at once. Each row is deleted once and
/// refunded once.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn concurrent_sweeps_delete_each_legacy_tombstone_once() {
    let first = env().await;
    let second_store = PostgresDomainStore::connect(&first.url, 8, &TlsConfig::default())
        .await
        .unwrap();
    let second = second_store.fragment_coordinator();
    let a = &first.coordinator;
    for byte in 0x70..0x76u8 {
        let hash = [byte; 32];
        let epoch = purged_predecessor(a, &hash).await;
        reinstate_legacy_tombstone(&first.direct, &hash, epoch).await;
    }
    let kept_hash = [0x7a; 32];
    let kept_epoch = kept_tombstone(a, &kept_hash).await;
    assert_eq!(usage(a).await, (0, 0, 7 * 256, 7));

    let (left, right) = tokio::join!(
        a.compact_stage_tombstones(None, 256),
        second.compact_stage_tombstones(None, 256)
    );
    let (left, right) = (left.unwrap(), right.unwrap());
    assert_eq!(
        left.compacted + right.compacted,
        6,
        "each legacy row is deleted by exactly one sweep: {left:?} {right:?}"
    );
    assert_eq!(usage(a).await, (0, 0, 256, 1), "refunded once, never twice");
    assert_eq!(custody_rows(&first.direct, &kept_hash, kept_epoch).await, 1);
    stage_invariant::assert_stage_ledger_matches_custody(&first.url).await;
    drop(second_store);
}

/// The rollback script restores one tombstone per PURGED staged epoch that has
/// none, adds exactly their charge to the ledger, and a second run adds nothing.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn rebuild_sql_restores_one_tombstone_per_purged_staged_epoch_exactly_once() {
    let env = env().await;
    let c = &env.coordinator;

    let mut missing = Vec::new();
    for byte in [0x21u8, 0x22, 0x23] {
        let hash = [byte; 32];
        missing.push((hash, purged_predecessor(c, &hash).await));
    }
    // Controls the script must leave alone.
    let present = [0x24; 32];
    let present_epoch = purged_predecessor(c, &present).await;
    reinstate_legacy_tombstone(&env.direct, &present, present_epoch).await;
    let quarantined = [0x25; 32];
    let quarantined_epoch = stage_and_promote(c, &quarantined).await;
    remove_live_custody_by_hand(&env.direct, &quarantined, quarantined_epoch).await;
    assert_eq!(usage(c).await, (0, 0, 256, 1));
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;

    env.direct
        .batch_execute(STAGE_TOMBSTONE_REBUILD_SQL)
        .await
        .unwrap();
    assert_eq!(
        usage(c).await,
        (0, 0, 256 + 3 * 256, 1 + 3),
        "the ledger grows by exactly the rebuilt rows"
    );
    for (hash, epoch) in &missing {
        let row = env
            .direct
            .query_one(
                "SELECT state,size_payload,original_flags IS NULL,metadata_bytes,purged_at IS NOT NULL,operation_fence \
                 FROM lore_fragment_stage_custody WHERE hash=$1 AND epoch=$2",
                &[&hash.as_slice(), epoch],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i16>(0), 3);
        assert_eq!(row.get::<_, i64>(1), 0);
        assert!(row.get::<_, bool>(2));
        assert_eq!(row.get::<_, i64>(3), 256);
        assert!(row.get::<_, bool>(4));
        assert!(row.get::<_, i64>(5) > 0);
    }
    assert_eq!(
        custody_rows(&env.direct, &quarantined, quarantined_epoch).await,
        0,
        "a QUARANTINED epoch is not rebuilt"
    );
    let distinct_fences: i64 = env
        .direct
        .query_one(
            "SELECT count(DISTINCT operation_fence) FROM lore_fragment_stage_custody",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(distinct_fences, 4, "every rebuilt row has its own fence");
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;

    env.direct
        .batch_execute(STAGE_TOMBSTONE_REBUILD_SQL)
        .await
        .unwrap();
    assert_eq!(
        usage(c).await,
        (0, 0, 256 + 3 * 256, 1 + 3),
        "a second run is a no-op"
    );
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;

    // A rebuilt tombstone is a real tombstone: the sweep reclaims it again.
    let sweep = c.compact_stage_tombstones(None, 256).await.unwrap();
    assert_eq!((sweep.examined, sweep.compacted), (4, 4));
    assert_eq!(usage(c).await, (0, 0, 0, 0));
    drop(env.store);
}

/// Seed the custody row a rival reclaim would commit, in an open transaction on
/// a second session, then let this replica's headless orphan reclaim race into
/// it. The loser's reserve waits on the unique key, then finds the key taken.
/// The error says so, the winner's single charge stands, and nothing is
/// refunded twice.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn the_loser_of_a_concurrent_headless_reserve_is_told_the_key_is_taken() {
    let env = env().await;
    let (rival, connection) = tokio_postgres::connect(&env.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("rival postgres connection error: {error}");
        }
    });
    let hash = [0xC1; 32];
    let epoch = 9100i64;
    rival
        .batch_execute(&format!(
            "BEGIN; \
             INSERT INTO lore_fragment_stage_custody \
               (hash,epoch,operation_fence,original_flags,size_payload,prepare_deadline,state,metadata_bytes) \
               VALUES('\\x{}',{epoch},nextval('lore_fragment_fence_seq'),0,{ORPHAN_CHARGE},clock_timestamp(),2,1024); \
             UPDATE lore_fragment_stage_usage SET live_bytes=live_bytes+{ORPHAN_CHARGE}, live_files=live_files+1, \
               charged_bytes=charged_bytes+{ORPHAN_CHARGE}, charged_files=charged_files+1, \
               metadata_bytes=metadata_bytes+1024, metadata_rows=metadata_rows+1;",
            hex::encode(hash)
        ))
        .await
        .unwrap();
    let release = async {
        // Commit only once the reclaim's insert is queued behind the rival's.
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let waiting: i64 = env
                    .direct
                    .query_one(
                        "SELECT count(*) FROM pg_stat_activity \
                         WHERE wait_event_type = 'Lock' \
                           AND query LIKE 'INSERT INTO lore_fragment_stage_custody%'",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get(0);
                if waiting > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the reclaim's reserve must queue behind the rival's insert");
        rival.batch_execute("COMMIT").await.unwrap();
    };
    let (result, ()) = tokio::join!(env.coordinator.begin_stage_cleanup(&hash, epoch), release);
    let error = result.expect_err("the loser has no reservation to hold");
    assert!(
        is_stage_custody_key_taken(&error),
        "the loser is told the key is taken: {error:?}"
    );
    assert_eq!(
        usage(&env.coordinator).await,
        (ORPHAN_CHARGE, 1, 1024, 1),
        "only the winner's charge stands"
    );
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;

    // The winner's row is a sealed grant: the next call returns it, and its
    // release gives the one charge back.
    clean(&env.coordinator, &hash, epoch).await;
    assert_eq!(usage(&env.coordinator).await, (0, 0, 0, 0));
    assert_eq!(custody_rows(&env.direct, &hash, epoch).await, 0);
    stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;
}

/// The same race without a seam: two replicas reclaim one headless orphan at
/// once. Whoever loses either sees the sealed row or is told the key is taken.
/// One charge is made, and it is refunded once.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn two_replicas_racing_one_headless_orphan_make_one_charge() {
    let first = env().await;
    let second_store = PostgresDomainStore::connect(&first.url, 8, &TlsConfig::default())
        .await
        .unwrap();
    let second = second_store.fragment_coordinator();
    let a = &first.coordinator;
    let mut taken = 0;
    for key in 0..8u8 {
        let hash = [0xC8 + key; 32];
        let epoch = 9200;
        let before = a.observe_stage().await.unwrap();
        let (left, right) = tokio::join!(
            a.begin_stage_cleanup(&hash, epoch),
            second.begin_stage_cleanup(&hash, epoch)
        );
        let mut intents = Vec::new();
        for outcome in [left, right] {
            match outcome {
                Ok(Some(intent)) => intents.push(intent),
                Ok(None) => panic!("key {key}: a headless orphan is never refused"),
                Err(error) if is_stage_custody_key_taken(&error) => taken += 1,
                Err(error) => panic!("key {key}: unexpected error {error:?}"),
            }
        }
        assert!(!intents.is_empty(), "key {key}: one replica wins");
        let held = a.observe_stage().await.unwrap();
        assert_eq!(
            (held.resident_bytes, held.resident_files),
            (ORPHAN_CHARGE, 1),
            "key {key}: one reservation"
        );
        assert_eq!(held.charged_files, before.charged_files + 1);
        assert_eq!(held.charged_bytes, before.charged_bytes + ORPHAN_CHARGE);
        for intent in &intents {
            a.commit_stage_cleanup(intent).await.unwrap();
        }
        assert_eq!(usage(a).await, (0, 0, 0, 0), "key {key}: refunded once");
        stage_invariant::assert_stage_ledger_matches_custody(&first.url).await;
    }
    eprintln!("replicas told the key was taken: {taken} of 8 races");
    drop(second_store);
}

/// The loser of a headless reserve is classified by the policy, not by a
/// re-read of the key. The winner may already have released and deleted its
/// redundant row, and a re-read would then read "policy absent or expired".
///
/// Each round holds the rival's insert open, queues the reclaim's reserve behind
/// it (`pg_stat_activity` shows the Lock wait), then sends the rival's commit and
/// its cleanup (delete plus refund) in ONE round trip. The reclaim wakes on the
/// commit and meets a deleted row as often as the scheduler allows; the
/// interleaving between the two backends cannot be pinned further without
/// production hooks, so every round asserts the classification, which must hold
/// whichever backend is first.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn a_loser_whose_winner_already_deleted_its_row_is_still_told_the_key_is_taken() {
    let env = env().await;
    let (rival, connection) = tokio_postgres::connect(&env.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("rival postgres connection error: {error}");
        }
    });
    for round in 0..25u8 {
        let hash = [0xE0 + (round % 16); 32];
        let epoch = 9300 + i64::from(round);
        let encoded = hex::encode(hash);
        rival
            .batch_execute(&format!(
                "BEGIN; \
                 INSERT INTO lore_fragment_stage_custody \
                   (hash,epoch,operation_fence,original_flags,size_payload,prepare_deadline,state,metadata_bytes) \
                   VALUES('\\x{encoded}',{epoch},nextval('lore_fragment_fence_seq'),0,{ORPHAN_CHARGE},clock_timestamp(),2,1024); \
                 UPDATE lore_fragment_stage_usage SET live_bytes=live_bytes+{ORPHAN_CHARGE}, live_files=live_files+1, \
                   charged_bytes=charged_bytes+{ORPHAN_CHARGE}, charged_files=charged_files+1, \
                   metadata_bytes=metadata_bytes+1024, metadata_rows=metadata_rows+1;"
            ))
            .await
            .unwrap();
        let release = async {
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    let waiting: i64 = env
                        .direct
                        .query_one(
                            "SELECT count(*) FROM pg_stat_activity \
                             WHERE wait_event_type = 'Lock' \
                               AND query LIKE 'INSERT INTO lore_fragment_stage_custody%'",
                            &[],
                        )
                        .await
                        .unwrap()
                        .get(0);
                    if waiting > 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the reclaim's reserve must queue behind the rival's insert");
            // The winner commits, then cleans up at once: delete the redundant
            // row and give its charge back.
            rival
                .batch_execute(&format!(
                    "COMMIT; BEGIN; \
                     DELETE FROM lore_fragment_stage_custody WHERE hash='\\x{encoded}' AND epoch={epoch}; \
                     UPDATE lore_fragment_stage_usage SET live_bytes=live_bytes-{ORPHAN_CHARGE}, live_files=live_files-1, \
                       metadata_bytes=metadata_bytes-1024, metadata_rows=metadata_rows-1; \
                     COMMIT;"
                ))
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(env.coordinator.begin_stage_cleanup(&hash, epoch), release);
        let error = result.expect_err("the loser holds no reservation");
        assert!(
            is_stage_custody_key_taken(&error),
            "round {round}: the loser is told the key is taken, not {error:?}"
        );
        assert_eq!(custody_rows(&env.direct, &hash, epoch).await, 0);
        assert_eq!(usage(&env.coordinator).await, (0, 0, 0, 0), "round {round}");
        stage_invariant::assert_stage_ledger_matches_custody(&env.url).await;
    }
}
