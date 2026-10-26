// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! A staged obliterate's release of its stage custody row.
//!
//! `commit_obliterate_payload` PURGEs the evidence epochs before it releases the
//! staged custody rows, so every released row is redundant and is deleted. The
//! release stays strict about a missing row: obliterate names only the current
//! epoch, which no cleanup may have deleted yet. These cases live in the library
//! because a purge proof can only be built inside the crate.
use rand::random;

use crate::domain::PostgresDomainStore;
use crate::domain::errors::DomainError;
use crate::domain::fragments::BeginOutcome;
use crate::domain::fragments::CommitVerdict;
use crate::domain::fragments::EpochAuthority;
use crate::domain::fragments::FragmentManifest;
use crate::domain::fragments::FragmentObliterateBegin;
use crate::domain::fragments::FragmentObliterateIntent;
use crate::domain::fragments::FragmentPurgeProof;
use crate::domain::fragments::FragmentWriteCapabilityCutover;
use crate::domain::fragments::IoObservation;
use crate::domain::fragments::PostgresFragmentCoordinator;
use crate::domain::fragments::StageReservationInput;
use crate::domain::fragments::schema;
use crate::domain::fragments::states::FragmentLifecycleState;
use crate::pool::TlsConfig;

const REVISION: &str = "write-claims-v1";

struct Fixture {
    _store: PostgresDomainStore,
    coordinator: PostgresFragmentCoordinator,
    client: tokio_postgres::Client,
    hash: [u8; 32],
    payload: Box<FragmentObliterateIntent>,
}

/// A staged, associated fragment at the payload phase of an exact obliterate,
/// with its 128-byte stage reservation still held.
async fn staged_obliterate_at_payload_phase() -> Fixture {
    let url = std::env::var("LORE_TEST_PG_URL").expect("runner must provide LORE_TEST_PG_URL");
    let store = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
        .await
        .expect("connect domain store");
    let coordinator = store.fragment_coordinator();
    coordinator
        .bootstrap()
        .await
        .expect("install fragment schema");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect assertion client");
    lore_base::lore_spawn!(async move {
        let _ = connection.await;
    });
    client
        .batch_execute(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance; END IF; END $$; \
             SET SESSION AUTHORIZATION object_dispatch_retention_maintenance",
        )
        .await
        .expect("assume the maintenance role");
    client
        .execute(
            "SELECT stage_policy_publish_v1('fixture-cell','fixture-policy-v1',decode(repeat('aa',32),'hex'),1073741824,100000,1073741824,100000,60000,4102444800000)",
            &[],
        )
        .await
        .expect("publish the stage policy");
    client
        .batch_execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("drop the maintenance role");
    client
        .execute(
            "UPDATE lore_fragment_schema_state \
                SET backfill_state = $1, cutover_at = clock_timestamp(), \
                    residue_classified = true, sequence_headroom_fence = 1 \
              WHERE id = 1",
            &[&schema::BACKFILL_CUTOVER],
        )
        .await
        .expect("stage lifecycle cutover");
    coordinator
        .enable_lifecycle()
        .await
        .expect("enable lifecycle");
    coordinator
        .require_write_claims(&FragmentWriteCapabilityCutover::new(REVISION).expect("revision"))
        .await
        .expect("require claims");
    let repository_id = random::<[u8; 16]>();
    client
        .execute(
            "INSERT INTO lore_domain_repositories ( \
                repository_id, state, generation, name, metadata_hash, \
                default_branch_id, creation_fingerprint_version, \
                creation_fingerprint, created_at \
             ) VALUES ($1, 0, 1, $2, $3, $4, 1, $5, clock_timestamp())",
            &[
                &repository_id.as_slice(),
                &format!("staged-obliterate-{:016x}", random::<u64>()),
                &random::<[u8; 32]>().as_slice(),
                &random::<[u8; 16]>().as_slice(),
                &random::<[u8; 32]>().as_slice(),
            ],
        )
        .await
        .expect("insert repository fixture");

    let hash = random::<[u8; 32]>();
    let context = random::<[u8; 16]>();
    let BeginOutcome::Admitted(stage) = coordinator
        .begin_stage(
            &hash,
            StageReservationInput {
                size_payload: 128,
                original_flags: 0,
            },
        )
        .await
        .expect("begin stage")
    else {
        panic!("a fresh hash admits a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage,
                IoObservation::Valid(FragmentManifest {
                    authority: EpochAuthority::Staged,
                    object_key: format!("{}.s{}", hex::encode(hash), stage.epoch),
                    manifest_id: vec![0x95; 32],
                    size_payload: 128,
                    size_content: 128,
                    decoded_hash: vec![0x96; 32],
                    payload_flags: 0,
                }),
            )
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );
    let FragmentObliterateBegin::Ready(children) = coordinator
        .begin_obliterate(&hash, &repository_id, &context, REVISION)
        .await
        .expect("begin obliterate")
    else {
        panic!("the sole association owns the obliterate");
    };
    assert_eq!(
        coordinator
            .commit_obliterate_children(&children)
            .await
            .expect("commit children"),
        CommitVerdict::Published
    );
    let FragmentObliterateBegin::Ready(payload) = coordinator
        .begin_obliterate(&hash, &repository_id, &context, REVISION)
        .await
        .expect("resume the payload phase")
    else {
        panic!("the payload phase is ready");
    };
    Fixture {
        _store: store,
        coordinator,
        client,
        hash,
        payload,
    }
}

impl Fixture {
    fn proofs(&self) -> Vec<FragmentPurgeProof> {
        self.payload
            .purge_targets()
            .iter()
            .cloned()
            .map(FragmentPurgeProof::new)
            .collect()
    }

    /// The usage counters must equal the custody rows.
    async fn assert_ledger_matches_custody(&self) {
        let row = self
            .client
            .query_one(
                "SELECT u.metadata_rows, u.metadata_bytes, u.live_files, u.live_bytes, \
                        (SELECT count(*) FROM lore_fragment_stage_custody)::bigint, \
                        (SELECT coalesce(sum(metadata_bytes),0) FROM lore_fragment_stage_custody)::bigint, \
                        (SELECT count(*) FROM lore_fragment_stage_custody WHERE state<>3)::bigint, \
                        (SELECT coalesce(sum(size_payload),0) FROM lore_fragment_stage_custody WHERE state<>3)::bigint \
                 FROM lore_fragment_stage_usage u WHERE u.singleton",
                &[],
            )
            .await
            .unwrap();
        let get = |index: usize| row.get::<_, i64>(index);
        assert_eq!(get(0), get(4), "metadata_rows vs custody rows");
        assert_eq!(get(1), get(5), "metadata_bytes vs custody bytes");
        assert_eq!(get(2), get(6), "live_files vs live custody rows");
        assert_eq!(get(3), get(7), "live_bytes vs live custody payload");
    }

    async fn counters(&self) -> (i64, i64, i64, i64) {
        let observed = self.coordinator.observe_stage().await.unwrap();
        (
            observed.resident_bytes,
            observed.resident_files,
            observed.metadata_bytes,
            observed.metadata_rows,
        )
    }
}

/// The obliterate PURGEs the epoch in its own transaction, so the released row
/// is redundant: it is deleted, its row and bytes come back, and the counters
/// match the custody table.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn staged_obliterate_deletes_the_redundant_custody_row_and_balances_the_ledger() {
    let fixture = staged_obliterate_at_payload_phase().await;
    assert_eq!(fixture.counters().await, (128, 1, 1024, 1));
    fixture.assert_ledger_matches_custody().await;
    let proofs = fixture.proofs();
    assert_eq!(proofs.len(), 1, "one staged target");
    assert_eq!(
        fixture
            .coordinator
            .commit_obliterate_payload(&fixture.payload, &proofs)
            .await
            .expect("commit payload"),
        CommitVerdict::Published
    );
    assert_eq!(fixture.counters().await, (0, 0, 0, 0));
    assert_eq!(
        fixture
            .coordinator
            .observe_stage()
            .await
            .unwrap()
            .kept_tombstones,
        0
    );
    let rows: i64 = fixture
        .client
        .query_one(
            "SELECT count(*) FROM lore_fragment_stage_custody WHERE hash = $1",
            &[&fixture.hash.as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 0, "the released row is deleted, not kept");
    fixture.assert_ledger_matches_custody().await;
}

/// A current staged epoch whose custody row is missing is corruption. The commit
/// refuses with `NotReady` and rolls back the tombstone and the epoch purge. The
/// redundancy rule is not an excuse, because the transaction's own purge would
/// always satisfy it.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn staged_obliterate_refuses_a_missing_current_epoch_custody_row_and_changes_nothing() {
    let fixture = staged_obliterate_at_payload_phase().await;
    let proofs = fixture.proofs();
    let removed = fixture
        .client
        .execute(
            "DELETE FROM lore_fragment_stage_custody WHERE hash = $1",
            &[&fixture.hash.as_slice()],
        )
        .await
        .unwrap();
    assert_eq!(removed, 1, "corrupt the ledger by hand");
    let before = fixture.counters().await;
    let result = fixture
        .coordinator
        .commit_obliterate_payload(&fixture.payload, &proofs)
        .await;
    assert!(
        matches!(&result, Err(DomainError::NotReady(detail)) if detail == "obliterate custody missing"),
        "a missing staged custody row refuses: {result:?}"
    );
    let head_state: i16 = fixture
        .client
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&fixture.hash.as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        head_state,
        FragmentLifecycleState::DeletingPayload.bits(),
        "the refusal rolled the tombstone back"
    );
    let dispositions: Vec<i16> = fixture
        .client
        .query(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1",
            &[&fixture.hash.as_slice()],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        dispositions,
        vec![schema::DISPOSITION_CURRENT_ELIGIBLE],
        "the refusal rolled the epoch purge back"
    );
    assert_eq!(fixture.counters().await, before, "no counter moved");
}
