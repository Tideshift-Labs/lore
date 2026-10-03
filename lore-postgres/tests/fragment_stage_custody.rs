// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

#[path = "common/stage_policy.rs"]
mod stage_policy;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::fragments::BeginOutcome;
use lore_postgres::domain::fragments::CommitVerdict;
use lore_postgres::domain::fragments::EpochAuthority;
use lore_postgres::domain::fragments::FragmentManifest;
use lore_postgres::domain::fragments::IoObservation;
use lore_postgres::domain::fragments::StageReservationInput;
use lore_postgres::pool::TlsConfig;

async fn store() -> (String, PostgresDomainStore) {
    let url = std::env::var("LORE_TEST_PG_URL").expect("owned disposable PostgreSQL required");
    let store = PostgresDomainStore::connect(&url, 8, &TlsConfig::default())
        .await
        .unwrap();
    store.fragment_coordinator().bootstrap().await.unwrap();
    (url, store)
}

fn input(size: u64) -> StageReservationInput {
    StageReservationInput {
        size_payload: size,
        original_flags: 0x8000_0000,
    }
}

async fn race_capacity(bytes: i64, files: i64) {
    let (url, first_store) = store().await;
    let first = first_store.fragment_coordinator();
    stage_policy::initialize_with_capacity(&url, &first, bytes, files).await;
    let second_store = PostgresDomainStore::connect(&url, 8, &TlsConfig::default())
        .await
        .unwrap();
    let second = second_store.fragment_coordinator();
    let (left, right) = tokio::join!(
        first.begin_stage(&[1; 32], input(128)),
        second.begin_stage(&[2; 32], input(128))
    );
    let winners = [&left, &right]
        .iter()
        .filter(|r| matches!(r, Ok(BeginOutcome::Admitted(_))))
        .count();
    assert_eq!(
        winners, 1,
        "one exact reservation fits: {left:?}, {right:?}"
    );
    assert_eq!([&left, &right].iter().filter(|r| r.is_err()).count(), 1);
    let usage = first.observe_stage().await.unwrap();
    assert_eq!((usage.resident_bytes, usage.resident_files), (128, 1));
    assert_eq!(
        (usage.charged_bytes, usage.charged_files),
        (128, 1),
        "the refused reservation charged nothing"
    );
    assert_eq!((usage.metadata_bytes, usage.metadata_rows), (1024, 1));
}

#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn two_replicas_cannot_overbook_the_last_stage_bytes() {
    race_capacity(128, 10).await;
}

#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn two_replicas_cannot_overbook_the_last_stage_file() {
    race_capacity(4096, 1).await;
}

#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn missing_policy_refuses_stage_without_leaving_custody_or_usage() {
    let (url, store) = store().await;
    let coordinator = store.fragment_coordinator();
    assert!(coordinator.begin_stage(&[3; 32], input(128)).await.is_err());
    assert!(
        coordinator.observe_stage().await.is_err(),
        "missing policy cannot report ready observation"
    );
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let task = lore_base::lore_spawn!(async move {
        connection.await.unwrap();
    });
    let row = client.query_one("SELECT live_bytes,live_files,metadata_rows,(SELECT count(*) FROM lore_fragment_stage_custody) FROM lore_fragment_stage_usage", &[]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2),
            row.get::<_, i64>(3)
        ),
        (0, 0, 0, 0)
    );
    drop(client);
    task.await.unwrap();
}

#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn already_readable_replay_does_not_reserve_capacity_twice() {
    let (url, store) = store().await;
    let coordinator = store.fragment_coordinator();
    stage_policy::initialize(&url, &coordinator).await;
    let hash = [4; 32];
    let BeginOutcome::Admitted(intent) = coordinator.begin_stage(&hash, input(128)).await.unwrap()
    else {
        panic!("fresh stage")
    };
    let manifest = FragmentManifest {
        authority: EpochAuthority::Staged,
        object_key: intent.object_key.clone(),
        manifest_id: vec![5; 32],
        size_payload: 128,
        size_content: 128,
        decoded_hash: hash.to_vec(),
        payload_flags: 0,
    };
    assert_eq!(
        coordinator
            .commit_staged(&intent, IoObservation::Valid(manifest))
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert!(matches!(
        coordinator.begin_stage(&hash, input(128)).await.unwrap(),
        BeginOutcome::AlreadyReadable(_)
    ));
    let usage = coordinator.observe_stage().await.unwrap();
    assert_eq!(
        (
            usage.resident_bytes,
            usage.resident_files,
            usage.metadata_rows
        ),
        (128, 1, 1)
    );
    assert_eq!(
        (usage.charged_bytes, usage.charged_files),
        (128, 1),
        "a replay charges nothing, so the counters do not move"
    );
}

/// Row 78: the charge counters add exactly what each reservation adds to the
/// ledger and never fall. A withdrawn and cleaned reservation gives its ledger
/// charge back and leaves the counters where they were.
#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn stage_charge_counters_only_grow() {
    let (url, store) = store().await;
    let coordinator = store.fragment_coordinator();
    stage_policy::initialize(&url, &coordinator).await;
    let fresh = coordinator.observe_stage().await.unwrap();
    assert_eq!((fresh.charged_bytes, fresh.charged_files), (0, 0));
    let BeginOutcome::Admitted(first) =
        coordinator.begin_stage(&[6; 32], input(128)).await.unwrap()
    else {
        panic!("first stage admitted")
    };
    let BeginOutcome::Admitted(_second) =
        coordinator.begin_stage(&[7; 32], input(64)).await.unwrap()
    else {
        panic!("second stage admitted")
    };
    let charged = coordinator.observe_stage().await.unwrap();
    assert_eq!((charged.resident_bytes, charged.resident_files), (192, 2));
    assert_eq!((charged.charged_bytes, charged.charged_files), (192, 2));

    assert!(coordinator.withdraw_stage(&first).await.unwrap());
    let cleanup = coordinator
        .begin_stage_cleanup(&[6; 32], first.epoch)
        .await
        .unwrap()
        .expect("a withdrawn reservation is cleaned");
    coordinator.commit_stage_cleanup(&cleanup).await.unwrap();
    let released = coordinator.observe_stage().await.unwrap();
    assert_eq!(
        (released.resident_bytes, released.resident_files),
        (64, 1),
        "the release gives the ledger charge back"
    );
    assert_eq!(
        (released.charged_bytes, released.charged_files),
        (192, 2),
        "a release never lowers the counters"
    );
}

#[tokio::test]
#[ignore = "requires owned live PostgreSQL"]
async fn stage_policy_identity_must_match_the_published_cell_revision_and_digest() {
    let (url, store) = store().await;
    let coordinator = store.fragment_coordinator();
    stage_policy::initialize(&url, &coordinator).await;
    coordinator
        .verify_stage_policy("fixture-cell", "fixture-policy-v1", &[0xaa; 32])
        .await
        .unwrap();
    for (cell, revision, digest) in [
        ("other-cell", "fixture-policy-v1", [0xaa; 32]),
        ("fixture-cell", "other-policy", [0xaa; 32]),
        ("fixture-cell", "fixture-policy-v1", [0xbb; 32]),
    ] {
        assert!(
            coordinator
                .verify_stage_policy(cell, revision, &digest)
                .await
                .is_err()
        );
    }
}
