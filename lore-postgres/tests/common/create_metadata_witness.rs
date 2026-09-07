// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Fixture-only Remote observations through real coordinator transitions. This does not prove provider I/O.
use std::time::Duration;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::fragments::BeginOutcome;
use lore_postgres::domain::fragments::CommitVerdict;
use lore_postgres::domain::fragments::EpochAuthority;
use lore_postgres::domain::fragments::EpochWitness;
use lore_postgres::domain::fragments::FragmentManifest;
use lore_postgres::domain::fragments::FragmentWriteClaimInput;
use lore_postgres::domain::fragments::FragmentWriteSettlement;
use lore_postgres::domain::fragments::IoObservation;
fn claim() -> FragmentWriteClaimInput {
    FragmentWriteClaimInput::new(
        *uuid::Uuid::now_v7().as_bytes(),
        *uuid::Uuid::now_v7().as_bytes(),
        [3; 32],
        1,
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .unwrap()
}
pub async fn publish(store: &PostgresDomainStore, hash: &[u8]) -> EpochWitness {
    let coordinator = store.fragment_coordinator();
    let key = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(hash, &key, claim())
        .await
        .unwrap()
    else {
        panic!("fresh or missing hash must admit fixture publication")
    };
    coordinator
        .authorize_write_claim(intent.write_claim().unwrap())
        .await
        .unwrap();
    let manifest = FragmentManifest {
        authority: EpochAuthority::Remote,
        object_key: intent.object_key.clone(),
        manifest_id: uuid::Uuid::now_v7().as_bytes().repeat(2),
        size_payload: 1,
        size_content: 1,
        decoded_hash: hash.to_vec(),
        payload_flags: 0,
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest),
                FragmentWriteSettlement::Decisive
            )
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    let BeginOutcome::AlreadyReadable(witness) = coordinator
        .begin_direct_write(hash, &key, claim())
        .await
        .unwrap()
    else {
        panic!("committed representation must be readable")
    };
    *witness
}
