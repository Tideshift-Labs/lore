// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Coordinator race proof with real staged unlink; remote purge proof is a fixture observation.
use super::*;
use crate::domain::fragments::FragmentObliterateBegin;
use crate::domain::fragments::FragmentPurgeProof;
use crate::domain::fragments::FragmentWriteCapabilityCutover;
use crate::domain::fragments::schema;

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture and stage.cleanup.settled=unknown"]
async fn cleanup_lost_ack_and_obliterate_reconcile_one_stage_capacity_release() {
    assert_eq!(
        std::env::var("LORE_FRAGMENT_FAILPOINTS").unwrap(),
        "stage.cleanup.settled=unknown"
    );
    let payload = payload();
    let fixture = Fixture::open(
        PutResult::Created,
        FragmentGetResponse::NotFound,
        payload.clone(),
    )
    .await;
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 1);
    let coordinator = &fixture.handle.coordinator;
    let hash = fixture.address.hash.data();
    let cleanup = coordinator
        .begin_stage_cleanup(hash, fixture.source_epoch)
        .await
        .unwrap()
        .expect("quarantined predecessor can be reclaimed");
    let repository = [0x76; 16];
    let context = [0x77; 16];
    fixture.admin.execute("INSERT INTO lore_domain_repositories(repository_id,state,generation,name,metadata_hash,default_branch_id,creation_fingerprint_version,creation_fingerprint,created_at) VALUES($1,0,1,'cleanup-race',$2,$3,1,$2,clock_timestamp())", &[&&repository[..], &&[0x78u8;32][..], &&[0x79u8;16][..]]).await.unwrap();
    coordinator
        .create_association(hash, &repository, &context)
        .await
        .unwrap();
    fixture.admin.execute("UPDATE lore_fragment_schema_state SET backfill_state=$1,cutover_at=clock_timestamp(),residue_classified=true,sequence_headroom_fence=1 WHERE id=1", &[&schema::BACKFILL_CUTOVER]).await.unwrap();
    coordinator.enable_lifecycle().await.unwrap();
    coordinator
        .require_write_claims(&FragmentWriteCapabilityCutover::new("cleanup-race-v1").unwrap())
        .await
        .unwrap();
    let FragmentObliterateBegin::Ready(deleting) = coordinator
        .begin_obliterate(hash, &repository, &context, "cleanup-race-v1")
        .await
        .unwrap()
    else {
        panic!("decisive promotion permits delete")
    };
    coordinator
        .commit_obliterate_children(&deleting)
        .await
        .unwrap();
    let FragmentObliterateBegin::Ready(deleting) = coordinator
        .begin_obliterate(hash, &repository, &context, "cleanup-race-v1")
        .await
        .unwrap()
    else {
        panic!("recover payload phase")
    };
    assert_eq!(cleanup.target().epoch(), fixture.source_epoch);
    assert_eq!(cleanup.target().authority(), EpochAuthority::Staged);
    assert!(
        deleting
            .purge_targets()
            .iter()
            .all(|target| target.authority() == EpochAuthority::Remote),
        "ordinary exact deletion captures the successor; predecessor cleanup retains its separate grant"
    );
    fixture
        .handle
        .stage
        .purge_placement(cleanup.target())
        .unwrap();
    assert!(
        coordinator.commit_stage_cleanup(&cleanup).await.is_err(),
        "ack is lost after the actual refund"
    );
    let usage = coordinator.observe_stage().await.unwrap();
    assert_eq!((usage.resident_bytes, usage.resident_files), (0, 0));
    // Remote transport is scripted in this fixture; these are exact coordinator proof inputs.
    // Staged targets are physically unlinked through the real confined collaborator above.
    let proofs = deleting
        .purge_targets()
        .iter()
        .cloned()
        .map(FragmentPurgeProof::new)
        .collect::<Vec<_>>();
    assert_eq!(
        coordinator
            .commit_obliterate_payload(&deleting, &proofs)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert!(
        coordinator.commit_stage_cleanup(&cleanup).await.is_err(),
        "replayed success also loses its acknowledgement"
    );
    let reconciled = coordinator.observe_stage().await.unwrap();
    assert_eq!(
        (
            reconciled.resident_bytes,
            reconciled.resident_files,
            reconciled.metadata_bytes,
            reconciled.metadata_rows
        ),
        (0, 0, usage.metadata_bytes, usage.metadata_rows)
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
}
