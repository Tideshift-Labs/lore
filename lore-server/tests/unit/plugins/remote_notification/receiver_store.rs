// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_postgres::domain::outbox::CheckpointOutcome;
use lore_postgres::domain::outbox::CheckpointReport;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::membership::CapturedPosition;
use lore_server::plugins::remote_notification::receiver_store::*;

fn report(
    membership_generation: i64,
    membership_version: i64,
    contiguous_frontier: i64,
) -> CheckpointReport {
    CheckpointReport {
        stream_identity: "DURABLE-sfo3-cell-a".to_string(),
        stream_epoch: 8,
        receiver_identity: "receiver-1".to_string(),
        membership_generation,
        membership_version,
        contiguous_frontier,
        gaps: Vec::new(),
        poison: Vec::new(),
    }
}

#[tokio::test]
async fn a_join_at_the_current_version_allocates_the_next_generation() {
    let store = InMemoryReceiverStore::new("sfo3-cell-a");
    let outcome = store.join("receiver-1", 1).await.expect("join answers");
    assert_eq!(
        outcome,
        MembershipCas::Applied {
            membership_version: 2,
            membership_generation: 1,
        }
    );
}

#[tokio::test]
async fn a_join_at_a_stale_version_conflicts_rather_than_allocating() {
    let store = InMemoryReceiverStore::new("sfo3-cell-a");
    store.set_membership_version(7);
    let outcome = store.join("receiver-1", 1).await.expect("join answers");
    assert_eq!(
        outcome,
        MembershipCas::VersionConflict {
            current_membership_version: 7,
        }
    );
}

/// Drive one generation through capture and baseline, so a readiness
/// compare-and-set reaches the checkpoint fence rather than stopping at an
/// earlier one.
async fn ready_to_cas(store: &InMemoryReceiverStore, receiver_identity: &str) {
    store
        .join(receiver_identity, 1)
        .await
        .expect("join answers");
    store
        .record_capture(
            receiver_identity,
            1,
            &CapturedPosition {
                stream_identity: "DURABLE-sfo3-cell-a".to_string(),
                stream_epoch: 8,
                start_sequence: 900,
            },
        )
        .await
        .expect("capture answers");
    store
        .record_baseline(receiver_identity, 1)
        .await
        .expect("baseline answers");
}

#[tokio::test]
async fn a_scripted_outcome_is_consumed_once() {
    let store = InMemoryReceiverStore::new("sfo3-cell-a");
    ready_to_cas(&store, "receiver-1").await;
    store
        .report_checkpoint(&report(1, 2, 916))
        .await
        .expect("checkpoint answers");
    store.next_readiness(Ok(MembershipCas::PlacementMoved {
        current_stream_identity: Some("DURABLE-a-r2".to_string()),
        current_stream_epoch: Some(1),
    }));
    assert!(matches!(
        store.readiness_cas("receiver-1", 1).await,
        Ok(MembershipCas::PlacementMoved { .. })
    ));
    assert!(matches!(
        store.readiness_cas("receiver-1", 1).await,
        Ok(MembershipCas::Applied { .. })
    ));
}

/// The fake refuses readiness with no checkpoint behind it, the way Step C
/// does. A fake that granted it would let a receiver skip the step the
/// contract exists to require.
#[tokio::test]
async fn readiness_is_refused_without_a_checkpoint() {
    let store = InMemoryReceiverStore::new("sfo3-cell-a");
    ready_to_cas(&store, "receiver-1").await;
    assert_eq!(
        store.readiness_cas("receiver-1", 1).await,
        Ok(MembershipCas::NoCheckpointAtCurrentPlacement)
    );
}

/// A generation that has not captured cannot reach the checkpoint fence at
/// all. Step C answers `WrongState` first, and a fake that answered
/// `NoCheckpointAtCurrentPlacement` here would misreport which of the
/// bootstrap's ordered steps was actually missing.
#[tokio::test]
async fn readiness_before_a_capture_is_the_wrong_state_not_a_missing_checkpoint() {
    let store = InMemoryReceiverStore::new("sfo3-cell-a");
    store.join("receiver-1", 1).await.expect("join answers");
    assert_eq!(
        store.readiness_cas("receiver-1", 1).await,
        Ok(MembershipCas::WrongState {
            state: "joining (no captured position)".to_string(),
        })
    );
}

/// The fence the ordered bootstrap exists to reach, modelled: the
/// placement this generation RECORDED is compared against the cell's
/// current one, and a mismatch retires the row. Without this the fake
/// would grant readiness to a seeded generation Step C refuses, which is
/// exactly the shape [`InMemoryReceiverStore::seed_member`] makes easy to
/// build.
#[tokio::test]
async fn readiness_at_a_placement_that_moved_retires_rather_than_applying() {
    let store = InMemoryReceiverStore::new("sfo3-cell-a");
    ready_to_cas(&store, "receiver-1").await;
    store
        .report_checkpoint(&report(1, 2, 916))
        .await
        .expect("checkpoint answers");
    store.set_current_placement("DURABLE-sfo3-cell-a-r2", 9);
    assert!(matches!(
        store.readiness_cas("receiver-1", 1).await,
        Ok(MembershipCas::PlacementMoved { .. })
    ));
    let snapshot = store
        .read_membership()
        .await
        .expect("read answers")
        .expect("an installed cell has a snapshot");
    assert_eq!(snapshot.members[0].state, "retired");
}

/// A join leaves an uncaptured `joining` row that a later bootstrap can
/// reuse. Without this the receiver cannot tell a fresh cell from one
/// whose previous bootstrap failed after joining.
#[tokio::test]
async fn a_join_leaves_an_uncaptured_joining_member_row() {
    let store = InMemoryReceiverStore::new("sfo3-cell-a");
    store.join("receiver-1", 1).await.expect("join answers");
    let snapshot = store
        .read_membership()
        .await
        .expect("read answers")
        .expect("an installed cell has a snapshot");
    assert_eq!(snapshot.members.len(), 1);
    let member = &snapshot.members[0];
    assert_eq!(member.state, "joining");
    assert!(member.captured.is_none());
    assert!(member.baseline_at.is_none());
}

#[tokio::test]
async fn a_checkpoint_report_projects_its_frontier() {
    let store = InMemoryReceiverStore::new("sfo3-cell-a");
    store.join("receiver-1", 1).await.expect("join answers");
    assert_eq!(
        store.report_checkpoint(&report(1, 2, 916)).await,
        Ok(CheckpointOutcome::Applied {
            contiguous_frontier: 916,
        })
    );
    assert_eq!(store.projected_frontier(), Some(916));
}

/// The version compare-and-set the projection performs, modelled. A report
/// at a version the cell has moved past is refused, and the refusal names
/// the version to resend at.
#[tokio::test]
async fn a_report_at_a_stale_membership_version_is_refused() {
    let store = InMemoryReceiverStore::new("sfo3-cell-a");
    store.join("receiver-1", 1).await.expect("join answers");
    store.set_membership_version(9);
    assert_eq!(
        store.report_checkpoint(&report(1, 2, 916)).await,
        Ok(CheckpointOutcome::MembershipVersionConflict {
            current_membership_version: 9,
        })
    );
    assert_eq!(store.projected_frontier(), None);
}
