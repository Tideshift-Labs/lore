// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! CR-032 outbox fixtures: appending pending rows, driving the relay, and
//! standing up the membership/checkpoint state the Step C evaluator reads.
//!
//! Everything here goes through the production functions
//! (`outbox::append`, `relay::claim_batch`, `relay::record_broker_accepted`,
//! `membership::*`, `report_checkpoint`) rather than seeding rows by SQL. The
//! evaluator's own suite seeds directly where it needs 2,500 rows in one
//! transaction; this harness never needs more than a handful, and a
//! shared-backend proof that hand-wrote its rows would prove nothing about the
//! two sets' writers agreeing.

#![allow(dead_code)]

use lore_postgres::domain::outbox::CapturedPosition;
use lore_postgres::domain::outbox::CheckpointOutcome;
use lore_postgres::domain::outbox::CheckpointReport;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::OutboxEvent;
use lore_postgres::domain::outbox::ResetReport;
use lore_postgres::domain::outbox::append;
use lore_postgres::domain::outbox::membership;
use lore_postgres::domain::outbox::report_checkpoint;
use lore_postgres::domain::outbox::reset::RESET_REASON_STREAM_EPOCH_ADVANCED;
use lore_postgres::domain::outbox::version::AggregateVersion;
use tokio_postgres::Client;
use uuid::Uuid;

/// Append one `pending` row through the production append path and commit it.
pub async fn append_pending(
    client: &mut Client,
    cell_id: &str,
    repository_id: &[u8],
    aggregate_id: &[u8],
    ordinal: u64,
) -> Uuid {
    let version = AggregateVersion::ordinal_only(ordinal).encode();
    let tx = client
        .transaction()
        .await
        .expect("begin append transaction");
    let event = OutboxEvent {
        cell_id,
        repository_id,
        repository_generation: 1,
        event_kind: "branch.pushed",
        aggregate_kind: "branch",
        aggregate_id,
        aggregate_version: &version,
        payload_schema_version: 1,
        payload: b"{}",
    };
    let appended = append(&tx, &event).await.expect("append a pending event");
    tx.commit().await.expect("commit the append");
    appended.event_id
}

/// Read one row's relay state straight from SQL.
pub async fn event_state(raw: &Client, event_id: Uuid) -> String {
    raw.query_one(
        "SELECT state FROM lore_outbox_events WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("read the event's relay state")
    .get("state")
}

/// The stable keys a reset must preserve across a requeue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableKeys {
    /// Event identity, created once in the mutation transaction.
    pub event_id: Uuid,
    /// The BLAKE3 idempotency key over CR-032's canonical tuple.
    pub idempotency_key: Vec<u8>,
    /// The committed aggregate version, in the v1 encoding.
    pub aggregate_version: Vec<u8>,
    /// Cell identity.
    pub cell_id: String,
}

/// Read the keys that must survive an epoch reset unchanged.
pub async fn stable_keys(raw: &Client, event_id: Uuid) -> StableKeys {
    let row = raw
        .query_one(
            "SELECT event_id, idempotency_key, aggregate_version, cell_id \
             FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("read the event's stable keys");
    StableKeys {
        event_id: row.get("event_id"),
        idempotency_key: row.get("idempotency_key"),
        aggregate_version: row.get("aggregate_version"),
        cell_id: row.get("cell_id"),
    }
}

/// Place a cell's current stream identity and epoch, creating its membership
/// state row first.
pub async fn place_cell(raw: &Client, cell_id: &str, stream_identity: &str, stream_epoch: i64) {
    let state = membership::ensure_membership_state(raw, cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        raw,
        cell_id,
        stream_identity,
        stream_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place the cell's current stream");
}

/// The membership version currently on the cell's state row.
pub async fn membership_version(raw: &Client, cell_id: &str) -> i64 {
    membership::read_membership_state(raw, cell_id)
        .await
        .expect("read membership state")
        .expect("membership state row is present")
        .membership_version
}

/// Join one receiver, capture its baseline, report a frontier, and make it
/// ready. Returns its membership generation.
///
/// `deadpool` and `raw` may come from different coordinator sets; the whole
/// point of the shared-backend proof is that they do.
pub async fn join_ready_receiver(
    raw: &Client,
    deadpool: &mut deadpool_postgres::Client,
    cell_id: &str,
    receiver_identity: &str,
    stream_identity: &str,
    stream_epoch: i64,
    frontier: i64,
) -> i64 {
    let version = membership_version(raw, cell_id).await;
    let joined = membership::join_receiver(deadpool, cell_id, receiver_identity, version)
        .await
        .expect("join the receiver");
    let MembershipCas::Applied {
        membership_generation: generation_id,
        ..
    } = joined
    else {
        panic!("a first join must apply, got {joined:?}");
    };
    let captured = CapturedPosition {
        stream_identity: stream_identity.to_owned(),
        stream_epoch,
        start_sequence: 0,
    };
    membership::record_capture(raw, cell_id, receiver_identity, generation_id, &captured)
        .await
        .expect("record the receiver's capture");
    membership::record_baseline(raw, cell_id, receiver_identity, generation_id)
        .await
        .expect("record the receiver's baseline");
    let version = membership_version(raw, cell_id).await;
    let report = CheckpointReport {
        stream_identity: stream_identity.to_owned(),
        stream_epoch,
        receiver_identity: receiver_identity.to_owned(),
        membership_generation: generation_id,
        membership_version: version,
        contiguous_frontier: frontier,
        gaps: Vec::new(),
        poison: Vec::new(),
    };
    let outcome = report_checkpoint(deadpool, cell_id, &report)
        .await
        .expect("report the receiver's checkpoint");
    assert_eq!(
        outcome,
        CheckpointOutcome::Applied {
            contiguous_frontier: frontier,
        },
        "the first checkpoint report must apply"
    );
    let ready = membership::readiness_cas(deadpool, cell_id, receiver_identity, generation_id)
        .await
        .expect("readiness compare-and-set");
    assert!(
        matches!(ready, MembershipCas::Applied { .. }),
        "the receiver must become ready, got {ready:?}"
    );
    generation_id
}

/// An epoch-advance reset report for `cell_id`.
///
/// `reset_fingerprint`/`detection_id` are derived in `lore-server`
/// (`event_relay::reset_wire`), which this crate cannot depend on — it would be
/// a dependency cycle. `reset::validate_report` only bounds these fields, and
/// nothing in the receipt transaction re-derives them, so synthesizing them
/// here exercises the same storage-side state machine. Their canonical
/// derivation is `lore-server/tests/event_relay_reset.rs`'s to prove.
pub fn epoch_advance_report(
    cell_id: &str,
    stream_identity: &str,
    old_epoch: i64,
    new_epoch: i64,
    fingerprint: [u8; 32],
) -> ResetReport {
    ResetReport {
        detection_id: format!(
            "wp109-detection-{:02x}{:02x}",
            fingerprint[0], fingerprint[1]
        ),
        reset_fingerprint: fingerprint,
        broker_reset_identity: "wp109-01:JS-SHARED-BACKEND".to_owned(),
        cell_id: cell_id.to_owned(),
        placement_revision: 0,
        old_stream_identity: stream_identity.to_owned(),
        old_stream_epoch: old_epoch,
        new_stream_identity: stream_identity.to_owned(),
        new_stream_epoch: new_epoch,
        reason_code: RESET_REASON_STREAM_EPOCH_ADVANCED,
        detected_at_unix_ms: 1_787_000_000_000,
    }
}
