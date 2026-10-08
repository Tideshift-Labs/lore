// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use lore_postgres::domain::outbox::AggregateVersion as StoredAggregateVersion;
use lore_postgres::domain::outbox::OutboxEventRecord;
use lore_server::event_relay::envelope_map::*;
use lore_server::plugins::remote_notification::envelope::AGGREGATE_IDENTITY_MAX_BYTES;
use lore_server::plugins::remote_notification::envelope::AGGREGATE_VERSION_IDENTITY_MAX_BYTES;
use lore_server::plugins::remote_notification::envelope::PAYLOAD_MAX_BYTES;
use uuid::Uuid;

fn source() -> EnvelopeSource {
    EnvelopeSource {
        cell_id: "cell-a".to_string(),
        placement_epoch: 7,
        producer_instance_id: "loreserver-1".to_string(),
    }
}

fn record() -> OutboxEventRecord {
    OutboxEventRecord {
        event_id: Uuid::from_bytes([9u8; 16]),
        cell_id: "cell-a".to_string(),
        idempotency_key: [3u8; 32],
        repository_id: vec![1u8; 16],
        repository_generation: 12,
        event_kind: "branch.pushed".to_string(),
        aggregate_kind: "branch".to_string(),
        aggregate_id: b"main".to_vec(),
        aggregate_version: StoredAggregateVersion::new(4, vec![0xAB; 32])
            .expect("in bounds")
            .encode(),
        payload_schema_version: 1,
        payload: b"{}".to_vec(),
        created_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    }
}

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_100)
}

#[test]
fn a_well_formed_row_maps_and_keeps_its_stable_keys() {
    let record = record();
    let envelope = map_event(&record, &source(), now()).expect("maps");
    assert_eq!(
        envelope.common.event_id.as_bytes(),
        record.event_id.as_bytes()
    );
    assert_eq!(envelope.body.idempotency_key, record.idempotency_key);
    assert_eq!(envelope.common.cell_id, "cell-a");
    assert_eq!(envelope.common.placement_epoch, 7);
    assert_eq!(envelope.body.repository_generation, 12);
    assert_eq!(envelope.body.aggregate_version.ordinal, 4);
    assert_eq!(
        envelope.body.aggregate_version.identity.as_deref(),
        Some("ab".repeat(32).as_str())
    );
    assert_eq!(envelope.body.aggregate_identity, hex::encode(b"main"));
    assert_eq!(envelope.body.committed_at, record.created_at);
    assert_eq!(envelope.body.actor, None);
}

/// The mapping must not be able to relabel a row onto this cell.
#[test]
fn a_row_from_another_cell_is_terminal() {
    let mut record = record();
    record.cell_id = "cell-b".to_string();
    let failure = map_event(&record, &source(), now()).expect_err("must refuse");
    assert_eq!(failure.as_terminal_class(), "cell_id_mismatch");
}

/// `From<&[u8]> for Partition` would have silently produced the zero
/// repository from a short slice, which is the exact defect this width
/// check exists for.
#[test]
fn a_short_repository_id_is_terminal_rather_than_silently_zeroed() {
    let mut record = record();
    record.repository_id = vec![1u8; 8];
    let failure = map_event(&record, &source(), now()).expect_err("must refuse");
    assert_eq!(failure.as_terminal_class(), "repository_id_width");
}

#[test]
fn a_zero_repository_is_terminal() {
    let mut record = record();
    record.repository_id = vec![0u8; 16];
    let failure = map_event(&record, &source(), now()).expect_err("must refuse");
    assert_eq!(failure.as_terminal_class(), "zero_repository");
}

#[test]
fn a_negative_or_zero_repository_generation_is_terminal() {
    let mut record = record();
    record.repository_generation = -1;
    assert_eq!(
        map_event(&record, &source(), now())
            .expect_err("must refuse")
            .as_terminal_class(),
        "negative_repository_generation"
    );
    record.repository_generation = 0;
    assert_eq!(
        map_event(&record, &source(), now())
            .expect_err("must refuse")
            .as_terminal_class(),
        "zero_repository_generation"
    );
}

#[test]
fn an_undecodable_aggregate_version_is_terminal() {
    let mut record = record();
    record.aggregate_version = vec![0u8; 4];
    let failure = map_event(&record, &source(), now()).expect_err("must refuse");
    assert_eq!(failure.as_terminal_class(), "aggregate_version_undecodable");
}

/// The PIN: hex doubles the width, so the stored 120-byte ceiling is wider
/// than what the envelope can carry. A row in that window must be named
/// poison, never truncated.
#[test]
fn an_identity_that_hex_widens_past_the_transport_bound_is_terminal() {
    let mut record = record();
    record.aggregate_version = StoredAggregateVersion::new(4, vec![0xCD; 65])
        .expect("inside the stored bound")
        .encode();
    let failure = map_event(&record, &source(), now()).expect_err("must refuse");
    assert_eq!(
        failure.as_terminal_class(),
        "aggregate_version_identity_not_transportable"
    );
    // And exactly 64 raw bytes is the widest that still fits.
    record.aggregate_version = StoredAggregateVersion::new(4, vec![0xCD; 64])
        .expect("inside the stored bound")
        .encode();
    let envelope = map_event(&record, &source(), now()).expect("64 raw bytes must map");
    assert_eq!(
        envelope
            .body
            .aggregate_version
            .identity
            .as_deref()
            .map(str::len),
        Some(AGGREGATE_VERSION_IDENTITY_MAX_BYTES)
    );
}

#[test]
fn an_empty_aggregate_id_is_terminal() {
    let mut record = record();
    record.aggregate_id = Vec::new();
    let failure = map_event(&record, &source(), now()).expect_err("must refuse");
    assert_eq!(
        failure.as_terminal_class(),
        "aggregate_identity_not_transportable"
    );
}

/// The guard is on F-032-4's 64-byte producer bound, not the envelope's
/// wider 256. Checking against the transport width would admit a row the
/// schema says cannot exist, which is exactly the drifted column this is
/// meant to catch, and no other assertion in the suite would notice.
#[test]
fn an_aggregate_id_wider_than_the_producer_bound_is_terminal() {
    let mut record = record();
    record.aggregate_id = vec![0xEE; 64];
    let envelope = map_event(&record, &source(), now()).expect("64 bytes is the bound");
    assert_eq!(
        envelope.body.aggregate_identity.len(),
        MAX_PRODUCER_IDENTITY_HEX_CHARS
    );

    record.aggregate_id = vec![0xEE; 65];
    let failure = map_event(&record, &source(), now()).expect_err("65 bytes must refuse");
    assert_eq!(
        failure.as_terminal_class(),
        "aggregate_identity_not_transportable"
    );
    // And it is refused well below the transport's own 256-byte width, so
    // this cannot be passing because of the envelope's own check.
    const _: () = assert!(MAX_PRODUCER_IDENTITY_HEX_CHARS < AGGREGATE_IDENTITY_MAX_BYTES);
}

#[test]
fn an_over_cap_payload_is_terminal() {
    let mut record = record();
    record.payload = vec![0u8; PAYLOAD_MAX_BYTES + 1];
    let failure = map_event(&record, &source(), now()).expect_err("must refuse");
    assert_eq!(failure.as_terminal_class(), "payload_over_cap");
}

/// The class strings are the dead-letter vocabulary and a metric label set,
/// so they must stay bounded, unique, and free of interpolation.
#[test]
fn every_terminal_class_is_a_distinct_bounded_label() {
    let classes = [
        MapFailure::RepositoryIdWidth(1),
        MapFailure::ZeroRepository,
        MapFailure::CellIdMismatch {
            row: "a".into(),
            configured: "b".into(),
        },
        MapFailure::NegativeRepositoryGeneration(-1),
        MapFailure::ZeroRepositoryGeneration,
        MapFailure::EventKindWidth,
        MapFailure::AggregateKindWidth,
        MapFailure::AggregateIdentityNotTransportable(0),
        MapFailure::AggregateVersionUndecodable("x".into()),
        MapFailure::AggregateVersionIdentityNotTransportable(0),
        MapFailure::NegativePayloadSchemaVersion(-1),
        MapFailure::PayloadOverCap(0),
    ];
    let mut labels: Vec<&'static str> = classes.iter().map(MapFailure::as_terminal_class).collect();
    let total = labels.len();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), total, "terminal classes must be distinct");
    for label in labels {
        assert!(!label.is_empty());
        assert!(label.is_ascii());
        assert!(label.len() <= 64, "must fit the terminal_class column");
    }
}
