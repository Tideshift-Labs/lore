// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::time::Duration;
use std::time::UNIX_EPOCH;

use bytes::Bytes;
use lore_base::types::RepositoryId;
use lore_proto::lore::notification;
use lore_server::plugins::remote_notification::config::PRODUCER_INSTANCE_ID_MAX_BYTES;
use lore_server::plugins::remote_notification::envelope::*;
use lore_server::plugins::remote_notification::wire;
use prost::Message;

fn repository(byte: u8) -> RepositoryId {
    let mut id = RepositoryId::default();
    *id.data_mut() = [byte; REPOSITORY_BYTES];
    id
}

fn common(repo: RepositoryId) -> EnvelopeCommon {
    EnvelopeCommon {
        cell_id: "sfo3-cell-a".to_string(),
        placement_epoch: 12,
        event_id: EventId::from_bytes([7; EVENT_ID_BYTES]),
        repository: repo,
        producer_instance_id: "loreserver-sfo3-cell-a-2".to_string(),
        produced_at: UNIX_EPOCH + Duration::from_secs(1_787_000_000),
    }
}

fn lore_event(repo: RepositoryId) -> notification::Event {
    notification::Event {
        id: "3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8".to_string(),
        time: None,
        repository: Bytes::copy_from_slice(repo.data()),
        event: Some(notification::event::Event::BranchCreated(
            notification::BranchCreated {
                branch: Bytes::from_static(&[1; 16]),
            },
        )),
    }
}

fn durable_body() -> DurableInvalidationBody {
    DurableInvalidationBody {
        payload_version: 1,
        idempotency_key: [3; IDEMPOTENCY_KEY_BYTES],
        event_kind: "branch.tip_advanced".to_string(),
        repository_generation: 8814,
        aggregate_kind: "branch".to_string(),
        aggregate_identity: "b1c2d3e4f5061728".to_string(),
        aggregate_version: AggregateVersion {
            ordinal: 417,
            identity: Some("revision:2c9f0a7b4d1e6358a0b1c2d3e4f50617".to_string()),
        },
        payload: Bytes::from_static(b"{}"),
        committed_at: UNIX_EPOCH + Duration::from_secs(1_787_000_000),
        actor: Some("user:0193f2ac-7b41-7c92-a5d1-4e8f0b3c6d27".to_string()),
    }
}

#[test]
fn a_live_hint_encodes_with_the_contract_subject() {
    let repo = repository(0x9f);
    let hint = HintEnvelopeV1 {
        common: common(repo),
        shadow: false,
        lore_event: lore_event(repo),
    };
    assert_eq!(
        hint.subject(),
        "lore.v1.cell.sfo3-cell-a.repo.9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f.live"
    );
    let encoded = hint.encode().expect("valid live hint");
    assert_eq!(encoded.transport_version, wire::TRANSPORT_VERSION);
    assert_eq!(
        encoded.delivery_class,
        wire::DeliveryClassV1::LiveHint as i32
    );
    validate_wire_envelope(&encoded).expect("self-encoded envelope validates");
}

#[test]
fn a_shadow_observation_uses_only_the_shadow_subject() {
    let repo = repository(0x9f);
    let hint = HintEnvelopeV1 {
        common: common(repo),
        shadow: true,
        lore_event: lore_event(repo),
    };
    assert!(hint.subject().ends_with(".shadow"));
    let encoded = hint.encode().expect("valid shadow observation");
    assert_eq!(
        encoded.delivery_class,
        wire::DeliveryClassV1::ShadowObservation as i32
    );
}

#[test]
fn an_embedded_event_for_another_repository_is_rejected_before_publication() {
    let hint = HintEnvelopeV1 {
        common: common(repository(0x9f)),
        shadow: false,
        lore_event: lore_event(repository(0x0a)),
    };
    assert_eq!(
        hint.encode().expect_err("mismatched repository"),
        EnvelopeViolation::LoreEventRepositoryMismatch
    );
}

#[test]
fn a_zero_repository_is_rejected_before_publication() {
    let hint = HintEnvelopeV1 {
        common: common(RepositoryId::default()),
        shadow: false,
        lore_event: lore_event(RepositoryId::default()),
    };
    assert_eq!(
        hint.encode().expect_err("zero repository"),
        EnvelopeViolation::ZeroRepository
    );
}

#[test]
fn an_invalid_cell_id_is_rejected_before_publication() {
    let repo = repository(0x9f);
    let mut c = common(repo);
    c.cell_id = "sfo3_cell_a".to_string();
    let hint = HintEnvelopeV1 {
        common: c,
        shadow: false,
        lore_event: lore_event(repo),
    };
    assert_eq!(
        hint.encode().expect_err("invalid cell id"),
        EnvelopeViolation::InvalidCellId
    );
}

#[test]
fn a_durable_envelope_encodes_and_stays_under_the_cap() {
    let envelope = DurableEnvelopeV1 {
        common: common(repository(0x9f)),
        body: durable_body(),
    };
    assert!(envelope.subject().ends_with(".durable"));
    let encoded = envelope.encode(1..=1).expect("valid durable envelope");
    assert!(encoded.encoded_len() <= DURABLE_ENVELOPE_MAX_BYTES);
    validate_wire_envelope(&encoded).expect("self-encoded envelope validates");
}

#[test]
fn a_maximal_durable_envelope_is_still_transportable() {
    // The worst case the contract's size accounting predicts: every
    // variable-width field at its maximum and a 64 KiB payload.
    let mut body = durable_body();
    body.event_kind = "e".repeat(EVENT_KIND_MAX_BYTES);
    body.aggregate_kind = "k".repeat(AGGREGATE_KIND_MAX_BYTES);
    body.aggregate_identity = "i".repeat(AGGREGATE_IDENTITY_MAX_BYTES);
    body.aggregate_version.identity = Some("v".repeat(AGGREGATE_VERSION_IDENTITY_MAX_BYTES));
    body.actor = Some("a".repeat(ACTOR_MAX_BYTES));
    body.payload = Bytes::from(vec![0xABu8; PAYLOAD_MAX_BYTES]);
    let mut c = common(repository(0x9f));
    c.cell_id = "c".repeat(63);
    c.producer_instance_id = "p".repeat(PRODUCER_INSTANCE_ID_MAX_BYTES);

    let encoded = DurableEnvelopeV1 { common: c, body }
        .encode(1..=1)
        .expect("the maximal legal envelope is accepted");
    assert!(
        encoded.encoded_len() <= DURABLE_ENVELOPE_MAX_BYTES,
        "maximal envelope was {} bytes, cap is {DURABLE_ENVELOPE_MAX_BYTES}",
        encoded.encoded_len()
    );

    // The cap alone is a weak assertion: it would still hold if a field
    // silently lost its bound. The contract derives the cap from a
    // 2048-byte non-payload budget, so pin THAT, measured on an envelope
    // where every variable-width field really is at its maximum.
    const NON_PAYLOAD_BUDGET_BYTES: usize = 2_048;
    let non_payload = encoded.encoded_len() - PAYLOAD_MAX_BYTES;
    assert!(
        non_payload <= NON_PAYLOAD_BUDGET_BYTES,
        "non-payload content was {non_payload} bytes; the contract's size accounting budgets \
         {NON_PAYLOAD_BUDGET_BYTES} and derives the {DURABLE_ENVELOPE_MAX_BYTES} cap from it"
    );
}

#[test]
fn an_over_width_producer_instance_id_is_rejected_before_publication() {
    let repo = repository(0x9f);
    let mut c = common(repo);
    c.producer_instance_id = "p".repeat(PRODUCER_INSTANCE_ID_MAX_BYTES + 1);
    let hint = HintEnvelopeV1 {
        common: c,
        shadow: false,
        lore_event: lore_event(repo),
    };
    assert_eq!(
        hint.encode().expect_err("producer instance id width"),
        EnvelopeViolation::ProducerInstanceIdTooLong
    );
}

#[test]
fn a_zero_placement_epoch_is_rejected_on_both_classes() {
    let repo = repository(0x9f);
    let mut c = common(repo);
    c.placement_epoch = 0;
    let hint = HintEnvelopeV1 {
        common: c.clone(),
        shadow: false,
        lore_event: lore_event(repo),
    };
    assert_eq!(
        hint.encode().expect_err("zero placement epoch"),
        EnvelopeViolation::MissingPlacementEpoch
    );
    let durable = DurableEnvelopeV1 {
        common: c,
        body: durable_body(),
    };
    assert_eq!(
        durable.encode(1..=1).expect_err("zero placement epoch"),
        EnvelopeViolation::MissingPlacementEpoch
    );
}

#[test]
fn a_wrong_width_repository_is_distinguished_from_a_zero_repository() {
    let mut envelope = common(repository(0x9f)).to_wire(wire::DeliveryClassV1::LiveHint);
    envelope.body = Some(wire::private_envelope_v1::Body::LoreEvent(
        Bytes::from_static(b"x"),
    ));
    envelope.repository = Bytes::from_static(&[1u8; 8]);
    assert_eq!(
        validate_wire_envelope(&envelope).expect_err("repository width"),
        EnvelopeViolation::InvalidRepositoryWidth
    );

    envelope.repository = Bytes::from_static(&[0u8; REPOSITORY_BYTES]);
    assert_eq!(
        validate_wire_envelope(&envelope).expect_err("zero repository"),
        EnvelopeViolation::ZeroRepository
    );
}

#[test]
fn a_payload_over_the_frozen_cap_is_rejected() {
    let mut body = durable_body();
    body.payload = Bytes::from(vec![0u8; PAYLOAD_MAX_BYTES + 1]);
    let envelope = DurableEnvelopeV1 {
        common: common(repository(0x9f)),
        body,
    };
    assert_eq!(
        envelope.encode(1..=1).expect_err("payload over cap"),
        EnvelopeViolation::PayloadOverCap
    );
}

#[test]
fn every_deferred_width_is_enforced() {
    /// One width mutation and the violation it must produce.
    type WidthCase = (Box<dyn Fn(&mut DurableInvalidationBody)>, EnvelopeViolation);

    let cases: Vec<WidthCase> = vec![
        (
            Box::new(|b: &mut DurableInvalidationBody| {
                b.event_kind = "e".repeat(EVENT_KIND_MAX_BYTES + 1);
            }),
            EnvelopeViolation::EventKindTooLong,
        ),
        (
            Box::new(|b: &mut DurableInvalidationBody| {
                b.aggregate_kind = "k".repeat(AGGREGATE_KIND_MAX_BYTES + 1);
            }),
            EnvelopeViolation::AggregateKindTooLong,
        ),
        (
            Box::new(|b: &mut DurableInvalidationBody| {
                b.aggregate_identity = "i".repeat(AGGREGATE_IDENTITY_MAX_BYTES + 1);
            }),
            EnvelopeViolation::AggregateIdentityTooLong,
        ),
        (
            Box::new(|b: &mut DurableInvalidationBody| {
                b.aggregate_version.identity =
                    Some("v".repeat(AGGREGATE_VERSION_IDENTITY_MAX_BYTES + 1));
            }),
            EnvelopeViolation::AggregateVersionIdentityTooLong,
        ),
        (
            Box::new(|b: &mut DurableInvalidationBody| {
                b.actor = Some("a".repeat(ACTOR_MAX_BYTES + 1));
            }),
            EnvelopeViolation::ActorTooLong,
        ),
        (
            Box::new(|b: &mut DurableInvalidationBody| {
                b.repository_generation = 0;
            }),
            EnvelopeViolation::MissingRepositoryGeneration,
        ),
    ];
    for (mutate, expected) in cases {
        let mut body = durable_body();
        mutate(&mut body);
        let envelope = DurableEnvelopeV1 {
            common: common(repository(0x9f)),
            body,
        };
        assert_eq!(envelope.encode(1..=1).expect_err("width"), expected);
    }
}

#[test]
fn an_unsupported_payload_version_is_rejected_rather_than_read_as_an_older_shape() {
    let mut body = durable_body();
    body.payload_version = 2;
    let envelope = DurableEnvelopeV1 {
        common: common(repository(0x9f)),
        body,
    };
    assert_eq!(
        envelope.encode(1..=1).expect_err("unknown payload version"),
        EnvelopeViolation::UnsupportedPayloadVersion
    );
}

#[test]
fn a_class_body_mismatch_is_rejected_in_both_directions() {
    let repo = repository(0x9f);
    // A durable class carrying a lore_event body.
    let mut envelope = common(repo).to_wire(wire::DeliveryClassV1::DurableInvalidation);
    envelope.body = Some(wire::private_envelope_v1::Body::LoreEvent(
        Bytes::from_static(b"x"),
    ));
    assert_eq!(
        validate_wire_envelope(&envelope).expect_err("durable carrying lore_event"),
        EnvelopeViolation::ClassBodyMismatch
    );

    // A live class carrying a durable body.
    let mut envelope = common(repo).to_wire(wire::DeliveryClassV1::LiveHint);
    envelope.body = Some(wire::private_envelope_v1::Body::DurableInvalidation(
        wire::DurableInvalidationBodyV1::default(),
    ));
    assert_eq!(
        validate_wire_envelope(&envelope).expect_err("live carrying durable body"),
        EnvelopeViolation::ClassBodyMismatch
    );
}

#[test]
fn an_unknown_transport_version_is_rejected() {
    let mut envelope = common(repository(0x9f)).to_wire(wire::DeliveryClassV1::LiveHint);
    envelope.body = Some(wire::private_envelope_v1::Body::LoreEvent(
        Bytes::from_static(b"x"),
    ));
    envelope.transport_version = 2;
    assert_eq!(
        validate_wire_envelope(&envelope).expect_err("transport version"),
        EnvelopeViolation::UnknownTransportVersion
    );
}

#[test]
fn a_wrong_width_idempotency_key_is_rejected() {
    let mut envelope = common(repository(0x9f)).to_wire(wire::DeliveryClassV1::DurableInvalidation);
    envelope.body = Some(wire::private_envelope_v1::Body::DurableInvalidation(
        wire::DurableInvalidationBodyV1 {
            idempotency_key: Bytes::from_static(&[1; 16]),
            ..Default::default()
        },
    ));
    assert_eq!(
        validate_wire_envelope(&envelope).expect_err("idempotency key width"),
        EnvelopeViolation::InvalidIdempotencyKeyWidth
    );
}

#[test]
fn an_event_id_is_stable_across_its_own_reuse() {
    let id = EventId::new_v4();
    assert_eq!(
        id.as_bytes(),
        EventId::from_bytes(*id.as_bytes()).as_bytes()
    );
    assert_eq!(id.to_hyphenated().len(), 36);
}
