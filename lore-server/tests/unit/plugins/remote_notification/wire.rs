// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_server::plugins::remote_notification::wire::*;
use prost::Message;

/// The `.proto` beside this module, read at test time.
///
/// The schema is maintained by hand in two artifacts, so the tests below
/// pin **both sides independently**: the encoded tag bytes prove what
/// `wire.rs` actually puts on the wire, and the `.proto` text proves the
/// vendored schema of record declares the same thing. A change to either
/// artifact alone fails here.
const VENDORED_PROTO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/plugins/remote_notification/proto/lorehub_notification_internal_v1.proto"
));

/// Protobuf wire types this schema uses.
const VARINT: u32 = 0;
const LENGTH_DELIMITED: u32 = 2;

/// The single tag byte protobuf emits for a field number below 16.
///
/// Every field in this schema is 1..=10, so one byte is always enough. A
/// field of 16 or more would need a two-byte varint and this helper would
/// silently truncate, so it asserts rather than lie.
fn tag_byte(field: u32, wire_type: u32) -> u8 {
    assert!(
        (1..16).contains(&field),
        "field {field} needs a multi-byte tag; this helper only covers 1..15"
    );
    assert!(
        wire_type < 8,
        "wire type {wire_type} is not a protobuf wire type"
    );
    ((field << 3) | wire_type) as u8
}

/// Asserts that `message`, which must have exactly one non-default field
/// set, encodes that field under `field`/`wire_type`.
///
/// This reads the bytes `wire.rs` really produces, so renumbering a
/// `#[prost(tag = ...)]` attribute fails here even if the `.proto` is left
/// untouched.
fn assert_encodes_tag<M: Message>(message: &M, field: u32, wire_type: u32, what: &str) {
    let bytes = encode(message);
    assert_eq!(
        bytes.first().copied(),
        Some(tag_byte(field, wire_type)),
        "{what} did not encode as field {field} wire type {wire_type}; got bytes {bytes:?}"
    );
}

/// One field-number case: the `.proto` declaration, the field number, the
/// wire type, and a setter that leaves only that field non-default.
type FieldCase<M> = (&'static str, u32, u32, fn(&mut M));

/// Returns the body of `message <name> {` / `enum <name> {` from the
/// vendored `.proto`, so a field-number assertion is scoped to its own
/// message rather than matched anywhere in the file.
fn declaration_block<'a>(proto: &'a str, kind: &str, name: &str) -> &'a str {
    let header = format!("{kind} {name} {{");
    let start = proto
        .find(&header)
        .unwrap_or_else(|| panic!("vendored proto declares no `{header}`"))
        + header.len();
    let rest = &proto[start..];
    let mut depth = 1usize;
    for (offset, byte) in rest.bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &rest[..offset];
                }
            }
            _ => {}
        }
    }
    panic!("`{kind} {name}` is not closed in the vendored proto")
}

/// Asserts the named message's own block declares `declaration`.
fn assert_declares(kind: &str, name: &str, declaration: &str) {
    let block = declaration_block(VENDORED_PROTO, kind, name);
    assert!(
        block.contains(declaration),
        "`{kind} {name}` no longer declares `{declaration}`; wire.rs and the .proto have drifted"
    );
}

fn empty_envelope() -> PrivateEnvelopeV1 {
    PrivateEnvelopeV1 {
        transport_version: 0,
        cell_id: String::new(),
        placement_epoch: 0,
        event_id: ::bytes::Bytes::new(),
        repository: ::bytes::Bytes::new(),
        delivery_class: 0,
        producer_instance_id: String::new(),
        produced_at: None,
        body: None,
    }
}

#[test]
fn the_vendored_proto_pins_the_method_path_this_client_calls() {
    assert!(VENDORED_PROTO.contains("package lorehub.notification.internal.v1;"));
    assert!(VENDORED_PROTO.contains("service PrivateNotificationService {"));
    assert!(VENDORED_PROTO.contains("rpc Publish (PrivateEnvelopeV1) returns (PublishResultV1);"));
    assert_eq!(
        PUBLISH_METHOD_PATH,
        "/lorehub.notification.internal.v1.PrivateNotificationService/Publish"
    );
    assert!(VENDORED_PROTO.contains(PUBLISH_METHOD_PATH));
    assert_eq!(
        PRIVATE_NOTIFICATION_SERVICE,
        "lorehub.notification.internal.v1.PrivateNotificationService"
    );
}

#[test]
fn every_envelope_field_encodes_under_the_number_the_proto_declares() {
    let cases: [FieldCase<PrivateEnvelopeV1>; 10] = [
        ("uint32 transport_version = 1;", 1, VARINT, |e| {
            e.transport_version = 1;
        }),
        ("string cell_id = 2;", 2, LENGTH_DELIMITED, |e| {
            e.cell_id = "a".to_string();
        }),
        ("uint64 placement_epoch = 3;", 3, VARINT, |e| {
            e.placement_epoch = 1;
        }),
        ("bytes event_id = 4;", 4, LENGTH_DELIMITED, |e| {
            e.event_id = ::bytes::Bytes::from_static(&[1]);
        }),
        ("bytes repository = 5;", 5, LENGTH_DELIMITED, |e| {
            e.repository = ::bytes::Bytes::from_static(&[1]);
        }),
        ("DeliveryClassV1 delivery_class = 6;", 6, VARINT, |e| {
            e.delivery_class = DeliveryClassV1::LiveHint as i32;
        }),
        (
            "string producer_instance_id = 7;",
            7,
            LENGTH_DELIMITED,
            |e| e.producer_instance_id = "a".to_string(),
        ),
        (
            "google.protobuf.Timestamp produced_at = 8;",
            8,
            LENGTH_DELIMITED,
            |e| e.produced_at = Some(::prost_types::Timestamp::default()),
        ),
        ("bytes lore_event = 9;", 9, LENGTH_DELIMITED, |e| {
            e.body = Some(private_envelope_v1::Body::LoreEvent(
                ::bytes::Bytes::from_static(&[1]),
            ));
        }),
        (
            "DurableInvalidationBodyV1 durable_invalidation = 10;",
            10,
            LENGTH_DELIMITED,
            |e| {
                e.body = Some(private_envelope_v1::Body::DurableInvalidation(
                    DurableInvalidationBodyV1::default(),
                ));
            },
        ),
    ];
    for (declaration, field, wire_type, set) in cases {
        assert_declares("message", "PrivateEnvelopeV1", declaration);
        let mut envelope = empty_envelope();
        set(&mut envelope);
        assert_encodes_tag(&envelope, field, wire_type, declaration);
    }
}

#[test]
fn every_durable_body_field_encodes_under_the_number_the_proto_declares() {
    let cases: [FieldCase<DurableInvalidationBodyV1>; 10] = [
        ("uint32 payload_version = 1;", 1, VARINT, |b| {
            b.payload_version = 1;
        }),
        ("bytes idempotency_key = 2;", 2, LENGTH_DELIMITED, |b| {
            b.idempotency_key = ::bytes::Bytes::from_static(&[1]);
        }),
        ("string event_kind = 3;", 3, LENGTH_DELIMITED, |b| {
            b.event_kind = "a".to_string();
        }),
        ("uint64 repository_generation = 4;", 4, VARINT, |b| {
            b.repository_generation = 1;
        }),
        ("string aggregate_kind = 5;", 5, LENGTH_DELIMITED, |b| {
            b.aggregate_kind = "a".to_string();
        }),
        ("string aggregate_identity = 6;", 6, LENGTH_DELIMITED, |b| {
            b.aggregate_identity = "a".to_string();
        }),
        (
            "AggregateVersionV1 aggregate_version = 7;",
            7,
            LENGTH_DELIMITED,
            |b| b.aggregate_version = Some(AggregateVersionV1::default()),
        ),
        ("bytes payload = 8;", 8, LENGTH_DELIMITED, |b| {
            b.payload = ::bytes::Bytes::from_static(&[1]);
        }),
        (
            "google.protobuf.Timestamp committed_at = 9;",
            9,
            LENGTH_DELIMITED,
            |b| b.committed_at = Some(::prost_types::Timestamp::default()),
        ),
        ("string actor = 10;", 10, LENGTH_DELIMITED, |b| {
            b.actor = "a".to_string();
        }),
    ];
    for (declaration, field, wire_type, set) in cases {
        assert_declares("message", "DurableInvalidationBodyV1", declaration);
        let mut body = DurableInvalidationBodyV1::default();
        set(&mut body);
        assert_encodes_tag(&body, field, wire_type, declaration);
    }
}

#[test]
fn every_aggregate_version_field_encodes_under_the_number_the_proto_declares() {
    let cases: [FieldCase<AggregateVersionV1>; 2] = [
        ("uint64 ordinal = 1;", 1, VARINT, |v| v.ordinal = 1),
        ("string identity = 2;", 2, LENGTH_DELIMITED, |v| {
            v.identity = "a".to_string();
        }),
    ];
    for (declaration, field, wire_type, set) in cases {
        assert_declares("message", "AggregateVersionV1", declaration);
        let mut version = AggregateVersionV1::default();
        set(&mut version);
        assert_encodes_tag(&version, field, wire_type, declaration);
    }
}

#[test]
fn every_publish_result_field_encodes_under_the_number_the_proto_declares() {
    let cases: [FieldCase<PublishResultV1>; 9] = [
        ("uint32 transport_version = 1;", 1, VARINT, |r| {
            r.transport_version = 1;
        }),
        ("PublishOutcomeV1 outcome = 2;", 2, VARINT, |r| {
            r.outcome = PublishOutcomeV1::Accepted as i32;
        }),
        ("bytes event_id = 3;", 3, LENGTH_DELIMITED, |r| {
            r.event_id = ::bytes::Bytes::from_static(&[1]);
        }),
        ("string stream_identity = 4;", 4, LENGTH_DELIMITED, |r| {
            r.stream_identity = "a".to_string();
        }),
        ("uint64 stream_epoch = 5;", 5, VARINT, |r| {
            r.stream_epoch = 1;
        }),
        ("uint64 broker_sequence = 6;", 6, VARINT, |r| {
            r.broker_sequence = 1;
        }),
        ("uint32 publisher_contract_version = 7;", 7, VARINT, |r| {
            r.publisher_contract_version = 1;
        }),
        (
            "google.protobuf.Timestamp broker_accepted_at = 8;",
            8,
            LENGTH_DELIMITED,
            |r| r.broker_accepted_at = Some(::prost_types::Timestamp::default()),
        ),
        ("PublishFailureClassV1 failure_class = 9;", 9, VARINT, |r| {
            r.failure_class = PublishFailureClassV1::StreamFull as i32;
        }),
    ];
    for (declaration, field, wire_type, set) in cases {
        assert_declares("message", "PublishResultV1", declaration);
        let mut result = PublishResultV1::default();
        set(&mut result);
        assert_encodes_tag(&result, field, wire_type, declaration);
    }
}

#[test]
fn every_enum_value_matches_the_vendored_proto() {
    let delivery: [(&str, DeliveryClassV1); 4] = [
        (
            "DELIVERY_CLASS_V1_UNSPECIFIED = 0;",
            DeliveryClassV1::Unspecified,
        ),
        ("LIVE_HINT = 1;", DeliveryClassV1::LiveHint),
        (
            "DURABLE_INVALIDATION = 2;",
            DeliveryClassV1::DurableInvalidation,
        ),
        (
            "SHADOW_OBSERVATION = 3;",
            DeliveryClassV1::ShadowObservation,
        ),
    ];
    for (declaration, value) in delivery {
        assert_declares("enum", "DeliveryClassV1", declaration);
        assert_eq!(declared_value(declaration), value as i32, "{declaration}");
        assert_eq!(DeliveryClassV1::try_from(value as i32), Ok(value));
    }

    let outcome: [(&str, PublishOutcomeV1); 5] = [
        (
            "PUBLISH_OUTCOME_V1_UNSPECIFIED = 0;",
            PublishOutcomeV1::Unspecified,
        ),
        ("ACCEPTED = 1;", PublishOutcomeV1::Accepted),
        ("RETRYABLE = 2;", PublishOutcomeV1::Retryable),
        ("TIMEOUT = 3;", PublishOutcomeV1::Timeout),
        ("TERMINAL = 4;", PublishOutcomeV1::Terminal),
    ];
    for (declaration, value) in outcome {
        assert_declares("enum", "PublishOutcomeV1", declaration);
        assert_eq!(declared_value(declaration), value as i32, "{declaration}");
        assert_eq!(PublishOutcomeV1::try_from(value as i32), Ok(value));
    }

    let failure: [(&str, PublishFailureClassV1); 6] = [
        (
            "PUBLISH_FAILURE_CLASS_V1_UNSPECIFIED = 0;",
            PublishFailureClassV1::Unspecified,
        ),
        (
            "BROKER_UNAVAILABLE = 1;",
            PublishFailureClassV1::BrokerUnavailable,
        ),
        (
            "PLACEMENT_QUIESCING = 2;",
            PublishFailureClassV1::PlacementQuiescing,
        ),
        ("STREAM_FULL = 3;", PublishFailureClassV1::StreamFull),
        ("SCOPE_MISMATCH = 4;", PublishFailureClassV1::ScopeMismatch),
        (
            "UNSUPPORTED_SCHEMA = 5;",
            PublishFailureClassV1::UnsupportedSchema,
        ),
    ];
    for (declaration, value) in failure {
        assert_declares("enum", "PublishFailureClassV1", declaration);
        assert_eq!(declared_value(declaration), value as i32, "{declaration}");
        assert_eq!(PublishFailureClassV1::try_from(value as i32), Ok(value));
    }
}

/// Parses the numeric value out of a `NAME = N;` proto enum declaration.
fn declared_value(declaration: &str) -> i32 {
    declaration
        .rsplit_once("= ")
        .and_then(|(_, tail)| tail.trim_end_matches(';').parse().ok())
        .unwrap_or_else(|| panic!("`{declaration}` is not a `NAME = N;` declaration"))
}

/// Every receiver-stream field, pinned against the vendored `.proto`.
///
/// A-24 numbers each of these explicitly, and the two copies of the schema
/// are byte-identical below their headers by contract. So a renumbering
/// that compiles here has to fail somewhere, and this is that somewhere.
#[test]
fn every_receiver_field_matches_the_vendored_proto() {
    let fields: [(&str, &str, &str); 34] = [
        ("CapturedPositionV1", "uint64 start_sequence = 1;", "1"),
        ("ConsumeRequestV1", "uint32 transport_version = 1;", "1"),
        ("ConsumeRequestV1", "string cell_id = 2;", "2"),
        ("ConsumeRequestV1", "string receiver_identity = 3;", "3"),
        ("ConsumeRequestV1", "uint64 membership_generation = 4;", "4"),
        ("ConsumeRequestV1", "string stream_identity = 5;", "5"),
        ("ConsumeRequestV1", "uint64 stream_epoch = 6;", "6"),
        ("ConsumeRequestV1", "uint64 placement_revision = 7;", "7"),
        (
            "ConsumeRequestV1",
            "CapturedPositionV1 captured_position = 8;",
            "8",
        ),
        ("ConsumeRequestV1", "CaptureNewV1 capture_new = 9;", "9"),
        ("ConsumeCaptureV1", "string stream_identity = 1;", "1"),
        ("ConsumeCaptureV1", "uint64 stream_epoch = 2;", "2"),
        ("ConsumeCaptureV1", "uint64 start_sequence = 3;", "3"),
        ("ConsumeCaptureV1", "string durable_consumer_name = 4;", "4"),
        ("ConsumeCaptureV1", "uint64 placement_revision = 5;", "5"),
        ("ConsumeDeliveryV1", "PrivateEnvelopeV1 envelope = 1;", "1"),
        ("ConsumeDeliveryV1", "uint64 broker_sequence = 2;", "2"),
        ("ConsumeDeliveryV1", "string stream_identity = 3;", "3"),
        ("ConsumeDeliveryV1", "uint64 stream_epoch = 4;", "4"),
        ("ConsumeDeliveryV1", "uint32 redelivery_count = 5;", "5"),
        ("ConsumeCaughtUpV1", "uint64 edge_sequence = 1;", "1"),
        ("ConsumeEventV1", "uint32 transport_version = 1;", "1"),
        ("ConsumeEventV1", "ConsumeCaptureV1 capture = 2;", "2"),
        ("ConsumeEventV1", "ConsumeDeliveryV1 delivery = 3;", "3"),
        ("ConsumeEventV1", "ConsumeCaughtUpV1 caught_up = 4;", "4"),
        ("SequenceGapV1", "uint64 from = 1;", "1"),
        ("SequenceGapV1", "uint64 to = 2;", "2"),
        ("PoisonEntryV1", "uint64 broker_sequence = 1;", "1"),
        ("PoisonEntryV1", "string poison_class = 2;", "2"),
        ("AckV1", "repeated uint64 acked_sequences = 7;", "7"),
        ("AckV1", "uint64 contiguous_frontier = 8;", "8"),
        ("AckResultV1", "AckOutcomeV1 outcome = 2;", "2"),
        (
            "AckResultV1",
            "repeated uint64 accepted_sequences = 3;",
            "3",
        ),
        ("AckResultV1", "ReceiverErrorV1 failure_class = 5;", "5"),
    ];
    for (message, declaration, number) in fields {
        assert_declares("message", message, declaration);
        assert!(
            declaration.ends_with(&format!("= {number};")),
            "{declaration} does not carry field number {number}"
        );
    }
}

/// The two new enums, value by value. `ReceiverErrorV1` in particular is
/// what the gateway's status mapping is derived from, so an off-by-one
/// here would silently reclassify a refusal as a retry.
#[test]
fn every_receiver_enum_value_matches_the_vendored_proto() {
    let outcomes: [(&str, AckOutcomeV1); 5] = [
        ("ACK_OUTCOME_V1_UNSPECIFIED = 0;", AckOutcomeV1::Unspecified),
        ("ACK_ALL_ACCEPTED = 1;", AckOutcomeV1::AllAccepted),
        (
            "ACK_PARTIALLY_ACCEPTED = 2;",
            AckOutcomeV1::PartiallyAccepted,
        ),
        ("ACK_RETRYABLE = 3;", AckOutcomeV1::Retryable),
        ("ACK_TERMINAL = 4;", AckOutcomeV1::Terminal),
    ];
    for (declaration, value) in outcomes {
        assert_declares("enum", "AckOutcomeV1", declaration);
        assert_eq!(declared_value(declaration), value as i32, "{declaration}");
        assert_eq!(AckOutcomeV1::try_from(value as i32), Ok(value));
    }

    let errors: [(&str, ReceiverErrorV1); 12] = [
        (
            "RECEIVER_ERROR_V1_UNSPECIFIED = 0;",
            ReceiverErrorV1::Unspecified,
        ),
        (
            "MALFORMED_RECEIVER_REQUEST_V1 = 1;",
            ReceiverErrorV1::MalformedReceiverRequest,
        ),
        (
            "UNSUPPORTED_RECEIVER_SCHEMA_V1 = 2;",
            ReceiverErrorV1::UnsupportedReceiverSchema,
        ),
        (
            "UNAUTHENTICATED_RECEIVER_V1 = 3;",
            ReceiverErrorV1::UnauthenticatedReceiver,
        ),
        (
            "UNAUTHORIZED_RECEIVER_ROLE_V1 = 4;",
            ReceiverErrorV1::UnauthorizedReceiverRole,
        ),
        (
            "CROSS_CELL_RECEIVER_V1 = 5;",
            ReceiverErrorV1::CrossCellReceiver,
        ),
        (
            "RECEIVER_SCOPE_MISMATCH_V1 = 6;",
            ReceiverErrorV1::ReceiverScopeMismatch,
        ),
        (
            "RECEIVER_PLACEMENT_MISMATCH_V1 = 7;",
            ReceiverErrorV1::ReceiverPlacementMismatch,
        ),
        (
            "RECEIVER_EPOCH_MISMATCH_V1 = 8;",
            ReceiverErrorV1::ReceiverEpochMismatch,
        ),
        (
            "STALE_MEMBERSHIP_GENERATION_V1 = 9;",
            ReceiverErrorV1::StaleMembershipGeneration,
        ),
        (
            "UNKNOWN_DURABLE_CONSUMER_V1 = 10;",
            ReceiverErrorV1::UnknownDurableConsumer,
        ),
        (
            "RECEIVER_BROKER_UNAVAILABLE_V1 = 11;",
            ReceiverErrorV1::ReceiverBrokerUnavailable,
        ),
    ];
    for (declaration, value) in errors {
        assert_declares("enum", "ReceiverErrorV1", declaration);
        assert_eq!(declared_value(declaration), value as i32, "{declaration}");
        assert_eq!(ReceiverErrorV1::try_from(value as i32), Ok(value));
    }
}

#[test]
fn the_vendored_proto_pins_both_receiver_method_paths() {
    assert!(
        VENDORED_PROTO.contains("rpc Consume (ConsumeRequestV1) returns (stream ConsumeEventV1);")
    );
    assert!(VENDORED_PROTO.contains("rpc Ack (AckV1) returns (AckResultV1);"));
    assert_eq!(
        CONSUME_METHOD_PATH,
        "/lorehub.notification.internal.v1.PrivateNotificationService/Consume"
    );
    assert_eq!(
        ACK_METHOD_PATH,
        "/lorehub.notification.internal.v1.PrivateNotificationService/Ack"
    );
    assert!(VENDORED_PROTO.contains(CONSUME_METHOD_PATH));
    assert!(VENDORED_PROTO.contains(ACK_METHOD_PATH));

    // The two bounds this module names as constants, against the schema's
    // own prose. Neither is a field number, so nothing else would catch a
    // change to them.
    assert_eq!(MAX_ACKED_SEQUENCES, 1024);
    assert!(
        declaration_block(VENDORED_PROTO, "message", "AckV1").contains("1 to 1024 entries"),
        "the acknowledgement batch bound moved; MAX_ACKED_SEQUENCES is stale"
    );
    assert_eq!(DURABLE_CONSUMER_NAME_LEN, 44);
    assert!(
        declaration_block(VENDORED_PROTO, "message", "ConsumeCaptureV1")
            .contains("Exactly 44 ASCII"),
        "the durable consumer name width moved; DURABLE_CONSUMER_NAME_LEN is stale"
    );
}

/// A `ConsumeEventV1` round trips, including the oneof arm that carries a
/// whole envelope. This is the message the receiver decodes on every
/// delivery, so a tag error here is a decode failure in production.
#[test]
fn a_consume_delivery_round_trips_through_protobuf() {
    let event = ConsumeEventV1 {
        transport_version: TRANSPORT_VERSION,
        event: Some(consume_event_v1::Event::Delivery(ConsumeDeliveryV1 {
            envelope: Some(PrivateEnvelopeV1 {
                transport_version: TRANSPORT_VERSION,
                cell_id: "sfo3-cell-a".to_string(),
                ..Default::default()
            }),
            broker_sequence: 918,
            stream_identity: "DURABLE-sfo3-cell-a".to_string(),
            stream_epoch: 8,
            redelivery_count: 1,
        })),
    };
    let decoded = ConsumeEventV1::decode(encode(&event)).expect("a consume event round trips");
    assert_eq!(decoded, event);
}

/// A guard for the guards: the block extractor must actually scope, or
/// every assertion above degrades to a whole-file substring search.
#[test]
fn the_declaration_block_extractor_really_scopes() {
    let envelope = declaration_block(VENDORED_PROTO, "message", "PrivateEnvelopeV1");
    assert!(envelope.contains("uint64 placement_epoch = 3;"));
    // `payload_version = 1` belongs to the durable body, not the envelope.
    assert!(!envelope.contains("uint32 payload_version = 1;"));
    let body = declaration_block(VENDORED_PROTO, "message", "DurableInvalidationBodyV1");
    assert!(body.contains("uint32 payload_version = 1;"));
    assert!(!body.contains("uint64 placement_epoch = 3;"));
}

#[test]
fn a_renumbered_field_would_be_caught_by_the_tag_assertion() {
    // Proves `assert_encodes_tag` discriminates rather than always passing:
    // `cell_id` is field 2, so asserting field 3 must fail.
    let mut envelope = empty_envelope();
    envelope.cell_id = "a".to_string();
    let bytes = encode(&envelope);
    assert_eq!(bytes.first().copied(), Some(tag_byte(2, LENGTH_DELIMITED)));
    assert_ne!(bytes.first().copied(), Some(tag_byte(3, LENGTH_DELIMITED)));
}

#[test]
fn an_envelope_round_trips_through_protobuf() {
    let envelope = PrivateEnvelopeV1 {
        transport_version: TRANSPORT_VERSION,
        cell_id: "sfo3-cell-a".to_string(),
        placement_epoch: 12,
        event_id: ::bytes::Bytes::from_static(&[7u8; 16]),
        repository: ::bytes::Bytes::from_static(&[3u8; 16]),
        delivery_class: DeliveryClassV1::LiveHint as i32,
        producer_instance_id: "loreserver-sfo3-cell-a-2".to_string(),
        produced_at: None,
        body: Some(private_envelope_v1::Body::LoreEvent(
            ::bytes::Bytes::from_static(b"opaque"),
        )),
    };
    let bytes = encode(&envelope);
    let decoded = PrivateEnvelopeV1::decode(bytes).expect("round trip");
    assert_eq!(envelope, decoded);
}

#[test]
fn a_durable_body_round_trips_through_protobuf() {
    let envelope = PrivateEnvelopeV1 {
        transport_version: TRANSPORT_VERSION,
        cell_id: "sfo3-cell-a".to_string(),
        placement_epoch: 12,
        event_id: ::bytes::Bytes::from_static(&[9u8; 16]),
        repository: ::bytes::Bytes::from_static(&[4u8; 16]),
        delivery_class: DeliveryClassV1::DurableInvalidation as i32,
        producer_instance_id: "loreserver-sfo3-cell-a-2".to_string(),
        produced_at: None,
        body: Some(private_envelope_v1::Body::DurableInvalidation(
            DurableInvalidationBodyV1 {
                payload_version: DURABLE_PAYLOAD_VERSION,
                idempotency_key: ::bytes::Bytes::from_static(&[1u8; 32]),
                event_kind: "branch.tip_advanced".to_string(),
                repository_generation: 8814,
                aggregate_kind: "branch".to_string(),
                aggregate_identity: "b1c2d3e4f5061728".to_string(),
                aggregate_version: Some(AggregateVersionV1 {
                    ordinal: 417,
                    identity: "revision:2c9f0a7b4d1e6358a0b1c2d3e4f50617".to_string(),
                }),
                payload: ::bytes::Bytes::from_static(b"{}"),
                committed_at: None,
                actor: String::new(),
            },
        )),
    };
    let decoded = PrivateEnvelopeV1::decode(encode(&envelope)).expect("round trip");
    assert_eq!(envelope, decoded);
}
