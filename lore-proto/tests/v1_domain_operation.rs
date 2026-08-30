// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Drift guards for CR-029's private `lore.domain.v1` receipt rail.

use lore_proto::lore::domain::v1::DomainOperationClockGetRequest;
use lore_proto::lore::domain::v1::DomainOperationClockGetResponse;
use lore_proto::lore::domain::v1::DomainOperationOutcome;
use lore_proto::lore::domain::v1::DomainOperationPrepareRequest;
use lore_proto::lore::domain::v1::DomainOperationPrepareResponse;
use lore_proto::lore::domain::v1::DomainOperationPrepareStatus;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceMaterializeReceiptV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceMaterializeRequestV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceMaterializeStatusV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceRetireAckV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceRetireRequestV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceRetireStatusV1;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetRequest;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetResponse;
use lore_proto::lore::domain::v1::DomainOperationReceiptStatus;
use lore_proto::lore::domain::v1::DomainOperationTerminalStatusAttachRequest;
use lore_proto::lore::domain::v1::DomainOperationTerminalStatusAttachmentAckV1;
use lore_proto::lore::domain::v1::DomainOperationTerminalStatusAttachmentStatusV1;
use lore_proto::lore::domain::v1::DomainOperationVerifiedStaleFinalizeRequest;
use lore_proto::lore::domain::v1::DomainOperationVerifiedStaleFinalizeResponse;
use lore_proto::lore::domain::v1::DomainOperationVerifiedStaleFinalizeStatus;
use lore_proto::lore::domain::v1::TerminalStatusAttachPhase2ActionV1;
use lore_proto::lore::domain::v1::TerminalStatusAttachPhaseV1;
use lore_proto::lore::domain::v1::domain_operation_service_client::DomainOperationServiceClient;
use lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationServiceServer;
use lore_proto::validate_domain_operation_v2_raw;
use prost::Message;

const PROTO: &str = include_str!("../proto/lore/domain/v1/domain_operation.proto");
const GENERATED: &str = include_str!("../src/grpc/lore.domain.v1.rs");

#[test]
fn request_and_response_field_shapes_are_frozen() {
    let DomainOperationClockGetRequest {} = DomainOperationClockGetRequest::default();
    let DomainOperationClockGetResponse {
        lore_clock_unix_millis: _,
        sample_nonce: _,
    } = DomainOperationClockGetResponse::default();

    let DomainOperationPrepareRequest {
        org_uuid: _,
        initiating_principal_namespace: _,
        operation_id: _,
        method: _,
        scope: _,
        fingerprint_version: _,
        fingerprint: _,
        canonical_intent_digest: _,
        authorization_id: _,
        authorization_revision: _,
        preclaim_ticket: _,
    } = DomainOperationPrepareRequest::default();
    let DomainOperationPrepareResponse {
        status: _,
        consume_token: _,
        hard_expires_at_unix_millis: _,
        outcome: _,
        reason_version: _,
        reason: _,
        verification_nonce: _,
        bound_fields_digest: _,
        consumed_ticket_sha256: _,
        authorization_revision: _,
    } = DomainOperationPrepareResponse::default();

    let DomainOperationReceiptGetRequest {
        org_uuid: _,
        initiating_principal_namespace: _,
        operation_id: _,
        method: _,
        scope: _,
        fingerprint_version: _,
        fingerprint: _,
        canonical_intent_digest: _,
        authorization_id: _,
        authorization_revision: _,
        consumed_ticket_sha256: _,
    } = DomainOperationReceiptGetRequest::default();
    let DomainOperationReceiptGetResponse {
        status: _,
        outcome: _,
        reason_version: _,
        reason: _,
        from_future_marker: _,
        prepared_at_unix_millis: _,
        hard_expires_at_unix_millis: _,
        verification_nonce: _,
        bound_fields_digest: _,
        consumed_ticket_sha256: _,
        authorization_revision: _,
    } = DomainOperationReceiptGetResponse::default();
}

#[test]
fn maintenance_request_and_response_field_shapes_are_frozen() {
    let DomainOperationVerifiedStaleFinalizeRequest {
        verified_issuer: _,
        authenticated_subject: _,
        org_uuid: _,
        initiating_principal_namespace: _,
        operation_id: _,
        method: _,
        scope: _,
        fingerprint_version: _,
        fingerprint: _,
        canonical_intent_digest: _,
        authorization_id: _,
        authorization_revision: _,
        verification_nonce: _,
        bound_fields_digest: _,
        consumed_ticket_sha256: _,
        expected_claim_identity_digest: _,
        stale_finalize_permit: _,
        stale_finalize_permit_revision: _,
    } = DomainOperationVerifiedStaleFinalizeRequest::default();
    let DomainOperationVerifiedStaleFinalizeResponse {
        status: _,
        stale_finalize_permit_revision: _,
        committed_receipt_canonical: _,
        committed_receipt_sha256: _,
        stale_finalize_clock_unix_millis: _,
        response_digest: _,
    } = DomainOperationVerifiedStaleFinalizeResponse::default();

    let DomainOperationTerminalStatusAttachRequest {
        verified_issuer: _,
        authenticated_subject: _,
        org_uuid: _,
        initiating_principal_namespace: _,
        operation_id: _,
        authorization_id: _,
        authorization_revision: _,
        claim_id: _,
        claim_revision: _,
        terminal_outcome: _,
        terminal_receipt_sha256: _,
        platform_terminal_status_revision: _,
        acknowledged_at_unix_millis: _,
        phase: _,
        reserve_charge_revision: _,
        reserve_charge_nonce: _,
        phase2_action: _,
        release_tombstone_digest: _,
        active_release_intent_revision: _,
        active_release_intent_nonce: _,
        tombstone_reservation_revision: _,
        tombstone_reservation_nonce: _,
        final_prune_digest: _,
        tombstone_release_intent_revision: _,
        tombstone_release_intent_nonce: _,
        release_proof_reservation_revision: _,
        release_proof_reservation_nonce: _,
        completion_marker_sequence: _,
        expected_completion_marker_digest: _,
        request_digest: _,
    } = DomainOperationTerminalStatusAttachRequest::default();
    let DomainOperationTerminalStatusAttachmentAckV1 {
        status: _,
        terminal_ack_canonical: _,
        terminal_ack_digest: _,
        receipt_prune_digest: _,
        fence_prune_digest: _,
        release_tombstone_digest: _,
        tombstone_created_at_unix_millis: _,
        tombstone_retain_until_unix_millis: _,
        active_release_ack_digest: _,
        active_release_ack_at_unix_millis: _,
        tombstone_reservation_claim_digest: _,
        final_prune_digest: _,
        final_pruned_at_unix_millis: _,
        completion_marker_digest: _,
        completion_marker_created_at_unix_millis: _,
        completion_marker_retain_until_unix_millis: _,
        completion_marker_sequence: _,
        completion_marker_proof_digest: _,
        prune_range_start_sequence: _,
        prune_range_end_sequence: _,
        prune_range_digest: _,
        prune_range_generation: _,
        informational_high_water: _,
        response_digest: _,
    } = DomainOperationTerminalStatusAttachmentAckV1::default();

    let DomainOperationProofNamespaceMaterializeRequestV1 {
        protocol_revision: _,
        verified_issuer: _,
        authenticated_subject: _,
        org_uuid: _,
        initiating_principal_namespace: _,
        namespace_epoch: _,
        namespace_claim_revision: _,
        namespace_claim_nonce: _,
        platform_capacity_revision: _,
        lore_local_capacity_revision: _,
        request_digest: _,
        materialization_jwt: _,
    } = DomainOperationProofNamespaceMaterializeRequestV1::default();
    let DomainOperationProofNamespaceMaterializeReceiptV1 {
        status: _,
        namespace_epoch: _,
        namespace_claim_revision: _,
        namespace_claim_nonce: _,
        lore_namespace_revision: _,
        lore_global_counter_revision: _,
        lore_org_counter_revision: _,
        created_at_unix_millis: _,
        materialization_receipt_digest: _,
        response_digest: _,
    } = DomainOperationProofNamespaceMaterializeReceiptV1::default();

    let DomainOperationProofNamespaceRetireRequestV1 {
        protocol_revision: _,
        verified_issuer: _,
        authenticated_subject: _,
        org_uuid: _,
        initiating_principal_namespace: _,
        namespace_epoch: _,
        quota_revision: _,
        final_range_set_digest: _,
        final_high_water: _,
        retirement_fence_generation: _,
        retirement_permit_revision: _,
        issued_at_unix_millis: _,
        expires_at_unix_millis: _,
        zero_platform_state_digest: _,
        request_digest: _,
        retirement_permit_jwt: _,
        namespace_claim_revision: _,
        namespace_claim_nonce: _,
    } = DomainOperationProofNamespaceRetireRequestV1::default();
    let DomainOperationProofNamespaceRetireAckV1 {
        status: _,
        namespace_epoch: _,
        retirement_fence_generation: _,
        quota_revision: _,
        final_range_set_digest: _,
        final_high_water: _,
        retired_at_unix_millis: _,
        namespace_claim_revision: _,
        namespace_claim_nonce: _,
        response_digest: _,
    } = DomainOperationProofNamespaceRetireAckV1::default();
}

#[test]
fn enum_discriminants_are_frozen() {
    assert_eq!(DomainOperationPrepareStatus::Prepared as i32, 1);
    assert_eq!(DomainOperationPrepareStatus::Committed as i32, 2);
    assert_eq!(DomainOperationPrepareStatus::ExpiredOrUnknown as i32, 3);
    assert_eq!(DomainOperationPrepareStatus::Mismatch as i32, 4);
    assert_eq!(DomainOperationPrepareStatus::CapacityExhausted as i32, 5);

    assert_eq!(DomainOperationOutcome::Applied as i32, 1);
    assert_eq!(DomainOperationOutcome::NotApplied as i32, 2);

    assert_eq!(DomainOperationReceiptStatus::Prepared as i32, 1);
    assert_eq!(DomainOperationReceiptStatus::Committed as i32, 2);
    assert_eq!(DomainOperationReceiptStatus::Mismatch as i32, 3);
    assert_eq!(DomainOperationReceiptStatus::Expired as i32, 4);
    assert_eq!(DomainOperationReceiptStatus::ExpiredOrUnknown as i32, 5);
    assert_eq!(DomainOperationReceiptStatus::NotFound as i32, 6);

    assert_eq!(
        DomainOperationVerifiedStaleFinalizeStatus::Committed as i32,
        1
    );
    assert_eq!(
        DomainOperationVerifiedStaleFinalizeStatus::NotEligibleNotStale as i32,
        2
    );
    assert_eq!(
        DomainOperationVerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible as i32,
        3
    );
    assert_eq!(
        DomainOperationVerifiedStaleFinalizeStatus::IneligibleFinalizePermit as i32,
        4
    );
    assert_eq!(
        DomainOperationVerifiedStaleFinalizeStatus::Mismatch as i32,
        5
    );

    assert_eq!(TerminalStatusAttachPhaseV1::Phase1TerminalAck as i32, 1);
    assert_eq!(TerminalStatusAttachPhaseV1::Phase2ReleaseAck as i32, 2);
    assert_eq!(
        TerminalStatusAttachPhase2ActionV1::ActiveReleaseIntentAck as i32,
        1
    );
    assert_eq!(
        TerminalStatusAttachPhase2ActionV1::TombstonePrunePoll as i32,
        2
    );
    assert_eq!(
        TerminalStatusAttachPhase2ActionV1::TombstoneReleaseIntentComplete as i32,
        3
    );
    assert_eq!(
        DomainOperationTerminalStatusAttachmentStatusV1::Phase1PendingRetention as i32,
        1
    );
    assert_eq!(
        DomainOperationTerminalStatusAttachmentStatusV1::Phase1TombstoneReady as i32,
        2
    );
    assert_eq!(
        DomainOperationTerminalStatusAttachmentStatusV1::Phase2ActiveReleaseAcked as i32,
        3
    );
    assert_eq!(
        DomainOperationTerminalStatusAttachmentStatusV1::Phase2TombstoneRetentionPending as i32,
        4
    );
    assert_eq!(
        DomainOperationTerminalStatusAttachmentStatusV1::Phase2TombstoneFinalPruned as i32,
        5
    );
    assert_eq!(
        DomainOperationTerminalStatusAttachmentStatusV1::Phase2ReleaseCompletionReady as i32,
        6
    );
    assert_eq!(
        DomainOperationTerminalStatusAttachmentStatusV1::Phase2PostPruneRecovery as i32,
        7
    );
    assert_eq!(
        DomainOperationTerminalStatusAttachmentStatusV1::Phase2PostPruneCompletionReplayRequired
            as i32,
        8
    );
    assert_eq!(
        DomainOperationTerminalStatusAttachmentStatusV1::Mismatch as i32,
        9
    );
    assert_eq!(
        DomainOperationTerminalStatusAttachmentStatusV1::Invalid as i32,
        10
    );

    assert_eq!(
        DomainOperationProofNamespaceMaterializeStatusV1::Materialized as i32,
        1
    );
    assert_eq!(
        DomainOperationProofNamespaceMaterializeStatusV1::Mismatch as i32,
        2
    );
    assert_eq!(
        DomainOperationProofNamespaceMaterializeStatusV1::CapacityBlocked as i32,
        3
    );
    assert_eq!(
        DomainOperationProofNamespaceMaterializeStatusV1::Invalid as i32,
        4
    );

    assert_eq!(
        DomainOperationProofNamespaceRetireStatusV1::Retired as i32,
        1
    );
    assert_eq!(
        DomainOperationProofNamespaceRetireStatusV1::RetiredOrAbsent as i32,
        2
    );
    assert_eq!(
        DomainOperationProofNamespaceRetireStatusV1::NotQuiescent as i32,
        3
    );
    assert_eq!(
        DomainOperationProofNamespaceRetireStatusV1::Mismatch as i32,
        4
    );
    assert_eq!(
        DomainOperationProofNamespaceRetireStatusV1::Expired as i32,
        5
    );
    assert_eq!(
        DomainOperationProofNamespaceRetireStatusV1::Invalid as i32,
        6
    );
}

#[test]
fn optional_zero_values_retain_wire_presence() {
    let prepare = DomainOperationPrepareResponse {
        hard_expires_at_unix_millis: Some(0),
        reason_version: Some(0),
        ..Default::default()
    };
    assert_eq!(prepare.encode_to_vec(), [0x18, 0x00, 0x28, 0x00]);

    let receipt = DomainOperationReceiptGetResponse {
        reason_version: Some(0),
        prepared_at_unix_millis: Some(0),
        hard_expires_at_unix_millis: Some(0),
        ..Default::default()
    };
    assert_eq!(
        receipt.encode_to_vec(),
        [0x18, 0x00, 0x30, 0x00, 0x38, 0x00]
    );

    let stale_finalize = DomainOperationVerifiedStaleFinalizeResponse {
        stale_finalize_clock_unix_millis: Some(0),
        ..Default::default()
    };
    assert_eq!(stale_finalize.encode_to_vec(), [0x28, 0x00]);

    let attach = DomainOperationTerminalStatusAttachmentAckV1 {
        tombstone_created_at_unix_millis: Some(0),
        tombstone_retain_until_unix_millis: Some(0),
        active_release_ack_at_unix_millis: Some(0),
        final_pruned_at_unix_millis: Some(0),
        completion_marker_created_at_unix_millis: Some(0),
        completion_marker_retain_until_unix_millis: Some(0),
        prune_range_start_sequence: Some(0),
        prune_range_end_sequence: Some(0),
        prune_range_generation: Some(0),
        informational_high_water: Some(0),
        ..Default::default()
    };
    assert_eq!(
        attach.encode_to_vec(),
        [
            0x38, 0x00, 0x40, 0x00, 0x50, 0x00, 0x68, 0x00, 0x78, 0x00, 0x80, 0x01, 0x00, 0x98,
            0x01, 0x00, 0xA0, 0x01, 0x00, 0xB0, 0x01, 0x00, 0xB8, 0x01, 0x00,
        ]
    );

    let retire = DomainOperationProofNamespaceRetireAckV1 {
        retired_at_unix_millis: Some(0),
        ..Default::default()
    };
    assert_eq!(retire.encode_to_vec(), [0x38, 0x00]);
}

fn strict_transport_frames() -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
    let identity = || {
        (
            "https://issuer.example".to_string(),
            "service-subject".to_string(),
            vec![0x11; 16].into(),
            b"principal-v1\0fixture".as_slice().into(),
        )
    };
    let prepare = DomainOperationPrepareRequest {
        org_uuid: vec![0x01; 16].into(),
        initiating_principal_namespace: b"principal-v1\0fixture".as_slice().into(),
        operation_id: vec![0x02; 16].into(),
        method: "lore.domain.v1.test/Prepare".into(),
        scope: b"scope".as_slice().into(),
        fingerprint_version: 1,
        fingerprint: vec![0x03; 32].into(),
        canonical_intent_digest: vec![0x04; 32].into(),
        authorization_id: vec![0x02; 16].into(),
        authorization_revision: 1,
        preclaim_ticket: vec![0x05; 32].into(),
    };
    let receipt_get = DomainOperationReceiptGetRequest {
        org_uuid: vec![0x11; 16].into(),
        initiating_principal_namespace: b"principal-v1\0fixture".as_slice().into(),
        operation_id: vec![0x12; 16].into(),
        method: "lore.domain.v1.test/ReceiptGet".into(),
        scope: b"scope".as_slice().into(),
        fingerprint_version: 1,
        fingerprint: vec![0x13; 32].into(),
        canonical_intent_digest: vec![0x14; 32].into(),
        authorization_id: vec![0x12; 16].into(),
        authorization_revision: 1,
        consumed_ticket_sha256: vec![0x15; 32].into(),
    };
    let (verified_issuer, authenticated_subject, org_uuid, principal) = identity();
    let finalize = DomainOperationVerifiedStaleFinalizeRequest {
        verified_issuer,
        authenticated_subject,
        org_uuid,
        initiating_principal_namespace: principal,
        operation_id: vec![0x12; 16].into(),
        method: "lore.domain.v1.test/Method".into(),
        scope: b"scope".as_slice().into(),
        fingerprint_version: 1,
        fingerprint: vec![0x13; 32].into(),
        canonical_intent_digest: vec![0x14; 32].into(),
        authorization_id: vec![0x15; 16].into(),
        authorization_revision: 1,
        verification_nonce: vec![0x16; 32].into(),
        bound_fields_digest: vec![0x17; 32].into(),
        consumed_ticket_sha256: vec![0x18; 32].into(),
        expected_claim_identity_digest: vec![0x19; 32].into(),
        stale_finalize_permit: vec![0x1a; 32].into(),
        stale_finalize_permit_revision: 1,
    };
    let (verified_issuer, authenticated_subject, org_uuid, principal) = identity();
    let attach = DomainOperationTerminalStatusAttachRequest {
        verified_issuer,
        authenticated_subject,
        org_uuid,
        initiating_principal_namespace: principal,
        operation_id: vec![0x21; 16].into(),
        authorization_id: vec![0x22; 16].into(),
        authorization_revision: 1,
        claim_id: vec![0x23; 16].into(),
        claim_revision: 1,
        terminal_outcome: 1,
        terminal_receipt_sha256: vec![0x24; 32].into(),
        platform_terminal_status_revision: 1,
        acknowledged_at_unix_millis: 1,
        phase: 1,
        reserve_charge_revision: 1,
        reserve_charge_nonce: vec![0x25; 32].into(),
        phase2_action: 0,
        release_tombstone_digest: Default::default(),
        active_release_intent_revision: 0,
        active_release_intent_nonce: Default::default(),
        tombstone_reservation_revision: 1,
        tombstone_reservation_nonce: vec![0x26; 32].into(),
        final_prune_digest: Default::default(),
        tombstone_release_intent_revision: 0,
        tombstone_release_intent_nonce: Default::default(),
        release_proof_reservation_revision: 1,
        release_proof_reservation_nonce: vec![0x27; 32].into(),
        completion_marker_sequence: 1,
        expected_completion_marker_digest: Default::default(),
        request_digest: vec![0x28; 32].into(),
    };
    let (verified_issuer, authenticated_subject, org_uuid, principal) = identity();
    let materialize = DomainOperationProofNamespaceMaterializeRequestV1 {
        protocol_revision: 2,
        verified_issuer,
        authenticated_subject,
        org_uuid,
        initiating_principal_namespace: principal,
        namespace_epoch: vec![0x31; 16].into(),
        namespace_claim_revision: 1,
        namespace_claim_nonce: vec![0x32; 32].into(),
        platform_capacity_revision: 1,
        lore_local_capacity_revision: 1,
        request_digest: vec![0x33; 32].into(),
        materialization_jwt: "jwt".into(),
    };
    let (verified_issuer, authenticated_subject, org_uuid, principal) = identity();
    let retire = DomainOperationProofNamespaceRetireRequestV1 {
        protocol_revision: 2,
        verified_issuer,
        authenticated_subject,
        org_uuid,
        initiating_principal_namespace: principal,
        namespace_epoch: vec![0x41; 16].into(),
        quota_revision: 1,
        final_range_set_digest: vec![0x42; 32].into(),
        final_high_water: 1,
        retirement_fence_generation: 1,
        retirement_permit_revision: 1,
        issued_at_unix_millis: 1,
        expires_at_unix_millis: 2,
        zero_platform_state_digest: vec![0x43; 32].into(),
        request_digest: vec![0x44; 32].into(),
        retirement_permit_jwt: "jwt".into(),
        namespace_claim_revision: 1,
        namespace_claim_nonce: vec![0x45; 32].into(),
    };
    vec![
        ("DomainOperationClockGetRequest", Vec::new(), Vec::new()),
        (
            "DomainOperationPrepareRequest",
            prepare.encode_to_vec(),
            vec![0x0a, 0x01, b'x'],
        ),
        (
            "DomainOperationReceiptGetRequest",
            receipt_get.encode_to_vec(),
            vec![0x0a, 0x01, b'x'],
        ),
        (
            "DomainOperationVerifiedStaleFinalizeRequest",
            finalize.encode_to_vec(),
            vec![0x0a, 0x01, b'x'],
        ),
        (
            "DomainOperationTerminalStatusAttachRequest",
            attach.encode_to_vec(),
            vec![0x0a, 0x01, b'x'],
        ),
        (
            "DomainOperationProofNamespaceMaterializeRequestV1",
            materialize.encode_to_vec(),
            vec![0x08, 0x02],
        ),
        (
            "DomainOperationProofNamespaceRetireRequestV1",
            retire.encode_to_vec(),
            vec![0x08, 0x02],
        ),
    ]
}

fn encode_test_varint(mut value: u64) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

fn test_varint_field(tag: u32) -> Vec<u8> {
    let mut encoded = encode_test_varint(u64::from(tag) << 3);
    encoded.push(0);
    encoded
}

fn test_empty_length_delimited_field(tag: u32) -> Vec<u8> {
    let mut encoded = encode_test_varint((u64::from(tag) << 3) | 2);
    encoded.push(0);
    encoded
}

fn assert_transport_implicit_zero_fields_remain_strict(name: &str, raw: &[u8], tags: &[u32]) {
    validate_domain_operation_v2_raw(name, raw)
        .unwrap_or_else(|error| panic!("{name} rejected implicit zero fields: {error}"));
    for tag in tags {
        let explicit = test_varint_field(*tag);
        let mut one_explicit_zero = raw.to_vec();
        one_explicit_zero.extend_from_slice(&explicit);
        validate_domain_operation_v2_raw(name, &one_explicit_zero).unwrap_or_else(|error| {
            panic!("{name} rejected one explicit zero for tag {tag}: {error}")
        });

        let mut duplicate = one_explicit_zero;
        duplicate.extend_from_slice(&explicit);
        assert!(
            validate_domain_operation_v2_raw(name, &duplicate).is_err(),
            "{name} accepted duplicate implicit-zero tag {tag}"
        );

        let mut wrong_wire = raw.to_vec();
        wrong_wire.extend_from_slice(&test_empty_length_delimited_field(*tag));
        assert!(
            validate_domain_operation_v2_raw(name, &wrong_wire).is_err(),
            "{name} accepted wrong wire type for implicit-zero tag {tag}"
        );
    }
}

#[test]
fn transport_strict_validator_accepts_only_the_frozen_implicit_zero_scalar_set() {
    let frames = strict_transport_frames();

    let mut retire = DomainOperationProofNamespaceRetireRequestV1::decode(
        frames
            .iter()
            .find(|(name, _, _)| *name == "DomainOperationProofNamespaceRetireRequestV1")
            .expect("retire frame")
            .1
            .as_slice(),
    )
    .expect("decode retire fixture");
    retire.final_high_water = 0;
    assert_transport_implicit_zero_fields_remain_strict(
        "DomainOperationProofNamespaceRetireRequestV1",
        &retire.encode_to_vec(),
        &[9],
    );

    let mut materialize = DomainOperationProofNamespaceMaterializeRequestV1::decode(
        frames
            .iter()
            .find(|(name, _, _)| *name == "DomainOperationProofNamespaceMaterializeRequestV1")
            .expect("materialize frame")
            .1
            .as_slice(),
    )
    .expect("decode materialize fixture");
    materialize.platform_capacity_revision = 0;
    materialize.lore_local_capacity_revision = 0;
    assert_transport_implicit_zero_fields_remain_strict(
        "DomainOperationProofNamespaceMaterializeRequestV1",
        &materialize.encode_to_vec(),
        &[9, 10],
    );

    let mut finalize = DomainOperationVerifiedStaleFinalizeRequest::decode(
        frames
            .iter()
            .find(|(name, _, _)| *name == "DomainOperationVerifiedStaleFinalizeRequest")
            .expect("stale-finalize frame")
            .1
            .as_slice(),
    )
    .expect("decode stale-finalize fixture");
    finalize.fingerprint_version = 0;
    finalize.authorization_revision = 0;
    finalize.stale_finalize_permit_revision = 0;
    assert_transport_implicit_zero_fields_remain_strict(
        "DomainOperationVerifiedStaleFinalizeRequest",
        &finalize.encode_to_vec(),
        &[8, 12, 18],
    );

    let mut attach = DomainOperationTerminalStatusAttachRequest::decode(
        frames
            .iter()
            .find(|(name, _, _)| *name == "DomainOperationTerminalStatusAttachRequest")
            .expect("terminal-attach frame")
            .1
            .as_slice(),
    )
    .expect("decode terminal-attach fixture");
    attach.authorization_revision = 0;
    attach.claim_revision = 0;
    attach.platform_terminal_status_revision = 0;
    attach.acknowledged_at_unix_millis = 0;
    attach.reserve_charge_revision = 0;
    attach.tombstone_reservation_revision = 0;
    attach.release_proof_reservation_revision = 0;
    attach.completion_marker_sequence = 0;
    assert_transport_implicit_zero_fields_remain_strict(
        "DomainOperationTerminalStatusAttachRequest",
        &attach.encode_to_vec(),
        &[7, 9, 12, 13, 15, 21, 26, 28],
    );
}

#[test]
fn transport_strict_validator_rejects_original_malformed_frames_for_each_wire() {
    for (name, valid, duplicate_field) in strict_transport_frames() {
        validate_domain_operation_v2_raw(name, &valid)
            .unwrap_or_else(|error| panic!("valid {name} rejected: {error}"));

        let mut unknown = valid.clone();
        unknown.extend_from_slice(&[0xfa, 0x01, 0x00]);
        assert!(validate_domain_operation_v2_raw(name, &unknown).is_err());

        if name == "DomainOperationClockGetRequest" {
            assert!(validate_domain_operation_v2_raw(name, &[0x08, 0x01]).is_err());
            assert!(validate_domain_operation_v2_raw(name, &vec![0; 16 * 1024 + 1]).is_err());
            continue;
        }

        let mut duplicate = valid;
        duplicate.extend_from_slice(&duplicate_field);
        assert!(validate_domain_operation_v2_raw(name, &duplicate).is_err());
        assert!(validate_domain_operation_v2_raw(name, &[]).is_err());
        assert!(validate_domain_operation_v2_raw(name, &[0x00]).is_err());
        assert!(validate_domain_operation_v2_raw(name, &[0x8a, 0x00, 0x00]).is_err());
        let wrong_wire: &[u8] = if name.contains("Materialize") || name.contains("Retire") {
            &[0x0a, 0x00]
        } else {
            &[0x08, 0x01]
        };
        assert!(validate_domain_operation_v2_raw(name, wrong_wire).is_err());
        assert!(
            validate_domain_operation_v2_raw(
                name,
                &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02],
            )
            .is_err()
        );
        assert!(validate_domain_operation_v2_raw(name, &[0x0a, 0x05, b'x']).is_err());
        assert!(validate_domain_operation_v2_raw(name, &vec![0; 16 * 1024 + 1]).is_err());
    }
}

#[test]
fn live_prepare_and_receipt_get_reject_noncanonical_keys_and_high_unknown_tags() {
    for (name, valid, _) in strict_transport_frames()
        .into_iter()
        .filter(|(name, _, _)| {
            matches!(
                *name,
                "DomainOperationPrepareRequest" | "DomainOperationReceiptGetRequest"
            )
        })
    {
        let mut noncanonical = vec![0x8a, 0x00];
        noncanonical.extend_from_slice(&valid[1..]);
        let error = validate_domain_operation_v2_raw(name, &noncanonical)
            .expect_err("the original noncanonical key must be rejected before Prost");
        assert!(error.message().contains("noncanonical protobuf varint"));

        for unknown_high_tag in [[0xfa, 0x01, 0x00], [0xfa, 0x03, 0x00]] {
            let mut raw = valid.clone();
            raw.extend_from_slice(&unknown_high_tag);
            let error = validate_domain_operation_v2_raw(name, &raw)
                .expect_err("unknown tag 31/63 must reject without indexing outside the table");
            assert!(error.message().contains("unknown protobuf field"));
        }
    }
}

#[test]
fn private_service_declares_the_complete_seven_rpc_rail() {
    let expected = [
        "rpc DomainOperationClockGet",
        "rpc DomainOperationPrepare",
        "rpc DomainOperationReceiptGet",
        "rpc DomainOperationVerifiedStaleFinalize",
        "rpc DomainOperationTerminalStatusAttach",
        "rpc DomainOperationProofNamespaceMaterialize",
        "rpc DomainOperationProofNamespaceRetire",
    ];
    assert_eq!(PROTO.matches("rpc DomainOperation").count(), expected.len());
    for declaration in expected {
        assert!(PROTO.contains(declaration), "missing {declaration}");
    }
}

#[test]
fn maintenance_request_tags_and_wire_scalar_kinds_are_frozen() {
    for declaration in [
        "string verified_issuer = 1;",
        "uint64 stale_finalize_permit_revision = 18;",
        "TerminalStatusAttachPhaseV1 phase = 14;",
        "bytes expected_completion_marker_digest = 29;",
        "bytes request_digest = 30;",
        "uint32 protocol_revision = 1;",
        "string materialization_jwt = 12;",
        "uint64 retirement_fence_generation = 10;",
        "string retirement_permit_jwt = 16;",
        "bytes namespace_claim_nonce = 18;",
    ] {
        assert!(
            PROTO.contains(declaration),
            "missing frozen field {declaration}"
        );
    }
}

#[test]
fn maintenance_response_tags_and_optional_presence_are_frozen() {
    for declaration in [
        "optional int64 stale_finalize_clock_unix_millis = 5;",
        "bytes response_digest = 6;",
        "optional int64 tombstone_created_at_unix_millis = 7;",
        "optional uint64 prune_range_start_sequence = 19;",
        "optional uint64 informational_high_water = 23;",
        "bytes response_digest = 24;",
        "bytes materialization_receipt_digest = 9;",
        "optional int64 retired_at_unix_millis = 7;",
        "bytes response_digest = 10;",
    ] {
        assert!(
            PROTO.contains(declaration),
            "missing frozen field {declaration}"
        );
    }
}

#[test]
fn generated_client_server_and_exact_method_paths_exist() {
    let _ = std::mem::size_of::<DomainOperationServiceClient<tonic::transport::Channel>>();
    let _ = std::mem::size_of::<DomainOperationServiceServer<UnimplementedService>>();
    for method in [
        "/lore.domain.v1.DomainOperationService/DomainOperationClockGet",
        "/lore.domain.v1.DomainOperationService/DomainOperationPrepare",
        "/lore.domain.v1.DomainOperationService/DomainOperationReceiptGet",
        "/lore.domain.v1.DomainOperationService/DomainOperationVerifiedStaleFinalize",
        "/lore.domain.v1.DomainOperationService/DomainOperationTerminalStatusAttach",
        "/lore.domain.v1.DomainOperationService/DomainOperationProofNamespaceMaterialize",
        "/lore.domain.v1.DomainOperationService/DomainOperationProofNamespaceRetire",
    ] {
        assert!(
            GENERATED.contains(method),
            "missing generated path {method}"
        );
    }
    assert_eq!(
        GENERATED.matches("DomainOperationV2StrictCodec").count(),
        14,
        "all seven generated client calls and seven server routes must use the strict codec"
    );
}

#[derive(Debug)]
struct UnimplementedService;

#[tonic::async_trait]
impl lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationService
    for UnimplementedService
{
    async fn domain_operation_clock_get(
        &self,
        _request: tonic::Request<DomainOperationClockGetRequest>,
    ) -> Result<tonic::Response<DomainOperationClockGetResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("test-only"))
    }

    async fn domain_operation_prepare(
        &self,
        _request: tonic::Request<DomainOperationPrepareRequest>,
    ) -> Result<tonic::Response<DomainOperationPrepareResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("test-only"))
    }

    async fn domain_operation_receipt_get(
        &self,
        _request: tonic::Request<DomainOperationReceiptGetRequest>,
    ) -> Result<tonic::Response<DomainOperationReceiptGetResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("test-only"))
    }

    async fn domain_operation_verified_stale_finalize(
        &self,
        _request: tonic::Request<DomainOperationVerifiedStaleFinalizeRequest>,
    ) -> Result<tonic::Response<DomainOperationVerifiedStaleFinalizeResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("test-only"))
    }

    async fn domain_operation_terminal_status_attach(
        &self,
        _request: tonic::Request<DomainOperationTerminalStatusAttachRequest>,
    ) -> Result<tonic::Response<DomainOperationTerminalStatusAttachmentAckV1>, tonic::Status> {
        Err(tonic::Status::unimplemented("test-only"))
    }

    async fn domain_operation_proof_namespace_materialize(
        &self,
        _request: tonic::Request<DomainOperationProofNamespaceMaterializeRequestV1>,
    ) -> Result<tonic::Response<DomainOperationProofNamespaceMaterializeReceiptV1>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("test-only"))
    }

    async fn domain_operation_proof_namespace_retire(
        &self,
        _request: tonic::Request<DomainOperationProofNamespaceRetireRequestV1>,
    ) -> Result<tonic::Response<DomainOperationProofNamespaceRetireAckV1>, tonic::Status> {
        Err(tonic::Status::unimplemented("test-only"))
    }
}
