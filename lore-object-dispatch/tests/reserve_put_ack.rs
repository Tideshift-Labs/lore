// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::ReservePutAckError;
use lore_object_dispatch::ReservePutAckLimits;
use lore_object_dispatch::validate_and_encode_object_store_reserve_put_ack;
use lore_proto::lore::object_dispatch::v1::ObjectStoreNoDispatchProofV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadReleaseReasonV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDispositionV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalRetryabilityV1;
use lore_proto::lore::object_dispatch::v1::PutReservationClosureV1;
use lore_proto::lore::object_dispatch::v1::PutReservationStateV1;
use lore_proto::lore::object_dispatch::v1::PutSpoolReadyV1;
use lore_proto::lore::object_dispatch::v1::ReservePutAckV1;

const ADMISSION: i64 = 2_000;
const EXPIRES: i64 = 3_000;
const ALLOCATION_EXPIRY: i64 = 4_000;
const BODY_DIGEST: [u8; 32] = [0x31; 32];
const ACK_FINGERPRINT: [u8; 32] = [0x41; 32];
const DISCARD_FINGERPRINT: [u8; 32] = [0x51; 32];

fn uuid_v7(timestamp_unix_ms: u64, tail: &str) -> String {
    let timestamp = format!("{timestamp_unix_ms:012x}");
    format!("{}-{}-7abc-8def-{tail}", &timestamp[..8], &timestamp[8..])
}

fn limits() -> ReservePutAckLimits {
    ReservePutAckLimits {
        max_identity_bytes: 256,
        max_durable_handle_bytes: 256,
        max_canonical_row_bytes: 16_384,
    }
}

fn push_text(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("fixture text length must fit u32")
            .to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
}

fn push_framed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("fixture child length must fit u32")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}

fn complete(mut preimage: Vec<u8>) -> Vec<u8> {
    let digest = *blake3::hash(&preimage).as_bytes();
    preimage.extend_from_slice(&digest);
    preimage
}

fn quota() -> ObjectStoreQuotaUnitsV1 {
    ObjectStoreQuotaUnitsV1 {
        bytes: 64,
        rows: 1,
        concurrency: 1,
    }
}

fn quota_bytes(value: &ObjectStoreQuotaUnitsV1) -> Vec<u8> {
    let mut output = b"object-store-quota-units-v1\0".to_vec();
    output.extend_from_slice(&value.bytes.to_be_bytes());
    output.extend_from_slice(&value.rows.to_be_bytes());
    output.extend_from_slice(&value.concurrency.to_be_bytes());
    complete(output)
}

fn ack_receipt() -> ObjectStoreResultAckReceiptV1 {
    ObjectStoreResultAckReceiptV1 {
        state: ObjectStoreResultAckStateV1::ObjectStoreResultAckStateAcked as i32,
        terminal_result_id: "terminal-1".to_string(),
        ack_fingerprint: ACK_FINGERPRINT.to_vec().into(),
        acked_at_unix_ms: 3_200,
        payload_purge_after_unix_ms: Some(3_300),
    }
}

fn discard_receipt() -> ObjectStoreResultDiscardReceiptV1 {
    ObjectStoreResultDiscardReceiptV1 {
        state: ObjectStoreResultDiscardStateV1::ObjectStoreResultDiscardStateDiscarded as i32,
        terminal_result_id: "terminal-1".to_string(),
        discard_fingerprint: DISCARD_FINGERPRINT.to_vec().into(),
        discarded_at_unix_ms: 3_200,
        payload_purge_after_unix_ms: Some(3_300),
    }
}

fn receipt_child(value: &ObjectStoreResultAckReceiptV1) -> Vec<u8> {
    let mut output = b"object-store-result-ack-receipt-v1\0".to_vec();
    output.extend_from_slice(&1_u32.to_be_bytes());
    push_text(&mut output, &value.terminal_result_id);
    output.extend_from_slice(&value.ack_fingerprint);
    output.extend_from_slice(&(value.acked_at_unix_ms as u64).to_be_bytes());
    output.push(u8::from(value.payload_purge_after_unix_ms.is_some()));
    if let Some(time) = value.payload_purge_after_unix_ms {
        output.extend_from_slice(&(time as u64).to_be_bytes());
    }
    complete(output)
}

fn discard_child(value: &ObjectStoreResultDiscardReceiptV1) -> Vec<u8> {
    let mut output = b"object-store-result-discard-receipt-v1\0".to_vec();
    output.extend_from_slice(&1_u32.to_be_bytes());
    push_text(&mut output, &value.terminal_result_id);
    output.extend_from_slice(&value.discard_fingerprint);
    output.extend_from_slice(&(value.discarded_at_unix_ms as u64).to_be_bytes());
    output.push(u8::from(value.payload_purge_after_unix_ms.is_some()));
    if let Some(time) = value.payload_purge_after_unix_ms {
        output.extend_from_slice(&(time as u64).to_be_bytes());
    }
    complete(output)
}

fn closure(disposition: i32) -> PutReservationClosureV1 {
    let (ack, discard) = match disposition {
        value
            if value
                == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32 =>
        {
            (Some(ack_receipt()), None)
        }
        value
            if value
                == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded as i32 =>
        {
            (None, Some(discard_receipt()))
        }
        _ => (None, None),
    };
    let mut value = PutReservationClosureV1 {
        terminal_result_id: "terminal-1".to_string(),
        terminal_retryability:
            ObjectStoreTerminalRetryabilityV1::ObjectStoreTerminalRetryabilityRetryable as i32,
        result_disposition: disposition,
        ack_receipt: ack,
        discard_receipt: discard,
        closed_at_unix_ms: 3_100,
        closure_blake3: Default::default(),
    };
    let mut output = b"object-store-put-reservation-closure-v1\0".to_vec();
    push_text(&mut output, &value.terminal_result_id);
    output.extend_from_slice(&(value.terminal_retryability as u32).to_be_bytes());
    output.extend_from_slice(&(value.result_disposition as u32).to_be_bytes());
    output.push(u8::from(value.ack_receipt.is_some()));
    if let Some(receipt) = &value.ack_receipt {
        push_framed(&mut output, &receipt_child(receipt));
    }
    output.push(u8::from(value.discard_receipt.is_some()));
    if let Some(receipt) = &value.discard_receipt {
        push_framed(&mut output, &discard_child(receipt));
    }
    output.extend_from_slice(&(value.closed_at_unix_ms as u64).to_be_bytes());
    value.closure_blake3 = blake3::hash(&output).as_bytes().to_vec().into();
    value
}

fn no_dispatch(reason: i32, committed_at_unix_ms: i64) -> ObjectStoreNoDispatchProofV1 {
    let mut value = ObjectStoreNoDispatchProofV1 {
        reason,
        proof_id: uuid_v7(committed_at_unix_ms as u64, "1123456789ab"),
        proof_fence: 9,
        committed_at_unix_ms,
        authority_epoch: 10,
        proof_blake3: Default::default(),
    };
    let mut output = b"object-store-no-dispatch-proof-v1\0".to_vec();
    output.extend_from_slice(&(reason as u32).to_be_bytes());
    push_text(&mut output, &value.proof_id);
    output.extend_from_slice(&value.proof_fence.to_be_bytes());
    output.extend_from_slice(&(committed_at_unix_ms as u64).to_be_bytes());
    output.extend_from_slice(&value.authority_epoch.to_be_bytes());
    value.proof_blake3 = blake3::hash(&output).as_bytes().to_vec().into();
    value
}

fn release(
    disposition: i32,
    release_reason: i32,
    terminal_result_id: Option<&str>,
    purged_at_unix_ms: i64,
) -> ObjectStorePayloadPurgeReceiptV1 {
    let quota = quota();
    let mut value = ObjectStorePayloadPurgeReceiptV1 {
        purge_id: uuid_v7(purged_at_unix_ms as u64, "2123456789ab"),
        payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody as i32,
        terminal_result_id: terminal_result_id.map(str::to_string),
        disposition,
        released_bytes: quota.bytes,
        released_rows: quota.rows,
        released_concurrency: quota.concurrency,
        purged_at_unix_ms,
        provider_authority_refunded: false,
        receipt_blake3: Default::default(),
        release_reason,
        deleted_partial_temp_bytes: 0,
        deleted_partial_temp_files: 0,
    };
    let mut output = b"object-store-payload-purge-receipt-v1\0".to_vec();
    push_text(&mut output, &value.purge_id);
    output.extend_from_slice(&(value.payload_kind as u32).to_be_bytes());
    output.push(u8::from(value.terminal_result_id.is_some()));
    if let Some(terminal_result_id) = &value.terminal_result_id {
        push_text(&mut output, terminal_result_id);
    }
    output.extend_from_slice(&(value.disposition as u32).to_be_bytes());
    for units in [
        value.released_bytes,
        value.released_rows,
        value.released_concurrency,
    ] {
        output.extend_from_slice(&units.to_be_bytes());
    }
    output.extend_from_slice(&(purged_at_unix_ms as u64).to_be_bytes());
    output.push(0);
    output.extend_from_slice(&(release_reason as u32).to_be_bytes());
    output.extend_from_slice(&value.deleted_partial_temp_bytes.to_be_bytes());
    output.extend_from_slice(&value.deleted_partial_temp_files.to_be_bytes());
    value.receipt_blake3 = blake3::hash(&output).as_bytes().to_vec().into();
    value
}

fn reserved() -> ReservePutAckV1 {
    ReservePutAckV1 {
        protocol_revision: "protocol-1".to_string(),
        policy_revision: "policy-1".to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        logical_request_id: uuid_v7(1_000, "0123456789ab"),
        attempt_id: uuid_v7(1_001, "0223456789ab"),
        upload_id: uuid_v7(1_002, "0323456789ab"),
        upload_fence: 7,
        state: PutReservationStateV1::PutReservationStateReserved as i32,
        reserved_quota: Some(quota()),
        expires_at_unix_ms: EXPIRES,
        max_chunk_bytes: 16,
        spool_ready: None,
        payload_release_receipt: None,
        admission_clock_unix_ms: ADMISSION,
        allocation_hard_expiry_unix_ms: ALLOCATION_EXPIRY,
        closure: None,
        no_dispatch_proof: None,
        ack_blake3: Default::default(),
    }
}

fn spool_ready(parent: &ReservePutAckV1) -> PutSpoolReadyV1 {
    PutSpoolReadyV1 {
        protocol_revision: parent.protocol_revision.clone(),
        provider_boundary_id: parent.provider_boundary_id.clone(),
        authenticated_cell_id: parent.authenticated_cell_id.clone(),
        authenticated_tenant_id: parent.authenticated_tenant_id.clone(),
        logical_request_id: parent.logical_request_id.clone(),
        attempt_id: parent.attempt_id.clone(),
        upload_id: parent.upload_id.clone(),
        upload_fence: parent.upload_fence,
        durable_body_handle: "put/body-1".to_string(),
        body_size: 64,
        body_blake3: BODY_DIGEST.to_vec().into(),
        ready_at_unix_ms: 2_500,
    }
}

fn spool_child_bytes(value: &PutSpoolReadyV1) -> Vec<u8> {
    let mut output = b"object-store-put-spool-ready-v1\0".to_vec();
    for identity in [
        &value.protocol_revision,
        &value.provider_boundary_id,
        &value.authenticated_cell_id,
        &value.authenticated_tenant_id,
        &value.logical_request_id,
        &value.attempt_id,
        &value.upload_id,
    ] {
        push_text(&mut output, identity);
    }
    output.extend_from_slice(&value.upload_fence.to_be_bytes());
    push_text(&mut output, &value.durable_body_handle);
    output.extend_from_slice(&value.body_size.to_be_bytes());
    output.extend_from_slice(&value.body_blake3);
    output.extend_from_slice(&(value.ready_at_unix_ms as u64).to_be_bytes());
    complete(output)
}

fn closure_child_bytes(value: &PutReservationClosureV1) -> Vec<u8> {
    let mut output = b"object-store-put-reservation-closure-v1\0".to_vec();
    push_text(&mut output, &value.terminal_result_id);
    output.extend_from_slice(&(value.terminal_retryability as u32).to_be_bytes());
    output.extend_from_slice(&(value.result_disposition as u32).to_be_bytes());
    output.push(u8::from(value.ack_receipt.is_some()));
    if let Some(receipt) = &value.ack_receipt {
        push_framed(&mut output, &receipt_child(receipt));
    }
    output.push(u8::from(value.discard_receipt.is_some()));
    if let Some(receipt) = &value.discard_receipt {
        push_framed(&mut output, &discard_child(receipt));
    }
    output.extend_from_slice(&(value.closed_at_unix_ms as u64).to_be_bytes());
    assert_eq!(
        blake3::hash(&output).as_bytes(),
        value.closure_blake3.as_ref()
    );
    complete(output)
}

fn no_dispatch_child_bytes(value: &ObjectStoreNoDispatchProofV1) -> Vec<u8> {
    let mut output = b"object-store-no-dispatch-proof-v1\0".to_vec();
    output.extend_from_slice(&(value.reason as u32).to_be_bytes());
    push_text(&mut output, &value.proof_id);
    output.extend_from_slice(&value.proof_fence.to_be_bytes());
    output.extend_from_slice(&(value.committed_at_unix_ms as u64).to_be_bytes());
    output.extend_from_slice(&value.authority_epoch.to_be_bytes());
    assert_eq!(
        blake3::hash(&output).as_bytes(),
        value.proof_blake3.as_ref()
    );
    complete(output)
}

fn release_child_bytes(value: &ObjectStorePayloadPurgeReceiptV1) -> Vec<u8> {
    let mut output = b"object-store-payload-purge-receipt-v1\0".to_vec();
    push_text(&mut output, &value.purge_id);
    output.extend_from_slice(&(value.payload_kind as u32).to_be_bytes());
    output.push(u8::from(value.terminal_result_id.is_some()));
    if let Some(terminal_result_id) = &value.terminal_result_id {
        push_text(&mut output, terminal_result_id);
    }
    output.extend_from_slice(&(value.disposition as u32).to_be_bytes());
    for units in [
        value.released_bytes,
        value.released_rows,
        value.released_concurrency,
    ] {
        output.extend_from_slice(&units.to_be_bytes());
    }
    output.extend_from_slice(&(value.purged_at_unix_ms as u64).to_be_bytes());
    output.push(u8::from(value.provider_authority_refunded));
    output.extend_from_slice(&(value.release_reason as u32).to_be_bytes());
    output.extend_from_slice(&value.deleted_partial_temp_bytes.to_be_bytes());
    output.extend_from_slice(&value.deleted_partial_temp_files.to_be_bytes());
    assert_eq!(
        blake3::hash(&output).as_bytes(),
        value.receipt_blake3.as_ref()
    );
    complete(output)
}

fn expected_ack_preimage(value: &ReservePutAckV1) -> Vec<u8> {
    let mut output = b"object-store-reserve-put-ack-v1\0".to_vec();
    for identity in [
        &value.protocol_revision,
        &value.policy_revision,
        &value.provider_boundary_id,
        &value.authenticated_cell_id,
        &value.authenticated_tenant_id,
        &value.logical_request_id,
        &value.attempt_id,
        &value.upload_id,
    ] {
        push_text(&mut output, identity);
    }
    output.extend_from_slice(&value.upload_fence.to_be_bytes());
    output.extend_from_slice(&(value.state as u32).to_be_bytes());
    push_framed(
        &mut output,
        &quota_bytes(value.reserved_quota.as_ref().expect("fixture quota")),
    );
    output.extend_from_slice(&(value.expires_at_unix_ms as u64).to_be_bytes());
    output.extend_from_slice(&value.max_chunk_bytes.to_be_bytes());
    output.push(u8::from(value.spool_ready.is_some()));
    if let Some(spool) = &value.spool_ready {
        push_framed(&mut output, &spool_child_bytes(spool));
    }
    output.push(u8::from(value.payload_release_receipt.is_some()));
    if let Some(release) = &value.payload_release_receipt {
        push_framed(&mut output, &release_child_bytes(release));
    }
    output.extend_from_slice(&(value.admission_clock_unix_ms as u64).to_be_bytes());
    output.extend_from_slice(&(value.allocation_hard_expiry_unix_ms as u64).to_be_bytes());
    output.push(u8::from(value.closure.is_some()));
    if let Some(closure) = &value.closure {
        push_framed(&mut output, &closure_child_bytes(closure));
    }
    output.push(u8::from(value.no_dispatch_proof.is_some()));
    if let Some(proof) = &value.no_dispatch_proof {
        push_framed(&mut output, &no_dispatch_child_bytes(proof));
    }
    output
}

fn encode(
    value: &ReservePutAckV1,
) -> Result<lore_object_dispatch::CanonicalObjectStoreReservePutAck, ReservePutAckError> {
    validate_and_encode_object_store_reserve_put_ack(value, &limits())
}

#[test]
fn reserved_ack_pins_independent_canonical_preimage_and_normalizes_empty_digest() {
    let value = reserved();
    let expected_preimage = expected_ack_preimage(&value);
    let canonical = encode(&value).expect("valid RESERVED ACK");
    let expected_digest = *blake3::hash(&expected_preimage).as_bytes();
    let mut expected_bytes = expected_preimage.clone();
    expected_bytes.extend_from_slice(&expected_digest);

    assert_eq!(canonical.canonical_preimage(), expected_preimage);
    assert_eq!(canonical.ack_blake3(), &expected_digest);
    assert_eq!(canonical.canonical_bytes(), expected_bytes);
    assert_eq!(canonical.value().ack_blake3.as_ref(), expected_digest);
}

#[test]
fn every_nested_ack_child_pins_independently_assembled_canonical_bytes() {
    let mut spool = reserved();
    spool.state = PutReservationStateV1::PutReservationStateSpoolReady as i32;
    spool.spool_ready = Some(spool_ready(&spool));

    let mut expired = reserved();
    expired.state = PutReservationStateV1::PutReservationStatePreparedExpired as i32;
    expired.no_dispatch_proof = Some(no_dispatch(4, EXPIRES));
    expired.payload_release_receipt = Some(release(
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable as i32,
        ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonNoPayloadCreated as i32,
        None,
        3_400,
    ));

    let mut closed = reserved();
    closed.state = PutReservationStateV1::PutReservationStateClosed as i32;
    closed.closure = Some(closure(
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32,
    ));

    for value in [spool, expired, closed] {
        let expected = expected_ack_preimage(&value);
        let canonical = encode(&value).expect("nested canonical ACK");
        assert_eq!(canonical.canonical_preimage(), expected);
        assert_eq!(canonical.ack_blake3(), blake3::hash(&expected).as_bytes());
    }
}

#[test]
fn exact_supplied_ack_digest_replays_and_wrong_digest_or_width_rejects() {
    let value = reserved();
    let canonical = encode(&value).expect("baseline ACK");
    let mut supplied = value.clone();
    supplied.ack_blake3 = canonical.ack_blake3().to_vec().into();
    assert_eq!(encode(&supplied), Ok(canonical));

    supplied.ack_blake3 = vec![0; 31].into();
    assert_eq!(encode(&supplied), Err(ReservePutAckError::InvalidDigest));
    supplied.ack_blake3 = vec![0; 32].into();
    assert_eq!(encode(&supplied), Err(ReservePutAckError::DigestMismatch));
}

#[test]
fn all_five_states_accept_only_the_six_frozen_evidence_masks() {
    let states = [
        PutReservationStateV1::PutReservationStateReserved as i32,
        PutReservationStateV1::PutReservationStateSpoolReady as i32,
        PutReservationStateV1::PutReservationStatePreparedExpired as i32,
        PutReservationStateV1::PutReservationStateClosed as i32,
        PutReservationStateV1::PutReservationStatePayloadDisposed as i32,
    ];
    for state in states {
        for mask in 0_u8..16 {
            let mut value = reserved();
            value.state = state;
            if mask & 1 != 0 {
                value.spool_ready = Some(spool_ready(&value));
            }
            if mask & 4 != 0 {
                value.closure = Some(closure(
                    ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32,
                ));
            }
            if mask & 8 != 0 {
                let reason =
                    if state == PutReservationStateV1::PutReservationStatePreparedExpired as i32 {
                        4
                    } else {
                        6
                    };
                value.no_dispatch_proof = Some(no_dispatch(reason, 3_100));
            }
            if mask & 2 != 0 {
                value.payload_release_receipt = if state
                    == PutReservationStateV1::PutReservationStatePayloadDisposed as i32
                    && mask & 4 != 0
                {
                    Some(release(
                        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32,
                        ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonAckedRetentionElapsed as i32,
                        Some("terminal-1"),
                        3_400,
                    ))
                } else if state == PutReservationStateV1::PutReservationStatePayloadDisposed as i32
                {
                    Some(release(
                        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable as i32,
                        ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonNoDispatchBodyPurged as i32,
                        None,
                        3_400,
                    ))
                } else {
                    Some(release(
                        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable as i32,
                        ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonNoPayloadCreated as i32,
                        None,
                        3_400,
                    ))
                };
            }
            let expected = matches!(
                (state, mask),
                (1, 0) | (2, 1) | (3, 10) | (4, 4) | (5, 6) | (5, 10)
            );
            assert_eq!(
                encode(&value).is_ok(),
                expected,
                "state {state} evidence mask {mask:04b}"
            );
        }
    }
}

#[test]
fn spool_ready_binds_every_parent_identity_and_upload_fence() {
    let mut value = reserved();
    value.state = PutReservationStateV1::PutReservationStateSpoolReady as i32;
    value.spool_ready = Some(spool_ready(&value));
    let base = value.spool_ready.clone().expect("fixture spool");
    let mut mutations = Vec::new();
    macro_rules! mutate {
        ($field:ident, $replacement:expr) => {{
            let mut candidate = base.clone();
            candidate.$field = $replacement;
            mutations.push(candidate);
        }};
    }
    mutate!(protocol_revision, "protocol-2".to_string());
    mutate!(provider_boundary_id, "boundary-2".to_string());
    mutate!(authenticated_cell_id, "cell-2".to_string());
    mutate!(authenticated_tenant_id, "tenant-2".to_string());
    mutate!(logical_request_id, value.attempt_id.clone());
    mutate!(attempt_id, value.logical_request_id.clone());
    mutate!(upload_id, value.attempt_id.clone());
    mutate!(upload_fence, value.upload_fence + 1);

    assert!(mutations.into_iter().all(|spool| {
        let mut candidate = value.clone();
        candidate.spool_ready = Some(spool);
        encode(&candidate) == Err(ReservePutAckError::InvalidIdentityProjection)
    }));
}

#[test]
fn parent_identifiers_are_canonical_uuidv7_and_authorities_are_positive() {
    for field in 0..3 {
        let mut value = reserved();
        match field {
            0 => value.logical_request_id.make_ascii_uppercase(),
            1 => value.attempt_id = "not-a-uuid".to_string(),
            2 => value.upload_id = uuid_v7(1_002, "0323456789ag"),
            _ => unreachable!(),
        }
        assert_eq!(encode(&value), Err(ReservePutAckError::InvalidUuidV7));
    }

    let mut fence = reserved();
    fence.upload_fence = 0;
    assert_eq!(
        encode(&fence),
        Err(ReservePutAckError::NonPositiveAuthority)
    );
    let mut chunk = reserved();
    chunk.max_chunk_bytes = 0;
    assert_eq!(
        encode(&chunk),
        Err(ReservePutAckError::NonPositiveAuthority)
    );
}

#[test]
fn parent_and_spool_time_ordering_is_closed_at_every_boundary() {
    let mut equal_expiry = reserved();
    equal_expiry.expires_at_unix_ms = ADMISSION;
    assert_eq!(
        encode(&equal_expiry),
        Err(ReservePutAckError::InvalidTimeProjection)
    );
    let mut after_allocation = reserved();
    after_allocation.expires_at_unix_ms = ALLOCATION_EXPIRY + 1;
    assert_eq!(
        encode(&after_allocation),
        Err(ReservePutAckError::InvalidTimeProjection)
    );
    let mut negative = reserved();
    negative.admission_clock_unix_ms = -1;
    assert_eq!(encode(&negative), Err(ReservePutAckError::NegativeTime));

    let mut value = reserved();
    value.state = PutReservationStateV1::PutReservationStateSpoolReady as i32;
    for time in [ADMISSION - 1, EXPIRES] {
        let mut spool = spool_ready(&value);
        spool.ready_at_unix_ms = time;
        value.spool_ready = Some(spool);
        assert_eq!(
            encode(&value),
            Err(ReservePutAckError::InvalidTimeProjection)
        );
    }
    for time in [ADMISSION, EXPIRES - 1] {
        let mut spool = spool_ready(&value);
        spool.ready_at_unix_ms = time;
        value.spool_ready = Some(spool);
        assert!(encode(&value).is_ok());
    }
}

#[test]
fn bounded_future_uuid_timestamps_remain_canonical_audit_identity() {
    for field in 0..3 {
        let mut value = reserved();
        let future = uuid_v7(ADMISSION as u64 + 1, "4123456789ab");
        match field {
            0 => value.logical_request_id = future,
            1 => value.attempt_id = future,
            2 => value.upload_id = future,
            _ => unreachable!(),
        }
        let first = encode(&value).expect("future UUID within admission policy is audit-only");
        let second = encode(&value).expect("same accepted identity is deterministic");
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    }
}

#[test]
fn quota_spool_handle_and_body_digest_are_validated() {
    let mut empty = reserved();
    empty.reserved_quota = Some(ObjectStoreQuotaUnitsV1::default());
    assert_eq!(encode(&empty), Err(ReservePutAckError::InvalidQuota));

    let mut value = reserved();
    value.state = PutReservationStateV1::PutReservationStateSpoolReady as i32;
    let mut spool = spool_ready(&value);
    spool.durable_body_handle.clear();
    value.spool_ready = Some(spool);
    assert_eq!(
        encode(&value),
        Err(ReservePutAckError::InvalidCanonicalText)
    );
    let mut spool = spool_ready(&value);
    spool.body_blake3 = vec![0; 31].into();
    value.spool_ready = Some(spool);
    assert_eq!(encode(&value), Err(ReservePutAckError::InvalidDigest));
    let mut spool = spool_ready(&value);
    spool.body_size += 1;
    value.spool_ready = Some(spool);
    assert_eq!(encode(&value), Err(ReservePutAckError::InvalidQuota));
}

#[test]
fn closure_accepts_available_acked_or_discarded_with_only_matching_receipt() {
    for disposition in [
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable as i32,
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32,
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded as i32,
    ] {
        let mut value = reserved();
        value.state = PutReservationStateV1::PutReservationStateClosed as i32;
        value.closure = Some(closure(disposition));
        assert!(encode(&value).is_ok(), "disposition {disposition}");
    }

    let mut value = reserved();
    value.state = PutReservationStateV1::PutReservationStateClosed as i32;
    let mut mixed =
        closure(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32);
    mixed.discard_receipt = Some(discard_receipt());
    value.closure = Some(mixed);
    assert_eq!(
        encode(&value),
        Err(ReservePutAckError::InvalidStateEvidence)
    );
}

#[test]
fn closure_digest_terminal_identity_and_receipt_time_are_exact() {
    let mut value = reserved();
    value.state = PutReservationStateV1::PutReservationStateClosed as i32;
    let mut valid =
        closure(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32);
    valid.closure_blake3 = vec![0; 32].into();
    value.closure = Some(valid);
    assert_eq!(
        encode(&value),
        Err(ReservePutAckError::InvalidNestedEvidence)
    );

    let mut wrong_terminal =
        closure(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32);
    wrong_terminal
        .ack_receipt
        .as_mut()
        .expect("ACK receipt")
        .terminal_result_id = "terminal-2".to_string();
    wrong_terminal.closure_blake3 = Default::default();
    value.closure = Some(wrong_terminal);
    assert_eq!(
        encode(&value),
        Err(ReservePutAckError::InvalidIdentityProjection)
    );

    let mut early_receipt =
        closure(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32);
    early_receipt
        .ack_receipt
        .as_mut()
        .expect("ACK receipt")
        .acked_at_unix_ms = early_receipt.closed_at_unix_ms - 1;
    early_receipt.closure_blake3 = Default::default();
    value.closure = Some(early_receipt);
    assert_eq!(
        encode(&value),
        Err(ReservePutAckError::InvalidTimeProjection)
    );
}

#[test]
fn no_dispatch_proof_requires_semantic_reason_uuid_time_fence_epoch_and_digest() {
    let mut value = reserved();
    value.state = PutReservationStateV1::PutReservationStatePreparedExpired as i32;
    value.payload_release_receipt = Some(release(
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable as i32,
        ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonNoPayloadCreated as i32,
        None,
        3_400,
    ));
    let base = no_dispatch(4, 3_100);
    for mutation in 0..5 {
        let mut proof = base.clone();
        match mutation {
            0 => proof.reason = 0,
            1 => proof.proof_id = uuid_v7(3_101, "1123456789ab"),
            2 => proof.proof_fence = 0,
            3 => proof.authority_epoch = 0,
            4 => proof.proof_blake3 = vec![0; 32].into(),
            _ => unreachable!(),
        }
        value.no_dispatch_proof = Some(proof);
        assert_eq!(
            encode(&value),
            Err(ReservePutAckError::InvalidNestedEvidence)
        );
    }

    value.no_dispatch_proof = Some(no_dispatch(4, EXPIRES - 1));
    assert_eq!(
        encode(&value),
        Err(ReservePutAckError::InvalidTimeProjection)
    );
    value.no_dispatch_proof = Some(no_dispatch(4, EXPIRES));
    assert!(encode(&value).is_ok());

    value.state = PutReservationStateV1::PutReservationStatePayloadDisposed as i32;
    value.payload_release_receipt = Some(release(
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable as i32,
        ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonNoPayloadCreated as i32,
        None,
        3_400,
    ));
    value.no_dispatch_proof = Some(no_dispatch(6, ADMISSION - 1));
    assert_eq!(
        encode(&value),
        Err(ReservePutAckError::InvalidTimeProjection)
    );
    value.no_dispatch_proof = Some(no_dispatch(6, ADMISSION));
    assert!(encode(&value).is_ok());
}

#[test]
fn release_receipt_matches_quota_disposition_terminal_identity_and_never_refunds_provider() {
    let mut value = reserved();
    value.state = PutReservationStateV1::PutReservationStatePayloadDisposed as i32;
    value.closure = Some(closure(
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32,
    ));
    let base = release(
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32,
        ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonAckedRetentionElapsed
            as i32,
        Some("terminal-1"),
        3_400,
    );
    for mutation in 0..6 {
        let mut release = base.clone();
        match mutation {
            0 => release.released_bytes += 1,
            1 => release.provider_authority_refunded = true,
            2 => release.payload_kind = ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult as i32,
            3 => release.disposition = ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded as i32,
            4 => release.terminal_result_id = Some("terminal-2".to_string()),
            5 => release.release_reason = ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonDiscardedRetentionElapsed as i32,
            _ => unreachable!(),
        }
        release.receipt_blake3 = Default::default();
        value.payload_release_receipt = Some(release);
        assert!(encode(&value).is_err(), "release mutation {mutation}");
    }
}

#[test]
fn release_cannot_predate_the_proof_closure_or_matching_disposition_receipt() {
    let mut no_dispatch_value = reserved();
    no_dispatch_value.state = PutReservationStateV1::PutReservationStatePayloadDisposed as i32;
    no_dispatch_value.no_dispatch_proof = Some(no_dispatch(6, 3_200));
    no_dispatch_value.payload_release_receipt = Some(release(
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable as i32,
        ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonNoDispatchBodyPurged
            as i32,
        None,
        3_199,
    ));
    assert_eq!(
        encode(&no_dispatch_value),
        Err(ReservePutAckError::InvalidTimeProjection)
    );

    let mut terminal_value = reserved();
    terminal_value.state = PutReservationStateV1::PutReservationStatePayloadDisposed as i32;
    terminal_value.closure = Some(closure(
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32,
    ));
    terminal_value.payload_release_receipt = Some(release(
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32,
        ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonAckedRetentionElapsed
            as i32,
        Some("terminal-1"),
        3_199,
    ));
    assert_eq!(
        encode(&terminal_value),
        Err(ReservePutAckError::InvalidTimeProjection)
    );

    terminal_value.payload_release_receipt = Some(release(
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32,
        ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonAckedRetentionElapsed
            as i32,
        Some("terminal-1"),
        3_299,
    ));
    assert_eq!(
        encode(&terminal_value),
        Err(ReservePutAckError::InvalidTimeProjection)
    );
    terminal_value.payload_release_receipt = Some(release(
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32,
        ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonAckedRetentionElapsed
            as i32,
        Some("terminal-1"),
        3_300,
    ));
    assert!(encode(&terminal_value).is_ok());
}

#[test]
fn canonical_row_bound_is_inclusive_and_every_limit_is_positive() {
    let value = reserved();
    let size = encode(&value)
        .expect("baseline ACK")
        .canonical_bytes()
        .len() as u32;
    let mut exact = limits();
    exact.max_canonical_row_bytes = size;
    assert_eq!(
        validate_and_encode_object_store_reserve_put_ack(&value, &exact)
            .expect("exact row bound")
            .canonical_bytes()
            .len() as u32,
        size
    );
    exact.max_canonical_row_bytes -= 1;
    assert_eq!(
        validate_and_encode_object_store_reserve_put_ack(&value, &exact),
        Err(ReservePutAckError::CanonicalTooLarge)
    );

    for field in 0..3 {
        let mut invalid = limits();
        match field {
            0 => invalid.max_identity_bytes = 0,
            1 => invalid.max_durable_handle_bytes = 0,
            2 => invalid.max_canonical_row_bytes = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            validate_and_encode_object_store_reserve_put_ack(&value, &invalid),
            Err(ReservePutAckError::InvalidLimits)
        );
    }
}

#[test]
fn diagnostics_and_source_contract_redact_and_remain_effect_free() {
    let canonical = encode(&reserved()).expect("baseline ACK");
    let diagnostic = format!("{canonical:?}");
    assert!(!diagnostic.contains("tenant-1"));
    assert!(!diagnostic.contains("object-store-reserve-put-ack-v1"));
    assert!(!diagnostic.contains("49, 49, 49, 49"));
    assert!(diagnostic.contains("[REDACTED]"));

    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let service = std::fs::read_to_string(manifest.join("src/service.rs"))
        .expect("source-dark service source");
    let source = std::fs::read_to_string(manifest.join("src/reserve_put_ack.rs"))
        .expect("ReservePut ACK source");
    assert!(!service.contains("validate_and_encode_object_store_reserve_put_ack"));
    for forbidden in [
        "tokio_postgres",
        "std::fs",
        "aws_sdk",
        "lore_aws",
        "lore_postgres",
    ] {
        assert!(!source.contains(forbidden), "effect surface {forbidden}");
    }
}
