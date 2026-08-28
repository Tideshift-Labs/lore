// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::ContinuityWireLimits;
use lore_object_dispatch::TerminalResultLimits;
use lore_object_dispatch::validate_and_encode_continuity_adjudicated;
use lore_object_dispatch::validate_and_encode_continuity_quarantined;
use lore_object_dispatch::validate_and_encode_object_store_request_outcome;
use lore_object_dispatch::validate_and_encode_object_store_request_receipt;
use lore_object_dispatch::validate_and_encode_object_store_request_state;
use lore_object_dispatch::validate_and_encode_terminal_result;
use lore_proto::lore::object_dispatch::v1::BoolResultV1;
use lore_proto::lore::object_dispatch::v1::ByteResultHandleV1;
use lore_proto::lore::object_dispatch::v1::DeleteObjectResultV1;
use lore_proto::lore::object_dispatch::v1::HeadObjectResultV1;
use lore_proto::lore::object_dispatch::v1::ListObjectVersionsResultV1;
use lore_proto::lore::object_dispatch::v1::ListObjectsV2ResultV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicatedV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicationKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicationProofV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityIntentKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuarantineReasonV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuarantinedV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuotaOwnershipV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuotaReleaseReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreDispatchAttemptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreNoDispatchProofV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreNoDispatchReasonV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadAvailabilityV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadReleaseReasonV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadRetentionV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestOutcomeV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestPhaseV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDispositionV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalResultV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalRetryabilityV1;
use lore_proto::lore::object_dispatch::v1::ProviderErrorClassV1;
use lore_proto::lore::object_dispatch::v1::ProviderErrorV1;
use lore_proto::lore::object_dispatch::v1::PutObjectResultV1;
use lore_proto::lore::object_dispatch::v1::PutSubmitBindingV1;
use lore_proto::lore::object_dispatch::v1::ReservedDimensionV1;
use lore_proto::lore::object_dispatch::v1::object_store_continuity_adjudicated_v1;
use lore_proto::lore::object_dispatch::v1::object_store_continuity_quarantined_v1;
use lore_proto::lore::object_dispatch::v1::object_store_request_outcome_v1;
use lore_proto::lore::object_dispatch::v1::object_store_request_receipt_v1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1::Result as TerminalPayload;
use prost::Message;

const NOW: i64 = 0x018f_3e12_a456;
const REQUEST_ID: &str = "018f3e12-a450-7abc-8def-0123456789ab";
const ATTEMPT_ID: &str = "018f3e12-a451-7abc-8def-0123456789ab";
const DIGEST: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const OTHER_DIGEST: [u8; 32] = [
    255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240, 239, 238, 237,
    236, 235, 234, 233, 232, 231, 230, 229, 228, 227, 226, 225, 224,
];
const BOOL_DIGEST: [u8; 32] = [
    0x16, 0x16, 0x2b, 0x78, 0xc2, 0x03, 0x57, 0xb8, 0xff, 0x6a, 0xd0, 0x78, 0x59, 0x2d, 0xa2, 0xed,
    0x41, 0x94, 0xef, 0xa3, 0xf3, 0x8a, 0x3f, 0x9e, 0x22, 0x3d, 0x86, 0x02, 0xf1, 0xa5, 0x37, 0x20,
];

fn limits() -> ContinuityWireLimits {
    ContinuityWireLimits {
        max_identity_bytes: 256,
        max_canonical_row_bytes: 16_384,
    }
}

fn terminal_limits() -> TerminalResultLimits {
    TerminalResultLimits {
        max_canonical_result_bytes: 16_384,
        max_list_entries: 16_384,
        max_key_bytes: 256,
        max_metadata_entries: 16_384,
        max_metadata_key_bytes: 256,
        max_metadata_value_bytes: 256,
        max_metadata_aggregate_bytes: 16_384,
        max_opaque_value_bytes: 256,
        max_result_handle_bytes: 256,
        max_provider_code_bytes: 256,
        max_provider_request_id_bytes: 256,
        max_retry_after_ms: u64::MAX,
    }
}

fn append_text(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn variable(value: &[u8]) -> Vec<u8> {
    let mut output = (value.len() as u32).to_be_bytes().to_vec();
    output.extend_from_slice(value);
    output
}

fn optional(value: Option<Vec<u8>>) -> Vec<u8> {
    match value {
        Some(value) => {
            let mut output = vec![1];
            output.extend(value);
            output
        }
        None => vec![0],
    }
}

fn complete_record(domain: &str, fields: &[u8]) -> Vec<u8> {
    let mut preimage = domain.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend_from_slice(fields);
    let mut complete = preimage.clone();
    complete.extend_from_slice(blake3::hash(&preimage).as_bytes());
    complete
}

fn reservation() -> ReservedDimensionV1 {
    ReservedDimensionV1 {
        reservation_id: "reservation-1".to_string(),
        physical_dimension_id: "physical-1".to_string(),
        operation_class_id: "PUT".to_string(),
        units: 3,
    }
}

fn reservation_record(value: &ReservedDimensionV1) -> Vec<u8> {
    let mut fields = Vec::new();
    append_text(&mut fields, &value.reservation_id);
    append_text(&mut fields, &value.physical_dimension_id);
    append_text(&mut fields, &value.operation_class_id);
    fields.extend_from_slice(&value.units.to_be_bytes());
    complete_record("object-store-reserved-dimension-v1", &fields)
}

fn reservations_bytes(values: &[ReservedDimensionV1]) -> Vec<u8> {
    let mut output = (values.len() as u32).to_be_bytes().to_vec();
    for value in values {
        output.extend(variable(&reservation_record(value)));
    }
    output
}

fn quota(bytes: u64, rows: u64, concurrency: u64) -> ObjectStoreQuotaUnitsV1 {
    ObjectStoreQuotaUnitsV1 {
        bytes,
        rows,
        concurrency,
    }
}

fn quota_record(value: &ObjectStoreQuotaUnitsV1) -> Vec<u8> {
    let mut fields = Vec::new();
    fields.extend_from_slice(&value.bytes.to_be_bytes());
    fields.extend_from_slice(&value.rows.to_be_bytes());
    fields.extend_from_slice(&value.concurrency.to_be_bytes());
    complete_record("object-store-quota-units-v1", &fields)
}

fn quota_state_record(value: &ObjectStoreQuotaStateV1) -> Vec<u8> {
    let mut fields = reservations_bytes(&value.provider_reservations);
    for quota in [
        value.put_spool_quota.as_ref().expect("fixture PUT quota"),
        value
            .result_spool_quota
            .as_ref()
            .expect("fixture result quota"),
        value
            .retained_metadata_quota
            .as_ref()
            .expect("fixture metadata quota"),
    ] {
        fields.extend(variable(&quota_record(quota)));
    }
    fields.extend_from_slice(&value.quota_revision.to_be_bytes());
    complete_record("object-store-quota-state-v1", &fields)
}

fn not_applicable(kind: ObjectStorePayloadKindV1) -> ObjectStorePayloadRetentionV1 {
    ObjectStorePayloadRetentionV1 {
        payload_kind: kind as i32,
        availability: ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityNotApplicable
            as i32,
        durable_handle: None,
        size: 0,
        blake3: Default::default(),
        purge_state: ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateNotEligible as i32,
        purge_eligible_at_unix_ms: None,
        purge_receipt: None,
        partial_temp_bytes: 0,
        partial_temp_chunks: 0,
    }
}

fn pending_put() -> ObjectStorePayloadRetentionV1 {
    ObjectStorePayloadRetentionV1 {
        payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody as i32,
        availability: ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityPendingUpload
            as i32,
        durable_handle: None,
        size: 100,
        blake3: DIGEST.to_vec().into(),
        purge_state: ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateRetentionPending
            as i32,
        purge_eligible_at_unix_ms: Some(NOW + 1_000),
        purge_receipt: None,
        partial_temp_bytes: 10,
        partial_temp_chunks: 1,
    }
}

fn retained_put() -> ObjectStorePayloadRetentionV1 {
    ObjectStorePayloadRetentionV1 {
        payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody as i32,
        availability: ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained
            as i32,
        durable_handle: Some("body-1".to_string()),
        size: 100,
        blake3: DIGEST.to_vec().into(),
        purge_state: ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateRetentionPending
            as i32,
        purge_eligible_at_unix_ms: Some(NOW + 1_000),
        purge_receipt: None,
        partial_temp_bytes: 0,
        partial_temp_chunks: 0,
    }
}

fn disposed_put() -> ObjectStorePayloadRetentionV1 {
    ObjectStorePayloadRetentionV1 {
        payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody as i32,
        availability: ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityDisposed
            as i32,
        durable_handle: None,
        size: 100,
        blake3: DIGEST.to_vec().into(),
        purge_state: ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStatePurged as i32,
        purge_eligible_at_unix_ms: Some(NOW + 1),
        purge_receipt: Some(ObjectStorePayloadPurgeReceiptV1 {
            purge_id: "purge-1".to_string(),
            payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody as i32,
            terminal_result_id: None,
            disposition: ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable
                as i32,
            released_bytes: 100,
            released_rows: 1,
            released_concurrency: 1,
            purged_at_unix_ms: NOW + 2,
            provider_authority_refunded: false,
            receipt_blake3: Default::default(),
            release_reason:
                ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonNoPayloadCreated
                    as i32,
            deleted_partial_temp_bytes: 10,
            deleted_partial_temp_files: 1,
        }),
        partial_temp_bytes: 0,
        partial_temp_chunks: 0,
    }
}

fn purge_receipt_record(value: &ObjectStorePayloadPurgeReceiptV1) -> Vec<u8> {
    let mut fields = Vec::new();
    append_text(&mut fields, &value.purge_id);
    fields.extend_from_slice(&(value.payload_kind as u32).to_be_bytes());
    fields.extend(optional(value.terminal_result_id.as_ref().map(|id| {
        let mut bytes = Vec::new();
        append_text(&mut bytes, id);
        bytes
    })));
    fields.extend_from_slice(&(value.disposition as u32).to_be_bytes());
    fields.extend_from_slice(&value.released_bytes.to_be_bytes());
    fields.extend_from_slice(&value.released_rows.to_be_bytes());
    fields.extend_from_slice(&value.released_concurrency.to_be_bytes());
    fields.extend_from_slice(&(value.purged_at_unix_ms as u64).to_be_bytes());
    fields.push(u8::from(value.provider_authority_refunded));
    fields.extend_from_slice(&(value.release_reason as u32).to_be_bytes());
    fields.extend_from_slice(&value.deleted_partial_temp_bytes.to_be_bytes());
    fields.extend_from_slice(&value.deleted_partial_temp_files.to_be_bytes());
    complete_record("object-store-payload-purge-receipt-v1", &fields)
}

fn retention_record(value: &ObjectStorePayloadRetentionV1) -> Vec<u8> {
    let mut fields = Vec::new();
    fields.extend_from_slice(&(value.payload_kind as u32).to_be_bytes());
    fields.extend_from_slice(&(value.availability as u32).to_be_bytes());
    fields.extend(optional(value.durable_handle.as_ref().map(|handle| {
        let mut bytes = Vec::new();
        append_text(&mut bytes, handle);
        bytes
    })));
    fields.extend_from_slice(&value.size.to_be_bytes());
    fields.extend(variable(&value.blake3));
    fields.extend_from_slice(&(value.purge_state as u32).to_be_bytes());
    fields.extend(optional(
        value
            .purge_eligible_at_unix_ms
            .map(|time| (time as u64).to_be_bytes().to_vec()),
    ));
    fields.extend(optional(
        value
            .purge_receipt
            .as_ref()
            .map(|receipt| variable(&purge_receipt_record(receipt))),
    ));
    fields.extend_from_slice(&value.partial_temp_bytes.to_be_bytes());
    fields.extend_from_slice(&value.partial_temp_chunks.to_be_bytes());
    complete_record("object-store-payload-retention-v1", &fields)
}

fn dispatch_attempt(ambiguous: bool) -> ObjectStoreDispatchAttemptV1 {
    ObjectStoreDispatchAttemptV1 {
        provider_attempt_id: "provider-attempt-1".to_string(),
        provider_grant_id: "provider-grant-1".to_string(),
        provider_grant_fence: 2,
        dispatcher_id: "dispatcher-1".to_string(),
        dispatcher_lease_generation: 3,
        dispatch_started_at_unix_ms: NOW,
        ambiguity_recorded_at_unix_ms: ambiguous.then_some(NOW + 1),
        provider_credential_revision: "credential-1".to_string(),
    }
}

fn dispatch_record(value: &ObjectStoreDispatchAttemptV1) -> Vec<u8> {
    let mut fields = Vec::new();
    append_text(&mut fields, &value.provider_attempt_id);
    append_text(&mut fields, &value.provider_grant_id);
    fields.extend_from_slice(&value.provider_grant_fence.to_be_bytes());
    append_text(&mut fields, &value.dispatcher_id);
    fields.extend_from_slice(&value.dispatcher_lease_generation.to_be_bytes());
    fields.extend_from_slice(&(value.dispatch_started_at_unix_ms as u64).to_be_bytes());
    fields.extend(optional(
        value
            .ambiguity_recorded_at_unix_ms
            .map(|time| (time as u64).to_be_bytes().to_vec()),
    ));
    append_text(&mut fields, &value.provider_credential_revision);
    complete_record("object-store-dispatch-attempt-v1", &fields)
}

fn terminal_result() -> ObjectStoreTerminalResultV1 {
    ObjectStoreTerminalResultV1 {
        terminal_result_id: "terminal-1".to_string(),
        canonical_result_blake3: BOOL_DIGEST.to_vec().into(),
        canonical_result_size: 2,
        result: Some(object_store_terminal_result_v1::Result::BoolResult(
            BoolResultV1 { value: true },
        )),
    }
}

fn byte_terminal_result() -> ObjectStoreTerminalResultV1 {
    let payload = ByteResultHandleV1 {
        handle: "result-1".to_string(),
        size: 5,
        blake3: DIGEST.to_vec().into(),
        content_length: 5,
        metadata: Vec::new(),
        etag: None,
        version_id: None,
    };
    let canonical = payload.encode_to_vec();
    ObjectStoreTerminalResultV1 {
        terminal_result_id: "terminal-byte-1".to_string(),
        canonical_result_blake3: blake3::hash(&canonical).as_bytes().to_vec().into(),
        canonical_result_size: canonical.len() as u64,
        result: Some(object_store_terminal_result_v1::Result::ByteResult(payload)),
    }
}

fn byte_terminal_state() -> ObjectStoreRequestStateV1 {
    let mut value = terminal(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable);
    value.terminal_result = Some(byte_terminal_result());
    value.result_payload = Some(ObjectStorePayloadRetentionV1 {
        payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult as i32,
        availability: ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained
            as i32,
        durable_handle: Some("result-1".to_string()),
        size: 5,
        blake3: DIGEST.to_vec().into(),
        purge_state: ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateEligible as i32,
        purge_eligible_at_unix_ms: Some(NOW + 2),
        purge_receipt: None,
        partial_temp_bytes: 0,
        partial_temp_chunks: 0,
    });
    value
        .quota_state
        .as_mut()
        .expect("fixture quota state")
        .result_spool_quota = Some(quota(5, 1, 0));
    value
}

fn terminal_record(value: &ObjectStoreTerminalResultV1) -> Vec<u8> {
    let mut fields = 1_u32.to_be_bytes().to_vec();
    fields.extend(variable(&[0x08, 0x01]));
    append_text(&mut fields, &value.terminal_result_id);
    fields.extend_from_slice(&BOOL_DIGEST);
    fields.extend_from_slice(&2_u64.to_be_bytes());
    complete_record("object-store-terminal-result-v1", &fields)
}

fn ack_receipt() -> ObjectStoreResultAckReceiptV1 {
    ObjectStoreResultAckReceiptV1 {
        state: ObjectStoreResultAckStateV1::ObjectStoreResultAckStateAcked as i32,
        terminal_result_id: "terminal-1".to_string(),
        ack_fingerprint: DIGEST.to_vec().into(),
        acked_at_unix_ms: NOW + 1,
        payload_purge_after_unix_ms: Some(NOW + 2),
    }
}

fn discard_receipt() -> ObjectStoreResultDiscardReceiptV1 {
    ObjectStoreResultDiscardReceiptV1 {
        state: ObjectStoreResultDiscardStateV1::ObjectStoreResultDiscardStateDiscarded as i32,
        terminal_result_id: "terminal-1".to_string(),
        discard_fingerprint: OTHER_DIGEST.to_vec().into(),
        discarded_at_unix_ms: NOW + 1,
        payload_purge_after_unix_ms: Some(NOW + 2),
    }
}

fn result_receipt_record(discard: bool) -> Vec<u8> {
    let mut fields = 1_u32.to_be_bytes().to_vec();
    append_text(&mut fields, "terminal-1");
    fields.extend_from_slice(if discard { &OTHER_DIGEST } else { &DIGEST });
    fields.extend_from_slice(&((NOW + 1) as u64).to_be_bytes());
    fields.extend(optional(Some(((NOW + 2) as u64).to_be_bytes().to_vec())));
    complete_record(
        if discard {
            "object-store-result-discard-receipt-v1"
        } else {
            "object-store-result-ack-receipt-v1"
        },
        &fields,
    )
}

fn uuid_v7(timestamp: i64) -> String {
    let timestamp = format!("{timestamp:012x}");
    format!(
        "{}-{}-7abc-8def-0123456789ab",
        &timestamp[..8],
        &timestamp[8..]
    )
}

fn no_dispatch(reason: ObjectStoreNoDispatchReasonV1) -> ObjectStoreNoDispatchProofV1 {
    let mut fields = (reason as u32).to_be_bytes().to_vec();
    let id = uuid_v7(NOW);
    append_text(&mut fields, &id);
    fields.extend_from_slice(&4_u64.to_be_bytes());
    fields.extend_from_slice(&(NOW as u64).to_be_bytes());
    fields.extend_from_slice(&5_u64.to_be_bytes());
    let complete = complete_record("object-store-no-dispatch-proof-v1", &fields);
    ObjectStoreNoDispatchProofV1 {
        reason: reason as i32,
        proof_id: id,
        proof_fence: 4,
        committed_at_unix_ms: NOW,
        authority_epoch: 5,
        proof_blake3: complete[complete.len() - 32..].to_vec().into(),
    }
}

fn no_dispatch_record(value: &ObjectStoreNoDispatchProofV1) -> Vec<u8> {
    let mut fields = (value.reason as u32).to_be_bytes().to_vec();
    append_text(&mut fields, &value.proof_id);
    fields.extend_from_slice(&value.proof_fence.to_be_bytes());
    fields.extend_from_slice(&(value.committed_at_unix_ms as u64).to_be_bytes());
    fields.extend_from_slice(&value.authority_epoch.to_be_bytes());
    complete_record("object-store-no-dispatch-proof-v1", &fields)
}

fn binding() -> PutSubmitBindingV1 {
    PutSubmitBindingV1 {
        upload_id: "upload-1".to_string(),
        upload_fence: 2,
        durable_body_handle: "body-1".to_string(),
        reservation_expires_at_unix_ms: NOW + 1_000,
        bound_at_unix_ms: NOW,
        binding_fence: 3,
        binding_blake3: Default::default(),
    }
}

fn binding_record(value: &PutSubmitBindingV1) -> Vec<u8> {
    let mut fields = Vec::new();
    append_text(&mut fields, &value.upload_id);
    fields.extend_from_slice(&value.upload_fence.to_be_bytes());
    append_text(&mut fields, &value.durable_body_handle);
    fields.extend_from_slice(&(value.reservation_expires_at_unix_ms as u64).to_be_bytes());
    fields.extend_from_slice(&(value.bound_at_unix_ms as u64).to_be_bytes());
    fields.extend_from_slice(&value.binding_fence.to_be_bytes());
    complete_record("object-store-put-submit-binding-v1", &fields)
}

fn prepared() -> ObjectStoreRequestStateV1 {
    ObjectStoreRequestStateV1 {
        protocol_revision: "object-dispatch-v1".to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        logical_request_id: REQUEST_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        put_reservation_fingerprint: Some(DIGEST.to_vec().into()),
        canonical_descriptor_fingerprint: None,
        phase: ObjectStoreRequestPhaseV1::ObjectStoreRequestPhasePrepared as i32,
        allocation_revision: "allocation-1".to_string(),
        allocation_fence: 2,
        cell_admission_id: None,
        cell_admission_fence: None,
        reservations: Vec::new(),
        dispatch_attempt: None,
        terminal_result: None,
        terminal_retryability:
            ObjectStoreTerminalRetryabilityV1::ObjectStoreTerminalRetryabilityNotApplicable as i32,
        result_disposition:
            ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable as i32,
        ack_receipt: None,
        discard_receipt: None,
        no_dispatch_proof: None,
        put_body: Some(pending_put()),
        result_payload: Some(not_applicable(
            ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
        )),
        quota_state: Some(ObjectStoreQuotaStateV1 {
            provider_reservations: Vec::new(),
            put_spool_quota: Some(quota(100, 1, 1)),
            result_spool_quota: Some(quota(0, 0, 0)),
            retained_metadata_quota: Some(quota(0, 0, 0)),
            quota_revision: 1,
        }),
        state_committed_at_unix_ms: NOW,
        closure_committed_at_unix_ms: None,
        state_blake3: Default::default(),
        policy_revision: "policy-1".to_string(),
        put_submit_binding: None,
    }
}

fn admitted() -> ObjectStoreRequestStateV1 {
    let mut value = prepared();
    value.canonical_descriptor_fingerprint = Some(OTHER_DIGEST.to_vec().into());
    value.phase = ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseAdmitted as i32;
    value.cell_admission_id = Some("admission-1".to_string());
    value.cell_admission_fence = Some(2);
    value.reservations = vec![reservation()];
    value.put_body = Some(retained_put());
    value.quota_state = Some(ObjectStoreQuotaStateV1 {
        provider_reservations: vec![reservation()],
        put_spool_quota: Some(quota(100, 1, 1)),
        result_spool_quota: Some(quota(0, 0, 0)),
        retained_metadata_quota: Some(quota(10, 1, 0)),
        quota_revision: 2,
    });
    value.put_submit_binding = Some(binding());
    value
}

fn terminal(disposition: ObjectStoreResultDispositionV1) -> ObjectStoreRequestStateV1 {
    let mut value = prepared();
    value.put_reservation_fingerprint = None;
    value.canonical_descriptor_fingerprint = Some(OTHER_DIGEST.to_vec().into());
    value.phase = ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseTerminal as i32;
    value.cell_admission_id = Some("admission-1".to_string());
    value.cell_admission_fence = Some(2);
    value.reservations = vec![reservation()];
    value.dispatch_attempt = Some(dispatch_attempt(false));
    value.terminal_result = Some(terminal_result());
    value.terminal_retryability =
        ObjectStoreTerminalRetryabilityV1::ObjectStoreTerminalRetryabilityNonRetryable as i32;
    value.result_disposition = disposition as i32;
    value.ack_receipt = (disposition
        == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked)
        .then(ack_receipt);
    value.discard_receipt = (disposition
        == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded)
        .then(discard_receipt);
    value.put_body = Some(not_applicable(
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
    ));
    value.quota_state = Some(ObjectStoreQuotaStateV1 {
        provider_reservations: vec![reservation()],
        put_spool_quota: Some(quota(0, 0, 0)),
        result_spool_quota: Some(quota(0, 0, 0)),
        retained_metadata_quota: Some(quota(10, 1, 0)),
        quota_revision: 3,
    });
    if disposition != ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable {
        value.closure_committed_at_unix_ms = Some(NOW + 3);
    }
    value
}

fn phase_fixtures() -> Vec<ObjectStoreRequestStateV1> {
    let mut dispatching = admitted();
    dispatching.phase = ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseDispatching as i32;
    dispatching.dispatch_attempt = Some(dispatch_attempt(false));
    let mut ambiguous = admitted();
    ambiguous.phase = ObjectStoreRequestPhaseV1::ObjectStoreRequestPhasePossiblyDispatched as i32;
    ambiguous.dispatch_attempt = Some(dispatch_attempt(true));
    let mut no_dispatch_state = prepared();
    no_dispatch_state.put_reservation_fingerprint = None;
    no_dispatch_state.canonical_descriptor_fingerprint = Some(OTHER_DIGEST.to_vec().into());
    no_dispatch_state.phase = ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseNoDispatch as i32;
    no_dispatch_state.no_dispatch_proof = Some(no_dispatch(
        ObjectStoreNoDispatchReasonV1::ObjectStoreNoDispatchReasonCellAdmissionRejected,
    ));
    no_dispatch_state.put_body = Some(not_applicable(
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
    ));
    no_dispatch_state
        .quota_state
        .as_mut()
        .expect("fixture quota")
        .put_spool_quota = Some(quota(0, 0, 0));
    no_dispatch_state.closure_committed_at_unix_ms = Some(NOW + 1);
    let mut expired = prepared();
    expired.phase = ObjectStoreRequestPhaseV1::ObjectStoreRequestPhasePreparedExpired as i32;
    expired.no_dispatch_proof = Some(no_dispatch(
        ObjectStoreNoDispatchReasonV1::ObjectStoreNoDispatchReasonPreparedTtlExpired,
    ));
    expired.put_body = Some(disposed_put());
    expired
        .quota_state
        .as_mut()
        .expect("fixture quota")
        .put_spool_quota = Some(quota(0, 0, 0));
    expired.closure_committed_at_unix_ms = Some(NOW + 3);
    vec![
        prepared(),
        admitted(),
        dispatching,
        ambiguous,
        terminal(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable),
        no_dispatch_state,
        expired,
    ]
}

fn state_preimage(input: &ObjectStoreRequestStateV1) -> Vec<u8> {
    let mut fields = Vec::new();
    for text in [
        &input.protocol_revision,
        &input.provider_boundary_id,
        &input.authenticated_cell_id,
        &input.authenticated_tenant_id,
        &input.logical_request_id,
        &input.attempt_id,
    ] {
        append_text(&mut fields, text);
    }
    fields.extend(optional(
        input
            .put_reservation_fingerprint
            .as_ref()
            .map(|v| v.to_vec()),
    ));
    fields.extend(optional(
        input
            .canonical_descriptor_fingerprint
            .as_ref()
            .map(|v| v.to_vec()),
    ));
    fields.extend_from_slice(&(input.phase as u32).to_be_bytes());
    append_text(&mut fields, &input.allocation_revision);
    fields.extend_from_slice(&input.allocation_fence.to_be_bytes());
    fields.extend(optional(input.cell_admission_id.as_ref().map(|value| {
        let mut output = Vec::new();
        append_text(&mut output, value);
        output
    })));
    fields.extend(optional(
        input
            .cell_admission_fence
            .map(|value| value.to_be_bytes().to_vec()),
    ));
    fields.extend(reservations_bytes(&input.reservations));
    fields.extend(optional(
        input
            .dispatch_attempt
            .as_ref()
            .map(|value| variable(&dispatch_record(value))),
    ));
    fields.extend(optional(
        input
            .terminal_result
            .as_ref()
            .map(|value| variable(&terminal_record(value))),
    ));
    fields.extend_from_slice(&(input.terminal_retryability as u32).to_be_bytes());
    fields.extend_from_slice(&(input.result_disposition as u32).to_be_bytes());
    fields.extend(optional(
        input
            .ack_receipt
            .as_ref()
            .map(|_| variable(&result_receipt_record(false))),
    ));
    fields.extend(optional(
        input
            .discard_receipt
            .as_ref()
            .map(|_| variable(&result_receipt_record(true))),
    ));
    fields.extend(optional(
        input
            .no_dispatch_proof
            .as_ref()
            .map(|value| variable(&no_dispatch_record(value))),
    ));
    fields.extend(variable(&retention_record(
        input.put_body.as_ref().expect("fixture PUT retention"),
    )));
    fields.extend(variable(&retention_record(
        input
            .result_payload
            .as_ref()
            .expect("fixture result retention"),
    )));
    fields.extend(variable(&quota_state_record(
        input.quota_state.as_ref().expect("fixture quota state"),
    )));
    fields.extend_from_slice(&(input.state_committed_at_unix_ms as u64).to_be_bytes());
    fields.extend(optional(
        input
            .closure_committed_at_unix_ms
            .map(|value| (value as u64).to_be_bytes().to_vec()),
    ));
    append_text(&mut fields, &input.policy_revision);
    fields.extend(optional(
        input
            .put_submit_binding
            .as_ref()
            .map(|value| variable(&binding_record(value))),
    ));
    let mut preimage = b"object-store-request-state-v1\0".to_vec();
    preimage.extend(fields);
    preimage
}

fn decode_digest(value: &str) -> [u8; 32] {
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex is UTF-8"), 16)
                .expect("hex digit pair is valid")
        })
        .collect::<Vec<_>>();
    bytes.try_into().expect("fixture digest is 32 bytes")
}

fn continuity_ownership() -> ObjectStoreContinuityQuotaOwnershipV1 {
    ObjectStoreContinuityQuotaOwnershipV1 {
        continuity_policy_revision: "continuity-policy-1".to_string(),
        operation_quota_class: "PUT".to_string(),
        units: Some(quota(125, 4, 1)),
        global_scope_id: "object-store-continuity-global-v1".to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        ownership_blake3: Default::default(),
    }
}

fn quarantined() -> ObjectStoreContinuityQuarantinedV1 {
    ObjectStoreContinuityQuarantinedV1 {
        protocol_revision: "object-dispatch-v1".to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        logical_request_id: REQUEST_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        continuity_token_id: "018f3e12-a452-7abc-8def-0123456789ab".to_string(),
        authority_epoch: 7,
        continuity_seq: 11,
        intent_kind: ObjectStoreContinuityIntentKindV1::ObjectStoreContinuityIntentKindUuidAdmission
            as i32,
        reason: ObjectStoreContinuityQuarantineReasonV1::ObjectStoreContinuityQuarantineReasonIncompleteIntent
            as i32,
        quarantined_at_unix_ms: NOW,
        retain_until_unix_ms: NOW + 1_000,
        quota_bearing: true,
        detail_blake3: Default::default(),
        quota_ownership: Some(continuity_ownership()),
        fingerprint: Some(
            object_store_continuity_quarantined_v1::Fingerprint::PutReservationFingerprint(
                DIGEST.to_vec().into(),
            ),
        ),
    }
}

fn adjudicated() -> ObjectStoreContinuityAdjudicatedV1 {
    let kind =
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect;
    ObjectStoreContinuityAdjudicatedV1 {
        protocol_revision: "object-dispatch-v1".to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        logical_request_id: REQUEST_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        continuity_token_id: "018f3e12-a452-7abc-8def-0123456789ab".to_string(),
        authority_epoch: 7,
        continuity_seq: 11,
        intent_kind: ObjectStoreContinuityIntentKindV1::ObjectStoreContinuityIntentKindUuidAdmission
            as i32,
        adjudication_kind: kind as i32,
        proof: Some(ObjectStoreContinuityAdjudicationProofV1 {
            proof_id: "018f3e12-a453-7abc-8def-0123456789ab".to_string(),
            adjudication_kind: kind as i32,
            external_row_blake3: DIGEST.to_vec().into(),
            local_quarantine_blake3: OTHER_DIGEST.to_vec().into(),
            authority_epoch: 7,
            continuity_seq: 11,
            adjudication_fence: 3,
            provider_credential_revision: "credential-9".to_string(),
            provider_no_dispatch_evidence_blake3: None,
            committed_at_unix_ms: NOW + 1,
            proof_blake3: Default::default(),
        }),
        quota_release_receipt: Some(ObjectStoreContinuityQuotaReleaseReceiptV1 {
            release_id: "018f3e12-a454-7abc-8def-0123456789ab".to_string(),
            adjudication_kind: kind as i32,
            released_put_spool: Some(quota(100, 1, 1)),
            released_result_spool: Some(quota(20, 1, 0)),
            released_retained_metadata: Some(quota(5, 2, 0)),
            provider_authority_refunded: false,
            released_at_unix_ms: NOW + 2,
            quota_revision: 8,
            receipt_blake3: Default::default(),
        }),
        adjudicated_at_unix_ms: NOW + 3,
        retain_until_unix_ms: NOW + 1_000,
        detail_blake3: Default::default(),
        quota_ownership: Some(continuity_ownership()),
        fingerprint: Some(
            object_store_continuity_adjudicated_v1::Fingerprint::PutReservationFingerprint(
                DIGEST.to_vec().into(),
            ),
        ),
    }
}

#[test]
fn all_seven_request_phases_match_independently_assembled_canonical_records() {
    let vectors = [
        (
            909,
            "a86e356a23530c5523fa82fbe9a624c228207c850d565627d337b21ee7253d09",
        ),
        (
            1_333,
            "04eaea21a9b5fe7385c93063d5a85d28651ab0f52144461db3d714fe0b7d8925",
        ),
        (
            1_501,
            "926a4f7955f5324aad4b4a688f62db4050d07f4fe5ef9f019bbd1658e8e62c9b",
        ),
        (
            1_509,
            "88d3471b67de4ca3c21a9085175b4568fe63f9bf609b1b0fcba2cfd300f1478a",
        ),
        (
            1_426,
            "4cced26c2dd71b48286980a265a5b5da0f6a921b6349e81a35842124708356a4",
        ),
        (
            1_015,
            "de81bf7f003e5097b284ea1bec6168829eb8a9dc88182d5aca75711d77ef18a2",
        ),
        (
            1_202,
            "75405a5ce19b806f5f73ebfe9c41a48186c5eaa54834694001a46862a049c94f",
        ),
    ];
    for (input, (expected_length, expected_digest)) in phase_fixtures().into_iter().zip(vectors) {
        let expected_preimage = state_preimage(&input);
        let encoded = validate_and_encode_object_store_request_state(&input, &limits())
            .expect("reference phase must validate");
        assert_eq!(encoded.canonical_preimage(), expected_preimage);
        assert_eq!(encoded.canonical_bytes().len(), expected_length);
        assert_eq!(encoded.state_blake3(), &decode_digest(expected_digest));
        assert_eq!(
            encoded.state_blake3(),
            blake3::hash(&expected_preimage).as_bytes()
        );
        let mut expected = expected_preimage;
        expected.extend_from_slice(encoded.state_blake3());
        assert_eq!(encoded.canonical_bytes(), expected);
    }
}

#[test]
fn terminal_children_pin_all_eight_envelope_tags() {
    let payloads = [
        TerminalPayload::BoolResult(BoolResultV1 { value: false }),
        TerminalPayload::HeadObject(HeadObjectResultV1::default()),
        TerminalPayload::PutObject(PutObjectResultV1::default()),
        TerminalPayload::DeleteObject(DeleteObjectResultV1::default()),
        TerminalPayload::ListObjectsV2(ListObjectsV2ResultV1::default()),
        TerminalPayload::ListObjectVersions(ListObjectVersionsResultV1::default()),
        TerminalPayload::ByteResult(ByteResultHandleV1 {
            handle: "result-1".to_string(),
            size: 5,
            blake3: DIGEST.to_vec().into(),
            content_length: 5,
            metadata: Vec::new(),
            etag: None,
            version_id: None,
        }),
        TerminalPayload::ProviderError(ProviderErrorV1 {
            error_class: ProviderErrorClassV1::ProviderErrorClassPermanent as i32,
            http_status: 418,
            provider_code: None,
            provider_request_id: None,
            retry_after_ms: None,
            provider_message_blake3: DIGEST.to_vec().into(),
        }),
    ];
    let domain = b"object-store-terminal-result-v1\0";

    for (index, payload) in payloads.into_iter().enumerate() {
        let canonical = validate_and_encode_terminal_result(
            &ObjectStoreTerminalResultV1 {
                terminal_result_id: format!("terminal-{}", index + 1),
                canonical_result_blake3: Default::default(),
                canonical_result_size: 0,
                result: Some(payload),
            },
            &terminal_limits(),
        )
        .expect("terminal payload fixture must validate");
        let mut state =
            terminal(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable);
        state.terminal_result = Some(canonical.result().clone());
        if let Some(TerminalPayload::ByteResult(byte)) = canonical.result().result.as_ref() {
            state.result_payload = Some(ObjectStorePayloadRetentionV1 {
                payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult as i32,
                availability:
                    ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained as i32,
                durable_handle: Some(byte.handle.clone()),
                size: byte.size,
                blake3: byte.blake3.clone(),
                purge_state: ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateEligible
                    as i32,
                purge_eligible_at_unix_ms: Some(NOW + 2),
                purge_receipt: None,
                partial_temp_bytes: 0,
                partial_temp_chunks: 0,
            });
            state
                .quota_state
                .as_mut()
                .expect("fixture quota state")
                .result_spool_quota = Some(quota(byte.size, 1, 0));
        }
        let encoded = validate_and_encode_object_store_request_state(&state, &limits())
            .expect("terminal state fixture must validate");
        let domain_start = encoded
            .canonical_bytes()
            .windows(domain.len())
            .position(|window| window == domain)
            .expect("terminal child domain must be present");
        let tag_start = domain_start + domain.len();
        assert_eq!(
            &encoded.canonical_bytes()[tag_start..tag_start + 4],
            &((index + 1) as u32).to_be_bytes()
        );
    }
}

#[test]
fn prepared_pins_cross_language_literal_length_digest_and_replay() {
    let first = validate_and_encode_object_store_request_state(&prepared(), &limits())
        .expect("PREPARED fixture must validate");
    let second = validate_and_encode_object_store_request_state(&prepared(), &limits())
        .expect("exact replay must validate");
    assert_eq!(first.canonical_bytes().len(), 909);
    assert_eq!(
        first.state_blake3(),
        &decode_digest("a86e356a23530c5523fa82fbe9a624c228207c850d565627d337b21ee7253d09")
    );
    assert_eq!(first.value(), second.value());
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
}

#[test]
fn reservations_are_permutation_stable_and_dimension_class_pairs_are_unique() {
    let second = ReservedDimensionV1 {
        reservation_id: "reservation-2".to_string(),
        physical_dimension_id: "physical-2".to_string(),
        operation_class_id: "PUT".to_string(),
        units: 4,
    };
    let mut forward = admitted();
    forward.reservations = vec![reservation(), second.clone()];
    forward
        .quota_state
        .as_mut()
        .expect("fixture quota")
        .provider_reservations = forward.reservations.clone();
    let mut reverse = forward.clone();
    reverse.reservations.reverse();
    reverse
        .quota_state
        .as_mut()
        .expect("fixture quota")
        .provider_reservations
        .reverse();
    let canonical = validate_and_encode_object_store_request_state(&forward, &limits())
        .expect("forward reservation order must validate");
    let permuted = validate_and_encode_object_store_request_state(&reverse, &limits())
        .expect("reverse reservation order must validate");
    assert_eq!(canonical.canonical_bytes(), permuted.canonical_bytes());
    assert_eq!(
        permuted.value().reservations[0].reservation_id,
        "reservation-1"
    );

    let mut duplicate_pair = forward;
    duplicate_pair.reservations[1].physical_dimension_id = "physical-1".to_string();
    duplicate_pair
        .quota_state
        .as_mut()
        .expect("fixture quota")
        .provider_reservations = duplicate_pair.reservations.clone();
    assert!(validate_and_encode_object_store_request_state(&duplicate_pair, &limits()).is_err());
}

#[test]
fn state_rejects_phase_authority_presence_and_closed_enum_drift() {
    let mut cases = Vec::new();
    let mut missing_prepared_fingerprint = prepared();
    missing_prepared_fingerprint.put_reservation_fingerprint = None;
    cases.push(missing_prepared_fingerprint);
    let mut admitted_without_binding = admitted();
    admitted_without_binding.put_submit_binding = None;
    cases.push(admitted_without_binding);
    let mut dispatching_without_attempt = admitted();
    dispatching_without_attempt.phase =
        ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseDispatching as i32;
    cases.push(dispatching_without_attempt);
    let mut possibly_without_ambiguity = admitted();
    possibly_without_ambiguity.phase =
        ObjectStoreRequestPhaseV1::ObjectStoreRequestPhasePossiblyDispatched as i32;
    possibly_without_ambiguity.dispatch_attempt = Some(dispatch_attempt(false));
    cases.push(possibly_without_ambiguity);
    let mut terminal_without_result =
        terminal(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable);
    terminal_without_result.terminal_result = None;
    cases.push(terminal_without_result);
    let mut future_phase = prepared();
    future_phase.phase = 99;
    cases.push(future_phase);
    let mut future_availability = prepared();
    future_availability
        .put_body
        .as_mut()
        .expect("fixture PUT")
        .availability = 99;
    cases.push(future_availability);
    let mut future_retryability = prepared();
    future_retryability.terminal_retryability = 99;
    cases.push(future_retryability);
    let mut future_disposition = prepared();
    future_disposition.result_disposition = 99;
    cases.push(future_disposition);
    let mut future_payload_kind = prepared();
    future_payload_kind
        .put_body
        .as_mut()
        .expect("fixture PUT")
        .payload_kind = 99;
    cases.push(future_payload_kind);
    let mut future_purge_state = prepared();
    future_purge_state
        .put_body
        .as_mut()
        .expect("fixture PUT")
        .purge_state = 99;
    cases.push(future_purge_state);
    let mut future_release_reason = phase_fixtures()[6].clone();
    future_release_reason
        .put_body
        .as_mut()
        .expect("fixture PUT")
        .purge_receipt
        .as_mut()
        .expect("fixture purge receipt")
        .release_reason = 99;
    cases.push(future_release_reason);
    let mut future_ack_state =
        terminal(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked);
    future_ack_state
        .ack_receipt
        .as_mut()
        .expect("fixture ACK")
        .state = 99;
    cases.push(future_ack_state);
    let mut future_discard_state =
        terminal(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded);
    future_discard_state
        .discard_receipt
        .as_mut()
        .expect("fixture discard")
        .state = 99;
    cases.push(future_discard_state);
    assert!(cases.into_iter().all(|input| {
        validate_and_encode_object_store_request_state(&input, &limits()).is_err()
    }));
}

#[test]
fn state_rejects_terminal_no_dispatch_payload_binding_and_reservation_inconsistency() {
    let mut acked_without_receipt =
        terminal(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked);
    acked_without_receipt.ack_receipt = None;
    let mut discarded_without_receipt =
        terminal(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded);
    discarded_without_receipt.discard_receipt = None;
    let mut available_with_closure =
        terminal(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable);
    available_with_closure.closure_committed_at_unix_ms = Some(NOW + 1);
    let mut no_dispatch_wrong_reason = phase_fixtures()[5].clone();
    no_dispatch_wrong_reason.no_dispatch_proof = Some(no_dispatch(
        ObjectStoreNoDispatchReasonV1::ObjectStoreNoDispatchReasonPreparedTtlExpired,
    ));
    let mut expired_wrong_reason = phase_fixtures()[6].clone();
    expired_wrong_reason.no_dispatch_proof = Some(no_dispatch(
        ObjectStoreNoDispatchReasonV1::ObjectStoreNoDispatchReasonCellAdmissionRejected,
    ));
    let mut binding_handle_mismatch = admitted();
    binding_handle_mismatch
        .put_body
        .as_mut()
        .expect("fixture PUT retention")
        .durable_handle = Some("wrong-body".to_string());
    let mut provider_reservation_mismatch = admitted();
    provider_reservation_mismatch
        .quota_state
        .as_mut()
        .expect("fixture quota state")
        .provider_reservations
        .clear();
    let mut reservation_units_mismatch = admitted();
    reservation_units_mismatch.reservations[0].units += 1;
    let mut submit_bound_no_dispatch = admitted();
    submit_bound_no_dispatch.phase =
        ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseNoDispatch as i32;
    submit_bound_no_dispatch.no_dispatch_proof = Some(no_dispatch(
        ObjectStoreNoDispatchReasonV1::ObjectStoreNoDispatchReasonCellAdmissionRejected,
    ));
    submit_bound_no_dispatch.closure_committed_at_unix_ms = Some(NOW + 1);
    submit_bound_no_dispatch.put_submit_binding = None;
    let mut binding_with_pending_upload = admitted();
    binding_with_pending_upload.put_body = Some(pending_put());
    let mut disposed_with_live_quota = phase_fixtures()[6].clone();
    disposed_with_live_quota
        .quota_state
        .as_mut()
        .expect("fixture quota state")
        .put_spool_quota = Some(quota(100, 1, 1));
    let mut no_dispatch_timestamp_mismatch = phase_fixtures()[5].clone();
    let mismatch_proof = no_dispatch_timestamp_mismatch
        .no_dispatch_proof
        .as_mut()
        .expect("fixture no-dispatch proof");
    mismatch_proof.proof_id = uuid_v7(NOW + 1);
    let recomputed = no_dispatch_record(mismatch_proof);
    mismatch_proof.proof_blake3 = recomputed[recomputed.len() - 32..].to_vec().into();
    let mut no_dispatch_empty_digest = phase_fixtures()[5].clone();
    no_dispatch_empty_digest
        .no_dispatch_proof
        .as_mut()
        .expect("fixture no-dispatch proof")
        .proof_blake3 = Default::default();
    let mut partial_bytes_without_file = phase_fixtures()[6].clone();
    partial_bytes_without_file
        .put_body
        .as_mut()
        .expect("fixture PUT retention")
        .purge_receipt
        .as_mut()
        .expect("fixture purge receipt")
        .deleted_partial_temp_files = 0;
    let mut partial_bytes_over_size = phase_fixtures()[6].clone();
    partial_bytes_over_size
        .put_body
        .as_mut()
        .expect("fixture PUT retention")
        .purge_receipt
        .as_mut()
        .expect("fixture purge receipt")
        .deleted_partial_temp_bytes = 101;
    let mut purge_before_floor = byte_terminal_state();
    purge_before_floor.result_disposition =
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32;
    purge_before_floor.ack_receipt = Some(ObjectStoreResultAckReceiptV1 {
        state: ObjectStoreResultAckStateV1::ObjectStoreResultAckStateAcked as i32,
        terminal_result_id: "terminal-byte-1".to_string(),
        ack_fingerprint: DIGEST.to_vec().into(),
        acked_at_unix_ms: NOW + 1,
        payload_purge_after_unix_ms: Some(NOW + 4),
    });
    let result_payload = purge_before_floor
        .result_payload
        .as_mut()
        .expect("fixture result retention");
    result_payload.availability =
        ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityDisposed as i32;
    result_payload.purge_state =
        ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStatePurged as i32;
    result_payload.purge_eligible_at_unix_ms = Some(NOW + 2);
    result_payload.purge_receipt = Some(ObjectStorePayloadPurgeReceiptV1 {
        purge_id: "purge-result-1".to_string(),
        payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult as i32,
        terminal_result_id: Some("terminal-byte-1".to_string()),
        disposition: ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32,
        released_bytes: 5,
        released_rows: 1,
        released_concurrency: 0,
        purged_at_unix_ms: NOW + 3,
        provider_authority_refunded: false,
        receipt_blake3: Default::default(),
        release_reason:
            ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonAckedRetentionElapsed
                as i32,
        deleted_partial_temp_bytes: 0,
        deleted_partial_temp_files: 0,
    });
    purge_before_floor
        .quota_state
        .as_mut()
        .expect("fixture quota")
        .result_spool_quota = Some(quota(0, 0, 0));
    purge_before_floor.closure_committed_at_unix_ms = Some(NOW + 5);

    assert!(
        [
            acked_without_receipt,
            discarded_without_receipt,
            available_with_closure,
            no_dispatch_wrong_reason,
            expired_wrong_reason,
            binding_handle_mismatch,
            provider_reservation_mismatch,
            reservation_units_mismatch,
            submit_bound_no_dispatch,
            binding_with_pending_upload,
            disposed_with_live_quota,
            no_dispatch_timestamp_mismatch,
            no_dispatch_empty_digest,
            partial_bytes_without_file,
            partial_bytes_over_size,
            purge_before_floor,
        ]
        .into_iter()
        .all(|input| validate_and_encode_object_store_request_state(&input, &limits()).is_err())
    );
}

#[test]
fn state_rejects_byte_result_retention_binding_and_tampered_digest() {
    let mut stale = validate_and_encode_object_store_request_state(&prepared(), &limits())
        .expect("PREPARED fixture must validate")
        .value()
        .clone();
    stale.policy_revision = "policy-2".to_string();
    assert!(validate_and_encode_object_store_request_state(&stale, &limits()).is_err());

    let mut malformed = prepared();
    malformed.state_blake3 = OTHER_DIGEST.to_vec().into();
    assert!(validate_and_encode_object_store_request_state(&malformed, &limits()).is_err());

    let mut malformed_terminal =
        terminal(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable);
    malformed_terminal
        .terminal_result
        .as_mut()
        .expect("fixture terminal")
        .canonical_result_size = 3;
    assert!(
        validate_and_encode_object_store_request_state(&malformed_terminal, &limits()).is_err()
    );
    let mut semantic_drift =
        terminal(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable);
    semantic_drift
        .terminal_result
        .as_mut()
        .expect("fixture terminal")
        .result = Some(object_store_terminal_result_v1::Result::BoolResult(
        BoolResultV1 { value: false },
    ));
    assert!(validate_and_encode_object_store_request_state(&semantic_drift, &limits()).is_err());

    let valid = byte_terminal_state();
    let mut wrong_handle = valid.clone();
    wrong_handle
        .result_payload
        .as_mut()
        .expect("fixture result retention")
        .durable_handle = Some("result-2".to_string());
    let mut wrong_size = valid.clone();
    wrong_size
        .result_payload
        .as_mut()
        .expect("fixture result retention")
        .size = 6;
    let mut wrong_digest = valid.clone();
    wrong_digest
        .result_payload
        .as_mut()
        .expect("fixture result retention")
        .blake3 = OTHER_DIGEST.to_vec().into();
    let mut wrong_quota = valid.clone();
    wrong_quota
        .quota_state
        .as_mut()
        .expect("fixture quota state")
        .result_spool_quota = Some(quota(6, 1, 0));
    assert!(
        [wrong_handle, wrong_size, wrong_digest, wrong_quota]
            .into_iter()
            .all(
                |input| validate_and_encode_object_store_request_state(&input, &limits()).is_err()
            )
    );
}

#[test]
fn state_bound_is_inclusive_and_validated_value_is_detached() {
    let mut input = prepared();
    let encoded = validate_and_encode_object_store_request_state(&input, &limits())
        .expect("PREPARED fixture must validate");
    let exact = encoded.canonical_bytes().len() as u32;
    assert!(
        validate_and_encode_object_store_request_state(
            &input,
            &ContinuityWireLimits {
                max_identity_bytes: 256,
                max_canonical_row_bytes: exact,
            },
        )
        .is_ok()
    );
    assert!(
        validate_and_encode_object_store_request_state(
            &input,
            &ContinuityWireLimits {
                max_identity_bytes: 256,
                max_canonical_row_bytes: exact - 1,
            },
        )
        .is_err()
    );
    *input
        .put_reservation_fingerprint
        .as_mut()
        .expect("fixture fingerprint") = vec![0; 32].into();
    assert_eq!(
        encoded
            .value()
            .put_reservation_fingerprint
            .as_ref()
            .expect("validated fingerprint")
            .as_ref(),
        DIGEST
    );
}

#[test]
fn request_state_receipt_and_outcome_pin_tag_one_framing_and_literals() {
    let state = validate_and_encode_object_store_request_state(&prepared(), &limits())
        .expect("PREPARED fixture must validate");
    let receipt_input = ObjectStoreRequestReceiptV1 {
        receipt_blake3: Default::default(),
        receipt_committed_at_unix_ms: NOW + 1,
        outcome: Some(object_store_request_receipt_v1::Outcome::RequestState(
            Box::new(state.value().clone()),
        )),
    };
    let outcome_input = ObjectStoreRequestOutcomeV1 {
        outcome_blake3: Default::default(),
        outcome: Some(object_store_request_outcome_v1::Outcome::RequestState(
            Box::new(state.value().clone()),
        )),
    };
    let receipt = validate_and_encode_object_store_request_receipt(&receipt_input, &limits())
        .expect("request-state receipt must validate");
    let outcome = validate_and_encode_object_store_request_outcome(&outcome_input, &limits())
        .expect("request-state outcome must validate");

    let mut receipt_preimage = b"object-store-request-receipt-v1\0".to_vec();
    receipt_preimage.extend_from_slice(&1_u32.to_be_bytes());
    receipt_preimage.extend(variable(state.canonical_bytes()));
    receipt_preimage.extend_from_slice(&((NOW + 1) as u64).to_be_bytes());
    let mut outcome_preimage = b"object-store-request-outcome-v1\0".to_vec();
    outcome_preimage.extend_from_slice(&1_u32.to_be_bytes());
    outcome_preimage.extend(variable(state.canonical_bytes()));

    assert_eq!(receipt.canonical_preimage(), receipt_preimage);
    assert_eq!(receipt.canonical_bytes().len(), 989);
    assert_eq!(
        receipt.receipt_blake3(),
        &decode_digest("e1d431af5e57ded6454133116e0db16f5f33c631e00414192eacd9ea263857c6")
    );
    assert_eq!(outcome.canonical_preimage(), outcome_preimage);
    assert_eq!(outcome.canonical_bytes().len(), 981);
    assert_eq!(
        outcome.outcome_blake3(),
        &decode_digest("6ae4e116ad923d5349f81bc89de9739099811ba379cfff266dc9c9d1c0b585d4")
    );
}

#[test]
fn request_state_wrappers_reject_stale_time_tamper_digest_and_short_bound() {
    let state = validate_and_encode_object_store_request_state(&prepared(), &limits())
        .expect("PREPARED fixture must validate");
    let mut stale_state = state.value().clone();
    stale_state.policy_revision = "policy-2".to_string();
    let receipt = |state, time, digest| ObjectStoreRequestReceiptV1 {
        receipt_blake3: digest,
        receipt_committed_at_unix_ms: time,
        outcome: Some(object_store_request_receipt_v1::Outcome::RequestState(
            Box::new(state),
        )),
    };
    let outcome = |state, digest| ObjectStoreRequestOutcomeV1 {
        outcome_blake3: digest,
        outcome: Some(object_store_request_outcome_v1::Outcome::RequestState(
            Box::new(state),
        )),
    };
    assert!(
        validate_and_encode_object_store_request_receipt(
            &receipt(state.value().clone(), NOW - 1, Default::default()),
            &limits(),
        )
        .is_err()
    );
    assert!(
        validate_and_encode_object_store_request_receipt(
            &receipt(stale_state.clone(), NOW + 1, Default::default()),
            &limits(),
        )
        .is_err()
    );
    assert!(
        validate_and_encode_object_store_request_outcome(
            &outcome(stale_state, Default::default()),
            &limits(),
        )
        .is_err()
    );
    assert!(
        validate_and_encode_object_store_request_receipt(
            &receipt(state.value().clone(), NOW + 1, OTHER_DIGEST.to_vec().into()),
            &limits(),
        )
        .is_err()
    );
    assert!(
        validate_and_encode_object_store_request_outcome(
            &outcome(state.value().clone(), OTHER_DIGEST.to_vec().into()),
            &limits(),
        )
        .is_err()
    );

    let valid = validate_and_encode_object_store_request_outcome(
        &outcome(state.value().clone(), Default::default()),
        &limits(),
    )
    .expect("reference outcome must validate");
    assert!(
        validate_and_encode_object_store_request_outcome(
            &outcome(state.value().clone(), Default::default()),
            &ContinuityWireLimits {
                max_identity_bytes: 256,
                max_canonical_row_bytes: valid.canonical_bytes().len() as u32 - 1,
            },
        )
        .is_err()
    );
}

#[test]
fn request_state_receipt_rejects_time_before_latest_nested_terminal_closure() {
    let state = validate_and_encode_object_store_request_state(
        &terminal(ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked),
        &limits(),
    )
    .expect("ACKED terminal fixture must validate");
    let input = ObjectStoreRequestReceiptV1 {
        receipt_blake3: Default::default(),
        receipt_committed_at_unix_ms: NOW + 2,
        outcome: Some(object_store_request_receipt_v1::Outcome::RequestState(
            Box::new(state.value().clone()),
        )),
    };

    assert!(input.receipt_committed_at_unix_ms >= state.value().state_committed_at_unix_ms);
    assert!(
        input.receipt_committed_at_unix_ms
            < state
                .value()
                .closure_committed_at_unix_ms
                .expect("ACKED terminal fixture is closed")
    );
    assert!(validate_and_encode_object_store_request_receipt(&input, &limits()).is_err());
}

#[test]
fn request_receipt_fences_each_nested_durable_timestamp_source() {
    let rejects = |state: ObjectStoreRequestStateV1, receipt_time: i64| {
        let state = validate_and_encode_object_store_request_state(&state, &limits())
            .expect("nested-time fixture must validate");
        validate_and_encode_object_store_request_receipt(
            &ObjectStoreRequestReceiptV1 {
                receipt_blake3: Default::default(),
                receipt_committed_at_unix_ms: receipt_time,
                outcome: Some(object_store_request_receipt_v1::Outcome::RequestState(
                    Box::new(state.value().clone()),
                )),
            },
            &limits(),
        )
        .is_err()
    };

    let mut dispatching = phase_fixtures()[2].clone();
    dispatching
        .dispatch_attempt
        .as_mut()
        .expect("fixture dispatch")
        .dispatch_started_at_unix_ms = NOW + 2;
    let mut ambiguous = phase_fixtures()[3].clone();
    ambiguous
        .dispatch_attempt
        .as_mut()
        .expect("fixture dispatch")
        .ambiguity_recorded_at_unix_ms = Some(NOW + 2);
    let mut bound = admitted();
    bound
        .put_submit_binding
        .as_mut()
        .expect("fixture binding")
        .bound_at_unix_ms = NOW + 2;
    let mut no_dispatch_state = phase_fixtures()[5].clone();
    let proof = no_dispatch_state
        .no_dispatch_proof
        .as_mut()
        .expect("fixture no-dispatch proof");
    proof.proof_id = uuid_v7(NOW + 2);
    proof.committed_at_unix_ms = NOW + 2;
    let recomputed = no_dispatch_record(proof);
    proof.proof_blake3 = recomputed[recomputed.len() - 32..].to_vec().into();
    let mut purged = phase_fixtures()[6].clone();
    purged
        .put_body
        .as_mut()
        .expect("fixture PUT retention")
        .purge_receipt
        .as_mut()
        .expect("fixture purge receipt")
        .purged_at_unix_ms = NOW + 5;

    assert!(rejects(dispatching, NOW + 1));
    assert!(rejects(ambiguous, NOW + 1));
    assert!(rejects(bound, NOW + 1));
    assert!(rejects(no_dispatch_state, NOW + 1));
    assert!(rejects(purged, NOW + 4));
}

#[test]
fn continuity_wrappers_pin_quarantine_and_adjudicated_tags_lengths_and_digests() {
    let quarantine = validate_and_encode_continuity_quarantined(&quarantined(), &limits())
        .expect("quarantine fixture must validate");
    let adjudicated = validate_and_encode_continuity_adjudicated(&adjudicated(), &limits())
        .expect("adjudication fixture must validate");
    let cases = [
        (
            object_store_request_receipt_v1::Outcome::ContinuityQuarantined(Box::new(
                quarantine.value().clone(),
            )),
            object_store_request_outcome_v1::Outcome::ContinuityQuarantined(Box::new(
                quarantine.value().clone(),
            )),
            4_u32,
            2_u32,
            quarantine.canonical_bytes(),
            612,
            "4246e0482e80cee40ba070ff81161e044fb542de6d9373328503a65a9e9a870e",
            604,
            "3eec007dae1dd4d98742d0df78b7c8185dfb8dcfd0f3636517881d9268670625",
        ),
        (
            object_store_request_receipt_v1::Outcome::ContinuityAdjudicated(Box::new(
                adjudicated.value().clone(),
            )),
            object_store_request_outcome_v1::Outcome::ContinuityAdjudicated(Box::new(
                adjudicated.value().clone(),
            )),
            5_u32,
            4_u32,
            adjudicated.canonical_bytes(),
            1_252,
            "585b0b7e5db15cb8fc07fd12d72cbaefec901b8920fa08af4af9ddc8b5b6ba88",
            1_244,
            "19bc72b59776f93e04dcc92027f91cab66b18531df9092749742a32757584f54",
        ),
    ];

    for (
        receipt_child,
        outcome_child,
        receipt_tag,
        outcome_tag,
        child_bytes,
        receipt_length,
        receipt_digest,
        outcome_length,
        outcome_digest,
    ) in cases
    {
        let receipt_input = ObjectStoreRequestReceiptV1 {
            receipt_blake3: Default::default(),
            receipt_committed_at_unix_ms: NOW + 1_001,
            outcome: Some(receipt_child),
        };
        let outcome_input = ObjectStoreRequestOutcomeV1 {
            outcome_blake3: Default::default(),
            outcome: Some(outcome_child),
        };
        let receipt = validate_and_encode_object_store_request_receipt(&receipt_input, &limits())
            .expect("continuity receipt must validate");
        let outcome = validate_and_encode_object_store_request_outcome(&outcome_input, &limits())
            .expect("continuity outcome must validate");

        let mut receipt_preimage = b"object-store-request-receipt-v1\0".to_vec();
        receipt_preimage.extend_from_slice(&receipt_tag.to_be_bytes());
        receipt_preimage.extend(variable(child_bytes));
        receipt_preimage.extend_from_slice(&((NOW + 1_001) as u64).to_be_bytes());
        let mut outcome_preimage = b"object-store-request-outcome-v1\0".to_vec();
        outcome_preimage.extend_from_slice(&outcome_tag.to_be_bytes());
        outcome_preimage.extend(variable(child_bytes));

        assert_eq!(receipt.canonical_preimage(), receipt_preimage);
        assert_eq!(receipt.canonical_bytes().len(), receipt_length);
        assert_eq!(receipt.receipt_blake3(), &decode_digest(receipt_digest));
        assert_eq!(outcome.canonical_preimage(), outcome_preimage);
        assert_eq!(outcome.canonical_bytes().len(), outcome_length);
        assert_eq!(outcome.outcome_blake3(), &decode_digest(outcome_digest));
    }
}

#[test]
fn continuity_wrappers_reject_stale_child_time_and_tampered_projection() {
    let quarantine = validate_and_encode_continuity_quarantined(&quarantined(), &limits())
        .expect("quarantine fixture must validate");
    let adjudicated = validate_and_encode_continuity_adjudicated(&adjudicated(), &limits())
        .expect("adjudication fixture must validate");

    let stale_quarantine = ObjectStoreRequestReceiptV1 {
        receipt_blake3: Default::default(),
        receipt_committed_at_unix_ms: NOW - 1,
        outcome: Some(
            object_store_request_receipt_v1::Outcome::ContinuityQuarantined(Box::new(
                quarantine.value().clone(),
            )),
        ),
    };
    let stale_adjudicated = ObjectStoreRequestReceiptV1 {
        receipt_blake3: Default::default(),
        receipt_committed_at_unix_ms: NOW + 2,
        outcome: Some(
            object_store_request_receipt_v1::Outcome::ContinuityAdjudicated(Box::new(
                adjudicated.value().clone(),
            )),
        ),
    };
    assert!(
        validate_and_encode_object_store_request_receipt(&stale_quarantine, &limits()).is_err()
    );
    assert!(
        validate_and_encode_object_store_request_receipt(&stale_adjudicated, &limits()).is_err()
    );

    let mut tampered = quarantine.value().clone();
    tampered.protocol_revision = "object-dispatch-v2".to_string();
    let tampered_outcome = ObjectStoreRequestOutcomeV1 {
        outcome_blake3: Default::default(),
        outcome: Some(
            object_store_request_outcome_v1::Outcome::ContinuityQuarantined(Box::new(tampered)),
        ),
    };
    assert!(
        validate_and_encode_object_store_request_outcome(&tampered_outcome, &limits()).is_err()
    );
}
