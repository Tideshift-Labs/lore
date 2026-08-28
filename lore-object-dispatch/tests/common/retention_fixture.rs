// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::*;
use lore_proto::lore::object_dispatch::v1::*;

pub const NOW: i64 = 0x018f_3e12_a456;
pub const REQUEST_ID: &str = "018f3e12-a450-7abc-8def-0123456789ab";
pub const ATTEMPT_ID: &str = "018f3e12-a451-7abc-8def-0123456789ab";

const DIGEST: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const OTHER_DIGEST: [u8; 32] = [
    255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240, 239, 238, 237,
    236, 235, 234, 233, 232, 231, 230, 229, 228, 227, 226, 225, 224,
];

fn compact_limits() -> ObjectStoreCompactReceiptLimits {
    ObjectStoreCompactReceiptLimits {
        max_identity_bytes: 256,
        max_canonical_row_bytes: 16_384,
        max_compact_row_bytes: 16_384,
        max_dependency_floors: 16,
        full_record_retention_ms: 30,
        anti_replay_admission_past_ms: 100,
        anti_replay_admission_future_ms: 20,
        anti_replay_compact_safety_ms: 10,
    }
}

fn wire_limits() -> RequestStateWireLimits {
    RequestStateWireLimits {
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
        max_metadata_value_bytes: 16_384,
        max_metadata_aggregate_bytes: 16_384,
        max_opaque_value_bytes: 16_384,
        max_result_handle_bytes: 256,
        max_provider_code_bytes: 256,
        max_provider_request_id_bytes: 256,
        max_retry_after_ms: 60_000,
    }
}

fn quota(bytes: u64, rows: u64, concurrency: u64) -> ObjectStoreQuotaUnitsV1 {
    ObjectStoreQuotaUnitsV1 {
        bytes,
        rows,
        concurrency,
    }
}

fn reservation() -> ReservedDimensionV1 {
    ReservedDimensionV1 {
        reservation_id: "reservation-1".to_string(),
        physical_dimension_id: "physical-1".to_string(),
        operation_class_id: "GET".to_string(),
        units: 1,
    }
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

fn disposed_get() -> ObjectStorePayloadRetentionV1 {
    ObjectStorePayloadRetentionV1 {
        payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult as i32,
        availability: ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityDisposed
            as i32,
        durable_handle: Some("result-1".to_string()),
        size: 5,
        blake3: DIGEST.to_vec().into(),
        purge_state: ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStatePurged as i32,
        purge_eligible_at_unix_ms: Some(NOW + 10),
        purge_receipt: Some(ObjectStorePayloadPurgeReceiptV1 {
            purge_id: "purge-result-1".to_string(),
            payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult as i32,
            terminal_result_id: Some("terminal-1".to_string()),
            disposition: ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32,
            released_bytes: 5,
            released_rows: 1,
            released_concurrency: 0,
            purged_at_unix_ms: NOW + 20,
            provider_authority_refunded: false,
            receipt_blake3: Default::default(),
            release_reason:
                ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonAckedRetentionElapsed
                    as i32,
            deleted_partial_temp_bytes: 0,
            deleted_partial_temp_files: 0,
        }),
        partial_temp_bytes: 0,
        partial_temp_chunks: 0,
    }
}

fn closed_state() -> lore_object_dispatch::CanonicalObjectStoreRequestState {
    let terminal = validate_and_encode_terminal_result(
        &ObjectStoreTerminalResultV1 {
            terminal_result_id: "terminal-1".to_string(),
            canonical_result_blake3: Default::default(),
            canonical_result_size: 0,
            result: Some(object_store_terminal_result_v1::Result::ByteResult(
                ByteResultHandleV1 {
                    handle: "result-1".to_string(),
                    size: 5,
                    blake3: DIGEST.to_vec().into(),
                    content_length: 5,
                    metadata: Vec::new(),
                    etag: None,
                    version_id: None,
                },
            )),
        },
        &terminal_limits(),
    )
    .expect("terminal fixture");
    validate_and_encode_object_store_request_state(
        &ObjectStoreRequestStateV1 {
            protocol_revision: "object-dispatch-v1".to_string(),
            provider_boundary_id: "boundary-1".to_string(),
            authenticated_cell_id: "cell-1".to_string(),
            authenticated_tenant_id: "tenant-1".to_string(),
            logical_request_id: REQUEST_ID.to_string(),
            attempt_id: ATTEMPT_ID.to_string(),
            put_reservation_fingerprint: None,
            canonical_descriptor_fingerprint: Some(OTHER_DIGEST.to_vec().into()),
            phase: ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseTerminal as i32,
            allocation_revision: "allocation-1".to_string(),
            allocation_fence: 2,
            cell_admission_id: Some("admission-1".to_string()),
            cell_admission_fence: Some(2),
            reservations: vec![reservation()],
            dispatch_attempt: Some(ObjectStoreDispatchAttemptV1 {
                provider_attempt_id: "provider-attempt-1".to_string(),
                provider_grant_id: "provider-grant-1".to_string(),
                provider_grant_fence: 2,
                dispatcher_id: "dispatcher-1".to_string(),
                dispatcher_lease_generation: 3,
                dispatch_started_at_unix_ms: NOW - 10,
                ambiguity_recorded_at_unix_ms: None,
                provider_credential_revision: "credential-1".to_string(),
            }),
            terminal_result: Some(terminal.result().clone()),
            terminal_retryability:
                ObjectStoreTerminalRetryabilityV1::ObjectStoreTerminalRetryabilityNonRetryable
                    as i32,
            result_disposition: ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked
                as i32,
            ack_receipt: Some(ObjectStoreResultAckReceiptV1 {
                state: ObjectStoreResultAckStateV1::ObjectStoreResultAckStateAcked as i32,
                terminal_result_id: "terminal-1".to_string(),
                ack_fingerprint: DIGEST.to_vec().into(),
                acked_at_unix_ms: NOW,
                payload_purge_after_unix_ms: Some(NOW + 10),
            }),
            discard_receipt: None,
            no_dispatch_proof: None,
            put_body: Some(not_applicable(
                ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
            )),
            result_payload: Some(disposed_get()),
            quota_state: Some(ObjectStoreQuotaStateV1 {
                provider_reservations: vec![reservation()],
                put_spool_quota: Some(quota(0, 0, 0)),
                result_spool_quota: Some(quota(0, 0, 0)),
                retained_metadata_quota: Some(quota(10, 1, 0)),
                quota_revision: 4,
            }),
            state_committed_at_unix_ms: NOW + 20,
            closure_committed_at_unix_ms: Some(NOW + 20),
            state_blake3: Default::default(),
            policy_revision: "policy-1".to_string(),
            put_submit_binding: None,
        },
        &wire_limits(),
    )
    .expect("closed state fixture")
}

pub fn compact_plan() -> ObjectStoreCompactReceiptDecision {
    let authority = ObjectStoreCompactAuthority::RequestState(Box::new(closed_state()));
    let ObjectStoreCompactAuthority::RequestState(state) = &authority;
    let receipt = validate_and_encode_object_store_request_receipt(
        &ObjectStoreRequestReceiptV1 {
            receipt_blake3: Default::default(),
            receipt_committed_at_unix_ms: NOW + 20,
            outcome: Some(object_store_request_receipt_v1::Outcome::RequestState(
                Box::new(state.value().clone()),
            )),
        },
        &wire_limits(),
    )
    .expect("receipt fixture");
    let outcome = validate_and_encode_object_store_request_outcome(
        &ObjectStoreRequestOutcomeV1 {
            outcome_blake3: Default::default(),
            outcome: Some(object_store_request_outcome_v1::Outcome::RequestState(
                Box::new(state.value().clone()),
            )),
        },
        &wire_limits(),
    )
    .expect("outcome fixture");
    decide_object_store_compact_receipt(
        &ObjectStoreCompactReceiptPlannerInput {
            authority: &authority,
            submit_receipt: &receipt,
            get_outcome: &outcome,
            admission_created_at_unix_ms: NOW - 50,
            reserve_put_ack: None,
            provider_attempt_audit: &ObjectStoreProviderAttemptAudit {
                attempt_count: 1,
                committed_grant_count: 1,
                no_dispatch_count: 0,
                decisive_terminal_count: 1,
                ambiguous_count: 0,
                provider_authority_refunded: false,
                audit_blake3: None,
            },
            trusted_dependency_floors: None,
            database_now_unix_ms: NOW + 50,
            existing_compact: None,
        },
        &compact_limits(),
    )
    .expect("compact plan fixture")
}

pub fn policy() -> ObjectStoreFullToCompactPolicy {
    ObjectStoreFullToCompactPolicy {
        policy_revision: "storage-policy-1".to_string(),
        max_full_record_rows_global: 1_000,
        max_full_record_bytes_global: 1_000_000,
        max_full_record_rows_per_cell: 1_000,
        max_full_record_bytes_per_cell: 1_000_000,
        max_full_record_rows_per_tenant: 1_000,
        max_full_record_bytes_per_tenant: 1_000_000,
        max_compact_rows_global: 1_000,
        max_compact_bytes_global: 1_000_000,
        max_compact_rows_per_cell: 1_000,
        max_compact_bytes_per_cell: 1_000_000,
        max_compact_rows_per_tenant: 1_000,
        max_compact_bytes_per_tenant: 1_000_000,
        full_record_low_water_reserve_rows: 100,
        full_record_low_water_reserve_bytes: 100_000,
    }
}
