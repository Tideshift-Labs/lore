// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::CompactReceiptError;
use lore_object_dispatch::NoDispatchProofFields;
use lore_object_dispatch::NoDispatchReason;
use lore_object_dispatch::ObjectStoreCompactAuthority;
use lore_object_dispatch::ObjectStoreCompactDependencyFloor;
use lore_object_dispatch::ObjectStoreCompactDependencyFloorKind;
use lore_object_dispatch::ObjectStoreCompactReceiptDecision;
use lore_object_dispatch::ObjectStoreCompactReceiptInput;
use lore_object_dispatch::ObjectStoreCompactReceiptLimits;
use lore_object_dispatch::ObjectStoreCompactReceiptPlannerInput;
use lore_object_dispatch::ObjectStoreProviderAttemptAudit;
use lore_object_dispatch::RequestStateWireLimits;
use lore_object_dispatch::ReservePutAckError;
use lore_object_dispatch::ReservePutAckLimits;
use lore_object_dispatch::TerminalResultLimits;
use lore_object_dispatch::build_no_dispatch_proof;
use lore_object_dispatch::decide_object_store_compact_receipt;
use lore_object_dispatch::validate_and_encode_object_store_compact_dependency_floor;
use lore_object_dispatch::validate_and_encode_object_store_compact_receipt;
use lore_object_dispatch::validate_and_encode_object_store_provider_attempt_audit;
use lore_object_dispatch::validate_and_encode_object_store_request_outcome;
use lore_object_dispatch::validate_and_encode_object_store_request_receipt;
use lore_object_dispatch::validate_and_encode_object_store_request_state;
use lore_object_dispatch::validate_and_encode_object_store_reserve_put_ack;
use lore_object_dispatch::validate_and_encode_terminal_result;
use lore_proto::lore::object_dispatch::v1::*;

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

fn limits() -> ObjectStoreCompactReceiptLimits {
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
        max_canonical_result_bytes: 4_096,
        max_list_entries: 8,
        max_key_bytes: 64,
        max_metadata_entries: 4,
        max_metadata_key_bytes: 32,
        max_metadata_value_bytes: 64,
        max_metadata_aggregate_bytes: 128,
        max_opaque_value_bytes: 64,
        max_result_handle_bytes: 128,
        max_provider_code_bytes: 32,
        max_provider_request_id_bytes: 64,
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

fn disposed(
    kind: ObjectStorePayloadKindV1,
    disposition: ObjectStoreResultDispositionV1,
    reason: ObjectStorePayloadReleaseReasonV1,
    size: u64,
) -> ObjectStorePayloadRetentionV1 {
    let is_put = kind == ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody;
    ObjectStorePayloadRetentionV1 {
        payload_kind: kind as i32,
        availability: ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityDisposed
            as i32,
        durable_handle: (reason
            != ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonNoPayloadCreated)
            .then(|| if is_put { "put-body-1" } else { "result-1" }.to_string()),
        size,
        blake3: DIGEST.to_vec().into(),
        purge_state: ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStatePurged as i32,
        purge_eligible_at_unix_ms: Some(NOW + 10),
        purge_receipt: Some(ObjectStorePayloadPurgeReceiptV1 {
            purge_id: if is_put { "purge-put-1" } else { "purge-result-1" }.to_string(),
            payload_kind: kind as i32,
            terminal_result_id: (disposition
                != ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable)
                .then(|| "terminal-1".to_string()),
            disposition: disposition as i32,
            released_bytes: size,
            released_rows: 1,
            released_concurrency: u64::from(is_put),
            purged_at_unix_ms: NOW + 20,
            provider_authority_refunded: false,
            receipt_blake3: Default::default(),
            release_reason: reason as i32,
            deleted_partial_temp_bytes: if reason
                == ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonNoPayloadCreated
            {
                size
            } else {
                0
            },
            deleted_partial_temp_files: u64::from(
                reason
                    == ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonNoPayloadCreated,
            ),
        }),
        partial_temp_bytes: 0,
        partial_temp_chunks: 0,
    }
}

fn byte_terminal() -> ObjectStoreTerminalResultV1 {
    validate_and_encode_terminal_result(
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
    .expect("byte terminal fixture")
    .result()
    .clone()
}

fn provider_error_terminal() -> ObjectStoreTerminalResultV1 {
    validate_and_encode_terminal_result(
        &ObjectStoreTerminalResultV1 {
            terminal_result_id: "terminal-1".to_string(),
            canonical_result_blake3: Default::default(),
            canonical_result_size: 0,
            result: Some(object_store_terminal_result_v1::Result::ProviderError(
                ProviderErrorV1 {
                    error_class: ProviderErrorClassV1::ProviderErrorClassThrottled as i32,
                    http_status: 429,
                    retry_after_ms: Some(1_000),
                    provider_code: None,
                    provider_request_id: None,
                    provider_message_blake3: DIGEST.to_vec().into(),
                },
            )),
        },
        &terminal_limits(),
    )
    .expect("provider error terminal fixture")
    .result()
    .clone()
}

#[derive(Clone, Copy)]
enum StateKind {
    GetAcked,
    PutRetryable,
    Available,
}

fn terminal_state(kind: StateKind) -> lore_object_dispatch::CanonicalObjectStoreRequestState {
    let is_put = matches!(kind, StateKind::PutRetryable);
    let disposition = match kind {
        StateKind::GetAcked => ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked,
        StateKind::PutRetryable => {
            ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded
        }
        StateKind::Available => {
            ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable
        }
    };
    let terminal = if is_put {
        provider_error_terminal()
    } else {
        byte_terminal()
    };
    validate_and_encode_object_store_request_state(
        &ObjectStoreRequestStateV1 {
            protocol_revision: "object-dispatch-v1".to_string(),
            provider_boundary_id: "boundary-1".to_string(),
            authenticated_cell_id: "cell-1".to_string(),
            authenticated_tenant_id: "tenant-1".to_string(),
            logical_request_id: REQUEST_ID.to_string(),
            attempt_id: ATTEMPT_ID.to_string(),
            put_reservation_fingerprint: is_put.then(|| DIGEST.to_vec().into()),
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
            terminal_result: Some(terminal),
            terminal_retryability: if is_put {
                ObjectStoreTerminalRetryabilityV1::ObjectStoreTerminalRetryabilityRetryable as i32
            } else {
                ObjectStoreTerminalRetryabilityV1::ObjectStoreTerminalRetryabilityNonRetryable
                    as i32
            },
            result_disposition: disposition as i32,
            ack_receipt: matches!(kind, StateKind::GetAcked).then(|| ObjectStoreResultAckReceiptV1 {
                state: ObjectStoreResultAckStateV1::ObjectStoreResultAckStateAcked as i32,
                terminal_result_id: "terminal-1".to_string(),
                ack_fingerprint: DIGEST.to_vec().into(),
                acked_at_unix_ms: NOW,
                payload_purge_after_unix_ms: Some(NOW + 10),
            }),
            discard_receipt: matches!(kind, StateKind::PutRetryable).then(|| {
                ObjectStoreResultDiscardReceiptV1 {
                    state: ObjectStoreResultDiscardStateV1::ObjectStoreResultDiscardStateDiscarded
                        as i32,
                    terminal_result_id: "terminal-1".to_string(),
                    discard_fingerprint: OTHER_DIGEST.to_vec().into(),
                    discarded_at_unix_ms: NOW,
                    payload_purge_after_unix_ms: Some(NOW + 10),
                }
            }),
            no_dispatch_proof: None,
            put_body: Some(if is_put {
                disposed(
                    ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
                    disposition,
                    ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonDiscardedRetentionElapsed,
                    11,
                )
            } else {
                not_applicable(ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody)
            }),
            result_payload: Some(match kind {
                StateKind::GetAcked => disposed(
                    ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
                    disposition,
                    ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonAckedRetentionElapsed,
                    5,
                ),
                StateKind::Available => ObjectStorePayloadRetentionV1 {
                    payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult as i32,
                    availability: ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained as i32,
                    durable_handle: Some("result-1".to_string()),
                    size: 5,
                    blake3: DIGEST.to_vec().into(),
                    purge_state: ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateNotEligible as i32,
                    purge_eligible_at_unix_ms: None,
                    purge_receipt: None,
                    partial_temp_bytes: 0,
                    partial_temp_chunks: 0,
                },
                StateKind::PutRetryable => not_applicable(
                    ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
                ),
            }),
            quota_state: Some(ObjectStoreQuotaStateV1 {
                provider_reservations: vec![reservation()],
                put_spool_quota: Some(quota(0, 0, 0)),
                result_spool_quota: Some(if matches!(kind, StateKind::Available) {
                    quota(5, 1, 0)
                } else {
                    quota(0, 0, 0)
                }),
                retained_metadata_quota: Some(quota(10, 1, 0)),
                quota_revision: 4,
            }),
            state_committed_at_unix_ms: if matches!(kind, StateKind::Available) {
                NOW
            } else {
                NOW + 20
            },
            closure_committed_at_unix_ms: (!matches!(kind, StateKind::Available))
                .then_some(NOW + 20),
            state_blake3: Default::default(),
            policy_revision: "policy-1".to_string(),
            put_submit_binding: is_put.then(|| PutSubmitBindingV1 {
                upload_id: "upload-1".to_string(),
                upload_fence: 2,
                durable_body_handle: "put-body-1".to_string(),
                reservation_expires_at_unix_ms: NOW + 1_000,
                bound_at_unix_ms: NOW - 20,
                binding_fence: 3,
                binding_blake3: Default::default(),
            }),
        },
        &wire_limits(),
    )
    .expect("terminal state fixture")
}

fn open_state(
    phase: ObjectStoreRequestPhaseV1,
) -> lore_object_dispatch::CanonicalObjectStoreRequestState {
    let admitted = phase != ObjectStoreRequestPhaseV1::ObjectStoreRequestPhasePrepared;
    let put_reservation = ReservedDimensionV1 {
        reservation_id: "reservation-1".to_string(),
        physical_dimension_id: "physical-1".to_string(),
        operation_class_id: "PUT".to_string(),
        units: 3,
    };
    let put_body = if admitted {
        ObjectStorePayloadRetentionV1 {
            payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody as i32,
            availability: ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained
                as i32,
            durable_handle: Some("put-body-1".to_string()),
            size: 100,
            blake3: DIGEST.to_vec().into(),
            purge_state:
                ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateRetentionPending as i32,
            purge_eligible_at_unix_ms: Some(NOW + 1_000),
            purge_receipt: None,
            partial_temp_bytes: 0,
            partial_temp_chunks: 0,
        }
    } else {
        ObjectStorePayloadRetentionV1 {
            payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody as i32,
            availability:
                ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityPendingUpload as i32,
            durable_handle: None,
            size: 100,
            blake3: DIGEST.to_vec().into(),
            purge_state:
                ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateRetentionPending as i32,
            purge_eligible_at_unix_ms: Some(NOW + 1_000),
            purge_receipt: None,
            partial_temp_bytes: 10,
            partial_temp_chunks: 1,
        }
    };
    let dispatch_attempt = match phase {
        ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseDispatching
        | ObjectStoreRequestPhaseV1::ObjectStoreRequestPhasePossiblyDispatched => {
            Some(ObjectStoreDispatchAttemptV1 {
                provider_attempt_id: "provider-attempt-1".to_string(),
                provider_grant_id: "provider-grant-1".to_string(),
                provider_grant_fence: 2,
                dispatcher_id: "dispatcher-1".to_string(),
                dispatcher_lease_generation: 3,
                dispatch_started_at_unix_ms: NOW - 10,
                ambiguity_recorded_at_unix_ms: (phase
                    == ObjectStoreRequestPhaseV1::ObjectStoreRequestPhasePossiblyDispatched)
                    .then_some(NOW - 1),
                provider_credential_revision: "credential-1".to_string(),
            })
        }
        _ => None,
    };
    validate_and_encode_object_store_request_state(
        &ObjectStoreRequestStateV1 {
            protocol_revision: "object-dispatch-v1".to_string(),
            provider_boundary_id: "boundary-1".to_string(),
            authenticated_cell_id: "cell-1".to_string(),
            authenticated_tenant_id: "tenant-1".to_string(),
            logical_request_id: REQUEST_ID.to_string(),
            attempt_id: ATTEMPT_ID.to_string(),
            put_reservation_fingerprint: Some(DIGEST.to_vec().into()),
            canonical_descriptor_fingerprint: admitted.then(|| OTHER_DIGEST.to_vec().into()),
            phase: phase as i32,
            allocation_revision: "allocation-1".to_string(),
            allocation_fence: 2,
            cell_admission_id: admitted.then(|| "admission-1".to_string()),
            cell_admission_fence: admitted.then_some(2),
            reservations: if admitted {
                vec![put_reservation.clone()]
            } else {
                Vec::new()
            },
            dispatch_attempt,
            terminal_result: None,
            terminal_retryability:
                ObjectStoreTerminalRetryabilityV1::ObjectStoreTerminalRetryabilityNotApplicable
                    as i32,
            result_disposition:
                ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable as i32,
            ack_receipt: None,
            discard_receipt: None,
            no_dispatch_proof: None,
            put_body: Some(put_body),
            result_payload: Some(not_applicable(
                ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
            )),
            quota_state: Some(ObjectStoreQuotaStateV1 {
                provider_reservations: if admitted {
                    vec![put_reservation]
                } else {
                    Vec::new()
                },
                put_spool_quota: Some(quota(100, 1, 1)),
                result_spool_quota: Some(quota(0, 0, 0)),
                retained_metadata_quota: Some(if admitted {
                    quota(10, 1, 0)
                } else {
                    quota(0, 0, 0)
                }),
                quota_revision: if admitted { 2 } else { 1 },
            }),
            state_committed_at_unix_ms: NOW,
            closure_committed_at_unix_ms: None,
            state_blake3: Default::default(),
            policy_revision: "policy-1".to_string(),
            put_submit_binding: admitted.then(|| PutSubmitBindingV1 {
                upload_id: "upload-1".to_string(),
                upload_fence: 2,
                durable_body_handle: "put-body-1".to_string(),
                reservation_expires_at_unix_ms: NOW + 1_000,
                bound_at_unix_ms: NOW - 20,
                binding_fence: 3,
                binding_blake3: Default::default(),
            }),
        },
        &wire_limits(),
    )
    .expect("open request-state fixture")
}

fn expired_state() -> lore_object_dispatch::CanonicalObjectStoreRequestState {
    let proof = build_no_dispatch_proof(
        NoDispatchProofFields {
            reason: NoDispatchReason::PreparedTtlExpired,
            proof_id: "018f3e12-a456-7abc-8def-0123456789ab".to_string(),
            proof_fence: 4,
            committed_at_unix_ms: NOW,
            authority_epoch: 5,
        },
        16_384,
    )
    .expect("no-dispatch proof fixture");
    validate_and_encode_object_store_request_state(
        &ObjectStoreRequestStateV1 {
            protocol_revision: "object-dispatch-v1".to_string(),
            provider_boundary_id: "boundary-1".to_string(),
            authenticated_cell_id: "cell-1".to_string(),
            authenticated_tenant_id: "tenant-1".to_string(),
            logical_request_id: REQUEST_ID.to_string(),
            attempt_id: ATTEMPT_ID.to_string(),
            put_reservation_fingerprint: Some(DIGEST.to_vec().into()),
            canonical_descriptor_fingerprint: None,
            phase: ObjectStoreRequestPhaseV1::ObjectStoreRequestPhasePreparedExpired as i32,
            allocation_revision: "allocation-1".to_string(),
            allocation_fence: 2,
            cell_admission_id: None,
            cell_admission_fence: None,
            reservations: Vec::new(),
            dispatch_attempt: None,
            terminal_result: None,
            terminal_retryability:
                ObjectStoreTerminalRetryabilityV1::ObjectStoreTerminalRetryabilityNotApplicable
                    as i32,
            result_disposition:
                ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable as i32,
            ack_receipt: None,
            discard_receipt: None,
            no_dispatch_proof: Some(ObjectStoreNoDispatchProofV1 {
                reason: ObjectStoreNoDispatchReasonV1::ObjectStoreNoDispatchReasonPreparedTtlExpired
                    as i32,
                proof_id: "018f3e12-a456-7abc-8def-0123456789ab".to_string(),
                proof_fence: 4,
                committed_at_unix_ms: NOW,
                authority_epoch: 5,
                proof_blake3: proof.proof().proof_blake3.to_vec().into(),
            }),
            put_body: Some(disposed(
                ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
                ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable,
                ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonNoPayloadCreated,
                11,
            )),
            result_payload: Some(not_applicable(
                ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
            )),
            quota_state: Some(ObjectStoreQuotaStateV1 {
                provider_reservations: Vec::new(),
                put_spool_quota: Some(quota(0, 0, 0)),
                result_spool_quota: Some(quota(0, 0, 0)),
                retained_metadata_quota: Some(quota(0, 0, 0)),
                quota_revision: 2,
            }),
            state_committed_at_unix_ms: NOW + 20,
            closure_committed_at_unix_ms: Some(NOW + 20),
            state_blake3: Default::default(),
            policy_revision: "policy-1".to_string(),
            put_submit_binding: None,
        },
        &wire_limits(),
    )
    .expect("expired state fixture")
}

fn terminal_audit() -> ObjectStoreProviderAttemptAudit {
    ObjectStoreProviderAttemptAudit {
        attempt_count: 1,
        committed_grant_count: 1,
        no_dispatch_count: 0,
        decisive_terminal_count: 1,
        ambiguous_count: 0,
        provider_authority_refunded: false,
        audit_blake3: None,
    }
}

fn no_dispatch_audit() -> ObjectStoreProviderAttemptAudit {
    ObjectStoreProviderAttemptAudit {
        attempt_count: 0,
        committed_grant_count: 0,
        no_dispatch_count: 1,
        decisive_terminal_count: 0,
        ambiguous_count: 0,
        provider_authority_refunded: false,
        audit_blake3: None,
    }
}

struct Fixture {
    authority: ObjectStoreCompactAuthority,
    receipt: lore_object_dispatch::CanonicalObjectStoreRequestReceipt,
    outcome: lore_object_dispatch::CanonicalObjectStoreRequestOutcome,
    reserve_put_ack: Option<lore_object_dispatch::CanonicalObjectStoreReservePutAck>,
    audit: ObjectStoreProviderAttemptAudit,
}

fn reserve_put_ack() -> lore_object_dispatch::CanonicalObjectStoreReservePutAck {
    let no_dispatch = build_no_dispatch_proof(
        NoDispatchProofFields {
            reason: NoDispatchReason::PreparedTtlExpired,
            proof_id: "018f3e12-a456-7abc-8def-0123456789ab".to_string(),
            proof_fence: 1,
            committed_at_unix_ms: NOW,
            authority_epoch: 1,
        },
        16_384,
    )
    .expect("ReservePut no-dispatch proof fixture");
    validate_and_encode_object_store_reserve_put_ack(
        &ReservePutAckV1 {
            protocol_revision: "object-dispatch-v1".to_string(),
            policy_revision: "policy-1".to_string(),
            provider_boundary_id: "boundary-1".to_string(),
            authenticated_cell_id: "cell-1".to_string(),
            authenticated_tenant_id: "tenant-1".to_string(),
            logical_request_id: REQUEST_ID.to_string(),
            attempt_id: ATTEMPT_ID.to_string(),
            upload_id: "018f3e12-a452-7abc-8def-0123456789ab".to_string(),
            upload_fence: 1,
            state: 3,
            reserved_quota: Some(quota(64, 1, 1)),
            expires_at_unix_ms: NOW,
            max_chunk_bytes: 64,
            spool_ready: None,
            payload_release_receipt: Some(ObjectStorePayloadPurgeReceiptV1 {
                purge_id: "reserve-put-purge-1".to_string(),
                payload_kind: 1,
                terminal_result_id: None,
                disposition: 1,
                released_bytes: 64,
                released_rows: 1,
                released_concurrency: 1,
                purged_at_unix_ms: NOW + 10,
                provider_authority_refunded: false,
                receipt_blake3: Default::default(),
                release_reason: 3,
                deleted_partial_temp_bytes: 0,
                deleted_partial_temp_files: 0,
            }),
            admission_clock_unix_ms: NOW - 10,
            allocation_hard_expiry_unix_ms: NOW + 20,
            closure: None,
            no_dispatch_proof: Some(ObjectStoreNoDispatchProofV1 {
                reason: 4,
                proof_id: "018f3e12-a456-7abc-8def-0123456789ab".to_string(),
                proof_fence: 1,
                committed_at_unix_ms: NOW,
                authority_epoch: 1,
                proof_blake3: no_dispatch.proof().proof_blake3.to_vec().into(),
            }),
            ack_blake3: Default::default(),
        },
        &ReservePutAckLimits {
            max_identity_bytes: 256,
            max_durable_handle_bytes: 256,
            max_canonical_row_bytes: 16_384,
        },
    )
    .expect("ReservePut ACK fixture")
}

fn fixture(
    authority: ObjectStoreCompactAuthority,
    audit: ObjectStoreProviderAttemptAudit,
) -> Fixture {
    let is_put = match &authority {
        ObjectStoreCompactAuthority::RequestState(value) => {
            value.value().put_reservation_fingerprint.is_some()
        }
    };
    let (receipt_outcome, get_outcome) = match &authority {
        ObjectStoreCompactAuthority::RequestState(value) => (
            object_store_request_receipt_v1::Outcome::RequestState(Box::new(value.value().clone())),
            object_store_request_outcome_v1::Outcome::RequestState(Box::new(value.value().clone())),
        ),
    };
    let receipt = validate_and_encode_object_store_request_receipt(
        &ObjectStoreRequestReceiptV1 {
            receipt_blake3: Default::default(),
            receipt_committed_at_unix_ms: NOW + 20,
            outcome: Some(receipt_outcome),
        },
        &wire_limits(),
    )
    .expect("receipt fixture");
    let outcome = validate_and_encode_object_store_request_outcome(
        &ObjectStoreRequestOutcomeV1 {
            outcome_blake3: Default::default(),
            outcome: Some(get_outcome),
        },
        &wire_limits(),
    )
    .expect("outcome fixture");
    Fixture {
        authority,
        receipt,
        outcome,
        reserve_put_ack: is_put.then(reserve_put_ack),
        audit,
    }
}

fn get_fixture() -> Fixture {
    fixture(
        ObjectStoreCompactAuthority::RequestState(Box::new(terminal_state(StateKind::GetAcked))),
        terminal_audit(),
    )
}

fn planner<'a>(fixture: &'a Fixture) -> ObjectStoreCompactReceiptPlannerInput<'a> {
    ObjectStoreCompactReceiptPlannerInput {
        authority: &fixture.authority,
        submit_receipt: &fixture.receipt,
        get_outcome: &fixture.outcome,
        admission_created_at_unix_ms: NOW - 50,
        reserve_put_ack: fixture.reserve_put_ack.as_ref(),
        provider_attempt_audit: &fixture.audit,
        trusted_dependency_floors: None,
        database_now_unix_ms: NOW + 50,
        existing_compact: None,
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex UTF-8"), 16)
                .expect("valid hex")
        })
        .collect()
}

#[test]
fn disposed_acked_get_pins_cross_language_compact_golden() {
    let fixture = get_fixture();
    let decision = decide_object_store_compact_receipt(&planner(&fixture), &limits())
        .expect("compaction decision");
    let ObjectStoreCompactReceiptDecision::ApplyCompaction {
        compact,
        compact_charge,
        ..
    } = decision
    else {
        panic!("disposed ACKed GET must compact");
    };
    assert_eq!(
        compact.value().schema_revision,
        "object-store-compact-receipt-v1"
    );
    assert_eq!(
        compact.value().logical_request_uuid_unix_ms,
        0x018f_3e12_a450
    );
    assert_eq!(compact.value().attempt_uuid_unix_ms, 0x018f_3e12_a451);
    assert_eq!(compact.value().closure_committed_at_unix_ms, NOW + 20);
    assert_eq!(compact.value().compacted_at_unix_ms, NOW + 50);
    assert_eq!(compact.value().compact_prune_after_unix_ms, NOW + 120);
    assert_eq!(compact_charge.bytes, compact.canonical_bytes().len() as u64);
    assert_eq!(compact_charge.rows, 1);
    assert_eq!(compact_charge.concurrency, 0);
    assert_ne!(
        compact.compact_blake3().as_ptr(),
        compact.value().compact_blake3.as_ptr()
    );
    assert_eq!(compact.canonical_bytes().len(), 6_519);
    assert_eq!(
        compact.compact_blake3(),
        decode_hex("5c172fbba2f48cda97bbbb2d3e4fde6d54fa25b51e955bfaa6eeb36d65e7f9d1").as_slice()
    );
}

#[test]
fn disposed_put_and_prepared_expired_no_payload_compact() {
    let cases = [
        fixture(
            ObjectStoreCompactAuthority::RequestState(Box::new(terminal_state(
                StateKind::PutRetryable,
            ))),
            terminal_audit(),
        ),
        fixture(
            ObjectStoreCompactAuthority::RequestState(Box::new(expired_state())),
            no_dispatch_audit(),
        ),
    ];
    for fixture in cases {
        assert!(matches!(
            decide_object_store_compact_receipt(&planner(&fixture), &limits()),
            Ok(ObjectStoreCompactReceiptDecision::ApplyCompaction { .. })
        ));
    }
}

#[test]
fn disposed_put_compact_pins_reserve_ack_and_replay_projection() {
    let fixture = fixture(
        ObjectStoreCompactAuthority::RequestState(Box::new(terminal_state(
            StateKind::PutRetryable,
        ))),
        terminal_audit(),
    );
    let ObjectStoreCompactReceiptDecision::ApplyCompaction { compact, .. } =
        decide_object_store_compact_receipt(&planner(&fixture), &limits()).expect("PUT compaction")
    else {
        panic!("disposed PUT must compact");
    };
    let source_ack = fixture.reserve_put_ack.as_ref().expect("PUT ACK fixture");
    let compact_ack = compact
        .value()
        .reserve_put_ack
        .as_ref()
        .expect("compact PUT ACK");
    assert_eq!(compact_ack.canonical_bytes(), source_ack.canonical_bytes());
    assert_eq!(compact_ack.ack_blake3(), source_ack.ack_blake3());
    assert_ne!(
        compact_ack.canonical_bytes().as_ptr(),
        source_ack.canonical_bytes().as_ptr()
    );
    assert_eq!(source_ack.canonical_bytes().len(), 687);
    assert_eq!(
        source_ack.ack_blake3(),
        decode_hex("9be99cf8cf771dae54f540a31ff5074839c4a3a71e928da7ba2885bdb2b623c5").as_slice()
    );
    assert_eq!(compact.canonical_bytes().len(), 7_749);
    assert_eq!(
        compact.compact_blake3(),
        decode_hex("06c714e55984f67f117f84b77e1e78b202dbd40d02258e1c3ae5680e1d73cd76").as_slice()
    );

    let mut replay = planner(&fixture);
    replay.existing_compact = Some(&compact);
    replay.database_now_unix_ms = -1;
    let ObjectStoreCompactReceiptDecision::ReplayCompact { compact: replayed } =
        decide_object_store_compact_receipt(&replay, &limits()).expect("PUT replay")
    else {
        panic!("exact PUT compact must replay");
    };
    assert_eq!(
        replayed
            .value()
            .reserve_put_ack
            .as_ref()
            .expect("replayed PUT ACK")
            .canonical_bytes(),
        source_ack.canonical_bytes()
    );
    replay.reserve_put_ack = None;
    assert_eq!(
        decide_object_store_compact_receipt(&replay, &limits()),
        Err(CompactReceiptError::InvalidReservePutAck)
    );
}

#[test]
fn every_dependency_floor_kind_pins_cross_language_canonical_record() {
    for (kind, dependency_id, retain_until_unix_ms, expected_size, expected_digest) in [
        (
            ObjectStoreCompactDependencyFloorKind::Ack,
            "floor-1",
            NOW,
            96,
            "53cefe5f298349be627e3c4309fe6b7b0b0579f1f18b7924e57a99bc56546380",
        ),
        (
            ObjectStoreCompactDependencyFloorKind::Discard,
            "floor-2",
            NOW + 1,
            96,
            "144f8e39921b0ce0a2a5a4686617c877d9daafada71d3a622c1accd148390325",
        ),
        (
            ObjectStoreCompactDependencyFloorKind::PutPayloadPurge,
            "floor-3",
            NOW + 2,
            96,
            "058392445cdc5677e67c73af3bf46d7058f1cb52f8972bfdb0c98eaf0c96934e",
        ),
        (
            ObjectStoreCompactDependencyFloorKind::ResultPayloadPurge,
            "floor-4",
            NOW + 3,
            96,
            "fc625b74501d4eb87df9f8f53b8cae6302df6dfdf3b148e4ffacc9a13418a256",
        ),
        (
            ObjectStoreCompactDependencyFloorKind::Continuity,
            "floor-5",
            NOW + 4,
            96,
            "8005d7cee014a8ca26423c0dedc9995caf86385158e40f276a1aacb3af188c2c",
        ),
        (
            ObjectStoreCompactDependencyFloorKind::LocalDependency,
            "floor-6",
            NOW + 5,
            96,
            "6b638ace7a46117143894ecbbdc487461a4f2c23f56ee346ef09c7053fe5c900",
        ),
    ] {
        let floor = validate_and_encode_object_store_compact_dependency_floor(
            &ObjectStoreCompactDependencyFloor {
                kind,
                dependency_id: dependency_id.to_string(),
                retain_until_unix_ms,
                floor_blake3: None,
            },
            &limits(),
        )
        .expect("canonical dependency floor");
        assert_eq!(floor.canonical_bytes().len(), expected_size);
        assert_eq!(floor.floor_blake3(), decode_hex(expected_digest).as_slice());
    }
}

#[test]
fn full_record_retention_is_inclusive_at_exact_boundary() {
    let fixture = get_fixture();
    let eligible = NOW + 50;
    let mut input = planner(&fixture);
    input.database_now_unix_ms = eligible - 1;
    assert_eq!(
        decide_object_store_compact_receipt(&input, &limits()),
        Ok(ObjectStoreCompactReceiptDecision::RetainFullFloor {
            eligible_at_unix_ms: eligible
        })
    );
    input.database_now_unix_ms = eligible;
    assert!(matches!(
        decide_object_store_compact_receipt(&input, &limits()),
        Ok(ObjectStoreCompactReceiptDecision::ApplyCompaction { .. })
    ));
    input.database_now_unix_ms = eligible + 1;
    assert!(matches!(
        decide_object_store_compact_receipt(&input, &limits()),
        Ok(ObjectStoreCompactReceiptDecision::ApplyCompaction { .. })
    ));
}

#[test]
fn fresh_compaction_rejects_a_receipt_committed_after_database_time() {
    let mut fixture = get_fixture();
    fixture.receipt = validate_and_encode_object_store_request_receipt(
        &ObjectStoreRequestReceiptV1 {
            receipt_blake3: Default::default(),
            receipt_committed_at_unix_ms: NOW + 51,
            outcome: fixture.receipt.value().outcome.clone(),
        },
        &wire_limits(),
    )
    .expect("future receipt fixture");
    let mut input = planner(&fixture);
    input.database_now_unix_ms = NOW + 50;
    assert_eq!(
        decide_object_store_compact_receipt(&input, &limits()),
        Err(CompactReceiptError::InvalidTimeProjection)
    );
}

#[test]
fn prune_deadline_takes_maximum_of_all_contributors_and_utf8_sorts_ids() {
    let fixture = get_fixture();
    let floors = [
        ObjectStoreCompactDependencyFloor {
            kind: ObjectStoreCompactDependencyFloorKind::LocalDependency,
            dependency_id: "é".to_string(),
            retain_until_unix_ms: NOW + 140,
            floor_blake3: None,
        },
        ObjectStoreCompactDependencyFloor {
            kind: ObjectStoreCompactDependencyFloorKind::LocalDependency,
            dependency_id: "z".to_string(),
            retain_until_unix_ms: NOW + 30,
            floor_blake3: None,
        },
    ];
    let mut input = planner(&fixture);
    input.trusted_dependency_floors = Some(&floors);
    let ObjectStoreCompactReceiptDecision::ApplyCompaction { compact, .. } =
        decide_object_store_compact_receipt(&input, &limits()).expect("compaction")
    else {
        panic!("closed request must compact");
    };
    assert_eq!(compact.value().compact_prune_after_unix_ms, NOW + 140);
    let local_ids: Vec<_> = compact
        .value()
        .dependency_floors
        .iter()
        .filter(|floor| {
            floor.value().kind == ObjectStoreCompactDependencyFloorKind::LocalDependency
        })
        .map(|floor| floor.value().dependency_id.as_str())
        .collect();
    assert_eq!(local_ids, ["z", "é"]);
}

#[test]
fn live_retained_payload_authority_does_not_compact() {
    let live = fixture(
        ObjectStoreCompactAuthority::RequestState(Box::new(terminal_state(StateKind::Available))),
        terminal_audit(),
    );
    assert_eq!(
        decide_object_store_compact_receipt(&planner(&live), &limits()),
        Ok(ObjectStoreCompactReceiptDecision::RetainFullNotClosed)
    );
}

#[test]
fn every_open_request_phase_retains_full_without_no_dispatch_audit() {
    for (phase, attempt_count, committed_grant_count, ambiguous_count) in [
        (
            ObjectStoreRequestPhaseV1::ObjectStoreRequestPhasePrepared,
            0,
            0,
            0,
        ),
        (
            ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseAdmitted,
            0,
            0,
            0,
        ),
        (
            ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseDispatching,
            1,
            1,
            0,
        ),
        (
            ObjectStoreRequestPhaseV1::ObjectStoreRequestPhasePossiblyDispatched,
            1,
            1,
            1,
        ),
    ] {
        let selected = fixture(
            ObjectStoreCompactAuthority::RequestState(Box::new(open_state(phase))),
            ObjectStoreProviderAttemptAudit {
                attempt_count,
                committed_grant_count,
                no_dispatch_count: 0,
                decisive_terminal_count: 0,
                ambiguous_count,
                provider_authority_refunded: false,
                audit_blake3: None,
            },
        );
        assert_eq!(
            decide_object_store_compact_receipt(&planner(&selected), &limits()),
            Ok(ObjectStoreCompactReceiptDecision::RetainFullNotClosed),
            "{phase:?} must remain open without no-dispatch audit"
        );
    }
}

#[test]
fn retention_overflow_and_compact_size_bound_fail_closed() {
    let fixture = get_fixture();
    let mut input = planner(&fixture);
    input.admission_created_at_unix_ms = i64::MAX - 50;
    assert_eq!(
        decide_object_store_compact_receipt(&input, &limits()),
        Ok(ObjectStoreCompactReceiptDecision::RetainFullOverflow)
    );

    let applied = decide_object_store_compact_receipt(&planner(&fixture), &limits())
        .expect("baseline compaction");
    let ObjectStoreCompactReceiptDecision::ApplyCompaction { compact, .. } = applied else {
        panic!("baseline must compact");
    };
    let size = compact.canonical_bytes().len() as u32;
    let mut exact = limits();
    exact.max_compact_row_bytes = size;
    assert!(matches!(
        decide_object_store_compact_receipt(&planner(&fixture), &exact),
        Ok(ObjectStoreCompactReceiptDecision::ApplyCompaction { .. })
    ));
    exact.max_compact_row_bytes = size - 1;
    assert_eq!(
        decide_object_store_compact_receipt(&planner(&fixture), &exact),
        Ok(ObjectStoreCompactReceiptDecision::RetainFullTooLarge {
            encoded_bytes: u64::from(size)
        })
    );
}

#[test]
fn exact_replay_wins_before_clock_drift_and_changed_intent_conflicts() {
    let fixture = get_fixture();
    let ObjectStoreCompactReceiptDecision::ApplyCompaction {
        compact,
        compact_charge,
        ..
    } = decide_object_store_compact_receipt(&planner(&fixture), &limits())
        .expect("baseline compaction")
    else {
        panic!("baseline must compact");
    };
    let mut replay = planner(&fixture);
    replay.database_now_unix_ms = -1;
    replay.existing_compact = Some(&compact);
    let ObjectStoreCompactReceiptDecision::ReplayCompact { compact: replayed } =
        decide_object_store_compact_receipt(&replay, &limits()).expect("exact replay")
    else {
        panic!("exact compact must replay");
    };
    assert_eq!(replayed.canonical_bytes(), compact.canonical_bytes());
    assert_eq!(compact_charge.bytes, compact.canonical_bytes().len() as u64);
    let drifted_limits = ObjectStoreCompactReceiptLimits {
        max_identity_bytes: 1,
        max_canonical_row_bytes: 1,
        max_compact_row_bytes: 1,
        max_dependency_floors: 1,
        full_record_retention_ms: 1,
        anti_replay_admission_past_ms: 1,
        anti_replay_admission_future_ms: 1,
        anti_replay_compact_safety_ms: 1,
    };
    assert!(matches!(
        decide_object_store_compact_receipt(&replay, &drifted_limits),
        Ok(ObjectStoreCompactReceiptDecision::ReplayCompact { .. })
    ));

    let changed = [ObjectStoreCompactDependencyFloor {
        kind: ObjectStoreCompactDependencyFloorKind::LocalDependency,
        dependency_id: "new".to_string(),
        retain_until_unix_ms: NOW + 200,
        floor_blake3: None,
    }];
    replay.trusted_dependency_floors = Some(&changed);
    assert_eq!(
        decide_object_store_compact_receipt(&replay, &limits()),
        Ok(ObjectStoreCompactReceiptDecision::CompactConflict)
    );
}

#[test]
fn historical_terminal_ambiguity_and_no_dispatch_grant_are_audited_exactly() {
    let terminal = terminal_state(StateKind::GetAcked);
    let mut terminal_value = terminal.value().clone();
    terminal_value.state_blake3 = Default::default();
    terminal_value
        .dispatch_attempt
        .as_mut()
        .expect("terminal dispatch attempt")
        .ambiguity_recorded_at_unix_ms = Some(NOW - 1);
    let terminal = validate_and_encode_object_store_request_state(&terminal_value, &wire_limits())
        .expect("historically ambiguous terminal state");
    let terminal_fixture = fixture(
        ObjectStoreCompactAuthority::RequestState(Box::new(terminal)),
        ObjectStoreProviderAttemptAudit {
            attempt_count: 1,
            committed_grant_count: 1,
            no_dispatch_count: 0,
            decisive_terminal_count: 1,
            ambiguous_count: 1,
            provider_authority_refunded: false,
            audit_blake3: None,
        },
    );
    assert!(matches!(
        decide_object_store_compact_receipt(&planner(&terminal_fixture), &limits()),
        Ok(ObjectStoreCompactReceiptDecision::ApplyCompaction { .. })
    ));

    let expired = expired_state();
    let mut expired_value = expired.value().clone();
    expired_value.state_blake3 = Default::default();
    expired_value.phase = ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseNoDispatch as i32;
    let no_dispatch = build_no_dispatch_proof(
        NoDispatchProofFields {
            reason: NoDispatchReason::DispatcherProvedNotSent,
            proof_id: "018f3e12-a456-7abc-8def-0123456789ab".to_string(),
            proof_fence: 4,
            committed_at_unix_ms: NOW,
            authority_epoch: 5,
        },
        16_384,
    )
    .expect("historical no-dispatch proof");
    expired_value.no_dispatch_proof = Some(ObjectStoreNoDispatchProofV1 {
        reason: ObjectStoreNoDispatchReasonV1::ObjectStoreNoDispatchReasonDispatcherProvedNotSent
            as i32,
        proof_id: "018f3e12-a456-7abc-8def-0123456789ab".to_string(),
        proof_fence: 4,
        committed_at_unix_ms: NOW,
        authority_epoch: 5,
        proof_blake3: no_dispatch.proof().proof_blake3.to_vec().into(),
    });
    expired_value.put_body = Some(disposed(
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable,
        ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonNoDispatchBodyPurged,
        11,
    ));
    expired_value.dispatch_attempt = Some(ObjectStoreDispatchAttemptV1 {
        provider_attempt_id: "provider-attempt-1".to_string(),
        provider_grant_id: "provider-grant-1".to_string(),
        provider_grant_fence: 2,
        dispatcher_id: "dispatcher-1".to_string(),
        dispatcher_lease_generation: 3,
        dispatch_started_at_unix_ms: NOW - 10,
        ambiguity_recorded_at_unix_ms: None,
        provider_credential_revision: "credential-1".to_string(),
    });
    let expired = validate_and_encode_object_store_request_state(&expired_value, &wire_limits())
        .expect("no-dispatch authority with historical grant");
    let expired_fixture = fixture(
        ObjectStoreCompactAuthority::RequestState(Box::new(expired)),
        ObjectStoreProviderAttemptAudit {
            attempt_count: 0,
            committed_grant_count: 1,
            no_dispatch_count: 1,
            decisive_terminal_count: 0,
            ambiguous_count: 0,
            provider_authority_refunded: false,
            audit_blake3: None,
        },
    );
    assert!(matches!(
        decide_object_store_compact_receipt(&planner(&expired_fixture), &limits()),
        Ok(ObjectStoreCompactReceiptDecision::ApplyCompaction { .. })
    ));
}

#[test]
fn audit_and_floor_records_reject_digest_algebra_duplicate_and_presence_drift() {
    let audit = terminal_audit();
    let canonical_audit =
        validate_and_encode_object_store_provider_attempt_audit(&audit, &limits())
            .expect("audit record");
    assert!(canonical_audit.canonical_bytes().len() > 32);
    assert_eq!(
        validate_and_encode_object_store_provider_attempt_audit(
            &ObjectStoreProviderAttemptAudit {
                audit_blake3: Some(OTHER_DIGEST),
                ..audit.clone()
            },
            &limits(),
        ),
        Err(CompactReceiptError::DigestMismatch)
    );
    assert_eq!(
        validate_and_encode_object_store_provider_attempt_audit(
            &ObjectStoreProviderAttemptAudit {
                no_dispatch_count: 2,
                ..audit.clone()
            },
            &limits(),
        ),
        Err(CompactReceiptError::InvalidProviderAttemptAudit)
    );
    assert_eq!(
        validate_and_encode_object_store_provider_attempt_audit(
            &ObjectStoreProviderAttemptAudit {
                attempt_count: 1,
                committed_grant_count: 0,
                ..audit.clone()
            },
            &limits(),
        ),
        Err(CompactReceiptError::InvalidProviderAttemptAudit)
    );

    let floor = ObjectStoreCompactDependencyFloor {
        kind: ObjectStoreCompactDependencyFloorKind::Ack,
        dependency_id: "ack-1".to_string(),
        retain_until_unix_ms: NOW,
        floor_blake3: None,
    };
    let canonical_floor =
        validate_and_encode_object_store_compact_dependency_floor(&floor, &limits())
            .expect("floor record");
    assert!(canonical_floor.canonical_bytes().len() > 32);
    assert_eq!(
        validate_and_encode_object_store_compact_dependency_floor(
            &ObjectStoreCompactDependencyFloor {
                floor_blake3: Some(OTHER_DIGEST),
                ..floor.clone()
            },
            &limits(),
        ),
        Err(CompactReceiptError::DigestMismatch)
    );

    let fixture = get_fixture();
    let duplicates = [
        ObjectStoreCompactDependencyFloor {
            kind: ObjectStoreCompactDependencyFloorKind::LocalDependency,
            dependency_id: "same".to_string(),
            retain_until_unix_ms: NOW,
            floor_blake3: None,
        },
        ObjectStoreCompactDependencyFloor {
            kind: ObjectStoreCompactDependencyFloorKind::LocalDependency,
            dependency_id: "same".to_string(),
            retain_until_unix_ms: NOW + 1,
            floor_blake3: None,
        },
    ];
    let mut input = planner(&fixture);
    input.trusted_dependency_floors = Some(&duplicates);
    assert_eq!(
        decide_object_store_compact_receipt(&input, &limits()),
        Err(CompactReceiptError::DuplicateDependencyFloor)
    );
}

#[test]
fn reserve_put_ack_validation_rejects_digest_mutation_and_detaches_values() {
    let canonical = reserve_put_ack();
    let mut source = canonical.value().clone();
    assert_ne!(source.ack_blake3.as_ptr(), canonical.ack_blake3().as_ptr());
    source.policy_revision.push_str("-mutated");
    assert_ne!(canonical.value().policy_revision, source.policy_revision);

    let mut bad = canonical.value().clone();
    bad.ack_blake3 = OTHER_DIGEST.to_vec().into();
    assert_eq!(
        validate_and_encode_object_store_reserve_put_ack(
            &bad,
            &ReservePutAckLimits {
                max_identity_bytes: 256,
                max_durable_handle_bytes: 256,
                max_canonical_row_bytes: 16_384,
            },
        ),
        Err(ReservePutAckError::DigestMismatch)
    );
}

#[test]
fn compact_rejects_foreign_or_nonterminal_reserve_put_ack_authority() {
    let fixture = fixture(
        ObjectStoreCompactAuthority::RequestState(Box::new(expired_state())),
        no_dispatch_audit(),
    );
    let source = fixture.reserve_put_ack.as_ref().expect("PUT ACK fixture");
    let ack_limits = ReservePutAckLimits {
        max_identity_bytes: 256,
        max_durable_handle_bytes: 256,
        max_canonical_row_bytes: 16_384,
    };

    let mut foreign_value = source.value().clone();
    foreign_value.authenticated_tenant_id = "tenant-foreign".to_string();
    foreign_value.ack_blake3 = Default::default();
    let foreign = validate_and_encode_object_store_reserve_put_ack(&foreign_value, &ack_limits)
        .expect("foreign semantic ACK");
    let mut input = planner(&fixture);
    input.reserve_put_ack = Some(&foreign);
    assert_eq!(
        decide_object_store_compact_receipt(&input, &limits()),
        Err(CompactReceiptError::InvalidReservePutAck)
    );

    for state in [1, 2, 4] {
        let mut value = source.value().clone();
        value.state = state;
        value.payload_release_receipt = None;
        value.no_dispatch_proof = None;
        value.ack_blake3 = Default::default();
        if state == 2 {
            value.spool_ready = Some(PutSpoolReadyV1 {
                protocol_revision: value.protocol_revision.clone(),
                provider_boundary_id: value.provider_boundary_id.clone(),
                authenticated_cell_id: value.authenticated_cell_id.clone(),
                authenticated_tenant_id: value.authenticated_tenant_id.clone(),
                logical_request_id: value.logical_request_id.clone(),
                attempt_id: value.attempt_id.clone(),
                upload_id: value.upload_id.clone(),
                upload_fence: value.upload_fence,
                durable_body_handle: "put-body-1".to_string(),
                body_size: 64,
                body_blake3: DIGEST.to_vec().into(),
                ready_at_unix_ms: NOW - 5,
            });
        }
        if state == 4 {
            value.closure = Some(PutReservationClosureV1 {
                terminal_result_id: "terminal-1".to_string(),
                terminal_retryability: 2,
                result_disposition: 2,
                ack_receipt: None,
                discard_receipt: None,
                closed_at_unix_ms: NOW,
                closure_blake3: Default::default(),
            });
        }
        let nonterminal = validate_and_encode_object_store_reserve_put_ack(&value, &ack_limits)
            .expect("semantic nonterminal ACK");
        let mut state_input = planner(&fixture);
        state_input.reserve_put_ack = Some(&nonterminal);
        assert_eq!(
            decide_object_store_compact_receipt(&state_input, &limits()),
            Err(CompactReceiptError::InvalidReservePutAck),
            "state {state}"
        );
    }
}

fn direct_input<'a>(
    fixture: &'a Fixture,
    compact: &'a lore_object_dispatch::CanonicalObjectStoreCompactReceipt,
) -> ObjectStoreCompactReceiptInput<'a> {
    ObjectStoreCompactReceiptInput {
        authority: &fixture.authority,
        submit_receipt: &fixture.receipt,
        get_outcome: &fixture.outcome,
        admission_created_at_unix_ms: NOW - 50,
        reserve_put_ack: fixture.reserve_put_ack.as_ref(),
        provider_attempt_audit: &fixture.audit,
        dependency_floors: &[],
        closure_committed_at_unix_ms: NOW + 20,
        compacted_at_unix_ms: NOW + 50,
        compact_prune_after_unix_ms: NOW + 120,
        compaction_fingerprint: Some(compact.value().compaction_fingerprint),
        compact_blake3: Some(*compact.compact_blake3()),
    }
}

#[test]
fn direct_codec_rejects_missing_derived_floor_digests_wrappers_and_time_projection() {
    let primary = get_fixture();
    let ObjectStoreCompactReceiptDecision::ApplyCompaction { compact, .. } =
        decide_object_store_compact_receipt(&planner(&primary), &limits())
            .expect("baseline compaction")
    else {
        panic!("baseline must compact");
    };
    let mut input = direct_input(&primary, &compact);
    assert_eq!(
        validate_and_encode_object_store_compact_receipt(&input, &limits()),
        Err(CompactReceiptError::InvalidAuthorityProjection)
    );

    let floors: Vec<_> = compact
        .value()
        .dependency_floors
        .iter()
        .map(|floor| floor.value().clone())
        .collect();
    input.dependency_floors = &floors;
    let exact = validate_and_encode_object_store_compact_receipt(&input, &limits())
        .expect("exact direct compact");
    assert_eq!(exact.canonical_bytes(), compact.canonical_bytes());
    input.compaction_fingerprint = Some(OTHER_DIGEST);
    assert_eq!(
        validate_and_encode_object_store_compact_receipt(&input, &limits()),
        Err(CompactReceiptError::DigestMismatch)
    );
    input.compaction_fingerprint = Some(compact.value().compaction_fingerprint);
    input.compact_blake3 = Some(OTHER_DIGEST);
    assert_eq!(
        validate_and_encode_object_store_compact_receipt(&input, &limits()),
        Err(CompactReceiptError::DigestMismatch)
    );
    input.compact_blake3 = Some(*compact.compact_blake3());
    input.closure_committed_at_unix_ms += 1;
    assert_eq!(
        validate_and_encode_object_store_compact_receipt(&input, &limits()),
        Err(CompactReceiptError::InvalidTimeProjection)
    );

    let other = fixture(
        ObjectStoreCompactAuthority::RequestState(Box::new(terminal_state(
            StateKind::PutRetryable,
        ))),
        terminal_audit(),
    );
    let wrapper_mismatch = ObjectStoreCompactReceiptInput {
        authority: &primary.authority,
        submit_receipt: &other.receipt,
        get_outcome: &primary.outcome,
        admission_created_at_unix_ms: NOW - 50,
        reserve_put_ack: None,
        provider_attempt_audit: &primary.audit,
        dependency_floors: &floors,
        closure_committed_at_unix_ms: NOW + 20,
        compacted_at_unix_ms: NOW + 50,
        compact_prune_after_unix_ms: NOW + 120,
        compaction_fingerprint: None,
        compact_blake3: None,
    };
    assert_eq!(
        validate_and_encode_object_store_compact_receipt(&wrapper_mismatch, &limits()),
        Err(CompactReceiptError::WrapperMismatch)
    );
}

#[test]
fn partial_temp_and_invalid_payload_presence_are_rejected_before_compaction() {
    let state = terminal_state(StateKind::GetAcked);
    let mut partial = state.value().clone();
    partial.state_blake3 = Default::default();
    partial
        .result_payload
        .as_mut()
        .expect("result payload")
        .partial_temp_bytes = 1;
    assert!(validate_and_encode_object_store_request_state(&partial, &wire_limits()).is_err());

    let mut missing = state.value().clone();
    missing.state_blake3 = Default::default();
    missing.result_payload = None;
    assert!(validate_and_encode_object_store_request_state(&missing, &wire_limits()).is_err());
}
