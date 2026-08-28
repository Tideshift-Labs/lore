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

fn wire_limits() -> ContinuityWireLimits {
    ContinuityWireLimits {
        max_identity_bytes: 256,
        max_canonical_row_bytes: 16_384,
    }
}

fn reserve_put_ack_fixture() -> CanonicalObjectStoreReservePutAck {
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
            reserved_quota: Some(ObjectStoreQuotaUnitsV1 {
                bytes: 64,
                rows: 1,
                concurrency: 1,
            }),
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

fn quota(bytes: u64, rows: u64, concurrency: u64) -> ObjectStoreQuotaUnitsV1 {
    ObjectStoreQuotaUnitsV1 {
        bytes,
        rows,
        concurrency,
    }
}

pub fn compact_plan() -> ObjectStoreCompactReceiptDecision {
    let kind =
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect;
    let authority_value = ObjectStoreContinuityAdjudicatedV1 {
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
            released_put_spool: Some(quota(1, 1, 1)),
            released_result_spool: Some(quota(0, 0, 0)),
            released_retained_metadata: Some(quota(0, 0, 0)),
            provider_authority_refunded: false,
            released_at_unix_ms: NOW + 2,
            quota_revision: 8,
            receipt_blake3: Default::default(),
        }),
        adjudicated_at_unix_ms: NOW + 20,
        retain_until_unix_ms: NOW + 110,
        detail_blake3: Default::default(),
        quota_ownership: Some(ObjectStoreContinuityQuotaOwnershipV1 {
            continuity_policy_revision: "continuity-policy-1".to_string(),
            operation_quota_class: "PUT".to_string(),
            units: Some(quota(1, 1, 1)),
            global_scope_id: "object-store-continuity-global-v1".to_string(),
            provider_boundary_id: "boundary-1".to_string(),
            authenticated_cell_id: "cell-1".to_string(),
            authenticated_tenant_id: "tenant-1".to_string(),
            ownership_blake3: Default::default(),
        }),
        fingerprint: Some(
            object_store_continuity_adjudicated_v1::Fingerprint::PutReservationFingerprint(
                DIGEST.to_vec().into(),
            ),
        ),
    };
    let authority = ObjectStoreCompactAuthority::from(
        &validate_and_encode_continuity_adjudicated(&authority_value, &wire_limits())
            .expect("adjudicated authority"),
    );
    let ObjectStoreCompactAuthority::ContinuityAdjudicated(encoded) = &authority else {
        unreachable!("adjudicated authority")
    };
    let receipt = validate_and_encode_object_store_request_receipt(
        &ObjectStoreRequestReceiptV1 {
            receipt_blake3: Default::default(),
            receipt_committed_at_unix_ms: NOW + 20,
            outcome: Some(
                object_store_request_receipt_v1::Outcome::ContinuityAdjudicated(Box::new(
                    encoded.value().clone(),
                )),
            ),
        },
        &wire_limits(),
    )
    .expect("adjudicated receipt");
    let outcome = validate_and_encode_object_store_request_outcome(
        &ObjectStoreRequestOutcomeV1 {
            outcome_blake3: Default::default(),
            outcome: Some(
                object_store_request_outcome_v1::Outcome::ContinuityAdjudicated(Box::new(
                    encoded.value().clone(),
                )),
            ),
        },
        &wire_limits(),
    )
    .expect("adjudicated outcome");
    let reserve_put_ack = reserve_put_ack_fixture();
    decide_object_store_compact_receipt(
        &ObjectStoreCompactReceiptPlannerInput {
            authority: &authority,
            submit_receipt: &receipt,
            get_outcome: &outcome,
            admission_created_at_unix_ms: NOW - 50,
            reserve_put_ack: Some(&reserve_put_ack),
            provider_attempt_audit: &ObjectStoreProviderAttemptAudit {
                attempt_count: 0,
                committed_grant_count: 0,
                no_dispatch_count: 0,
                decisive_terminal_count: 0,
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
    .expect("adjudicated compact plan")
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
