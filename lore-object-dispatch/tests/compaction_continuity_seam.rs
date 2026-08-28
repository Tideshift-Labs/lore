// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Compact-authority record parity for CR-033's `compaction.rs`/`full_to_compact.rs` decoupling
//! from `continuity_wire`.
//!
//! Before the refactor, `ObjectStoreCompactAuthority::ContinuityQuarantined`/`ContinuityAdjudicated`
//! boxed `continuity_wire::CanonicalContinuityQuarantined`/`CanonicalContinuityAdjudicated` directly.
//! After it, those variants carry a compaction-owned `ObjectStoreCompactContinuityAuthority<T>` built
//! via `From<&CanonicalContinuityQuarantined>`/`From<&CanonicalContinuityAdjudicated>` impls that live
//! in `continuity_wire.rs`. This suite proves that going through the new `From` construction path
//! reproduces the exact same compact-receipt canonical bytes and BLAKE3 fingerprint already pinned by
//! `tests/compaction.rs::final_continuity_adjudication_compacts_with_automatic_floor` (owned by the
//! main session; not edited here) -- i.e. that the accessor-compatible replacement record type carries
//! forward byte-identical authority into the compaction pipeline, including the frozen `Continuity`
//! dependency-floor wire code (5), which is baked into the pinned digest below.
//!
//! `compaction.rs`, `full_to_compact.rs`, and their own `tests/compaction.rs`/`tests/full_to_compact.rs`
//! are out of scope for this file; it duplicates only the minimal fixture plumbing needed to drive the
//! public `decide_object_store_compact_receipt` entry point independently.

use lore_object_dispatch::ContinuityWireLimits;
use lore_object_dispatch::NoDispatchProofFields;
use lore_object_dispatch::NoDispatchReason;
use lore_object_dispatch::ObjectStoreCompactAuthority;
use lore_object_dispatch::ObjectStoreCompactDependencyFloorKind;
use lore_object_dispatch::ObjectStoreCompactReceiptDecision;
use lore_object_dispatch::ObjectStoreCompactReceiptLimits;
use lore_object_dispatch::ObjectStoreCompactReceiptPlannerInput;
use lore_object_dispatch::ObjectStoreProviderAttemptAudit;
use lore_object_dispatch::ReservePutAckLimits;
use lore_object_dispatch::build_no_dispatch_proof;
use lore_object_dispatch::decide_object_store_compact_receipt;
use lore_object_dispatch::validate_and_encode_continuity_adjudicated;
use lore_object_dispatch::validate_and_encode_continuity_quarantined;
use lore_object_dispatch::validate_and_encode_object_store_request_outcome;
use lore_object_dispatch::validate_and_encode_object_store_request_receipt;
use lore_object_dispatch::validate_and_encode_object_store_reserve_put_ack;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicatedV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicationKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicationProofV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityIntentKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuotaOwnershipV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuotaReleaseReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreNoDispatchProofV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestOutcomeV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestReceiptV1;
use lore_proto::lore::object_dispatch::v1::ReservePutAckV1;
use lore_proto::lore::object_dispatch::v1::object_store_continuity_adjudicated_v1;
use lore_proto::lore::object_dispatch::v1::object_store_request_outcome_v1;
use lore_proto::lore::object_dispatch::v1::object_store_request_receipt_v1;

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

/// Byte-for-byte identical to `tests/compaction.rs::final_continuity_adjudication_compacts_with_automatic_floor`'s
/// pinned golden. Not derived from that file at runtime -- copied as a literal so this suite fails
/// independently if either the fixture or the encoding drifts.
const PINNED_ADJUDICATED_COMPACT_LEN: usize = 5_105;
const PINNED_ADJUDICATED_COMPACT_DIGEST: &str =
    "8e96074a7ca6cee392f89853607b7897c5171da8b7b6fe8fef62bfcd5eddaff0";

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

fn wire_limits() -> ContinuityWireLimits {
    ContinuityWireLimits {
        max_identity_bytes: 256,
        max_canonical_row_bytes: 16_384,
    }
}

fn quota(bytes: u64, rows: u64, concurrency: u64) -> ObjectStoreQuotaUnitsV1 {
    ObjectStoreQuotaUnitsV1 {
        bytes,
        rows,
        concurrency,
    }
}

/// Identical to `tests/compaction.rs::reserve_put_ack`, kept as a private copy for the same reason
/// as `adjudicated_value` above. The pinned adjudicated-authority golden was built against a fixture
/// whose fingerprint is `PutReservationFingerprint`, which makes `is_put` true and requires a PUT
/// ReservePut ACK to be present -- without it, compaction planning fails closed with
/// `InvalidReservePutAck` before it ever reaches continuity-authority handling.
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

/// Identical fixture to `tests/compaction.rs::adjudicated_authority`, kept as a private copy so this
/// file has no compile-time dependency on that file's internals.
fn adjudicated_value(
    kind: ObjectStoreContinuityAdjudicationKindV1,
) -> ObjectStoreContinuityAdjudicatedV1 {
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
            provider_no_dispatch_evidence_blake3: (kind
                == ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch)
                .then(|| vec![0x77; 32].into()),
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
    }
}

#[test]
fn from_canonical_continuity_adjudicated_authority_reproduces_pinned_compact_golden() {
    let canonical = validate_and_encode_continuity_adjudicated(
        &adjudicated_value(
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
        ),
        &wire_limits(),
    )
    .expect("adjudicated fixture must validate");

    // The seam under test: construct the compact authority through the new conversion instead of
    // reaching into `compaction.rs` to box the canonical record directly.
    let authority: ObjectStoreCompactAuthority = ObjectStoreCompactAuthority::from(&canonical);

    let receipt_outcome = object_store_request_receipt_v1::Outcome::ContinuityAdjudicated(
        Box::new(canonical.value().clone()),
    );
    let get_outcome = object_store_request_outcome_v1::Outcome::ContinuityAdjudicated(Box::new(
        canonical.value().clone(),
    ));
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

    let audit = ObjectStoreProviderAttemptAudit {
        attempt_count: 0,
        committed_grant_count: 0,
        no_dispatch_count: 0,
        decisive_terminal_count: 0,
        ambiguous_count: 0,
        provider_authority_refunded: false,
        audit_blake3: None,
    };

    let ack = reserve_put_ack();
    let planner_input = ObjectStoreCompactReceiptPlannerInput {
        authority: &authority,
        submit_receipt: &receipt,
        get_outcome: &outcome,
        admission_created_at_unix_ms: NOW - 50,
        reserve_put_ack: Some(&ack),
        provider_attempt_audit: &audit,
        trusted_dependency_floors: None,
        database_now_unix_ms: NOW + 50,
        existing_compact: None,
    };

    let decision = decide_object_store_compact_receipt(&planner_input, &limits())
        .expect("adjudicated decision");
    let ObjectStoreCompactReceiptDecision::ApplyCompaction { compact, .. } = decision else {
        panic!("adjudicated authority must compact");
    };

    assert_eq!(compact.value().dependency_floors.len(), 1);
    assert_eq!(
        compact.value().dependency_floors[0].value().kind,
        ObjectStoreCompactDependencyFloorKind::Continuity
    );
    assert_eq!(
        compact.value().dependency_floors[0]
            .value()
            .retain_until_unix_ms,
        NOW + 110
    );
    assert_eq!(
        compact.canonical_bytes().len(),
        PINNED_ADJUDICATED_COMPACT_LEN
    );
    assert_eq!(
        compact.compact_blake3(),
        decode_hex(PINNED_ADJUDICATED_COMPACT_DIGEST).as_slice()
    );
}

#[test]
fn from_canonical_continuity_quarantined_authority_round_trips_through_compact_authority_debug() {
    // A lighter parity check for the Quarantined arm: the `From` conversion must preserve the exact
    // canonical bytes minted by `validate_and_encode_continuity_quarantined`, independent of whatever
    // internal record shape `compaction.rs` now wraps them in.
    use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuarantineReasonV1;
    use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuarantinedV1;
    use lore_proto::lore::object_dispatch::v1::object_store_continuity_quarantined_v1;

    let value = ObjectStoreContinuityQuarantinedV1 {
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
        reason:
            ObjectStoreContinuityQuarantineReasonV1::ObjectStoreContinuityQuarantineReasonIncompleteIntent
                as i32,
        quarantined_at_unix_ms: NOW,
        retain_until_unix_ms: NOW + 100,
        quota_bearing: true,
        detail_blake3: Default::default(),
        quota_ownership: Some(ObjectStoreContinuityQuotaOwnershipV1 {
            continuity_policy_revision: "policy-1".to_string(),
            operation_quota_class: "PUT".to_string(),
            units: Some(quota(1, 1, 1)),
            global_scope_id: "object-store-continuity-global-v1".to_string(),
            provider_boundary_id: "boundary-1".to_string(),
            authenticated_cell_id: "cell-1".to_string(),
            authenticated_tenant_id: "tenant-1".to_string(),
            ownership_blake3: Default::default(),
        }),
        fingerprint: Some(
            object_store_continuity_quarantined_v1::Fingerprint::PutReservationFingerprint(
                DIGEST.to_vec().into(),
            ),
        ),
    };
    let canonical = validate_and_encode_continuity_quarantined(&value, &wire_limits())
        .expect("quarantined fixture must validate");
    let expected_bytes = canonical.canonical_bytes().to_vec();
    let expected_digest = *canonical.detail_blake3();

    let authority: ObjectStoreCompactAuthority = ObjectStoreCompactAuthority::from(&canonical);
    let ObjectStoreCompactAuthority::ContinuityQuarantined(child) = &authority else {
        panic!("From<&CanonicalContinuityQuarantined> must produce the Quarantined variant");
    };
    assert_eq!(child.canonical_bytes(), expected_bytes.as_slice());
    assert_eq!(child.detail_blake3(), &expected_digest);
    assert_eq!(child.value(), canonical.value());
}
