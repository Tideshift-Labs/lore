// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Seam-parity coverage for CR-033's `request_state_wire.rs` -> `continuity_wire.rs` decoupling.
//!
//! Before the refactor, `request_state_wire.rs` imported `continuity_wire::{validate_and_encode_
//! continuity_quarantined, validate_and_encode_continuity_adjudicated}` directly. After it, the
//! exhaustive proto-oneof match lives behind `validate_and_encode_object_store_request_receipt_with`
//! / `..._outcome_with`, driven by an injected `ContinuityChildEncoders { quarantined, adjudicated }`
//! function-pointer pair. The old two-argument `validate_and_encode_object_store_request_receipt` /
//! `..._outcome` become thin wrappers (now defined in `continuity_wire.rs`, still exported at the
//! crate root) that pass `CONTINUITY_CHILD_ENCODERS`, the one real pair.
//!
//! `CheckedContinuityChild<T>` and `ContinuityChildEncoders` both seal their fields `pub(crate)`
//! after a reviewer finding: public fields would let any external caller frame arbitrary canonical
//! bytes and an arbitrary `latest_durable_time_unix_ms` into an envelope, reopening the
//! `InvalidTimeOrder`/continuity-validation contract the pre-refactor direct call graph made
//! structurally impossible. So this suite cannot construct a custom encoder pair -- it drives the
//! seam through the two exported pairs only: `CONTINUITY_CHILD_ENCODERS` (real) and
//! `ContinuityChildEncoders::UNAVAILABLE` (fails closed with `RequestStateWireError::Continuity`).
//!
//! This suite:
//! 1. Proves the seam is transparent: driving `_with` through `CONTINUITY_CHILD_ENCODERS`
//!    reproduces the exact pinned canonical bytes/digests already asserted for a `ContinuityQuarantined`
//!    and a `ContinuityAdjudicated` child (same literals as
//!    `tests/request_state_wire.rs::continuity_wrappers_pin_quarantine_and_adjudicated_tags_lengths_and_digests`,
//!    which this file does not edit), with full payload-and-order preimage vectors, not tag-only
//!    assertions -- covering receipt tags 4/5 and outcome tags 2/4.
//! 2. Proves the seam is actually a seam: `ContinuityChildEncoders::UNAVAILABLE` makes the
//!    receipt/outcome encode fail, surfacing `RequestStateWireError::Continuity` undisturbed.
//! 3. Proves the untouched `RequestState` arm (receipt/outcome tag 1) is unaffected by which
//!    encoder pair is passed: `_with` using `UNAVAILABLE` must still succeed and be byte-identical
//!    to the plain two-argument entry point on the same input, since tag 1 never calls either
//!    encoder.

use lore_object_dispatch::CONTINUITY_CHILD_ENCODERS;
use lore_object_dispatch::ContinuityChildEncoders;
use lore_object_dispatch::RequestStateWireError;
use lore_object_dispatch::RequestStateWireLimits;
use lore_object_dispatch::validate_and_encode_continuity_adjudicated;
use lore_object_dispatch::validate_and_encode_continuity_quarantined;
use lore_object_dispatch::validate_and_encode_object_store_request_outcome;
use lore_object_dispatch::validate_and_encode_object_store_request_outcome_with;
use lore_object_dispatch::validate_and_encode_object_store_request_receipt;
use lore_object_dispatch::validate_and_encode_object_store_request_receipt_with;
use lore_object_dispatch::validate_and_encode_object_store_request_state;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicatedV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicationKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicationProofV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityIntentKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuarantineReasonV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuarantinedV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuotaOwnershipV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuotaReleaseReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestOutcomeV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestPhaseV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDispositionV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalRetryabilityV1;
use lore_proto::lore::object_dispatch::v1::object_store_continuity_adjudicated_v1;
use lore_proto::lore::object_dispatch::v1::object_store_continuity_quarantined_v1;
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

fn limits() -> RequestStateWireLimits {
    RequestStateWireLimits {
        max_identity_bytes: 256,
        max_canonical_row_bytes: 16_384,
    }
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

fn variable(value: &[u8]) -> Vec<u8> {
    let mut output = (value.len() as u32).to_be_bytes().to_vec();
    output.extend_from_slice(value);
    output
}

fn quota(bytes: u64, rows: u64, concurrency: u64) -> ObjectStoreQuotaUnitsV1 {
    ObjectStoreQuotaUnitsV1 {
        bytes,
        rows,
        concurrency,
    }
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

/// Identical to `tests/request_state_wire.rs::quarantined`, kept as a private copy so this file has
/// no compile-time dependency on that file's internals.
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

/// Identical to `tests/request_state_wire.rs::adjudicated`, kept as a private copy for the same
/// reason as `quarantined` above.
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

/// Minimal PREPARED-phase state fixture: sufficient to drive the `RequestState` (tag 1) oneof arm
/// without duplicating the large multi-phase fixture table owned by `tests/request_state_wire.rs`.
fn minimal_prepared_state() -> ObjectStoreRequestStateV1 {
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
        allocation_fence: 1,
        cell_admission_id: None,
        cell_admission_fence: None,
        reservations: Vec::new(),
        dispatch_attempt: None,
        terminal_result: None,
        terminal_retryability: ObjectStoreTerminalRetryabilityV1::ObjectStoreTerminalRetryabilityNotApplicable
            as i32,
        result_disposition: ObjectStoreResultDispositionV1::ObjectStoreResultDispositionNotApplicable
            as i32,
        ack_receipt: None,
        discard_receipt: None,
        no_dispatch_proof: None,
        put_body: Some(lore_proto::lore::object_dispatch::v1::ObjectStorePayloadRetentionV1 {
            payload_kind: lore_proto::lore::object_dispatch::v1::ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody as i32,
            availability: lore_proto::lore::object_dispatch::v1::ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityNotApplicable as i32,
            durable_handle: None,
            size: 0,
            blake3: Default::default(),
            purge_state: lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateNotEligible as i32,
            purge_eligible_at_unix_ms: None,
            purge_receipt: None,
            partial_temp_bytes: 0,
            partial_temp_chunks: 0,
        }),
        result_payload: Some(lore_proto::lore::object_dispatch::v1::ObjectStorePayloadRetentionV1 {
            payload_kind: lore_proto::lore::object_dispatch::v1::ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult as i32,
            availability: lore_proto::lore::object_dispatch::v1::ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityNotApplicable as i32,
            durable_handle: None,
            size: 0,
            blake3: Default::default(),
            purge_state: lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateNotEligible as i32,
            purge_eligible_at_unix_ms: None,
            purge_receipt: None,
            partial_temp_bytes: 0,
            partial_temp_chunks: 0,
        }),
        quota_state: Some(lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaStateV1 {
            provider_reservations: Vec::new(),
            put_spool_quota: Some(quota(0, 0, 0)),
            result_spool_quota: Some(quota(0, 0, 0)),
            retained_metadata_quota: Some(quota(0, 0, 0)),
            quota_revision: 1,
        }),
        state_committed_at_unix_ms: NOW,
        closure_committed_at_unix_ms: None,
        policy_revision: "policy-1".to_string(),
        put_submit_binding: None,
        state_blake3: Default::default(),
    }
}

#[test]
fn with_real_encoders_reproduces_pinned_quarantine_and_adjudicated_goldens() {
    let quarantine = validate_and_encode_continuity_quarantined(&quarantined(), &limits())
        .expect("quarantine fixture must validate");
    let adjudicated_child = validate_and_encode_continuity_adjudicated(&adjudicated(), &limits())
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
            quarantine.canonical_bytes().to_vec(),
            612_usize,
            "4246e0482e80cee40ba070ff81161e044fb542de6d9373328503a65a9e9a870e",
            604_usize,
            "3eec007dae1dd4d98742d0df78b7c8185dfb8dcfd0f3636517881d9268670625",
        ),
        (
            object_store_request_receipt_v1::Outcome::ContinuityAdjudicated(Box::new(
                adjudicated_child.value().clone(),
            )),
            object_store_request_outcome_v1::Outcome::ContinuityAdjudicated(Box::new(
                adjudicated_child.value().clone(),
            )),
            5_u32,
            4_u32,
            adjudicated_child.canonical_bytes().to_vec(),
            1_252_usize,
            "585b0b7e5db15cb8fc07fd12d72cbaefec901b8920fa08af4af9ddc8b5b6ba88",
            1_244_usize,
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

        let receipt = validate_and_encode_object_store_request_receipt_with(
            &receipt_input,
            &limits(),
            &CONTINUITY_CHILD_ENCODERS,
        )
        .expect("continuity receipt via the seam must validate");
        let outcome = validate_and_encode_object_store_request_outcome_with(
            &outcome_input,
            &limits(),
            &CONTINUITY_CHILD_ENCODERS,
        )
        .expect("continuity outcome via the seam must validate");

        let mut receipt_preimage = b"object-store-request-receipt-v1\0".to_vec();
        receipt_preimage.extend_from_slice(&receipt_tag.to_be_bytes());
        receipt_preimage.extend(variable(&child_bytes));
        receipt_preimage.extend_from_slice(&((NOW + 1_001) as u64).to_be_bytes());
        let mut outcome_preimage = b"object-store-request-outcome-v1\0".to_vec();
        outcome_preimage.extend_from_slice(&outcome_tag.to_be_bytes());
        outcome_preimage.extend(variable(&child_bytes));

        assert_eq!(receipt.canonical_preimage(), receipt_preimage);
        assert_eq!(receipt.canonical_bytes().len(), receipt_length);
        assert_eq!(receipt.receipt_blake3(), &decode_digest(receipt_digest));
        assert_eq!(outcome.canonical_preimage(), outcome_preimage);
        assert_eq!(outcome.canonical_bytes().len(), outcome_length);
        assert_eq!(outcome.outcome_blake3(), &decode_digest(outcome_digest));

        // The public two-argument entry points (still exact crate-root paths) must agree exactly
        // with driving the same input through the seam and the real encoders.
        let legacy_receipt =
            validate_and_encode_object_store_request_receipt(&receipt_input, &limits())
                .expect("legacy two-arg receipt must validate");
        let legacy_outcome =
            validate_and_encode_object_store_request_outcome(&outcome_input, &limits())
                .expect("legacy two-arg outcome must validate");
        assert_eq!(legacy_receipt.canonical_bytes(), receipt.canonical_bytes());
        assert_eq!(legacy_outcome.canonical_bytes(), outcome.canonical_bytes());
    }
}

#[test]
fn failing_injected_encoder_surfaces_as_continuity_error_for_both_child_kinds() {
    let receipt_quarantined = ObjectStoreRequestReceiptV1 {
        receipt_blake3: Default::default(),
        receipt_committed_at_unix_ms: NOW + 1_001,
        outcome: Some(
            object_store_request_receipt_v1::Outcome::ContinuityQuarantined(
                Box::new(quarantined()),
            ),
        ),
    };
    let receipt_adjudicated = ObjectStoreRequestReceiptV1 {
        receipt_blake3: Default::default(),
        receipt_committed_at_unix_ms: NOW + 1_001,
        outcome: Some(
            object_store_request_receipt_v1::Outcome::ContinuityAdjudicated(
                Box::new(adjudicated()),
            ),
        ),
    };
    let outcome_quarantined = ObjectStoreRequestOutcomeV1 {
        outcome_blake3: Default::default(),
        outcome: Some(
            object_store_request_outcome_v1::Outcome::ContinuityQuarantined(
                Box::new(quarantined()),
            ),
        ),
    };
    let outcome_adjudicated = ObjectStoreRequestOutcomeV1 {
        outcome_blake3: Default::default(),
        outcome: Some(
            object_store_request_outcome_v1::Outcome::ContinuityAdjudicated(
                Box::new(adjudicated()),
            ),
        ),
    };

    assert_eq!(
        validate_and_encode_object_store_request_receipt_with(
            &receipt_quarantined,
            &limits(),
            &ContinuityChildEncoders::UNAVAILABLE,
        ),
        Err(RequestStateWireError::Continuity)
    );
    assert_eq!(
        validate_and_encode_object_store_request_receipt_with(
            &receipt_adjudicated,
            &limits(),
            &ContinuityChildEncoders::UNAVAILABLE,
        ),
        Err(RequestStateWireError::Continuity)
    );
    assert_eq!(
        validate_and_encode_object_store_request_outcome_with(
            &outcome_quarantined,
            &limits(),
            &ContinuityChildEncoders::UNAVAILABLE,
        ),
        Err(RequestStateWireError::Continuity)
    );
    assert_eq!(
        validate_and_encode_object_store_request_outcome_with(
            &outcome_adjudicated,
            &limits(),
            &ContinuityChildEncoders::UNAVAILABLE,
        ),
        Err(RequestStateWireError::Continuity)
    );

    // Positive control in the same fixture set: the real encoders must still succeed on the exact
    // same inputs, proving the failure above comes from the injected encoder, not the fixture.
    assert!(
        validate_and_encode_object_store_request_receipt_with(
            &receipt_quarantined,
            &limits(),
            &CONTINUITY_CHILD_ENCODERS,
        )
        .is_ok()
    );
    assert!(
        validate_and_encode_object_store_request_outcome_with(
            &outcome_adjudicated,
            &limits(),
            &CONTINUITY_CHILD_ENCODERS,
        )
        .is_ok()
    );
}

#[test]
fn request_state_arm_is_unaffected_by_encoder_injection() {
    let state =
        validate_and_encode_object_store_request_state(&minimal_prepared_state(), &limits())
            .expect("minimal PREPARED fixture must validate");

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

    let legacy_receipt =
        validate_and_encode_object_store_request_receipt(&receipt_input, &limits())
            .expect("legacy two-arg receipt must validate");
    let legacy_outcome =
        validate_and_encode_object_store_request_outcome(&outcome_input, &limits())
            .expect("legacy two-arg outcome must validate");

    // Tag 1 (RequestState) never calls either injected encoder, so even the deliberately failing
    // pair must not affect it -- the exhaustive match must only reach `quarantined`/`adjudicated`
    // for their own oneof arms.
    let seam_receipt = validate_and_encode_object_store_request_receipt_with(
        &receipt_input,
        &limits(),
        &ContinuityChildEncoders::UNAVAILABLE,
    )
    .expect(
        "RequestState receipt via the seam must validate even with failing continuity encoders",
    );
    let seam_outcome = validate_and_encode_object_store_request_outcome_with(
        &outcome_input,
        &limits(),
        &ContinuityChildEncoders::UNAVAILABLE,
    )
    .expect(
        "RequestState outcome via the seam must validate even with failing continuity encoders",
    );

    assert_eq!(
        seam_receipt.canonical_bytes(),
        legacy_receipt.canonical_bytes()
    );
    assert_eq!(
        seam_receipt.receipt_blake3(),
        legacy_receipt.receipt_blake3()
    );
    assert_eq!(
        seam_outcome.canonical_bytes(),
        legacy_outcome.canonical_bytes()
    );
    assert_eq!(
        seam_outcome.outcome_blake3(),
        legacy_outcome.outcome_blake3()
    );

    let mut receipt_preimage = b"object-store-request-receipt-v1\0".to_vec();
    receipt_preimage.extend_from_slice(&1_u32.to_be_bytes());
    receipt_preimage.extend(variable(state.canonical_bytes()));
    receipt_preimage.extend_from_slice(&((NOW + 1) as u64).to_be_bytes());
    assert_eq!(seam_receipt.canonical_preimage(), receipt_preimage);

    let mut outcome_preimage = b"object-store-request-outcome-v1\0".to_vec();
    outcome_preimage.extend_from_slice(&1_u32.to_be_bytes());
    outcome_preimage.extend(variable(state.canonical_bytes()));
    assert_eq!(seam_outcome.canonical_preimage(), outcome_preimage);
}
