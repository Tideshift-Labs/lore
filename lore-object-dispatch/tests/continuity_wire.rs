// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::ContinuityWireLimits;
use lore_object_dispatch::validate_and_encode_continuity_adjudicated;
use lore_object_dispatch::validate_and_encode_continuity_adjudication_proof;
use lore_object_dispatch::validate_and_encode_continuity_quarantined;
use lore_object_dispatch::validate_and_encode_continuity_quota_release_receipt;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicatedV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicationKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicationProofV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityIntentKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuarantineReasonV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuarantinedV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuotaOwnershipV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuotaReleaseReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::object_store_continuity_adjudicated_v1;
use lore_proto::lore::object_dispatch::v1::object_store_continuity_quarantined_v1;

const NOW: i64 = 0x018f_3e12_a456;
const REQUEST_ID: &str = "018f3e12-a450-7abc-8def-0123456789ab";
const ATTEMPT_ID: &str = "018f3e12-a451-7abc-8def-0123456789ab";
const TOKEN_ID: &str = "018f3e12-a452-7abc-8def-0123456789ab";
const PROOF_ID: &str = "018f3e12-a453-7abc-8def-0123456789ab";
const RELEASE_ID: &str = "018f3e12-a454-7abc-8def-0123456789ab";
const DIGEST: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const OTHER_DIGEST: [u8; 32] = [
    255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240, 239, 238, 237,
    236, 235, 234, 233, 232, 231, 230, 229, 228, 227, 226, 225, 224,
];
const THIRD_DIGEST: [u8; 32] = [0x5a; 32];

fn limits() -> ContinuityWireLimits {
    ContinuityWireLimits {
        max_identity_bytes: 256,
        max_canonical_row_bytes: 8_192,
    }
}

fn append_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn append_nested(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn append_quota_units(bytes: &mut Vec<u8>, units: &ObjectStoreQuotaUnitsV1) {
    bytes.extend_from_slice(&units.bytes.to_be_bytes());
    bytes.extend_from_slice(&units.rows.to_be_bytes());
    bytes.extend_from_slice(&units.concurrency.to_be_bytes());
}

fn quota_units_record(units: &ObjectStoreQuotaUnitsV1) -> Vec<u8> {
    let mut preimage = b"object-store-quota-units-v1\0".to_vec();
    append_quota_units(&mut preimage, units);
    complete_record(&preimage)
}

fn complete_record(preimage: &[u8]) -> Vec<u8> {
    let mut bytes = preimage.to_vec();
    bytes.extend_from_slice(blake3::hash(preimage).as_bytes());
    bytes
}

fn ownership() -> ObjectStoreContinuityQuotaOwnershipV1 {
    ObjectStoreContinuityQuotaOwnershipV1 {
        continuity_policy_revision: "continuity-policy-1".to_string(),
        operation_quota_class: "PUT".to_string(),
        units: Some(ObjectStoreQuotaUnitsV1 {
            bytes: 125,
            rows: 4,
            concurrency: 1,
        }),
        global_scope_id: "object-store-continuity-global-v1".to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        ownership_blake3: Default::default(),
    }
}

fn ownership_preimage() -> Vec<u8> {
    let input = ownership();
    let mut bytes = b"object-store-continuity-quota-ownership-v1\0".to_vec();
    append_text(&mut bytes, &input.continuity_policy_revision);
    append_text(&mut bytes, &input.operation_quota_class);
    append_quota_units(&mut bytes, input.units.as_ref().expect("fixture units"));
    append_text(&mut bytes, &input.global_scope_id);
    append_text(&mut bytes, &input.provider_boundary_id);
    append_text(&mut bytes, &input.authenticated_cell_id);
    append_text(&mut bytes, &input.authenticated_tenant_id);
    bytes
}

fn quarantine() -> ObjectStoreContinuityQuarantinedV1 {
    ObjectStoreContinuityQuarantinedV1 {
        protocol_revision: "object-dispatch-v1".to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        logical_request_id: REQUEST_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        continuity_token_id: TOKEN_ID.to_string(),
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
        quota_ownership: Some(ownership()),
        fingerprint: Some(
            object_store_continuity_quarantined_v1::Fingerprint::PutReservationFingerprint(
                DIGEST.to_vec().into(),
            ),
        ),
    }
}

fn quarantine_preimage() -> Vec<u8> {
    let input = quarantine();
    let mut bytes = b"object-store-continuity-quarantined-v1\0".to_vec();
    append_text(&mut bytes, &input.protocol_revision);
    append_text(&mut bytes, &input.provider_boundary_id);
    append_text(&mut bytes, &input.authenticated_cell_id);
    append_text(&mut bytes, &input.authenticated_tenant_id);
    append_text(&mut bytes, &input.logical_request_id);
    append_text(&mut bytes, &input.attempt_id);
    append_text(&mut bytes, &input.continuity_token_id);
    bytes.extend_from_slice(&input.authority_epoch.to_be_bytes());
    bytes.extend_from_slice(&input.continuity_seq.to_be_bytes());
    bytes.extend_from_slice(&(input.intent_kind as u32).to_be_bytes());
    bytes.extend_from_slice(&11_u32.to_be_bytes());
    bytes.extend_from_slice(&DIGEST);
    bytes.extend_from_slice(&(input.reason as u32).to_be_bytes());
    bytes.extend_from_slice(&(input.quarantined_at_unix_ms as u64).to_be_bytes());
    bytes.extend_from_slice(&(input.retain_until_unix_ms as u64).to_be_bytes());
    bytes.push(1);
    append_nested(&mut bytes, &complete_record(&ownership_preimage()));
    bytes
}

fn proof(
    kind: ObjectStoreContinuityAdjudicationKindV1,
) -> ObjectStoreContinuityAdjudicationProofV1 {
    ObjectStoreContinuityAdjudicationProofV1 {
        proof_id: PROOF_ID.to_string(),
        adjudication_kind: kind as i32,
        external_row_blake3: DIGEST.to_vec().into(),
        local_quarantine_blake3: OTHER_DIGEST.to_vec().into(),
        authority_epoch: 7,
        continuity_seq: 11,
        adjudication_fence: 3,
        provider_credential_revision: "credential-9".to_string(),
        provider_no_dispatch_evidence_blake3: (kind
            == ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch)
            .then(|| THIRD_DIGEST.to_vec().into()),
        committed_at_unix_ms: NOW + 1,
        proof_blake3: Default::default(),
    }
}

fn proof_preimage(input: &ObjectStoreContinuityAdjudicationProofV1) -> Vec<u8> {
    let mut bytes = b"object-store-continuity-adjudication-proof-v1\0".to_vec();
    append_text(&mut bytes, &input.proof_id);
    bytes.extend_from_slice(&(input.adjudication_kind as u32).to_be_bytes());
    bytes.extend_from_slice(&input.external_row_blake3);
    bytes.extend_from_slice(&input.local_quarantine_blake3);
    bytes.extend_from_slice(&input.authority_epoch.to_be_bytes());
    bytes.extend_from_slice(&input.continuity_seq.to_be_bytes());
    bytes.extend_from_slice(&input.adjudication_fence.to_be_bytes());
    append_text(&mut bytes, &input.provider_credential_revision);
    match &input.provider_no_dispatch_evidence_blake3 {
        Some(digest) => {
            bytes.push(1);
            bytes.extend_from_slice(digest);
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&(input.committed_at_unix_ms as u64).to_be_bytes());
    bytes
}

fn release(
    kind: ObjectStoreContinuityAdjudicationKindV1,
) -> ObjectStoreContinuityQuotaReleaseReceiptV1 {
    ObjectStoreContinuityQuotaReleaseReceiptV1 {
        release_id: RELEASE_ID.to_string(),
        adjudication_kind: kind as i32,
        released_put_spool: Some(ObjectStoreQuotaUnitsV1 {
            bytes: 100,
            rows: 1,
            concurrency: 1,
        }),
        released_result_spool: Some(ObjectStoreQuotaUnitsV1 {
            bytes: 20,
            rows: 1,
            concurrency: 0,
        }),
        released_retained_metadata: Some(ObjectStoreQuotaUnitsV1 {
            bytes: 5,
            rows: 2,
            concurrency: 0,
        }),
        provider_authority_refunded: false,
        released_at_unix_ms: NOW + 2,
        quota_revision: 8,
        receipt_blake3: Default::default(),
    }
}

fn release_preimage(input: &ObjectStoreContinuityQuotaReleaseReceiptV1) -> Vec<u8> {
    let mut bytes = b"object-store-continuity-quota-release-v1\0".to_vec();
    append_text(&mut bytes, &input.release_id);
    bytes.extend_from_slice(&(input.adjudication_kind as u32).to_be_bytes());
    for units in [
        input
            .released_put_spool
            .as_ref()
            .expect("fixture PUT units"),
        input
            .released_result_spool
            .as_ref()
            .expect("fixture result units"),
        input
            .released_retained_metadata
            .as_ref()
            .expect("fixture metadata units"),
    ] {
        append_nested(&mut bytes, &quota_units_record(units));
    }
    bytes.push(u8::from(input.provider_authority_refunded));
    bytes.extend_from_slice(&(input.released_at_unix_ms as u64).to_be_bytes());
    bytes.extend_from_slice(&input.quota_revision.to_be_bytes());
    bytes
}

fn adjudicated(
    kind: ObjectStoreContinuityAdjudicationKindV1,
) -> ObjectStoreContinuityAdjudicatedV1 {
    ObjectStoreContinuityAdjudicatedV1 {
        protocol_revision: "object-dispatch-v1".to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        logical_request_id: REQUEST_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        continuity_token_id: TOKEN_ID.to_string(),
        authority_epoch: 7,
        continuity_seq: 11,
        intent_kind: ObjectStoreContinuityIntentKindV1::ObjectStoreContinuityIntentKindUuidAdmission
            as i32,
        adjudication_kind: kind as i32,
        proof: Some(proof(kind)),
        quota_release_receipt: Some(release(kind)),
        adjudicated_at_unix_ms: NOW + 3,
        retain_until_unix_ms: NOW + 1_000,
        detail_blake3: Default::default(),
        quota_ownership: Some(ownership()),
        fingerprint: Some(
            object_store_continuity_adjudicated_v1::Fingerprint::PutReservationFingerprint(
                DIGEST.to_vec().into(),
            ),
        ),
    }
}

fn adjudicated_preimage(input: &ObjectStoreContinuityAdjudicatedV1) -> Vec<u8> {
    let mut bytes = b"object-store-continuity-adjudicated-v1\0".to_vec();
    append_text(&mut bytes, &input.protocol_revision);
    append_text(&mut bytes, &input.provider_boundary_id);
    append_text(&mut bytes, &input.authenticated_cell_id);
    append_text(&mut bytes, &input.authenticated_tenant_id);
    append_text(&mut bytes, &input.logical_request_id);
    append_text(&mut bytes, &input.attempt_id);
    append_text(&mut bytes, &input.continuity_token_id);
    bytes.extend_from_slice(&input.authority_epoch.to_be_bytes());
    bytes.extend_from_slice(&input.continuity_seq.to_be_bytes());
    bytes.extend_from_slice(&(input.intent_kind as u32).to_be_bytes());
    match input.fingerprint.as_ref().expect("fixture fingerprint") {
        object_store_continuity_adjudicated_v1::Fingerprint::PutReservationFingerprint(digest) => {
            bytes.extend_from_slice(&11_u32.to_be_bytes());
            bytes.extend_from_slice(digest);
        }
        object_store_continuity_adjudicated_v1::Fingerprint::CanonicalDescriptorFingerprint(
            digest,
        ) => {
            bytes.extend_from_slice(&12_u32.to_be_bytes());
            bytes.extend_from_slice(digest);
        }
    }
    bytes.extend_from_slice(&(input.adjudication_kind as u32).to_be_bytes());
    append_nested(
        &mut bytes,
        &complete_record(&proof_preimage(
            input.proof.as_ref().expect("fixture proof"),
        )),
    );
    append_nested(
        &mut bytes,
        &complete_record(&release_preimage(
            input
                .quota_release_receipt
                .as_ref()
                .expect("fixture release"),
        )),
    );
    bytes.extend_from_slice(&(input.adjudicated_at_unix_ms as u64).to_be_bytes());
    bytes.extend_from_slice(&(input.retain_until_unix_ms as u64).to_be_bytes());
    append_nested(&mut bytes, &complete_record(&ownership_preimage()));
    bytes
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

#[test]
fn quarantine_pins_cross_language_preimage_digest_boolean_and_nested_ownership() {
    let expected_preimage = quarantine_preimage();
    let expected_digest =
        decode_digest("94eb308ebe67969be1772c585a9a25218100b97563ef9d22723cd772ba9e6cc2");
    let encoded = validate_and_encode_continuity_quarantined(&quarantine(), &limits())
        .expect("reference quarantine must validate");

    assert_eq!(encoded.canonical_preimage(), expected_preimage);
    assert_eq!(encoded.detail_blake3(), &expected_digest);
    assert_eq!(
        encoded.canonical_bytes(),
        complete_record(&expected_preimage)
    );
    assert_eq!(encoded.canonical_bytes().len(), 532);
}

#[test]
fn quarantine_accepts_only_closed_reason_and_matching_fingerprint_arms() {
    for reason in [
        ObjectStoreContinuityQuarantineReasonV1::ObjectStoreContinuityQuarantineReasonIncompleteIntent,
        ObjectStoreContinuityQuarantineReasonV1::ObjectStoreContinuityQuarantineReasonLocalBindingMissing,
        ObjectStoreContinuityQuarantineReasonV1::ObjectStoreContinuityQuarantineReasonDispatchOutcomeUnknown,
        ObjectStoreContinuityQuarantineReasonV1::ObjectStoreContinuityQuarantineReasonRestoreMismatch,
    ] {
        let mut input = quarantine();
        input.reason = reason as i32;
        assert!(validate_and_encode_continuity_quarantined(&input, &limits()).is_ok());
    }

    let mut dispatch = quarantine();
    dispatch.intent_kind =
        ObjectStoreContinuityIntentKindV1::ObjectStoreContinuityIntentKindDispatchCas as i32;
    dispatch.fingerprint = Some(
        object_store_continuity_quarantined_v1::Fingerprint::CanonicalDescriptorFingerprint(
            OTHER_DIGEST.to_vec().into(),
        ),
    );
    assert!(validate_and_encode_continuity_quarantined(&dispatch, &limits()).is_ok());

    for mutate in [
        |value: &mut ObjectStoreContinuityQuarantinedV1| value.fingerprint = None,
        |value: &mut ObjectStoreContinuityQuarantinedV1| {
            value.intent_kind =
                ObjectStoreContinuityIntentKindV1::ObjectStoreContinuityIntentKindDispatchCas as i32
        },
        |value: &mut ObjectStoreContinuityQuarantinedV1| value.intent_kind = 99,
        |value: &mut ObjectStoreContinuityQuarantinedV1| value.reason = 99,
        |value: &mut ObjectStoreContinuityQuarantinedV1| {
            value.fingerprint = Some(
                object_store_continuity_quarantined_v1::Fingerprint::PutReservationFingerprint(
                    vec![0; 31].into(),
                ),
            )
        },
    ] {
        let mut input = quarantine();
        mutate(&mut input);
        assert!(validate_and_encode_continuity_quarantined(&input, &limits()).is_err());
    }
}

#[test]
fn quarantine_rejects_stale_digest_identity_time_quota_and_ownership_mutations() {
    let encoded = validate_and_encode_continuity_quarantined(&quarantine(), &limits())
        .expect("reference quarantine must validate");
    let valid = encoded.value();
    let stale_digest = valid.detail_blake3.clone();
    type Mutation = Box<dyn Fn(&mut ObjectStoreContinuityQuarantinedV1)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|value| value.protocol_revision.push('x')),
        Box::new(|value| value.provider_boundary_id.push('x')),
        Box::new(|value| value.authenticated_cell_id.push('x')),
        Box::new(|value| value.authenticated_tenant_id.push('x')),
        Box::new(|value| value.logical_request_id = ATTEMPT_ID.to_string()),
        Box::new(|value| value.attempt_id = REQUEST_ID.to_string()),
        Box::new(|value| value.continuity_token_id = PROOF_ID.to_string()),
        Box::new(|value| value.authority_epoch += 1),
        Box::new(|value| value.continuity_seq += 1),
        Box::new(|value| value.quarantined_at_unix_ms += 1),
        Box::new(|value| value.retain_until_unix_ms += 1),
        Box::new(|value| value.quota_bearing = false),
        Box::new(|value| {
            value
                .quota_ownership
                .as_mut()
                .expect("validated ownership")
                .continuity_policy_revision
                .push('x')
        }),
        Box::new(|value| {
            value
                .quota_ownership
                .as_mut()
                .expect("validated ownership")
                .units
                .as_mut()
                .expect("validated units")
                .bytes += 1
        }),
    ];
    for mutate in mutations {
        let mut input = valid.clone();
        mutate(&mut input);
        input.detail_blake3 = stale_digest.clone();
        assert!(validate_and_encode_continuity_quarantined(&input, &limits()).is_err());
    }

    for mutate in [
        |value: &mut ObjectStoreContinuityQuarantinedV1| value.authority_epoch = 0,
        |value: &mut ObjectStoreContinuityQuarantinedV1| value.continuity_seq = 0,
        |value: &mut ObjectStoreContinuityQuarantinedV1| {
            value.retain_until_unix_ms = value.quarantined_at_unix_ms - 1
        },
    ] {
        let mut input = quarantine();
        mutate(&mut input);
        assert!(validate_and_encode_continuity_quarantined(&input, &limits()).is_err());
    }
}

#[test]
fn proof_pins_both_cross_language_optional_presence_vectors() {
    for (kind, expected_length, expected_digest) in [
        (
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
            235,
            "0f0f923f69a6105e05b1bb2ad43f77aa784524d63ab7b529f68e23adda2686d1",
        ),
        (
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch,
            267,
            "5bb0fde0648744f0aacc5370e6f1c2b32db2f73cbaef9d77964d19817895b84d",
        ),
    ] {
        let input = proof(kind);
        let expected_preimage = proof_preimage(&input);
        let encoded = validate_and_encode_continuity_adjudication_proof(&input, &limits())
            .expect("reference proof must validate");
        assert_eq!(encoded.canonical_preimage(), expected_preimage);
        assert_eq!(encoded.proof_blake3(), &decode_digest(expected_digest));
        assert_eq!(encoded.canonical_bytes(), complete_record(&expected_preimage));
        assert_eq!(encoded.canonical_bytes().len(), expected_length);
    }
}

#[test]
fn proof_rejects_wrong_presence_closed_values_and_every_stale_digest_mutation() {
    let mut local = proof(
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
    );
    local.provider_no_dispatch_evidence_blake3 = Some(DIGEST.to_vec().into());
    assert!(validate_and_encode_continuity_adjudication_proof(&local, &limits()).is_err());
    let mut no_dispatch = proof(
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch,
    );
    no_dispatch.provider_no_dispatch_evidence_blake3 = None;
    assert!(validate_and_encode_continuity_adjudication_proof(&no_dispatch, &limits()).is_err());
    for mutate in [
        |value: &mut ObjectStoreContinuityAdjudicationProofV1| value.adjudication_kind = 99,
        |value: &mut ObjectStoreContinuityAdjudicationProofV1| value.authority_epoch = 0,
        |value: &mut ObjectStoreContinuityAdjudicationProofV1| value.continuity_seq = 0,
        |value: &mut ObjectStoreContinuityAdjudicationProofV1| value.adjudication_fence = 0,
        |value: &mut ObjectStoreContinuityAdjudicationProofV1| value.committed_at_unix_ms = -1,
    ] {
        let mut input = proof(
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch,
        );
        mutate(&mut input);
        assert!(validate_and_encode_continuity_adjudication_proof(&input, &limits()).is_err());
    }

    let encoded = validate_and_encode_continuity_adjudication_proof(
        &proof(
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch,
        ),
        &limits(),
    )
    .expect("reference proof must validate");
    let valid = encoded.value();
    type Mutation = Box<dyn Fn(&mut ObjectStoreContinuityAdjudicationProofV1)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|value| value.proof_id = RELEASE_ID.to_string()),
        Box::new(|value| value.external_row_blake3 = OTHER_DIGEST.to_vec().into()),
        Box::new(|value| value.local_quarantine_blake3 = DIGEST.to_vec().into()),
        Box::new(|value| value.authority_epoch += 1),
        Box::new(|value| value.continuity_seq += 1),
        Box::new(|value| value.adjudication_fence += 1),
        Box::new(|value| value.provider_credential_revision.push('x')),
        Box::new(|value| value.provider_no_dispatch_evidence_blake3 = Some(DIGEST.to_vec().into())),
        Box::new(|value| value.committed_at_unix_ms += 1),
    ];
    for mutate in mutations {
        let mut input = valid.clone();
        mutate(&mut input);
        assert!(validate_and_encode_continuity_adjudication_proof(&input, &limits()).is_err());
    }
}

#[test]
fn release_pins_cross_language_boolean_nested_quota_and_digest_vector() {
    let input = release(
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
    );
    let expected_preimage = release_preimage(&input);
    let expected_digest =
        decode_digest("acd9f63eabc96b21dceaf619fbdec58fbab44233af0da9b495f3f9b3b3d29210");
    let encoded = validate_and_encode_continuity_quota_release_receipt(&input, &limits())
        .expect("reference release must validate");
    assert_eq!(encoded.canonical_preimage(), expected_preimage);
    assert_eq!(encoded.receipt_blake3(), &expected_digest);
    assert_eq!(
        encoded.canonical_bytes(),
        complete_record(&expected_preimage)
    );
    assert_eq!(encoded.canonical_bytes().len(), 398);
}

#[test]
fn release_rejects_closed_value_boolean_time_quota_and_stale_digest_mutations() {
    for mutate in [
        |value: &mut ObjectStoreContinuityQuotaReleaseReceiptV1| value.adjudication_kind = 99,
        |value: &mut ObjectStoreContinuityQuotaReleaseReceiptV1| {
            value.provider_authority_refunded = true
        },
        |value: &mut ObjectStoreContinuityQuotaReleaseReceiptV1| value.released_at_unix_ms = -1,
        |value: &mut ObjectStoreContinuityQuotaReleaseReceiptV1| value.quota_revision = 0,
        |value: &mut ObjectStoreContinuityQuotaReleaseReceiptV1| value.released_put_spool = None,
    ] {
        let mut input = release(
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
        );
        mutate(&mut input);
        assert!(validate_and_encode_continuity_quota_release_receipt(&input, &limits()).is_err());
    }

    let encoded = validate_and_encode_continuity_quota_release_receipt(
        &release(
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
        ),
        &limits(),
    )
    .expect("reference release must validate");
    let valid = encoded.value();
    type Mutation = Box<dyn Fn(&mut ObjectStoreContinuityQuotaReleaseReceiptV1)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|value| value.release_id = PROOF_ID.to_string()),
        Box::new(|value| value.adjudication_kind = 2),
        Box::new(|value| {
            value
                .released_put_spool
                .as_mut()
                .expect("validated PUT units")
                .bytes += 1
        }),
        Box::new(|value| {
            value
                .released_result_spool
                .as_mut()
                .expect("validated result units")
                .rows += 1
        }),
        Box::new(|value| {
            value
                .released_retained_metadata
                .as_mut()
                .expect("validated metadata units")
                .concurrency += 1
        }),
        Box::new(|value| value.provider_authority_refunded = true),
        Box::new(|value| value.released_at_unix_ms += 1),
        Box::new(|value| value.quota_revision += 1),
    ];
    for mutate in mutations {
        let mut input = valid.clone();
        mutate(&mut input);
        assert!(validate_and_encode_continuity_quota_release_receipt(&input, &limits()).is_err());
    }
}

#[test]
fn adjudicated_pins_both_cross_language_nested_record_vectors() {
    for (kind, expected_length, expected_digest) in [
        (
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
            1_172,
            "829bee945d7bf80757818e35ee4a3c9ab6016e2db0f2e41c6e3aedfb49ba811b",
        ),
        (
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch,
            1_204,
            "d78a25f4361b3ce28897d1cd715fb5ab6de5e24864e590ccaa196b1a08772340",
        ),
    ] {
        let input = adjudicated(kind);
        let expected_preimage = adjudicated_preimage(&input);
        let encoded = validate_and_encode_continuity_adjudicated(&input, &limits())
            .expect("reference adjudication must validate");
        assert_eq!(encoded.canonical_preimage(), expected_preimage);
        assert_eq!(encoded.detail_blake3(), &decode_digest(expected_digest));
        assert_eq!(encoded.canonical_bytes(), complete_record(&expected_preimage));
        assert_eq!(encoded.canonical_bytes().len(), expected_length);
    }
}

#[test]
fn adjudicated_dispatch_cas_pins_canonical_descriptor_arm_in_independent_preimage() {
    let kind =
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch;
    let mut input = adjudicated(kind);
    input.intent_kind =
        ObjectStoreContinuityIntentKindV1::ObjectStoreContinuityIntentKindDispatchCas as i32;
    input.fingerprint = Some(
        object_store_continuity_adjudicated_v1::Fingerprint::CanonicalDescriptorFingerprint(
            OTHER_DIGEST.to_vec().into(),
        ),
    );
    let expected_preimage = adjudicated_preimage(&input);
    let expected_digest = *blake3::hash(&expected_preimage).as_bytes();

    let encoded = validate_and_encode_continuity_adjudicated(&input, &limits())
        .expect("DISPATCH_CAS adjudication with descriptor fingerprint must validate");

    assert_eq!(encoded.canonical_preimage(), expected_preimage);
    assert_eq!(encoded.detail_blake3(), &expected_digest);
    assert_eq!(
        encoded.canonical_bytes(),
        complete_record(&expected_preimage)
    );
    assert_eq!(encoded.canonical_bytes().len(), 1_204);
}

#[test]
fn adjudicated_rejects_mismatched_children_quota_totals_and_time_ordering() {
    let local_kind =
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect;
    let no_dispatch_kind =
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch;
    type Mutation = Box<dyn Fn(&mut ObjectStoreContinuityAdjudicatedV1)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(move |value| value.proof = Some(proof(no_dispatch_kind))),
        Box::new(move |value| value.quota_release_receipt = Some(release(no_dispatch_kind))),
        Box::new(|value| value.fingerprint = None),
        Box::new(|value| {
            value.fingerprint = Some(
                object_store_continuity_adjudicated_v1::Fingerprint::CanonicalDescriptorFingerprint(
                    OTHER_DIGEST.to_vec().into(),
                ),
            )
        }),
        Box::new(|value| {
            value
                .proof
                .as_mut()
                .expect("fixture proof")
                .committed_at_unix_ms = NOW + 4
        }),
        Box::new(|value| {
            value
                .quota_release_receipt
                .as_mut()
                .expect("fixture release")
                .released_at_unix_ms = NOW
        }),
        Box::new(|value| value.adjudicated_at_unix_ms = NOW + 1),
        Box::new(|value| value.retain_until_unix_ms = NOW + 2),
        Box::new(|value| {
            value
                .quota_release_receipt
                .as_mut()
                .expect("fixture release")
                .released_put_spool
                .as_mut()
                .expect("fixture PUT units")
                .bytes += 1
        }),
    ];
    for mutate in mutations {
        let mut input = adjudicated(local_kind);
        mutate(&mut input);
        assert!(validate_and_encode_continuity_adjudicated(&input, &limits()).is_err());
    }
}

#[test]
fn adjudicated_rejects_quota_category_sum_overflow() {
    let kind =
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect;
    let mut input = adjudicated(kind);
    input
        .quota_ownership
        .as_mut()
        .expect("fixture ownership")
        .units
        .as_mut()
        .expect("fixture ownership units")
        .bytes = u64::MAX;
    let release = input
        .quota_release_receipt
        .as_mut()
        .expect("fixture release");
    release
        .released_put_spool
        .as_mut()
        .expect("fixture PUT units")
        .bytes = u64::MAX;
    release
        .released_result_spool
        .as_mut()
        .expect("fixture result units")
        .bytes = 1;
    release
        .released_retained_metadata
        .as_mut()
        .expect("fixture metadata units")
        .bytes = 0;

    assert!(validate_and_encode_continuity_adjudicated(&input, &limits()).is_err());
}

#[test]
fn adjudicated_rejects_every_stale_outer_digest_mutation() {
    let kind =
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect;
    let encoded = validate_and_encode_continuity_adjudicated(&adjudicated(kind), &limits())
        .expect("reference adjudication must validate");
    let valid = encoded.value();
    type Mutation = Box<dyn Fn(&mut ObjectStoreContinuityAdjudicatedV1)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|value| value.protocol_revision.push('x')),
        Box::new(|value| value.provider_boundary_id.push('x')),
        Box::new(|value| value.authenticated_cell_id.push('x')),
        Box::new(|value| value.authenticated_tenant_id.push('x')),
        Box::new(|value| value.logical_request_id = ATTEMPT_ID.to_string()),
        Box::new(|value| value.attempt_id = REQUEST_ID.to_string()),
        Box::new(|value| value.continuity_token_id = PROOF_ID.to_string()),
        Box::new(|value| value.authority_epoch += 1),
        Box::new(|value| value.continuity_seq += 1),
        Box::new(|value| value.intent_kind = 99),
        Box::new(|value| value.adjudication_kind = 2),
        Box::new(|value| value.adjudicated_at_unix_ms += 1),
        Box::new(|value| value.retain_until_unix_ms += 1),
        Box::new(|value| {
            value
                .quota_ownership
                .as_mut()
                .expect("validated ownership")
                .authenticated_tenant_id
                .push('x')
        }),
    ];
    for mutate in mutations {
        let mut input = valid.clone();
        mutate(&mut input);
        assert!(validate_and_encode_continuity_adjudicated(&input, &limits()).is_err());
    }
}

#[test]
fn row_bounds_are_positive_inclusive_and_apply_to_every_record() {
    let quarantine_input = quarantine();
    let proof = proof(
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch,
    );
    let release = release(
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
    );
    let adjudicated = adjudicated(
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
    );
    for (exact, accepts, rejects) in [
        (
            532,
            validate_and_encode_continuity_quarantined(
                &quarantine_input,
                &ContinuityWireLimits {
                    max_identity_bytes: 256,
                    max_canonical_row_bytes: 532,
                },
            )
            .is_ok(),
            validate_and_encode_continuity_quarantined(
                &quarantine_input,
                &ContinuityWireLimits {
                    max_identity_bytes: 256,
                    max_canonical_row_bytes: 531,
                },
            )
            .is_err(),
        ),
        (
            267,
            validate_and_encode_continuity_adjudication_proof(
                &proof,
                &ContinuityWireLimits {
                    max_identity_bytes: 256,
                    max_canonical_row_bytes: 267,
                },
            )
            .is_ok(),
            validate_and_encode_continuity_adjudication_proof(
                &proof,
                &ContinuityWireLimits {
                    max_identity_bytes: 256,
                    max_canonical_row_bytes: 266,
                },
            )
            .is_err(),
        ),
        (
            398,
            validate_and_encode_continuity_quota_release_receipt(
                &release,
                &ContinuityWireLimits {
                    max_identity_bytes: 256,
                    max_canonical_row_bytes: 398,
                },
            )
            .is_ok(),
            validate_and_encode_continuity_quota_release_receipt(
                &release,
                &ContinuityWireLimits {
                    max_identity_bytes: 256,
                    max_canonical_row_bytes: 397,
                },
            )
            .is_err(),
        ),
        (
            1_172,
            validate_and_encode_continuity_adjudicated(
                &adjudicated,
                &ContinuityWireLimits {
                    max_identity_bytes: 256,
                    max_canonical_row_bytes: 1_172,
                },
            )
            .is_ok(),
            validate_and_encode_continuity_adjudicated(
                &adjudicated,
                &ContinuityWireLimits {
                    max_identity_bytes: 256,
                    max_canonical_row_bytes: 1_171,
                },
            )
            .is_err(),
        ),
    ] {
        assert!(accepts, "exact {exact}-byte record bound must pass");
        assert!(rejects, "one byte below {exact} must fail");
    }

    let zero = ContinuityWireLimits {
        max_identity_bytes: 0,
        max_canonical_row_bytes: 0,
    };
    assert!(validate_and_encode_continuity_quarantined(&quarantine_input, &zero).is_err());
    let mut identity_over = quarantine_input;
    identity_over.protocol_revision = "x".repeat(257);
    assert!(validate_and_encode_continuity_quarantined(&identity_over, &limits()).is_err());

    let identity_exact = ContinuityWireLimits {
        max_identity_bytes: 36,
        max_canonical_row_bytes: 8_192,
    };
    assert!(validate_and_encode_continuity_quarantined(&quarantine(), &identity_exact).is_ok());
    assert!(
        validate_and_encode_continuity_quarantined(
            &quarantine(),
            &ContinuityWireLimits {
                max_identity_bytes: 35,
                ..identity_exact
            },
        )
        .is_err()
    );
}

#[test]
fn every_record_rejects_malformed_or_wrong_supplied_digests() {
    for digest in [vec![0; 31], vec![0; 32], vec![0; 33]] {
        let mut quarantine = quarantine();
        quarantine.detail_blake3 = digest.clone().into();
        assert!(validate_and_encode_continuity_quarantined(&quarantine, &limits()).is_err());

        let mut proof = proof(
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
        );
        proof.proof_blake3 = digest.clone().into();
        assert!(validate_and_encode_continuity_adjudication_proof(&proof, &limits()).is_err());

        let mut release = release(
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
        );
        release.receipt_blake3 = digest.clone().into();
        assert!(validate_and_encode_continuity_quota_release_receipt(&release, &limits()).is_err());

        let mut adjudicated = adjudicated(
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
        );
        adjudicated.detail_blake3 = digest.into();
        assert!(validate_and_encode_continuity_adjudicated(&adjudicated, &limits()).is_err());
    }
}

#[test]
fn validated_records_are_detached_and_exact_replay_is_pure() {
    let kind =
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch;
    let mut input = adjudicated(kind);
    let first = validate_and_encode_continuity_adjudicated(&input, &limits())
        .expect("reference adjudication must validate");
    let second = validate_and_encode_continuity_adjudicated(&input, &limits())
        .expect("exact replay must validate");
    assert_eq!(first.value(), second.value());
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());

    input.protocol_revision = "mutated-after-validation".to_string();
    input
        .proof
        .as_mut()
        .expect("fixture proof")
        .external_row_blake3 = vec![0; 32].into();
    input
        .quota_ownership
        .as_mut()
        .expect("fixture ownership")
        .units
        .as_mut()
        .expect("fixture units")
        .bytes = 999;
    assert_eq!(first.value().protocol_revision, "object-dispatch-v1");
    assert_eq!(
        first
            .value()
            .proof
            .as_ref()
            .expect("validated proof")
            .external_row_blake3
            .as_ref(),
        DIGEST
    );
    assert_eq!(
        first
            .value()
            .quota_ownership
            .as_ref()
            .expect("validated ownership")
            .units
            .as_ref()
            .expect("validated units")
            .bytes,
        125
    );
}

#[test]
fn canonical_debug_output_redacts_identity_quota_preimage_and_digest_material() {
    let kind =
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch;
    let encoded = validate_and_encode_continuity_adjudicated(&adjudicated(kind), &limits())
        .expect("reference adjudication must validate");
    let debug = format!("{encoded:?}");

    for secret in [
        "object-dispatch-v1",
        "boundary-1",
        "cell-1",
        "tenant-1",
        REQUEST_ID,
        PROOF_ID,
        "credential-9",
        "d78a25f4",
        "125",
    ] {
        assert!(!debug.contains(secret), "Debug leaked {secret}: {debug}");
    }
}
