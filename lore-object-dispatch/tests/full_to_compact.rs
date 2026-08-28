// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::*;
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

fn reservation() -> ReservedDimensionV1 {
    ReservedDimensionV1 {
        reservation_id: "reservation-1".to_string(),
        physical_dimension_id: "physical-1".to_string(),
        operation_class_id: "GET".to_string(),
        units: 1,
    }
}

fn quota(bytes: u64, rows: u64, concurrency: u64) -> ObjectStoreQuotaUnitsV1 {
    ObjectStoreQuotaUnitsV1 {
        bytes,
        rows,
        concurrency,
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

fn closed_state() -> CanonicalObjectStoreRequestState {
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

fn compact_plan_at(database_now_unix_ms: i64) -> ObjectStoreCompactReceiptDecision {
    let state = closed_state();
    let authority = ObjectStoreCompactAuthority::RequestState(Box::new(state));
    let receipt = validate_and_encode_object_store_request_receipt(
        &ObjectStoreRequestReceiptV1 {
            receipt_blake3: Default::default(),
            receipt_committed_at_unix_ms: NOW + 20,
            outcome: Some(object_store_request_receipt_v1::Outcome::RequestState(
                Box::new(match &authority {
                    ObjectStoreCompactAuthority::RequestState(state) => state.value().clone(),
                    _ => unreachable!("request-state fixture"),
                }),
            )),
        },
        &wire_limits(),
    )
    .expect("receipt fixture");
    let outcome = validate_and_encode_object_store_request_outcome(
        &ObjectStoreRequestOutcomeV1 {
            outcome_blake3: Default::default(),
            outcome: Some(object_store_request_outcome_v1::Outcome::RequestState(
                Box::new(match &authority {
                    ObjectStoreCompactAuthority::RequestState(state) => state.value().clone(),
                    _ => unreachable!("request-state fixture"),
                }),
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
            database_now_unix_ms,
            existing_compact: None,
        },
        &compact_limits(),
    )
    .expect("compact planner fixture")
}

fn compact_plan() -> ObjectStoreCompactReceiptDecision {
    compact_plan_at(NOW + 50)
}

fn adjudicated_compact_plan() -> ObjectStoreCompactReceiptDecision {
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

fn counter(
    scope: ObjectStoreFullToCompactScope,
    scope_id: &str,
) -> ObjectStoreRecordStorageCounter {
    ObjectStoreRecordStorageCounter {
        scope,
        scope_id: scope_id.to_string(),
        full_record_rows: 10,
        full_record_bytes: 100_000,
        compact_rows: 2,
        compact_bytes: 10_000,
        counter_revision: 7,
    }
}

fn policy() -> ObjectStoreFullToCompactPolicy {
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

struct Fixture {
    compact_plan: ObjectStoreCompactReceiptDecision,
    full_ownership: ObjectStoreFullRecordOwnership,
    global_counter: ObjectStoreRecordStorageCounter,
    cell_counter: ObjectStoreRecordStorageCounter,
    tenant_counter: ObjectStoreRecordStorageCounter,
    policy: ObjectStoreFullToCompactPolicy,
    lifecycle: ObjectStoreFullToCompactLifecycle,
}

impl Fixture {
    fn input(&self) -> ObjectStoreFullToCompactInput<'_> {
        ObjectStoreFullToCompactInput {
            compact_plan: &self.compact_plan,
            full_ownership: &self.full_ownership,
            global_counter: &self.global_counter,
            cell_counter: &self.cell_counter,
            tenant_counter: &self.tenant_counter,
            policy: &self.policy,
            lifecycle: &self.lifecycle,
        }
    }
}

fn fixture() -> Fixture {
    fixture_with_plan(compact_plan())
}

fn fixture_with_plan(compact_plan: ObjectStoreCompactReceiptDecision) -> Fixture {
    let (value, source_authority_blake3) = match &compact_plan {
        ObjectStoreCompactReceiptDecision::ApplyCompaction {
            expected_authority_blake3,
            compact,
            ..
        } => (compact.value(), *expected_authority_blake3),
        other => panic!("compact fixture did not apply: {other:?}"),
    };
    let full_ownership = ObjectStoreFullRecordOwnership {
        provider_boundary_id: value.provider_boundary_id.clone(),
        authenticated_cell_id: value.authenticated_cell_id.clone(),
        authenticated_tenant_id: value.authenticated_tenant_id.clone(),
        logical_request_id: value.logical_request_id.clone(),
        attempt_id: value.attempt_id.clone(),
        source_authority_blake3,
        rows: 1,
        bytes: 7_000,
        concurrency: 0,
    };
    let global_counter = counter(
        ObjectStoreFullToCompactScope::Global,
        OBJECT_STORE_FULL_TO_COMPACT_GLOBAL_SCOPE_ID,
    );
    let cell_counter = counter(
        ObjectStoreFullToCompactScope::Cell,
        &full_ownership.authenticated_cell_id,
    );
    let tenant_counter = counter(
        ObjectStoreFullToCompactScope::Tenant,
        &full_ownership.authenticated_tenant_id,
    );
    let lifecycle = ObjectStoreFullToCompactLifecycle::FullOwned {
        source_authority_blake3,
    };
    Fixture {
        compact_plan,
        full_ownership,
        global_counter,
        cell_counter,
        tenant_counter,
        policy: policy(),
        lifecycle,
    }
}

fn apply(fixture: &Fixture) -> ObjectStoreFullToCompactDecision {
    let decision =
        decide_object_store_full_to_compact(&fixture.input()).expect("transfer decision");
    assert!(matches!(
        decision,
        ObjectStoreFullToCompactDecision::ApplyFullToCompact { .. }
    ));
    decision
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
fn literal_compact_golden_projects_into_all_three_counters_exactly_once() {
    let fixture = fixture();
    let ObjectStoreCompactReceiptDecision::ApplyCompaction { compact, .. } = &fixture.compact_plan
    else {
        panic!("compact fixture must apply");
    };
    assert_eq!(compact.canonical_bytes().len(), 6_519);
    assert_eq!(
        compact.compact_blake3(),
        decode_hex("5c172fbba2f48cda97bbbb2d3e4fde6d54fa25b51e955bfaa6eeb36d65e7f9d1").as_slice()
    );
    let ObjectStoreFullToCompactDecision::ApplyFullToCompact {
        policy_revision,
        transfer_fingerprint,
        expected_source_authority_blake3,
        expected_counter_revisions,
        next_counters,
        compact: projected,
        ..
    } = apply(&fixture)
    else {
        unreachable!("apply helper checks decision");
    };
    assert_eq!(policy_revision, "storage-policy-1");
    assert_eq!(
        transfer_fingerprint,
        decode_hex("20991308e09eacbdcf10d73995db73d7966fec2137daed91412f10de8aa98393").as_slice()
    );
    assert_eq!(
        expected_source_authority_blake3,
        fixture.full_ownership.source_authority_blake3
    );
    assert_eq!(
        expected_counter_revisions,
        ObjectStoreFullToCompactExpectedRevisions {
            global: 7,
            cell: 7,
            tenant: 7,
        }
    );
    for next in [
        &next_counters.global,
        &next_counters.cell,
        &next_counters.tenant,
    ] {
        assert_eq!(next.full_record_rows, 9);
        assert_eq!(next.full_record_bytes, 93_000);
        assert_eq!(next.compact_rows, 3);
        assert_eq!(next.compact_bytes, 16_519);
        assert_eq!(next.counter_revision, 8);
    }
    assert_eq!(projected.canonical_bytes(), compact.canonical_bytes());
}

#[test]
fn continuity_adjudicated_authority_projects_its_detail_digest() {
    let fixture = fixture_with_plan(adjudicated_compact_plan());
    let expected = match &fixture.compact_plan {
        ObjectStoreCompactReceiptDecision::ApplyCompaction {
            expected_authority_blake3,
            compact,
            ..
        } => {
            let ObjectStoreCompactAuthority::ContinuityAdjudicated(authority) =
                &compact.value().authority
            else {
                panic!("continuity compact authority")
            };
            assert_eq!(expected_authority_blake3, authority.detail_blake3());
            *expected_authority_blake3
        }
        other => panic!("adjudicated compact plan did not apply: {other:?}"),
    };
    let ObjectStoreFullToCompactDecision::ApplyFullToCompact {
        expected_source_authority_blake3,
        ..
    } = apply(&fixture)
    else {
        unreachable!("apply helper")
    };
    assert_eq!(expected_source_authority_blake3, expected);
}

#[test]
fn every_compact_limit_admits_below_and_equal_then_denies_above() {
    let cases = [
        (
            ObjectStoreFullToCompactScope::Global,
            ObjectStoreFullToCompactDimension::Rows,
        ),
        (
            ObjectStoreFullToCompactScope::Global,
            ObjectStoreFullToCompactDimension::Bytes,
        ),
        (
            ObjectStoreFullToCompactScope::Cell,
            ObjectStoreFullToCompactDimension::Rows,
        ),
        (
            ObjectStoreFullToCompactScope::Cell,
            ObjectStoreFullToCompactDimension::Bytes,
        ),
        (
            ObjectStoreFullToCompactScope::Tenant,
            ObjectStoreFullToCompactDimension::Rows,
        ),
        (
            ObjectStoreFullToCompactScope::Tenant,
            ObjectStoreFullToCompactDimension::Bytes,
        ),
    ];
    for (scope, dimension) in cases {
        for delta in [-1_i64, 0, 1] {
            let mut fixture = fixture();
            let charge = if dimension == ObjectStoreFullToCompactDimension::Rows {
                1
            } else {
                let ObjectStoreCompactReceiptDecision::ApplyCompaction { compact_charge, .. } =
                    fixture.compact_plan
                else {
                    unreachable!("compact fixture")
                };
                compact_charge.bytes
            };
            let maximum = 100_000_u64;
            let used = maximum - charge;
            let used = if delta < 0 {
                used - 1
            } else {
                used + delta as u64
            };
            let counter = match scope {
                ObjectStoreFullToCompactScope::Global => &mut fixture.global_counter,
                ObjectStoreFullToCompactScope::Cell => &mut fixture.cell_counter,
                ObjectStoreFullToCompactScope::Tenant => &mut fixture.tenant_counter,
            };
            match dimension {
                ObjectStoreFullToCompactDimension::Rows => counter.compact_rows = used,
                ObjectStoreFullToCompactDimension::Bytes => counter.compact_bytes = used,
            }
            match (scope, dimension) {
                (
                    ObjectStoreFullToCompactScope::Global,
                    ObjectStoreFullToCompactDimension::Rows,
                ) => fixture.policy.max_compact_rows_global = maximum,
                (
                    ObjectStoreFullToCompactScope::Global,
                    ObjectStoreFullToCompactDimension::Bytes,
                ) => fixture.policy.max_compact_bytes_global = maximum,
                (ObjectStoreFullToCompactScope::Cell, ObjectStoreFullToCompactDimension::Rows) => {
                    fixture.policy.max_compact_rows_per_cell = maximum;
                    fixture.policy.max_compact_rows_global = maximum + 2 * charge;
                    fixture.global_counter.compact_rows = maximum + charge;
                }
                (ObjectStoreFullToCompactScope::Cell, ObjectStoreFullToCompactDimension::Bytes) => {
                    fixture.policy.max_compact_bytes_per_cell = maximum;
                    fixture.policy.max_compact_bytes_global = maximum + 2 * charge;
                    fixture.global_counter.compact_bytes = maximum + charge;
                }
                (
                    ObjectStoreFullToCompactScope::Tenant,
                    ObjectStoreFullToCompactDimension::Rows,
                ) => {
                    fixture.policy.max_compact_rows_per_tenant = maximum;
                    fixture.policy.max_compact_rows_global = maximum + 2 * charge;
                    fixture.global_counter.compact_rows = maximum + charge;
                }
                (
                    ObjectStoreFullToCompactScope::Tenant,
                    ObjectStoreFullToCompactDimension::Bytes,
                ) => {
                    fixture.policy.max_compact_bytes_per_tenant = maximum;
                    fixture.policy.max_compact_bytes_global = maximum + 2 * charge;
                    fixture.global_counter.compact_bytes = maximum + charge;
                }
            }
            let decision = decide_object_store_full_to_compact(&fixture.input())
                .expect("capacity boundary decision");
            if delta <= 0 {
                assert!(matches!(
                    decision,
                    ObjectStoreFullToCompactDecision::ApplyFullToCompact { .. }
                ));
            } else {
                assert_eq!(
                    decision,
                    ObjectStoreFullToCompactDecision::RetainFullCompactCapacity {
                        exhausted_scope: scope,
                        exhausted_dimension: dimension,
                    }
                );
            }
        }
    }
}

#[test]
fn simultaneous_compact_exhaustion_uses_the_frozen_precedence() {
    let mut fixture = fixture();
    fixture.policy.max_compact_rows_global = fixture.global_counter.compact_rows;
    fixture.policy.max_compact_bytes_global = fixture.global_counter.compact_bytes;
    fixture.policy.max_compact_rows_per_cell = fixture.cell_counter.compact_rows;
    fixture.policy.max_compact_bytes_per_cell = fixture.cell_counter.compact_bytes;
    fixture.policy.max_compact_rows_per_tenant = fixture.tenant_counter.compact_rows;
    fixture.policy.max_compact_bytes_per_tenant = fixture.tenant_counter.compact_bytes;
    assert_eq!(
        decide_object_store_full_to_compact(&fixture.input()),
        Ok(
            ObjectStoreFullToCompactDecision::RetainFullCompactCapacity {
                exhausted_scope: ObjectStoreFullToCompactScope::Global,
                exhausted_dimension: ObjectStoreFullToCompactDimension::Rows,
            }
        )
    );
}

#[test]
fn exact_replay_wins_before_mutable_policy_and_counter_validation() {
    let first_fixture = fixture();
    let ObjectStoreFullToCompactDecision::ApplyFullToCompact {
        transfer_fingerprint,
        compact,
        ..
    } = apply(&first_fixture)
    else {
        unreachable!("apply helper");
    };
    let mut replay = fixture();
    replay.policy.policy_revision.clear();
    replay.policy.max_compact_rows_global = 0;
    replay.global_counter.counter_revision = 0;
    replay.cell_counter.full_record_rows = 0;
    replay.tenant_counter.compact_bytes = u64::MAX;
    replay.lifecycle = ObjectStoreFullToCompactLifecycle::CompactInstalled {
        transfer_fingerprint,
        compact: Box::new((*compact).clone()),
    };
    let decision = decide_object_store_full_to_compact(&replay.input()).expect("exact replay");
    assert!(matches!(
        decision,
        ObjectStoreFullToCompactDecision::ReplayTransfer { .. }
    ));
}

#[test]
fn lifecycle_conflict_source_mismatch_and_changed_installed_intent_conflict() {
    let mut direct = fixture();
    direct.lifecycle = ObjectStoreFullToCompactLifecycle::Conflict;
    assert_eq!(
        decide_object_store_full_to_compact(&direct.input()),
        Ok(ObjectStoreFullToCompactDecision::TransferConflict)
    );
    direct.lifecycle = ObjectStoreFullToCompactLifecycle::FullOwned {
        source_authority_blake3: OTHER_DIGEST,
    };
    assert_eq!(
        decide_object_store_full_to_compact(&direct.input()),
        Ok(ObjectStoreFullToCompactDecision::TransferConflict)
    );

    let first = fixture();
    let ObjectStoreFullToCompactDecision::ApplyFullToCompact {
        transfer_fingerprint,
        compact,
        ..
    } = apply(&first)
    else {
        unreachable!("apply helper");
    };
    let mut changed = fixture();
    changed.lifecycle = ObjectStoreFullToCompactLifecycle::CompactInstalled {
        transfer_fingerprint: OTHER_DIGEST,
        compact: compact.clone(),
    };
    assert_eq!(
        decide_object_store_full_to_compact(&changed.input()),
        Ok(ObjectStoreFullToCompactDecision::TransferConflict)
    );

    let mut changed_compact = fixture();
    changed_compact.compact_plan = compact_plan_at(NOW + 51);
    changed_compact.lifecycle = ObjectStoreFullToCompactLifecycle::CompactInstalled {
        transfer_fingerprint,
        compact,
    };
    assert_eq!(
        decide_object_store_full_to_compact(&changed_compact.input()),
        Ok(ObjectStoreFullToCompactDecision::TransferConflict)
    );
}

#[test]
fn low_water_policy_is_validated_but_not_applied_to_maintenance() {
    let mut fixture = fixture();
    fixture.policy.full_record_low_water_reserve_rows =
        fixture.policy.max_full_record_rows_per_tenant;
    fixture.policy.full_record_low_water_reserve_bytes =
        fixture.policy.max_full_record_bytes_per_tenant;
    assert!(matches!(
        decide_object_store_full_to_compact(&fixture.input()),
        Ok(ObjectStoreFullToCompactDecision::ApplyFullToCompact { .. })
    ));
    fixture.policy.full_record_low_water_reserve_rows += 1;
    assert_eq!(
        decide_object_store_full_to_compact(&fixture.input()),
        Err(FullToCompactError::InvalidPolicy)
    );
}

#[test]
fn every_full_and_compact_policy_maximum_must_be_positive() {
    for field in 0..12 {
        let mut fixture = fixture();
        match field {
            0 => fixture.policy.max_full_record_rows_global = 0,
            1 => fixture.policy.max_full_record_bytes_global = 0,
            2 => fixture.policy.max_full_record_rows_per_cell = 0,
            3 => fixture.policy.max_full_record_bytes_per_cell = 0,
            4 => fixture.policy.max_full_record_rows_per_tenant = 0,
            5 => fixture.policy.max_full_record_bytes_per_tenant = 0,
            6 => fixture.policy.max_compact_rows_global = 0,
            7 => fixture.policy.max_compact_bytes_global = 0,
            8 => fixture.policy.max_compact_rows_per_cell = 0,
            9 => fixture.policy.max_compact_bytes_per_cell = 0,
            10 => fixture.policy.max_compact_rows_per_tenant = 0,
            11 => fixture.policy.max_compact_bytes_per_tenant = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            decide_object_store_full_to_compact(&fixture.input()),
            Err(FullToCompactError::InvalidPolicy),
            "policy maximum {field} must fail closed"
        );
    }
}

#[test]
fn malformed_charge_ownership_and_scope_fail_closed() {
    let mut bad_charge = fixture();
    let ObjectStoreCompactReceiptDecision::ApplyCompaction { compact_charge, .. } =
        &mut bad_charge.compact_plan
    else {
        unreachable!("compact fixture");
    };
    compact_charge.rows = 0;
    assert_eq!(
        decide_object_store_full_to_compact(&bad_charge.input()),
        Err(FullToCompactError::InvalidCompactPlan)
    );

    for mutate_submit in [true, false] {
        let mut bad_expected_digest = fixture();
        let ObjectStoreCompactReceiptDecision::ApplyCompaction {
            expected_submit_receipt_blake3,
            expected_get_outcome_blake3,
            ..
        } = &mut bad_expected_digest.compact_plan
        else {
            unreachable!("compact fixture")
        };
        if mutate_submit {
            *expected_submit_receipt_blake3 = OTHER_DIGEST;
        } else {
            *expected_get_outcome_blake3 = OTHER_DIGEST;
        }
        assert_eq!(
            decide_object_store_full_to_compact(&bad_expected_digest.input()),
            Err(FullToCompactError::InvalidCompactPlan)
        );
    }

    let mut bad_ownership = fixture();
    bad_ownership.full_ownership.bytes = 0;
    assert_eq!(
        decide_object_store_full_to_compact(&bad_ownership.input()),
        Err(FullToCompactError::InvalidFullOwnership)
    );
    for mutation in 0..8 {
        let mut fixture = fixture();
        match mutation {
            0 => fixture.full_ownership.rows = 0,
            1 => fixture.full_ownership.concurrency = 1,
            2 => fixture.full_ownership.provider_boundary_id = "other-boundary".to_string(),
            3 => fixture.full_ownership.authenticated_cell_id = "other-cell".to_string(),
            4 => fixture.full_ownership.authenticated_tenant_id = "other-tenant".to_string(),
            5 => {
                fixture.full_ownership.logical_request_id =
                    "018f3e12-a460-7abc-8def-0123456789ab".to_string()
            }
            6 => {
                fixture.full_ownership.attempt_id =
                    "018f3e12-a461-7abc-8def-0123456789ab".to_string()
            }
            7 => fixture.full_ownership.source_authority_blake3 = OTHER_DIGEST,
            _ => unreachable!(),
        }
        let decision = decide_object_store_full_to_compact(&fixture.input());
        if mutation <= 1 {
            assert_eq!(
                decision,
                Err(FullToCompactError::InvalidFullOwnership),
                "malformed full charge {mutation} must fail closed"
            );
        } else {
            assert_eq!(
                decision,
                Ok(ObjectStoreFullToCompactDecision::TransferConflict),
                "stable ownership binding mutation {mutation} must conflict"
            );
        }
    }
    let mut bad_scope = fixture();
    bad_scope.global_counter.scope_id = "wrong-global".to_string();
    assert_eq!(
        decide_object_store_full_to_compact(&bad_scope.input()),
        Err(FullToCompactError::InvalidCounter)
    );
    let mut bad_revision = fixture();
    bad_revision.cell_counter.counter_revision = 0;
    assert_eq!(
        decide_object_store_full_to_compact(&bad_revision.input()),
        Err(FullToCompactError::InvalidCounter)
    );
}

#[test]
fn checked_counter_underflow_and_overflow_fail_closed() {
    for mutate in [0_u8, 1, 2, 3] {
        let mut fixture = fixture();
        match mutate {
            0 => fixture.tenant_counter.full_record_rows = 0,
            1 => fixture.tenant_counter.full_record_bytes = fixture.full_ownership.bytes - 1,
            2 => fixture.global_counter.compact_rows = u64::MAX,
            3 => fixture.global_counter.counter_revision = u64::MAX,
            _ => unreachable!(),
        }
        let expected = if mutate <= 1 {
            FullToCompactError::CounterUnderflow
        } else {
            FullToCompactError::CounterOverflow
        };
        assert_eq!(
            decide_object_store_full_to_compact(&fixture.input()),
            Err(expected)
        );
    }
}

#[test]
fn child_counters_must_not_exceed_global() {
    let mut before = fixture();
    before.cell_counter.compact_rows = before.global_counter.compact_rows + 1;
    assert_eq!(
        decide_object_store_full_to_compact(&before.input()),
        Err(FullToCompactError::ChildExceedsGlobal)
    );
}

#[test]
fn identical_callers_produce_the_same_two_winner_cas_plan() {
    assert_eq!(apply(&fixture()), apply(&fixture()));
}

#[test]
fn returned_apply_and_replay_values_own_detached_compact_buffers() {
    let initial = fixture();
    let source_ptr = match &initial.compact_plan {
        ObjectStoreCompactReceiptDecision::ApplyCompaction { compact, .. } => {
            compact.canonical_bytes().as_ptr()
        }
        _ => unreachable!("compact fixture"),
    };
    let ObjectStoreFullToCompactDecision::ApplyFullToCompact {
        transfer_fingerprint,
        compact,
        ..
    } = apply(&initial)
    else {
        unreachable!("apply helper");
    };
    assert_ne!(source_ptr, compact.canonical_bytes().as_ptr());
    let installed_ptr = compact.canonical_bytes().as_ptr();
    let mut replay = fixture();
    replay.lifecycle = ObjectStoreFullToCompactLifecycle::CompactInstalled {
        transfer_fingerprint,
        compact,
    };
    let ObjectStoreFullToCompactDecision::ReplayTransfer {
        compact: replayed, ..
    } = decide_object_store_full_to_compact(&replay.input()).expect("replay")
    else {
        panic!("installed exact transfer must replay");
    };
    assert_ne!(installed_ptr, replayed.canonical_bytes().as_ptr());
}
