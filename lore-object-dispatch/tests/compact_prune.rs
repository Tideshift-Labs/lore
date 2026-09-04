// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

#[path = "common/committed_audit.rs"]
mod committed_audit;

use lore_object_dispatch::*;
use lore_proto::lore::object_dispatch::v1::*;

const NOW: i64 = 0x018f_3e12_a456;
const REQUEST_ID: &str = "018f3e12-a450-7abc-8def-0123456789ab";
const ATTEMPT_ID: &str = "018f3e12-a451-7abc-8def-0123456789ab";
const BOUNDARY_ID: &str = "boundary-1";
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

fn compact() -> CanonicalObjectStoreCompactReceipt {
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
    let state = validate_and_encode_object_store_request_state(
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
    .expect("closed state fixture");
    let authority = ObjectStoreCompactAuthority::RequestState(Box::new(state));
    let receipt = validate_and_encode_object_store_request_receipt(
        &ObjectStoreRequestReceiptV1 {
            receipt_blake3: Default::default(),
            receipt_committed_at_unix_ms: NOW + 20,
            outcome: Some(object_store_request_receipt_v1::Outcome::RequestState(
                Box::new(match &authority {
                    ObjectStoreCompactAuthority::RequestState(state) => state.value().clone(),
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
                }),
            )),
        },
        &wire_limits(),
    )
    .expect("outcome fixture");
    let plan = decide_object_store_compact_receipt(
        &ObjectStoreCompactReceiptPlannerInput {
            authority: &authority,
            submit_receipt: &receipt,
            get_outcome: &outcome,
            admission_created_at_unix_ms: NOW - 50,
            reserve_put_ack: None,
            provider_attempt_audit: &committed_audit::committed_decisive_audit_sync(
                BOUNDARY_ID,
                REQUEST_ID,
                ATTEMPT_ID,
                NOW,
            ),
            trusted_dependency_floors: None,
            database_now_unix_ms: NOW + 50,
            existing_compact: None,
        },
        &compact_limits(),
    )
    .expect("compact planner fixture");
    match plan {
        ObjectStoreCompactReceiptDecision::ApplyCompaction { compact, .. } => compact,
        other => panic!("compact fixture did not apply: {other:?}"),
    }
}

fn counter(
    scope: ObjectStoreFullToCompactScope,
    scope_id: &str,
) -> ObjectStoreRecordStorageCounter {
    ObjectStoreRecordStorageCounter {
        scope,
        scope_id: scope_id.to_string(),
        full_record_rows: 9,
        full_record_bytes: 93_000,
        compact_rows: 3,
        compact_bytes: 16_519,
        counter_revision: 8,
    }
}

#[derive(Clone, Copy)]
enum CandidateKind {
    Installed,
    Absent,
    Conflict,
}

struct Fixture {
    compact: CanonicalObjectStoreCompactReceipt,
    sequence: u64,
    candidate_kind: CandidateKind,
    watermark: ObjectStoreCompactPruneWatermark,
    backup: ObjectStoreCompactPruneBackupCoverage,
    database_now_unix_ms: i64,
    global_counter: ObjectStoreRecordStorageCounter,
    cell_counter: ObjectStoreRecordStorageCounter,
    tenant_counter: ObjectStoreRecordStorageCounter,
}

impl Fixture {
    fn input(&self) -> ObjectStoreCompactPruneInput<'_> {
        let candidate = match self.candidate_kind {
            CandidateKind::Installed => ObjectStoreCompactPruneCandidate::CompactInstalled {
                compact_sequence: self.sequence,
                compact: &self.compact,
            },
            CandidateKind::Absent => ObjectStoreCompactPruneCandidate::CompactAbsent {
                compact_sequence: self.sequence,
                compact_blake3: *self.compact.compact_blake3(),
            },
            CandidateKind::Conflict => ObjectStoreCompactPruneCandidate::Conflict,
        };
        ObjectStoreCompactPruneInput {
            candidate,
            watermark: &self.watermark,
            backup_coverage: &self.backup,
            database_now_unix_ms: self.database_now_unix_ms,
            global_counter: &self.global_counter,
            cell_counter: &self.cell_counter,
            tenant_counter: &self.tenant_counter,
        }
    }
}

fn fixture() -> Fixture {
    let compact = compact();
    let global_counter = counter(
        ObjectStoreFullToCompactScope::Global,
        OBJECT_STORE_FULL_TO_COMPACT_GLOBAL_SCOPE_ID,
    );
    let cell_counter = counter(
        ObjectStoreFullToCompactScope::Cell,
        &compact.value().authenticated_cell_id,
    );
    let tenant_counter = counter(
        ObjectStoreFullToCompactScope::Tenant,
        &compact.value().authenticated_tenant_id,
    );
    Fixture {
        compact,
        sequence: 1,
        candidate_kind: CandidateKind::Installed,
        watermark: ObjectStoreCompactPruneWatermark {
            pruned_through_compact_sequence: 0,
            watermark_revision: 3,
            last_prune_fingerprint: None,
            last_compact_blake3: None,
            last_pruned_at_unix_ms: None,
            last_backup_revision: None,
            last_backup_manifest_blake3: None,
        },
        backup: ObjectStoreCompactPruneBackupCoverage {
            backup_revision: "backup-1".to_string(),
            backup_manifest_blake3: OTHER_DIGEST,
            durable_covered_through_compact_sequence: 1,
            restore_verified_through_compact_sequence: 1,
            observed_at_unix_ms: NOW + 120,
        },
        database_now_unix_ms: NOW + 120,
        global_counter,
        cell_counter,
        tenant_counter,
    }
}

fn apply(fixture: &Fixture) -> ObjectStoreCompactPruneDecision {
    let decision = decide_object_store_compact_prune(&fixture.input()).expect("prune decision");
    assert!(matches!(
        decision,
        ObjectStoreCompactPruneDecision::ApplyCompactPrune { .. }
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

fn advance_watermark(fixture: &mut Fixture, sequence: u64, pruned_at: i64) {
    fixture.watermark = ObjectStoreCompactPruneWatermark {
        pruned_through_compact_sequence: sequence,
        watermark_revision: 4,
        last_prune_fingerprint: Some(DIGEST),
        last_compact_blake3: Some(*fixture.compact.compact_blake3()),
        last_pruned_at_unix_ms: Some(pruned_at),
        last_backup_revision: Some("backup-previous".to_string()),
        last_backup_manifest_blake3: Some(OTHER_DIGEST),
    };
}

#[test]
fn shared_compact_golden_projects_exact_prune_cas_and_accounting() {
    let fixture = fixture();
    assert_eq!(fixture.compact.canonical_bytes().len(), 6_519);
    assert_eq!(
        fixture.compact.compact_blake3(),
        decode_hex("5c172fbba2f48cda97bbbb2d3e4fde6d54fa25b51e955bfaa6eeb36d65e7f9d1").as_slice()
    );
    let ObjectStoreCompactPruneDecision::ApplyCompactPrune {
        prune_fingerprint,
        expected_compact_blake3,
        expected_watermark_revision,
        expected_counter_revisions,
        next_watermark,
        next_counters,
    } = apply(&fixture)
    else {
        unreachable!("apply helper checks decision")
    };
    assert_eq!(
        prune_fingerprint,
        decode_hex("416b0021f596caee3a78004271537999552cf42b1dd02334d740dd518c5ee033").as_slice()
    );
    assert_eq!(expected_compact_blake3, *fixture.compact.compact_blake3());
    assert_eq!(expected_watermark_revision, 3);
    assert_eq!(
        expected_counter_revisions,
        ObjectStoreFullToCompactExpectedRevisions {
            global: 8,
            cell: 8,
            tenant: 8,
        }
    );
    for counter in [
        &next_counters.global,
        &next_counters.cell,
        &next_counters.tenant,
    ] {
        assert_eq!(counter.full_record_rows, 9);
        assert_eq!(counter.full_record_bytes, 93_000);
        assert_eq!(counter.compact_rows, 2);
        assert_eq!(counter.compact_bytes, 10_000);
        assert_eq!(counter.counter_revision, 9);
    }
    assert_eq!(next_watermark.pruned_through_compact_sequence, 1);
    assert_eq!(next_watermark.watermark_revision, 4);
    assert_eq!(
        next_watermark.last_prune_fingerprint,
        Some(prune_fingerprint)
    );
    assert_eq!(
        next_watermark.last_compact_blake3,
        Some(*fixture.compact.compact_blake3())
    );
    assert_eq!(next_watermark.last_pruned_at_unix_ms, Some(NOW + 120));
    assert_eq!(
        next_watermark.last_backup_revision.as_deref(),
        Some("backup-1")
    );
    assert_eq!(
        next_watermark.last_backup_manifest_blake3,
        Some(OTHER_DIGEST)
    );
}

#[test]
fn prune_floor_is_inclusive_and_gap_wins_before_mutable_checks() {
    let at_floor = fixture();
    assert_eq!(
        at_floor.database_now_unix_ms,
        at_floor.compact.value().compact_prune_after_unix_ms
    );
    assert!(matches!(
        apply(&at_floor),
        ObjectStoreCompactPruneDecision::ApplyCompactPrune { .. }
    ));
    let mut before = fixture();
    before.database_now_unix_ms = before.compact.value().compact_prune_after_unix_ms - 1;
    assert_eq!(
        decide_object_store_compact_prune(&before.input()),
        Ok(ObjectStoreCompactPruneDecision::WaitPruneFloor {
            eligible_at_unix_ms: before.compact.value().compact_prune_after_unix_ms,
        })
    );

    let mut gap = fixture();
    gap.sequence = 2;
    gap.database_now_unix_ms = -1;
    gap.backup.backup_revision.clear();
    gap.global_counter.counter_revision = 0;
    assert_eq!(
        decide_object_store_compact_prune(&gap.input()),
        Ok(ObjectStoreCompactPruneDecision::WaitPruneGap {
            expected_compact_sequence: 1,
        })
    );
}

#[test]
fn backup_coverage_requires_durable_then_restore_and_valid_chronology() {
    let mut fixture = fixture();
    fixture.backup.durable_covered_through_compact_sequence = 0;
    fixture.backup.restore_verified_through_compact_sequence = 0;
    assert_eq!(
        decide_object_store_compact_prune(&fixture.input()),
        Ok(ObjectStoreCompactPruneDecision::WaitBackupCoverage {
            missing: ObjectStoreCompactPruneBackupMissing::DurableBackup,
        })
    );
    fixture.backup.durable_covered_through_compact_sequence = 1;
    assert_eq!(
        decide_object_store_compact_prune(&fixture.input()),
        Ok(ObjectStoreCompactPruneDecision::WaitBackupCoverage {
            missing: ObjectStoreCompactPruneBackupMissing::RestoreVerification,
        })
    );
    fixture.backup.restore_verified_through_compact_sequence = 1;
    fixture.backup.observed_at_unix_ms = fixture.compact.value().compacted_at_unix_ms - 1;
    assert_eq!(
        decide_object_store_compact_prune(&fixture.input()),
        Err(CompactPruneError::InvalidBackupCoverage)
    );
    fixture.backup.observed_at_unix_ms = fixture.database_now_unix_ms + 1;
    assert_eq!(
        decide_object_store_compact_prune(&fixture.input()),
        Err(CompactPruneError::InvalidBackupCoverage)
    );
    fixture.backup.observed_at_unix_ms = fixture.database_now_unix_ms;
    fixture.backup.restore_verified_through_compact_sequence = 2;
    assert_eq!(
        decide_object_store_compact_prune(&fixture.input()),
        Err(CompactPruneError::InvalidBackupCoverage)
    );
}

#[test]
fn absent_replay_wins_before_mutable_values_and_other_lifecycle_orders_conflict() {
    let mut replay = fixture();
    let replay_now = replay.database_now_unix_ms;
    advance_watermark(&mut replay, 3, replay_now);
    replay.candidate_kind = CandidateKind::Absent;
    replay.sequence = 2;
    replay.database_now_unix_ms = -1;
    replay.backup.backup_revision.clear();
    replay.global_counter.counter_revision = 0;
    assert_eq!(
        decide_object_store_compact_prune(&replay.input()),
        Ok(ObjectStoreCompactPruneDecision::ReplayPruned {
            pruned_through_compact_sequence: 3,
        })
    );

    let mut mismatched_high_water = fixture();
    let mismatched_now = mismatched_high_water.database_now_unix_ms;
    advance_watermark(&mut mismatched_high_water, 1, mismatched_now);
    let mismatched_candidate = ObjectStoreCompactPruneCandidate::CompactAbsent {
        compact_sequence: 1,
        compact_blake3: OTHER_DIGEST,
    };
    let mismatched_input = ObjectStoreCompactPruneInput {
        candidate: mismatched_candidate,
        watermark: &mismatched_high_water.watermark,
        backup_coverage: &mismatched_high_water.backup,
        database_now_unix_ms: mismatched_high_water.database_now_unix_ms,
        global_counter: &mismatched_high_water.global_counter,
        cell_counter: &mismatched_high_water.cell_counter,
        tenant_counter: &mismatched_high_water.tenant_counter,
    };
    assert_eq!(
        decide_object_store_compact_prune(&mismatched_input),
        Ok(ObjectStoreCompactPruneDecision::PruneConflict)
    );

    let mut absent_above = fixture();
    absent_above.candidate_kind = CandidateKind::Absent;
    assert_eq!(
        decide_object_store_compact_prune(&absent_above.input()),
        Ok(ObjectStoreCompactPruneDecision::PruneConflict)
    );
    let mut installed_below = fixture();
    let installed_now = installed_below.database_now_unix_ms;
    advance_watermark(&mut installed_below, 1, installed_now);
    assert_eq!(
        decide_object_store_compact_prune(&installed_below.input()),
        Ok(ObjectStoreCompactPruneDecision::PruneConflict)
    );
    let mut conflict = fixture();
    conflict.candidate_kind = CandidateKind::Conflict;
    assert_eq!(
        decide_object_store_compact_prune(&conflict.input()),
        Ok(ObjectStoreCompactPruneDecision::PruneConflict)
    );
}

#[test]
fn watermark_presence_and_advanced_time_chronology_fail_closed() {
    for field in 0..5 {
        let mut initial = fixture();
        match field {
            0 => initial.watermark.last_prune_fingerprint = Some(DIGEST),
            1 => initial.watermark.last_compact_blake3 = Some(DIGEST),
            2 => initial.watermark.last_pruned_at_unix_ms = Some(NOW),
            3 => initial.watermark.last_backup_revision = Some("backup-previous".to_string()),
            4 => initial.watermark.last_backup_manifest_blake3 = Some(DIGEST),
            _ => unreachable!(),
        }
        assert_eq!(
            decide_object_store_compact_prune(&initial.input()),
            Err(CompactPruneError::InvalidWatermark),
            "initial optional field {field} must fail closed"
        );

        let mut advanced = fixture();
        advance_watermark(&mut advanced, 1, NOW);
        match field {
            0 => advanced.watermark.last_prune_fingerprint = None,
            1 => advanced.watermark.last_compact_blake3 = None,
            2 => advanced.watermark.last_pruned_at_unix_ms = None,
            3 => advanced.watermark.last_backup_revision = None,
            4 => advanced.watermark.last_backup_manifest_blake3 = None,
            _ => unreachable!(),
        }
        assert_eq!(
            decide_object_store_compact_prune(&advanced.input()),
            Err(CompactPruneError::InvalidWatermark),
            "advanced optional field {field} must fail closed"
        );
    }

    let mut time_regression = fixture();
    let future_prune_time = time_regression.database_now_unix_ms + 1;
    advance_watermark(&mut time_regression, 1, future_prune_time);
    time_regression.sequence = 2;
    assert_eq!(
        decide_object_store_compact_prune(&time_regression.input()),
        Err(CompactPruneError::InvalidTime)
    );
}

#[test]
fn zero_and_overflowing_sequences_and_revisions_fail_closed() {
    let mut zero = fixture();
    zero.sequence = 0;
    assert_eq!(
        decide_object_store_compact_prune(&zero.input()),
        Err(CompactPruneError::InvalidSequence)
    );
    zero.candidate_kind = CandidateKind::Absent;
    assert_eq!(
        decide_object_store_compact_prune(&zero.input()),
        Err(CompactPruneError::InvalidSequence)
    );

    let mut sequence_overflow = fixture();
    let sequence_overflow_now = sequence_overflow.database_now_unix_ms;
    advance_watermark(&mut sequence_overflow, u64::MAX, sequence_overflow_now);
    sequence_overflow.sequence = u64::MAX;
    assert_eq!(
        decide_object_store_compact_prune(&sequence_overflow.input()),
        Ok(ObjectStoreCompactPruneDecision::PruneConflict)
    );

    let mut watermark_revision = fixture();
    watermark_revision.watermark.watermark_revision = u64::MAX;
    assert_eq!(
        decide_object_store_compact_prune(&watermark_revision.input()),
        Err(CompactPruneError::CounterOverflow)
    );
    let mut counter_revision = fixture();
    counter_revision.tenant_counter.counter_revision = u64::MAX;
    assert_eq!(
        decide_object_store_compact_prune(&counter_revision.input()),
        Err(CompactPruneError::CounterOverflow)
    );
    let mut zero_revision = fixture();
    zero_revision.watermark.watermark_revision = 0;
    assert_eq!(
        decide_object_store_compact_prune(&zero_revision.input()),
        Err(CompactPruneError::InvalidWatermark)
    );
}

#[test]
fn malformed_scopes_underflow_and_child_global_bounds_fail_closed() {
    for mutation in 0..4 {
        let mut fixture = fixture();
        match mutation {
            0 => fixture.global_counter.scope_id = "wrong-global".to_string(),
            1 => fixture.cell_counter.scope = ObjectStoreFullToCompactScope::Tenant,
            2 => fixture.tenant_counter.scope_id = "other-tenant".to_string(),
            3 => fixture.cell_counter.counter_revision = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            decide_object_store_compact_prune(&fixture.input()),
            Err(CompactPruneError::InvalidCounter),
            "counter mutation {mutation} must fail closed"
        );
    }
    for mutation in 0..2 {
        let mut fixture = fixture();
        if mutation == 0 {
            fixture.tenant_counter.compact_rows = 0;
        } else {
            fixture.tenant_counter.compact_bytes = 6_518;
        }
        assert_eq!(
            decide_object_store_compact_prune(&fixture.input()),
            Err(CompactPruneError::CounterUnderflow)
        );
    }
    let mut child = fixture();
    child.cell_counter.compact_rows = child.global_counter.compact_rows + 1;
    assert_eq!(
        decide_object_store_compact_prune(&child.input()),
        Err(CompactPruneError::ChildExceedsGlobal)
    );
}

#[test]
fn returned_apply_projection_owns_detached_strings() {
    let fixture = fixture();
    let backup_ptr = fixture.backup.backup_revision.as_ptr();
    let global_scope_ptr = fixture.global_counter.scope_id.as_ptr();
    let ObjectStoreCompactPruneDecision::ApplyCompactPrune {
        next_watermark,
        next_counters,
        ..
    } = apply(&fixture)
    else {
        unreachable!("apply helper checks decision")
    };
    assert_ne!(
        backup_ptr,
        next_watermark
            .last_backup_revision
            .as_ref()
            .expect("backup revision")
            .as_ptr()
    );
    assert_ne!(global_scope_ptr, next_counters.global.scope_id.as_ptr());
    assert_eq!(apply(&fixture), apply(&fixture));
}
