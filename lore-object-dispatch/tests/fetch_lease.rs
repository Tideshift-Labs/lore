// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::CanonicalObjectStoreFetchHead;
use lore_object_dispatch::CanonicalObjectStoreFetchLease;
use lore_object_dispatch::ContinuityWireLimits;
use lore_object_dispatch::FetchLeaseError;
use lore_object_dispatch::FetchLeaseLimits;
use lore_object_dispatch::ObjectStoreFetchChunkPermit;
use lore_object_dispatch::ObjectStoreFetchHead;
use lore_object_dispatch::ObjectStoreFetchHeadState;
use lore_object_dispatch::ObjectStoreFetchLease;
use lore_object_dispatch::ObjectStoreFetchLeaseState;
use lore_object_dispatch::ObjectStoreFetchLeaseTerminalReason;
use lore_object_dispatch::ObjectStoreFetchOwnerRevocationEvidence;
use lore_object_dispatch::ObjectStoreFetchPayloadPurgeFenceDecision;
use lore_object_dispatch::ObjectStoreFetchResolvedCallerAuthority;
use lore_object_dispatch::OpenObjectStoreFetchLeaseDecision;
use lore_object_dispatch::OpenObjectStoreFetchLeaseInput;
use lore_object_dispatch::ReserveObjectStoreFetchDiscardDecision;
use lore_object_dispatch::ReserveObjectStoreFetchDiscardInput;
use lore_object_dispatch::TerminalObjectStoreFetchLeaseDecision;
use lore_object_dispatch::TerminalObjectStoreFetchLeaseInput;
use lore_object_dispatch::TerminalResultLimits;
use lore_object_dispatch::commit_object_store_fetch_discard;
use lore_object_dispatch::decide_cancel_object_store_fetch_lease;
use lore_object_dispatch::decide_cancel_orphaned_object_store_fetch_lease;
use lore_object_dispatch::decide_close_object_store_fetch_lease;
use lore_object_dispatch::decide_object_store_fetch_chunk;
use lore_object_dispatch::decide_object_store_fetch_payload_purge_fence;
use lore_object_dispatch::decide_open_object_store_fetch_lease;
use lore_object_dispatch::decide_reserve_object_store_fetch_discard;
use lore_object_dispatch::fingerprint_object_store_fetch_lease_cancel;
use lore_object_dispatch::fingerprint_object_store_fetch_lease_close;
use lore_object_dispatch::initialize_object_store_fetch_head;
use lore_object_dispatch::validate_and_encode_object_store_fetch_head;
use lore_object_dispatch::validate_and_encode_object_store_fetch_lease;
use lore_object_dispatch::validate_and_encode_object_store_fetch_owner_revocation;
use lore_object_dispatch::validate_and_encode_object_store_request_state;
use lore_object_dispatch::validate_and_encode_terminal_result;
use lore_object_dispatch::validate_object_store_fetch_projection;
use lore_proto::lore::object_dispatch::v1::ByteResultHandleV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreDispatchAttemptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadAvailabilityV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadRetentionV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestPhaseV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDispositionV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalResultV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalRetryabilityV1;
use lore_proto::lore::object_dispatch::v1::ReservedDimensionV1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1;

const NOW: i64 = 1_700_000_000_000;
const LOGICAL_ID: &str = "018f3e12-a450-7abc-8def-0123456789ab";
const ATTEMPT_ID: &str = "018f3e12-a451-7abc-8def-0123456789ab";
const LEASE_ID: &str = "018f3e12-a452-7abc-8def-0123456789ab";
const REVOCATION_ID: &str = "018f3e12-a453-7abc-8def-0123456789ab";
const RESULT_DIGEST: [u8; 32] = [0x51; 32];
const DESCRIPTOR_DIGEST: [u8; 32] = [0x31; 32];

fn state_limits() -> ContinuityWireLimits {
    ContinuityWireLimits {
        max_identity_bytes: 256,
        max_canonical_row_bytes: 16_384,
    }
}

fn limits() -> FetchLeaseLimits {
    FetchLeaseLimits {
        max_identity_bytes: 256,
        max_authenticated_scope_bytes: 1_024,
        max_canonical_record_bytes: 16_384,
        max_canonical_discard_bytes: 4_096,
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

fn retained_result() -> ObjectStorePayloadRetentionV1 {
    ObjectStorePayloadRetentionV1 {
        payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult as i32,
        availability: ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained
            as i32,
        durable_handle: Some("result-1".to_string()),
        size: 5,
        blake3: RESULT_DIGEST.to_vec().into(),
        purge_state: ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateNotEligible as i32,
        purge_eligible_at_unix_ms: None,
        purge_receipt: None,
        partial_temp_bytes: 0,
        partial_temp_chunks: 0,
    }
}

fn request_state() -> lore_object_dispatch::CanonicalObjectStoreRequestState {
    let terminal = validate_and_encode_terminal_result(
        &ObjectStoreTerminalResultV1 {
            terminal_result_id: "terminal-1".to_string(),
            canonical_result_blake3: Default::default(),
            canonical_result_size: 0,
            result: Some(object_store_terminal_result_v1::Result::ByteResult(
                ByteResultHandleV1 {
                    handle: "result-1".to_string(),
                    size: 5,
                    blake3: RESULT_DIGEST.to_vec().into(),
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
    let reservation = ReservedDimensionV1 {
        reservation_id: "reservation-1".to_string(),
        physical_dimension_id: "physical-1".to_string(),
        operation_class_id: "GET".to_string(),
        units: 1,
    };
    validate_and_encode_object_store_request_state(
        &ObjectStoreRequestStateV1 {
            protocol_revision: "object-dispatch-v1".to_string(),
            provider_boundary_id: "boundary-1".to_string(),
            authenticated_cell_id: "cell-1".to_string(),
            authenticated_tenant_id: "tenant-1".to_string(),
            logical_request_id: LOGICAL_ID.to_string(),
            attempt_id: ATTEMPT_ID.to_string(),
            put_reservation_fingerprint: None,
            canonical_descriptor_fingerprint: Some(DESCRIPTOR_DIGEST.to_vec().into()),
            phase: ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseTerminal as i32,
            allocation_revision: "allocation-1".to_string(),
            allocation_fence: 2,
            cell_admission_id: Some("admission-1".to_string()),
            cell_admission_fence: Some(2),
            reservations: vec![reservation.clone()],
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
            result_disposition:
                ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable as i32,
            ack_receipt: None,
            discard_receipt: None,
            no_dispatch_proof: None,
            put_body: Some(not_applicable(
                ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
            )),
            result_payload: Some(retained_result()),
            quota_state: Some(ObjectStoreQuotaStateV1 {
                provider_reservations: vec![reservation],
                put_spool_quota: Some(quota(0, 0, 0)),
                result_spool_quota: Some(quota(5, 1, 0)),
                retained_metadata_quota: Some(quota(10, 1, 0)),
                quota_revision: 3,
            }),
            state_committed_at_unix_ms: NOW - 5,
            closure_committed_at_unix_ms: None,
            state_blake3: Default::default(),
            policy_revision: "policy-1".to_string(),
            put_submit_binding: None,
        },
        &state_limits(),
    )
    .expect("GET request state fixture")
}

fn head() -> CanonicalObjectStoreFetchHead {
    initialize_object_store_fetch_head(&request_state(), NOW, &state_limits(), &limits())
        .expect("fetch head fixture")
}

fn authority(head: &CanonicalObjectStoreFetchHead) -> ObjectStoreFetchResolvedCallerAuthority {
    ObjectStoreFetchResolvedCallerAuthority {
        result_key: head.value().result_key.clone(),
        owner_service_instance_id: "service-1".to_string(),
        owner_generation: 7,
        owner_authority_revision: 6,
        authenticated_principal_id: "principal-1".to_string(),
        authenticated_scope: "urn:lore:scope-1".to_string(),
        canonical_descriptor_fingerprint: DESCRIPTOR_DIGEST,
        caller_fence: 4,
    }
}

fn opened() -> (
    CanonicalObjectStoreFetchHead,
    CanonicalObjectStoreFetchLease,
) {
    let state = request_state();
    let head =
        initialize_object_store_fetch_head(&state, NOW, &state_limits(), &limits()).expect("head");
    let authority = authority(&head);
    let decision = decide_open_object_store_fetch_lease(
        &OpenObjectStoreFetchLeaseInput {
            current_state: &state,
            current_head: &head,
            existing_lease: None,
            lease_id: LEASE_ID,
            authority: &authority,
            database_now_unix_ms: NOW + 1,
        },
        &state_limits(),
        &limits(),
    )
    .expect("open decision");
    let OpenObjectStoreFetchLeaseDecision::Apply {
        next_head, lease, ..
    } = decision
    else {
        panic!("first open must apply")
    };
    (next_head, *lease)
}

fn reserve(head: &CanonicalObjectStoreFetchHead) -> CanonicalObjectStoreFetchHead {
    let bytes = b"canonical-discard";
    let decision = decide_reserve_object_store_fetch_discard(
        &ReserveObjectStoreFetchDiscardInput {
            current_head: head,
            discard_fingerprint: *blake3::hash(bytes).as_bytes(),
            canonical_discard_bytes: bytes,
            expected_request_state_blake3: *request_state().state_blake3(),
            database_now_unix_ms: NOW + 2,
        },
        &limits(),
    )
    .expect("reserve discard");
    let ReserveObjectStoreFetchDiscardDecision::Apply { next_head, .. } = decision else {
        panic!("first reserve must apply")
    };
    next_head
}

#[test]
fn head_initialization_binds_exact_retained_byte_result_and_pins_canonical_record() {
    let state = request_state();
    assert_eq!(
        initialize_object_store_fetch_head(&state, NOW - 6, &state_limits(), &limits()),
        Err(FetchLeaseError::InvalidTime)
    );
    let head =
        initialize_object_store_fetch_head(&state, NOW, &state_limits(), &limits()).expect("head");
    assert_eq!(head.value().result_key.logical_request_id, LOGICAL_ID);
    assert_eq!(head.value().result_key.byte_result_handle, "result-1");
    assert_eq!(head.value().result_key.payload_size, 5);
    assert_eq!(head.value().state, ObjectStoreFetchHeadState::Unfenced);
    assert_eq!(head.value().fence_generation, 1);
    assert_eq!(head.value().open_lease_count, 0);
    assert_eq!(head.value().head_revision, 1);
    assert_eq!(head.value().head_committed_at_unix_ms, NOW);
    assert_eq!(head.canonical_bytes().len(), 298);
    assert_eq!(
        head.head_blake3(),
        &[
            0x66, 0x99, 0x35, 0xd6, 0x53, 0xce, 0x91, 0x17, 0x46, 0x66, 0xb5, 0x5b, 0x28, 0x3c,
            0x87, 0x23, 0x31, 0x9e, 0xa9, 0x6a, 0x10, 0x43, 0xa8, 0xbf, 0xa0, 0x3f, 0x54, 0xb6,
            0x7f, 0x8f, 0xac, 0xe1,
        ]
    );
}

#[test]
fn open_replays_exact_authority_and_rejects_id_reuse_or_fenced_admission() {
    let state = request_state();
    let initial = head();
    let (opened_head, lease) = opened();
    assert_eq!(opened_head.value().open_lease_count, 1);
    assert_eq!(lease.value().admitted_generation, 1);
    assert_eq!(lease.value().next_chunk_index, 0);
    assert_eq!(lease.value().state, ObjectStoreFetchLeaseState::Open);
    let exact_authority = authority(&opened_head);

    let replay_head = reserve(&opened_head);
    let replay = decide_open_object_store_fetch_lease(
        &OpenObjectStoreFetchLeaseInput {
            current_state: &state,
            current_head: &replay_head,
            existing_lease: Some(&lease),
            lease_id: LEASE_ID,
            authority: &exact_authority,
            database_now_unix_ms: -1,
        },
        &state_limits(),
        &limits(),
    );
    assert!(matches!(
        replay,
        Ok(OpenObjectStoreFetchLeaseDecision::Replay { .. })
    ));

    let changed_authority = ObjectStoreFetchResolvedCallerAuthority {
        owner_generation: 8,
        ..exact_authority.clone()
    };
    let reused = decide_open_object_store_fetch_lease(
        &OpenObjectStoreFetchLeaseInput {
            current_state: &state,
            current_head: &opened_head,
            existing_lease: Some(&lease),
            lease_id: LEASE_ID,
            authority: &changed_authority,
            database_now_unix_ms: NOW + 1,
        },
        &state_limits(),
        &limits(),
    );
    assert_eq!(reused, Err(FetchLeaseError::LeaseIdReuse));

    for changed_authority in [
        ObjectStoreFetchResolvedCallerAuthority {
            authenticated_principal_id: "principal-2".to_string(),
            ..exact_authority.clone()
        },
        ObjectStoreFetchResolvedCallerAuthority {
            authenticated_scope: "urn:lore:scope-2".to_string(),
            ..exact_authority.clone()
        },
    ] {
        assert_eq!(
            decide_open_object_store_fetch_lease(
                &OpenObjectStoreFetchLeaseInput {
                    current_state: &state,
                    current_head: &opened_head,
                    existing_lease: Some(&lease),
                    lease_id: LEASE_ID,
                    authority: &changed_authority,
                    database_now_unix_ms: NOW + 1,
                },
                &state_limits(),
                &limits(),
            ),
            Err(FetchLeaseError::LeaseIdReuse)
        );
    }

    let fenced = reserve(&initial);
    let denied = decide_open_object_store_fetch_lease(
        &OpenObjectStoreFetchLeaseInput {
            current_state: &state,
            current_head: &fenced,
            existing_lease: None,
            lease_id: "018f3e12-a460-7abc-8def-0123456789ab",
            authority: &exact_authority,
            database_now_unix_ms: NOW + 3,
        },
        &state_limits(),
        &limits(),
    );
    assert_eq!(denied, Err(FetchLeaseError::FetchesFenced));
}

#[test]
fn chunk_permits_are_strictly_monotonic_replayable_and_fence_aware() {
    let (head, lease) = opened();
    let authority = authority(&head);
    let ObjectStoreFetchChunkPermit::Grant { next_lease, .. } =
        decide_object_store_fetch_chunk(&head, &lease, &authority, 0, &limits())
            .expect("first chunk")
    else {
        panic!("first chunk must be granted")
    };
    assert_eq!(next_lease.value().next_chunk_index, 1);
    assert!(matches!(
        decide_object_store_fetch_chunk(&head, &next_lease, &authority, 0, &limits()),
        Ok(ObjectStoreFetchChunkPermit::Replay { .. })
    ));
    assert_eq!(
        decide_object_store_fetch_chunk(&head, &next_lease, &authority, 2, &limits()),
        Ok(ObjectStoreFetchChunkPermit::ChunkIndexGap)
    );
    let fenced = reserve(&head);
    assert_eq!(
        decide_object_store_fetch_chunk(&fenced, &next_lease, &authority, 1, &limits()),
        Ok(ObjectStoreFetchChunkPermit::FetchesFenced)
    );
    let cross_authority = ObjectStoreFetchResolvedCallerAuthority {
        authenticated_principal_id: "principal-2".to_string(),
        ..authority
    };
    assert_eq!(
        decide_object_store_fetch_chunk(&head, &next_lease, &cross_authority, 1, &limits()),
        Err(FetchLeaseError::ResultMismatch)
    );
}

#[test]
fn terminal_replay_preserves_evidence_and_decrements_open_count_once() {
    let (head, lease) = opened();
    let authority = authority(&head);
    let fingerprint = fingerprint_object_store_fetch_lease_close(&lease, &authority, &limits())
        .expect("close fingerprint");
    let input = TerminalObjectStoreFetchLeaseInput {
        current_head: &head,
        current_lease: &lease,
        authority: Some(&authority),
        database_now_unix_ms: NOW + 2,
    };
    let cross_authority = ObjectStoreFetchResolvedCallerAuthority {
        authenticated_scope: "urn:lore:scope-2".to_string(),
        ..authority.clone()
    };
    assert_eq!(
        decide_close_object_store_fetch_lease(
            &TerminalObjectStoreFetchLeaseInput {
                authority: Some(&cross_authority),
                ..input
            },
            &limits(),
        ),
        Err(FetchLeaseError::ResultMismatch)
    );
    let TerminalObjectStoreFetchLeaseDecision::Apply {
        next_head,
        next_lease,
        ..
    } = decide_close_object_store_fetch_lease(&input, &limits()).expect("close")
    else {
        panic!("first close must apply")
    };
    assert_eq!(next_head.value().open_lease_count, 0);
    assert_eq!(next_lease.value().state, ObjectStoreFetchLeaseState::Closed);
    assert_eq!(
        next_lease.value().terminal_reason,
        Some(ObjectStoreFetchLeaseTerminalReason::Completed)
    );
    assert_eq!(next_lease.value().terminal_at_unix_ms, Some(NOW + 2));
    assert_eq!(next_lease.value().terminal_fingerprint, Some(fingerprint));
    let replay_head = reserve(&next_head);
    let replay = decide_close_object_store_fetch_lease(
        &TerminalObjectStoreFetchLeaseInput {
            current_head: &replay_head,
            current_lease: &next_lease,
            authority: Some(&authority),
            database_now_unix_ms: -1,
        },
        &limits(),
    );
    assert!(
        matches!(replay, Ok(TerminalObjectStoreFetchLeaseDecision::Replay { lease: replayed }) if replayed == *next_lease)
    );
    for changed_authority in [
        ObjectStoreFetchResolvedCallerAuthority {
            authenticated_principal_id: "principal-2".to_string(),
            ..authority.clone()
        },
        ObjectStoreFetchResolvedCallerAuthority {
            authenticated_scope: "urn:lore:scope-2".to_string(),
            ..authority.clone()
        },
        ObjectStoreFetchResolvedCallerAuthority {
            owner_authority_revision: authority.owner_authority_revision + 1,
            ..authority.clone()
        },
        ObjectStoreFetchResolvedCallerAuthority {
            caller_fence: authority.caller_fence + 1,
            ..authority.clone()
        },
    ] {
        assert_eq!(
            decide_close_object_store_fetch_lease(
                &TerminalObjectStoreFetchLeaseInput {
                    current_head: &replay_head,
                    current_lease: &next_lease,
                    authority: Some(&changed_authority),
                    database_now_unix_ms: -1,
                },
                &limits(),
            ),
            Err(FetchLeaseError::ResultMismatch)
        );
    }
    let changed = fingerprint_object_store_fetch_lease_cancel(
        &next_lease,
        ObjectStoreFetchLeaseTerminalReason::CallerCancelled,
        Some(&authority),
        None,
        &limits(),
    )
    .expect("cancel fingerprint");
    assert_ne!(changed, fingerprint);
    assert_eq!(
        decide_cancel_object_store_fetch_lease(
            &TerminalObjectStoreFetchLeaseInput {
                current_head: &next_head,
                current_lease: &next_lease,
                authority: Some(&authority),
                database_now_unix_ms: NOW + 3,
            },
            ObjectStoreFetchLeaseTerminalReason::CallerCancelled,
            &limits(),
        ),
        Err(FetchLeaseError::TerminalConflict)
    );
}

#[test]
fn cancel_replay_requires_exact_authority_but_ignores_later_clock_and_fence_drift() {
    let (head, lease) = opened();
    let authority = authority(&head);
    let TerminalObjectStoreFetchLeaseDecision::Apply {
        next_head,
        next_lease,
        ..
    } = decide_cancel_object_store_fetch_lease(
        &TerminalObjectStoreFetchLeaseInput {
            current_head: &head,
            current_lease: &lease,
            authority: Some(&authority),
            database_now_unix_ms: NOW + 2,
        },
        ObjectStoreFetchLeaseTerminalReason::CallerCancelled,
        &limits(),
    )
    .expect("cancel")
    else {
        panic!("first cancel must apply")
    };
    let replay_head = reserve(&next_head);
    assert!(matches!(
        decide_cancel_object_store_fetch_lease(
            &TerminalObjectStoreFetchLeaseInput {
                current_head: &replay_head,
                current_lease: &next_lease,
                authority: Some(&authority),
                database_now_unix_ms: -1,
            },
            ObjectStoreFetchLeaseTerminalReason::CallerCancelled,
            &limits(),
        ),
        Ok(TerminalObjectStoreFetchLeaseDecision::Replay { lease: replayed })
            if replayed == *next_lease
    ));

    for changed_authority in [
        ObjectStoreFetchResolvedCallerAuthority {
            authenticated_principal_id: "principal-2".to_string(),
            ..authority.clone()
        },
        ObjectStoreFetchResolvedCallerAuthority {
            authenticated_scope: "urn:lore:scope-2".to_string(),
            ..authority.clone()
        },
        ObjectStoreFetchResolvedCallerAuthority {
            owner_authority_revision: authority.owner_authority_revision + 1,
            ..authority.clone()
        },
        ObjectStoreFetchResolvedCallerAuthority {
            caller_fence: authority.caller_fence + 1,
            ..authority.clone()
        },
    ] {
        assert_eq!(
            decide_cancel_object_store_fetch_lease(
                &TerminalObjectStoreFetchLeaseInput {
                    current_head: &replay_head,
                    current_lease: &next_lease,
                    authority: Some(&changed_authority),
                    database_now_unix_ms: -1,
                },
                ObjectStoreFetchLeaseTerminalReason::CallerCancelled,
                &limits(),
            ),
            Err(FetchLeaseError::ResultMismatch)
        );
    }
}

#[test]
fn payload_purge_fence_cancellation_closes_one_real_open_lease() {
    let (head, lease) = opened();
    let authority = authority(&head);
    let ObjectStoreFetchPayloadPurgeFenceDecision::Apply {
        next_head: fenced, ..
    } = decide_object_store_fetch_payload_purge_fence(&head, NOW + 2, &limits())
        .expect("payload-purge fence")
    else {
        panic!("first payload-purge fence must apply");
    };
    assert_eq!(
        fenced.value().state,
        ObjectStoreFetchHeadState::PayloadPurgeReserved
    );
    assert_eq!(fenced.value().fence_generation, 2);
    assert_eq!(fenced.value().open_lease_count, 1);

    let TerminalObjectStoreFetchLeaseDecision::Apply {
        next_head,
        next_lease,
        ..
    } = decide_cancel_object_store_fetch_lease(
        &TerminalObjectStoreFetchLeaseInput {
            current_head: &fenced,
            current_lease: &lease,
            authority: Some(&authority),
            database_now_unix_ms: NOW + 3,
        },
        ObjectStoreFetchLeaseTerminalReason::PayloadPurgeFenced,
        &limits(),
    )
    .expect("payload-purge fenced cancellation")
    else {
        panic!("payload-purge cancellation must apply");
    };
    assert_eq!(next_head.value().open_lease_count, 0);
    assert_eq!(
        next_head.value().head_revision,
        fenced.value().head_revision + 1
    );
    assert_eq!(
        next_lease.value().state,
        ObjectStoreFetchLeaseState::Cancelled
    );
    assert_eq!(
        next_lease.value().terminal_reason,
        Some(ObjectStoreFetchLeaseTerminalReason::PayloadPurgeFenced)
    );
    assert_eq!(next_lease.value().terminal_at_unix_ms, Some(NOW + 3));
    assert_eq!(
        next_lease.value().lease_revision,
        lease.value().lease_revision + 1
    );
}

#[test]
fn discard_reservation_replays_exactly_conflicts_on_change_and_commits_only_after_drain() {
    let initial = head();
    let bytes = b"canonical-discard";
    let fingerprint = *blake3::hash(bytes).as_bytes();
    let state_digest = *request_state().state_blake3();
    let reserved = reserve(&initial);
    assert_eq!(
        reserved.value().state,
        ObjectStoreFetchHeadState::DiscardReserved
    );
    assert_eq!(reserved.value().fence_generation, 2);
    assert_eq!(
        reserved
            .value()
            .pending_discard
            .as_ref()
            .expect("pending")
            .canonical_discard_bytes,
        bytes
    );
    let replay = decide_reserve_object_store_fetch_discard(
        &ReserveObjectStoreFetchDiscardInput {
            current_head: &reserved,
            discard_fingerprint: fingerprint,
            canonical_discard_bytes: bytes,
            expected_request_state_blake3: state_digest,
            database_now_unix_ms: i64::MAX,
        },
        &limits(),
    );
    assert!(matches!(
        replay,
        Ok(ReserveObjectStoreFetchDiscardDecision::Replay { .. })
    ));
    assert_eq!(
        decide_reserve_object_store_fetch_discard(
            &ReserveObjectStoreFetchDiscardInput {
                current_head: &reserved,
                discard_fingerprint: fingerprint,
                canonical_discard_bytes: bytes,
                expected_request_state_blake3: [3; 32],
                database_now_unix_ms: NOW + 3,
            },
            &limits(),
        ),
        Err(FetchLeaseError::DiscardReservationConflict)
    );

    let mut undrained_value = reserved.value().clone();
    undrained_value.open_lease_count = 1;
    let undrained = validate_and_encode_object_store_fetch_head(&undrained_value, &limits())
        .expect("undrained head");
    assert_eq!(
        commit_object_store_fetch_discard(&undrained, fingerprint, NOW + 3, &limits()),
        Err(FetchLeaseError::InvalidHeadState)
    );
    let committed = commit_object_store_fetch_discard(&reserved, fingerprint, NOW + 3, &limits())
        .expect("commit discard");
    assert_eq!(
        committed.value().state,
        ObjectStoreFetchHeadState::DiscardCommitted
    );
    assert_eq!(
        committed
            .value()
            .pending_discard
            .as_ref()
            .expect("committed reservation")
            .discard_fingerprint,
        fingerprint
    );
}

#[test]
fn orphan_cancel_requires_a_fence_and_strictly_newer_typed_owner_revocation() {
    let (open_head, lease) = opened();
    let evidence = ObjectStoreFetchOwnerRevocationEvidence {
        owner_service_instance_id: "service-1".to_string(),
        revoked_owner_generation: 7,
        successor_owner_generation: 8,
        revocation_id: REVOCATION_ID.to_string(),
        revocation_revision: 9,
        revocation_fence: 10,
        revoked_at_unix_ms: NOW + 2,
    };
    let evidence = validate_and_encode_object_store_fetch_owner_revocation(&evidence, &limits())
        .expect("canonical owner revocation");
    let fingerprint = fingerprint_object_store_fetch_lease_cancel(
        &lease,
        ObjectStoreFetchLeaseTerminalReason::OwnerRevoked,
        None,
        Some(&evidence),
        &limits(),
    )
    .expect("owner-revoked fingerprint");
    let unfenced = TerminalObjectStoreFetchLeaseInput {
        current_head: &open_head,
        current_lease: &lease,
        authority: None,
        database_now_unix_ms: NOW + 3,
    };
    assert_eq!(
        decide_cancel_orphaned_object_store_fetch_lease(&unfenced, &evidence, &limits()),
        Err(FetchLeaseError::InvalidOwnerRevocation)
    );
    let fenced = reserve(&open_head);
    let TerminalObjectStoreFetchLeaseDecision::Apply {
        next_head,
        next_lease,
        ..
    } = decide_cancel_orphaned_object_store_fetch_lease(
        &TerminalObjectStoreFetchLeaseInput {
            current_head: &fenced,
            ..unfenced
        },
        &evidence,
        &limits(),
    )
    .expect("fenced orphan cancellation")
    else {
        panic!("orphan cancellation must apply")
    };
    assert_eq!(next_head.value().open_lease_count, 0);
    assert_eq!(
        next_lease.value().terminal_reason,
        Some(ObjectStoreFetchLeaseTerminalReason::OwnerRevoked)
    );
    assert_eq!(next_lease.value().terminal_fingerprint, Some(fingerprint));
    assert_eq!(
        next_lease.value().owner_revocation.as_ref(),
        Some(evidence.value())
    );
    let mut terminal_before_revocation = next_lease.value().clone();
    terminal_before_revocation.terminal_at_unix_ms = Some(evidence.value().revoked_at_unix_ms - 1);
    assert_eq!(
        validate_and_encode_object_store_fetch_lease(&terminal_before_revocation, &limits()),
        Err(FetchLeaseError::InvalidOwnerRevocation)
    );

    let stale = ObjectStoreFetchOwnerRevocationEvidence {
        successor_owner_generation: 7,
        ..evidence.value().clone()
    };
    let stale = validate_and_encode_object_store_fetch_owner_revocation(&stale, &limits());
    assert_eq!(stale, Err(FetchLeaseError::InvalidOwnerRevocation));

    for stale in [
        ObjectStoreFetchOwnerRevocationEvidence {
            revocation_revision: lease.value().owner_authority_revision,
            ..evidence.value().clone()
        },
        ObjectStoreFetchOwnerRevocationEvidence {
            revocation_fence: lease.value().caller_fence,
            ..evidence.value().clone()
        },
        ObjectStoreFetchOwnerRevocationEvidence {
            owner_service_instance_id: "service-2".to_string(),
            ..evidence.value().clone()
        },
    ] {
        let stale = validate_and_encode_object_store_fetch_owner_revocation(&stale, &limits())
            .expect("independently canonical revocation evidence");
        assert_eq!(
            decide_cancel_orphaned_object_store_fetch_lease(
                &TerminalObjectStoreFetchLeaseInput {
                    current_head: &fenced,
                    current_lease: &lease,
                    authority: None,
                    database_now_unix_ms: NOW + 3,
                },
                &stale,
                &limits(),
            ),
            Err(FetchLeaseError::InvalidOwnerRevocation)
        );
    }
}

#[test]
fn fenced_terminal_reason_requires_the_matching_head_fence() {
    let (head, lease) = opened();
    let authority = authority(&head);
    assert_eq!(
        decide_cancel_object_store_fetch_lease(
            &TerminalObjectStoreFetchLeaseInput {
                current_head: &head,
                current_lease: &lease,
                authority: Some(&authority),
                database_now_unix_ms: NOW + 2,
            },
            ObjectStoreFetchLeaseTerminalReason::DiscardFenced,
            &limits(),
        ),
        Err(FetchLeaseError::FetchesFenced)
    );
}

#[test]
fn canonical_validation_projection_and_debug_fail_closed_without_leaking_authority() {
    let (head, lease) = opened();
    validate_object_store_fetch_projection(&head, std::slice::from_ref(&lease), &limits())
        .expect("valid projection");
    assert_eq!(
        validate_object_store_fetch_projection(&head, &[lease.clone(), lease.clone()], &limits()),
        Err(FetchLeaseError::InvalidProjection)
    );
    assert_eq!(
        validate_object_store_fetch_projection(&head, &[], &limits()),
        Err(FetchLeaseError::InvalidProjection)
    );

    let mut forged_open = lease.value().clone();
    forged_open.authenticated_scope = "urn:lore:changed".to_string();
    assert_eq!(
        validate_and_encode_object_store_fetch_lease(&forged_open, &limits()),
        Err(FetchLeaseError::InvalidCanonicalRecord)
    );

    let authority = authority(&head);
    let TerminalObjectStoreFetchLeaseDecision::Apply { next_lease, .. } =
        decide_close_object_store_fetch_lease(
            &TerminalObjectStoreFetchLeaseInput {
                current_head: &head,
                current_lease: &lease,
                authority: Some(&authority),
                database_now_unix_ms: NOW + 2,
            },
            &limits(),
        )
        .expect("closed lease fixture")
    else {
        panic!("close must apply")
    };
    let mut forged_terminal = next_lease.value().clone();
    forged_terminal
        .terminal_fingerprint
        .as_mut()
        .expect("terminal fingerprint")[0] ^= 1;
    assert_eq!(
        validate_and_encode_object_store_fetch_lease(&forged_terminal, &limits()),
        Err(FetchLeaseError::InvalidCanonicalRecord)
    );

    let mut purge_reserved = head.value().clone();
    purge_reserved.state = ObjectStoreFetchHeadState::PayloadPurgeReserved;
    purge_reserved.fence_generation += 1;
    purge_reserved.pending_discard = None;
    let purge_reserved = validate_and_encode_object_store_fetch_head(&purge_reserved, &limits())
        .expect("purge-reserved head");
    validate_object_store_fetch_projection(
        &purge_reserved,
        std::slice::from_ref(&lease),
        &limits(),
    )
    .expect("purge-reserved projection may retain open leases");

    let mut purge_committed = purge_reserved.value().clone();
    purge_committed.state = ObjectStoreFetchHeadState::PayloadPurgeCommitted;
    purge_committed.open_lease_count = 0;
    let purge_committed = validate_and_encode_object_store_fetch_head(&purge_committed, &limits())
        .expect("purge-committed head");
    validate_object_store_fetch_projection(&purge_committed, &[], &limits())
        .expect("purge-committed projection is drained");
    let mut invalid_purge_committed = purge_committed.value().clone();
    invalid_purge_committed.open_lease_count = 1;
    assert_eq!(
        validate_and_encode_object_store_fetch_head(&invalid_purge_committed, &limits()),
        Err(FetchLeaseError::InvalidHeadState)
    );

    let mut invalid_discard_committed = reserve(&head).value().clone();
    invalid_discard_committed.state = ObjectStoreFetchHeadState::DiscardCommitted;
    assert_eq!(
        validate_and_encode_object_store_fetch_head(&invalid_discard_committed, &limits()),
        Err(FetchLeaseError::InvalidHeadState)
    );

    let mut invalid_discard_time = reserve(&head).value().clone();
    invalid_discard_time
        .pending_discard
        .as_mut()
        .expect("pending discard")
        .reserved_at_unix_ms = invalid_discard_time.head_committed_at_unix_ms + 1;
    assert_eq!(
        validate_and_encode_object_store_fetch_head(&invalid_discard_time, &limits()),
        Err(FetchLeaseError::InvalidTime)
    );

    let debug = format!("{head:?} {lease:?}");
    assert!(debug.contains("[REDACTED]"));
    for secret in [
        LOGICAL_ID,
        ATTEMPT_ID,
        LEASE_ID,
        "principal-1",
        "urn:lore:scope-1",
        "result-1",
    ] {
        assert!(!debug.contains(secret));
    }

    let mut invalid_limits = limits();
    invalid_limits.max_canonical_record_bytes = 1;
    assert_eq!(
        validate_and_encode_object_store_fetch_head(head.value(), &invalid_limits),
        Err(FetchLeaseError::CanonicalTooLarge)
    );
    let mut invalid_lease: ObjectStoreFetchLease = lease.value().clone();
    invalid_lease.terminal_reason = Some(ObjectStoreFetchLeaseTerminalReason::Completed);
    assert_eq!(
        validate_and_encode_object_store_fetch_lease(&invalid_lease, &limits()),
        Err(FetchLeaseError::InvalidLeaseState)
    );
}

#[test]
fn generation_and_count_overflow_are_rejected_without_a_partial_plan() {
    let initial = head();
    let mut count_value: ObjectStoreFetchHead = initial.value().clone();
    count_value.open_lease_count = u64::MAX;
    let count_head = validate_and_encode_object_store_fetch_head(&count_value, &limits())
        .expect("maximum count head");
    let state = request_state();
    let authority = authority(&count_head);
    assert_eq!(
        decide_open_object_store_fetch_lease(
            &OpenObjectStoreFetchLeaseInput {
                current_state: &state,
                current_head: &count_head,
                existing_lease: None,
                lease_id: LEASE_ID,
                authority: &authority,
                database_now_unix_ms: NOW + 1,
            },
            &state_limits(),
            &limits(),
        ),
        Err(FetchLeaseError::CountOverflow)
    );

    let mut generation_value = initial.value().clone();
    generation_value.fence_generation = u64::MAX;
    let generation_head = validate_and_encode_object_store_fetch_head(&generation_value, &limits())
        .expect("maximum generation head");
    let bytes = b"canonical-discard";
    assert_eq!(
        decide_reserve_object_store_fetch_discard(
            &ReserveObjectStoreFetchDiscardInput {
                current_head: &generation_head,
                discard_fingerprint: *blake3::hash(bytes).as_bytes(),
                canonical_discard_bytes: bytes,
                expected_request_state_blake3: *state.state_blake3(),
                database_now_unix_ms: NOW + 2,
            },
            &limits(),
        ),
        Err(FetchLeaseError::GenerationOverflow)
    );
}
