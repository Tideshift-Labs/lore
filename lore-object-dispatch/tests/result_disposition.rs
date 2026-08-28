// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::AuthenticatedConsumerIdentity;
use lore_object_dispatch::CanonicalObjectStoreFetchHead;
use lore_object_dispatch::CanonicalObjectStoreRequestState;
use lore_object_dispatch::CanonicalTerminalResult;
use lore_object_dispatch::ContinuityWireLimits;
use lore_object_dispatch::ObjectStoreFetchAdmissionDecision;
use lore_object_dispatch::ObjectStoreFetchHeadState;
use lore_object_dispatch::ObjectStorePendingFetchDiscard;
use lore_object_dispatch::ObjectStoreResultAckAuthority;
use lore_object_dispatch::ObjectStoreResultDispositionIntent;
use lore_object_dispatch::RequestIdentityLimits;
use lore_object_dispatch::ResultAckLimits;
use lore_object_dispatch::ResultDiscardLimits;
use lore_object_dispatch::ResultDispositionCasDecision;
use lore_object_dispatch::ResultDispositionCasInput;
use lore_object_dispatch::ResultDispositionConflict;
use lore_object_dispatch::ResultDispositionError;
use lore_object_dispatch::ResultDispositionLimits;
use lore_object_dispatch::TerminalResultLimits;
use lore_object_dispatch::ValidatedObjectStoreResultAck;
use lore_object_dispatch::ValidatedObjectStoreResultDiscard;
use lore_object_dispatch::decide_object_store_fetch_admission;
use lore_object_dispatch::decide_object_store_result_disposition_cas;
use lore_object_dispatch::initialize_object_store_fetch_head;
use lore_object_dispatch::validate_and_encode_object_store_fetch_head;
use lore_object_dispatch::validate_and_encode_object_store_request_state;
use lore_object_dispatch::validate_and_encode_terminal_result;
use lore_object_dispatch::validate_object_store_result_ack;
use lore_object_dispatch::validate_object_store_result_discard;
use lore_proto::lore::object_dispatch::v1::BoolResultV1;
use lore_proto::lore::object_dispatch::v1::ByteResultHandleV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleResultAckProofV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleSupersededProofV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleSupersessionKindV1;
use lore_proto::lore::object_dispatch::v1::GetObjectV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreDispatchAttemptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadAvailabilityV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadReleaseReasonV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadRetentionV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestPhaseV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDispositionV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalResultV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalRetryabilityV1;
use lore_proto::lore::object_dispatch::v1::PutObjectV1;
use lore_proto::lore::object_dispatch::v1::PutSubmitBindingV1;
use lore_proto::lore::object_dispatch::v1::ReservedDimensionV1;
use lore_proto::lore::object_dispatch::v1::ResultConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::object_store_request_v1;
use lore_proto::lore::object_dispatch::v1::object_store_result_ack_v1;
use lore_proto::lore::object_dispatch::v1::object_store_result_discard_v1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1;
use lore_proto::lore::object_dispatch::v1::result_consumer_context_v1;

const NOW: i64 = 1_715_000_000_000;
const LOGICAL_ID: &str = "018f3e12-a456-7abc-8def-0123456789ab";
const ATTEMPT_ID: &str = "018f3e12-a457-7abc-8def-0123456789ab";
const PAYLOAD_DIGEST: [u8; 32] = [9; 32];

#[derive(Clone, Copy)]
enum PayloadFixture {
    Inline,
    Put,
    Get,
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

fn limits() -> ResultDispositionLimits {
    ResultDispositionLimits {
        state: ContinuityWireLimits {
            max_identity_bytes: 256,
            max_canonical_row_bytes: 16_384,
        },
        discard: ResultDiscardLimits {
            ack: ResultAckLimits {
                identity: RequestIdentityLimits {
                    max_identity_bytes: 256,
                    max_authenticated_scope_bytes: 1_024,
                },
                max_terminal_result_id_bytes: 64,
                max_result_handle_bytes: 128,
                max_fingerprint_preimage_bytes: 4_096,
            },
            max_checkpoint_id_bytes: 64,
            max_operation_id_bytes: 64,
            max_revision_id_bytes: 64,
        },
    }
}

#[derive(Clone, Copy)]
struct ObjectStoreFetchLeaseProjection {
    fence_generation: u64,
    new_fetches_fenced: bool,
    open_lease_count: u64,
}

fn fetches(fenced: bool, open: u64) -> ObjectStoreFetchLeaseProjection {
    ObjectStoreFetchLeaseProjection {
        fence_generation: 7,
        new_fetches_fenced: fenced,
        open_lease_count: open,
    }
}

fn fetch_head(
    state: &CanonicalObjectStoreRequestState,
    discard: Option<&ValidatedObjectStoreResultDiscard>,
    fixture: ObjectStoreFetchLeaseProjection,
) -> CanonicalObjectStoreFetchHead {
    let initial = initialize_object_store_fetch_head(
        state,
        NOW,
        &limits().state,
        &lore_object_dispatch::FetchLeaseLimits {
            max_identity_bytes: limits().state.max_identity_bytes,
            max_authenticated_scope_bytes: limits().state.max_identity_bytes,
            max_canonical_record_bytes: limits().state.max_canonical_row_bytes,
            max_canonical_discard_bytes: limits().state.max_canonical_row_bytes,
        },
    )
    .expect("fetch head fixture");
    let mut value = initial.value().clone();
    value.fence_generation = fixture.fence_generation;
    value.open_lease_count = fixture.open_lease_count;
    if fixture.new_fetches_fenced {
        let discard = discard.expect("reserved fetch head needs discard intent");
        value.state = ObjectStoreFetchHeadState::DiscardReserved;
        value.head_revision += 1;
        value.head_committed_at_unix_ms = NOW + 1;
        value.pending_discard = Some(ObjectStorePendingFetchDiscard {
            discard_fingerprint: *discard.discard_fingerprint(),
            canonical_discard_bytes: discard.canonical_discard_bytes().to_vec(),
            expected_request_state_blake3: *state.state_blake3(),
            reserved_at_unix_ms: NOW + 1,
        });
    }
    validate_and_encode_object_store_fetch_head(
        &value,
        &lore_object_dispatch::FetchLeaseLimits {
            max_identity_bytes: limits().state.max_identity_bytes,
            max_authenticated_scope_bytes: limits().state.max_identity_bytes,
            max_canonical_record_bytes: limits().state.max_canonical_row_bytes,
            max_canonical_discard_bytes: limits().state.max_canonical_row_bytes,
        },
    )
    .expect("canonical fetch head fixture")
}

fn terminal(payload: PayloadFixture) -> CanonicalTerminalResult {
    let result = match payload {
        PayloadFixture::Get => {
            object_store_terminal_result_v1::Result::ByteResult(ByteResultHandleV1 {
                handle: "result/body-1".to_string(),
                size: 3,
                blake3: PAYLOAD_DIGEST.to_vec().into(),
                content_length: 3,
                metadata: Vec::new(),
                etag: None,
                version_id: None,
            })
        }
        PayloadFixture::Inline | PayloadFixture::Put => {
            object_store_terminal_result_v1::Result::BoolResult(BoolResultV1 { value: true })
        }
    };
    validate_and_encode_terminal_result(
        &ObjectStoreTerminalResultV1 {
            terminal_result_id: "terminal-1".to_string(),
            canonical_result_blake3: Default::default(),
            canonical_result_size: 0,
            result: Some(result),
        },
        &terminal_limits(),
    )
    .expect("terminal result fixture must be valid")
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

fn retained(kind: ObjectStorePayloadKindV1, handle: &str) -> ObjectStorePayloadRetentionV1 {
    ObjectStorePayloadRetentionV1 {
        payload_kind: kind as i32,
        availability: ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained
            as i32,
        durable_handle: Some(handle.to_string()),
        size: 3,
        blake3: PAYLOAD_DIGEST.to_vec().into(),
        purge_state: ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateEligible as i32,
        purge_eligible_at_unix_ms: Some(NOW + 1),
        purge_receipt: None,
        partial_temp_bytes: 0,
        partial_temp_chunks: 0,
    }
}

fn available_state(payload: PayloadFixture) -> CanonicalObjectStoreRequestState {
    let terminal = terminal(payload);
    let (put_body, result_payload, put_quota, result_quota) = match payload {
        PayloadFixture::Inline => (
            not_applicable(ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody),
            not_applicable(ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult),
            quota(0, 0, 0),
            quota(0, 0, 0),
        ),
        PayloadFixture::Put => (
            retained(
                ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
                "put/body-1",
            ),
            not_applicable(ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult),
            quota(3, 1, 1),
            quota(0, 0, 0),
        ),
        PayloadFixture::Get => (
            not_applicable(ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody),
            retained(
                ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
                "result/body-1",
            ),
            quota(0, 0, 0),
            quota(3, 1, 0),
        ),
    };
    let reservation = reservation();
    let is_put = matches!(payload, PayloadFixture::Put);
    validate_and_encode_object_store_request_state(
        &ObjectStoreRequestStateV1 {
            protocol_revision: "protocol-1".to_string(),
            provider_boundary_id: "boundary-1".to_string(),
            authenticated_cell_id: "cell-1".to_string(),
            authenticated_tenant_id: "tenant-1".to_string(),
            logical_request_id: LOGICAL_ID.to_string(),
            attempt_id: ATTEMPT_ID.to_string(),
            put_reservation_fingerprint: is_put.then(|| vec![7; 32].into()),
            canonical_descriptor_fingerprint: Some(vec![8; 32].into()),
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
                dispatch_started_at_unix_ms: NOW,
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
            put_body: Some(put_body),
            result_payload: Some(result_payload),
            quota_state: Some(ObjectStoreQuotaStateV1 {
                provider_reservations: vec![reservation],
                put_spool_quota: Some(put_quota),
                result_spool_quota: Some(result_quota),
                retained_metadata_quota: Some(quota(10, 1, 0)),
                quota_revision: 3,
            }),
            state_committed_at_unix_ms: NOW,
            closure_committed_at_unix_ms: None,
            state_blake3: Default::default(),
            policy_revision: "policy-1".to_string(),
            put_submit_binding: is_put.then(|| PutSubmitBindingV1 {
                upload_id: "upload-1".to_string(),
                upload_fence: 2,
                durable_body_handle: "put/body-1".to_string(),
                reservation_expires_at_unix_ms: NOW + 1_000,
                bound_at_unix_ms: NOW,
                binding_fence: 3,
                binding_blake3: Default::default(),
            }),
        },
        &limits().state,
    )
    .expect("available request-state fixture must be valid")
}

fn identity() -> AuthenticatedConsumerIdentity {
    AuthenticatedConsumerIdentity {
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        principal_id: "consumer-1".to_string(),
    }
}

fn context(reader_fence: u64) -> ResultConsumerContextV1 {
    ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::FragmentLifecycle(
            FragmentLifecycleConsumerContextV1 {
                fragment_id: vec![42; 32].into(),
                repository_id: Some("repo-1".to_string()),
                association_context: Some("main".to_string()),
                repository_generation: Some(3),
                association_epoch: Some(4),
                lifecycle_generation: 5,
                fragment_epoch: 6,
                lifecycle_fence: 7,
                reader_lease_id: Some("reader-1".to_string()),
                reader_fence: Some(reader_fence),
            },
        )),
    }
}

fn operation(payload: PayloadFixture) -> object_store_request_v1::Operation {
    match payload {
        PayloadFixture::Get => {
            object_store_request_v1::Operation::GetObject(GetObjectV1::default())
        }
        PayloadFixture::Inline | PayloadFixture::Put => {
            object_store_request_v1::Operation::PutObject(PutObjectV1::default())
        }
    }
}

fn validated_ack(
    state: &CanonicalObjectStoreRequestState,
    payload: PayloadFixture,
    reader_fence: u64,
) -> ValidatedObjectStoreResultAck {
    let terminal = terminal(payload);
    let context = context(reader_fence);
    let operation = operation(payload);
    let identity = identity();
    let terminal_value = terminal.result();
    let byte_handle = match terminal_value.result.as_ref() {
        Some(object_store_terminal_result_v1::Result::ByteResult(value)) => {
            Some(value.handle.clone())
        }
        _ => None,
    };
    let fragment = match context.consumer.as_ref().expect("fixture context") {
        result_consumer_context_v1::Consumer::FragmentLifecycle(value) => value,
        _ => unreachable!(),
    };
    let ack = ObjectStoreResultAckV1 {
        protocol_revision: state.value().protocol_revision.clone(),
        provider_boundary_id: state.value().provider_boundary_id.clone(),
        authenticated_cell_id: state.value().authenticated_cell_id.clone(),
        authenticated_tenant_id: state.value().authenticated_tenant_id.clone(),
        logical_request_id: state.value().logical_request_id.clone(),
        attempt_id: state.value().attempt_id.clone(),
        terminal_result_id: terminal_value.terminal_result_id.clone(),
        canonical_result_size: terminal.canonical_result_size(),
        canonical_result_blake3: terminal.canonical_result_blake3().to_vec().into(),
        byte_result_handle: byte_handle,
        proof: Some(object_store_result_ack_v1::Proof::FragmentLifecycle(
            FragmentLifecycleResultAckProofV1 {
                fragment_id: fragment.fragment_id.clone(),
                repository_id: fragment.repository_id.clone(),
                association_context: fragment.association_context.clone(),
                repository_generation: fragment.repository_generation,
                association_epoch: fragment.association_epoch,
                lifecycle_generation: fragment.lifecycle_generation,
                fragment_epoch: fragment.fragment_epoch,
                lifecycle_fence: fragment.lifecycle_fence,
                reader_lease_id: fragment.reader_lease_id.clone(),
                reader_fence: fragment.reader_fence,
                terminal_result_blake3: terminal.canonical_result_blake3().to_vec().into(),
            },
        )),
    };
    validate_object_store_result_ack(
        &ack,
        &ObjectStoreResultAckAuthority {
            operation: &operation,
            consumer_context: &context,
            authenticated_identity: &identity,
            protocol_revision: "protocol-1",
            provider_boundary_id: "boundary-1",
            authenticated_cell_id: "cell-1",
            authenticated_tenant_id: "tenant-1",
            logical_request_id: LOGICAL_ID,
            attempt_id: ATTEMPT_ID,
            terminal_result: &terminal,
        },
        &limits().discard.ack,
    )
    .expect("ACK intent fixture must validate independently")
}

fn validated_discard(
    state: &CanonicalObjectStoreRequestState,
    payload: PayloadFixture,
    checkpoint_suffix: &str,
) -> ValidatedObjectStoreResultDiscard {
    let terminal = terminal(payload);
    let context = context(8);
    let operation = operation(payload);
    let identity = identity();
    let terminal_value = terminal.result();
    let byte_handle = match terminal_value.result.as_ref() {
        Some(object_store_terminal_result_v1::Result::ByteResult(value)) => {
            Some(value.handle.clone())
        }
        _ => None,
    };
    let fragment = match context.consumer.as_ref().expect("fixture context") {
        result_consumer_context_v1::Consumer::FragmentLifecycle(value) => value,
        _ => unreachable!(),
    };
    let discard = ObjectStoreResultDiscardV1 {
        protocol_revision: state.value().protocol_revision.clone(),
        provider_boundary_id: state.value().provider_boundary_id.clone(),
        authenticated_cell_id: state.value().authenticated_cell_id.clone(),
        authenticated_tenant_id: state.value().authenticated_tenant_id.clone(),
        logical_request_id: state.value().logical_request_id.clone(),
        attempt_id: state.value().attempt_id.clone(),
        terminal_result_id: terminal_value.terminal_result_id.clone(),
        canonical_result_size: terminal.canonical_result_size(),
        canonical_result_blake3: terminal.canonical_result_blake3().to_vec().into(),
        byte_result_handle: byte_handle,
        proof: Some(
            object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(
                FragmentLifecycleSupersededProofV1 {
                    fragment_id: fragment.fragment_id.clone(),
                    repository_id: fragment.repository_id.clone(),
                    association_context: fragment.association_context.clone(),
                    repository_generation: fragment.repository_generation,
                    association_epoch: fragment.association_epoch,
                    lifecycle_generation: fragment.lifecycle_generation,
                    fragment_epoch: fragment.fragment_epoch,
                    lifecycle_fence: fragment.lifecycle_fence,
                    reader_lease_id: fragment.reader_lease_id.clone(),
                    reader_fence: fragment.reader_fence,
                    supersession_kind: FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor as i32,
                    superseding_lifecycle_generation: Some(6),
                    superseding_fragment_epoch: Some(7),
                    superseding_lifecycle_fence: Some(8),
                    no_exposure_checkpoint_id: format!("no-exposure-{checkpoint_suffix}"),
                    no_exposure_checkpoint_revision: 11,
                    no_exposure_checkpoint_fence: 12,
                    terminal_result_blake3: terminal.canonical_result_blake3().to_vec().into(),
                    successor_repository_generation: None,
                    successor_association_epoch: None,
                    repository_tombstone_revision: None,
                },
            ),
        ),
    };
    validate_object_store_result_discard(
        &discard,
        &ObjectStoreResultAckAuthority {
            operation: &operation,
            consumer_context: &context,
            authenticated_identity: &identity,
            protocol_revision: "protocol-1",
            provider_boundary_id: "boundary-1",
            authenticated_cell_id: "cell-1",
            authenticated_tenant_id: "tenant-1",
            logical_request_id: LOGICAL_ID,
            attempt_id: ATTEMPT_ID,
            terminal_result: &terminal,
        },
        &limits().discard,
    )
    .expect("discard intent fixture must validate independently")
}

fn ack_decision(
    state: &CanonicalObjectStoreRequestState,
    ack: &ValidatedObjectStoreResultAck,
    now: i64,
    retention: i64,
) -> Result<ResultDispositionCasDecision, ResultDispositionError> {
    let has_fetch_head = matches!(
        state
            .value()
            .terminal_result
            .as_ref()
            .and_then(|value| value.result.as_ref()),
        Some(object_store_terminal_result_v1::Result::ByteResult(_))
    ) && state.value().result_disposition
        == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable as i32;
    let fetch_head = has_fetch_head.then(|| fetch_head(state, None, fetches(false, 0)));
    decide_object_store_result_disposition_cas(
        &ResultDispositionCasInput {
            current_state: state,
            intent: ObjectStoreResultDispositionIntent::Ack(ack),
            database_now_unix_ms: now,
            minimum_retention_ms: retention,
            fetch_head: fetch_head.as_ref(),
        },
        &limits(),
    )
}

fn discard_decision(
    state: &CanonicalObjectStoreRequestState,
    discard: &ValidatedObjectStoreResultDiscard,
    now: i64,
    retention: i64,
    fetch_leases: ObjectStoreFetchLeaseProjection,
) -> Result<ResultDispositionCasDecision, ResultDispositionError> {
    let has_fetch_head = matches!(
        state
            .value()
            .terminal_result
            .as_ref()
            .and_then(|value| value.result.as_ref()),
        Some(object_store_terminal_result_v1::Result::ByteResult(_))
    ) && state.value().result_disposition
        == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable as i32;
    let fetch_head = has_fetch_head.then(|| fetch_head(state, Some(discard), fetch_leases));
    decide_object_store_result_disposition_cas(
        &ResultDispositionCasInput {
            current_state: state,
            intent: ObjectStoreResultDispositionIntent::Discard(discard),
            database_now_unix_ms: now,
            minimum_retention_ms: retention,
            fetch_head: fetch_head.as_ref(),
        },
        &limits(),
    )
}

#[test]
fn available_ack_applies_exact_state_bound_plan_for_inline_and_retained_payloads() {
    for payload in [
        PayloadFixture::Inline,
        PayloadFixture::Put,
        PayloadFixture::Get,
    ] {
        let current = available_state(payload);
        let ack = validated_ack(&current, payload, 8);
        let decision = ack_decision(&current, &ack, NOW + 10, 50).expect("ACK must apply");
        let ResultDispositionCasDecision::ApplyAck {
            expected_state_blake3,
            next_state,
            receipt,
            ..
        } = decision
        else {
            panic!("expected ACK apply plan");
        };
        assert_eq!(expected_state_blake3, *current.state_blake3());
        assert_ne!(next_state.state_blake3(), current.state_blake3());
        assert_eq!(receipt.acked_at_unix_ms, NOW + 10);
        assert_eq!(
            receipt.payload_purge_after_unix_ms,
            match payload {
                PayloadFixture::Inline => None,
                PayloadFixture::Put | PayloadFixture::Get => Some(NOW + 60),
            }
        );
        assert_eq!(next_state.value().ack_receipt.as_ref(), Some(&receipt));
        assert!(next_state.value().discard_receipt.is_none());
    }
}

#[test]
fn byte_result_ack_cannot_precede_the_persisted_fetch_head_commit() {
    let current = available_state(PayloadFixture::Get);
    let ack = validated_ack(&current, PayloadFixture::Get, 8);
    let initial = fetch_head(&current, None, fetches(false, 0));
    let mut future_value = initial.value().clone();
    future_value.head_committed_at_unix_ms = NOW + 20;
    let future_head = validate_and_encode_object_store_fetch_head(
        &future_value,
        &lore_object_dispatch::FetchLeaseLimits {
            max_identity_bytes: limits().state.max_identity_bytes,
            max_authenticated_scope_bytes: limits().state.max_identity_bytes,
            max_canonical_record_bytes: limits().state.max_canonical_row_bytes,
            max_canonical_discard_bytes: limits().state.max_canonical_row_bytes,
        },
    )
    .expect("future fetch-head fixture");

    assert_eq!(
        decide_object_store_result_disposition_cas(
            &ResultDispositionCasInput {
                current_state: &current,
                intent: ObjectStoreResultDispositionIntent::Ack(&ack),
                database_now_unix_ms: NOW + 10,
                minimum_retention_ms: 50,
                fetch_head: Some(&future_head),
            },
            &limits(),
        ),
        Err(ResultDispositionError::InvalidTime)
    );
}

#[test]
fn discard_fences_then_waits_for_drain_before_applying() {
    let current = available_state(PayloadFixture::Get);
    let discard = validated_discard(&current, PayloadFixture::Get, "one");
    assert!(matches!(
        discard_decision(&current, &discard, NOW + 1, 0, fetches(false, u64::MAX)),
        Ok(ResultDispositionCasDecision::ReserveFetchDiscard { next_fetch_head, .. })
            if next_fetch_head.value().state == ObjectStoreFetchHeadState::DiscardReserved
                && next_fetch_head.value().fence_generation == 8
    ));
    assert!(matches!(
        discard_decision(&current, &discard, -1, 0, fetches(true, 1)),
        Ok(ResultDispositionCasDecision::WaitForFetchDrain {
            fence_generation: 7,
            open_lease_count: 1,
            ..
        })
    ));
    assert!(matches!(
        discard_decision(&current, &discard, -1, 0, fetches(true, u64::MAX)),
        Ok(ResultDispositionCasDecision::WaitForFetchDrain {
            open_lease_count: u64::MAX,
            ..
        })
    ));
    let decision = discard_decision(&current, &discard, NOW + 10, 50, fetches(true, 0))
        .expect("fenced and drained discard must apply");
    let ResultDispositionCasDecision::ApplyDiscard {
        expected_state_blake3,
        expected_fetch_head_blake3,
        next_fetch_head,
        next_state,
        receipt,
    } = decision
    else {
        panic!("expected discard apply plan");
    };
    assert_eq!(expected_state_blake3, *current.state_blake3());
    assert!(expected_fetch_head_blake3.is_some());
    assert_eq!(
        next_fetch_head
            .as_ref()
            .expect("committed fetch head")
            .value()
            .state,
        ObjectStoreFetchHeadState::DiscardCommitted
    );
    assert_eq!(receipt.payload_purge_after_unix_ms, Some(NOW + 60));
    assert_eq!(next_state.value().discard_receipt.as_ref(), Some(&receipt));
    assert!(next_state.value().ack_receipt.is_none());
}

#[test]
fn reserved_fetch_discard_wins_ack_and_only_the_exact_discard_can_resume() {
    let current = available_state(PayloadFixture::Get);
    let ack = validated_ack(&current, PayloadFixture::Get, 8);
    let discard = validated_discard(&current, PayloadFixture::Get, "one");
    let changed = validated_discard(&current, PayloadFixture::Get, "two");
    let reserved = fetch_head(&current, Some(&discard), fetches(true, 0));

    assert_eq!(
        decide_object_store_result_disposition_cas(
            &ResultDispositionCasInput {
                current_state: &current,
                intent: ObjectStoreResultDispositionIntent::Ack(&ack),
                database_now_unix_ms: NOW + 10,
                minimum_retention_ms: 50,
                fetch_head: Some(&reserved),
            },
            &limits(),
        ),
        Ok(ResultDispositionCasDecision::Conflict(
            ResultDispositionConflict::AckAfterDiscardReservation
        ))
    );
    assert_eq!(
        decide_object_store_result_disposition_cas(
            &ResultDispositionCasInput {
                current_state: &current,
                intent: ObjectStoreResultDispositionIntent::Discard(&changed),
                database_now_unix_ms: NOW + 10,
                minimum_retention_ms: 50,
                fetch_head: Some(&reserved),
            },
            &limits(),
        ),
        Ok(ResultDispositionCasDecision::Conflict(
            ResultDispositionConflict::DiscardReservationMismatch
        ))
    );
    assert!(matches!(
        decide_object_store_result_disposition_cas(
            &ResultDispositionCasInput {
                current_state: &current,
                intent: ObjectStoreResultDispositionIntent::Discard(&discard),
                database_now_unix_ms: NOW + 10,
                minimum_retention_ms: 50,
                fetch_head: Some(&reserved),
            },
            &limits(),
        ),
        Ok(ResultDispositionCasDecision::ApplyDiscard {
            next_fetch_head: Some(head),
            ..
        }) if head.value().state == ObjectStoreFetchHeadState::DiscardCommitted
    ));
}

#[test]
fn ack_then_discard_and_discard_then_ack_have_exactly_one_winner() {
    let initial = available_state(PayloadFixture::Inline);
    let ack = validated_ack(&initial, PayloadFixture::Inline, 8);
    let discard = validated_discard(&initial, PayloadFixture::Inline, "one");
    let ResultDispositionCasDecision::ApplyAck { next_state, .. } =
        ack_decision(&initial, &ack, NOW + 10, 50).expect("ACK winner")
    else {
        panic!("expected ACK winner");
    };
    assert_eq!(
        discard_decision(&next_state, &discard, -1, 0, fetches(false, u64::MAX)),
        Ok(ResultDispositionCasDecision::Conflict(
            ResultDispositionConflict::DiscardAfterAck
        ))
    );

    let ResultDispositionCasDecision::ApplyDiscard { next_state, .. } =
        discard_decision(&initial, &discard, NOW + 10, 50, fetches(true, 0))
            .expect("discard winner")
    else {
        panic!("expected discard winner");
    };
    assert_eq!(
        ack_decision(&next_state, &ack, -1, 0),
        Ok(ResultDispositionCasDecision::Conflict(
            ResultDispositionConflict::AckAfterDiscard
        ))
    );
}

#[test]
fn exact_replay_precedes_clock_retention_payload_and_fetch_projection_validation() {
    let initial = available_state(PayloadFixture::Get);
    let ack = validated_ack(&initial, PayloadFixture::Get, 8);
    let discard = validated_discard(&initial, PayloadFixture::Get, "one");
    let ResultDispositionCasDecision::ApplyAck {
        next_state,
        receipt,
        ..
    } = ack_decision(&initial, &ack, NOW + 10, 50).expect("ACK apply")
    else {
        panic!("expected ACK apply");
    };
    let next_state = disposed_result_state(&next_state);
    let replay = ack_decision(&next_state, &ack, -1, 0)
        .expect("ACK replay bypasses later inputs after payload purge");
    assert!(matches!(
        replay,
        ResultDispositionCasDecision::ReplayAck { receipt: replayed, .. }
            if replayed == receipt
    ));

    let ResultDispositionCasDecision::ApplyDiscard {
        next_state,
        receipt,
        ..
    } = discard_decision(&initial, &discard, NOW + 10, 50, fetches(true, 0))
        .expect("discard apply")
    else {
        panic!("expected discard apply");
    };
    let next_state = disposed_result_state(&next_state);
    let replay = discard_decision(
        &next_state,
        &discard,
        -1,
        0,
        ObjectStoreFetchLeaseProjection {
            fence_generation: 0,
            new_fetches_fenced: false,
            open_lease_count: u64::MAX,
        },
    )
    .expect("discard replay bypasses later inputs");
    assert!(matches!(
        replay,
        ResultDispositionCasDecision::ReplayDiscard { receipt: replayed, .. }
            if replayed == receipt
    ));
}

#[test]
fn same_kind_changed_fingerprint_is_a_reuse_conflict() {
    let initial = available_state(PayloadFixture::Inline);
    let ack = validated_ack(&initial, PayloadFixture::Inline, 8);
    let changed_ack = validated_ack(&initial, PayloadFixture::Inline, 9);
    let ResultDispositionCasDecision::ApplyAck { next_state, .. } =
        ack_decision(&initial, &ack, NOW + 10, 50).expect("ACK apply")
    else {
        panic!("expected ACK apply");
    };
    assert_eq!(
        ack_decision(&next_state, &changed_ack, NOW + 20, 60),
        Ok(ResultDispositionCasDecision::Conflict(
            ResultDispositionConflict::FingerprintReuse
        ))
    );

    let discard = validated_discard(&initial, PayloadFixture::Inline, "one");
    let changed_discard = validated_discard(&initial, PayloadFixture::Inline, "two");
    let ResultDispositionCasDecision::ApplyDiscard { next_state, .. } =
        discard_decision(&initial, &discard, NOW + 10, 50, fetches(true, 0))
            .expect("discard apply")
    else {
        panic!("expected discard apply");
    };
    assert_eq!(
        discard_decision(
            &next_state,
            &changed_discard,
            NOW + 20,
            60,
            fetches(true, 0)
        ),
        Ok(ResultDispositionCasDecision::Conflict(
            ResultDispositionConflict::FingerprintReuse
        ))
    );
}

#[test]
fn first_seen_time_retention_and_fetch_fence_overflow_fail_closed() {
    let current = available_state(PayloadFixture::Inline);
    let ack = validated_ack(&current, PayloadFixture::Inline, 8);
    for (now, retention, expected) in [
        (NOW - 1, 1, ResultDispositionError::InvalidTime),
        (NOW, 0, ResultDispositionError::InvalidTime),
        (i64::MAX, 1, ResultDispositionError::RetentionOverflow),
    ] {
        assert_eq!(ack_decision(&current, &ack, now, retention), Err(expected));
    }

    let get = available_state(PayloadFixture::Get);
    let discard = validated_discard(&get, PayloadFixture::Get, "one");
    assert_eq!(
        discard_decision(
            &get,
            &discard,
            NOW,
            1,
            ObjectStoreFetchLeaseProjection {
                fence_generation: u64::MAX,
                new_fetches_fenced: false,
                open_lease_count: 0,
            }
        ),
        Err(ResultDispositionError::FetchFenceOverflow)
    );
    assert_eq!(
        decide_object_store_result_disposition_cas(
            &ResultDispositionCasInput {
                current_state: &get,
                intent: ObjectStoreResultDispositionIntent::Discard(&discard),
                database_now_unix_ms: NOW,
                minimum_retention_ms: 1,
                fetch_head: None,
            },
            &limits(),
        ),
        Err(ResultDispositionError::InvalidFetchProjection)
    );

    let put = available_state(PayloadFixture::Put);
    let mut future_bound_value = put.value().clone();
    let binding = future_bound_value
        .put_submit_binding
        .as_mut()
        .expect("PUT binding fixture");
    binding.bound_at_unix_ms = NOW + 11;
    binding.binding_blake3 = Default::default();
    future_bound_value.state_blake3 = Default::default();
    let future_bound =
        validate_and_encode_object_store_request_state(&future_bound_value, &limits().state)
            .expect("future-bound PUT state remains canonical");
    let put_ack = validated_ack(&future_bound, PayloadFixture::Put, 8);
    assert_eq!(
        ack_decision(&future_bound, &put_ack, NOW + 10, 1),
        Err(ResultDispositionError::InvalidTime)
    );
}

#[test]
fn independently_validated_intent_must_match_the_current_terminal_tuple() {
    let current = available_state(PayloadFixture::Inline);
    let other = available_state(PayloadFixture::Get);
    let other_ack = validated_ack(&other, PayloadFixture::Get, 8);
    assert_eq!(
        ack_decision(&current, &other_ack, NOW + 1, 1),
        Err(ResultDispositionError::IntentMismatch)
    );
}

#[test]
fn fetch_admission_orders_disposed_discarded_fenced_and_retained_states() {
    let available = available_state(PayloadFixture::Get);
    let discard = validated_discard(&available, PayloadFixture::Get, "one");
    let available_head = fetch_head(&available, None, fetches(false, 2));
    let fenced_head = fetch_head(&available, Some(&discard), fetches(true, 0));
    assert_eq!(
        decide_object_store_fetch_admission(&available, Some(&available_head), &limits().state),
        Ok(ObjectStoreFetchAdmissionDecision::Admit {
            fence_generation: 7
        })
    );
    assert_eq!(
        decide_object_store_fetch_admission(&available, Some(&fenced_head), &limits().state),
        Ok(ObjectStoreFetchAdmissionDecision::FetchesFenced)
    );

    let ack = validated_ack(&available, PayloadFixture::Get, 8);
    let ResultDispositionCasDecision::ApplyAck {
        next_state: acked, ..
    } = ack_decision(&available, &ack, NOW + 10, 50).expect("ACK apply")
    else {
        panic!("expected ACK apply");
    };
    assert_eq!(
        decide_object_store_fetch_admission(&acked, Some(&available_head), &limits().state),
        Ok(ObjectStoreFetchAdmissionDecision::Admit {
            fence_generation: 7
        })
    );

    let ResultDispositionCasDecision::ApplyDiscard {
        next_state: discarded,
        ..
    } = discard_decision(&available, &discard, NOW + 10, 50, fetches(true, 0))
        .expect("discard apply")
    else {
        panic!("expected discard apply");
    };
    assert_eq!(
        decide_object_store_fetch_admission(&discarded, None, &limits().state,),
        Ok(ObjectStoreFetchAdmissionDecision::ResultDiscarded)
    );

    let disposed = disposed_result_state(&discarded);
    assert_eq!(
        decide_object_store_fetch_admission(&disposed, None, &limits().state,),
        Ok(ObjectStoreFetchAdmissionDecision::ResultPayloadDisposed)
    );
    assert_eq!(
        decide_object_store_fetch_admission(
            &available_state(PayloadFixture::Inline),
            None,
            &limits().state,
        ),
        Ok(ObjectStoreFetchAdmissionDecision::NotFetchable)
    );
}

fn disposed_result_state(
    discarded: &CanonicalObjectStoreRequestState,
) -> CanonicalObjectStoreRequestState {
    let mut value = discarded.value().clone();
    let (release_reason, disposition) = match value.result_disposition {
        value if value == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32 => (
            ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonAckedRetentionElapsed,
            ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked,
        ),
        value
            if value
                == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded as i32 =>
        {
            (
                ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonDiscardedRetentionElapsed,
                ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded,
            )
        }
        _ => panic!("disposed fixture requires a decided state"),
    };
    let retention = value
        .result_payload
        .as_mut()
        .expect("fixture result retention");
    retention.availability =
        ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityDisposed as i32;
    retention.purge_state =
        ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStatePurged as i32;
    retention.purge_receipt = Some(ObjectStorePayloadPurgeReceiptV1 {
        purge_id: "purge-1".to_string(),
        payload_kind: ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult as i32,
        terminal_result_id: Some("terminal-1".to_string()),
        disposition: disposition as i32,
        released_bytes: 3,
        released_rows: 1,
        released_concurrency: 0,
        purged_at_unix_ms: NOW + 61,
        provider_authority_refunded: false,
        receipt_blake3: Default::default(),
        release_reason: release_reason as i32,
        deleted_partial_temp_bytes: 0,
        deleted_partial_temp_files: 0,
    });
    value
        .quota_state
        .as_mut()
        .expect("fixture quota")
        .result_spool_quota = Some(quota(0, 0, 0));
    value.state_committed_at_unix_ms = NOW + 61;
    value.closure_committed_at_unix_ms = Some(NOW + 61);
    value.state_blake3 = Default::default();
    validate_and_encode_object_store_request_state(&value, &limits().state)
        .expect("disposed result state fixture must be valid")
}

#[test]
fn planner_is_deterministic_detached_redacted_and_effect_free() {
    let current = available_state(PayloadFixture::Put);
    let original = current.clone();
    let ack = validated_ack(&current, PayloadFixture::Put, 8);
    let first = ack_decision(&current, &ack, NOW + 10, 50).expect("first plan");
    let second = ack_decision(&current, &ack, NOW + 10, 50).expect("second plan");
    assert_eq!(first, second);
    assert_eq!(current, original);
    let debug = format!("{first:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("terminal-1"));
    assert!(!debug.contains("put/body-1"));
}
