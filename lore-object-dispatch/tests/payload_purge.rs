// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::AuthenticatedConsumerIdentity;
use lore_object_dispatch::CanonicalObjectStoreFetchHead;
use lore_object_dispatch::CanonicalObjectStorePayloadPurgeReservation;
use lore_object_dispatch::CanonicalObjectStoreRequestState;
use lore_object_dispatch::FetchLeaseLimits;
use lore_object_dispatch::ObjectStoreFetchHeadState;
use lore_object_dispatch::ObjectStorePayloadPurgeCasDecision;
use lore_object_dispatch::ObjectStorePayloadPurgeCasInput;
use lore_object_dispatch::ObjectStorePayloadPurgeIntent;
use lore_object_dispatch::ObjectStorePayloadPurgeReservation;
use lore_object_dispatch::ObjectStoreResultAckAuthority;
use lore_object_dispatch::ObjectStoreResultDispositionIntent;
use lore_object_dispatch::PayloadPurgeCasLimits;
use lore_object_dispatch::PayloadPurgeError;
use lore_object_dispatch::RequestIdentityLimits;
use lore_object_dispatch::RequestStateWireLimits;
use lore_object_dispatch::ReserveObjectStoreFetchDiscardDecision;
use lore_object_dispatch::ReserveObjectStoreFetchDiscardInput;
use lore_object_dispatch::ResultAckLimits;
use lore_object_dispatch::ResultDiscardLimits;
use lore_object_dispatch::ResultDispositionCasDecision;
use lore_object_dispatch::ResultDispositionCasInput;
use lore_object_dispatch::ResultDispositionLimits;
use lore_object_dispatch::TerminalResultLimits;
use lore_object_dispatch::decide_object_store_payload_purge_cas;
use lore_object_dispatch::decide_object_store_result_disposition_cas;
use lore_object_dispatch::decide_reserve_object_store_fetch_discard;
use lore_object_dispatch::initialize_object_store_fetch_head;
use lore_object_dispatch::validate_and_encode_object_store_fetch_head;
use lore_object_dispatch::validate_and_encode_object_store_payload_purge_reservation;
use lore_object_dispatch::validate_and_encode_object_store_request_state;
use lore_object_dispatch::validate_and_encode_terminal_result;
use lore_object_dispatch::validate_object_store_result_ack;
use lore_object_dispatch::validate_object_store_result_discard;
use lore_proto::lore::object_dispatch::v1::BoolResultV1;
use lore_proto::lore::object_dispatch::v1::ByteResultHandleV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerCancellationKindV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerCancelledProofV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerKindV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerResultAckProofV1;
use lore_proto::lore::object_dispatch::v1::GetObjectV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreDispatchAttemptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadAvailabilityV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeStateV1;
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

const NOW: i64 = 1_700_000_000_000;
const RETENTION: i64 = 5_000;
const ELIGIBLE: i64 = NOW + RETENTION;
const LOGICAL_ID: &str = "018f3e12-a450-7abc-8def-0123456789ab";
const ATTEMPT_ID: &str = "018f3e12-a451-7abc-8def-0123456789ab";
const PURGE_ID: &str = "018f3e12-a453-7abc-8def-0123456789ab";
const OTHER_PURGE_ID: &str = "018f3e12-a454-7abc-8def-0123456789ab";
const PAYLOAD_DIGEST: [u8; 32] = [0x51; 32];
const SCOPE: &str =
    "urn:lore:object-dispatch:Ym91bmRhcnktMQ:Y2VsbC0x:dGVuYW50LTE:job:Y29uc3VtZXItMQ";

#[derive(Clone, Copy)]
enum PayloadFixture {
    Put,
    Get,
}

#[derive(Clone, Copy)]
enum DispositionFixture {
    Acked,
    Discarded,
}

struct DisposedFixture {
    state: CanonicalObjectStoreRequestState,
    head: Option<CanonicalObjectStoreFetchHead>,
}

fn state_limits() -> RequestStateWireLimits {
    RequestStateWireLimits {
        max_identity_bytes: 256,
        max_canonical_row_bytes: 16_384,
    }
}

fn fetch_limits() -> FetchLeaseLimits {
    FetchLeaseLimits {
        max_identity_bytes: 256,
        max_authenticated_scope_bytes: 1_024,
        max_canonical_record_bytes: 16_384,
        max_canonical_discard_bytes: 4_096,
    }
}

fn purge_limits() -> PayloadPurgeCasLimits {
    PayloadPurgeCasLimits {
        state: state_limits(),
        fetch: fetch_limits(),
    }
}

fn disposition_limits() -> ResultDispositionLimits {
    ResultDispositionLimits {
        state: state_limits(),
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

fn retained(
    kind: ObjectStorePayloadKindV1,
    handle: &str,
    size: u64,
) -> ObjectStorePayloadRetentionV1 {
    ObjectStorePayloadRetentionV1 {
        payload_kind: kind as i32,
        availability: ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained
            as i32,
        durable_handle: Some(handle.to_string()),
        size,
        blake3: PAYLOAD_DIGEST.to_vec().into(),
        purge_state: ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateNotEligible as i32,
        purge_eligible_at_unix_ms: None,
        purge_receipt: None,
        partial_temp_bytes: 0,
        partial_temp_chunks: 0,
    }
}

fn terminal(fixture: PayloadFixture) -> lore_object_dispatch::CanonicalTerminalResult {
    let result = match fixture {
        PayloadFixture::Get => {
            object_store_terminal_result_v1::Result::ByteResult(ByteResultHandleV1 {
                handle: "result-1".to_string(),
                size: 5,
                blake3: PAYLOAD_DIGEST.to_vec().into(),
                content_length: 5,
                metadata: Vec::new(),
                etag: None,
                version_id: None,
            })
        }
        PayloadFixture::Put => {
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
    .expect("terminal fixture")
}

fn available_state(fixture: PayloadFixture) -> CanonicalObjectStoreRequestState {
    let terminal = terminal(fixture);
    let is_get = matches!(fixture, PayloadFixture::Get);
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
            put_reservation_fingerprint: (!is_get).then(|| vec![0x21; 32].into()),
            canonical_descriptor_fingerprint: Some(vec![0x31; 32].into()),
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
            put_body: Some(if is_get {
                not_applicable(ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody)
            } else {
                retained(
                    ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
                    "put-body-1",
                    11,
                )
            }),
            result_payload: Some(if is_get {
                retained(
                    ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
                    "result-1",
                    5,
                )
            } else {
                not_applicable(ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult)
            }),
            quota_state: Some(ObjectStoreQuotaStateV1 {
                provider_reservations: vec![reservation],
                put_spool_quota: Some(if is_get {
                    quota(0, 0, 0)
                } else {
                    quota(11, 1, 1)
                }),
                result_spool_quota: Some(if is_get {
                    quota(5, 1, 0)
                } else {
                    quota(0, 0, 0)
                }),
                retained_metadata_quota: Some(quota(10, 1, 0)),
                quota_revision: 3,
            }),
            state_committed_at_unix_ms: NOW - 5,
            closure_committed_at_unix_ms: None,
            state_blake3: Default::default(),
            policy_revision: "policy-1".to_string(),
            put_submit_binding: (!is_get).then(|| PutSubmitBindingV1 {
                upload_id: "upload-1".to_string(),
                upload_fence: 2,
                durable_body_handle: "put-body-1".to_string(),
                reservation_expires_at_unix_ms: NOW + 60_000,
                bound_at_unix_ms: NOW - 20,
                binding_fence: 3,
                binding_blake3: Default::default(),
            }),
        },
        &state_limits(),
    )
    .expect("available state fixture")
}

fn consumer_context() -> ResultConsumerContextV1 {
    ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::DurableConsumer(
            DurableConsumerContextV1 {
                consumer_kind: DurableConsumerKindV1::DurableConsumerKindJob as i32,
                authenticated_scope: SCOPE.to_string(),
                operation_id: "operation-1".to_string(),
                checkpoint_revision: 1,
                checkpoint_fence: 1,
            },
        )),
    }
}

fn identity() -> AuthenticatedConsumerIdentity {
    AuthenticatedConsumerIdentity {
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        principal_id: "consumer-1".to_string(),
    }
}

fn operation(fixture: PayloadFixture) -> object_store_request_v1::Operation {
    match fixture {
        PayloadFixture::Get => {
            object_store_request_v1::Operation::GetObject(GetObjectV1::default())
        }
        PayloadFixture::Put => {
            object_store_request_v1::Operation::PutObject(PutObjectV1::default())
        }
    }
}

fn disposed_fixture(fixture: PayloadFixture, disposition: DispositionFixture) -> DisposedFixture {
    let state = available_state(fixture);
    let terminal = terminal(fixture);
    let context = consumer_context();
    let identity = identity();
    let operation = operation(fixture);
    let authority = ObjectStoreResultAckAuthority {
        operation: &operation,
        consumer_context: &context,
        authenticated_identity: &identity,
        protocol_revision: "object-dispatch-v1",
        provider_boundary_id: "boundary-1",
        authenticated_cell_id: "cell-1",
        authenticated_tenant_id: "tenant-1",
        logical_request_id: LOGICAL_ID,
        attempt_id: ATTEMPT_ID,
        terminal_result: &terminal,
    };
    let terminal_value = terminal.result();
    let byte_result_handle = match terminal_value.result.as_ref() {
        Some(object_store_terminal_result_v1::Result::ByteResult(value)) => {
            Some(value.handle.clone())
        }
        _ => None,
    };
    let durable = match context.consumer.as_ref().expect("consumer fixture") {
        result_consumer_context_v1::Consumer::DurableConsumer(value) => value,
        _ => unreachable!(),
    };
    let initial_head = matches!(fixture, PayloadFixture::Get).then(|| {
        initialize_object_store_fetch_head(&state, NOW - 4, &state_limits(), &fetch_limits())
            .expect("initial head")
    });
    match disposition {
        DispositionFixture::Acked => {
            let validated = validate_object_store_result_ack(
                &ObjectStoreResultAckV1 {
                    protocol_revision: "object-dispatch-v1".to_string(),
                    provider_boundary_id: "boundary-1".to_string(),
                    authenticated_cell_id: "cell-1".to_string(),
                    authenticated_tenant_id: "tenant-1".to_string(),
                    logical_request_id: LOGICAL_ID.to_string(),
                    attempt_id: ATTEMPT_ID.to_string(),
                    terminal_result_id: "terminal-1".to_string(),
                    canonical_result_size: terminal.canonical_result_size(),
                    canonical_result_blake3: terminal.canonical_result_blake3().to_vec().into(),
                    byte_result_handle,
                    proof: Some(object_store_result_ack_v1::Proof::DurableConsumer(
                        DurableConsumerResultAckProofV1 {
                            consumer_kind: durable.consumer_kind,
                            authenticated_scope: durable.authenticated_scope.clone(),
                            operation_id: durable.operation_id.clone(),
                            checkpoint_revision: durable.checkpoint_revision,
                            checkpoint_fence: durable.checkpoint_fence,
                            terminal_result_blake3: terminal
                                .canonical_result_blake3()
                                .to_vec()
                                .into(),
                        },
                    )),
                },
                &authority,
                &disposition_limits().discard.ack,
            )
            .expect("ACK fixture");
            let decision = decide_object_store_result_disposition_cas(
                &ResultDispositionCasInput {
                    current_state: &state,
                    intent: ObjectStoreResultDispositionIntent::Ack(&validated),
                    database_now_unix_ms: NOW,
                    minimum_retention_ms: RETENTION,
                    fetch_head: initial_head.as_ref(),
                },
                &disposition_limits(),
            )
            .expect("ACK disposition");
            let ResultDispositionCasDecision::ApplyAck { next_state, .. } = decision else {
                panic!("ACK disposition must apply");
            };
            DisposedFixture {
                state: next_state,
                head: initial_head,
            }
        }
        DispositionFixture::Discarded => {
            let validated = validate_object_store_result_discard(
                &ObjectStoreResultDiscardV1 {
                    protocol_revision: "object-dispatch-v1".to_string(),
                    provider_boundary_id: "boundary-1".to_string(),
                    authenticated_cell_id: "cell-1".to_string(),
                    authenticated_tenant_id: "tenant-1".to_string(),
                    logical_request_id: LOGICAL_ID.to_string(),
                    attempt_id: ATTEMPT_ID.to_string(),
                    terminal_result_id: "terminal-1".to_string(),
                    canonical_result_size: terminal.canonical_result_size(),
                    canonical_result_blake3: terminal.canonical_result_blake3().to_vec().into(),
                    byte_result_handle,
                    proof: Some(object_store_result_discard_v1::Proof::DurableConsumerCancelled(
                        DurableConsumerCancelledProofV1 {
                            consumer_kind: durable.consumer_kind,
                            authenticated_scope: durable.authenticated_scope.clone(),
                            operation_id: durable.operation_id.clone(),
                            checkpoint_revision: durable.checkpoint_revision,
                            checkpoint_fence: durable.checkpoint_fence,
                            cancellation_kind: DurableConsumerCancellationKindV1::DurableConsumerCancellationKindCancelled as i32,
                            disposition_checkpoint_id: "disposition-1".to_string(),
                            disposition_checkpoint_revision: 2,
                            disposition_checkpoint_fence: 1,
                            superseding_operation_id: None,
                            no_exposure_checkpoint_id: "no-exposure-1".to_string(),
                            no_exposure_checkpoint_revision: 2,
                            no_exposure_checkpoint_fence: 1,
                            terminal_result_blake3: terminal.canonical_result_blake3().to_vec().into(),
                        },
                    )),
                },
                &authority,
                &disposition_limits().discard,
            )
            .expect("discard fixture");
            let reserved_head = initial_head.map(|head| {
                let reserved = decide_reserve_object_store_fetch_discard(
                    &ReserveObjectStoreFetchDiscardInput {
                        current_head: &head,
                        discard_fingerprint: *validated.discard_fingerprint(),
                        canonical_discard_bytes: validated.canonical_discard_bytes(),
                        expected_request_state_blake3: *state.state_blake3(),
                        database_now_unix_ms: NOW - 1,
                    },
                    &fetch_limits(),
                )
                .expect("discard fence");
                let ReserveObjectStoreFetchDiscardDecision::Apply { next_head, .. } = reserved
                else {
                    panic!("first discard fence must apply");
                };
                next_head
            });
            let decision = decide_object_store_result_disposition_cas(
                &ResultDispositionCasInput {
                    current_state: &state,
                    intent: ObjectStoreResultDispositionIntent::Discard(&validated),
                    database_now_unix_ms: NOW,
                    minimum_retention_ms: RETENTION,
                    fetch_head: reserved_head.as_ref(),
                },
                &disposition_limits(),
            )
            .expect("discard disposition");
            let ResultDispositionCasDecision::ApplyDiscard {
                next_state,
                next_fetch_head,
                ..
            } = decision
            else {
                panic!("discard disposition must apply");
            };
            DisposedFixture {
                state: next_state,
                head: next_fetch_head.map(|head| *head),
            }
        }
    }
}

fn purge_intent(
    state: &CanonicalObjectStoreRequestState,
    kind: ObjectStorePayloadKindV1,
) -> ObjectStorePayloadPurgeIntent {
    let payload = if kind == ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult {
        state.value().result_payload.as_ref()
    } else {
        state.value().put_body.as_ref()
    }
    .expect("payload fixture");
    ObjectStorePayloadPurgeIntent {
        protocol_revision: state.value().protocol_revision.clone(),
        provider_boundary_id: state.value().provider_boundary_id.clone(),
        authenticated_cell_id: state.value().authenticated_cell_id.clone(),
        authenticated_tenant_id: state.value().authenticated_tenant_id.clone(),
        logical_request_id: state.value().logical_request_id.clone(),
        attempt_id: state.value().attempt_id.clone(),
        purge_id: PURGE_ID.to_string(),
        payload_kind: kind,
        terminal_result_id: state
            .value()
            .terminal_result
            .as_ref()
            .expect("terminal fixture")
            .terminal_result_id
            .clone(),
        disposition: ObjectStoreResultDispositionV1::try_from(state.value().result_disposition)
            .expect("disposition fixture"),
        durable_handle: payload.durable_handle.clone().expect("retained handle"),
        payload_size: payload.size,
        payload_blake3: payload.blake3.as_ref().try_into().expect("payload digest"),
        purge_not_before_unix_ms: payload
            .purge_eligible_at_unix_ms
            .expect("retention deadline"),
    }
}

fn reserve(
    fixture: &DisposedFixture,
    kind: ObjectStorePayloadKindV1,
    now: i64,
) -> Result<ObjectStorePayloadPurgeCasDecision, PayloadPurgeError> {
    let intent = purge_intent(&fixture.state, kind);
    decide_object_store_payload_purge_cas(
        &ObjectStorePayloadPurgeCasInput {
            current_state: &fixture.state,
            current_fetch_head: fixture.head.as_ref(),
            existing_reservation: None,
            intent: &intent,
            database_now_unix_ms: now,
        },
        &purge_limits(),
    )
}

fn apply_after_reservation(
    fixture: &DisposedFixture,
    head: Option<&CanonicalObjectStoreFetchHead>,
    reservation: &CanonicalObjectStorePayloadPurgeReservation,
    kind: ObjectStorePayloadKindV1,
    now: i64,
) -> Result<ObjectStorePayloadPurgeCasDecision, PayloadPurgeError> {
    let intent = purge_intent(&fixture.state, kind);
    decide_object_store_payload_purge_cas(
        &ObjectStorePayloadPurgeCasInput {
            current_state: &fixture.state,
            current_fetch_head: head,
            existing_reservation: Some(reservation),
            intent: &intent,
            database_now_unix_ms: now,
        },
        &purge_limits(),
    )
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
fn acked_get_first_reservation_pins_cross_language_canonical_golden() {
    let fixture = disposed_fixture(PayloadFixture::Get, DispositionFixture::Acked);
    let ObjectStorePayloadPurgeCasDecision::ApplyReservation {
        reservation,
        next_fetch_head: Some(next_head),
        ..
    } = reserve(
        &fixture,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
        ELIGIBLE,
    )
    .expect("reservation")
    else {
        panic!("expected reservation with fetch fence");
    };
    assert_eq!(
        next_head.value().state,
        ObjectStoreFetchHeadState::PayloadPurgeReserved
    );
    assert_eq!(next_head.value().fence_generation, 2);
    assert_eq!(reservation.canonical_bytes().len(), 461);
    assert_eq!(
        reservation.value().purge_fingerprint,
        decode_hex("66ee8d0098c504d2faaec2018752fec3c066f89f4a79f5ff407a7a17eb6e7f05").as_slice()
    );
    assert_eq!(
        reservation.reservation_blake3(),
        decode_hex("b408ace8e6505a21e61443ea471bb2826c57885b73420892f4a31d5c08b3f2a3").as_slice()
    );
}

#[test]
fn acked_get_waits_for_drain_then_commits_head_state_and_quota_once() {
    let mut fixture = disposed_fixture(PayloadFixture::Get, DispositionFixture::Acked);
    let mut open = fixture.head.take().expect("GET head").value().clone();
    open.open_lease_count = 2;
    fixture.head = Some(
        validate_and_encode_object_store_fetch_head(&open, &fetch_limits()).expect("open head"),
    );
    let ObjectStorePayloadPurgeCasDecision::ApplyReservation {
        reservation,
        next_fetch_head: Some(reserved),
        ..
    } = reserve(
        &fixture,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
        ELIGIBLE,
    )
    .expect("reservation")
    else {
        panic!("expected reservation");
    };
    assert_eq!(reservation.value().reserved_open_lease_count, Some(2));
    assert!(matches!(
        apply_after_reservation(
            &fixture,
            Some(&reserved),
            &reservation,
            ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
            ELIGIBLE + 1,
        ),
        Ok(ObjectStorePayloadPurgeCasDecision::WaitForFetchDrain {
            fence_generation: 2,
            open_lease_count: 2,
            ..
        })
    ));
    let mut drained_value = reserved.value().clone();
    drained_value.open_lease_count = 0;
    drained_value.head_revision += 2;
    drained_value.head_committed_at_unix_ms = ELIGIBLE + 1;
    let drained = validate_and_encode_object_store_fetch_head(&drained_value, &fetch_limits())
        .expect("drained head");
    let ObjectStorePayloadPurgeCasDecision::ApplyPurge {
        next_state,
        next_fetch_head: Some(committed),
        receipt,
        ..
    } = apply_after_reservation(
        &fixture,
        Some(&drained),
        &reservation,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
        ELIGIBLE + 2,
    )
    .expect("purge")
    else {
        panic!("expected purge");
    };
    assert_eq!(
        committed.value().state,
        ObjectStoreFetchHeadState::PayloadPurgeCommitted
    );
    let payload = next_state
        .value()
        .result_payload
        .as_ref()
        .expect("result payload");
    assert_eq!(
        payload.availability,
        ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityDisposed as i32
    );
    assert_eq!(
        payload.purge_state,
        ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStatePurged as i32
    );
    assert_eq!(
        next_state
            .value()
            .quota_state
            .as_ref()
            .expect("quota")
            .result_spool_quota,
        Some(quota(0, 0, 0))
    );
    assert_eq!(
        next_state
            .value()
            .quota_state
            .as_ref()
            .expect("quota")
            .quota_revision,
        4
    );
    assert_eq!(
        (
            receipt.released_bytes,
            receipt.released_rows,
            receipt.released_concurrency
        ),
        (5, 1, 0)
    );
    assert!(!receipt.provider_authority_refunded);
}

#[test]
fn discarded_get_reuses_committed_discard_fence_at_retention_equality() {
    let fixture = disposed_fixture(PayloadFixture::Get, DispositionFixture::Discarded);
    assert_eq!(
        fixture.head.as_ref().expect("GET head").value().state,
        ObjectStoreFetchHeadState::DiscardCommitted
    );
    let ObjectStorePayloadPurgeCasDecision::ApplyReservation {
        reservation,
        next_fetch_head: None,
        ..
    } = reserve(
        &fixture,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
        ELIGIBLE,
    )
    .expect("reservation")
    else {
        panic!("discarded GET must reuse its fence");
    };
    let head = fixture.head.as_ref().expect("GET head");
    assert_eq!(
        reservation.value().reserved_fetch_fence_generation,
        Some(head.value().fence_generation)
    );
    assert_eq!(
        reservation.value().reserved_fetch_head_revision,
        Some(head.value().head_revision)
    );
    assert_eq!(
        reservation.value().reserved_open_lease_count,
        Some(head.value().open_lease_count)
    );
    assert_eq!(
        reservation.value().reserved_fetch_head_blake3,
        Some(*head.head_blake3())
    );
    let ObjectStorePayloadPurgeCasDecision::ApplyPurge { receipt, .. } = apply_after_reservation(
        &fixture,
        fixture.head.as_ref(),
        &reservation,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
        ELIGIBLE,
    )
    .expect("purge") else {
        panic!("expected purge");
    };
    assert_eq!(receipt.purged_at_unix_ms, ELIGIBLE);
}

#[test]
fn put_purge_has_no_fetch_head_and_releases_concurrency_without_refund() {
    let fixture = disposed_fixture(PayloadFixture::Put, DispositionFixture::Acked);
    let ObjectStorePayloadPurgeCasDecision::ApplyReservation {
        reservation,
        expected_fetch_head_blake3: None,
        next_fetch_head: None,
        ..
    } = reserve(
        &fixture,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
        ELIGIBLE,
    )
    .expect("reservation")
    else {
        panic!("PUT must reserve without a head");
    };
    let ObjectStorePayloadPurgeCasDecision::ApplyPurge {
        next_state,
        receipt,
        ..
    } = apply_after_reservation(
        &fixture,
        None,
        &reservation,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
        ELIGIBLE + 1,
    )
    .expect("purge")
    else {
        panic!("expected purge");
    };
    assert_eq!(
        (
            receipt.released_bytes,
            receipt.released_rows,
            receipt.released_concurrency
        ),
        (11, 1, 1)
    );
    assert!(!receipt.provider_authority_refunded);
    assert_eq!(
        next_state
            .value()
            .quota_state
            .as_ref()
            .expect("quota")
            .put_spool_quota,
        Some(quota(0, 0, 0))
    );
    assert_eq!(
        next_state
            .value()
            .quota_state
            .as_ref()
            .expect("quota")
            .quota_revision,
        4
    );
}

#[test]
fn eligibility_is_inclusive_and_strictly_earlier_is_not_yet() {
    let fixture = disposed_fixture(PayloadFixture::Put, DispositionFixture::Acked);
    assert!(matches!(
        reserve(&fixture, ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody, ELIGIBLE - 1),
        Ok(ObjectStorePayloadPurgeCasDecision::NotYetEligible { purge_not_before_unix_ms })
            if purge_not_before_unix_ms == ELIGIBLE
    ));
    assert!(matches!(
        reserve(
            &fixture,
            ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
            ELIGIBLE
        ),
        Ok(ObjectStorePayloadPurgeCasDecision::ApplyReservation { .. })
    ));
}

#[test]
fn purge_id_reuse_conflicts_and_changed_retained_tuple_rejects() {
    let fixture = disposed_fixture(PayloadFixture::Put, DispositionFixture::Acked);
    let ObjectStorePayloadPurgeCasDecision::ApplyReservation { reservation, .. } = reserve(
        &fixture,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
        ELIGIBLE,
    )
    .expect("reservation") else {
        panic!("expected reservation");
    };
    let mut reused = purge_intent(
        &fixture.state,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
    );
    reused.purge_id = OTHER_PURGE_ID.to_string();
    assert_eq!(
        decide_object_store_payload_purge_cas(
            &ObjectStorePayloadPurgeCasInput {
                current_state: &fixture.state,
                current_fetch_head: None,
                existing_reservation: Some(&reservation),
                intent: &reused,
                database_now_unix_ms: ELIGIBLE,
            },
            &purge_limits(),
        ),
        Ok(ObjectStorePayloadPurgeCasDecision::PurgeIdReuse)
    );
    for mutation in 0..4 {
        let mut changed = purge_intent(
            &fixture.state,
            ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
        );
        match mutation {
            0 => changed.durable_handle = "other-handle".to_string(),
            1 => changed.payload_size += 1,
            2 => changed.payload_blake3 = *blake3::hash(&[9]).as_bytes(),
            _ => changed.purge_not_before_unix_ms += 1,
        }
        assert_eq!(
            decide_object_store_payload_purge_cas(
                &ObjectStorePayloadPurgeCasInput {
                    current_state: &fixture.state,
                    current_fetch_head: None,
                    existing_reservation: Some(&reservation),
                    intent: &changed,
                    database_now_unix_ms: ELIGIBLE + 1,
                },
                &purge_limits(),
            ),
            Err(PayloadPurgeError::IntentMismatch)
        );
    }
}

#[test]
fn disposed_response_loss_replays_before_clock_and_head_drift_validation() {
    let fixture = disposed_fixture(PayloadFixture::Get, DispositionFixture::Acked);
    let ObjectStorePayloadPurgeCasDecision::ApplyReservation {
        reservation,
        next_fetch_head: Some(reserved),
        ..
    } = reserve(
        &fixture,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
        ELIGIBLE,
    )
    .expect("reservation")
    else {
        panic!("expected reservation");
    };
    let ObjectStorePayloadPurgeCasDecision::ApplyPurge {
        next_state,
        receipt,
        ..
    } = apply_after_reservation(
        &fixture,
        Some(&reserved),
        &reservation,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
        ELIGIBLE + 1,
    )
    .expect("purge")
    else {
        panic!("expected purge");
    };
    let mut drifted_head_value = reserved.value().clone();
    drifted_head_value.head_revision += 1;
    drifted_head_value.head_committed_at_unix_ms = ELIGIBLE + 2;
    let drifted_head =
        validate_and_encode_object_store_fetch_head(&drifted_head_value, &fetch_limits())
            .expect("drifted head");
    let original_intent = purge_intent(
        &fixture.state,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
    );
    assert!(matches!(
        decide_object_store_payload_purge_cas(
            &ObjectStorePayloadPurgeCasInput {
                current_state: &next_state,
                current_fetch_head: Some(&drifted_head),
                existing_reservation: Some(&reservation),
                intent: &original_intent,
                database_now_unix_ms: -1,
            },
            &purge_limits(),
        ),
        Ok(ObjectStorePayloadPurgeCasDecision::ReplayPurge { receipt: replay, .. }) if replay == receipt
    ));
    assert_eq!(
        next_state
            .value()
            .quota_state
            .as_ref()
            .expect("quota")
            .quota_revision,
        4
    );
}

#[test]
fn disposed_authority_requires_an_intact_matching_reservation() {
    let fixture = disposed_fixture(PayloadFixture::Put, DispositionFixture::Acked);
    let ObjectStorePayloadPurgeCasDecision::ApplyReservation { reservation, .. } = reserve(
        &fixture,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
        ELIGIBLE,
    )
    .expect("reservation") else {
        panic!("expected reservation");
    };
    let ObjectStorePayloadPurgeCasDecision::ApplyPurge { next_state, .. } =
        apply_after_reservation(
            &fixture,
            None,
            &reservation,
            ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
            ELIGIBLE + 1,
        )
        .expect("purge")
    else {
        panic!("expected purge");
    };
    let intent = purge_intent(
        &fixture.state,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
    );
    assert_eq!(
        decide_object_store_payload_purge_cas(
            &ObjectStorePayloadPurgeCasInput {
                current_state: &next_state,
                current_fetch_head: None,
                existing_reservation: None,
                intent: &intent,
                database_now_unix_ms: ELIGIBLE + 2,
            },
            &purge_limits(),
        ),
        Err(PayloadPurgeError::InvalidReservation)
    );
}

#[test]
fn reserved_fetch_binding_allows_only_monotonic_drain_evolution() {
    let mut fixture = disposed_fixture(PayloadFixture::Get, DispositionFixture::Acked);
    let mut open = fixture.head.take().expect("GET head").value().clone();
    open.open_lease_count = 2;
    fixture.head = Some(
        validate_and_encode_object_store_fetch_head(&open, &fetch_limits()).expect("open head"),
    );
    let ObjectStorePayloadPurgeCasDecision::ApplyReservation {
        reservation,
        next_fetch_head: Some(reserved),
        ..
    } = reserve(
        &fixture,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
        ELIGIBLE,
    )
    .expect("reservation")
    else {
        panic!("expected reservation");
    };
    for mutation in 0..4 {
        let mut drifted_value = reserved.value().clone();
        match mutation {
            0 => drifted_value.open_lease_count = 3,
            1 => drifted_value.fence_generation += 1,
            2 => drifted_value.head_revision -= 1,
            _ => drifted_value.head_committed_at_unix_ms += 1,
        }
        let drifted = validate_and_encode_object_store_fetch_head(&drifted_value, &fetch_limits())
            .expect("drifted head");
        assert_eq!(
            apply_after_reservation(
                &fixture,
                Some(&drifted),
                &reservation,
                ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
                ELIGIBLE + 2,
            ),
            Err(PayloadPurgeError::InvalidReservation)
        );
    }

    let invalid_evolution = [
        (2, reserved.value().head_revision + 100, ELIGIBLE),
        (0, reserved.value().head_revision + 1, ELIGIBLE + 1),
        (1, reserved.value().head_revision + 1, ELIGIBLE - 1),
    ];
    for (open_lease_count, head_revision, head_committed_at_unix_ms) in invalid_evolution {
        let mut drifted_value = reserved.value().clone();
        drifted_value.open_lease_count = open_lease_count;
        drifted_value.head_revision = head_revision;
        drifted_value.head_committed_at_unix_ms = head_committed_at_unix_ms;
        let drifted = validate_and_encode_object_store_fetch_head(&drifted_value, &fetch_limits())
            .expect("drifted head");
        assert_eq!(
            apply_after_reservation(
                &fixture,
                Some(&drifted),
                &reservation,
                ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
                ELIGIBLE + 2,
            ),
            Err(PayloadPurgeError::InvalidReservation)
        );
    }
}

#[test]
fn state_head_and_reservation_time_floors_are_enforced() {
    let mut future_state_fixture = disposed_fixture(PayloadFixture::Put, DispositionFixture::Acked);
    let mut future_state_value = future_state_fixture.state.value().clone();
    future_state_value.state_committed_at_unix_ms = ELIGIBLE + 1;
    future_state_value.closure_committed_at_unix_ms = Some(ELIGIBLE + 1);
    future_state_value.state_blake3 = Default::default();
    future_state_fixture.state =
        validate_and_encode_object_store_request_state(&future_state_value, &state_limits())
            .expect("future state");
    assert_eq!(
        reserve(
            &future_state_fixture,
            ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
            ELIGIBLE,
        ),
        Err(PayloadPurgeError::InvalidTime)
    );

    let mut fixture = disposed_fixture(PayloadFixture::Get, DispositionFixture::Acked);
    let mut future_head_value = fixture.head.take().expect("GET head").value().clone();
    future_head_value.head_revision += 1;
    future_head_value.head_committed_at_unix_ms = ELIGIBLE + 1;
    fixture.head = Some(
        validate_and_encode_object_store_fetch_head(&future_head_value, &fetch_limits())
            .expect("future head"),
    );
    assert_eq!(
        reserve(
            &fixture,
            ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
            ELIGIBLE
        ),
        Err(PayloadPurgeError::InvalidTime)
    );

    let fixture = disposed_fixture(PayloadFixture::Get, DispositionFixture::Acked);
    let ObjectStorePayloadPurgeCasDecision::ApplyReservation {
        reservation,
        next_fetch_head: Some(reserved),
        ..
    } = reserve(
        &fixture,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
        ELIGIBLE,
    )
    .expect("reservation")
    else {
        panic!("expected reservation");
    };
    let mut future_reservation_value = reservation.value().clone();
    future_reservation_value.reserved_at_unix_ms = ELIGIBLE + 2;
    let future_reservation = validate_and_encode_object_store_payload_purge_reservation(
        &future_reservation_value,
        &purge_limits(),
    )
    .expect("future reservation");
    assert_eq!(
        apply_after_reservation(
            &fixture,
            Some(&reserved),
            &future_reservation,
            ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
            ELIGIBLE + 1,
        ),
        Err(PayloadPurgeError::InvalidReservation)
    );
}

#[test]
fn canonical_reservations_are_bounded_detached_and_structurally_complete() {
    let mut intent = vec![1, 2, 3];
    let mut state_digest = [4; 32];
    let reservation = validate_and_encode_object_store_payload_purge_reservation(
        &ObjectStorePayloadPurgeReservation {
            purge_fingerprint: *blake3::hash(&intent).as_bytes(),
            canonical_intent_bytes: intent.clone(),
            expected_request_state_blake3: state_digest,
            expected_fetch_head_blake3: None,
            reserved_fetch_head_blake3: None,
            reserved_fetch_fence_generation: None,
            reserved_fetch_head_revision: None,
            reserved_open_lease_count: None,
            reserved_at_unix_ms: ELIGIBLE,
        },
        &purge_limits(),
    )
    .expect("reservation");
    intent.fill(0);
    state_digest.fill(0);
    assert_eq!(reservation.value().canonical_intent_bytes, vec![1, 2, 3]);
    assert_eq!(reservation.value().expected_request_state_blake3, [4; 32]);

    let mut invalid = reservation.value().clone();
    invalid.expected_fetch_head_blake3 = Some([1; 32]);
    assert_eq!(
        validate_and_encode_object_store_payload_purge_reservation(&invalid, &purge_limits()),
        Err(PayloadPurgeError::InvalidReservation)
    );
    let mut corrupt = reservation.value().clone();
    corrupt.purge_fingerprint[0] ^= 1;
    assert_eq!(
        validate_and_encode_object_store_payload_purge_reservation(&corrupt, &purge_limits()),
        Err(PayloadPurgeError::InvalidReservation)
    );
    let tiny = PayloadPurgeCasLimits {
        state: RequestStateWireLimits {
            max_identity_bytes: 256,
            max_canonical_row_bytes: 128,
        },
        fetch: FetchLeaseLimits {
            max_identity_bytes: 256,
            max_authenticated_scope_bytes: 1_024,
            max_canonical_record_bytes: 128,
            max_canonical_discard_bytes: 128,
        },
    };
    assert_eq!(
        validate_and_encode_object_store_payload_purge_reservation(reservation.value(), &tiny),
        Err(PayloadPurgeError::CanonicalTooLarge)
    );
}

#[test]
fn fetch_fence_and_quota_revision_overflow_fail_closed() {
    let mut get = disposed_fixture(PayloadFixture::Get, DispositionFixture::Acked);
    let mut saturated_head_value = get.head.take().expect("GET head").value().clone();
    saturated_head_value.fence_generation = u64::MAX;
    get.head = Some(
        validate_and_encode_object_store_fetch_head(&saturated_head_value, &fetch_limits())
            .expect("saturated head"),
    );
    assert_eq!(
        reserve(
            &get,
            ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult,
            ELIGIBLE
        ),
        Err(PayloadPurgeError::InvalidFetchProjection)
    );

    let mut put = disposed_fixture(PayloadFixture::Put, DispositionFixture::Acked);
    let mut saturated_state = put.state.value().clone();
    saturated_state
        .quota_state
        .as_mut()
        .expect("quota")
        .quota_revision = u64::MAX;
    saturated_state.state_blake3 = Default::default();
    put.state = validate_and_encode_object_store_request_state(&saturated_state, &state_limits())
        .expect("saturated state");
    let ObjectStorePayloadPurgeCasDecision::ApplyReservation { reservation, .. } = reserve(
        &put,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
        ELIGIBLE,
    )
    .expect("reservation") else {
        panic!("expected reservation");
    };
    assert_eq!(
        apply_after_reservation(
            &put,
            None,
            &reservation,
            ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody,
            ELIGIBLE + 1,
        ),
        Err(PayloadPurgeError::RevisionOverflow)
    );
}
