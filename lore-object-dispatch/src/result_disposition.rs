// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure result-disposition replay and mutation planning.
//!
//! The planner binds a future serializable CAS to exact canonical request state and durable fetch
//! fencing. It performs no database, filesystem, provider, clock, quota, or purge effects.

use std::fmt;

use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadAvailabilityV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestPhaseV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDispositionV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalResultV1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1;
use thiserror::Error;

use crate::fetch_lease::CanonicalObjectStoreFetchHead;
use crate::fetch_lease::FetchLeaseLimits;
use crate::fetch_lease::ObjectStoreFetchHeadState;
use crate::fetch_lease::ReserveObjectStoreFetchDiscardDecision;
use crate::fetch_lease::ReserveObjectStoreFetchDiscardInput;
use crate::fetch_lease::commit_object_store_fetch_discard;
use crate::fetch_lease::decide_reserve_object_store_fetch_discard;
use crate::fetch_lease::object_store_fetch_result_key_from_state;
use crate::fetch_lease::validate_and_encode_object_store_fetch_head;
use crate::request_state_wire::CanonicalObjectStoreRequestState;
use crate::request_state_wire::RequestStateWireLimits;
use crate::request_state_wire::validate_and_encode_object_store_request_state;
use crate::result_ack::ResultAckReceiptInput;
use crate::result_ack::ValidatedObjectStoreResultAck;
use crate::result_ack::build_object_store_result_ack_receipt;
use crate::result_discard::ResultDiscardLimits;
use crate::result_discard::ResultDiscardReceiptInput;
use crate::result_discard::ValidatedObjectStoreResultDiscard;
use crate::result_discard::build_object_store_result_discard_receipt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultDispositionLimits {
    pub state: RequestStateWireLimits,
    pub discard: ResultDiscardLimits,
}

pub enum ObjectStoreResultDispositionIntent<'a> {
    Ack(&'a ValidatedObjectStoreResultAck),
    Discard(&'a ValidatedObjectStoreResultDiscard),
}

pub struct ResultDispositionCasInput<'a> {
    pub current_state: &'a CanonicalObjectStoreRequestState,
    pub intent: ObjectStoreResultDispositionIntent<'a>,
    pub database_now_unix_ms: i64,
    pub minimum_retention_ms: i64,
    pub fetch_head: Option<&'a CanonicalObjectStoreFetchHead>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultDispositionConflict {
    FingerprintReuse,
    AckAfterDiscard,
    DiscardAfterAck,
    AckAfterDiscardReservation,
    DiscardReservationMismatch,
}

#[derive(Clone, PartialEq)]
pub enum ResultDispositionCasDecision {
    ReplayAck {
        state: CanonicalObjectStoreRequestState,
        receipt: ObjectStoreResultAckReceiptV1,
    },
    ReplayDiscard {
        state: CanonicalObjectStoreRequestState,
        receipt: ObjectStoreResultDiscardReceiptV1,
    },
    Conflict(ResultDispositionConflict),
    ReserveFetchDiscard {
        expected_state_blake3: [u8; 32],
        expected_fetch_head_blake3: [u8; 32],
        next_fetch_head: CanonicalObjectStoreFetchHead,
    },
    WaitForFetchDrain {
        expected_state_blake3: [u8; 32],
        expected_fetch_head_blake3: [u8; 32],
        fence_generation: u64,
        open_lease_count: u64,
    },
    ApplyAck {
        expected_state_blake3: [u8; 32],
        expected_fetch_head_blake3: Option<[u8; 32]>,
        next_state: CanonicalObjectStoreRequestState,
        receipt: ObjectStoreResultAckReceiptV1,
    },
    ApplyDiscard {
        expected_state_blake3: [u8; 32],
        expected_fetch_head_blake3: Option<[u8; 32]>,
        next_fetch_head: Option<Box<CanonicalObjectStoreFetchHead>>,
        next_state: CanonicalObjectStoreRequestState,
        receipt: ObjectStoreResultDiscardReceiptV1,
    },
}

impl fmt::Debug for ResultDispositionCasDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ReplayAck { .. } => "ReplayAck",
            Self::ReplayDiscard { .. } => "ReplayDiscard",
            Self::Conflict(_) => "Conflict",
            Self::ReserveFetchDiscard { .. } => "ReserveFetchDiscard",
            Self::WaitForFetchDrain { .. } => "WaitForFetchDrain",
            Self::ApplyAck { .. } => "ApplyAck",
            Self::ApplyDiscard { .. } => "ApplyDiscard",
        };
        formatter
            .debug_struct(name)
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectStoreFetchAdmissionDecision {
    Admit { fence_generation: u64 },
    FetchesFenced,
    ResultDiscarded,
    ResultPayloadDisposed,
    NotFetchable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ResultDispositionError {
    #[error("persisted object-store request state is not canonical")]
    InvalidPersistedState,
    #[error("result disposition intent does not match persisted request authority")]
    IntentMismatch,
    #[error("result disposition fingerprint must contain exactly 32 bytes")]
    InvalidFingerprint,
    #[error("durable fetch-lease projection is invalid")]
    InvalidFetchProjection,
    #[error("durable fetch fence generation overflows")]
    FetchFenceOverflow,
    #[error("result disposition time or retention floor is invalid")]
    InvalidTime,
    #[error("result disposition retention deadline overflows")]
    RetentionOverflow,
    #[error("result disposition request state retains incompatible payloads")]
    InvalidPayload,
    #[error("planned object-store request state is invalid")]
    InvalidNextState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IntentKind {
    Ack,
    Discard,
}

struct CheckedIntent<'a> {
    kind: IntentKind,
    fingerprint: &'a [u8],
    canonical_bytes: &'a [u8],
}

fn checked_current_state(
    input: &CanonicalObjectStoreRequestState,
    limits: &RequestStateWireLimits,
) -> Result<CanonicalObjectStoreRequestState, ResultDispositionError> {
    let checked = validate_and_encode_object_store_request_state(input.value(), limits)
        .map_err(|_| ResultDispositionError::InvalidPersistedState)?;
    if checked.canonical_preimage() != input.canonical_preimage()
        || checked.canonical_bytes() != input.canonical_bytes()
        || checked.state_blake3() != input.state_blake3()
    {
        return Err(ResultDispositionError::InvalidPersistedState);
    }
    Ok(checked)
}

fn fetch_limits(limits: &ResultDispositionLimits) -> FetchLeaseLimits {
    FetchLeaseLimits {
        max_identity_bytes: limits.state.max_identity_bytes,
        max_authenticated_scope_bytes: limits.discard.ack.identity.max_authenticated_scope_bytes,
        max_canonical_record_bytes: limits.state.max_canonical_row_bytes,
        max_canonical_discard_bytes: limits.state.max_canonical_row_bytes,
    }
}

fn checked_fetch_head(
    state: &CanonicalObjectStoreRequestState,
    head: Option<&CanonicalObjectStoreFetchHead>,
    limits: &ResultDispositionLimits,
) -> Result<CanonicalObjectStoreFetchHead, ResultDispositionError> {
    let head = head.ok_or(ResultDispositionError::InvalidFetchProjection)?;
    let checked = validate_and_encode_object_store_fetch_head(head.value(), &fetch_limits(limits))
        .map_err(|_| ResultDispositionError::InvalidFetchProjection)?;
    if checked.canonical_preimage() != head.canonical_preimage()
        || checked.canonical_bytes() != head.canonical_bytes()
        || checked.head_blake3() != head.head_blake3()
    {
        return Err(ResultDispositionError::InvalidFetchProjection);
    }
    let expected = object_store_fetch_result_key_from_state(state, &limits.state)
        .map_err(|_| ResultDispositionError::InvalidFetchProjection)?;
    if checked.value().result_key != expected {
        return Err(ResultDispositionError::InvalidFetchProjection);
    }
    Ok(checked)
}

fn expected_byte_handle(terminal: &ObjectStoreTerminalResultV1) -> Option<&str> {
    match terminal.result.as_ref() {
        Some(object_store_terminal_result_v1::Result::ByteResult(value)) => {
            Some(value.handle.as_str())
        }
        _ => None,
    }
}

fn is_byte_result(state: &CanonicalObjectStoreRequestState) -> bool {
    state
        .value()
        .terminal_result
        .as_ref()
        .and_then(|value| value.result.as_ref())
        .is_some_and(|value| {
            matches!(
                value,
                object_store_terminal_result_v1::Result::ByteResult(_)
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn validate_intent_fields(
    protocol_revision: &str,
    provider_boundary_id: &str,
    authenticated_cell_id: &str,
    authenticated_tenant_id: &str,
    logical_request_id: &str,
    attempt_id: &str,
    terminal_result_id: &str,
    canonical_result_size: u64,
    canonical_result_blake3: &[u8],
    byte_result_handle: Option<&str>,
    terminal: &ObjectStoreTerminalResultV1,
    state: &CanonicalObjectStoreRequestState,
) -> Result<(), ResultDispositionError> {
    let value = state.value();
    if protocol_revision != value.protocol_revision
        || provider_boundary_id != value.provider_boundary_id
        || authenticated_cell_id != value.authenticated_cell_id
        || authenticated_tenant_id != value.authenticated_tenant_id
        || logical_request_id != value.logical_request_id
        || attempt_id != value.attempt_id
        || terminal_result_id != terminal.terminal_result_id
        || canonical_result_size != terminal.canonical_result_size
        || canonical_result_blake3 != terminal.canonical_result_blake3.as_ref()
        || byte_result_handle != expected_byte_handle(terminal)
    {
        return Err(ResultDispositionError::IntentMismatch);
    }
    Ok(())
}

fn checked_intent<'a>(
    intent: &'a ObjectStoreResultDispositionIntent<'a>,
    state: &CanonicalObjectStoreRequestState,
) -> Result<CheckedIntent<'a>, ResultDispositionError> {
    let value = state.value();
    if value.phase != ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseTerminal as i32 {
        return Err(ResultDispositionError::IntentMismatch);
    }
    let terminal = value
        .terminal_result
        .as_ref()
        .ok_or(ResultDispositionError::IntentMismatch)?;
    let checked = match intent {
        ObjectStoreResultDispositionIntent::Ack(validated) => {
            let input = validated.ack();
            validate_intent_fields(
                &input.protocol_revision,
                &input.provider_boundary_id,
                &input.authenticated_cell_id,
                &input.authenticated_tenant_id,
                &input.logical_request_id,
                &input.attempt_id,
                &input.terminal_result_id,
                input.canonical_result_size,
                input.canonical_result_blake3.as_ref(),
                input.byte_result_handle.as_deref(),
                terminal,
                state,
            )?;
            CheckedIntent {
                kind: IntentKind::Ack,
                fingerprint: validated.ack_fingerprint(),
                canonical_bytes: validated.canonical_ack_bytes(),
            }
        }
        ObjectStoreResultDispositionIntent::Discard(validated) => {
            let input = validated.discard();
            validate_intent_fields(
                &input.protocol_revision,
                &input.provider_boundary_id,
                &input.authenticated_cell_id,
                &input.authenticated_tenant_id,
                &input.logical_request_id,
                &input.attempt_id,
                &input.terminal_result_id,
                input.canonical_result_size,
                input.canonical_result_blake3.as_ref(),
                input.byte_result_handle.as_deref(),
                terminal,
                state,
            )?;
            CheckedIntent {
                kind: IntentKind::Discard,
                fingerprint: validated.discard_fingerprint(),
                canonical_bytes: validated.canonical_discard_bytes(),
            }
        }
    };
    if checked.fingerprint.len() != 32 {
        return Err(ResultDispositionError::InvalidFingerprint);
    }
    Ok(checked)
}

fn replay_or_conflict(
    state: &CanonicalObjectStoreRequestState,
    intent: &CheckedIntent<'_>,
) -> Result<Option<ResultDispositionCasDecision>, ResultDispositionError> {
    match state.value().result_disposition {
        value
            if value
                == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable as i32 =>
        {
            Ok(None)
        }
        value
            if value
                == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32 =>
        {
            let receipt = state
                .value()
                .ack_receipt
                .as_ref()
                .ok_or(ResultDispositionError::InvalidPersistedState)?;
            if intent.kind == IntentKind::Discard {
                return Ok(Some(ResultDispositionCasDecision::Conflict(
                    ResultDispositionConflict::DiscardAfterAck,
                )));
            }
            if receipt.ack_fingerprint.as_ref() != intent.fingerprint {
                return Ok(Some(ResultDispositionCasDecision::Conflict(
                    ResultDispositionConflict::FingerprintReuse,
                )));
            }
            Ok(Some(ResultDispositionCasDecision::ReplayAck {
                state: state.clone(),
                receipt: receipt.clone(),
            }))
        }
        value
            if value
                == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded as i32 =>
        {
            let receipt = state
                .value()
                .discard_receipt
                .as_ref()
                .ok_or(ResultDispositionError::InvalidPersistedState)?;
            if intent.kind == IntentKind::Ack {
                return Ok(Some(ResultDispositionCasDecision::Conflict(
                    ResultDispositionConflict::AckAfterDiscard,
                )));
            }
            if receipt.discard_fingerprint.as_ref() != intent.fingerprint {
                return Ok(Some(ResultDispositionCasDecision::Conflict(
                    ResultDispositionConflict::FingerprintReuse,
                )));
            }
            Ok(Some(ResultDispositionCasDecision::ReplayDiscard {
                state: state.clone(),
                receipt: receipt.clone(),
            }))
        }
        _ => Err(ResultDispositionError::InvalidPersistedState),
    }
}

fn latest_durable_time(state: &CanonicalObjectStoreRequestState) -> i64 {
    let value = state.value();
    let mut latest = value.state_committed_at_unix_ms;
    if let Some(time) = value.closure_committed_at_unix_ms {
        latest = latest.max(time);
    }
    if let Some(dispatch) = value.dispatch_attempt.as_ref() {
        latest = latest.max(dispatch.dispatch_started_at_unix_ms);
        if let Some(time) = dispatch.ambiguity_recorded_at_unix_ms {
            latest = latest.max(time);
        }
    }
    if let Some(binding) = value.put_submit_binding.as_ref() {
        latest = latest.max(binding.bound_at_unix_ms);
    }
    latest
}

#[derive(Clone, Copy)]
enum PayloadField {
    Put,
    Result,
}

fn disposition_payload(
    state: &CanonicalObjectStoreRequestState,
) -> Result<Option<PayloadField>, ResultDispositionError> {
    let retained = ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained as i32;
    let put = state
        .value()
        .put_body
        .as_ref()
        .is_some_and(|value| value.availability == retained);
    let result = state
        .value()
        .result_payload
        .as_ref()
        .is_some_and(|value| value.availability == retained);
    match (put, result) {
        (true, true) => Err(ResultDispositionError::InvalidPayload),
        (true, false) => Ok(Some(PayloadField::Put)),
        (false, true) => Ok(Some(PayloadField::Result)),
        (false, false) => Ok(None),
    }
}

fn set_retention_deadline(
    state: &mut lore_proto::lore::object_dispatch::v1::ObjectStoreRequestStateV1,
    field: PayloadField,
    deadline: i64,
) -> Result<(), ResultDispositionError> {
    let retention = match field {
        PayloadField::Put => state.put_body.as_mut(),
        PayloadField::Result => state.result_payload.as_mut(),
    }
    .ok_or(ResultDispositionError::InvalidPayload)?;
    if retention.availability
        != ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained as i32
        || retention.purge_receipt.is_some()
    {
        return Err(ResultDispositionError::InvalidPayload);
    }
    retention.purge_state =
        ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStateRetentionPending as i32;
    retention.purge_eligible_at_unix_ms = Some(deadline);
    Ok(())
}

pub fn decide_object_store_result_disposition_cas(
    input: &ResultDispositionCasInput<'_>,
    limits: &ResultDispositionLimits,
) -> Result<ResultDispositionCasDecision, ResultDispositionError> {
    let current = checked_current_state(input.current_state, &limits.state)?;
    let intent = checked_intent(&input.intent, &current)?;
    if let Some(decision) = replay_or_conflict(&current, &intent)? {
        return Ok(decision);
    }

    let byte_result = is_byte_result(&current);
    let fetch_head = if byte_result {
        Some(checked_fetch_head(&current, input.fetch_head, limits)?)
    } else {
        None
    };
    if let Some(head) = fetch_head.as_ref() {
        match intent.kind {
            IntentKind::Ack => {
                if head.value().state != ObjectStoreFetchHeadState::Unfenced {
                    return Ok(ResultDispositionCasDecision::Conflict(
                        ResultDispositionConflict::AckAfterDiscardReservation,
                    ));
                }
            }
            IntentKind::Discard => match head.value().state {
                ObjectStoreFetchHeadState::Unfenced => {
                    if input.database_now_unix_ms < latest_durable_time(&current) {
                        return Err(ResultDispositionError::InvalidTime);
                    }
                    let fingerprint: [u8; 32] = intent
                        .fingerprint
                        .try_into()
                        .map_err(|_| ResultDispositionError::InvalidFingerprint)?;
                    let decision = decide_reserve_object_store_fetch_discard(
                        &ReserveObjectStoreFetchDiscardInput {
                            current_head: head,
                            discard_fingerprint: fingerprint,
                            canonical_discard_bytes: intent.canonical_bytes,
                            expected_request_state_blake3: *current.state_blake3(),
                            database_now_unix_ms: input.database_now_unix_ms,
                        },
                        &fetch_limits(limits),
                    )
                    .map_err(|error| match error {
                        crate::fetch_lease::FetchLeaseError::GenerationOverflow => {
                            ResultDispositionError::FetchFenceOverflow
                        }
                        _ => ResultDispositionError::InvalidFetchProjection,
                    })?;
                    let ReserveObjectStoreFetchDiscardDecision::Apply {
                        expected_head_blake3,
                        next_head,
                        ..
                    } = decision
                    else {
                        return Err(ResultDispositionError::InvalidFetchProjection);
                    };
                    return Ok(ResultDispositionCasDecision::ReserveFetchDiscard {
                        expected_state_blake3: *current.state_blake3(),
                        expected_fetch_head_blake3: expected_head_blake3,
                        next_fetch_head: next_head,
                    });
                }
                ObjectStoreFetchHeadState::DiscardReserved => {
                    let pending = head
                        .value()
                        .pending_discard
                        .as_ref()
                        .ok_or(ResultDispositionError::InvalidFetchProjection)?;
                    if pending.discard_fingerprint.as_ref() != intent.fingerprint
                        || pending.canonical_discard_bytes != intent.canonical_bytes
                        || pending.expected_request_state_blake3 != *current.state_blake3()
                    {
                        return Ok(ResultDispositionCasDecision::Conflict(
                            ResultDispositionConflict::DiscardReservationMismatch,
                        ));
                    }
                    if head.value().open_lease_count != 0 {
                        return Ok(ResultDispositionCasDecision::WaitForFetchDrain {
                            expected_state_blake3: *current.state_blake3(),
                            expected_fetch_head_blake3: *head.head_blake3(),
                            fence_generation: head.value().fence_generation,
                            open_lease_count: head.value().open_lease_count,
                        });
                    }
                }
                ObjectStoreFetchHeadState::DiscardCommitted => {
                    return Err(ResultDispositionError::InvalidFetchProjection);
                }
                ObjectStoreFetchHeadState::PayloadPurgeReserved
                | ObjectStoreFetchHeadState::PayloadPurgeCommitted => {
                    return Err(ResultDispositionError::InvalidFetchProjection);
                }
            },
        }
    }

    if input.database_now_unix_ms < 0
        || input.minimum_retention_ms <= 0
        || input.database_now_unix_ms < latest_durable_time(&current)
        || (intent.kind == IntentKind::Ack
            && fetch_head.as_ref().is_some_and(|head| {
                input.database_now_unix_ms < head.value().head_committed_at_unix_ms
            }))
    {
        return Err(ResultDispositionError::InvalidTime);
    }
    let deadline = input
        .database_now_unix_ms
        .checked_add(input.minimum_retention_ms)
        .ok_or(ResultDispositionError::RetentionOverflow)?;
    let payload = disposition_payload(&current)?;
    let purge_after = payload.map(|_| deadline);
    let terminal_result_id = current
        .value()
        .terminal_result
        .as_ref()
        .ok_or(ResultDispositionError::InvalidPersistedState)?
        .terminal_result_id
        .clone();
    let mut next = current.value().clone();
    next.state_blake3 = Default::default();
    next.state_committed_at_unix_ms = input.database_now_unix_ms;
    next.closure_committed_at_unix_ms = Some(input.database_now_unix_ms);
    if let Some(field) = payload {
        set_retention_deadline(&mut next, field, deadline)?;
    }

    match intent.kind {
        IntentKind::Ack => {
            let receipt = build_object_store_result_ack_receipt(
                &ResultAckReceiptInput {
                    terminal_result_id: &terminal_result_id,
                    ack_fingerprint: intent.fingerprint,
                    acked_at_unix_ms: input.database_now_unix_ms,
                    payload_purge_after_unix_ms: purge_after,
                },
                &limits.discard.ack,
            )
            .map_err(|_| ResultDispositionError::InvalidNextState)?;
            next.result_disposition =
                ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32;
            next.ack_receipt = Some(receipt.clone());
            next.discard_receipt = None;
            let next_state = validate_and_encode_object_store_request_state(&next, &limits.state)
                .map_err(|_| ResultDispositionError::InvalidNextState)?;
            Ok(ResultDispositionCasDecision::ApplyAck {
                expected_state_blake3: *current.state_blake3(),
                expected_fetch_head_blake3: fetch_head.as_ref().map(|value| *value.head_blake3()),
                next_state,
                receipt,
            })
        }
        IntentKind::Discard => {
            let receipt = build_object_store_result_discard_receipt(
                &ResultDiscardReceiptInput {
                    terminal_result_id: &terminal_result_id,
                    discard_fingerprint: intent.fingerprint,
                    discarded_at_unix_ms: input.database_now_unix_ms,
                    payload_purge_after_unix_ms: purge_after,
                },
                &limits.discard,
            )
            .map_err(|_| ResultDispositionError::InvalidNextState)?;
            next.result_disposition =
                ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded as i32;
            next.ack_receipt = None;
            next.discard_receipt = Some(receipt.clone());
            let next_state = validate_and_encode_object_store_request_state(&next, &limits.state)
                .map_err(|_| ResultDispositionError::InvalidNextState)?;
            let next_fetch_head = fetch_head
                .as_ref()
                .map(|value| {
                    let fingerprint: [u8; 32] = intent
                        .fingerprint
                        .try_into()
                        .map_err(|_| ResultDispositionError::InvalidFingerprint)?;
                    commit_object_store_fetch_discard(
                        value,
                        fingerprint,
                        input.database_now_unix_ms,
                        &fetch_limits(limits),
                    )
                    .map_err(|_| ResultDispositionError::InvalidFetchProjection)
                })
                .transpose()?
                .map(Box::new);
            Ok(ResultDispositionCasDecision::ApplyDiscard {
                expected_state_blake3: *current.state_blake3(),
                expected_fetch_head_blake3: fetch_head.as_ref().map(|value| *value.head_blake3()),
                next_fetch_head,
                next_state,
                receipt,
            })
        }
    }
}

pub fn decide_object_store_fetch_admission(
    current_state: &CanonicalObjectStoreRequestState,
    fetch_head: Option<&CanonicalObjectStoreFetchHead>,
    limits: &RequestStateWireLimits,
) -> Result<ObjectStoreFetchAdmissionDecision, ResultDispositionError> {
    let state = checked_current_state(current_state, limits)?;
    let result_payload = state
        .value()
        .result_payload
        .as_ref()
        .ok_or(ResultDispositionError::InvalidPersistedState)?;
    if result_payload.availability
        == ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityDisposed as i32
    {
        return Ok(ObjectStoreFetchAdmissionDecision::ResultPayloadDisposed);
    }
    if state.value().result_disposition
        == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded as i32
    {
        return Ok(ObjectStoreFetchAdmissionDecision::ResultDiscarded);
    }
    let byte_result = state
        .value()
        .terminal_result
        .as_ref()
        .and_then(|value| value.result.as_ref())
        .is_some_and(|value| {
            matches!(
                value,
                object_store_terminal_result_v1::Result::ByteResult(_)
            )
        });
    if state.value().phase != ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseTerminal as i32
        || result_payload.availability
            != ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained as i32
        || !byte_result
    {
        return Ok(ObjectStoreFetchAdmissionDecision::NotFetchable);
    }
    let fetch_limits = FetchLeaseLimits {
        max_identity_bytes: limits.max_identity_bytes,
        max_authenticated_scope_bytes: limits.max_identity_bytes,
        max_canonical_record_bytes: limits.max_canonical_row_bytes,
        max_canonical_discard_bytes: limits.max_canonical_row_bytes,
    };
    let head = fetch_head.ok_or(ResultDispositionError::InvalidFetchProjection)?;
    let checked = validate_and_encode_object_store_fetch_head(head.value(), &fetch_limits)
        .map_err(|_| ResultDispositionError::InvalidFetchProjection)?;
    if checked.canonical_preimage() != head.canonical_preimage()
        || checked.canonical_bytes() != head.canonical_bytes()
        || checked.head_blake3() != head.head_blake3()
        || object_store_fetch_result_key_from_state(&state, limits)
            .map_err(|_| ResultDispositionError::InvalidFetchProjection)?
            != checked.value().result_key
    {
        return Err(ResultDispositionError::InvalidFetchProjection);
    }
    if checked.value().state != ObjectStoreFetchHeadState::Unfenced {
        return Ok(ObjectStoreFetchAdmissionDecision::FetchesFenced);
    }
    Ok(ObjectStoreFetchAdmissionDecision::Admit {
        fence_generation: checked.value().fence_generation,
    })
}
