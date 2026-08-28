// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure durable payload-purge reservations and compare-and-swap plans.
//!
//! This source-dark kernel performs no database, filesystem, provider, clock, or runtime effects.

use std::fmt;

use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadAvailabilityV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadReleaseReasonV1;
use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadRetentionV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestPhaseV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDispositionV1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1;
use thiserror::Error;

use crate::contract::BoundedCanonicalWriter;
use crate::contract::decode_canonical_uuid_v7;
use crate::contract::validate_canonical_text;
use crate::fetch_lease::CanonicalObjectStoreFetchHead;
use crate::fetch_lease::FetchLeaseLimits;
use crate::fetch_lease::ObjectStoreFetchHeadState;
use crate::fetch_lease::ObjectStoreFetchPayloadPurgeFenceDecision;
use crate::fetch_lease::ObjectStoreFetchResultKey;
use crate::fetch_lease::commit_object_store_fetch_payload_purge;
use crate::fetch_lease::decide_object_store_fetch_payload_purge_fence;
use crate::fetch_lease::validate_and_encode_object_store_fetch_head;
use crate::request_state_wire::CanonicalObjectStoreRequestState;
use crate::request_state_wire::RequestStateWireLimits;
use crate::request_state_wire::validate_and_encode_object_store_request_state;

const INTENT_DOMAIN: &[u8] = b"object-store-payload-purge-v1\0";
const RESERVATION_DOMAIN: &[u8] = b"object-store-payload-purge-reservation-v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadPurgeCasLimits {
    pub state: RequestStateWireLimits,
    pub fetch: FetchLeaseLimits,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ObjectStorePayloadPurgeIntent {
    pub protocol_revision: String,
    pub provider_boundary_id: String,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub logical_request_id: String,
    pub attempt_id: String,
    pub purge_id: String,
    pub payload_kind: ObjectStorePayloadKindV1,
    pub terminal_result_id: String,
    pub disposition: ObjectStoreResultDispositionV1,
    pub durable_handle: String,
    pub payload_size: u64,
    pub payload_blake3: [u8; 32],
    pub purge_not_before_unix_ms: i64,
}

impl fmt::Debug for ObjectStorePayloadPurgeIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStorePayloadPurgeIntent")
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ObjectStorePayloadPurgeReservation {
    pub purge_fingerprint: [u8; 32],
    pub canonical_intent_bytes: Vec<u8>,
    pub expected_request_state_blake3: [u8; 32],
    pub expected_fetch_head_blake3: Option<[u8; 32]>,
    pub reserved_fetch_head_blake3: Option<[u8; 32]>,
    pub reserved_fetch_fence_generation: Option<u64>,
    pub reserved_fetch_head_revision: Option<u64>,
    pub reserved_open_lease_count: Option<u64>,
    pub reserved_at_unix_ms: i64,
}

impl fmt::Debug for ObjectStorePayloadPurgeReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStorePayloadPurgeReservation")
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalObjectStorePayloadPurgeReservation {
    value: ObjectStorePayloadPurgeReservation,
    canonical_preimage: Vec<u8>,
    canonical_bytes: Vec<u8>,
    reservation_blake3: [u8; 32],
}

impl CanonicalObjectStorePayloadPurgeReservation {
    pub fn value(&self) -> &ObjectStorePayloadPurgeReservation {
        &self.value
    }

    pub fn canonical_preimage(&self) -> &[u8] {
        &self.canonical_preimage
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn reservation_blake3(&self) -> &[u8; 32] {
        &self.reservation_blake3
    }
}

impl fmt::Debug for CanonicalObjectStorePayloadPurgeReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalObjectStorePayloadPurgeReservation")
            .field("value", &"[REDACTED]")
            .field("canonical_preimage", &"[REDACTED]")
            .field("canonical_bytes", &"[REDACTED]")
            .field("reservation_blake3", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PayloadPurgeError {
    #[error("payload-purge limits are invalid or inconsistent")]
    InvalidLimits,
    #[error("payload-purge canonical record exceeds its bound")]
    CanonicalTooLarge,
    #[error("payload-purge canonical record or digest is invalid")]
    InvalidCanonicalRecord,
    #[error("payload-purge intent is invalid")]
    InvalidIntent,
    #[error("payload-purge intent does not match retained authority")]
    IntentMismatch,
    #[error("payload-purge request state is invalid")]
    InvalidState,
    #[error("payload-purge fetch projection is invalid")]
    InvalidFetchProjection,
    #[error("payload-purge reservation is invalid or has drifted")]
    InvalidReservation,
    #[error("payload-purge time is invalid")]
    InvalidTime,
    #[error("payload-purge revision overflows")]
    RevisionOverflow,
}

pub struct ObjectStorePayloadPurgeCasInput<'a> {
    pub current_state: &'a CanonicalObjectStoreRequestState,
    pub current_fetch_head: Option<&'a CanonicalObjectStoreFetchHead>,
    pub existing_reservation: Option<&'a CanonicalObjectStorePayloadPurgeReservation>,
    pub intent: &'a ObjectStorePayloadPurgeIntent,
    pub database_now_unix_ms: i64,
}

#[derive(Clone, PartialEq)]
pub enum ObjectStorePayloadPurgeCasDecision {
    ReplayPurge {
        state: CanonicalObjectStoreRequestState,
        receipt: ObjectStorePayloadPurgeReceiptV1,
    },
    PurgeIdReuse,
    NotYetEligible {
        purge_not_before_unix_ms: i64,
    },
    FetchFenceConflict,
    ApplyReservation {
        expected_state_blake3: [u8; 32],
        expected_fetch_head_blake3: Option<[u8; 32]>,
        reservation: CanonicalObjectStorePayloadPurgeReservation,
        next_fetch_head: Option<Box<CanonicalObjectStoreFetchHead>>,
    },
    WaitForFetchDrain {
        expected_state_blake3: [u8; 32],
        expected_reservation_blake3: [u8; 32],
        fence_generation: u64,
        open_lease_count: u64,
    },
    ApplyPurge {
        expected_state_blake3: [u8; 32],
        expected_reservation_blake3: [u8; 32],
        expected_fetch_head_blake3: Option<[u8; 32]>,
        next_state: CanonicalObjectStoreRequestState,
        next_fetch_head: Option<Box<CanonicalObjectStoreFetchHead>>,
        receipt: ObjectStorePayloadPurgeReceiptV1,
    },
}

impl fmt::Debug for ObjectStorePayloadPurgeCasDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ReplayPurge { .. } => "ReplayPurge",
            Self::PurgeIdReuse => "PurgeIdReuse",
            Self::NotYetEligible { .. } => "NotYetEligible",
            Self::FetchFenceConflict => "FetchFenceConflict",
            Self::ApplyReservation { .. } => "ApplyReservation",
            Self::WaitForFetchDrain { .. } => "WaitForFetchDrain",
            Self::ApplyPurge { .. } => "ApplyPurge",
        };
        formatter
            .debug_struct(name)
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

fn validate_limits(limits: &PayloadPurgeCasLimits) -> Result<(), PayloadPurgeError> {
    if limits.state.max_identity_bytes == 0
        || limits.state.max_canonical_row_bytes == 0
        || limits.fetch.max_authenticated_scope_bytes == 0
        || limits.fetch.max_canonical_discard_bytes == 0
        || limits.fetch.max_identity_bytes != limits.state.max_identity_bytes
        || limits.fetch.max_canonical_record_bytes != limits.state.max_canonical_row_bytes
    {
        return Err(PayloadPurgeError::InvalidLimits);
    }
    Ok(())
}

fn writer(limits: &PayloadPurgeCasLimits) -> Result<BoundedCanonicalWriter, PayloadPurgeError> {
    validate_limits(limits)?;
    BoundedCanonicalWriter::new(limits.state.max_canonical_row_bytes)
        .map_err(|_| PayloadPurgeError::InvalidLimits)
}

fn write_text(
    output: &mut BoundedCanonicalWriter,
    value: &str,
    limits: &PayloadPurgeCasLimits,
) -> Result<(), PayloadPurgeError> {
    validate_canonical_text(value, limits.state.max_identity_bytes)
        .map_err(|_| PayloadPurgeError::InvalidIntent)?;
    output
        .text(value)
        .map_err(|_| PayloadPurgeError::CanonicalTooLarge)
}

fn write_time(output: &mut BoundedCanonicalWriter, value: i64) -> Result<(), PayloadPurgeError> {
    output
        .u64(u64::try_from(value).map_err(|_| PayloadPurgeError::InvalidTime)?)
        .map_err(|_| PayloadPurgeError::CanonicalTooLarge)
}

fn finish_record(
    preimage: Vec<u8>,
    maximum: u32,
) -> Result<(Vec<u8>, [u8; 32]), PayloadPurgeError> {
    let digest = *blake3::hash(&preimage).as_bytes();
    let size = preimage
        .len()
        .checked_add(digest.len())
        .ok_or(PayloadPurgeError::CanonicalTooLarge)?;
    if size > maximum as usize {
        return Err(PayloadPurgeError::CanonicalTooLarge);
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(&preimage);
    bytes.extend_from_slice(&digest);
    Ok((bytes, digest))
}

fn encoded_intent(
    value: &ObjectStorePayloadPurgeIntent,
    limits: &PayloadPurgeCasLimits,
) -> Result<(Vec<u8>, [u8; 32]), PayloadPurgeError> {
    if !matches!(
        value.payload_kind,
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody
            | ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult
    ) || !matches!(
        value.disposition,
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked
            | ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded
    ) {
        return Err(PayloadPurgeError::InvalidIntent);
    }
    let logical = decode_canonical_uuid_v7(&value.logical_request_id)
        .map_err(|_| PayloadPurgeError::InvalidIntent)?;
    let attempt = decode_canonical_uuid_v7(&value.attempt_id)
        .map_err(|_| PayloadPurgeError::InvalidIntent)?;
    let purge =
        decode_canonical_uuid_v7(&value.purge_id).map_err(|_| PayloadPurgeError::InvalidIntent)?;
    let mut output = writer(limits)?;
    output
        .raw(INTENT_DOMAIN)
        .map_err(|_| PayloadPurgeError::CanonicalTooLarge)?;
    for text in [
        &value.protocol_revision,
        &value.provider_boundary_id,
        &value.authenticated_cell_id,
        &value.authenticated_tenant_id,
    ] {
        write_text(&mut output, text, limits)?;
    }
    output
        .raw(&logical)
        .and_then(|_| output.raw(&attempt))
        .and_then(|_| output.raw(&purge))
        .and_then(|_| output.u32(value.payload_kind as u32))
        .map_err(|_| PayloadPurgeError::CanonicalTooLarge)?;
    write_text(&mut output, &value.terminal_result_id, limits)?;
    output
        .u32(value.disposition as u32)
        .map_err(|_| PayloadPurgeError::CanonicalTooLarge)?;
    write_text(&mut output, &value.durable_handle, limits)?;
    output
        .u64(value.payload_size)
        .and_then(|_| output.raw(&value.payload_blake3))
        .map_err(|_| PayloadPurgeError::CanonicalTooLarge)?;
    write_time(&mut output, value.purge_not_before_unix_ms)?;
    let bytes = output.finish();
    let digest = *blake3::hash(&bytes).as_bytes();
    Ok((bytes, digest))
}

pub fn validate_and_encode_object_store_payload_purge_reservation(
    value: &ObjectStorePayloadPurgeReservation,
    limits: &PayloadPurgeCasLimits,
) -> Result<CanonicalObjectStorePayloadPurgeReservation, PayloadPurgeError> {
    validate_limits(limits)?;
    let fetch_field_count = [
        value.expected_fetch_head_blake3.is_some(),
        value.reserved_fetch_head_blake3.is_some(),
        value.reserved_fetch_fence_generation.is_some(),
        value.reserved_fetch_head_revision.is_some(),
        value.reserved_open_lease_count.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if !matches!(fetch_field_count, 0 | 5)
        || value.canonical_intent_bytes.is_empty()
        || value.canonical_intent_bytes.len() > limits.state.max_canonical_row_bytes as usize
        || *blake3::hash(&value.canonical_intent_bytes).as_bytes() != value.purge_fingerprint
    {
        return Err(PayloadPurgeError::InvalidReservation);
    }
    let mut output = writer(limits)?;
    output
        .raw(RESERVATION_DOMAIN)
        .and_then(|_| output.raw(&value.purge_fingerprint))
        .and_then(|_| output.bytes(&value.canonical_intent_bytes))
        .and_then(|_| output.raw(&value.expected_request_state_blake3))
        .and_then(|_| output.u8(u8::from(value.expected_fetch_head_blake3.is_some())))
        .map_err(|_| PayloadPurgeError::CanonicalTooLarge)?;
    if let Some(digest) = value.expected_fetch_head_blake3 {
        output
            .raw(&digest)
            .map_err(|_| PayloadPurgeError::CanonicalTooLarge)?;
    }
    output
        .u8(u8::from(value.reserved_fetch_head_blake3.is_some()))
        .map_err(|_| PayloadPurgeError::CanonicalTooLarge)?;
    if let Some(digest) = value.reserved_fetch_head_blake3 {
        output
            .raw(&digest)
            .map_err(|_| PayloadPurgeError::CanonicalTooLarge)?;
    }
    for field in [
        value.reserved_fetch_fence_generation,
        value.reserved_fetch_head_revision,
        value.reserved_open_lease_count,
    ] {
        output
            .u8(u8::from(field.is_some()))
            .map_err(|_| PayloadPurgeError::CanonicalTooLarge)?;
        if let Some(field) = field {
            output
                .u64(field)
                .map_err(|_| PayloadPurgeError::CanonicalTooLarge)?;
        }
    }
    write_time(&mut output, value.reserved_at_unix_ms)?;
    let canonical_preimage = output.finish();
    let (canonical_bytes, reservation_blake3) = finish_record(
        canonical_preimage.clone(),
        limits.state.max_canonical_row_bytes,
    )?;
    Ok(CanonicalObjectStorePayloadPurgeReservation {
        value: value.clone(),
        canonical_preimage,
        canonical_bytes,
        reservation_blake3,
    })
}

fn checked_state(
    state: &CanonicalObjectStoreRequestState,
    limits: &PayloadPurgeCasLimits,
) -> Result<CanonicalObjectStoreRequestState, PayloadPurgeError> {
    let checked = validate_and_encode_object_store_request_state(state.value(), &limits.state)
        .map_err(|_| PayloadPurgeError::InvalidState)?;
    if checked.canonical_preimage() != state.canonical_preimage()
        || checked.canonical_bytes() != state.canonical_bytes()
        || checked.state_blake3() != state.state_blake3()
    {
        return Err(PayloadPurgeError::InvalidCanonicalRecord);
    }
    Ok(checked)
}

fn checked_reservation(
    reservation: &CanonicalObjectStorePayloadPurgeReservation,
    limits: &PayloadPurgeCasLimits,
) -> Result<CanonicalObjectStorePayloadPurgeReservation, PayloadPurgeError> {
    let checked =
        validate_and_encode_object_store_payload_purge_reservation(reservation.value(), limits)?;
    if checked.canonical_preimage() != reservation.canonical_preimage()
        || checked.canonical_bytes() != reservation.canonical_bytes()
        || checked.reservation_blake3() != reservation.reservation_blake3()
    {
        return Err(PayloadPurgeError::InvalidCanonicalRecord);
    }
    Ok(checked)
}

#[derive(Clone, Copy)]
enum PayloadField {
    PutBody,
    ResultPayload,
}

struct SelectedPayload {
    field: PayloadField,
    retention: ObjectStorePayloadRetentionV1,
    release_reason: ObjectStorePayloadReleaseReasonV1,
}

fn selected_payload(
    state: &CanonicalObjectStoreRequestState,
    intent: &ObjectStorePayloadPurgeIntent,
) -> Result<SelectedPayload, PayloadPurgeError> {
    let value = state.value();
    if intent.protocol_revision != value.protocol_revision
        || intent.provider_boundary_id != value.provider_boundary_id
        || intent.authenticated_cell_id != value.authenticated_cell_id
        || intent.authenticated_tenant_id != value.authenticated_tenant_id
        || intent.logical_request_id != value.logical_request_id
        || intent.attempt_id != value.attempt_id
        || value.phase != ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseTerminal as i32
        || value.result_disposition != intent.disposition as i32
        || value
            .terminal_result
            .as_ref()
            .is_none_or(|terminal| terminal.terminal_result_id != intent.terminal_result_id)
    {
        return Err(PayloadPurgeError::IntentMismatch);
    }
    let (field, retention) = match intent.payload_kind {
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody => (
            PayloadField::PutBody,
            value
                .put_body
                .as_ref()
                .ok_or(PayloadPurgeError::IntentMismatch)?,
        ),
        ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult => (
            PayloadField::ResultPayload,
            value
                .result_payload
                .as_ref()
                .ok_or(PayloadPurgeError::IntentMismatch)?,
        ),
        _ => return Err(PayloadPurgeError::InvalidIntent),
    };
    if retention.payload_kind != intent.payload_kind as i32
        || retention.durable_handle.as_deref() != Some(intent.durable_handle.as_str())
        || retention.size != intent.payload_size
        || retention.blake3.as_ref() != intent.payload_blake3
        || retention.purge_eligible_at_unix_ms != Some(intent.purge_not_before_unix_ms)
    {
        return Err(PayloadPurgeError::IntentMismatch);
    }
    let release_reason = match intent.disposition {
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked => {
            ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonAckedRetentionElapsed
        }
        ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded => {
            ObjectStorePayloadReleaseReasonV1::ObjectStorePayloadReleaseReasonDiscardedRetentionElapsed
        }
        _ => return Err(PayloadPurgeError::InvalidIntent),
    };
    Ok(SelectedPayload {
        field,
        retention: retention.clone(),
        release_reason,
    })
}

fn expected_fetch_key(
    state: &CanonicalObjectStoreRequestState,
) -> Result<ObjectStoreFetchResultKey, PayloadPurgeError> {
    let value = state.value();
    let terminal = value
        .terminal_result
        .as_ref()
        .ok_or(PayloadPurgeError::InvalidFetchProjection)?;
    let byte_result = match terminal.result.as_ref() {
        Some(object_store_terminal_result_v1::Result::ByteResult(result)) => result,
        _ => return Err(PayloadPurgeError::InvalidFetchProjection),
    };
    Ok(ObjectStoreFetchResultKey {
        protocol_revision: value.protocol_revision.clone(),
        provider_boundary_id: value.provider_boundary_id.clone(),
        authenticated_cell_id: value.authenticated_cell_id.clone(),
        authenticated_tenant_id: value.authenticated_tenant_id.clone(),
        logical_request_id: value.logical_request_id.clone(),
        attempt_id: value.attempt_id.clone(),
        terminal_result_id: terminal.terminal_result_id.clone(),
        canonical_result_size: terminal.canonical_result_size,
        canonical_result_blake3: terminal
            .canonical_result_blake3
            .as_ref()
            .try_into()
            .map_err(|_| PayloadPurgeError::InvalidFetchProjection)?,
        byte_result_handle: byte_result.handle.clone(),
        payload_size: byte_result.size,
        payload_blake3: byte_result
            .blake3
            .as_ref()
            .try_into()
            .map_err(|_| PayloadPurgeError::InvalidFetchProjection)?,
    })
}

fn checked_fetch_head(
    state: &CanonicalObjectStoreRequestState,
    head: &CanonicalObjectStoreFetchHead,
    limits: &PayloadPurgeCasLimits,
) -> Result<CanonicalObjectStoreFetchHead, PayloadPurgeError> {
    let checked = validate_and_encode_object_store_fetch_head(head.value(), &limits.fetch)
        .map_err(|_| PayloadPurgeError::InvalidFetchProjection)?;
    if checked.canonical_preimage() != head.canonical_preimage()
        || checked.canonical_bytes() != head.canonical_bytes()
        || checked.head_blake3() != head.head_blake3()
        || checked.value().result_key != expected_fetch_key(state)?
    {
        return Err(PayloadPurgeError::InvalidFetchProjection);
    }
    Ok(checked)
}

fn latest_state_time(state: &CanonicalObjectStoreRequestState) -> i64 {
    state
        .value()
        .closure_committed_at_unix_ms
        .map_or(state.value().state_committed_at_unix_ms, |closure| {
            closure.max(state.value().state_committed_at_unix_ms)
        })
}

fn zero_quota() -> ObjectStoreQuotaUnitsV1 {
    ObjectStoreQuotaUnitsV1 {
        bytes: 0,
        rows: 0,
        concurrency: 0,
    }
}

pub fn decide_object_store_payload_purge_cas(
    input: &ObjectStorePayloadPurgeCasInput<'_>,
    limits: &PayloadPurgeCasLimits,
) -> Result<ObjectStorePayloadPurgeCasDecision, PayloadPurgeError> {
    validate_limits(limits)?;
    let state = checked_state(input.current_state, limits)?;
    let (canonical_intent_bytes, purge_fingerprint) = encoded_intent(input.intent, limits)?;
    let selection = selected_payload(&state, input.intent)?;
    let payload = &selection.retention;
    let existing = input
        .existing_reservation
        .map(|reservation| checked_reservation(reservation, limits))
        .transpose()?;
    if let Some(existing) = existing.as_ref() {
        if existing.value().purge_fingerprint != purge_fingerprint
            || existing.value().canonical_intent_bytes != canonical_intent_bytes
        {
            return Ok(ObjectStorePayloadPurgeCasDecision::PurgeIdReuse);
        }
        if payload.availability
            == ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityDisposed as i32
        {
            let receipt = payload
                .purge_receipt
                .as_ref()
                .filter(|receipt| receipt.purge_id == input.intent.purge_id)
                .ok_or(PayloadPurgeError::InvalidReservation)?;
            return Ok(ObjectStorePayloadPurgeCasDecision::ReplayPurge {
                state,
                receipt: receipt.clone(),
            });
        }
        if existing.value().expected_request_state_blake3 != *state.state_blake3() {
            return Err(PayloadPurgeError::InvalidReservation);
        }
    } else if payload.availability
        == ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityDisposed as i32
    {
        return Err(PayloadPurgeError::InvalidReservation);
    }
    if payload.availability
        != ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained as i32
        || payload.purge_receipt.is_some()
    {
        return Err(PayloadPurgeError::InvalidState);
    }
    if input.database_now_unix_ms < input.intent.purge_not_before_unix_ms {
        if input.database_now_unix_ms < 0 {
            return Err(PayloadPurgeError::InvalidTime);
        }
        return Ok(ObjectStorePayloadPurgeCasDecision::NotYetEligible {
            purge_not_before_unix_ms: input.intent.purge_not_before_unix_ms,
        });
    }

    let head = match input.intent.payload_kind {
        ObjectStorePayloadKindV1::ObjectStorePayloadKindGetResult => Some(checked_fetch_head(
            &state,
            input
                .current_fetch_head
                .ok_or(PayloadPurgeError::InvalidFetchProjection)?,
            limits,
        )?),
        ObjectStorePayloadKindV1::ObjectStorePayloadKindPutBody => {
            if input.current_fetch_head.is_some() {
                return Err(PayloadPurgeError::InvalidFetchProjection);
            }
            None
        }
        _ => return Err(PayloadPurgeError::InvalidIntent),
    };
    if let Some(existing) = existing.as_ref() {
        if head.is_some() != existing.value().reserved_fetch_head_blake3.is_some() {
            return Err(PayloadPurgeError::InvalidReservation);
        }
        if let Some(head) = head.as_ref() {
            let reserved_generation = existing
                .value()
                .reserved_fetch_fence_generation
                .ok_or(PayloadPurgeError::InvalidReservation)?;
            let reserved_revision = existing
                .value()
                .reserved_fetch_head_revision
                .ok_or(PayloadPurgeError::InvalidReservation)?;
            let reserved_open_count = existing
                .value()
                .reserved_open_lease_count
                .ok_or(PayloadPurgeError::InvalidReservation)?;
            if head.value().fence_generation != reserved_generation
                || head.value().head_revision < reserved_revision
                || head.value().open_lease_count > reserved_open_count
                || (input.intent.disposition
                    == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked
                    && head.value().head_committed_at_unix_ms
                        < existing.value().reserved_at_unix_ms)
                || head.value().head_revision - reserved_revision
                    != reserved_open_count - head.value().open_lease_count
                || ((input.intent.disposition
                    == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded
                    || head.value().head_revision == reserved_revision)
                    && existing.value().reserved_fetch_head_blake3 != Some(*head.head_blake3()))
            {
                return Err(PayloadPurgeError::InvalidReservation);
            }
        }
    }
    if input.database_now_unix_ms < 0
        || input.database_now_unix_ms < latest_state_time(&state)
        || input.database_now_unix_ms < input.intent.purge_not_before_unix_ms
        || head
            .as_ref()
            .is_some_and(|head| input.database_now_unix_ms < head.value().head_committed_at_unix_ms)
        || existing.as_ref().is_some_and(|reservation| {
            input.database_now_unix_ms < reservation.value().reserved_at_unix_ms
        })
    {
        return Err(PayloadPurgeError::InvalidTime);
    }

    if existing.is_none() {
        let mut next_fetch_head = None;
        if let Some(head) = head.as_ref() {
            if input.intent.disposition
                == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked
            {
                match decide_object_store_fetch_payload_purge_fence(
                    head,
                    input.database_now_unix_ms,
                    &limits.fetch,
                )
                .map_err(|_| PayloadPurgeError::InvalidFetchProjection)?
                {
                    ObjectStoreFetchPayloadPurgeFenceDecision::DispositionFenceConflict => {
                        return Ok(ObjectStorePayloadPurgeCasDecision::FetchFenceConflict);
                    }
                    ObjectStoreFetchPayloadPurgeFenceDecision::Apply { next_head, .. } => {
                        next_fetch_head = Some(next_head);
                    }
                    ObjectStoreFetchPayloadPurgeFenceDecision::Replay { .. } => {
                        return Err(PayloadPurgeError::InvalidReservation);
                    }
                }
            } else if head.value().state != ObjectStoreFetchHeadState::DiscardCommitted
                || head.value().open_lease_count != 0
            {
                return Ok(ObjectStorePayloadPurgeCasDecision::FetchFenceConflict);
            }
        }
        let expected_fetch_head_blake3 = head.as_ref().map(|head| *head.head_blake3());
        let reserved_head = next_fetch_head.as_ref().or(head.as_ref());
        let reserved_fetch_head_blake3 = reserved_head.map(|head| *head.head_blake3());
        let reservation = validate_and_encode_object_store_payload_purge_reservation(
            &ObjectStorePayloadPurgeReservation {
                purge_fingerprint,
                canonical_intent_bytes,
                expected_request_state_blake3: *state.state_blake3(),
                expected_fetch_head_blake3,
                reserved_fetch_head_blake3,
                reserved_fetch_fence_generation: reserved_head
                    .map(|head| head.value().fence_generation),
                reserved_fetch_head_revision: reserved_head.map(|head| head.value().head_revision),
                reserved_open_lease_count: reserved_head.map(|head| head.value().open_lease_count),
                reserved_at_unix_ms: input.database_now_unix_ms,
            },
            limits,
        )?;
        return Ok(ObjectStorePayloadPurgeCasDecision::ApplyReservation {
            expected_state_blake3: *state.state_blake3(),
            expected_fetch_head_blake3,
            reservation,
            next_fetch_head: next_fetch_head.map(Box::new),
        });
    }

    let existing = existing.ok_or(PayloadPurgeError::InvalidReservation)?;
    let mut next_fetch_head = None;
    if let Some(head) = head.as_ref() {
        if input.intent.disposition
            == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked
        {
            if head.value().state != ObjectStoreFetchHeadState::PayloadPurgeReserved {
                return Ok(ObjectStorePayloadPurgeCasDecision::FetchFenceConflict);
            }
            if head.value().open_lease_count != 0 {
                return Ok(ObjectStorePayloadPurgeCasDecision::WaitForFetchDrain {
                    expected_state_blake3: *state.state_blake3(),
                    expected_reservation_blake3: *existing.reservation_blake3(),
                    fence_generation: head.value().fence_generation,
                    open_lease_count: head.value().open_lease_count,
                });
            }
            next_fetch_head = Some(
                commit_object_store_fetch_payload_purge(
                    head,
                    input.database_now_unix_ms,
                    &limits.fetch,
                )
                .map_err(|_| PayloadPurgeError::InvalidFetchProjection)?,
            );
        } else if head.value().state != ObjectStoreFetchHeadState::DiscardCommitted
            || head.value().open_lease_count != 0
        {
            return Ok(ObjectStorePayloadPurgeCasDecision::FetchFenceConflict);
        }
    }

    let mut next = state.value().clone();
    let quota = next
        .quota_state
        .as_mut()
        .ok_or(PayloadPurgeError::InvalidState)?;
    quota.quota_revision = quota
        .quota_revision
        .checked_add(1)
        .ok_or(PayloadPurgeError::RevisionOverflow)?;
    match selection.field {
        PayloadField::PutBody => quota.put_spool_quota = Some(zero_quota()),
        PayloadField::ResultPayload => quota.result_spool_quota = Some(zero_quota()),
    }
    let receipt = ObjectStorePayloadPurgeReceiptV1 {
        purge_id: input.intent.purge_id.clone(),
        payload_kind: input.intent.payload_kind as i32,
        terminal_result_id: Some(input.intent.terminal_result_id.clone()),
        disposition: input.intent.disposition as i32,
        released_bytes: payload.size,
        released_rows: 1,
        released_concurrency: u64::from(matches!(selection.field, PayloadField::PutBody)),
        purged_at_unix_ms: input.database_now_unix_ms,
        provider_authority_refunded: false,
        receipt_blake3: Default::default(),
        release_reason: selection.release_reason as i32,
        deleted_partial_temp_bytes: 0,
        deleted_partial_temp_files: 0,
    };
    let next_payload = match selection.field {
        PayloadField::PutBody => next
            .put_body
            .as_mut()
            .ok_or(PayloadPurgeError::InvalidState)?,
        PayloadField::ResultPayload => next
            .result_payload
            .as_mut()
            .ok_or(PayloadPurgeError::InvalidState)?,
    };
    next_payload.availability =
        ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityDisposed as i32;
    next_payload.purge_state =
        ObjectStorePayloadPurgeStateV1::ObjectStorePayloadPurgeStatePurged as i32;
    next_payload.purge_receipt = Some(receipt);
    next.state_committed_at_unix_ms = input.database_now_unix_ms;
    next.closure_committed_at_unix_ms = Some(input.database_now_unix_ms);
    next.state_blake3 = Default::default();
    let next_state = validate_and_encode_object_store_request_state(&next, &limits.state)
        .map_err(|_| PayloadPurgeError::InvalidState)?;
    let receipt = match selection.field {
        PayloadField::PutBody => next_state.value().put_body.as_ref(),
        PayloadField::ResultPayload => next_state.value().result_payload.as_ref(),
    }
    .and_then(|payload| payload.purge_receipt.as_ref())
    .ok_or(PayloadPurgeError::InvalidState)?
    .clone();
    Ok(ObjectStorePayloadPurgeCasDecision::ApplyPurge {
        expected_state_blake3: *state.state_blake3(),
        expected_reservation_blake3: *existing.reservation_blake3(),
        expected_fetch_head_blake3: head.as_ref().map(|head| *head.head_blake3()),
        next_state,
        next_fetch_head: next_fetch_head.map(Box::new),
        receipt,
    })
}
