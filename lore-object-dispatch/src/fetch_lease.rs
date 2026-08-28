// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure durable fetch-lease records and mutation plans.
//!
//! This source-dark kernel performs no database, filesystem, clock, provider, or runtime effects.
//! Every `Apply` result is a serializable compare-and-swap plan over complete canonical records.

use std::collections::HashSet;
use std::fmt;

use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadAvailabilityV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestPhaseV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDispositionV1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1;
use thiserror::Error;

use crate::contract::BoundedCanonicalWriter;
use crate::contract::decode_canonical_uuid_v7;
use crate::contract::validate_canonical_text;
use crate::request_state_wire::CanonicalObjectStoreRequestState;
use crate::request_state_wire::RequestStateWireLimits;
use crate::request_state_wire::validate_and_encode_object_store_request_state;

const PENDING_DISCARD_DOMAIN: &[u8] = b"object-store-pending-discard-v1\0";
const HEAD_DOMAIN: &[u8] = b"object-store-fetch-lease-head-v1\0";
const OWNER_REVOCATION_DOMAIN: &[u8] = b"object-store-fetch-owner-revocation-v1\0";
const LEASE_DOMAIN: &[u8] = b"object-store-fetch-lease-v1\0";
const TERMINAL_FINGERPRINT_DOMAIN: &[u8] = b"object-store-fetch-lease-terminal-v1\0";
const OPEN_FINGERPRINT_DOMAIN: &[u8] = b"object-store-fetch-lease-open-v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchLeaseLimits {
    pub max_identity_bytes: u32,
    pub max_authenticated_scope_bytes: u32,
    pub max_canonical_record_bytes: u32,
    pub max_canonical_discard_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStoreFetchResultKey {
    pub protocol_revision: String,
    pub provider_boundary_id: String,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub logical_request_id: String,
    pub attempt_id: String,
    pub terminal_result_id: String,
    pub canonical_result_size: u64,
    pub canonical_result_blake3: [u8; 32],
    pub byte_result_handle: String,
    pub payload_size: u64,
    pub payload_blake3: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectStoreFetchHeadState {
    Unfenced = 1,
    DiscardReserved = 2,
    DiscardCommitted = 3,
    PayloadPurgeReserved = 4,
    PayloadPurgeCommitted = 5,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ObjectStorePendingFetchDiscard {
    pub discard_fingerprint: [u8; 32],
    pub canonical_discard_bytes: Vec<u8>,
    pub expected_request_state_blake3: [u8; 32],
    pub reserved_at_unix_ms: i64,
}

impl fmt::Debug for ObjectStorePendingFetchDiscard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStorePendingFetchDiscard")
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ObjectStoreFetchHead {
    pub result_key: ObjectStoreFetchResultKey,
    pub state: ObjectStoreFetchHeadState,
    pub fence_generation: u64,
    pub open_lease_count: u64,
    pub head_revision: u64,
    pub head_committed_at_unix_ms: i64,
    pub pending_discard: Option<ObjectStorePendingFetchDiscard>,
}

impl fmt::Debug for ObjectStoreFetchHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStoreFetchHead")
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalObjectStoreFetchHead {
    value: ObjectStoreFetchHead,
    canonical_preimage: Vec<u8>,
    canonical_bytes: Vec<u8>,
    head_blake3: [u8; 32],
}

impl CanonicalObjectStoreFetchHead {
    pub fn value(&self) -> &ObjectStoreFetchHead {
        &self.value
    }

    pub fn canonical_preimage(&self) -> &[u8] {
        &self.canonical_preimage
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn head_blake3(&self) -> &[u8; 32] {
        &self.head_blake3
    }
}

impl fmt::Debug for CanonicalObjectStoreFetchHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalObjectStoreFetchHead")
            .field("value", &"[REDACTED]")
            .field("canonical_preimage", &"[REDACTED]")
            .field("canonical_bytes", &"[REDACTED]")
            .field("head_blake3", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectStoreFetchLeaseState {
    Open = 1,
    Closed = 2,
    Cancelled = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectStoreFetchLeaseTerminalReason {
    Completed = 1,
    CallerCancelled = 2,
    StreamFailed = 3,
    DiscardFenced = 4,
    OwnerRevoked = 5,
    PayloadPurgeFenced = 6,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ObjectStoreFetchOwnerRevocationEvidence {
    pub owner_service_instance_id: String,
    pub revoked_owner_generation: u64,
    pub successor_owner_generation: u64,
    pub revocation_id: String,
    pub revocation_revision: u64,
    pub revocation_fence: u64,
    pub revoked_at_unix_ms: i64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalObjectStoreFetchOwnerRevocationEvidence {
    value: ObjectStoreFetchOwnerRevocationEvidence,
    canonical_preimage: Vec<u8>,
    canonical_bytes: Vec<u8>,
    evidence_blake3: [u8; 32],
}

impl CanonicalObjectStoreFetchOwnerRevocationEvidence {
    pub fn value(&self) -> &ObjectStoreFetchOwnerRevocationEvidence {
        &self.value
    }

    pub fn canonical_preimage(&self) -> &[u8] {
        &self.canonical_preimage
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn evidence_blake3(&self) -> &[u8; 32] {
        &self.evidence_blake3
    }
}

impl fmt::Debug for CanonicalObjectStoreFetchOwnerRevocationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalObjectStoreFetchOwnerRevocationEvidence")
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ObjectStoreFetchResolvedCallerAuthority {
    pub result_key: ObjectStoreFetchResultKey,
    pub owner_service_instance_id: String,
    pub owner_generation: u64,
    pub owner_authority_revision: u64,
    pub authenticated_principal_id: String,
    pub authenticated_scope: String,
    pub canonical_descriptor_fingerprint: [u8; 32],
    pub caller_fence: u64,
}

impl fmt::Debug for ObjectStoreFetchResolvedCallerAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStoreFetchResolvedCallerAuthority")
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for ObjectStoreFetchOwnerRevocationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStoreFetchOwnerRevocationEvidence")
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ObjectStoreFetchLease {
    pub result_key: ObjectStoreFetchResultKey,
    pub lease_id: String,
    pub owner_service_instance_id: String,
    pub owner_generation: u64,
    pub owner_authority_revision: u64,
    pub authenticated_principal_id: String,
    pub authenticated_scope: String,
    pub canonical_descriptor_fingerprint: [u8; 32],
    pub caller_fence: u64,
    pub admitted_generation: u64,
    pub open_fingerprint: [u8; 32],
    pub next_chunk_index: u64,
    pub lease_revision: u64,
    pub opened_at_unix_ms: i64,
    pub state: ObjectStoreFetchLeaseState,
    pub terminal_reason: Option<ObjectStoreFetchLeaseTerminalReason>,
    pub terminal_at_unix_ms: Option<i64>,
    pub terminal_fingerprint: Option<[u8; 32]>,
    pub owner_revocation: Option<ObjectStoreFetchOwnerRevocationEvidence>,
}

impl fmt::Debug for ObjectStoreFetchLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStoreFetchLease")
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalObjectStoreFetchLease {
    value: ObjectStoreFetchLease,
    canonical_preimage: Vec<u8>,
    canonical_bytes: Vec<u8>,
    lease_blake3: [u8; 32],
}

impl CanonicalObjectStoreFetchLease {
    pub fn value(&self) -> &ObjectStoreFetchLease {
        &self.value
    }

    pub fn canonical_preimage(&self) -> &[u8] {
        &self.canonical_preimage
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn lease_blake3(&self) -> &[u8; 32] {
        &self.lease_blake3
    }
}

impl fmt::Debug for CanonicalObjectStoreFetchLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalObjectStoreFetchLease")
            .field("value", &"[REDACTED]")
            .field("canonical_preimage", &"[REDACTED]")
            .field("canonical_bytes", &"[REDACTED]")
            .field("lease_blake3", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FetchLeaseError {
    #[error("durable fetch-lease limits are invalid")]
    InvalidLimits,
    #[error("durable fetch-lease text or UUID is invalid")]
    InvalidIdentity,
    #[error("durable fetch-lease canonical record exceeds its bound")]
    CanonicalTooLarge,
    #[error("durable fetch-lease record or digest is not canonical")]
    InvalidCanonicalRecord,
    #[error("object-store request state is not a retained byte result")]
    NotFetchable,
    #[error("durable fetch-lease result authority does not match")]
    ResultMismatch,
    #[error("durable fetch-lease head state is invalid")]
    InvalidHeadState,
    #[error("durable fetch-lease state is invalid")]
    InvalidLeaseState,
    #[error("durable fetch-lease generation or revision overflows")]
    GenerationOverflow,
    #[error("durable fetch-lease count overflows or underflows")]
    CountOverflow,
    #[error("durable fetch-lease ID was reused with different authority")]
    LeaseIdReuse,
    #[error("durable fetch-lease caller fence is stale")]
    StaleFence,
    #[error("durable fetch-lease head rejects new leases")]
    FetchesFenced,
    #[error("durable fetch-lease chunk index is stale or non-monotonic")]
    InvalidChunkIndex,
    #[error("durable fetch-lease terminal action conflicts with retained terminal evidence")]
    TerminalConflict,
    #[error("durable fetch-lease time is invalid")]
    InvalidTime,
    #[error("durable fetch-lease discard reservation conflicts")]
    DiscardReservationConflict,
    #[error("durable fetch-lease owner-revocation evidence is invalid")]
    InvalidOwnerRevocation,
    #[error("durable fetch-lease projection contains duplicate or inconsistent rows")]
    InvalidProjection,
}

fn writer(limits: &FetchLeaseLimits) -> Result<BoundedCanonicalWriter, FetchLeaseError> {
    if limits.max_identity_bytes == 0
        || limits.max_authenticated_scope_bytes == 0
        || limits.max_canonical_record_bytes == 0
        || limits.max_canonical_discard_bytes == 0
    {
        return Err(FetchLeaseError::InvalidLimits);
    }
    BoundedCanonicalWriter::new(limits.max_canonical_record_bytes)
        .map_err(|_| FetchLeaseError::InvalidLimits)
}

fn write_text(
    output: &mut BoundedCanonicalWriter,
    value: &str,
    limits: &FetchLeaseLimits,
) -> Result<(), FetchLeaseError> {
    validate_canonical_text(value, limits.max_identity_bytes)
        .map_err(|_| FetchLeaseError::InvalidIdentity)?;
    output
        .text(value)
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)
}

fn write_time(output: &mut BoundedCanonicalWriter, value: i64) -> Result<(), FetchLeaseError> {
    output
        .u64(u64::try_from(value).map_err(|_| FetchLeaseError::InvalidTime)?)
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)
}

fn write_scope(
    output: &mut BoundedCanonicalWriter,
    value: &str,
    limits: &FetchLeaseLimits,
) -> Result<(), FetchLeaseError> {
    validate_canonical_text(value, limits.max_authenticated_scope_bytes)
        .map_err(|_| FetchLeaseError::InvalidIdentity)?;
    output
        .text(value)
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)
}

fn write_optional_complete(
    output: &mut BoundedCanonicalWriter,
    value: Option<&[u8]>,
) -> Result<(), FetchLeaseError> {
    output
        .u8(u8::from(value.is_some()))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    if let Some(value) = value {
        output
            .bytes(value)
            .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    }
    Ok(())
}

fn finish(preimage: Vec<u8>, maximum: u32) -> Result<(Vec<u8>, [u8; 32]), FetchLeaseError> {
    let digest = *blake3::hash(&preimage).as_bytes();
    let size = preimage
        .len()
        .checked_add(digest.len())
        .ok_or(FetchLeaseError::CanonicalTooLarge)?;
    if size > maximum as usize {
        return Err(FetchLeaseError::CanonicalTooLarge);
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(&preimage);
    bytes.extend_from_slice(&digest);
    Ok((bytes, digest))
}

fn write_result_key(
    output: &mut BoundedCanonicalWriter,
    value: &ObjectStoreFetchResultKey,
    limits: &FetchLeaseLimits,
) -> Result<(), FetchLeaseError> {
    for value in [
        &value.protocol_revision,
        &value.provider_boundary_id,
        &value.authenticated_cell_id,
        &value.authenticated_tenant_id,
    ] {
        write_text(output, value, limits)?;
    }
    let logical = decode_canonical_uuid_v7(&value.logical_request_id)
        .map_err(|_| FetchLeaseError::InvalidIdentity)?;
    let attempt = decode_canonical_uuid_v7(&value.attempt_id)
        .map_err(|_| FetchLeaseError::InvalidIdentity)?;
    output
        .raw(&logical)
        .and_then(|_| output.raw(&attempt))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_text(output, &value.terminal_result_id, limits)?;
    write_text(output, &value.byte_result_handle, limits)?;
    output
        .u64(value.canonical_result_size)
        .and_then(|_| output.raw(&value.canonical_result_blake3))
        .and_then(|_| output.u64(value.payload_size))
        .and_then(|_| output.raw(&value.payload_blake3))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    Ok(())
}

fn pending_discard_preimage(
    value: &ObjectStorePendingFetchDiscard,
    limits: &FetchLeaseLimits,
) -> Result<Vec<u8>, FetchLeaseError> {
    if value.canonical_discard_bytes.is_empty()
        || value.canonical_discard_bytes.len() > limits.max_canonical_discard_bytes as usize
        || *blake3::hash(&value.canonical_discard_bytes).as_bytes() != value.discard_fingerprint
    {
        return Err(FetchLeaseError::DiscardReservationConflict);
    }
    let mut output = writer(limits)?;
    output
        .raw(PENDING_DISCARD_DOMAIN)
        .and_then(|_| output.raw(&value.discard_fingerprint))
        .and_then(|_| output.bytes(&value.canonical_discard_bytes))
        .and_then(|_| output.raw(&value.expected_request_state_blake3))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_time(&mut output, value.reserved_at_unix_ms)?;
    Ok(output.finish())
}

fn complete_pending_discard(
    value: &ObjectStorePendingFetchDiscard,
    limits: &FetchLeaseLimits,
) -> Result<Vec<u8>, FetchLeaseError> {
    let preimage = pending_discard_preimage(value, limits)?;
    finish(preimage, limits.max_canonical_record_bytes).map(|value| value.0)
}

pub fn validate_and_encode_object_store_fetch_head(
    input: &ObjectStoreFetchHead,
    limits: &FetchLeaseLimits,
) -> Result<CanonicalObjectStoreFetchHead, FetchLeaseError> {
    if input.fence_generation == 0 || input.head_revision == 0 {
        return Err(FetchLeaseError::InvalidHeadState);
    }
    match (input.state, input.pending_discard.as_ref()) {
        (ObjectStoreFetchHeadState::Unfenced, None)
        | (ObjectStoreFetchHeadState::PayloadPurgeReserved, None)
        | (ObjectStoreFetchHeadState::PayloadPurgeCommitted, None) => {}
        (ObjectStoreFetchHeadState::DiscardReserved, Some(_))
        | (ObjectStoreFetchHeadState::DiscardCommitted, Some(_)) => {}
        _ => return Err(FetchLeaseError::InvalidHeadState),
    }
    if matches!(
        input.state,
        ObjectStoreFetchHeadState::DiscardCommitted
            | ObjectStoreFetchHeadState::PayloadPurgeCommitted
    ) && input.open_lease_count != 0
    {
        return Err(FetchLeaseError::InvalidHeadState);
    }
    if input
        .pending_discard
        .as_ref()
        .is_some_and(|pending| pending.reserved_at_unix_ms > input.head_committed_at_unix_ms)
    {
        return Err(FetchLeaseError::InvalidTime);
    }
    let pending = input
        .pending_discard
        .as_ref()
        .map(|value| complete_pending_discard(value, limits))
        .transpose()?;
    let mut output = writer(limits)?;
    output
        .raw(HEAD_DOMAIN)
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_result_key(&mut output, &input.result_key, limits)?;
    output
        .u64(input.fence_generation)
        .and_then(|_| output.u32(input.state as u32))
        .and_then(|_| output.u64(input.open_lease_count))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_optional_complete(&mut output, pending.as_deref())?;
    output
        .u64(input.head_revision)
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_time(&mut output, input.head_committed_at_unix_ms)?;
    let canonical_preimage = output.finish();
    let (canonical_bytes, head_blake3) = finish(
        canonical_preimage.clone(),
        limits.max_canonical_record_bytes,
    )?;
    Ok(CanonicalObjectStoreFetchHead {
        value: input.clone(),
        canonical_preimage,
        canonical_bytes,
        head_blake3,
    })
}

fn owner_revocation_preimage(
    value: &ObjectStoreFetchOwnerRevocationEvidence,
    limits: &FetchLeaseLimits,
) -> Result<Vec<u8>, FetchLeaseError> {
    if value.revoked_owner_generation == 0
        || value.successor_owner_generation <= value.revoked_owner_generation
        || value.revocation_revision == 0
        || value.revocation_fence == 0
    {
        return Err(FetchLeaseError::InvalidOwnerRevocation);
    }
    let mut output = writer(limits)?;
    output
        .raw(OWNER_REVOCATION_DOMAIN)
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_text(&mut output, &value.owner_service_instance_id, limits)?;
    output
        .u64(value.revoked_owner_generation)
        .and_then(|_| output.u64(value.successor_owner_generation))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_text(&mut output, &value.revocation_id, limits)?;
    output
        .u64(value.revocation_revision)
        .and_then(|_| output.u64(value.revocation_fence))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_time(&mut output, value.revoked_at_unix_ms)?;
    Ok(output.finish())
}

fn complete_owner_revocation(
    value: &ObjectStoreFetchOwnerRevocationEvidence,
    limits: &FetchLeaseLimits,
) -> Result<Vec<u8>, FetchLeaseError> {
    let preimage = owner_revocation_preimage(value, limits)?;
    finish(preimage, limits.max_canonical_record_bytes).map(|value| value.0)
}

fn terminal_semantic_fingerprint(
    lease: &ObjectStoreFetchLease,
    evidence: Option<&[u8]>,
    limits: &FetchLeaseLimits,
) -> Result<Option<[u8; 32]>, FetchLeaseError> {
    if lease.state == ObjectStoreFetchLeaseState::Open {
        return Ok(None);
    }
    let reason = lease
        .terminal_reason
        .ok_or(FetchLeaseError::InvalidLeaseState)?;
    let lease_id =
        decode_canonical_uuid_v7(&lease.lease_id).map_err(|_| FetchLeaseError::InvalidIdentity)?;
    let mut output = writer(limits)?;
    output
        .raw(TERMINAL_FINGERPRINT_DOMAIN)
        .and_then(|_| output.raw(&lease_id))
        .and_then(|_| output.raw(&lease.open_fingerprint))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    match reason {
        ObjectStoreFetchLeaseTerminalReason::Completed => {
            output
                .u32(1)
                .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
            write_text(&mut output, &lease.owner_service_instance_id, limits)?;
            output
                .u64(lease.owner_generation)
                .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
        }
        ObjectStoreFetchLeaseTerminalReason::OwnerRevoked => {
            let evidence = evidence.ok_or(FetchLeaseError::InvalidOwnerRevocation)?;
            output
                .u32(3)
                .and_then(|_| output.bytes(evidence))
                .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
        }
        _ => {
            output
                .u32(2)
                .and_then(|_| output.u32(reason as u32))
                .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
            write_text(&mut output, &lease.owner_service_instance_id, limits)?;
            output
                .u64(lease.owner_generation)
                .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
        }
    }
    Ok(Some(*blake3::hash(&output.finish()).as_bytes()))
}

pub fn validate_and_encode_object_store_fetch_owner_revocation(
    input: &ObjectStoreFetchOwnerRevocationEvidence,
    limits: &FetchLeaseLimits,
) -> Result<CanonicalObjectStoreFetchOwnerRevocationEvidence, FetchLeaseError> {
    let canonical_preimage = owner_revocation_preimage(input, limits)?;
    let (canonical_bytes, evidence_blake3) = finish(
        canonical_preimage.clone(),
        limits.max_canonical_record_bytes,
    )?;
    Ok(CanonicalObjectStoreFetchOwnerRevocationEvidence {
        value: input.clone(),
        canonical_preimage,
        canonical_bytes,
        evidence_blake3,
    })
}

fn checked_owner_revocation(
    input: &CanonicalObjectStoreFetchOwnerRevocationEvidence,
    limits: &FetchLeaseLimits,
) -> Result<CanonicalObjectStoreFetchOwnerRevocationEvidence, FetchLeaseError> {
    let checked = validate_and_encode_object_store_fetch_owner_revocation(input.value(), limits)?;
    if checked.canonical_preimage() != input.canonical_preimage()
        || checked.canonical_bytes() != input.canonical_bytes()
        || checked.evidence_blake3() != input.evidence_blake3()
    {
        return Err(FetchLeaseError::InvalidCanonicalRecord);
    }
    Ok(checked)
}

pub fn validate_and_encode_object_store_fetch_lease(
    input: &ObjectStoreFetchLease,
    limits: &FetchLeaseLimits,
) -> Result<CanonicalObjectStoreFetchLease, FetchLeaseError> {
    let lease_id =
        decode_canonical_uuid_v7(&input.lease_id).map_err(|_| FetchLeaseError::InvalidIdentity)?;
    if input.owner_generation == 0
        || input.owner_authority_revision == 0
        || input.caller_fence == 0
        || input.admitted_generation == 0
        || input.lease_revision == 0
    {
        return Err(FetchLeaseError::InvalidLeaseState);
    }
    let terminal_fields = input.terminal_reason.is_some()
        && input.terminal_at_unix_ms.is_some()
        && input.terminal_fingerprint.is_some();
    match input.state {
        ObjectStoreFetchLeaseState::Open
            if !terminal_fields
                && input.terminal_reason.is_none()
                && input.terminal_at_unix_ms.is_none()
                && input.terminal_fingerprint.is_none()
                && input.owner_revocation.is_none() => {}
        ObjectStoreFetchLeaseState::Closed
            if terminal_fields
                && input.terminal_reason
                    == Some(ObjectStoreFetchLeaseTerminalReason::Completed)
                && input.owner_revocation.is_none() => {}
        ObjectStoreFetchLeaseState::Cancelled
            if terminal_fields
                && input.terminal_reason
                    != Some(ObjectStoreFetchLeaseTerminalReason::Completed)
                && (input.owner_revocation.is_some()
                    == (input.terminal_reason
                        == Some(ObjectStoreFetchLeaseTerminalReason::OwnerRevoked))) => {}
        _ => return Err(FetchLeaseError::InvalidLeaseState),
    }
    if input
        .terminal_at_unix_ms
        .is_some_and(|value| value < input.opened_at_unix_ms)
    {
        return Err(FetchLeaseError::InvalidTime);
    }
    let evidence = input
        .owner_revocation
        .as_ref()
        .map(|value| complete_owner_revocation(value, limits))
        .transpose()?;
    if let Some(value) = input.owner_revocation.as_ref()
        && (value.owner_service_instance_id != input.owner_service_instance_id
            || value.revoked_owner_generation != input.owner_generation
            || value.successor_owner_generation <= input.owner_generation
            || value.revocation_revision <= input.owner_authority_revision
            || value.revocation_fence <= input.caller_fence
            || value.revoked_at_unix_ms < input.opened_at_unix_ms
            || input
                .terminal_at_unix_ms
                .is_none_or(|terminal_at| terminal_at < value.revoked_at_unix_ms))
    {
        return Err(FetchLeaseError::InvalidOwnerRevocation);
    }
    let authority = ObjectStoreFetchResolvedCallerAuthority {
        result_key: input.result_key.clone(),
        owner_service_instance_id: input.owner_service_instance_id.clone(),
        owner_generation: input.owner_generation,
        owner_authority_revision: input.owner_authority_revision,
        authenticated_principal_id: input.authenticated_principal_id.clone(),
        authenticated_scope: input.authenticated_scope.clone(),
        canonical_descriptor_fingerprint: input.canonical_descriptor_fingerprint,
        caller_fence: input.caller_fence,
    };
    let expected_open = open_fingerprint(
        &input.result_key,
        &input.lease_id,
        &authority,
        input.admitted_generation,
        limits,
    )?;
    if input.open_fingerprint != expected_open {
        return Err(FetchLeaseError::InvalidCanonicalRecord);
    }
    let expected_terminal = terminal_semantic_fingerprint(input, evidence.as_deref(), limits)?;
    if expected_terminal.is_some() != input.terminal_fingerprint.is_some()
        || expected_terminal != input.terminal_fingerprint
    {
        return Err(FetchLeaseError::InvalidCanonicalRecord);
    }
    let mut output = writer(limits)?;
    output
        .raw(LEASE_DOMAIN)
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_result_key(&mut output, &input.result_key, limits)?;
    output
        .raw(&lease_id)
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_text(&mut output, &input.owner_service_instance_id, limits)?;
    output
        .u64(input.owner_generation)
        .and_then(|_| output.u64(input.owner_authority_revision))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_text(&mut output, &input.authenticated_principal_id, limits)?;
    write_scope(&mut output, &input.authenticated_scope, limits)?;
    output
        .raw(&input.canonical_descriptor_fingerprint)
        .and_then(|_| output.u64(input.caller_fence))
        .and_then(|_| output.u64(input.admitted_generation))
        .and_then(|_| output.raw(&input.open_fingerprint))
        .and_then(|_| output.u64(input.next_chunk_index))
        .and_then(|_| output.u64(input.lease_revision))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_time(&mut output, input.opened_at_unix_ms)?;
    output
        .u32(input.state as u32)
        .and_then(|_| output.u8(u8::from(input.terminal_reason.is_some())))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    if let Some(reason) = input.terminal_reason {
        output
            .u32(reason as u32)
            .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    }
    output
        .u8(u8::from(input.terminal_at_unix_ms.is_some()))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    if let Some(value) = input.terminal_at_unix_ms {
        write_time(&mut output, value)?;
    }
    output
        .u8(u8::from(input.terminal_fingerprint.is_some()))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    if let Some(value) = input.terminal_fingerprint {
        output
            .raw(&value)
            .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    }
    write_optional_complete(&mut output, evidence.as_deref())?;
    let canonical_preimage = output.finish();
    let (canonical_bytes, lease_blake3) = finish(
        canonical_preimage.clone(),
        limits.max_canonical_record_bytes,
    )?;
    Ok(CanonicalObjectStoreFetchLease {
        value: input.clone(),
        canonical_preimage,
        canonical_bytes,
        lease_blake3,
    })
}

fn checked_head(
    input: &CanonicalObjectStoreFetchHead,
    limits: &FetchLeaseLimits,
) -> Result<CanonicalObjectStoreFetchHead, FetchLeaseError> {
    let checked = validate_and_encode_object_store_fetch_head(input.value(), limits)?;
    if checked.canonical_preimage() != input.canonical_preimage()
        || checked.canonical_bytes() != input.canonical_bytes()
        || checked.head_blake3() != input.head_blake3()
    {
        return Err(FetchLeaseError::InvalidCanonicalRecord);
    }
    Ok(checked)
}

fn checked_lease(
    input: &CanonicalObjectStoreFetchLease,
    limits: &FetchLeaseLimits,
) -> Result<CanonicalObjectStoreFetchLease, FetchLeaseError> {
    let checked = validate_and_encode_object_store_fetch_lease(input.value(), limits)?;
    if checked.canonical_preimage() != input.canonical_preimage()
        || checked.canonical_bytes() != input.canonical_bytes()
        || checked.lease_blake3() != input.lease_blake3()
    {
        return Err(FetchLeaseError::InvalidCanonicalRecord);
    }
    Ok(checked)
}

fn checked_request_state(
    state: &CanonicalObjectStoreRequestState,
    limits: &RequestStateWireLimits,
) -> Result<CanonicalObjectStoreRequestState, FetchLeaseError> {
    let checked = validate_and_encode_object_store_request_state(state.value(), limits)
        .map_err(|_| FetchLeaseError::NotFetchable)?;
    if checked.canonical_bytes() != state.canonical_bytes()
        || checked.canonical_preimage() != state.canonical_preimage()
        || checked.state_blake3() != state.state_blake3()
    {
        return Err(FetchLeaseError::InvalidCanonicalRecord);
    }
    Ok(checked)
}

pub fn object_store_fetch_result_key_from_state(
    state: &CanonicalObjectStoreRequestState,
    state_limits: &RequestStateWireLimits,
) -> Result<ObjectStoreFetchResultKey, FetchLeaseError> {
    let checked = checked_request_state(state, state_limits)?;
    let value = checked.value();
    if value.phase != ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseTerminal as i32
        || !matches!(
            value.result_disposition,
            value
                if value
                    == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable
                        as i32
                || value
                    == ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked as i32
        )
        || value.result_payload.as_ref().is_none_or(|payload| {
            payload.availability
                != ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityRetained as i32
        })
    {
        return Err(FetchLeaseError::NotFetchable);
    }
    let terminal = value
        .terminal_result
        .as_ref()
        .ok_or(FetchLeaseError::NotFetchable)?;
    let byte_result = match terminal.result.as_ref() {
        Some(object_store_terminal_result_v1::Result::ByteResult(value)) => value,
        _ => return Err(FetchLeaseError::NotFetchable),
    };
    let result_digest = terminal
        .canonical_result_blake3
        .as_ref()
        .try_into()
        .map_err(|_| FetchLeaseError::NotFetchable)?;
    Ok(ObjectStoreFetchResultKey {
        protocol_revision: value.protocol_revision.clone(),
        provider_boundary_id: value.provider_boundary_id.clone(),
        authenticated_cell_id: value.authenticated_cell_id.clone(),
        authenticated_tenant_id: value.authenticated_tenant_id.clone(),
        logical_request_id: value.logical_request_id.clone(),
        attempt_id: value.attempt_id.clone(),
        terminal_result_id: terminal.terminal_result_id.clone(),
        canonical_result_size: terminal.canonical_result_size,
        canonical_result_blake3: result_digest,
        byte_result_handle: byte_result.handle.clone(),
        payload_size: byte_result.size,
        payload_blake3: byte_result
            .blake3
            .as_ref()
            .try_into()
            .map_err(|_| FetchLeaseError::NotFetchable)?,
    })
}

pub fn initialize_object_store_fetch_head(
    state: &CanonicalObjectStoreRequestState,
    database_now_unix_ms: i64,
    state_limits: &RequestStateWireLimits,
    limits: &FetchLeaseLimits,
) -> Result<CanonicalObjectStoreFetchHead, FetchLeaseError> {
    if state.value().result_disposition
        != ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAvailable as i32
    {
        return Err(FetchLeaseError::NotFetchable);
    }
    let result_key = object_store_fetch_result_key_from_state(state, state_limits)?;
    if database_now_unix_ms < state.value().state_committed_at_unix_ms {
        return Err(FetchLeaseError::InvalidTime);
    }
    validate_and_encode_object_store_fetch_head(
        &ObjectStoreFetchHead {
            result_key,
            state: ObjectStoreFetchHeadState::Unfenced,
            fence_generation: 1,
            open_lease_count: 0,
            head_revision: 1,
            head_committed_at_unix_ms: database_now_unix_ms,
            pending_discard: None,
        },
        limits,
    )
}

pub fn validate_object_store_fetch_projection(
    head: &CanonicalObjectStoreFetchHead,
    leases: &[CanonicalObjectStoreFetchLease],
    limits: &FetchLeaseLimits,
) -> Result<(), FetchLeaseError> {
    let head = checked_head(head, limits)?;
    let mut ids = HashSet::with_capacity(leases.len());
    let mut open = 0u64;
    for lease in leases {
        let lease = checked_lease(lease, limits)?;
        if lease.value().result_key != head.value().result_key
            || lease.value().admitted_generation > head.value().fence_generation
            || !ids.insert(lease.value().lease_id.clone())
        {
            return Err(FetchLeaseError::InvalidProjection);
        }
        if lease.value().state == ObjectStoreFetchLeaseState::Open {
            open = open.checked_add(1).ok_or(FetchLeaseError::CountOverflow)?;
        }
    }
    if open != head.value().open_lease_count {
        return Err(FetchLeaseError::InvalidProjection);
    }
    Ok(())
}

pub struct OpenObjectStoreFetchLeaseInput<'a> {
    pub current_state: &'a CanonicalObjectStoreRequestState,
    pub current_head: &'a CanonicalObjectStoreFetchHead,
    pub existing_lease: Option<&'a CanonicalObjectStoreFetchLease>,
    pub lease_id: &'a str,
    pub authority: &'a ObjectStoreFetchResolvedCallerAuthority,
    pub database_now_unix_ms: i64,
}

fn open_fingerprint(
    key: &ObjectStoreFetchResultKey,
    lease_id: &str,
    authority: &ObjectStoreFetchResolvedCallerAuthority,
    admitted_generation: u64,
    limits: &FetchLeaseLimits,
) -> Result<[u8; 32], FetchLeaseError> {
    if authority.owner_generation == 0
        || authority.owner_authority_revision == 0
        || authority.caller_fence == 0
        || admitted_generation == 0
    {
        return Err(FetchLeaseError::InvalidLeaseState);
    }
    let lease_id =
        decode_canonical_uuid_v7(lease_id).map_err(|_| FetchLeaseError::InvalidIdentity)?;
    let mut output = writer(limits)?;
    output
        .raw(OPEN_FINGERPRINT_DOMAIN)
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_result_key(&mut output, key, limits)?;
    output
        .raw(&lease_id)
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_text(&mut output, &authority.owner_service_instance_id, limits)?;
    output
        .u64(authority.owner_generation)
        .and_then(|_| output.u64(authority.owner_authority_revision))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    write_text(&mut output, &authority.authenticated_principal_id, limits)?;
    write_scope(&mut output, &authority.authenticated_scope, limits)?;
    output
        .raw(&authority.canonical_descriptor_fingerprint)
        .and_then(|_| output.u64(authority.caller_fence))
        .and_then(|_| output.u64(admitted_generation))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    Ok(*blake3::hash(&output.finish()).as_bytes())
}

fn validate_resolved_authority(
    authority: &ObjectStoreFetchResolvedCallerAuthority,
    key: &ObjectStoreFetchResultKey,
    descriptor_fingerprint: [u8; 32],
    limits: &FetchLeaseLimits,
) -> Result<(), FetchLeaseError> {
    if authority.result_key != *key
        || authority.canonical_descriptor_fingerprint != descriptor_fingerprint
        || authority.owner_generation == 0
        || authority.owner_authority_revision == 0
        || authority.caller_fence == 0
    {
        return Err(FetchLeaseError::ResultMismatch);
    }
    let mut output = writer(limits)?;
    write_text(&mut output, &authority.owner_service_instance_id, limits)?;
    write_text(&mut output, &authority.authenticated_principal_id, limits)?;
    write_scope(&mut output, &authority.authenticated_scope, limits)
}

fn exact_lease_authority(
    lease: &ObjectStoreFetchLease,
    authority: &ObjectStoreFetchResolvedCallerAuthority,
) -> Result<(), FetchLeaseError> {
    if lease.result_key != authority.result_key
        || lease.owner_service_instance_id != authority.owner_service_instance_id
        || lease.owner_generation != authority.owner_generation
        || lease.owner_authority_revision != authority.owner_authority_revision
        || lease.authenticated_principal_id != authority.authenticated_principal_id
        || lease.authenticated_scope != authority.authenticated_scope
        || lease.canonical_descriptor_fingerprint != authority.canonical_descriptor_fingerprint
        || lease.caller_fence != authority.caller_fence
    {
        return Err(FetchLeaseError::ResultMismatch);
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
pub enum OpenObjectStoreFetchLeaseDecision {
    Replay {
        lease: CanonicalObjectStoreFetchLease,
    },
    Apply {
        expected_head_blake3: [u8; 32],
        expected_head_revision: u64,
        expected_open_lease_count: u64,
        next_head: CanonicalObjectStoreFetchHead,
        lease: Box<CanonicalObjectStoreFetchLease>,
    },
}

impl fmt::Debug for OpenObjectStoreFetchLeaseDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Replay { .. } => "Replay",
            Self::Apply { .. } => "Apply",
        };
        formatter
            .debug_struct(name)
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

pub fn decide_open_object_store_fetch_lease(
    input: &OpenObjectStoreFetchLeaseInput<'_>,
    state_limits: &RequestStateWireLimits,
    limits: &FetchLeaseLimits,
) -> Result<OpenObjectStoreFetchLeaseDecision, FetchLeaseError> {
    let key = object_store_fetch_result_key_from_state(input.current_state, state_limits)?;
    let head = checked_head(input.current_head, limits)?;
    if head.value().result_key != key {
        return Err(FetchLeaseError::ResultMismatch);
    }
    let descriptor: [u8; 32] = input
        .current_state
        .value()
        .canonical_descriptor_fingerprint
        .as_deref()
        .ok_or(FetchLeaseError::NotFetchable)?
        .try_into()
        .map_err(|_| FetchLeaseError::NotFetchable)?;
    validate_resolved_authority(input.authority, &key, descriptor, limits)?;
    if let Some(existing) = input.existing_lease {
        let existing = checked_lease(existing, limits)?;
        if existing.value().lease_id != input.lease_id {
            return Err(FetchLeaseError::LeaseIdReuse);
        }
        if existing.value().result_key != key
            || existing.value().admitted_generation > head.value().fence_generation
            || (existing.value().state == ObjectStoreFetchLeaseState::Open
                && head.value().open_lease_count == 0)
            || existing.value().open_fingerprint
                != open_fingerprint(
                    &key,
                    input.lease_id,
                    input.authority,
                    existing.value().admitted_generation,
                    limits,
                )?
        {
            return Err(FetchLeaseError::LeaseIdReuse);
        }
        return Ok(OpenObjectStoreFetchLeaseDecision::Replay { lease: existing });
    }
    if head.value().state != ObjectStoreFetchHeadState::Unfenced {
        return Err(FetchLeaseError::FetchesFenced);
    }
    if input.database_now_unix_ms < input.current_state.value().state_committed_at_unix_ms
        || input.database_now_unix_ms < head.value().head_committed_at_unix_ms
    {
        return Err(FetchLeaseError::InvalidTime);
    }
    let fingerprint = open_fingerprint(
        &key,
        input.lease_id,
        input.authority,
        head.value().fence_generation,
        limits,
    )?;
    let candidate = validate_and_encode_object_store_fetch_lease(
        &ObjectStoreFetchLease {
            result_key: key,
            lease_id: input.lease_id.to_owned(),
            owner_service_instance_id: input.authority.owner_service_instance_id.clone(),
            owner_generation: input.authority.owner_generation,
            owner_authority_revision: input.authority.owner_authority_revision,
            authenticated_principal_id: input.authority.authenticated_principal_id.clone(),
            authenticated_scope: input.authority.authenticated_scope.clone(),
            canonical_descriptor_fingerprint: input.authority.canonical_descriptor_fingerprint,
            caller_fence: input.authority.caller_fence,
            admitted_generation: head.value().fence_generation,
            open_fingerprint: fingerprint,
            next_chunk_index: 0,
            lease_revision: 1,
            opened_at_unix_ms: input.database_now_unix_ms,
            state: ObjectStoreFetchLeaseState::Open,
            terminal_reason: None,
            terminal_at_unix_ms: None,
            terminal_fingerprint: None,
            owner_revocation: None,
        },
        limits,
    )?;
    let mut next = head.value().clone();
    next.open_lease_count = next
        .open_lease_count
        .checked_add(1)
        .ok_or(FetchLeaseError::CountOverflow)?;
    next.head_revision = next
        .head_revision
        .checked_add(1)
        .ok_or(FetchLeaseError::GenerationOverflow)?;
    next.head_committed_at_unix_ms = input.database_now_unix_ms;
    let next_head = validate_and_encode_object_store_fetch_head(&next, limits)?;
    Ok(OpenObjectStoreFetchLeaseDecision::Apply {
        expected_head_blake3: *head.head_blake3(),
        expected_head_revision: head.value().head_revision,
        expected_open_lease_count: head.value().open_lease_count,
        next_head,
        lease: Box::new(candidate),
    })
}

#[derive(Clone, PartialEq, Eq)]
pub enum ObjectStoreFetchChunkPermit {
    Grant {
        expected_head_blake3: [u8; 32],
        expected_lease_blake3: [u8; 32],
        next_lease: CanonicalObjectStoreFetchLease,
    },
    Replay {
        expected_head_blake3: [u8; 32],
        expected_lease_blake3: [u8; 32],
        lease: CanonicalObjectStoreFetchLease,
    },
    FetchesFenced,
    LeaseTerminal,
    ChunkIndexGap,
}

impl fmt::Debug for ObjectStoreFetchChunkPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStoreFetchChunkPermit")
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

pub fn decide_object_store_fetch_chunk(
    current_head: &CanonicalObjectStoreFetchHead,
    lease: &CanonicalObjectStoreFetchLease,
    authority: &ObjectStoreFetchResolvedCallerAuthority,
    chunk_index: u64,
    limits: &FetchLeaseLimits,
) -> Result<ObjectStoreFetchChunkPermit, FetchLeaseError> {
    let head = checked_head(current_head, limits)?;
    let lease = checked_lease(lease, limits)?;
    if head.value().result_key != lease.value().result_key {
        return Err(FetchLeaseError::ResultMismatch);
    }
    validate_resolved_authority(
        authority,
        &head.value().result_key,
        lease.value().canonical_descriptor_fingerprint,
        limits,
    )?;
    exact_lease_authority(lease.value(), authority)?;
    if lease.value().state != ObjectStoreFetchLeaseState::Open {
        return Ok(ObjectStoreFetchChunkPermit::LeaseTerminal);
    }
    if head.value().state != ObjectStoreFetchHeadState::Unfenced
        || head.value().fence_generation != lease.value().admitted_generation
    {
        return Ok(ObjectStoreFetchChunkPermit::FetchesFenced);
    }
    if chunk_index > lease.value().next_chunk_index {
        return Ok(ObjectStoreFetchChunkPermit::ChunkIndexGap);
    }
    if chunk_index < lease.value().next_chunk_index {
        return Ok(ObjectStoreFetchChunkPermit::Replay {
            expected_head_blake3: *head.head_blake3(),
            expected_lease_blake3: *lease.lease_blake3(),
            lease,
        });
    }
    let mut next = lease.value().clone();
    next.next_chunk_index = next
        .next_chunk_index
        .checked_add(1)
        .ok_or(FetchLeaseError::GenerationOverflow)?;
    next.lease_revision = next
        .lease_revision
        .checked_add(1)
        .ok_or(FetchLeaseError::GenerationOverflow)?;
    Ok(ObjectStoreFetchChunkPermit::Grant {
        expected_head_blake3: *head.head_blake3(),
        expected_lease_blake3: *lease.lease_blake3(),
        next_lease: validate_and_encode_object_store_fetch_lease(&next, limits)?,
    })
}

fn terminal_fingerprint(
    lease: &CanonicalObjectStoreFetchLease,
    target_state: ObjectStoreFetchLeaseState,
    reason: ObjectStoreFetchLeaseTerminalReason,
    authority: Option<&ObjectStoreFetchResolvedCallerAuthority>,
    evidence: Option<&ObjectStoreFetchOwnerRevocationEvidence>,
    limits: &FetchLeaseLimits,
) -> Result<[u8; 32], FetchLeaseError> {
    let evidence = evidence
        .map(|value| complete_owner_revocation(value, limits))
        .transpose()?;
    let mut output = writer(limits)?;
    output
        .raw(TERMINAL_FINGERPRINT_DOMAIN)
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    let lease_id = decode_canonical_uuid_v7(&lease.value().lease_id)
        .map_err(|_| FetchLeaseError::InvalidIdentity)?;
    output
        .raw(&lease_id)
        .and_then(|_| output.raw(&lease.value().open_fingerprint))
        .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    if let Some(evidence) = evidence.as_deref() {
        output
            .u32(3)
            .and_then(|_| output.bytes(evidence))
            .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    } else {
        let authority = authority.ok_or(FetchLeaseError::InvalidLeaseState)?;
        let owner = authority.owner_service_instance_id.as_str();
        let generation = authority.owner_generation;
        if generation == 0 {
            return Err(FetchLeaseError::InvalidLeaseState);
        }
        let tag = if target_state == ObjectStoreFetchLeaseState::Closed {
            1
        } else {
            2
        };
        output
            .u32(tag)
            .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
        if tag == 2 {
            output
                .u32(reason as u32)
                .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
        }
        write_text(&mut output, owner, limits)?;
        output
            .u64(generation)
            .map_err(|_| FetchLeaseError::CanonicalTooLarge)?;
    }
    Ok(*blake3::hash(&output.finish()).as_bytes())
}

pub fn fingerprint_object_store_fetch_lease_close(
    lease: &CanonicalObjectStoreFetchLease,
    authority: &ObjectStoreFetchResolvedCallerAuthority,
    limits: &FetchLeaseLimits,
) -> Result<[u8; 32], FetchLeaseError> {
    terminal_fingerprint(
        lease,
        ObjectStoreFetchLeaseState::Closed,
        ObjectStoreFetchLeaseTerminalReason::Completed,
        Some(authority),
        None,
        limits,
    )
}

pub fn fingerprint_object_store_fetch_lease_cancel(
    lease: &CanonicalObjectStoreFetchLease,
    reason: ObjectStoreFetchLeaseTerminalReason,
    authority: Option<&ObjectStoreFetchResolvedCallerAuthority>,
    evidence: Option<&CanonicalObjectStoreFetchOwnerRevocationEvidence>,
    limits: &FetchLeaseLimits,
) -> Result<[u8; 32], FetchLeaseError> {
    if reason == ObjectStoreFetchLeaseTerminalReason::Completed
        || (reason == ObjectStoreFetchLeaseTerminalReason::OwnerRevoked) != evidence.is_some()
    {
        return Err(FetchLeaseError::InvalidLeaseState);
    }
    let evidence = evidence
        .map(|value| checked_owner_revocation(value, limits))
        .transpose()?;
    terminal_fingerprint(
        lease,
        ObjectStoreFetchLeaseState::Cancelled,
        reason,
        authority,
        evidence.as_ref().map(|value| value.value()),
        limits,
    )
}

pub struct TerminalObjectStoreFetchLeaseInput<'a> {
    pub current_head: &'a CanonicalObjectStoreFetchHead,
    pub current_lease: &'a CanonicalObjectStoreFetchLease,
    pub authority: Option<&'a ObjectStoreFetchResolvedCallerAuthority>,
    pub database_now_unix_ms: i64,
}

#[derive(Clone, PartialEq, Eq)]
pub enum TerminalObjectStoreFetchLeaseDecision {
    Replay {
        lease: CanonicalObjectStoreFetchLease,
    },
    Apply {
        expected_head_blake3: [u8; 32],
        expected_head_revision: u64,
        expected_open_lease_count: u64,
        expected_lease_blake3: [u8; 32],
        next_head: CanonicalObjectStoreFetchHead,
        next_lease: Box<CanonicalObjectStoreFetchLease>,
    },
}

impl fmt::Debug for TerminalObjectStoreFetchLeaseDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Replay { .. } => "Replay",
            Self::Apply { .. } => "Apply",
        };
        formatter
            .debug_struct(name)
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

fn decide_terminal(
    input: &TerminalObjectStoreFetchLeaseInput<'_>,
    target_state: ObjectStoreFetchLeaseState,
    reason: ObjectStoreFetchLeaseTerminalReason,
    evidence: Option<CanonicalObjectStoreFetchOwnerRevocationEvidence>,
    limits: &FetchLeaseLimits,
) -> Result<TerminalObjectStoreFetchLeaseDecision, FetchLeaseError> {
    let lease = checked_lease(input.current_lease, limits)?;
    let head = checked_head(input.current_head, limits)?;
    if head.value().result_key != lease.value().result_key {
        return Err(FetchLeaseError::ResultMismatch);
    }
    if input.authority.is_none() && evidence.is_none() {
        return Err(FetchLeaseError::TerminalConflict);
    }
    if let Some(authority) = input.authority {
        validate_resolved_authority(
            authority,
            &head.value().result_key,
            lease.value().canonical_descriptor_fingerprint,
            limits,
        )?;
        exact_lease_authority(lease.value(), authority)?;
    }
    let expected = terminal_fingerprint(
        &lease,
        target_state,
        reason,
        input.authority,
        evidence.as_ref().map(|value| value.value()),
        limits,
    )?;
    if lease.value().state != ObjectStoreFetchLeaseState::Open {
        if lease.value().terminal_fingerprint == Some(expected) {
            return Ok(TerminalObjectStoreFetchLeaseDecision::Replay { lease });
        }
        return Err(FetchLeaseError::TerminalConflict);
    }
    if input.authority.is_none() {
        let evidence = evidence
            .as_ref()
            .ok_or(FetchLeaseError::InvalidOwnerRevocation)?;
        let value = evidence.value();
        if !matches!(
            head.value().state,
            ObjectStoreFetchHeadState::DiscardReserved
                | ObjectStoreFetchHeadState::PayloadPurgeReserved
        ) || lease.value().admitted_generation >= head.value().fence_generation
            || value.owner_service_instance_id != lease.value().owner_service_instance_id
            || value.revoked_owner_generation != lease.value().owner_generation
            || value.successor_owner_generation <= lease.value().owner_generation
            || value.revocation_revision <= lease.value().owner_authority_revision
            || value.revocation_fence <= lease.value().caller_fence
            || value.revoked_at_unix_ms < lease.value().opened_at_unix_ms
            || value.revoked_at_unix_ms > input.database_now_unix_ms
        {
            return Err(FetchLeaseError::InvalidOwnerRevocation);
        }
    }
    if (reason == ObjectStoreFetchLeaseTerminalReason::DiscardFenced
        && (head.value().state != ObjectStoreFetchHeadState::DiscardReserved
            || lease.value().admitted_generation >= head.value().fence_generation))
        || (reason == ObjectStoreFetchLeaseTerminalReason::PayloadPurgeFenced
            && (head.value().state != ObjectStoreFetchHeadState::PayloadPurgeReserved
                || lease.value().admitted_generation >= head.value().fence_generation))
    {
        return Err(FetchLeaseError::FetchesFenced);
    }
    if head.value().open_lease_count == 0 {
        return Err(FetchLeaseError::CountOverflow);
    }
    if input.database_now_unix_ms < lease.value().opened_at_unix_ms
        || input.database_now_unix_ms < head.value().head_committed_at_unix_ms
        || evidence
            .as_ref()
            .is_some_and(|value| input.database_now_unix_ms < value.value().revoked_at_unix_ms)
    {
        return Err(FetchLeaseError::InvalidTime);
    }
    let mut next_head_value = head.value().clone();
    next_head_value.open_lease_count -= 1;
    next_head_value.head_revision = next_head_value
        .head_revision
        .checked_add(1)
        .ok_or(FetchLeaseError::GenerationOverflow)?;
    next_head_value.head_committed_at_unix_ms = input.database_now_unix_ms;
    let mut next_lease_value = lease.value().clone();
    next_lease_value.state = target_state;
    next_lease_value.terminal_reason = Some(reason);
    next_lease_value.terminal_at_unix_ms = Some(input.database_now_unix_ms);
    next_lease_value.terminal_fingerprint = Some(expected);
    next_lease_value.owner_revocation = evidence.map(|value| value.value().clone());
    next_lease_value.lease_revision = next_lease_value
        .lease_revision
        .checked_add(1)
        .ok_or(FetchLeaseError::GenerationOverflow)?;
    Ok(TerminalObjectStoreFetchLeaseDecision::Apply {
        expected_head_blake3: *head.head_blake3(),
        expected_head_revision: head.value().head_revision,
        expected_open_lease_count: head.value().open_lease_count,
        expected_lease_blake3: *lease.lease_blake3(),
        next_head: validate_and_encode_object_store_fetch_head(&next_head_value, limits)?,
        next_lease: Box::new(validate_and_encode_object_store_fetch_lease(
            &next_lease_value,
            limits,
        )?),
    })
}

pub fn decide_close_object_store_fetch_lease(
    input: &TerminalObjectStoreFetchLeaseInput<'_>,
    limits: &FetchLeaseLimits,
) -> Result<TerminalObjectStoreFetchLeaseDecision, FetchLeaseError> {
    if input.authority.is_none() {
        return Err(FetchLeaseError::TerminalConflict);
    }
    decide_terminal(
        input,
        ObjectStoreFetchLeaseState::Closed,
        ObjectStoreFetchLeaseTerminalReason::Completed,
        None,
        limits,
    )
}

pub fn decide_cancel_object_store_fetch_lease(
    input: &TerminalObjectStoreFetchLeaseInput<'_>,
    reason: ObjectStoreFetchLeaseTerminalReason,
    limits: &FetchLeaseLimits,
) -> Result<TerminalObjectStoreFetchLeaseDecision, FetchLeaseError> {
    if input.authority.is_none()
        || matches!(
            reason,
            ObjectStoreFetchLeaseTerminalReason::Completed
                | ObjectStoreFetchLeaseTerminalReason::OwnerRevoked
        )
    {
        return Err(FetchLeaseError::InvalidLeaseState);
    }
    decide_terminal(
        input,
        ObjectStoreFetchLeaseState::Cancelled,
        reason,
        None,
        limits,
    )
}

pub fn decide_cancel_orphaned_object_store_fetch_lease(
    input: &TerminalObjectStoreFetchLeaseInput<'_>,
    evidence: &CanonicalObjectStoreFetchOwnerRevocationEvidence,
    limits: &FetchLeaseLimits,
) -> Result<TerminalObjectStoreFetchLeaseDecision, FetchLeaseError> {
    if input.authority.is_some() {
        return Err(FetchLeaseError::InvalidOwnerRevocation);
    }
    let evidence = checked_owner_revocation(evidence, limits)?;
    decide_terminal(
        input,
        ObjectStoreFetchLeaseState::Cancelled,
        ObjectStoreFetchLeaseTerminalReason::OwnerRevoked,
        Some(evidence),
        limits,
    )
}

pub struct ReserveObjectStoreFetchDiscardInput<'a> {
    pub current_head: &'a CanonicalObjectStoreFetchHead,
    pub discard_fingerprint: [u8; 32],
    pub canonical_discard_bytes: &'a [u8],
    pub expected_request_state_blake3: [u8; 32],
    pub database_now_unix_ms: i64,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ReserveObjectStoreFetchDiscardDecision {
    Replay {
        head: CanonicalObjectStoreFetchHead,
    },
    Apply {
        expected_head_blake3: [u8; 32],
        expected_head_revision: u64,
        expected_fence_generation: u64,
        next_head: CanonicalObjectStoreFetchHead,
    },
}

impl fmt::Debug for ReserveObjectStoreFetchDiscardDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Replay { .. } => "Replay",
            Self::Apply { .. } => "Apply",
        };
        formatter
            .debug_struct(name)
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

pub fn decide_reserve_object_store_fetch_discard(
    input: &ReserveObjectStoreFetchDiscardInput<'_>,
    limits: &FetchLeaseLimits,
) -> Result<ReserveObjectStoreFetchDiscardDecision, FetchLeaseError> {
    let head = checked_head(input.current_head, limits)?;
    if head.value().state != ObjectStoreFetchHeadState::Unfenced {
        let existing = head
            .value()
            .pending_discard
            .as_ref()
            .ok_or(FetchLeaseError::InvalidHeadState)?;
        if existing.discard_fingerprint == input.discard_fingerprint
            && existing.canonical_discard_bytes == input.canonical_discard_bytes
            && existing.expected_request_state_blake3 == input.expected_request_state_blake3
        {
            return Ok(ReserveObjectStoreFetchDiscardDecision::Replay { head });
        }
        return Err(FetchLeaseError::DiscardReservationConflict);
    }
    if head.value().state != ObjectStoreFetchHeadState::Unfenced {
        return Err(FetchLeaseError::DiscardReservationConflict);
    }
    let pending = ObjectStorePendingFetchDiscard {
        discard_fingerprint: input.discard_fingerprint,
        canonical_discard_bytes: input.canonical_discard_bytes.to_vec(),
        expected_request_state_blake3: input.expected_request_state_blake3,
        reserved_at_unix_ms: input.database_now_unix_ms,
    };
    // First-seen reservations validate the complete discard artifact and database time.
    complete_pending_discard(&pending, limits)?;
    if input.database_now_unix_ms < head.value().head_committed_at_unix_ms {
        return Err(FetchLeaseError::InvalidTime);
    }
    let next_generation = head
        .value()
        .fence_generation
        .checked_add(1)
        .ok_or(FetchLeaseError::GenerationOverflow)?;
    let mut next = head.value().clone();
    next.state = ObjectStoreFetchHeadState::DiscardReserved;
    next.fence_generation = next_generation;
    next.head_revision = next
        .head_revision
        .checked_add(1)
        .ok_or(FetchLeaseError::GenerationOverflow)?;
    next.pending_discard = Some(pending);
    next.head_committed_at_unix_ms = input.database_now_unix_ms;
    Ok(ReserveObjectStoreFetchDiscardDecision::Apply {
        expected_head_blake3: *head.head_blake3(),
        expected_head_revision: head.value().head_revision,
        expected_fence_generation: head.value().fence_generation,
        next_head: validate_and_encode_object_store_fetch_head(&next, limits)?,
    })
}

pub fn commit_object_store_fetch_discard(
    current_head: &CanonicalObjectStoreFetchHead,
    discard_fingerprint: [u8; 32],
    database_now_unix_ms: i64,
    limits: &FetchLeaseLimits,
) -> Result<CanonicalObjectStoreFetchHead, FetchLeaseError> {
    let head = checked_head(current_head, limits)?;
    if head.value().state == ObjectStoreFetchHeadState::DiscardCommitted {
        if head
            .value()
            .pending_discard
            .as_ref()
            .is_some_and(|value| value.discard_fingerprint == discard_fingerprint)
        {
            return Ok(head);
        }
        return Err(FetchLeaseError::DiscardReservationConflict);
    }
    if head.value().state != ObjectStoreFetchHeadState::DiscardReserved
        || head.value().open_lease_count != 0
        || head
            .value()
            .pending_discard
            .as_ref()
            .is_none_or(|value| value.discard_fingerprint != discard_fingerprint)
    {
        return Err(FetchLeaseError::InvalidHeadState);
    }
    if database_now_unix_ms < head.value().head_committed_at_unix_ms {
        return Err(FetchLeaseError::InvalidTime);
    }
    let mut next = head.value().clone();
    next.state = ObjectStoreFetchHeadState::DiscardCommitted;
    next.head_revision = next
        .head_revision
        .checked_add(1)
        .ok_or(FetchLeaseError::GenerationOverflow)?;
    next.head_committed_at_unix_ms = database_now_unix_ms;
    validate_and_encode_object_store_fetch_head(&next, limits)
}

#[derive(Clone, PartialEq, Eq)]
pub enum ObjectStoreFetchPayloadPurgeFenceDecision {
    Replay {
        head: CanonicalObjectStoreFetchHead,
    },
    DispositionFenceConflict,
    Apply {
        expected_head_blake3: [u8; 32],
        next_head: CanonicalObjectStoreFetchHead,
    },
}

impl fmt::Debug for ObjectStoreFetchPayloadPurgeFenceDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Replay { .. } => "Replay",
            Self::DispositionFenceConflict => "DispositionFenceConflict",
            Self::Apply { .. } => "Apply",
        };
        formatter
            .debug_struct(name)
            .field("authority", &"[REDACTED]")
            .finish()
    }
}

pub fn decide_object_store_fetch_payload_purge_fence(
    current_head: &CanonicalObjectStoreFetchHead,
    database_now_unix_ms: i64,
    limits: &FetchLeaseLimits,
) -> Result<ObjectStoreFetchPayloadPurgeFenceDecision, FetchLeaseError> {
    let head = checked_head(current_head, limits)?;
    if matches!(
        head.value().state,
        ObjectStoreFetchHeadState::PayloadPurgeReserved
            | ObjectStoreFetchHeadState::PayloadPurgeCommitted
    ) {
        return Ok(ObjectStoreFetchPayloadPurgeFenceDecision::Replay { head });
    }
    if head.value().state != ObjectStoreFetchHeadState::Unfenced {
        return Ok(ObjectStoreFetchPayloadPurgeFenceDecision::DispositionFenceConflict);
    }
    if database_now_unix_ms < head.value().head_committed_at_unix_ms {
        return Err(FetchLeaseError::InvalidTime);
    }
    let mut next = head.value().clone();
    next.fence_generation = next
        .fence_generation
        .checked_add(1)
        .ok_or(FetchLeaseError::GenerationOverflow)?;
    next.state = ObjectStoreFetchHeadState::PayloadPurgeReserved;
    next.head_revision = next
        .head_revision
        .checked_add(1)
        .ok_or(FetchLeaseError::GenerationOverflow)?;
    next.head_committed_at_unix_ms = database_now_unix_ms;
    Ok(ObjectStoreFetchPayloadPurgeFenceDecision::Apply {
        expected_head_blake3: *head.head_blake3(),
        next_head: validate_and_encode_object_store_fetch_head(&next, limits)?,
    })
}

pub fn commit_object_store_fetch_payload_purge(
    current_head: &CanonicalObjectStoreFetchHead,
    database_now_unix_ms: i64,
    limits: &FetchLeaseLimits,
) -> Result<CanonicalObjectStoreFetchHead, FetchLeaseError> {
    let head = checked_head(current_head, limits)?;
    if head.value().state == ObjectStoreFetchHeadState::PayloadPurgeCommitted {
        return Ok(head);
    }
    if head.value().state != ObjectStoreFetchHeadState::PayloadPurgeReserved
        || head.value().open_lease_count != 0
    {
        return Err(FetchLeaseError::InvalidHeadState);
    }
    if database_now_unix_ms < head.value().head_committed_at_unix_ms {
        return Err(FetchLeaseError::InvalidTime);
    }
    let mut next = head.value().clone();
    next.state = ObjectStoreFetchHeadState::PayloadPurgeCommitted;
    next.head_revision = next
        .head_revision
        .checked_add(1)
        .ok_or(FetchLeaseError::GenerationOverflow)?;
    next.head_committed_at_unix_ms = database_now_unix_ms;
    validate_and_encode_object_store_fetch_head(&next, limits)
}
