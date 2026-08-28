// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure canonical encoding for the persisted `ReservePutAckV1` authority record.
//!
//! This module is source-dark. It performs no provider, database, clock, filesystem, or runtime
//! I/O. Empty digest fields are normalized to their canonical BLAKE3 values so callers can persist
//! and replay one byte-identical ACK.

use std::fmt;

use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadPurgeReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::PutReservationClosureV1;
use lore_proto::lore::object_dispatch::v1::PutSpoolReadyV1;
use lore_proto::lore::object_dispatch::v1::ReservePutAckV1;
use thiserror::Error;

use crate::contract::BoundedCanonicalWriter;
use crate::contract::canonical_uuid_v7_timestamp;
use crate::contract::validate_canonical_text;
use crate::request_state_wire::RequestStateWireLimits;
use crate::request_state_wire::ack_child;
use crate::request_state_wire::discard_child;
use crate::request_state_wire::no_dispatch_child;
use crate::request_state_wire::purge_child;

const ACK_DOMAIN: &[u8] = b"object-store-reserve-put-ack-v1\0";
const QUOTA_DOMAIN: &[u8] = b"object-store-quota-units-v1\0";
const SPOOL_DOMAIN: &[u8] = b"object-store-put-spool-ready-v1\0";
const CLOSURE_DOMAIN: &[u8] = b"object-store-put-reservation-closure-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservePutAckLimits {
    pub max_identity_bytes: u32,
    pub max_durable_handle_bytes: u32,
    pub max_canonical_row_bytes: u32,
}

#[derive(Clone, PartialEq)]
pub struct CanonicalObjectStoreReservePutAck {
    value: ReservePutAckV1,
    canonical_preimage: Vec<u8>,
    canonical_bytes: Vec<u8>,
    ack_blake3: [u8; 32],
}

impl CanonicalObjectStoreReservePutAck {
    pub fn value(&self) -> &ReservePutAckV1 {
        &self.value
    }

    pub fn canonical_preimage(&self) -> &[u8] {
        &self.canonical_preimage
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn ack_blake3(&self) -> &[u8; 32] {
        &self.ack_blake3
    }
}

impl fmt::Debug for CanonicalObjectStoreReservePutAck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalObjectStoreReservePutAck")
            .field("value", &"[REDACTED]")
            .field("canonical_preimage", &"[REDACTED]")
            .field("canonical_bytes", &"[REDACTED]")
            .field("ack_blake3", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ReservePutAckError {
    #[error("ReservePut ACK limits must be positive")]
    InvalidLimits,
    #[error("ReservePut ACK text is not canonical or bounded")]
    InvalidCanonicalText,
    #[error("ReservePut ACK identifier is not canonical UUIDv7")]
    InvalidUuidV7,
    #[error("ReservePut ACK time must be nonnegative")]
    NegativeTime,
    #[error("ReservePut ACK authority value must be positive")]
    NonPositiveAuthority,
    #[error("ReservePut ACK digest has invalid width")]
    InvalidDigest,
    #[error("ReservePut ACK digest does not match canonical fields")]
    DigestMismatch,
    #[error("ReservePut ACK state and evidence are inconsistent")]
    InvalidStateEvidence,
    #[error("ReservePut ACK nested evidence is invalid")]
    InvalidNestedEvidence,
    #[error("ReservePut ACK nested identity does not select the parent authority")]
    InvalidIdentityProjection,
    #[error("ReservePut ACK quota is empty or inconsistent with its release")]
    InvalidQuota,
    #[error("ReservePut ACK time projection is invalid")]
    InvalidTimeProjection,
    #[error("ReservePut ACK canonical bytes exceed the configured limit")]
    CanonicalTooLarge,
}

fn validate_limits(limits: &ReservePutAckLimits) -> Result<(), ReservePutAckError> {
    if limits.max_identity_bytes == 0
        || limits.max_durable_handle_bytes == 0
        || limits.max_canonical_row_bytes == 0
    {
        return Err(ReservePutAckError::InvalidLimits);
    }
    Ok(())
}

fn wire_limits(limits: &ReservePutAckLimits) -> RequestStateWireLimits {
    RequestStateWireLimits {
        max_identity_bytes: limits.max_identity_bytes,
        max_canonical_row_bytes: limits.max_canonical_row_bytes,
    }
}

fn writer(limits: &ReservePutAckLimits) -> Result<BoundedCanonicalWriter, ReservePutAckError> {
    BoundedCanonicalWriter::new(limits.max_canonical_row_bytes)
        .map_err(|_| ReservePutAckError::InvalidLimits)
}

fn text(value: &str, maximum: u32) -> Result<(), ReservePutAckError> {
    validate_canonical_text(value, maximum).map_err(|_| ReservePutAckError::InvalidCanonicalText)
}

fn nonnegative(value: i64) -> Result<u64, ReservePutAckError> {
    u64::try_from(value).map_err(|_| ReservePutAckError::NegativeTime)
}

fn positive(value: u64) -> Result<u64, ReservePutAckError> {
    if value == 0 {
        Err(ReservePutAckError::NonPositiveAuthority)
    } else {
        Ok(value)
    }
}

fn digest(value: &[u8]) -> Result<[u8; 32], ReservePutAckError> {
    value
        .try_into()
        .map_err(|_| ReservePutAckError::InvalidDigest)
}

fn finish(
    preimage: &[u8],
    supplied: &[u8],
    limits: &ReservePutAckLimits,
) -> Result<(Vec<u8>, [u8; 32]), ReservePutAckError> {
    let result = *blake3::hash(preimage).as_bytes();
    if !supplied.is_empty() && supplied.len() != 32 {
        return Err(ReservePutAckError::InvalidDigest);
    }
    if !supplied.is_empty() && supplied != result {
        return Err(ReservePutAckError::DigestMismatch);
    }
    let size = preimage
        .len()
        .checked_add(32)
        .ok_or(ReservePutAckError::CanonicalTooLarge)?;
    if size > limits.max_canonical_row_bytes as usize {
        return Err(ReservePutAckError::CanonicalTooLarge);
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(preimage);
    bytes.extend_from_slice(&result);
    Ok((bytes, result))
}

fn complete_child(
    preimage: &[u8],
    limits: &ReservePutAckLimits,
) -> Result<Vec<u8>, ReservePutAckError> {
    finish(preimage, &[], limits).map(|value| value.0)
}

fn write_framed(
    output: &mut BoundedCanonicalWriter,
    bytes: &[u8],
) -> Result<(), ReservePutAckError> {
    output
        .bytes(bytes)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)
}

fn write_optional_framed(
    output: &mut BoundedCanonicalWriter,
    bytes: Option<&[u8]>,
) -> Result<(), ReservePutAckError> {
    output
        .u8(u8::from(bytes.is_some()))
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    if let Some(bytes) = bytes {
        write_framed(output, bytes)?;
    }
    Ok(())
}

fn quota_child(
    value: &ObjectStoreQuotaUnitsV1,
    limits: &ReservePutAckLimits,
) -> Result<Vec<u8>, ReservePutAckError> {
    if value.bytes == 0 && value.rows == 0 && value.concurrency == 0 {
        return Err(ReservePutAckError::InvalidQuota);
    }
    let mut output = writer(limits)?;
    output
        .raw(QUOTA_DOMAIN)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    for value in [value.bytes, value.rows, value.concurrency] {
        output
            .u64(value)
            .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    }
    complete_child(&output.finish(), limits)
}

fn spool_child(
    parent: &ReservePutAckV1,
    value: &PutSpoolReadyV1,
    limits: &ReservePutAckLimits,
) -> Result<Vec<u8>, ReservePutAckError> {
    let projections = [
        (&parent.protocol_revision, &value.protocol_revision),
        (&parent.provider_boundary_id, &value.provider_boundary_id),
        (&parent.authenticated_cell_id, &value.authenticated_cell_id),
        (
            &parent.authenticated_tenant_id,
            &value.authenticated_tenant_id,
        ),
        (&parent.logical_request_id, &value.logical_request_id),
        (&parent.attempt_id, &value.attempt_id),
        (&parent.upload_id, &value.upload_id),
    ];
    if projections.iter().any(|(parent, child)| parent != child)
        || value.upload_fence != parent.upload_fence
    {
        return Err(ReservePutAckError::InvalidIdentityProjection);
    }
    if parent
        .reserved_quota
        .as_ref()
        .is_none_or(|quota| value.body_size != quota.bytes)
    {
        return Err(ReservePutAckError::InvalidQuota);
    }
    text(&value.durable_body_handle, limits.max_durable_handle_bytes)?;
    digest(&value.body_blake3)?;
    let ready_at = nonnegative(value.ready_at_unix_ms)?;
    let admission = nonnegative(parent.admission_clock_unix_ms)?;
    let expires = nonnegative(parent.expires_at_unix_ms)?;
    if ready_at < admission || ready_at >= expires {
        return Err(ReservePutAckError::InvalidTimeProjection);
    }

    let mut output = writer(limits)?;
    output
        .raw(SPOOL_DOMAIN)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    for identity in [
        &value.protocol_revision,
        &value.provider_boundary_id,
        &value.authenticated_cell_id,
        &value.authenticated_tenant_id,
        &value.logical_request_id,
        &value.attempt_id,
        &value.upload_id,
    ] {
        output
            .text(identity)
            .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    }
    output
        .u64(positive(value.upload_fence)?)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    output
        .text(&value.durable_body_handle)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    output
        .u64(value.body_size)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    output
        .raw(&digest(&value.body_blake3)?)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    output
        .u64(ready_at)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    complete_child(&output.finish(), limits)
}

fn normalize_child_digest(bytes: &[u8]) -> Result<Vec<u8>, ReservePutAckError> {
    if bytes.len() < 32 {
        return Err(ReservePutAckError::InvalidNestedEvidence);
    }
    Ok(bytes[bytes.len() - 32..].to_vec())
}

fn closure_child(
    value: &PutReservationClosureV1,
    admission_clock_unix_ms: i64,
    limits: &ReservePutAckLimits,
) -> Result<(Vec<u8>, PutReservationClosureV1), ReservePutAckError> {
    text(&value.terminal_result_id, limits.max_identity_bytes)?;
    if !(1..=3).contains(&value.terminal_retryability)
        || !(2..=4).contains(&value.result_disposition)
    {
        return Err(ReservePutAckError::InvalidNestedEvidence);
    }
    let wire_limits = wire_limits(limits);
    let ack = value
        .ack_receipt
        .as_ref()
        .map(|value| ack_child(value, &wire_limits))
        .transpose()
        .map_err(|_| ReservePutAckError::InvalidNestedEvidence)?;
    let discard = value
        .discard_receipt
        .as_ref()
        .map(|value| discard_child(value, &wire_limits))
        .transpose()
        .map_err(|_| ReservePutAckError::InvalidNestedEvidence)?;
    let receipt_time = match value.result_disposition {
        2 if ack.is_none() && discard.is_none() => None,
        3 if ack.is_some() && discard.is_none() => value
            .ack_receipt
            .as_ref()
            .map(|receipt| {
                if receipt.terminal_result_id != value.terminal_result_id {
                    return Err(ReservePutAckError::InvalidIdentityProjection);
                }
                nonnegative(receipt.acked_at_unix_ms)
            })
            .transpose()?,
        4 if ack.is_none() && discard.is_some() => value
            .discard_receipt
            .as_ref()
            .map(|receipt| {
                if receipt.terminal_result_id != value.terminal_result_id {
                    return Err(ReservePutAckError::InvalidIdentityProjection);
                }
                nonnegative(receipt.discarded_at_unix_ms)
            })
            .transpose()?,
        _ => return Err(ReservePutAckError::InvalidStateEvidence),
    };
    let closed_at = nonnegative(value.closed_at_unix_ms)?;
    if closed_at < nonnegative(admission_clock_unix_ms)?
        || receipt_time.is_some_and(|receipt_time| receipt_time < closed_at)
    {
        return Err(ReservePutAckError::InvalidTimeProjection);
    }

    let mut output = writer(limits)?;
    output
        .raw(CLOSURE_DOMAIN)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    output
        .text(&value.terminal_result_id)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    output
        .u32(value.terminal_retryability as u32)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    output
        .u32(value.result_disposition as u32)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    write_optional_framed(&mut output, ack.as_deref())?;
    write_optional_framed(&mut output, discard.as_deref())?;
    output
        .u64(closed_at)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    let (bytes, closure_blake3) =
        finish(&output.finish(), &value.closure_blake3, limits).map_err(|error| match error {
            ReservePutAckError::InvalidDigest | ReservePutAckError::DigestMismatch => {
                ReservePutAckError::InvalidNestedEvidence
            }
            error => error,
        })?;
    let mut normalized = value.clone();
    normalized.closure_blake3 = closure_blake3.to_vec().into();
    Ok((bytes, normalized))
}

fn validate_release(
    state: i32,
    quota: &ObjectStoreQuotaUnitsV1,
    closure: Option<&PutReservationClosureV1>,
    proof: Option<(i32, i64)>,
    release: &ObjectStorePayloadPurgeReceiptV1,
    admission_clock_unix_ms: i64,
) -> Result<(), ReservePutAckError> {
    if release.payload_kind != 1
        || release.released_bytes != quota.bytes
        || release.released_rows != quota.rows
        || release.released_concurrency != quota.concurrency
    {
        return Err(ReservePutAckError::InvalidQuota);
    }
    let purged_at = nonnegative(release.purged_at_unix_ms)?;
    if purged_at < nonnegative(admission_clock_unix_ms)? {
        return Err(ReservePutAckError::InvalidTimeProjection);
    }
    if let Some((_, committed_at)) = proof
        && purged_at < nonnegative(committed_at)?
    {
        return Err(ReservePutAckError::InvalidTimeProjection);
    }
    if let Some(closure) = closure {
        if purged_at < nonnegative(closure.closed_at_unix_ms)? {
            return Err(ReservePutAckError::InvalidTimeProjection);
        }
        let receipt_time = closure
            .ack_receipt
            .as_ref()
            .map(|receipt| receipt.acked_at_unix_ms)
            .or_else(|| {
                closure
                    .discard_receipt
                    .as_ref()
                    .map(|receipt| receipt.discarded_at_unix_ms)
            });
        if let Some(receipt_time) = receipt_time
            && purged_at < nonnegative(receipt_time)?
        {
            return Err(ReservePutAckError::InvalidTimeProjection);
        }
        let purge_after = closure
            .ack_receipt
            .as_ref()
            .and_then(|receipt| receipt.payload_purge_after_unix_ms)
            .or_else(|| {
                closure
                    .discard_receipt
                    .as_ref()
                    .and_then(|receipt| receipt.payload_purge_after_unix_ms)
            });
        if let Some(purge_after) = purge_after
            && purged_at < nonnegative(purge_after)?
        {
            return Err(ReservePutAckError::InvalidTimeProjection);
        }
    }
    match (state, closure, proof.map(|(reason, _)| reason)) {
        (3, None, Some(4))
            if release.terminal_result_id.is_none()
                && release.disposition == 1
                && matches!(release.release_reason, 3 | 4) =>
        {
            Ok(())
        }
        (5, Some(closure), None)
            if matches!(closure.result_disposition, 3 | 4)
                && release.terminal_result_id.as_deref()
                    == Some(closure.terminal_result_id.as_str())
                && release.disposition == closure.result_disposition
                && ((closure.result_disposition == 3 && release.release_reason == 1)
                    || (closure.result_disposition == 4 && release.release_reason == 2)) =>
        {
            Ok(())
        }
        (5, None, Some(reason))
            if reason != 4
                && release.terminal_result_id.is_none()
                && release.disposition == 1
                && matches!(release.release_reason, 3 | 5) =>
        {
            Ok(())
        }
        _ => Err(ReservePutAckError::InvalidStateEvidence),
    }
}

pub fn validate_and_encode_object_store_reserve_put_ack(
    value: &ReservePutAckV1,
    limits: &ReservePutAckLimits,
) -> Result<CanonicalObjectStoreReservePutAck, ReservePutAckError> {
    validate_limits(limits)?;
    for identity in [
        &value.protocol_revision,
        &value.policy_revision,
        &value.provider_boundary_id,
        &value.authenticated_cell_id,
        &value.authenticated_tenant_id,
        &value.logical_request_id,
        &value.attempt_id,
        &value.upload_id,
    ] {
        text(identity, limits.max_identity_bytes)?;
    }
    for identifier in [
        &value.logical_request_id,
        &value.attempt_id,
        &value.upload_id,
    ] {
        canonical_uuid_v7_timestamp(identifier).map_err(|_| ReservePutAckError::InvalidUuidV7)?;
    }
    positive(value.upload_fence)?;
    positive(value.max_chunk_bytes)?;
    let quota = value
        .reserved_quota
        .as_ref()
        .ok_or(ReservePutAckError::InvalidQuota)?;
    let quota_bytes = quota_child(quota, limits)?;
    let admission = nonnegative(value.admission_clock_unix_ms)?;
    let expires = nonnegative(value.expires_at_unix_ms)?;
    let allocation_expiry = nonnegative(value.allocation_hard_expiry_unix_ms)?;
    if admission >= expires || expires > allocation_expiry {
        return Err(ReservePutAckError::InvalidTimeProjection);
    }

    let spool = value
        .spool_ready
        .as_ref()
        .map(|spool| spool_child(value, spool, limits))
        .transpose()?;
    let closure = value
        .closure
        .as_ref()
        .map(|closure| closure_child(closure, value.admission_clock_unix_ms, limits))
        .transpose()?;
    let wire_limits = wire_limits(limits);
    let proof = value
        .no_dispatch_proof
        .as_ref()
        .map(|proof| no_dispatch_child(proof, &wire_limits))
        .transpose()
        .map_err(|_| ReservePutAckError::InvalidNestedEvidence)?;
    if let Some(proof) = value.no_dispatch_proof.as_ref() {
        let committed_at = nonnegative(proof.committed_at_unix_ms)?;
        if committed_at < admission || (proof.reason == 4 && committed_at < expires) {
            return Err(ReservePutAckError::InvalidTimeProjection);
        }
    }
    let release = value
        .payload_release_receipt
        .as_ref()
        .map(|release| purge_child(release, &wire_limits))
        .transpose()
        .map_err(|_| ReservePutAckError::InvalidNestedEvidence)?;

    let valid_state = match value.state {
        1 => spool.is_none() && closure.is_none() && proof.is_none() && release.is_none(),
        2 => spool.is_some() && closure.is_none() && proof.is_none() && release.is_none(),
        3 => {
            spool.is_none()
                && closure.is_none()
                && proof.is_some()
                && release.is_some()
                && value
                    .no_dispatch_proof
                    .as_ref()
                    .is_some_and(|proof| proof.reason == 4)
        }
        4 => spool.is_none() && closure.is_some() && proof.is_none() && release.is_none(),
        5 => spool.is_none() && release.is_some() && (closure.is_some() ^ proof.is_some()),
        _ => false,
    };
    if !valid_state {
        return Err(ReservePutAckError::InvalidStateEvidence);
    }
    if let Some((_, release)) = release.as_ref() {
        validate_release(
            value.state,
            quota,
            closure.as_ref().map(|value| &value.1),
            value
                .no_dispatch_proof
                .as_ref()
                .map(|proof| (proof.reason, proof.committed_at_unix_ms)),
            release,
            value.admission_clock_unix_ms,
        )?;
    }

    let mut normalized = value.clone();
    if let Some((_, closure)) = closure.as_ref() {
        normalized.closure = Some(closure.clone());
    }
    if let (Some(normalized_proof), Some(proof)) =
        (normalized.no_dispatch_proof.as_mut(), proof.as_ref())
    {
        normalized_proof.proof_blake3 = normalize_child_digest(proof)?.into();
    }
    if let Some((_, release)) = release.as_ref() {
        normalized.payload_release_receipt = Some(release.clone());
    }

    let mut output = writer(limits)?;
    output
        .raw(ACK_DOMAIN)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    for identity in [
        &normalized.protocol_revision,
        &normalized.policy_revision,
        &normalized.provider_boundary_id,
        &normalized.authenticated_cell_id,
        &normalized.authenticated_tenant_id,
        &normalized.logical_request_id,
        &normalized.attempt_id,
        &normalized.upload_id,
    ] {
        output
            .text(identity)
            .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    }
    output
        .u64(value.upload_fence)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    output
        .u32(value.state as u32)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    write_framed(&mut output, &quota_bytes)?;
    output
        .u64(expires)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    output
        .u64(value.max_chunk_bytes)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    write_optional_framed(&mut output, spool.as_deref())?;
    write_optional_framed(
        &mut output,
        release.as_ref().map(|(bytes, _)| bytes.as_slice()),
    )?;
    output
        .u64(admission)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    output
        .u64(allocation_expiry)
        .map_err(|_| ReservePutAckError::CanonicalTooLarge)?;
    write_optional_framed(
        &mut output,
        closure.as_ref().map(|(bytes, _)| bytes.as_slice()),
    )?;
    write_optional_framed(&mut output, proof.as_deref())?;
    let canonical_preimage = output.finish();
    let (canonical_bytes, ack_blake3) = finish(&canonical_preimage, &value.ack_blake3, limits)?;
    normalized.ack_blake3 = ack_blake3.to_vec().into();
    Ok(CanonicalObjectStoreReservePutAck {
        value: normalized,
        canonical_preimage,
        canonical_bytes,
        ack_blake3,
    })
}
