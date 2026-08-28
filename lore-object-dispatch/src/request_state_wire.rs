// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure canonical wire records for persisted object-store request state and its envelopes.
//!
//! This module is source-dark. It performs no provider, database, clock, or runtime I/O.

use std::collections::HashSet;
use std::fmt;

use lore_proto::lore::object_dispatch::v1::object_store_request_outcome_v1;
use lore_proto::lore::object_dispatch::v1::object_store_request_receipt_v1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1;
use lore_proto::lore::object_dispatch::v1::*;
use thiserror::Error;

use crate::contract::BoundedCanonicalWriter;
use crate::contract::canonical_uuid_v7_timestamp;
use crate::contract::validate_canonical_text;
use crate::terminal_result::TerminalResultLimits;
use crate::terminal_result::validate_and_encode_terminal_result;

const STATE_DOMAIN: &[u8] = b"object-store-request-state-v1\0";
const RECEIPT_DOMAIN: &[u8] = b"object-store-request-receipt-v1\0";
const OUTCOME_DOMAIN: &[u8] = b"object-store-request-outcome-v1\0";

/// The receipt envelope's `request_state` oneof tag, written into the canonical preimage.
const REQUEST_STATE_RECEIPT_TAG: u32 = 1;
/// The outcome envelope's `request_state` oneof tag, written into the canonical preimage.
const REQUEST_STATE_OUTCOME_TAG: u32 = 1;

/// Byte bounds for one canonical request-state wire record and the identities inside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestStateWireLimits {
    pub max_identity_bytes: u32,
    pub max_canonical_row_bytes: u32,
}

macro_rules! canonical_record {
    ($name:ident, $value:ty, $digest_method:ident) => {
        #[derive(Clone, PartialEq)]
        pub struct $name {
            value: $value,
            canonical_preimage: Vec<u8>,
            canonical_bytes: Vec<u8>,
            digest: [u8; 32],
        }

        impl $name {
            pub fn value(&self) -> &$value {
                &self.value
            }
            pub fn canonical_preimage(&self) -> &[u8] {
                &self.canonical_preimage
            }
            pub fn canonical_bytes(&self) -> &[u8] {
                &self.canonical_bytes
            }
            pub fn $digest_method(&self) -> &[u8; 32] {
                &self.digest
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("value", &"[REDACTED]")
                    .field("canonical_preimage", &"[REDACTED]")
                    .field("canonical_bytes", &"[REDACTED]")
                    .field("digest", &"[REDACTED]")
                    .finish()
            }
        }
    };
}

canonical_record!(
    CanonicalObjectStoreRequestState,
    ObjectStoreRequestStateV1,
    state_blake3
);
canonical_record!(
    CanonicalObjectStoreRequestReceipt,
    ObjectStoreRequestReceiptV1,
    receipt_blake3
);
canonical_record!(
    CanonicalObjectStoreRequestOutcome,
    ObjectStoreRequestOutcomeV1,
    outcome_blake3
);

fn validate_limits(limits: &RequestStateWireLimits) -> Result<(), RequestStateWireError> {
    if limits.max_identity_bytes == 0 || limits.max_canonical_row_bytes == 0 {
        return Err(RequestStateWireError::InvalidLimits);
    }
    Ok(())
}

fn writer(
    limits: &RequestStateWireLimits,
) -> Result<BoundedCanonicalWriter, RequestStateWireError> {
    BoundedCanonicalWriter::new(limits.max_canonical_row_bytes)
        .map_err(|_| RequestStateWireError::InvalidLimits)
}

fn text(value: &str, limits: &RequestStateWireLimits) -> Result<(), RequestStateWireError> {
    validate_canonical_text(value, limits.max_identity_bytes)
        .map_err(|_| RequestStateWireError::InvalidCanonicalText)
}

fn nonnegative(value: i64) -> Result<u64, RequestStateWireError> {
    u64::try_from(value).map_err(|_| RequestStateWireError::NegativeTime)
}

fn positive(value: u64) -> Result<u64, RequestStateWireError> {
    if value == 0 {
        Err(RequestStateWireError::NonPositiveAuthority)
    } else {
        Ok(value)
    }
}

fn digest(value: &[u8]) -> Result<[u8; 32], RequestStateWireError> {
    value
        .try_into()
        .map_err(|_| RequestStateWireError::InvalidDigest)
}

fn finish(
    preimage: &[u8],
    supplied: &[u8],
    limits: &RequestStateWireLimits,
) -> Result<(Vec<u8>, [u8; 32]), RequestStateWireError> {
    let result = *blake3::hash(preimage).as_bytes();
    if !supplied.is_empty() && supplied.len() != 32 {
        return Err(RequestStateWireError::InvalidDigest);
    }
    if !supplied.is_empty() && supplied != result {
        return Err(RequestStateWireError::DigestMismatch);
    }
    let size = preimage
        .len()
        .checked_add(32)
        .ok_or(RequestStateWireError::CanonicalTooLarge)?;
    if size > limits.max_canonical_row_bytes as usize {
        return Err(RequestStateWireError::CanonicalTooLarge);
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(preimage);
    bytes.extend_from_slice(&result);
    Ok((bytes, result))
}

fn complete_child(
    preimage: Vec<u8>,
    supplied: &[u8],
    limits: &RequestStateWireLimits,
) -> Result<Vec<u8>, RequestStateWireError> {
    finish(&preimage, supplied, limits).map(|value| value.0)
}

fn write_framed(
    output: &mut BoundedCanonicalWriter,
    bytes: &[u8],
) -> Result<(), RequestStateWireError> {
    output
        .bytes(bytes)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)
}

fn write_optional_framed(
    output: &mut BoundedCanonicalWriter,
    bytes: Option<&[u8]>,
) -> Result<(), RequestStateWireError> {
    output
        .u8(u8::from(bytes.is_some()))
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    if let Some(value) = bytes {
        write_framed(output, value)?;
    }
    Ok(())
}

fn write_optional_text(
    output: &mut BoundedCanonicalWriter,
    value: Option<&str>,
    limits: &RequestStateWireLimits,
) -> Result<(), RequestStateWireError> {
    output
        .u8(u8::from(value.is_some()))
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    if let Some(value) = value {
        text(value, limits)?;
        output
            .text(value)
            .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    }
    Ok(())
}

fn write_optional_u64(
    output: &mut BoundedCanonicalWriter,
    value: Option<u64>,
) -> Result<(), RequestStateWireError> {
    output
        .u8(u8::from(value.is_some()))
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    if let Some(value) = value {
        output
            .u64(value)
            .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    }
    Ok(())
}

fn quota_preimage(
    value: &ObjectStoreQuotaUnitsV1,
    limits: &RequestStateWireLimits,
) -> Result<Vec<u8>, RequestStateWireError> {
    let mut output = writer(limits)?;
    output
        .raw(b"object-store-quota-units-v1\0")
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    for value in [value.bytes, value.rows, value.concurrency] {
        output
            .u64(value)
            .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    }
    Ok(output.finish())
}

fn reservation_preimage(
    value: &ReservedDimensionV1,
    limits: &RequestStateWireLimits,
) -> Result<Vec<u8>, RequestStateWireError> {
    let mut output = writer(limits)?;
    output
        .raw(b"object-store-reserved-dimension-v1\0")
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    for value in [
        &value.reservation_id,
        &value.physical_dimension_id,
        &value.operation_class_id,
    ] {
        text(value, limits)?;
        output
            .text(value)
            .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    }
    output
        .u64(positive(value.units)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    Ok(output.finish())
}

fn reservations_bytes(
    values: &[ReservedDimensionV1],
    limits: &RequestStateWireLimits,
) -> Result<(Vec<u8>, Vec<ReservedDimensionV1>), RequestStateWireError> {
    let count =
        u32::try_from(values.len()).map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    let mut ids = HashSet::new();
    let mut pairs = HashSet::new();
    let mut canonical = Vec::with_capacity(values.len());
    for value in values {
        if !ids.insert(value.reservation_id.clone())
            || !pairs.insert((
                value.physical_dimension_id.clone(),
                value.operation_class_id.clone(),
            ))
        {
            return Err(RequestStateWireError::InvalidStateAlgebra);
        }
        reservation_preimage(value, limits)?;
        canonical.push(value.clone());
    }
    canonical.sort_by(|left, right| {
        left.physical_dimension_id
            .as_bytes()
            .cmp(right.physical_dimension_id.as_bytes())
            .then_with(|| {
                left.operation_class_id
                    .as_bytes()
                    .cmp(right.operation_class_id.as_bytes())
            })
            .then_with(|| {
                left.reservation_id
                    .as_bytes()
                    .cmp(right.reservation_id.as_bytes())
            })
    });
    let mut output = writer(limits)?;
    output
        .u32(count)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    for value in &canonical {
        let complete = complete_child(reservation_preimage(value, limits)?, &[], limits)?;
        write_framed(&mut output, &complete)?;
    }
    Ok((output.finish(), canonical))
}

fn dispatch_child(
    value: &ObjectStoreDispatchAttemptV1,
    limits: &RequestStateWireLimits,
) -> Result<Vec<u8>, RequestStateWireError> {
    if value
        .ambiguity_recorded_at_unix_ms
        .is_some_and(|time| time < value.dispatch_started_at_unix_ms)
    {
        return Err(RequestStateWireError::InvalidTimeOrder);
    }
    let mut output = writer(limits)?;
    output
        .raw(b"object-store-dispatch-attempt-v1\0")
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    for value in [&value.provider_attempt_id, &value.provider_grant_id] {
        text(value, limits)?;
        output
            .text(value)
            .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    }
    output
        .u64(positive(value.provider_grant_fence)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    text(&value.dispatcher_id, limits)?;
    output
        .text(&value.dispatcher_id)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(positive(value.dispatcher_lease_generation)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(nonnegative(value.dispatch_started_at_unix_ms)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_optional_u64(
        &mut output,
        value
            .ambiguity_recorded_at_unix_ms
            .map(nonnegative)
            .transpose()?,
    )?;
    text(&value.provider_credential_revision, limits)?;
    output
        .text(&value.provider_credential_revision)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    complete_child(output.finish(), &[], limits)
}

fn terminal_limits(limits: &RequestStateWireLimits) -> TerminalResultLimits {
    TerminalResultLimits {
        max_canonical_result_bytes: limits.max_canonical_row_bytes,
        max_list_entries: limits.max_canonical_row_bytes,
        max_key_bytes: limits.max_identity_bytes,
        max_metadata_entries: limits.max_canonical_row_bytes,
        max_metadata_key_bytes: limits.max_identity_bytes,
        max_metadata_value_bytes: limits.max_identity_bytes,
        max_metadata_aggregate_bytes: limits.max_canonical_row_bytes,
        max_opaque_value_bytes: limits.max_identity_bytes,
        max_result_handle_bytes: limits.max_identity_bytes,
        max_provider_code_bytes: limits.max_identity_bytes,
        max_provider_request_id_bytes: limits.max_identity_bytes,
        max_retry_after_ms: u64::MAX,
    }
}

fn terminal_child(
    value: &ObjectStoreTerminalResultV1,
    limits: &RequestStateWireLimits,
) -> Result<
    (
        Vec<u8>,
        ObjectStoreTerminalResultV1,
        Option<ByteResultHandleV1>,
    ),
    RequestStateWireError,
> {
    let canonical = validate_and_encode_terminal_result(value, &terminal_limits(limits))
        .map_err(|_| RequestStateWireError::InvalidTerminalResult)?;
    if value.canonical_result_size != canonical.canonical_result_size()
        || value.canonical_result_blake3.as_ref() != canonical.canonical_result_blake3()
    {
        return Err(RequestStateWireError::InvalidTerminalResult);
    }
    let selected = canonical
        .result()
        .result
        .as_ref()
        .ok_or(RequestStateWireError::MissingChild)?;
    let tag = match selected {
        object_store_terminal_result_v1::Result::BoolResult(_) => 1,
        object_store_terminal_result_v1::Result::HeadObject(_) => 2,
        object_store_terminal_result_v1::Result::PutObject(_) => 3,
        object_store_terminal_result_v1::Result::DeleteObject(_) => 4,
        object_store_terminal_result_v1::Result::ListObjectsV2(_) => 5,
        object_store_terminal_result_v1::Result::ListObjectVersions(_) => 6,
        object_store_terminal_result_v1::Result::ByteResult(_) => 7,
        object_store_terminal_result_v1::Result::ProviderError(_) => 8,
    };
    let mut output = writer(limits)?;
    output
        .raw(b"object-store-terminal-result-v1\0")
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u32(tag)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .bytes(canonical.canonical_result_bytes())
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    text(&value.terminal_result_id, limits)?;
    output
        .text(&value.terminal_result_id)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .raw(canonical.canonical_result_blake3())
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(canonical.canonical_result_size())
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    let complete = complete_child(output.finish(), &[], limits)?;
    let normalized = canonical.result().clone();
    let byte = match selected {
        object_store_terminal_result_v1::Result::ByteResult(value) => Some(value.clone()),
        _ => None,
    };
    Ok((complete, normalized, byte))
}

pub(crate) fn ack_child(
    value: &ObjectStoreResultAckReceiptV1,
    limits: &RequestStateWireLimits,
) -> Result<Vec<u8>, RequestStateWireError> {
    if value.state != 1
        || value
            .payload_purge_after_unix_ms
            .is_some_and(|time| time < value.acked_at_unix_ms)
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    let mut output = writer(limits)?;
    output
        .raw(b"object-store-result-ack-receipt-v1\0")
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u32(1)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    text(&value.terminal_result_id, limits)?;
    output
        .text(&value.terminal_result_id)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .raw(&digest(&value.ack_fingerprint)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(nonnegative(value.acked_at_unix_ms)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_optional_u64(
        &mut output,
        value
            .payload_purge_after_unix_ms
            .map(nonnegative)
            .transpose()?,
    )?;
    complete_child(output.finish(), &[], limits)
}

pub(crate) fn discard_child(
    value: &ObjectStoreResultDiscardReceiptV1,
    limits: &RequestStateWireLimits,
) -> Result<Vec<u8>, RequestStateWireError> {
    if value.state != 1
        || value
            .payload_purge_after_unix_ms
            .is_some_and(|time| time < value.discarded_at_unix_ms)
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    let mut output = writer(limits)?;
    output
        .raw(b"object-store-result-discard-receipt-v1\0")
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u32(1)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    text(&value.terminal_result_id, limits)?;
    output
        .text(&value.terminal_result_id)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .raw(&digest(&value.discard_fingerprint)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(nonnegative(value.discarded_at_unix_ms)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_optional_u64(
        &mut output,
        value
            .payload_purge_after_unix_ms
            .map(nonnegative)
            .transpose()?,
    )?;
    complete_child(output.finish(), &[], limits)
}

pub(crate) fn no_dispatch_child(
    value: &ObjectStoreNoDispatchProofV1,
    limits: &RequestStateWireLimits,
) -> Result<Vec<u8>, RequestStateWireError> {
    if !(1..=8).contains(&value.reason) {
        return Err(RequestStateWireError::InvalidEnum);
    }
    let proof_timestamp = canonical_uuid_v7_timestamp(&value.proof_id)
        .map_err(|_| RequestStateWireError::InvalidUuidV7)?;
    if proof_timestamp != nonnegative(value.committed_at_unix_ms)? {
        return Err(RequestStateWireError::InvalidTimeOrder);
    }
    digest(&value.proof_blake3)?;
    let mut output = writer(limits)?;
    output
        .raw(b"object-store-no-dispatch-proof-v1\0")
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u32(value.reason as u32)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    text(&value.proof_id, limits)?;
    output
        .text(&value.proof_id)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(positive(value.proof_fence)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(nonnegative(value.committed_at_unix_ms)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(positive(value.authority_epoch)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    complete_child(output.finish(), &value.proof_blake3, limits)
}

pub(crate) fn purge_child(
    value: &ObjectStorePayloadPurgeReceiptV1,
    limits: &RequestStateWireLimits,
) -> Result<(Vec<u8>, ObjectStorePayloadPurgeReceiptV1), RequestStateWireError> {
    if value.provider_authority_refunded
        || value.deleted_partial_temp_files > 1
        || !(1..=2).contains(&value.payload_kind)
        || !(1..=4).contains(&value.disposition)
        || !(1..=5).contains(&value.release_reason)
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    let mut output = writer(limits)?;
    output
        .raw(b"object-store-payload-purge-receipt-v1\0")
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    text(&value.purge_id, limits)?;
    output
        .text(&value.purge_id)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u32(value.payload_kind as u32)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_optional_text(&mut output, value.terminal_result_id.as_deref(), limits)?;
    output
        .u32(value.disposition as u32)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    for value in [
        value.released_bytes,
        value.released_rows,
        value.released_concurrency,
    ] {
        output
            .u64(value)
            .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    }
    output
        .u64(nonnegative(value.purged_at_unix_ms)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u8(0)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u32(value.release_reason as u32)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(value.deleted_partial_temp_bytes)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(value.deleted_partial_temp_files)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    let (bytes, result) = finish(&output.finish(), &value.receipt_blake3, limits)?;
    let mut normalized = value.clone();
    normalized.receipt_blake3 = result.to_vec().into();
    Ok((bytes, normalized))
}

fn retention_child(
    value: &ObjectStorePayloadRetentionV1,
    limits: &RequestStateWireLimits,
) -> Result<(Vec<u8>, ObjectStorePayloadRetentionV1), RequestStateWireError> {
    if !(1..=2).contains(&value.payload_kind)
        || !(1..=4).contains(&value.availability)
        || !(1..=4).contains(&value.purge_state)
    {
        return Err(RequestStateWireError::InvalidEnum);
    }
    let digest_value = if value.blake3.is_empty() {
        None
    } else {
        Some(digest(&value.blake3)?)
    };
    let receipt = value
        .purge_receipt
        .as_ref()
        .map(|value| purge_child(value, limits))
        .transpose()?;
    match value.availability {
        1 if value.durable_handle.is_none()
            && value.size == 0
            && digest_value.is_none()
            && value.purge_state == 1
            && value.purge_eligible_at_unix_ms.is_none()
            && receipt.is_none()
            && value.partial_temp_bytes == 0
            && value.partial_temp_chunks == 0 => {}
        4 if value.payload_kind == 1
            && value.durable_handle.is_none()
            && digest_value.is_some()
            && value.purge_state == 2
            && value.purge_eligible_at_unix_ms.is_some()
            && receipt.is_none() => {}
        2 if value.durable_handle.is_some()
            && digest_value.is_some()
            && value.purge_state != 4
            && receipt.is_none()
            && value.partial_temp_bytes == 0
            && value.partial_temp_chunks == 0 =>
        {
            if (value.purge_state == 1) != value.purge_eligible_at_unix_ms.is_none() {
                return Err(RequestStateWireError::InvalidStateAlgebra);
            }
        }
        3 if digest_value.is_some()
            && value.purge_state == 4
            && receipt.is_some()
            && value.partial_temp_bytes == 0
            && value.partial_temp_chunks == 0 =>
        {
            let receipt_value = &receipt
                .as_ref()
                .ok_or(RequestStateWireError::MissingChild)?
                .1;
            if value
                .purge_eligible_at_unix_ms
                .is_some_and(|time| time > receipt_value.purged_at_unix_ms)
                || ((receipt_value.release_reason == 3) != value.durable_handle.is_none())
            {
                return Err(RequestStateWireError::InvalidStateAlgebra);
            }
        }
        _ => return Err(RequestStateWireError::InvalidStateAlgebra),
    }
    if let Some(handle) = value.durable_handle.as_deref() {
        text(handle, limits)?;
    }
    let mut output = writer(limits)?;
    output
        .raw(b"object-store-payload-retention-v1\0")
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u32(value.payload_kind as u32)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u32(value.availability as u32)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_optional_text(&mut output, value.durable_handle.as_deref(), limits)?;
    output
        .u64(value.size)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .bytes(&value.blake3)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u32(value.purge_state as u32)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_optional_u64(
        &mut output,
        value
            .purge_eligible_at_unix_ms
            .map(nonnegative)
            .transpose()?,
    )?;
    write_optional_framed(
        &mut output,
        receipt.as_ref().map(|value| value.0.as_slice()),
    )?;
    output
        .u64(value.partial_temp_bytes)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(value.partial_temp_chunks)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    let (bytes, _) = finish(&output.finish(), &[], limits)?;
    let mut normalized = value.clone();
    normalized.purge_receipt = receipt.map(|value| value.1);
    Ok((bytes, normalized))
}

fn quota_state_child(
    value: &ObjectStoreQuotaStateV1,
    limits: &RequestStateWireLimits,
) -> Result<(Vec<u8>, ObjectStoreQuotaStateV1, Vec<u8>), RequestStateWireError> {
    let (reservation_bytes, canonical_reservations) =
        reservations_bytes(&value.provider_reservations, limits)?;
    let put = value
        .put_spool_quota
        .as_ref()
        .ok_or(RequestStateWireError::MissingChild)?;
    let result = value
        .result_spool_quota
        .as_ref()
        .ok_or(RequestStateWireError::MissingChild)?;
    let metadata = value
        .retained_metadata_quota
        .as_ref()
        .ok_or(RequestStateWireError::MissingChild)?;
    let mut output = writer(limits)?;
    output
        .raw(b"object-store-quota-state-v1\0")
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .raw(&reservation_bytes)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    for value in [put, result, metadata] {
        let child = complete_child(quota_preimage(value, limits)?, &[], limits)?;
        write_framed(&mut output, &child)?;
    }
    output
        .u64(positive(value.quota_revision)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    let complete = complete_child(output.finish(), &[], limits)?;
    let mut normalized = value.clone();
    normalized.provider_reservations = canonical_reservations;
    Ok((complete, normalized, reservation_bytes))
}

fn binding_child(
    value: &PutSubmitBindingV1,
    limits: &RequestStateWireLimits,
) -> Result<(Vec<u8>, PutSubmitBindingV1), RequestStateWireError> {
    if value.bound_at_unix_ms > value.reservation_expires_at_unix_ms {
        return Err(RequestStateWireError::InvalidTimeOrder);
    }
    let mut output = writer(limits)?;
    output
        .raw(b"object-store-put-submit-binding-v1\0")
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    text(&value.upload_id, limits)?;
    output
        .text(&value.upload_id)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(positive(value.upload_fence)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    text(&value.durable_body_handle, limits)?;
    output
        .text(&value.durable_body_handle)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(nonnegative(value.reservation_expires_at_unix_ms)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(nonnegative(value.bound_at_unix_ms)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(positive(value.binding_fence)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    let (bytes, result) = finish(&output.finish(), &value.binding_blake3, limits)?;
    let mut normalized = value.clone();
    normalized.binding_blake3 = result.to_vec().into();
    Ok((bytes, normalized))
}

fn quota_eq(left: &ObjectStoreQuotaUnitsV1, right: &ObjectStoreQuotaUnitsV1) -> bool {
    left.bytes == right.bytes && left.rows == right.rows && left.concurrency == right.concurrency
}

fn expected_spool(
    retention: &ObjectStorePayloadRetentionV1,
) -> Result<ObjectStoreQuotaUnitsV1, RequestStateWireError> {
    match retention.availability {
        1 => Ok(ObjectStoreQuotaUnitsV1 {
            bytes: 0,
            rows: 0,
            concurrency: 0,
        }),
        3 => Ok(ObjectStoreQuotaUnitsV1 {
            bytes: 0,
            rows: 0,
            concurrency: 0,
        }),
        2 | 4 => Ok(ObjectStoreQuotaUnitsV1 {
            bytes: retention.size,
            rows: 1,
            concurrency: u64::from(retention.payload_kind == 1),
        }),
        _ => Err(RequestStateWireError::InvalidEnum),
    }
}

fn validate_purge_authority(
    retention: &ObjectStorePayloadRetentionV1,
    phase: i32,
    disposition: i32,
    terminal_result_id: Option<&str>,
    purge_not_before_unix_ms: Option<i64>,
) -> Result<(), RequestStateWireError> {
    let Some(receipt) = retention.purge_receipt.as_ref() else {
        return Ok(());
    };
    if receipt.payload_kind != retention.payload_kind
        || receipt.released_bytes != retention.size
        || receipt.released_rows != 1
        || receipt.released_concurrency != u64::from(retention.payload_kind == 1)
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    match receipt.release_reason {
        1 | 2 => {
            let expected = if receipt.release_reason == 1 { 3 } else { 4 };
            if phase != 5
                || disposition != expected
                || receipt.disposition != expected
                || terminal_result_id.is_none()
                || receipt.terminal_result_id.as_deref() != terminal_result_id
            {
                return Err(RequestStateWireError::InvalidStateAlgebra);
            }
            match purge_not_before_unix_ms {
                Some(floor) if receipt.purged_at_unix_ms >= floor => {}
                _ => return Err(RequestStateWireError::InvalidStateAlgebra),
            }
        }
        3 | 4 => {
            if phase != 7
                || receipt.payload_kind != 1
                || receipt.disposition != 1
                || receipt.terminal_result_id.is_some()
            {
                return Err(RequestStateWireError::InvalidStateAlgebra);
            }
        }
        5 => {
            if phase != 6
                || receipt.payload_kind != 1
                || receipt.disposition != 1
                || receipt.terminal_result_id.is_some()
            {
                return Err(RequestStateWireError::InvalidStateAlgebra);
            }
        }
        _ => return Err(RequestStateWireError::InvalidEnum),
    }
    if receipt.release_reason != 3
        && (receipt.deleted_partial_temp_bytes != 0 || receipt.deleted_partial_temp_files != 0)
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    if receipt.release_reason == 3
        && ((receipt.deleted_partial_temp_bytes > 0 && receipt.deleted_partial_temp_files != 1)
            || receipt.deleted_partial_temp_bytes > retention.size)
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    Ok(())
}

fn expected_retryability(
    value: &ObjectStoreTerminalResultV1,
) -> Result<i32, RequestStateWireError> {
    match value
        .result
        .as_ref()
        .ok_or(RequestStateWireError::MissingChild)?
    {
        object_store_terminal_result_v1::Result::ProviderError(error)
            if matches!(error.error_class, 3 | 4) =>
        {
            Ok(2)
        }
        _ => Ok(3),
    }
}

fn validate_state_algebra(input: &ObjectStoreRequestStateV1) -> Result<(), RequestStateWireError> {
    if !(1..=7).contains(&input.phase)
        || !(1..=3).contains(&input.terminal_retryability)
        || !(1..=4).contains(&input.result_disposition)
    {
        return Err(RequestStateWireError::InvalidEnum);
    }
    let reservation = input.put_reservation_fingerprint.is_some();
    let descriptor = input.canonical_descriptor_fingerprint.is_some();
    if !reservation && !descriptor {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    if matches!(input.phase, 1 | 7) {
        if !reservation || descriptor || input.put_submit_binding.is_some() {
            return Err(RequestStateWireError::InvalidStateAlgebra);
        }
    } else if reservation && !descriptor && input.phase != 6 {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    if (!reservation && input.put_submit_binding.is_some())
        || (reservation && descriptor && input.put_submit_binding.is_none())
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    if input.cell_admission_id.is_some() != input.cell_admission_fence.is_some() {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    if input.phase == 1 && (input.cell_admission_id.is_some() || !input.reservations.is_empty()) {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    if matches!(input.phase, 2..=5)
        && (input.cell_admission_id.is_none() || input.reservations.is_empty())
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    match input.phase {
        3 if input
            .dispatch_attempt
            .as_ref()
            .is_some_and(|attempt| attempt.ambiguity_recorded_at_unix_ms.is_none()) => {}
        4 if input
            .dispatch_attempt
            .as_ref()
            .is_some_and(|attempt| attempt.ambiguity_recorded_at_unix_ms.is_some()) => {}
        5 if input.dispatch_attempt.is_some() => {}
        6 => {}
        1 | 2 | 7 if input.dispatch_attempt.is_none() => {}
        _ => return Err(RequestStateWireError::InvalidStateAlgebra),
    }
    if input.phase == 5 {
        if input.terminal_result.is_none()
            || input.terminal_retryability == 1
            || !matches!(input.result_disposition, 2..=4)
            || (input.result_disposition == 3) != input.ack_receipt.is_some()
            || (input.result_disposition == 4) != input.discard_receipt.is_some()
            || input.no_dispatch_proof.is_some()
        {
            return Err(RequestStateWireError::InvalidStateAlgebra);
        }
    } else if matches!(input.phase, 6 | 7) {
        let proof = input
            .no_dispatch_proof
            .as_ref()
            .ok_or(RequestStateWireError::MissingChild)?;
        if input.terminal_result.is_some()
            || input.terminal_retryability != 1
            || input.result_disposition != 1
            || input.ack_receipt.is_some()
            || input.discard_receipt.is_some()
            || ((input.phase == 7) != (proof.reason == 4))
        {
            return Err(RequestStateWireError::InvalidStateAlgebra);
        }
    } else if input.terminal_result.is_some()
        || input.terminal_retryability != 1
        || input.result_disposition != 1
        || input.ack_receipt.is_some()
        || input.discard_receipt.is_some()
        || input.no_dispatch_proof.is_some()
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    let closure =
        matches!(input.phase, 6 | 7) || (input.phase == 5 && input.result_disposition != 2);
    if closure != input.closure_committed_at_unix_ms.is_some()
        || input
            .closure_committed_at_unix_ms
            .is_some_and(|time| time < input.state_committed_at_unix_ms)
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    Ok(())
}

pub fn validate_and_encode_object_store_request_state(
    input: &ObjectStoreRequestStateV1,
    limits: &RequestStateWireLimits,
) -> Result<CanonicalObjectStoreRequestState, RequestStateWireError> {
    validate_limits(limits)?;
    validate_state_algebra(input)?;
    canonical_uuid_v7_timestamp(&input.logical_request_id)
        .map_err(|_| RequestStateWireError::InvalidUuidV7)?;
    canonical_uuid_v7_timestamp(&input.attempt_id)
        .map_err(|_| RequestStateWireError::InvalidUuidV7)?;
    for value in [
        &input.protocol_revision,
        &input.provider_boundary_id,
        &input.authenticated_cell_id,
        &input.authenticated_tenant_id,
        &input.logical_request_id,
        &input.attempt_id,
        &input.allocation_revision,
        &input.policy_revision,
    ] {
        text(value, limits)?;
    }

    let (reservations, canonical_reservations) = reservations_bytes(&input.reservations, limits)?;
    let quota_input = input
        .quota_state
        .as_ref()
        .ok_or(RequestStateWireError::MissingChild)?;
    let (quota, quota_value, quota_reservations) = quota_state_child(quota_input, limits)?;
    if reservations != quota_reservations {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    let dispatch = input
        .dispatch_attempt
        .as_ref()
        .map(|value| dispatch_child(value, limits))
        .transpose()?;
    let terminal = input
        .terminal_result
        .as_ref()
        .map(|value| terminal_child(value, limits))
        .transpose()?;
    if terminal.as_ref().is_some_and(|value| {
        expected_retryability(&value.1).ok() != Some(input.terminal_retryability)
    }) {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    let ack = input
        .ack_receipt
        .as_ref()
        .map(|value| ack_child(value, limits))
        .transpose()?;
    let discard = input
        .discard_receipt
        .as_ref()
        .map(|value| discard_child(value, limits))
        .transpose()?;
    let terminal_id = terminal
        .as_ref()
        .map(|value| value.1.terminal_result_id.as_str());
    if input
        .ack_receipt
        .as_ref()
        .is_some_and(|value| Some(value.terminal_result_id.as_str()) != terminal_id)
        || input
            .discard_receipt
            .as_ref()
            .is_some_and(|value| Some(value.terminal_result_id.as_str()) != terminal_id)
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    let no_dispatch = input
        .no_dispatch_proof
        .as_ref()
        .map(|value| no_dispatch_child(value, limits))
        .transpose()?;
    let put_input = input
        .put_body
        .as_ref()
        .ok_or(RequestStateWireError::MissingChild)?;
    let result_input = input
        .result_payload
        .as_ref()
        .ok_or(RequestStateWireError::MissingChild)?;
    let (put, put_value) = retention_child(put_input, limits)?;
    let (result, result_value) = retention_child(result_input, limits)?;
    if put_value.payload_kind != 1 || result_value.payload_kind != 2 {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    let is_put = input.put_reservation_fingerprint.is_some();
    if !is_put && put_value.availability != 1 {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    let byte_result = terminal.as_ref().and_then(|value| value.2.as_ref());
    if input.phase == 5 && (byte_result.is_some() == (result_value.availability == 1)) {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    if input.phase != 5 && result_value.availability != 1 {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    if let Some(byte) = byte_result
        && (result_value.durable_handle.as_deref() != Some(&byte.handle)
            || result_value.size != byte.size
            || result_value.blake3 != byte.blake3)
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    let put_quota = quota_value
        .put_spool_quota
        .as_ref()
        .ok_or(RequestStateWireError::MissingChild)?;
    let result_quota = quota_value
        .result_spool_quota
        .as_ref()
        .ok_or(RequestStateWireError::MissingChild)?;
    if !quota_eq(put_quota, &expected_spool(&put_value)?)
        || !quota_eq(result_quota, &expected_spool(&result_value)?)
    {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }
    let purge_not_before = input
        .ack_receipt
        .as_ref()
        .and_then(|value| value.payload_purge_after_unix_ms)
        .or_else(|| {
            input
                .discard_receipt
                .as_ref()
                .and_then(|value| value.payload_purge_after_unix_ms)
        });
    validate_purge_authority(
        &put_value,
        input.phase,
        input.result_disposition,
        terminal_id,
        purge_not_before,
    )?;
    validate_purge_authority(
        &result_value,
        input.phase,
        input.result_disposition,
        terminal_id,
        purge_not_before,
    )?;
    let binding = input
        .put_submit_binding
        .as_ref()
        .map(|value| binding_child(value, limits))
        .transpose()?;
    if binding.as_ref().is_some_and(|value| {
        put_value.durable_handle.as_deref() != Some(&value.1.durable_body_handle)
    }) {
        return Err(RequestStateWireError::InvalidStateAlgebra);
    }

    let mut output = writer(limits)?;
    output
        .raw(STATE_DOMAIN)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    for value in [
        &input.protocol_revision,
        &input.provider_boundary_id,
        &input.authenticated_cell_id,
        &input.authenticated_tenant_id,
        &input.logical_request_id,
        &input.attempt_id,
    ] {
        output
            .text(value)
            .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    }
    for value in [
        &input.put_reservation_fingerprint,
        &input.canonical_descriptor_fingerprint,
    ] {
        output
            .u8(u8::from(value.is_some()))
            .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
        if let Some(value) = value {
            output
                .raw(&digest(value)?)
                .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
        }
    }
    output
        .u32(input.phase as u32)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .text(&input.allocation_revision)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u64(positive(input.allocation_fence)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_optional_text(&mut output, input.cell_admission_id.as_deref(), limits)?;
    write_optional_u64(
        &mut output,
        input.cell_admission_fence.map(positive).transpose()?,
    )?;
    output
        .raw(&reservations)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_optional_framed(&mut output, dispatch.as_deref())?;
    write_optional_framed(
        &mut output,
        terminal.as_ref().map(|value| value.0.as_slice()),
    )?;
    output
        .u32(input.terminal_retryability as u32)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u32(input.result_disposition as u32)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_optional_framed(&mut output, ack.as_deref())?;
    write_optional_framed(&mut output, discard.as_deref())?;
    write_optional_framed(&mut output, no_dispatch.as_deref())?;
    write_framed(&mut output, &put)?;
    write_framed(&mut output, &result)?;
    write_framed(&mut output, &quota)?;
    output
        .u64(nonnegative(input.state_committed_at_unix_ms)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_optional_u64(
        &mut output,
        input
            .closure_committed_at_unix_ms
            .map(nonnegative)
            .transpose()?,
    )?;
    output
        .text(&input.policy_revision)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_optional_framed(
        &mut output,
        binding.as_ref().map(|value| value.0.as_slice()),
    )?;
    let canonical_preimage = output.finish();
    let (canonical_bytes, state_blake3) = finish(&canonical_preimage, &input.state_blake3, limits)?;
    let mut value = input.clone();
    value.reservations = canonical_reservations;
    value.state_blake3 = state_blake3.to_vec().into();
    value.terminal_result = terminal.map(|value| value.1);
    value.put_body = Some(put_value);
    value.result_payload = Some(result_value);
    value.quota_state = Some(quota_value);
    value.put_submit_binding = binding.map(|value| value.1);
    Ok(CanonicalObjectStoreRequestState {
        value,
        canonical_preimage,
        canonical_bytes,
        digest: state_blake3,
    })
}

fn latest_state_durable_time(value: &ObjectStoreRequestStateV1) -> i64 {
    let mut latest = value.state_committed_at_unix_ms;
    for time in [
        value.closure_committed_at_unix_ms,
        value
            .dispatch_attempt
            .as_ref()
            .map(|value| value.dispatch_started_at_unix_ms),
        value
            .dispatch_attempt
            .as_ref()
            .and_then(|value| value.ambiguity_recorded_at_unix_ms),
        value
            .ack_receipt
            .as_ref()
            .map(|value| value.acked_at_unix_ms),
        value
            .discard_receipt
            .as_ref()
            .map(|value| value.discarded_at_unix_ms),
        value
            .no_dispatch_proof
            .as_ref()
            .map(|value| value.committed_at_unix_ms),
        value
            .put_submit_binding
            .as_ref()
            .map(|value| value.bound_at_unix_ms),
        value
            .put_body
            .as_ref()
            .and_then(|value| value.purge_receipt.as_ref())
            .map(|value| value.purged_at_unix_ms),
        value
            .result_payload
            .as_ref()
            .and_then(|value| value.purge_receipt.as_ref())
            .map(|value| value.purged_at_unix_ms),
    ]
    .into_iter()
    .flatten()
    {
        latest = latest.max(time);
    }
    latest
}

pub fn validate_and_encode_object_store_request_receipt(
    input: &ObjectStoreRequestReceiptV1,
    limits: &RequestStateWireLimits,
) -> Result<CanonicalObjectStoreRequestReceipt, RequestStateWireError> {
    validate_limits(limits)?;
    let object_store_request_receipt_v1::Outcome::RequestState(state) = input
        .outcome
        .as_ref()
        .ok_or(RequestStateWireError::MissingChild)?;
    let state = validate_and_encode_object_store_request_state(state, limits)?;
    if input.receipt_committed_at_unix_ms < latest_state_durable_time(state.value()) {
        return Err(RequestStateWireError::InvalidTimeOrder);
    }
    let mut output = writer(limits)?;
    output
        .raw(RECEIPT_DOMAIN)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u32(REQUEST_STATE_RECEIPT_TAG)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_framed(&mut output, state.canonical_bytes())?;
    output
        .u64(nonnegative(input.receipt_committed_at_unix_ms)?)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    let canonical_preimage = output.finish();
    let (canonical_bytes, receipt_blake3) =
        finish(&canonical_preimage, &input.receipt_blake3, limits)?;
    let mut value = input.clone();
    value.receipt_blake3 = receipt_blake3.to_vec().into();
    value.outcome = Some(object_store_request_receipt_v1::Outcome::RequestState(
        Box::new(state.value().clone()),
    ));
    Ok(CanonicalObjectStoreRequestReceipt {
        value,
        canonical_preimage,
        canonical_bytes,
        digest: receipt_blake3,
    })
}

pub fn validate_and_encode_object_store_request_outcome(
    input: &ObjectStoreRequestOutcomeV1,
    limits: &RequestStateWireLimits,
) -> Result<CanonicalObjectStoreRequestOutcome, RequestStateWireError> {
    validate_limits(limits)?;
    let object_store_request_outcome_v1::Outcome::RequestState(state) = input
        .outcome
        .as_ref()
        .ok_or(RequestStateWireError::MissingChild)?;
    let state = validate_and_encode_object_store_request_state(state, limits)?;
    let mut output = writer(limits)?;
    output
        .raw(OUTCOME_DOMAIN)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    output
        .u32(REQUEST_STATE_OUTCOME_TAG)
        .map_err(|_| RequestStateWireError::CanonicalTooLarge)?;
    write_framed(&mut output, state.canonical_bytes())?;
    let canonical_preimage = output.finish();
    let (canonical_bytes, outcome_blake3) =
        finish(&canonical_preimage, &input.outcome_blake3, limits)?;
    let mut value = input.clone();
    value.outcome_blake3 = outcome_blake3.to_vec().into();
    value.outcome = Some(object_store_request_outcome_v1::Outcome::RequestState(
        Box::new(state.value().clone()),
    ));
    Ok(CanonicalObjectStoreRequestOutcome {
        value,
        canonical_preimage,
        canonical_bytes,
        digest: outcome_blake3,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RequestStateWireError {
    #[error("request-state wire limits must be positive")]
    InvalidLimits,
    #[error("request-state wire text is not canonical or bounded")]
    InvalidCanonicalText,
    #[error("request-state wire UUID is not canonical UUIDv7")]
    InvalidUuidV7,
    #[error("request-state wire enum is unknown or unspecified")]
    InvalidEnum,
    #[error("request-state wire authority value must be positive")]
    NonPositiveAuthority,
    #[error("request-state wire timestamp must be nonnegative")]
    NegativeTime,
    #[error("request-state wire timestamp ordering is invalid")]
    InvalidTimeOrder,
    #[error("request-state wire required child is missing")]
    MissingChild,
    #[error("request-state algebra is inconsistent")]
    InvalidStateAlgebra,
    #[error("terminal-result canonical authority is invalid")]
    InvalidTerminalResult,
    #[error("request-state wire digest must contain exactly 32 bytes")]
    InvalidDigest,
    #[error("request-state wire digest does not match canonical fields")]
    DigestMismatch,
    #[error("canonical request-state wire record exceeds its byte bound")]
    CanonicalTooLarge,
}
