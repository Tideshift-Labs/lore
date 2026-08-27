// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure terminal-result selected-payload validation and protobuf encoding.
//!
//! The canonical bytes contain only the selected payload message. They deliberately exclude the
//! terminal-result envelope oneof tag, terminal ID, digest, and size fields.

use std::collections::HashSet;
use std::fmt;

use lore_proto::lore::object_dispatch::v1::ByteResultHandleV1;
use lore_proto::lore::object_dispatch::v1::DeleteMarkerV1;
use lore_proto::lore::object_dispatch::v1::HeadObjectResultV1;
use lore_proto::lore::object_dispatch::v1::ListObjectEntryV1;
use lore_proto::lore::object_dispatch::v1::ListObjectVersionsResultV1;
use lore_proto::lore::object_dispatch::v1::ListObjectsV2ResultV1;
use lore_proto::lore::object_dispatch::v1::ObjectMetadataEntryV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalResultV1;
use lore_proto::lore::object_dispatch::v1::ObjectVersionV1;
use lore_proto::lore::object_dispatch::v1::ProviderErrorClassV1;
use lore_proto::lore::object_dispatch::v1::ProviderErrorV1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1;
use prost::Message;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use crate::contract::validate_canonical_text;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalResultLimits {
    pub max_canonical_result_bytes: u32,
    pub max_list_entries: u32,
    pub max_key_bytes: u32,
    pub max_metadata_entries: u32,
    pub max_metadata_key_bytes: u32,
    pub max_metadata_value_bytes: u32,
    pub max_metadata_aggregate_bytes: u32,
    pub max_opaque_value_bytes: u32,
    pub max_result_handle_bytes: u32,
    pub max_provider_code_bytes: u32,
    pub max_provider_request_id_bytes: u32,
    pub max_retry_after_ms: u64,
}

#[derive(Clone, PartialEq)]
pub struct CanonicalTerminalResult {
    result: ObjectStoreTerminalResultV1,
    canonical_result_bytes: Vec<u8>,
    canonical_result_blake3: [u8; 32],
}

impl CanonicalTerminalResult {
    pub fn result(&self) -> &ObjectStoreTerminalResultV1 {
        &self.result
    }

    pub fn canonical_result_bytes(&self) -> &[u8] {
        &self.canonical_result_bytes
    }

    pub fn canonical_result_blake3(&self) -> &[u8; 32] {
        &self.canonical_result_blake3
    }

    pub fn canonical_result_size(&self) -> u64 {
        self.canonical_result_bytes.len() as u64
    }
}

impl fmt::Debug for CanonicalTerminalResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalTerminalResult")
            .field("result", &"[REDACTED]")
            .field("canonical_result_bytes", &"[REDACTED]")
            .field("canonical_result_blake3", &"[REDACTED]")
            .field("canonical_result_size", &self.canonical_result_size())
            .finish()
    }
}

pub fn validate_and_encode_terminal_result(
    input: &ObjectStoreTerminalResultV1,
    limits: &TerminalResultLimits,
) -> Result<CanonicalTerminalResult, TerminalResultError> {
    validate_limits(limits)?;
    validate_canonical_text(&input.terminal_result_id, limits.max_opaque_value_bytes)
        .map_err(|_| TerminalResultError::InvalidTerminalResultId)?;
    let payload = canonicalize_payload(
        input
            .result
            .as_ref()
            .ok_or(TerminalResultError::MissingResult)?,
        limits,
    )?;
    let canonical_result_bytes = encode_payload(&payload);
    if canonical_result_bytes.len() > limits.max_canonical_result_bytes as usize {
        return Err(TerminalResultError::CanonicalResultTooLarge);
    }
    let canonical_result_blake3 = *blake3::hash(&canonical_result_bytes).as_bytes();
    let canonical_result_size = canonical_result_bytes.len() as u64;
    Ok(CanonicalTerminalResult {
        result: ObjectStoreTerminalResultV1 {
            result: Some(payload),
            terminal_result_id: input.terminal_result_id.clone(),
            canonical_result_blake3: canonical_result_blake3.to_vec().into(),
            canonical_result_size,
        },
        canonical_result_bytes,
        canonical_result_blake3,
    })
}

fn validate_limits(limits: &TerminalResultLimits) -> Result<(), TerminalResultError> {
    if [
        limits.max_canonical_result_bytes,
        limits.max_list_entries,
        limits.max_key_bytes,
        limits.max_metadata_entries,
        limits.max_metadata_key_bytes,
        limits.max_metadata_value_bytes,
        limits.max_metadata_aggregate_bytes,
        limits.max_opaque_value_bytes,
        limits.max_result_handle_bytes,
        limits.max_provider_code_bytes,
        limits.max_provider_request_id_bytes,
    ]
    .contains(&0)
    {
        return Err(TerminalResultError::InvalidLimits);
    }
    Ok(())
}

fn canonicalize_payload(
    payload: &object_store_terminal_result_v1::Result,
    limits: &TerminalResultLimits,
) -> Result<object_store_terminal_result_v1::Result, TerminalResultError> {
    use object_store_terminal_result_v1::Result;
    match payload {
        Result::BoolResult(value) => Ok(Result::BoolResult(*value)),
        Result::HeadObject(value) => Ok(Result::HeadObject(canonical_head_object(value, limits)?)),
        Result::PutObject(value) => {
            validate_optional_text(&value.etag, limits.max_opaque_value_bytes)?;
            validate_optional_text(&value.version_id, limits.max_opaque_value_bytes)?;
            Ok(Result::PutObject(value.clone()))
        }
        Result::DeleteObject(value) => {
            validate_optional_text(&value.version_id, limits.max_opaque_value_bytes)?;
            Ok(Result::DeleteObject(value.clone()))
        }
        Result::ListObjectsV2(value) => Ok(Result::ListObjectsV2(canonical_list_objects(
            value, limits,
        )?)),
        Result::ListObjectVersions(value) => Ok(Result::ListObjectVersions(
            canonical_list_versions(value, limits)?,
        )),
        Result::ByteResult(value) => Ok(Result::ByteResult(canonical_byte_result(value, limits)?)),
        Result::ProviderError(value) => Ok(Result::ProviderError(canonical_provider_error(
            value, limits,
        )?)),
    }
}

fn canonical_head_object(
    value: &HeadObjectResultV1,
    limits: &TerminalResultLimits,
) -> Result<HeadObjectResultV1, TerminalResultError> {
    validate_optional_text(&value.etag, limits.max_opaque_value_bytes)?;
    validate_optional_text(&value.version_id, limits.max_opaque_value_bytes)?;
    Ok(HeadObjectResultV1 {
        content_length: value.content_length,
        etag: value.etag.clone(),
        last_modified_unix_ms: value.last_modified_unix_ms,
        version_id: value.version_id.clone(),
        metadata: canonical_metadata(&value.metadata, limits)?,
    })
}

fn canonical_list_objects(
    value: &ListObjectsV2ResultV1,
    limits: &TerminalResultLimits,
) -> Result<ListObjectsV2ResultV1, TerminalResultError> {
    validate_list_count(value.entries.len(), value.common_prefixes.len(), 0, limits)?;
    validate_truncation(value.is_truncated, value.next_continuation_token.is_some())?;
    let mut entries = Vec::with_capacity(value.entries.len());
    for entry in &value.entries {
        validate_required_text(&entry.key, limits.max_key_bytes)?;
        validate_optional_text(&entry.etag, limits.max_opaque_value_bytes)?;
        entries.push(ListObjectEntryV1 {
            key: entry.key.clone(),
            size: entry.size,
            etag: entry.etag.clone(),
            last_modified_unix_ms: entry.last_modified_unix_ms,
        });
    }
    let common_prefixes = value
        .common_prefixes
        .iter()
        .map(|prefix| {
            validate_text(prefix, limits.max_key_bytes, true)?;
            Ok(prefix.clone())
        })
        .collect::<Result<Vec<_>, TerminalResultError>>()?;
    validate_optional_text(
        &value.next_continuation_token,
        limits.max_opaque_value_bytes,
    )?;
    Ok(ListObjectsV2ResultV1 {
        entries,
        common_prefixes,
        is_truncated: value.is_truncated,
        next_continuation_token: value.next_continuation_token.clone(),
    })
}

fn canonical_list_versions(
    value: &ListObjectVersionsResultV1,
    limits: &TerminalResultLimits,
) -> Result<ListObjectVersionsResultV1, TerminalResultError> {
    validate_list_count(
        value.versions.len(),
        value.delete_markers.len(),
        value.common_prefixes.len(),
        limits,
    )?;
    let markers_present = value.next_key_marker.is_some() || value.next_version_id_marker.is_some();
    validate_truncation(value.is_truncated, markers_present)?;
    if value.is_truncated
        && (value.next_key_marker.is_none() || value.next_version_id_marker.is_none())
    {
        return Err(TerminalResultError::InvalidTruncation);
    }
    validate_optional_text(&value.next_key_marker, limits.max_opaque_value_bytes)?;
    validate_optional_text(&value.next_version_id_marker, limits.max_opaque_value_bytes)?;
    let mut versions = Vec::with_capacity(value.versions.len());
    for entry in &value.versions {
        validate_required_text(&entry.key, limits.max_key_bytes)?;
        validate_required_text(&entry.version_id, limits.max_opaque_value_bytes)?;
        validate_optional_text(&entry.etag, limits.max_opaque_value_bytes)?;
        versions.push(ObjectVersionV1 {
            key: entry.key.clone(),
            version_id: entry.version_id.clone(),
            is_latest: entry.is_latest,
            size: entry.size,
            etag: entry.etag.clone(),
            last_modified_unix_ms: entry.last_modified_unix_ms,
        });
    }
    let mut delete_markers = Vec::with_capacity(value.delete_markers.len());
    for entry in &value.delete_markers {
        validate_required_text(&entry.key, limits.max_key_bytes)?;
        validate_required_text(&entry.version_id, limits.max_opaque_value_bytes)?;
        delete_markers.push(DeleteMarkerV1 {
            key: entry.key.clone(),
            version_id: entry.version_id.clone(),
            is_latest: entry.is_latest,
            last_modified_unix_ms: entry.last_modified_unix_ms,
        });
    }
    let common_prefixes = value
        .common_prefixes
        .iter()
        .map(|prefix| {
            validate_text(prefix, limits.max_key_bytes, true)?;
            Ok(prefix.clone())
        })
        .collect::<Result<Vec<_>, TerminalResultError>>()?;
    Ok(ListObjectVersionsResultV1 {
        versions,
        delete_markers,
        common_prefixes,
        is_truncated: value.is_truncated,
        next_key_marker: value.next_key_marker.clone(),
        next_version_id_marker: value.next_version_id_marker.clone(),
    })
}

fn canonical_byte_result(
    value: &ByteResultHandleV1,
    limits: &TerminalResultLimits,
) -> Result<ByteResultHandleV1, TerminalResultError> {
    validate_required_text(&value.handle, limits.max_result_handle_bytes)?;
    if value.blake3.len() != 32 {
        return Err(TerminalResultError::InvalidDigest);
    }
    if value.content_length != value.size {
        return Err(TerminalResultError::ByteResultSizeMismatch);
    }
    validate_optional_text(&value.etag, limits.max_opaque_value_bytes)?;
    validate_optional_text(&value.version_id, limits.max_opaque_value_bytes)?;
    Ok(ByteResultHandleV1 {
        handle: value.handle.clone(),
        size: value.size,
        blake3: value.blake3.clone(),
        content_length: value.content_length,
        metadata: canonical_metadata(&value.metadata, limits)?,
        etag: value.etag.clone(),
        version_id: value.version_id.clone(),
    })
}

fn canonical_provider_error(
    value: &ProviderErrorV1,
    limits: &TerminalResultLimits,
) -> Result<ProviderErrorV1, TerminalResultError> {
    let class = ProviderErrorClassV1::try_from(value.error_class)
        .map_err(|_| TerminalResultError::InvalidProviderErrorClass)?;
    match class {
        ProviderErrorClassV1::ProviderErrorClassUnspecified => {
            return Err(TerminalResultError::InvalidProviderErrorClass);
        }
        ProviderErrorClassV1::ProviderErrorClassNotFound
        | ProviderErrorClassV1::ProviderErrorClassAuthorization
        | ProviderErrorClassV1::ProviderErrorClassThrottled
        | ProviderErrorClassV1::ProviderErrorClassRetryableDecisive
        | ProviderErrorClassV1::ProviderErrorClassPermanent
        | ProviderErrorClassV1::ProviderErrorClassMalformedResult
        | ProviderErrorClassV1::ProviderErrorClassOversizedResult => {}
    }
    if !(100..=599).contains(&value.http_status) {
        return Err(TerminalResultError::InvalidHttpStatus);
    }
    validate_optional_text(&value.provider_code, limits.max_provider_code_bytes)?;
    validate_optional_text(
        &value.provider_request_id,
        limits.max_provider_request_id_bytes,
    )?;
    if value
        .retry_after_ms
        .is_some_and(|retry| retry > limits.max_retry_after_ms)
    {
        return Err(TerminalResultError::RetryAfterTooLarge);
    }
    if value.provider_message_blake3.len() != 32 {
        return Err(TerminalResultError::InvalidDigest);
    }
    Ok(value.clone())
}

fn canonical_metadata(
    values: &[ObjectMetadataEntryV1],
    limits: &TerminalResultLimits,
) -> Result<Vec<ObjectMetadataEntryV1>, TerminalResultError> {
    if values.len() > limits.max_metadata_entries as usize {
        return Err(TerminalResultError::MetadataTooLarge);
    }
    let mut seen = HashSet::with_capacity(values.len());
    let mut aggregate = 0usize;
    let mut copied = Vec::with_capacity(values.len());
    for entry in values {
        if !is_metadata_key(&entry.key) {
            return Err(TerminalResultError::InvalidMetadataKey);
        }
        validate_required_text(&entry.key, limits.max_metadata_key_bytes)?;
        validate_text(&entry.value, limits.max_metadata_value_bytes, true)?;
        if !seen.insert(entry.key.clone()) {
            return Err(TerminalResultError::DuplicateMetadataKey);
        }
        aggregate = aggregate
            .checked_add(entry.key.len())
            .and_then(|size| size.checked_add(entry.value.len()))
            .ok_or(TerminalResultError::MetadataTooLarge)?;
        if aggregate > limits.max_metadata_aggregate_bytes as usize {
            return Err(TerminalResultError::MetadataTooLarge);
        }
        copied.push(entry.clone());
    }
    copied.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
    Ok(copied)
}

fn validate_list_count(
    first: usize,
    second: usize,
    third: usize,
    limits: &TerminalResultLimits,
) -> Result<(), TerminalResultError> {
    let count = first
        .checked_add(second)
        .and_then(|value| value.checked_add(third))
        .ok_or(TerminalResultError::ListTooLarge)?;
    if count > u32::MAX as usize || count > limits.max_list_entries as usize {
        return Err(TerminalResultError::ListTooLarge);
    }
    Ok(())
}

fn validate_truncation(truncated: bool, marker_present: bool) -> Result<(), TerminalResultError> {
    if truncated != marker_present {
        return Err(TerminalResultError::InvalidTruncation);
    }
    Ok(())
}

fn validate_optional_text(value: &Option<String>, maximum: u32) -> Result<(), TerminalResultError> {
    if let Some(value) = value {
        validate_required_text(value, maximum)?;
    }
    Ok(())
}

fn validate_required_text(value: &str, maximum: u32) -> Result<(), TerminalResultError> {
    validate_text(value, maximum, false)
}

fn validate_text(value: &str, maximum: u32, allow_empty: bool) -> Result<(), TerminalResultError> {
    if maximum == 0
        || (!allow_empty && value.is_empty())
        || value.len() > maximum as usize
        || value.contains('\0')
        || value.nfc().ne(value.chars())
    {
        return Err(TerminalResultError::InvalidCanonicalText);
    }
    Ok(())
}

fn is_metadata_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn encode_payload(payload: &object_store_terminal_result_v1::Result) -> Vec<u8> {
    use object_store_terminal_result_v1::Result;
    match payload {
        Result::BoolResult(value) => value.encode_to_vec(),
        Result::HeadObject(value) => value.encode_to_vec(),
        Result::PutObject(value) => value.encode_to_vec(),
        Result::DeleteObject(value) => value.encode_to_vec(),
        Result::ListObjectsV2(value) => value.encode_to_vec(),
        Result::ListObjectVersions(value) => value.encode_to_vec(),
        Result::ByteResult(value) => value.encode_to_vec(),
        Result::ProviderError(value) => value.encode_to_vec(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum TerminalResultError {
    #[error("terminal-result limits must be positive")]
    InvalidLimits,
    #[error("terminal-result ID is invalid")]
    InvalidTerminalResultId,
    #[error("terminal-result payload is missing")]
    MissingResult,
    #[error("terminal-result text is not canonical or bounded")]
    InvalidCanonicalText,
    #[error("terminal-result metadata key is invalid")]
    InvalidMetadataKey,
    #[error("terminal-result metadata key is duplicated")]
    DuplicateMetadataKey,
    #[error("terminal-result metadata exceeds its bound")]
    MetadataTooLarge,
    #[error("terminal-result list exceeds its entry bound")]
    ListTooLarge,
    #[error("terminal-result truncation markers are inconsistent")]
    InvalidTruncation,
    #[error("terminal-result digest must contain exactly 32 bytes")]
    InvalidDigest,
    #[error("terminal byte-result content length does not equal size")]
    ByteResultSizeMismatch,
    #[error("terminal provider-error class is unknown or unspecified")]
    InvalidProviderErrorClass,
    #[error("terminal provider HTTP status is outside 100 through 599")]
    InvalidHttpStatus,
    #[error("terminal provider retry-after exceeds its bound")]
    RetryAfterTooLarge,
    #[error("canonical terminal result exceeds its byte bound")]
    CanonicalResultTooLarge,
}
