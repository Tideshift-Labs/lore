// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure, unwired UploadPut stream identity and rejection-detail contracts.

use std::fmt;

use thiserror::Error;

use crate::contract::BoundedCanonicalWriter;
use crate::contract::canonical_uuid_v7_timestamp;
use crate::contract::validate_canonical_text;

const UPLOAD_IDENTITY_DOMAIN: &[u8] = b"object-store-upload-stream-identity-v1\0";
const UPLOAD_REJECTED_DOMAIN: &[u8] = b"object-store-upload-stream-rejected-v1\0";

#[derive(Clone, PartialEq, Eq)]
pub struct UploadPutStreamIdentity {
    pub protocol_revision: String,
    pub provider_boundary_id: String,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub logical_request_id: String,
    pub attempt_id: String,
    pub upload_id: String,
    pub upload_fence: u64,
}

impl fmt::Debug for UploadPutStreamIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UploadPutStreamIdentity")
            .field("protocol_revision", &self.protocol_revision)
            .field("provider_boundary_id", &"[REDACTED]")
            .field("authenticated_cell_id", &"[REDACTED]")
            .field("authenticated_tenant_id", &"[REDACTED]")
            .field("logical_request_id", &"[REDACTED]")
            .field("attempt_id", &"[REDACTED]")
            .field("upload_id", &"[REDACTED]")
            .field("upload_fence", &self.upload_fence)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalUploadPutStreamIdentity {
    identity: UploadPutStreamIdentity,
    canonical_preimage: Vec<u8>,
    stream_identity_blake3: [u8; 32],
}

impl CanonicalUploadPutStreamIdentity {
    pub fn identity(&self) -> &UploadPutStreamIdentity {
        &self.identity
    }

    pub fn canonical_preimage(&self) -> &[u8] {
        &self.canonical_preimage
    }

    pub fn stream_identity_blake3(&self) -> &[u8; 32] {
        &self.stream_identity_blake3
    }
}

impl fmt::Debug for CanonicalUploadPutStreamIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalUploadPutStreamIdentity")
            .field("identity", &self.identity)
            .field("canonical_preimage", &"[REDACTED]")
            .field("stream_identity_blake3", &"[REDACTED]")
            .finish()
    }
}

pub fn build_upload_put_stream_identity(
    identity: UploadPutStreamIdentity,
    max_text_bytes: u32,
) -> Result<CanonicalUploadPutStreamIdentity, UploadContractError> {
    validate_identity(&identity, max_text_bytes)?;
    let canonical_preimage = identity_preimage(&identity)?;
    let stream_identity_blake3 = *blake3::hash(&canonical_preimage).as_bytes();
    Ok(CanonicalUploadPutStreamIdentity {
        identity,
        canonical_preimage,
        stream_identity_blake3,
    })
}

pub fn empty_upload_put_stream_identity_blake3() -> [u8; 32] {
    *blake3::hash(UPLOAD_IDENTITY_DOMAIN).as_bytes()
}

pub fn lowest_upload_put_stream_identity_mismatch_field(
    frozen: &UploadPutStreamIdentity,
    candidate: &UploadPutStreamIdentity,
) -> u32 {
    if frozen.protocol_revision != candidate.protocol_revision {
        1
    } else if frozen.provider_boundary_id != candidate.provider_boundary_id {
        2
    } else if frozen.authenticated_cell_id != candidate.authenticated_cell_id {
        3
    } else if frozen.authenticated_tenant_id != candidate.authenticated_tenant_id {
        4
    } else if frozen.logical_request_id != candidate.logical_request_id {
        5
    } else if frozen.attempt_id != candidate.attempt_id {
        6
    } else if frozen.upload_id != candidate.upload_id {
        7
    } else if frozen.upload_fence != candidate.upload_fence {
        8
    } else {
        0
    }
}

fn validate_identity(
    identity: &UploadPutStreamIdentity,
    max_text_bytes: u32,
) -> Result<(), UploadContractError> {
    if max_text_bytes == 0 {
        return Err(UploadContractError::InvalidTextMaximum);
    }
    for value in [
        &identity.protocol_revision,
        &identity.provider_boundary_id,
        &identity.authenticated_cell_id,
        &identity.authenticated_tenant_id,
        &identity.logical_request_id,
        &identity.attempt_id,
        &identity.upload_id,
    ] {
        validate_canonical_text(value, max_text_bytes)
            .map_err(|_| UploadContractError::InvalidCanonicalText)?;
    }
    canonical_uuid_v7_timestamp(&identity.logical_request_id)
        .map_err(|_| UploadContractError::InvalidUuidV7)?;
    canonical_uuid_v7_timestamp(&identity.attempt_id)
        .map_err(|_| UploadContractError::InvalidUuidV7)?;
    if identity.upload_fence == 0 {
        return Err(UploadContractError::InvalidUploadFence);
    }
    Ok(())
}

fn identity_preimage(identity: &UploadPutStreamIdentity) -> Result<Vec<u8>, UploadContractError> {
    let mut writer =
        BoundedCanonicalWriter::new(u32::MAX).map_err(|_| UploadContractError::PreimageTooLarge)?;
    writer
        .raw(UPLOAD_IDENTITY_DOMAIN)
        .and_then(|()| writer.text(&identity.protocol_revision))
        .and_then(|()| writer.text(&identity.provider_boundary_id))
        .and_then(|()| writer.text(&identity.authenticated_cell_id))
        .and_then(|()| writer.text(&identity.authenticated_tenant_id))
        .and_then(|()| writer.text(&identity.logical_request_id))
        .and_then(|()| writer.text(&identity.attempt_id))
        .and_then(|()| writer.text(&identity.upload_id))
        .and_then(|()| writer.u64(identity.upload_fence))
        .map_err(|_| UploadContractError::PreimageTooLarge)?;
    Ok(writer.finish())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PutUploadStreamRejectReason {
    IdentityMismatch = 1,
    EmptyStream = 2,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PutUploadStreamRejected {
    pub protocol_revision: String,
    pub reason: PutUploadStreamRejectReason,
    pub stream_identity_blake3: [u8; 32],
    pub rejected_chunk_index: u64,
    pub rejected_field_number: u32,
    pub detail_blake3: [u8; 32],
}

impl fmt::Debug for PutUploadStreamRejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PutUploadStreamRejected")
            .field("protocol_revision", &self.protocol_revision)
            .field("reason", &self.reason)
            .field("stream_identity_blake3", &"[REDACTED]")
            .field("rejected_chunk_index", &self.rejected_chunk_index)
            .field("rejected_field_number", &self.rejected_field_number)
            .field("detail_blake3", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalPutUploadStreamRejected {
    detail: PutUploadStreamRejected,
    canonical_preimage: Vec<u8>,
}

impl CanonicalPutUploadStreamRejected {
    pub fn detail(&self) -> &PutUploadStreamRejected {
        &self.detail
    }

    pub fn canonical_preimage(&self) -> &[u8] {
        &self.canonical_preimage
    }
}

impl fmt::Debug for CanonicalPutUploadStreamRejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalPutUploadStreamRejected")
            .field("detail", &self.detail)
            .field("canonical_preimage", &"[REDACTED]")
            .finish()
    }
}

pub fn build_identity_mismatch_upload_rejection(
    frozen: &CanonicalUploadPutStreamIdentity,
    candidate: &UploadPutStreamIdentity,
    rejected_chunk_index: u64,
    max_text_bytes: u32,
) -> Result<CanonicalPutUploadStreamRejected, UploadContractError> {
    let rejected_field_number =
        lowest_upload_put_stream_identity_mismatch_field(&frozen.identity, candidate);
    if rejected_field_number == 0 {
        return Err(UploadContractError::IdentitiesMatch);
    }
    build_rejection(
        frozen.identity.protocol_revision.clone(),
        PutUploadStreamRejectReason::IdentityMismatch,
        frozen.stream_identity_blake3,
        rejected_chunk_index,
        rejected_field_number,
        max_text_bytes,
    )
}

pub fn build_empty_stream_upload_rejection(
    protocol_revision: String,
    max_text_bytes: u32,
) -> Result<CanonicalPutUploadStreamRejected, UploadContractError> {
    build_rejection(
        protocol_revision,
        PutUploadStreamRejectReason::EmptyStream,
        empty_upload_put_stream_identity_blake3(),
        0,
        0,
        max_text_bytes,
    )
}

pub fn validate_upload_stream_rejection(
    detail: &PutUploadStreamRejected,
    max_text_bytes: u32,
) -> Result<CanonicalPutUploadStreamRejected, UploadContractError> {
    let canonical_preimage = rejection_preimage(detail, max_text_bytes)?;
    if *blake3::hash(&canonical_preimage).as_bytes() != detail.detail_blake3 {
        return Err(UploadContractError::DigestMismatch);
    }
    Ok(CanonicalPutUploadStreamRejected {
        detail: detail.clone(),
        canonical_preimage,
    })
}

fn build_rejection(
    protocol_revision: String,
    reason: PutUploadStreamRejectReason,
    stream_identity_blake3: [u8; 32],
    rejected_chunk_index: u64,
    rejected_field_number: u32,
    max_text_bytes: u32,
) -> Result<CanonicalPutUploadStreamRejected, UploadContractError> {
    let mut detail = PutUploadStreamRejected {
        protocol_revision,
        reason,
        stream_identity_blake3,
        rejected_chunk_index,
        rejected_field_number,
        detail_blake3: [0; 32],
    };
    let canonical_preimage = rejection_preimage(&detail, max_text_bytes)?;
    detail.detail_blake3 = *blake3::hash(&canonical_preimage).as_bytes();
    Ok(CanonicalPutUploadStreamRejected {
        detail,
        canonical_preimage,
    })
}

fn rejection_preimage(
    detail: &PutUploadStreamRejected,
    max_text_bytes: u32,
) -> Result<Vec<u8>, UploadContractError> {
    if max_text_bytes == 0 {
        return Err(UploadContractError::InvalidTextMaximum);
    }
    validate_canonical_text(&detail.protocol_revision, max_text_bytes)
        .map_err(|_| UploadContractError::InvalidCanonicalText)?;
    match detail.reason {
        PutUploadStreamRejectReason::IdentityMismatch
            if !(1..=8).contains(&detail.rejected_field_number) =>
        {
            return Err(UploadContractError::InvalidRejectedField);
        }
        PutUploadStreamRejectReason::EmptyStream
            if detail.rejected_chunk_index != 0
                || detail.rejected_field_number != 0
                || detail.stream_identity_blake3 != empty_upload_put_stream_identity_blake3() =>
        {
            return Err(UploadContractError::InvalidEmptyStreamShape);
        }
        _ => {}
    }
    let mut writer =
        BoundedCanonicalWriter::new(u32::MAX).map_err(|_| UploadContractError::PreimageTooLarge)?;
    writer
        .raw(UPLOAD_REJECTED_DOMAIN)
        .and_then(|()| writer.text(&detail.protocol_revision))
        .and_then(|()| writer.u32(detail.reason as u32))
        .and_then(|()| writer.bytes(&detail.stream_identity_blake3))
        .and_then(|()| writer.u64(detail.rejected_chunk_index))
        .and_then(|()| writer.u32(detail.rejected_field_number))
        .map_err(|_| UploadContractError::PreimageTooLarge)?;
    Ok(writer.finish())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum UploadContractError {
    #[error("upload identity text maximum must be positive")]
    InvalidTextMaximum,
    #[error("upload identity contains noncanonical bounded text")]
    InvalidCanonicalText,
    #[error("upload request identity is not canonical UUIDv7")]
    InvalidUuidV7,
    #[error("upload fence must be positive")]
    InvalidUploadFence,
    #[error("upload canonical preimage is too large")]
    PreimageTooLarge,
    #[error("upload rejection field number is outside 1 through 8")]
    InvalidRejectedField,
    #[error("upload mismatch rejection requires identities to differ")]
    IdentitiesMatch,
    #[error("empty-stream upload rejection fields are inconsistent")]
    InvalidEmptyStreamShape,
    #[error("upload rejection detail digest does not match")]
    DigestMismatch,
}
