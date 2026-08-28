// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure canonical validation for continuity shadow-quota ownership.
//!
//! This module does not read a clock, database, spool, or provider. It validates the frozen
//! `object-store-continuity-quota-ownership-v1` record and returns detached canonical evidence for
//! later persistence and wire projection.

use std::fmt;

use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuotaOwnershipV1;
use thiserror::Error;

use crate::contract::BoundedCanonicalWriter;
use crate::contract::validate_canonical_text;

const DOMAIN: &[u8] = b"object-store-continuity-quota-ownership-v1\0";
pub const OBJECT_STORE_CONTINUITY_GLOBAL_SCOPE_ID: &str = "object-store-continuity-global-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContinuityQuotaOwnershipLimits {
    pub max_identity_bytes: u32,
    pub max_operation_quota_class_bytes: u32,
    pub max_policy_revision_bytes: u32,
    pub max_canonical_ownership_bytes: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalContinuityQuotaOwnership {
    value: ObjectStoreContinuityQuotaOwnershipV1,
    canonical_preimage: Vec<u8>,
    canonical_bytes: Vec<u8>,
    ownership_blake3: [u8; 32],
}

impl CanonicalContinuityQuotaOwnership {
    pub fn value(&self) -> &ObjectStoreContinuityQuotaOwnershipV1 {
        &self.value
    }

    pub fn canonical_preimage(&self) -> &[u8] {
        &self.canonical_preimage
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn ownership_blake3(&self) -> &[u8; 32] {
        &self.ownership_blake3
    }
}

impl fmt::Debug for CanonicalContinuityQuotaOwnership {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalContinuityQuotaOwnership")
            .field("value", &"[REDACTED]")
            .field("canonical_preimage", &"[REDACTED]")
            .field("canonical_bytes", &"[REDACTED]")
            .field("ownership_blake3", &"[REDACTED]")
            .finish()
    }
}

pub fn validate_and_encode_continuity_quota_ownership(
    input: &ObjectStoreContinuityQuotaOwnershipV1,
    limits: &ContinuityQuotaOwnershipLimits,
) -> Result<CanonicalContinuityQuotaOwnership, ContinuityQuotaOwnershipError> {
    validate_limits(limits)?;
    validate_canonical_text(
        &input.continuity_policy_revision,
        limits.max_policy_revision_bytes,
    )
    .map_err(|_| ContinuityQuotaOwnershipError::InvalidCanonicalText)?;
    validate_canonical_text(
        &input.operation_quota_class,
        limits.max_operation_quota_class_bytes,
    )
    .map_err(|_| ContinuityQuotaOwnershipError::InvalidCanonicalText)?;
    for value in [
        input.global_scope_id.as_str(),
        input.provider_boundary_id.as_str(),
        input.authenticated_cell_id.as_str(),
        input.authenticated_tenant_id.as_str(),
    ] {
        validate_canonical_text(value, limits.max_identity_bytes)
            .map_err(|_| ContinuityQuotaOwnershipError::InvalidCanonicalText)?;
    }
    if input.global_scope_id != OBJECT_STORE_CONTINUITY_GLOBAL_SCOPE_ID {
        return Err(ContinuityQuotaOwnershipError::InvalidGlobalScope);
    }
    let units = input
        .units
        .as_ref()
        .ok_or(ContinuityQuotaOwnershipError::MissingUnits)?;
    if units.bytes == 0 && units.rows == 0 && units.concurrency == 0 {
        return Err(ContinuityQuotaOwnershipError::EmptyUnits);
    }

    let mut writer = BoundedCanonicalWriter::new(limits.max_canonical_ownership_bytes)
        .map_err(|_| ContinuityQuotaOwnershipError::InvalidLimits)?;
    writer
        .raw(DOMAIN)
        .and_then(|()| writer.text(&input.continuity_policy_revision))
        .and_then(|()| writer.text(&input.operation_quota_class))
        .and_then(|()| writer.u64(units.bytes))
        .and_then(|()| writer.u64(units.rows))
        .and_then(|()| writer.u64(units.concurrency))
        .and_then(|()| writer.text(&input.global_scope_id))
        .and_then(|()| writer.text(&input.provider_boundary_id))
        .and_then(|()| writer.text(&input.authenticated_cell_id))
        .and_then(|()| writer.text(&input.authenticated_tenant_id))
        .map_err(|_| ContinuityQuotaOwnershipError::CanonicalTooLarge)?;
    let canonical_preimage = writer.finish();
    let canonical_size = canonical_preimage
        .len()
        .checked_add(32)
        .ok_or(ContinuityQuotaOwnershipError::CanonicalTooLarge)?;
    if canonical_size > limits.max_canonical_ownership_bytes as usize {
        return Err(ContinuityQuotaOwnershipError::CanonicalTooLarge);
    }
    let ownership_blake3 = *blake3::hash(&canonical_preimage).as_bytes();
    if !input.ownership_blake3.is_empty() && input.ownership_blake3.len() != 32 {
        return Err(ContinuityQuotaOwnershipError::InvalidDigest);
    }
    if !input.ownership_blake3.is_empty() && input.ownership_blake3.as_ref() != ownership_blake3 {
        return Err(ContinuityQuotaOwnershipError::DigestMismatch);
    }
    let mut canonical_bytes = Vec::with_capacity(canonical_size);
    canonical_bytes.extend_from_slice(&canonical_preimage);
    canonical_bytes.extend_from_slice(&ownership_blake3);
    let mut value = input.clone();
    value.ownership_blake3 = ownership_blake3.to_vec().into();

    Ok(CanonicalContinuityQuotaOwnership {
        value,
        canonical_preimage,
        canonical_bytes,
        ownership_blake3,
    })
}

fn validate_limits(
    limits: &ContinuityQuotaOwnershipLimits,
) -> Result<(), ContinuityQuotaOwnershipError> {
    if [
        limits.max_identity_bytes,
        limits.max_operation_quota_class_bytes,
        limits.max_policy_revision_bytes,
        limits.max_canonical_ownership_bytes,
    ]
    .contains(&0)
    {
        return Err(ContinuityQuotaOwnershipError::InvalidLimits);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ContinuityQuotaOwnershipError {
    #[error("continuity quota ownership limits must be positive")]
    InvalidLimits,
    #[error("continuity quota ownership text is not canonical or bounded")]
    InvalidCanonicalText,
    #[error("continuity quota ownership global scope is invalid")]
    InvalidGlobalScope,
    #[error("continuity quota ownership units are missing")]
    MissingUnits,
    #[error("continuity quota ownership units must not all be zero")]
    EmptyUnits,
    #[error("supplied continuity quota ownership digest must contain exactly 32 bytes")]
    InvalidDigest,
    #[error("continuity quota ownership digest does not match canonical fields")]
    DigestMismatch,
    #[error("canonical continuity quota ownership exceeds its byte bound")]
    CanonicalTooLarge,
}
