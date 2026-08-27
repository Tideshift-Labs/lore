// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure authority-slice validation for later stateful admission.
//!
//! These validators consume injected, already-authenticated state. They do not read a provider,
//! database, request stream, process clock, or payload and cannot grant admission or dispatch.

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use crate::AuthenticatedCaller;
use crate::auth::validate_id;

const MAX_REVISION_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedRequestContext {
    pub caller: AuthenticatedCaller,
    pub tenant_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellAllocationState {
    Prepared,
    Active,
    Sealed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentCellAllocation {
    pub provider_boundary_id: String,
    pub cell_id: String,
    pub allocation_revision: String,
    pub allocation_fence: u64,
    pub hard_expiry_unix_ms: i64,
    pub state: CellAllocationState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentCellAdmission {
    pub provider_boundary_id: String,
    pub cell_id: String,
    pub tenant_id: String,
    pub cell_admission_id: String,
    pub cell_admission_fence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmittedAuthority {
    pub protocol_revision: String,
    pub policy_revision: String,
    pub provider_boundary_id: String,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub allocation_revision: String,
    pub allocation_fence: u64,
    pub cell_admission_id: String,
    pub cell_admission_fence: u64,
}

pub fn validate_request_authority(
    submitted: &SubmittedAuthority,
    authenticated: &AuthenticatedRequestContext,
    current_allocation: &CurrentCellAllocation,
    current_admission: &CurrentCellAdmission,
    expected_protocol_revision: &str,
    expected_policy_revision: &str,
    database_now_unix_ms: i64,
) -> Result<(), AuthorityValidationError> {
    validate_inputs(
        submitted,
        authenticated,
        current_allocation,
        current_admission,
        expected_protocol_revision,
        expected_policy_revision,
        database_now_unix_ms,
    )?;

    if submitted.protocol_revision != expected_protocol_revision {
        return Err(AuthorityValidationError::ProtocolRevisionMismatch);
    }
    if submitted.policy_revision != expected_policy_revision {
        return Err(AuthorityValidationError::PolicyRevisionMismatch);
    }
    if submitted.provider_boundary_id != authenticated.caller.provider_boundary_id() {
        return Err(AuthorityValidationError::CallerBoundaryMismatch);
    }
    if !authenticated
        .caller
        .allows_cell(&submitted.authenticated_cell_id)
    {
        return Err(AuthorityValidationError::CallerCellNotAllowed);
    }
    if submitted.authenticated_tenant_id != authenticated.tenant_id {
        return Err(AuthorityValidationError::AuthenticatedTenantMismatch);
    }

    if current_allocation.provider_boundary_id != submitted.provider_boundary_id
        || current_allocation.cell_id != submitted.authenticated_cell_id
    {
        return Err(AuthorityValidationError::AllocationScopeMismatch);
    }
    if current_allocation.state != CellAllocationState::Active {
        return Err(AuthorityValidationError::AllocationNotActive);
    }
    if current_allocation.allocation_revision != submitted.allocation_revision {
        return Err(AuthorityValidationError::AllocationRevisionMismatch);
    }
    if current_allocation.allocation_fence != submitted.allocation_fence {
        return Err(AuthorityValidationError::AllocationFenceMismatch);
    }
    if database_now_unix_ms >= current_allocation.hard_expiry_unix_ms {
        return Err(AuthorityValidationError::AllocationExpired);
    }

    if current_admission.provider_boundary_id != submitted.provider_boundary_id
        || current_admission.cell_id != submitted.authenticated_cell_id
        || current_admission.tenant_id != authenticated.tenant_id
    {
        return Err(AuthorityValidationError::AdmissionScopeMismatch);
    }
    if current_admission.cell_admission_id != submitted.cell_admission_id {
        return Err(AuthorityValidationError::AdmissionIdMismatch);
    }
    if current_admission.cell_admission_fence != submitted.cell_admission_fence {
        return Err(AuthorityValidationError::AdmissionFenceMismatch);
    }

    Ok(())
}

fn validate_inputs(
    submitted: &SubmittedAuthority,
    authenticated: &AuthenticatedRequestContext,
    current_allocation: &CurrentCellAllocation,
    current_admission: &CurrentCellAdmission,
    expected_protocol_revision: &str,
    expected_policy_revision: &str,
    database_now_unix_ms: i64,
) -> Result<(), AuthorityValidationError> {
    for id in [
        &submitted.provider_boundary_id,
        &submitted.authenticated_cell_id,
        &submitted.authenticated_tenant_id,
        &submitted.cell_admission_id,
        &authenticated.tenant_id,
        &current_allocation.provider_boundary_id,
        &current_allocation.cell_id,
        &current_admission.provider_boundary_id,
        &current_admission.cell_id,
        &current_admission.tenant_id,
        &current_admission.cell_admission_id,
    ] {
        validate_id(id).map_err(|_| AuthorityValidationError::InvalidCanonicalInput)?;
    }
    for revision in [
        &submitted.protocol_revision,
        &submitted.policy_revision,
        &submitted.allocation_revision,
        &current_allocation.allocation_revision,
        expected_protocol_revision,
        expected_policy_revision,
    ] {
        validate_revision(revision)?;
    }
    if submitted.allocation_fence == 0
        || submitted.cell_admission_fence == 0
        || current_allocation.allocation_fence == 0
        || current_admission.cell_admission_fence == 0
        || current_allocation.hard_expiry_unix_ms < 0
        || database_now_unix_ms < 0
    {
        return Err(AuthorityValidationError::InvalidCanonicalInput);
    }
    Ok(())
}

fn validate_revision(value: &str) -> Result<(), AuthorityValidationError> {
    if value.is_empty()
        || value.len() > MAX_REVISION_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
        || value.nfc().ne(value.chars())
    {
        return Err(AuthorityValidationError::InvalidCanonicalInput);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AuthorityValidationError {
    #[error("object-dispatch authority input is not canonical")]
    InvalidCanonicalInput,
    #[error("object-dispatch protocol revision does not match authority")]
    ProtocolRevisionMismatch,
    #[error("object-dispatch policy revision does not match authority")]
    PolicyRevisionMismatch,
    #[error("object-dispatch caller boundary does not match authority")]
    CallerBoundaryMismatch,
    #[error("object-dispatch caller is not authorized for the requested cell")]
    CallerCellNotAllowed,
    #[error("object-dispatch authenticated tenant does not match the request")]
    AuthenticatedTenantMismatch,
    #[error("object-dispatch provider allocation scope does not match the request")]
    AllocationScopeMismatch,
    #[error("object-dispatch provider allocation is not active")]
    AllocationNotActive,
    #[error("object-dispatch provider allocation revision does not match the request")]
    AllocationRevisionMismatch,
    #[error("object-dispatch provider allocation fence does not match the request")]
    AllocationFenceMismatch,
    #[error("object-dispatch provider allocation is expired")]
    AllocationExpired,
    #[error("object-dispatch cell admission scope does not match the request")]
    AdmissionScopeMismatch,
    #[error("object-dispatch cell admission ID does not match the request")]
    AdmissionIdMismatch,
    #[error("object-dispatch cell admission fence does not match the request")]
    AdmissionFenceMismatch,
}
