// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure, unwired ReservePut admission and evidence-presence state algebra.
//!
//! Evidence references prove only exact 32-byte record identities. They do not decode or authorize
//! complete ACK, closure, purge-receipt, spool, quota, filesystem, or database effects.

use thiserror::Error;

use crate::no_dispatch::NoDispatchProof;
use crate::no_dispatch::NoDispatchReason;
use crate::no_dispatch::validate_no_dispatch_proof;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservePutAdmissionInput {
    pub database_now_unix_ms: i64,
    pub reservation_deadline_unix_ms: i64,
    pub allocation_hard_expiry_unix_ms: Option<i64>,
    pub current_allocation_hard_expiry_unix_ms: i64,
    pub prepared_ttl_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservePutAdmissionSnapshot {
    pub admission_clock_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub reservation_deadline_unix_ms: i64,
    pub allocation_hard_expiry_unix_ms: i64,
    pub prepared_ttl_ms: i64,
}

pub fn calculate_reserve_put_admission(
    input: ReservePutAdmissionInput,
) -> Result<ReservePutAdmissionSnapshot, ReservePutError> {
    let supplied_expiry = input
        .allocation_hard_expiry_unix_ms
        .ok_or(ReservePutError::MissingAllocationExpiry)?;
    if input.database_now_unix_ms < 0
        || input.reservation_deadline_unix_ms < 0
        || supplied_expiry < 0
        || input.current_allocation_hard_expiry_unix_ms < 0
        || input.prepared_ttl_ms < 0
    {
        return Err(ReservePutError::NegativeTime);
    }
    if input.reservation_deadline_unix_ms <= input.database_now_unix_ms {
        return Err(ReservePutError::DeadlineNotFuture);
    }
    if supplied_expiry <= input.database_now_unix_ms
        || input.current_allocation_hard_expiry_unix_ms <= input.database_now_unix_ms
    {
        return Err(ReservePutError::AllocationExpired);
    }
    if supplied_expiry != input.current_allocation_hard_expiry_unix_ms {
        return Err(ReservePutError::AllocationExpiryMismatch);
    }
    if input.prepared_ttl_ms == 0 {
        return Err(ReservePutError::InvalidPreparedTtl);
    }
    let prepared_cap = input
        .database_now_unix_ms
        .checked_add(input.prepared_ttl_ms)
        .ok_or(ReservePutError::ArithmeticOverflow)?;
    let expires_at_unix_ms = input
        .reservation_deadline_unix_ms
        .min(prepared_cap)
        .min(supplied_expiry);
    if expires_at_unix_ms <= input.database_now_unix_ms {
        return Err(ReservePutError::ComputedExpiryNotFuture);
    }
    Ok(ReservePutAdmissionSnapshot {
        admission_clock_unix_ms: input.database_now_unix_ms,
        expires_at_unix_ms,
        reservation_deadline_unix_ms: input.reservation_deadline_unix_ms,
        allocation_hard_expiry_unix_ms: supplied_expiry,
        prepared_ttl_ms: input.prepared_ttl_ms,
    })
}

pub fn validate_persisted_reserve_put_admission(
    snapshot: ReservePutAdmissionSnapshot,
) -> Result<ReservePutAdmissionSnapshot, ReservePutError> {
    let recalculated = calculate_reserve_put_admission(ReservePutAdmissionInput {
        database_now_unix_ms: snapshot.admission_clock_unix_ms,
        reservation_deadline_unix_ms: snapshot.reservation_deadline_unix_ms,
        allocation_hard_expiry_unix_ms: Some(snapshot.allocation_hard_expiry_unix_ms),
        current_allocation_hard_expiry_unix_ms: snapshot.allocation_hard_expiry_unix_ms,
        prepared_ttl_ms: snapshot.prepared_ttl_ms,
    })?;
    if recalculated.expires_at_unix_ms != snapshot.expires_at_unix_ms {
        return Err(ReservePutError::PersistedExpiryMismatch);
    }
    Ok(snapshot)
}

pub fn is_reserve_put_cleanup_eligible(
    snapshot: ReservePutAdmissionSnapshot,
    database_now_unix_ms: i64,
) -> Result<bool, ReservePutError> {
    let validated = validate_persisted_reserve_put_admission(snapshot)?;
    if database_now_unix_ms < 0 {
        return Err(ReservePutError::NegativeTime);
    }
    Ok(database_now_unix_ms >= validated.expires_at_unix_ms)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservePutState {
    Reserved,
    SpoolReady,
    PreparedExpired,
    Closed,
    PayloadDisposed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectStoreQuotaUnits {
    pub bytes: u64,
    pub rows: u64,
    pub concurrency: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EvidenceReference {
    record_blake3: [u8; 32],
}

impl EvidenceReference {
    pub fn from_slice(record_blake3: &[u8]) -> Result<Self, ReservePutError> {
        let record_blake3 = <[u8; 32]>::try_from(record_blake3)
            .map_err(|_| ReservePutError::InvalidEvidenceDigest)?;
        Ok(Self { record_blake3 })
    }

    pub fn record_blake3(&self) -> &[u8; 32] {
        &self.record_blake3
    }
}

impl std::fmt::Debug for EvidenceReference {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceReference")
            .field("record_blake3", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservePutStateSnapshot {
    pub state: ReservePutState,
    pub admission: ReservePutAdmissionSnapshot,
    pub reserved_quota: ObjectStoreQuotaUnits,
    pub spool_ready: Option<EvidenceReference>,
    pub closure: Option<EvidenceReference>,
    pub no_dispatch_proof: Option<NoDispatchProof>,
    pub payload_release_receipt: Option<EvidenceReference>,
}

pub fn validate_reserve_put_state_snapshot(
    snapshot: &ReservePutStateSnapshot,
    max_no_dispatch_proof_preimage_bytes: u32,
) -> Result<ReservePutStateSnapshot, ReservePutError> {
    validate_persisted_reserve_put_admission(snapshot.admission)?;
    if snapshot.reserved_quota.bytes == 0
        && snapshot.reserved_quota.rows == 0
        && snapshot.reserved_quota.concurrency == 0
    {
        return Err(ReservePutError::EmptyReservedQuota);
    }
    if max_no_dispatch_proof_preimage_bytes == 0 {
        return Err(ReservePutError::InvalidNoDispatchMaximum);
    }
    if let Some(proof) = &snapshot.no_dispatch_proof {
        validate_no_dispatch_proof(proof, max_no_dispatch_proof_preimage_bytes)
            .map_err(|_| ReservePutError::InvalidNoDispatchProof)?;
    }

    let spool = snapshot.spool_ready.is_some();
    let closure = snapshot.closure.is_some();
    let proof = snapshot.no_dispatch_proof.as_ref();
    let release = snapshot.payload_release_receipt.is_some();
    let valid = match snapshot.state {
        ReservePutState::Reserved => !spool && !closure && proof.is_none() && !release,
        ReservePutState::SpoolReady => spool && !closure && proof.is_none() && !release,
        ReservePutState::PreparedExpired => {
            !spool
                && !closure
                && proof.is_some_and(|proof| {
                    proof.fields.reason == NoDispatchReason::PreparedTtlExpired
                })
                && release
        }
        ReservePutState::Closed => !spool && closure && proof.is_none() && !release,
        ReservePutState::PayloadDisposed => !spool && release && (closure ^ proof.is_some()),
    };
    if !valid {
        return Err(ReservePutError::InvalidStateEvidence);
    }
    Ok(snapshot.clone())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ReservePutError {
    #[error("ReservePut allocation hard expiry is required")]
    MissingAllocationExpiry,
    #[error("ReservePut time value is outside nonnegative i64")]
    NegativeTime,
    #[error("ReservePut reservation deadline is not in the future")]
    DeadlineNotFuture,
    #[error("ReservePut allocation authority is expired")]
    AllocationExpired,
    #[error("ReservePut allocation hard expiry does not match current authority")]
    AllocationExpiryMismatch,
    #[error("ReservePut prepared TTL must be positive")]
    InvalidPreparedTtl,
    #[error("ReservePut prepared expiry addition overflows i64")]
    ArithmeticOverflow,
    #[error("ReservePut computed expiry is not in the future")]
    ComputedExpiryNotFuture,
    #[error("persisted ReservePut expiry does not match its original inputs")]
    PersistedExpiryMismatch,
    #[error("ReservePut reserved quota must not be empty")]
    EmptyReservedQuota,
    #[error("ReservePut evidence digest must contain exactly 32 bytes")]
    InvalidEvidenceDigest,
    #[error("ReservePut no-dispatch proof maximum must be positive")]
    InvalidNoDispatchMaximum,
    #[error("ReservePut no-dispatch proof is invalid")]
    InvalidNoDispatchProof,
    #[error("ReservePut state and evidence are inconsistent")]
    InvalidStateEvidence,
}
