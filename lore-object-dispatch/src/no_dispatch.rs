// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure, unwired no-dispatch proof contract.

use std::fmt;

use thiserror::Error;

use crate::contract::BoundedCanonicalWriter;
use crate::contract::canonical_uuid_v7_timestamp;

const NO_DISPATCH_PROOF_DOMAIN: &[u8] = b"object-store-no-dispatch-proof-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NoDispatchReason {
    CellAdmissionRejected = 1,
    AuthorityCancelledBeforeSend = 2,
    DispatcherProvedNotSent = 3,
    PreparedTtlExpired = 4,
    SdkConstructionFailed = 5,
    LocalValidationFailed = 6,
    RequestDeadlineExpired = 7,
    AuthorityLostBeforeDispatch = 8,
}

impl TryFrom<u32> for NoDispatchReason {
    type Error = NoDispatchProofError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::CellAdmissionRejected),
            2 => Ok(Self::AuthorityCancelledBeforeSend),
            3 => Ok(Self::DispatcherProvedNotSent),
            4 => Ok(Self::PreparedTtlExpired),
            5 => Ok(Self::SdkConstructionFailed),
            6 => Ok(Self::LocalValidationFailed),
            7 => Ok(Self::RequestDeadlineExpired),
            8 => Ok(Self::AuthorityLostBeforeDispatch),
            _ => Err(NoDispatchProofError::InvalidReason),
        }
    }
}

/// The fields a no-dispatch proof commits to.
///
/// **Closed by CD-6 (INV-EJ B1's last unbound edge).** The proof commits to the logical request it
/// describes, so it attests that *this* request resolved without dispatch rather than that some
/// request did, and
/// [`crate::provider_client::ProviderAttemptLedger::record_no_dispatch`] can refuse a proof minted
/// for a different request than its ledger is bound to. The identity is inside the canonical
/// preimage rather than beside it: a caller-supplied identity checked against a proof that does not
/// commit to one restates the caller's claim instead of binding the record.
///
/// `logical_request_id` is validated for canonicality only. It deliberately carries no ordering
/// constraint against `committed_at_unix_ms`: a request necessarily predates the proof that closes
/// it, but the two clocks are not the same authority's, so an ordering check here would reject
/// valid records rather than catch invalid ones. `proof_id`'s timestamp equality below is a
/// different claim — that one is self-consistency within a single minted value.
#[derive(Clone, PartialEq, Eq)]
pub struct NoDispatchProofFields {
    pub reason: NoDispatchReason,
    pub logical_request_id: String,
    pub proof_id: String,
    pub proof_fence: u64,
    pub committed_at_unix_ms: i64,
    pub authority_epoch: u64,
}

impl fmt::Debug for NoDispatchProofFields {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoDispatchProofFields")
            .field("reason", &self.reason)
            .field("logical_request_id", &"[REDACTED]")
            .field("proof_id", &"[REDACTED]")
            .field("proof_fence", &self.proof_fence)
            .field("committed_at_unix_ms", &self.committed_at_unix_ms)
            .field("authority_epoch", &self.authority_epoch)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NoDispatchProof {
    pub fields: NoDispatchProofFields,
    pub proof_blake3: [u8; 32],
}

impl fmt::Debug for NoDispatchProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoDispatchProof")
            .field("fields", &self.fields)
            .field("proof_blake3", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalNoDispatchProof {
    proof: NoDispatchProof,
    canonical_preimage: Vec<u8>,
}

impl CanonicalNoDispatchProof {
    pub fn proof(&self) -> &NoDispatchProof {
        &self.proof
    }

    pub fn canonical_preimage(&self) -> &[u8] {
        &self.canonical_preimage
    }
}

impl fmt::Debug for CanonicalNoDispatchProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalNoDispatchProof")
            .field("proof", &self.proof)
            .field("canonical_preimage", &"[REDACTED]")
            .finish()
    }
}

pub fn build_no_dispatch_proof(
    fields: NoDispatchProofFields,
    max_preimage_bytes: u32,
) -> Result<CanonicalNoDispatchProof, NoDispatchProofError> {
    let canonical_preimage = canonical_preimage(&fields, max_preimage_bytes)?;
    let proof_blake3 = *blake3::hash(&canonical_preimage).as_bytes();
    Ok(CanonicalNoDispatchProof {
        proof: NoDispatchProof {
            fields,
            proof_blake3,
        },
        canonical_preimage,
    })
}

pub fn validate_no_dispatch_proof(
    proof: &NoDispatchProof,
    max_preimage_bytes: u32,
) -> Result<CanonicalNoDispatchProof, NoDispatchProofError> {
    let canonical_preimage = canonical_preimage(&proof.fields, max_preimage_bytes)?;
    let expected = *blake3::hash(&canonical_preimage).as_bytes();
    if proof.proof_blake3 != expected {
        return Err(NoDispatchProofError::DigestMismatch);
    }
    Ok(CanonicalNoDispatchProof {
        proof: proof.clone(),
        canonical_preimage,
    })
}

fn canonical_preimage(
    fields: &NoDispatchProofFields,
    max_preimage_bytes: u32,
) -> Result<Vec<u8>, NoDispatchProofError> {
    if fields.proof_fence == 0 {
        return Err(NoDispatchProofError::InvalidProofFence);
    }
    if fields.authority_epoch == 0 {
        return Err(NoDispatchProofError::InvalidAuthorityEpoch);
    }
    let committed_at = u64::try_from(fields.committed_at_unix_ms)
        .map_err(|_| NoDispatchProofError::InvalidCommitTime)?;
    let proof_timestamp = canonical_uuid_v7_timestamp(&fields.proof_id)
        .map_err(|_| NoDispatchProofError::InvalidProofId)?;
    if proof_timestamp != committed_at {
        return Err(NoDispatchProofError::ProofTimestampMismatch);
    }
    // Canonicality is the whole bound here. A canonical UUIDv7 is fixed-width at 36 bytes, so
    // the separate identity byte-length check that `request_state_wire::no_dispatch_child`
    // applies to its own inputs cannot fire under any validated limit (`max_identity_bytes` is
    // never below 36), and the two writers still agree byte for byte. That is a statement about
    // the validated limits, not an absolute one.
    canonical_uuid_v7_timestamp(&fields.logical_request_id)
        .map_err(|_| NoDispatchProofError::InvalidLogicalRequestId)?;
    let mut writer = BoundedCanonicalWriter::new(max_preimage_bytes)
        .map_err(|_| NoDispatchProofError::InvalidMaximum)?;
    writer
        .raw(NO_DISPATCH_PROOF_DOMAIN)
        .and_then(|()| writer.u32(fields.reason as u32))
        .and_then(|()| writer.text(&fields.logical_request_id))
        .and_then(|()| writer.text(&fields.proof_id))
        .and_then(|()| writer.u64(fields.proof_fence))
        .and_then(|()| writer.u64(committed_at))
        .and_then(|()| writer.u64(fields.authority_epoch))
        .map_err(|_| NoDispatchProofError::PreimageTooLarge)?;
    Ok(writer.finish())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum NoDispatchProofError {
    #[error("no-dispatch reason is unknown or unspecified")]
    InvalidReason,
    #[error("no-dispatch proof ID is not canonical UUIDv7")]
    InvalidProofId,
    #[error("no-dispatch logical request ID is not canonical UUIDv7")]
    InvalidLogicalRequestId,
    #[error("no-dispatch proof fence must be positive")]
    InvalidProofFence,
    #[error("no-dispatch proof commit time is outside nonnegative i64")]
    InvalidCommitTime,
    #[error("no-dispatch proof UUID timestamp does not match commit time")]
    ProofTimestampMismatch,
    #[error("no-dispatch authority epoch must be positive")]
    InvalidAuthorityEpoch,
    #[error("no-dispatch proof preimage maximum must be positive")]
    InvalidMaximum,
    #[error("no-dispatch proof preimage exceeds its bound")]
    PreimageTooLarge,
    #[error("no-dispatch proof digest does not match")]
    DigestMismatch,
}
