// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure canonical wire records for continuity quarantine and adjudication.
//!
//! This module performs no provider, database, clock, or runtime I/O. It only validates generated
//! protobuf values against the frozen WP-121 contract and produces detached canonical evidence.

use std::fmt;

use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicatedV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicationKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityAdjudicationProofV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityIntentKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuarantineReasonV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuarantinedV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuotaOwnershipV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuotaReleaseReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::object_store_continuity_adjudicated_v1;
use lore_proto::lore::object_dispatch::v1::object_store_continuity_quarantined_v1;
use thiserror::Error;

use crate::continuity_quota::ContinuityQuotaOwnershipError;
use crate::continuity_quota::ContinuityQuotaOwnershipLimits;
use crate::continuity_quota::validate_and_encode_continuity_quota_ownership;
use crate::contract::BoundedCanonicalWriter;
use crate::contract::canonical_uuid_v7_timestamp;
use crate::contract::validate_canonical_text;

const QUARANTINED_DOMAIN: &[u8] = b"object-store-continuity-quarantined-v1\0";
const PROOF_DOMAIN: &[u8] = b"object-store-continuity-adjudication-proof-v1\0";
const RELEASE_DOMAIN: &[u8] = b"object-store-continuity-quota-release-v1\0";
const ADJUDICATED_DOMAIN: &[u8] = b"object-store-continuity-adjudicated-v1\0";
const QUOTA_UNITS_DOMAIN: &[u8] = b"object-store-quota-units-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContinuityWireLimits {
    pub max_identity_bytes: u32,
    pub max_canonical_row_bytes: u32,
}

macro_rules! canonical_record {
    ($name:ident, $value:ty, $digest_method:ident) => {
        #[derive(Clone, PartialEq, Eq)]
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
    CanonicalContinuityQuarantined,
    ObjectStoreContinuityQuarantinedV1,
    detail_blake3
);
canonical_record!(
    CanonicalContinuityAdjudicationProof,
    ObjectStoreContinuityAdjudicationProofV1,
    proof_blake3
);
canonical_record!(
    CanonicalContinuityQuotaReleaseReceipt,
    ObjectStoreContinuityQuotaReleaseReceiptV1,
    receipt_blake3
);
canonical_record!(
    CanonicalContinuityAdjudicated,
    ObjectStoreContinuityAdjudicatedV1,
    detail_blake3
);

fn validate_limits(limits: &ContinuityWireLimits) -> Result<(), ContinuityWireError> {
    if limits.max_identity_bytes == 0 || limits.max_canonical_row_bytes == 0 {
        return Err(ContinuityWireError::InvalidLimits);
    }
    Ok(())
}

fn ownership_limits(limits: &ContinuityWireLimits) -> ContinuityQuotaOwnershipLimits {
    ContinuityQuotaOwnershipLimits {
        max_identity_bytes: limits.max_identity_bytes,
        max_operation_quota_class_bytes: limits.max_identity_bytes,
        max_policy_revision_bytes: limits.max_identity_bytes,
        max_canonical_ownership_bytes: limits.max_canonical_row_bytes,
    }
}

fn text(value: &str, limits: &ContinuityWireLimits) -> Result<(), ContinuityWireError> {
    validate_canonical_text(value, limits.max_identity_bytes)
        .map_err(|_| ContinuityWireError::InvalidCanonicalText)
}

fn uuid(value: &str) -> Result<(), ContinuityWireError> {
    canonical_uuid_v7_timestamp(value)
        .map(|_| ())
        .map_err(|_| ContinuityWireError::InvalidUuidV7)
}

fn positive(value: u64) -> Result<u64, ContinuityWireError> {
    if value == 0 {
        Err(ContinuityWireError::NonPositiveAuthority)
    } else {
        Ok(value)
    }
}

fn nonnegative(value: i64) -> Result<u64, ContinuityWireError> {
    u64::try_from(value).map_err(|_| ContinuityWireError::NegativeTime)
}

fn exact_digest(value: &[u8]) -> Result<[u8; 32], ContinuityWireError> {
    value
        .try_into()
        .map_err(|_| ContinuityWireError::InvalidDigest)
}

fn finish(
    preimage: &[u8],
    supplied: &[u8],
    limits: &ContinuityWireLimits,
) -> Result<(Vec<u8>, [u8; 32]), ContinuityWireError> {
    let digest = *blake3::hash(preimage).as_bytes();
    if !supplied.is_empty() && supplied.len() != 32 {
        return Err(ContinuityWireError::InvalidDigest);
    }
    if !supplied.is_empty() && supplied != digest {
        return Err(ContinuityWireError::DigestMismatch);
    }
    let size = preimage
        .len()
        .checked_add(32)
        .ok_or(ContinuityWireError::CanonicalTooLarge)?;
    if size > limits.max_canonical_row_bytes as usize {
        return Err(ContinuityWireError::CanonicalTooLarge);
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(preimage);
    bytes.extend_from_slice(&digest);
    Ok((bytes, digest))
}

fn writer(limits: &ContinuityWireLimits) -> Result<BoundedCanonicalWriter, ContinuityWireError> {
    BoundedCanonicalWriter::new(limits.max_canonical_row_bytes)
        .map_err(|_| ContinuityWireError::InvalidLimits)
}

struct ContinuityIdentity<'a> {
    protocol_revision: &'a str,
    provider_boundary_id: &'a str,
    authenticated_cell_id: &'a str,
    authenticated_tenant_id: &'a str,
    logical_request_id: &'a str,
    attempt_id: &'a str,
    continuity_token_id: &'a str,
}

fn write_identity(
    writer: &mut BoundedCanonicalWriter,
    identity: &ContinuityIdentity<'_>,
    limits: &ContinuityWireLimits,
) -> Result<(), ContinuityWireError> {
    for value in [
        identity.protocol_revision,
        identity.provider_boundary_id,
        identity.authenticated_cell_id,
        identity.authenticated_tenant_id,
        identity.logical_request_id,
        identity.attempt_id,
        identity.continuity_token_id,
    ] {
        text(value, limits)?;
        writer
            .text(value)
            .map_err(|_| ContinuityWireError::CanonicalTooLarge)?;
    }
    uuid(identity.logical_request_id)?;
    uuid(identity.attempt_id)?;
    uuid(identity.continuity_token_id)?;
    Ok(())
}

fn fingerprint_quarantined(
    input: &ObjectStoreContinuityQuarantinedV1,
) -> Result<(u32, [u8; 32]), ContinuityWireError> {
    match (
        ObjectStoreContinuityIntentKindV1::try_from(input.intent_kind),
        input.fingerprint.as_ref(),
    ) {
        (
            Ok(ObjectStoreContinuityIntentKindV1::ObjectStoreContinuityIntentKindUuidAdmission),
            Some(object_store_continuity_quarantined_v1::Fingerprint::PutReservationFingerprint(
                digest,
            )),
        ) => Ok((11, exact_digest(digest)?)),
        (
            Ok(ObjectStoreContinuityIntentKindV1::ObjectStoreContinuityIntentKindDispatchCas),
            Some(
                object_store_continuity_quarantined_v1::Fingerprint::CanonicalDescriptorFingerprint(
                    digest,
                ),
            ),
        ) => Ok((12, exact_digest(digest)?)),
        _ => Err(ContinuityWireError::InvalidFingerprint),
    }
}

fn fingerprint_adjudicated(
    input: &ObjectStoreContinuityAdjudicatedV1,
) -> Result<(u32, [u8; 32]), ContinuityWireError> {
    match (
        ObjectStoreContinuityIntentKindV1::try_from(input.intent_kind),
        input.fingerprint.as_ref(),
    ) {
        (
            Ok(ObjectStoreContinuityIntentKindV1::ObjectStoreContinuityIntentKindUuidAdmission),
            Some(object_store_continuity_adjudicated_v1::Fingerprint::PutReservationFingerprint(
                digest,
            )),
        ) => Ok((11, exact_digest(digest)?)),
        (
            Ok(ObjectStoreContinuityIntentKindV1::ObjectStoreContinuityIntentKindDispatchCas),
            Some(
                object_store_continuity_adjudicated_v1::Fingerprint::CanonicalDescriptorFingerprint(
                    digest,
                ),
            ),
        ) => Ok((12, exact_digest(digest)?)),
        _ => Err(ContinuityWireError::InvalidFingerprint),
    }
}

fn validate_ownership(
    ownership: &Option<ObjectStoreContinuityQuotaOwnershipV1>,
    provider_boundary_id: &str,
    authenticated_cell_id: &str,
    authenticated_tenant_id: &str,
    limits: &ContinuityWireLimits,
) -> Result<crate::CanonicalContinuityQuotaOwnership, ContinuityWireError> {
    let ownership = ownership
        .as_ref()
        .ok_or(ContinuityWireError::MissingChild)?;
    let encoded =
        validate_and_encode_continuity_quota_ownership(ownership, &ownership_limits(limits))?;
    let value = encoded.value();
    if value.provider_boundary_id != provider_boundary_id
        || value.authenticated_cell_id != authenticated_cell_id
        || value.authenticated_tenant_id != authenticated_tenant_id
    {
        return Err(ContinuityWireError::OwnershipIdentityMismatch);
    }
    Ok(encoded)
}

pub fn validate_and_encode_continuity_quarantined(
    input: &ObjectStoreContinuityQuarantinedV1,
    limits: &ContinuityWireLimits,
) -> Result<CanonicalContinuityQuarantined, ContinuityWireError> {
    validate_limits(limits)?;
    if !matches!(
        ObjectStoreContinuityQuarantineReasonV1::try_from(input.reason),
        Ok(
            ObjectStoreContinuityQuarantineReasonV1::ObjectStoreContinuityQuarantineReasonIncompleteIntent
                | ObjectStoreContinuityQuarantineReasonV1::ObjectStoreContinuityQuarantineReasonLocalBindingMissing
                | ObjectStoreContinuityQuarantineReasonV1::ObjectStoreContinuityQuarantineReasonDispatchOutcomeUnknown
                | ObjectStoreContinuityQuarantineReasonV1::ObjectStoreContinuityQuarantineReasonRestoreMismatch
        )
    ) {
        return Err(ContinuityWireError::InvalidEnum);
    }
    if !input.quota_bearing {
        return Err(ContinuityWireError::QuotaBearingRequired);
    }
    let quarantined_at = nonnegative(input.quarantined_at_unix_ms)?;
    let retain_until = nonnegative(input.retain_until_unix_ms)?;
    if retain_until < quarantined_at {
        return Err(ContinuityWireError::InvalidTimeOrder);
    }
    let (fingerprint_tag, fingerprint) = fingerprint_quarantined(input)?;
    let ownership = validate_ownership(
        &input.quota_ownership,
        &input.provider_boundary_id,
        &input.authenticated_cell_id,
        &input.authenticated_tenant_id,
        limits,
    )?;

    let mut output = writer(limits)?;
    output
        .raw(QUARANTINED_DOMAIN)
        .map_err(|_| ContinuityWireError::CanonicalTooLarge)?;
    write_identity(
        &mut output,
        &ContinuityIdentity {
            protocol_revision: &input.protocol_revision,
            provider_boundary_id: &input.provider_boundary_id,
            authenticated_cell_id: &input.authenticated_cell_id,
            authenticated_tenant_id: &input.authenticated_tenant_id,
            logical_request_id: &input.logical_request_id,
            attempt_id: &input.attempt_id,
            continuity_token_id: &input.continuity_token_id,
        },
        limits,
    )?;
    let authority_epoch = positive(input.authority_epoch)?;
    let continuity_seq = positive(input.continuity_seq)?;
    output
        .u64(authority_epoch)
        .and_then(|()| output.u64(continuity_seq))
        .and_then(|()| output.u32(input.intent_kind as u32))
        .and_then(|()| output.u32(fingerprint_tag))
        .and_then(|()| output.raw(&fingerprint))
        .and_then(|()| output.u32(input.reason as u32))
        .and_then(|()| output.u64(quarantined_at))
        .and_then(|()| output.u64(retain_until))
        .and_then(|()| output.u8(1))
        .and_then(|()| output.bytes(ownership.canonical_bytes()))
        .map_err(|_| ContinuityWireError::CanonicalTooLarge)?;
    let canonical_preimage = output.finish();
    let (canonical_bytes, digest) = finish(&canonical_preimage, &input.detail_blake3, limits)?;
    let mut value = input.clone();
    value.detail_blake3 = digest.to_vec().into();
    value.quota_ownership = Some(ownership.value().clone());
    Ok(CanonicalContinuityQuarantined {
        value,
        canonical_preimage,
        canonical_bytes,
        digest,
    })
}

pub fn validate_and_encode_continuity_adjudication_proof(
    input: &ObjectStoreContinuityAdjudicationProofV1,
    limits: &ContinuityWireLimits,
) -> Result<CanonicalContinuityAdjudicationProof, ContinuityWireError> {
    validate_limits(limits)?;
    uuid(&input.proof_id)?;
    text(&input.proof_id, limits)?;
    text(&input.provider_credential_revision, limits)?;
    let kind = ObjectStoreContinuityAdjudicationKindV1::try_from(input.adjudication_kind)
        .map_err(|_| ContinuityWireError::InvalidEnum)?;
    if !matches!(
        kind,
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect
            | ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch
    ) {
        return Err(ContinuityWireError::InvalidEnum);
    }
    let evidence = match (&kind, &input.provider_no_dispatch_evidence_blake3) {
        (
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect,
            None,
        ) => None,
        (
            ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch,
            Some(value),
        ) => Some(exact_digest(value)?),
        _ => return Err(ContinuityWireError::InvalidEvidencePresence),
    };
    let external = exact_digest(&input.external_row_blake3)?;
    let local = exact_digest(&input.local_quarantine_blake3)?;
    let committed = nonnegative(input.committed_at_unix_ms)?;
    let mut output = writer(limits)?;
    let authority_epoch = positive(input.authority_epoch)?;
    let continuity_seq = positive(input.continuity_seq)?;
    let adjudication_fence = positive(input.adjudication_fence)?;
    output
        .raw(PROOF_DOMAIN)
        .and_then(|()| output.text(&input.proof_id))
        .and_then(|()| output.u32(input.adjudication_kind as u32))
        .and_then(|()| output.raw(&external))
        .and_then(|()| output.raw(&local))
        .and_then(|()| output.u64(authority_epoch))
        .and_then(|()| output.u64(continuity_seq))
        .and_then(|()| output.u64(adjudication_fence))
        .and_then(|()| output.text(&input.provider_credential_revision))
        .and_then(|()| output.u8(u8::from(evidence.is_some())))
        .and_then(|()| match evidence {
            Some(value) => output.raw(&value),
            None => Ok(()),
        })
        .and_then(|()| output.u64(committed))
        .map_err(|_| ContinuityWireError::CanonicalTooLarge)?;
    let canonical_preimage = output.finish();
    let (canonical_bytes, digest) = finish(&canonical_preimage, &input.proof_blake3, limits)?;
    let mut value = input.clone();
    value.proof_blake3 = digest.to_vec().into();
    Ok(CanonicalContinuityAdjudicationProof {
        value,
        canonical_preimage,
        canonical_bytes,
        digest,
    })
}

fn quota_units(
    value: &Option<ObjectStoreQuotaUnitsV1>,
) -> Result<&ObjectStoreQuotaUnitsV1, ContinuityWireError> {
    value.as_ref().ok_or(ContinuityWireError::MissingChild)
}

fn write_quota_units(
    output: &mut BoundedCanonicalWriter,
    value: &ObjectStoreQuotaUnitsV1,
    limits: &ContinuityWireLimits,
) -> Result<(), ContinuityWireError> {
    let mut child = writer(limits)?;
    child
        .raw(QUOTA_UNITS_DOMAIN)
        .and_then(|()| child.u64(value.bytes))
        .and_then(|()| child.u64(value.rows))
        .and_then(|()| child.u64(value.concurrency))
        .map_err(|_| ContinuityWireError::CanonicalTooLarge)?;
    let preimage = child.finish();
    let (bytes, _) = finish(&preimage, &[], limits)?;
    output
        .bytes(&bytes)
        .map_err(|_| ContinuityWireError::CanonicalTooLarge)
}

pub fn validate_and_encode_continuity_quota_release_receipt(
    input: &ObjectStoreContinuityQuotaReleaseReceiptV1,
    limits: &ContinuityWireLimits,
) -> Result<CanonicalContinuityQuotaReleaseReceipt, ContinuityWireError> {
    validate_limits(limits)?;
    uuid(&input.release_id)?;
    text(&input.release_id, limits)?;
    let kind = ObjectStoreContinuityAdjudicationKindV1::try_from(input.adjudication_kind)
        .map_err(|_| ContinuityWireError::InvalidEnum)?;
    if !matches!(
        kind,
        ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoLocalEffect
            | ObjectStoreContinuityAdjudicationKindV1::ObjectStoreContinuityAdjudicationKindNoDispatch
    ) {
        return Err(ContinuityWireError::InvalidEnum);
    }
    if input.provider_authority_refunded {
        return Err(ContinuityWireError::ProviderRefundForbidden);
    }
    let put = quota_units(&input.released_put_spool)?;
    let result = quota_units(&input.released_result_spool)?;
    let metadata = quota_units(&input.released_retained_metadata)?;
    if [put, result, metadata]
        .iter()
        .all(|units| units.bytes == 0 && units.rows == 0 && units.concurrency == 0)
    {
        return Err(ContinuityWireError::EmptyRelease);
    }
    let released_at = nonnegative(input.released_at_unix_ms)?;
    let quota_revision = positive(input.quota_revision)?;
    let mut output = writer(limits)?;
    output
        .raw(RELEASE_DOMAIN)
        .and_then(|()| output.text(&input.release_id))
        .and_then(|()| output.u32(input.adjudication_kind as u32))
        .map_err(|_| ContinuityWireError::CanonicalTooLarge)?;
    write_quota_units(&mut output, put, limits)?;
    write_quota_units(&mut output, result, limits)?;
    write_quota_units(&mut output, metadata, limits)?;
    output
        .u8(0)
        .and_then(|()| output.u64(released_at))
        .and_then(|()| output.u64(quota_revision))
        .map_err(|_| ContinuityWireError::CanonicalTooLarge)?;
    let canonical_preimage = output.finish();
    let (canonical_bytes, digest) = finish(&canonical_preimage, &input.receipt_blake3, limits)?;
    let mut value = input.clone();
    value.receipt_blake3 = digest.to_vec().into();
    Ok(CanonicalContinuityQuotaReleaseReceipt {
        value,
        canonical_preimage,
        canonical_bytes,
        digest,
    })
}

fn release_matches_ownership(
    ownership: &ObjectStoreQuotaUnitsV1,
    release: &ObjectStoreContinuityQuotaReleaseReceiptV1,
) -> Result<bool, ContinuityWireError> {
    let put = quota_units(&release.released_put_spool)?;
    let result = quota_units(&release.released_result_spool)?;
    let metadata = quota_units(&release.released_retained_metadata)?;
    let bytes = put
        .bytes
        .checked_add(result.bytes)
        .and_then(|value| value.checked_add(metadata.bytes));
    let rows = put
        .rows
        .checked_add(result.rows)
        .and_then(|value| value.checked_add(metadata.rows));
    let concurrency = put
        .concurrency
        .checked_add(result.concurrency)
        .and_then(|value| value.checked_add(metadata.concurrency));
    Ok(bytes == Some(ownership.bytes)
        && rows == Some(ownership.rows)
        && concurrency == Some(ownership.concurrency))
}

pub fn validate_and_encode_continuity_adjudicated(
    input: &ObjectStoreContinuityAdjudicatedV1,
    limits: &ContinuityWireLimits,
) -> Result<CanonicalContinuityAdjudicated, ContinuityWireError> {
    validate_limits(limits)?;
    let (fingerprint_tag, fingerprint) = fingerprint_adjudicated(input)?;
    let ownership = validate_ownership(
        &input.quota_ownership,
        &input.provider_boundary_id,
        &input.authenticated_cell_id,
        &input.authenticated_tenant_id,
        limits,
    )?;
    let proof = validate_and_encode_continuity_adjudication_proof(
        input
            .proof
            .as_ref()
            .ok_or(ContinuityWireError::MissingChild)?,
        limits,
    )?;
    let release = validate_and_encode_continuity_quota_release_receipt(
        input
            .quota_release_receipt
            .as_ref()
            .ok_or(ContinuityWireError::MissingChild)?,
        limits,
    )?;
    if input.adjudication_kind != proof.value().adjudication_kind
        || input.adjudication_kind != release.value().adjudication_kind
    {
        return Err(ContinuityWireError::ChildKindMismatch);
    }
    if input.authority_epoch != proof.value().authority_epoch
        || input.continuity_seq != proof.value().continuity_seq
    {
        return Err(ContinuityWireError::ChildIdentityMismatch);
    }
    let units = ownership
        .value()
        .units
        .as_ref()
        .ok_or(ContinuityWireError::MissingChild)?;
    if !release_matches_ownership(units, release.value())? {
        return Err(ContinuityWireError::ReleaseMismatch);
    }
    let proof_time = nonnegative(proof.value().committed_at_unix_ms)?;
    let release_time = nonnegative(release.value().released_at_unix_ms)?;
    let adjudicated_time = nonnegative(input.adjudicated_at_unix_ms)?;
    let retain_until = nonnegative(input.retain_until_unix_ms)?;
    if proof_time > release_time
        || release_time > adjudicated_time
        || adjudicated_time > retain_until
    {
        return Err(ContinuityWireError::InvalidTimeOrder);
    }

    let mut output = writer(limits)?;
    output
        .raw(ADJUDICATED_DOMAIN)
        .map_err(|_| ContinuityWireError::CanonicalTooLarge)?;
    write_identity(
        &mut output,
        &ContinuityIdentity {
            protocol_revision: &input.protocol_revision,
            provider_boundary_id: &input.provider_boundary_id,
            authenticated_cell_id: &input.authenticated_cell_id,
            authenticated_tenant_id: &input.authenticated_tenant_id,
            logical_request_id: &input.logical_request_id,
            attempt_id: &input.attempt_id,
            continuity_token_id: &input.continuity_token_id,
        },
        limits,
    )?;
    let authority_epoch = positive(input.authority_epoch)?;
    let continuity_seq = positive(input.continuity_seq)?;
    output
        .u64(authority_epoch)
        .and_then(|()| output.u64(continuity_seq))
        .and_then(|()| output.u32(input.intent_kind as u32))
        .and_then(|()| output.u32(fingerprint_tag))
        .and_then(|()| output.raw(&fingerprint))
        .and_then(|()| output.u32(input.adjudication_kind as u32))
        .and_then(|()| output.bytes(proof.canonical_bytes()))
        .and_then(|()| output.bytes(release.canonical_bytes()))
        .and_then(|()| output.u64(adjudicated_time))
        .and_then(|()| output.u64(retain_until))
        .and_then(|()| output.bytes(ownership.canonical_bytes()))
        .map_err(|_| ContinuityWireError::CanonicalTooLarge)?;
    let canonical_preimage = output.finish();
    let (canonical_bytes, digest) = finish(&canonical_preimage, &input.detail_blake3, limits)?;
    let mut value = input.clone();
    value.detail_blake3 = digest.to_vec().into();
    value.proof = Some(proof.value().clone());
    value.quota_release_receipt = Some(release.value().clone());
    value.quota_ownership = Some(ownership.value().clone());
    Ok(CanonicalContinuityAdjudicated {
        value,
        canonical_preimage,
        canonical_bytes,
        digest,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ContinuityWireError {
    #[error("continuity wire limits must be positive")]
    InvalidLimits,
    #[error("continuity wire text is not canonical or bounded")]
    InvalidCanonicalText,
    #[error("continuity wire UUID is not canonical UUIDv7")]
    InvalidUuidV7,
    #[error("continuity wire enum is unknown or unspecified")]
    InvalidEnum,
    #[error("continuity wire fingerprint does not match intent kind")]
    InvalidFingerprint,
    #[error("continuity wire authority value must be positive")]
    NonPositiveAuthority,
    #[error("continuity wire timestamp must be nonnegative")]
    NegativeTime,
    #[error("continuity wire timestamp ordering is invalid")]
    InvalidTimeOrder,
    #[error("continuity quarantine must remain quota bearing")]
    QuotaBearingRequired,
    #[error("continuity wire required child is missing")]
    MissingChild,
    #[error("continuity ownership identity does not match outer identity")]
    OwnershipIdentityMismatch,
    #[error("continuity adjudication evidence presence does not match kind")]
    InvalidEvidencePresence,
    #[error("provider authority refund is forbidden")]
    ProviderRefundForbidden,
    #[error("continuity quota release must not be empty")]
    EmptyRelease,
    #[error("continuity adjudication child kind does not match outer kind")]
    ChildKindMismatch,
    #[error("continuity adjudication proof identity does not match outer identity")]
    ChildIdentityMismatch,
    #[error("released quota does not equal retained continuity ownership")]
    ReleaseMismatch,
    #[error("continuity wire digest must contain exactly 32 bytes")]
    InvalidDigest,
    #[error("continuity wire digest does not match canonical fields")]
    DigestMismatch,
    #[error("canonical continuity wire record exceeds its byte bound")]
    CanonicalTooLarge,
    #[error(transparent)]
    Ownership(#[from] ContinuityQuotaOwnershipError),
}
