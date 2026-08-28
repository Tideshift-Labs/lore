// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure compact-receipt codec and retention planner for closed object-store requests.
//!
//! This module performs no database, provider, filesystem, clock, or runtime I/O. Callers supply
//! canonical authority evidence and authoritative database time; the returned decision only
//! describes the compare-and-swap mutation a later persistence layer may apply.

use std::fmt;

use lore_proto::lore::object_dispatch::v1::ObjectStorePayloadAvailabilityV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestOutcomeV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestPhaseV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDispositionV1;
use lore_proto::lore::object_dispatch::v1::object_store_request_outcome_v1;
use lore_proto::lore::object_dispatch::v1::object_store_request_receipt_v1;
use thiserror::Error;

use crate::contract::BoundedCanonicalWriter;
use crate::contract::canonical_uuid_v7_timestamp;
use crate::contract::validate_canonical_text;
use crate::request_state_wire::CanonicalObjectStoreRequestOutcome;
use crate::request_state_wire::CanonicalObjectStoreRequestReceipt;
use crate::request_state_wire::CanonicalObjectStoreRequestState;
use crate::request_state_wire::RequestStateWireLimits;
use crate::request_state_wire::validate_and_encode_object_store_request_outcome;
use crate::request_state_wire::validate_and_encode_object_store_request_receipt;
use crate::reserve_put_ack::CanonicalObjectStoreReservePutAck;

const SCHEMA_REVISION: &str = "object-store-compact-receipt-v1";
const COMPACT_DOMAIN: &[u8] = b"object-store-compact-receipt-v1\0";
const AUDIT_DOMAIN: &[u8] = b"object-store-provider-attempt-audit-v1\0";
const FLOOR_DOMAIN: &[u8] = b"object-store-compact-dependency-floor-v1\0";
const INTENT_DOMAIN: &[u8] = b"object-store-compaction-intent-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectStoreCompactReceiptLimits {
    pub max_identity_bytes: u32,
    pub max_canonical_row_bytes: u32,
    pub max_compact_row_bytes: u32,
    pub max_dependency_floors: u32,
    pub full_record_retention_ms: u64,
    pub anti_replay_admission_past_ms: u64,
    pub anti_replay_admission_future_ms: u64,
    pub anti_replay_compact_safety_ms: u64,
}

impl ObjectStoreCompactReceiptLimits {
    fn wire_limits(&self) -> RequestStateWireLimits {
        RequestStateWireLimits {
            max_identity_bytes: self.max_identity_bytes,
            max_canonical_row_bytes: self.max_canonical_row_bytes,
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum ObjectStoreCompactAuthority {
    RequestState(Box<CanonicalObjectStoreRequestState>),
}

impl fmt::Debug for ObjectStoreCompactAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::RequestState(_) => "REQUEST_STATE",
        };
        formatter
            .debug_struct("ObjectStoreCompactAuthority")
            .field("kind", &kind)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStoreProviderAttemptAudit {
    pub attempt_count: u64,
    pub committed_grant_count: u64,
    pub no_dispatch_count: u64,
    pub decisive_terminal_count: u64,
    pub ambiguous_count: u64,
    pub provider_authority_refunded: bool,
    pub audit_blake3: Option<[u8; 32]>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalObjectStoreProviderAttemptAudit {
    value: ObjectStoreProviderAttemptAudit,
    canonical_bytes: Vec<u8>,
    audit_blake3: [u8; 32],
}

impl CanonicalObjectStoreProviderAttemptAudit {
    pub fn value(&self) -> &ObjectStoreProviderAttemptAudit {
        &self.value
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn audit_blake3(&self) -> &[u8; 32] {
        &self.audit_blake3
    }
}

impl fmt::Debug for CanonicalObjectStoreProviderAttemptAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalObjectStoreProviderAttemptAudit")
            .field("value", &"[REDACTED]")
            .field("canonical_bytes", &"[REDACTED]")
            .field("audit_blake3", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObjectStoreCompactDependencyFloorKind {
    Ack,
    Discard,
    PutPayloadPurge,
    ResultPayloadPurge,
    Continuity,
    LocalDependency,
}

impl ObjectStoreCompactDependencyFloorKind {
    fn code(self) -> u32 {
        match self {
            Self::Ack => 1,
            Self::Discard => 2,
            Self::PutPayloadPurge => 3,
            Self::ResultPayloadPurge => 4,
            Self::Continuity => 5,
            Self::LocalDependency => 6,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStoreCompactDependencyFloor {
    pub kind: ObjectStoreCompactDependencyFloorKind,
    pub dependency_id: String,
    pub retain_until_unix_ms: i64,
    pub floor_blake3: Option<[u8; 32]>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalObjectStoreCompactDependencyFloor {
    value: ObjectStoreCompactDependencyFloor,
    canonical_bytes: Vec<u8>,
    floor_blake3: [u8; 32],
}

impl CanonicalObjectStoreCompactDependencyFloor {
    pub fn value(&self) -> &ObjectStoreCompactDependencyFloor {
        &self.value
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn floor_blake3(&self) -> &[u8; 32] {
        &self.floor_blake3
    }
}

impl fmt::Debug for CanonicalObjectStoreCompactDependencyFloor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalObjectStoreCompactDependencyFloor")
            .field("value", &"[REDACTED]")
            .field("canonical_bytes", &"[REDACTED]")
            .field("floor_blake3", &"[REDACTED]")
            .finish()
    }
}

pub struct ObjectStoreCompactReceiptInput<'a> {
    pub authority: &'a ObjectStoreCompactAuthority,
    pub submit_receipt: &'a CanonicalObjectStoreRequestReceipt,
    pub get_outcome: &'a CanonicalObjectStoreRequestOutcome,
    pub admission_created_at_unix_ms: i64,
    pub reserve_put_ack: Option<&'a CanonicalObjectStoreReservePutAck>,
    pub provider_attempt_audit: &'a ObjectStoreProviderAttemptAudit,
    pub dependency_floors: &'a [ObjectStoreCompactDependencyFloor],
    pub closure_committed_at_unix_ms: i64,
    pub compacted_at_unix_ms: i64,
    pub compact_prune_after_unix_ms: i64,
    pub compaction_fingerprint: Option<[u8; 32]>,
    pub compact_blake3: Option<[u8; 32]>,
}

#[derive(Clone, PartialEq)]
pub struct ObjectStoreCompactReceipt {
    pub schema_revision: &'static str,
    pub protocol_revision: String,
    pub provider_boundary_id: String,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub logical_request_id: String,
    pub attempt_id: String,
    pub logical_request_uuid_unix_ms: u64,
    pub attempt_uuid_unix_ms: u64,
    pub admission_created_at_unix_ms: i64,
    pub put_reservation_fingerprint: Option<[u8; 32]>,
    pub canonical_descriptor_fingerprint: Option<[u8; 32]>,
    pub reserve_put_ack: Option<CanonicalObjectStoreReservePutAck>,
    pub authority: ObjectStoreCompactAuthority,
    pub submit_receipt: CanonicalObjectStoreRequestReceipt,
    pub get_outcome: CanonicalObjectStoreRequestOutcome,
    pub provider_attempt_audit: CanonicalObjectStoreProviderAttemptAudit,
    pub dependency_floors: Vec<CanonicalObjectStoreCompactDependencyFloor>,
    pub closure_committed_at_unix_ms: i64,
    pub compacted_at_unix_ms: i64,
    pub compact_prune_after_unix_ms: i64,
    pub compaction_fingerprint: [u8; 32],
    pub compact_blake3: [u8; 32],
}

impl fmt::Debug for ObjectStoreCompactReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStoreCompactReceipt")
            .field("schema_revision", &self.schema_revision)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct CanonicalObjectStoreCompactReceipt {
    value: ObjectStoreCompactReceipt,
    canonical_preimage: Vec<u8>,
    canonical_bytes: Vec<u8>,
    compact_blake3: [u8; 32],
}

impl CanonicalObjectStoreCompactReceipt {
    pub fn value(&self) -> &ObjectStoreCompactReceipt {
        &self.value
    }

    pub fn canonical_preimage(&self) -> &[u8] {
        &self.canonical_preimage
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn compact_blake3(&self) -> &[u8; 32] {
        &self.compact_blake3
    }
}

impl fmt::Debug for CanonicalObjectStoreCompactReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalObjectStoreCompactReceipt")
            .field("value", &"[REDACTED]")
            .field("canonical_preimage", &"[REDACTED]")
            .field("canonical_bytes", &"[REDACTED]")
            .field("compact_blake3", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectStoreCompactCharge {
    pub bytes: u64,
    pub rows: u64,
    pub concurrency: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ObjectStoreCompactReceiptDecision {
    ReplayCompact {
        compact: CanonicalObjectStoreCompactReceipt,
    },
    CompactConflict,
    RetainFullNotClosed,
    RetainFullPayload,
    RetainFullFloor {
        eligible_at_unix_ms: i64,
    },
    RetainFullOverflow,
    RetainFullTooLarge {
        encoded_bytes: u64,
    },
    ApplyCompaction {
        expected_authority_blake3: [u8; 32],
        expected_submit_receipt_blake3: [u8; 32],
        expected_get_outcome_blake3: [u8; 32],
        compact: CanonicalObjectStoreCompactReceipt,
        compact_charge: ObjectStoreCompactCharge,
    },
}

pub struct ObjectStoreCompactReceiptPlannerInput<'a> {
    pub authority: &'a ObjectStoreCompactAuthority,
    pub submit_receipt: &'a CanonicalObjectStoreRequestReceipt,
    pub get_outcome: &'a CanonicalObjectStoreRequestOutcome,
    pub admission_created_at_unix_ms: i64,
    pub reserve_put_ack: Option<&'a CanonicalObjectStoreReservePutAck>,
    pub provider_attempt_audit: &'a ObjectStoreProviderAttemptAudit,
    pub trusted_dependency_floors: Option<&'a [ObjectStoreCompactDependencyFloor]>,
    pub database_now_unix_ms: i64,
    pub existing_compact: Option<&'a CanonicalObjectStoreCompactReceipt>,
}

struct AuthorityProjection<'a> {
    protocol_revision: &'a str,
    provider_boundary_id: &'a str,
    authenticated_cell_id: &'a str,
    authenticated_tenant_id: &'a str,
    logical_request_id: &'a str,
    attempt_id: &'a str,
    put_reservation_fingerprint: Option<&'a [u8]>,
    canonical_descriptor_fingerprint: Option<&'a [u8]>,
    closure_committed_at_unix_ms: Option<i64>,
    authority_blake3: [u8; 32],
    closed: bool,
    payload_free: bool,
    expected_no_dispatch_count: u64,
    expected_decisive_terminal_count: u64,
    expected_ambiguous_count: u64,
    automatic_floors: Vec<ObjectStoreCompactDependencyFloor>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CompactReceiptError {
    #[error("compact receipt limits must be positive")]
    InvalidLimits,
    #[error("compact receipt text is not canonical or bounded")]
    InvalidCanonicalText,
    #[error("compact receipt timestamp must be nonnegative")]
    NegativeTime,
    #[error("compact receipt UUID is not canonical UUIDv7")]
    InvalidUuidV7,
    #[error("compact receipt digest has invalid width")]
    InvalidDigest,
    #[error("compact receipt digest does not match canonical bytes")]
    DigestMismatch,
    #[error("canonical ReservePut ACK framing is invalid")]
    InvalidReservePutAck,
    #[error("compact receipt canonical bytes exceed the configured limit")]
    CanonicalTooLarge,
    #[error("compact provider-attempt audit algebra is invalid")]
    InvalidProviderAttemptAudit,
    #[error("compact authority is invalid")]
    InvalidAuthority,
    #[error("compact receipt wrappers do not select the exact authority")]
    WrapperMismatch,
    #[error("compact receipt authority projection is invalid")]
    InvalidAuthorityProjection,
    #[error("too many compact dependency floors")]
    TooManyDependencyFloors,
    #[error("duplicate compact dependency floor")]
    DuplicateDependencyFloor,
    #[error("compact receipt time projection is invalid")]
    InvalidTimeProjection,
    #[error("compact receipt retention arithmetic overflows")]
    RetentionOverflow,
    #[error("compact receipt retention projection is invalid")]
    InvalidRetentionProjection,
    #[error("encoded compact receipt does not match its value")]
    EncodedValueMismatch,
}

fn validate_limits(limits: &ObjectStoreCompactReceiptLimits) -> Result<(), CompactReceiptError> {
    if limits.max_identity_bytes == 0
        || limits.max_canonical_row_bytes == 0
        || limits.max_compact_row_bytes == 0
        || limits.max_dependency_floors == 0
        || limits.full_record_retention_ms == 0
        || limits.anti_replay_admission_past_ms == 0
        || limits.anti_replay_admission_future_ms == 0
        || limits.anti_replay_compact_safety_ms == 0
    {
        return Err(CompactReceiptError::InvalidLimits);
    }
    Ok(())
}

fn writer(maximum: u32) -> Result<BoundedCanonicalWriter, CompactReceiptError> {
    BoundedCanonicalWriter::new(maximum).map_err(|_| CompactReceiptError::InvalidLimits)
}

fn nonnegative(value: i64) -> Result<u64, CompactReceiptError> {
    u64::try_from(value).map_err(|_| CompactReceiptError::NegativeTime)
}

fn exact_digest(value: &[u8]) -> Result<[u8; 32], CompactReceiptError> {
    value
        .try_into()
        .map_err(|_| CompactReceiptError::InvalidDigest)
}

fn complete(
    preimage: Vec<u8>,
    supplied: Option<[u8; 32]>,
    maximum: u32,
) -> Result<(Vec<u8>, [u8; 32]), CompactReceiptError> {
    let digest = *blake3::hash(&preimage).as_bytes();
    if supplied.is_some_and(|value| value != digest) {
        return Err(CompactReceiptError::DigestMismatch);
    }
    let size = preimage
        .len()
        .checked_add(32)
        .ok_or(CompactReceiptError::CanonicalTooLarge)?;
    if size > maximum as usize {
        return Err(CompactReceiptError::CanonicalTooLarge);
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(&preimage);
    bytes.extend_from_slice(&digest);
    Ok((bytes, digest))
}

fn audit_fields(value: &ObjectStoreProviderAttemptAudit) -> Result<[u64; 5], CompactReceiptError> {
    let values = [
        value.attempt_count,
        value.committed_grant_count,
        value.no_dispatch_count,
        value.decisive_terminal_count,
        value.ambiguous_count,
    ];
    if value.provider_authority_refunded
        || value.no_dispatch_count > 1
        || value.attempt_count > value.committed_grant_count
        || value.decisive_terminal_count > value.attempt_count
        || value.ambiguous_count > value.attempt_count
        || (value.no_dispatch_count == 1 && value.decisive_terminal_count != 0)
    {
        return Err(CompactReceiptError::InvalidProviderAttemptAudit);
    }
    Ok(values)
}

pub fn validate_and_encode_object_store_provider_attempt_audit(
    input: &ObjectStoreProviderAttemptAudit,
    limits: &ObjectStoreCompactReceiptLimits,
) -> Result<CanonicalObjectStoreProviderAttemptAudit, CompactReceiptError> {
    validate_limits(limits)?;
    let values = audit_fields(input)?;
    let mut output = writer(limits.max_canonical_row_bytes)?;
    output
        .raw(AUDIT_DOMAIN)
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    for value in values {
        output
            .u64(value)
            .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    }
    output
        .u8(0)
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    let (canonical_bytes, audit_blake3) = complete(
        output.finish(),
        input.audit_blake3,
        limits.max_canonical_row_bytes,
    )?;
    let mut value = input.clone();
    value.audit_blake3 = Some(audit_blake3);
    Ok(CanonicalObjectStoreProviderAttemptAudit {
        value,
        canonical_bytes,
        audit_blake3,
    })
}

pub fn validate_and_encode_object_store_compact_dependency_floor(
    input: &ObjectStoreCompactDependencyFloor,
    limits: &ObjectStoreCompactReceiptLimits,
) -> Result<CanonicalObjectStoreCompactDependencyFloor, CompactReceiptError> {
    validate_limits(limits)?;
    validate_canonical_text(&input.dependency_id, limits.max_identity_bytes)
        .map_err(|_| CompactReceiptError::InvalidCanonicalText)?;
    let retain_until_unix_ms = nonnegative(input.retain_until_unix_ms)?;
    let mut output = writer(limits.max_canonical_row_bytes)?;
    output
        .raw(FLOOR_DOMAIN)
        .and_then(|()| output.u32(input.kind.code()))
        .and_then(|()| output.text(&input.dependency_id))
        .and_then(|()| output.u64(retain_until_unix_ms))
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    let (canonical_bytes, floor_blake3) = complete(
        output.finish(),
        input.floor_blake3,
        limits.max_canonical_row_bytes,
    )?;
    let mut value = input.clone();
    value.floor_blake3 = Some(floor_blake3);
    Ok(CanonicalObjectStoreCompactDependencyFloor {
        value,
        canonical_bytes,
        floor_blake3,
    })
}

fn checked_add(left: i64, right: u64) -> Option<i64> {
    let right = i64::try_from(right).ok()?;
    left.checked_add(right)
}

fn fingerprint_id(prefix: &str, digest: &[u8]) -> Result<String, CompactReceiptError> {
    let digest = exact_digest(digest)?;
    let mut value = String::with_capacity(prefix.len() + 1 + 64);
    value.push_str(prefix);
    value.push(':');
    for byte in digest {
        use std::fmt::Write;
        write!(&mut value, "{byte:02x}").map_err(|_| CompactReceiptError::InvalidAuthority)?;
    }
    Ok(value)
}

fn payload_free(
    value: &lore_proto::lore::object_dispatch::v1::ObjectStorePayloadRetentionV1,
) -> bool {
    matches!(
        ObjectStorePayloadAvailabilityV1::try_from(value.availability),
        Ok(ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityNotApplicable)
            | Ok(ObjectStorePayloadAvailabilityV1::ObjectStorePayloadAvailabilityDisposed)
    ) && value.partial_temp_bytes == 0
        && value.partial_temp_chunks == 0
}

fn project_authority(
    authority: &ObjectStoreCompactAuthority,
) -> Result<AuthorityProjection<'_>, CompactReceiptError> {
    match authority {
        ObjectStoreCompactAuthority::RequestState(value) => {
            let projected = value.value();
            let phase = ObjectStoreRequestPhaseV1::try_from(projected.phase)
                .map_err(|_| CompactReceiptError::InvalidAuthority)?;
            let disposition =
                ObjectStoreResultDispositionV1::try_from(projected.result_disposition)
                    .map_err(|_| CompactReceiptError::InvalidAuthority)?;
            let closed = matches!(
                phase,
                ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseNoDispatch
                    | ObjectStoreRequestPhaseV1::ObjectStoreRequestPhasePreparedExpired
            ) || (phase == ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseTerminal
                && matches!(
                    disposition,
                    ObjectStoreResultDispositionV1::ObjectStoreResultDispositionAcked
                        | ObjectStoreResultDispositionV1::ObjectStoreResultDispositionDiscarded
                ));
            let put_body = projected
                .put_body
                .as_ref()
                .ok_or(CompactReceiptError::InvalidAuthority)?;
            let result_payload = projected
                .result_payload
                .as_ref()
                .ok_or(CompactReceiptError::InvalidAuthority)?;
            let mut automatic_floors = Vec::new();
            if let Some(receipt) = projected.ack_receipt.as_ref()
                && let Some(retain_until_unix_ms) = receipt.payload_purge_after_unix_ms
            {
                automatic_floors.push(ObjectStoreCompactDependencyFloor {
                    kind: ObjectStoreCompactDependencyFloorKind::Ack,
                    dependency_id: fingerprint_id("ack", &receipt.ack_fingerprint)?,
                    retain_until_unix_ms,
                    floor_blake3: None,
                });
            }
            if let Some(receipt) = projected.discard_receipt.as_ref()
                && let Some(retain_until_unix_ms) = receipt.payload_purge_after_unix_ms
            {
                automatic_floors.push(ObjectStoreCompactDependencyFloor {
                    kind: ObjectStoreCompactDependencyFloorKind::Discard,
                    dependency_id: fingerprint_id("discard", &receipt.discard_fingerprint)?,
                    retain_until_unix_ms,
                    floor_blake3: None,
                });
            }
            for (kind, payload) in [
                (
                    ObjectStoreCompactDependencyFloorKind::PutPayloadPurge,
                    put_body,
                ),
                (
                    ObjectStoreCompactDependencyFloorKind::ResultPayloadPurge,
                    result_payload,
                ),
            ] {
                if let Some(receipt) = payload.purge_receipt.as_ref() {
                    automatic_floors.push(ObjectStoreCompactDependencyFloor {
                        kind,
                        dependency_id: receipt.purge_id.clone(),
                        retain_until_unix_ms: receipt.purged_at_unix_ms,
                        floor_blake3: None,
                    });
                }
            }
            let was_ambiguous = u64::from(
                projected
                    .dispatch_attempt
                    .as_ref()
                    .and_then(|attempt| attempt.ambiguity_recorded_at_unix_ms)
                    .is_some(),
            );
            Ok(AuthorityProjection {
                protocol_revision: &projected.protocol_revision,
                provider_boundary_id: &projected.provider_boundary_id,
                authenticated_cell_id: &projected.authenticated_cell_id,
                authenticated_tenant_id: &projected.authenticated_tenant_id,
                logical_request_id: &projected.logical_request_id,
                attempt_id: &projected.attempt_id,
                put_reservation_fingerprint: projected
                    .put_reservation_fingerprint
                    .as_ref()
                    .map(AsRef::as_ref),
                canonical_descriptor_fingerprint: projected
                    .canonical_descriptor_fingerprint
                    .as_ref()
                    .map(AsRef::as_ref),
                closure_committed_at_unix_ms: projected.closure_committed_at_unix_ms,
                authority_blake3: *value.state_blake3(),
                closed,
                payload_free: payload_free(put_body) && payload_free(result_payload),
                expected_no_dispatch_count: u64::from(matches!(
                    phase,
                    ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseNoDispatch
                        | ObjectStoreRequestPhaseV1::ObjectStoreRequestPhasePreparedExpired
                )),
                expected_decisive_terminal_count: u64::from(
                    phase == ObjectStoreRequestPhaseV1::ObjectStoreRequestPhaseTerminal,
                ),
                expected_ambiguous_count: was_ambiguous,
                automatic_floors,
            })
        }
    }
}

fn authority_kind_code(authority: &ObjectStoreCompactAuthority) -> u32 {
    match authority {
        ObjectStoreCompactAuthority::RequestState(_) => 1,
    }
}

fn authority_bytes(authority: &ObjectStoreCompactAuthority) -> &[u8] {
    match authority {
        ObjectStoreCompactAuthority::RequestState(value) => value.canonical_bytes(),
    }
}

fn authority_receipt_outcome(
    authority: &ObjectStoreCompactAuthority,
) -> (
    object_store_request_receipt_v1::Outcome,
    object_store_request_outcome_v1::Outcome,
) {
    match authority {
        ObjectStoreCompactAuthority::RequestState(value) => (
            object_store_request_receipt_v1::Outcome::RequestState(Box::new(value.value().clone())),
            object_store_request_outcome_v1::Outcome::RequestState(Box::new(value.value().clone())),
        ),
    }
}

fn checked_wrappers(
    authority: &ObjectStoreCompactAuthority,
    receipt: &CanonicalObjectStoreRequestReceipt,
    outcome: &CanonicalObjectStoreRequestOutcome,
    limits: &ObjectStoreCompactReceiptLimits,
) -> Result<
    (
        CanonicalObjectStoreRequestReceipt,
        CanonicalObjectStoreRequestOutcome,
    ),
    CompactReceiptError,
> {
    let (receipt_outcome, outcome_outcome) = authority_receipt_outcome(authority);
    let checked_receipt = validate_and_encode_object_store_request_receipt(
        &ObjectStoreRequestReceiptV1 {
            receipt_blake3: receipt.receipt_blake3().to_vec().into(),
            receipt_committed_at_unix_ms: receipt.value().receipt_committed_at_unix_ms,
            outcome: Some(receipt_outcome),
        },
        &limits.wire_limits(),
    )
    .map_err(|_| CompactReceiptError::WrapperMismatch)?;
    let checked_outcome = validate_and_encode_object_store_request_outcome(
        &ObjectStoreRequestOutcomeV1 {
            outcome_blake3: outcome.outcome_blake3().to_vec().into(),
            outcome: Some(outcome_outcome),
        },
        &limits.wire_limits(),
    )
    .map_err(|_| CompactReceiptError::WrapperMismatch)?;
    if checked_receipt.canonical_bytes() != receipt.canonical_bytes()
        || checked_receipt.receipt_blake3() != receipt.receipt_blake3()
        || checked_outcome.canonical_bytes() != outcome.canonical_bytes()
        || checked_outcome.outcome_blake3() != outcome.outcome_blake3()
    {
        return Err(CompactReceiptError::WrapperMismatch);
    }
    Ok((checked_receipt, checked_outcome))
}

fn checked_floors(
    values: &[ObjectStoreCompactDependencyFloor],
    limits: &ObjectStoreCompactReceiptLimits,
) -> Result<Vec<CanonicalObjectStoreCompactDependencyFloor>, CompactReceiptError> {
    if values.len() > limits.max_dependency_floors as usize {
        return Err(CompactReceiptError::TooManyDependencyFloors);
    }
    let mut encoded = values
        .iter()
        .map(|value| validate_and_encode_object_store_compact_dependency_floor(value, limits))
        .collect::<Result<Vec<_>, _>>()?;
    encoded.sort_by(|left, right| {
        left.value.kind.cmp(&right.value.kind).then_with(|| {
            left.value
                .dependency_id
                .as_bytes()
                .cmp(right.value.dependency_id.as_bytes())
        })
    });
    if encoded.windows(2).any(|pair| {
        pair[0].value.kind == pair[1].value.kind
            && pair[0].value.dependency_id == pair[1].value.dependency_id
    }) {
        return Err(CompactReceiptError::DuplicateDependencyFloor);
    }
    Ok(encoded)
}

fn compact_fingerprint(
    authority: &ObjectStoreCompactAuthority,
    receipt: &CanonicalObjectStoreRequestReceipt,
    outcome: &CanonicalObjectStoreRequestOutcome,
    reserve_put_ack: Option<&CanonicalObjectStoreReservePutAck>,
    audit: &CanonicalObjectStoreProviderAttemptAudit,
    floors: &[CanonicalObjectStoreCompactDependencyFloor],
    admission_created_at_unix_ms: i64,
) -> Result<[u8; 32], CompactReceiptError> {
    let authority_kind = authority_kind_code(authority);
    let floor_count =
        u32::try_from(floors.len()).map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    let admission_created_at_unix_ms = nonnegative(admission_created_at_unix_ms)?;
    let mut output = writer(u32::MAX)?;
    output
        .raw(INTENT_DOMAIN)
        .and_then(|()| output.u32(authority_kind))
        .and_then(|()| output.bytes(authority_bytes(authority)))
        .and_then(|()| output.bytes(receipt.canonical_bytes()))
        .and_then(|()| output.bytes(outcome.canonical_bytes()))
        .and_then(|()| output.u8(u8::from(reserve_put_ack.is_some())))
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    if let Some(ack) = reserve_put_ack {
        output
            .bytes(ack.canonical_bytes())
            .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    }
    output
        .u8(u8::from(reserve_put_ack.is_some()))
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    if let Some(ack) = reserve_put_ack {
        output
            .raw(ack.ack_blake3())
            .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    }
    output
        .bytes(audit.canonical_bytes())
        .and_then(|()| output.u32(floor_count))
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    for floor in floors {
        output
            .bytes(floor.canonical_bytes())
            .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    }
    output
        .u64(admission_created_at_unix_ms)
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    Ok(*blake3::hash(&output.finish()).as_bytes())
}

fn audit_matches_authority(
    actual: &ObjectStoreProviderAttemptAudit,
    projection: &AuthorityProjection<'_>,
) -> Result<bool, CompactReceiptError> {
    audit_fields(actual)?;
    Ok((projection.expected_no_dispatch_count == 0
        || actual.no_dispatch_count == projection.expected_no_dispatch_count)
        && (projection.expected_decisive_terminal_count == 0
            || actual.decisive_terminal_count == projection.expected_decisive_terminal_count)
        && (projection.expected_ambiguous_count == 0 || actual.ambiguous_count > 0))
}

fn write_optional_digest(
    output: &mut BoundedCanonicalWriter,
    digest: Option<&[u8]>,
) -> Result<Option<[u8; 32]>, CompactReceiptError> {
    output
        .u8(u8::from(digest.is_some()))
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    let exact = digest.map(exact_digest).transpose()?;
    if let Some(value) = exact {
        output
            .raw(&value)
            .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    }
    Ok(exact)
}

fn checked_reserve_put_ack<'a>(
    value: Option<&'a CanonicalObjectStoreReservePutAck>,
    projection: &AuthorityProjection<'_>,
    maximum: u32,
) -> Result<Option<&'a CanonicalObjectStoreReservePutAck>, CompactReceiptError> {
    let required = projection.put_reservation_fingerprint.is_some();
    if required != value.is_some()
        || value.is_some_and(|ack| ack.canonical_bytes().len() > maximum as usize)
    {
        return Err(CompactReceiptError::InvalidReservePutAck);
    }
    if let Some(ack) = value {
        let ack = ack.value();
        if !matches!(ack.state, 3 | 5)
            || ack.protocol_revision != projection.protocol_revision
            || ack.provider_boundary_id != projection.provider_boundary_id
            || ack.authenticated_cell_id != projection.authenticated_cell_id
            || ack.authenticated_tenant_id != projection.authenticated_tenant_id
            || ack.logical_request_id != projection.logical_request_id
            || ack.attempt_id != projection.attempt_id
        {
            return Err(CompactReceiptError::InvalidReservePutAck);
        }
    }
    Ok(value)
}

pub fn validate_and_encode_object_store_compact_receipt(
    input: &ObjectStoreCompactReceiptInput<'_>,
    limits: &ObjectStoreCompactReceiptLimits,
) -> Result<CanonicalObjectStoreCompactReceipt, CompactReceiptError> {
    validate_limits(limits)?;
    let projection = project_authority(input.authority)?;
    let (receipt, outcome) = checked_wrappers(
        input.authority,
        input.submit_receipt,
        input.get_outcome,
        limits,
    )?;
    let audit = validate_and_encode_object_store_provider_attempt_audit(
        input.provider_attempt_audit,
        limits,
    )?;
    let floors = checked_floors(input.dependency_floors, limits)?;
    let reserve_put_ack = checked_reserve_put_ack(
        input.reserve_put_ack,
        &projection,
        limits.max_canonical_row_bytes,
    )?;
    if !projection.closed
        || !projection.payload_free
        || projection.closure_committed_at_unix_ms.is_none()
    {
        return Err(CompactReceiptError::InvalidAuthorityProjection);
    }
    if !audit_matches_authority(audit.value(), &projection)? {
        return Err(CompactReceiptError::InvalidProviderAttemptAudit);
    }
    for automatic in &projection.automatic_floors {
        if !floors.iter().any(|floor| {
            floor.value.kind == automatic.kind
                && floor.value.dependency_id == automatic.dependency_id
                && floor.value.retain_until_unix_ms == automatic.retain_until_unix_ms
        }) {
            return Err(CompactReceiptError::InvalidAuthorityProjection);
        }
    }
    let logical_request_uuid_unix_ms = canonical_uuid_v7_timestamp(projection.logical_request_id)
        .map_err(|_| CompactReceiptError::InvalidUuidV7)?;
    let attempt_uuid_unix_ms = canonical_uuid_v7_timestamp(projection.attempt_id)
        .map_err(|_| CompactReceiptError::InvalidUuidV7)?;
    nonnegative(input.admission_created_at_unix_ms)?;
    nonnegative(input.closure_committed_at_unix_ms)?;
    nonnegative(input.compacted_at_unix_ms)?;
    nonnegative(input.compact_prune_after_unix_ms)?;
    if projection.closure_committed_at_unix_ms != Some(input.closure_committed_at_unix_ms)
        || input.admission_created_at_unix_ms > input.closure_committed_at_unix_ms
        || receipt.value().receipt_committed_at_unix_ms > input.compacted_at_unix_ms
        || input.compacted_at_unix_ms < input.closure_committed_at_unix_ms
        || input.compact_prune_after_unix_ms < input.compacted_at_unix_ms
    {
        return Err(CompactReceiptError::InvalidTimeProjection);
    }
    let fingerprint = compact_fingerprint(
        input.authority,
        &receipt,
        &outcome,
        reserve_put_ack,
        &audit,
        &floors,
        input.admission_created_at_unix_ms,
    )?;
    if input
        .compaction_fingerprint
        .is_some_and(|supplied| supplied != fingerprint)
    {
        return Err(CompactReceiptError::DigestMismatch);
    }
    let full_eligible_at = checked_add(
        input.closure_committed_at_unix_ms,
        limits.full_record_retention_ms,
    )
    .ok_or(CompactReceiptError::RetentionOverflow)?;
    let admission_prune = checked_add(
        input.admission_created_at_unix_ms,
        limits.anti_replay_admission_past_ms,
    )
    .and_then(|value| checked_add(value, limits.anti_replay_admission_future_ms))
    .and_then(|value| checked_add(value, limits.anti_replay_compact_safety_ms))
    .ok_or(CompactReceiptError::RetentionOverflow)?;
    let closure_prune = checked_add(
        input.closure_committed_at_unix_ms,
        limits.anti_replay_admission_past_ms,
    )
    .ok_or(CompactReceiptError::RetentionOverflow)?;
    let required_prune_after = floors.iter().fold(
        admission_prune
            .max(closure_prune)
            .max(input.compacted_at_unix_ms),
        |latest, floor| latest.max(floor.value.retain_until_unix_ms),
    );
    if input.compacted_at_unix_ms < full_eligible_at
        || input.compact_prune_after_unix_ms != required_prune_after
    {
        return Err(CompactReceiptError::InvalidRetentionProjection);
    }

    let admission_created_at_unix_ms = nonnegative(input.admission_created_at_unix_ms)?;
    let closure_committed_at_unix_ms = nonnegative(input.closure_committed_at_unix_ms)?;
    let compacted_at_unix_ms = nonnegative(input.compacted_at_unix_ms)?;
    let compact_prune_after_unix_ms = nonnegative(input.compact_prune_after_unix_ms)?;
    let authority_kind = authority_kind_code(input.authority);
    let floor_count =
        u32::try_from(floors.len()).map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    let mut output = writer(limits.max_compact_row_bytes)?;
    output
        .raw(COMPACT_DOMAIN)
        .and_then(|()| output.text(SCHEMA_REVISION))
        .and_then(|()| output.text(projection.protocol_revision))
        .and_then(|()| output.text(projection.provider_boundary_id))
        .and_then(|()| output.text(projection.authenticated_cell_id))
        .and_then(|()| output.text(projection.authenticated_tenant_id))
        .and_then(|()| output.text(projection.logical_request_id))
        .and_then(|()| output.text(projection.attempt_id))
        .and_then(|()| output.u64(logical_request_uuid_unix_ms))
        .and_then(|()| output.u64(attempt_uuid_unix_ms))
        .and_then(|()| output.u64(admission_created_at_unix_ms))
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    let put_reservation_fingerprint =
        write_optional_digest(&mut output, projection.put_reservation_fingerprint)?;
    let canonical_descriptor_fingerprint =
        write_optional_digest(&mut output, projection.canonical_descriptor_fingerprint)?;
    output
        .u8(u8::from(reserve_put_ack.is_some()))
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    if let Some(ack) = reserve_put_ack {
        output
            .bytes(ack.canonical_bytes())
            .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    }
    output
        .u8(u8::from(reserve_put_ack.is_some()))
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    if let Some(ack) = reserve_put_ack {
        output
            .raw(ack.ack_blake3())
            .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    }
    output
        .u32(authority_kind)
        .and_then(|()| output.bytes(authority_bytes(input.authority)))
        .and_then(|()| output.raw(&projection.authority_blake3))
        .and_then(|()| output.bytes(receipt.canonical_bytes()))
        .and_then(|()| output.raw(receipt.receipt_blake3()))
        .and_then(|()| output.bytes(outcome.canonical_bytes()))
        .and_then(|()| output.raw(outcome.outcome_blake3()))
        .and_then(|()| output.bytes(audit.canonical_bytes()))
        .and_then(|()| output.u32(floor_count))
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    for floor in &floors {
        output
            .bytes(floor.canonical_bytes())
            .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    }
    output
        .u64(closure_committed_at_unix_ms)
        .and_then(|()| output.u64(compacted_at_unix_ms))
        .and_then(|()| output.u64(compact_prune_after_unix_ms))
        .and_then(|()| output.raw(&fingerprint))
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    let canonical_preimage = output.finish();
    let (canonical_bytes, compact_blake3) = complete(
        canonical_preimage.clone(),
        input.compact_blake3,
        limits.max_compact_row_bytes,
    )?;
    Ok(CanonicalObjectStoreCompactReceipt {
        value: ObjectStoreCompactReceipt {
            schema_revision: SCHEMA_REVISION,
            protocol_revision: projection.protocol_revision.to_string(),
            provider_boundary_id: projection.provider_boundary_id.to_string(),
            authenticated_cell_id: projection.authenticated_cell_id.to_string(),
            authenticated_tenant_id: projection.authenticated_tenant_id.to_string(),
            logical_request_id: projection.logical_request_id.to_string(),
            attempt_id: projection.attempt_id.to_string(),
            logical_request_uuid_unix_ms,
            attempt_uuid_unix_ms,
            admission_created_at_unix_ms: input.admission_created_at_unix_ms,
            put_reservation_fingerprint,
            canonical_descriptor_fingerprint,
            reserve_put_ack: reserve_put_ack.cloned(),
            authority: input.authority.clone(),
            submit_receipt: receipt,
            get_outcome: outcome,
            provider_attempt_audit: audit,
            dependency_floors: floors,
            closure_committed_at_unix_ms: input.closure_committed_at_unix_ms,
            compacted_at_unix_ms: input.compacted_at_unix_ms,
            compact_prune_after_unix_ms: input.compact_prune_after_unix_ms,
            compaction_fingerprint: fingerprint,
            compact_blake3,
        },
        canonical_preimage,
        canonical_bytes,
        compact_blake3,
    })
}

pub fn decide_object_store_compact_receipt(
    input: &ObjectStoreCompactReceiptPlannerInput<'_>,
    limits: &ObjectStoreCompactReceiptLimits,
) -> Result<ObjectStoreCompactReceiptDecision, CompactReceiptError> {
    validate_limits(limits)?;
    let projection = project_authority(input.authority)?;
    let validation_limits = if input.existing_compact.is_some() {
        ObjectStoreCompactReceiptLimits {
            max_identity_bytes: u32::MAX,
            max_canonical_row_bytes: u32::MAX,
            max_compact_row_bytes: u32::MAX,
            max_dependency_floors: u32::MAX,
            ..*limits
        }
    } else {
        *limits
    };
    let (receipt, outcome) = checked_wrappers(
        input.authority,
        input.submit_receipt,
        input.get_outcome,
        &validation_limits,
    )?;
    let audit = validate_and_encode_object_store_provider_attempt_audit(
        input.provider_attempt_audit,
        &validation_limits,
    )?;
    if !audit_matches_authority(audit.value(), &projection)? {
        return Err(CompactReceiptError::InvalidProviderAttemptAudit);
    }
    if input.existing_compact.is_none() {
        nonnegative(input.database_now_unix_ms)?;
        if receipt.value().receipt_committed_at_unix_ms > input.database_now_unix_ms {
            return Err(CompactReceiptError::InvalidTimeProjection);
        }
    }
    if !projection.closed || projection.closure_committed_at_unix_ms.is_none() {
        return Ok(ObjectStoreCompactReceiptDecision::RetainFullNotClosed);
    }
    if !projection.payload_free {
        return Ok(ObjectStoreCompactReceiptDecision::RetainFullPayload);
    }
    let reserve_put_ack = checked_reserve_put_ack(
        input.reserve_put_ack,
        &projection,
        validation_limits.max_canonical_row_bytes,
    )?;
    let mut floor_values = projection.automatic_floors.clone();
    if let Some(trusted) = input.trusted_dependency_floors {
        floor_values.extend_from_slice(trusted);
    }
    let floors = checked_floors(&floor_values, &validation_limits)?;
    let fingerprint = compact_fingerprint(
        input.authority,
        &receipt,
        &outcome,
        reserve_put_ack,
        &audit,
        &floors,
        input.admission_created_at_unix_ms,
    )?;
    if let Some(existing) = input.existing_compact {
        if existing.value.logical_request_id != projection.logical_request_id
            || existing.value.attempt_id != projection.attempt_id
            || existing.value.compaction_fingerprint != fingerprint
        {
            return Ok(ObjectStoreCompactReceiptDecision::CompactConflict);
        }
        return Ok(ObjectStoreCompactReceiptDecision::ReplayCompact {
            compact: existing.clone(),
        });
    }
    let closure_committed_at_unix_ms = projection
        .closure_committed_at_unix_ms
        .ok_or(CompactReceiptError::InvalidAuthorityProjection)?;
    let full_eligible_at = match checked_add(
        closure_committed_at_unix_ms,
        limits.full_record_retention_ms,
    ) {
        Some(value) => value,
        None => return Ok(ObjectStoreCompactReceiptDecision::RetainFullOverflow),
    };
    let admission_prune = checked_add(
        input.admission_created_at_unix_ms,
        limits.anti_replay_admission_past_ms,
    )
    .and_then(|value| checked_add(value, limits.anti_replay_admission_future_ms))
    .and_then(|value| checked_add(value, limits.anti_replay_compact_safety_ms));
    let closure_prune = checked_add(
        closure_committed_at_unix_ms,
        limits.anti_replay_admission_past_ms,
    );
    let (Some(admission_prune), Some(closure_prune)) = (admission_prune, closure_prune) else {
        return Ok(ObjectStoreCompactReceiptDecision::RetainFullOverflow);
    };
    if input.database_now_unix_ms < full_eligible_at {
        return Ok(ObjectStoreCompactReceiptDecision::RetainFullFloor {
            eligible_at_unix_ms: full_eligible_at,
        });
    }
    let prune_after = floors.iter().fold(
        admission_prune
            .max(closure_prune)
            .max(input.database_now_unix_ms),
        |latest, floor| latest.max(floor.value.retain_until_unix_ms),
    );
    let expanded_limits = ObjectStoreCompactReceiptLimits {
        max_compact_row_bytes: u32::MAX,
        ..*limits
    };
    let floor_values = floors
        .iter()
        .map(|floor| floor.value.clone())
        .collect::<Vec<_>>();
    let compact = validate_and_encode_object_store_compact_receipt(
        &ObjectStoreCompactReceiptInput {
            authority: input.authority,
            submit_receipt: &receipt,
            get_outcome: &outcome,
            admission_created_at_unix_ms: input.admission_created_at_unix_ms,
            reserve_put_ack,
            provider_attempt_audit: audit.value(),
            dependency_floors: &floor_values,
            closure_committed_at_unix_ms,
            compacted_at_unix_ms: input.database_now_unix_ms,
            compact_prune_after_unix_ms: prune_after,
            compaction_fingerprint: Some(fingerprint),
            compact_blake3: None,
        },
        &expanded_limits,
    )?;
    let encoded_bytes = u64::try_from(compact.canonical_bytes().len())
        .map_err(|_| CompactReceiptError::CanonicalTooLarge)?;
    if encoded_bytes > u64::from(limits.max_compact_row_bytes) {
        return Ok(ObjectStoreCompactReceiptDecision::RetainFullTooLarge { encoded_bytes });
    }
    Ok(ObjectStoreCompactReceiptDecision::ApplyCompaction {
        expected_authority_blake3: projection.authority_blake3,
        expected_submit_receipt_blake3: *receipt.receipt_blake3(),
        expected_get_outcome_blake3: *outcome.outcome_blake3(),
        compact,
        compact_charge: ObjectStoreCompactCharge {
            bytes: encoded_bytes,
            rows: 1,
            concurrency: 0,
        },
    })
}
