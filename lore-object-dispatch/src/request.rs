// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure request-shape, fingerprint, and idempotency prerequisites.
//!
//! Nothing in this module reads a clock, database, spool, or provider, and nothing calls these
//! functions yet. A future admission transaction must perform the durable fingerprint lookup
//! before applying the first-seen-only authority, time, reservation, and spool checks.
//!
//! CR-033 D3 folded the former `authority.rs` slice in here: with boundary equal to cell, there is
//! one authority context to validate, not two that can drift apart.

use std::cmp::Ordering;
use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lore_proto::lore::object_dispatch::v1::DurableConsumerKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectMetadataEntryV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestV1;
use lore_proto::lore::object_dispatch::v1::ReservedDimensionV1;
use lore_proto::lore::object_dispatch::v1::ResultConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::object_store_request_v1;
use lore_proto::lore::object_dispatch::v1::result_consumer_context_v1;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use crate::contract::MAX_CANONICAL_ID_BYTES;
use crate::contract::canonical_uuid_v7_timestamp;
use crate::contract::validate_canonical_id;

const FINGERPRINT_DOMAIN: &[u8] = b"object-dispatch-fingerprint-v1\0";
const UUID_PAST_WINDOW_MS: i64 = 365 * 24 * 60 * 60 * 1_000;
const UUID_FUTURE_WINDOW_MS: i64 = 5 * 60 * 1_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestIdentityLimits {
    pub max_identity_bytes: u32,
    pub max_authenticated_scope_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationPolicyLimits {
    pub max_reserved_dimensions_per_request: u32,
    pub max_reservation_id_bytes: u32,
    pub max_physical_dimension_id_bytes: u32,
    pub max_operation_class_id_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStoreOperationLimits {
    pub max_bucket_bytes: u32,
    pub max_key_bytes: u32,
    pub max_opaque_value_bytes: u32,
    pub max_body_handle_bytes: u32,
    pub max_metadata_entries: u32,
    pub max_metadata_key_bytes: u32,
    pub max_metadata_value_bytes: u32,
    pub max_metadata_aggregate_bytes: u32,
    pub max_list_entries: u32,
    pub max_result_bytes: u64,
    pub max_body_bytes: u64,
    pub allowed_metadata_keys: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestFingerprintLimits {
    pub identity: RequestIdentityLimits,
    pub reservations: ReservationPolicyLimits,
    pub operation: ObjectStoreOperationLimits,
    pub max_fingerprint_preimage_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedConsumerIdentity {
    pub provider_boundary_id: String,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub principal_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationRequirement {
    pub physical_dimension_id: String,
    pub operation_class_id: String,
    pub units: u64,
    pub class_cap_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurablePutSpoolExpectation {
    pub durable_body_handle: String,
    pub body_size: u64,
    pub body_blake3: [u8; 32],
}

/// The cell's current authority context, exact-matched against a first-seen request.
///
/// CR-033 D3 folded the former `authority.rs` slice into this validator: with one boundary, one
/// budget and one cell, "validate the authority context" and "validate the request" are the same
/// operation, and keeping them apart only invited them to drift.
///
/// `allocation_revision` and `allocation_fence` keep the frozen migration-0007 column names but no
/// longer describe a cross-cell allocation state machine. They are re-bound to the cell's frozen
/// budget-configuration revision from WP-121's per-cell `OBJECT-STORE-BUDGET-FROZEN` envelope and
/// that envelope's monotonic generation. A request pinning anything but the cell's current pair
/// fails closed. This is one pin, not a state machine: there is no ACTIVE state and no expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedRequestAuthority {
    pub protocol_revision: String,
    pub policy_revision: String,
    pub provider_boundary_id: String,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub allocation_revision: String,
    pub allocation_fence: u64,
}

/// Cell-admission identity, retained only for a caller that still supplies one.
///
/// The cell authority supplies neither field (CR-033 D3): admission existed so a cell could be
/// admitted to or evicted from a global allocation set, and there is no global set. Migration
/// 0007's columns stay nullable under
/// `CHECK (num_nonnulls(cell_admission_id, cell_admission_fence) IN (0, 2))`, so both-absent is a
/// legal retained state and needs no migration edit. A half-supplied pair is still rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedCellAdmission {
    pub cell_admission_id: String,
    pub cell_admission_fence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstSeenPrerequisites<'a> {
    pub expected_authority: &'a ExpectedRequestAuthority,
    /// `None` is the cell authority's own shape: it supplies no admission identity, so the
    /// request must carry none either.
    pub expected_cell_admission: Option<&'a ExpectedCellAdmission>,
    pub reservation_requirements: &'a [ReservationRequirement],
    pub put_spool: Option<&'a DurablePutSpoolExpectation>,
    pub database_now_unix_ms: i64,
    pub max_request_deadline_horizon_ms: i64,
    pub cell_allocation_hard_expiry_unix_ms: i64,
    pub dispatch_authority_hard_expiry_unix_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DurableRequestKey {
    pub provider_boundary_id: String,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub logical_request_id: String,
    pub attempt_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedRequest {
    durable_key: DurableRequestKey,
    logical_request_timestamp_unix_ms: u64,
    attempt_timestamp_unix_ms: u64,
    canonical_preimage: Vec<u8>,
    canonical_fingerprint: [u8; 32],
    canonical_reservation_ids: Vec<String>,
    operation_tag: u32,
    consumer_tag: u32,
    source_request: ObjectStoreRequestV1,
}

impl ValidatedRequest {
    pub fn durable_key(&self) -> &DurableRequestKey {
        &self.durable_key
    }

    pub fn logical_request_timestamp_unix_ms(&self) -> u64 {
        self.logical_request_timestamp_unix_ms
    }

    pub fn attempt_timestamp_unix_ms(&self) -> u64 {
        self.attempt_timestamp_unix_ms
    }

    pub fn canonical_preimage(&self) -> &[u8] {
        &self.canonical_preimage
    }

    pub fn canonical_fingerprint(&self) -> &[u8; 32] {
        &self.canonical_fingerprint
    }

    pub fn canonical_reservation_ids(&self) -> &[String] {
        &self.canonical_reservation_ids
    }

    pub fn operation_tag(&self) -> u32 {
        self.operation_tag
    }

    pub fn consumer_tag(&self) -> u32 {
        self.consumer_tag
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExistingFingerprint {
    Absent,
    Full([u8; 32]),
    Compact([u8; 32]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdempotencyDecision {
    FirstSeen,
    ExactReplay,
    IdentityReuseConflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstSeenIdentityDecision {
    Admit {
        logical_request_timestamp_unix_ms: u64,
        attempt_timestamp_unix_ms: u64,
    },
    InvalidUuidV7,
    ExpiredOrUnknown,
    TimestampTooFarInFuture,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RequestContractError {
    #[error("object-store request policy limits are invalid")]
    InvalidLimits,
    #[error("object-store request text is not canonical and bounded")]
    InvalidCanonicalText,
    #[error("object-store request UUID is not canonical RFC 9562 UUIDv7")]
    InvalidUuidV7,
    #[error("object-store request authority does not match authenticated authority")]
    AuthorityMismatch,
    #[error("object-store request cell admission does not match current admission")]
    CellAdmissionMismatch,
    #[error("object-store request reservation set is invalid")]
    InvalidReservations,
    #[error("object-store request consumer context is invalid")]
    InvalidConsumerContext,
    #[error("object-store request operation is invalid")]
    InvalidOperation,
    #[error("object-store request PUT descriptor does not match durable spool")]
    PutSpoolMismatch,
    #[error("object-store request deadline is invalid")]
    InvalidDeadline,
    #[error("object-store request canonical preimage exceeds its bound")]
    PreimageTooLarge,
    #[error("object-store request canonical fingerprint is invalid")]
    InvalidFingerprint,
    #[error("object-store request arithmetic overflowed")]
    ArithmeticOverflow,
}

pub fn fingerprint_object_store_request(
    request: &ObjectStoreRequestV1,
    authenticated_consumer: &AuthenticatedConsumerIdentity,
    limits: &RequestFingerprintLimits,
) -> Result<ValidatedRequest, RequestContractError> {
    validate_limits(limits)?;
    validate_authenticated_consumer(request, authenticated_consumer, &limits.identity)?;
    validate_canonical_text(
        &request.protocol_revision,
        limits.identity.max_identity_bytes,
    )?;
    validate_canonical_text(&request.policy_revision, limits.identity.max_identity_bytes)?;
    validate_canonical_text(
        &request.provider_boundary_id,
        limits.identity.max_identity_bytes,
    )?;
    validate_canonical_text(
        &request.authenticated_cell_id,
        limits.identity.max_identity_bytes,
    )?;
    validate_canonical_text(
        &request.authenticated_tenant_id,
        limits.identity.max_identity_bytes,
    )?;
    validate_canonical_text(
        &request.allocation_revision,
        limits.identity.max_identity_bytes,
    )?;
    // Cell admission is all-or-none, mirroring migration 0007's
    // CHECK (num_nonnulls(cell_admission_id, cell_admission_fence) IN (0, 2)). The cell authority
    // supplies neither (CR-033 D3), so the absent form is a legal retained state; a half-supplied
    // pair is not. Both forms fingerprint distinctly because the preimage writes both fields.
    match (
        request.cell_admission_id.is_empty(),
        request.cell_admission_fence,
    ) {
        (true, 0) => {}
        (false, fence) if fence > 0 => validate_canonical_text(
            &request.cell_admission_id,
            limits.identity.max_identity_bytes,
        )?,
        _ => return Err(RequestContractError::AuthorityMismatch),
    }
    if request.allocation_fence == 0 {
        return Err(RequestContractError::AuthorityMismatch);
    }
    let logical_timestamp = parse_canonical_uuid_v7_timestamp(&request.logical_request_id)?;
    let attempt_timestamp = parse_canonical_uuid_v7_timestamp(&request.attempt_id)?;
    if request.deadline_unix_ms < 0 {
        return Err(RequestContractError::InvalidDeadline);
    }

    let reservations = validate_and_sort_reservations(&request.reservations, &limits.reservations)?;
    let (consumer_tag, consumer_parts) =
        validate_and_encode_consumer(request, authenticated_consumer, &limits.identity)?;
    let (operation_tag, operation_parts) =
        validate_and_encode_operation(request, &limits.operation)?;

    let mut writer = CanonicalWriter::new(limits.max_fingerprint_preimage_bytes as usize);
    writer.raw(FINGERPRINT_DOMAIN)?;
    writer.text(&request.protocol_revision)?;
    writer.text(&request.provider_boundary_id)?;
    writer.text(&request.authenticated_cell_id)?;
    writer.text(&request.authenticated_tenant_id)?;
    writer.text(&request.logical_request_id)?;
    writer.text(&request.attempt_id)?;
    writer.text(&request.allocation_revision)?;
    writer.u64(request.allocation_fence)?;
    writer.text(&request.cell_admission_id)?;
    writer.u64(request.cell_admission_fence)?;
    writer.u64(request.deadline_unix_ms as u64)?;
    writer
        .u32(u32::try_from(reservations.len()).map_err(|_| RequestContractError::InvalidLimits)?)?;
    for reservation in &reservations {
        writer.text(&reservation.reservation_id)?;
        writer.text(&reservation.physical_dimension_id)?;
        writer.text(&reservation.operation_class_id)?;
        writer.u64(reservation.units)?;
    }
    writer.parts(&consumer_parts)?;
    writer.text(&request.policy_revision)?;
    writer.parts(&operation_parts)?;
    let canonical_preimage = writer.finish();
    let canonical_fingerprint = *blake3::hash(&canonical_preimage).as_bytes();

    let mut source_request = request.clone();
    source_request.canonical_fingerprint.clear();
    Ok(ValidatedRequest {
        durable_key: DurableRequestKey {
            provider_boundary_id: request.provider_boundary_id.clone(),
            authenticated_cell_id: request.authenticated_cell_id.clone(),
            authenticated_tenant_id: request.authenticated_tenant_id.clone(),
            logical_request_id: request.logical_request_id.clone(),
            attempt_id: request.attempt_id.clone(),
        },
        logical_request_timestamp_unix_ms: logical_timestamp,
        attempt_timestamp_unix_ms: attempt_timestamp,
        canonical_preimage,
        canonical_fingerprint,
        canonical_reservation_ids: reservations
            .iter()
            .map(|reservation| reservation.reservation_id.clone())
            .collect(),
        operation_tag,
        consumer_tag,
        source_request,
    })
}

pub fn validate_submitted_request_fingerprint(
    request: &ObjectStoreRequestV1,
    validated: &ValidatedRequest,
) -> Result<(), RequestContractError> {
    let mut source_request = request.clone();
    source_request.canonical_fingerprint.clear();
    if source_request != validated.source_request
        || *blake3::hash(&validated.canonical_preimage).as_bytes()
            != validated.canonical_fingerprint
        || request.canonical_fingerprint.as_ref() != validated.canonical_fingerprint
    {
        return Err(RequestContractError::InvalidFingerprint);
    }
    Ok(())
}

pub fn classify_idempotency(
    request: &ObjectStoreRequestV1,
    validated: &ValidatedRequest,
    existing: ExistingFingerprint,
) -> Result<IdempotencyDecision, RequestContractError> {
    validate_submitted_request_fingerprint(request, validated)?;
    Ok(match existing {
        ExistingFingerprint::Absent => IdempotencyDecision::FirstSeen,
        ExistingFingerprint::Full(fingerprint) | ExistingFingerprint::Compact(fingerprint)
            if fingerprint == validated.canonical_fingerprint =>
        {
            IdempotencyDecision::ExactReplay
        }
        ExistingFingerprint::Full(_) | ExistingFingerprint::Compact(_) => {
            IdempotencyDecision::IdentityReuseConflict
        }
    })
}

pub fn classify_first_seen_identity(
    database_now_unix_ms: i64,
    logical_request_id: &str,
    attempt_id: &str,
) -> Result<FirstSeenIdentityDecision, RequestContractError> {
    if database_now_unix_ms < 0 {
        return Err(RequestContractError::InvalidDeadline);
    }
    let logical = match parse_canonical_uuid_v7_timestamp(logical_request_id) {
        Ok(timestamp) => timestamp,
        Err(_) => return Ok(FirstSeenIdentityDecision::InvalidUuidV7),
    };
    let attempt = match parse_canonical_uuid_v7_timestamp(attempt_id) {
        Ok(timestamp) => timestamp,
        Err(_) => return Ok(FirstSeenIdentityDecision::InvalidUuidV7),
    };
    let upper = database_now_unix_ms
        .checked_add(UUID_FUTURE_WINDOW_MS)
        .ok_or(RequestContractError::ArithmeticOverflow)? as u64;
    let lower = if database_now_unix_ms > UUID_PAST_WINDOW_MS {
        (database_now_unix_ms - UUID_PAST_WINDOW_MS) as u64
    } else {
        0
    };
    if logical > upper || attempt > upper {
        return Ok(FirstSeenIdentityDecision::TimestampTooFarInFuture);
    }
    if logical < lower || attempt < lower {
        return Ok(FirstSeenIdentityDecision::ExpiredOrUnknown);
    }
    Ok(FirstSeenIdentityDecision::Admit {
        logical_request_timestamp_unix_ms: logical,
        attempt_timestamp_unix_ms: attempt,
    })
}

pub fn validate_first_seen_prerequisites(
    request: &ObjectStoreRequestV1,
    validated: &ValidatedRequest,
    prerequisites: &FirstSeenPrerequisites<'_>,
    limits: &RequestFingerprintLimits,
) -> Result<FirstSeenIdentityDecision, RequestContractError> {
    validate_submitted_request_fingerprint(request, validated)?;
    let identity = classify_first_seen_identity(
        prerequisites.database_now_unix_ms,
        &request.logical_request_id,
        &request.attempt_id,
    )?;
    if !matches!(identity, FirstSeenIdentityDecision::Admit { .. }) {
        return Ok(identity);
    }
    validate_expected_authority(request, prerequisites.expected_authority, &limits.identity)?;
    validate_expected_admission(
        request,
        prerequisites.expected_cell_admission,
        &limits.identity,
    )?;
    validate_first_seen_deadline(request.deadline_unix_ms, prerequisites)?;
    validate_reservation_requirements(
        &request.reservations,
        prerequisites.reservation_requirements,
        &limits.reservations,
    )?;
    validate_put_spool(request, prerequisites.put_spool, &limits.operation)?;
    Ok(identity)
}

fn validate_limits(limits: &RequestFingerprintLimits) -> Result<(), RequestContractError> {
    let positive = [
        limits.identity.max_identity_bytes,
        limits.identity.max_authenticated_scope_bytes,
        limits.reservations.max_reserved_dimensions_per_request,
        limits.reservations.max_reservation_id_bytes,
        limits.reservations.max_physical_dimension_id_bytes,
        limits.reservations.max_operation_class_id_bytes,
        limits.operation.max_bucket_bytes,
        limits.operation.max_key_bytes,
        limits.operation.max_opaque_value_bytes,
        limits.operation.max_body_handle_bytes,
        limits.operation.max_metadata_entries,
        limits.operation.max_metadata_key_bytes,
        limits.operation.max_metadata_value_bytes,
        limits.operation.max_metadata_aggregate_bytes,
        limits.operation.max_list_entries,
        limits.max_fingerprint_preimage_bytes,
    ];
    if positive.contains(&0) || limits.operation.max_result_bytes == 0 {
        return Err(RequestContractError::InvalidLimits);
    }
    let mut allowed = HashSet::new();
    for key in &limits.operation.allowed_metadata_keys {
        validate_metadata_key(key, &limits.operation)
            .map_err(|_| RequestContractError::InvalidLimits)?;
        if !allowed.insert(key) {
            return Err(RequestContractError::InvalidLimits);
        }
    }
    Ok(())
}

fn validate_authenticated_consumer(
    request: &ObjectStoreRequestV1,
    identity: &AuthenticatedConsumerIdentity,
    limits: &RequestIdentityLimits,
) -> Result<(), RequestContractError> {
    for value in [
        &identity.provider_boundary_id,
        &identity.authenticated_cell_id,
        &identity.authenticated_tenant_id,
    ] {
        validate_canonical_text(value, limits.max_identity_bytes)?;
    }
    if request.provider_boundary_id != identity.provider_boundary_id
        || request.authenticated_cell_id != identity.authenticated_cell_id
        || request.authenticated_tenant_id != identity.authenticated_tenant_id
    {
        return Err(RequestContractError::AuthorityMismatch);
    }
    Ok(())
}

/// A revision string carried by the cell's authority context.
///
/// Folded verbatim from the removed `authority.rs` (CR-033 D3). `validate_canonical_text` bounds
/// length and pins NFC but permits control characters, and its bound is caller-supplied; an
/// authority revision additionally rejects control characters and is pinned to
/// `MAX_CANONICAL_ID_BYTES` regardless of the caller's limit.
fn validate_authority_revision(value: &str) -> Result<(), RequestContractError> {
    if value.len() > MAX_CANONICAL_ID_BYTES || value.chars().any(char::is_control) {
        return Err(RequestContractError::InvalidCanonicalText);
    }
    Ok(())
}

fn validate_expected_authority(
    request: &ObjectStoreRequestV1,
    expected: &ExpectedRequestAuthority,
    limits: &RequestIdentityLimits,
) -> Result<(), RequestContractError> {
    for value in [
        &expected.protocol_revision,
        &expected.policy_revision,
        &expected.provider_boundary_id,
        &expected.authenticated_cell_id,
        &expected.authenticated_tenant_id,
        &expected.allocation_revision,
    ] {
        validate_canonical_text(value, limits.max_identity_bytes)?;
    }
    // The revision and identity checks the removed `authority.rs` applied to the same fields.
    for revision in [
        &expected.protocol_revision,
        &expected.policy_revision,
        &expected.allocation_revision,
        &request.protocol_revision,
        &request.policy_revision,
        &request.allocation_revision,
    ] {
        validate_authority_revision(revision)?;
    }
    for id in [
        &expected.provider_boundary_id,
        &expected.authenticated_cell_id,
        &expected.authenticated_tenant_id,
        &request.provider_boundary_id,
        &request.authenticated_cell_id,
        &request.authenticated_tenant_id,
    ] {
        validate_canonical_id(id).map_err(|_| RequestContractError::InvalidCanonicalText)?;
    }
    if expected.allocation_fence == 0
        || request.protocol_revision != expected.protocol_revision
        || request.policy_revision != expected.policy_revision
        || request.provider_boundary_id != expected.provider_boundary_id
        || request.authenticated_cell_id != expected.authenticated_cell_id
        || request.authenticated_tenant_id != expected.authenticated_tenant_id
        || request.allocation_revision != expected.allocation_revision
        || request.allocation_fence != expected.allocation_fence
    {
        return Err(RequestContractError::AuthorityMismatch);
    }
    Ok(())
}

fn validate_expected_admission(
    request: &ObjectStoreRequestV1,
    expected: Option<&ExpectedCellAdmission>,
    limits: &RequestIdentityLimits,
) -> Result<(), RequestContractError> {
    let Some(expected) = expected else {
        // The cell authority holds no admission identity, so the request must carry none.
        if !request.cell_admission_id.is_empty() || request.cell_admission_fence != 0 {
            return Err(RequestContractError::CellAdmissionMismatch);
        }
        return Ok(());
    };
    validate_canonical_text(&expected.cell_admission_id, limits.max_identity_bytes)?;
    validate_canonical_id(&expected.cell_admission_id)
        .map_err(|_| RequestContractError::InvalidCanonicalText)?;
    if expected.cell_admission_fence == 0
        || request.cell_admission_id != expected.cell_admission_id
        || request.cell_admission_fence != expected.cell_admission_fence
    {
        return Err(RequestContractError::CellAdmissionMismatch);
    }
    Ok(())
}

fn validate_and_sort_reservations<'a>(
    reservations: &'a [ReservedDimensionV1],
    limits: &ReservationPolicyLimits,
) -> Result<Vec<&'a ReservedDimensionV1>, RequestContractError> {
    if reservations.is_empty()
        || reservations.len() > limits.max_reserved_dimensions_per_request as usize
    {
        return Err(RequestContractError::InvalidReservations);
    }
    let mut ids = HashSet::new();
    let mut pairs = HashSet::new();
    for reservation in reservations {
        validate_canonical_text(&reservation.reservation_id, limits.max_reservation_id_bytes)
            .map_err(|_| RequestContractError::InvalidReservations)?;
        validate_canonical_text(
            &reservation.physical_dimension_id,
            limits.max_physical_dimension_id_bytes,
        )
        .map_err(|_| RequestContractError::InvalidReservations)?;
        validate_canonical_text(
            &reservation.operation_class_id,
            limits.max_operation_class_id_bytes,
        )
        .map_err(|_| RequestContractError::InvalidReservations)?;
        if reservation.units == 0
            || !ids.insert(reservation.reservation_id.as_str())
            || !pairs.insert((
                reservation.physical_dimension_id.as_str(),
                reservation.operation_class_id.as_str(),
            ))
        {
            return Err(RequestContractError::InvalidReservations);
        }
    }
    let mut canonical: Vec<_> = reservations.iter().collect();
    canonical.sort_by(|left, right| {
        compare_utf8(&left.physical_dimension_id, &right.physical_dimension_id)
            .then_with(|| compare_utf8(&left.operation_class_id, &right.operation_class_id))
            .then_with(|| compare_utf8(&left.reservation_id, &right.reservation_id))
    });
    Ok(canonical)
}

fn validate_reservation_requirements(
    reservations: &[ReservedDimensionV1],
    requirements: &[ReservationRequirement],
    limits: &ReservationPolicyLimits,
) -> Result<(), RequestContractError> {
    if requirements.len() != reservations.len() {
        return Err(RequestContractError::InvalidReservations);
    }
    let mut required_pairs = HashSet::new();
    for requirement in requirements {
        validate_canonical_text(
            &requirement.physical_dimension_id,
            limits.max_physical_dimension_id_bytes,
        )
        .map_err(|_| RequestContractError::InvalidReservations)?;
        validate_canonical_text(
            &requirement.operation_class_id,
            limits.max_operation_class_id_bytes,
        )
        .map_err(|_| RequestContractError::InvalidReservations)?;
        if requirement.units == 0
            || !required_pairs.insert((
                requirement.physical_dimension_id.as_str(),
                requirement.operation_class_id.as_str(),
            ))
        {
            return Err(RequestContractError::InvalidReservations);
        }
    }
    for reservation in reservations {
        let Some(requirement) = requirements.iter().find(|requirement| {
            requirement.physical_dimension_id == reservation.physical_dimension_id
                && requirement.operation_class_id == reservation.operation_class_id
        }) else {
            return Err(RequestContractError::InvalidReservations);
        };
        if requirement.units != reservation.units {
            return Err(RequestContractError::InvalidReservations);
        }
    }
    Ok(())
}

fn validate_and_encode_consumer(
    request: &ObjectStoreRequestV1,
    identity: &AuthenticatedConsumerIdentity,
    limits: &RequestIdentityLimits,
) -> Result<(u32, Vec<CanonicalPart>), RequestContractError> {
    let context = request
        .consumer_context
        .as_ref()
        .ok_or(RequestContractError::InvalidConsumerContext)?;
    let operation = request
        .operation
        .as_ref()
        .ok_or(RequestContractError::InvalidConsumerContext)?;
    validate_and_encode_result_consumer_context(operation, context, identity, limits)
}

pub(crate) fn validate_result_consumer_context(
    operation: &object_store_request_v1::Operation,
    context: &ResultConsumerContextV1,
    identity: &AuthenticatedConsumerIdentity,
    limits: &RequestIdentityLimits,
) -> Result<(), RequestContractError> {
    if limits.max_identity_bytes == 0 || limits.max_authenticated_scope_bytes == 0 {
        return Err(RequestContractError::InvalidLimits);
    }
    validate_and_encode_result_consumer_context(operation, context, identity, limits).map(|_| ())
}

fn validate_and_encode_result_consumer_context(
    operation: &object_store_request_v1::Operation,
    context: &ResultConsumerContextV1,
    identity: &AuthenticatedConsumerIdentity,
    limits: &RequestIdentityLimits,
) -> Result<(u32, Vec<CanonicalPart>), RequestContractError> {
    match operation {
        object_store_request_v1::Operation::HeadBucket(_)
        | object_store_request_v1::Operation::ListObjectsV2(_)
        | object_store_request_v1::Operation::HeadObject(_)
        | object_store_request_v1::Operation::GetObject(_)
        | object_store_request_v1::Operation::PutObject(_)
        | object_store_request_v1::Operation::ListObjectVersions(_)
        | object_store_request_v1::Operation::DeleteObject(_) => {}
    }
    let consumer = context
        .consumer
        .as_ref()
        .ok_or(RequestContractError::InvalidConsumerContext)?;
    match consumer {
        result_consumer_context_v1::Consumer::FragmentLifecycle(context) => {
            if !matches!(
                operation,
                object_store_request_v1::Operation::HeadObject(_)
                    | object_store_request_v1::Operation::GetObject(_)
                    | object_store_request_v1::Operation::PutObject(_)
                    | object_store_request_v1::Operation::ListObjectVersions(_)
                    | object_store_request_v1::Operation::DeleteObject(_)
            ) || context.fragment_id.len() != 32
                || context.lifecycle_generation == 0
                || context.fragment_epoch == 0
                || context.lifecycle_fence == 0
            {
                return Err(RequestContractError::InvalidConsumerContext);
            }
            let association_count = [
                context.repository_id.is_some(),
                context.association_context.is_some(),
                context.repository_generation.is_some(),
                context.association_epoch.is_some(),
            ]
            .into_iter()
            .filter(|present| *present)
            .count();
            if association_count != 0 && association_count != 4 {
                return Err(RequestContractError::InvalidConsumerContext);
            }
            if let (Some(repository_id), Some(association_context), Some(generation), Some(epoch)) = (
                context.repository_id.as_ref(),
                context.association_context.as_ref(),
                context.repository_generation,
                context.association_epoch,
            ) {
                validate_canonical_text(repository_id, limits.max_identity_bytes)
                    .map_err(|_| RequestContractError::InvalidConsumerContext)?;
                validate_canonical_text(association_context, limits.max_identity_bytes)
                    .map_err(|_| RequestContractError::InvalidConsumerContext)?;
                if generation == 0 || epoch == 0 {
                    return Err(RequestContractError::InvalidConsumerContext);
                }
            }
            let reader_count = usize::from(context.reader_lease_id.is_some())
                + usize::from(context.reader_fence.is_some());
            if reader_count == 1
                || (matches!(
                    operation,
                    object_store_request_v1::Operation::HeadObject(_)
                        | object_store_request_v1::Operation::GetObject(_)
                ) && reader_count != 2)
            {
                return Err(RequestContractError::InvalidConsumerContext);
            }
            if let (Some(lease), Some(fence)) = (&context.reader_lease_id, context.reader_fence) {
                validate_canonical_text(lease, limits.max_identity_bytes)
                    .map_err(|_| RequestContractError::InvalidConsumerContext)?;
                if fence == 0 {
                    return Err(RequestContractError::InvalidConsumerContext);
                }
            }
            Ok((
                1,
                vec![
                    CanonicalPart::U32(1),
                    CanonicalPart::Bytes(context.fragment_id.to_vec()),
                    CanonicalPart::OptionalText(context.repository_id.clone()),
                    CanonicalPart::OptionalText(context.association_context.clone()),
                    CanonicalPart::OptionalU64(context.repository_generation),
                    CanonicalPart::OptionalU64(context.association_epoch),
                    CanonicalPart::U64(context.lifecycle_generation),
                    CanonicalPart::U64(context.fragment_epoch),
                    CanonicalPart::U64(context.lifecycle_fence),
                    CanonicalPart::OptionalText(context.reader_lease_id.clone()),
                    CanonicalPart::OptionalU64(context.reader_fence),
                ],
            ))
        }
        result_consumer_context_v1::Consumer::StartupAdmission(context) => {
            if !matches!(operation, object_store_request_v1::Operation::HeadBucket(_))
                || context.readiness_generation == 0
            {
                return Err(RequestContractError::InvalidConsumerContext);
            }
            for value in [
                &context.policy_revision,
                &context.allocation_revision,
                &context.config_revision,
                &context.startup_attempt_id,
            ] {
                validate_canonical_text(value, limits.max_identity_bytes)
                    .map_err(|_| RequestContractError::InvalidConsumerContext)?;
            }
            Ok((
                2,
                vec![
                    CanonicalPart::U32(2),
                    CanonicalPart::Text(context.policy_revision.clone()),
                    CanonicalPart::Text(context.allocation_revision.clone()),
                    CanonicalPart::Text(context.config_revision.clone()),
                    CanonicalPart::Text(context.startup_attempt_id.clone()),
                    CanonicalPart::U64(context.readiness_generation),
                ],
            ))
        }
        result_consumer_context_v1::Consumer::DurableConsumer(context) => {
            validate_canonical_text(&context.operation_id, limits.max_identity_bytes)
                .map_err(|_| RequestContractError::InvalidConsumerContext)?;
            if context.checkpoint_revision == 0 || context.checkpoint_fence == 0 {
                return Err(RequestContractError::InvalidConsumerContext);
            }
            let (kind_tag, kind_text) = match DurableConsumerKindV1::try_from(context.consumer_kind)
            {
                Ok(DurableConsumerKindV1::DurableConsumerKindJob) => (1, "job"),
                Ok(DurableConsumerKindV1::DurableConsumerKindOperator) => (2, "operator"),
                Ok(DurableConsumerKindV1::DurableConsumerKindMigrator) => (3, "migrator"),
                _ => return Err(RequestContractError::InvalidConsumerContext),
            };
            let scope = reconstruct_authenticated_scope(identity, kind_text, limits)?;
            if context.authenticated_scope != scope {
                return Err(RequestContractError::InvalidConsumerContext);
            }
            Ok((
                3,
                vec![
                    CanonicalPart::U32(3),
                    CanonicalPart::U8(kind_tag),
                    CanonicalPart::Text(context.authenticated_scope.clone()),
                    CanonicalPart::Text(context.operation_id.clone()),
                    CanonicalPart::U64(context.checkpoint_revision),
                    CanonicalPart::U64(context.checkpoint_fence),
                ],
            ))
        }
    }
}

fn reconstruct_authenticated_scope(
    identity: &AuthenticatedConsumerIdentity,
    kind: &str,
    limits: &RequestIdentityLimits,
) -> Result<String, RequestContractError> {
    for value in [
        &identity.provider_boundary_id,
        &identity.authenticated_cell_id,
        &identity.authenticated_tenant_id,
        &identity.principal_id,
    ] {
        validate_canonical_text(value, limits.max_identity_bytes)
            .map_err(|_| RequestContractError::InvalidConsumerContext)?;
    }
    let encode = |value: &str| URL_SAFE_NO_PAD.encode(value.as_bytes());
    let scope = format!(
        "urn:lore:object-dispatch:{}:{}:{}:{kind}:{}",
        encode(&identity.provider_boundary_id),
        encode(&identity.authenticated_cell_id),
        encode(&identity.authenticated_tenant_id),
        encode(&identity.principal_id),
    );
    validate_canonical_text(&scope, limits.max_authenticated_scope_bytes)
        .map_err(|_| RequestContractError::InvalidConsumerContext)?;
    Ok(scope)
}

fn validate_and_encode_operation(
    request: &ObjectStoreRequestV1,
    limits: &ObjectStoreOperationLimits,
) -> Result<(u32, Vec<CanonicalPart>), RequestContractError> {
    let operation = request
        .operation
        .as_ref()
        .ok_or(RequestContractError::InvalidOperation)?;
    match operation {
        object_store_request_v1::Operation::HeadBucket(value) => {
            validate_bucket(&value.bucket, limits)?;
            Ok((
                20,
                vec![
                    CanonicalPart::U32(20),
                    CanonicalPart::Text(value.bucket.clone()),
                ],
            ))
        }
        object_store_request_v1::Operation::ListObjectsV2(value) => {
            validate_list_fields(
                &value.bucket,
                &value.prefix,
                &value.delimiter,
                value.max_keys,
                limits,
            )?;
            validate_optional_raw(&value.continuation_token, limits.max_opaque_value_bytes)?;
            Ok((
                21,
                vec![
                    CanonicalPart::U32(21),
                    CanonicalPart::Text(value.bucket.clone()),
                    CanonicalPart::Text(value.prefix.clone()),
                    CanonicalPart::Text(value.delimiter.clone()),
                    CanonicalPart::U32(value.max_keys),
                    CanonicalPart::OptionalText(value.continuation_token.clone()),
                ],
            ))
        }
        object_store_request_v1::Operation::HeadObject(value) => {
            validate_bucket(&value.bucket, limits)?;
            validate_raw_text(&value.key, limits.max_key_bytes, false)?;
            Ok((
                22,
                vec![
                    CanonicalPart::U32(22),
                    CanonicalPart::Text(value.bucket.clone()),
                    CanonicalPart::Text(value.key.clone()),
                ],
            ))
        }
        object_store_request_v1::Operation::GetObject(value) => {
            validate_bucket(&value.bucket, limits)?;
            validate_raw_text(&value.key, limits.max_key_bytes, false)?;
            if value.range_length == 0
                || value.range_length > limits.max_result_bytes
                || value.range_start.checked_add(value.range_length).is_none()
            {
                return Err(RequestContractError::InvalidOperation);
            }
            Ok((
                23,
                vec![
                    CanonicalPart::U32(23),
                    CanonicalPart::Text(value.bucket.clone()),
                    CanonicalPart::Text(value.key.clone()),
                    CanonicalPart::U64(value.range_start),
                    CanonicalPart::U64(value.range_length),
                ],
            ))
        }
        object_store_request_v1::Operation::PutObject(value) => {
            validate_bucket(&value.bucket, limits)?;
            validate_raw_text(&value.key, limits.max_key_bytes, false)?;
            validate_canonical_text(&value.durable_body_handle, limits.max_body_handle_bytes)
                .map_err(|_| RequestContractError::InvalidOperation)?;
            if value.body_size > limits.max_body_bytes || value.body_blake3.len() != 32 {
                return Err(RequestContractError::InvalidOperation);
            }
            let metadata = validate_and_sort_metadata(&value.metadata, limits)?;
            let mut parts = vec![
                CanonicalPart::U32(24),
                CanonicalPart::Text(value.bucket.clone()),
                CanonicalPart::Text(value.key.clone()),
                CanonicalPart::Text(value.durable_body_handle.clone()),
                CanonicalPart::U64(value.body_size),
                CanonicalPart::Bytes(value.body_blake3.to_vec()),
                CanonicalPart::U32(
                    u32::try_from(metadata.len())
                        .map_err(|_| RequestContractError::InvalidLimits)?,
                ),
            ];
            for entry in metadata {
                parts.push(CanonicalPart::Text(entry.key.clone()));
                parts.push(CanonicalPart::Text(entry.value.clone()));
            }
            Ok((24, parts))
        }
        object_store_request_v1::Operation::ListObjectVersions(value) => {
            validate_list_fields(
                &value.bucket,
                &value.prefix,
                &value.delimiter,
                value.max_keys,
                limits,
            )?;
            validate_optional_raw(&value.key_marker, limits.max_opaque_value_bytes)?;
            validate_optional_raw(&value.version_id_marker, limits.max_opaque_value_bytes)?;
            Ok((
                25,
                vec![
                    CanonicalPart::U32(25),
                    CanonicalPart::Text(value.bucket.clone()),
                    CanonicalPart::Text(value.prefix.clone()),
                    CanonicalPart::Text(value.delimiter.clone()),
                    CanonicalPart::U32(value.max_keys),
                    CanonicalPart::OptionalText(value.key_marker.clone()),
                    CanonicalPart::OptionalText(value.version_id_marker.clone()),
                ],
            ))
        }
        object_store_request_v1::Operation::DeleteObject(value) => {
            validate_bucket(&value.bucket, limits)?;
            validate_raw_text(&value.key, limits.max_key_bytes, false)?;
            validate_optional_raw(&value.version_id, limits.max_opaque_value_bytes)?;
            Ok((
                26,
                vec![
                    CanonicalPart::U32(26),
                    CanonicalPart::Text(value.bucket.clone()),
                    CanonicalPart::Text(value.key.clone()),
                    CanonicalPart::OptionalText(value.version_id.clone()),
                ],
            ))
        }
    }
}

fn validate_list_fields(
    bucket: &str,
    prefix: &str,
    delimiter: &str,
    max_keys: u32,
    limits: &ObjectStoreOperationLimits,
) -> Result<(), RequestContractError> {
    validate_bucket(bucket, limits)?;
    validate_raw_text(prefix, limits.max_key_bytes, true)?;
    validate_raw_text(delimiter, limits.max_key_bytes, true)?;
    if max_keys == 0 || max_keys > limits.max_list_entries {
        return Err(RequestContractError::InvalidOperation);
    }
    Ok(())
}

fn validate_bucket(
    value: &str,
    limits: &ObjectStoreOperationLimits,
) -> Result<(), RequestContractError> {
    validate_raw_text(value, limits.max_bucket_bytes, false)?;
    let bytes = value.as_bytes();
    let valid_chars = bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
    });
    let edge = bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    let ipv4_looking = value.split('.').count() == 4
        && value.split('.').all(|part| {
            (1..=3).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_digit())
        });
    if !(3..=63).contains(&bytes.len())
        || !valid_chars
        || !edge
        || value.contains("..")
        || value.contains(".-")
        || value.contains("-.")
        || ipv4_looking
    {
        return Err(RequestContractError::InvalidOperation);
    }
    Ok(())
}

fn validate_and_sort_metadata<'a>(
    metadata: &'a [ObjectMetadataEntryV1],
    limits: &ObjectStoreOperationLimits,
) -> Result<Vec<&'a ObjectMetadataEntryV1>, RequestContractError> {
    if metadata.len() > limits.max_metadata_entries as usize {
        return Err(RequestContractError::InvalidOperation);
    }
    let allowed: HashSet<&str> = limits
        .allowed_metadata_keys
        .iter()
        .map(String::as_str)
        .collect();
    let mut seen = HashSet::new();
    let mut aggregate = 0usize;
    for entry in metadata {
        validate_metadata_key(&entry.key, limits)?;
        validate_raw_text(&entry.value, limits.max_metadata_value_bytes, true)?;
        if !allowed.contains(entry.key.as_str()) || !seen.insert(entry.key.as_str()) {
            return Err(RequestContractError::InvalidOperation);
        }
        aggregate = aggregate
            .checked_add(entry.key.len())
            .and_then(|value| value.checked_add(entry.value.len()))
            .ok_or(RequestContractError::ArithmeticOverflow)?;
        if aggregate > limits.max_metadata_aggregate_bytes as usize {
            return Err(RequestContractError::InvalidOperation);
        }
    }
    let mut canonical: Vec<_> = metadata.iter().collect();
    canonical.sort_by(|left, right| {
        compare_utf8(&left.key, &right.key).then_with(|| compare_utf8(&left.value, &right.value))
    });
    Ok(canonical)
}

fn validate_metadata_key(
    value: &str,
    limits: &ObjectStoreOperationLimits,
) -> Result<(), RequestContractError> {
    validate_raw_text(value, limits.max_metadata_key_bytes, false)?;
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(RequestContractError::InvalidOperation);
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(RequestContractError::InvalidOperation);
    }
    Ok(())
}

fn validate_optional_raw(value: &Option<String>, maximum: u32) -> Result<(), RequestContractError> {
    if let Some(value) = value {
        validate_raw_text(value, maximum, true)?;
    }
    Ok(())
}

fn validate_put_spool(
    request: &ObjectStoreRequestV1,
    expected: Option<&DurablePutSpoolExpectation>,
    limits: &ObjectStoreOperationLimits,
) -> Result<(), RequestContractError> {
    match (request.operation.as_ref(), expected) {
        (Some(object_store_request_v1::Operation::PutObject(put)), Some(expected)) => {
            validate_canonical_text(&expected.durable_body_handle, limits.max_body_handle_bytes)
                .map_err(|_| RequestContractError::PutSpoolMismatch)?;
            if expected.durable_body_handle != put.durable_body_handle
                || expected.body_size != put.body_size
                || expected.body_blake3.as_slice() != put.body_blake3.as_ref()
            {
                return Err(RequestContractError::PutSpoolMismatch);
            }
            Ok(())
        }
        (Some(object_store_request_v1::Operation::PutObject(_)), None) | (_, Some(_)) => {
            Err(RequestContractError::PutSpoolMismatch)
        }
        (_, None) => Ok(()),
    }
}

fn validate_first_seen_deadline(
    deadline_unix_ms: i64,
    prerequisites: &FirstSeenPrerequisites<'_>,
) -> Result<(), RequestContractError> {
    let values = [
        deadline_unix_ms,
        prerequisites.database_now_unix_ms,
        prerequisites.max_request_deadline_horizon_ms,
        prerequisites.cell_allocation_hard_expiry_unix_ms,
        prerequisites.dispatch_authority_hard_expiry_unix_ms,
    ];
    if values.iter().any(|value| *value < 0) || prerequisites.max_request_deadline_horizon_ms == 0 {
        return Err(RequestContractError::InvalidDeadline);
    }
    let horizon = prerequisites
        .database_now_unix_ms
        .checked_add(prerequisites.max_request_deadline_horizon_ms)
        .ok_or(RequestContractError::ArithmeticOverflow)?;
    if deadline_unix_ms <= prerequisites.database_now_unix_ms
        || deadline_unix_ms > horizon
        || deadline_unix_ms > prerequisites.cell_allocation_hard_expiry_unix_ms
        || deadline_unix_ms > prerequisites.dispatch_authority_hard_expiry_unix_ms
    {
        return Err(RequestContractError::InvalidDeadline);
    }
    Ok(())
}

fn parse_canonical_uuid_v7_timestamp(value: &str) -> Result<u64, RequestContractError> {
    canonical_uuid_v7_timestamp(value).map_err(|_| RequestContractError::InvalidUuidV7)
}

fn validate_canonical_text(value: &str, maximum: u32) -> Result<(), RequestContractError> {
    if value.is_empty()
        || value.len() > maximum as usize
        || value.contains('\0')
        || value.nfc().ne(value.chars())
    {
        return Err(RequestContractError::InvalidCanonicalText);
    }
    Ok(())
}

fn validate_raw_text(
    value: &str,
    maximum: u32,
    allow_empty: bool,
) -> Result<(), RequestContractError> {
    if value.contains('\0') || (!allow_empty && value.is_empty()) || value.len() > maximum as usize
    {
        return Err(RequestContractError::InvalidOperation);
    }
    Ok(())
}

fn compare_utf8(left: &str, right: &str) -> Ordering {
    left.as_bytes().cmp(right.as_bytes())
}

enum CanonicalPart {
    U8(u8),
    U32(u32),
    U64(u64),
    Text(String),
    Bytes(Vec<u8>),
    OptionalText(Option<String>),
    OptionalU64(Option<u64>),
}

struct CanonicalWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl CanonicalWriter {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn ensure(&self, additional: usize) -> Result<(), RequestContractError> {
        if self
            .bytes
            .len()
            .checked_add(additional)
            .is_none_or(|size| size > self.maximum)
        {
            return Err(RequestContractError::PreimageTooLarge);
        }
        Ok(())
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), RequestContractError> {
        self.ensure(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), RequestContractError> {
        self.raw(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), RequestContractError> {
        self.raw(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), RequestContractError> {
        self.raw(&value.to_be_bytes())
    }

    fn text(&mut self, value: &str) -> Result<(), RequestContractError> {
        self.bytes(value.as_bytes())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), RequestContractError> {
        let length = u32::try_from(value.len()).map_err(|_| RequestContractError::InvalidLimits)?;
        self.u32(length)?;
        self.raw(value)
    }

    fn parts(&mut self, parts: &[CanonicalPart]) -> Result<(), RequestContractError> {
        for part in parts {
            match part {
                CanonicalPart::U8(value) => self.u8(*value)?,
                CanonicalPart::U32(value) => self.u32(*value)?,
                CanonicalPart::U64(value) => self.u64(*value)?,
                CanonicalPart::Text(value) => self.text(value)?,
                CanonicalPart::Bytes(value) => self.bytes(value)?,
                CanonicalPart::OptionalText(value) => {
                    self.u8(u8::from(value.is_some()))?;
                    if let Some(value) = value {
                        self.text(value)?;
                    }
                }
                CanonicalPart::OptionalU64(value) => {
                    self.u8(u8::from(value.is_some()))?;
                    if let Some(value) = value {
                        self.u64(*value)?;
                    }
                }
            }
        }
        Ok(())
    }
}
