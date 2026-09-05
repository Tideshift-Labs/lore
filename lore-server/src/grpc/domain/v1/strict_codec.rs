// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Bounded decoded-field and raw protobuf validation for the CR-029 private
//! receipt-v2 rail.

use lore_proto::lore::domain::v1::DomainOperationAttemptReceiptGetRequest;
use lore_proto::lore::domain::v1::DomainOperationPrepareRequest;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceMaterializeRequestV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceRetireRequestV1;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetRequest;
use lore_proto::lore::domain::v1::DomainOperationTerminalStatusAttachRequest;
use lore_proto::lore::domain::v1::DomainOperationVerifiedStaleFinalizeRequest;
use lore_proto::lore::domain::v1::TerminalStatusAttachPhase2ActionV1;
use lore_proto::lore::domain::v1::TerminalStatusAttachPhaseV1;
use tonic::Status;
use uuid::Uuid;

const UUID_LEN: usize = 16;
const DIGEST_LEN: usize = 32;
const MAX_METHOD_LEN: usize = 128;
const MAX_SCOPE_LEN: usize = 4096;
const MAX_PRINCIPAL_NAMESPACE_LEN: usize = 49;
const MAX_RAW_REQUEST_LEN: usize = 16 * 1024;
const MAX_ISSUER_OR_SUBJECT_LEN: usize = 256;
const MAX_SIGNED_JWT_LEN: usize = 8 * 1024;

#[derive(Clone, Copy)]
enum RawWire {
    Varint,
    LengthDelimited(usize),
}

#[derive(Clone, Copy)]
struct RawField {
    tag: u32,
    wire: RawWire,
    presence: RawPresence,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RawPresence {
    Required,
    MayBeImplicitlyAbsent,
}

const fn ld(tag: u32, maximum: usize) -> RawField {
    RawField {
        tag,
        wire: RawWire::LengthDelimited(maximum),
        presence: RawPresence::Required,
    }
}

const fn varint(tag: u32) -> RawField {
    RawField {
        tag,
        wire: RawWire::Varint,
        presence: RawPresence::Required,
    }
}

const fn optional_ld(tag: u32, maximum: usize) -> RawField {
    RawField {
        tag,
        wire: RawWire::LengthDelimited(maximum),
        presence: RawPresence::MayBeImplicitlyAbsent,
    }
}

const fn implicit_varint(tag: u32) -> RawField {
    RawField {
        tag,
        wire: RawWire::Varint,
        presence: RawPresence::MayBeImplicitlyAbsent,
    }
}

fn varint_encoded_len(value: u64) -> usize {
    let significant_bits = 64usize.saturating_sub(value.leading_zeros() as usize);
    significant_bits.max(1).div_ceil(7)
}

fn read_raw_varint(raw: &[u8], offset: &mut usize) -> Result<u64, Status> {
    let start = *offset;
    let mut value = 0u64;
    for shift in (0..=63).step_by(7) {
        let byte = *raw
            .get(*offset)
            .ok_or_else(|| Status::invalid_argument("truncated protobuf varint"))?;
        *offset += 1;
        if shift == 63 && byte > 1 {
            return Err(Status::invalid_argument("overflow protobuf varint"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            if *offset - start != varint_encoded_len(value) {
                return Err(Status::invalid_argument("noncanonical protobuf varint"));
            }
            return Ok(value);
        }
    }
    Err(Status::invalid_argument("overflow protobuf varint"))
}

fn validate_raw_fields(raw: &[u8], rules: &[RawField]) -> Result<(u64, [u64; 64]), Status> {
    if raw.len() > MAX_RAW_REQUEST_LEN {
        return Err(Status::invalid_argument(
            "protobuf request exceeds 16384 bytes",
        ));
    }
    let mut offset = 0usize;
    let mut seen = 0u64;
    let mut values = [0u64; 64];
    while offset < raw.len() {
        let key = read_raw_varint(raw, &mut offset)?;
        let tag = u32::try_from(key >> 3)
            .map_err(|_| Status::invalid_argument("protobuf field tag overflows u32"))?;
        if tag == 0 || tag > 63 {
            return Err(Status::invalid_argument("invalid protobuf field tag"));
        }
        let rule = rules
            .iter()
            .find(|rule| rule.tag == tag)
            .ok_or_else(|| Status::invalid_argument(format!("unknown protobuf field {tag}")))?;
        let bit = 1u64 << tag;
        if seen & bit != 0 {
            return Err(Status::invalid_argument(format!(
                "duplicate singular protobuf field {tag}"
            )));
        }
        seen |= bit;
        let actual_wire = (key & 0x07) as u8;
        match rule.wire {
            RawWire::Varint => {
                if actual_wire != 0 {
                    return Err(Status::invalid_argument(format!(
                        "protobuf field {tag} has wrong wire type"
                    )));
                }
                values[tag as usize] = read_raw_varint(raw, &mut offset)?;
            }
            RawWire::LengthDelimited(maximum) => {
                if actual_wire != 2 {
                    return Err(Status::invalid_argument(format!(
                        "protobuf field {tag} has wrong wire type"
                    )));
                }
                let length = read_raw_varint(raw, &mut offset)?;
                let length = usize::try_from(length)
                    .map_err(|_| Status::invalid_argument("protobuf length overflows usize"))?;
                if length > maximum {
                    return Err(Status::invalid_argument(format!(
                        "protobuf field {tag} exceeds its canonical bound"
                    )));
                }
                offset = offset
                    .checked_add(length)
                    .filter(|end| *end <= raw.len())
                    .ok_or_else(|| Status::invalid_argument("truncated length-delimited field"))?;
            }
        }
    }
    let required_mask = rules.iter().fold(0_u64, |required, rule| {
        if rule.presence == RawPresence::Required {
            required | (1_u64 << rule.tag)
        } else {
            required
        }
    });
    if seen & required_mask != required_mask {
        return Err(Status::invalid_argument(
            "protobuf request is missing required field presence",
        ));
    }
    Ok((seen, values))
}

const fn field_mask(tags: &[u32]) -> u64 {
    let mut mask = 0u64;
    let mut index = 0;
    while index < tags.len() {
        mask |= 1u64 << tags[index];
        index += 1;
    }
    mask
}

const FINALIZE_FIELDS: &[RawField] = &[
    ld(1, MAX_ISSUER_OR_SUBJECT_LEN),
    ld(2, MAX_ISSUER_OR_SUBJECT_LEN),
    ld(3, UUID_LEN),
    ld(4, MAX_PRINCIPAL_NAMESPACE_LEN),
    ld(5, UUID_LEN),
    ld(6, MAX_METHOD_LEN),
    ld(7, MAX_SCOPE_LEN),
    implicit_varint(8),
    ld(9, DIGEST_LEN),
    ld(10, DIGEST_LEN),
    ld(11, UUID_LEN),
    implicit_varint(12),
    ld(13, DIGEST_LEN),
    ld(14, DIGEST_LEN),
    ld(15, DIGEST_LEN),
    ld(16, DIGEST_LEN),
    ld(17, DIGEST_LEN),
    implicit_varint(18),
];

/// Reject malformed stale-finalize raw bytes before Prost can discard unknown
/// or duplicate singular fields and before auth-grpc can claim a permit.
pub(super) fn validate_verified_stale_finalize_raw(raw: &[u8]) -> Result<(), Status> {
    validate_raw_fields(raw, FINALIZE_FIELDS)?;
    Ok(())
}

const ATTACH_FIELDS: &[RawField] = &[
    ld(1, MAX_ISSUER_OR_SUBJECT_LEN),
    ld(2, MAX_ISSUER_OR_SUBJECT_LEN),
    ld(3, UUID_LEN),
    ld(4, MAX_PRINCIPAL_NAMESPACE_LEN),
    ld(5, UUID_LEN),
    ld(6, UUID_LEN),
    implicit_varint(7),
    ld(8, UUID_LEN),
    implicit_varint(9),
    varint(10),
    ld(11, DIGEST_LEN),
    implicit_varint(12),
    implicit_varint(13),
    varint(14),
    implicit_varint(15),
    ld(16, DIGEST_LEN),
    implicit_varint(17),
    optional_ld(18, DIGEST_LEN),
    implicit_varint(19),
    optional_ld(20, DIGEST_LEN),
    implicit_varint(21),
    ld(22, DIGEST_LEN),
    optional_ld(23, DIGEST_LEN),
    implicit_varint(24),
    optional_ld(25, DIGEST_LEN),
    implicit_varint(26),
    ld(27, DIGEST_LEN),
    implicit_varint(28),
    optional_ld(29, DIGEST_LEN),
    ld(30, DIGEST_LEN),
];

/// Strict raw validation for the two-phase terminal-status attachment request.
pub(super) fn validate_terminal_status_attach_raw(raw: &[u8]) -> Result<(), Status> {
    let (seen, values) = validate_raw_fields(raw, ATTACH_FIELDS)?;
    match values[14] {
        1 => {
            let forbidden = field_mask(&[17, 18, 19, 20, 23, 24, 25, 29]);
            if seen & forbidden != 0 {
                return Err(Status::invalid_argument(
                    "Phase 1 carries Phase 2-only fields",
                ));
            }
        }
        2 => {
            let required = field_mask(&[17, 18, 19, 20]);
            if seen & required != required {
                return Err(Status::invalid_argument(
                    "Phase 2 is missing action evidence",
                ));
            }
            match values[17] {
                1 | 2 => {
                    if seen & field_mask(&[23, 24, 25, 29]) != 0 {
                        return Err(Status::invalid_argument(
                            "noncompletion Phase 2 action carries completion-only fields",
                        ));
                    }
                }
                3 => {
                    let completion = field_mask(&[23, 24, 25, 29]);
                    if seen & completion != completion {
                        return Err(Status::invalid_argument(
                            "completion action is missing completion proof",
                        ));
                    }
                }
                _ => return Err(Status::invalid_argument("invalid Phase 2 action")),
            }
        }
        _ => return Err(Status::invalid_argument("invalid terminal attach phase")),
    }
    Ok(())
}

const MATERIALIZE_FIELDS: &[RawField] = &[
    varint(1),
    ld(2, MAX_ISSUER_OR_SUBJECT_LEN),
    ld(3, MAX_ISSUER_OR_SUBJECT_LEN),
    ld(4, UUID_LEN),
    ld(5, MAX_PRINCIPAL_NAMESPACE_LEN),
    ld(6, UUID_LEN),
    varint(7),
    ld(8, DIGEST_LEN),
    implicit_varint(9),
    implicit_varint(10),
    ld(11, DIGEST_LEN),
    ld(12, MAX_SIGNED_JWT_LEN),
];

/// Strict raw validation for proof-namespace materialization.
pub(super) fn validate_proof_namespace_materialize_raw(raw: &[u8]) -> Result<(), Status> {
    validate_raw_fields(raw, MATERIALIZE_FIELDS)?;
    Ok(())
}

const RETIRE_FIELDS: &[RawField] = &[
    varint(1),
    ld(2, MAX_ISSUER_OR_SUBJECT_LEN),
    ld(3, MAX_ISSUER_OR_SUBJECT_LEN),
    ld(4, UUID_LEN),
    ld(5, MAX_PRINCIPAL_NAMESPACE_LEN),
    ld(6, UUID_LEN),
    varint(7),
    ld(8, DIGEST_LEN),
    implicit_varint(9),
    varint(10),
    varint(11),
    varint(12),
    varint(13),
    ld(14, DIGEST_LEN),
    ld(15, DIGEST_LEN),
    ld(16, MAX_SIGNED_JWT_LEN),
    varint(17),
    ld(18, DIGEST_LEN),
];

/// Strict raw validation for proof-namespace retirement.
pub(super) fn validate_proof_namespace_retire_raw(raw: &[u8]) -> Result<(), Status> {
    validate_raw_fields(raw, RETIRE_FIELDS)?;
    Ok(())
}

/// Exact caller-known receipt binding after all wire bounds are checked.
#[derive(Debug, Clone)]
pub(super) struct ValidatedBinding {
    pub(super) org_uuid: Vec<u8>,
    pub(super) initiating_principal_namespace: Vec<u8>,
    pub(super) operation_id: Uuid,
    pub(super) method: String,
    pub(super) scope: Vec<u8>,
    pub(super) fingerprint_version: i32,
    pub(super) fingerprint: Vec<u8>,
    pub(super) canonical_intent_digest: Vec<u8>,
    pub(super) authorization_id: Vec<u8>,
    pub(super) authorization_revision: u64,
}

pub(super) struct ValidatedPrepare {
    pub(super) binding: ValidatedBinding,
    pub(super) preclaim_ticket: Vec<u8>,
}

pub(super) struct ValidatedReceiptGet {
    pub(super) binding: ValidatedBinding,
    pub(super) consumed_ticket_sha256: Vec<u8>,
}

fn exact_len(field: &'static str, bytes: &[u8], expected: usize) -> Result<(), Status> {
    if bytes.len() == expected {
        return Ok(());
    }
    Err(Status::invalid_argument(format!(
        "{field} must be exactly {expected} bytes"
    )))
}

fn bounded_nonempty(field: &'static str, bytes: &[u8], maximum: usize) -> Result<(), Status> {
    if !bytes.is_empty() && bytes.len() <= maximum {
        return Ok(());
    }
    Err(Status::invalid_argument(format!(
        "{field} must contain 1..={maximum} bytes"
    )))
}

#[allow(clippy::too_many_arguments)]
fn validate_binding(
    org_uuid: &[u8],
    initiating_principal_namespace: &[u8],
    operation_id: &[u8],
    method: &str,
    scope: &[u8],
    fingerprint_version: u32,
    fingerprint: &[u8],
    canonical_intent_digest: &[u8],
    authorization_id: &[u8],
    authorization_revision: u64,
) -> Result<ValidatedBinding, Status> {
    exact_len("org_uuid", org_uuid, UUID_LEN)?;
    bounded_nonempty(
        "initiating_principal_namespace",
        initiating_principal_namespace,
        MAX_PRINCIPAL_NAMESPACE_LEN,
    )?;
    crate::grpc::domain_operation_metadata::scope_key_mediated_namespace(
        org_uuid,
        initiating_principal_namespace,
    )
    .map_err(|e| Status::invalid_argument(e.to_string()))?;
    exact_len("operation_id", operation_id, UUID_LEN)?;
    bounded_nonempty("method", method.as_bytes(), MAX_METHOD_LEN)?;
    bounded_nonempty("scope", scope, MAX_SCOPE_LEN)?;
    if fingerprint_version == 0 {
        return Err(Status::invalid_argument(
            "fingerprint_version must be nonzero",
        ));
    }
    let fingerprint_version = i32::try_from(fingerprint_version)
        .map_err(|_| Status::invalid_argument("fingerprint_version exceeds i32"))?;
    exact_len("fingerprint", fingerprint, DIGEST_LEN)?;
    exact_len(
        "canonical_intent_digest",
        canonical_intent_digest,
        DIGEST_LEN,
    )?;
    exact_len("authorization_id", authorization_id, UUID_LEN)?;
    if authorization_id != operation_id {
        return Err(Status::invalid_argument(
            "authorization_id must equal operation_id for CR-029 v1",
        ));
    }
    if authorization_revision == 0 {
        return Err(Status::invalid_argument(
            "authorization_revision must be nonzero",
        ));
    }

    let operation_id = Uuid::from_slice(operation_id)
        .map_err(|_| Status::invalid_argument("operation_id is not a UUID"))?;
    lore_postgres::domain::receipts::uuid_v7_timestamp(&operation_id)
        .map_err(|e| Status::invalid_argument(e.to_string()))?;

    Ok(ValidatedBinding {
        org_uuid: org_uuid.to_vec(),
        initiating_principal_namespace: initiating_principal_namespace.to_vec(),
        operation_id,
        method: method.to_owned(),
        scope: scope.to_vec(),
        fingerprint_version,
        fingerprint: fingerprint.to_vec(),
        canonical_intent_digest: canonical_intent_digest.to_vec(),
        authorization_id: authorization_id.to_vec(),
        authorization_revision,
    })
}

pub(super) fn validate_prepare(
    request: DomainOperationPrepareRequest,
) -> Result<ValidatedPrepare, Status> {
    let binding = validate_binding(
        &request.org_uuid,
        &request.initiating_principal_namespace,
        &request.operation_id,
        &request.method,
        &request.scope,
        request.fingerprint_version,
        &request.fingerprint,
        &request.canonical_intent_digest,
        &request.authorization_id,
        request.authorization_revision,
    )?;
    exact_len("preclaim_ticket", &request.preclaim_ticket, DIGEST_LEN)?;
    Ok(ValidatedPrepare {
        binding,
        preclaim_ticket: request.preclaim_ticket.to_vec(),
    })
}

/// Validate the public attempt lookup: one field, checked for shape only.
///
/// There is nothing here to cross-check against, and that is by design. The private lookup
/// validates a whole restated intent because its caller has one; this caller has an identity it
/// minted before dispatch and nothing else, so the only questions worth asking are whether the
/// value is the right width and the right UUID version.
///
/// The v7 check is not cosmetic. The receipt rail orders and classifies attempts by a UUID's
/// embedded timestamp, so a value of any other version could never have been filed as one and
/// asking for it is a caller error rather than a miss.
pub(super) fn validate_attempt_receipt_get(
    request: &DomainOperationAttemptReceiptGetRequest,
) -> Result<Uuid, Status> {
    exact_len("client_attempt_id", &request.client_attempt_id, UUID_LEN)?;
    let attempt = Uuid::from_slice(&request.client_attempt_id)
        .map_err(|_| Status::invalid_argument("client_attempt_id is not a UUID"))?;
    if attempt.get_version_num() != 7 {
        return Err(Status::invalid_argument(
            "client_attempt_id must be a UUIDv7",
        ));
    }
    Ok(attempt)
}

pub(super) fn validate_receipt_get(
    request: DomainOperationReceiptGetRequest,
) -> Result<ValidatedReceiptGet, Status> {
    let binding = validate_binding(
        &request.org_uuid,
        &request.initiating_principal_namespace,
        &request.operation_id,
        &request.method,
        &request.scope,
        request.fingerprint_version,
        &request.fingerprint,
        &request.canonical_intent_digest,
        &request.authorization_id,
        request.authorization_revision,
    )?;
    exact_len(
        "consumed_ticket_sha256",
        &request.consumed_ticket_sha256,
        DIGEST_LEN,
    )?;
    Ok(ValidatedReceiptGet {
        binding,
        consumed_ticket_sha256: request.consumed_ticket_sha256.to_vec(),
    })
}

fn validate_verified_identity(
    verified_issuer: &str,
    authenticated_subject: &str,
    org_uuid: &[u8],
    principal_namespace: &[u8],
) -> Result<(), Status> {
    bounded_nonempty(
        "verified_issuer",
        verified_issuer.as_bytes(),
        MAX_ISSUER_OR_SUBJECT_LEN,
    )?;
    bounded_nonempty(
        "authenticated_subject",
        authenticated_subject.as_bytes(),
        MAX_ISSUER_OR_SUBJECT_LEN,
    )?;
    exact_len("org_uuid", org_uuid, UUID_LEN)?;
    bounded_nonempty(
        "initiating_principal_namespace",
        principal_namespace,
        MAX_PRINCIPAL_NAMESPACE_LEN,
    )?;
    crate::grpc::domain_operation_metadata::scope_key_mediated_namespace(
        org_uuid,
        principal_namespace,
    )
    .map_err(|e| Status::invalid_argument(e.to_string()))?;
    Ok(())
}

pub(super) fn validate_verified_stale_finalize(
    request: &DomainOperationVerifiedStaleFinalizeRequest,
) -> Result<(), Status> {
    validate_verified_identity(
        &request.verified_issuer,
        &request.authenticated_subject,
        &request.org_uuid,
        &request.initiating_principal_namespace,
    )?;
    exact_len("operation_id", &request.operation_id, UUID_LEN)?;
    let operation_id = Uuid::from_slice(&request.operation_id)
        .map_err(|_| Status::invalid_argument("operation_id is not a UUID"))?;
    lore_postgres::domain::receipts::uuid_v7_timestamp(&operation_id)
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    bounded_nonempty("method", request.method.as_bytes(), MAX_METHOD_LEN)?;
    bounded_nonempty("scope", &request.scope, MAX_SCOPE_LEN)?;
    if request.fingerprint_version == 0
        || request.authorization_revision == 0
        || request.stale_finalize_permit_revision == 0
    {
        return Err(Status::invalid_argument(
            "fingerprint and authorization/permit revisions must be nonzero",
        ));
    }
    for (name, value, length) in [
        ("fingerprint", request.fingerprint.as_ref(), DIGEST_LEN),
        (
            "canonical_intent_digest",
            request.canonical_intent_digest.as_ref(),
            DIGEST_LEN,
        ),
        (
            "authorization_id",
            request.authorization_id.as_ref(),
            UUID_LEN,
        ),
        (
            "verification_nonce",
            request.verification_nonce.as_ref(),
            DIGEST_LEN,
        ),
        (
            "bound_fields_digest",
            request.bound_fields_digest.as_ref(),
            DIGEST_LEN,
        ),
        (
            "consumed_ticket_sha256",
            request.consumed_ticket_sha256.as_ref(),
            DIGEST_LEN,
        ),
        (
            "expected_claim_identity_digest",
            request.expected_claim_identity_digest.as_ref(),
            DIGEST_LEN,
        ),
        (
            "stale_finalize_permit",
            request.stale_finalize_permit.as_ref(),
            DIGEST_LEN,
        ),
    ] {
        exact_len(name, value, length)?;
    }
    Ok(())
}

pub(super) fn validate_terminal_status_attach(
    request: &DomainOperationTerminalStatusAttachRequest,
) -> Result<(), Status> {
    validate_verified_identity(
        &request.verified_issuer,
        &request.authenticated_subject,
        &request.org_uuid,
        &request.initiating_principal_namespace,
    )?;
    for (name, value, length) in [
        ("operation_id", request.operation_id.as_ref(), UUID_LEN),
        (
            "authorization_id",
            request.authorization_id.as_ref(),
            UUID_LEN,
        ),
        ("claim_id", request.claim_id.as_ref(), UUID_LEN),
        (
            "terminal_receipt_sha256",
            request.terminal_receipt_sha256.as_ref(),
            DIGEST_LEN,
        ),
        (
            "reserve_charge_nonce",
            request.reserve_charge_nonce.as_ref(),
            DIGEST_LEN,
        ),
        (
            "tombstone_reservation_nonce",
            request.tombstone_reservation_nonce.as_ref(),
            DIGEST_LEN,
        ),
        (
            "release_proof_reservation_nonce",
            request.release_proof_reservation_nonce.as_ref(),
            DIGEST_LEN,
        ),
        (
            "request_digest",
            request.request_digest.as_ref(),
            DIGEST_LEN,
        ),
    ] {
        exact_len(name, value, length)?;
    }
    if request.authorization_revision == 0
        || request.claim_revision == 0
        || request.platform_terminal_status_revision == 0
        || request.reserve_charge_revision == 0
        || request.tombstone_reservation_revision == 0
        || request.release_proof_reservation_revision == 0
        || request.completion_marker_sequence == 0
        || request.acknowledged_at_unix_millis < 0
        || !matches!(request.terminal_outcome, 1 | 2)
    {
        return Err(Status::invalid_argument(
            "terminal attachment carries an invalid required revision/outcome/time",
        ));
    }
    let phase = TerminalStatusAttachPhaseV1::try_from(request.phase)
        .map_err(|_| Status::invalid_argument("invalid terminal attachment phase"))?;
    let action = TerminalStatusAttachPhase2ActionV1::try_from(request.phase2_action)
        .map_err(|_| Status::invalid_argument("invalid terminal attachment action"))?;
    match phase {
        TerminalStatusAttachPhaseV1::Phase1TerminalAck => {
            if action != TerminalStatusAttachPhase2ActionV1::Unspecified
                || !request.release_tombstone_digest.is_empty()
                || request.active_release_intent_revision != 0
                || !request.active_release_intent_nonce.is_empty()
                || !request.final_prune_digest.is_empty()
                || request.tombstone_release_intent_revision != 0
                || !request.tombstone_release_intent_nonce.is_empty()
                || !request.expected_completion_marker_digest.is_empty()
            {
                return Err(Status::invalid_argument(
                    "Phase 1 carries Phase 2-only fields",
                ));
            }
        }
        TerminalStatusAttachPhaseV1::Phase2ReleaseAck => {
            exact_len(
                "release_tombstone_digest",
                &request.release_tombstone_digest,
                DIGEST_LEN,
            )?;
            exact_len(
                "active_release_intent_nonce",
                &request.active_release_intent_nonce,
                DIGEST_LEN,
            )?;
            if request.active_release_intent_revision == 0 {
                return Err(Status::invalid_argument(
                    "Phase 2 active-release revision must be nonzero",
                ));
            }
            match action {
                TerminalStatusAttachPhase2ActionV1::ActiveReleaseIntentAck
                | TerminalStatusAttachPhase2ActionV1::TombstonePrunePoll => {
                    if !request.final_prune_digest.is_empty()
                        || request.tombstone_release_intent_revision != 0
                        || !request.tombstone_release_intent_nonce.is_empty()
                        || !request.expected_completion_marker_digest.is_empty()
                    {
                        return Err(Status::invalid_argument(
                            "noncompletion action carries completion-only fields",
                        ));
                    }
                }
                TerminalStatusAttachPhase2ActionV1::TombstoneReleaseIntentComplete => {
                    for (name, value) in [
                        ("final_prune_digest", request.final_prune_digest.as_ref()),
                        (
                            "tombstone_release_intent_nonce",
                            request.tombstone_release_intent_nonce.as_ref(),
                        ),
                        (
                            "expected_completion_marker_digest",
                            request.expected_completion_marker_digest.as_ref(),
                        ),
                    ] {
                        exact_len(name, value, DIGEST_LEN)?;
                    }
                    if request.tombstone_release_intent_revision == 0 {
                        return Err(Status::invalid_argument(
                            "completion release-intent revision must be nonzero",
                        ));
                    }
                }
                _ => return Err(Status::invalid_argument("Phase 2 action is required")),
            }
        }
        _ => {
            return Err(Status::invalid_argument(
                "terminal attachment phase is unspecified",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_proof_namespace_materialize(
    request: &DomainOperationProofNamespaceMaterializeRequestV1,
) -> Result<(), Status> {
    validate_verified_identity(
        &request.verified_issuer,
        &request.authenticated_subject,
        &request.org_uuid,
        &request.initiating_principal_namespace,
    )?;
    if request.protocol_revision != 2
        || request.namespace_claim_revision == 0
        || request.platform_capacity_revision == 0
    {
        return Err(Status::invalid_argument(
            "materialization revisions are invalid",
        ));
    }
    exact_len("namespace_epoch", &request.namespace_epoch, UUID_LEN)?;
    exact_len(
        "namespace_claim_nonce",
        &request.namespace_claim_nonce,
        DIGEST_LEN,
    )?;
    exact_len("request_digest", &request.request_digest, DIGEST_LEN)?;
    bounded_nonempty(
        "materialization_jwt",
        request.materialization_jwt.as_bytes(),
        MAX_SIGNED_JWT_LEN,
    )?;
    Ok(())
}

pub(super) fn validate_proof_namespace_retire(
    request: &DomainOperationProofNamespaceRetireRequestV1,
) -> Result<(), Status> {
    validate_verified_identity(
        &request.verified_issuer,
        &request.authenticated_subject,
        &request.org_uuid,
        &request.initiating_principal_namespace,
    )?;
    if request.protocol_revision != 2
        || request.quota_revision == 0
        || request.retirement_fence_generation == 0
        || request.retirement_permit_revision == 0
        || request.namespace_claim_revision == 0
        || request.issued_at_unix_millis < 0
        || request.expires_at_unix_millis <= request.issued_at_unix_millis
    {
        return Err(Status::invalid_argument(
            "retirement revisions/times are invalid",
        ));
    }
    exact_len("namespace_epoch", &request.namespace_epoch, UUID_LEN)?;
    for (name, value) in [
        (
            "final_range_set_digest",
            request.final_range_set_digest.as_ref(),
        ),
        (
            "zero_platform_state_digest",
            request.zero_platform_state_digest.as_ref(),
        ),
        ("request_digest", request.request_digest.as_ref()),
        (
            "namespace_claim_nonce",
            request.namespace_claim_nonce.as_ref(),
        ),
    ] {
        exact_len(name, value, DIGEST_LEN)?;
    }
    bounded_nonempty(
        "retirement_permit_jwt",
        request.retirement_permit_jwt.as_bytes(),
        MAX_SIGNED_JWT_LEN,
    )?;
    Ok(())
}

#[cfg(test)]
mod raw_field_tests {
    use super::*;

    #[test]
    fn varint_rule_above_tag_thirty_cannot_index_panic() {
        // tag 63, wire type 0 => key 504 => canonical varint f8 03.
        let raw = [0xf8, 0x03, 0x01];
        let (seen, values) = validate_raw_fields(&raw, &[varint(63)])
            .expect("a declared high varint tag must validate without indexing past the array");
        assert_eq!(seen, 1u64 << 63);
        assert_eq!(values[63], 1);
    }
}
