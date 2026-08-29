// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Bounded validation for the CR-029 API-first prepare/receipt slice.
//!
//! The full receipt-v2 rail also requires a raw-frame strict codec for its
//! remaining four RPCs. Those methods are not declared or advertised yet, so
//! this module validates the decoded fields the three coherent RPCs expose and
//! keeps every database/auth callback behind exact bounds and UUID checks.

use lore_proto::lore::domain::v1::DomainOperationPrepareRequest;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetRequest;
use tonic::Status;
use uuid::Uuid;

const UUID_LEN: usize = 16;
const DIGEST_LEN: usize = 32;
const MAX_METHOD_LEN: usize = 128;
const MAX_SCOPE_LEN: usize = 4096;
const MAX_PRINCIPAL_NAMESPACE_LEN: usize = 49;

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
