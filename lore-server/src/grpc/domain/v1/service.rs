// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Authenticated private CR-029 clock, prepare, and receipt lookup service.

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use lore_postgres::domain::DomainOutcome;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::ReceiptLookup;
use lore_proto::lore::domain::v1::DomainOperationClockGetRequest;
use lore_proto::lore::domain::v1::DomainOperationClockGetResponse;
use lore_proto::lore::domain::v1::DomainOperationOutcome;
use lore_proto::lore::domain::v1::DomainOperationPrepareRequest;
use lore_proto::lore::domain::v1::DomainOperationPrepareResponse;
use lore_proto::lore::domain::v1::DomainOperationPrepareStatus;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetRequest;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetResponse;
use lore_proto::lore::domain::v1::DomainOperationReceiptStatus;
use lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationService;
use lore_proto::rebac::VerifyRepositoryOperationAuthorizationRequest;
use lore_proto::rebac::VerifyRepositoryOperationAuthorizationResponse;
use lore_proto::rebac::verify_repository_operation_authorization_request::Proof;
use ring::digest::SHA256;
use ring::digest::digest;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use super::strict_codec::ValidatedBinding;
use super::strict_codec::validate_prepare;
use super::strict_codec::validate_receipt_get;
use crate::auth::jwt::AuthorizationToken;
use crate::authnz::common::create_request_with_authorization;
use crate::authnz::rebac::RepositoryOperationAuthorizationVerifier;
use crate::domain::DomainContext;
use crate::grpc::domain_operation_metadata::scope_key_mediated_namespace;
use crate::grpc::extract_authorization_header;
use crate::grpc::map_domain_error_to_status;

const WITNESS_FIELD_LEN: usize = 32;
const CONTROL_PLANE_SERVICE_SUBJECT: &str = "lorehub-control-plane";

/// Private service. Construction requires both the domain store and a verifier
/// dependency, so no method can silently fall back to unverified caller input.
pub struct LoreDomainOperationV1Service {
    domain: Arc<DomainContext>,
    verifier: Arc<dyn RepositoryOperationAuthorizationVerifier>,
}

impl LoreDomainOperationV1Service {
    pub fn new(
        domain: Arc<DomainContext>,
        verifier: Arc<dyn RepositoryOperationAuthorizationVerifier>,
    ) -> Self {
        Self { domain, verifier }
    }
}

fn authenticated_service<T>(request: &Request<T>) -> Result<AuthorizationToken, Status> {
    let token = request
        .extensions()
        .get::<AuthorizationToken>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("Verified service identity required"))?;
    if token.is_service_account != Some(true)
        || token.issuer.is_empty()
        || token.user_id != CONTROL_PLANE_SERVICE_SUBJECT
    {
        return Err(Status::permission_denied(
            "Repository operation rail requires a verified service account",
        ));
    }
    Ok(token)
}

fn receipt_key(
    token: &AuthorizationToken,
    binding: &ValidatedBinding,
) -> Result<ReceiptKey, Status> {
    let tenant_scope_key =
        scope_key_mediated_namespace(&binding.org_uuid, &binding.initiating_principal_namespace)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
    Ok(ReceiptKey {
        verified_issuer: token.issuer.clone(),
        authenticated_subject: token.user_id.clone(),
        tenant_scope_key,
        operation_id: binding.operation_id,
    })
}

fn operation_binding(binding: &ValidatedBinding) -> OperationBinding {
    OperationBinding {
        method: binding.method.clone(),
        scope: binding.scope.clone(),
        fingerprint_version: binding.fingerprint_version,
        fingerprint: binding.fingerprint.clone(),
        canonical_intent_digest: binding.canonical_intent_digest.clone(),
    }
}

fn verifier_request(
    token: &AuthorizationToken,
    binding: &ValidatedBinding,
    proof: Proof,
    authorization: String,
) -> Result<Request<VerifyRepositoryOperationAuthorizationRequest>, Status> {
    create_request_with_authorization(
        VerifyRepositoryOperationAuthorizationRequest {
            verified_issuer: token.issuer.clone(),
            authenticated_subject: token.user_id.clone(),
            org_uuid: Bytes::copy_from_slice(&binding.org_uuid),
            initiating_principal_namespace: Bytes::copy_from_slice(
                &binding.initiating_principal_namespace,
            ),
            operation_id: Bytes::copy_from_slice(binding.operation_id.as_bytes()),
            method: binding.method.clone(),
            scope: Bytes::copy_from_slice(&binding.scope),
            fingerprint_version: binding.fingerprint_version as u32,
            fingerprint: Bytes::copy_from_slice(&binding.fingerprint),
            canonical_intent_digest: Bytes::copy_from_slice(&binding.canonical_intent_digest),
            authorization_id: Bytes::copy_from_slice(&binding.authorization_id),
            authorization_revision: binding.authorization_revision,
            proof: Some(proof),
        },
        Some(authorization),
    )
}

fn exact_echo(
    token: &AuthorizationToken,
    binding: &ValidatedBinding,
    response: &VerifyRepositoryOperationAuthorizationResponse,
    expected_revision: u64,
    expected_consumed_ticket_sha256: &[u8],
) -> Result<AuthorizationWitness, Status> {
    let exact = response.authorization_id.as_ref() == binding.authorization_id
        && response.org_uuid.as_ref() == binding.org_uuid
        && response.initiating_principal_namespace.as_ref()
            == binding.initiating_principal_namespace
        && response.operation_id.as_ref() == binding.operation_id.as_bytes()
        && response.method == binding.method
        && response.scope.as_ref() == binding.scope
        && response.fingerprint_version == binding.fingerprint_version as u32
        && response.fingerprint.as_ref() == binding.fingerprint
        && response.canonical_intent_digest.as_ref() == binding.canonical_intent_digest
        && response.verified_issuer == token.issuer
        && response.authenticated_subject == token.user_id;
    let exact = exact
        && response.authorization_revision == expected_revision
        && response.consumed_ticket_sha256.as_ref() == expected_consumed_ticket_sha256;
    if !exact {
        return Err(Status::permission_denied(
            "Repository operation authorization binding mismatch",
        ));
    }
    for (field, bytes) in [
        ("verification_nonce", response.verification_nonce.as_ref()),
        ("bound_fields_digest", response.bound_fields_digest.as_ref()),
        (
            "consumed_ticket_sha256",
            response.consumed_ticket_sha256.as_ref(),
        ),
    ] {
        if bytes.len() != WITNESS_FIELD_LEN {
            return Err(Status::permission_denied(format!(
                "Repository operation verifier returned invalid {field}"
            )));
        }
    }
    let authorization_revision = i64::try_from(response.authorization_revision)
        .map_err(|_| Status::permission_denied("Authorization revision exceeds i64"))?;
    Ok(AuthorizationWitness {
        authorization_id: response.authorization_id.to_vec(),
        authorization_revision,
        verification_nonce: response.verification_nonce.to_vec(),
        bound_fields_digest: response.bound_fields_digest.to_vec(),
        consumed_ticket_sha256: response.consumed_ticket_sha256.to_vec(),
    })
}

fn unix_millis(time: SystemTime) -> Result<i64, Status> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| Status::internal("Postgres clock precedes Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| Status::internal("Postgres clock milliseconds exceed i64"))
}

fn outcome_fields(
    outcome: DomainOutcome,
) -> Result<(DomainOperationOutcome, Option<u32>, String), Status> {
    match outcome {
        DomainOutcome::Applied => Ok((DomainOperationOutcome::Applied, None, String::new())),
        DomainOutcome::NotApplied {
            reason_version,
            reason,
        } => {
            Ok((
                DomainOperationOutcome::NotApplied,
                Some(u32::try_from(reason_version).map_err(|_| {
                    Status::internal("Stored NOT_APPLIED reason version is invalid")
                })?),
                reason,
            ))
        }
    }
}

#[tonic::async_trait]
impl DomainOperationService for LoreDomainOperationV1Service {
    async fn domain_operation_clock_get(
        &self,
        request: Request<DomainOperationClockGetRequest>,
    ) -> Result<Response<DomainOperationClockGetResponse>, Status> {
        let _ = authenticated_service(&request)?;
        let clock = self
            .domain
            .store()
            .domain_operation_clock_get()
            .await
            .map_err(|e| map_domain_error_to_status(&e))?;
        Ok(Response::new(DomainOperationClockGetResponse {
            lore_clock_unix_millis: unix_millis(clock)?,
            sample_nonce: Bytes::copy_from_slice(&rand::random::<[u8; 32]>()),
        }))
    }

    async fn domain_operation_prepare(
        &self,
        request: Request<DomainOperationPrepareRequest>,
    ) -> Result<Response<DomainOperationPrepareResponse>, Status> {
        let token = authenticated_service(&request)?;
        let authorization = extract_authorization_header(&request)
            .ok_or_else(|| Status::unauthenticated("Authorization header required"))?;
        let validated = validate_prepare(request.into_inner())?;
        let verification = self
            .verifier
            .verify_repository_operation_authorization(verifier_request(
                &token,
                &validated.binding,
                Proof::PreclaimTicket(Bytes::copy_from_slice(&validated.preclaim_ticket)),
                authorization,
            )?)
            .await?;
        let expected_revision = validated
            .binding
            .authorization_revision
            .checked_add(1)
            .ok_or_else(|| Status::invalid_argument("authorization_revision cannot advance"))?;
        let ticket_commitment = digest(&SHA256, &validated.preclaim_ticket);
        let witness = exact_echo(
            &token,
            &validated.binding,
            &verification,
            expected_revision,
            ticket_commitment.as_ref(),
        )?;
        let key = receipt_key(&token, &validated.binding)?;
        let binding = operation_binding(&validated.binding);
        let result = self
            .domain
            .store()
            .domain_operation_prepare(&key, &binding, Some(&witness))
            .await
            .map_err(|e| map_domain_error_to_status(&e))?;

        let mut response = DomainOperationPrepareResponse {
            status: DomainOperationPrepareStatus::Unspecified as i32,
            consume_token: Bytes::new(),
            hard_expires_at_unix_millis: None,
            outcome: DomainOperationOutcome::Unspecified as i32,
            reason_version: None,
            reason: String::new(),
            verification_nonce: Bytes::copy_from_slice(&witness.verification_nonce),
            bound_fields_digest: Bytes::copy_from_slice(&witness.bound_fields_digest),
            consumed_ticket_sha256: Bytes::copy_from_slice(&witness.consumed_ticket_sha256),
            authorization_revision: verification.authorization_revision,
        };
        match result {
            PrepareResult::Prepared {
                token,
                hard_expires_at,
            } => {
                response.status = DomainOperationPrepareStatus::Prepared as i32;
                response.consume_token = Bytes::copy_from_slice(&token);
                response.hard_expires_at_unix_millis = Some(unix_millis(hard_expires_at)?);
            }
            PrepareResult::Committed(outcome) => {
                response.status = DomainOperationPrepareStatus::Committed as i32;
                let (outcome, version, reason) = outcome_fields(outcome)?;
                response.outcome = outcome as i32;
                response.reason_version = version;
                response.reason = reason;
            }
            PrepareResult::ExpiredOrUnknown => {
                response.status = DomainOperationPrepareStatus::ExpiredOrUnknown as i32;
            }
            PrepareResult::Mismatch => {
                response.status = DomainOperationPrepareStatus::Mismatch as i32;
            }
            PrepareResult::CapacityExhausted => {
                response.status = DomainOperationPrepareStatus::CapacityExhausted as i32;
            }
        }
        Ok(Response::new(response))
    }

    async fn domain_operation_receipt_get(
        &self,
        request: Request<DomainOperationReceiptGetRequest>,
    ) -> Result<Response<DomainOperationReceiptGetResponse>, Status> {
        let token = authenticated_service(&request)?;
        let authorization = extract_authorization_header(&request)
            .ok_or_else(|| Status::unauthenticated("Authorization header required"))?;
        let validated = validate_receipt_get(request.into_inner())?;
        let verification = self
            .verifier
            .verify_repository_operation_authorization(verifier_request(
                &token,
                &validated.binding,
                Proof::ConsumedTicketSha256(Bytes::copy_from_slice(
                    &validated.consumed_ticket_sha256,
                )),
                authorization,
            )?)
            .await?;
        let witness = exact_echo(
            &token,
            &validated.binding,
            &verification,
            validated.binding.authorization_revision,
            &validated.consumed_ticket_sha256,
        )?;
        let key = receipt_key(&token, &validated.binding)?;
        let binding = operation_binding(&validated.binding);
        let result = self
            .domain
            .store()
            .domain_operation_receipt_get(&key, &binding)
            .await
            .map_err(|e| map_domain_error_to_status(&e))?;

        let mut response = DomainOperationReceiptGetResponse {
            status: DomainOperationReceiptStatus::Unspecified as i32,
            outcome: DomainOperationOutcome::Unspecified as i32,
            reason_version: None,
            reason: String::new(),
            from_future_marker: false,
            prepared_at_unix_millis: None,
            hard_expires_at_unix_millis: None,
            verification_nonce: Bytes::copy_from_slice(&witness.verification_nonce),
            bound_fields_digest: Bytes::copy_from_slice(&witness.bound_fields_digest),
            consumed_ticket_sha256: Bytes::copy_from_slice(&witness.consumed_ticket_sha256),
            authorization_revision: verification.authorization_revision,
        };
        match result {
            ReceiptLookup::Prepared {
                prepared_at,
                hard_expires_at,
            } => {
                response.status = DomainOperationReceiptStatus::Prepared as i32;
                response.prepared_at_unix_millis = Some(unix_millis(prepared_at)?);
                response.hard_expires_at_unix_millis = Some(unix_millis(hard_expires_at)?);
            }
            ReceiptLookup::Committed {
                outcome,
                from_future_marker,
            } => {
                response.status = DomainOperationReceiptStatus::Committed as i32;
                response.from_future_marker = from_future_marker;
                let (outcome, version, reason) = outcome_fields(outcome)?;
                response.outcome = outcome as i32;
                response.reason_version = version;
                response.reason = reason;
            }
            ReceiptLookup::Mismatch => {
                response.status = DomainOperationReceiptStatus::Mismatch as i32;
            }
            ReceiptLookup::Expired => {
                response.status = DomainOperationReceiptStatus::Expired as i32;
            }
            ReceiptLookup::ExpiredOrUnknown => {
                response.status = DomainOperationReceiptStatus::ExpiredOrUnknown as i32;
            }
            ReceiptLookup::NotFound => {
                response.status = DomainOperationReceiptStatus::NotFound as i32;
            }
        }
        Ok(Response::new(response))
    }
}
