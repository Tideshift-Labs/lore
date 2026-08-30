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
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceMaterializeReceiptV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceMaterializeRequestV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceMaterializeStatusV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceRetireAckV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceRetireRequestV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceRetireStatusV1;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetRequest;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetResponse;
use lore_proto::lore::domain::v1::DomainOperationReceiptStatus;
use lore_proto::lore::domain::v1::DomainOperationTerminalStatusAttachRequest;
use lore_proto::lore::domain::v1::DomainOperationTerminalStatusAttachmentAckV1;
use lore_proto::lore::domain::v1::DomainOperationTerminalStatusAttachmentStatusV1;
use lore_proto::lore::domain::v1::DomainOperationVerifiedStaleFinalizeRequest;
use lore_proto::lore::domain::v1::DomainOperationVerifiedStaleFinalizeResponse;
use lore_proto::lore::domain::v1::DomainOperationVerifiedStaleFinalizeStatus;
use lore_proto::lore::domain::v1::TerminalStatusAttachPhase2ActionV1;
use lore_proto::lore::domain::v1::TerminalStatusAttachPhaseV1;
use lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationService;
use lore_proto::rebac::DomainOperationMaintenanceMethod;
use lore_proto::rebac::DomainOperationMaintenanceVerificationRequest;
use lore_proto::rebac::DomainOperationMaintenanceVerificationResponse;
use lore_proto::rebac::DomainOperationProofNamespaceMaterializationVerification;
use lore_proto::rebac::DomainOperationProofNamespaceRetirementVerification;
use lore_proto::rebac::DomainOperationStaleFinalizePermitVerification;
use lore_proto::rebac::DomainOperationTerminalStatusAttachmentVerification;
use lore_proto::rebac::VerifyRepositoryOperationAuthorizationRequest;
use lore_proto::rebac::VerifyRepositoryOperationAuthorizationResponse;
use lore_proto::rebac::domain_operation_maintenance_verification_request::MethodBinding;
use lore_proto::rebac::verify_repository_operation_authorization_request::Proof;
use ring::digest::SHA256;
use ring::digest::digest;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic_prost::prost::Message;

use super::strict_codec::ValidatedBinding;
use super::strict_codec::validate_prepare;
use super::strict_codec::validate_proof_namespace_materialize;
use super::strict_codec::validate_proof_namespace_materialize_raw;
use super::strict_codec::validate_proof_namespace_retire;
use super::strict_codec::validate_proof_namespace_retire_raw;
use super::strict_codec::validate_receipt_get;
use super::strict_codec::validate_terminal_status_attach;
use super::strict_codec::validate_terminal_status_attach_raw;
use super::strict_codec::validate_verified_stale_finalize;
use super::strict_codec::validate_verified_stale_finalize_raw;
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
        (
            "expected_claim_identity_digest",
            response.expected_claim_identity_digest.as_ref(),
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
        expected_claim_identity_digest: response.expected_claim_identity_digest.to_vec(),
    })
}

fn unix_millis(time: SystemTime) -> Result<i64, Status> {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| Status::internal("Postgres clock precedes Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| Status::internal("Postgres clock milliseconds exceed i64"))
}

fn system_time_from_millis(value: i64, field: &'static str) -> Result<SystemTime, Status> {
    let value = u64::try_from(value)
        .map_err(|_| Status::invalid_argument(format!("{field} must be nonnegative")))?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(value))
        .ok_or_else(|| Status::invalid_argument(format!("{field} overflows SystemTime")))
}

fn require_request_identity(
    token: &AuthorizationToken,
    verified_issuer: &str,
    authenticated_subject: &str,
) -> Result<(), Status> {
    if token.issuer != verified_issuer || token.user_id != authenticated_subject {
        return Err(Status::permission_denied(
            "Maintenance request identity does not match the verified service token",
        ));
    }
    Ok(())
}

// Builds the exact verifier envelope for the active private maintenance rail.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
fn maintenance_verifier_request<M: Message>(
    token: &AuthorizationToken,
    method: DomainOperationMaintenanceMethod,
    org_uuid: &[u8],
    principal_namespace: &[u8],
    target_identity: &[u8],
    mut method_binding: MethodBinding,
    message: &M,
    authorization: String,
) -> Result<
    (
        Request<DomainOperationMaintenanceVerificationRequest>,
        Vec<u8>,
        Vec<u8>,
    ),
    Status,
> {
    let canonical = message.encode_to_vec();
    let request_sha256 = digest(&SHA256, &canonical).as_ref().to_vec();
    // The frozen stale-finalize domain request has no separate request-digest
    // field. Its private platform claim binds the digest of the complete
    // canonical request passed here.
    if let MethodBinding::StaleFinalize(binding) = &mut method_binding {
        binding.request_digest = Bytes::copy_from_slice(&request_sha256);
    }
    let request = create_request_with_authorization(
        DomainOperationMaintenanceVerificationRequest {
            method: method as i32,
            verified_issuer: token.issuer.clone(),
            authenticated_subject: token.user_id.clone(),
            org_uuid: Bytes::copy_from_slice(org_uuid),
            initiating_principal_namespace: Bytes::copy_from_slice(principal_namespace),
            target_identity: Bytes::copy_from_slice(target_identity),
            canonical_request: Bytes::copy_from_slice(&canonical),
            canonical_request_sha256: Bytes::copy_from_slice(&request_sha256),
            method_binding: Some(method_binding),
        },
        Some(authorization),
    )?;
    Ok((request, canonical, request_sha256))
}

fn exact_maintenance_echo(
    token: &AuthorizationToken,
    method: DomainOperationMaintenanceMethod,
    org_uuid: &[u8],
    principal_namespace: &[u8],
    target_identity: &[u8],
    request_sha256: &[u8],
    response: DomainOperationMaintenanceVerificationResponse,
) -> Result<Vec<u8>, Status> {
    if response.method != method as i32
        || response.verified_issuer != token.issuer
        || response.authenticated_subject != token.user_id
        || response.org_uuid.as_ref() != org_uuid
        || response.initiating_principal_namespace.as_ref() != principal_namespace
        || response.target_identity.as_ref() != target_identity
        || response.canonical_request_sha256.as_ref() != request_sha256
        || response.verification_digest.len() != WITNESS_FIELD_LEN
    {
        return Err(Status::permission_denied(
            "Maintenance verifier returned a divergent binding",
        ));
    }
    Ok(response.verification_digest.to_vec())
}

fn bearer_payload(authorization: &str) -> Option<&str> {
    authorization.strip_prefix("Bearer ")
}

fn nonempty(value: &[u8]) -> Option<Vec<u8>> {
    (!value.is_empty()).then(|| value.to_vec())
}

fn positive_i64(value: u64) -> Result<Option<i64>, Status> {
    if value == 0 {
        return Ok(None);
    }
    i64::try_from(value)
        .map(Some)
        .map_err(|_| Status::invalid_argument("revision exceeds i64"))
}

fn to_u64(value: i64, field: &'static str) -> Result<u64, Status> {
    u64::try_from(value).map_err(|_| Status::internal(format!("stored {field} is negative")))
}

fn proof_namespace_key(
    token: &AuthorizationToken,
    org_uuid: &[u8],
    principal_namespace: &[u8],
) -> Result<lore_postgres::domain::maintenance::ProofNamespaceKey, Status> {
    let tenant_scope_key = scope_key_mediated_namespace(org_uuid, principal_namespace)
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    Ok(lore_postgres::domain::maintenance::ProofNamespaceKey {
        verified_issuer: token.issuer.clone(),
        authenticated_subject: token.user_id.clone(),
        tenant_scope_key,
        org_uuid: org_uuid.to_vec(),
    })
}

fn terminal_ack_response(
    ack: lore_postgres::domain::maintenance::TerminalStatusAttachmentAck,
) -> Result<DomainOperationTerminalStatusAttachmentAckV1, Status> {
    use lore_postgres::domain::maintenance::TerminalStatusAttachStatus as StoredStatus;

    let status = match ack.status {
        StoredStatus::Phase1PendingRetention => {
            DomainOperationTerminalStatusAttachmentStatusV1::Phase1PendingRetention
        }
        StoredStatus::Phase1TombstoneReady => {
            DomainOperationTerminalStatusAttachmentStatusV1::Phase1TombstoneReady
        }
        StoredStatus::Phase2ActiveReleaseAcked => {
            DomainOperationTerminalStatusAttachmentStatusV1::Phase2ActiveReleaseAcked
        }
        StoredStatus::Phase2TombstoneRetentionPending => {
            DomainOperationTerminalStatusAttachmentStatusV1::Phase2TombstoneRetentionPending
        }
        StoredStatus::Phase2TombstoneFinalPruned => {
            DomainOperationTerminalStatusAttachmentStatusV1::Phase2TombstoneFinalPruned
        }
        StoredStatus::Phase2ReleaseCompletionReady => {
            DomainOperationTerminalStatusAttachmentStatusV1::Phase2ReleaseCompletionReady
        }
        StoredStatus::Phase2PostPruneRecovery => {
            DomainOperationTerminalStatusAttachmentStatusV1::Phase2PostPruneRecovery
        }
        StoredStatus::Phase2PostPruneCompletionReplayRequired => {
            DomainOperationTerminalStatusAttachmentStatusV1::Phase2PostPruneCompletionReplayRequired
        }
        StoredStatus::Mismatch => DomainOperationTerminalStatusAttachmentStatusV1::Mismatch,
        StoredStatus::Invalid => DomainOperationTerminalStatusAttachmentStatusV1::Invalid,
    };
    let range = ack.range;
    Ok(DomainOperationTerminalStatusAttachmentAckV1 {
        status: status as i32,
        terminal_ack_canonical: Bytes::from(ack.fields[0].clone().unwrap_or_default()),
        terminal_ack_digest: Bytes::from(ack.fields[1].clone().unwrap_or_default()),
        receipt_prune_digest: Bytes::from(ack.fields[2].clone().unwrap_or_default()),
        fence_prune_digest: Bytes::from(ack.fields[3].clone().unwrap_or_default()),
        release_tombstone_digest: Bytes::from(ack.fields[4].clone().unwrap_or_default()),
        tombstone_created_at_unix_millis: ack.times[0].map(unix_millis).transpose()?,
        tombstone_retain_until_unix_millis: ack.times[1].map(unix_millis).transpose()?,
        active_release_ack_digest: Bytes::from(ack.fields[5].clone().unwrap_or_default()),
        active_release_ack_at_unix_millis: ack.times[2].map(unix_millis).transpose()?,
        tombstone_reservation_claim_digest: Bytes::from(ack.fields[6].clone().unwrap_or_default()),
        final_prune_digest: Bytes::from(ack.fields[7].clone().unwrap_or_default()),
        final_pruned_at_unix_millis: ack.times[3].map(unix_millis).transpose()?,
        completion_marker_digest: Bytes::from(ack.fields[8].clone().unwrap_or_default()),
        completion_marker_created_at_unix_millis: ack.times[4].map(unix_millis).transpose()?,
        completion_marker_retain_until_unix_millis: ack.times[5].map(unix_millis).transpose()?,
        completion_marker_sequence: to_u64(
            ack.completion_marker_sequence,
            "completion marker sequence",
        )?,
        completion_marker_proof_digest: Bytes::from(ack.fields[9].clone().unwrap_or_default()),
        prune_range_start_sequence: range
            .as_ref()
            .map(|value| to_u64(value.start_sequence, "prune range start"))
            .transpose()?,
        prune_range_end_sequence: range
            .as_ref()
            .map(|value| to_u64(value.end_sequence, "prune range end"))
            .transpose()?,
        prune_range_digest: Bytes::from(
            range
                .as_ref()
                .map(|value| value.digest.clone())
                .unwrap_or_default(),
        ),
        prune_range_generation: range
            .as_ref()
            .map(|value| to_u64(value.generation, "prune range generation"))
            .transpose()?,
        informational_high_water: ack
            .informational_high_water
            .map(|value| to_u64(value, "informational high-water"))
            .transpose()?,
        response_digest: Bytes::from(ack.response_digest),
    })
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

    async fn domain_operation_verified_stale_finalize(
        &self,
        request: Request<DomainOperationVerifiedStaleFinalizeRequest>,
    ) -> Result<Response<DomainOperationVerifiedStaleFinalizeResponse>, Status> {
        let token = authenticated_service(&request)?;
        let authorization = extract_authorization_header(&request)
            .ok_or_else(|| Status::unauthenticated("Authorization header required"))?;
        let request = request.into_inner();
        validate_verified_stale_finalize(&request)?;
        require_request_identity(
            &token,
            &request.verified_issuer,
            &request.authenticated_subject,
        )?;
        let (verify_request, canonical, request_sha256) = maintenance_verifier_request(
            &token,
            DomainOperationMaintenanceMethod::VerifiedStaleFinalize,
            &request.org_uuid,
            &request.initiating_principal_namespace,
            &request.operation_id,
            MethodBinding::StaleFinalize(DomainOperationStaleFinalizePermitVerification {
                operation_id: request.operation_id.clone(),
                authorization_id: request.authorization_id.clone(),
                authorization_revision: request.authorization_revision,
                verification_nonce: request.verification_nonce.clone(),
                bound_fields_digest: request.bound_fields_digest.clone(),
                consumed_ticket_sha256: request.consumed_ticket_sha256.clone(),
                expected_claim_identity_digest: request.expected_claim_identity_digest.clone(),
                stale_finalize_permit: request.stale_finalize_permit.clone(),
                stale_finalize_permit_revision: request.stale_finalize_permit_revision,
                request_digest: Bytes::new(),
            }),
            &request,
            authorization,
        )?;
        // This validates the exact canonical form passed to the verifier. The
        // registered transport wrapper rejects the original raw frame before
        // Prost; this second check keeps direct service calls fail closed too.
        validate_verified_stale_finalize_raw(&canonical)?;
        let verified = match self
            .verifier
            .claim_repository_operation_stale_finalize_permit(verify_request)
            .await
        {
            Ok(response) => response,
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::PermissionDenied
                        | tonic::Code::FailedPrecondition
                        | tonic::Code::NotFound
                ) =>
            {
                return Ok(Response::new(
                    DomainOperationVerifiedStaleFinalizeResponse {
                        status: DomainOperationVerifiedStaleFinalizeStatus::IneligibleFinalizePermit
                            as i32,
                        stale_finalize_permit_revision: request.stale_finalize_permit_revision,
                        committed_receipt_canonical: Bytes::new(),
                        committed_receipt_sha256: Bytes::new(),
                        stale_finalize_clock_unix_millis: None,
                        response_digest: Bytes::new(),
                    },
                ));
            }
            Err(status) => return Err(status),
        };
        let verification_digest = exact_maintenance_echo(
            &token,
            DomainOperationMaintenanceMethod::VerifiedStaleFinalize,
            &request.org_uuid,
            &request.initiating_principal_namespace,
            &request.operation_id,
            &request_sha256,
            verified,
        )?;
        let operation_id = uuid::Uuid::from_slice(&request.operation_id)
            .map_err(|_| Status::invalid_argument("operation_id is not a UUID"))?;
        let key = receipt_key(
            &token,
            &ValidatedBinding {
                org_uuid: request.org_uuid.to_vec(),
                initiating_principal_namespace: request.initiating_principal_namespace.to_vec(),
                operation_id,
                method: request.method.clone(),
                scope: request.scope.to_vec(),
                fingerprint_version: i32::try_from(request.fingerprint_version)
                    .map_err(|_| Status::invalid_argument("fingerprint_version exceeds i32"))?,
                fingerprint: request.fingerprint.to_vec(),
                canonical_intent_digest: request.canonical_intent_digest.to_vec(),
                authorization_id: request.authorization_id.to_vec(),
                authorization_revision: request.authorization_revision,
            },
        )?;
        let input = lore_postgres::domain::maintenance::VerifiedStaleFinalizeInput {
            key,
            binding: OperationBinding {
                method: request.method,
                scope: request.scope.to_vec(),
                fingerprint_version: i32::try_from(request.fingerprint_version)
                    .map_err(|_| Status::invalid_argument("fingerprint_version exceeds i32"))?,
                fingerprint: request.fingerprint.to_vec(),
                canonical_intent_digest: request.canonical_intent_digest.to_vec(),
            },
            witness: AuthorizationWitness {
                authorization_id: request.authorization_id.to_vec(),
                authorization_revision: i64::try_from(request.authorization_revision)
                    .map_err(|_| Status::invalid_argument("authorization revision exceeds i64"))?,
                verification_nonce: request.verification_nonce.to_vec(),
                bound_fields_digest: request.bound_fields_digest.to_vec(),
                consumed_ticket_sha256: request.consumed_ticket_sha256.to_vec(),
                expected_claim_identity_digest: request.expected_claim_identity_digest.to_vec(),
            },
            expected_claim_identity_digest: request.expected_claim_identity_digest.to_vec(),
            stale_finalize_permit: request.stale_finalize_permit.to_vec(),
            stale_finalize_permit_revision: i64::try_from(request.stale_finalize_permit_revision)
                .map_err(|_| {
                Status::invalid_argument("permit revision exceeds i64")
            })?,
            permit_verification_digest: verification_digest,
        };
        let result = self
            .domain
            .store()
            .domain_operation_verified_stale_finalize(&input)
            .await
            .map_err(|e| map_domain_error_to_status(&e))?;
        let status = match result.status {
            lore_postgres::domain::maintenance::VerifiedStaleFinalizeStatus::Committed => {
                DomainOperationVerifiedStaleFinalizeStatus::Committed
            }
            lore_postgres::domain::maintenance::VerifiedStaleFinalizeStatus::NotEligibleNotStale => {
                DomainOperationVerifiedStaleFinalizeStatus::NotEligibleNotStale
            }
            lore_postgres::domain::maintenance::VerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible => {
                DomainOperationVerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible
            }
            lore_postgres::domain::maintenance::VerifiedStaleFinalizeStatus::Mismatch => {
                DomainOperationVerifiedStaleFinalizeStatus::Mismatch
            }
        };
        let receipt_sha256 = if result.committed_receipt_canonical.is_empty() {
            Bytes::new()
        } else {
            Bytes::copy_from_slice(digest(&SHA256, &result.committed_receipt_canonical).as_ref())
        };
        Ok(Response::new(
            DomainOperationVerifiedStaleFinalizeResponse {
                status: status as i32,
                stale_finalize_permit_revision: u64::try_from(
                    result.stale_finalize_permit_revision,
                )
                .map_err(|_| Status::internal("stored permit revision is negative"))?,
                committed_receipt_canonical: Bytes::from(result.committed_receipt_canonical),
                committed_receipt_sha256: receipt_sha256,
                stale_finalize_clock_unix_millis: result
                    .stale_finalize_clock
                    .map(unix_millis)
                    .transpose()?,
                response_digest: Bytes::from(result.response_digest),
            },
        ))
    }

    async fn domain_operation_terminal_status_attach(
        &self,
        request: Request<DomainOperationTerminalStatusAttachRequest>,
    ) -> Result<Response<DomainOperationTerminalStatusAttachmentAckV1>, Status> {
        let token = authenticated_service(&request)?;
        let authorization = extract_authorization_header(&request)
            .ok_or_else(|| Status::unauthenticated("Authorization header required"))?;
        let request = request.into_inner();
        validate_terminal_status_attach(&request)?;
        require_request_identity(
            &token,
            &request.verified_issuer,
            &request.authenticated_subject,
        )?;
        let (verify_request, canonical, request_sha256) = maintenance_verifier_request(
            &token,
            DomainOperationMaintenanceMethod::TerminalStatusAttach,
            &request.org_uuid,
            &request.initiating_principal_namespace,
            &request.operation_id,
            MethodBinding::TerminalStatusAttach(
                DomainOperationTerminalStatusAttachmentVerification {
                    operation_id: request.operation_id.clone(),
                    authorization_id: request.authorization_id.clone(),
                    authorization_revision: request.authorization_revision,
                    claim_id: request.claim_id.clone(),
                    claim_revision: request.claim_revision,
                    terminal_outcome: u32::try_from(request.terminal_outcome)
                        .map_err(|_| Status::invalid_argument("terminal outcome is negative"))?,
                    terminal_receipt_sha256: request.terminal_receipt_sha256.clone(),
                    platform_terminal_status_revision: request.platform_terminal_status_revision,
                    acknowledged_at_unix_millis: request.acknowledged_at_unix_millis,
                    phase: request.phase as u32,
                    reserve_charge_revision: request.reserve_charge_revision,
                    reserve_charge_nonce: request.reserve_charge_nonce.clone(),
                    phase2_action: request.phase2_action as u32,
                    release_tombstone_digest: request.release_tombstone_digest.clone(),
                    active_release_intent_revision: request.active_release_intent_revision,
                    active_release_intent_nonce: request.active_release_intent_nonce.clone(),
                    tombstone_reservation_revision: request.tombstone_reservation_revision,
                    tombstone_reservation_nonce: request.tombstone_reservation_nonce.clone(),
                    final_prune_digest: request.final_prune_digest.clone(),
                    tombstone_release_intent_revision: request.tombstone_release_intent_revision,
                    tombstone_release_intent_nonce: request.tombstone_release_intent_nonce.clone(),
                    release_proof_reservation_revision: request.release_proof_reservation_revision,
                    release_proof_reservation_nonce: request
                        .release_proof_reservation_nonce
                        .clone(),
                    completion_marker_sequence: request.completion_marker_sequence,
                    expected_completion_marker_digest: request
                        .expected_completion_marker_digest
                        .clone(),
                    request_digest: request.request_digest.clone(),
                },
            ),
            &request,
            authorization,
        )?;
        validate_terminal_status_attach_raw(&canonical)?;
        let verified = self
            .verifier
            .verify_repository_operation_terminal_status_attach(verify_request)
            .await?;
        let verification_digest = exact_maintenance_echo(
            &token,
            DomainOperationMaintenanceMethod::TerminalStatusAttach,
            &request.org_uuid,
            &request.initiating_principal_namespace,
            &request.operation_id,
            &request_sha256,
            verified,
        )?;
        let operation_id = uuid::Uuid::from_slice(&request.operation_id)
            .map_err(|_| Status::invalid_argument("operation_id is not a UUID"))?;
        let tenant_scope_key = scope_key_mediated_namespace(
            &request.org_uuid,
            &request.initiating_principal_namespace,
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let phase = TerminalStatusAttachPhaseV1::try_from(request.phase)
            .map_err(|_| Status::invalid_argument("invalid terminal attach phase"))?;
        let action = TerminalStatusAttachPhase2ActionV1::try_from(request.phase2_action)
            .map_err(|_| Status::invalid_argument("invalid terminal attach action"))?;
        let input = lore_postgres::domain::maintenance::TerminalStatusAttachInput {
            key: ReceiptKey {
                verified_issuer: token.issuer,
                authenticated_subject: token.user_id,
                tenant_scope_key,
                operation_id,
            },
            authorization_id: request.authorization_id.to_vec(),
            authorization_revision: i64::try_from(request.authorization_revision)
                .map_err(|_| Status::invalid_argument("authorization revision exceeds i64"))?,
            claim_id: request.claim_id.to_vec(),
            claim_revision: i64::try_from(request.claim_revision)
                .map_err(|_| Status::invalid_argument("claim revision exceeds i64"))?,
            terminal_outcome: i16::try_from(request.terminal_outcome)
                .map_err(|_| Status::invalid_argument("terminal outcome exceeds i16"))?,
            terminal_receipt_sha256: request.terminal_receipt_sha256.to_vec(),
            platform_terminal_status_revision: i64::try_from(
                request.platform_terminal_status_revision,
            )
            .map_err(|_| Status::invalid_argument("terminal status revision exceeds i64"))?,
            acknowledged_at: system_time_from_millis(
                request.acknowledged_at_unix_millis,
                "acknowledged_at_unix_millis",
            )?,
            phase: match phase {
                TerminalStatusAttachPhaseV1::Phase1TerminalAck => {
                    lore_postgres::domain::maintenance::TerminalStatusAttachPhase::Phase1TerminalAck
                }
                TerminalStatusAttachPhaseV1::Phase2ReleaseAck => {
                    lore_postgres::domain::maintenance::TerminalStatusAttachPhase::Phase2ReleaseAck
                }
                _ => return Err(Status::invalid_argument("phase is unspecified")),
            },
            action: match action {
                TerminalStatusAttachPhase2ActionV1::Unspecified => {
                    lore_postgres::domain::maintenance::TerminalStatusAttachAction::None
                }
                TerminalStatusAttachPhase2ActionV1::ActiveReleaseIntentAck => {
                    lore_postgres::domain::maintenance::TerminalStatusAttachAction::ActiveReleaseIntentAck
                }
                TerminalStatusAttachPhase2ActionV1::TombstonePrunePoll => {
                    lore_postgres::domain::maintenance::TerminalStatusAttachAction::TombstonePrunePoll
                }
                TerminalStatusAttachPhase2ActionV1::TombstoneReleaseIntentComplete => {
                    lore_postgres::domain::maintenance::TerminalStatusAttachAction::TombstoneReleaseIntentComplete
                }
            },
            reserve_charge_revision: i64::try_from(request.reserve_charge_revision)
                .map_err(|_| Status::invalid_argument("charge revision exceeds i64"))?,
            reserve_charge_nonce: request.reserve_charge_nonce.to_vec(),
            release_tombstone_digest: nonempty(request.release_tombstone_digest.as_ref()),
            active_release_intent_revision: positive_i64(request.active_release_intent_revision)?,
            active_release_intent_nonce: nonempty(request.active_release_intent_nonce.as_ref()),
            tombstone_reservation_revision: i64::try_from(
                request.tombstone_reservation_revision,
            )
            .map_err(|_| Status::invalid_argument("tombstone revision exceeds i64"))?,
            tombstone_reservation_nonce: request.tombstone_reservation_nonce.to_vec(),
            final_prune_digest: nonempty(request.final_prune_digest.as_ref()),
            tombstone_release_intent_revision: positive_i64(
                request.tombstone_release_intent_revision,
            )?,
            tombstone_release_intent_nonce: nonempty(
                request.tombstone_release_intent_nonce.as_ref(),
            ),
            release_proof_reservation_revision: i64::try_from(
                request.release_proof_reservation_revision,
            )
            .map_err(|_| Status::invalid_argument("proof reservation revision exceeds i64"))?,
            release_proof_reservation_nonce: request.release_proof_reservation_nonce.to_vec(),
            completion_marker_sequence: i64::try_from(request.completion_marker_sequence)
                .map_err(|_| Status::invalid_argument("marker sequence exceeds i64"))?,
            expected_completion_marker_digest: nonempty(
                request.expected_completion_marker_digest.as_ref(),
            ),
            request_digest: request.request_digest.to_vec(),
            verification_digest,
        };
        let ack = self
            .domain
            .store()
            .domain_operation_terminal_status_attach(&input)
            .await
            .map_err(|e| map_domain_error_to_status(&e))?;
        Ok(Response::new(terminal_ack_response(ack)?))
    }

    async fn domain_operation_proof_namespace_materialize(
        &self,
        request: Request<DomainOperationProofNamespaceMaterializeRequestV1>,
    ) -> Result<Response<DomainOperationProofNamespaceMaterializeReceiptV1>, Status> {
        let token = authenticated_service(&request)?;
        let authorization = extract_authorization_header(&request)
            .ok_or_else(|| Status::unauthenticated("Authorization header required"))?;
        let request = request.into_inner();
        validate_proof_namespace_materialize(&request)?;
        require_request_identity(
            &token,
            &request.verified_issuer,
            &request.authenticated_subject,
        )?;
        if bearer_payload(&authorization) != Some(request.materialization_jwt.as_str()) {
            return Err(Status::permission_denied(
                "materialization JWT must be the verified bearer token",
            ));
        }
        let (verify_request, canonical, request_sha256) = maintenance_verifier_request(
            &token,
            DomainOperationMaintenanceMethod::ProofNamespaceMaterialize,
            &request.org_uuid,
            &request.initiating_principal_namespace,
            &request.namespace_epoch,
            MethodBinding::ProofNamespaceMaterialize(
                DomainOperationProofNamespaceMaterializationVerification {
                    protocol_revision: request.protocol_revision,
                    namespace_epoch: request.namespace_epoch.clone(),
                    namespace_claim_revision: request.namespace_claim_revision,
                    namespace_claim_nonce: request.namespace_claim_nonce.clone(),
                    platform_capacity_revision: request.platform_capacity_revision,
                    lore_local_capacity_revision: request.lore_local_capacity_revision,
                    request_digest: request.request_digest.clone(),
                    signed_jwt: request.materialization_jwt.clone(),
                },
            ),
            &request,
            authorization,
        )?;
        validate_proof_namespace_materialize_raw(&canonical)?;
        let verified = self
            .verifier
            .verify_repository_operation_proof_namespace_materialize(verify_request)
            .await?;
        let verification_digest = exact_maintenance_echo(
            &token,
            DomainOperationMaintenanceMethod::ProofNamespaceMaterialize,
            &request.org_uuid,
            &request.initiating_principal_namespace,
            &request.namespace_epoch,
            &request_sha256,
            verified,
        )?;
        let key = proof_namespace_key(
            &token,
            &request.org_uuid,
            &request.initiating_principal_namespace,
        )?;
        let input = lore_postgres::domain::maintenance::ProofNamespaceMaterializeInput {
            key,
            protocol_revision: i32::try_from(request.protocol_revision)
                .map_err(|_| Status::invalid_argument("protocol revision exceeds i32"))?,
            namespace_epoch: request.namespace_epoch.to_vec(),
            namespace_claim_revision: i64::try_from(request.namespace_claim_revision)
                .map_err(|_| Status::invalid_argument("claim revision exceeds i64"))?,
            namespace_claim_nonce: request.namespace_claim_nonce.to_vec(),
            platform_capacity_revision: i64::try_from(request.platform_capacity_revision)
                .map_err(|_| Status::invalid_argument("platform capacity revision exceeds i64"))?,
            lore_local_capacity_revision: i64::try_from(request.lore_local_capacity_revision)
                .map_err(|_| Status::invalid_argument("Lore capacity revision exceeds i64"))?,
            request_digest: request.request_digest.to_vec(),
            verification_digest,
        };
        let receipt = self
            .domain
            .store()
            .domain_operation_proof_namespace_materialize(&input)
            .await
            .map_err(|e| map_domain_error_to_status(&e))?;
        Ok(Response::new(DomainOperationProofNamespaceMaterializeReceiptV1 {
            status: match receipt.status {
                lore_postgres::domain::maintenance::ProofNamespaceMaterializeStatus::Materialized => DomainOperationProofNamespaceMaterializeStatusV1::Materialized,
                lore_postgres::domain::maintenance::ProofNamespaceMaterializeStatus::Mismatch => DomainOperationProofNamespaceMaterializeStatusV1::Mismatch,
                lore_postgres::domain::maintenance::ProofNamespaceMaterializeStatus::CapacityBlocked => DomainOperationProofNamespaceMaterializeStatusV1::CapacityBlocked,
            } as i32,
            namespace_epoch: Bytes::from(receipt.namespace_epoch),
            namespace_claim_revision: to_u64(receipt.namespace_claim_revision, "claim revision")?,
            namespace_claim_nonce: Bytes::from(receipt.namespace_claim_nonce),
            lore_namespace_revision: to_u64(receipt.lore_namespace_revision, "namespace revision")?,
            lore_global_counter_revision: to_u64(receipt.lore_global_counter_revision, "global counter revision")?,
            lore_org_counter_revision: to_u64(receipt.lore_org_counter_revision, "org counter revision")?,
            created_at_unix_millis: unix_millis(receipt.created_at)?,
            materialization_receipt_digest: Bytes::from(receipt.materialization_receipt_digest),
            response_digest: Bytes::from(receipt.response_digest),
        }))
    }

    async fn domain_operation_proof_namespace_retire(
        &self,
        request: Request<DomainOperationProofNamespaceRetireRequestV1>,
    ) -> Result<Response<DomainOperationProofNamespaceRetireAckV1>, Status> {
        let token = authenticated_service(&request)?;
        let authorization = extract_authorization_header(&request)
            .ok_or_else(|| Status::unauthenticated("Authorization header required"))?;
        let request = request.into_inner();
        validate_proof_namespace_retire(&request)?;
        require_request_identity(
            &token,
            &request.verified_issuer,
            &request.authenticated_subject,
        )?;
        if bearer_payload(&authorization) != Some(request.retirement_permit_jwt.as_str()) {
            return Err(Status::permission_denied(
                "retirement permit JWT must be the verified bearer token",
            ));
        }
        let (verify_request, canonical, request_sha256) = maintenance_verifier_request(
            &token,
            DomainOperationMaintenanceMethod::ProofNamespaceRetire,
            &request.org_uuid,
            &request.initiating_principal_namespace,
            &request.namespace_epoch,
            MethodBinding::ProofNamespaceRetire(
                DomainOperationProofNamespaceRetirementVerification {
                    protocol_revision: request.protocol_revision,
                    namespace_epoch: request.namespace_epoch.clone(),
                    quota_revision: request.quota_revision,
                    final_range_set_digest: request.final_range_set_digest.clone(),
                    final_high_water: request.final_high_water,
                    retirement_fence_generation: request.retirement_fence_generation,
                    retirement_permit_revision: request.retirement_permit_revision,
                    issued_at_unix_millis: request.issued_at_unix_millis,
                    expires_at_unix_millis: request.expires_at_unix_millis,
                    zero_platform_state_digest: request.zero_platform_state_digest.clone(),
                    request_digest: request.request_digest.clone(),
                    signed_jwt: request.retirement_permit_jwt.clone(),
                    namespace_claim_revision: request.namespace_claim_revision,
                    namespace_claim_nonce: request.namespace_claim_nonce.clone(),
                },
            ),
            &request,
            authorization,
        )?;
        validate_proof_namespace_retire_raw(&canonical)?;
        let verified = self
            .verifier
            .verify_repository_operation_proof_namespace_retire(verify_request)
            .await?;
        let verification_digest = exact_maintenance_echo(
            &token,
            DomainOperationMaintenanceMethod::ProofNamespaceRetire,
            &request.org_uuid,
            &request.initiating_principal_namespace,
            &request.namespace_epoch,
            &request_sha256,
            verified,
        )?;
        let input = lore_postgres::domain::maintenance::ProofNamespaceRetireInput {
            key: proof_namespace_key(
                &token,
                &request.org_uuid,
                &request.initiating_principal_namespace,
            )?,
            protocol_revision: i32::try_from(request.protocol_revision)
                .map_err(|_| Status::invalid_argument("protocol revision exceeds i32"))?,
            namespace_epoch: request.namespace_epoch.to_vec(),
            quota_revision: i32::try_from(request.quota_revision)
                .map_err(|_| Status::invalid_argument("quota revision exceeds i32"))?,
            final_range_set_digest: request.final_range_set_digest.to_vec(),
            final_high_water: i64::try_from(request.final_high_water)
                .map_err(|_| Status::invalid_argument("final high-water exceeds i64"))?,
            retirement_fence_generation: i64::try_from(request.retirement_fence_generation)
                .map_err(|_| Status::invalid_argument("fence generation exceeds i64"))?,
            retirement_permit_revision: i64::try_from(request.retirement_permit_revision)
                .map_err(|_| Status::invalid_argument("permit revision exceeds i64"))?,
            issued_at: system_time_from_millis(
                request.issued_at_unix_millis,
                "issued_at_unix_millis",
            )?,
            expires_at: system_time_from_millis(
                request.expires_at_unix_millis,
                "expires_at_unix_millis",
            )?,
            zero_platform_state_digest: request.zero_platform_state_digest.to_vec(),
            request_digest: request.request_digest.to_vec(),
            namespace_claim_revision: i64::try_from(request.namespace_claim_revision)
                .map_err(|_| Status::invalid_argument("claim revision exceeds i64"))?,
            namespace_claim_nonce: request.namespace_claim_nonce.to_vec(),
            verification_digest,
        };
        let ack = self
            .domain
            .store()
            .domain_operation_proof_namespace_retire(&input)
            .await
            .map_err(|e| map_domain_error_to_status(&e))?;
        Ok(Response::new(DomainOperationProofNamespaceRetireAckV1 {
            status: match ack.status {
                lore_postgres::domain::maintenance::ProofNamespaceRetireStatus::Retired => {
                    DomainOperationProofNamespaceRetireStatusV1::Retired
                }
                lore_postgres::domain::maintenance::ProofNamespaceRetireStatus::RetiredOrAbsent => {
                    DomainOperationProofNamespaceRetireStatusV1::RetiredOrAbsent
                }
                lore_postgres::domain::maintenance::ProofNamespaceRetireStatus::NotQuiescent => {
                    DomainOperationProofNamespaceRetireStatusV1::NotQuiescent
                }
                lore_postgres::domain::maintenance::ProofNamespaceRetireStatus::Mismatch => {
                    DomainOperationProofNamespaceRetireStatusV1::Mismatch
                }
                lore_postgres::domain::maintenance::ProofNamespaceRetireStatus::Expired => {
                    DomainOperationProofNamespaceRetireStatusV1::Expired
                }
            } as i32,
            namespace_epoch: Bytes::from(ack.namespace_epoch),
            retirement_fence_generation: to_u64(
                ack.retirement_fence_generation,
                "fence generation",
            )?,
            quota_revision: u64::try_from(ack.quota_revision)
                .map_err(|_| Status::internal("stored quota revision is negative"))?,
            final_range_set_digest: Bytes::from(ack.final_range_set_digest),
            final_high_water: to_u64(ack.final_high_water, "final high-water")?,
            retired_at_unix_millis: ack.retired_at.map(unix_millis).transpose()?,
            namespace_claim_revision: to_u64(ack.namespace_claim_revision, "claim revision")?,
            namespace_claim_nonce: Bytes::from(ack.namespace_claim_nonce),
            response_digest: Bytes::from(ack.response_digest),
        }))
    }
}
