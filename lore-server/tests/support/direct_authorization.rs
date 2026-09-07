// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_proto::rebac::AuthorizeDirectRepositoryOperationRequest;
use lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse;

/// Independent fixture encoder for the platform's frozen direct witness.
pub fn direct_echo(
    request: AuthorizeDirectRepositoryOperationRequest,
) -> AuthorizeDirectRepositoryOperationResponse {
    let nonce = [0x11; 32];
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    digest.update(b"repository-operation-direct-authorization-v1\0");
    for field in [
        request.verified_issuer.as_bytes(),
        request.authenticated_subject.as_bytes(),
        request.operation_id.as_ref(),
        request.method.as_bytes(),
        request.scope.as_ref(),
        &request.fingerprint_version.to_be_bytes(),
        request.fingerprint.as_ref(),
        request.canonical_intent_digest.as_ref(),
        request.repository_id.as_ref(),
        request.branch_id.as_ref(),
        request.operation_id.as_ref(),
        &1u64.to_be_bytes(),
        &nonce,
    ] {
        digest.update(
            &u32::try_from(field.len())
                .expect("fixture field length")
                .to_be_bytes(),
        );
        digest.update(field);
    }
    AuthorizeDirectRepositoryOperationResponse {
        verified_issuer: request.verified_issuer,
        authenticated_subject: request.authenticated_subject,
        operation_id: request.operation_id.clone(),
        method: request.method,
        scope: request.scope,
        fingerprint_version: request.fingerprint_version,
        fingerprint: request.fingerprint,
        canonical_intent_digest: request.canonical_intent_digest,
        authorization_id: request.operation_id,
        authorization_revision: 1,
        verification_nonce: nonce.to_vec().into(),
        bound_fields_digest: digest.finish().as_ref().to_vec().into(),
        repository_id: request.repository_id,
        org_uuid: bytes::Bytes::new(),
    }
}
