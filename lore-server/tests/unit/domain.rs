// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The fork's `domain` tests, moved out of the inline `domain::tests` module
//! when upstream set `[lib] test = false`.

mod backfill_source;
mod creation_readback_tests;
mod operator;
mod p12_tests;
mod schema_operator;

use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use lore_postgres::domain::DomainSchemaState;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::locks::LockFencingReadiness;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::schema::BACKFILL_CUTOVER;
use lore_postgres::domain::schema::BACKFILL_NOT_STARTED;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::authnz::rebac::RepositoryOperationAuthorizationVerifier;
use lore_server::domain::test_support::PREPARED_TEST_TOKEN;
use lore_server::domain::test_support::context;
use lore_server::domain::test_support::preparing_context;
use lore_server::domain::*;
use lore_server::grpc::domain_operation_metadata;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_KEY;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_V1_LEN;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
use lore_server::grpc::domain_operation_metadata::OPERATION_ID_KEY;
use lore_server::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
use lore_server::grpc::domain_operation_metadata::PREPARE_TOKEN_LEN;
use lore_server::grpc::domain_operation_metadata::SCOPE_PRINCIPAL_NAMESPACE_V1;
use lore_server::settings::AuthSettings;
use lore_server::settings::Settings;
use tonic::Code;
use tonic::Status;
use tonic::metadata::BinaryMetadataValue;
use tonic::metadata::MetadataMap;
use uuid::Uuid;

// --- shared helpers ------------------------------------------------

fn valid_metadata(operation_id: Uuid) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    metadata.insert_bin(
        OPERATION_ID_KEY,
        BinaryMetadataValue::from_bytes(operation_id.as_bytes()),
    );
    let mut fingerprint = vec![FINGERPRINT_VERSION_V1];
    fingerprint.extend(std::iter::repeat_n(0xAB, FINGERPRINT_V1_LEN));
    metadata.insert_bin(
        FINGERPRINT_KEY,
        BinaryMetadataValue::from_bytes(&fingerprint),
    );
    metadata.insert_bin(
        PREPARE_TOKEN_KEY,
        BinaryMetadataValue::from_bytes(&[0xCDu8; PREPARE_TOKEN_LEN]),
    );
    metadata
}

fn test_token(issuer: &str, subject: &str) -> AuthorizationToken {
    AuthorizationToken {
        issuer: issuer.to_string(),
        user_id: subject.to_string(),
        ..Default::default()
    }
}

fn test_repository_id() -> [u8; 16] {
    *Uuid::new_v4().as_bytes()
}

// Outputs of the real platform directAuthorizationBoundFieldsDigest, also
// pinned by packages/control-plane/test/mutation-authorization.test.ts.
fn platform_direct_vector(
    branch: &[u8],
    expected: &str,
) -> (
    ReceiptKey,
    OperationBinding,
    lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse,
) {
    let operation_id = Uuid::parse_str("01882f40-5b1c-71a9-8b3d-5e027791c466").unwrap();
    let key = ReceiptKey {
        verified_issuer: "https://id.commit0.localhost".into(),
        authenticated_subject: "case-i-writer".into(),
        operation_id,
        tenant_scope_key: vec![0x30; 24],
    };
    let binding = OperationBinding {
        method: "branch.push".into(),
        scope: key.tenant_scope_key.clone(),
        fingerprint_version: 1,
        fingerprint: vec![0x11; 32],
        canonical_intent_digest: vec![0x22; 32],
    };
    let response = lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse {
        verified_issuer: key.verified_issuer.clone(),
        authenticated_subject: key.authenticated_subject.clone(),
        operation_id: key.operation_id.as_bytes().to_vec().into(),
        method: binding.method.clone(),
        scope: binding.scope.clone().into(),
        fingerprint_version: 1,
        fingerprint: binding.fingerprint.clone().into(),
        canonical_intent_digest: binding.canonical_intent_digest.clone().into(),
        authorization_id: key.operation_id.as_bytes().to_vec().into(),
        authorization_revision: 1,
        verification_nonce: vec![0x55; 32].into(),
        bound_fields_digest: (0..expected.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&expected[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .into(),
        repository_id: vec![0x33; 16].into(),
        org_uuid: bytes::Bytes::new(),
    };
    assert_eq!(
        direct_authorization_bound_fields_digest(
            &key,
            &binding,
            &response.repository_id,
            branch,
            &response,
        )
        .unwrap(),
        response.bound_fields_digest
    );
    (key, binding, response)
}

#[test]
fn direct_echo_accepts_platform_vectors_with_and_without_branch() {
    for (branch, expected) in [
        (
            &[0x44; 16][..],
            "a7941dfaea01b967312cd346d1154e12cd0a64dd4b96a5a03a6436c18771eb7e",
        ),
        (
            &[][..],
            "6ab0bde51f1c90376d3b33fb815a2ea0c9e7b57813a9fe3aea856604971c1f3a",
        ),
    ] {
        let (key, binding, response) = platform_direct_vector(branch, expected);
        verify_direct_echo(&key, &binding, &[0x33; 16], branch, &response).unwrap();
    }
}

#[test]
fn direct_echo_binds_the_request_branch_and_rejects_branchless_substitution() {
    let (key, binding, response) = platform_direct_vector(
        &[0x44; 16],
        "a7941dfaea01b967312cd346d1154e12cd0a64dd4b96a5a03a6436c18771eb7e",
    );
    for wrong_branch in [&[0x45; 16][..], &[][..]] {
        let error = verify_direct_echo(&key, &binding, &[0x33; 16], wrong_branch, &response)
            .expect_err("request branch must be bound by the platform witness");
        assert_eq!(error.code(), Code::PermissionDenied);
    }
}

// --- 1. GovernedScope::tenant_scope_key -------------------------------

#[test]
fn repository_create_and_target_repository_scopes_differ_over_the_same_id() {
    let repository_id = test_repository_id();

    let create = GovernedScope::RepositoryCreate {
        repository_id: &repository_id,
    }
    .tenant_scope_key()
    .expect("valid repository id");
    let target = GovernedScope::TargetRepository {
        repository_id: &repository_id,
    }
    .tenant_scope_key()
    .expect("valid repository id");

    assert_ne!(create, target);
}

#[test]
fn mediated_scope_contains_the_principal_namespace_tag() {
    let org_uuid = test_repository_id();

    let key = GovernedScope::Mediated {
        org_uuid: &org_uuid,
        principal_user_id: b"user-1",
    }
    .tenant_scope_key()
    .expect("valid mediated components");

    assert!(
        key.windows(SCOPE_PRINCIPAL_NAMESPACE_V1.len())
            .any(|window| window == SCOPE_PRINCIPAL_NAMESPACE_V1)
    );
}

// A bad target identity is the caller's mistake, not the server's: the
// gate runs before handler logic, so nothing has validated `repository_id`
// yet. `Code::Internal` would misattribute the fault and is the one code
// an operator pages on. Both cases need carriage present and a token, or
// `admit` short-circuits before the scope key is ever built.
#[test]
fn wrong_length_repository_id_reaches_admit_as_invalid_argument_not_internal() {
    let ctx = context(false);
    let metadata = valid_metadata(Uuid::now_v7());
    let token = test_token("https://issuer.example", "subject-123");
    let repository_id = [0xAAu8; 15];

    let err = ctx
        .admit(
            &metadata,
            Some(&token),
            GovernedScope::TargetRepository {
                repository_id: &repository_id,
            },
        )
        .expect_err("a wrong-length repository id must be rejected");

    assert_eq!(err.code(), Code::InvalidArgument);
}

#[test]
fn urc_prefixed_repository_id_reaches_admit_as_invalid_argument_not_internal() {
    let ctx = context(false);
    let metadata = valid_metadata(Uuid::now_v7());
    let token = test_token("https://issuer.example", "subject-123");
    let mut repository_id = [0u8; 16];
    repository_id[..4].copy_from_slice(b"urc-");

    let err = ctx
        .admit(
            &metadata,
            Some(&token),
            GovernedScope::TargetRepository {
                repository_id: &repository_id,
            },
        )
        .expect_err("a urc--prefixed repository id must be rejected");

    assert_eq!(err.code(), Code::InvalidArgument);
}

// --- 2/3. admit_at_entry against a cell with no coordinator -----------

#[test]
fn admit_at_entry_with_no_coordinator_and_no_carriage_is_the_legacy_path() {
    let metadata = MetadataMap::new();
    let repository_id = test_repository_id();

    let result = admit_at_entry(
        None,
        &metadata,
        None,
        GovernedScope::TargetRepository {
            repository_id: &repository_id,
        },
    );

    assert!(matches!(result, Ok(None)));
}

#[test]
fn admit_at_entry_with_no_coordinator_and_valid_carriage_is_refused() {
    let metadata = valid_metadata(Uuid::now_v7());
    let repository_id = test_repository_id();

    let err = admit_at_entry(
        None,
        &metadata,
        None,
        GovernedScope::TargetRepository {
            repository_id: &repository_id,
        },
    )
    .expect_err("carriage against a cell with no coordinator must be refused, never downgraded");

    assert_eq!(err.code(), Code::FailedPrecondition);
}

// --- 4. DomainContext::admit, enforcement off --------------------------

#[test]
fn enforcement_off_with_no_carriage_is_the_legacy_path() {
    let ctx = context(false);
    let metadata = MetadataMap::new();
    let repository_id = test_repository_id();

    let result = ctx.admit(
        &metadata,
        None,
        GovernedScope::TargetRepository {
            repository_id: &repository_id,
        },
    );

    assert!(matches!(result, Ok(None)));
}

#[test]
fn enforcement_off_with_carriage_and_a_token_admits_keyed_by_the_token_not_the_body() {
    let ctx = context(false);
    let operation_id = Uuid::now_v7();
    let metadata = valid_metadata(operation_id);
    let token = test_token("https://issuer.example", "subject-123");
    let repository_id = test_repository_id();

    let admitted = ctx
        .admit(
            &metadata,
            Some(&token),
            GovernedScope::TargetRepository {
                repository_id: &repository_id,
            },
        )
        .expect("valid carriage plus a verified principal must admit")
        .expect("must be Some, not the legacy path");

    assert_eq!(admitted.key.operation_id, operation_id);
    assert_eq!(admitted.key.verified_issuer, token.issuer);
    assert_eq!(admitted.key.authenticated_subject, token.user_id);
}

// --- 5. DomainContext::admit, absence and unauthenticated carriage ----

#[test]
fn enforcement_on_with_no_carriage_is_refused_as_invalid_argument() {
    let ctx = context(true);
    let metadata = MetadataMap::new();
    let repository_id = test_repository_id();

    let err = ctx
        .admit(
            &metadata,
            None,
            GovernedScope::TargetRepository {
                repository_id: &repository_id,
            },
        )
        .expect_err("enforcement on requires carriage");

    assert_eq!(err.code(), Code::InvalidArgument);
}

#[test]
fn carriage_without_a_verified_principal_is_refused_with_enforcement_on() {
    let ctx = context(true);
    let metadata = valid_metadata(Uuid::now_v7());
    let repository_id = test_repository_id();

    let err = ctx
        .admit(
            &metadata,
            None,
            GovernedScope::TargetRepository {
                repository_id: &repository_id,
            },
        )
        .expect_err("carriage without a verified principal must be refused");

    assert_eq!(err.code(), Code::Unauthenticated);
}

// Absence of enforcement is not a licence to ignore carriage: a caller
// that asked for governed semantics by supplying operation identity must
// not be silently handed today's unsynchronised writes just because this
// cell has not turned enforcement on yet.
#[test]
fn carriage_without_a_verified_principal_is_refused_even_with_enforcement_off() {
    let ctx = context(false);
    let metadata = valid_metadata(Uuid::now_v7());
    let repository_id = test_repository_id();

    let err = ctx
        .admit(
            &metadata,
            None,
            GovernedScope::TargetRepository {
                repository_id: &repository_id,
            },
        )
        .expect_err(
            "carriage without a verified principal must be refused regardless of enforcement",
        );

    assert_eq!(err.code(), Code::Unauthenticated);
}

// --- 6. AdmittedOperation::into_governed -------------------------------

#[test]
fn into_governed_carries_prepare_token_and_fingerprint_unchanged_and_binds_scope_to_the_key() {
    let ctx = context(false);
    let operation_id = Uuid::now_v7();
    let metadata = valid_metadata(operation_id);
    let token = test_token("https://issuer.example", "subject-123");
    let repository_id = test_repository_id();

    let admitted = ctx
        .admit(
            &metadata,
            Some(&token),
            GovernedScope::TargetRepository {
                repository_id: &repository_id,
            },
        )
        .expect("valid carriage plus a verified principal must admit")
        .expect("must be Some");

    let carried = admitted.carried().expect("presented carriage").clone();
    let expected_prepare_token = carried.prepare_token;
    let expected_fingerprint = carried.fingerprint.clone();
    let expected_scope = admitted.key.tenant_scope_key.clone();

    let governed =
        admitted.into_governed("lore.RepositoryService/RepositoryDelete", vec![0xAAu8; 8]);

    assert_eq!(governed.prepare_token, expected_prepare_token);
    assert_eq!(governed.binding.fingerprint, expected_fingerprint);
    assert_eq!(governed.binding.scope, expected_scope);
    assert_eq!(governed.binding.scope, governed.key.tenant_scope_key);
}

// --- 6a. WP-120 internal admission --------------------------------------

/// A verifier double for the direct-authorization rail. Every method but
/// `authorize_direct_repository_operation` is unreachable, matching this
/// file's other doubles (`UnreachableDomainStore`) -- a signature drift on
/// an unused method must fail to compile, not silently inherit a body.
struct DirectVerifierDouble {
    calls: std::sync::atomic::AtomicUsize,
    forwarded_bearer: std::sync::Mutex<Option<String>>,
    diverge: Option<EchoDivergence>,
    error: Option<Status>,
}

/// Which single field of an otherwise-exact echo this double flips.
#[derive(Clone, Copy)]
enum EchoDivergence {
    VerifiedIssuer,
    AuthenticatedSubject,
    OperationId,
    Method,
    Scope,
    FingerprintVersion,
    Fingerprint,
    CanonicalIntentDigest,
    RepositoryId,
    MissingRepositoryId,
    AuthorizationId,
    AuthorizationRevision,
    VerificationNonce,
    BoundFieldsDigest,
}

impl DirectVerifierDouble {
    fn echo() -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
            forwarded_bearer: std::sync::Mutex::new(None),
            diverge: None,
            error: None,
        }
    }

    fn diverging(divergence: EchoDivergence) -> Self {
        Self {
            diverge: Some(divergence),
            ..Self::echo()
        }
    }

    fn erroring(status: Status) -> Self {
        Self {
            error: Some(status),
            ..Self::echo()
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn forwarded_bearer(&self) -> Option<String> {
        self.forwarded_bearer
            .lock()
            .expect("forwarded-bearer mutex poisoned")
            .clone()
    }
}

#[async_trait::async_trait]
impl RepositoryOperationAuthorizationVerifier for DirectVerifierDouble {
    async fn verify_repository_operation_authorization(
        &self,
        _request: tonic::Request<lore_proto::rebac::VerifyRepositoryOperationAuthorizationRequest>,
    ) -> Result<lore_proto::rebac::VerifyRepositoryOperationAuthorizationResponse, Status> {
        unreachable!("WP-120 internal-admission tests exercise only the direct rail")
    }

    async fn claim_repository_operation_stale_finalize_permit(
        &self,
        _request: tonic::Request<lore_proto::rebac::DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<lore_proto::rebac::DomainOperationMaintenanceVerificationResponse, Status> {
        unreachable!("WP-120 internal-admission tests exercise only the direct rail")
    }

    async fn verify_repository_operation_terminal_status_attach(
        &self,
        _request: tonic::Request<lore_proto::rebac::DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<lore_proto::rebac::DomainOperationMaintenanceVerificationResponse, Status> {
        unreachable!("WP-120 internal-admission tests exercise only the direct rail")
    }

    async fn verify_repository_operation_proof_namespace_materialize(
        &self,
        _request: tonic::Request<lore_proto::rebac::DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<lore_proto::rebac::DomainOperationMaintenanceVerificationResponse, Status> {
        unreachable!("WP-120 internal-admission tests exercise only the direct rail")
    }

    async fn verify_repository_operation_proof_namespace_retire(
        &self,
        _request: tonic::Request<lore_proto::rebac::DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<lore_proto::rebac::DomainOperationMaintenanceVerificationResponse, Status> {
        unreachable!("WP-120 internal-admission tests exercise only the direct rail")
    }

    async fn authorize_direct_repository_operation(
        &self,
        request: tonic::Request<lore_proto::rebac::AuthorizeDirectRepositoryOperationRequest>,
    ) -> Result<lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse, Status> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *self
            .forwarded_bearer
            .lock()
            .expect("forwarded-bearer mutex poisoned") = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if let Some(status) = &self.error {
            return Err(status.clone());
        }
        let request = request.into_inner();
        let key = ReceiptKey {
            verified_issuer: request.verified_issuer.clone(),
            authenticated_subject: request.authenticated_subject.clone(),
            operation_id: Uuid::from_slice(&request.operation_id).expect("operation UUID"),
            tenant_scope_key: request.scope.to_vec(),
        };
        let binding = OperationBinding {
            method: request.method.clone(),
            scope: request.scope.to_vec(),
            fingerprint_version: request.fingerprint_version.try_into().expect("version"),
            fingerprint: request.fingerprint.to_vec(),
            canonical_intent_digest: request.canonical_intent_digest.to_vec(),
        };
        let mut response = lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse {
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
            verification_nonce: bytes::Bytes::from_static(&[0x11u8; 32]),
            bound_fields_digest: bytes::Bytes::from_static(&[0x22u8; 32]),
            org_uuid: bytes::Bytes::new(),
            repository_id: request.repository_id.clone(),
        };
        response.bound_fields_digest = direct_authorization_bound_fields_digest(
            &key,
            &binding,
            &request.repository_id,
            &request.branch_id,
            &response,
        )?
        .into();
        match self.diverge {
            Some(EchoDivergence::RepositoryId) => {
                response.repository_id = bytes::Bytes::from_static(&[0xFE; 16]);
                // Even a coherent digest for another repository cannot authorize this target.
                response.bound_fields_digest = direct_authorization_bound_fields_digest(
                    &key,
                    &binding,
                    &response.repository_id,
                    &request.branch_id,
                    &response,
                )?
                .into();
            }
            Some(EchoDivergence::MissingRepositoryId) => response.repository_id.clear(),
            Some(EchoDivergence::AuthorizationId) => {
                response.authorization_id = bytes::Bytes::from_static(&[0xFE; 16]);
            }
            Some(EchoDivergence::AuthorizationRevision) => response.authorization_revision += 1,
            Some(EchoDivergence::VerificationNonce) => {
                response.verification_nonce = bytes::Bytes::from_static(&[0xFE; 32]);
            }
            Some(EchoDivergence::BoundFieldsDigest) => {
                response.bound_fields_digest = bytes::Bytes::from_static(&[0xFE; 32]);
            }
            Some(EchoDivergence::VerifiedIssuer) => {
                response.verified_issuer = "wrong-issuer".to_owned();
            }
            Some(EchoDivergence::AuthenticatedSubject) => {
                response.authenticated_subject = "wrong-subject".to_owned();
            }
            Some(EchoDivergence::OperationId) => {
                response.operation_id = bytes::Bytes::from_static(&[0xFFu8; 16]);
            }
            Some(EchoDivergence::Method) => {
                response.method = "wrong-method".to_owned();
            }
            Some(EchoDivergence::Scope) => {
                response.scope = bytes::Bytes::from_static(b"wrong-scope");
            }
            Some(EchoDivergence::FingerprintVersion) => {
                response.fingerprint_version = response.fingerprint_version.wrapping_add(1);
            }
            Some(EchoDivergence::Fingerprint) => {
                response.fingerprint = bytes::Bytes::from_static(&[0xEEu8; 32]);
            }
            Some(EchoDivergence::CanonicalIntentDigest) => {
                response.canonical_intent_digest = bytes::Bytes::from_static(&[0xDDu8; 32]);
            }
            None => {}
        }
        Ok(response)
    }
}

fn human_token() -> AuthorizationToken {
    test_token("https://issuer.example", "released-desktop-user")
}

fn direct_scope_ctx(repository_id: &[u8; 16]) -> GovernedScope<'_> {
    GovernedScope::TargetRepository { repository_id }
}

/// The bearer this cell's JWT interceptor would have verified, carried on
/// `authorization`.
pub(crate) const TEST_BEARER: &str = "Bearer released-desktop-jwt";

/// The human's own authentication bearer, carried on `lore-authn-bearer`.
///
/// PIN(WP-120, 2026-09-05): deliberately a DIFFERENT literal from
/// [`TEST_BEARER`]. Before this fix, `authorization` was the only credential
/// in play anywhere in these fixtures, so a test asserting "the verifier got
/// the right bearer" could not tell "it got `lore-authn-bearer`" apart from
/// "it got whatever `authorization` happened to hold" -- that
/// indistinguishability is exactly what let the underlying defect ship
/// undetected. Every fixture exercising internal admission or internal
/// prepare must keep the two values distinct so a wrong-header regression
/// actually fails a test.
pub(crate) const TEST_AUTHN_BEARER: &str = "Bearer released-desktop-authn-jwt";

/// Request metadata carrying the caller's own `authorization` header and a
/// DISTINCT `lore-authn-bearer` header, and nothing else.
///
/// An empty `MetadataMap` beside a verified `AuthorizationToken` is a shape
/// the real server never emits: the interceptor derives that token FROM the
/// `authorization` header, so one cannot exist without the other.
///
/// PIN(WP-120, 2026-09-05): the internal path forwards `lore-authn-bearer`
/// -- NOT `authorization` -- to auth-grpc as the human's bearer, and there is
/// deliberately no fallback between them (see `internal_admission_reason`).
/// A fixture missing `lore-authn-bearer` exercises the no-bearer refusal
/// rather than the gate-open case most callers here want; use
/// [`human_metadata_missing_authn_bearer`] when that refusal, or an
/// earlier-gate outcome unaffected by it, is the point of the test.
fn human_metadata() -> MetadataMap {
    let mut metadata = MetadataMap::new();
    metadata.insert(
        "authorization",
        TEST_BEARER.parse().expect("a static header value parses"),
    );
    metadata.insert(
        domain_operation_metadata::AUTHN_BEARER_KEY,
        TEST_AUTHN_BEARER
            .parse()
            .expect("a static header value parses"),
    );
    metadata
}

/// [`human_metadata`] with `lore-authn-bearer` withheld -- the shape a
/// pre-WP-120 client, or any caller an earlier gate already turns away,
/// presents. Used only where the point of the test is that outcome, not the
/// bearer forwarding this file otherwise pins.
fn human_metadata_missing_authn_bearer() -> MetadataMap {
    let mut metadata = MetadataMap::new();
    metadata.insert(
        "authorization",
        TEST_BEARER.parse().expect("a static header value parses"),
    );
    metadata
}

// Gate 1: enforcement off leaves the caller on the legacy path even with
// a verifier configured -- a verifier's presence is not itself a licence
// to admit a governed mutation on a cell that still writes the generic
// mutable path unfenced.
#[test]
fn internal_admission_is_unavailable_when_enforcement_is_off_even_with_a_verifier_configured() {
    let ctx = context(false)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let token = human_token();

    let result = ctx.admit_internal(
        &human_metadata(),
        Some(&token),
        &direct_scope_ctx(&repository_id),
    );

    assert!(matches!(result, Ok(None)));
}

// Gate 2: no verifier configured, enforcement on, no carriage -- falls
// through to the exact pre-WP-120 absent-carriage refusal. This is the
// same status `enforcement_on_with_no_carriage_is_refused_as_invalid_argument`
// already pins through the public `admit` entry point; this one exercises
// `admit_internal` directly so the gate itself, not just its caller, is
// proven byte-identical.
#[test]
fn internal_admission_is_unavailable_with_no_verifier_configured_and_falls_through_to_the_pre_wp120_refusal()
 {
    let ctx = context(true);
    let repository_id = test_repository_id();
    let token = human_token();

    let err = ctx
        .admit(
            &human_metadata(),
            Some(&token),
            direct_scope_ctx(&repository_id),
        )
        .expect_err("no verifier configured must fall through to the pre-WP-120 refusal");

    assert_eq!(err.code(), Code::InvalidArgument);
}

// Gate 3: no verified principal at all -- absent carriage still refuses
// through `require`, not through a WP-120-specific status, even with a
// verifier configured.
#[test]
fn internal_admission_is_unavailable_with_no_authorization_token() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();

    let err = ctx
        .admit(&human_metadata(), None, direct_scope_ctx(&repository_id))
        .expect_err("no authorization token must fall through to the pre-WP-120 refusal");

    assert_eq!(err.code(), Code::InvalidArgument);
}

// Gate 4 (security-critical): the control-plane service principal never
// takes the internal-admission path, even with a verifier configured and
// every other gate open. It always carries its own mediated carriage; a
// silent internal admission would drop a mediated operation into a
// direct human's receipt namespace.
#[test]
fn internal_admission_excludes_the_control_plane_service_principal() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let control_plane = AuthorizationToken {
        issuer: "https://issuer.example".to_owned(),
        user_id: CONTROL_PLANE_SERVICE_SUBJECT.to_owned(),
        is_service_account: Some(true),
        ..Default::default()
    };

    let err = ctx
        .admit(
            &human_metadata(),
            Some(&control_plane),
            direct_scope_ctx(&repository_id),
        )
        .expect_err("the control-plane principal must never take the internal path");

    assert_eq!(err.code(), Code::InvalidArgument);
}

// Gate 4 (security-critical), the other half: ANY service account is
// excluded, not only the named control-plane subject.
#[test]
fn internal_admission_excludes_every_service_account_not_only_the_control_plane_subject() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let service_account = AuthorizationToken {
        issuer: "https://issuer.example".to_owned(),
        user_id: "some-other-service-account".to_owned(),
        is_service_account: Some(true),
        ..Default::default()
    };

    let err = ctx
        .admit(
            &human_metadata(),
            Some(&service_account),
            direct_scope_ctx(&repository_id),
        )
        .expect_err("no service account, named or not, may take the internal path");

    assert_eq!(err.code(), Code::InvalidArgument);
}

// Gate 5: a mediated scope with no carriage is a contradiction -- refused
// directly, not silently downgraded to the legacy path or the generic
// absent-carriage refusal.
#[test]
fn internal_admission_refuses_a_mediated_scope_with_no_carriage() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let org_uuid = test_repository_id();
    let token = human_token();

    let err = ctx
        .admit(
            &human_metadata(),
            Some(&token),
            GovernedScope::Mediated {
                org_uuid: &org_uuid,
                principal_user_id: b"user-1",
            },
        )
        .expect_err("a mediated scope with no carriage must be refused, not downgraded");

    assert_eq!(err.code(), Code::InvalidArgument);
}

// The positive case: every gate open admits, keyed by the token and a
// freshly minted operation id, and is reported as internally prepared.
#[test]
fn internal_admission_admits_a_released_client_when_every_gate_is_open() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let token = human_token();

    let admitted = ctx
        .admit(
            &human_metadata(),
            Some(&token),
            direct_scope_ctx(&repository_id),
        )
        .expect("every gate open must admit")
        .expect("must be Some, not the legacy path");

    assert!(admitted.is_internally_prepared());
    assert!(admitted.carried().is_none());
    assert_eq!(admitted.key.verified_issuer, token.issuer);
    assert_eq!(admitted.key.authenticated_subject, token.user_id);
}

// Two internal admissions for the same repository mint two different
// operation ids: a released client carries no operation identity of its
// own, so there is no cross-attempt idempotency by construction.
#[test]
fn internal_admission_mints_a_fresh_operation_id_per_attempt() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let token = human_token();

    let first = ctx
        .admit(
            &human_metadata(),
            Some(&token),
            direct_scope_ctx(&repository_id),
        )
        .expect("admit")
        .expect("Some");
    let second = ctx
        .admit(
            &human_metadata(),
            Some(&token),
            direct_scope_ctx(&repository_id),
        )
        .expect("admit")
        .expect("Some");

    assert_ne!(first.key.operation_id, second.key.operation_id);
}

// --- 6a-bis. WP-120 `lore-authn-bearer` carriage at the entry gate -------

// The one refusal a released client sees on an armed cell that has no
// `lore-authn-bearer` at all: `FAILED_PRECONDITION` naming the header, not
// the pre-fix `UNAUTHENTICATED` and not the pre-WP-120 `INVALID_ARGUMENT`.
#[test]
fn internal_admission_refuses_a_governed_mutation_missing_the_authn_bearer_header() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let token = human_token();

    let err = ctx
        .admit(
            &human_metadata_missing_authn_bearer(),
            Some(&token),
            direct_scope_ctx(&repository_id),
        )
        .expect_err("a governed mutation with no lore-authn-bearer must be refused");

    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_ne!(
        err.code(),
        Code::Unauthenticated,
        "must not resurrect the pre-fix UNAUTHENTICATED failure this change replaces"
    );
    assert_ne!(
        err.code(),
        Code::InvalidArgument,
        "must not fall back to the pre-WP-120 absent-carriage code either"
    );
    assert_eq!(
        err.message(),
        domain_operation_metadata::MISSING_AUTHN_BEARER_MESSAGE
    );
}

// A whitespace-only value is not a credential -- `extract_authn_bearer`
// trims and empties it, and the gate must refuse it exactly like absence,
// never forward it to the verifier as an empty bearer.
#[test]
fn internal_admission_treats_a_blank_authn_bearer_as_absent() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let token = human_token();
    let mut metadata = human_metadata_missing_authn_bearer();
    metadata.insert(
        domain_operation_metadata::AUTHN_BEARER_KEY,
        "   ".parse().expect("ascii header"),
    );

    let err = ctx
        .admit(&metadata, Some(&token), direct_scope_ctx(&repository_id))
        .expect_err("a whitespace-only lore-authn-bearer must be treated as absent");

    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(
        err.message(),
        domain_operation_metadata::MISSING_AUTHN_BEARER_MESSAGE
    );
}

// Two divergent values for the same header are ambiguous, not a value to
// pick between -- refused as the pre-existing `extract_*` contract already
// refuses every other divergent-duplicate domain-operation header.
#[test]
fn internal_admission_refuses_a_divergent_duplicate_authn_bearer_header() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let token = human_token();
    let mut metadata = human_metadata_missing_authn_bearer();
    metadata.append(
        domain_operation_metadata::AUTHN_BEARER_KEY,
        "Bearer first-value".parse().expect("ascii header"),
    );
    metadata.append(
        domain_operation_metadata::AUTHN_BEARER_KEY,
        "Bearer second-value".parse().expect("ascii header"),
    );

    let err = ctx
        .admit(&metadata, Some(&token), direct_scope_ctx(&repository_id))
        .expect_err("divergent duplicate lore-authn-bearer values must be refused");

    assert_eq!(err.code(), Code::InvalidArgument);
}

// --- The ordering property: an earlier gate's outcome must survive the
// --- bearer lift unchanged, whether or not the header is present. Each
// --- case below uses `human_metadata_missing_authn_bearer` specifically
// --- so a regression that moved the bearer check earlier than these gates
// --- would flip its outcome to `FAILED_PRECONDITION` and fail here.

#[test]
fn internal_admission_with_enforcement_off_ignores_a_missing_authn_bearer() {
    let ctx = context(false)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let token = human_token();

    let result = ctx.admit(
        &human_metadata_missing_authn_bearer(),
        Some(&token),
        direct_scope_ctx(&repository_id),
    );

    assert!(matches!(result, Ok(None)));
}

#[test]
fn internal_admission_with_no_verifier_configured_falls_through_to_invalid_argument_even_without_an_authn_bearer()
 {
    let ctx = context(true);
    let repository_id = test_repository_id();
    let token = human_token();

    let err = ctx
        .admit(
            &human_metadata_missing_authn_bearer(),
            Some(&token),
            direct_scope_ctx(&repository_id),
        )
        .expect_err("no verifier configured must fall through to the pre-WP-120 refusal");

    assert_eq!(err.code(), Code::InvalidArgument);
}

#[test]
fn internal_admission_excludes_a_service_account_even_without_an_authn_bearer() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let service_account = AuthorizationToken {
        issuer: "https://issuer.example".to_owned(),
        user_id: "some-other-service-account".to_owned(),
        is_service_account: Some(true),
        ..Default::default()
    };

    let err = ctx
        .admit(
            &human_metadata_missing_authn_bearer(),
            Some(&service_account),
            direct_scope_ctx(&repository_id),
        )
        .expect_err(
            "a service account must keep its pre-WP-120 outcome regardless of the authn bearer",
        );

    assert_eq!(err.code(), Code::InvalidArgument);
}

#[test]
fn internal_admission_excludes_the_control_plane_subject_even_without_an_authn_bearer() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let control_plane = AuthorizationToken {
        issuer: "https://issuer.example".to_owned(),
        user_id: CONTROL_PLANE_SERVICE_SUBJECT.to_owned(),
        is_service_account: Some(true),
        ..Default::default()
    };

    let err = ctx
        .admit(
            &human_metadata_missing_authn_bearer(),
            Some(&control_plane),
            direct_scope_ctx(&repository_id),
        )
        .expect_err(
            "the control-plane principal must keep its pre-WP-120 outcome regardless of the \
             authn bearer",
        );

    assert_eq!(err.code(), Code::InvalidArgument);
}

// `internal_admission_reason`'s own gate 5 returns `Ok(None)` for
// `RepositoryCreate` -- but that is not what `admit()` reports, because
// reaching gate 5 at all means gate 1 (enforcement) already passed.
// `admit_internal`'s `None` handling then takes its `self.enforcement`
// branch, which re-derives the identical pre-WP-120 outcome through
// `require(metadata)` -- the same `INVALID_ARGUMENT` an absent-carriage
// caller with no verifier configured gets, not `Ok(None)`. The property
// under test is unchanged either way: whichever code this caller got
// before WP-120, it still gets, and specifically NOT the new
// `FAILED_PRECONDITION` refusal.
#[test]
fn internal_admission_falls_through_to_invalid_argument_for_repository_create_scope_even_without_an_authn_bearer()
 {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let token = human_token();

    let err = ctx
        .admit(
            &human_metadata_missing_authn_bearer(),
            Some(&token),
            GovernedScope::RepositoryCreate {
                repository_id: &repository_id,
            },
        )
        .expect_err(
            "repository.create must keep its pre-WP-120 outcome regardless of the authn \
             bearer",
        );

    assert_eq!(err.code(), Code::InvalidArgument);
    assert_ne!(
        err.code(),
        Code::FailedPrecondition,
        "the bearer lift must not have moved earlier than repository.create's own exclusion"
    );
}

// --- 6b. WP-120 complete_governed / internal_prepare --------------------

// Carriage still wins: `complete_governed` on a `Carried` admission never
// calls the verifier, even when one is configured, and produces the exact
// same `GovernedOperation` `into_governed` builds directly.
#[tokio::test]
async fn complete_governed_on_carried_admission_never_calls_the_verifier_and_matches_into_governed()
{
    let verifier = std::sync::Arc::new(DirectVerifierDouble::echo());
    let ctx = context(false).with_operation_verifier(Some(verifier.clone()));
    let operation_id = Uuid::now_v7();
    let metadata = valid_metadata(operation_id);
    let token = test_token("https://issuer.example", "subject-123");
    let repository_id = test_repository_id();

    let admitted = ctx
        .admit(
            &metadata,
            Some(&token),
            GovernedScope::TargetRepository {
                repository_id: &repository_id,
            },
        )
        .expect("valid carriage plus a verified principal must admit")
        .expect("must be Some");
    let digest = vec![0x99u8; 32];
    let expected = admitted
        .clone()
        .into_governed("lore.RepositoryService/RepositoryDelete", digest.clone());

    let governed = ctx
        .complete_governed(admitted, "lore.RepositoryService/RepositoryDelete", digest)
        .await
        .expect("carried admission must complete without touching the verifier");

    assert_eq!(governed.prepare_token, expected.prepare_token);
    assert_eq!(governed.binding.fingerprint, expected.binding.fingerprint);
    assert_eq!(governed.binding.scope, expected.binding.scope);
    assert_eq!(governed.key.operation_id, expected.key.operation_id);
    assert_eq!(verifier.call_count(), 0);
}

// Echo divergence: a verifier that flips any single field of its
// otherwise-exact echo must be refused `PERMISSION_DENIED`, and the
// refusal happens before `domain_operation_prepare` is ever called --
// `UnreachableDomainStore` backs this context, so a regression that
// reordered the echo check after the store call would panic this test
// instead of merely failing an assertion.
async fn assert_echo_divergence_is_refused(divergence: EchoDivergence) {
    let ctx = context(true).with_operation_verifier(Some(std::sync::Arc::new(
        DirectVerifierDouble::diverging(divergence),
    )));
    let repository_id = test_repository_id();
    let token = human_token();

    let admitted = ctx
        .admit(
            &human_metadata(),
            Some(&token),
            direct_scope_ctx(&repository_id),
        )
        .expect("every gate open must admit")
        .expect("must be Some");

    let error = ctx
        .complete_governed(
            admitted,
            PLATFORM_METHOD_REPOSITORY_METADATA_SET,
            vec![0x11u8; 32],
        )
        .await
        .expect_err("a divergent echo must be refused, not admitted");

    assert_eq!(error.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn internal_prepare_refuses_a_verified_issuer_echo_divergence() {
    assert_echo_divergence_is_refused(EchoDivergence::VerifiedIssuer).await;
}

#[tokio::test]
async fn internal_prepare_refuses_an_authenticated_subject_echo_divergence() {
    assert_echo_divergence_is_refused(EchoDivergence::AuthenticatedSubject).await;
}

#[tokio::test]
async fn internal_prepare_refuses_an_operation_id_echo_divergence() {
    assert_echo_divergence_is_refused(EchoDivergence::OperationId).await;
}

#[tokio::test]
async fn internal_prepare_refuses_a_method_echo_divergence() {
    assert_echo_divergence_is_refused(EchoDivergence::Method).await;
}

#[tokio::test]
async fn internal_prepare_refuses_a_scope_echo_divergence() {
    assert_echo_divergence_is_refused(EchoDivergence::Scope).await;
}

#[tokio::test]
async fn internal_prepare_refuses_a_fingerprint_version_echo_divergence() {
    assert_echo_divergence_is_refused(EchoDivergence::FingerprintVersion).await;
}

#[tokio::test]
async fn internal_prepare_refuses_a_fingerprint_echo_divergence() {
    assert_echo_divergence_is_refused(EchoDivergence::Fingerprint).await;
}

#[tokio::test]
async fn internal_prepare_refuses_a_canonical_intent_digest_echo_divergence() {
    assert_echo_divergence_is_refused(EchoDivergence::CanonicalIntentDigest).await;
}

#[tokio::test]
async fn internal_prepare_refuses_wrong_repository_even_with_a_coherent_digest() {
    assert_echo_divergence_is_refused(EchoDivergence::RepositoryId).await;
}

#[tokio::test]
async fn internal_prepare_refuses_an_old_response_without_repository_id() {
    assert_echo_divergence_is_refused(EchoDivergence::MissingRepositoryId).await;
}

#[tokio::test]
async fn internal_prepare_refuses_changed_authorization_evidence_before_any_receipt_access() {
    for divergence in [
        EchoDivergence::AuthorizationId,
        EchoDivergence::AuthorizationRevision,
        EchoDivergence::VerificationNonce,
        EchoDivergence::BoundFieldsDigest,
    ] {
        assert_echo_divergence_is_refused(divergence).await;
    }
}

#[tokio::test]
async fn internal_prepare_forwards_all_four_verified_evidence_fields_to_the_store() {
    let store = Arc::new(lore_server::domain::test_support::PreparingDomainStore::default());
    let ctx = DomainContext::new(store.clone(), true)
        .with_operation_verifier(Some(Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let admitted = ctx
        .admit(
            &human_metadata(),
            Some(&human_token()),
            direct_scope_ctx(&repository_id),
        )
        .unwrap()
        .unwrap();
    let governed = ctx
        .complete_governed(
            admitted,
            PLATFORM_METHOD_REPOSITORY_METADATA_SET,
            vec![0x11; 32],
        )
        .await
        .unwrap();
    let evidence = store
        .direct_evidence
        .lock()
        .unwrap()
        .clone()
        .expect("direct evidence captured");
    assert_eq!(
        evidence.authorization_id,
        governed.key.operation_id.as_bytes()
    );
    assert_eq!(evidence.authorization_revision, 1);
    assert_eq!(evidence.verification_nonce, vec![0x11; 32]);
    let response = lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse {
        authorization_id: evidence.authorization_id.clone().into(),
        authorization_revision: 1,
        verification_nonce: vec![0x11; 32].into(),
        ..Default::default()
    };
    assert_eq!(
        evidence.bound_fields_digest,
        direct_authorization_bound_fields_digest(
            &governed.key,
            &governed.binding,
            &repository_id,
            &[],
            &response,
        )
        .unwrap()
    );
}

// The internal prepare forwards the caller's own bearer token to the
// verifier, unaltered, so the verifier re-verifies the JWT itself rather
// than trusting this server's report of who is calling.
#[tokio::test]
async fn internal_prepare_forwards_the_callers_own_bearer_token_to_the_verifier() {
    let verifier = std::sync::Arc::new(DirectVerifierDouble::echo());
    // `preparing_context` rather than `context(true)`: an ACCEPTING verifier
    // means execution continues past the echo check into the coordinator's
    // prepare, which `UnreachableDomainStore` panics on by design. Every
    // refusal case still uses that store, and its panic is what proves those
    // paths write no receipt row.
    let ctx = preparing_context().with_operation_verifier(Some(verifier.clone()));
    let repository_id = test_repository_id();
    let token = human_token();
    // Deliberately two DIFFERENT values on `authorization` and
    // `lore-authn-bearer`: with only one value in play this test cannot
    // discriminate which header the verifier actually received, which is
    // exactly the gap that let the pre-fix code forward `authorization`
    // undetected (see `human_metadata`'s doc comment).
    let mut metadata = MetadataMap::new();
    metadata.insert(
        "authorization",
        "Bearer released-client-authz-jwt"
            .parse()
            .expect("ascii header"),
    );
    metadata.insert(
        domain_operation_metadata::AUTHN_BEARER_KEY,
        "Bearer released-client-authn-jwt"
            .parse()
            .expect("ascii header"),
    );

    let admitted = ctx
        .admit_internal(&metadata, Some(&token), &direct_scope_ctx(&repository_id))
        .expect("every gate open must admit")
        .expect("must be Some");

    let governed = ctx
        .complete_governed(
            admitted,
            PLATFORM_METHOD_REPOSITORY_METADATA_SET,
            vec![0x22u8; 32],
        )
        .await
        .expect("echoing verifier must admit");

    assert_eq!(
        verifier.forwarded_bearer(),
        Some("Bearer released-client-authn-jwt".to_owned()),
        "the verifier must receive the lore-authn-bearer value, unaltered"
    );
    assert_ne!(
        verifier.forwarded_bearer(),
        Some("Bearer released-client-authz-jwt".to_owned()),
        "the verifier must never receive the authorization header's value -- that is the \
         WP-120 defect this test exists to catch"
    );
    assert_eq!(
        governed.prepare_token, PREPARED_TEST_TOKEN,
        "the governed operation must carry the token the coordinator minted"
    );
    assert_eq!(
        governed.binding.method,
        PLATFORM_METHOD_REPOSITORY_METADATA_SET
    );
}

// A verifier that errors is a refusal, never a silent downgrade to the
// legacy path -- the caller already committed to the internal path by
// reaching `complete_governed`'s `Internal` arm.
#[tokio::test]
async fn internal_prepare_refuses_when_the_configured_verifier_errors() {
    let ctx = context(true).with_operation_verifier(Some(std::sync::Arc::new(
        DirectVerifierDouble::erroring(Status::unavailable("verifier unreachable")),
    )));
    let repository_id = test_repository_id();
    let token = human_token();

    let admitted = ctx
        .admit(
            &human_metadata(),
            Some(&token),
            direct_scope_ctx(&repository_id),
        )
        .expect("every gate open must admit")
        .expect("must be Some");

    let error = ctx
        .complete_governed(
            admitted,
            PLATFORM_METHOD_REPOSITORY_METADATA_SET,
            vec![0x33u8; 32],
        )
        .await
        .expect_err("a verifier error must be refused, not downgraded");

    assert_eq!(error.code(), Code::Unavailable);
}

// A fenced-lock direct prepare against a cell with no verifier configured
// is refused the same way -- `prepare_direct_lock_operation` does not
// gate on verifier presence itself the way `admit_internal` does, so this
// is its own independent proof rather than a restatement of the
// repository-mutation gate table above.
#[tokio::test]
async fn prepare_direct_lock_operation_refuses_with_no_verifier_configured() {
    let ctx = context(true);
    let token = human_token();
    let repository_id = test_repository_id();
    let branch_id = test_repository_id();
    let binding = OperationBinding {
        method: "lock.acquire".to_owned(),
        scope: vec![0x44u8; 16],
        fingerprint_version: 1,
        fingerprint: vec![0x55u8; 32],
        canonical_intent_digest: vec![0x66u8; 32],
    };

    let error = ctx
        .prepare_direct_lock_operation(
            &token,
            Some("Bearer x"),
            &repository_id,
            &branch_id,
            binding,
            None,
        )
        .await
        .expect_err("no verifier configured must refuse, not panic or silently admit");
    let error = before_prepare(error);

    assert_eq!(error.code(), Code::FailedPrecondition);
}

// A fenced-lock direct prepare excludes the control-plane and service
// accounts the same way the repository-mutation gate does -- a direct
// fenced lock is for human principals.
#[tokio::test]
async fn prepare_direct_lock_operation_excludes_service_accounts() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let branch_id = test_repository_id();
    let service_account = AuthorizationToken {
        issuer: "https://issuer.example".to_owned(),
        user_id: "some-service-account".to_owned(),
        is_service_account: Some(true),
        ..Default::default()
    };
    let binding = OperationBinding {
        method: "lock.acquire".to_owned(),
        scope: vec![0x44u8; 16],
        fingerprint_version: 1,
        fingerprint: vec![0x55u8; 32],
        canonical_intent_digest: vec![0x66u8; 32],
    };

    let error = ctx
        .prepare_direct_lock_operation(
            &service_account,
            Some("Bearer x"),
            &repository_id,
            &branch_id,
            binding,
            None,
        )
        .await
        .expect_err("a service account must be refused a direct fenced lock");
    let error = before_prepare(error);

    assert_eq!(error.code(), Code::PermissionDenied);
}

// --- 6b-bis. WP-120 `prepare_direct`'s bearer check on the lock rail,
// --- and the ordering property the reviewer's finding is about: the
// --- bearer check runs LAST, after the verifier-presence check and after
// --- `prepare_direct_lock_operation`'s own service-account exclusion, so
// --- neither an unconfigured cell nor a service account is told to
// --- upgrade a client that is already current.

/// The status of a refusal that must have been raised before the receipt store was reached.
/// Anything else is a failure: the fenced lock rail marks only these refusals as not prepared.
fn before_prepare(refusal: DirectPrepareRefusal) -> Status {
    match refusal {
        DirectPrepareRefusal::BeforePrepare(status) => status,
        DirectPrepareRefusal::AtPrepare(status) => {
            panic!("expected a refusal before the prepare, got one at it: {status:?}")
        }
    }
}

fn lock_binding() -> OperationBinding {
    OperationBinding {
        method: "lock.acquire".to_owned(),
        scope: vec![0x44u8; 16],
        fingerprint_version: 1,
        fingerprint: vec![0x55u8; 32],
        canonical_intent_digest: vec![0x66u8; 32],
    }
}

// The bearer check itself: a human principal with a configured verifier
// but no bearer is refused exactly like the branch/repository rail is.
#[tokio::test]
async fn prepare_direct_lock_operation_refuses_an_absent_bearer_for_a_human_principal() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let token = human_token();
    let repository_id = test_repository_id();
    let branch_id = test_repository_id();

    let error = ctx
        .prepare_direct_lock_operation(
            &token,
            None,
            &repository_id,
            &branch_id,
            lock_binding(),
            None,
        )
        .await
        .expect_err("an absent bearer must be refused for a human principal");
    let error = before_prepare(error);

    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_eq!(
        error.message(),
        domain_operation_metadata::MISSING_AUTHN_BEARER_MESSAGE
    );
}

// Ordering, half 1: a service account with NO bearer at all must still see
// the service-account exclusion, not the carriage refusal -- proving the
// exclusion (which runs before `prepare_direct` is ever called) wins.
#[tokio::test]
async fn prepare_direct_lock_operation_excludes_a_service_account_even_with_no_bearer() {
    let ctx = context(true)
        .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
    let repository_id = test_repository_id();
    let branch_id = test_repository_id();
    let service_account = AuthorizationToken {
        issuer: "https://issuer.example".to_owned(),
        user_id: "some-service-account".to_owned(),
        is_service_account: Some(true),
        ..Default::default()
    };

    let error = ctx
        .prepare_direct_lock_operation(
            &service_account,
            None,
            &repository_id,
            &branch_id,
            lock_binding(),
            None,
        )
        .await
        .expect_err("a service account must be refused regardless of the bearer");
    let error = before_prepare(error);

    assert_eq!(error.code(), Code::PermissionDenied);
    assert_ne!(
        error.message(),
        domain_operation_metadata::MISSING_AUTHN_BEARER_MESSAGE,
        "a service account must be told it may not take this rail at all, not to upgrade a \
         client that is already current"
    );
}

// Ordering, half 2: a cell with no verifier configured refuses on THAT
// ground, not the carriage ground, even for a human principal with no
// bearer -- proving the verifier-presence check (at the top of
// `prepare_direct`) wins over the bearer check (at the bottom of it).
#[tokio::test]
async fn prepare_direct_lock_operation_with_no_verifier_configured_refuses_before_the_bearer_check()
{
    let ctx = context(true); // no verifier attached
    let token = human_token();
    let repository_id = test_repository_id();
    let branch_id = test_repository_id();

    let error = ctx
        .prepare_direct_lock_operation(
            &token,
            None,
            &repository_id,
            &branch_id,
            lock_binding(),
            None,
        )
        .await
        .expect_err("no verifier configured must refuse before ever inspecting the bearer");
    let error = before_prepare(error);

    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_ne!(
        error.message(),
        domain_operation_metadata::MISSING_AUTHN_BEARER_MESSAGE,
        "the verifier-missing refusal must win over the carriage refusal when both \
         conditions hold"
    );
}

// --- 6b-ter. The `BeforePrepare` / `AtPrepare` split (Gate 0 campaign c13) ---
//
// The fenced lock rail stamps `lore-not-prepared-attempt-v1` on exactly the refusals that arrive
// before the receipt store is asked to prepare. `UnreachableDomainStore` panics on any store call,
// so each `BeforePrepare` case below also proves no receipt row could have been written.

// A verifier outage is the c13 trigger itself: it must be BeforePrepare and keep its own status.
#[tokio::test]
async fn prepare_direct_lock_operation_marks_a_verifier_outage_before_prepare() {
    let ctx = context(true).with_operation_verifier(Some(std::sync::Arc::new(
        DirectVerifierDouble::erroring(Status::unavailable("verifier unreachable")),
    )));

    let error = ctx
        .prepare_direct_lock_operation(
            &human_token(),
            Some("Bearer x"),
            &test_repository_id(),
            &test_repository_id(),
            lock_binding(),
            None,
        )
        .await
        .expect_err("a verifier outage must refuse");
    let status = before_prepare(error);

    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(status.message(), "verifier unreachable");
}

// A verifier answer that fails the echo check is also refused before any write.
#[tokio::test]
async fn prepare_direct_lock_operation_marks_an_echo_mismatch_before_prepare() {
    let ctx = context(true).with_operation_verifier(Some(std::sync::Arc::new(
        DirectVerifierDouble::diverging(EchoDivergence::Fingerprint),
    )));

    let error = ctx
        .prepare_direct_lock_operation(
            &human_token(),
            Some("Bearer x"),
            &test_repository_id(),
            &test_repository_id(),
            lock_binding(),
            None,
        )
        .await
        .expect_err("a diverging echo must refuse");

    before_prepare(error);
}

// Negative control: a refusal FROM the store prepare is AtPrepare, never BeforePrepare. A failed
// commit there can leave a row the caller never learned about.
#[tokio::test]
async fn prepare_direct_lock_operation_marks_a_store_prepare_refusal_at_prepare() {
    let store = lore_server::domain::test_support::PreparingDomainStore::default();
    *store.direct_result.lock().unwrap() = Some(PrepareResult::Mismatch);
    let ctx = DomainContext::new(Arc::new(store), true)
        .with_operation_verifier(Some(Arc::new(DirectVerifierDouble::echo())));

    let error = ctx
        .prepare_direct_lock_operation(
            &human_token(),
            Some("Bearer x"),
            &test_repository_id(),
            &test_repository_id(),
            lock_binding(),
            None,
        )
        .await
        .expect_err("a store Mismatch must refuse");

    match error {
        DirectPrepareRefusal::AtPrepare(status) => {
            assert_eq!(status.code(), Code::Aborted, "got {status:?}");
        }
        DirectPrepareRefusal::BeforePrepare(status) => {
            panic!("a refusal from the store prepare must be AtPrepare, got {status:?}")
        }
    }
}

// `into_status` collapses either side to the status it carries, unchanged.
#[test]
fn direct_prepare_refusal_into_status_returns_the_carried_status() {
    for refusal in [
        DirectPrepareRefusal::BeforePrepare(Status::unavailable("a")),
        DirectPrepareRefusal::AtPrepare(Status::unavailable("a")),
    ] {
        let status = refusal.into_status();
        assert_eq!(status.code(), Code::Unavailable);
        assert_eq!(status.message(), "a");
    }
}
// --- 6c. internal_prepare_fingerprint determinism -----------------------
//
// Every vector below is computed independently (Python's `blake3`
// package, not this function's own output) over
// `b"lore-internal-prepare-fingerprint-v1\0"` followed by each of
// method/scope/canonical_intent_digest, u32-big-endian length-prefixed.
// Per the testing guide's "never hash two blocks of output to rule out a
// difference" rule, these are golden values, not a change detector.

fn fingerprint_digest_fixture() -> [u8; 32] {
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = index as u8;
    }
    digest
}

#[test]
fn internal_prepare_fingerprint_matches_an_independently_computed_golden_vector() {
    let fingerprint = internal_prepare_fingerprint(
        "branch.push",
        b"test-scope-bytes",
        &fingerprint_digest_fixture(),
    )
    .expect("bounded inputs must not overflow the frame width");

    assert_eq!(
        hex::encode(&fingerprint),
        "8b51c6c83b92f3c6f2f40e85d611ead84ff1bde91c64b82babe004a7baef90d8"
    );
}

#[test]
fn internal_prepare_fingerprint_changes_when_the_method_changes() {
    let fingerprint = internal_prepare_fingerprint(
        "repository.metadata-set",
        b"test-scope-bytes",
        &fingerprint_digest_fixture(),
    )
    .expect("bounded inputs must not overflow the frame width");

    assert_eq!(
        hex::encode(&fingerprint),
        "220c20b16ec8c3bd3a0a61400255fb492a1d598832abd66b3a70978cbb5c6616"
    );
}

#[test]
fn internal_prepare_fingerprint_changes_when_the_scope_changes() {
    let fingerprint = internal_prepare_fingerprint(
        "branch.push",
        b"different-scope",
        &fingerprint_digest_fixture(),
    )
    .expect("bounded inputs must not overflow the frame width");

    assert_eq!(
        hex::encode(&fingerprint),
        "8e356e78514930907e37109a15e141a2d15983f1ed752829589be3cdfe7c8b48"
    );
}

#[test]
fn internal_prepare_fingerprint_changes_when_the_digest_changes() {
    let mut digest = fingerprint_digest_fixture();
    digest[0] = 0xff;

    let fingerprint = internal_prepare_fingerprint("branch.push", b"test-scope-bytes", &digest)
        .expect("bounded inputs must not overflow the frame width");

    assert_eq!(
        hex::encode(&fingerprint),
        "89d96fa375318e4a0e156584292745ba017b99d40c6c2dc5de0dd866fdc8fe35"
    );
}

#[test]
fn internal_prepare_fingerprint_changes_with_an_empty_scope() {
    let fingerprint =
        internal_prepare_fingerprint("branch.push", b"", &fingerprint_digest_fixture())
            .expect("bounded inputs must not overflow the frame width");

    assert_eq!(
        hex::encode(&fingerprint),
        "94bfef7a8a2c81b22e1d5217d45bffd6dfa5e00ff0eba7e91e2b3c04afe729fc"
    );
}

// --- 7. resolve_enforcement ---------------------------------------------

fn schema_state(
    enforcement_enabled: bool,
    backfill_state: i16,
    residue_classified: bool,
    cutover_at: Option<SystemTime>,
) -> DomainSchemaState {
    DomainSchemaState {
        schema_version: 1,
        backfill_version: 1,
        backfill_state,
        backfill_cursor: None,
        residue_classified,
        cutover_at,
        enforcement_enabled,
        database_identity: "test-database".to_string(),
    }
}

#[test]
fn resolve_enforcement_off_is_ok_false_regardless_of_backfill_state() {
    let state = schema_state(false, BACKFILL_NOT_STARTED, false, None);

    let enforcement = resolve_enforcement(&state).expect("enforcement off never fails");

    assert!(!enforcement);
}

// The readiness rule: an incomplete backfill must refuse the cell's
// readiness, never silently downgrade to the unsynchronised path.
#[test]
fn resolve_enforcement_on_but_not_ready_refuses_readiness_rather_than_downgrading() {
    let state = schema_state(true, BACKFILL_NOT_STARTED, false, None);

    let err = resolve_enforcement(&state)
        .expect_err("an unready cell with enforcement requested must refuse readiness");

    // Case-insensitive: the message now leads with "Refusing readiness"
    // as a new sentence following the cutover hint, not lowercase mid-
    // sentence as before -- the substantive claim under test is the
    // phrase itself, not its capitalization.
    assert!(
        err.to_string()
            .to_lowercase()
            .contains("refusing readiness")
    );
}

#[test]
fn resolve_enforcement_on_and_ready_is_ok_true() {
    let state = schema_state(true, BACKFILL_CUTOVER, true, Some(SystemTime::now()));

    let enforcement = resolve_enforcement(&state).expect("a ready cell must enforce");

    assert!(enforcement);
}

/// Each `ready_for_enforcement` term, failing alone, names only itself and
/// still names the fix. A transposed check (naming the wrong gap for the
/// wrong condition) must not pass review.
///
/// Tuple-array shape (case label, mutator, its own expected fragment) in
/// one literal per case, matching `lock_fencing_each_evidence_gap_names_itself_and_not_the_others`
/// below -- a case added here without its fragment fails to compile
/// instead of silently dropping out of a separately `zip`'d fragments
/// list.
#[test]
fn domain_enforcement_each_gap_names_itself_and_the_fix() {
    type GapCase = (&'static str, fn(&mut DomainSchemaState), &'static str);
    let cases: [GapCase; 3] = [
        (
            "backfill_state",
            |s| s.backfill_state = BACKFILL_NOT_STARTED,
            "domain backfill state is",
        ),
        (
            "residue_classified",
            |s| s.residue_classified = false,
            "the backfill's residue has not been classified",
        ),
        (
            "cutover_at",
            |s| s.cutover_at = None,
            "no cutover marker is recorded",
        ),
    ];
    let every_fragment = [
        "domain backfill state is",
        "the backfill's residue has not been classified",
        "no cutover marker is recorded",
    ];

    for (label, mutate, own_fragment) in cases {
        let mut state = schema_state(true, BACKFILL_CUTOVER, true, Some(SystemTime::now()));
        mutate(&mut state);

        let Err(err) = resolve_enforcement(&state) else {
            panic!("{label} alone must refuse readiness");
        };
        let message = err.to_string();

        assert!(
            message.contains(own_fragment),
            "{label}: message did not name its own gap ({own_fragment}): {message}"
        );
        for other in every_fragment.iter().filter(|f| **f != own_fragment) {
            assert!(
                !message.contains(other),
                "{label}: message wrongly named an unrelated gap ({other}): {message}"
            );
        }
        assert!(
            message.contains("domain cutover"),
            "{label}: message did not name the fix: {message}"
        );
    }
}

/// The drift guard itself (see [`domain_enforcement_gaps`]'s doc comment):
/// whatever combination of the three `ready_for_enforcement` terms is
/// short, `resolve_enforcement` must refuse with a non-empty, named
/// clause -- never the blank-looking fallback text substituting for real
/// silence. Exhaustive over all three terms (skipping the one
/// fully-ready combination) so a future term added to
/// `ready_for_enforcement` without a matching branch here would leave
/// that new combination refusing with an empty gap list -- caught here
/// as a non-empty-but-generic clause, not this test alone, but this is
/// the assertion that pins the fallback substitution never degrades to
/// the blank clause it replaced.
#[test]
fn domain_enforcement_never_prints_a_blank_clause_across_every_unready_combination() {
    for &backfill_state in &[BACKFILL_NOT_STARTED, BACKFILL_CUTOVER] {
        for residue_classified in [false, true] {
            for cutover_at in [None, Some(SystemTime::now())] {
                let ready = backfill_state == BACKFILL_CUTOVER
                    && residue_classified
                    && cutover_at.is_some();
                if ready {
                    continue;
                }

                let state = schema_state(true, backfill_state, residue_classified, cutover_at);
                let err = resolve_enforcement(&state)
                    .expect_err("an unready combination must refuse readiness");
                let message = err.to_string();

                assert!(
                    !message.contains("not ready for it: ."),
                    "blank clause for backfill_state={backfill_state}, \
                     residue_classified={residue_classified}, \
                     cutover_at={cutover_at:?}: {message}"
                );
                assert!(
                    !message.contains("not ready for it: To fix"),
                    "blank clause for backfill_state={backfill_state}, \
                     residue_classified={residue_classified}, \
                     cutover_at={cutover_at:?}: {message}"
                );
            }
        }
    }
}

// Two terms missing at once must both be named, joined the same way as
// the lock-side refusal, and the full-state dump must still survive at
// the end of the message -- no diagnostic detail was traded away when
// the message gained named gaps.
#[test]
fn domain_enforcement_two_gaps_at_once_names_both_and_keeps_the_full_state_dump() {
    let state = schema_state(true, BACKFILL_NOT_STARTED, false, Some(SystemTime::now()));

    let err =
        resolve_enforcement(&state).expect_err("two missing terms must still refuse readiness");
    let message = err.to_string();

    assert!(message.contains("domain backfill state is"));
    assert!(message.contains("the backfill's residue has not been classified"));
    assert!(
        message.contains(&format!(
            "domain backfill state is {BACKFILL_NOT_STARTED}, cutover is {}; the backfill's \
             residue has not been classified",
            lore_postgres::domain::schema::BACKFILL_CUTOVER
        )),
        "message did not join the two gaps with \"; \" in order: {message}"
    );
    assert!(
        message.contains("Full state: (backfill_state="),
        "message dropped the full state dump: {message}"
    );
    assert!(
        message.trim_end().ends_with(')'),
        "message did not end with the full-state parenthetical: {message}"
    );
}

/// Enforcement-off is `Ok(false)` with no error, whatever the backfill
/// state, residue-classified flag, or cutover marker say.
#[test]
fn domain_enforcement_off_is_ok_false_for_every_backfill_state_and_residue_combination() {
    let backfill_states = [
        BACKFILL_NOT_STARTED,
        lore_postgres::domain::schema::BACKFILL_RUNNING,
        lore_postgres::domain::schema::BACKFILL_VERIFIED,
        BACKFILL_CUTOVER,
    ];
    for &backfill_state in &backfill_states {
        for residue_classified in [false, true] {
            for cutover_at in [None, Some(SystemTime::now())] {
                let state = schema_state(false, backfill_state, residue_classified, cutover_at);
                let enforcement = resolve_enforcement(&state)
                    .expect("enforcement off must never fail regardless of backfill state");
                assert!(!enforcement);
            }
        }
    }
}

fn lock_ready() -> LockFencingReadiness {
    LockFencingReadiness {
        provisioned: true,
        schema_version: lore_postgres::domain::locks::schema::LOCK_SCHEMA_VERSION,
        backfill_state: lore_postgres::domain::locks::schema::BACKFILL_COMPLETE,
        fencing_enabled: true,
        lease_enabled: false,
        same_database: true,
        sequence_headroom: true,
        quarantined_rows: 0,
        unfenced_rows: 0,
        never_issued_token_rows: 0,
    }
}

fn fenced_settings() -> Settings {
    let mut settings: Settings = toml::from_str(include_str!("../../config/default.toml"))
        .expect("built-in settings fixture must deserialize");
    settings
        .lock_store
        .as_mut()
        .expect("default lock store")
        .mode = POSTGRES_MODE.to_owned();
    // Built from TOML rather than a struct literal: upstream v0.10.0 grew
    // `AuthSettings` (mandatory audience, list issuer, authorizer keys).
    let auth: AuthSettings = toml::from_str(
        r#"
        jwt_issuer = "https://issuer.example"
        jwt_audience = ["lore"]
        enforce_write_permission = true

        [jwk]
        endpoint = "https://issuer.example/.well-known/jwks.json"
        "#,
    )
    .expect("fenced [server.auth] fixture must deserialize");
    settings.server.auth = Some(auth);
    settings
}

#[test]
fn lock_fencing_off_keeps_the_legacy_route_without_auth_requirements() {
    let mut readiness = lock_ready();
    readiness.fencing_enabled = false;
    let settings: Settings = toml::from_str(include_str!("../../config/default.toml"))
        .expect("built-in settings fixture must deserialize");
    assert!(!resolve_lock_fencing(&readiness, &settings).expect("disabled route"));
}

#[test]
fn lock_fencing_requires_auth_issuer_write_permission_and_postgres_routing() {
    let readiness = lock_ready();

    let mut no_auth = fenced_settings();
    no_auth.server.auth = None;
    assert!(resolve_lock_fencing(&readiness, &no_auth).is_err());

    let mut no_jwk = fenced_settings();
    no_jwk.server.auth.as_mut().expect("auth").jwk = None;
    assert!(resolve_lock_fencing(&readiness, &no_jwk).is_err());

    let mut no_issuer = fenced_settings();
    no_issuer.server.auth.as_mut().expect("auth").jwt_issuer = Vec::new();
    assert!(resolve_lock_fencing(&readiness, &no_issuer).is_err());

    // D3: an issuer cutover list cannot pin a fenced owner pair.
    let mut two_issuers = fenced_settings();
    two_issuers.server.auth.as_mut().expect("auth").jwt_issuer = vec![
        "https://issuer.example".to_owned(),
        "https://issuer-next.example".to_owned(),
    ];
    assert!(resolve_lock_fencing(&readiness, &two_issuers).is_err());

    let mut no_write_enforcement = fenced_settings();
    no_write_enforcement
        .server
        .auth
        .as_mut()
        .expect("auth")
        .enforce_write_permission = false;
    assert!(resolve_lock_fencing(&readiness, &no_write_enforcement).is_err());

    let mut wrong_store = fenced_settings();
    wrong_store.lock_store.as_mut().expect("lock store").mode = "local".to_owned();
    assert!(resolve_lock_fencing(&readiness, &wrong_store).is_err());
}

#[test]
fn lock_fencing_requires_every_database_backfill_and_cutover_witness() {
    let settings = fenced_settings();
    assert!(resolve_lock_fencing(&lock_ready(), &settings).expect("complete evidence"));

    let mut cases = Vec::new();
    let mut schema = lock_ready();
    schema.schema_version += 1;
    cases.push(schema);
    let mut backfill = lock_ready();
    backfill.backfill_state = lore_postgres::domain::locks::schema::BACKFILL_RUNNING;
    cases.push(backfill);
    let mut database = lock_ready();
    database.same_database = false;
    cases.push(database);
    let mut sequence = lock_ready();
    sequence.sequence_headroom = false;
    cases.push(sequence);
    let mut quarantine = lock_ready();
    quarantine.quarantined_rows = 1;
    cases.push(quarantine);
    let mut lease = lock_ready();
    lease.lease_enabled = true;
    cases.push(lease);

    for readiness in cases {
        assert!(resolve_lock_fencing(&readiness, &settings).is_err());
    }
}

// The exact incident this change exists for: a fork merge bumps
// `LOCK_SCHEMA_VERSION` and the next binary boots against a cell one
// revision behind. The refusal must name both revisions, not just report
// a mismatch, and must name the fix.
#[test]
fn lock_fencing_one_schema_revision_behind_names_both_revisions_and_the_fix() {
    let mut readiness = lock_ready();
    readiness.schema_version -= 1;
    let settings = fenced_settings();

    let err = resolve_lock_fencing(&readiness, &settings)
        .expect_err("a stale lock schema revision must refuse readiness");
    let message = err.to_string();

    assert!(
        message.contains(&format!(
            "lock schema revision {} on disk",
            readiness.schema_version
        )),
        "message did not name the on-disk revision: {message}"
    );
    assert!(
        message.contains(&format!(
            "this binary compiles revision {}",
            lore_postgres::domain::locks::schema::LOCK_SCHEMA_VERSION
        )),
        "message did not name the compiled revision: {message}"
    );
    assert!(
        message.contains("domain cutover"),
        "message did not name the fix: {message}"
    );
}

/// Each remaining SCHEMA-117 term, failing alone, names only itself. A
/// transposed check (naming the wrong gap for the wrong condition) must
/// not pass review.
#[test]
fn lock_fencing_each_evidence_gap_names_itself_and_not_the_others() {
    type GapCase = (&'static str, fn(&mut LockFencingReadiness), &'static str);
    let cases: [GapCase; 5] = [
        (
            "backfill_state",
            |r| r.backfill_state = lore_postgres::domain::locks::schema::BACKFILL_RUNNING,
            "lock backfill state is",
        ),
        (
            "same_database",
            |r| r.same_database = false,
            "not in the database this cell recorded at bootstrap",
        ),
        (
            "sequence_headroom",
            |r| r.sequence_headroom = false,
            "not reserved above every persisted fence",
        ),
        (
            "quarantined_rows",
            |r| r.quarantined_rows = 1,
            "lock row(s) are quarantined",
        ),
        (
            "unfenced_rows",
            |r| r.unfenced_rows = 1,
            "legacy lock row(s) are still unfenced",
        ),
    ];
    let every_fragment = [
        "lock schema revision",
        "lock backfill state is",
        "not in the database this cell recorded at bootstrap",
        "not reserved above every persisted fence",
        "lock row(s) are quarantined",
        "legacy lock row(s) are still unfenced",
    ];

    let settings = fenced_settings();
    for (label, mutate, own_fragment) in cases {
        let mut readiness = lock_ready();
        mutate(&mut readiness);

        let Err(err) = resolve_lock_fencing(&readiness, &settings) else {
            panic!("{label} alone must refuse readiness");
        };
        let message = err.to_string();

        assert!(
            message.contains(own_fragment),
            "{label}: message did not name its own gap: {message}"
        );
        for other in every_fragment.iter().filter(|f| **f != own_fragment) {
            assert!(
                !message.contains(other),
                "{label}: message wrongly named an unrelated gap ({other}): {message}"
            );
        }
    }
}

// Two terms missing at once must both be named, not just the first --
// otherwise an operator clears one gap, reboots, and discovers the second
// only on the next failed boot.
#[test]
fn lock_fencing_two_gaps_at_once_names_both() {
    let mut readiness = lock_ready();
    readiness.same_database = false;
    readiness.quarantined_rows = 3;
    let settings = fenced_settings();

    let err = resolve_lock_fencing(&readiness, &settings)
        .expect_err("two missing terms must still refuse readiness");
    let message = err.to_string();

    assert!(message.contains("not in the database this cell recorded at bootstrap"));
    assert!(message.contains("3 lock row(s) are quarantined"));
    // The join separator itself: two gaps must read as one sentence
    // joined by "; ", not merely both be present somewhere in the
    // message (which would also pass if they were concatenated with no
    // separator, or in the wrong order).
    assert!(
        message.contains(
            "the fenced lock tables are not in the database this cell recorded at \
             bootstrap; 3 lock row(s) are quarantined"
        ),
        "message did not join the two gaps with \"; \" in order: {message}"
    );
    // The full readiness dump was deliberately kept alongside the named
    // gaps -- no diagnostic detail was traded for readability. Prove it
    // still survives to the end of the message.
    assert!(
        message.contains("Full readiness: (schema_version="),
        "message dropped the full readiness dump: {message}"
    );
    assert!(
        message.trim_end().ends_with(')'),
        "message did not end with the full-readiness parenthetical: {message}"
    );
}

// The settings preconditions are configuration problems, not migration
// problems -- pointing an operator at `domain cutover` for a missing JWK
// or a non-Postgres lock store would send them chasing the wrong fix.
#[test]
fn lock_fencing_settings_precondition_refusals_do_not_carry_the_cutover_hint() {
    let readiness = lock_ready();

    let mut no_auth = fenced_settings();
    no_auth.server.auth = None;
    let err = resolve_lock_fencing(&readiness, &no_auth).expect_err("missing auth must refuse");
    assert!(!err.to_string().contains("domain cutover"), "{err}");

    let mut no_jwk = fenced_settings();
    no_jwk.server.auth.as_mut().expect("auth").jwk = None;
    let err = resolve_lock_fencing(&readiness, &no_jwk).expect_err("missing jwk must refuse");
    assert!(!err.to_string().contains("domain cutover"), "{err}");

    let mut no_issuer = fenced_settings();
    no_issuer.server.auth.as_mut().expect("auth").jwt_issuer = Vec::new();
    let err = resolve_lock_fencing(&readiness, &no_issuer).expect_err("missing issuer must refuse");
    assert!(!err.to_string().contains("domain cutover"), "{err}");

    let mut no_write_enforcement = fenced_settings();
    no_write_enforcement
        .server
        .auth
        .as_mut()
        .expect("auth")
        .enforce_write_permission = false;
    let err = resolve_lock_fencing(&readiness, &no_write_enforcement)
        .expect_err("enforce_write_permission=false must refuse");
    assert!(!err.to_string().contains("domain cutover"), "{err}");

    let mut wrong_store = fenced_settings();
    wrong_store.lock_store.as_mut().expect("lock store").mode = "local".to_owned();
    let err = resolve_lock_fencing(&readiness, &wrong_store)
        .expect_err("a non-Postgres lock store must refuse");
    assert!(!err.to_string().contains("domain cutover"), "{err}");
}

// The lease refusal is also a configuration/rollout problem (no client
// renews a lease yet), not a migration gap -- it must not carry the
// cutover hint either.
#[test]
fn lock_fencing_lease_enabled_refusal_does_not_carry_the_cutover_hint() {
    let mut readiness = lock_ready();
    readiness.lease_enabled = true;
    let settings = fenced_settings();

    let err = resolve_lock_fencing(&readiness, &settings)
        .expect_err("finite leases without a renewal cadence must refuse");
    assert!(!err.to_string().contains("domain cutover"), "{}", err);
}

// --- 8. Boot against a cell the SCHEMA-117 migration never touched ------

/// A Postgres-mode cell that has never had the SCHEMA-117 migration
/// applied must still boot, on the legacy lock route.
///
/// `configure_domain_context` runs before `configure_lock_store_via_plugin`
/// (`server.rs`), so when it reads lock readiness neither the fenced tables
/// nor `lore_locks` itself exists yet. Nothing in the runtime creates them:
/// CR-030 N-7 keeps `LOCK_SCHEMA` migration-owned, and `bootstrap()` is a
/// fixture-only method production never calls. Every other test reaching
/// this path calls `bootstrap()` first — a state the production rail never
/// produces — so this case boots the way an unmigrated cell actually boots.
#[tokio::test]
#[ignore = "needs live Postgres env (LORE_TEST_PG_URL); run with -- --ignored"]
async fn a_never_migrated_postgres_cell_boots_on_the_legacy_lock_route() {
    let url = std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; a skipped live case is NOT RUN, never a pass");

    let mut settings: Settings = toml::from_str(include_str!("../../config/default.toml"))
        .expect("built-in settings fixture must deserialize");
    settings.mutable_store.mode = POSTGRES_MODE.to_owned();
    settings.plugins.insert(
        "postgres".to_owned(),
        toml::from_str(&format!("url = {url:?}\npool_max = 2\ndomain_pool_max = 2"))
            .expect("Postgres plugin fixture config"),
    );

    let configured = configure_domain_context(&settings)
        .await
        .expect("an unmigrated cell must boot rather than abort on SQLSTATE 42P01");

    let context = configured
        .context
        .expect("a Postgres-mode cell always gets a domain context");
    assert!(
        context.lock_coordinator().is_none(),
        "a cell without the SCHEMA-117 migration must stay on the legacy lock route"
    );
}

// --- 9. WP-116 guarded-stop contract gap: real construction paths ------

// PERMANENT cross-namespace isolation guarantee (WP-116 guarded stop),
// corrected 2026-08-30 after a reviewer round. This test deliberately
// consumes under the WRONG scope key (a direct handler's
// `GovernedScope::TargetRepository`/`RepositoryCreate` key) against a row
// `domain_operation_prepare` created under the CORRECT mediated key. That
// must ALWAYS fail closed -- cross-namespace consumption is a permanent
// invariant of the receipt state machine, not an artifact of today's gap,
// and this test's assertions (`ADMISSION_REJECTED_V1`, no domain
// mutation, the source row still `PREPARED`) must stay green forever. Do
// NOT replace them with a positive `Applied` proof when the WP-116
// carriage gap closes: add a positive proof ALONGSIDE these assertions
// instead, exercising a call site that correctly threads the mediated key
// end-to-end once carriage exists.
//
// What today's gap actually is: a governed handler has no way to obtain
// the `org_uuid`/principal identity a correct mediated key would need.
// One of the two carriage sites is pinned at compile time
// (`grpc::domain_operation_metadata::tests::
// domain_operation_metadata_carries_no_org_or_principal_identity`, over
// this module's own request-metadata carriage struct); the other,
// `AuthorizationToken` (`auth/jwt.rs:60`), is deliberately not pinned by
// an exhaustive destructure there and must be checked by hand when
// closing MISSING-1 -- see that test's own comment for why. This test is
// the live, decisive companion to
// `grpc::domain_operation_metadata::tests::
// direct_and_mediated_scope_key_families_never_collide`, driven through
// the REAL production construction path against a live Postgres domain
// store rather than by comparing key bytes in isolation: a
// `domain_operation_prepare` call built exactly the way the private
// `DomainOperationPrepare` RPC builds it, followed by a coordinator
// mutation call built exactly the way a governed handler builds it.
#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn a_mediated_prepare_key_cannot_be_consumed_by_a_repository_scoped_governed_mutation() {
    use lore_postgres::domain::DomainOutcome;
    use lore_postgres::domain::coordinator::ADMISSION_REJECTED_V1;
    use lore_postgres::domain::coordinator::GovernedOperation;
    use lore_postgres::domain::coordinator::RepositoryCreateInput;
    use lore_postgres::domain::receipts::OperationBinding;
    use lore_postgres::domain::receipts::PrepareResult;
    use lore_postgres::domain::receipts::ReceiptKey;
    use lore_postgres::domain::receipts::ReceiptLookup;
    use lore_server::grpc::domain_operation_metadata::ScopeKeyError;
    use lore_server::grpc::domain_operation_metadata::scope_key_mediated_namespace;
    use lore_server::grpc::domain_operation_metadata::scope_key_repository_create;
    use lore_server::grpc::domain_operation_metadata::scope_key_target_repository;

    // Required explicitly, matching this module's other live case: a
    // silent `return` here would let an unconfigured run report a pass it
    // never earned. A skipped live case is NOT RUN, never a pass.
    std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; a skipped live case is NOT RUN, never a pass");
    let context = lore_server::domain::test_support::configured_enforcing_context()
        .await
        .expect("real domain-context construction path must yield an enforcing context");
    let store = context.store().clone();

    type ScopeBuilder = fn(&[u8]) -> Result<Vec<u8>, ScopeKeyError>;
    let handler_builders: [(&str, ScopeBuilder); 2] = [
        (
            "GovernedScope::TargetRepository",
            scope_key_target_repository,
        ),
        (
            "GovernedScope::RepositoryCreate",
            scope_key_repository_create,
        ),
    ];

    for (label, build_handler_scope) in handler_builders {
        let repository_id = *Uuid::new_v4().as_bytes();
        let org_uuid = *Uuid::new_v4().as_bytes();
        let principal_namespace = format!("principal-v1\0{}", Uuid::new_v4());
        let verified_issuer = format!(
            "https://issuer.example/wp116-gap/{:016x}",
            rand::random::<u64>()
        );
        let authenticated_subject = "svc:wp116-gap-test".to_string();
        let operation_id = Uuid::now_v7();

        let mediated_scope =
            scope_key_mediated_namespace(&org_uuid, principal_namespace.as_bytes())
                .expect("valid mediated namespace components");
        let mediated_key = ReceiptKey {
            verified_issuer: verified_issuer.clone(),
            authenticated_subject: authenticated_subject.clone(),
            tenant_scope_key: mediated_scope,
            operation_id,
        };
        let binding = OperationBinding {
            method: PLATFORM_METHOD_REPOSITORY_CREATE.to_string(),
            scope: mediated_key.tenant_scope_key.clone(),
            fingerprint_version: 1,
            fingerprint: rand::random::<[u8; 32]>().to_vec(),
            canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
        };

        // Prepare exactly the way DomainOperationPrepare does: the
        // mediated key.
        let prepared = store
            .domain_operation_prepare(&mediated_key, &binding, None, None)
            .await
            .expect("prepare through the real production construction path must succeed");
        let PrepareResult::Prepared { token, .. } = prepared else {
            panic!("{label}: expected Prepared, got {prepared:?}");
        };

        // Now build the operation the way a governed handler would: same
        // prepare token and identity fields, but a repository-scoped key.
        let handler_scope = build_handler_scope(&repository_id).expect("valid repository id");
        let handler_key = ReceiptKey {
            verified_issuer,
            authenticated_subject,
            tenant_scope_key: handler_scope,
            operation_id,
        };
        let governed = GovernedOperation {
            key: handler_key,
            binding: binding.clone(),
            prepare_token: token,
        };
        let input = RepositoryCreateInput {
            metadata_witnesses: Vec::new(),
            repository_id: repository_id.to_vec(),
            name: format!("wp116-gap-{operation_id}"),
            metadata_hash: rand::random::<[u8; 32]>().to_vec(),
            default_branch_id: Uuid::new_v4().as_bytes().to_vec(),
            default_branch_name: "main".to_string(),
            default_branch_metadata_hash: rand::random::<[u8; 32]>().to_vec(),
            default_branch_latest_hash: vec![0u8; 32],
            creation_fingerprint: binding.fingerprint.clone(),
            creation_fingerprint_version: binding.fingerprint_version,
            projection: Vec::new(),
            events: Vec::new(),
        };

        let result = store.repository_create(&governed, &input).await.expect(
            "a wrong-scope consume must fail closed with a decisive result, not a \
                 transport/database error",
        );

        assert_eq!(
            result.repository_generation, None,
            "{label}: no domain mutation may happen on a scope-key mismatch"
        );
        assert_eq!(
            result.branch_generation, None,
            "{label}: no domain mutation may happen on a scope-key mismatch"
        );
        match result.outcome {
            DomainOutcome::NotApplied { reason, .. } => {
                assert_eq!(
                    reason, ADMISSION_REJECTED_V1,
                    "{label}: must be refused as an admission rejection, not a downstream \
                     precondition failure"
                );
            }
            other @ DomainOutcome::Applied => {
                panic!("{label}: expected NotApplied(ADMISSION_REJECTED_V1), got {other:?}")
            }
        }

        // No repository row was ever written.
        let snapshot = store
            .repository_snapshot(&repository_id)
            .await
            .expect("repository snapshot lookup");
        assert!(
            snapshot.is_none(),
            "{label}: repository_create must not have written a domain row"
        );

        // The originally prepared row, under its own mediated key, is
        // left completely untouched by the failed consume attempt.
        let lookup = store
            .domain_operation_receipt_get(&mediated_key, &binding)
            .await
            .expect("receipt lookup under the mediated key");
        assert!(
            matches!(lookup, ReceiptLookup::Prepared { .. }),
            "{label}: the mediated-key row must remain PREPARED, untouched by the failed \
             consume attempt under a different scope key"
        );
    }
}

// Formerly `include!`d from `src/domain/branch_create_replay_tests.rs` into
// `domain::tests` to reuse its verified-echo and admission fixtures.
fn branch_create_assert_frozen(
    actual: lore_postgres::domain::coordinator::BranchCreateResult,
    expected: &lore_postgres::domain::coordinator::BranchCreateResult,
) {
    assert!(actual.replayed);
    assert_eq!(actual.outcome, expected.outcome);
    assert_eq!(actual.public_result, expected.public_result);
}

fn branch_create_admission(ctx: &DomainContext, attempt: Uuid) -> AdmittedOperation {
    let mut metadata = human_metadata();
    metadata.insert("lore-attempt-id", attempt.to_string().parse().unwrap());
    ctx.admit(
        &metadata,
        Some(&human_token()),
        direct_scope_ctx(&test_repository_id()),
    )
    .unwrap()
    .unwrap()
}

fn branch_create_frozen() -> lore_postgres::domain::coordinator::BranchCreateResult {
    let response = lore_proto::lore::revision::v1::BranchCreateResponse {
        branch: Some(lore_proto::lore::model::v1::Branch {
            id: vec![1; 16].into(),
            creator: "original-foreign-creator".into(),
            latest: vec![2; 32].into(),
            metadata: vec![3; 32].into(),
            created: 123,
            ..Default::default()
        }),
    };
    let mut bytes = vec![1];
    prost::Message::encode(&response, &mut bytes).unwrap();
    lore_postgres::domain::coordinator::BranchCreateResult {
        replayed: true,
        outcome: DomainOutcome::Applied,
        public_result: Some(bytes),
    }
}

#[tokio::test]
async fn branch_create_internal_prepare_uses_client_attempt_as_stable_key() {
    let store = Arc::new(lore_server::domain::test_support::PreparingDomainStore::default());
    let verifier = Arc::new(DirectVerifierDouble::echo());
    let ctx = Arc::new(
        DomainContext::new(store.clone(), true).with_operation_verifier(Some(verifier.clone())),
    );
    let attempt = Uuid::now_v7();
    let first = branch_create_admission(&ctx, attempt);
    let second = branch_create_admission(&ctx, attempt);
    assert_ne!(
        first.key.operation_id, second.key.operation_id,
        "admission initially mints distinct keys"
    );
    for admitted in [first, second] {
        let prepared = GovernedBranchCreate::prepare(&ctx, admitted, vec![7; 32])
            .await
            .unwrap();
        let BranchCreateAdmission::Prepared(operation) = prepared.admission else {
            panic!("expected Prepared")
        };
        assert_eq!(operation.key.operation_id, attempt);
    }
    let calls = store.direct_calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    for (key, binding, id) in calls.iter() {
        assert_eq!(key.operation_id, attempt);
        assert_eq!(*id, Some(attempt));
        assert_eq!(binding.method, "branch.create");
        assert_eq!(binding.canonical_intent_digest, vec![7; 32]);
    }
    assert_eq!(verifier.call_count(), 2);
}

#[tokio::test]
async fn branch_create_frozen_terminal_replays_before_fresh_authorization_even_after_downgrade() {
    for downgraded in [false, true] {
        let store = Arc::new(lore_server::domain::test_support::PreparingDomainStore::default());
        let verifier = Arc::new(if downgraded {
            DirectVerifierDouble::erroring(Status::permission_denied("role downgraded"))
        } else {
            DirectVerifierDouble::echo()
        });
        let ctx = Arc::new(
            DomainContext::new(store.clone(), true).with_operation_verifier(Some(verifier.clone())),
        );
        let frozen = branch_create_frozen();
        store
            .branch_terminal_replies
            .lock()
            .unwrap()
            .push_back(Ok(Some(frozen.clone())));
        let governed = GovernedBranchCreate::prepare(
            &ctx,
            branch_create_admission(&ctx, Uuid::now_v7()),
            vec![7; 32],
        )
        .await
        .unwrap();
        branch_create_assert_frozen(governed.replay().await.unwrap().unwrap(), &frozen);
        assert_eq!(verifier.call_count(), 0);
        assert!(store.direct_calls.lock().unwrap().is_empty());
        assert!(matches!(
            governed.admission,
            BranchCreateAdmission::Terminal(_)
        ));
    }
}

#[tokio::test]
async fn branch_create_prepare_already_committed_rechecks_exact_terminal() {
    let store = Arc::new(lore_server::domain::test_support::PreparingDomainStore::default());
    let verifier = Arc::new(DirectVerifierDouble::echo());
    let ctx = Arc::new(
        DomainContext::new(store.clone(), true).with_operation_verifier(Some(verifier.clone())),
    );
    let frozen = branch_create_frozen();
    store
        .branch_terminal_replies
        .lock()
        .unwrap()
        .extend([Ok(None), Ok(Some(frozen.clone()))]);
    *store.direct_result.lock().unwrap() = Some(PrepareResult::Committed(DomainOutcome::Applied));
    let attempt = Uuid::now_v7();
    let governed =
        GovernedBranchCreate::prepare(&ctx, branch_create_admission(&ctx, attempt), vec![7; 32])
            .await
            .unwrap();
    branch_create_assert_frozen(governed.replay().await.unwrap().unwrap(), &frozen);
    assert_eq!(verifier.call_count(), 1);
    let calls = store.branch_terminal_calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, calls[1].0);
    assert_eq!(calls[0].1, calls[1].1);
    assert_eq!(calls[0].0.operation_id, attempt);
}

#[tokio::test]
async fn branch_create_terminal_lookup_preserves_conflict_and_unknown_classification() {
    for unknown in [false, true] {
        let store = Arc::new(lore_server::domain::test_support::PreparingDomainStore::default());
        let verifier = Arc::new(DirectVerifierDouble::echo());
        let ctx = Arc::new(
            DomainContext::new(store.clone(), true).with_operation_verifier(Some(verifier.clone())),
        );
        store
            .branch_terminal_replies
            .lock()
            .unwrap()
            .push_back(Err(if unknown {
                DomainError::OutcomeUnknown("expired or unavailable payload".into())
            } else {
                DomainError::InvalidInput("binding mismatch".into())
            }));
        let error = GovernedBranchCreate::prepare(
            &ctx,
            branch_create_admission(&ctx, Uuid::now_v7()),
            vec![8; 32],
        )
        .await
        .err()
        .unwrap();
        assert_eq!(
            error.code(),
            if unknown {
                Code::Aborted
            } else {
                Code::InvalidArgument
            }
        );
        assert_eq!(
            error
                .metadata()
                .get(lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_KEY)
                .is_some(),
            unknown
        );
        assert_eq!(
            lore_transport::error::ProtocolError::from(error).is_outcome_unknown(),
            unknown
        );
        assert_eq!(verifier.call_count(), 0);
        assert!(store.direct_calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn branch_create_missing_attempt_refuses_before_terminal_lookup_or_verifier() {
    let store = Arc::new(lore_server::domain::test_support::PreparingDomainStore::default());
    let verifier = Arc::new(DirectVerifierDouble::echo());
    let ctx = Arc::new(
        DomainContext::new(store.clone(), true).with_operation_verifier(Some(verifier.clone())),
    );
    let admitted = ctx
        .admit(
            &human_metadata(),
            Some(&human_token()),
            direct_scope_ctx(&test_repository_id()),
        )
        .unwrap()
        .unwrap();
    let error = GovernedBranchCreate::prepare(&ctx, admitted, vec![7; 32])
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert!(store.branch_terminal_calls.lock().unwrap().is_empty());
    assert_eq!(verifier.call_count(), 0);
}
