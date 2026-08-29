// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;
use lore_postgres::domain::DomainError;
use lore_postgres::domain::DomainOutcome;
use lore_postgres::domain::coordinator::BranchPushCommitInput;
use lore_postgres::domain::coordinator::BranchSnapshot;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::MetadataCasInput;
use lore_postgres::domain::coordinator::MutationResult;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;
use lore_postgres::domain::coordinator::RepositorySnapshot;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::ReceiptLookup;
use lore_proto::lore::domain::v1::DomainOperationClockGetRequest;
use lore_proto::lore::domain::v1::DomainOperationOutcome;
use lore_proto::lore::domain::v1::DomainOperationPrepareRequest;
use lore_proto::lore::domain::v1::DomainOperationPrepareStatus;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetRequest;
use lore_proto::lore::domain::v1::DomainOperationReceiptStatus;
use lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationService;
use lore_proto::rebac::VerifyRepositoryOperationAuthorizationRequest;
use lore_proto::rebac::VerifyRepositoryOperationAuthorizationResponse;
use lore_proto::rebac::verify_repository_operation_authorization_request::Proof;
use ring::digest::SHA256;
use ring::digest::digest;
use tonic::Code;
use tonic::Request;
use tonic::Status;
use uuid::Uuid;

use super::service::LoreDomainOperationV1Service;
use super::strict_codec::validate_prepare;
use super::strict_codec::validate_receipt_get;
use crate::auth::jwt::AuthorizationToken;
use crate::authnz::rebac::RepositoryOperationAuthorizationVerifier;
use crate::domain::DomainContext;
use crate::grpc::domain_operation_metadata::scope_key_mediated_namespace;

const AUTHORIZATION_REVISION: u64 = 7;
const CLOCK_MILLIS: u64 = 1_800_000_000_000;
const SERVER_ENTRY_SOURCE: &str = include_str!("../../../server.rs");

#[derive(Clone)]
struct RecordedPrepare {
    key: ReceiptKey,
    binding: OperationBinding,
    witness: Option<AuthorizationWitness>,
}

struct RecordingStore {
    clock_calls: AtomicUsize,
    prepare_calls: AtomicUsize,
    receipt_calls: AtomicUsize,
    fail_prepare_outcome_unknown: AtomicBool,
    prepare_result: Mutex<PrepareResult>,
    receipt_result: Mutex<ReceiptLookup>,
    recorded_prepare: Mutex<Option<RecordedPrepare>>,
}

impl RecordingStore {
    fn new() -> Self {
        Self {
            clock_calls: AtomicUsize::new(0),
            prepare_calls: AtomicUsize::new(0),
            receipt_calls: AtomicUsize::new(0),
            fail_prepare_outcome_unknown: AtomicBool::new(false),
            prepare_result: Mutex::new(PrepareResult::Prepared {
                token: [0xA5; 32],
                hard_expires_at: SystemTime::UNIX_EPOCH
                    + Duration::from_millis(CLOCK_MILLIS + 900_000),
            }),
            receipt_result: Mutex::new(ReceiptLookup::Prepared {
                prepared_at: SystemTime::UNIX_EPOCH + Duration::from_millis(CLOCK_MILLIS),
                hard_expires_at: SystemTime::UNIX_EPOCH
                    + Duration::from_millis(CLOCK_MILLIS + 900_000),
            }),
            recorded_prepare: Mutex::new(None),
        }
    }
}

#[async_trait]
impl DomainTransactionStore for RecordingStore {
    async fn domain_operation_clock_get(&self) -> Result<SystemTime, DomainError> {
        self.clock_calls.fetch_add(1, Ordering::SeqCst);
        Ok(SystemTime::UNIX_EPOCH + Duration::from_millis(CLOCK_MILLIS))
    }

    async fn domain_operation_prepare(
        &self,
        key: &ReceiptKey,
        binding: &OperationBinding,
        witness: Option<&AuthorizationWitness>,
    ) -> Result<PrepareResult, DomainError> {
        self.prepare_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_prepare_outcome_unknown.load(Ordering::SeqCst) {
            return Err(DomainError::OutcomeUnknown(
                "lost commit acknowledgement".into(),
            ));
        }
        *self.recorded_prepare.lock().expect("record lock") = Some(RecordedPrepare {
            key: key.clone(),
            binding: binding.clone(),
            witness: witness.cloned(),
        });
        Ok(self.prepare_result.lock().expect("prepare result").clone())
    }

    async fn domain_operation_receipt_get(
        &self,
        _key: &ReceiptKey,
        _binding: &OperationBinding,
    ) -> Result<ReceiptLookup, DomainError> {
        self.receipt_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.receipt_result.lock().expect("receipt result").clone())
    }

    async fn repository_snapshot(
        &self,
        _repository_id: &[u8],
    ) -> Result<Option<RepositorySnapshot>, DomainError> {
        unreachable!("receipt-rail tests do not call repository_snapshot")
    }

    async fn branch_snapshot(
        &self,
        _repository_id: &[u8],
        _branch_id: &[u8],
    ) -> Result<Option<BranchSnapshot>, DomainError> {
        unreachable!("receipt-rail tests do not call branch_snapshot")
    }

    async fn repository_create(
        &self,
        _operation: &GovernedOperation,
        _input: &RepositoryCreateInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("receipt-rail tests do not call repository_create")
    }

    async fn repository_delete(
        &self,
        _operation: &GovernedOperation,
        _input: &RepositoryDeleteInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("receipt-rail tests do not call repository_delete")
    }

    async fn metadata_compare_and_swap(
        &self,
        _operation: &GovernedOperation,
        _input: &MetadataCasInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("receipt-rail tests do not call metadata_compare_and_swap")
    }

    async fn branch_push_commit(
        &self,
        _operation: &GovernedOperation,
        _input: &BranchPushCommitInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("receipt-rail tests do not call branch_push_commit")
    }

    async fn begin_obliterate(
        &self,
        _operation: &GovernedOperation,
        _repository_id: &[u8],
    ) -> Result<MutationResult, DomainError> {
        unreachable!("receipt-rail tests do not call begin_obliterate")
    }
}

struct EchoVerifier {
    calls: AtomicUsize,
    mismatch_echo: AtomicBool,
    mismatch_revision: AtomicBool,
    mismatch_commitment: AtomicBool,
    forwarded_authorization: Mutex<Option<String>>,
}

impl EchoVerifier {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mismatch_echo: AtomicBool::new(false),
            mismatch_revision: AtomicBool::new(false),
            mismatch_commitment: AtomicBool::new(false),
            forwarded_authorization: Mutex::new(None),
        }
    }
}

#[async_trait]
impl RepositoryOperationAuthorizationVerifier for EchoVerifier {
    async fn verify_repository_operation_authorization(
        &self,
        request: Request<VerifyRepositoryOperationAuthorizationRequest>,
    ) -> Result<VerifyRepositoryOperationAuthorizationResponse, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self
            .forwarded_authorization
            .lock()
            .expect("authorization record lock") = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let request = request.into_inner();
        let (authorization_revision, consumed_ticket_sha256) = match request
            .proof
            .as_ref()
            .expect("test verifier requires one proof")
        {
            Proof::PreclaimTicket(ticket) => (
                request
                    .authorization_revision
                    .checked_add(1)
                    .expect("test revision advances"),
                Bytes::copy_from_slice(digest(&SHA256, ticket).as_ref()),
            ),
            Proof::ConsumedTicketSha256(commitment) => {
                (request.authorization_revision, commitment.clone())
            }
        };
        Ok(VerifyRepositoryOperationAuthorizationResponse {
            authorization_id: request.authorization_id,
            authorization_revision: if self.mismatch_revision.load(Ordering::SeqCst) {
                authorization_revision + 1
            } else {
                authorization_revision
            },
            verification_nonce: Bytes::from_static(&[0x31; 32]),
            bound_fields_digest: Bytes::from_static(&[0x32; 32]),
            consumed_ticket_sha256: if self.mismatch_commitment.load(Ordering::SeqCst) {
                Bytes::from_static(&[0xFF; 32])
            } else {
                consumed_ticket_sha256
            },
            org_uuid: request.org_uuid,
            initiating_principal_namespace: request.initiating_principal_namespace,
            operation_id: request.operation_id,
            method: if self.mismatch_echo.load(Ordering::SeqCst) {
                "mismatched-method".into()
            } else {
                request.method
            },
            scope: request.scope,
            fingerprint_version: request.fingerprint_version,
            fingerprint: request.fingerprint,
            canonical_intent_digest: request.canonical_intent_digest,
            verified_issuer: request.verified_issuer,
            authenticated_subject: request.authenticated_subject,
        })
    }
}

fn service() -> (
    LoreDomainOperationV1Service,
    Arc<RecordingStore>,
    Arc<EchoVerifier>,
) {
    let store = Arc::new(RecordingStore::new());
    let verifier = Arc::new(EchoVerifier::new());
    let domain = Arc::new(DomainContext::new(store.clone(), true));
    (
        LoreDomainOperationV1Service::new(domain, verifier.clone()),
        store,
        verifier,
    )
}

fn service_token() -> AuthorizationToken {
    AuthorizationToken {
        issuer: "https://issuer.example".into(),
        user_id: "lorehub-control-plane".into(),
        is_service_account: Some(true),
        ..Default::default()
    }
}

fn valid_prepare() -> DomainOperationPrepareRequest {
    let operation_id = Uuid::now_v7();
    DomainOperationPrepareRequest {
        org_uuid: Bytes::from_static(&[0x11; 16]),
        initiating_principal_namespace: Bytes::from_static(
            b"principal-v1\x0001111111-1111-4111-8111-111111111111",
        ),
        operation_id: Bytes::copy_from_slice(operation_id.as_bytes()),
        method: "lore.domain.v1.RepositoryCreate".into(),
        scope: Bytes::from_static(b"repository-scope"),
        fingerprint_version: 1,
        fingerprint: Bytes::from_static(&[0x21; 32]),
        canonical_intent_digest: Bytes::from_static(&[0x22; 32]),
        authorization_id: Bytes::copy_from_slice(operation_id.as_bytes()),
        authorization_revision: AUTHORIZATION_REVISION,
        preclaim_ticket: Bytes::from_static(&[0x23; 32]),
    }
}

fn valid_receipt_get() -> DomainOperationReceiptGetRequest {
    let prepare = valid_prepare();
    DomainOperationReceiptGetRequest {
        org_uuid: prepare.org_uuid,
        initiating_principal_namespace: prepare.initiating_principal_namespace,
        operation_id: prepare.operation_id,
        method: prepare.method,
        scope: prepare.scope,
        fingerprint_version: prepare.fingerprint_version,
        fingerprint: prepare.fingerprint,
        canonical_intent_digest: prepare.canonical_intent_digest,
        authorization_id: prepare.authorization_id,
        authorization_revision: prepare.authorization_revision,
        consumed_ticket_sha256: Bytes::from_static(&[0x33; 32]),
    }
}

fn authenticated<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(service_token());
    request.metadata_mut().insert(
        "authorization",
        "Bearer service-token"
            .parse()
            .expect("valid authorization metadata"),
    );
    request
}

#[test]
fn decoded_field_bounds_and_presence_fail_closed() {
    let mut request = valid_prepare();
    request.method.clear();
    assert_eq!(
        validate_prepare(request)
            .err()
            .expect("empty method")
            .code(),
        Code::InvalidArgument
    );

    let mut request = valid_prepare();
    request.initiating_principal_namespace = Bytes::from_static(b"principal-v1\0not-a-uuid");
    assert_eq!(
        validate_prepare(request)
            .err()
            .expect("noncanonical principal namespace")
            .code(),
        Code::InvalidArgument
    );

    let mut request = valid_prepare();
    request.scope = Bytes::from(vec![0; 4097]);
    assert_eq!(
        validate_prepare(request)
            .err()
            .expect("oversized scope")
            .code(),
        Code::InvalidArgument
    );

    let mut request = valid_prepare();
    request.fingerprint_version = u32::MAX;
    assert_eq!(
        validate_prepare(request)
            .err()
            .expect("version overflow")
            .code(),
        Code::InvalidArgument
    );

    let mut request = valid_prepare();
    request.preclaim_ticket = Bytes::from_static(&[0; 31]);
    assert_eq!(
        validate_prepare(request)
            .err()
            .expect("short ticket")
            .code(),
        Code::InvalidArgument
    );

    let mut request = valid_receipt_get();
    request.consumed_ticket_sha256 = Bytes::from_static(&[0; 33]);
    assert_eq!(
        validate_receipt_get(request)
            .err()
            .expect("long commitment")
            .code(),
        Code::InvalidArgument
    );
}

#[tokio::test]
async fn invalid_request_stops_before_verifier_and_store() {
    let (service, store, verifier) = service();
    let mut request = valid_prepare();
    request.operation_id = Bytes::from_static(&[0; 16]);

    let error = service
        .domain_operation_prepare(authenticated(request))
        .await
        .expect_err("non-v7 operation id must fail");
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.prepare_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn prepare_returns_token_and_records_exact_authenticated_binding() {
    let (service, store, verifier) = service();
    let request = valid_prepare();
    let expected_operation_id = request.operation_id.clone();
    let response = service
        .domain_operation_prepare(authenticated(request))
        .await
        .expect("prepare succeeds")
        .into_inner();

    assert_eq!(
        response.status,
        DomainOperationPrepareStatus::Prepared as i32
    );
    assert_eq!(response.consume_token.as_ref(), &[0xA5; 32]);
    assert_eq!(
        response.hard_expires_at_unix_millis,
        Some(CLOCK_MILLIS as i64 + 900_000)
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        verifier
            .forwarded_authorization
            .lock()
            .expect("authorization record lock")
            .as_deref(),
        Some("Bearer service-token")
    );
    let recorded = store
        .recorded_prepare
        .lock()
        .expect("record lock")
        .clone()
        .expect("prepare recorded");
    assert_eq!(recorded.key.verified_issuer, "https://issuer.example");
    assert_eq!(recorded.key.authenticated_subject, "lorehub-control-plane");
    assert_eq!(
        recorded.key.operation_id.as_bytes(),
        expected_operation_id.as_ref()
    );
    assert_eq!(recorded.binding.fingerprint, vec![0x21; 32]);
    assert_eq!(
        recorded.key.tenant_scope_key,
        scope_key_mediated_namespace(
            &[0x11; 16],
            b"principal-v1\x0001111111-1111-4111-8111-111111111111",
        )
        .expect("canonical namespace encodes once")
    );
    assert_eq!(
        recorded
            .witness
            .expect("verified witness")
            .authorization_revision,
        (AUTHORIZATION_REVISION + 1) as i64
    );
}

#[tokio::test]
async fn receipt_prepared_is_nondecisive_and_exposes_no_consume_token_field() {
    let (service, store, _) = service();
    let response = service
        .domain_operation_receipt_get(authenticated(valid_receipt_get()))
        .await
        .expect("receipt lookup succeeds")
        .into_inner();

    assert_eq!(
        response.status,
        DomainOperationReceiptStatus::Prepared as i32
    );
    assert_eq!(response.outcome, DomainOperationOutcome::Unspecified as i32);
    assert_eq!(response.prepared_at_unix_millis, Some(CLOCK_MILLIS as i64));
    assert_eq!(
        response.hard_expires_at_unix_millis,
        Some(CLOCK_MILLIS as i64 + 900_000)
    );
    assert_eq!(store.receipt_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn receipt_maps_terminal_and_future_marker_results_exactly() {
    let (service, store, _) = service();
    *store.receipt_result.lock().expect("receipt result") = ReceiptLookup::Committed {
        outcome: DomainOutcome::NotApplied {
            reason_version: 1,
            reason: "UUID_FUTURE_HORIZON_EXCEEDED_V1".into(),
        },
        from_future_marker: true,
    };

    let response = service
        .domain_operation_receipt_get(authenticated(valid_receipt_get()))
        .await
        .expect("receipt lookup succeeds")
        .into_inner();
    assert_eq!(
        response.status,
        DomainOperationReceiptStatus::Committed as i32
    );
    assert_eq!(response.outcome, DomainOperationOutcome::NotApplied as i32);
    assert_eq!(response.reason_version, Some(1));
    assert_eq!(response.reason, "UUID_FUTURE_HORIZON_EXCEEDED_V1");
    assert!(response.from_future_marker);
}

#[tokio::test]
async fn verifier_echo_mismatch_stops_before_store() {
    let (service, store, verifier) = service();
    verifier.mismatch_echo.store(true, Ordering::SeqCst);

    let error = service
        .domain_operation_prepare(authenticated(valid_prepare()))
        .await
        .expect_err("divergent verifier echo must fail");
    assert_eq!(error.code(), Code::PermissionDenied);
    assert_eq!(store.prepare_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn verifier_revision_or_commitment_mismatch_stops_before_store() {
    for mismatch_revision in [true, false] {
        let (service, store, verifier) = service();
        verifier
            .mismatch_revision
            .store(mismatch_revision, Ordering::SeqCst);
        verifier
            .mismatch_commitment
            .store(!mismatch_revision, Ordering::SeqCst);

        let error = service
            .domain_operation_prepare(authenticated(valid_prepare()))
            .await
            .expect_err("divergent verifier witness must fail");
        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(store.prepare_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn outcome_unknown_maps_to_aborted_without_service_retry() {
    let (service, store, _) = service();
    store
        .fail_prepare_outcome_unknown
        .store(true, Ordering::SeqCst);

    let error = service
        .domain_operation_prepare(authenticated(valid_prepare()))
        .await
        .expect_err("lost commit acknowledgement is ambiguous");
    assert_eq!(error.code(), Code::Aborted);
    assert_eq!(store.prepare_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn missing_or_nonservice_identity_cannot_reach_the_private_rail() {
    let (service, store, _) = service();
    let missing = service
        .domain_operation_clock_get(Request::new(DomainOperationClockGetRequest {}))
        .await
        .expect_err("missing authn extension must fail");
    assert_eq!(missing.code(), Code::Unauthenticated);

    let mut human = service_token();
    human.is_service_account = Some(false);
    let mut request = Request::new(DomainOperationClockGetRequest {});
    request.extensions_mut().insert(human);
    let denied = service
        .domain_operation_clock_get(request)
        .await
        .expect_err("human token must fail");
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert_eq!(store.clock_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn partial_three_rpc_rail_does_not_advertise_v2_capabilities() {
    for deferred_capability in [
        "domain_operation_receipt_v2",
        "domain_operation_proof_namespace_lifecycle_v1",
    ] {
        assert!(
            !SERVER_ENTRY_SOURCE.contains(deferred_capability),
            "partial rail must not advertise {deferred_capability}"
        );
    }
}
