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
use lore_postgres::domain::maintenance::ProofNamespaceMaterializeInput;
use lore_postgres::domain::maintenance::ProofNamespaceMaterializeReceipt;
use lore_postgres::domain::maintenance::ProofNamespaceRetireAck;
use lore_postgres::domain::maintenance::ProofNamespaceRetireInput;
use lore_postgres::domain::maintenance::TerminalStatusAttachInput;
use lore_postgres::domain::maintenance::TerminalStatusAttachmentAck;
use lore_postgres::domain::maintenance::VerifiedStaleFinalizeInput;
use lore_postgres::domain::maintenance::VerifiedStaleFinalizeResult;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::ReceiptLookup;
use lore_proto::lore::domain::v1::DomainOperationClockGetRequest;
use lore_proto::lore::domain::v1::DomainOperationOutcome;
use lore_proto::lore::domain::v1::DomainOperationPrepareRequest;
use lore_proto::lore::domain::v1::DomainOperationPrepareStatus;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceMaterializeRequestV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceMaterializeStatusV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceRetireRequestV1;
use lore_proto::lore::domain::v1::DomainOperationProofNamespaceRetireStatusV1;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetRequest;
use lore_proto::lore::domain::v1::DomainOperationReceiptStatus;
use lore_proto::lore::domain::v1::DomainOperationTerminalStatusAttachRequest;
use lore_proto::lore::domain::v1::DomainOperationTerminalStatusAttachmentStatusV1;
use lore_proto::lore::domain::v1::DomainOperationVerifiedStaleFinalizeRequest;
use lore_proto::lore::domain::v1::DomainOperationVerifiedStaleFinalizeStatus;
use lore_proto::lore::domain::v1::TerminalStatusAttachPhase2ActionV1;
use lore_proto::lore::domain::v1::TerminalStatusAttachPhaseV1;
use lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationService;
use lore_proto::rebac::DomainOperationMaintenanceVerificationRequest;
use lore_proto::rebac::DomainOperationMaintenanceVerificationResponse;
use lore_proto::rebac::VerifyRepositoryOperationAuthorizationRequest;
use lore_proto::rebac::VerifyRepositoryOperationAuthorizationResponse;
use lore_proto::rebac::verify_repository_operation_authorization_request::Proof;
use ring::digest::SHA256;
use ring::digest::digest;
use tonic::Code;
use tonic::Request;
use tonic::Status;
use tonic_prost::prost::Message;
use uuid::Uuid;

use super::service::LoreDomainOperationV1Service;
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
use crate::authnz::rebac::RepositoryOperationAuthorizationVerifier;
use crate::domain::DomainContext;
use crate::grpc::domain_operation_metadata::scope_key_mediated_namespace;

const AUTHORIZATION_REVISION: u64 = 7;
const CLOCK_MILLIS: u64 = 1_800_000_000_000;
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
    stale_finalize_calls: AtomicUsize,
    terminal_attach_calls: AtomicUsize,
    materialize_calls: AtomicUsize,
    retire_calls: AtomicUsize,
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
            stale_finalize_calls: AtomicUsize::new(0),
            terminal_attach_calls: AtomicUsize::new(0),
            materialize_calls: AtomicUsize::new(0),
            retire_calls: AtomicUsize::new(0),
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

    fn maintenance_calls(&self) -> usize {
        self.stale_finalize_calls.load(Ordering::SeqCst)
            + self.terminal_attach_calls.load(Ordering::SeqCst)
            + self.materialize_calls.load(Ordering::SeqCst)
            + self.retire_calls.load(Ordering::SeqCst)
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

    async fn domain_operation_verified_stale_finalize(
        &self,
        input: &VerifiedStaleFinalizeInput,
    ) -> Result<VerifiedStaleFinalizeResult, DomainError> {
        self.stale_finalize_calls.fetch_add(1, Ordering::SeqCst);
        Ok(VerifiedStaleFinalizeResult {
            status: lore_postgres::domain::maintenance::VerifiedStaleFinalizeStatus::Mismatch,
            stale_finalize_permit_revision: input.stale_finalize_permit_revision,
            committed_receipt_canonical: Vec::new(),
            stale_finalize_clock: None,
            response_digest: vec![0x71; 32],
        })
    }

    async fn domain_operation_terminal_status_attach(
        &self,
        input: &TerminalStatusAttachInput,
    ) -> Result<TerminalStatusAttachmentAck, DomainError> {
        self.terminal_attach_calls.fetch_add(1, Ordering::SeqCst);
        Ok(TerminalStatusAttachmentAck {
            status: lore_postgres::domain::maintenance::TerminalStatusAttachStatus::Mismatch,
            fields: std::array::from_fn(|_| None),
            times: std::array::from_fn(|_| None),
            completion_marker_sequence: input.completion_marker_sequence,
            range: None,
            informational_high_water: None,
            response_digest: vec![0x72; 32],
        })
    }

    async fn domain_operation_proof_namespace_materialize(
        &self,
        input: &ProofNamespaceMaterializeInput,
    ) -> Result<ProofNamespaceMaterializeReceipt, DomainError> {
        self.materialize_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ProofNamespaceMaterializeReceipt {
            status: lore_postgres::domain::maintenance::ProofNamespaceMaterializeStatus::Mismatch,
            namespace_epoch: input.namespace_epoch.clone(),
            namespace_claim_revision: input.namespace_claim_revision,
            namespace_claim_nonce: input.namespace_claim_nonce.clone(),
            lore_namespace_revision: 1,
            lore_global_counter_revision: 1,
            lore_org_counter_revision: 1,
            created_at: SystemTime::UNIX_EPOCH + Duration::from_millis(1),
            materialization_receipt_digest: vec![0x73; 32],
            response_digest: vec![0x74; 32],
        })
    }

    async fn domain_operation_proof_namespace_retire(
        &self,
        input: &ProofNamespaceRetireInput,
    ) -> Result<ProofNamespaceRetireAck, DomainError> {
        self.retire_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ProofNamespaceRetireAck {
            status: lore_postgres::domain::maintenance::ProofNamespaceRetireStatus::Mismatch,
            namespace_epoch: input.namespace_epoch.clone(),
            retirement_fence_generation: input.retirement_fence_generation,
            quota_revision: input.quota_revision,
            final_range_set_digest: input.final_range_set_digest.clone(),
            final_high_water: input.final_high_water,
            retired_at: None,
            namespace_claim_revision: input.namespace_claim_revision,
            namespace_claim_nonce: input.namespace_claim_nonce.clone(),
            response_digest: vec![0x75; 32],
        })
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
    omit_claim_identity_digest: AtomicBool,
    forwarded_authorization: Mutex<Option<String>>,
}

impl EchoVerifier {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mismatch_echo: AtomicBool::new(false),
            mismatch_revision: AtomicBool::new(false),
            mismatch_commitment: AtomicBool::new(false),
            omit_claim_identity_digest: AtomicBool::new(false),
            forwarded_authorization: Mutex::new(None),
        }
    }

    fn maintenance_response(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> DomainOperationMaintenanceVerificationResponse {
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
        DomainOperationMaintenanceVerificationResponse {
            method: request.method,
            verified_issuer: request.verified_issuer,
            authenticated_subject: request.authenticated_subject,
            org_uuid: request.org_uuid,
            initiating_principal_namespace: request.initiating_principal_namespace,
            target_identity: if self.mismatch_echo.load(Ordering::SeqCst) {
                Bytes::from_static(&[0xff; 16])
            } else {
                request.target_identity
            },
            canonical_request_sha256: request.canonical_request_sha256,
            verification_digest: Bytes::from_static(&[0x61; 32]),
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
            expected_claim_identity_digest: if self
                .omit_claim_identity_digest
                .load(Ordering::SeqCst)
            {
                Bytes::new()
            } else {
                Bytes::from_static(&[0x33; 32])
            },
        })
    }

    async fn claim_repository_operation_stale_finalize_permit(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status> {
        Ok(self.maintenance_response(request))
    }

    async fn verify_repository_operation_terminal_status_attach(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status> {
        Ok(self.maintenance_response(request))
    }

    async fn verify_repository_operation_proof_namespace_materialize(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status> {
        Ok(self.maintenance_response(request))
    }

    async fn verify_repository_operation_proof_namespace_retire(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status> {
        Ok(self.maintenance_response(request))
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

fn valid_stale_finalize() -> DomainOperationVerifiedStaleFinalizeRequest {
    let operation_id = Uuid::now_v7();
    DomainOperationVerifiedStaleFinalizeRequest {
        verified_issuer: "https://issuer.example".into(),
        authenticated_subject: "lorehub-control-plane".into(),
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
        authorization_revision: 7,
        verification_nonce: Bytes::from_static(&[0x23; 32]),
        bound_fields_digest: Bytes::from_static(&[0x24; 32]),
        consumed_ticket_sha256: Bytes::from_static(&[0x25; 32]),
        expected_claim_identity_digest: Bytes::from_static(&[0x26; 32]),
        stale_finalize_permit: Bytes::from_static(&[0x27; 32]),
        stale_finalize_permit_revision: 9,
    }
}

fn valid_terminal_attach_phase1() -> DomainOperationTerminalStatusAttachRequest {
    let operation_id = Uuid::now_v7();
    DomainOperationTerminalStatusAttachRequest {
        verified_issuer: "https://issuer.example".into(),
        authenticated_subject: "lorehub-control-plane".into(),
        org_uuid: Bytes::from_static(&[0x11; 16]),
        initiating_principal_namespace: Bytes::from_static(
            b"principal-v1\x0001111111-1111-4111-8111-111111111111",
        ),
        operation_id: Bytes::copy_from_slice(operation_id.as_bytes()),
        authorization_id: Bytes::copy_from_slice(operation_id.as_bytes()),
        authorization_revision: 7,
        claim_id: Bytes::from_static(&[0x31; 16]),
        claim_revision: 8,
        terminal_outcome: DomainOperationOutcome::Applied as i32,
        terminal_receipt_sha256: Bytes::from_static(&[0x32; 32]),
        platform_terminal_status_revision: 9,
        acknowledged_at_unix_millis: 1,
        phase: TerminalStatusAttachPhaseV1::Phase1TerminalAck as i32,
        reserve_charge_revision: 10,
        reserve_charge_nonce: Bytes::from_static(&[0x33; 32]),
        phase2_action: TerminalStatusAttachPhase2ActionV1::Unspecified as i32,
        release_tombstone_digest: Bytes::new(),
        active_release_intent_revision: 0,
        active_release_intent_nonce: Bytes::new(),
        tombstone_reservation_revision: 11,
        tombstone_reservation_nonce: Bytes::from_static(&[0x34; 32]),
        final_prune_digest: Bytes::new(),
        tombstone_release_intent_revision: 0,
        tombstone_release_intent_nonce: Bytes::new(),
        release_proof_reservation_revision: 12,
        release_proof_reservation_nonce: Bytes::from_static(&[0x35; 32]),
        completion_marker_sequence: 1,
        expected_completion_marker_digest: Bytes::new(),
        request_digest: Bytes::from_static(&[0x36; 32]),
    }
}

fn valid_materialize() -> DomainOperationProofNamespaceMaterializeRequestV1 {
    DomainOperationProofNamespaceMaterializeRequestV1 {
        protocol_revision: 2,
        verified_issuer: "https://issuer.example".into(),
        authenticated_subject: "lorehub-control-plane".into(),
        org_uuid: Bytes::from_static(&[0x11; 16]),
        initiating_principal_namespace: Bytes::from_static(
            b"principal-v1\x0001111111-1111-4111-8111-111111111111",
        ),
        namespace_epoch: Bytes::from_static(&[0x41; 16]),
        namespace_claim_revision: 1,
        namespace_claim_nonce: Bytes::from_static(&[0x42; 32]),
        platform_capacity_revision: 2,
        lore_local_capacity_revision: 3,
        request_digest: Bytes::from_static(&[0x43; 32]),
        materialization_jwt: "signed-materialization-jwt".into(),
    }
}

fn valid_retire() -> DomainOperationProofNamespaceRetireRequestV1 {
    DomainOperationProofNamespaceRetireRequestV1 {
        protocol_revision: 2,
        verified_issuer: "https://issuer.example".into(),
        authenticated_subject: "lorehub-control-plane".into(),
        org_uuid: Bytes::from_static(&[0x11; 16]),
        initiating_principal_namespace: Bytes::from_static(
            b"principal-v1\x0001111111-1111-4111-8111-111111111111",
        ),
        namespace_epoch: Bytes::from_static(&[0x41; 16]),
        quota_revision: 4,
        final_range_set_digest: Bytes::from_static(&[0x44; 32]),
        final_high_water: 1,
        retirement_fence_generation: 2,
        retirement_permit_revision: 3,
        issued_at_unix_millis: 1,
        expires_at_unix_millis: 2,
        zero_platform_state_digest: Bytes::from_static(&[0x45; 32]),
        request_digest: Bytes::from_static(&[0x46; 32]),
        retirement_permit_jwt: "signed-retirement-jwt".into(),
        namespace_claim_revision: 5,
        namespace_claim_nonce: Bytes::from_static(&[0x47; 32]),
    }
}

fn authenticated<T>(message: T) -> Request<T> {
    authenticated_as(message, service_token())
}

fn authenticated_as<T>(message: T, token: AuthorizationToken) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(token);
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

type RawValidator = fn(&[u8]) -> Result<(), Status>;

fn strict_raw_cases() -> Vec<(&'static str, Vec<u8>, RawValidator)> {
    vec![
        (
            "stale finalize",
            valid_stale_finalize().encode_to_vec(),
            validate_verified_stale_finalize_raw,
        ),
        (
            "terminal attach",
            valid_terminal_attach_phase1().encode_to_vec(),
            validate_terminal_status_attach_raw,
        ),
        (
            "namespace materialize",
            valid_materialize().encode_to_vec(),
            validate_proof_namespace_materialize_raw,
        ),
        (
            "namespace retire",
            valid_retire().encode_to_vec(),
            validate_proof_namespace_retire_raw,
        ),
    ]
}

fn length_delimited_field(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(
        tag < 16,
        "test helper supports one-byte length-delimited keys"
    );
    assert!(value.len() < 128, "test helper supports one-byte lengths");
    let mut encoded = vec![(tag << 3) | 2, value.len() as u8];
    encoded.extend_from_slice(value);
    encoded
}

fn encode_raw_varint(mut value: u64) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

fn raw_varint_field(tag: u32, value: u64) -> Vec<u8> {
    let mut encoded = encode_raw_varint(u64::from(tag) << 3);
    encoded.extend_from_slice(&encode_raw_varint(value));
    encoded
}

fn raw_empty_length_delimited_field(tag: u32) -> Vec<u8> {
    let mut encoded = encode_raw_varint((u64::from(tag) << 3) | 2);
    encoded.push(0);
    encoded
}

fn assert_implicit_zero_fields_keep_strict_wire_checks(
    name: &str,
    raw: &[u8],
    tags: &[u32],
    validate: RawValidator,
) {
    validate(raw).unwrap_or_else(|error| panic!("{name} rejected implicit zero fields: {error}"));
    for tag in tags {
        let explicit = raw_varint_field(*tag, 0);
        let mut one_explicit_zero = raw.to_vec();
        one_explicit_zero.extend_from_slice(&explicit);
        validate(&one_explicit_zero).unwrap_or_else(|error| {
            panic!("{name} rejected one explicit zero for tag {tag}: {error}")
        });

        let mut duplicate = one_explicit_zero;
        duplicate.extend_from_slice(&explicit);
        assert!(
            validate(&duplicate).is_err(),
            "{name} accepted duplicate implicit-zero tag {tag}"
        );

        let mut wrong_wire = raw.to_vec();
        wrong_wire.extend_from_slice(&raw_empty_length_delimited_field(*tag));
        assert!(
            validate(&wrong_wire).is_err(),
            "{name} accepted wrong wire type for implicit-zero tag {tag}"
        );
    }
}

#[test]
fn strict_raw_validators_accept_each_complete_frozen_wire() {
    for (name, raw, validate) in strict_raw_cases() {
        validate(&raw).unwrap_or_else(|error| panic!("valid {name} frame rejected: {error}"));
    }
}

#[test]
fn strict_raw_validators_accept_only_the_frozen_implicit_zero_scalar_set() {
    let mut retire = valid_retire();
    retire.final_high_water = 0;
    assert_implicit_zero_fields_keep_strict_wire_checks(
        "namespace retire",
        &retire.encode_to_vec(),
        &[9],
        validate_proof_namespace_retire_raw,
    );

    let mut materialize = valid_materialize();
    materialize.platform_capacity_revision = 0;
    materialize.lore_local_capacity_revision = 0;
    assert_implicit_zero_fields_keep_strict_wire_checks(
        "namespace materialize",
        &materialize.encode_to_vec(),
        &[9, 10],
        validate_proof_namespace_materialize_raw,
    );

    let mut finalize = valid_stale_finalize();
    finalize.fingerprint_version = 0;
    finalize.authorization_revision = 0;
    finalize.stale_finalize_permit_revision = 0;
    assert_implicit_zero_fields_keep_strict_wire_checks(
        "stale finalize",
        &finalize.encode_to_vec(),
        &[8, 12, 18],
        validate_verified_stale_finalize_raw,
    );

    let mut attach = valid_terminal_attach_phase1();
    attach.authorization_revision = 0;
    attach.claim_revision = 0;
    attach.platform_terminal_status_revision = 0;
    attach.acknowledged_at_unix_millis = 0;
    attach.reserve_charge_revision = 0;
    attach.tombstone_reservation_revision = 0;
    attach.release_proof_reservation_revision = 0;
    attach.completion_marker_sequence = 0;
    assert_implicit_zero_fields_keep_strict_wire_checks(
        "terminal attach",
        &attach.encode_to_vec(),
        &[7, 9, 12, 13, 15, 21, 26, 28],
        validate_terminal_status_attach_raw,
    );
}

#[test]
fn strict_raw_validators_reject_unknown_and_duplicate_singular_fields() {
    for (name, raw, validate) in strict_raw_cases() {
        let mut unknown = raw.clone();
        unknown.extend_from_slice(&[0xFA, 0x01, 0x00]); // length-delimited tag 31
        assert!(
            validate(&unknown).is_err(),
            "{name} accepted unknown tag 31"
        );

        let mut duplicate = raw;
        duplicate.extend_from_slice(&length_delimited_field(1, b"duplicate"));
        assert!(
            validate(&duplicate).is_err(),
            "{name} accepted a duplicate singular tag"
        );
    }
}

#[test]
fn strict_raw_validators_reject_wrong_wire_groups_field_zero_and_truncation() {
    for (name, raw, validate) in strict_raw_cases() {
        let mut wrong_wire = vec![0x08, 0x01]; // tag 1 as varint
        wrong_wire.extend_from_slice(&raw);
        assert!(
            validate(&wrong_wire).is_err(),
            "{name} accepted wrong wire type"
        );

        let mut group = vec![0x0B]; // tag 1, start-group wire type
        group.extend_from_slice(&raw);
        assert!(validate(&group).is_err(), "{name} accepted a group");

        let mut field_zero = vec![0x00];
        field_zero.extend_from_slice(&raw);
        assert!(validate(&field_zero).is_err(), "{name} accepted field zero");

        assert!(
            validate(&[0x0A, 0x05, b'x']).is_err(),
            "{name} accepted a truncated length-delimited field"
        );
    }
}

#[test]
fn strict_raw_validators_reject_noncanonical_overflow_and_oversized_frames() {
    for (name, raw, validate) in strict_raw_cases() {
        let mut noncanonical_key = vec![0x8A, 0x00, 0x00];
        noncanonical_key.extend_from_slice(&raw);
        assert!(
            validate(&noncanonical_key).is_err(),
            "{name} accepted a noncanonical field-key varint"
        );

        let overflow_key = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        assert!(
            validate(&overflow_key).is_err(),
            "{name} accepted an overflowing varint"
        );

        assert!(
            validate(&vec![0; 16 * 1024 + 1]).is_err(),
            "{name} accepted an oversized raw frame"
        );
    }
}

#[test]
fn strict_raw_validators_reject_missing_required_presence_and_field_bounds() {
    let mut finalize = valid_stale_finalize();
    finalize.stale_finalize_permit.clear();
    assert!(validate_verified_stale_finalize_raw(&finalize.encode_to_vec()).is_err());
    let mut finalize_oversized = valid_stale_finalize();
    finalize_oversized.verified_issuer = "i".repeat(257);
    assert!(validate_verified_stale_finalize_raw(&finalize_oversized.encode_to_vec()).is_err());

    let mut attach = valid_terminal_attach_phase1();
    attach.request_digest.clear();
    assert!(validate_terminal_status_attach_raw(&attach.encode_to_vec()).is_err());
    let mut attach_oversized = valid_terminal_attach_phase1();
    attach_oversized.authenticated_subject = "s".repeat(257);
    assert!(validate_terminal_status_attach_raw(&attach_oversized.encode_to_vec()).is_err());

    let mut materialize = valid_materialize();
    materialize.namespace_claim_nonce.clear();
    assert!(validate_proof_namespace_materialize_raw(&materialize.encode_to_vec()).is_err());
    let mut materialize_oversized = valid_materialize();
    materialize_oversized.materialization_jwt = "j".repeat(8 * 1024 + 1);
    assert!(
        validate_proof_namespace_materialize_raw(&materialize_oversized.encode_to_vec()).is_err()
    );

    let mut retire = valid_retire();
    retire.namespace_claim_nonce.clear();
    assert!(validate_proof_namespace_retire_raw(&retire.encode_to_vec()).is_err());
    let mut retire_oversized = valid_retire();
    retire_oversized.retirement_permit_jwt = "j".repeat(8 * 1024 + 1);
    assert!(validate_proof_namespace_retire_raw(&retire_oversized.encode_to_vec()).is_err());
}

#[test]
fn terminal_attach_raw_presence_matrix_rejects_cross_phase_evidence() {
    let mut phase1_with_phase2 = valid_terminal_attach_phase1();
    phase1_with_phase2.phase2_action =
        TerminalStatusAttachPhase2ActionV1::ActiveReleaseIntentAck as i32;
    phase1_with_phase2.release_tombstone_digest = Bytes::from_static(&[0x51; 32]);
    phase1_with_phase2.active_release_intent_revision = 1;
    phase1_with_phase2.active_release_intent_nonce = Bytes::from_static(&[0x52; 32]);
    assert!(validate_terminal_status_attach_raw(&phase1_with_phase2.encode_to_vec()).is_err());

    let mut completion_missing_digest = valid_terminal_attach_phase1();
    completion_missing_digest.phase = TerminalStatusAttachPhaseV1::Phase2ReleaseAck as i32;
    completion_missing_digest.phase2_action =
        TerminalStatusAttachPhase2ActionV1::TombstoneReleaseIntentComplete as i32;
    completion_missing_digest.release_tombstone_digest = Bytes::from_static(&[0x53; 32]);
    completion_missing_digest.active_release_intent_revision = 1;
    completion_missing_digest.active_release_intent_nonce = Bytes::from_static(&[0x54; 32]);
    completion_missing_digest.final_prune_digest = Bytes::from_static(&[0x55; 32]);
    completion_missing_digest.tombstone_release_intent_revision = 1;
    completion_missing_digest.tombstone_release_intent_nonce = Bytes::from_static(&[0x56; 32]);
    assert!(
        validate_terminal_status_attach_raw(&completion_missing_digest.encode_to_vec()).is_err()
    );

    let mut poll_with_completion_digest = completion_missing_digest;
    poll_with_completion_digest.phase2_action =
        TerminalStatusAttachPhase2ActionV1::TombstonePrunePoll as i32;
    poll_with_completion_digest.expected_completion_marker_digest = Bytes::from_static(&[0x57; 32]);
    assert!(
        validate_terminal_status_attach_raw(&poll_with_completion_digest.encode_to_vec()).is_err()
    );
}

#[test]
fn maintenance_decoded_validators_enforce_exact_lengths_revisions_and_times() {
    let mut finalize = valid_stale_finalize();
    assert!(validate_verified_stale_finalize(&finalize).is_ok());
    finalize.fingerprint.truncate(31);
    assert!(validate_verified_stale_finalize(&finalize).is_err());
    let mut finalize_zero_revision = valid_stale_finalize();
    finalize_zero_revision.stale_finalize_permit_revision = 0;
    assert!(validate_verified_stale_finalize(&finalize_zero_revision).is_err());

    let mut attach = valid_terminal_attach_phase1();
    assert!(validate_terminal_status_attach(&attach).is_ok());
    attach.claim_id.truncate(15);
    assert!(validate_terminal_status_attach(&attach).is_err());
    let mut attach_bad_outcome = valid_terminal_attach_phase1();
    attach_bad_outcome.terminal_outcome = 3;
    assert!(validate_terminal_status_attach(&attach_bad_outcome).is_err());

    let mut materialize = valid_materialize();
    assert!(validate_proof_namespace_materialize(&materialize).is_ok());
    materialize.namespace_epoch.truncate(15);
    assert!(validate_proof_namespace_materialize(&materialize).is_err());
    let mut materialize_bad_protocol = valid_materialize();
    materialize_bad_protocol.protocol_revision = 3;
    assert!(validate_proof_namespace_materialize(&materialize_bad_protocol).is_err());

    let mut retire = valid_retire();
    assert!(validate_proof_namespace_retire(&retire).is_ok());
    retire.final_range_set_digest.truncate(31);
    assert!(validate_proof_namespace_retire(&retire).is_err());
    let mut retire_equal_expiry = valid_retire();
    retire_equal_expiry.expires_at_unix_millis = retire_equal_expiry.issued_at_unix_millis;
    assert!(validate_proof_namespace_retire(&retire_equal_expiry).is_err());
}

#[tokio::test]
async fn maintenance_auth_binding_stops_before_verifier_and_store() {
    let (service, store, verifier) = service();

    let mut finalize = valid_stale_finalize();
    finalize.verified_issuer = "https://different-issuer.example".into();
    let error = service
        .domain_operation_verified_stale_finalize(authenticated(finalize))
        .await
        .expect_err("stale-finalize must reject a divergent authenticated issuer");
    assert_eq!(error.code(), Code::PermissionDenied);

    let mut attach = valid_terminal_attach_phase1();
    attach.authenticated_subject = "different-subject".into();
    let error = service
        .domain_operation_terminal_status_attach(authenticated(attach))
        .await
        .expect_err("terminal-attach must reject a divergent authenticated subject");
    assert_eq!(error.code(), Code::PermissionDenied);

    let mut materialize = valid_materialize();
    materialize.verified_issuer = "https://different-issuer.example".into();
    let error = service
        .domain_operation_proof_namespace_materialize(authenticated(materialize))
        .await
        .expect_err("materialize must reject a divergent authenticated issuer");
    assert_eq!(error.code(), Code::PermissionDenied);

    let mut retire = valid_retire();
    retire.authenticated_subject = "different-subject".into();
    let error = service
        .domain_operation_proof_namespace_retire(authenticated(retire))
        .await
        .expect_err("retire must reject a divergent authenticated subject");
    assert_eq!(error.code(), Code::PermissionDenied);

    assert_eq!(
        verifier.calls.load(Ordering::SeqCst),
        0,
        "request identity must be exact before any maintenance verifier call"
    );
    assert_eq!(store.maintenance_calls(), 0);
}

#[tokio::test]
async fn maintenance_verifier_binding_stops_before_store() {
    let (service, store, verifier) = service();
    verifier.mismatch_echo.store(true, Ordering::SeqCst);

    let error = service
        .domain_operation_verified_stale_finalize(authenticated(valid_stale_finalize()))
        .await
        .expect_err("stale-finalize must reject a divergent verifier echo");
    assert_eq!(error.code(), Code::PermissionDenied);
    let error = service
        .domain_operation_terminal_status_attach(authenticated(valid_terminal_attach_phase1()))
        .await
        .expect_err("terminal-attach must reject a divergent verifier echo");
    assert_eq!(error.code(), Code::PermissionDenied);
    let mut materialize = valid_materialize();
    materialize.materialization_jwt = "service-token".into();
    let error = service
        .domain_operation_proof_namespace_materialize(authenticated(materialize))
        .await
        .expect_err("materialize must reject a divergent verifier echo");
    assert_eq!(error.code(), Code::PermissionDenied);
    let mut retire = valid_retire();
    retire.retirement_permit_jwt = "service-token".into();
    let error = service
        .domain_operation_proof_namespace_retire(authenticated(retire))
        .await
        .expect_err("retire must reject a divergent verifier echo");
    assert_eq!(error.code(), Code::PermissionDenied);
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 4);
    assert_eq!(
        store.maintenance_calls(),
        0,
        "no maintenance store call may precede exact verifier echo validation"
    );
}

#[tokio::test]
async fn missing_claim_identity_digest_is_reported_as_verifier_version_skew() {
    let (service, store, verifier) = service();
    verifier
        .omit_claim_identity_digest
        .store(true, Ordering::SeqCst);

    let error = service
        .domain_operation_prepare(authenticated(valid_prepare()))
        .await
        .expect_err("a verifier without tag 16 must fail closed");
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(
        error.message().contains("claim-identity digest") && error.message().contains("verifier"),
        "version-skew error must identify the missing verifier carriage: {error}"
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.prepare_calls.load(Ordering::SeqCst),
        0,
        "missing verifier carriage must reject before receipt persistence"
    );
}

#[tokio::test]
async fn jwt_identity_bounds_reject_before_verifier_and_receipt_store() {
    for (field, token) in [
        (
            "issuer",
            AuthorizationToken {
                issuer: "i".repeat(257),
                ..service_token()
            },
        ),
        (
            "subject",
            AuthorizationToken {
                user_id: "s".repeat(257),
                ..service_token()
            },
        ),
    ] {
        let (service, store, verifier) = service();
        let error = service
            .domain_operation_prepare(authenticated_as(valid_prepare(), token))
            .await
            .err()
            .unwrap_or_else(|| panic!("oversized JWT {field} must reject"));
        assert_eq!(error.code(), Code::InvalidArgument, "JWT {field}");
        assert_eq!(
            verifier.calls.load(Ordering::SeqCst),
            0,
            "JWT {field} must reject before verifier I/O"
        );
        assert_eq!(
            store.prepare_calls.load(Ordering::SeqCst),
            0,
            "JWT {field} must reject before receipt-key SQL"
        );
    }
}

#[tokio::test]
async fn zero_high_water_retirement_decodes_and_reaches_the_handler_boundary() {
    let (service, store, verifier) = service();
    let mut request = valid_retire();
    request.final_high_water = 0;
    request.retirement_permit_jwt = "service-token".into();
    let raw = request.encode_to_vec();
    validate_proof_namespace_retire_raw(&raw)
        .expect("implicit absence of zero-valued final_high_water must be canonical");
    let decoded = DomainOperationProofNamespaceRetireRequestV1::decode(raw.as_slice())
        .expect("prost decodes the strict frame");

    let response = service
        .domain_operation_proof_namespace_retire(authenticated(decoded))
        .await
        .expect("zero high-water retirement reaches the store")
        .into_inner();
    assert_eq!(
        response.status,
        DomainOperationProofNamespaceRetireStatusV1::Mismatch as i32
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.retire_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn maintenance_handlers_reach_verifier_then_store_and_map_responses() {
    let (service, store, verifier) = service();

    let finalize = service
        .domain_operation_verified_stale_finalize(authenticated(valid_stale_finalize()))
        .await
        .expect("stale-finalize verifier and store succeed")
        .into_inner();
    assert_eq!(
        finalize.status,
        DomainOperationVerifiedStaleFinalizeStatus::Mismatch as i32
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.stale_finalize_calls.load(Ordering::SeqCst), 1);

    let attach = service
        .domain_operation_terminal_status_attach(authenticated(valid_terminal_attach_phase1()))
        .await
        .expect("terminal-attach verifier and store succeed")
        .into_inner();
    assert_eq!(
        attach.status,
        DomainOperationTerminalStatusAttachmentStatusV1::Mismatch as i32
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 2);
    assert_eq!(store.terminal_attach_calls.load(Ordering::SeqCst), 1);

    let mut materialize_request = valid_materialize();
    materialize_request.materialization_jwt = "service-token".into();
    let materialize = service
        .domain_operation_proof_namespace_materialize(authenticated(materialize_request))
        .await
        .expect("materialize verifier and store succeed")
        .into_inner();
    assert_eq!(
        materialize.status,
        DomainOperationProofNamespaceMaterializeStatusV1::Mismatch as i32
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 3);
    assert_eq!(store.materialize_calls.load(Ordering::SeqCst), 1);

    let mut retire_request = valid_retire();
    retire_request.retirement_permit_jwt = "service-token".into();
    let retire = service
        .domain_operation_proof_namespace_retire(authenticated(retire_request))
        .await
        .expect("retire verifier and store succeed")
        .into_inner();
    assert_eq!(
        retire.status,
        DomainOperationProofNamespaceRetireStatusV1::Mismatch as i32
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 4);
    assert_eq!(store.retire_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.maintenance_calls(), 4);
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
