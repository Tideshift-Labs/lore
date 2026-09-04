// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::str::FromStr;
use std::sync::Mutex;

use async_trait::async_trait;
use lore_base::runtime::LORE_CONTEXT;
use lore_postgres::domain::coordinator::ADMISSION_REJECTED_V1;
use lore_postgres::domain::coordinator::BranchDeleteInput;
use lore_postgres::domain::coordinator::BranchPushCommitInput;
use lore_postgres::domain::coordinator::DEFAULT_BRANCH_V1;
use lore_postgres::domain::coordinator::GENERATION_MISMATCH_V1;
use lore_postgres::domain::coordinator::MutationResult;
use lore_postgres::domain::coordinator::NOT_FOUND_V1;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;
use lore_postgres::domain::coordinator::RepositorySnapshot;
use lore_postgres::domain::coordinator::TOMBSTONED_V1;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::maintenance::ProofNamespaceMaterializeInput;
use lore_postgres::domain::maintenance::ProofNamespaceMaterializeReceipt;
use lore_postgres::domain::maintenance::ProofNamespaceRetireAck;
use lore_postgres::domain::maintenance::ProofNamespaceRetireInput;
use lore_postgres::domain::maintenance::TerminalStatusAttachInput;
use lore_postgres::domain::maintenance::TerminalStatusAttachmentAck;
use lore_postgres::domain::maintenance::VerifiedStaleFinalizeInput;
use lore_postgres::domain::maintenance::VerifiedStaleFinalizeResult;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptLookup;
use lore_proto::rebac::CreateResourceRequest;
use lore_proto::rebac::CreateResourceResponse;
use lore_proto::rebac::DeleteResourceRequest;
use lore_proto::rebac::DeleteResourceResponse;
use lore_revision::repository::RepositoryContext;
use rand::random;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::metadata::BinaryMetadataValue;
use uuid::Uuid;

use super::test_support::context;
use super::*;
use crate::authnz::rebac::RebacApiClient;
use crate::authnz::rebac::RebacApiResult;
use crate::grpc::domain_operation_metadata::CLAIM_WITNESS_KEY;
use crate::grpc::domain_operation_metadata::CLAIM_WITNESS_V1_LEN;
use crate::grpc::domain_operation_metadata::CLAIM_WITNESS_VERSION_V1;
use crate::grpc::domain_operation_metadata::ClaimWitness;
use crate::grpc::domain_operation_metadata::DomainOperationMetadata;
use crate::grpc::domain_operation_metadata::FINGERPRINT_KEY;
use crate::grpc::domain_operation_metadata::FINGERPRINT_V1_LEN;
use crate::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
use crate::grpc::domain_operation_metadata::MEDIATED_SCOPE_KEY;
use crate::grpc::domain_operation_metadata::MEDIATED_SCOPE_V1_LEN;
use crate::grpc::domain_operation_metadata::MediatedScope;
use crate::grpc::domain_operation_metadata::OPERATION_ID_KEY;
use crate::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
use crate::grpc::domain_operation_metadata::PREPARE_TOKEN_LEN;
use crate::grpc::domain_operation_metadata::scope_key_mediated_namespace;
use crate::grpc::handlers::repository_create::governed_repository_create;
use crate::grpc::handlers::repository_create::repository_create_auth_resource;

const ORG_UUID: [u8; 16] = [
    0x01, 0x91, 0x23, 0x45, 0x67, 0x89, 0x7a, 0xbc, 0x8d, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
];
const PRINCIPAL_NAMESPACE: [u8; 49] = *b"principal-v1\x0001912345-6789-7abc-8def-0123456789ac";

fn token(subject: &str, is_service_account: Option<bool>) -> AuthorizationToken {
    AuthorizationToken {
        issuer: "https://issuer.example".to_string(),
        user_id: subject.to_string(),
        is_service_account,
        ..Default::default()
    }
}

fn carriage(include_mediated_scope: bool) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    metadata.insert_bin(
        OPERATION_ID_KEY,
        BinaryMetadataValue::from_bytes(Uuid::now_v7().as_bytes()),
    );
    let mut fingerprint = vec![FINGERPRINT_VERSION_V1];
    fingerprint.extend(std::iter::repeat_n(0x42, FINGERPRINT_V1_LEN));
    metadata.insert_bin(
        FINGERPRINT_KEY,
        BinaryMetadataValue::from_bytes(&fingerprint),
    );
    metadata.insert_bin(
        PREPARE_TOKEN_KEY,
        BinaryMetadataValue::from_bytes(&[0x53; PREPARE_TOKEN_LEN]),
    );
    if include_mediated_scope {
        let mut scope = Vec::with_capacity(MEDIATED_SCOPE_V1_LEN);
        scope.push(1);
        scope.extend_from_slice(&ORG_UUID);
        scope.extend_from_slice(&PRINCIPAL_NAMESPACE);
        metadata.insert_bin(MEDIATED_SCOPE_KEY, BinaryMetadataValue::from_bytes(&scope));
    }
    metadata
}

fn direct_scope() -> GovernedScope<'static> {
    GovernedScope::TargetRepository {
        repository_id: &[0x77; 16],
    }
}

#[test]
fn exact_control_plane_service_uses_only_the_carried_mediated_scope() {
    let admitted = context(true)
        .admit(
            &carriage(true),
            Some(&token("lorehub-control-plane", Some(true))),
            direct_scope(),
        )
        .expect("exact service carriage must admit")
        .expect("enforced carriage must be governed");

    assert_eq!(
        admitted.key.tenant_scope_key,
        scope_key_mediated_namespace(&ORG_UUID, &PRINCIPAL_NAMESPACE)
            .expect("frozen mediated tuple must be canonical")
    );
}

#[test]
fn exact_control_plane_service_without_mediated_scope_fails_closed() {
    let error = context(true)
        .admit(
            &carriage(false),
            Some(&token("lorehub-control-plane", Some(true))),
            direct_scope(),
        )
        .expect_err("exact service absence must fail");
    assert_eq!(error.code(), Code::InvalidArgument);
}

#[test]
fn mediated_scope_is_refused_for_every_non_service_identity_shape() {
    let identities = [
        token("human-user", Some(false)),
        token("human-user", None),
        token("human-user", Some(true)),
        token("lorehub-control-plane", Some(false)),
        token("lorehub-control-plane", None),
    ];
    for identity in identities {
        let error = context(true)
            .admit(&carriage(true), Some(&identity), direct_scope())
            .expect_err("platform-only carriage must reject non-service identity");
        assert_eq!(error.code(), Code::InvalidArgument);
    }
}

#[test]
fn exact_org_and_principal_bytes_are_both_receipt_key_inputs() {
    let identity = token("lorehub-control-plane", Some(true));
    let expected = context(true)
        .admit(&carriage(true), Some(&identity), direct_scope())
        .expect("exact carriage must parse")
        .expect("exact carriage must govern")
        .key
        .tenant_scope_key;

    let mut changed_org = ORG_UUID;
    changed_org[0] ^= 0x01;
    assert_ne!(
        scope_key_mediated_namespace(&changed_org, &PRINCIPAL_NAMESPACE)
            .expect("changed org remains structurally valid"),
        expected
    );

    let mut changed_principal = PRINCIPAL_NAMESPACE;
    *changed_principal.last_mut().expect("namespace is nonempty") = b'd';
    assert_ne!(
        scope_key_mediated_namespace(&ORG_UUID, &changed_principal)
            .expect("changed principal remains structurally valid"),
        expected
    );
}

// ---------------------------------------------------------------------------
// WP-116 Part 2: `GovernedMetadataCas::commit`'s own mapping from a
// coordinator `MutationResult` to `MetadataCasOutcome`/`Status`.
//
// A standalone scripted store, not `test_support::ScriptedDomainStore` (which
// only scripts `branch_push_commit` and would need editing in `domain.rs`
// itself to add a second scriptable method -- avoided here to stay out of a
// file another lane is actively editing). `GovernedMetadataCas`'s fields are
// module-private, so this module (a declared child of `domain.rs`) can
// construct one directly via `use super::*`, the same way
// `branch_push::governed_tests`'s `build_governed` constructs a
// `GovernedPushCommit` directly, bypassing `admit_at_entry`/`AdmittedOperation`
// entirely: nothing under test here is admission logic.
//
// This proves the seam's OWN mapping in isolation, not that the real
// coordinator sets `observed_pointer` correctly on an actual CAS loss --
// that's `lore-postgres/tests/domain_outbox_producers.rs`'s job, against real
// Postgres. Together the two prove the full path: coordinator sets the value,
// seam propagates it unchanged.
// ---------------------------------------------------------------------------

struct MetadataCasScriptedStore {
    result: MutationResult,
}

impl MetadataCasScriptedStore {
    fn new(result: MutationResult) -> Self {
        Self { result }
    }
}

#[async_trait]
impl DomainTransactionStore for MetadataCasScriptedStore {
    async fn domain_operation_clock_get(&self) -> Result<std::time::SystemTime, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn domain_operation_prepare(
        &self,
        _key: &ReceiptKey,
        _binding: &OperationBinding,
        _witness: Option<&AuthorizationWitness>,
    ) -> Result<PrepareResult, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn domain_operation_receipt_get(
        &self,
        _key: &ReceiptKey,
        _binding: &OperationBinding,
    ) -> Result<ReceiptLookup, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn domain_operation_verified_stale_finalize(
        &self,
        _input: &VerifiedStaleFinalizeInput,
    ) -> Result<VerifiedStaleFinalizeResult, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn domain_operation_terminal_status_attach(
        &self,
        _input: &TerminalStatusAttachInput,
    ) -> Result<TerminalStatusAttachmentAck, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn domain_operation_proof_namespace_materialize(
        &self,
        _input: &ProofNamespaceMaterializeInput,
    ) -> Result<ProofNamespaceMaterializeReceipt, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn domain_operation_proof_namespace_retire(
        &self,
        _input: &ProofNamespaceRetireInput,
    ) -> Result<ProofNamespaceRetireAck, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn repository_snapshot(
        &self,
        _repository_id: &[u8],
    ) -> Result<Option<RepositorySnapshot>, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn branch_snapshot(
        &self,
        _repository_id: &[u8],
        _branch_id: &[u8],
    ) -> Result<Option<BranchSnapshot>, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn repository_create(
        &self,
        _operation: &GovernedOperation,
        _input: &RepositoryCreateInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn repository_delete(
        &self,
        _operation: &GovernedOperation,
        _input: &RepositoryDeleteInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn branch_delete(
        &self,
        _operation: &GovernedOperation,
        _input: &BranchDeleteInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn metadata_compare_and_swap(
        &self,
        _operation: &GovernedOperation,
        _input: &MetadataCasInput,
    ) -> Result<MutationResult, DomainError> {
        Ok(self.result.clone())
    }

    async fn branch_push_commit(
        &self,
        _operation: &GovernedOperation,
        _input: &BranchPushCommitInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }

    async fn begin_obliterate(
        &self,
        _operation: &GovernedOperation,
        _repository_id: &[u8],
        _event: Option<&PendingEvent>,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("MetadataCasScriptedStore only scripts metadata_compare_and_swap")
    }
}

fn dummy_metadata_cas_operation() -> GovernedOperation {
    GovernedOperation {
        key: ReceiptKey {
            verified_issuer: "https://issuer.example".to_owned(),
            authenticated_subject: "metadata-cas-scripted-test".to_owned(),
            tenant_scope_key: vec![7; 16],
            operation_id: Uuid::now_v7(),
        },
        binding: OperationBinding {
            method: "metadata_compare_and_swap".to_owned(),
            scope: vec![7; 16],
            fingerprint_version: 1,
            fingerprint: vec![8; 32],
            canonical_intent_digest: vec![9; 32],
        },
        prepare_token: [0u8; 32],
    }
}

fn build_governed_metadata_cas(result: MutationResult) -> GovernedMetadataCas {
    let store: Arc<dyn DomainTransactionStore> = Arc::new(MetadataCasScriptedStore::new(result));
    GovernedMetadataCas {
        domain: Arc::new(DomainContext::new(store, false)),
        operation: dummy_metadata_cas_operation(),
    }
}

fn empty_projection() -> ProjectionWrite {
    ProjectionWrite {
        partition: vec![1; 16],
        key_type: 0,
        key: vec![2; 32],
        value: Some(vec![3; 32]),
    }
}

/// An `Applied` `MutationResult` maps to `MetadataCasOutcome::Applied`.
#[tokio::test]
async fn commit_maps_applied_to_metadata_cas_outcome_applied() {
    let governed = build_governed_metadata_cas(MutationResult {
        outcome: DomainOutcome::Applied,
        repository_generation: Some(4),
        branch_generation: None,
        observed_pointer: None,
    });
    let outcome = governed
        .commit(
            &[1u8; 16],
            None,
            &[0u8; 32],
            &[9u8; 32],
            empty_projection(),
            None,
        )
        .await
        .expect("an Applied result must not error");
    assert!(matches!(outcome, MetadataCasOutcome::Applied));
}

/// A `CAS_MISMATCH_V1` result carrying `observed_pointer` maps to
/// `MetadataCasOutcome::Lost` with the exact observed bytes -- the property
/// wp116-producers flagged as most likely to regress into a `Status` mapping.
#[tokio::test]
async fn commit_maps_cas_mismatch_with_observed_pointer_to_lost_with_the_exact_bytes() {
    let observed = vec![0xABu8; 32];
    let governed = build_governed_metadata_cas(MutationResult::cas_lost(observed.clone()));
    let outcome = governed
        .commit(
            &[1u8; 16],
            None,
            &[0u8; 32],
            &[9u8; 32],
            empty_projection(),
            None,
        )
        .await
        .expect("a CAS loss with an observed pointer must not error");
    match outcome {
        MetadataCasOutcome::Lost(bytes) => assert_eq!(
            bytes, observed,
            "commit() must propagate the coordinator's observed_pointer unchanged, not the \
             caller's expected_hash or new_hash"
        ),
        MetadataCasOutcome::Applied => panic!("a CAS_MISMATCH_V1 result must never map to Applied"),
    }
}

/// The defensive branch: a `CAS_MISMATCH_V1` result with NO `observed_pointer`
/// is a coordinator defect by contract (the coordinator promises the pointer
/// on exactly this reason), and `commit()` must refuse to fabricate or empty
/// one -- it maps to `Status::internal`, never a reported CAS loss, because a
/// client would otherwise retry against a value nothing ever held. A correct
/// coordinator can never actually produce this shape; this test exists so a
/// future regression that drops `observed_pointer` on the mismatch path is
/// caught here rather than by a client seeing a wrong retry target.
#[tokio::test]
async fn commit_maps_cas_mismatch_without_observed_pointer_to_status_internal() {
    // `MetadataCasOutcome` has no `Debug` impl, so a plain `Result::expect_err`
    // can't be used here -- match explicitly instead.
    let governed = build_governed_metadata_cas(MutationResult::rejected(CAS_MISMATCH_V1));
    let result = governed
        .commit(
            &[1u8; 16],
            None,
            &[0u8; 32],
            &[9u8; 32],
            empty_projection(),
            None,
        )
        .await;
    let Err(error) = result else {
        panic!("a CAS_MISMATCH_V1 with no observed_pointer must be refused, not reported");
    };
    assert_eq!(error.code(), Code::Internal);
}

/// A non-CAS-mismatch rejection (e.g. a tombstoned target) still goes through
/// the ordinary rejection-to-status mapping, unaffected by the CAS-loss
/// special case.
#[tokio::test]
async fn commit_maps_a_non_cas_mismatch_rejection_through_the_ordinary_status_mapping() {
    let governed = build_governed_metadata_cas(MutationResult::rejected(TOMBSTONED_V1));
    let result = governed
        .commit(
            &[1u8; 16],
            None,
            &[0u8; 32],
            &[9u8; 32],
            empty_projection(),
            None,
        )
        .await;
    let Err(error) = result else {
        panic!("a tombstoned target must not be reported as a CAS loss");
    };
    assert_eq!(error.code(), Code::NotFound);
}

// ---------------------------------------------------------------------------
// WP-116 Part 3: `GovernedRepositoryCreate`'s own seam.
//
// `prepare`'s enforcement-off refusal (the 2026-09-03 ruling: a cell whose
// coordinator exists but is not enforcing must refuse governed create
// carriage with `FAILED_PRECONDITION` rather than silently downgrade to the
// legacy path) and `commit`'s outcome/rejection mapping, readback-not-
// published metadata pointer, and its own construction of the two CR-032
// events it owes.
//
// Another standalone scripted store, for the same reason
// `MetadataCasScriptedStore` is standalone rather than
// `test_support::ScriptedDomainStore`: this seam needs `repository_create`
// AND `repository_snapshot` scripted together, and capturing the exact
// `RepositoryCreateInput` the seam builds -- proving what `commit()` itself
// constructs (event count, order, and fields), complementary to
// `lore-postgres/tests/domain_outbox_producers.rs`'s proof that the
// COORDINATOR commits whatever `events` it is given correctly. Neither file
// alone proves the full path: this one proves the seam builds the right
// input; that one proves the coordinator commits it right.
// ---------------------------------------------------------------------------

struct RepositoryCreateScriptedStore {
    result: MutationResult,
    snapshot: Option<RepositorySnapshot>,
    captured_input: Arc<Mutex<Option<RepositoryCreateInput>>>,
}

#[async_trait]
impl DomainTransactionStore for RepositoryCreateScriptedStore {
    async fn domain_operation_clock_get(&self) -> Result<std::time::SystemTime, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }

    async fn domain_operation_prepare(
        &self,
        _key: &ReceiptKey,
        _binding: &OperationBinding,
        _witness: Option<&AuthorizationWitness>,
    ) -> Result<PrepareResult, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }

    async fn domain_operation_receipt_get(
        &self,
        _key: &ReceiptKey,
        _binding: &OperationBinding,
    ) -> Result<ReceiptLookup, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }

    async fn domain_operation_verified_stale_finalize(
        &self,
        _input: &VerifiedStaleFinalizeInput,
    ) -> Result<VerifiedStaleFinalizeResult, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }

    async fn domain_operation_terminal_status_attach(
        &self,
        _input: &TerminalStatusAttachInput,
    ) -> Result<TerminalStatusAttachmentAck, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }

    async fn domain_operation_proof_namespace_materialize(
        &self,
        _input: &ProofNamespaceMaterializeInput,
    ) -> Result<ProofNamespaceMaterializeReceipt, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }

    async fn domain_operation_proof_namespace_retire(
        &self,
        _input: &ProofNamespaceRetireInput,
    ) -> Result<ProofNamespaceRetireAck, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }

    async fn repository_snapshot(
        &self,
        _repository_id: &[u8],
    ) -> Result<Option<RepositorySnapshot>, DomainError> {
        Ok(self.snapshot.clone())
    }

    async fn branch_snapshot(
        &self,
        _repository_id: &[u8],
        _branch_id: &[u8],
    ) -> Result<Option<BranchSnapshot>, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }

    async fn repository_create(
        &self,
        _operation: &GovernedOperation,
        input: &RepositoryCreateInput,
    ) -> Result<MutationResult, DomainError> {
        *self.captured_input.lock().unwrap() = Some(input.clone());
        Ok(self.result.clone())
    }

    async fn repository_delete(
        &self,
        _operation: &GovernedOperation,
        _input: &RepositoryDeleteInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }

    async fn branch_delete(
        &self,
        _operation: &GovernedOperation,
        _input: &BranchDeleteInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }

    async fn metadata_compare_and_swap(
        &self,
        _operation: &GovernedOperation,
        _input: &MetadataCasInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }

    async fn branch_push_commit(
        &self,
        _operation: &GovernedOperation,
        _input: &BranchPushCommitInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }

    async fn begin_obliterate(
        &self,
        _operation: &GovernedOperation,
        _repository_id: &[u8],
        _event: Option<&PendingEvent>,
    ) -> Result<MutationResult, DomainError> {
        unreachable!(
            "RepositoryCreateScriptedStore only scripts repository_create/repository_snapshot"
        )
    }
}

fn dummy_create_operation() -> GovernedOperation {
    GovernedOperation {
        key: ReceiptKey {
            verified_issuer: "https://issuer.example".to_owned(),
            authenticated_subject: "repository-create-scripted-test".to_owned(),
            tenant_scope_key: vec![7; 16],
            operation_id: Uuid::now_v7(),
        },
        binding: OperationBinding {
            method: "repository_create".to_owned(),
            scope: vec![7; 16],
            fingerprint_version: 1,
            fingerprint: vec![8; 32],
            canonical_intent_digest: vec![9; 32],
        },
        prepare_token: [0u8; 32],
    }
}

/// Build a `GovernedRepositoryCreate` directly, bypassing `prepare`/admission
/// entirely -- nothing under test in `commit()` is admission logic. Returns
/// the handle plus the shared cell the scripted store records its captured
/// `RepositoryCreateInput` into.
fn build_governed_repository_create(
    result: MutationResult,
    snapshot: Option<RepositorySnapshot>,
    cell_id: Option<&str>,
) -> (
    GovernedRepositoryCreate,
    Arc<Mutex<Option<RepositoryCreateInput>>>,
) {
    let captured_input = Arc::new(Mutex::new(None));
    let store: Arc<dyn DomainTransactionStore> = Arc::new(RepositoryCreateScriptedStore {
        result,
        snapshot,
        captured_input: Arc::clone(&captured_input),
    });
    let domain = Arc::new(DomainContext::new(store, true).with_cell_id(cell_id.map(str::to_owned)));
    let governed = GovernedRepositoryCreate {
        domain,
        operation: dummy_create_operation(),
        create_witness: None,
    };
    (governed, captured_input)
}

struct DummyPublicationBytes {
    repository_id: [u8; 16],
    metadata_hash: [u8; 32],
    default_branch_id: [u8; 16],
    default_branch_metadata_hash: [u8; 32],
    default_branch_latest_hash: [u8; 32],
}

fn dummy_publication_bytes() -> DummyPublicationBytes {
    DummyPublicationBytes {
        repository_id: [7u8; 16],
        metadata_hash: [8u8; 32],
        default_branch_id: [9u8; 16],
        default_branch_metadata_hash: [10u8; 32],
        default_branch_latest_hash: [11u8; 32],
    }
}

impl DummyPublicationBytes {
    fn publication(&self) -> RepositoryCreatePublication<'_> {
        RepositoryCreatePublication {
            salt: b"test-salt",
            repository_id: &self.repository_id,
            name: "my-repo",
            metadata_hash: &self.metadata_hash,
            default_branch_id: &self.default_branch_id,
            default_branch_name: "main",
            default_branch_metadata_hash: &self.default_branch_metadata_hash,
            default_branch_latest_hash: &self.default_branch_latest_hash,
        }
    }

    fn snapshot(&self, generation: i64) -> RepositorySnapshot {
        RepositorySnapshot {
            repository_id: self.repository_id.to_vec(),
            live: true,
            generation,
            name: "my-repo".to_string(),
            metadata_hash: self.metadata_hash.to_vec(),
            default_branch_id: self.default_branch_id.to_vec(),
        }
    }

    fn applied_result(&self, repository_generation: i64) -> MutationResult {
        MutationResult {
            outcome: DomainOutcome::Applied,
            repository_generation: Some(repository_generation),
            branch_generation: Some(1),
            observed_pointer: None,
        }
    }
}

/// `GovernedRepositoryCreate::prepare` with no admitted operation is the
/// legacy carve-out, exactly like every other governed seam's `Ok(None)`
/// path -- proven here independent of `domain` (never inspected before the
/// early return).
#[test]
fn prepare_with_no_admitted_operation_is_the_legacy_path() {
    let result = GovernedRepositoryCreate::prepare(None, None, vec![0u8; 32]);
    assert!(matches!(result, Ok(None)));
}

/// The 2026-09-03 ruling: an admitted operation against a cell whose
/// coordinator exists but is not enforcing is refused `FAILED_PRECONDITION`,
/// never silently downgraded to the legacy path.
#[test]
fn prepare_refuses_carriage_when_enforcement_is_off() {
    let domain = Arc::new(context(false));
    let admitted = AdmittedOperation {
        key: ReceiptKey {
            verified_issuer: "https://issuer.example".to_owned(),
            authenticated_subject: "prepare-enforcement-off-test".to_owned(),
            tenant_scope_key: vec![7; 16],
            operation_id: Uuid::now_v7(),
        },
        carried: DomainOperationMetadata {
            operation_id: Uuid::now_v7(),
            fingerprint_version: i32::from(FINGERPRINT_VERSION_V1),
            fingerprint: vec![0x42; FINGERPRINT_V1_LEN],
            prepare_token: [0x53; PREPARE_TOKEN_LEN],
            mediated_scope: None,
            claim_witness: None,
        },
    };
    // `GovernedRepositoryCreate` has no `Debug` impl, so `Result::expect_err`
    // (which requires the `Ok` side to be `Debug`) can't be used here -- match
    // explicitly instead, matching this file's other `Debug`-less-type
    // convention (see `commit_maps_cas_mismatch_without_observed_pointer_to_status_internal`
    // above).
    let result = GovernedRepositoryCreate::prepare(Some(&domain), Some(admitted), vec![0u8; 32]);
    let Err(error) = result else {
        panic!("carriage with enforcement off must be refused, not admitted");
    };
    assert_eq!(error.code(), Code::FailedPrecondition);
}

/// The mirror case: the same admitted operation against a cell that IS
/// enforcing is accepted.
#[test]
fn prepare_admits_carriage_when_enforcement_is_on() {
    let domain = Arc::new(context(true));
    let admitted = AdmittedOperation {
        key: ReceiptKey {
            verified_issuer: "https://issuer.example".to_owned(),
            authenticated_subject: "prepare-enforcement-on-test".to_owned(),
            tenant_scope_key: vec![7; 16],
            operation_id: Uuid::now_v7(),
        },
        carried: DomainOperationMetadata {
            operation_id: Uuid::now_v7(),
            fingerprint_version: i32::from(FINGERPRINT_VERSION_V1),
            fingerprint: vec![0x42; FINGERPRINT_V1_LEN],
            prepare_token: [0x53; PREPARE_TOKEN_LEN],
            mediated_scope: None,
            claim_witness: None,
        },
    };
    let result = GovernedRepositoryCreate::prepare(Some(&domain), Some(admitted), vec![0u8; 32])
        .expect("carriage with enforcement on must be admitted");
    assert!(result.is_some());
}

/// `commit()` with a cell identity configured builds exactly the two CR-032
/// rows a create owes -- `repository.published` then `branch.created`, per
/// `event-kinds.json` -- and passes them to the coordinator in that order.
#[tokio::test]
async fn commit_with_cell_id_configured_builds_both_pinned_events_in_order() {
    let bytes = dummy_publication_bytes();
    let (governed, captured) = build_governed_repository_create(
        bytes.applied_result(1),
        Some(bytes.snapshot(1)),
        Some("cell-a"),
    );

    let outcome = governed
        .commit(&bytes.publication())
        .await
        .expect("an Applied result must not error");
    assert_eq!(outcome.repository_generation, Some(1));

    let input = captured
        .lock()
        .unwrap()
        .take()
        .expect("repository_create must have been called");
    assert_eq!(
        input.events.len(),
        2,
        "a create with a configured cell_id must build exactly two events"
    );
    assert_eq!(input.events[0].event_kind, "repository.published");
    assert_eq!(input.events[0].aggregate_kind, "repository");
    assert_eq!(input.events[0].aggregate_id, bytes.repository_id);
    assert_eq!(input.events[1].event_kind, "branch.created");
    assert_eq!(input.events[1].aggregate_kind, "branch");
    assert_eq!(input.events[1].aggregate_id, bytes.default_branch_id);
}

/// The companion negative: no configured cell identity builds no events at
/// all, per `DomainContext::cell_id`'s own contract (a cell with no `cell_id`
/// still mutates and simply produces no outbox rows).
#[tokio::test]
async fn commit_with_no_cell_id_configured_builds_no_events() {
    let bytes = dummy_publication_bytes();
    let (governed, captured) =
        build_governed_repository_create(bytes.applied_result(1), Some(bytes.snapshot(1)), None);

    governed
        .commit(&bytes.publication())
        .await
        .expect("an Applied result must not error");

    let input = captured
        .lock()
        .unwrap()
        .take()
        .expect("repository_create must have been called");
    assert!(
        input.events.is_empty(),
        "a cell with no configured cell_id must build no events"
    );
}

/// `commit()` reports the domain row's actually-committed metadata pointer,
/// not the one this call published -- they differ on an exact retry whose
/// metadata moved between the original create and the retry.
#[tokio::test]
async fn commit_reads_back_the_committed_metadata_pointer_rather_than_the_published_one() {
    let bytes = dummy_publication_bytes();
    let committed_metadata_hash = [99u8; 32];
    let mut snapshot = bytes.snapshot(3);
    snapshot.metadata_hash = committed_metadata_hash.to_vec();
    let (governed, _captured) =
        build_governed_repository_create(bytes.applied_result(3), Some(snapshot), Some("cell-a"));

    let outcome = governed
        .commit(&bytes.publication())
        .await
        .expect("an Applied result must not error");
    assert_eq!(
        outcome.metadata_hash,
        Hash::from(committed_metadata_hash.as_slice()),
        "the outcome must report the domain row's actually-committed pointer"
    );
    assert_ne!(
        outcome.metadata_hash,
        Hash::from(bytes.metadata_hash.as_slice()),
        "the outcome must not report the hash this call merely published"
    );
}

/// `TOMBSTONED_V1` is overridden to `ALREADY_EXISTS` for create specifically
/// -- the shared mapper's `NOT_FOUND` (non-disclosure for an operation on a
/// repository the caller may not know exists) is the wrong contract here: the
/// caller chose the identity itself, so the answer discloses only that its
/// own id is already spent.
#[tokio::test]
async fn commit_maps_tombstoned_v1_to_already_exists_not_the_shared_not_found() {
    let bytes = dummy_publication_bytes();
    let (governed, _captured) = build_governed_repository_create(
        MutationResult::rejected(TOMBSTONED_V1),
        None,
        Some("cell-a"),
    );

    // `RepositoryCreateOutcome` has no `Debug` impl either -- same pattern.
    let result = governed.commit(&bytes.publication()).await;
    let Err(error) = result else {
        panic!("a tombstoned repository id must be refused");
    };
    assert_eq!(error.code(), Code::AlreadyExists);
}

/// A rejection create does not specially handle (an admission-rail failure,
/// not a statement about the repository) still goes through the shared
/// mapper unchanged.
#[tokio::test]
async fn commit_maps_a_non_tombstoned_rejection_through_the_shared_mapper() {
    let bytes = dummy_publication_bytes();
    let (governed, _captured) = build_governed_repository_create(
        MutationResult::rejected(ADMISSION_REJECTED_V1),
        None,
        Some("cell-a"),
    );

    let result = governed.commit(&bytes.publication()).await;
    let Err(error) = result else {
        panic!("an admission rejection must be refused");
    };
    assert_eq!(error.code(), Code::FailedPrecondition);
}

// ---------------------------------------------------------------------------
// WP-119 Part D reviewer gap: `RepositoryDeletePublication::projection()` and
// `GovernedRepositoryDelete::commit`'s fenced-on-`RepositoryDeleteProof`
// refusal had zero executed coverage. Both were confirmed row-exact/correct
// against the legacy handlers by source read, which is not an executed
// check; these pin the current shape so a regression is caught rather than
// re-confirmed by another read.
// ---------------------------------------------------------------------------

/// `projection()` reproduces exactly 2 + 3N rows (minus one per branch with
/// an empty name, which skips its `BranchId` row -- the legacy path's own
/// `delete_name_to_id` is skipped there too), every row a delete (`value:
/// None`), with the exact `KeyType`/partition/key-derivation shape the
/// legacy v0 and v1 delete handlers build by hand.
///
/// Independently reproduces each row's key through the same primitive
/// `hash::hash_function_arg`/`hash_function_args` the legacy handlers call,
/// rather than trusting `projection()` to grade itself: a wrong function tag,
/// wrong argument order, or a missed `.to_lowercase()` on the branch-name key
/// would still produce a `Hash`, just the wrong one, and only an independent
/// recomputation catches that.
#[test]
fn projection_reproduces_two_plus_three_n_rows_matching_the_legacy_key_derivation() {
    let salt = b"wp119-part-d-salt";
    let repository_id = [0x11u8; 16];
    let name = "my-deleted-repo";
    let named_branch = RepositoryDeleteBranch {
        branch_id: [0x22u8; 16].to_vec(),
        name: "Feature/Some-Branch".to_owned(),
    };
    let empty_name_branch = RepositoryDeleteBranch {
        branch_id: [0x33u8; 16].to_vec(),
        name: String::new(),
    };
    let branches = [named_branch.clone(), empty_name_branch.clone()];
    let publication = RepositoryDeletePublication {
        salt,
        repository_id: &repository_id,
        name,
        expected_generation: Some(4),
        branches: &branches,
        delete_proof: RepositoryDeleteProof::Unfrozen,
    };

    let rows = publication.projection();
    assert_eq!(
        rows.len(),
        7,
        "2 base rows + 3 for the named branch + 2 for the empty-name branch (BranchId skipped)"
    );
    assert!(
        rows.iter().all(|row| row.value.is_none()),
        "every projection row is a delete"
    );

    let repository_hex = hex::encode(repository_id);
    let global_partition = RepositoryId::default().data().to_vec();

    assert_eq!(rows[0].key_type, KeyType::RepositoryMetadata as i16);
    assert_eq!(rows[0].partition, repository_id.to_vec());
    assert_eq!(
        rows[0].key,
        hash::hash_function_arg(salt, repository::METADATA, &repository_hex).as_ref()
    );

    assert_eq!(rows[1].key_type, KeyType::RepositoryId as i16);
    assert_eq!(rows[1].partition, global_partition);
    assert_eq!(
        rows[1].key,
        hash::hash_function_arg(salt, repository::ID, name).as_ref()
    );

    let named_branch_hex = hex::encode(named_branch.branch_id);
    assert_eq!(rows[2].key_type, KeyType::BranchMetadata as i16);
    assert_eq!(rows[2].partition, repository_id.to_vec());
    assert_eq!(
        rows[2].key,
        hash::hash_function_args(salt, branch::METADATA, &repository_hex, &named_branch_hex)
            .as_ref()
    );
    assert_eq!(rows[3].key_type, KeyType::BranchLatestPointer as i16);
    assert_eq!(rows[3].partition, repository_id.to_vec());
    assert_eq!(
        rows[3].key,
        hash::hash_function_args(salt, branch::LATEST, &repository_hex, &named_branch_hex).as_ref()
    );
    assert_eq!(rows[4].key_type, KeyType::BranchId as i16);
    assert_eq!(rows[4].partition, repository_id.to_vec());
    assert_eq!(
        rows[4].key,
        hash::hash_function_arg(salt, branch::ID, &named_branch.name.to_lowercase()).as_ref(),
        "the branch-id key folds the name to lowercase, matching the name-to-id row's own key"
    );

    let empty_branch_hex = hex::encode(empty_name_branch.branch_id);
    assert_eq!(rows[5].key_type, KeyType::BranchMetadata as i16);
    assert_eq!(
        rows[5].key,
        hash::hash_function_args(salt, branch::METADATA, &repository_hex, &empty_branch_hex)
            .as_ref()
    );
    assert_eq!(rows[6].key_type, KeyType::BranchLatestPointer as i16);
    assert_eq!(
        rows[6].key,
        hash::hash_function_args(salt, branch::LATEST, &repository_hex, &empty_branch_hex).as_ref()
    );
    assert!(
        !rows
            .iter()
            .any(|row| row.key_type == KeyType::BranchId as i16
                && row.key == hash::hash_function_arg(salt, branch::ID, "").as_ref()),
        "an empty branch name must retire no BranchId row, matching the legacy path's own \
         skipped delete_name_to_id call"
    );
}

/// A repository with no branches at all still owes its two base rows and
/// nothing else.
#[test]
fn projection_with_no_branches_is_exactly_the_two_base_rows() {
    let publication = RepositoryDeletePublication {
        salt: b"wp119-part-d-salt",
        repository_id: &[0x44u8; 16],
        name: "no-branches-repo",
        expected_generation: None,
        branches: &[],
        delete_proof: RepositoryDeleteProof::Unfrozen,
    };
    let rows = publication.projection();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].key_type, KeyType::RepositoryMetadata as i16);
    assert_eq!(rows[1].key_type, KeyType::RepositoryId as i16);
}

/// `GovernedRepositoryDelete::commit` refuses on `RepositoryDeleteProof::Unfrozen`
/// before it builds a projection, derives an event, or reaches the
/// coordinator -- `UnreachableDomainStore` backs the domain context, so a
/// regression that called into the store at all would panic the test rather
/// than merely fail an assertion.
#[tokio::test]
async fn commit_refuses_on_the_unfrozen_delete_proof_before_touching_the_coordinator() {
    let domain = Arc::new(context(true));
    let mut operation = dummy_create_operation();
    operation.binding.method = "repository_delete".to_owned();
    let governed = GovernedRepositoryDelete { domain, operation };
    let publication = RepositoryDeletePublication {
        salt: b"wp119-part-d-salt",
        repository_id: &[0x55u8; 16],
        name: "unfrozen-proof-repo",
        expected_generation: None,
        branches: &[],
        delete_proof: RepositoryDeleteProof::Unfrozen,
    };

    let result = governed.commit(&publication).await;
    let Err(error) = result else {
        panic!("an unfrozen delete_proof must refuse, not commit");
    };
    assert_eq!(error.code(), Code::Unimplemented);
}

// ---------------------------------------------------------------------------
// GovernedBranchDelete: fenced the same way GovernedRepositoryDelete is, on two
// missing artefacts (BranchDeleteProof::Unfrozen, and the absent
// CanonicalIntent::BranchDelete family), so `prepare`/`commit`'s own admission
// and proof-refusal logic is what's reachable and testable here -- the
// coordinator call inside `publish()` is not reachable through `commit()`
// today, the same shape as GovernedRepositoryDelete's own tests above.
// ---------------------------------------------------------------------------

fn dummy_branch_delete_operation() -> GovernedOperation {
    let mut operation = dummy_create_operation();
    operation.binding.method = "branch_delete".to_owned();
    operation
}

/// `GovernedBranchDelete::prepare` with no admitted operation is the legacy
/// carve-out, exactly like every other governed seam's `Ok(None)` path.
#[test]
fn branch_delete_prepare_with_no_admitted_operation_is_the_legacy_path() {
    let result = GovernedBranchDelete::prepare(None, None, "branch_delete", vec![0u8; 32]);
    assert!(matches!(result, Ok(None)));
}

/// The same 2026-09-03 ruling `GovernedRepositoryCreate`/`GovernedRepositoryDelete`
/// already carry: an admitted operation against a cell whose coordinator exists
/// but is not enforcing is refused `FAILED_PRECONDITION`, never silently
/// downgraded to the legacy path.
#[test]
fn branch_delete_prepare_refuses_carriage_when_enforcement_is_off() {
    let domain = Arc::new(context(false));
    let admitted = AdmittedOperation {
        key: ReceiptKey {
            verified_issuer: "https://issuer.example".to_owned(),
            authenticated_subject: "branch-delete-prepare-enforcement-off-test".to_owned(),
            tenant_scope_key: vec![7; 16],
            operation_id: Uuid::now_v7(),
        },
        carried: DomainOperationMetadata {
            operation_id: Uuid::now_v7(),
            fingerprint_version: i32::from(FINGERPRINT_VERSION_V1),
            fingerprint: vec![0x42; FINGERPRINT_V1_LEN],
            prepare_token: [0x53; PREPARE_TOKEN_LEN],
            mediated_scope: None,
            claim_witness: None,
        },
    };
    // `GovernedBranchDelete` has no `Debug` impl -- match explicitly, same
    // convention as this file's other `Debug`-less-type cases.
    let result = GovernedBranchDelete::prepare(
        Some(&domain),
        Some(admitted),
        "branch_delete",
        vec![0u8; 32],
    );
    let Err(error) = result else {
        panic!("carriage with enforcement off must be refused, not admitted");
    };
    assert_eq!(error.code(), Code::FailedPrecondition);
}

/// The mirror case: the same admitted operation against a cell that IS
/// enforcing is accepted.
#[test]
fn branch_delete_prepare_admits_carriage_when_enforcement_is_on() {
    let domain = Arc::new(context(true));
    let admitted = AdmittedOperation {
        key: ReceiptKey {
            verified_issuer: "https://issuer.example".to_owned(),
            authenticated_subject: "branch-delete-prepare-enforcement-on-test".to_owned(),
            tenant_scope_key: vec![7; 16],
            operation_id: Uuid::now_v7(),
        },
        carried: DomainOperationMetadata {
            operation_id: Uuid::now_v7(),
            fingerprint_version: i32::from(FINGERPRINT_VERSION_V1),
            fingerprint: vec![0x42; FINGERPRINT_V1_LEN],
            prepare_token: [0x53; PREPARE_TOKEN_LEN],
            mediated_scope: None,
            claim_witness: None,
        },
    };
    let result = GovernedBranchDelete::prepare(
        Some(&domain),
        Some(admitted),
        "branch_delete",
        vec![0u8; 32],
    )
    .expect("carriage with enforcement on must be admitted");
    assert!(result.is_some());
}

/// `GovernedBranchDelete::commit` refuses on `BranchDeleteProof::Unfrozen`
/// before it builds a projection, derives an event, or reaches the
/// coordinator -- `UnreachableDomainStore` backs the domain context, so a
/// regression that called into the store at all would panic the test rather
/// than merely fail an assertion. Mirrors
/// `commit_refuses_on_the_unfrozen_delete_proof_before_touching_the_coordinator`
/// above, for the branch-delete seam's own (separate) proof type.
#[tokio::test]
async fn branch_delete_commit_refuses_on_the_unfrozen_delete_proof_before_touching_the_coordinator()
{
    let domain = Arc::new(context(true));
    let operation = dummy_branch_delete_operation();
    let governed = GovernedBranchDelete { domain, operation };
    let publication = BranchDeletePublication {
        salt: b"wp119-branch-delete-salt",
        repository_id: &[0x66u8; 16],
        branch_id: &[0x77u8; 16],
        name: "unfrozen-proof-branch",
        expected_generation: None,
        final_latest_hash: &[0x88u8; 32],
        delete_proof: BranchDeleteProof::Unfrozen,
    };

    let result = governed.commit(&publication).await;
    let Err(error) = result else {
        panic!("an unfrozen delete_proof must refuse, not commit");
    };
    assert_eq!(error.code(), Code::Unimplemented);
}

/// `BranchDeletePublication::projection()` reproduces exactly the one row the
/// legacy writer leaves (`lore_revision::branch::delete` calls only
/// `delete_name_to_id`, unlike a repository delete's 2 + 3N): `KeyType::BranchId`,
/// partitioned on the repository id, keyed by the same
/// `hash::hash_function_arg(salt, branch::ID, name.to_lowercase())` the legacy
/// path derives, and a delete (`value: None`).
///
/// Independently reproduces the key through the same primitive the legacy
/// writer calls, rather than trusting `projection()` to grade itself -- a wrong
/// function tag, wrong argument, or a missed `.to_lowercase()` would still
/// produce a `Hash`, just the wrong one.
#[test]
fn branch_delete_projection_reproduces_the_one_row_matching_the_legacy_key_derivation() {
    let salt = b"wp119-branch-delete-projection-salt";
    let repository_id = [0x11u8; 16];
    let branch_id = [0x22u8; 16];
    let name = "Feature/Some-Branch";
    let publication = BranchDeletePublication {
        salt,
        repository_id: &repository_id,
        branch_id: &branch_id,
        name,
        expected_generation: Some(4),
        final_latest_hash: &[0x99u8; 32],
        delete_proof: BranchDeleteProof::Unfrozen,
    };

    let rows = publication.projection();
    assert_eq!(
        rows.len(),
        1,
        "a branch delete retires exactly one lore_mutable row, not the 2 + 3N a repository \
         delete does"
    );
    assert!(
        rows[0].value.is_none(),
        "the one projection row is a delete"
    );
    assert_eq!(rows[0].key_type, KeyType::BranchId as i16);
    assert_eq!(rows[0].partition, repository_id.to_vec());
    assert_eq!(
        rows[0].key,
        hash::hash_function_arg(salt, branch::ID, &name.to_lowercase()).as_ref(),
        "the key must fold the name to lowercase, matching branch::mutable_name_key"
    );
}

// ---------------------------------------------------------------------------
// WP-119 Phase 8 reviewer gap: `DomainContext::attach_admission` (`wiring.rs`
// calls this once, from `configure_event_relay`, after every startup
// precondition passes) must refuse a second handle rather than replacing the
// first -- two gates over one cell would mean two caches and a coin flip
// over which verdict a mutation reads. Offline: `attach_admission` and
// `admission` are both plain `OnceLock` operations, and `OutboxAdmission::new`
// takes a `Pool`, which `build_pool` constructs lazily (no connection is
// opened until first use), so this needs no live Postgres.
// ---------------------------------------------------------------------------

fn unconnected_admission() -> Arc<crate::event_relay::admission::OutboxAdmission> {
    let pool = lore_postgres::pool::build_pool(
        "postgresql://unused@127.0.0.1:1/unused",
        1,
        &lore_postgres::pool::TlsConfig::default(),
    )
    .expect("build_pool constructs lazily and must not dial anything");
    Arc::new(crate::event_relay::admission::OutboxAdmission::new(
        pool,
        lore_postgres::domain::outbox::relay::AdmissionLimits::default(),
    ))
}

#[test]
fn attach_admission_succeeds_once_and_refuses_a_second_handle() {
    let domain = context(true);
    let first = unconnected_admission();
    domain
        .attach_admission(first.clone())
        .expect("the first attach must succeed");

    let second = unconnected_admission();
    let rejected = domain
        .attach_admission(second.clone())
        .expect_err("a second attach must be refused, not silently replace the first");
    assert!(
        Arc::ptr_eq(&rejected, &second),
        "the refusal must hand back the exact handle that was rejected"
    );

    let attached = domain
        .admission()
        .expect("a successfully attached gate must be readable back");
    assert!(
        Arc::ptr_eq(attached, &first),
        "the ORIGINAL handle must remain attached after a refused second attach, not the rejected one"
    );
}

// ---------------------------------------------------------------------------
// WP-119: `map_branch_delete_rejection`, the branch-delete seam's own mapper.
//
// A pure function, and the one place where a permanent, actionable refusal can
// silently become an opaque server error. `DEFAULT_BRANCH_V1` is a reason only
// this family produces, so the shared `crate::grpc::map_domain_rejection_to_status`
// does not know it and its unrecognised-reason arm answers
// `Status::internal("Internal error")`. If the local arm is ever dropped, a
// caller that tried to delete the default branch stops being told a rule it can
// act on and starts getting a server fault, and no other test in this file or
// in the real-Postgres tier would notice: the coordinator would still commit the
// correct decisive `NOT_APPLIED`, and only the gRPC code a client sees changes.
// ---------------------------------------------------------------------------

#[test]
fn the_branch_delete_mapper_answers_its_own_reason_and_defers_every_other() {
    // The one reason this family owns.
    assert_eq!(
        map_branch_delete_rejection(DEFAULT_BRANCH_V1).code(),
        Code::FailedPrecondition,
        "deleting the default branch is a rule the caller can act on, and it is \
         what the ungoverned handlers already answer for the same refusal"
    );

    // Deferral to the shared mapper, proven with reasons whose codes DIFFER
    // from the arm above. Asserting only on a reason that also maps to
    // `FailedPrecondition` would pass with the deferral removed entirely.
    assert_eq!(
        map_branch_delete_rejection(NOT_FOUND_V1).code(),
        Code::NotFound,
        "the shared vocabulary must survive: a local arm that swallowed \
         everything would answer FailedPrecondition here"
    );
    assert_eq!(
        map_branch_delete_rejection(GENERATION_MISMATCH_V1).code(),
        Code::Aborted,
        "a stale generation is retryable and must stay Aborted, unlike the \
         permanent default-branch refusal"
    );
    assert_eq!(
        map_branch_delete_rejection(TOMBSTONED_V1).code(),
        Code::NotFound,
        "a tombstoned target is indistinguishable from an absent one by \
         contract, and that non-disclosure rule lives in the shared mapper"
    );

    // An unrecognised reason must NOT be guessed into a plausible code. The
    // shared mapper refuses to invent one, because a wrong code can instruct a
    // client to retry a decisive rejection forever.
    assert_eq!(
        map_branch_delete_rejection("SOME_REASON_NOBODY_DEFINED_V1").code(),
        Code::Internal,
        "vocabulary drift must surface as Internal, never as a guessed code"
    );

    // The two codes that must never be confused, stated as a relation rather
    // than as two independent constants: the whole reason the default-branch
    // check runs BEFORE the generation fence in the coordinator is that one is
    // permanent and the other tells the caller to try again.
    assert_ne!(
        map_branch_delete_rejection(DEFAULT_BRANCH_V1).code(),
        map_branch_delete_rejection(GENERATION_MISMATCH_V1).code(),
        "a permanent refusal and a retryable one must not share a code"
    );
}

// ---------------------------------------------------------------------------
// WP-116 governed create witness: the platform claim `hasGovernedCreateWitness`
// flip. Three downstream consumers of `CLAIM_WITNESS_KEY`
// (`grpc::domain_operation_metadata`'s own header parsing is that module's
// coverage, not this file's): `DomainContext::admit`'s mediated-only gate,
// `GovernedRepositoryCreate::prepare`'s witness assembly, and
// `repository_create_auth_resource`'s `CreateResourceRequest` population plus
// its response-acknowledgement check.
//
// `claim_witness_wire_bytes` re-derives the 161-byte wire layout by hand from
// the documented offsets (`domain_operation_metadata.rs`'s own PIN comment),
// independent of `ClaimWitness` parsing itself -- the same "reproduce, don't
// round-trip" shape every other fixed-width-header fixture in this file uses.
// ---------------------------------------------------------------------------

fn claim_witness_fixture() -> ClaimWitness {
    ClaimWitness {
        claim_id: [0x61; 16],
        claim_revision: 7,
        claim_verification_witness: [0x62; 32],
        authorization_revision: 3,
        verification_nonce: [0x63; 32],
        bound_fields_digest: [0x64; 32],
        consumed_ticket_sha256: [0x65; 32],
    }
}

fn claim_witness_wire_bytes(witness: &ClaimWitness) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CLAIM_WITNESS_V1_LEN);
    bytes.push(CLAIM_WITNESS_VERSION_V1);
    bytes.extend_from_slice(&witness.claim_id);
    bytes.extend_from_slice(&witness.claim_revision.to_be_bytes());
    bytes.extend_from_slice(&witness.claim_verification_witness);
    bytes.extend_from_slice(&witness.authorization_revision.to_be_bytes());
    bytes.extend_from_slice(&witness.verification_nonce);
    bytes.extend_from_slice(&witness.bound_fields_digest);
    bytes.extend_from_slice(&witness.consumed_ticket_sha256);
    assert_eq!(
        bytes.len(),
        CLAIM_WITNESS_V1_LEN,
        "fixture layout drifted from CLAIM_WITNESS_V1_LEN"
    );
    bytes
}

fn carriage_with_claim(include_mediated_scope: bool, include_claim_witness: bool) -> MetadataMap {
    let mut metadata = carriage(include_mediated_scope);
    if include_claim_witness {
        metadata.insert_bin(
            CLAIM_WITNESS_KEY,
            BinaryMetadataValue::from_bytes(&claim_witness_wire_bytes(&claim_witness_fixture())),
        );
    }
    metadata
}

/// `admit()`'s own gate: a claim witness is control-plane-only, and it is
/// refused on a direct (non-mediated) operation even though the same carriage
/// carries a syntactically valid claim-witness header. Uses a non-service
/// identity so the earlier `(is_control_plane, mediated_scope)` match arm
/// (`"control-plane governed mutation is missing mediated-scope carriage"`)
/// cannot fire first and mask the assertion this test actually wants.
#[test]
fn admit_refuses_claim_witness_carried_without_mediated_scope() {
    let error = context(true)
        .admit(
            &carriage_with_claim(false, true),
            Some(&token("human-user", Some(false))),
            direct_scope(),
        )
        .expect_err("claim witness without mediated scope must be refused");
    assert_eq!(error.code(), Code::InvalidArgument);
}

/// The mirror case: a claim witness alongside a mediated scope, on the
/// control-plane service principal, is admitted, and the parsed
/// `claim_witness` survives unchanged into `AdmittedOperation`.
#[test]
fn admit_admits_claim_witness_carried_with_mediated_scope_on_the_control_plane() {
    let admitted = context(true)
        .admit(
            &carriage_with_claim(true, true),
            Some(&token("lorehub-control-plane", Some(true))),
            direct_scope(),
        )
        .expect("mediated carriage with a claim witness must admit")
        .expect("enforced carriage must be governed");

    assert_eq!(
        admitted.key.tenant_scope_key,
        scope_key_mediated_namespace(&ORG_UUID, &PRINCIPAL_NAMESPACE)
            .expect("frozen mediated tuple must be canonical")
    );
    assert_eq!(
        admitted.carried.claim_witness,
        Some(claim_witness_fixture())
    );
}

/// Build an `AdmittedOperation` for a mediated governed create directly (not
/// through header parsing, which is `domain_operation_metadata`'s own
/// coverage): a mediated scope always present, and the caller chooses whether
/// a claim witness rides along.
fn mediated_admitted_operation(claim_witness: Option<ClaimWitness>) -> AdmittedOperation {
    AdmittedOperation {
        key: ReceiptKey {
            verified_issuer: "https://issuer.example/create-witness".to_owned(),
            authenticated_subject: "lorehub-control-plane".to_owned(),
            tenant_scope_key: scope_key_mediated_namespace(&ORG_UUID, &PRINCIPAL_NAMESPACE)
                .expect("frozen mediated tuple must be canonical"),
            operation_id: Uuid::now_v7(),
        },
        carried: DomainOperationMetadata {
            operation_id: Uuid::now_v7(),
            fingerprint_version: i32::from(FINGERPRINT_VERSION_V1),
            fingerprint: vec![0x42; FINGERPRINT_V1_LEN],
            prepare_token: [0x53; PREPARE_TOKEN_LEN],
            mediated_scope: Some(MediatedScope {
                org_uuid: ORG_UUID,
                initiating_principal_namespace: PRINCIPAL_NAMESPACE,
            }),
            claim_witness,
        },
    }
}

/// A direct (non-mediated) governed create carries no platform claim at all --
/// `create_witness()` is `None`, not a degraded or partial witness.
#[test]
fn create_witness_is_none_for_a_direct_non_mediated_governed_create() {
    let domain = Arc::new(context(true));
    let admitted = AdmittedOperation {
        key: ReceiptKey {
            verified_issuer: "https://issuer.example".to_owned(),
            authenticated_subject: "direct-create-tester".to_owned(),
            tenant_scope_key: vec![7; 16],
            operation_id: Uuid::now_v7(),
        },
        carried: DomainOperationMetadata {
            operation_id: Uuid::now_v7(),
            fingerprint_version: i32::from(FINGERPRINT_VERSION_V1),
            fingerprint: vec![0x42; FINGERPRINT_V1_LEN],
            prepare_token: [0x53; PREPARE_TOKEN_LEN],
            mediated_scope: None,
            claim_witness: None,
        },
    };
    let governed = GovernedRepositoryCreate::prepare(Some(&domain), Some(admitted), vec![0u8; 32])
        .expect("carriage with enforcement on must be admitted")
        .expect("carriage must govern");
    assert!(
        governed.create_witness().is_none(),
        "a direct governed create (no mediated scope) must carry no platform claim witness"
    );
}

/// A mediated operation with no claim witness is refused before it ever
/// becomes a `GovernedRepositoryCreate` -- and therefore before the handler
/// could reach `repository_create_auth_resource`'s ReBAC callback at all,
/// since that call site only exists behind a successfully constructed
/// `GovernedRepositoryCreate`. `context(true)` backs an
/// `UnreachableDomainStore`: `prepare()` never touches the coordinator on any
/// path today, and this keeps that a proven property rather than an assumed
/// one -- a future regression that routed this refusal through the store
/// would panic this test instead of silently passing.
#[test]
fn prepare_refuses_mediated_scope_without_claim_witness_before_touching_the_coordinator() {
    let domain = Arc::new(context(true));
    let admitted = mediated_admitted_operation(None);

    let result = GovernedRepositoryCreate::prepare(Some(&domain), Some(admitted), vec![0u8; 32]);
    let Err(error) = result else {
        panic!("mediated carriage missing a claim witness must be refused, not admitted");
    };
    assert_eq!(error.code(), Code::InvalidArgument);
}

/// The full assembly: a mediated operation with both a mediated scope and a
/// claim witness admits, and `create_witness()` combines all three
/// provenances (the verified token, Lore's own validated carriage, and the
/// claim-witness header) into the exact `GovernedCreateWitness` the ReBAC
/// callback will send. `GovernedCreateWitness` has no `PartialEq`, so every
/// field is asserted individually rather than compared as a whole value.
#[tokio::test]
async fn prepare_assembles_the_full_create_witness_from_three_separate_provenances() {
    let domain = Arc::new(context(true));
    let claim = claim_witness_fixture();
    let admitted = mediated_admitted_operation(Some(claim.clone()));
    let expected_key = admitted.key.clone();
    let expected_carried = admitted.carried.clone();
    let digest = vec![0x77u8; 32];

    let governed = GovernedRepositoryCreate::prepare(Some(&domain), Some(admitted), digest.clone())
        .expect("mediated carriage with a claim witness must not error")
        .expect("mediated carriage with a claim witness must govern");

    let witness = governed
        .create_witness()
        .expect("a mediated governed create must carry the assembled witness");

    assert_eq!(witness.verified_issuer, expected_key.verified_issuer);
    assert_eq!(
        witness.authenticated_subject,
        expected_key.authenticated_subject
    );
    assert_eq!(witness.org_uuid, ORG_UUID);
    assert_eq!(witness.initiating_principal_namespace, PRINCIPAL_NAMESPACE);
    assert_eq!(witness.operation_id, *expected_key.operation_id.as_bytes());
    assert_eq!(witness.scope, expected_key.tenant_scope_key);
    assert_eq!(
        witness.fingerprint_version,
        u32::from(FINGERPRINT_VERSION_V1)
    );
    assert_eq!(witness.fingerprint, expected_carried.fingerprint);
    assert_eq!(witness.canonical_intent_digest, digest);
    assert_eq!(witness.prepare_token, expected_carried.prepare_token);
    assert_eq!(witness.claim, claim);
}

// ---------------------------------------------------------------------------
// `repository_create_auth_resource`: the `CreateResourceRequest` it builds and
// the `CreateResourceResponse` acknowledgement it requires. `GovernedCreateWitness`
// and `ClaimWitness` are constructed by hand here rather than through
// `admit`/`prepare` above -- this section is about the ReBAC wire shape, not
// about admission, and the two are proven independently.
// ---------------------------------------------------------------------------

fn create_witness_fixture() -> GovernedCreateWitness {
    GovernedCreateWitness {
        verified_issuer: "https://issuer.example/create-witness".to_owned(),
        authenticated_subject: "lorehub-control-plane".to_owned(),
        org_uuid: ORG_UUID,
        initiating_principal_namespace: PRINCIPAL_NAMESPACE,
        operation_id: [0x71; 16],
        scope: vec![0x72; 20],
        fingerprint_version: 1,
        fingerprint: vec![0x73; 32],
        canonical_intent_digest: vec![0x74; 32],
        prepare_token: [0x75; PREPARE_TOKEN_LEN],
        claim: claim_witness_fixture(),
    }
}

/// A single-use recording fake: captures the one request it receives and
/// returns a scripted response. `delete_resource` is `unreachable!` --
/// `repository_create_auth_resource` never calls it, and a regression that
/// did would panic this test rather than silently returning a default.
struct RecordingRebacClient {
    captured: Arc<Mutex<Option<CreateResourceRequest>>>,
    response: Arc<Mutex<Option<RebacApiResult<CreateResourceResponse>>>>,
}

#[async_trait]
impl RebacApiClient for RecordingRebacClient {
    async fn create_resource(
        &mut self,
        request: Request<CreateResourceRequest>,
    ) -> RebacApiResult<CreateResourceResponse> {
        *self.captured.lock().unwrap() = Some(request.into_inner());
        self.response
            .lock()
            .unwrap()
            .take()
            .expect("create_resource called more than once in a single-shot test double")
    }

    async fn delete_resource(
        &mut self,
        _request: Request<DeleteResourceRequest>,
    ) -> RebacApiResult<DeleteResourceResponse> {
        unreachable!("repository_create_auth_resource never calls delete_resource")
    }
}

fn recording_client(
    response: RebacApiResult<CreateResourceResponse>,
) -> (
    Box<dyn RebacApiClient + Send + Sync>,
    Arc<Mutex<Option<CreateResourceRequest>>>,
) {
    let captured = Arc::new(Mutex::new(None));
    let client = RecordingRebacClient {
        captured: Arc::clone(&captured),
        response: Arc::new(Mutex::new(Some(response))),
    };
    (Box::new(client), captured)
}

fn matching_response(witness: &GovernedCreateWitness) -> CreateResourceResponse {
    CreateResourceResponse {
        claim_id: witness.claim.claim_id.to_vec().into(),
        claim_revision: witness.claim.claim_revision,
        claim_verification_witness: witness.claim.claim_verification_witness.to_vec().into(),
    }
}

fn fixture_repository() -> (RepositoryId, &'static str) {
    let repo_name = "2fc8bf934117e250152eba9a1fc78e71";
    let repository: RepositoryId = Context::from_str(repo_name)
        .expect("fixture id must parse")
        .into();
    (repository, repo_name)
}

/// The legacy carve-out: `witness: None` sends exactly the pre-CR-029
/// request, with every one of tags 3-21 left at its prost default. This is
/// the property that keeps every ungoverned create off auth-grpc's
/// `hasGovernedCreateWitness` path. Checked field-by-field rather than via a
/// single struct comparison, so the pin does not depend on
/// `CreateResourceRequest` deriving `Debug`.
#[tokio::test]
async fn repository_create_auth_resource_with_no_witness_sends_the_byte_identical_legacy_request() {
    let (repository, repo_name) = fixture_repository();
    let (client, captured) = recording_client(Ok(Response::new(CreateResourceResponse::default())));

    repository_create_auth_resource(client, None, repository, repo_name, None)
        .await
        .expect("a legacy (non-witness) create must succeed");

    let request = captured
        .lock()
        .unwrap()
        .take()
        .expect("create_resource must have been called");
    assert_eq!(request.resource_id, format!("urc-{repository}"));
    assert_eq!(request.resource_name, repo_name);
    assert!(request.verified_issuer.is_empty());
    assert!(request.authenticated_subject.is_empty());
    assert!(request.org_uuid.is_empty());
    assert!(request.initiating_principal_namespace.is_empty());
    assert!(request.operation_id.is_empty());
    assert!(request.method.is_empty());
    assert!(request.scope.is_empty());
    assert_eq!(request.fingerprint_version, 0);
    assert!(request.fingerprint.is_empty());
    assert!(request.canonical_intent_digest.is_empty());
    assert!(request.authorization_id.is_empty());
    assert_eq!(request.authorization_revision, 0);
    assert!(request.verification_nonce.is_empty());
    assert!(request.bound_fields_digest.is_empty());
    assert!(request.consumed_ticket_sha256.is_empty());
    assert!(request.claim_id.is_empty());
    assert_eq!(request.claim_revision, 0);
    assert!(request.claim_verification_witness.is_empty());
    assert!(request.prepare_token.is_empty());
}

/// `Some(witness)` populates every one of tags 3-21, each field checked
/// individually against the witness, plus a non-default sweep proving no
/// field could be silently elided on the wire (auth-grpc's proto loader runs
/// with `defaults: false`, so a zero/empty field there is indistinguishable
/// from absent).
#[tokio::test]
async fn repository_create_auth_resource_with_a_witness_populates_every_governed_field_non_default()
{
    let (repository, repo_name) = fixture_repository();
    let witness = create_witness_fixture();
    let (client, captured) = recording_client(Ok(Response::new(matching_response(&witness))));

    repository_create_auth_resource(client, None, repository, repo_name, Some(&witness))
        .await
        .expect("a matching acknowledgement must succeed");

    let request = captured
        .lock()
        .unwrap()
        .take()
        .expect("create_resource must have been called");

    assert_eq!(request.resource_id, format!("urc-{repository}"));
    assert_eq!(request.resource_name, repo_name);
    assert_eq!(request.verified_issuer, witness.verified_issuer);
    assert_eq!(request.authenticated_subject, witness.authenticated_subject);
    assert_eq!(request.org_uuid.as_ref(), witness.org_uuid.as_slice());
    assert_eq!(
        request.initiating_principal_namespace.as_ref(),
        witness.initiating_principal_namespace.as_slice()
    );
    assert_eq!(
        request.operation_id.as_ref(),
        witness.operation_id.as_slice()
    );
    assert_eq!(
        request.method, PLATFORM_METHOD_REPOSITORY_CREATE,
        "the method tag is the fixed platform-family constant, not the gRPC binding method"
    );
    assert_eq!(request.scope.as_ref(), witness.scope.as_slice());
    assert_eq!(request.fingerprint_version, witness.fingerprint_version);
    assert_eq!(request.fingerprint.as_ref(), witness.fingerprint.as_slice());
    assert_eq!(
        request.canonical_intent_digest.as_ref(),
        witness.canonical_intent_digest.as_slice()
    );
    assert_eq!(
        request.authorization_id.as_ref(),
        witness.operation_id.as_slice(),
        "CR-029 freezes authorization_id to the operation id"
    );
    assert_eq!(
        request.authorization_revision,
        witness.claim.authorization_revision
    );
    assert_eq!(
        request.verification_nonce.as_ref(),
        witness.claim.verification_nonce.as_slice()
    );
    assert_eq!(
        request.bound_fields_digest.as_ref(),
        witness.claim.bound_fields_digest.as_slice()
    );
    assert_eq!(
        request.consumed_ticket_sha256.as_ref(),
        witness.claim.consumed_ticket_sha256.as_slice()
    );
    assert_eq!(request.claim_id.as_ref(), witness.claim.claim_id.as_slice());
    assert_eq!(request.claim_revision, witness.claim.claim_revision);
    assert_eq!(
        request.claim_verification_witness.as_ref(),
        witness.claim.claim_verification_witness.as_slice()
    );
    assert_eq!(
        request.prepare_token.as_ref(),
        witness.prepare_token.as_slice()
    );

    assert!(!request.verified_issuer.is_empty());
    assert!(!request.authenticated_subject.is_empty());
    assert!(!request.org_uuid.is_empty());
    assert!(!request.initiating_principal_namespace.is_empty());
    assert!(!request.operation_id.is_empty());
    assert!(!request.method.is_empty());
    assert!(!request.scope.is_empty());
    assert_ne!(request.fingerprint_version, 0);
    assert!(!request.fingerprint.is_empty());
    assert!(!request.canonical_intent_digest.is_empty());
    assert!(!request.authorization_id.is_empty());
    assert_ne!(request.authorization_revision, 0);
    assert!(!request.verification_nonce.is_empty());
    assert!(!request.bound_fields_digest.is_empty());
    assert!(!request.consumed_ticket_sha256.is_empty());
    assert!(!request.claim_id.is_empty());
    assert_ne!(request.claim_revision, 0);
    assert!(!request.claim_verification_witness.is_empty());
    assert!(!request.prepare_token.is_empty());
}

/// Three independent one-field-divergence cases: a `CreateResourceResponse`
/// diverging on exactly one of the three acknowledged claim fields must be
/// refused, never partially accepted.
#[tokio::test]
async fn repository_create_auth_resource_rejects_a_response_with_a_divergent_claim_id() {
    let (repository, repo_name) = fixture_repository();
    let witness = create_witness_fixture();
    let mut response = matching_response(&witness);
    response.claim_id = vec![0xFFu8; 16].into();
    let (client, _captured) = recording_client(Ok(Response::new(response)));

    let result =
        repository_create_auth_resource(client, None, repository, repo_name, Some(&witness)).await;
    assert!(
        result.is_err(),
        "a divergent claim_id acknowledgement must be refused, not accepted"
    );
}

#[tokio::test]
async fn repository_create_auth_resource_rejects_a_response_with_a_divergent_claim_revision() {
    let (repository, repo_name) = fixture_repository();
    let witness = create_witness_fixture();
    let mut response = matching_response(&witness);
    response.claim_revision += 1;
    let (client, _captured) = recording_client(Ok(Response::new(response)));

    let result =
        repository_create_auth_resource(client, None, repository, repo_name, Some(&witness)).await;
    assert!(
        result.is_err(),
        "a divergent claim_revision acknowledgement must be refused, not accepted"
    );
}

#[tokio::test]
async fn repository_create_auth_resource_rejects_a_response_with_a_divergent_claim_verification_witness()
 {
    let (repository, repo_name) = fixture_repository();
    let witness = create_witness_fixture();
    let mut response = matching_response(&witness);
    response.claim_verification_witness = vec![0xFFu8; 32].into();
    let (client, _captured) = recording_client(Ok(Response::new(response)));

    let result =
        repository_create_auth_resource(client, None, repository, repo_name, Some(&witness)).await;
    assert!(
        result.is_err(),
        "a divergent claim_verification_witness acknowledgement must be refused, not accepted"
    );
}

#[tokio::test]
async fn repository_create_auth_resource_rejects_an_empty_or_default_response() {
    let (repository, repo_name) = fixture_repository();
    let witness = create_witness_fixture();
    let (client, _captured) =
        recording_client(Ok(Response::new(CreateResourceResponse::default())));

    let result =
        repository_create_auth_resource(client, None, repository, repo_name, Some(&witness)).await;
    assert!(
        result.is_err(),
        "an empty/default acknowledgement must be refused for a governed create, not treated \
         as a claim"
    );
}

/// `Code::AlreadyExists` on the governed path carries no claim triple at all,
/// so it must not be treated as an acknowledgement even though the same code
/// is a success on the legacy path (the negative half of the pair below).
#[tokio::test]
async fn repository_create_auth_resource_governed_already_exists_is_not_an_acknowledgement() {
    let (repository, repo_name) = fixture_repository();
    let witness = create_witness_fixture();
    let (client, _captured) = recording_client(Err(Status::already_exists("")));

    let error =
        repository_create_auth_resource(client, None, repository, repo_name, Some(&witness))
            .await
            .expect_err(
                "AlreadyExists on the governed path carries no claim acknowledgement and must \
                 be refused",
            );
    assert_eq!(error.code(), Code::FailedPrecondition);
}

/// The positive half of the pair above: `AlreadyExists` on the legacy
/// (`witness: None`) path remains a success, exactly as it does today.
#[tokio::test]
async fn repository_create_auth_resource_ungoverned_already_exists_still_short_circuits_to_ok() {
    let (repository, repo_name) = fixture_repository();
    let (client, _captured) = recording_client(Err(Status::already_exists("")));

    repository_create_auth_resource(client, None, repository, repo_name, None)
        .await
        .expect("AlreadyExists on the legacy path must remain a success, as it does today");
}

// ---------------------------------------------------------------------------
// Two refusals added after a cold-review pass on the create seam. Both are
// misconfiguration guards, not carriage-validation logic, so they belong at
// this level (the shared `governed_repository_create` body and
// `repository_create_auth_resource`'s own status mapping) rather than beside
// `admit`/`prepare` above.
// ---------------------------------------------------------------------------

/// A cell can verify a principal, enforce the domain, and still have no ReBAC
/// endpoint configured (`auth_url` and JWT authentication are independent
/// settings). Without this guard a claimed create on such a cell would skip
/// the callback entirely and commit a claim nothing ever acknowledged.
/// `governed_repository_create` refuses `FAILED_PRECONDITION` before that can
/// happen, so this test drives the real shared seam function (not a fixture
/// standing in for it) with a witness-bearing `GovernedRepositoryCreate` and
/// `auth_url: None`.
#[tokio::test]
async fn governed_repository_create_refuses_a_claim_witness_with_no_configured_auth_url() {
    let (immutable_store, mutable_store, execution) = crate::store::test_store_create()
        .await
        .expect("test stores");
    let repository_id: RepositoryId = random();

    LORE_CONTEXT
        .scope(execution, async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store,
                mutable_store,
                repository_id,
            ));
            let domain = Arc::new(context(true));
            let admitted = mediated_admitted_operation(Some(claim_witness_fixture()));
            let governed =
                GovernedRepositoryCreate::prepare(Some(&domain), Some(admitted), vec![0u8; 32])
                    .expect("mediated carriage with a claim witness must not error")
                    .expect("mediated carriage with a claim witness must govern");
            assert!(
                governed.create_witness().is_some(),
                "fixture setup: this test needs a witness-bearing governed create"
            );

            let error = governed_repository_create(
                &governed,
                repository,
                "wp116-claim-witness-no-auth-url",
                "",
                Context::from(uuid::Uuid::now_v7()),
                "main",
                "alice",
                "alice",
                0,
                None, /* no auth_url */
                None, /* no authorization */
            )
            .await
            .expect_err("a claim witness with no configured authorization service must be refused");
            assert_eq!(error.code(), Code::FailedPrecondition);
        })
        .await;
}

/// A malformed-claim `INVALID_ARGUMENT` from the verifier is refused as
/// `INVALID_ARGUMENT`, not `INTERNAL` -- the caller's own wire fault, not a
/// server defect. The verifier's own message is deliberately not forwarded,
/// since it names a claim field this caller may not be entitled to see.
#[tokio::test]
async fn repository_create_auth_resource_maps_a_governed_invalid_argument_to_invalid_argument_not_internal()
 {
    let (repository, repo_name) = fixture_repository();
    let witness = create_witness_fixture();
    let (client, _captured) = recording_client(Err(Status::invalid_argument(
        "claim_revision does not match",
    )));

    let error =
        repository_create_auth_resource(client, None, repository, repo_name, Some(&witness))
            .await
            .expect_err("a governed InvalidArgument from the verifier must be refused");
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(
        error.message(),
        "Governed repository create carriage was rejected by the authorization service"
    );
    assert!(
        !error.message().contains("claim_revision"),
        "the verifier's own message must not be forwarded to the caller"
    );
}

/// The mirror control: the SAME verifier error, on the legacy (`witness:
/// None`) path, still falls through to `INTERNAL` exactly as it did before
/// this change -- the new mapping is witness-gated, not a blanket change to
/// every `InvalidArgument`.
#[tokio::test]
async fn repository_create_auth_resource_ungoverned_invalid_argument_still_falls_through_to_internal()
 {
    let (repository, repo_name) = fixture_repository();
    let (client, _captured) = recording_client(Err(Status::invalid_argument(
        "some unrelated verifier complaint",
    )));

    let error = repository_create_auth_resource(client, None, repository, repo_name, None)
        .await
        .expect_err("an ungoverned InvalidArgument must still fall through to Internal");
    assert_eq!(error.code(), Code::Internal);
}

/// The pre-existing "missing Organization context" arm must keep winning over
/// the new governed-InvalidArgument arm even when a witness is attached --
/// proving the match arm order, not just that each arm individually maps
/// correctly in isolation.
#[tokio::test]
async fn repository_create_auth_resource_missing_resource_context_wins_over_the_governed_invalid_argument_arm()
 {
    let (repository, repo_name) = fixture_repository();
    let witness = create_witness_fixture();
    let (client, _captured) = recording_client(Err(Status::invalid_argument(
        "Missing resource context in resourceName",
    )));

    let error =
        repository_create_auth_resource(client, None, repository, repo_name, Some(&witness))
            .await
            .expect_err("missing org context must still be refused even on the governed path");
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(
        error.message(),
        "Invalid repository name - missing Organization context"
    );
}
