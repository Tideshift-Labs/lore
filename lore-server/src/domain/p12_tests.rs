// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::sync::Mutex;

use async_trait::async_trait;
use lore_postgres::domain::coordinator::ADMISSION_REJECTED_V1;
use lore_postgres::domain::coordinator::BranchPushCommitInput;
use lore_postgres::domain::coordinator::MutationResult;
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
use tonic::Code;
use tonic::metadata::BinaryMetadataValue;
use uuid::Uuid;

use super::test_support::context;
use super::*;
use crate::grpc::domain_operation_metadata::DomainOperationMetadata;
use crate::grpc::domain_operation_metadata::FINGERPRINT_KEY;
use crate::grpc::domain_operation_metadata::FINGERPRINT_V1_LEN;
use crate::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
use crate::grpc::domain_operation_metadata::MEDIATED_SCOPE_KEY;
use crate::grpc::domain_operation_metadata::MEDIATED_SCOPE_V1_LEN;
use crate::grpc::domain_operation_metadata::OPERATION_ID_KEY;
use crate::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
use crate::grpc::domain_operation_metadata::PREPARE_TOKEN_LEN;
use crate::grpc::domain_operation_metadata::scope_key_mediated_namespace;

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
    let result = GovernedRepositoryCreate::prepare(None, None, "repository_create", vec![0u8; 32]);
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
        },
    };
    // `GovernedRepositoryCreate` has no `Debug` impl, so `Result::expect_err`
    // (which requires the `Ok` side to be `Debug`) can't be used here -- match
    // explicitly instead, matching this file's other `Debug`-less-type
    // convention (see `commit_maps_cas_mismatch_without_observed_pointer_to_status_internal`
    // above).
    let result = GovernedRepositoryCreate::prepare(
        Some(&domain),
        Some(admitted),
        "repository_create",
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
        },
    };
    let result = GovernedRepositoryCreate::prepare(
        Some(&domain),
        Some(admitted),
        "repository_create",
        vec![0u8; 32],
    )
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
