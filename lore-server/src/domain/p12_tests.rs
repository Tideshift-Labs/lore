// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use async_trait::async_trait;
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
