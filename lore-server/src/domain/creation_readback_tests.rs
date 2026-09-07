// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Response honesty after a scripted Applied create; transaction durability is covered in PostgreSQL.
use lore_postgres::domain::coordinator::MutationResult;
use lore_postgres::domain::coordinator::RepositorySnapshot;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::fragments::EpochWitness;
use lore_postgres::domain::fragments::FragmentLifecycleState;

use super::test_support::PREPARED_TEST_TOKEN;
use super::test_support::ScriptedDomainStore;
use super::*;

async fn readback(
    coordinated: bool,
    snapshot: Result<Option<RepositorySnapshot>, DomainError>,
) -> (
    Result<RepositoryCreateOutcome, Status>,
    Arc<ScriptedDomainStore>,
) {
    let script = Arc::new(ScriptedDomainStore::new(MutationResult {
        outcome: DomainOutcome::Applied,
        repository_generation: Some(1),
        branch_generation: Some(1),
        observed_pointer: None,
    }));
    *script.create_snapshot.lock().unwrap() = Some(snapshot);
    let governed = GovernedRepositoryCreate {
        domain: Arc::new(DomainContext::new(script.clone(), true)),
        operation: GovernedOperation {
            key: ReceiptKey {
                verified_issuer: "https://fixture.invalid".into(),
                authenticated_subject: "fixture".into(),
                tenant_scope_key: vec![1; 16],
                operation_id: uuid::Uuid::now_v7(),
            },
            binding: OperationBinding {
                method: "repository.create".into(),
                scope: vec![1; 16],
                fingerprint_version: 1,
                fingerprint: vec![2; 32],
                canonical_intent_digest: vec![3; 32],
            },
            prepare_token: PREPARED_TEST_TOKEN,
        },
        create_witness: None,
    };
    let publication = RepositoryCreatePublication {
        salt: b"fixture",
        repository_id: &[1; 16],
        name: "fixture",
        metadata_hash: &[4; 32],
        default_branch_id: &[5; 16],
        default_branch_name: "main",
        default_branch_metadata_hash: &[6; 32],
        default_branch_latest_hash: &[0; 32],
    };
    let witnesses = if coordinated {
        vec![EpochWitness {
            hash: vec![4; 32],
            epoch: 1,
            state: FragmentLifecycleState::Remote,
            manifest_id: Some(vec![7; 32]),
            fence: 1,
        }]
    } else {
        Vec::new()
    };
    (
        governed
            .commit_with_metadata(&publication, &witnesses)
            .await,
        script,
    )
}

#[tokio::test]
async fn coordinated_applied_create_never_reports_speculative_pointer_when_readback_is_missing_or_fails()
 {
    for snapshot in [
        Ok(None),
        Err(DomainError::Transient("fixture read unavailable".into())),
    ] {
        let (result, script) = readback(true, snapshot).await;
        let error = result
            .err()
            .expect("unavailable committed pointer must refuse response");
        assert_eq!(error.code(), tonic::Code::Aborted);
        assert!(error.message().contains("applied"), "{error}");
        assert!(error.message().contains("reconcile"), "{error}");
        assert_eq!(
            script.create_calls.lock().unwrap().len(),
            1,
            "readback must not reissue Applied mutation"
        );
    }
}

#[tokio::test]
async fn legacy_applied_create_retains_fallback_and_coordinated_success_returns_authoritative_pointer()
 {
    for snapshot in [
        Ok(None),
        Err(DomainError::Transient("fixture read unavailable".into())),
    ] {
        let (result, script) = readback(false, snapshot).await;
        assert_eq!(result.unwrap().metadata_hash, Hash::from(&[4; 32][..]));
        assert_eq!(script.create_calls.lock().unwrap().len(), 1);
    }
    let (result, script) = readback(
        true,
        Ok(Some(RepositorySnapshot {
            repository_id: vec![1; 16],
            live: true,
            generation: 2,
            name: "fixture".into(),
            metadata_hash: vec![9; 32],
            default_branch_id: vec![5; 16],
        })),
    )
    .await;
    assert_eq!(result.unwrap().metadata_hash, Hash::from(&[9; 32][..]));
    assert_eq!(script.create_calls.lock().unwrap().len(), 1);
}
