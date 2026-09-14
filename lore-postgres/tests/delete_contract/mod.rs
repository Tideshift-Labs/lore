// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Delete mutations must reject missing targets without changing receipt evidence.

#[path = "../common/delete_observations.rs"]
mod delete_observations;

use lore_postgres::domain::coordinator::BranchDeleteInput;
use lore_postgres::domain::coordinator::NOT_FOUND_V1;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::receipts::ReceiptLookup;

use super::*;

struct Target {
    repository: Vec<u8>,
    branch: Option<Vec<u8>>,
}

impl Target {
    fn method(&self) -> &'static str {
        if self.branch.is_some() {
            "branch_delete"
        } else {
            "repository_delete"
        }
    }

    async fn delete(
        &self,
        store: &PostgresDomainStore,
        op: &GovernedOperation,
        proof: &[u8],
    ) -> Result<MutationResult, DomainError> {
        if let Some(branch) = &self.branch {
            store
                .branch_delete(
                    op,
                    &BranchDeleteInput {
                        repository_id: self.repository.clone(),
                        branch_id: branch.clone(),
                        expected_generation: None,
                        delete_proof: proof.to_vec(),
                        projection: Vec::new(),
                        events: Vec::new(),
                    },
                )
                .await
        } else {
            store
                .repository_delete(
                    op,
                    &RepositoryDeleteInput {
                        repository_id: self.repository.clone(),
                        expected_generation: None,
                        projection: Vec::new(),
                        events: Vec::new(),
                        ..delete_observations::repository_delete_input(&self.repository).await
                    },
                )
                .await
        }
    }

    async fn row(&self, db: &Client) -> String {
        if let Some(branch) = &self.branch {
            db.query_one("SELECT row_to_json(r)::text FROM lore_domain_branches r WHERE repository_id=$1 AND branch_id=$2", &[&self.repository, branch]).await.unwrap().get(0)
        } else {
            db.query_one("SELECT row_to_json(r)::text FROM lore_domain_repositories r WHERE repository_id=$1", &[&self.repository]).await.unwrap().get(0)
        }
    }
}

async fn fixture(store: &PostgresDomainStore, db: &Client, branch: bool) -> Target {
    let input = repository_create_input(format!("delete-contract-{}", Uuid::new_v4()));
    let (op, _) = admitted_operation(store, "repository_create").await;
    assert_eq!(
        store.repository_create(&op, &input).await.unwrap().outcome,
        DomainOutcome::Applied
    );
    let branch_id = branch.then(|| rand::random::<[u8; 16]>().to_vec());
    if let Some(id) = &branch_id {
        // Seed the extra non-default branch with the same lifecycle columns as repository create.
        db.execute("INSERT INTO lore_domain_branches (repository_id,branch_id,repository_generation,state,generation,name,metadata_hash,latest_hash,creation_fingerprint_version,creation_fingerprint,created_at) VALUES ($1,$2,1,0,1,'extra',$3,$3,1,$3,clock_timestamp())", &[&input.repository_id,id,&vec![23u8;32]]).await.unwrap();
    }
    Target {
        repository: input.repository_id,
        branch: branch_id,
    }
}

async fn receipt(db: &Client, op: &GovernedOperation) -> Option<String> {
    db.query_opt("SELECT row_to_json(r)::text FROM lore_domain_operation_receipts r WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4", &[&op.key.verified_issuer,&op.key.authenticated_subject,&op.key.tenant_scope_key,&op.key.operation_id.as_bytes().as_slice()]).await.unwrap().map(|r| r.get(0))
}

async fn assert_proof(db: &Client, target: &Target, op: &GovernedOperation, proof: &[u8]) {
    let repository_proof;
    let proof = if target.branch.is_none() {
        let preimage = lore_postgres::domain::delete_proof::repository_delete_preimage(
            &lore_postgres::domain::delete_proof::DeleteProofReceipt {
                key: &op.key,
                binding: &op.binding,
                client_attempt_id: None,
            },
            &target.repository,
            1,
            2,
        )
        .unwrap();
        repository_proof = *blake3::hash(&preimage).as_bytes();
        &repository_proof[..]
    } else {
        proof
    };
    let row = db.query_one("SELECT tombstone_proof,public_result FROM lore_domain_operation_receipts WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4", &[&op.key.verified_issuer,&op.key.authenticated_subject,&op.key.tenant_scope_key,&op.key.operation_id.as_bytes().as_slice()]).await.unwrap();
    assert_eq!(row.get::<_, Option<Vec<u8>>>(0).as_deref(), Some(proof));
    assert_eq!(row.get::<_, Option<Vec<u8>>>(1), None);
    let row = if let Some(branch) = &target.branch {
        db.query_one("SELECT state,delete_proof FROM lore_domain_branches WHERE repository_id=$1 AND branch_id=$2", &[&target.repository,branch]).await.unwrap()
    } else {
        db.query_one(
            "SELECT state,delete_proof FROM lore_domain_repositories WHERE repository_id=$1",
            &[&target.repository],
        )
        .await
        .unwrap()
    };
    assert_eq!(row.get::<_, i16>(0), 1);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(1).as_deref(), Some(proof));
}

#[tokio::test]
#[ignore = "requires owned Postgres; run with --ignored --test-threads=1"]
async fn delete_success_preserves_proof_and_lookup_but_rejects_old_and_fresh_redispatch() {
    let url = pg_url().expect("LORE_TEST_PG_URL required");
    let store = store(&url).await;
    let db = client(&url).await;
    for branch in [false, true] {
        let target = fixture(&store, &db, branch).await;
        let (op, _) = admitted_operation(&store, target.method()).await;
        let proof = [83; 32];
        assert_eq!(
            target.delete(&store, &op, &proof).await.unwrap().outcome,
            DomainOutcome::Applied
        );
        assert_proof(&db, &target, &op, &proof).await;
        let before = receipt(&db, &op).await;
        let lifecycle = target.row(&db).await;
        assert_eq!(
            target.delete(&store, &op, &proof).await.unwrap(),
            MutationResult::rejected(NOT_FOUND_V1)
        );
        assert_eq!(receipt(&db, &op).await, before);
        assert_eq!(
            store
                .domain_operation_receipt_get(&op.key, &op.binding)
                .await
                .unwrap(),
            ReceiptLookup::Committed {
                outcome: DomainOutcome::Applied,
                from_future_marker: false
            }
        );
        let (fresh, _) = admitted_operation(&store, target.method()).await;
        let prepared = receipt(&db, &fresh).await;
        assert_eq!(
            target.delete(&store, &fresh, &[91; 32]).await.unwrap(),
            MutationResult::rejected(NOT_FOUND_V1)
        );
        assert_eq!(receipt(&db, &fresh).await, prepared);
        assert_eq!(target.row(&db).await, lifecycle);
    }
}

#[tokio::test]
#[ignore = "requires owned Postgres; run with --ignored --test-threads=1"]
async fn delete_missing_target_preserves_even_expired_prepared_receipt() {
    let url = pg_url().expect("LORE_TEST_PG_URL required");
    let store = store(&url).await;
    let db = client(&url).await;
    for branch in [false, true] {
        for expired in [false, true] {
            let mut target = fixture(&store, &db, branch).await;
            if branch {
                target.branch = Some(rand::random::<[u8; 16]>().to_vec());
            } else {
                target.repository = rand::random::<[u8; 16]>().to_vec();
            }
            let (op, _) = admitted_operation(&store, target.method()).await;
            if expired {
                db.execute("UPDATE lore_domain_operation_receipts SET hard_expires_at=clock_timestamp()-interval '1 second' WHERE verified_issuer=$1 AND operation_id=$2", &[&op.key.verified_issuer,&op.key.operation_id.as_bytes().as_slice()]).await.unwrap();
            }
            let before = receipt(&db, &op).await;
            assert!(before.is_some());
            assert_eq!(
                target.delete(&store, &op, &[17; 32]).await.unwrap(),
                MutationResult::rejected(NOT_FOUND_V1)
            );
            assert_eq!(receipt(&db, &op).await, before);
        }
    }
}

#[tokio::test]
#[ignore = "requires owned Postgres; run with --ignored --test-threads=1"]
async fn delete_malformed_proof_rolls_back_receipt_and_lifecycle() {
    let url = pg_url().expect("LORE_TEST_PG_URL required");
    let store = store(&url).await;
    let db = client(&url).await;
    let target = fixture(&store, &db, true).await;
    for width in [0, 31, 33] {
        let (op, _) = admitted_operation(&store, target.method()).await;
        let before = receipt(&db, &op).await;
        let lifecycle = target.row(&db).await;
        assert!(target.delete(&store, &op, &vec![41; width]).await.is_err());
        assert_eq!(receipt(&db, &op).await, before);
        assert_eq!(target.row(&db).await, lifecycle);
    }
    // Repository proofs no longer accept caller bytes. A stored generation that
    // cannot advance must fail before any receipt or lifecycle write commits.
    let target = fixture(&store, &db, false).await;
    db.execute(
        "UPDATE lore_domain_repositories SET generation=$2 WHERE repository_id=$1",
        &[&target.repository, &i64::MAX],
    )
    .await
    .unwrap();
    let (op, _) = admitted_operation(&store, target.method()).await;
    let before = receipt(&db, &op).await;
    let lifecycle = target.row(&db).await;
    assert!(target.delete(&store, &op, &[41; 32]).await.is_err());
    assert_eq!(receipt(&db, &op).await, before);
    assert_eq!(target.row(&db).await, lifecycle);
}

#[tokio::test]
#[ignore = "requires owned Postgres; run with --ignored --test-threads=1"]
async fn delete_branch_under_missing_or_tombstoned_repository_preserves_receipt() {
    let url = pg_url().expect("LORE_TEST_PG_URL required");
    let store = store(&url).await;
    let db = client(&url).await;
    let target = fixture(&store, &db, true).await;
    let parent = Target {
        repository: target.repository.clone(),
        branch: None,
    };
    let (parent_op, _) = admitted_operation(&store, parent.method()).await;
    assert_eq!(
        parent
            .delete(&store, &parent_op, &[71; 32])
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    let lifecycle = target.row(&db).await;
    let (op, _) = admitted_operation(&store, target.method()).await;
    let before = receipt(&db, &op).await;
    assert_eq!(
        target.delete(&store, &op, &[72; 32]).await.unwrap(),
        MutationResult::rejected(NOT_FOUND_V1)
    );
    assert_eq!(receipt(&db, &op).await, before);
    assert_eq!(target.row(&db).await, lifecycle);
    let missing_parent = Target {
        repository: rand::random::<[u8; 16]>().to_vec(),
        branch: target.branch,
    };
    let (missing_op, _) = admitted_operation(&store, missing_parent.method()).await;
    let before = receipt(&db, &missing_op).await;
    assert_eq!(
        missing_parent
            .delete(&store, &missing_op, &[73; 32])
            .await
            .unwrap(),
        MutationResult::rejected(NOT_FOUND_V1)
    );
    assert_eq!(receipt(&db, &missing_op).await, before);
}

#[tokio::test]
#[ignore = "requires owned Postgres; run with --ignored --test-threads=1"]
async fn delete_competitors_have_one_winner_and_unchanged_loser_receipt() {
    let url = pg_url().expect("LORE_TEST_PG_URL required");
    let store = store(&url).await;
    let db = client(&url).await;
    for branch in [false, true] {
        let target = fixture(&store, &db, branch).await;
        let (a, _) = admitted_operation(&store, target.method()).await;
        let (b, _) = admitted_operation(&store, target.method()).await;
        let before_a = receipt(&db, &a).await;
        let before_b = receipt(&db, &b).await;
        let (ra, rb) = tokio::join!(
            target.delete(&store, &a, &[51; 32]),
            target.delete(&store, &b, &[52; 32])
        );
        let (ra, rb) = (ra.unwrap(), rb.unwrap());
        if ra.outcome == DomainOutcome::Applied {
            assert_eq!(rb, MutationResult::rejected(NOT_FOUND_V1));
            assert_eq!(receipt(&db, &b).await, before_b);
            assert_proof(&db, &target, &a, &[51; 32]).await;
        } else {
            assert_eq!(ra, MutationResult::rejected(NOT_FOUND_V1));
            assert_eq!(rb.outcome, DomainOutcome::Applied);
            assert_eq!(receipt(&db, &a).await, before_a);
            assert_proof(&db, &target, &b, &[52; 32]).await;
        }
    }
}
