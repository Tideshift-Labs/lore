// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Transactional repository delete proof tests. Requires an owned disposable Postgres.
use std::time::SystemTime;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GENERATION_MISMATCH_V1;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::PendingEvent;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::delete_proof::DeleteProofReceipt;
use lore_postgres::domain::delete_proof::repository_delete_preimage;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;
#[path = "common/delete_observations.rs"]
mod delete_observations;
async fn store(url: &str) -> PostgresDomainStore {
    let store = PostgresDomainStore::connect(url, 4, &TlsConfig::default())
        .await
        .expect("connect domain store");
    store
        .lock_coordinator()
        .bootstrap()
        .await
        .expect("install SCHEMA-117 before any domain row exists");
    store
}

async fn client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect direct assertion client");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });
    client
}

fn uuid_v7_at(time: SystemTime) -> Uuid {
    let elapsed = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("test timestamp follows epoch");
    Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        elapsed.as_secs(),
        elapsed.subsec_nanos(),
    ))
}

fn binding(method: &str) -> OperationBinding {
    OperationBinding {
        method: method.to_string(),
        scope: rand::random::<[u8; 16]>().to_vec(),
        fingerprint_version: 1,
        fingerprint: rand::random::<[u8; 32]>().to_vec(),
        canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

fn witness(operation_id: Uuid) -> AuthorizationWitness {
    AuthorizationWitness {
        authorization_id: operation_id.as_bytes().to_vec(),
        authorization_revision: 7,
        verification_nonce: rand::random::<[u8; 32]>().to_vec(),
        bound_fields_digest: rand::random::<[u8; 32]>().to_vec(),
        consumed_ticket_sha256: rand::random::<[u8; 32]>().to_vec(),
        expected_claim_identity_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

async fn admitted_operation(
    store: &PostgresDomainStore,
    method: &str,
    attempt: Option<Uuid>,
) -> (GovernedOperation, AuthorizationWitness) {
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("read database clock");
    let operation_id = uuid_v7_at(clock);
    let key = ReceiptKey {
        verified_issuer: format!(
            "https://issuer.example/wp116-producers/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "lorehub-control-plane".to_string(),
        tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
        operation_id,
    };
    let binding = binding(method);
    let witness = witness(operation_id);
    let prepared = store
        .domain_operation_prepare(&key, &binding, Some(&witness), attempt)
        .await
        .expect("prepare governed operation");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("admissible operation must prepare, got {prepared:?}");
    };
    (
        GovernedOperation {
            key,
            binding,
            prepare_token: token,
        },
        witness,
    )
}

fn repository_create_input(
    repository_id: Vec<u8>,
    name: String,
    event: Option<PendingEvent>,
) -> RepositoryCreateInput {
    RepositoryCreateInput {
        metadata_witnesses: Vec::new(),
        repository_id,
        name,
        metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_id: rand::random::<[u8; 16]>().to_vec(),
        default_branch_name: "main".to_string(),
        default_branch_metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_latest_hash: rand::random::<[u8; 32]>().to_vec(),
        creation_fingerprint: rand::random::<[u8; 32]>().to_vec(),
        creation_fingerprint_version: 1,
        projection: Vec::new(),
        // WP-116 Part 3 widened the create carriage to a bounded `Vec`. This
        // helper keeps its one-event parameter so every existing caller reads
        // the same; a case that needs the two-event pair builds the input
        // directly.
        events: event.into_iter().collect(),
    }
}

async fn fixture() -> (PostgresDomainStore, Client, RepositoryCreateInput) {
    let url = std::env::var("LORE_TEST_PG_URL").expect("owned Postgres required");
    let store = store(&url).await;
    lore_postgres::store::mutable_store::PostgresMutableStore::connect(
        &url,
        2,
        &TlsConfig::default(),
    )
    .await
    .unwrap();
    let db = client(&url).await;
    let input = repository_create_input(
        Uuid::new_v4().as_bytes().to_vec(),
        format!("proof-{}", Uuid::new_v4()),
        None,
    );
    let (op, _) = admitted_operation(&store, "repository.create", None).await;
    assert_eq!(
        store.repository_create(&op, &input).await.unwrap().outcome,
        DomainOutcome::Applied
    );
    (store, db, input)
}

async fn receipt_row(db: &Client, op: &GovernedOperation) -> String {
    db.query_one("SELECT row_to_json(r)::text FROM lore_domain_operation_receipts r WHERE verified_issuer=$1 AND operation_id=$2", &[&op.key.verified_issuer, &op.key.operation_id.as_bytes().as_slice()]).await.unwrap().get(0)
}

async fn lifecycle(db: &Client, id: &[u8]) -> Vec<String> {
    db.query("SELECT row_to_json(r)::text FROM lore_domain_repositories r WHERE repository_id=$1 UNION ALL SELECT row_to_json(b)::text FROM lore_domain_branches b WHERE repository_id=$1", &[&id]).await.unwrap().iter().map(|r| r.get(0)).collect()
}

fn attach_publication_sentinels(
    input: &mut lore_postgres::domain::coordinator::RepositoryDeleteInput,
) {
    input
        .projection
        .push(lore_postgres::domain::coordinator::ProjectionWrite {
            partition: input.repository_id.clone(),
            key_type: lore_base::types::KeyType::RepositoryMetadata as i16,
            key: vec![0xE1; 32],
            value: Some(vec![0xE2; 32]),
        });
    input.events.push(PendingEvent {
        cell_id: "delete-proof-fixture".into(),
        event_kind: "repository.tombstoned".into(),
        aggregate_kind: "repository".into(),
        aggregate_id: input.repository_id.clone(),
        aggregate_ordinal:
            lore_postgres::domain::coordinator::CommittedOrdinal::RepositoryGeneration,
        aggregate_identity: vec![],
        payload_schema_version: 1,
        payload: b"{}".to_vec(),
    });
}

async fn assert_no_publication(db: &Client, repository_id: &[u8]) {
    let mutable: i64 = db
        .query_one(
            "SELECT count(*) FROM lore_mutable WHERE partition=$1 AND key=$2",
            &[&repository_id, &vec![0xE1u8; 32]],
        )
        .await
        .unwrap()
        .get(0);
    let events: i64 = db
        .query_one(
            "SELECT count(*) FROM lore_outbox_events WHERE repository_id=$1",
            &[&repository_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!((mutable, events), (0, 0));
}

#[tokio::test]
#[ignore = "requires owned Postgres; run with --ignored --test-threads=1"]
async fn repository_proof_binds_persisted_attempt_and_inherits_only_to_live_branches() {
    for attempt in [None, Some(Uuid::new_v4())] {
        let (store, db, created) = fixture().await;
        let old_branch = Uuid::new_v4().as_bytes().to_vec();
        let old_proof = vec![91u8; 32];
        db.execute("INSERT INTO lore_domain_branches (repository_id,branch_id,repository_generation,state,generation,name,metadata_hash,latest_hash,creation_fingerprint_version,creation_fingerprint,delete_proof,created_at,deleted_at) VALUES ($1,$2,1,1,2,'old',$3,$3,1,$3,$4,clock_timestamp(),clock_timestamp())", &[&created.repository_id,&old_branch,&vec![90u8;32],&old_proof]).await.unwrap();
        let mut input = delete_observations::repository_delete_input(&created.repository_id).await;
        input.branches.reverse(); // order does not participate in the proof
        let (op, _) = admitted_operation(&store, "repository.delete", attempt).await;
        assert_eq!(
            store.repository_delete(&op, &input).await.unwrap().outcome,
            DomainOutcome::Applied
        );
        let expected = blake3::hash(
            &repository_delete_preimage(
                &DeleteProofReceipt {
                    key: &op.key,
                    binding: &op.binding,
                    client_attempt_id: attempt.as_ref().map(|a| a.as_bytes().as_slice()),
                },
                &created.repository_id,
                1,
                2,
            )
            .unwrap(),
        );
        let proof: Vec<u8> = db
            .query_one(
                "SELECT delete_proof FROM lore_domain_repositories WHERE repository_id=$1",
                &[&created.repository_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(proof, expected.as_bytes());
        let receipt = db.query_one("SELECT tombstone_proof,public_result,client_attempt_id FROM lore_domain_operation_receipts WHERE verified_issuer=$1 AND operation_id=$2", &[&op.key.verified_issuer,&op.key.operation_id.as_bytes().as_slice()]).await.unwrap();
        assert_eq!(receipt.get::<_, Vec<u8>>(0), proof);
        assert_eq!(receipt.get::<_, Option<Vec<u8>>>(1), None);
        assert_eq!(
            receipt.get::<_, Option<Vec<u8>>>(2),
            attempt.map(|a| a.as_bytes().to_vec())
        );
        let live_proof: Vec<u8> = db.query_one("SELECT delete_proof FROM lore_domain_branches WHERE repository_id=$1 AND branch_id=$2", &[&created.repository_id,&created.default_branch_id]).await.unwrap().get(0);
        assert_eq!(live_proof, proof);
        let retained: Vec<u8> = db.query_one("SELECT delete_proof FROM lore_domain_branches WHERE repository_id=$1 AND branch_id=$2", &[&created.repository_id,&old_branch]).await.unwrap().get(0);
        assert_eq!(retained, old_proof);
    }
}

#[tokio::test]
#[ignore = "requires owned Postgres; run with --ignored --test-threads=1"]
async fn repository_delete_rejects_changed_or_incomplete_observations_without_publication() {
    for case in 0..7 {
        let (store, db, created) = fixture().await;
        let mut input = delete_observations::repository_delete_input(&created.repository_id).await;
        attach_publication_sentinels(&mut input);
        match case {
            0 => input.branches.clear(),
            1 => {
                let mut extra = input.branches[0].clone();
                extra.branch_id = Uuid::new_v4().as_bytes().to_vec();
                input.branches.push(extra);
            }
            2 => input.branches[0].name.push_str("-changed"),
            3 => input.branches[0].metadata_hash[0] ^= 1,
            4 => input.expected_name.push_str("-changed"),
            5 => input.expected_metadata_hash[0] ^= 1,
            6 => input.branches.push(input.branches[0].clone()),
            _ => unreachable!(),
        }
        let before = lifecycle(&db, &created.repository_id).await;
        let (op, _) = admitted_operation(&store, "repository.delete", None).await;
        let result = store.repository_delete(&op, &input).await.unwrap();
        assert!(
            matches!(result.outcome, DomainOutcome::NotApplied { reason, .. } if reason == GENERATION_MISMATCH_V1),
            "case {case}"
        );
        assert_eq!(
            lifecycle(&db, &created.repository_id).await,
            before,
            "case {case}"
        );
        let proof: Option<Vec<u8>> = db.query_one("SELECT tombstone_proof FROM lore_domain_operation_receipts WHERE verified_issuer=$1 AND operation_id=$2", &[&op.key.verified_issuer,&op.key.operation_id.as_bytes().as_slice()]).await.unwrap().get(0);
        assert_eq!(proof, None, "case {case}");
        assert_no_publication(&db, &created.repository_id).await;
    }
}

#[tokio::test]
#[ignore = "requires owned Postgres; run with --ignored --test-threads=1"]
async fn repository_delete_overflow_rolls_back_receipt_and_every_lifecycle_row() {
    for branch_overflow in [false, true] {
        let (store, db, created) = fixture().await;
        if branch_overflow {
            db.execute(
                "UPDATE lore_domain_branches SET generation=$2 WHERE repository_id=$1",
                &[&created.repository_id, &i64::MAX],
            )
            .await
            .unwrap();
        } else {
            db.execute(
                "UPDATE lore_domain_repositories SET generation=$2 WHERE repository_id=$1",
                &[&created.repository_id, &i64::MAX],
            )
            .await
            .unwrap();
        }
        let mut input = delete_observations::repository_delete_input(&created.repository_id).await;
        attach_publication_sentinels(&mut input);
        let (op, _) = admitted_operation(&store, "repository.delete", None).await;
        let before = lifecycle(&db, &created.repository_id).await;
        let receipt_before = receipt_row(&db, &op).await;
        assert!(store.repository_delete(&op, &input).await.is_err());
        assert_eq!(lifecycle(&db, &created.repository_id).await, before);
        assert_eq!(receipt_row(&db, &op).await, receipt_before);
        assert_no_publication(&db, &created.repository_id).await;
    }
}

async fn branch_fixture() -> (PostgresDomainStore, Client, Vec<u8>, Vec<u8>) {
    let (store, db, created) = fixture().await;
    let branch = Uuid::new_v4().as_bytes().to_vec();
    db.execute("INSERT INTO lore_domain_branches (repository_id,branch_id,repository_generation,state,generation,name,metadata_hash,latest_hash,creation_fingerprint_version,creation_fingerprint,created_at) VALUES ($1,$2,1,0,1,'feature',$3,$4,1,$3,clock_timestamp())", &[&created.repository_id,&branch,&vec![90u8;32],&vec![91u8;32]]).await.unwrap();
    (store, db, created.repository_id, branch)
}

#[tokio::test]
#[ignore = "requires owned Postgres; run with --ignored --test-threads=1"]
async fn branch_proof_binds_persisted_attempt_generations_and_final_tip() {
    for attempt in [None, Some(Uuid::new_v4())] {
        let (store, db, repo, branch) = branch_fixture().await;
        db.execute(
            "UPDATE lore_domain_repositories SET generation=7 WHERE repository_id=$1",
            &[&repo],
        )
        .await
        .unwrap();
        db.execute("UPDATE lore_domain_branches SET repository_generation=7,generation=11 WHERE repository_id=$1 AND branch_id=$2", &[&repo,&branch]).await.unwrap();
        let input = delete_observations::branch_delete_input(&repo, &branch).await;
        let (op, _) = admitted_operation(&store, "branch.delete", attempt).await;
        assert_eq!(
            store.branch_delete(&op, &input).await.unwrap().outcome,
            DomainOutcome::Applied
        );
        let expected = blake3::hash(
            &lore_postgres::domain::delete_proof::branch_delete_preimage(
                &DeleteProofReceipt {
                    key: &op.key,
                    binding: &op.binding,
                    client_attempt_id: attempt.as_ref().map(|a| a.as_bytes().as_slice()),
                },
                &repo,
                &branch,
                7,
                11,
                12,
                &[91; 32],
            )
            .unwrap(),
        );
        let row=db.query_one("SELECT generation,delete_proof,latest_hash FROM lore_domain_branches WHERE repository_id=$1 AND branch_id=$2", &[&repo,&branch]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 12);
        assert_eq!(row.get::<_, Vec<u8>>(1), expected.as_bytes());
        assert_eq!(row.get::<_, Vec<u8>>(2), vec![91; 32]);
        let receipt=db.query_one("SELECT tombstone_proof,public_result,client_attempt_id FROM lore_domain_operation_receipts WHERE verified_issuer=$1 AND operation_id=$2", &[&op.key.verified_issuer,&op.key.operation_id.as_bytes().as_slice()]).await.unwrap();
        assert_eq!(receipt.get::<_, Vec<u8>>(0), expected.as_bytes());
        assert_eq!(receipt.get::<_, Option<Vec<u8>>>(1), None);
        assert_eq!(
            receipt.get::<_, Option<Vec<u8>>>(2),
            attempt.map(|id| id.as_bytes().to_vec())
        );
    }
}

#[tokio::test]
#[ignore = "requires owned Postgres; run with --ignored --test-threads=1"]
async fn branch_delete_rejects_stale_observations_protection_and_default_without_publication() {
    use lore_postgres::domain::coordinator::DEFAULT_BRANCH_V1;
    use lore_postgres::domain::coordinator::DELETE_PROTECTED_V1;
    for case in 0..6 {
        let (store, db, repo, branch) = branch_fixture().await;
        let mut input = delete_observations::branch_delete_input(&repo, &branch).await;
        let expected = match case {
            0 => {
                input.expected_name.push_str("-stale");
                GENERATION_MISMATCH_V1
            }
            1 => {
                db.execute("UPDATE lore_domain_branches SET metadata_hash=$3 WHERE repository_id=$1 AND branch_id=$2", &[&repo,&branch,&vec![92u8;32]]).await.unwrap();
                GENERATION_MISMATCH_V1
            }
            2 => {
                db.execute("UPDATE lore_domain_branches SET latest_hash=$3 WHERE repository_id=$1 AND branch_id=$2", &[&repo,&branch,&vec![93u8;32]]).await.unwrap();
                GENERATION_MISMATCH_V1
            }
            3 => {
                input.delete_protected = true;
                DELETE_PROTECTED_V1
            }
            4 => {
                input.legacy_default = true;
                DEFAULT_BRANCH_V1
            }
            5 => {
                db.execute("UPDATE lore_domain_repositories SET default_branch_id=$2 WHERE repository_id=$1", &[&repo,&branch]).await.unwrap();
                DEFAULT_BRANCH_V1
            }
            _ => unreachable!(),
        };
        input
            .projection
            .push(lore_postgres::domain::coordinator::ProjectionWrite {
                partition: repo.clone(),
                key_type: lore_base::types::KeyType::BranchId as i16,
                key: vec![0xE1; 32],
                value: Some(vec![0xE2; 32]),
            });
        input.events.push(PendingEvent {
            cell_id: "branch-delete-test".into(),
            event_kind: "branch.deleted".into(),
            aggregate_kind: "branch".into(),
            aggregate_id: branch.clone(),
            aggregate_ordinal:
                lore_postgres::domain::coordinator::CommittedOrdinal::BranchGeneration,
            aggregate_identity: vec![91; 32],
            payload_schema_version: 1,
            payload: b"{}".to_vec(),
        });
        let before = lifecycle(&db, &repo).await;
        let (op, _) = admitted_operation(&store, "branch.delete", None).await;
        assert!(
            matches!(store.branch_delete(&op,&input).await.unwrap().outcome,DomainOutcome::NotApplied{reason,..} if reason==expected),
            "case {case}"
        );
        assert_eq!(lifecycle(&db, &repo).await, before);
        assert_no_publication(&db, &repo).await;
    }
}
