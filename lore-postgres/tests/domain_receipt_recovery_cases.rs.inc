// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_postgres::domain::receipts::ConsumeResult;
use lore_postgres::domain::receipts::ReceiptLookup;
use lore_postgres::domain::receipts::admission_clock;
use lore_postgres::domain::receipts::commit_terminal;
use lore_postgres::domain::receipts::consume;

use super::*;

async fn prepared_acquire(
    store: &PostgresDomainStore,
    repo: &[u8; 16],
    branch: &[u8; 16],
) -> (GovernedOperation, AcquireOrRenewInput, Uuid) {
    let owner = owner("https://receipt-recovery.test", "human");
    let input = acquire_input(
        repo,
        branch,
        owner.clone(),
        vec![resource(rand::random(), None)],
        None,
    );
    let binding = acquire_or_renew_binding(&input).unwrap();
    let key = ReceiptKey {
        verified_issuer: owner.verified_issuer.clone(),
        authenticated_subject: owner.authenticated_subject.clone(),
        tenant_scope_key: lock_tenant_scope_key(repo, branch).unwrap(),
        operation_id: Uuid::now_v7(),
    };
    let attempt = Uuid::now_v7();
    let PrepareResult::Prepared { token, .. } = store
        .domain_operation_prepare(&key, &binding, None, Some(attempt))
        .await
        .unwrap()
    else {
        panic!("fresh acquire must prepare")
    };
    (
        GovernedOperation {
            key,
            binding,
            prepare_token: token,
        },
        input,
        attempt,
    )
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; LORE_TEST_PG_URL"]
async fn acquire_attempt_recovers_original_tokens_after_release_without_exposing_them_to_other_principals()
 {
    let url = pg_url().expect("PostgreSQL required");
    let store = store(&url).await;
    let (repo, branch) = create_repository(&store).await;
    let (operation, input, attempt) = prepared_acquire(&store, &repo, &branch).await;
    let acquired = store
        .lock_coordinator()
        .acquire_or_renew(&operation, &input)
        .await
        .unwrap();
    assert_eq!(acquired.outcome, DomainOutcome::Applied);
    let original = acquired.locks[0].ownership_token.unwrap();
    let release = ReleaseInput {
        repository_id: repo.to_vec(),
        branch_id: branch.to_vec(),
        owner: input.owner.clone(),
        resources: vec![resource(
            input.resources[0]
                .resource_hash
                .as_slice()
                .try_into()
                .unwrap(),
            Some(original),
        )],
        outbox_cell_id: None,
    };
    let release_op = prepare_bound_operation(
        &store,
        &input.owner,
        &repo,
        &branch,
        release_binding(&release).unwrap(),
    )
    .await;
    assert_eq!(
        store
            .lock_coordinator()
            .release(&release_op, &release)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    for _ in 0..2 {
        let receipt = store
            .domain_operation_attempt_receipt_get(
                &operation.key.verified_issuer,
                &operation.key.authenticated_subject,
                &attempt,
            )
            .await
            .unwrap();
        assert!(matches!(
            receipt.lookup,
            ReceiptLookup::Committed {
                outcome: DomainOutcome::Applied,
                ..
            }
        ));
        assert_eq!(receipt.acquired_locks.len(), 1);
        assert_eq!(receipt.acquired_locks[0].ownership_token, Some(original));
        assert_eq!(
            receipt.acquired_locks[0].resource_hash,
            input.resources[0].resource_hash
        );
    }
    for (issuer, subject) in [
        ("foreign", operation.key.authenticated_subject.as_str()),
        (operation.key.verified_issuer.as_str(), "foreign"),
    ] {
        let receipt = store
            .domain_operation_attempt_receipt_get(issuer, subject, &attempt)
            .await
            .unwrap();
        assert!(matches!(receipt.lookup, ReceiptLookup::NotFound));
        assert!(receipt.acquired_locks.is_empty());
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; LORE_TEST_PG_URL"]
async fn acquire_attempt_missing_historical_result_is_empty_but_malformed_result_refuses() {
    let url = pg_url().expect("PostgreSQL required");
    let store = store(&url).await;
    let (repo, branch) = create_repository(&store).await;
    let mut client = client(&url).await;
    let (seed, input, _) = prepared_acquire(&store, &repo, &branch).await;
    let acquired = store
        .lock_coordinator()
        .acquire_or_renew(&seed, &input)
        .await
        .unwrap();
    assert_eq!(acquired.outcome, DomainOutcome::Applied);
    let bytes: Vec<u8> = client
        .query_one(
            "SELECT public_result FROM lore_domain_operation_receipts WHERE operation_id=$1",
            &[&seed.key.operation_id.as_bytes().as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    let mut zero_token = bytes.clone();
    let token = acquired.locks[0].ownership_token.unwrap();
    let token_offset = bytes
        .windows(32)
        .position(|window| window == token)
        .expect("issued token in actual canonical result");
    zero_token[token_offset..token_offset + 32].fill(0);
    let mut wrong_owner = bytes.clone();
    let owner_bytes = input.owner.authenticated_subject.as_bytes();
    let owner_offset = bytes
        .windows(owner_bytes.len())
        .position(|window| window == owner_bytes)
        .unwrap();
    wrong_owner[owner_offset] ^= 1;
    let mut oversized_count = b"lock-result-v1\0".to_vec();
    oversized_count.extend_from_slice(&u32::MAX.to_be_bytes());
    for payload in [
        None,
        Some(vec![0xff; 17]),
        Some(vec![0; 4096]),
        Some(oversized_count),
        Some(zero_token),
        Some(wrong_owner),
    ] {
        let (operation, _, attempt) = prepared_acquire(&store, &repo, &branch).await;
        let tx = client.transaction().await.unwrap();
        assert!(matches!(
            consume(
                &tx,
                &operation.key,
                &operation.binding,
                &operation.prepare_token
            )
            .await
            .unwrap(),
            ConsumeResult::Admitted(_)
        ));
        commit_terminal(
            &tx,
            &operation.key,
            &DomainOutcome::Applied,
            payload.as_deref(),
            admission_clock(&tx).await.unwrap(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let result = store
            .domain_operation_attempt_receipt_get(
                &operation.key.verified_issuer,
                &operation.key.authenticated_subject,
                &attempt,
            )
            .await;
        if payload.is_none() {
            assert!(result.unwrap().acquired_locks.is_empty());
        } else {
            assert!(
                result.is_err(),
                "malformed stored acquire result must not become tokenless Applied"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; LORE_TEST_PG_URL"]
async fn attempt_recovery_never_combines_unique_prepared_snapshot_with_later_duplicate_and_tokens()
{
    let url = pg_url().expect("PostgreSQL required");
    let store = store(&url).await;
    let (repo, branch) = create_repository(&store).await;
    let (seed, input, _) = prepared_acquire(&store, &repo, &branch).await;
    let acquired = store
        .lock_coordinator()
        .acquire_or_renew(&seed, &input)
        .await
        .unwrap();
    assert_eq!(acquired.outcome, DomainOutcome::Applied);
    let mut holder = client(&url).await;
    let bytes: Vec<u8> = holder
        .query_one(
            "SELECT public_result FROM lore_domain_operation_receipts WHERE operation_id=$1",
            &[&seed.key.operation_id.as_bytes().as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    let attempt = Uuid::now_v7();
    let key = ReceiptKey {
        operation_id: Uuid::now_v7(),
        ..seed.key.clone()
    };
    let PrepareResult::Prepared { token, .. } = store
        .domain_operation_prepare(&key, &seed.binding, None, Some(attempt))
        .await
        .unwrap()
    else {
        panic!("fresh prepare")
    };
    let operation = GovernedOperation {
        key,
        binding: seed.binding.clone(),
        prepare_token: token,
    };
    let tx = holder.transaction().await.unwrap();
    tx.query_one(
        "SELECT operation_id FROM lore_domain_operation_receipts WHERE operation_id=$1 FOR UPDATE",
        &[&operation.key.operation_id.as_bytes().as_slice()],
    )
    .await
    .unwrap();
    let observer = barrier::observer(&url).await;
    let read = store.domain_operation_attempt_receipt_get(
        &operation.key.verified_issuer,
        &operation.key.authenticated_subject,
        &attempt,
    );
    let mutate = async {
        barrier::wait_for_lock_waiters(
            &observer,
            1,
            "attempt read has selected its unique Prepared receipt",
        )
        .await;
        let duplicate = ReceiptKey {
            operation_id: Uuid::now_v7(),
            ..operation.key.clone()
        };
        assert!(matches!(
            store
                .domain_operation_prepare(&duplicate, &operation.binding, None, Some(attempt))
                .await
                .unwrap(),
            PrepareResult::Prepared { .. }
        ));
        assert!(matches!(
            consume(
                &tx,
                &operation.key,
                &operation.binding,
                &operation.prepare_token
            )
            .await
            .unwrap(),
            ConsumeResult::Admitted(_)
        ));
        commit_terminal(
            &tx,
            &operation.key,
            &DomainOutcome::Applied,
            Some(&bytes),
            admission_clock(&tx).await.unwrap(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(read, mutate);
    assert!(
        result.is_err(),
        "a changed locked row must refuse this repeatable-read transaction, never expose mixed-snapshot tokens: {result:?}"
    );
    let later = store
        .domain_operation_attempt_receipt_get(
            &operation.key.verified_issuer,
            &operation.key.authenticated_subject,
            &attempt,
        )
        .await
        .unwrap();
    assert!(matches!(later.lookup, ReceiptLookup::NotFound));
    assert!(later.acquired_locks.is_empty());
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; LORE_TEST_PG_URL"]
async fn branch_publication_and_refusal_serialize_both_orders_without_overwriting_applied() {
    use lore_postgres::domain::coordinator::BranchPushCommitInput;
    let url = pg_url().expect("PostgreSQL required");
    let store = store(&url).await;
    let observer = barrier::observer(&url).await;
    for publication_first in [true, false] {
        let (repo, branch) = create_repository(&store).await;
        let owner = owner("https://push-refusal.test", "writer");
        let operation = prepare_operation(&store, &owner, &repo, &branch, "branch.push").await;
        let before = store
            .branch_snapshot(&repo, &branch)
            .await
            .unwrap()
            .unwrap();
        let repository = store.repository_snapshot(&repo).await.unwrap().unwrap();
        let witness = store
            .lock_coordinator()
            .capture_push_witness(&repo, &branch)
            .await
            .unwrap();
        let mut input = BranchPushCommitInput {
            repository_id: repo.to_vec(),
            branch_id: branch.to_vec(),
            expected_repository_generation: repository.generation,
            expected_branch_generation: before.generation,
            expected_repository_lock_generation: witness.repository_lock_generation,
            expected_branch_lock_generation: witness.branch_lock_generation,
            expected_branch_lock_namespace_last_applied_fence: witness
                .branch_lock_namespace_last_applied_fence,
            expected_latest_hash: before.latest_hash.clone(),
            new_latest_hash: rand::random::<[u8; 32]>().to_vec(),
            fragment_witness: None,
            projection: Vec::new(),
            event: None,
        };
        input.event = Some(
            lore_postgres::domain::outbox::builders::branch_pushed(
                "refusal-test-cell",
                &repo,
                &branch,
                "main",
                &before.latest_hash,
                &input.new_latest_hash,
            )
            .unwrap(),
        );
        let mut holder = client(&url).await;
        let (published, refused) = if publication_first {
            let tx = holder.transaction().await.unwrap();
            tx.query_one("SELECT repository_id FROM lore_domain_repositories WHERE repository_id=$1 FOR UPDATE", &[&repo.as_slice()]).await.unwrap();
            let other = async {
                barrier::wait_for_lock_waiters(
                    &observer,
                    1,
                    "publication holds receipt and waits for repository",
                )
                .await;
                let unlock = async {
                    barrier::wait_for_lock_waiters(
                        &observer,
                        2,
                        "refusal waits behind publication receipt",
                    )
                    .await;
                    tx.commit().await.unwrap();
                };
                tokio::join!(store.branch_push_refuse(&operation), unlock).0
            };
            tokio::join!(store.branch_push_commit(&operation, &input), other)
        } else {
            let gate: i64 = rand::random();
            holder
                .query_one("SELECT pg_advisory_lock($1)", &[&gate])
                .await
                .unwrap();
            let name = format!("refusal_gate_{}", Uuid::new_v4().simple());
            let op_hex = operation.key.operation_id.simple().to_string();
            holder.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.operation_id=decode('{op_hex}','hex') AND NEW.state=1 THEN PERFORM pg_advisory_xact_lock({gate}); END IF; RETURN NEW; END $$; CREATE TRIGGER {name} BEFORE UPDATE ON lore_domain_operation_receipts FOR EACH ROW EXECUTE FUNCTION {name}();")).await.unwrap();
            let other = async {
                barrier::wait_for_lock_waiters(
                    &observer,
                    1,
                    "refusal holds receipt before terminal commit",
                )
                .await;
                let unlock = async {
                    barrier::wait_for_lock_waiters(
                        &observer,
                        2,
                        "publication waits behind refusal receipt",
                    )
                    .await;
                    holder
                        .query_one("SELECT pg_advisory_unlock($1)", &[&gate])
                        .await
                        .unwrap();
                };
                tokio::join!(store.branch_push_commit(&operation, &input), unlock).0
            };
            let (refused, published) = tokio::join!(store.branch_push_refuse(&operation), other);
            holder
                .batch_execute(&format!(
                    "DROP TRIGGER {name} ON lore_domain_operation_receipts; DROP FUNCTION {name}();"
                ))
                .await
                .unwrap();
            (published, refused)
        };
        let expected = if publication_first {
            DomainOutcome::Applied
        } else {
            DomainOutcome::NotApplied {
                reason_version: 1,
                reason: "BRANCH_PUSH_REFUSED_V1".into(),
            }
        };
        assert_eq!(published.unwrap().outcome, expected);
        assert_eq!(refused.unwrap(), expected);
        assert_eq!(
            store.branch_push_refuse(&operation).await.unwrap(),
            expected,
            "exact subsequent refusal cannot overwrite the winner"
        );
        let after = store
            .branch_snapshot(&repo, &branch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.latest_hash,
            if publication_first {
                input.new_latest_hash
            } else {
                before.latest_hash
            }
        );
        assert_eq!(
            outbox_row_count_for_repository(&observer, &repo).await,
            i64::from(publication_first),
            "only Applied publication appends an outbox row, including after repeated refusal"
        );
        assert!(
            matches!(store.domain_operation_receipt_get(&operation.key, &operation.binding).await.unwrap(), ReceiptLookup::Committed { outcome, .. } if outcome == expected)
        );
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; LORE_TEST_PG_URL"]
async fn branch_refusal_without_exact_admission_is_unknown_and_keeps_prepared_receipt() {
    let url = pg_url().expect("PostgreSQL required");
    let store = store(&url).await;
    let (repo, branch) = create_repository(&store).await;
    let owner = owner("https://push-refusal-admission.test", "writer");
    let operation = prepare_operation(&store, &owner, &repo, &branch, "branch.push").await;
    for kind in 0..3 {
        let mut wrong = operation.clone();
        match kind {
            0 => wrong.prepare_token[0] ^= 1,
            1 => wrong.binding.fingerprint[0] ^= 1,
            _ => wrong.binding.method = "lock.release".into(),
        }
        assert!(
            matches!(
                store.branch_push_refuse(&wrong).await,
                Err(DomainError::OutcomeUnknown(_))
            ),
            "no exact terminal refusal without admission"
        );
        assert!(matches!(
            store
                .domain_operation_receipt_get(&operation.key, &operation.binding)
                .await
                .unwrap(),
            ReceiptLookup::Prepared { .. }
        ));
    }
    assert_eq!(
        outbox_row_count_for_repository(&client(&url).await, &repo).await,
        0
    );
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; LORE_TEST_PG_URL"]
async fn admin_acquire_recovers_original_target_token_only_for_original_administrator() {
    let url = pg_url().expect("PostgreSQL required");
    let store = store(&url).await;
    let (repo, branch) = create_repository(&store).await;
    let admin = owner("https://admin-recovery.test", "administrator");
    let target = owner("https://admin-recovery.test", "target-human");
    let mut input = acquire_input(
        &repo,
        &branch,
        target.clone(),
        vec![resource(rand::random(), None)],
        None,
    );
    input.acting_owner = Some(admin.clone());
    let binding = acquire_or_renew_binding(&input).unwrap();
    assert_eq!(binding.method, "lock.admin_acquire");
    let key = ReceiptKey {
        verified_issuer: admin.verified_issuer.clone(),
        authenticated_subject: admin.authenticated_subject.clone(),
        tenant_scope_key: lock_tenant_scope_key(&repo, &branch).unwrap(),
        operation_id: Uuid::now_v7(),
    };
    let attempt = Uuid::now_v7();
    let PrepareResult::Prepared { token, .. } = store
        .domain_operation_prepare(&key, &binding, None, Some(attempt))
        .await
        .unwrap()
    else {
        panic!("fresh admin prepare")
    };
    let operation = GovernedOperation {
        key,
        binding,
        prepare_token: token,
    };
    let acquired = store
        .lock_coordinator()
        .acquire_or_renew(&operation, &input)
        .await
        .unwrap();
    assert_eq!(acquired.outcome, DomainOutcome::Applied);
    let receipt = store
        .domain_operation_attempt_receipt_get(
            &admin.verified_issuer,
            &admin.authenticated_subject,
            &attempt,
        )
        .await
        .unwrap();
    assert_eq!(receipt.acquired_locks.len(), 1);
    assert_eq!(receipt.acquired_locks[0].owner, target);
    assert_eq!(
        receipt.acquired_locks[0].ownership_token,
        acquired.locks[0].ownership_token
    );
    for (issuer, subject) in [
        (
            target.verified_issuer.as_str(),
            target.authenticated_subject.as_str(),
        ),
        ("foreign", admin.authenticated_subject.as_str()),
    ] {
        let foreign = store
            .domain_operation_attempt_receipt_get(issuer, subject, &attempt)
            .await
            .unwrap();
        assert!(matches!(foreign.lookup, ReceiptLookup::NotFound));
        assert!(foreign.acquired_locks.is_empty());
    }
}
