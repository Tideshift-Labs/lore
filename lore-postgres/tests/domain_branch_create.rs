// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! SERVER transaction tests. Each ignored case requires an owned PostgreSQL database.

#[path = "common/delete_observations.rs"]
mod delete_observations;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::*;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use tokio_postgres::Client;
use uuid::Uuid;

#[path = "common/create_metadata_fixture.rs"]
mod setup;
#[path = "common/create_metadata_witness.rs"]
mod witness;

fn id() -> Vec<u8> {
    Uuid::now_v7().as_bytes().to_vec()
}

async fn operation(store: &PostgresDomainStore, method: &str) -> GovernedOperation {
    let elapsed = store
        .domain_operation_clock_get()
        .await
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let key = ReceiptKey {
        verified_issuer: "https://branch-create-test.invalid".into(),
        authenticated_subject: "fixture".into(),
        tenant_scope_key: id(),
        operation_id: Uuid::new_v7(uuid::Timestamp::from_unix(
            uuid::NoContext,
            elapsed.as_secs(),
            elapsed.subsec_nanos(),
        )),
    };
    let binding = OperationBinding {
        method: method.into(),
        scope: id(),
        fingerprint_version: 1,
        fingerprint: id().repeat(2),
        canonical_intent_digest: id().repeat(2),
    };
    let PrepareResult::Prepared { token, .. } = store
        .domain_operation_prepare(&key, &binding, None, None)
        .await
        .unwrap()
    else {
        panic!("fresh operation must prepare")
    };
    GovernedOperation {
        key,
        binding,
        prepare_token: token,
    }
}

fn repository_input() -> RepositoryCreateInput {
    RepositoryCreateInput {
        repository_id: id(),
        name: format!("repo-{}", Uuid::now_v7()),
        metadata_hash: id().repeat(2),
        default_branch_id: id(),
        default_branch_name: "main".into(),
        default_branch_metadata_hash: id().repeat(2),
        default_branch_latest_hash: id().repeat(2),
        creation_fingerprint: id().repeat(2),
        creation_fingerprint_version: 1,
        metadata_witnesses: vec![],
        projection: vec![],
        events: vec![],
    }
}

async fn repository(store: &PostgresDomainStore) -> RepositoryCreateInput {
    let input = repository_input();
    assert_eq!(
        store
            .repository_create(&operation(store, "repository.create").await, &input)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    input
}

fn input(repo: &RepositoryCreateInput) -> BranchCreateInput {
    let branch_id = id();
    BranchCreateInput {
        repository_id: repo.repository_id.clone(),
        branch_id: branch_id.clone(),
        expected_repository_generation: 1,
        expected_repository_metadata_hash: repo.metadata_hash.clone(),
        expected_default_branch_id: repo.default_branch_id.clone(),
        parent_metadata: None,
        name: format!("branch-{}", Uuid::now_v7()),
        metadata_hash: id().repeat(2),
        latest_hash: id().repeat(2),
        metadata_witness: None,
        events: vec![],
        public_result: vec![1, 2, 3],
        projection: vec![ProjectionWrite {
            partition: repo.repository_id.clone(),
            key_type: 1,
            key: branch_id.repeat(2),
            value: Some(vec![9; 32]),
        }],
    }
}

fn rejected(outcome: DomainOutcome, reason: &str) {
    assert_eq!(
        outcome,
        DomainOutcome::NotApplied {
            reason_version: 1,
            reason: reason.into()
        }
    );
}

async fn direct_branch_operation(store: &PostgresDomainStore, repo: &[u8]) -> GovernedOperation {
    let elapsed = store
        .domain_operation_clock_get()
        .await
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let attempt = Uuid::new_v7(uuid::Timestamp::from_unix(
        uuid::NoContext,
        elapsed.as_secs(),
        elapsed.subsec_nanos(),
    ));
    let key = ReceiptKey {
        verified_issuer: "https://direct-branch.invalid".into(),
        authenticated_subject: "creator".into(),
        tenant_scope_key: repo.to_vec(),
        operation_id: attempt,
    };
    let binding = OperationBinding {
        method: "branch.create".into(),
        scope: repo.to_vec(),
        fingerprint_version: 1,
        fingerprint: vec![4; 32],
        canonical_intent_digest: vec![5; 32],
    };
    let evidence = lore_postgres::domain::receipts::DirectAuthorizationEvidence {
        authorization_id: attempt.as_bytes().to_vec(),
        authorization_revision: 1,
        verification_nonce: vec![6; 32],
        bound_fields_digest: vec![7; 32],
    };
    let PrepareResult::Prepared { token, .. } = store
        .domain_operation_prepare_direct(&key, &binding, &evidence, Some(attempt))
        .await
        .unwrap()
    else {
        panic!("fresh direct operation")
    };
    GovernedOperation {
        key,
        binding,
        prepare_token: token,
    }
}

#[tokio::test]
#[ignore = "owned PostgreSQL; explicitly registered live target"]
async fn direct_terminal_replay_checks_full_binding_namespace_and_retained_payload() {
    use lore_postgres::domain::errors::DomainError;
    let (_, store, client) = setup::fixture(false).await;
    let repo = repository(&store).await;
    let input = input(&repo);
    let op = direct_branch_operation(&store, &repo.repository_id).await;
    assert!(
        store
            .branch_create_terminal_replay(&op.key, &op.binding)
            .await
            .unwrap()
            .is_none()
    );
    let applied = store.branch_create(&op, &input).await.unwrap();
    let replay = store
        .branch_create_terminal_replay(&op.key, &op.binding)
        .await
        .unwrap()
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.outcome, applied.outcome);
    assert_eq!(replay.public_result, applied.public_result);
    for dimension in 0..5 {
        let mut changed = op.binding.clone();
        match dimension {
            0 => changed.canonical_intent_digest[0] ^= 1,
            1 => changed.fingerprint[0] ^= 1,
            2 => changed.scope[0] ^= 1,
            3 => changed.fingerprint_version += 1,
            _ => changed.method = "branch.push".into(),
        }
        assert!(matches!(
            store.branch_create_terminal_replay(&op.key, &changed).await,
            Err(DomainError::InvalidInput(_))
        ));
    }
    for dimension in 0..3 {
        let mut other = op.key.clone();
        match dimension {
            0 => other.authenticated_subject = "another-user".into(),
            1 => other.verified_issuer = "https://another-issuer.invalid".into(),
            _ => other.tenant_scope_key = id(),
        }
        assert!(
            store
                .branch_create_terminal_replay(&other, &op.binding)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(artifacts(&client, &input).await, vec![1, 1, 1]);
    client
        .execute(
            "UPDATE lore_domain_operation_receipts SET public_result=NULL WHERE operation_id=$1",
            &[&op.key.operation_id.as_bytes().as_slice()],
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .branch_create_terminal_replay(&op.key, &op.binding)
            .await,
        Err(DomainError::OutcomeUnknown(_))
    ));
    client.execute("UPDATE lore_domain_operation_receipts SET public_result=$2, full_result_expires_at=clock_timestamp()-interval '1 second' WHERE operation_id=$1",
        &[&op.key.operation_id.as_bytes().as_slice(), &input.public_result]).await.unwrap();
    assert!(matches!(
        store
            .branch_create_terminal_replay(&op.key, &op.binding)
            .await,
        Err(DomainError::OutcomeUnknown(_))
    ));
    assert_eq!(artifacts(&client, &input).await, vec![1, 1, 1]);
}

#[tokio::test]
#[ignore = "owned PostgreSQL; explicitly registered live target"]
async fn concurrent_direct_attempt_commits_once_and_has_one_lookup_receipt() {
    let (url, store, client) = setup::fixture(false).await;
    let repo = repository(&store).await;
    let input = input(&repo);
    let op = direct_branch_operation(&store, &repo.repository_id).await;
    let mut blocker = setup::client(&url).await;
    let blocked = blocker.transaction().await.unwrap();
    blocked.query_one("SELECT operation_id FROM lore_domain_operation_receipts WHERE operation_id=$1 FOR UPDATE",
        &[&op.key.operation_id.as_bytes().as_slice()]).await.unwrap();
    let release = async {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let waiting: i64 = client.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%lore_domain_operation_receipts%'", &[]).await.unwrap().get(0);
                if waiting >= 2 { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("both creates must be blocked on the held receipt before release");
        blocked.commit().await.unwrap();
    };
    let (a, b, ()) = tokio::join!(
        store.branch_create(&op, &input),
        store.branch_create(&op, &input),
        release
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_ne!(a.replayed, b.replayed);
    assert_eq!(a.outcome, DomainOutcome::Applied);
    assert_eq!(a.outcome, b.outcome);
    assert_eq!(a.public_result, b.public_result);
    assert_eq!(artifacts(&client, &input).await, vec![1, 1, 1]);
    let rows: i64 = client
        .query_one(
            "SELECT count(*) FROM lore_domain_operation_receipts WHERE client_attempt_id=$1",
            &[&op.key.operation_id.as_bytes().as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 1);
    let receipt = store
        .domain_operation_attempt_receipt_get(
            &op.key.verified_issuer,
            &op.key.authenticated_subject,
            &op.key.operation_id,
        )
        .await
        .unwrap();
    assert_eq!(receipt.method.as_deref(), Some("branch.create"));
    assert!(matches!(
        receipt.lookup,
        lore_postgres::domain::receipts::ReceiptLookup::Committed { .. }
    ));
    let replay = store
        .branch_create_terminal_replay(&op.key, &op.binding)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replay.public_result, Some(input.public_result));
}

async fn artifacts(client: &Client, input: &BranchCreateInput) -> Vec<i64> {
    let row = client
        .query_one(
            "SELECT
        (SELECT count(*) FROM lore_domain_branches WHERE repository_id=$1 AND branch_id=$2),
        (SELECT count(*) FROM lore_domain_branch_names WHERE repository_id=$1 AND branch_id=$2),
        (SELECT count(*) FROM lore_mutable WHERE partition=$1 AND key=$3)",
            &[
                &input.repository_id,
                &input.branch_id,
                &input.projection[0].key,
            ],
        )
        .await
        .unwrap();
    (0..3).map(|i| row.get(i)).collect()
}

#[tokio::test]
#[ignore = "owned PostgreSQL; explicitly registered live target"]
async fn fresh_create_is_atomic_and_exact_replay_survives_deleted_state() {
    let (_, store, client) = setup::fixture(false).await;
    let repo = repository(&store).await;
    let input = input(&repo);
    let op = operation(&store, "branch.create").await;
    assert!(store.branch_create_replay(&op).await.unwrap().is_none());
    let result = store.branch_create(&op, &input).await.unwrap();
    assert!(!result.replayed);
    assert_eq!(result.outcome, DomainOutcome::Applied);
    assert_eq!(result.public_result, Some(input.public_result.clone()));
    assert_eq!(artifacts(&client, &input).await, vec![1, 1, 1]);
    let snapshot = store
        .branch_snapshot(&input.repository_id, &input.branch_id)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.live);
    assert_eq!(snapshot.generation, 1);
    assert_eq!(snapshot.metadata_hash, input.metadata_hash);
    assert_eq!(snapshot.latest_hash, input.latest_hash);
    let delete = RepositoryDeleteInput {
        repository_id: repo.repository_id.clone(),
        expected_generation: Some(1),
        projection: vec![],
        events: vec![],
        ..delete_observations::repository_delete_input(&repo.repository_id).await
    };
    assert_eq!(
        store
            .repository_delete(&operation(&store, "repository.delete").await, &delete)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    let mut invalid = input.clone();
    invalid.public_result = vec![0; 4097];
    invalid.metadata_hash.clear();
    let replay = store.branch_create(&op, &invalid).await.unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.outcome, DomainOutcome::Applied);
    assert_eq!(replay.public_result, Some(input.public_result.clone()));
    assert_eq!(
        store
            .branch_create_replay(&op)
            .await
            .unwrap()
            .unwrap()
            .public_result,
        Some(input.public_result)
    );
}

#[tokio::test]
#[ignore = "owned PostgreSQL; explicitly registered live target"]
async fn full_response_bound_is_inclusive_and_rejection_publishes_nothing() {
    let (_, store, client) = setup::fixture(false).await;
    let repo = repository(&store).await;
    for size in [4096, 4097] {
        let mut input = input(&repo);
        input.public_result = vec![1; size];
        let op = operation(&store, "branch.create").await;
        let result = store.branch_create(&op, &input).await.unwrap();
        if size == 4096 {
            assert_eq!(result.outcome, DomainOutcome::Applied);
            assert_eq!(result.public_result, Some(input.public_result.clone()));
            assert_eq!(artifacts(&client, &input).await, vec![1, 1, 1]);
        } else {
            rejected(result.outcome, "branch_create_response_too_large_v1");
            assert_eq!(result.public_result, None);
            assert_eq!(artifacts(&client, &input).await, vec![0, 0, 0]);
            input.public_result.truncate(4096);
            rejected(
                store.branch_create(&op, &input).await.unwrap().outcome,
                "branch_create_response_too_large_v1",
            );
        }
    }
}

#[tokio::test]
#[ignore = "owned PostgreSQL; explicitly registered live target"]
async fn repository_and_first_parent_read_sets_are_exact() {
    let (_, store, client) = setup::fixture(false).await;
    let repo = repository(&store).await;
    for shape in 0..5 {
        let mut input = input(&repo);
        match shape {
            0 => input.expected_repository_generation += 1,
            1 => input.expected_repository_metadata_hash = vec![0; 32],
            2 => input.expected_default_branch_id = id(),
            3 => {
                input.parent_metadata = Some(BranchCreateParentMetadata {
                    branch_id: repo.default_branch_id.clone(),
                    metadata_hash: None,
                })
            }
            _ => {
                input.parent_metadata = Some(BranchCreateParentMetadata {
                    branch_id: id(),
                    metadata_hash: Some(vec![4; 32]),
                })
            }
        }
        rejected(
            store
                .branch_create(&operation(&store, "branch.create").await, &input)
                .await
                .unwrap()
                .outcome,
            if shape == 0 {
                GENERATION_MISMATCH_V1
            } else {
                "branch_create_read_set_changed_v1"
            },
        );
        assert_eq!(artifacts(&client, &input).await, vec![0, 0, 0]);
    }
    for parent in [
        BranchCreateParentMetadata {
            branch_id: id(),
            metadata_hash: None,
        },
        BranchCreateParentMetadata {
            branch_id: repo.default_branch_id.clone(),
            metadata_hash: Some(repo.default_branch_metadata_hash.clone()),
        },
    ] {
        let mut input = input(&repo);
        input.parent_metadata = Some(parent);
        assert_eq!(
            store
                .branch_create(&operation(&store, "branch.create").await, &input)
                .await
                .unwrap()
                .outcome,
            DomainOutcome::Applied
        );
    }
}

#[tokio::test]
#[ignore = "owned PostgreSQL; explicitly registered live target"]
async fn parent_head_advance_is_allowed_but_deleted_child_identity_is_permanent() {
    let (_, store, client) = setup::fixture(false).await;
    let repo = repository(&store).await;
    let mut input = input(&repo);
    input.parent_metadata = Some(BranchCreateParentMetadata {
        branch_id: repo.default_branch_id.clone(),
        metadata_hash: Some(repo.default_branch_metadata_hash.clone()),
    });
    // Simulate a separately committed parent push after preparation. Its metadata pointer stays fixed.
    client.execute("UPDATE lore_domain_branches SET latest_hash=$3, generation=generation+1 WHERE repository_id=$1 AND branch_id=$2", &[&repo.repository_id,&repo.default_branch_id,&vec![6u8;32]]).await.unwrap();
    assert_eq!(
        store
            .branch_create(&operation(&store, "branch.create").await, &input)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    let delete = BranchDeleteInput {
        repository_id: repo.repository_id.clone(),
        branch_id: input.branch_id.clone(),
        expected_generation: Some(1),
        delete_proof: vec![7; 32],
        projection: vec![],
        events: vec![],
    };
    assert_eq!(
        store
            .branch_delete(&operation(&store, "branch.delete").await, &delete)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    input.name = format!("renamed-{}", Uuid::now_v7());
    rejected(
        store
            .branch_create(&operation(&store, "branch.create").await, &input)
            .await
            .unwrap()
            .outcome,
        TOMBSTONED_V1,
    );
    assert!(
        !store
            .branch_snapshot(&input.repository_id, &input.branch_id)
            .await
            .unwrap()
            .unwrap()
            .live
    );
}

#[tokio::test]
#[ignore = "owned PostgreSQL; explicitly registered live target"]
async fn stale_metadata_epoch_rolls_back_and_lost_response_replays_one_event() {
    use lore_postgres::domain::fragments::MissingDiagnostic;
    use lore_postgres::domain::fragments::initialization::CleanCellInitialization;
    let (_, store, client) = setup::fixture(true).await;
    store
        .fragment_coordinator()
        .initialize_empty(
            &CleanCellInitialization::new(
                "branch-create-fixture".into(),
                "scoped-writer-v1".into(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    lore_postgres::domain::outbox::stamp_cutover(&client, "branch-create-test")
        .await
        .unwrap();
    let mut repo = repository_input();
    repo.default_branch_latest_hash = vec![0; 32];
    repo.metadata_witnesses = vec![
        witness::publish(&store, &repo.metadata_hash).await,
        witness::publish(&store, &repo.default_branch_metadata_hash).await,
    ];
    repo.events.push(
        lore_postgres::domain::outbox::builders::repository_published(
            "branch-create-test",
            &repo.repository_id,
            &repo.name,
            &repo.default_branch_id,
            "main",
        )
        .unwrap(),
    );
    assert_eq!(
        store
            .repository_create(&operation(&store, "repository.create").await, &repo)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    let mut stale = input(&repo);
    let old = witness::publish(&store, &stale.metadata_hash).await;
    store
        .fragment_coordinator()
        .mark_missing(&old, MissingDiagnostic::Absent)
        .await
        .unwrap();
    let current = witness::publish(&store, &stale.metadata_hash).await;
    assert_ne!(old, current);
    stale.metadata_witness = Some(old);
    rejected(
        store
            .branch_create(&operation(&store, "branch.create").await, &stale)
            .await
            .unwrap()
            .outcome,
        "branch_create_metadata_stale_v1",
    );
    assert_eq!(artifacts(&client, &stale).await, vec![0, 0, 0]);
    let count = client
        .query_one(
            "SELECT count(*) FROM lore_fragment_associations WHERE repository_id=$1 AND hash=$2",
            &[&repo.repository_id, &stale.metadata_hash],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(count, 0);
    let mut fresh = input(&repo);
    fresh.metadata_witness = Some(witness::publish(&store, &fresh.metadata_hash).await);
    fresh.events.push(
        lore_postgres::domain::outbox::builders::branch_created(
            "branch-create-test",
            &fresh.repository_id,
            &fresh.branch_id,
            &fresh.name,
            &fresh.latest_hash,
        )
        .unwrap(),
    );
    let op = operation(&store, "branch.create").await;
    // Deliberately discard the first acknowledgement, then reconstruct only from durable replay.
    let (first, second) = tokio::join!(
        store.branch_create(&op, &fresh),
        store.branch_create(&op, &fresh)
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.outcome, DomainOutcome::Applied);
    assert_eq!(second.outcome, DomainOutcome::Applied);
    assert_ne!(first.replayed, second.replayed);
    assert_eq!(first.public_result, second.public_result);
    for _ in 0..2 {
        let replay = store.branch_create_replay(&op).await.unwrap().unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.outcome, DomainOutcome::Applied);
        assert_eq!(replay.public_result, Some(fresh.public_result.clone()));
    }
    let events = client.query_one("SELECT count(*) FROM lore_outbox_events WHERE repository_id=$1 AND event_kind='branch.created'",&[&repo.repository_id]).await.unwrap().get::<_,i64>(0);
    assert_eq!(events, 1);
    let receipts = client
        .query_one(
            "SELECT count(*) FROM lore_domain_operation_receipts WHERE operation_id=$1",
            &[&op.key.operation_id.as_bytes().as_slice()],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(receipts, 1);
    assert_eq!(artifacts(&client, &fresh).await, vec![1, 1, 1]);
}

#[tokio::test]
#[ignore = "owned PostgreSQL; explicitly registered live target"]
async fn simultaneous_casefold_names_and_fresh_ids_have_one_winner() {
    let (_, store, client) = setup::fixture(false).await;
    let repo = repository(&store).await;
    for same_id in [false, true] {
        let mut a = input(&repo);
        a.name = format!("Race-{}", Uuid::now_v7());
        let mut b = input(&repo);
        if same_id {
            b.branch_id = a.branch_id.clone();
        } else {
            b.name = a.name.to_lowercase();
        }
        let op_a = operation(&store, "branch.create").await;
        let op_b = operation(&store, "branch.create").await;
        let (a_result, b_result) = tokio::join!(
            store.branch_create(&op_a, &a),
            store.branch_create(&op_b, &b)
        );
        let outcomes = [a_result.unwrap().outcome, b_result.unwrap().outcome];
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == DomainOutcome::Applied)
                .count(),
            1
        );
        let loser = outcomes
            .into_iter()
            .find(|o| *o != DomainOutcome::Applied)
            .unwrap();
        rejected(
            loser,
            if same_id {
                "branch_create_id_exists_v1"
            } else {
                NAME_TAKEN_V1
            },
        );
        let projections = client
            .query_one(
                "SELECT count(*) FROM lore_mutable WHERE partition=$1 AND key IN ($2,$3)",
                &[
                    &repo.repository_id,
                    &a.projection[0].key,
                    &b.projection[0].key,
                ],
            )
            .await
            .unwrap()
            .get::<_, i64>(0);
        assert_eq!(projections, 1);
    }
}

#[tokio::test]
#[ignore = "owned PostgreSQL; explicitly registered live target"]
async fn repository_delete_racing_create_never_publishes_after_the_tombstone() {
    let (_, store, client) = setup::fixture(false).await;
    let repo = repository(&store).await;
    let input = input(&repo);
    let create_op = operation(&store, "branch.create").await;
    let delete_op = operation(&store, "repository.delete").await;
    let delete = RepositoryDeleteInput {
        repository_id: repo.repository_id.clone(),
        expected_generation: Some(1),
        projection: vec![],
        events: vec![],
        ..delete_observations::repository_delete_input(&repo.repository_id).await
    };
    let (created, deleted) = tokio::join!(
        store.branch_create(&create_op, &input),
        store.repository_delete(&delete_op, &delete)
    );
    let created = created.unwrap();
    let deleted = deleted.unwrap();
    if created.outcome == DomainOutcome::Applied {
        rejected(
            deleted.outcome,
            lore_postgres::domain::coordinator::GENERATION_MISMATCH_V1,
        );
        // The newly created branch was absent from delete's preflight. A fresh
        // operation and complete observation must be used to delete it.
        let refreshed = delete_observations::repository_delete_input(&repo.repository_id).await;
        assert_eq!(
            store
                .repository_delete(&operation(&store, "repository.delete").await, &refreshed)
                .await
                .unwrap()
                .outcome,
            DomainOutcome::Applied
        );
    } else {
        assert_eq!(deleted.outcome, DomainOutcome::Applied);
    }
    match created.outcome {
        DomainOutcome::Applied => {
            assert_eq!(created.public_result, Some(input.public_result.clone()))
        }
        other => {
            rejected(other, TOMBSTONED_V1);
            assert_eq!(artifacts(&client, &input).await, vec![0, 0, 0]);
        }
    }
    let mut later = input.clone();
    later.branch_id = id();
    later.projection[0].key = later.branch_id.repeat(2);
    rejected(
        store
            .branch_create(&operation(&store, "branch.create").await, &later)
            .await
            .unwrap()
            .outcome,
        TOMBSTONED_V1,
    );
    assert_eq!(artifacts(&client, &later).await, vec![0, 0, 0]);
    assert!(
        !store
            .repository_snapshot(&repo.repository_id)
            .await
            .unwrap()
            .unwrap()
            .live
    );
}
