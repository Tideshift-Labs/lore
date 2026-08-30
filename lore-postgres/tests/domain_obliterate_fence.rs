// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `begin_obliterate`'s repository-generation fence (CR-029 Phase 3;
//! `DomainTransactionStore`/`PostgresDomainStore` in
//! `lore-postgres/src/domain/{coordinator,postgres_coordinator}.rs`).
//!
//! `begin_obliterate` was the one mutation missing the `STATE_TOMBSTONED`
//! check every other coordinator method has, which would have let it bump a
//! tombstoned repository's generation. Two cases: a live repository advances
//! by exactly one, and a tombstoned one is refused with the generation
//! unchanged. A third test pins the actual point of the fence: the
//! generation `begin_obliterate` writes is the same value
//! `branch_push_commit` checks a push against, so a push holding the
//! pre-obliteration generation is refused and one holding the post-
//! obliteration generation succeeds.
//!
//! Gated on `LORE_TEST_PG_URL`; skipped when unset. Isolated per test by a
//! random repository/branch identity since the domain tables are shared.

use std::time::SystemTime;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::BranchPushCommitInput;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GENERATION_MISMATCH_V1;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;
use lore_postgres::domain::coordinator::TOMBSTONED_V1;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::admission_clock;
use lore_postgres::domain::receipts::prepare;
use lore_postgres::pool::TlsConfig;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn pg_client(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect for direct test setup");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

fn uuid_v7_at(ts: SystemTime) -> Uuid {
    let since_epoch = ts
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("timestamp must be after the Unix epoch");
    Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        since_epoch.as_secs(),
        since_epoch.subsec_nanos(),
    ))
}

fn isolated_key(operation_id: Uuid) -> ReceiptKey {
    ReceiptKey {
        verified_issuer: format!(
            "https://issuer.example/wp116-obliterate/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "svc:wp116-obliterate-test".to_string(),
        tenant_scope_key: rand::random::<[u8; 8]>().to_vec(),
        operation_id,
    }
}

fn binding(method: &str) -> OperationBinding {
    OperationBinding {
        method: method.to_string(),
        scope: rand::random::<[u8; 8]>().to_vec(),
        fingerprint_version: 1,
        fingerprint: rand::random::<[u8; 32]>().to_vec(),
        canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

/// Prepare one admissible receipt in its own transaction, ahead of the
/// mutation, matching the real production ordering: `domain_operation_prepare`
/// runs before the mutation transaction that consumes its token.
async fn admitted_operation(url: &str, method: &str) -> GovernedOperation {
    let mut client = pg_client(url).await;
    let tx = client.transaction().await.expect("begin prepare tx");
    let clock = admission_clock(&tx).await.expect("read admission clock");
    let key = isolated_key(uuid_v7_at(clock));
    let op_binding = binding(method);
    let result = prepare(&tx, &key, &op_binding, None)
        .await
        .expect("prepare must not error");
    tx.commit().await.expect("commit prepare");
    let PrepareResult::Prepared { token, .. } = result else {
        panic!("expected an admissible prepare to yield Prepared, got {result:?}");
    };
    GovernedOperation {
        key,
        binding: op_binding,
        prepare_token: token,
    }
}

fn not_applied(reason: &str) -> DomainOutcome {
    DomainOutcome::NotApplied {
        reason_version: 1,
        reason: reason.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn repository_create_input(
    repository_id: &[u8; 16],
    name: String,
    default_branch_id: &[u8; 16],
    default_branch_name: &str,
    default_branch_latest_hash: &[u8; 32],
) -> RepositoryCreateInput {
    RepositoryCreateInput {
        repository_id: repository_id.to_vec(),
        name,
        metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_id: default_branch_id.to_vec(),
        default_branch_name: default_branch_name.to_string(),
        default_branch_metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_latest_hash: default_branch_latest_hash.to_vec(),
        creation_fingerprint: rand::random::<[u8; 32]>().to_vec(),
        creation_fingerprint_version: 1,
        projection: Vec::new(),
        event: None,
    }
}

/// The two cases the tombstone check exists for: a live repository's
/// generation advances by exactly one, and a tombstoned one is refused with
/// the generation left exactly where the tombstoning transaction left it.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn begin_obliterate_advances_live_generation_and_refuses_a_tombstoned_repository() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping begin_obliterate tombstone test");
        return;
    };
    let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store");

    let repository_id: [u8; 16] = rand::random();
    let branch_id: [u8; 16] = rand::random();
    let create_op = admitted_operation(&url, "lore.domain.v1.test/ObliterateFenceCreate").await;
    let create_input = repository_create_input(
        &repository_id,
        format!("obliterate-fence-{:016x}", rand::random::<u64>()),
        &branch_id,
        "main",
        &rand::random::<[u8; 32]>(),
    );
    let created = store
        .repository_create(&create_op, &create_input)
        .await
        .expect("repository_create must not error");
    assert_eq!(created.outcome, DomainOutcome::Applied);
    assert_eq!(created.repository_generation, Some(1));

    // A live repository advances by exactly one.
    let obliterate_op = admitted_operation(&url, "lore.domain.v1.test/ObliterateFenceLive").await;
    let obliterated = store
        .begin_obliterate(&obliterate_op, &repository_id)
        .await
        .expect("begin_obliterate on a live repository must not error");
    assert_eq!(obliterated.outcome, DomainOutcome::Applied);
    assert_eq!(
        obliterated.repository_generation,
        Some(2),
        "the fence must advance the generation by exactly one"
    );

    let snapshot = store
        .repository_snapshot(&repository_id)
        .await
        .expect("read snapshot")
        .expect("repository must exist");
    assert!(snapshot.live);
    assert_eq!(snapshot.generation, 2);

    // Tombstone the repository.
    let delete_op = admitted_operation(&url, "lore.domain.v1.test/ObliterateFenceDelete").await;
    let delete_input = RepositoryDeleteInput {
        repository_id: repository_id.to_vec(),
        expected_generation: None,
        delete_proof: rand::random::<[u8; 32]>().to_vec(),
        projection: Vec::new(),
        event: None,
    };
    let deleted = store
        .repository_delete(&delete_op, &delete_input)
        .await
        .expect("repository_delete must not error");
    assert_eq!(deleted.outcome, DomainOutcome::Applied);
    let tombstoned_generation = deleted
        .repository_generation
        .expect("an applied delete reports its generation");

    // A tombstoned repository is refused, and its generation must not move.
    let obliterate_after_delete =
        admitted_operation(&url, "lore.domain.v1.test/ObliterateFenceTombstoned").await;
    let refused = store
        .begin_obliterate(&obliterate_after_delete, &repository_id)
        .await
        .expect("begin_obliterate on a tombstoned repository must not error");
    assert_eq!(refused.outcome, not_applied(TOMBSTONED_V1));
    assert_eq!(
        refused.repository_generation, None,
        "a rejected obliterate reports no generation (MutationResult::rejected)"
    );

    let final_snapshot = store
        .repository_snapshot(&repository_id)
        .await
        .expect("read snapshot")
        .expect("the tombstoned row must still exist");
    assert!(!final_snapshot.live);
    assert_eq!(
        final_snapshot.generation, tombstoned_generation,
        "a refused obliterate must leave the tombstoned generation exactly where delete left it"
    );
}

/// The actual point of the fence: `begin_obliterate`'s generation write and
/// `branch_push_commit`'s generation check must agree. A push carrying the
/// pre-obliteration generation is refused; the same push carrying the
/// post-obliteration generation succeeds.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn begin_obliterate_and_branch_push_commit_agree_on_the_repository_generation() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping obliterate/push generation-agreement test");
        return;
    };
    let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store");

    let repository_id: [u8; 16] = rand::random();
    let branch_id: [u8; 16] = rand::random();
    let initial_latest_hash: [u8; 32] = rand::random();
    let create_op = admitted_operation(&url, "lore.domain.v1.test/ObliteratePushCreate").await;
    let create_input = repository_create_input(
        &repository_id,
        format!("obliterate-push-fence-{:016x}", rand::random::<u64>()),
        &branch_id,
        "main",
        &initial_latest_hash,
    );
    let created = store
        .repository_create(&create_op, &create_input)
        .await
        .expect("repository_create must not error");
    assert_eq!(created.repository_generation, Some(1));
    assert_eq!(created.branch_generation, Some(1));

    let obliterate_op = admitted_operation(&url, "lore.domain.v1.test/ObliteratePushFence").await;
    let obliterated = store
        .begin_obliterate(&obliterate_op, &repository_id)
        .await
        .expect("begin_obliterate must not error");
    assert_eq!(obliterated.repository_generation, Some(2));

    let new_latest_hash: [u8; 32] = rand::random();

    // Stale push: still carries the pre-obliteration repository generation.
    let stale_push_op = admitted_operation(&url, "lore.domain.v1.test/ObliteratePushStale").await;
    let stale_push_input = BranchPushCommitInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        expected_repository_generation: 1,
        expected_branch_generation: 1,
        expected_repository_lock_generation: 1,
        expected_branch_lock_generation: 1,
        expected_branch_lock_namespace_last_applied_fence: 0,
        expected_latest_hash: initial_latest_hash.to_vec(),
        new_latest_hash: new_latest_hash.to_vec(),
        projection: Vec::new(),
        event: None,
    };
    let stale_result = store
        .branch_push_commit(&stale_push_op, &stale_push_input)
        .await
        .expect("stale branch_push_commit must not error");
    assert_eq!(
        stale_result.outcome,
        not_applied(GENERATION_MISMATCH_V1),
        "a push holding the pre-obliteration generation must be refused"
    );

    let branch_after_stale = store
        .branch_snapshot(&repository_id, &branch_id)
        .await
        .expect("read branch snapshot")
        .expect("branch must exist");
    assert_eq!(
        branch_after_stale.generation, 1,
        "a refused push must not advance the branch"
    );
    assert_eq!(
        branch_after_stale.latest_hash,
        initial_latest_hash.to_vec(),
        "a refused push must not publish its tip"
    );

    // The same push, carrying the post-obliteration generation, must succeed —
    // proving begin_obliterate's write and branch_push_commit's check agree.
    let correct_push_op =
        admitted_operation(&url, "lore.domain.v1.test/ObliteratePushCorrect").await;
    let correct_push_input = BranchPushCommitInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        expected_repository_generation: 2,
        expected_branch_generation: 1,
        expected_repository_lock_generation: 2,
        expected_branch_lock_generation: 1,
        expected_branch_lock_namespace_last_applied_fence: 0,
        expected_latest_hash: initial_latest_hash.to_vec(),
        new_latest_hash: new_latest_hash.to_vec(),
        projection: Vec::new(),
        event: None,
    };
    let correct_result = store
        .branch_push_commit(&correct_push_op, &correct_push_input)
        .await
        .expect("correct branch_push_commit must not error");
    assert_eq!(correct_result.outcome, DomainOutcome::Applied);
    assert_eq!(correct_result.branch_generation, Some(2));

    let branch_after_correct = store
        .branch_snapshot(&repository_id, &branch_id)
        .await
        .expect("read branch snapshot")
        .expect("branch must exist");
    assert_eq!(branch_after_correct.generation, 2);
    assert_eq!(branch_after_correct.latest_hash, new_latest_hash.to_vec());
}
