// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Real-Postgres regressions for the WP-116 activation review findings.
//!
//! These cases use the public [`DomainTransactionStore`] entry points. They do
//! not arm a test fence or insert an admission receipt directly. Run with
//! `LORE_TEST_PG_URL` and `-- --ignored --test-threads=1`.

use std::time::SystemTime;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::ADMISSION_REJECTED_V1;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::MutationResult;
use lore_postgres::domain::coordinator::NAME_TAKEN_V1;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PREPARED_HARD_TTL_EXPIRED_V1;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn store(url: &str) -> PostgresDomainStore {
    PostgresDomainStore::connect(url, 4, &TlsConfig::default())
        .await
        .expect("connect domain store")
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
) -> (GovernedOperation, AuthorizationWitness) {
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("read database clock");
    let operation_id = uuid_v7_at(clock);
    let key = ReceiptKey {
        verified_issuer: format!(
            "https://issuer.example/wp116-regressions/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "lorehub-control-plane".to_string(),
        tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
        operation_id,
    };
    let binding = binding(method);
    let witness = witness(operation_id);
    let prepared = store
        .domain_operation_prepare(&key, &binding, Some(&witness))
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

fn repository_create_input(name: String) -> RepositoryCreateInput {
    RepositoryCreateInput {
        repository_id: rand::random::<[u8; 16]>().to_vec(),
        name,
        metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_id: rand::random::<[u8; 16]>().to_vec(),
        default_branch_name: "main".to_string(),
        default_branch_metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_latest_hash: rand::random::<[u8; 32]>().to_vec(),
        creation_fingerprint: rand::random::<[u8; 32]>().to_vec(),
        creation_fingerprint_version: 1,
        projection: Vec::new(),
        event: None,
    }
}

fn not_applied(reason: &str) -> DomainOutcome {
    DomainOutcome::NotApplied {
        reason_version: 1,
        reason: reason.to_string(),
    }
}

#[tokio::test]
#[ignore = "needs live Postgres env; run with -- --ignored --test-threads=1"]
async fn prepare_creates_the_dispatch_fence_with_the_exact_verified_binding() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping prepare-created fence test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let (operation, witness) = admitted_operation(&store, "repository_create").await;

    let row = direct
        .query_one(
            "SELECT method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
                    authorization_id, authorization_revision, verification_nonce, \
                    bound_fields_digest, consumed_ticket_sha256, \
                    expected_claim_identity_digest, created_revision, safe_prune_after > created_at \
               FROM lore_domain_operation_dispatch_possibility_fences \
              WHERE verified_issuer=$1 AND authenticated_subject=$2 \
                AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &operation.key.verified_issuer,
                &operation.key.authenticated_subject,
                &operation.key.tenant_scope_key,
                &operation.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("prepare must publish one dispatch-possibility fence");

    assert_eq!(row.get::<_, String>("method"), operation.binding.method);
    assert_eq!(row.get::<_, Vec<u8>>("scope"), operation.binding.scope);
    assert_eq!(
        row.get::<_, i32>("fingerprint_version"),
        operation.binding.fingerprint_version
    );
    assert_eq!(
        row.get::<_, Vec<u8>>("fingerprint"),
        operation.binding.fingerprint
    );
    assert_eq!(
        row.get::<_, Vec<u8>>("canonical_intent_digest"),
        operation.binding.canonical_intent_digest
    );
    assert_eq!(
        row.get::<_, Vec<u8>>("authorization_id"),
        witness.authorization_id
    );
    assert_eq!(
        row.get::<_, i64>("authorization_revision"),
        witness.authorization_revision
    );
    assert_eq!(
        row.get::<_, Vec<u8>>("verification_nonce"),
        witness.verification_nonce
    );
    assert_eq!(
        row.get::<_, Vec<u8>>("bound_fields_digest"),
        witness.bound_fields_digest
    );
    assert_eq!(
        row.get::<_, Vec<u8>>("consumed_ticket_sha256"),
        witness.consumed_ticket_sha256
    );
    assert_eq!(
        row.get::<_, Vec<u8>>("expected_claim_identity_digest"),
        witness.expected_claim_identity_digest
    );
    assert_eq!(
        row.get::<_, i64>("created_revision"),
        witness.authorization_revision
    );
    assert!(row.get::<_, bool>(12), "fence retention must be nonempty");
}

#[tokio::test]
#[ignore = "needs live Postgres env; run with -- --ignored --test-threads=1"]
async fn repository_create_exact_replay_returns_the_committed_outcome() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping committed replay test");
        return;
    };
    let store = store(&url).await;
    let (operation, _) = admitted_operation(&store, "repository_create").await;
    let input = repository_create_input(format!("wp116-replay-{:016x}", rand::random::<u64>()));

    let first = store
        .repository_create(&operation, &input)
        .await
        .expect("first create");
    assert_eq!(first.outcome, DomainOutcome::Applied);

    let replay = store
        .repository_create(&operation, &input)
        .await
        .expect("exact replay");
    assert_eq!(
        replay,
        MutationResult {
            outcome: DomainOutcome::Applied,
            repository_generation: None,
            branch_generation: None,
        },
        "a consumed operation replays its committed outcome, never {ADMISSION_REJECTED_V1}"
    );
}

#[tokio::test]
#[ignore = "needs live Postgres env; run with -- --ignored --test-threads=1"]
async fn expired_prepare_terminalization_survives_the_coordinator_return() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping durable TTL test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let (operation, _) = admitted_operation(&store, "repository_create").await;
    direct
        .execute(
            "UPDATE lore_domain_operation_receipts \
                SET hard_expires_at=clock_timestamp()-interval '1 second' \
              WHERE verified_issuer=$1 AND authenticated_subject=$2 \
                AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &operation.key.verified_issuer,
                &operation.key.authenticated_subject,
                &operation.key.tenant_scope_key,
                &operation.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("age prepared receipt past hard TTL");

    let result = store
        .repository_create(
            &operation,
            &repository_create_input(format!("wp116-expired-{:016x}", rand::random::<u64>())),
        )
        .await
        .expect("expired admission is decisive");
    assert_eq!(result.outcome, not_applied(PREPARED_HARD_TTL_EXPIRED_V1));

    let row = direct
        .query_one(
            "SELECT state, consume_token, outcome, not_applied_reason \
               FROM lore_domain_operation_receipts \
              WHERE verified_issuer=$1 AND authenticated_subject=$2 \
                AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &operation.key.verified_issuer,
                &operation.key.authenticated_subject,
                &operation.key.tenant_scope_key,
                &operation.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("read durable expired receipt");
    assert_eq!(row.get::<_, i16>("state"), 1, "receipt is COMMITTED");
    assert!(row.get::<_, Option<Vec<u8>>>("consume_token").is_none());
    assert_eq!(row.get::<_, Option<i16>>("outcome"), Some(1));
    assert_eq!(
        row.get::<_, Option<String>>("not_applied_reason")
            .as_deref(),
        Some(PREPARED_HARD_TTL_EXPIRED_V1)
    );
}

#[tokio::test]
#[ignore = "needs live Postgres env; run with -- --ignored --test-threads=1"]
async fn concurrent_repository_create_name_conflict_is_decisive_name_taken() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping concurrent name conflict test");
        return;
    };
    let store_a = store(&url).await;
    let store_b = store(&url).await;
    let (operation_a, _) = admitted_operation(&store_a, "repository_create").await;
    let (operation_b, _) = admitted_operation(&store_b, "repository_create").await;
    let name = format!("wp116-name-race-{:016x}", rand::random::<u64>());
    let input_a = repository_create_input(name.clone());
    let input_b = repository_create_input(name);

    let (result_a, result_b) = tokio::join!(
        store_a.repository_create(&operation_a, &input_a),
        store_b.repository_create(&operation_b, &input_b),
    );
    let outcome_a = result_a.expect("first contender must be decisive").outcome;
    let outcome_b = result_b.expect("second contender must be decisive").outcome;
    assert!(
        matches!(
            (&outcome_a, &outcome_b),
            (DomainOutcome::Applied, DomainOutcome::NotApplied { reason, .. })
                | (DomainOutcome::NotApplied { reason, .. }, DomainOutcome::Applied)
                if reason == NAME_TAKEN_V1
        ),
        "exactly one create must apply and the loser must be {NAME_TAKEN_V1}: {outcome_a:?}, {outcome_b:?}"
    );
}
