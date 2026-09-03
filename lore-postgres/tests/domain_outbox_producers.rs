// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-116 outbox-producer wiring: coordinator-level atomicity and no-row
//! rules for the six governed methods `outbox::append` reaches
//! (`repository_create`, `repository_delete`, `metadata_compare_and_swap`,
//! `branch_push_commit`, `acquire_or_renew`, `release`) plus `begin_obliterate`
//! (CR-032 PIN-3), per CR-032's exhaustive event classification and the
//! WP-119 writer inventory
//! (`lorehub/docs/work-packages/wp-119-writer-inventory.md`).
//!
//! # Scope and a deliberate limitation
//!
//! These tests drive each governed coordinator method directly with a
//! **hand-built `PendingEvent`** rather than through the production event
//! builders in `lore-postgres/src/domain/outbox/builders.rs`. As of this
//! writing that module does not exist yet (WP-116's producer-builder work is
//! still landing). What this file proves is the **coordinator's own
//! contract** given an arbitrary well-formed event: exactly-once atomic
//! append, the documented no-row rules, and the idempotency-key derivation
//! -- independent of whether a specific production call site builds the
//! "right" event yet. It does **not** prove that any production writer
//! currently supplies `Some(event)` (per the WP-119 inventory, none does at
//! `ee171ce`) or that a builder's output matches the pinned
//! `event-kinds.json`/`aggregate-version.json` fixtures -- that is separate,
//! additional coverage owed once `builders.rs` lands, and is not a
//! substitute for it.
//!
//! `PendingEvent.aggregate_ordinal` is a [`CommittedOrdinal`] rather than a
//! caller-supplied number: the coordinator resolves it from the values its
//! own transaction actually committed (`CommittedVersions`), so these tests
//! deliberately do not pre-compute an expected generation for the ordinal --
//! only the *identity* half (`aggregate_identity`) is caller-supplied, and is
//! asserted against exactly.
//!
//! Gated on `LORE_TEST_PG_URL`; skipped when unset. Isolated per test by
//! random repository/branch/cell identities since the tables are shared.

use std::time::SystemTime;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::ADMISSION_REJECTED_V1;
use lore_postgres::domain::coordinator::BranchPushCommitInput;
use lore_postgres::domain::coordinator::CommittedOrdinal;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::MetadataCasInput;
use lore_postgres::domain::coordinator::PendingEvent;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::OperationBinding;
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

/// Connect and install SCHEMA-117 before any domain row exists.
///
/// `branch_push_commit` revalidates CR-030's push witness against
/// `lore_domain_lock_namespaces`, and that row is created by an after-insert
/// trigger on `lore_domain_branches` -- so the lock schema must be installed
/// *before* the first `repository_create`, not merely before the push call
/// (INV-EE P1-3; see `domain_obliterate_fence.rs`'s identical setup).
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

/// Prepare a fresh governed operation. Each call mints an independent
/// `ReceiptKey`/token pair, i.e. a genuinely new admission, not a retry of a
/// prior one -- callers that want to prove a *retry* reuse the returned
/// `GovernedOperation` a second time against the same coordinator method.
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

fn cell_id() -> String {
    format!("cell-{:016x}", rand::random::<u64>())
}

/// A well-formed `PendingEvent`. The literals default to CR-032 PIN-4's
/// pinned `repository`/`repository.published` pair; override `event_kind`
/// and `aggregate_kind` per case. This is a **test-authored** event, not the
/// production builder's output -- see the module docs.
fn pending_event(
    aggregate_id: Vec<u8>,
    aggregate_ordinal: CommittedOrdinal,
    aggregate_identity: Vec<u8>,
) -> PendingEvent {
    PendingEvent {
        cell_id: cell_id(),
        event_kind: "repository.published".to_string(),
        aggregate_kind: "repository".to_string(),
        aggregate_id,
        aggregate_ordinal,
        aggregate_identity,
        payload_schema_version: 1,
        payload: b"{}".to_vec(),
    }
}

async fn outbox_row_count_for_repository(client: &Client, repository_id: &[u8]) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM lore_outbox_events WHERE repository_id = $1",
            &[&repository_id],
        )
        .await
        .expect("count outbox rows for repository")
        .get(0)
}

struct OutboxRow {
    event_kind: String,
    aggregate_kind: String,
    aggregate_id: Vec<u8>,
    aggregate_version: Vec<u8>,
    repository_generation: i64,
    idempotency_key: Vec<u8>,
    cell_id: String,
}

async fn one_outbox_row_for_repository(client: &Client, repository_id: &[u8]) -> OutboxRow {
    let row = client
        .query_one(
            "SELECT event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                    repository_generation, idempotency_key, cell_id \
             FROM lore_outbox_events WHERE repository_id = $1",
            &[&repository_id],
        )
        .await
        .expect("exactly one outbox row for repository");
    OutboxRow {
        event_kind: row.get("event_kind"),
        aggregate_kind: row.get("aggregate_kind"),
        aggregate_id: row.get("aggregate_id"),
        aggregate_version: row.get("aggregate_version"),
        repository_generation: row.get("repository_generation"),
        idempotency_key: row.get("idempotency_key"),
        cell_id: row.get("cell_id"),
    }
}

fn repository_create_input(
    repository_id: Vec<u8>,
    name: String,
    event: Option<PendingEvent>,
) -> RepositoryCreateInput {
    RepositoryCreateInput {
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
        event,
    }
}

fn rand_repo_id() -> Vec<u8> {
    rand::random::<[u8; 16]>().to_vec()
}

fn rand_name() -> String {
    format!("wp116-producers-{:016x}", rand::random::<u64>())
}

// ---------------------------------------------------------------------------
// repository_create
// ---------------------------------------------------------------------------

/// A committed `repository_create` with a supplied event leaves exactly one
/// outbox row whose `aggregate_id` is the 16 repository bytes, whose
/// `aggregate_version` decodes to the actual committed repository generation
/// (1, the first generation) with an empty identity per CR-032 PIN-4's
/// `repository` row, and whose outer `repository_generation` column matches
/// the same value.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn repository_create_wired_event_commits_exactly_one_row_with_pinned_fields() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();
    let (operation, _witness) = admitted_operation(&store, "repository_create").await;

    let event = pending_event(
        repository_id.clone(),
        CommittedOrdinal::RepositoryGeneration,
        Vec::new(),
    );
    let input = repository_create_input(repository_id.clone(), rand_name(), Some(event));

    let result = store
        .repository_create(&operation, &input)
        .await
        .expect("repository_create must succeed");
    assert!(matches!(result.outcome, DomainOutcome::Applied));
    assert_eq!(result.repository_generation, Some(1));

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1,
        "a committed create with a supplied event must leave exactly one row"
    );
    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.event_kind, "repository.published");
    assert_eq!(row.aggregate_kind, "repository");
    assert_eq!(row.aggregate_id, repository_id);
    assert_eq!(row.repository_generation, 1);
    let decoded =
        AggregateVersion::decode(&row.aggregate_version).expect("decode aggregate_version");
    assert_eq!(
        decoded.ordinal, 1,
        "ordinal must be the actual committed repository generation, not a caller guess"
    );
    assert!(
        decoded.identity.is_empty(),
        "repository-kind identity is empty per PIN-4"
    );
}

/// A losing writer (name already taken by a different repository) commits
/// `NOT_APPLIED` and must leave no row, even though a `Some(event)` was
/// supplied -- the coordinator returns before `append_event` on this path.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn repository_create_name_taken_rejection_leaves_no_row_even_with_event_supplied() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let name = rand_name();

    let (first_op, _w) = admitted_operation(&store, "repository_create").await;
    let first_id = rand_repo_id();
    let first_input = repository_create_input(first_id.clone(), name.clone(), None);
    let first = store
        .repository_create(&first_op, &first_input)
        .await
        .expect("first create must succeed");
    assert!(matches!(first.outcome, DomainOutcome::Applied));

    let (second_op, _w) = admitted_operation(&store, "repository_create").await;
    let second_id = rand_repo_id();
    let second_input = repository_create_input(
        second_id.clone(),
        name,
        Some(pending_event(
            second_id.clone(),
            CommittedOrdinal::RepositoryGeneration,
            Vec::new(),
        )),
    );
    let second = store
        .repository_create(&second_op, &second_input)
        .await
        .expect("second create call must return a decisive rejection, not an error");
    assert!(
        matches!(second.outcome, DomainOutcome::NotApplied { .. }),
        "a name collision must be NOT_APPLIED, got {:?}",
        second.outcome
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &second_id).await,
        0,
        "a losing writer must leave no row for the rejected repository id"
    );
}

/// An exact create retry (same repository id and creation fingerprint, via a
/// brand-new governed operation) returns the original committed generation
/// and must not create a second row -- the coordinator's own fingerprint
/// match returns before `append_event` runs a second time.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn repository_create_exact_fingerprint_retry_leaves_no_second_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();
    let name = rand_name();

    let (first_op, _w) = admitted_operation(&store, "repository_create").await;
    let mut input = repository_create_input(
        repository_id.clone(),
        name.clone(),
        Some(pending_event(
            repository_id.clone(),
            CommittedOrdinal::RepositoryGeneration,
            Vec::new(),
        )),
    );
    let first = store
        .repository_create(&first_op, &input)
        .await
        .expect("first create must succeed");
    assert!(matches!(first.outcome, DomainOutcome::Applied));
    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );

    // A second, independently-admitted operation with the identical
    // repository id + creation fingerprint is an "exact retry" by the
    // coordinator's own rule (not the outbox's ON CONFLICT dedupe -- a
    // different mechanism entirely; see the module docs).
    let (second_op, _w) = admitted_operation(&store, "repository_create").await;
    input.event = Some(pending_event(
        repository_id.clone(),
        CommittedOrdinal::RepositoryGeneration,
        Vec::new(),
    ));
    let second = store
        .repository_create(&second_op, &input)
        .await
        .expect("exact retry must succeed");
    assert!(matches!(second.outcome, DomainOutcome::Applied));
    assert_eq!(second.repository_generation, Some(1));

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1,
        "an exact fingerprint retry must not create a second outbox row"
    );
}

// ---------------------------------------------------------------------------
// repository_delete
// ---------------------------------------------------------------------------

/// Deleting an absent repository is a decisive `NOT_FOUND` rejection and must
/// leave no row.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn repository_delete_not_found_rejection_leaves_no_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();
    let (operation, _w) = admitted_operation(&store, "repository_delete").await;

    let input = RepositoryDeleteInput {
        repository_id: repository_id.clone(),
        expected_generation: None,
        delete_proof: rand::random::<[u8; 32]>().to_vec(),
        projection: Vec::new(),
        event: Some(pending_event(
            repository_id.clone(),
            CommittedOrdinal::RepositoryGeneration,
            Vec::new(),
        )),
    };
    let result = store
        .repository_delete(&operation, &input)
        .await
        .expect("delete of an absent repository must return a decisive result");
    assert!(matches!(result.outcome, DomainOutcome::NotApplied { .. }));

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
}

/// A repository tombstone commits exactly one `repository.tombstoned`-shaped
/// row whose ordinal is the actual post-tombstone generation (2, after the
/// create's generation 1).
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn repository_delete_commits_exactly_one_row_at_the_tombstone_generation() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();

    let (create_op, _w) = admitted_operation(&store, "repository_create").await;
    let create_input = repository_create_input(repository_id.clone(), rand_name(), None);
    store
        .repository_create(&create_op, &create_input)
        .await
        .expect("create must succeed");
    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0,
        "create with no event supplied leaves no row"
    );

    let (delete_op, _w) = admitted_operation(&store, "repository_delete").await;
    let delete_input = RepositoryDeleteInput {
        repository_id: repository_id.clone(),
        expected_generation: Some(1),
        delete_proof: rand::random::<[u8; 32]>().to_vec(),
        projection: Vec::new(),
        event: Some({
            let mut e = pending_event(
                repository_id.clone(),
                CommittedOrdinal::RepositoryGeneration,
                Vec::new(),
            );
            e.event_kind = "repository.tombstoned".to_string();
            e
        }),
    };
    let result = store
        .repository_delete(&delete_op, &delete_input)
        .await
        .expect("delete must succeed");
    assert!(matches!(result.outcome, DomainOutcome::Applied));
    assert_eq!(result.repository_generation, Some(2));

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );
    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.event_kind, "repository.tombstoned");
    assert_eq!(row.repository_generation, 2);
    let decoded = AggregateVersion::decode(&row.aggregate_version).expect("decode");
    assert_eq!(decoded.ordinal, 2);
}

/// An exact delete retry against an already-tombstoned repository is
/// idempotent success and must not create a second row -- the coordinator
/// returns before `append_event` on the tombstone-preserved path.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn repository_delete_retry_on_an_already_tombstoned_repository_leaves_no_second_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();

    let (create_op, _w) = admitted_operation(&store, "repository_create").await;
    store
        .repository_create(
            &create_op,
            &repository_create_input(repository_id.clone(), rand_name(), None),
        )
        .await
        .expect("create must succeed");

    let delete_proof = rand::random::<[u8; 32]>().to_vec();
    let (first_delete_op, _w) = admitted_operation(&store, "repository_delete").await;
    let first_delete = RepositoryDeleteInput {
        repository_id: repository_id.clone(),
        expected_generation: None,
        delete_proof: delete_proof.clone(),
        projection: Vec::new(),
        event: Some(pending_event(
            repository_id.clone(),
            CommittedOrdinal::RepositoryGeneration,
            Vec::new(),
        )),
    };
    let first = store
        .repository_delete(&first_delete_op, &first_delete)
        .await
        .expect("first delete must succeed");
    assert!(matches!(first.outcome, DomainOutcome::Applied));
    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );

    // A second, independently-admitted delete against the already-tombstoned
    // repository.
    let (second_delete_op, _w) = admitted_operation(&store, "repository_delete").await;
    let second_delete = RepositoryDeleteInput {
        repository_id: repository_id.clone(),
        expected_generation: None,
        delete_proof,
        projection: Vec::new(),
        event: Some(pending_event(
            repository_id.clone(),
            CommittedOrdinal::RepositoryGeneration,
            Vec::new(),
        )),
    };
    let second = store
        .repository_delete(&second_delete_op, &second_delete)
        .await
        .expect("retry delete must succeed idempotently");
    assert!(matches!(second.outcome, DomainOutcome::Applied));

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1,
        "a delete retry against an already-tombstoned repository must not add a second row"
    );
}

// ---------------------------------------------------------------------------
// metadata_compare_and_swap
// ---------------------------------------------------------------------------

/// A CAS mismatch is a decisive rejection and must leave no row.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn metadata_cas_mismatch_leaves_no_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();

    let (create_op, _w) = admitted_operation(&store, "repository_create").await;
    store
        .repository_create(
            &create_op,
            &repository_create_input(repository_id.clone(), rand_name(), None),
        )
        .await
        .expect("create must succeed");

    let (cas_op, _w) = admitted_operation(&store, "metadata_compare_and_swap").await;
    let cas_input = MetadataCasInput {
        repository_id: repository_id.clone(),
        branch_id: None,
        expected_hash: rand::random::<[u8; 32]>().to_vec(), // deliberately wrong
        new_hash: rand::random::<[u8; 32]>().to_vec(),
        projection: Vec::new(),
        event: Some({
            let mut e = pending_event(
                repository_id.clone(),
                CommittedOrdinal::RepositoryGeneration,
                Vec::new(),
            );
            e.event_kind = "repository.metadata_changed".to_string();
            e
        }),
    };
    let result = store
        .metadata_compare_and_swap(&cas_op, &cas_input)
        .await
        .expect("mismatched CAS must return a decisive rejection");
    assert!(matches!(result.outcome, DomainOutcome::NotApplied { .. }));

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
}

/// A successful repository-metadata CAS commits exactly one row at the new
/// generation.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn metadata_cas_success_commits_exactly_one_row_with_the_new_generation() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();

    let (create_op, _w) = admitted_operation(&store, "repository_create").await;
    let create_input = repository_create_input(repository_id.clone(), rand_name(), None);
    let original_metadata_hash = create_input.metadata_hash.clone();
    store
        .repository_create(&create_op, &create_input)
        .await
        .expect("create must succeed");

    let (cas_op, _w) = admitted_operation(&store, "metadata_compare_and_swap").await;
    let cas_input = MetadataCasInput {
        repository_id: repository_id.clone(),
        branch_id: None,
        expected_hash: original_metadata_hash,
        new_hash: rand::random::<[u8; 32]>().to_vec(),
        projection: Vec::new(),
        event: Some({
            let mut e = pending_event(
                repository_id.clone(),
                CommittedOrdinal::RepositoryGeneration,
                Vec::new(),
            );
            e.event_kind = "repository.metadata_changed".to_string();
            e
        }),
    };
    let result = store
        .metadata_compare_and_swap(&cas_op, &cas_input)
        .await
        .expect("CAS must succeed");
    assert!(matches!(result.outcome, DomainOutcome::Applied));
    assert_eq!(result.repository_generation, Some(2));

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );
    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.event_kind, "repository.metadata_changed");
    assert_eq!(row.repository_generation, 2);
}

// ---------------------------------------------------------------------------
// branch_push_commit
// ---------------------------------------------------------------------------

async fn create_repository_and_branch(store: &PostgresDomainStore) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let repository_id = rand_repo_id();
    let (create_op, _w) = admitted_operation(store, "repository_create").await;
    let create_input = repository_create_input(repository_id.clone(), rand_name(), None);
    let branch_id = create_input.default_branch_id.clone();
    let initial_head = create_input.default_branch_latest_hash.clone();
    store
        .repository_create(&create_op, &create_input)
        .await
        .expect("create must succeed");
    (repository_id, branch_id, initial_head)
}

/// A current-head push (`expected_latest_hash == new_latest_hash`) is
/// CR-032's classified no-event transition (inventory C1). This proves the
/// coordinator's own suppression point: `branch_push_commit` returns
/// `Applied` *before* it ever reaches `append_event` on this path, so a
/// row is never written even though a `Some(event)` is supplied.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_push_current_head_noop_leaves_no_row_even_with_event_supplied() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let (repository_id, branch_id, head) = create_repository_and_branch(&store).await;

    let (push_op, _w) = admitted_operation(&store, "branch_push_commit").await;
    let push_input = BranchPushCommitInput {
        repository_id: repository_id.clone(),
        branch_id,
        expected_repository_generation: 1,
        expected_branch_generation: 1,
        // The after-insert trigger that creates the lock namespace row seeds
        // both lock generations at 1, not 0 -- confirmed live (this test
        // failed with Contention against 0 before the fix).
        expected_repository_lock_generation: 1,
        expected_branch_lock_generation: 1,
        expected_branch_lock_namespace_last_applied_fence: 0,
        expected_latest_hash: head.clone(),
        new_latest_hash: head.clone(), // same as expected: current-head no-op
        projection: Vec::new(),
        event: Some({
            let mut e = pending_event(
                repository_id.clone(),
                CommittedOrdinal::BranchGeneration,
                head,
            );
            e.event_kind = "branch.pushed".to_string();
            e.aggregate_kind = "branch".to_string();
            e
        }),
    };
    let result = store
        .branch_push_commit(&push_op, &push_input)
        .await
        .expect("current-head push must succeed");
    assert!(matches!(result.outcome, DomainOutcome::Applied));

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0,
        "a current-head no-op push must leave no outbox row (CR-032 inventory C1)"
    );
}

/// A genuine tip advance commits exactly one row whose `aggregate_version`
/// ordinal is the actual committed branch generation and whose identity is
/// the new tip hash, per CR-032 PIN-4's `branch` row (ordinal: branch
/// generation, identity: exact revision hash).
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_push_tip_advance_commits_exactly_one_row_with_branch_generation_and_revision_identity()
 {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let (repository_id, branch_id, head) = create_repository_and_branch(&store).await;

    let new_head = rand::random::<[u8; 32]>().to_vec();
    let (push_op, _w) = admitted_operation(&store, "branch_push_commit").await;
    let push_input = BranchPushCommitInput {
        repository_id: repository_id.clone(),
        branch_id,
        expected_repository_generation: 1,
        expected_branch_generation: 1,
        // See the current-head no-op test's comment: the namespace trigger
        // seeds both lock generations at 1.
        expected_repository_lock_generation: 1,
        expected_branch_lock_generation: 1,
        expected_branch_lock_namespace_last_applied_fence: 0,
        expected_latest_hash: head,
        new_latest_hash: new_head.clone(),
        projection: Vec::new(),
        event: Some({
            let mut e = pending_event(
                repository_id.clone(),
                CommittedOrdinal::BranchGeneration,
                new_head.clone(),
            );
            e.event_kind = "branch.pushed".to_string();
            e.aggregate_kind = "branch".to_string();
            e
        }),
    };
    let result = store
        .branch_push_commit(&push_op, &push_input)
        .await
        .expect("tip advance must succeed");
    assert!(matches!(result.outcome, DomainOutcome::Applied));
    assert_eq!(result.branch_generation, Some(2));
    assert_eq!(
        result.repository_generation,
        Some(1),
        "push does not bump the repository generation"
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );
    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.event_kind, "branch.pushed");
    assert_eq!(row.aggregate_kind, "branch");
    // The outer OutboxEvent.repository_generation is the repository row's
    // generation at commit time (1), independent of the branch generation
    // encoded inside aggregate_version (2) -- these are deliberately
    // different numbers; conflating them would be the bug this pins.
    assert_eq!(row.repository_generation, 1);
    let decoded = AggregateVersion::decode(&row.aggregate_version).expect("decode");
    assert_eq!(
        decoded.ordinal, 2,
        "ordinal must be the actual committed branch generation"
    );
    assert_eq!(
        decoded.identity, new_head,
        "identity must be the exact new revision hash"
    );
}

/// A generation-mismatch CAS rejection (preflight went stale) is a decisive
/// `NOT_APPLIED` and must leave no row.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_push_cas_mismatch_leaves_no_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let (repository_id, branch_id, _head) = create_repository_and_branch(&store).await;

    let (push_op, _w) = admitted_operation(&store, "branch_push_commit").await;
    let push_input = BranchPushCommitInput {
        repository_id: repository_id.clone(),
        branch_id,
        expected_repository_generation: 1,
        expected_branch_generation: 1,
        expected_repository_lock_generation: 0,
        expected_branch_lock_generation: 0,
        expected_branch_lock_namespace_last_applied_fence: 0,
        expected_latest_hash: rand::random::<[u8; 32]>().to_vec(), // deliberately stale
        new_latest_hash: rand::random::<[u8; 32]>().to_vec(),
        projection: Vec::new(),
        event: Some(pending_event(
            repository_id.clone(),
            CommittedOrdinal::BranchGeneration,
            Vec::new(),
        )),
    };
    let result = store
        .branch_push_commit(&push_op, &push_input)
        .await
        .expect("stale preflight must return a decisive rejection");
    assert!(matches!(result.outcome, DomainOutcome::NotApplied { .. }));

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
}

// ---------------------------------------------------------------------------
// begin_obliterate (CR-032 PIN-3)
// ---------------------------------------------------------------------------

/// `begin_obliterate` commits exactly one `repository.obliterated` row per
/// commit, ordinal the committed repository generation, empty identity, per
/// CR-032 PIN-3.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn begin_obliterate_commits_exactly_one_repository_obliterated_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();

    let (create_op, _w) = admitted_operation(&store, "repository_create").await;
    store
        .repository_create(
            &create_op,
            &repository_create_input(repository_id.clone(), rand_name(), None),
        )
        .await
        .expect("create must succeed");

    let (obliterate_op, _w) = admitted_operation(&store, "begin_obliterate").await;
    let event = pending_event(
        repository_id.clone(),
        CommittedOrdinal::RepositoryGeneration,
        Vec::new(),
    );
    let mut event = event;
    event.event_kind = "repository.obliterated".to_string();
    let result = store
        .begin_obliterate(&obliterate_op, &repository_id, Some(&event))
        .await
        .expect("begin_obliterate must succeed");
    assert!(matches!(result.outcome, DomainOutcome::Applied));
    assert_eq!(result.repository_generation, Some(2));

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );
    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.event_kind, "repository.obliterated");
    assert_eq!(row.aggregate_kind, "repository");
    assert_eq!(row.aggregate_id, repository_id);
    assert_eq!(row.repository_generation, 2);
    let decoded = AggregateVersion::decode(&row.aggregate_version).expect("decode");
    assert_eq!(decoded.ordinal, 2);
    assert!(decoded.identity.is_empty());
}

/// `begin_obliterate` against a tombstoned repository is a decisive
/// rejection and must leave no row, even with an event supplied.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn begin_obliterate_on_a_tombstoned_repository_leaves_no_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();

    let (create_op, _w) = admitted_operation(&store, "repository_create").await;
    store
        .repository_create(
            &create_op,
            &repository_create_input(repository_id.clone(), rand_name(), None),
        )
        .await
        .expect("create must succeed");

    let (delete_op, _w) = admitted_operation(&store, "repository_delete").await;
    store
        .repository_delete(
            &delete_op,
            &RepositoryDeleteInput {
                repository_id: repository_id.clone(),
                expected_generation: None,
                delete_proof: rand::random::<[u8; 32]>().to_vec(),
                projection: Vec::new(),
                event: None,
            },
        )
        .await
        .expect("delete must succeed");

    let (obliterate_op, _w) = admitted_operation(&store, "begin_obliterate").await;
    let mut event = pending_event(
        repository_id.clone(),
        CommittedOrdinal::RepositoryGeneration,
        Vec::new(),
    );
    event.event_kind = "repository.obliterated".to_string();
    let result = store
        .begin_obliterate(&obliterate_op, &repository_id, Some(&event))
        .await
        .expect("obliterate of a tombstoned repository must return a decisive rejection");
    assert!(matches!(result.outcome, DomainOutcome::NotApplied { .. }));

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
}

// ---------------------------------------------------------------------------
// Idempotency-key derivation (row-level, F-032-2 PIN-1)
// ---------------------------------------------------------------------------

/// The committed row's `idempotency_key` equals the BLAKE3 preimage defined
/// by CR-032 PIN-1 and pinned by
/// `fixtures/lore-notification-plane/idempotency-key.json`: the domain
/// separator plus seven length-prefixed fields (cell, event kind, repository
/// id, repository generation, aggregate kind, aggregate id, aggregate
/// version). This is an independent recomputation, not a call into the
/// crate's own `idempotency_key` function (that agreement is already proven
/// by `domain_outbox_encoding.rs`); it proves the *coordinator* actually
/// passes the fields it claims -- including the resolved-not-caller-supplied
/// ordinal -- to the append layer.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn committed_row_idempotency_key_matches_the_pin_1_preimage() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();
    let (operation, _w) = admitted_operation(&store, "repository_create").await;

    let event = pending_event(
        repository_id.clone(),
        CommittedOrdinal::RepositoryGeneration,
        Vec::new(),
    );
    let input = repository_create_input(repository_id.clone(), rand_name(), Some(event.clone()));
    let result = store
        .repository_create(&operation, &input)
        .await
        .expect("create must succeed");
    let committed_generation = result
        .repository_generation
        .expect("Applied outcome carries a repository generation")
        as u64;

    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.cell_id, event.cell_id);

    let aggregate_version = AggregateVersion::ordinal_only(committed_generation).encode();
    let manual = manual_idempotency_key(
        &event.cell_id,
        &event.event_kind,
        &repository_id,
        committed_generation as i64,
        &event.aggregate_kind,
        &repository_id,
        &aggregate_version,
    );
    assert_eq!(
        row.idempotency_key, manual,
        "committed idempotency_key must equal the PIN-1 seven-field preimage over the fields \
         actually committed"
    );
}

/// Independent reimplementation of the PIN-1 preimage/BLAKE3 derivation, not
/// a call into `lore_postgres::domain::outbox::idempotency_key`.
fn manual_idempotency_key(
    cell_id: &str,
    event_kind: &str,
    repository_id: &[u8],
    repository_generation: i64,
    aggregate_kind: &str,
    aggregate_id: &[u8],
    aggregate_version: &[u8],
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"lore-outbox-idempotency-v1\0";
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    for field in [
        cell_id.as_bytes(),
        event_kind.as_bytes(),
        repository_id,
        &repository_generation.to_be_bytes(),
        aggregate_kind.as_bytes(),
        aggregate_id,
        aggregate_version,
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().as_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Admission rejection: no coordinator work at all
// ---------------------------------------------------------------------------

/// A rejected admission (reused/invalid prepare token) never reaches the
/// domain rows or the outbox at all -- `ADMISSION_REJECTED_V1` is returned
/// before `begin_admitted` ever opens a transaction against repository state.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn admission_rejection_leaves_no_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();

    let (mut operation, _w) = admitted_operation(&store, "repository_create").await;
    // Corrupt the prepare token so consume() rejects the admission outright.
    operation.prepare_token = rand::random();

    let input = repository_create_input(
        repository_id.clone(),
        rand_name(),
        Some(pending_event(
            repository_id.clone(),
            CommittedOrdinal::RepositoryGeneration,
            Vec::new(),
        )),
    );
    let result = store
        .repository_create(&operation, &input)
        .await
        .expect("a rejected admission is still a decisive, non-error result");
    assert!(
        matches!(&result.outcome, DomainOutcome::NotApplied { reason, .. } if reason == ADMISSION_REJECTED_V1)
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
}
