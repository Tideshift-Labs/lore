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

use lore_base::types::KeyType;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::ADMISSION_REJECTED_V1;
use lore_postgres::domain::coordinator::BranchDeleteInput;
use lore_postgres::domain::coordinator::BranchPushCommitInput;
use lore_postgres::domain::coordinator::CommittedOrdinal;
use lore_postgres::domain::coordinator::DEFAULT_BRANCH_V1;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GENERATION_MISMATCH_V1;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::MAX_PENDING_EVENTS;
use lore_postgres::domain::coordinator::MetadataCasInput;
use lore_postgres::domain::coordinator::NOT_FOUND_V1;
use lore_postgres::domain::coordinator::PendingEvent;
use lore_postgres::domain::coordinator::ProjectionWrite;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;
use lore_postgres::domain::coordinator::TOMBSTONED_V1;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::mutable_store::PostgresMutableStore;
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
        .domain_operation_prepare(&key, &binding, Some(&witness), None)
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

/// All outbox rows for a repository, ordered by `created_at` ascending.
///
/// `event_id` is a random `Uuid::new_v4()` (see `outbox::append`), so it
/// carries no ordering signal; `created_at` is `clock_timestamp()`, read fresh
/// per `INSERT` rather than frozen at transaction start, so two sequential
/// appends inside one transaction get two distinct, increasing values -- this
/// is the "if observable" evidence for F-032-3's outbox-last ordering. Field
/// correctness assertions below still look each row up by `aggregate_kind`
/// rather than trusting vector position, so a tie (if one somehow occurred)
/// would only weaken the ordering assertion, not produce a false field match.
async fn all_outbox_rows_for_repository(client: &Client, repository_id: &[u8]) -> Vec<OutboxRow> {
    client
        .query(
            "SELECT event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                    repository_generation, idempotency_key, cell_id \
             FROM lore_outbox_events WHERE repository_id = $1 ORDER BY created_at ASC",
            &[&repository_id],
        )
        .await
        .expect("query outbox rows for repository")
        .into_iter()
        .map(|row| OutboxRow {
            event_kind: row.get("event_kind"),
            aggregate_kind: row.get("aggregate_kind"),
            aggregate_id: row.get("aggregate_id"),
            aggregate_version: row.get("aggregate_version"),
            repository_generation: row.get("repository_generation"),
            idempotency_key: row.get("idempotency_key"),
            cell_id: row.get("cell_id"),
        })
        .collect()
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
        // WP-116 Part 3 widened the create carriage to a bounded `Vec`. This
        // helper keeps its one-event parameter so every existing caller reads
        // the same; a case that needs the two-event pair builds the input
        // directly.
        events: event.into_iter().collect(),
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
    input.events = vec![pending_event(
        repository_id.clone(),
        CommittedOrdinal::RepositoryGeneration,
        Vec::new(),
    )];
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

/// WP-116 Part 3: `RepositoryCreateInput.events` widened from one `Option` to
/// a bounded `Vec<PendingEvent>` so one create transaction can commit both
/// CR-032 rows it owes -- the repository publication and its default branch
/// creation -- in a single transaction. A supplied two-event pair
/// (`repository.published` then `branch.created`) must commit exactly two
/// outbox rows, each with the pinned fields, and (F-032-3: outbox insert is
/// the transaction's last write, in caller order) the repository row's
/// `created_at` must not be later than the branch row's.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn repository_create_wired_two_events_commits_both_rows_with_pinned_fields_in_order() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();
    let (operation, _witness) = admitted_operation(&store, "repository_create").await;

    let mut input = repository_create_input(repository_id.clone(), rand_name(), None);
    let branch_id = input.default_branch_id.clone();
    let default_branch_latest_hash = input.default_branch_latest_hash.clone();
    let repository_event = pending_event(
        repository_id.clone(),
        CommittedOrdinal::RepositoryGeneration,
        Vec::new(),
    );
    let branch_event = {
        let mut e = pending_event(
            branch_id.clone(),
            CommittedOrdinal::BranchGeneration,
            default_branch_latest_hash.clone(),
        );
        e.event_kind = "branch.created".to_string();
        e.aggregate_kind = "branch".to_string();
        e
    };
    input.events = vec![repository_event, branch_event];

    let result = store
        .repository_create(&operation, &input)
        .await
        .expect("two-event repository create must succeed");
    assert!(matches!(result.outcome, DomainOutcome::Applied));
    assert_eq!(result.repository_generation, Some(1));
    assert_eq!(result.branch_generation, Some(1));

    let rows = all_outbox_rows_for_repository(&db, &repository_id).await;
    assert_eq!(
        rows.len(),
        2,
        "a committed create with two supplied events must leave exactly two rows, got {} \
         (kinds: {:?})",
        rows.len(),
        rows.iter().map(|r| &r.event_kind).collect::<Vec<_>>()
    );

    let repository_position = rows
        .iter()
        .position(|r| r.aggregate_kind == "repository")
        .expect("a repository.published row must be present");
    let branch_position = rows
        .iter()
        .position(|r| r.aggregate_kind == "branch")
        .expect("a branch.created row must be present");

    let repo_row = &rows[repository_position];
    assert_eq!(repo_row.event_kind, "repository.published");
    assert_eq!(repo_row.aggregate_id, repository_id);
    assert_eq!(repo_row.repository_generation, 1);
    let repo_decoded =
        AggregateVersion::decode(&repo_row.aggregate_version).expect("decode repository version");
    assert_eq!(repo_decoded.ordinal, 1);
    assert!(
        repo_decoded.identity.is_empty(),
        "repository-kind identity is empty per PIN-4"
    );

    let branch_row = &rows[branch_position];
    assert_eq!(branch_row.event_kind, "branch.created");
    assert_eq!(branch_row.aggregate_id, branch_id);
    assert_eq!(
        branch_row.repository_generation, 1,
        "the outer repository_generation column is the repository row's generation at commit \
         time for both rows, independent of the branch generation encoded inside its own \
         aggregate_version"
    );
    let branch_decoded =
        AggregateVersion::decode(&branch_row.aggregate_version).expect("decode branch version");
    assert_eq!(branch_decoded.ordinal, 1, "committed branch generation");
    assert_eq!(
        branch_decoded.identity, default_branch_latest_hash,
        "branch.created's identity is the exact initial tip, per event-kinds.json"
    );

    assert!(
        repository_position < branch_position,
        "F-032-3: repository.published must be appended before branch.created (caller order is \
         preserved by append_events); observed insertion order was {:?}",
        rows.iter().map(|r| &r.aggregate_kind).collect::<Vec<_>>()
    );
}

/// The bounded `Vec<PendingEvent>` is checked before the transaction opens
/// (`validate_pending_events`, called ahead of the pool checkout): a carriage
/// over [`MAX_PENDING_EVENTS`] is refused at validation, with no repository
/// row, no branch row, and no outbox row -- not a decisive `NOT_APPLIED`
/// result, since this is a caller-shape defect the coordinator never admits
/// far enough to evaluate against repository state.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn repository_create_over_cap_events_is_rejected_at_validation_with_zero_rows() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();
    let (operation, _witness) = admitted_operation(&store, "repository_create").await;

    let mut input = repository_create_input(repository_id.clone(), rand_name(), None);
    input.events = (0..=MAX_PENDING_EVENTS)
        .map(|_| {
            pending_event(
                repository_id.clone(),
                CommittedOrdinal::RepositoryGeneration,
                Vec::new(),
            )
        })
        .collect();
    assert_eq!(
        input.events.len(),
        MAX_PENDING_EVENTS + 1,
        "test fixture sanity: exactly one event over the cap"
    );

    let result = store.repository_create(&operation, &input).await;
    match result {
        Err(DomainError::InvalidInput(message)) => {
            assert!(
                message.contains("repository_create"),
                "the validation error should name the offending method, got: {message}"
            );
        }
        other => panic!(
            "an over-cap event carriage must be refused as DomainError::InvalidInput before the \
             transaction opens, got {other:?}"
        ),
    }

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
    let repository_row_exists: bool = db
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM lore_domain_repositories WHERE repository_id = $1)",
            &[&repository_id],
        )
        .await
        .expect("query repository existence")
        .get(0);
    assert!(
        !repository_row_exists,
        "an over-cap carriage must be refused before any transaction opens, leaving no \
         repository row at all -- not merely no outbox row"
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
        events: vec![pending_event(
            repository_id.clone(),
            CommittedOrdinal::RepositoryGeneration,
            Vec::new(),
        )],
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
        events: vec![{
            let mut e = pending_event(
                repository_id.clone(),
                CommittedOrdinal::RepositoryGeneration,
                Vec::new(),
            );
            e.event_kind = "repository.tombstoned".to_string();
            e
        }],
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
        events: vec![pending_event(
            repository_id.clone(),
            CommittedOrdinal::RepositoryGeneration,
            Vec::new(),
        )],
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
        events: vec![pending_event(
            repository_id.clone(),
            CommittedOrdinal::RepositoryGeneration,
            Vec::new(),
        )],
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

/// Seed a live branch row directly, bypassing the coordinator: there is no
/// governed branch-create method (WP-119 writer inventory section 2, B1-B3 are
/// all direct store calls), so a repository with more than its one default
/// branch has to be built with SQL, matching `domain_schema.rs`'s
/// `insert_branch` pattern.
async fn insert_live_branch(client: &Client, repository_id: &[u8], branch_id: &[u8], name: &str) {
    let metadata_hash: [u8; 32] = rand::random();
    let latest_hash: [u8; 32] = rand::random();
    let creation_fingerprint: [u8; 32] = rand::random();
    client
        .execute(
            "INSERT INTO lore_domain_branches (
                repository_id, branch_id, repository_generation, state, generation, name,
                metadata_hash, latest_hash, creation_fingerprint_version, creation_fingerprint,
                delete_proof, created_at, deleted_at
            ) VALUES ($1, $2, 1, 0, 1, $3, $4, $5, 1, $6, NULL, clock_timestamp(), NULL)",
            &[
                &repository_id,
                &branch_id,
                &name,
                &metadata_hash.as_slice(),
                &latest_hash.as_slice(),
                &creation_fingerprint.as_slice(),
            ],
        )
        .await
        .expect("seed live branch row");
}

/// CR-032 classifies a repository tombstone as "One repository-generation
/// event, not one row per hidden association", and F-032-2's amendment
/// (`RepositoryDeleteInput::events`, 2026-09-04) applies the same rule to the
/// branches a tombstone hides: the transition is one bounded generation event,
/// not one `branch.deleted` row per tombstoned branch. A repository with three
/// live branches beyond its default (four total) still commits exactly one
/// `repository.tombstoned` row when tombstoned, and an exact retry appends
/// zero more.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn repository_delete_with_three_extra_live_branches_still_commits_exactly_one_row() {
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
    for n in 0..3u8 {
        let branch_id = rand::random::<[u8; 16]>().to_vec();
        insert_live_branch(
            &db,
            &repository_id,
            &branch_id,
            &format!("wp119-extra-branch-{n}"),
        )
        .await;
    }

    let delete_proof = rand::random::<[u8; 32]>().to_vec();
    let (delete_op, _w) = admitted_operation(&store, "repository_delete").await;
    let delete_input = RepositoryDeleteInput {
        repository_id: repository_id.clone(),
        expected_generation: None,
        delete_proof: delete_proof.clone(),
        projection: Vec::new(),
        events: vec![{
            let mut e = pending_event(
                repository_id.clone(),
                CommittedOrdinal::RepositoryGeneration,
                Vec::new(),
            );
            e.event_kind = "repository.tombstoned".to_string();
            e
        }],
    };
    let result = store
        .repository_delete(&delete_op, &delete_input)
        .await
        .expect("delete with extra branches must succeed");
    assert!(matches!(result.outcome, DomainOutcome::Applied));
    let repository_generation = result
        .repository_generation
        .expect("delete must report a committed repository generation");

    // Sanity: all four branches (the default plus the three seeded above)
    // were actually hidden by the one `UPDATE`, so the "exactly one row"
    // assertion below is proving the summary rule, not a fixture that never
    // exercised more than one branch.
    let live_branch_count: i64 = db
        .query_one(
            "SELECT count(*) FROM lore_domain_branches \
             WHERE repository_id = $1 AND deleted_at IS NULL",
            &[&repository_id],
        )
        .await
        .expect("count remaining live branches")
        .get(0);
    assert_eq!(
        live_branch_count, 0,
        "test fixture sanity: the tombstone must hide every branch, including the three \
         seeded ones, for the row-count assertion below to mean anything"
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1,
        "a repository with three extra live branches must still commit exactly one \
         repository.tombstoned row, not one per hidden branch"
    );
    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.event_kind, "repository.tombstoned");
    let decoded = AggregateVersion::decode(&row.aggregate_version).expect("decode");
    assert_eq!(
        decoded.ordinal,
        u64::try_from(repository_generation).expect("generation fits u64")
    );

    // An exact retry against the now-tombstoned repository appends nothing.
    let (retry_op, _w) = admitted_operation(&store, "repository_delete").await;
    let retry_input = RepositoryDeleteInput {
        repository_id: repository_id.clone(),
        expected_generation: None,
        delete_proof,
        projection: Vec::new(),
        events: vec![{
            let mut e = pending_event(
                repository_id.clone(),
                CommittedOrdinal::RepositoryGeneration,
                Vec::new(),
            );
            e.event_kind = "repository.tombstoned".to_string();
            e
        }],
    };
    let retried = store
        .repository_delete(&retry_op, &retry_input)
        .await
        .expect("exact retry delete must succeed idempotently");
    assert!(matches!(retried.outcome, DomainOutcome::Applied));
    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1,
        "an exact retry against an already-tombstoned repository must append zero more rows"
    );
}

// ---------------------------------------------------------------------------
// branch_delete
// ---------------------------------------------------------------------------

/// A `branch.deleted`-shaped `PendingEvent`, matching `outbox/builders.rs`'s
/// `branch_deleted` pinned shape: `aggregate_kind = "branch"`, ordinal the
/// committed branch generation, identity the final tip. Test-authored, not a
/// call into the production builder -- same rationale as `pending_event`.
fn branch_deleted_event(branch_id: Vec<u8>, final_latest_hash: Vec<u8>) -> PendingEvent {
    let mut e = pending_event(
        branch_id,
        CommittedOrdinal::BranchGeneration,
        final_latest_hash,
    );
    e.event_kind = "branch.deleted".to_string();
    e.aggregate_kind = "branch".to_string();
    e
}

fn rand_delete_proof() -> Vec<u8> {
    rand::random::<[u8; 32]>().to_vec()
}

/// Seed a live `lore_domain_branch_names` row directly, matching what a real
/// branch create's name claim would leave. There is no governed branch-create
/// method (see `insert_live_branch`'s own doc comment), so this is built with
/// SQL, mirroring the branch row it must reference via its foreign key.
async fn insert_live_branch_name(
    client: &Client,
    repository_id: &[u8],
    branch_id: &[u8],
    name: &str,
) {
    client
        .execute(
            "INSERT INTO lore_domain_branch_names (
                repository_id, name_key, display_name, branch_id,
                repository_generation, branch_generation, created_at
            ) VALUES ($1, lower($2), $2, $3, 1, 1, clock_timestamp())",
            &[&repository_id, &name, &branch_id],
        )
        .await
        .expect("seed live branch name row");
}

/// Build a repository plus one extra live branch (beyond the default), with
/// both the branch row and its name row seeded -- the shape `branch_delete`
/// expects to find and the shape a real create would have left. Returns
/// `(repository_id, extra_branch_id)`; the default branch id is available via
/// `PostgresDomainStore::repository_snapshot` for a caller that needs it.
async fn create_repository_with_one_extra_branch(
    store: &PostgresDomainStore,
    db: &Client,
    extra_branch_name: &str,
) -> (Vec<u8>, Vec<u8>) {
    let repository_id = rand_repo_id();
    let (create_op, _w) = admitted_operation(store, "repository_create").await;
    store
        .repository_create(
            &create_op,
            &repository_create_input(repository_id.clone(), rand_name(), None),
        )
        .await
        .expect("create must succeed");

    let branch_id = rand::random::<[u8; 16]>().to_vec();
    insert_live_branch(db, &repository_id, &branch_id, extra_branch_name).await;
    insert_live_branch_name(db, &repository_id, &branch_id, extra_branch_name).await;

    (repository_id, branch_id)
}

fn branch_delete_input(
    repository_id: Vec<u8>,
    branch_id: Vec<u8>,
    events: Vec<PendingEvent>,
) -> BranchDeleteInput {
    BranchDeleteInput {
        repository_id,
        branch_id,
        expected_generation: None,
        delete_proof: rand_delete_proof(),
        projection: Vec::new(),
        events,
    }
}

/// A committed `branch_delete` with a supplied event leaves exactly one
/// outbox row whose `aggregate_id` is the 16 branch bytes and whose
/// `aggregate_version` decodes to the actual committed **branch** generation
/// (2, after the branch's seeded generation 1) -- not the repository
/// generation, which a branch delete does not bump.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_delete_commits_exactly_one_branch_deleted_row_at_the_committed_generation() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let (repository_id, branch_id) =
        create_repository_with_one_extra_branch(&store, &db, "wp119-branch-delete-happy").await;

    let final_latest_hash = rand::random::<[u8; 32]>().to_vec();
    let (delete_op, _w) = admitted_operation(&store, "branch_delete").await;
    let input = branch_delete_input(
        repository_id.clone(),
        branch_id.clone(),
        vec![branch_deleted_event(
            branch_id.clone(),
            final_latest_hash.clone(),
        )],
    );
    let result = store
        .branch_delete(&delete_op, &input)
        .await
        .expect("branch_delete must succeed");
    assert!(matches!(result.outcome, DomainOutcome::Applied));
    assert_eq!(
        result.repository_generation,
        Some(1),
        "a branch delete does not bump the repository generation"
    );
    assert_eq!(result.branch_generation, Some(2));

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1,
        "a committed branch delete with a supplied event must leave exactly one row"
    );
    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.event_kind, "branch.deleted");
    assert_eq!(row.aggregate_kind, "branch");
    assert_eq!(row.aggregate_id, branch_id);
    assert_eq!(
        row.repository_generation, 1,
        "the outer repository_generation column is the repository's unbumped generation"
    );
    let decoded = AggregateVersion::decode(&row.aggregate_version).expect("decode");
    assert_eq!(
        decoded.ordinal, 2,
        "ordinal must be the actual committed branch generation, not a caller guess"
    );
    assert_eq!(
        decoded.identity, final_latest_hash,
        "identity must be the exact final tip, per event-kinds.json"
    );

    let branch_row = db
        .query_one(
            "SELECT state, generation, repository_generation, deleted_at, delete_proof \
             FROM lore_domain_branches WHERE repository_id = $1 AND branch_id = $2",
            &[&repository_id, &branch_id],
        )
        .await
        .expect("branch row must still exist, tombstoned");
    let state: i16 = branch_row.get("state");
    let generation: i64 = branch_row.get("generation");
    let repository_generation: i64 = branch_row.get("repository_generation");
    assert_eq!(state, 1, "STATE_TOMBSTONED");
    assert_eq!(generation, 2);
    assert_eq!(repository_generation, 1);
    let deleted_at: Option<std::time::SystemTime> = branch_row.get("deleted_at");
    assert!(deleted_at.is_some());
    let delete_proof: Option<Vec<u8>> = branch_row.get("delete_proof");
    assert_eq!(delete_proof, Some(input.delete_proof));
}

/// Deleting an absent branch (never existed, on an otherwise live repository)
/// is a decisive `NOT_FOUND_V1` rejection and must leave no row.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_delete_missing_branch_leaves_no_row() {
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

    let missing_branch_id = rand::random::<[u8; 16]>().to_vec();
    let (delete_op, _w) = admitted_operation(&store, "branch_delete").await;
    let input = branch_delete_input(
        repository_id.clone(),
        missing_branch_id.clone(),
        vec![branch_deleted_event(missing_branch_id.clone(), Vec::new())],
    );
    let result = store
        .branch_delete(&delete_op, &input)
        .await
        .expect("delete of an absent branch must return a decisive result");
    assert!(
        matches!(&result.outcome, DomainOutcome::NotApplied { reason, .. } if reason == NOT_FOUND_V1)
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
}

/// Deleting a branch under an absent repository is also `NOT_FOUND_V1` and
/// leaves no row -- the repository lock is checked before the branch lock.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_delete_missing_repository_leaves_no_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();
    let branch_id = rand::random::<[u8; 16]>().to_vec();

    let (delete_op, _w) = admitted_operation(&store, "branch_delete").await;
    let input = branch_delete_input(
        repository_id.clone(),
        branch_id.clone(),
        vec![branch_deleted_event(branch_id.clone(), Vec::new())],
    );
    let result = store
        .branch_delete(&delete_op, &input)
        .await
        .expect("delete under an absent repository must return a decisive result");
    assert!(
        matches!(&result.outcome, DomainOutcome::NotApplied { reason, .. } if reason == NOT_FOUND_V1)
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
}

/// A branch under an already-tombstoned repository is refused `TOMBSTONED_V1`
/// -- the repository's own tombstone already hides it, so branch_delete must
/// not resurrect the branch row to tombstone it a second time.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_delete_under_a_tombstoned_repository_leaves_no_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let (repository_id, branch_id) =
        create_repository_with_one_extra_branch(&store, &db, "wp119-branch-delete-repo-gone").await;

    let (repo_delete_op, _w) = admitted_operation(&store, "repository_delete").await;
    store
        .repository_delete(
            &repo_delete_op,
            &RepositoryDeleteInput {
                repository_id: repository_id.clone(),
                expected_generation: None,
                delete_proof: rand_delete_proof(),
                projection: Vec::new(),
                events: Vec::new(),
            },
        )
        .await
        .expect("repository delete must succeed");

    let (delete_op, _w) = admitted_operation(&store, "branch_delete").await;
    let input = branch_delete_input(
        repository_id.clone(),
        branch_id.clone(),
        vec![branch_deleted_event(branch_id.clone(), Vec::new())],
    );
    let result = store
        .branch_delete(&delete_op, &input)
        .await
        .expect("delete under a tombstoned repository must return a decisive result");
    assert!(
        matches!(&result.outcome, DomainOutcome::NotApplied { reason, .. } if reason == TOMBSTONED_V1)
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
}

/// A stale `expected_generation` (preflight went stale) is a decisive
/// `GENERATION_MISMATCH_V1` rejection and must leave no row.
///
/// The target branch is deliberately the extra (non-default) branch
/// `create_repository_with_one_extra_branch` seeds, not the repository's
/// default branch: the coordinator checks `DEFAULT_BRANCH_V1` **before**
/// `GENERATION_MISMATCH_V1` (a permanent rule is answered before a retryable
/// one), so a default-branch target with a stale generation would get
/// `DEFAULT_BRANCH_V1` here instead, and this test would silently stop
/// exercising the generation check. See
/// `branch_delete_of_the_default_branch_leaves_no_row` for that ordering.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_delete_generation_mismatch_leaves_no_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let (repository_id, branch_id) =
        create_repository_with_one_extra_branch(&store, &db, "wp119-branch-delete-gen-mismatch")
            .await;
    let repository_snapshot = store
        .repository_snapshot(&repository_id)
        .await
        .expect("repository snapshot must read")
        .expect("fixture repository must exist");
    assert_ne!(
        branch_id, repository_snapshot.default_branch_id,
        "test fixture sanity: the target branch must NOT be the default branch, or this test \
         would exercise DEFAULT_BRANCH_V1 instead of GENERATION_MISMATCH_V1"
    );

    let (delete_op, _w) = admitted_operation(&store, "branch_delete").await;
    let mut input = branch_delete_input(
        repository_id.clone(),
        branch_id.clone(),
        vec![branch_deleted_event(branch_id.clone(), Vec::new())],
    );
    input.expected_generation = Some(99); // deliberately stale; seeded branches start at 1
    let result = store
        .branch_delete(&delete_op, &input)
        .await
        .expect("a stale expected_generation must return a decisive result");
    assert!(
        matches!(&result.outcome, DomainOutcome::NotApplied { reason, .. } if reason == GENERATION_MISMATCH_V1)
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
}

/// Deleting a repository's default branch is refused `DEFAULT_BRANCH_V1`,
/// rechecked under the locked repository row, and leaves no row.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_delete_of_the_default_branch_leaves_no_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();
    let (create_op, _w) = admitted_operation(&store, "repository_create").await;
    let create_input = repository_create_input(repository_id.clone(), rand_name(), None);
    let default_branch_id = create_input.default_branch_id.clone();
    store
        .repository_create(&create_op, &create_input)
        .await
        .expect("create must succeed");

    let (delete_op, _w) = admitted_operation(&store, "branch_delete").await;
    let input = branch_delete_input(
        repository_id.clone(),
        default_branch_id.clone(),
        vec![branch_deleted_event(default_branch_id.clone(), Vec::new())],
    );
    let result = store
        .branch_delete(&delete_op, &input)
        .await
        .expect("deleting the default branch must return a decisive result");
    assert!(
        matches!(&result.outcome, DomainOutcome::NotApplied { reason, .. } if reason == DEFAULT_BRANCH_V1)
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
    let branch_state: i16 = db
        .query_one(
            "SELECT state FROM lore_domain_branches WHERE repository_id = $1 AND branch_id = $2",
            &[&repository_id, &default_branch_id],
        )
        .await
        .expect("default branch row must still exist")
        .get("state");
    assert_eq!(
        branch_state, 0,
        "STATE_LIVE: the default branch must remain live"
    );
}

/// An exact delete retry against an already-tombstoned branch is idempotent
/// success and must not create a second row -- the coordinator returns
/// before `append_events` on the tombstone-preserved path.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_delete_retry_on_an_already_tombstoned_branch_leaves_no_second_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let (repository_id, branch_id) =
        create_repository_with_one_extra_branch(&store, &db, "wp119-branch-delete-retry").await;

    let (first_op, _w) = admitted_operation(&store, "branch_delete").await;
    let first_input = branch_delete_input(
        repository_id.clone(),
        branch_id.clone(),
        vec![branch_deleted_event(branch_id.clone(), Vec::new())],
    );
    let first = store
        .branch_delete(&first_op, &first_input)
        .await
        .expect("first delete must succeed");
    assert!(matches!(first.outcome, DomainOutcome::Applied));
    assert_eq!(first.branch_generation, Some(2));
    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );

    // A second, independently-admitted delete against the already-tombstoned
    // branch.
    let (second_op, _w) = admitted_operation(&store, "branch_delete").await;
    let second_input = branch_delete_input(
        repository_id.clone(),
        branch_id.clone(),
        vec![branch_deleted_event(branch_id.clone(), Vec::new())],
    );
    let second = store
        .branch_delete(&second_op, &second_input)
        .await
        .expect("retry delete must succeed idempotently");
    assert!(matches!(second.outcome, DomainOutcome::Applied));
    assert_eq!(
        second.branch_generation,
        Some(2),
        "the retry must report the existing generation, not a re-bumped one"
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1,
        "a delete retry against an already-tombstoned branch must not add a second row"
    );
}

/// A rejected admission (reused/invalid prepare token) never reaches the
/// domain rows or the outbox at all.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_delete_admission_rejection_leaves_no_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let (repository_id, branch_id) =
        create_repository_with_one_extra_branch(&store, &db, "wp119-branch-delete-admission").await;

    let (mut delete_op, _w) = admitted_operation(&store, "branch_delete").await;
    delete_op.prepare_token = rand::random();
    let input = branch_delete_input(
        repository_id.clone(),
        branch_id.clone(),
        vec![branch_deleted_event(branch_id.clone(), Vec::new())],
    );
    let result = store
        .branch_delete(&delete_op, &input)
        .await
        .expect("a rejected admission is still a decisive, non-error result");
    assert!(
        matches!(&result.outcome, DomainOutcome::NotApplied { reason, .. } if reason == ADMISSION_REJECTED_V1)
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
    let branch_state: i16 = db
        .query_one(
            "SELECT state FROM lore_domain_branches WHERE repository_id = $1 AND branch_id = $2",
            &[&repository_id, &branch_id],
        )
        .await
        .expect("branch row must be untouched")
        .get("state");
    assert_eq!(
        branch_state, 0,
        "STATE_LIVE: an admission rejection must not tombstone anything"
    );
}

/// The name row released is scoped to `(repository_id, branch_id)`, not to
/// the whole repository: deleting one branch releases only its own name row
/// and leaves a sibling live branch's name row intact. This is the property
/// that distinguishes `branch_delete`'s scoped `DELETE` from
/// `repository_delete`'s repository-wide one.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_delete_releases_only_its_own_name_row_leaving_a_sibling_intact() {
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

    let target_branch_id = rand::random::<[u8; 16]>().to_vec();
    let target_name = "wp119-branch-delete-name-target";
    insert_live_branch(&db, &repository_id, &target_branch_id, target_name).await;
    insert_live_branch_name(&db, &repository_id, &target_branch_id, target_name).await;

    let sibling_branch_id = rand::random::<[u8; 16]>().to_vec();
    let sibling_name = "wp119-branch-delete-name-sibling";
    insert_live_branch(&db, &repository_id, &sibling_branch_id, sibling_name).await;
    insert_live_branch_name(&db, &repository_id, &sibling_branch_id, sibling_name).await;

    let name_row_exists = |branch_id: Vec<u8>| {
        let db = &db;
        let repository_id = repository_id.clone();
        async move {
            db.query_opt(
                "SELECT 1 FROM lore_domain_branch_names \
                 WHERE repository_id = $1 AND branch_id = $2",
                &[&repository_id, &branch_id],
            )
            .await
            .expect("query branch name row")
            .is_some()
        }
    };
    assert!(name_row_exists(target_branch_id.clone()).await);
    assert!(name_row_exists(sibling_branch_id.clone()).await);

    let (delete_op, _w) = admitted_operation(&store, "branch_delete").await;
    let input = branch_delete_input(
        repository_id.clone(),
        target_branch_id.clone(),
        vec![branch_deleted_event(target_branch_id.clone(), Vec::new())],
    );
    store
        .branch_delete(&delete_op, &input)
        .await
        .expect("branch delete must succeed");

    assert!(
        !name_row_exists(target_branch_id).await,
        "the deleted branch's own name row must be released"
    );
    assert!(
        name_row_exists(sibling_branch_id).await,
        "a sibling live branch's name row must survive"
    );
}

/// `branch_delete`'s projection is the coordinator's ordinary
/// `apply_projection`, exercised here with the delete-shaped
/// `ProjectionWrite { value: None }` a real caller supplies: it removes
/// exactly the one supplied `KeyType::BranchId` row and leaves the branch's
/// `KeyType::BranchMetadata` and `KeyType::BranchLatestPointer` rows
/// untouched.
///
/// The metadata/latest survival is the property a reader is most likely to
/// get wrong by analogy with `repository_delete` (whose projection retires
/// all three): `BranchDeletePublication::projection()`
/// (`lore-server/src/domain.rs`) deliberately builds only the one
/// `BranchId` row, because the legacy `lore_revision::branch::delete` calls
/// only `delete_name_to_id` and leaves metadata/latest in place so the v1
/// handler's idempotent response can still read them after the delete. This
/// coordinator-level test cannot call that seam function directly (a
/// separate crate, and gated by `BranchDeleteProof::Unfrozen` besides), so it
/// reproduces the same three-row shape by hand with the real `KeyType`
/// discriminants and asserts the coordinator's `apply_projection` honours
/// exactly the rows it is given, nothing more.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_delete_projection_removes_only_its_own_row() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    // The projection write below lands in `lore_mutable`, the CR-007 store's
    // own table, distinct from the domain schema `store()` installs.
    PostgresMutableStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("install the lore_mutable schema for the projection write");
    let (repository_id, branch_id) =
        create_repository_with_one_extra_branch(&store, &db, "wp119-branch-delete-projection")
            .await;

    let name_key_type = KeyType::BranchId as i16;
    let name_key = rand::random::<[u8; 32]>().to_vec();
    let metadata_key_type = KeyType::BranchMetadata as i16;
    let metadata_key = rand::random::<[u8; 32]>().to_vec();
    let metadata_value = rand::random::<[u8; 32]>().to_vec();
    let latest_key_type = KeyType::BranchLatestPointer as i16;
    let latest_key = rand::random::<[u8; 32]>().to_vec();
    let latest_value = rand::random::<[u8; 32]>().to_vec();
    db.execute(
        "INSERT INTO lore_mutable (partition, key_type, key, value) VALUES ($1, $2, $3, $4)",
        &[
            &repository_id,
            &name_key_type,
            &name_key,
            &rand::random::<[u8; 32]>().to_vec(),
        ],
    )
    .await
    .expect("seed the name row the projection will remove");
    db.execute(
        "INSERT INTO lore_mutable (partition, key_type, key, value) VALUES ($1, $2, $3, $4)",
        &[
            &repository_id,
            &metadata_key_type,
            &metadata_key,
            &metadata_value,
        ],
    )
    .await
    .expect("seed the branch metadata row, which must survive");
    db.execute(
        "INSERT INTO lore_mutable (partition, key_type, key, value) VALUES ($1, $2, $3, $4)",
        &[&repository_id, &latest_key_type, &latest_key, &latest_value],
    )
    .await
    .expect("seed the branch latest-pointer row, which must survive");

    let (delete_op, _w) = admitted_operation(&store, "branch_delete").await;
    let mut input = branch_delete_input(
        repository_id.clone(),
        branch_id.clone(),
        vec![branch_deleted_event(branch_id.clone(), Vec::new())],
    );
    input.projection = vec![ProjectionWrite {
        partition: repository_id.clone(),
        key_type: name_key_type,
        key: name_key.clone(),
        value: None,
    }];
    store
        .branch_delete(&delete_op, &input)
        .await
        .expect("branch delete must succeed");

    let name_row: Option<Vec<u8>> = db
        .query_opt(
            "SELECT value FROM lore_mutable WHERE partition = $1 AND key_type = $2 AND key = $3",
            &[&repository_id, &name_key_type, &name_key],
        )
        .await
        .expect("query the removed name row")
        .map(|row| row.get("value"));
    assert_eq!(
        name_row, None,
        "the one supplied projection row (KeyType::BranchId) must be removed"
    );

    let metadata_row: Option<Vec<u8>> = db
        .query_opt(
            "SELECT value FROM lore_mutable WHERE partition = $1 AND key_type = $2 AND key = $3",
            &[&repository_id, &metadata_key_type, &metadata_key],
        )
        .await
        .expect("query the branch metadata row")
        .map(|row| row.get("value"));
    assert_eq!(
        metadata_row,
        Some(metadata_value),
        "KeyType::BranchMetadata must survive a branch delete unchanged -- the legacy writer \
         never touches it, and the v1 handler's idempotent response reads it after the delete"
    );

    let latest_row: Option<Vec<u8>> = db
        .query_opt(
            "SELECT value FROM lore_mutable WHERE partition = $1 AND key_type = $2 AND key = $3",
            &[&repository_id, &latest_key_type, &latest_key],
        )
        .await
        .expect("query the branch latest-pointer row")
        .map(|row| row.get("value"));
    assert_eq!(
        latest_row,
        Some(latest_value),
        "KeyType::BranchLatestPointer must survive a branch delete unchanged -- the legacy \
         writer never touches it"
    );
}

// ---------------------------------------------------------------------------
// metadata_compare_and_swap
// ---------------------------------------------------------------------------

/// A CAS mismatch is a decisive rejection and must leave no row. The
/// coordinator's `MutationResult.observed_pointer` must carry the exact
/// bytes actually read under the row lock -- the current repository metadata
/// hash -- never the caller's wrong `expected_hash` and never empty. This is
/// the property `GovernedMetadataCas::commit` (`lore-server/src/domain.rs`)
/// depends on to preserve CR-029 Phase 5's in-band CAS-loss pointer; the
/// seam's own mapping of that value is separately proven, without Postgres,
/// in `lore-server/src/domain/p12_tests.rs`.
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
    let create_input = repository_create_input(repository_id.clone(), rand_name(), None);
    let actual_current_metadata_hash = create_input.metadata_hash.clone();
    store
        .repository_create(&create_op, &create_input)
        .await
        .expect("create must succeed");

    let (cas_op, _w) = admitted_operation(&store, "metadata_compare_and_swap").await;
    let wrong_expected_hash = rand::random::<[u8; 32]>().to_vec();
    assert_ne!(
        wrong_expected_hash, actual_current_metadata_hash,
        "test fixture sanity: the wrong hash must not coincidentally match the real one"
    );
    let cas_input = MetadataCasInput {
        repository_id: repository_id.clone(),
        branch_id: None,
        expected_hash: wrong_expected_hash.clone(), // deliberately wrong
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
        result.observed_pointer,
        Some(actual_current_metadata_hash),
        "observed_pointer must be the real current metadata hash the transaction read under \
         its row lock"
    );
    assert_ne!(
        result.observed_pointer,
        Some(wrong_expected_hash),
        "observed_pointer must never echo back the caller's wrong expected_hash"
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
}

/// The branch-scoped variant of the same property: a branch metadata CAS
/// mismatch reports the branch's actual current metadata hash as
/// `observed_pointer`, not the repository's.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_metadata_cas_mismatch_reports_the_branch_metadata_hash_as_observed_pointer() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let repository_id = rand_repo_id();

    let (create_op, _w) = admitted_operation(&store, "repository_create").await;
    let create_input = repository_create_input(repository_id.clone(), rand_name(), None);
    let branch_id = create_input.default_branch_id.clone();
    let actual_branch_metadata_hash = create_input.default_branch_metadata_hash.clone();
    store
        .repository_create(&create_op, &create_input)
        .await
        .expect("create must succeed");

    let (cas_op, _w) = admitted_operation(&store, "metadata_compare_and_swap").await;
    let wrong_expected_hash = rand::random::<[u8; 32]>().to_vec();
    let cas_input = MetadataCasInput {
        repository_id: repository_id.clone(),
        branch_id: Some(branch_id),
        expected_hash: wrong_expected_hash,
        new_hash: rand::random::<[u8; 32]>().to_vec(),
        projection: Vec::new(),
        event: Some({
            let mut e = pending_event(
                repository_id.clone(),
                CommittedOrdinal::RepositoryGeneration,
                Vec::new(),
            );
            e.event_kind = "branch.metadata_changed".to_string();
            e
        }),
    };
    let result = store
        .metadata_compare_and_swap(&cas_op, &cas_input)
        .await
        .expect("mismatched branch CAS must return a decisive rejection");
    assert!(matches!(result.outcome, DomainOutcome::NotApplied { .. }));
    assert_eq!(
        result.observed_pointer,
        Some(actual_branch_metadata_hash),
        "a branch-scoped CAS loss must report the BRANCH's metadata hash, not the repository's"
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0
    );
}

/// A successful repository-metadata CAS commits exactly one row at the new
/// generation, and writes the same `lore_mutable` projection row a direct
/// (ungoverned) writer would have written -- same partition, `key_type`, and
/// key, with the new pointer as its value. CR-029 requires this: a reader
/// that used the projection before governed cutover must not silently stop
/// working after it, and that is a real-Postgres property, not a unit one.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn metadata_cas_success_commits_exactly_one_row_with_the_new_generation() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let store = store(&url).await;
    let db = client(&url).await;
    // The projection write below lands in `lore_mutable`, the CR-007 store's
    // own table -- distinct from the domain schema `store()` installs.
    // Nothing else in this file writes a non-empty projection, so this is
    // the first test that needs it.
    PostgresMutableStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("install the lore_mutable schema for the projection write");
    let repository_id = rand_repo_id();

    let (create_op, _w) = admitted_operation(&store, "repository_create").await;
    let create_input = repository_create_input(repository_id.clone(), rand_name(), None);
    let original_metadata_hash = create_input.metadata_hash.clone();
    store
        .repository_create(&create_op, &create_input)
        .await
        .expect("create must succeed");

    let (cas_op, _w) = admitted_operation(&store, "metadata_compare_and_swap").await;
    let new_metadata_hash = rand::random::<[u8; 32]>().to_vec();
    // Same shape a real handler builds: partition = repository, an arbitrary
    // but fixed key_type/key identifying "this repository's metadata
    // pointer", value = the new hash.
    let projection_key_type: i16 = 4;
    let projection_key = rand::random::<[u8; 32]>().to_vec();
    let cas_input = MetadataCasInput {
        repository_id: repository_id.clone(),
        branch_id: None,
        expected_hash: original_metadata_hash,
        new_hash: new_metadata_hash.clone(),
        projection: vec![ProjectionWrite {
            partition: repository_id.clone(),
            key_type: projection_key_type,
            key: projection_key.clone(),
            value: Some(new_metadata_hash.clone()),
        }],
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

    let projection_value: Option<Vec<u8>> = db
        .query_opt(
            "SELECT value FROM lore_mutable WHERE partition = $1 AND key_type = $2 AND key = $3",
            &[&repository_id, &projection_key_type, &projection_key],
        )
        .await
        .expect("query the projection row")
        .map(|row| row.get("value"));
    assert_eq!(
        projection_value,
        Some(new_metadata_hash),
        "the committed transaction must have written the exact same lore_mutable row (same \
         partition/key_type/key) that a direct writer would have written, with the new pointer \
         as its value"
    );
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
                events: Vec::new(),
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
