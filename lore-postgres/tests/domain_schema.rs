// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Schema-level integration tests for CR-029's domain tables (WP-116 Phase 2):
//! bootstrap idempotence, coexistence with pre-existing CR-007 rows, tombstone
//! evidence, name-key normalisation and release, identity non-reuse, the
//! future-rejection quota bounds, schema-state gating, and same-database
//! identity (R-SHOULD-1).
//!
//! Gated on `LORE_TEST_PG_URL`; skipped when unset. `lore_domain_*` tables are
//! shared across the whole suite (like `lore_mutable`), so every test uses
//! random identities/names for isolation rather than a dedicated database,
//! except the same-database-identity test, which needs a second database by
//! construction.

use lore_base::types::KeyType;
use lore_base::types::LockResource;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use lore_postgres::store::lock_store::PostgresLockStore;
use lore_postgres::store::mutable_store::PostgresMutableStore;
use lore_revision::lock::LockStore;
use lore_revision::lore::RepositoryId;
use lore_storage::Hash;
use lore_storage::MutableStore;
use lore_storage::Partition;
use serial_test::serial;
use tokio_postgres::error::SqlState;

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

/// Connect a `PostgresDomainStore` — the real bootstrap path (schema +
/// mediated + outbox DDL under the shared advisory lock, then the singleton
/// state rows), not a stand-in.
async fn connect_domain_store(url: &str) -> PostgresDomainStore {
    PostgresDomainStore::connect(url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store")
}

fn assert_violation(err: &tokio_postgres::Error, code: &SqlState, expected_constraint: &str) {
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(
        db_err.code(),
        code,
        "expected SQLSTATE {code:?}, got {:?}: {db_err}",
        db_err.code()
    );
    assert_eq!(
        db_err.constraint(),
        Some(expected_constraint),
        "expected the {expected_constraint} constraint to fire, got {:?}: {db_err}",
        db_err.constraint()
    );
}

// ─── throwaway-database helpers (only for same-database identity) ─────────

fn replace_dbname(url: &str, db_name: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };
    let last_slash = base
        .rfind('/')
        .expect("postgres URL must have a /dbname path");
    let mut new_url = format!("{}/{}", &base[..last_slash], db_name);
    if let Some(q) = query {
        new_url.push('?');
        new_url.push_str(q);
    }
    new_url
}

async fn create_throwaway_database(admin_url: &str) -> (String, String) {
    let client = pg_client(admin_url).await;
    let suffix: u64 = rand::random();
    let db_name = format!("lore_wp116_test_{suffix:016x}");
    client
        .batch_execute(&format!("CREATE DATABASE \"{db_name}\""))
        .await
        .expect("create throwaway database");
    (db_name.clone(), replace_dbname(admin_url, &db_name))
}

async fn drop_throwaway_database(admin_url: &str, db_name: &str) {
    let client = pg_client(admin_url).await;
    let _ = client
        .execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
            &[&db_name],
        )
        .await;
    client
        .batch_execute(&format!("DROP DATABASE IF EXISTS \"{db_name}\""))
        .await
        .expect("drop throwaway database");
}

// ─── repository / branch row helpers ────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn insert_repository(
    client: &tokio_postgres::Client,
    repository_id: &[u8],
    state: i16,
    name: &str,
    deleted_at_present: bool,
    delete_proof: Option<&[u8]>,
) -> Result<(), tokio_postgres::Error> {
    let metadata_hash: [u8; 32] = rand::random();
    let default_branch_id: [u8; 16] = rand::random();
    let creation_fingerprint: [u8; 32] = rand::random();
    let deleted_at_expr = if deleted_at_present {
        "clock_timestamp()"
    } else {
        "NULL"
    };
    let sql = format!(
        "INSERT INTO lore_domain_repositories (
            repository_id, state, generation, name, metadata_hash, default_branch_id,
            creation_fingerprint_version, creation_fingerprint, delete_proof,
            created_at, deleted_at
        ) VALUES ($1, $2, 1, $3, $4, $5, 1, $6, $7, clock_timestamp(), {deleted_at_expr})"
    );
    client
        .execute(
            &sql,
            &[
                &repository_id,
                &state,
                &name,
                &metadata_hash.as_slice(),
                &default_branch_id.as_slice(),
                &creation_fingerprint.as_slice(),
                &delete_proof,
            ],
        )
        .await
        .map(|_| ())
}

async fn insert_repository_name(
    client: &tokio_postgres::Client,
    name: &str,
    repository_id: &[u8],
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "INSERT INTO lore_domain_repository_names
                (name, repository_id, repository_generation, created_at)
             VALUES ($1, $2, 1, clock_timestamp())",
            &[&name, &repository_id],
        )
        .await
        .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
async fn insert_branch(
    client: &tokio_postgres::Client,
    repository_id: &[u8],
    branch_id: &[u8],
    state: i16,
    name: &str,
    deleted_at_present: bool,
    delete_proof: Option<&[u8]>,
) -> Result<(), tokio_postgres::Error> {
    let metadata_hash: [u8; 32] = rand::random();
    let latest_hash: [u8; 32] = rand::random();
    let creation_fingerprint: [u8; 32] = rand::random();
    let deleted_at_expr = if deleted_at_present {
        "clock_timestamp()"
    } else {
        "NULL"
    };
    let sql = format!(
        "INSERT INTO lore_domain_branches (
            repository_id, branch_id, repository_generation, state, generation, name,
            metadata_hash, latest_hash, creation_fingerprint_version, creation_fingerprint,
            delete_proof, created_at, deleted_at
        ) VALUES ($1, $2, 1, $3, 1, $4, $5, $6, 1, $7, $8, clock_timestamp(), {deleted_at_expr})"
    );
    client
        .execute(
            &sql,
            &[
                &repository_id,
                &branch_id,
                &state,
                &name,
                &metadata_hash.as_slice(),
                &latest_hash.as_slice(),
                &creation_fingerprint.as_slice(),
                &delete_proof,
            ],
        )
        .await
        .map(|_| ())
}

async fn insert_branch_name(
    client: &tokio_postgres::Client,
    repository_id: &[u8],
    name_key: &str,
    display_name: &str,
    branch_id: &[u8],
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "INSERT INTO lore_domain_branch_names
                (repository_id, name_key, display_name, branch_id,
                 repository_generation, branch_generation, created_at)
             VALUES ($1, $2, $3, $4, 1, 1, clock_timestamp())",
            &[&repository_id, &name_key, &display_name, &branch_id],
        )
        .await
        .map(|_| ())
}

// ─── bootstrap idempotence (spec item 2) ────────────────────────────────────

/// `PostgresDomainStore::connect` must be safe to call twice in a row, and
/// safe to call concurrently from two independent pools — the shared
/// `SCHEMA_LOCK_KEY` advisory lock underlying `pool::ensure_schema` is what
/// makes concurrent multi-replica boot safe against the `IF NOT EXISTS` DDL
/// race, and `ensure_state_rows`'s `ON CONFLICT (id) DO NOTHING` makes the
/// singleton rows idempotent too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn domain_store_connect_is_idempotent_sequential_and_concurrent() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping domain store bootstrap test");
        return;
    };

    let first = connect_domain_store(&url).await;
    let second = connect_domain_store(&url).await;
    assert_eq!(
        first.identity(),
        second.identity(),
        "two sequential connects to the same URL must report the same database identity"
    );

    let tls = TlsConfig::default();
    let (a, b) = tokio::join!(
        PostgresDomainStore::connect(&url, 2, &tls),
        PostgresDomainStore::connect(&url, 2, &tls),
    );
    a.expect("concurrent connect (a) must succeed");
    b.expect("concurrent connect (b) must succeed");
}

// ─── coexistence with pre-existing CR-007 rows (spec item 3) ───────────────

/// Bootstrapping the domain store on a database that already has populated
/// CR-007 tables (`lore_mutable`, `lore_locks`) must succeed and must not
/// touch those existing rows — this is the "existing-cell" upgrade shape the
/// real cutover runs against.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn domain_schema_applies_cleanly_alongside_existing_cr007_rows() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping domain schema upgrade-fixture test");
        return;
    };
    let tls = TlsConfig::default();

    let mutable = std::sync::Arc::new(
        PostgresMutableStore::connect(&url, 2, &tls)
            .await
            .expect("connect mutable store"),
    );
    let part: Partition = rand::random();
    let key: Hash = rand::random();
    let kt = KeyType::RepositoryId;
    let value: Hash = rand::random();
    mutable
        .clone()
        .store(part, key, value, kt)
        .await
        .expect("seed pre-existing lore_mutable row");

    let lock_store = PostgresLockStore::connect(&url, 2, &tls)
        .await
        .expect("connect lock store");
    let repo: RepositoryId = rand::random();
    let resource = LockResource {
        branch: rand::random(),
        hash: rand::random(),
        description: "domain-schema-upgrade-fixture".to_string(),
    };
    lock_store
        .lock_resources(
            "domain-schema-fixture-owner",
            repo,
            std::slice::from_ref(&resource),
        )
        .await
        .expect("seed pre-existing lock row");

    connect_domain_store(&url).await;

    assert_eq!(
        mutable
            .clone()
            .load(part, key, kt)
            .await
            .expect("load lore_mutable row after domain schema apply"),
        value,
        "pre-existing lore_mutable row must be untouched by the domain schema apply"
    );
    let status = lock_store
        .check_locks_status(repo, std::slice::from_ref(&resource))
        .await
        .expect("lock status after domain schema apply");
    assert_eq!(
        status.len(),
        1,
        "pre-existing lock row must still be present"
    );
    assert_eq!(status[0].owner, "domain-schema-fixture-owner");
}

// ─── same-database identity (spec item 13, R-SHOULD-1) ──────────────────────

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn database_identity_agrees_for_two_pools_on_the_same_database_and_differs_across_databases()
{
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping same-database identity test");
        return;
    };
    let tls = TlsConfig::default();

    let store = connect_domain_store(&url).await;
    let same_db_pool = build_pool(&url, 2, &tls).expect("build second pool for the same database");
    store
        .assert_same_database(&same_db_pool, "mutable")
        .await
        .expect("a second pool addressing the same database must agree");

    let (other_db_name, other_db_url) = create_throwaway_database(&url).await;
    let other_pool = build_pool(&other_db_url, 2, &tls).expect("build pool for the other database");
    let err = store
        .assert_same_database(&other_pool, "mutable")
        .await
        .expect_err("a pool addressing a different database must not agree");
    assert!(
        matches!(err, lore_postgres::domain::DomainError::NotReady(_)),
        "a database-identity mismatch must be reported as NotReady, got {err:?}"
    );
    drop(other_pool);
    drop_throwaway_database(&url, &other_db_name).await;
}

// ─── tombstone evidence (spec item 5) ───────────────────────────────────────

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn repository_tombstone_evidence_constraint_rejects_incomplete_state() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping repository tombstone-evidence test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let name_prefix = format!("tombstone-evidence-{:016x}", rand::random::<u64>());

    // Positive control: a live row with no deletion evidence must succeed.
    let live_id: [u8; 16] = rand::random();
    insert_repository(
        &client,
        &live_id,
        0,
        &format!("{name_prefix}-live"),
        false,
        None,
    )
    .await
    .expect("live repository row with no deletion evidence must be accepted");

    // Positive control: a tombstoned row with both fields must succeed.
    let tombstoned_id: [u8; 16] = rand::random();
    let proof: [u8; 32] = rand::random();
    insert_repository(
        &client,
        &tombstoned_id,
        1,
        &format!("{name_prefix}-tombstoned"),
        true,
        Some(&proof),
    )
    .await
    .expect("tombstoned repository row with both deleted_at and delete_proof must be accepted");

    // Negative: live with deleted_at set.
    let bad_id: [u8; 16] = rand::random();
    let err = insert_repository(
        &client,
        &bad_id,
        0,
        &format!("{name_prefix}-live-dat"),
        true,
        None,
    )
    .await
    .expect_err("live repository with deleted_at must be rejected");
    assert_violation(
        &err,
        &SqlState::CHECK_VIOLATION,
        "lore_domain_repositories_tombstone_evidence",
    );

    // Negative: live with delete_proof set.
    let bad_id2: [u8; 16] = rand::random();
    let err = insert_repository(
        &client,
        &bad_id2,
        0,
        &format!("{name_prefix}-live-proof"),
        false,
        Some(&proof),
    )
    .await
    .expect_err("live repository with delete_proof must be rejected");
    assert_violation(
        &err,
        &SqlState::CHECK_VIOLATION,
        "lore_domain_repositories_tombstone_evidence",
    );

    // Negative: tombstoned without deleted_at.
    let bad_id3: [u8; 16] = rand::random();
    let err = insert_repository(
        &client,
        &bad_id3,
        1,
        &format!("{name_prefix}-tomb-no-dat"),
        false,
        Some(&proof),
    )
    .await
    .expect_err("tombstoned repository without deleted_at must be rejected");
    assert_violation(
        &err,
        &SqlState::CHECK_VIOLATION,
        "lore_domain_repositories_tombstone_evidence",
    );

    // Negative: tombstoned without delete_proof.
    let bad_id4: [u8; 16] = rand::random();
    let err = insert_repository(
        &client,
        &bad_id4,
        1,
        &format!("{name_prefix}-tomb-no-proof"),
        true,
        None,
    )
    .await
    .expect_err("tombstoned repository without delete_proof must be rejected");
    assert_violation(
        &err,
        &SqlState::CHECK_VIOLATION,
        "lore_domain_repositories_tombstone_evidence",
    );
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_tombstone_evidence_constraint_rejects_incomplete_state() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping branch tombstone-evidence test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let name_prefix = format!("branch-tombstone-{:016x}", rand::random::<u64>());
    let repository_id: [u8; 16] = rand::random();
    insert_repository(
        &client,
        &repository_id,
        0,
        &format!("{name_prefix}-repo"),
        false,
        None,
    )
    .await
    .expect("seed owning repository");

    // Positive controls.
    let live_branch: [u8; 16] = rand::random();
    insert_branch(
        &client,
        &repository_id,
        &live_branch,
        0,
        &format!("{name_prefix}-live"),
        false,
        None,
    )
    .await
    .expect("live branch row with no deletion evidence must be accepted");

    let tombstoned_branch: [u8; 16] = rand::random();
    let proof: [u8; 32] = rand::random();
    insert_branch(
        &client,
        &repository_id,
        &tombstoned_branch,
        1,
        &format!("{name_prefix}-tombstoned"),
        true,
        Some(&proof),
    )
    .await
    .expect("tombstoned branch row with both fields must be accepted");

    // Negatives, one per missing/extra evidence combination.
    for (state, deleted_at_present, delete_proof, label) in [
        (0i16, true, None, "live-with-deleted-at"),
        (0i16, false, Some(proof.as_slice()), "live-with-proof"),
        (
            1i16,
            false,
            Some(proof.as_slice()),
            "tombstoned-without-deleted-at",
        ),
        (1i16, true, None, "tombstoned-without-proof"),
    ] {
        let branch_id: [u8; 16] = rand::random();
        let err = insert_branch(
            &client,
            &repository_id,
            &branch_id,
            state,
            &format!("{name_prefix}-{label}"),
            deleted_at_present,
            delete_proof,
        )
        .await
        .unwrap_err();
        assert_violation(
            &err,
            &SqlState::CHECK_VIOLATION,
            "lore_domain_branches_tombstone_evidence",
        );
    }
}

// ─── R-BLOCK-3 case folding (spec item 6) ───────────────────────────────────

/// The exact pair required by CR-029's independent-review triage: within one
/// repository, live branch names `Feature` and `feature` collide on
/// `lore_domain_branch_names` because that table keys on `lowercase(name)`
/// (matching `branch.rs:477`), while two repositories named `Repo` and `repo`
/// coexist because `lore_domain_repository_names` keys on exact bytes
/// (matching `repository.rs:3264`).
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn r_block_3_branch_names_fold_case_but_repository_names_key_on_exact_bytes() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping R-BLOCK-3 case-folding test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let suffix = format!("{:016x}", rand::random::<u64>());

    // Branch half: same repository, "Feature" then "feature" — both fold to
    // the same name_key and must collide on the primary key.
    let repository_id: [u8; 16] = rand::random();
    insert_repository(
        &client,
        &repository_id,
        0,
        &format!("case-fold-owner-{suffix}"),
        false,
        None,
    )
    .await
    .expect("seed owning repository");

    let branch_a: [u8; 16] = rand::random();
    insert_branch(
        &client,
        &repository_id,
        &branch_a,
        0,
        "Feature",
        false,
        None,
    )
    .await
    .expect("seed branch domain row for Feature");
    insert_branch_name(&client, &repository_id, "feature", "Feature", &branch_a)
        .await
        .expect("insert live branch name for Feature (name_key = feature)");

    let branch_b: [u8; 16] = rand::random();
    insert_branch(
        &client,
        &repository_id,
        &branch_b,
        0,
        "feature",
        false,
        None,
    )
    .await
    .expect("seed branch domain row for feature");
    let err = insert_branch_name(&client, &repository_id, "feature", "feature", &branch_b)
        .await
        .expect_err(
            "a second live branch whose name folds to the same key must be rejected \
             (Feature and feature must collide)",
        );
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::UNIQUE_VIOLATION);
    assert_eq!(
        db_err.constraint(),
        Some("lore_domain_branch_names_pkey"),
        "collision must be on the (repository_id, name_key) primary key"
    );

    // Repository half: "Repo" and "repo" are independent names — exact bytes,
    // no folding — so both must be admitted as distinct live owners.
    let repo_upper: [u8; 16] = rand::random();
    insert_repository(
        &client,
        &repo_upper,
        0,
        &format!("Repo-{suffix}"),
        false,
        None,
    )
    .await
    .expect("seed repository named Repo-<suffix>");
    insert_repository_name(&client, &format!("Repo-{suffix}"), &repo_upper)
        .await
        .expect("repository name Repo-<suffix> must be accepted");

    let repo_lower: [u8; 16] = rand::random();
    insert_repository(
        &client,
        &repo_lower,
        0,
        &format!("repo-{suffix}"),
        false,
        None,
    )
    .await
    .expect("seed repository named repo-<suffix>");
    insert_repository_name(&client, &format!("repo-{suffix}"), &repo_lower)
        .await
        .expect(
            "repository name repo-<suffix> must coexist with Repo-<suffix> \
             (repository names key on exact bytes, no folding)",
        );
}

// ─── name release (spec item 7) ─────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn repository_name_is_releasable_only_after_prior_owner_tombstoned_same_transaction() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping repository name-release test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let name = format!("name-release-{:016x}", rand::random::<u64>());

    let owner_a: [u8; 16] = rand::random();
    insert_repository(&client, &owner_a, 0, &name, false, None)
        .await
        .expect("seed original owner");
    insert_repository_name(&client, &name, &owner_a)
        .await
        .expect("original owner claims the name");

    // While the original owner is still live, a second repository cannot
    // claim the same name.
    let owner_b: [u8; 16] = rand::random();
    insert_repository(&client, &owner_b, 0, &format!("{name}-b"), false, None)
        .await
        .expect("seed second owner row (different repository name)");
    let err = insert_repository_name(&client, &name, &owner_b)
        .await
        .expect_err("name must not be claimable while the original owner is live");
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::UNIQUE_VIOLATION);
    assert_eq!(
        db_err.constraint(),
        Some("lore_domain_repository_names_pkey")
    );

    // Tombstoning the original owner and deleting its name row, then handing
    // the name to the new owner, must succeed as one transaction.
    let proof: [u8; 32] = rand::random();
    let tx = client
        .transaction()
        .await
        .expect("begin release transaction");
    tx.execute(
        "UPDATE lore_domain_repositories
            SET state = 1, deleted_at = clock_timestamp(), delete_proof = $2
          WHERE repository_id = $1",
        &[&owner_a.as_slice(), &proof.as_slice()],
    )
    .await
    .expect("tombstone original owner");
    tx.execute(
        "DELETE FROM lore_domain_repository_names WHERE name = $1",
        &[&name],
    )
    .await
    .expect("release original owner's name row");
    tx.execute(
        "INSERT INTO lore_domain_repository_names
            (name, repository_id, repository_generation, created_at)
         VALUES ($1, $2, 1, clock_timestamp())",
        &[&name, &owner_b.as_slice()],
    )
    .await
    .expect("new owner claims the released name");
    tx.commit().await.expect("commit name-release transaction");

    let row = client
        .query_one(
            "SELECT repository_id FROM lore_domain_repository_names WHERE name = $1",
            &[&name],
        )
        .await
        .expect("name row must exist after release");
    let owning: Vec<u8> = row.get(0);
    assert_eq!(owning, owner_b, "the name must now belong to the new owner");
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn branch_name_is_releasable_only_after_prior_owner_tombstoned_same_transaction() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping branch name-release test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let repository_id: [u8; 16] = rand::random();
    insert_repository(
        &client,
        &repository_id,
        0,
        &format!("branch-release-owner-{:016x}", rand::random::<u64>()),
        false,
        None,
    )
    .await
    .expect("seed owning repository");
    let name_key = format!("branch-release-{:016x}", rand::random::<u64>());

    let owner_a: [u8; 16] = rand::random();
    insert_branch(&client, &repository_id, &owner_a, 0, &name_key, false, None)
        .await
        .expect("seed original branch owner");
    insert_branch_name(&client, &repository_id, &name_key, &name_key, &owner_a)
        .await
        .expect("original branch claims the name");

    let owner_b: [u8; 16] = rand::random();
    insert_branch(
        &client,
        &repository_id,
        &owner_b,
        0,
        &format!("{name_key}-b"),
        false,
        None,
    )
    .await
    .expect("seed second branch owner row");
    let err = insert_branch_name(&client, &repository_id, &name_key, &name_key, &owner_b)
        .await
        .expect_err("branch name must not be claimable while the original owner is live");
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::UNIQUE_VIOLATION);
    assert_eq!(db_err.constraint(), Some("lore_domain_branch_names_pkey"));

    let proof: [u8; 32] = rand::random();
    let tx = client
        .transaction()
        .await
        .expect("begin branch release transaction");
    tx.execute(
        "UPDATE lore_domain_branches
            SET state = 1, deleted_at = clock_timestamp(), delete_proof = $3
          WHERE repository_id = $1 AND branch_id = $2",
        &[
            &repository_id.as_slice(),
            &owner_a.as_slice(),
            &proof.as_slice(),
        ],
    )
    .await
    .expect("tombstone original branch owner");
    tx.execute(
        "DELETE FROM lore_domain_branch_names WHERE repository_id = $1 AND name_key = $2",
        &[&repository_id.as_slice(), &name_key],
    )
    .await
    .expect("release original branch name row");
    tx.execute(
        "INSERT INTO lore_domain_branch_names
            (repository_id, name_key, display_name, branch_id,
             repository_generation, branch_generation, created_at)
         VALUES ($1, $2, $2, $3, 1, 1, clock_timestamp())",
        &[&repository_id.as_slice(), &name_key, &owner_b.as_slice()],
    )
    .await
    .expect("new branch owner claims the released name");
    tx.commit()
        .await
        .expect("commit branch name-release transaction");

    let row = client
        .query_one(
            "SELECT branch_id FROM lore_domain_branch_names
              WHERE repository_id = $1 AND name_key = $2",
            &[&repository_id.as_slice(), &name_key],
        )
        .await
        .expect("branch name row must exist after release");
    let owning: Vec<u8> = row.get(0);
    assert_eq!(owning, owner_b);
}

// ─── identity non-reuse (spec item 8) ───────────────────────────────────────

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn repository_identity_is_never_reusable_after_tombstoning() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping repository identity-reuse test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let repository_id: [u8; 16] = rand::random();
    let proof: [u8; 32] = rand::random();
    let name = format!("identity-reuse-{:016x}", rand::random::<u64>());
    insert_repository(&client, &repository_id, 1, &name, true, Some(&proof))
        .await
        .expect("seed tombstoned repository");

    let err = insert_repository(
        &client,
        &repository_id,
        0,
        &format!("{name}-again"),
        false,
        None,
    )
    .await
    .expect_err("a second row with the same tombstoned repository_id must be rejected");
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::UNIQUE_VIOLATION);
    assert_eq!(db_err.constraint(), Some("lore_domain_repositories_pkey"));
}

// ─── future-rejection quota bounds (spec item 9) ────────────────────────────

async fn insert_quota_row(
    client: &tokio_postgres::Client,
    key: &(String, String, Vec<u8>),
    retained_count: i64,
    bucket_count: i64,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "INSERT INTO lore_domain_operation_future_reject_quotas
                (verified_issuer, authenticated_subject, tenant_scope_key,
                 quota_version, retained_count, bucket_start, bucket_count, updated_at)
             VALUES ($1, $2, $3, 1, $4, clock_timestamp(), $5, clock_timestamp())",
            &[
                &key.0,
                &key.1,
                &key.2.as_slice(),
                &retained_count,
                &bucket_count,
            ],
        )
        .await
        .map(|_| ())
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn future_reject_quota_bounds_reject_out_of_range_counts() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping future-rejection quota bounds test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    let suffix: u64 = rand::random();

    let key_ok = (
        format!("issuer-{suffix:016x}"),
        "subject".to_string(),
        rand::random::<[u8; 8]>().to_vec(),
    );
    insert_quota_row(&client, &key_ok, 1024, 64)
        .await
        .expect("retained_count=1024, bucket_count=64 are the inclusive upper bound");

    let key_over_retained = (
        format!("issuer-retained-{suffix:016x}"),
        "subject".to_string(),
        rand::random::<[u8; 8]>().to_vec(),
    );
    let err = insert_quota_row(&client, &key_over_retained, 1025, 1)
        .await
        .expect_err("retained_count=1025 must exceed FUTURE_REJECT_QUOTA_RETAINED_MAX");
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::CHECK_VIOLATION);

    let key_over_bucket = (
        format!("issuer-bucket-{suffix:016x}"),
        "subject".to_string(),
        rand::random::<[u8; 8]>().to_vec(),
    );
    let err = insert_quota_row(&client, &key_over_bucket, 1, 65)
        .await
        .expect_err("bucket_count=65 must exceed FUTURE_REJECT_QUOTA_HOURLY_MAX");
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::CHECK_VIOLATION);
}

// ─── schema-state gating (spec item 10) ─────────────────────────────────────

async fn upsert_schema_state(
    client: &tokio_postgres::Client,
    backfill_state: i16,
    cutover_at_present: bool,
    enforcement_enabled: bool,
) -> Result<(), tokio_postgres::Error> {
    let cutover_expr = if cutover_at_present {
        "clock_timestamp()"
    } else {
        "NULL"
    };
    let sql = format!(
        "UPDATE lore_domain_schema_state SET
            backfill_state = $1, cutover_at = {cutover_expr},
            enforcement_enabled = $2, updated_at = clock_timestamp()
         WHERE id = 1"
    );
    client
        .execute(&sql, &[&backfill_state, &enforcement_enabled])
        .await
        .map(|_| ())
}

/// `PostgresDomainStore::enable_enforcement` refuses with a typed `NotReady`
/// rather than a bare SQLSTATE, for a deterministically-forced not-ready
/// state. `#[serial]` because this mutates the shared singleton
/// `lore_domain_schema_state` row (`id = 1`).
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
#[serial]
async fn enable_enforcement_refuses_before_backfill_cutover() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping enable_enforcement gating test");
        return;
    };
    let store = connect_domain_store(&url).await;
    let client = pg_client(&url).await;
    upsert_schema_state(&client, 0, false, false)
        .await
        .expect("force a deterministic not-ready state");

    let err = store
        .enable_enforcement()
        .await
        .expect_err("enable_enforcement must refuse before cutover");
    assert!(matches!(
        err,
        lore_postgres::domain::DomainError::NotReady(_)
    ));

    // Restore for any test that runs after this one against the shared row.
    upsert_schema_state(&client, 0, false, false)
        .await
        .expect("restore schema state to backfill-not-started");
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
#[serial]
async fn schema_state_gating_rejects_enforcement_without_cutover_and_cutover_shape_mismatch() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping schema-state gating test");
        return;
    };
    connect_domain_store(&url).await;
    let client = pg_client(&url).await;

    // Positive controls (the singleton row already exists from connect()).
    upsert_schema_state(&client, 0, false, false)
        .await
        .expect("backfill not started, no cutover, enforcement off must be accepted");
    upsert_schema_state(&client, 3, true, true)
        .await
        .expect("cutover set with backfill_state=3 and enforcement on must be accepted");

    // Negative: enforcement requested before cutover (backfill_state != 3).
    let err = upsert_schema_state(&client, 2, false, true)
        .await
        .expect_err("enforcement_enabled must require backfill_state = 3");
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::CHECK_VIOLATION);
    assert_eq!(
        db_err.constraint(),
        Some("lore_domain_schema_state_enforcement_needs_cutover")
    );

    // Negative: backfill_state = 3 without cutover_at.
    let err = upsert_schema_state(&client, 3, false, false)
        .await
        .expect_err("backfill_state = 3 must require cutover_at");
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::CHECK_VIOLATION);
    assert_eq!(
        db_err.constraint(),
        Some("lore_domain_schema_state_cutover_shape")
    );

    // Negative: cutover_at present without backfill_state = 3.
    let err = upsert_schema_state(&client, 1, true, false)
        .await
        .expect_err("cutover_at must require backfill_state = 3");
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::CHECK_VIOLATION);
    assert_eq!(
        db_err.constraint(),
        Some("lore_domain_schema_state_cutover_shape")
    );

    // Restore the shared row to a harmless state for any test that runs after
    // this one against the same shared database.
    upsert_schema_state(&client, 0, false, false)
        .await
        .expect("restore schema state to backfill-not-started");
}
