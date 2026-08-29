// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Restartability and residue-classification tests for
//! [`lore_postgres::domain::backfill::DomainBackfill`] (CR-029 R-SHOULD-7;
//! WP-116 Phase 2).
//!
//! `DomainBackfillSource` is deliberately fake here: the real source lives in
//! `lore-server` (it deserializes immutable metadata and derives Lore's own
//! key hashes), and the backfill module's own docs say this trait boundary
//! exists precisely so its transaction logic is "testable against a fake".
//!
//! Every test here uses its own throwaway database, not the shared
//! `LORE_TEST_PG_URL` database the rest of the WP-116 suite writes to:
//! `DomainBackfill::verify()` runs whole-table queries over
//! `lore_domain_repositories`/`lore_mutable` with no test-scoping filter, so
//! it would otherwise see (and be confused by) every other test file's raw
//! SQL fixture rows.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Mutex;

use async_trait::async_trait;
use lore_base::types::KeyType;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::backfill::BranchFacts;
use lore_postgres::domain::backfill::DomainBackfill;
use lore_postgres::domain::backfill::DomainBackfillSource;
use lore_postgres::domain::backfill::OrphanKey;
use lore_postgres::domain::backfill::RepositoryFacts;
use lore_postgres::domain::backfill::ResidueClass;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use lore_postgres::store::mutable_store::PostgresMutableStore;
use lore_storage::Hash;
use lore_storage::MutableStore;
use lore_storage::Partition;

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

async fn create_throwaway_database(admin_url: &str, label: &str) -> (String, String) {
    let client = pg_client(admin_url).await;
    let suffix: u64 = rand::random();
    let db_name = format!("lore_wp116_backfill_{label}_{suffix:016x}");
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

/// A fixed, deterministic fixture: four repositories ascending by ID, each
/// with one or two branches. Fixed (not random) so two independent runs
/// against the same fixture are directly comparable.
fn fixture_repositories() -> Vec<(RepositoryFacts, Vec<BranchFacts>)> {
    (1u8..=4)
        .map(|n| {
            let repo = RepositoryFacts {
                repository_id: vec![n; 16],
                name: format!("fixture-repo-{n}"),
                name_map_resolves: true,
                metadata_hash: vec![n.wrapping_mul(7); 32],
                default_branch_id: vec![n.wrapping_add(100); 16],
                creation_fingerprint: vec![n.wrapping_mul(3); 32],
                creation_fingerprint_version: 1,
            };
            let branches = vec![BranchFacts {
                branch_id: vec![n.wrapping_add(100); 16],
                name: "main".to_string(),
                metadata_hash: vec![n.wrapping_mul(11); 32],
                latest_hash: vec![n.wrapping_mul(13); 32],
                creation_fingerprint: vec![n.wrapping_mul(5); 32],
                creation_fingerprint_version: 1,
            }];
            (repo, branches)
        })
        .collect()
}

/// A fake [`DomainBackfillSource`] over a fixed in-memory fixture.
/// `poisoned` repository IDs make `list_branches` fail once, simulating a
/// crash partway through a run without needing a real process kill.
struct FakeSource {
    repositories: Vec<RepositoryFacts>,
    branches: HashMap<Vec<u8>, Vec<BranchFacts>>,
    poisoned: Mutex<HashSet<Vec<u8>>>,
    orphans: Vec<OrphanKey>,
}

impl FakeSource {
    fn new(data: Vec<(RepositoryFacts, Vec<BranchFacts>)>) -> Self {
        let mut repositories = Vec::new();
        let mut branches = HashMap::new();
        for (repo, repo_branches) in data {
            branches.insert(repo.repository_id.clone(), repo_branches);
            repositories.push(repo);
        }
        repositories.sort_by(|a, b| a.repository_id.cmp(&b.repository_id));
        Self {
            repositories,
            branches,
            poisoned: Mutex::new(HashSet::new()),
            orphans: Vec::new(),
        }
    }

    fn with_orphans(mut self, orphans: Vec<OrphanKey>) -> Self {
        self.orphans = orphans;
        self
    }

    fn poison(&self, repository_id: &[u8]) {
        self.poisoned.lock().unwrap().insert(repository_id.to_vec());
    }
}

#[async_trait]
impl DomainBackfillSource for FakeSource {
    async fn list_repositories(&self) -> Result<Vec<RepositoryFacts>, DomainError> {
        Ok(self.repositories.clone())
    }

    async fn list_branches(&self, repository_id: &[u8]) -> Result<Vec<BranchFacts>, DomainError> {
        if self.poisoned.lock().unwrap().contains(repository_id) {
            return Err(DomainError::Internal(format!(
                "simulated crash reading branches for {}",
                hex::encode(repository_id)
            )));
        }
        Ok(self
            .branches
            .get(repository_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn snapshot_token(&self, repository_id: &[u8]) -> Result<Vec<u8>, DomainError> {
        Ok(repository_id.to_vec())
    }

    async fn orphan_projection_keys(&self) -> Result<Vec<OrphanKey>, DomainError> {
        Ok(self.orphans.clone())
    }
}

/// Seed one matching `lore_mutable` row per repository so
/// `DomainBackfill::verify()`'s forward-projection check passes: it looks for
/// any row with `partition = repository_id AND value = metadata_hash`.
async fn seed_projection_rows(url: &str, fixture: &[(RepositoryFacts, Vec<BranchFacts>)]) {
    let mutable = std::sync::Arc::new(
        PostgresMutableStore::connect(url, 2, &TlsConfig::default())
            .await
            .expect("connect mutable store to seed projection rows"),
    );
    for (repo, _) in fixture {
        let partition =
            Partition::from(<[u8; 16]>::try_from(repo.repository_id.as_slice()).unwrap());
        let value = Hash::from(<[u8; 32]>::try_from(repo.metadata_hash.as_slice()).unwrap());
        mutable
            .clone()
            .store(
                partition,
                Hash::default(),
                value,
                KeyType::RepositoryMetadata,
            )
            .await
            .expect("seed lore_mutable projection row");
    }
}

/// Sorted, diffable snapshot of the domain rows one backfill run produced.
async fn domain_rows_snapshot(client: &tokio_postgres::Client) -> Vec<String> {
    let mut lines = Vec::new();
    for row in client
        .query(
            "SELECT repository_id, name, metadata_hash, default_branch_id, state, generation \
             FROM lore_domain_repositories ORDER BY repository_id",
            &[],
        )
        .await
        .expect("read repositories")
    {
        let id: Vec<u8> = row.get("repository_id");
        let name: String = row.get("name");
        let hash: Vec<u8> = row.get("metadata_hash");
        let default_branch: Vec<u8> = row.get("default_branch_id");
        let state: i16 = row.get("state");
        let generation: i64 = row.get("generation");
        lines.push(format!(
            "repo::{}::{name}::{}::{}::{state}::{generation}",
            hex::encode(&id),
            hex::encode(&hash),
            hex::encode(&default_branch)
        ));
    }
    for row in client
        .query(
            "SELECT repository_id, branch_id, name, metadata_hash, latest_hash, state, generation \
             FROM lore_domain_branches ORDER BY repository_id, branch_id",
            &[],
        )
        .await
        .expect("read branches")
    {
        let repo_id: Vec<u8> = row.get("repository_id");
        let branch_id: Vec<u8> = row.get("branch_id");
        let name: String = row.get("name");
        let metadata_hash: Vec<u8> = row.get("metadata_hash");
        let latest_hash: Vec<u8> = row.get("latest_hash");
        let state: i16 = row.get("state");
        let generation: i64 = row.get("generation");
        lines.push(format!(
            "branch::{}::{}::{name}::{}::{}::{state}::{generation}",
            hex::encode(&repo_id),
            hex::encode(&branch_id),
            hex::encode(&metadata_hash),
            hex::encode(&latest_hash),
        ));
    }
    lines
}

/// The core WP-116 backfill claim: a run interrupted partway through (here,
/// by a source error on the third of four repositories) and then resumed
/// must produce domain rows identical to a single uninterrupted clean run —
/// the cursor makes resumption a no-op for already-committed repositories,
/// not a duplicate or divergent projection.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn backfill_restart_after_partial_failure_matches_a_single_clean_run() {
    let Some(admin_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping backfill restart test");
        return;
    };
    let fixture = fixture_repositories();

    // Clean run: one uninterrupted pass.
    let (clean_db, clean_url) = create_throwaway_database(&admin_url, "clean").await;
    PostgresDomainStore::connect(&clean_url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap clean-run database");
    seed_projection_rows(&clean_url, &fixture).await;
    let clean_pool = build_pool(&clean_url, 2, &TlsConfig::default()).expect("build clean pool");
    let clean_source = FakeSource::new(fixture.clone());
    let clean_backfill = DomainBackfill::new(&clean_pool, &clean_source);
    let clean_projected = clean_backfill.run().await.expect("clean run must succeed");
    assert_eq!(
        clean_projected, 4,
        "clean run must project all four repositories"
    );
    let clean_report = clean_backfill.verify().await.expect("clean verify");
    assert!(
        clean_report.passed(),
        "clean run projection must be complete: {clean_report:?}"
    );
    clean_backfill
        .complete(&clean_report)
        .await
        .expect("clean run must reach cutover");

    // Restart run: interrupted on the third repository (index 2, ID [3;16]),
    // then resumed with the poison lifted.
    let (restart_db, restart_url) = create_throwaway_database(&admin_url, "restart").await;
    PostgresDomainStore::connect(&restart_url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap restart-run database");
    seed_projection_rows(&restart_url, &fixture).await;
    let restart_pool =
        build_pool(&restart_url, 2, &TlsConfig::default()).expect("build restart pool");

    {
        let poisoned_source = FakeSource::new(fixture.clone());
        poisoned_source.poison(&[3u8; 16]);
        let backfill = DomainBackfill::new(&restart_pool, &poisoned_source);
        let err = backfill
            .run()
            .await
            .expect_err("a poisoned repository must fail the run partway through");
        assert!(matches!(err, DomainError::Internal(_)));
    }
    {
        // A fresh, unpoisoned source — the resumed process would reconstruct
        // its source the same way on restart.
        let resumed_source = FakeSource::new(fixture.clone());
        let backfill = DomainBackfill::new(&restart_pool, &resumed_source);
        let projected = backfill
            .run()
            .await
            .expect("resumed run must complete the remaining repositories");
        assert_eq!(
            projected, 2,
            "resume must project only the two repositories the interrupted run never reached"
        );
        let report = backfill.verify().await.expect("resumed verify");
        assert!(
            report.passed(),
            "resumed run projection must be complete: {report:?}"
        );
        backfill
            .complete(&report)
            .await
            .expect("resumed run must reach cutover");
    }

    let clean_client = pg_client(&clean_url).await;
    let restart_client = pg_client(&restart_url).await;
    let clean_snapshot = domain_rows_snapshot(&clean_client).await;
    let restart_snapshot = domain_rows_snapshot(&restart_client).await;
    assert_eq!(
        clean_snapshot, restart_snapshot,
        "a single clean run and an interrupted-then-resumed run over the same fixture \
         must produce identical domain rows"
    );

    drop(clean_client);
    drop(restart_client);
    drop_throwaway_database(&admin_url, &clean_db).await;
    drop_throwaway_database(&admin_url, &restart_db).await;
}

/// Re-running an already-fully-projected backfill must be a pure no-op: same
/// row count, same content, no error and no duplicate projection attempt.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn backfill_run_after_completion_is_a_no_op() {
    let Some(admin_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping backfill no-op-rerun test");
        return;
    };
    let fixture = fixture_repositories();
    let (db_name, db_url) = create_throwaway_database(&admin_url, "noop").await;
    PostgresDomainStore::connect(&db_url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap database");
    seed_projection_rows(&db_url, &fixture).await;
    let pool = build_pool(&db_url, 2, &TlsConfig::default()).expect("build pool");

    let source = FakeSource::new(fixture.clone());
    let backfill = DomainBackfill::new(&pool, &source);
    let first = backfill.run().await.expect("first run");
    assert_eq!(first, 4);
    let client = pg_client(&db_url).await;
    let before = domain_rows_snapshot(&client).await;

    let second_source = FakeSource::new(fixture.clone());
    let second_backfill = DomainBackfill::new(&pool, &second_source);
    let second = second_backfill
        .run()
        .await
        .expect("re-running a completed backfill must not error");
    assert_eq!(
        second, 0,
        "every repository is already at or below the cursor"
    );
    let after = domain_rows_snapshot(&client).await;
    assert_eq!(before, after, "re-running must not change any domain row");

    drop(client);
    drop_throwaway_database(&admin_url, &db_name).await;
}

/// CR-029 R-SHOULD-7: verification is one-way plus an explicit residue
/// classification. A `lore_mutable` name-map row whose owning repository is
/// gone (the shape a crashed/partial `RepositoryDelete` leaves behind) must
/// be classified as delete residue and must not fail the check, because it
/// is not something the backfill created or can repair.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn residue_from_a_crashed_delete_is_classified_not_failed() {
    let Some(admin_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping backfill residue-classification test");
        return;
    };
    let (db_name, db_url) = create_throwaway_database(&admin_url, "residue").await;
    PostgresDomainStore::connect(&db_url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap database");
    // verify()'s forward-projection check joins against lore_mutable, a
    // CR-007 table PostgresDomainStore::connect does not create. A real cell
    // always has it (CR-007 predates WP-116); bootstrap it here too so this
    // throwaway database matches that assumption instead of failing on a
    // missing relation unrelated to residue classification.
    PostgresMutableStore::connect(&db_url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap lore_mutable (CR-007) alongside the domain schema");
    let pool = build_pool(&db_url, 2, &TlsConfig::default()).expect("build pool");

    // No repositories at all, so the forward-projection check trivially
    // passes; the only thing under test is residue classification.
    let orphan = OrphanKey {
        key_type: KeyType::RepositoryId as i16,
        partition: vec![9u8; 16],
        key: vec![8u8; 32],
    };
    let source = FakeSource::new(Vec::new()).with_orphans(vec![orphan.clone()]);
    let backfill = DomainBackfill::new(&pool, &source);
    backfill.run().await.expect("run with zero repositories");
    let report = backfill.verify().await.expect("verify");

    assert!(
        report.passed(),
        "residue alone must not fail verification: {report:?}"
    );
    assert_eq!(report.residue.len(), 1);
    assert_eq!(report.residue[0].0, orphan);
    assert_eq!(report.residue[0].1, ResidueClass::DeleteResidue);

    backfill
        .complete(&report)
        .await
        .expect("a passed report with residue must still be allowed to reach cutover");

    drop_throwaway_database(&admin_url, &db_name).await;
}
