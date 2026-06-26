// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Postgres-backed advisory lock store (CR-007).
//!
//! Exclusivity is a `PRIMARY KEY (repository, branch, hash)`. Acquire is an
//! idempotent-same-owner conditional insert (`ON CONFLICT DO NOTHING`) of all
//! requested resources in a single transaction (batch-or-nothing); release is
//! owner-checked with a force bypass. This mirrors the semantics of the
//! in-process `LocalLockStore` and the DynamoDB store (INV-R §3). There is no
//! TTL/lease — locks persist until explicitly released.

use async_trait::async_trait;
use deadpool_postgres::Manager;
use deadpool_postgres::ManagerConfig;
use deadpool_postgres::Pool;
use deadpool_postgres::RecyclingMethod;
use lore_base::error::InvalidArguments;
use lore_base::error::LockNotFound;
use lore_base::error::LockNotOwned;
use lore_base::types::Hash;
use lore_base::types::LockData;
use lore_base::types::LockResource;
use lore_revision::lock::LockError;
use lore_revision::lock::LockQuery;
use lore_revision::lock::LockStore;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::util;
use tokio_postgres::NoTls;
use tokio_postgres::Row;

/// Self-bootstrapping schema. The `PRIMARY KEY` is the exclusivity constraint;
/// the three indexes back the supported `LockQuery` filters (the DynamoDB "3
/// GSIs" map 1:1 — INV-R §5).
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS lore_locks (
    repository  bytea  NOT NULL,
    branch      bytea  NOT NULL,
    hash        bytea  NOT NULL,
    owner       text   NOT NULL,
    description text   NOT NULL,
    locked_at   bigint NOT NULL,
    PRIMARY KEY (repository, branch, hash)
);
CREATE INDEX IF NOT EXISTS lore_locks_owner_repo_branch ON lore_locks (owner, repository, branch);
CREATE INDEX IF NOT EXISTS lore_locks_repo_branch       ON lore_locks (repository, branch);
CREATE INDEX IF NOT EXISTS lore_locks_repo_branch_desc  ON lore_locks (repository, branch, description);
";

const SELECT_COLS: &str =
    "SELECT repository, branch, hash, owner, description, locked_at FROM lore_locks";

/// Postgres advisory lock store.
pub struct PostgresLockStore {
    pool: Pool,
}

impl PostgresLockStore {
    /// Build the connection pool and ensure the schema exists.
    ///
    /// Async because the schema DDL needs a live connection; the plugin factory
    /// drives it to completion via `block_on` at startup.
    pub async fn connect(url: &str, pool_max: u32) -> Result<Self, String> {
        let pg_config = url
            .parse::<tokio_postgres::Config>()
            .map_err(|e| format!("invalid postgres url: {e}"))?;
        let manager = Manager::from_config(
            pg_config,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(pool_max as usize)
            .build()
            .map_err(|e| format!("failed to build postgres pool: {e}"))?;
        let client = pool
            .get()
            .await
            .map_err(|e| format!("postgres connect failed: {e}"))?;
        client
            .batch_execute(SCHEMA)
            .await
            .map_err(|e| format!("postgres lock-store schema failed: {e}"))?;
        Ok(Self { pool })
    }
}

/// Map any pool/query error to an opaque `LockError` (DB internals are not leaked
/// to clients; the message is logged-level detail).
fn db_err<E: std::fmt::Display>(e: E) -> LockError {
    LockError::internal(format!("postgres lock store: {e}"))
}

fn row_to_lock_data(row: &Row) -> LockData {
    let branch: Vec<u8> = row.get("branch");
    let hash: Vec<u8> = row.get("hash");
    LockData {
        resource: LockResource {
            branch: BranchId::from(branch.as_slice()),
            hash: Hash::from(hash.as_slice()),
            description: row.get("description"),
        },
        owner: row.get("owner"),
        locked_at: row.get::<_, i64>("locked_at") as u64,
    }
}

#[async_trait]
impl LockStore for PostgresLockStore {
    async fn lock_resources(
        &self,
        owner_id: &str,
        repository: RepositoryId,
        resources: &[LockResource],
    ) -> Result<Vec<LockData>, LockError> {
        let mut client = self.pool.get().await.map_err(db_err)?;
        let tx = client.transaction().await.map_err(db_err)?;
        let timestamp = util::time::timestamp();
        let ts = timestamp as i64;
        let repo = repository.data().as_slice();
        let mut locks = Vec::with_capacity(resources.len());

        for resource in resources {
            let branch = resource.branch.data().as_slice();
            let hash = resource.hash.data().as_slice();

            let inserted = tx
                .query_opt(
                    "INSERT INTO lore_locks \
                     (repository, branch, hash, owner, description, locked_at) \
                     VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT (repository, branch, hash) DO NOTHING RETURNING owner",
                    &[
                        &repo,
                        &branch,
                        &hash,
                        &owner_id,
                        &resource.description,
                        &ts,
                    ],
                )
                .await
                .map_err(db_err)?;

            if inserted.is_some() {
                locks.push(LockData {
                    resource: resource.clone(),
                    owner: owner_id.to_string(),
                    locked_at: timestamp,
                });
                continue;
            }

            // Conflict: idempotent if we already hold it, otherwise fail the
            // whole batch. Dropping `tx` without `commit` rolls everything back.
            let existing = tx
                .query_one(
                    "SELECT owner FROM lore_locks \
                     WHERE repository = $1 AND branch = $2 AND hash = $3",
                    &[&repo, &branch, &hash],
                )
                .await
                .map_err(db_err)?;
            let existing_owner: String = existing.get("owner");
            if existing_owner == owner_id {
                continue;
            }
            return Err(LockError::internal("resource already locked"));
        }

        tx.commit().await.map_err(db_err)?;
        Ok(locks)
    }

    async fn query_locks(&self, query: LockQuery) -> Result<Vec<LockData>, LockError> {
        let client = self.pool.get().await.map_err(db_err)?;
        let rows = match query {
            LockQuery::Repository(repo) => {
                client
                    .query(
                        &format!("{SELECT_COLS} WHERE repository = $1"),
                        &[&repo.data().as_slice()],
                    )
                    .await
            }
            LockQuery::RepositoryBranch(repo, branch) => {
                client
                    .query(
                        &format!("{SELECT_COLS} WHERE repository = $1 AND branch = $2"),
                        &[&repo.data().as_slice(), &branch.data().as_slice()],
                    )
                    .await
            }
            LockQuery::RepositoryBranchDescription(repo, branch, description) => {
                client
                    .query(
                        &format!(
                            "{SELECT_COLS} WHERE repository = $1 AND branch = $2 AND description = $3"
                        ),
                        &[&repo.data().as_slice(), &branch.data().as_slice(), &description],
                    )
                    .await
            }
            LockQuery::OwnerRepository(owner, repo) => {
                client
                    .query(
                        &format!("{SELECT_COLS} WHERE owner = $1 AND repository = $2"),
                        &[&owner, &repo.data().as_slice()],
                    )
                    .await
            }
            LockQuery::OwnerRepositoryBranch(owner, repo, branch) => {
                client
                    .query(
                        &format!(
                            "{SELECT_COLS} WHERE owner = $1 AND repository = $2 AND branch = $3"
                        ),
                        &[&owner, &repo.data().as_slice(), &branch.data().as_slice()],
                    )
                    .await
            }
            LockQuery::HashRepositoryBranch(hash, repo, branch) => {
                client
                    .query(
                        &format!(
                            "{SELECT_COLS} WHERE hash = $1 AND repository = $2 AND branch = $3"
                        ),
                        &[&hash.data().as_slice(), &repo.data().as_slice(), &branch.data().as_slice()],
                    )
                    .await
            }
            _ => {
                return Err(InvalidArguments {
                    reason: "unsupported lock query".into(),
                }
                .into());
            }
        }
        .map_err(db_err)?;

        Ok(rows.iter().map(row_to_lock_data).collect())
    }

    async fn check_locks_status(
        &self,
        repository: RepositoryId,
        resources: &[LockResource],
    ) -> Result<Vec<LockData>, LockError> {
        let client = self.pool.get().await.map_err(db_err)?;
        let repo = repository.data().as_slice();
        let mut locked = Vec::new();
        for resource in resources {
            let row = client
                .query_opt(
                    &format!(
                        "{SELECT_COLS} WHERE repository = $1 AND branch = $2 AND hash = $3"
                    ),
                    &[
                        &repo,
                        &resource.branch.data().as_slice(),
                        &resource.hash.data().as_slice(),
                    ],
                )
                .await
                .map_err(db_err)?;
            if let Some(row) = row {
                locked.push(row_to_lock_data(&row));
            }
        }
        Ok(locked)
    }

    async fn unlock_resources(
        &self,
        owner_id: &str,
        validate_user: bool,
        repository: RepositoryId,
        resources: &[LockResource],
    ) -> Result<Vec<LockResource>, LockError> {
        let mut client = self.pool.get().await.map_err(db_err)?;
        let tx = client.transaction().await.map_err(db_err)?;
        let repo = repository.data().as_slice();

        for resource in resources {
            let branch = resource.branch.data().as_slice();
            let hash = resource.hash.data().as_slice();

            let existing = tx
                .query_opt(
                    "SELECT owner FROM lore_locks \
                     WHERE repository = $1 AND branch = $2 AND hash = $3",
                    &[&repo, &branch, &hash],
                )
                .await
                .map_err(db_err)?;

            match existing {
                None => return Err(LockNotFound.into()),
                Some(row) => {
                    if validate_user {
                        let existing_owner: String = row.get("owner");
                        if existing_owner != owner_id {
                            return Err(LockNotOwned.into());
                        }
                    }
                    tx.execute(
                        "DELETE FROM lore_locks \
                         WHERE repository = $1 AND branch = $2 AND hash = $3",
                        &[&repo, &branch, &hash],
                    )
                    .await
                    .map_err(db_err)?;
                }
            }
        }

        tx.commit().await.map_err(db_err)?;
        Ok(resources.to_vec())
    }
}
