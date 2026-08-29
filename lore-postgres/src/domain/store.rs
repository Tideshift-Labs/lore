// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `PostgresDomainStore` — schema bootstrap, database identity, and the
//! migration/backfill/cutover state machine (CR-029; WP-116 Phase 2).
//!
//! The transaction methods themselves (`repository_create`, `branch_push_commit`,
//! `domain_operation_prepare`, …) land in Phase 3 on the narrow
//! `DomainTransactionStore` trait. What lives here is everything Phase 2 needs
//! to stand the schema up on an existing cell and refuse to enforce anything
//! until that cell is provably ready.
//!
//! **Fail closed is the whole point of this file.** A cell that has the tables
//! but has not finished backfill, or has finished backfill but not set the
//! cutover marker, must not enforce domain ownership — otherwise the generic
//! mutable path starts rejecting writes for keys that have no domain row yet.
//! The two CHECK constraints on `lore_domain_schema_state` make the unsafe
//! combinations unrepresentable rather than merely unlikely.

use deadpool_postgres::Pool;

use crate::domain::errors::DomainError;
use crate::domain::outbox::schema::OUTBOX_BASE_API_VERSION;
use crate::domain::outbox::schema::OUTBOX_SCHEMA;
use crate::domain::schema;
use crate::domain::schema_mediated::MEDIATED_SCHEMA;

/// Postgres-backed CR-029 domain coordinator.
pub struct PostgresDomainStore {
    pool: Pool,
    instruments: crate::metrics::Instruments,
    /// Identity of the database this store is bound to, captured at connect.
    /// Compared against the other three CR-007 pools by
    /// [`assert_same_database`] so a misconfigured cell cannot run its domain
    /// transactions against a different database from its mutable store.
    identity: DatabaseIdentity,
}

/// A value that is equal for two pools if and only if they address the same
/// physical database.
///
/// `system_identifier` alone identifies the *cluster*, so a cell pointed at two
/// databases inside one cluster would compare equal on it. The database OID
/// separates those, and the name is carried for a legible error message rather
/// than for the comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseIdentity {
    /// `pg_control_system().system_identifier`, as text (it exceeds `i64` range
    /// semantics in some builds and is only ever compared, never arithmetic).
    pub system_identifier: String,
    /// OID of the current database within that cluster.
    pub database_oid: u32,
    /// `current_database()`, for diagnostics only.
    pub database_name: String,
}

impl DatabaseIdentity {
    /// Stable rendering stored in `lore_domain_schema_state.database_identity`.
    pub fn as_marker(&self) -> String {
        format!(
            "{}:{}:{}",
            self.system_identifier, self.database_oid, self.database_name
        )
    }
}

/// Current migration/backfill/cutover state of one cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSchemaState {
    /// Version of the DDL the row was last written by.
    pub schema_version: i64,
    /// Backfill algorithm version.
    pub backfill_version: i64,
    /// One of the `BACKFILL_*` constants.
    pub backfill_state: i16,
    /// Restart cursor: the last repository the backfill completed.
    pub backfill_cursor: Option<Vec<u8>>,
    /// Whether the one-way verification's residue classification has run.
    pub residue_classified: bool,
    /// Set exactly when `backfill_state` is `BACKFILL_CUTOVER`.
    pub cutover_at: Option<std::time::SystemTime>,
    /// Whether domain enforcement is on. Requires cutover.
    pub enforcement_enabled: bool,
    /// The database identity recorded at bootstrap.
    pub database_identity: String,
}

impl DomainSchemaState {
    /// True only when the cell has completed backfill, classified its residue,
    /// and set the cutover marker. Readiness must consult this before enabling
    /// enforcement; the schema CHECK is the backstop, not the gate.
    pub fn ready_for_enforcement(&self) -> bool {
        self.backfill_state == schema::BACKFILL_CUTOVER
            && self.residue_classified
            && self.cutover_at.is_some()
    }
}

impl PostgresDomainStore {
    /// Build the pool, apply the domain, mediated-proof, and outbox-base DDL
    /// under the shared advisory lock, and record this cell's database identity.
    pub async fn connect(
        url: &str,
        pool_max: u32,
        tls: &crate::pool::TlsConfig,
    ) -> Result<Self, String> {
        let pool = crate::pool::build_pool(url, pool_max, tls)?;
        // One batch per logical schema so a failure names which block broke,
        // but all three under the same `SCHEMA_LOCK_KEY` so concurrent replica
        // boots cannot race the `IF NOT EXISTS` DDL.
        crate::pool::ensure_schema(&pool, schema::SCHEMA).await?;
        crate::pool::ensure_schema(&pool, MEDIATED_SCHEMA).await?;
        crate::pool::ensure_schema(&pool, OUTBOX_SCHEMA).await?;

        let identity = read_database_identity(&pool)
            .await
            .map_err(|e| format!("postgres domain store identity: {e}"))?;

        let store = Self {
            pool,
            instruments: crate::metrics::Instruments::new("domain"),
            identity,
        };
        store
            .ensure_state_rows()
            .await
            .map_err(|e| format!("postgres domain schema state: {e}"))?;
        Ok(store)
    }

    /// The database this store is bound to.
    pub fn identity(&self) -> &DatabaseIdentity {
        &self.identity
    }

    /// R-SHOULD-1: prove positively that another CR-007 pool addresses the same
    /// database as this store, rather than assuming it from configuration.
    ///
    /// Startup calls this for the mutable, immutable, and lock pools. A domain
    /// transaction that updates `lore_mutable` in the same transaction as its
    /// domain rows is only atomic if those rows are in one database; four
    /// independent URLs make that a configuration property, and this turns it
    /// into a checked one.
    pub async fn assert_same_database(&self, other: &Pool, label: &str) -> Result<(), DomainError> {
        let other_identity = read_database_identity(other).await?;
        if other_identity == self.identity {
            return Ok(());
        }
        Err(DomainError::NotReady(format!(
            "the {label} pool addresses {} but the domain coordinator addresses {}; \
             CR-029 domain transactions update lore_mutable in the same transaction \
             as their domain rows and cannot span two databases",
            other_identity.as_marker(),
            self.identity.as_marker()
        )))
    }

    /// Create the two singleton state rows if absent. Idempotent, and safe to
    /// run concurrently from several booting replicas.
    async fn ensure_state_rows(&self) -> Result<(), DomainError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::from_pool("domain schema state pool", e))?;
        client
            .execute(
                "INSERT INTO lore_domain_schema_state ( \
                     id, schema_version, backfill_version, backfill_state, \
                     database_identity, updated_at \
                 ) VALUES (1, $1, 0, $2, $3, clock_timestamp()) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &schema::DOMAIN_SCHEMA_VERSION,
                    &schema::BACKFILL_NOT_STARTED,
                    &self.identity.as_marker(),
                ],
            )
            .await
            .map_err(|e| DomainError::from_pg("domain schema state insert", e))?;
        // `migration_version` is bigint and the three compatibility floors are
        // integer, so they need separate placeholders: Postgres infers one type
        // per parameter number across the whole statement, and reusing `$1` for
        // both fails with 42P08 "inconsistent types deduced for parameter $1
        // (bigint versus integer)" on every fresh database.
        client
            .execute(
                "INSERT INTO lore_outbox_schema_state ( \
                     id, migration_version, backfill_version, \
                     producer_compat_floor, relay_compat_floor, consumer_compat_floor, \
                     updated_at \
                 ) VALUES (1, $1, 0, $2, $2, $2, clock_timestamp()) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &i64::from(OUTBOX_BASE_API_VERSION),
                    &OUTBOX_BASE_API_VERSION,
                ],
            )
            .await
            .map_err(|e| DomainError::from_pg("outbox schema state insert", e))?;
        Ok(())
    }

    /// Read the singleton domain schema state.
    pub async fn schema_state(&self) -> Result<DomainSchemaState, DomainError> {
        let _t = self.instruments.start("schema_state", self.pool.status());
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::from_pool("domain schema state pool", e))?;
        let row = client
            .query_one(
                "SELECT schema_version, backfill_version, backfill_state, backfill_cursor, \
                        residue_classified, cutover_at, enforcement_enabled, database_identity \
                 FROM lore_domain_schema_state WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DomainError::from_pg("domain schema state select", e))?;
        Ok(DomainSchemaState {
            schema_version: row.get("schema_version"),
            backfill_version: row.get("backfill_version"),
            backfill_state: row.get("backfill_state"),
            backfill_cursor: row.get("backfill_cursor"),
            residue_classified: row.get("residue_classified"),
            cutover_at: row.get("cutover_at"),
            enforcement_enabled: row.get("enforcement_enabled"),
            database_identity: row.get("database_identity"),
        })
    }

    /// Enable domain enforcement, refusing unless the cell is provably ready.
    ///
    /// The schema CHECK would reject the write anyway; this returns the typed
    /// [`DomainError::NotReady`] with the actual reason instead of a SQLSTATE
    /// 23514 the operator has to decode.
    pub async fn enable_enforcement(&self) -> Result<(), DomainError> {
        let state = self.schema_state().await?;
        if !state.ready_for_enforcement() {
            return Err(DomainError::NotReady(format!(
                "backfill_state={} residue_classified={} cutover_at={}; \
                 enforcement requires a completed backfill, a classified residue set, \
                 and the cutover marker",
                state.backfill_state,
                state.residue_classified,
                state.cutover_at.is_some()
            )));
        }
        if state.database_identity != self.identity.as_marker() {
            return Err(DomainError::NotReady(format!(
                "schema state was bootstrapped against {} but this process addresses {}",
                state.database_identity,
                self.identity.as_marker()
            )));
        }
        if state.schema_version > schema::DOMAIN_SCHEMA_VERSION {
            return Err(DomainError::NotReady(format!(
                "cell schema_version {} is newer than this binary's {}; \
                 roll the binary forward before enabling enforcement",
                state.schema_version,
                schema::DOMAIN_SCHEMA_VERSION
            )));
        }
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::from_pool("domain enforcement pool", e))?;
        client
            .execute(
                "UPDATE lore_domain_schema_state \
                 SET enforcement_enabled = true, updated_at = clock_timestamp() \
                 WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DomainError::from_pg("domain enforcement enable", e))?;
        Ok(())
    }

    /// Pool handle for the backfill and, from Phase 3, the transaction methods.
    pub(crate) fn pool(&self) -> &Pool {
        &self.pool
    }
}

/// Read one pool's database identity.
pub async fn read_database_identity(pool: &Pool) -> Result<DatabaseIdentity, DomainError> {
    let client = pool
        .get()
        .await
        .map_err(|e| DomainError::from_pool("database identity pool", e))?;
    let row = client
        .query_one(
            "SELECT (SELECT system_identifier::text FROM pg_control_system()) AS system_identifier, \
                    current_database()::text                                  AS database_name, \
                    (SELECT oid FROM pg_database WHERE datname = current_database()) AS database_oid",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("database identity select", e))?;
    Ok(DatabaseIdentity {
        system_identifier: row.get("system_identifier"),
        database_oid: row.get("database_oid"),
        database_name: row.get("database_name"),
    })
}
