// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-039: offline forward upgrade of a clean-initialized fragment schema.
//!
//! Clean initialization installs a permanent fence on
//! `lore_fragment_schema_state` (see `initialization.rs`): the row may never
//! change again. WP-122's stage custody schema raises `schema_version` from 4
//! to 6 with a plain `UPDATE`, which the fence refuses. A fresh cell never
//! notices, because its bootstrap runs that DDL before the fence exists. A cell
//! initialized at revision 4 cannot reach revision 6 through bootstrap at all.
//!
//! This is the one supported path across that gap. It recognises a closed list
//! of states, refuses every other one by name, and runs in one transaction:
//!
//! 1. take the schema advisory lock and refuse while any other client backend
//!    is connected to the cell database. An idle replica holds no table lock,
//!    so a lock probe alone cannot see it; `pg_stat_database.numbackends` can,
//!    whatever the other session's role. `ACCESS EXCLUSIVE NOWAIT` on every
//!    fragment table stays as the backstop for a session that races the count;
//! 2. snapshot the schema-state row and every fragment trigger's full
//!    definition, enablement and function body;
//! 3. disable only `lore_clean_state_permanent`, apply the same stage DDL a
//!    fresh cell runs, and re-enable the trigger `ALWAYS`;
//! 4. prove that only `schema_version` moved (4 -> 7), that every trigger is
//!    exactly as before, that the stage objects exist with a fresh cell's
//!    seed, that clean readiness still holds, and that no other backend
//!    connected meanwhile; then commit.
//!
//! Row 78 adds a second supported start, revision 6. Its step applies only the
//! two stage charge counter columns (revision 7) and proves that the stage
//! usage, policy and custody rows are otherwise unchanged and the counters
//! start at zero.
//!
//! The trigger disable is transactional and never visible to another session.
//! It needs table ownership, which can already drop the trigger, so the fence
//! is not weakened. The fence's purpose, that no writer changes the clean
//! record, is what step 4 re-proves before the commit.

use std::time::Duration;

use tokio_postgres::Transaction;
use tokio_postgres::error::SqlState;

use super::coordinator::PostgresFragmentCoordinator;
use super::initialization;
use super::schema;
use super::stage_charge_schema::STAGE_CHARGE_COUNTER_SCHEMA;
use super::stage_rotation_schema::STAGE_POLICY_ROTATION_SCHEMA;
use super::stage_schema::STAGE_CUSTODY_SCHEMA;
use super::states::FragmentLifecycleState;
use crate::domain::errors::DomainError;
use crate::domain::fragments::failpoint;

/// The revision a clean cell initialized before WP-122's stage custody holds.
pub const PRE_STAGE_SCHEMA_VERSION: i64 = 4;

/// The revision a clean cell initialized before row 78's stage charge counters
/// holds. Its upgrade adds only the two counter columns.
pub const PRE_CHARGE_SCHEMA_VERSION: i64 = 6;

/// The revisions a clean cell may be upgraded from.
pub const UPGRADABLE_SCHEMA_VERSIONS: [i64; 2] =
    [PRE_STAGE_SCHEMA_VERSION, PRE_CHARGE_SCHEMA_VERSION];

/// The stage usage columns revision 7 adds.
const CHARGE_COLUMNS: [&str; 2] = ["charged_bytes", "charged_files"];

/// The relations a revision-4 cell has. The rest of
/// [`schema::FRAGMENT_SCHEMA_RELATIONS`] is [`STAGE_RELATIONS`].
pub const PRE_STAGE_RELATIONS: [&str; 8] = [
    "lore_fragment_lifecycle",
    "lore_fragment_epochs",
    "lore_fragment_associations",
    "lore_fragment_lifecycle_metering",
    "lore_fragment_write_claims",
    "lore_fragment_staged_leases",
    "lore_fragment_staged_lease_members",
    "lore_fragment_schema_state",
];

/// Relations the stage custody schema adds (revision 5).
pub const STAGE_RELATIONS: [&str; 3] = [
    "lore_fragment_stage_policy",
    "lore_fragment_stage_usage",
    "lore_fragment_stage_custody",
];

/// Every `lore_fragment_*` relation, index and sequence of a clean-initialized
/// revision-4 cell: SCHEMA-118 revision 4, the legacy immutable-store tables the
/// clean fences guard, and the membership protocol table. Read from a real cell
/// initialized by `lore` `dae71dfc` (2026-09-23). The classifier requires set
/// equality, so a missing index or an unknown extra object is refused.
pub const PRE_STAGE_CLASSES: [&str; 29] = [
    "lore_fragment_associations",
    "lore_fragment_associations_live_fanout",
    "lore_fragment_associations_pkey",
    "lore_fragment_associations_repository",
    "lore_fragment_epochs",
    "lore_fragment_epochs_pkey",
    "lore_fragment_fence_seq",
    "lore_fragment_lifecycle",
    "lore_fragment_lifecycle_metering",
    "lore_fragment_lifecycle_metering_pkey",
    "lore_fragment_lifecycle_pkey",
    "lore_fragment_membership_protocol",
    "lore_fragment_membership_protocol_pkey",
    "lore_fragment_metering",
    "lore_fragment_metering_pkey",
    "lore_fragment_schema_state",
    "lore_fragment_schema_state_pkey",
    "lore_fragment_staged_lease_members",
    "lore_fragment_staged_lease_members_epoch",
    "lore_fragment_staged_lease_members_pkey",
    "lore_fragment_staged_leases",
    "lore_fragment_staged_leases_deadline",
    "lore_fragment_staged_leases_pkey",
    "lore_fragment_state",
    "lore_fragment_state_pkey",
    "lore_fragment_write_claims",
    "lore_fragment_write_claims_barrier",
    "lore_fragment_write_claims_pkey",
    "lore_fragment_write_claims_terminal_prune",
];

/// The `lore_fragment_*` classes revisions 5 and 6 add.
pub const STAGE_CLASSES: [&str; 8] = [
    "lore_fragment_stage_custody",
    "lore_fragment_stage_custody_cleanup",
    "lore_fragment_stage_custody_pkey",
    "lore_fragment_stage_drain_recovery",
    "lore_fragment_stage_policy",
    "lore_fragment_stage_policy_pkey",
    "lore_fragment_stage_usage",
    "lore_fragment_stage_usage_pkey",
];

const STAGE_FUNCTIONS: [&str; 3] = [
    "stage_policy_publish_v1",
    "stage_policy_verify_v1",
    "stage_policy_rotate_v1",
];

const STAGE_INDEXES: [&str; 2] = [
    "lore_fragment_stage_custody_cleanup",
    "lore_fragment_stage_drain_recovery",
];

/// Bounded wait for a just-closed backend (for example this process's own
/// co-location check pool) to leave `numbackends` before refusing.
const BACKEND_SETTLE_ATTEMPTS: u32 = 10;
const BACKEND_SETTLE_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentSchemaUpgradeOutcome {
    /// The cell moved from `from_version` to the compiled revision.
    Upgraded { from_version: i64 },
    /// The cell was already at the compiled revision. Nothing was written.
    AlreadyCurrent,
}

/// Catalog facts that place a cell on the closed list.
#[derive(Debug, PartialEq, Eq)]
struct StageCatalog {
    /// Sorted `lore_fragment_*` class names in the current schema.
    classes: Vec<String>,
    stage_functions: i64,
    rotation_columns: i64,
    charge_columns: i64,
    promotion_claim_columns: i64,
    promotion_shape: bool,
}

/// Which supported revision a clean cell's catalog is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CatalogRevision {
    PreStage,
    PreCharge,
    Current,
}

impl CatalogRevision {
    fn version(self) -> i64 {
        match self {
            Self::PreStage => PRE_STAGE_SCHEMA_VERSION,
            Self::PreCharge => PRE_CHARGE_SCHEMA_VERSION,
            Self::Current => schema::FRAGMENT_SCHEMA_VERSION,
        }
    }
}

impl StageCatalog {
    fn revision(&self) -> Option<CatalogRevision> {
        if self.is_current() {
            Some(CatalogRevision::Current)
        } else if self.is_pre_charge() {
            Some(CatalogRevision::PreCharge)
        } else if self.is_pre_stage() {
            Some(CatalogRevision::PreStage)
        } else {
            None
        }
    }
    fn expected(current: bool) -> Vec<String> {
        let mut names: Vec<String> = PRE_STAGE_CLASSES.iter().map(|s| (*s).to_owned()).collect();
        if current {
            names.extend(STAGE_CLASSES.iter().map(|s| (*s).to_owned()));
        }
        names.sort();
        names
    }

    fn is_pre_stage(&self) -> bool {
        self.classes == Self::expected(false)
            && self.promotion_claim_columns == 3
            && self.promotion_shape
            && self.stage_functions == 0
            && self.rotation_columns == 0
            && self.charge_columns == 0
    }

    /// Revision 6: every stage object, without the charge counters.
    fn is_pre_charge(&self) -> bool {
        self.classes == Self::expected(true)
            && self.promotion_claim_columns == 3
            && self.promotion_shape
            && self.stage_functions == STAGE_FUNCTIONS.len() as i64
            && self.rotation_columns == 2
            && self.charge_columns == 0
    }

    fn is_current(&self) -> bool {
        self.classes == Self::expected(true)
            && self.promotion_claim_columns == 3
            && self.promotion_shape
            && self.stage_functions == STAGE_FUNCTIONS.len() as i64
            && self.rotation_columns == 2
            && self.charge_columns == CHARGE_COLUMNS.len() as i64
    }

    /// Name what separates this catalog from the nearer supported revision.
    fn describe(&self) -> String {
        let has_stage = self
            .classes
            .iter()
            .any(|name| STAGE_CLASSES.contains(&name.as_str()));
        let expected = Self::expected(has_stage);
        let missing: Vec<&String> = expected
            .iter()
            .filter(|name| !self.classes.contains(name))
            .collect();
        let unexpected: Vec<&String> = self
            .classes
            .iter()
            .filter(|name| !expected.contains(name))
            .collect();
        format!(
            "compared with revision {}: missing {missing:?}, unexpected {unexpected:?}, \
             stage functions {}/3, rotation columns {}/2, charge columns {}/2, promotion claim \
             columns {}/3, promotion shape constraint {}",
            if has_stage {
                schema::FRAGMENT_SCHEMA_VERSION
            } else {
                PRE_STAGE_SCHEMA_VERSION
            },
            self.stage_functions,
            self.rotation_columns,
            self.charge_columns,
            self.promotion_claim_columns,
            self.promotion_shape
        )
    }
}

/// Keep the SQLSTATE and the server's own message. `tokio_postgres::Error`'s
/// `Display` renders a server error as a bare `db error`.
fn pg(context: &'static str) -> impl FnOnce(tokio_postgres::Error) -> DomainError {
    move |error| match error.as_db_error() {
        Some(db) => DomainError::Internal(format!(
            "{context}: SQLSTATE {} {}{}",
            db.code().code(),
            db.message(),
            db.detail()
                .map(|detail| format!(" ({detail})"))
                .unwrap_or_default()
        )),
        None => DomainError::from_pg(context, error),
    }
}

impl PostgresFragmentCoordinator {
    /// Upgrade a clean-initialized revision-4 or revision-6 cell to the
    /// compiled revision.
    ///
    /// The caller must stop every replica first. The upgrade refuses while any
    /// backend outside this coordinator's own pool is connected to the cell
    /// database, whether idle or not, and `NOWAIT` refuses a lock holder that
    /// races that count. Rerunning after a crash or a lost commit reply is
    /// safe: an upgraded cell reports `AlreadyCurrent`.
    pub async fn upgrade_clean_schema(&self) -> Result<FragmentSchemaUpgradeOutcome, DomainError> {
        let mut client =
            self.pool.get().await.map_err(|e| {
                DomainError::Internal(format!("fragment schema upgrade checkout: {e}"))
            })?;
        let tx = client
            .transaction()
            .await
            .map_err(pg("fragment schema upgrade begin"))?;
        tx.batch_execute("SET LOCAL lock_timeout = '5s'; SET LOCAL statement_timeout = '120s'")
            .await
            .map_err(pg("fragment schema upgrade bounds"))?;
        tx.execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&crate::pool::SCHEMA_LOCK_KEY],
        )
        .await
        .map_err(pg("fragment schema upgrade schema lock"))?;
        self.refuse_other_backends(&tx).await?;

        let before = stage_catalog(&tx).await?;
        let Some(revision) = before.revision() else {
            return Err(DomainError::NotReady(format!(
                "fragment schema upgrade refuses an unknown catalog state ({}); only an exact \
                 revision-{PRE_STAGE_SCHEMA_VERSION}, revision-{PRE_CHARGE_SCHEMA_VERSION} or \
                 revision-{} clean cell is supported",
                before.describe(),
                schema::FRAGMENT_SCHEMA_VERSION
            )));
        };
        let mut locked: Vec<&str> = PRE_STAGE_RELATIONS.to_vec();
        locked.extend(["lore_fragment_state", "lore_fragment_metering"]);
        if revision != CatalogRevision::PreStage {
            locked.extend(STAGE_RELATIONS);
        }
        let lock = format!(
            "LOCK TABLE {} IN ACCESS EXCLUSIVE MODE NOWAIT",
            locked.join(", ")
        );
        // The window a session can race the backend count through.
        failpoint!("schema_upgrade.drain.before_update")?;
        if let Err(error) = tx.batch_execute(&lock).await {
            if error.code() == Some(&SqlState::LOCK_NOT_AVAILABLE) {
                return Err(DomainError::Contention(
                    "fragment schema upgrade refused: a live session holds a fragment table; \
                     stop every loreserver replica first"
                        .into(),
                ));
            }
            return Err(pg("fragment schema upgrade drain")(error));
        }

        let state_before = state_snapshot(&tx).await?;
        let version: i64 = tx
            .query_one(
                "SELECT schema_version FROM lore_fragment_schema_state WHERE id = 1",
                &[],
            )
            .await
            .map_err(pg("fragment schema upgrade version"))?
            .get(0);
        self.refuse_unclean(&tx).await?;
        if version != revision.version() {
            return Err(DomainError::NotReady(format!(
                "fragment schema upgrade refuses a revision-{} catalog recording \
                 schema_version {version}",
                revision.version()
            )));
        }
        if revision == CatalogRevision::Current {
            // Read-only. The transaction rolls back on drop.
            return Ok(FragmentSchemaUpgradeOutcome::AlreadyCurrent);
        }
        let stage_before = if revision == CatalogRevision::PreStage {
            refuse_staged_work(&tx).await?;
            None
        } else {
            Some(stage_snapshot(&tx).await?)
        };
        let triggers_before = trigger_snapshot(&tx).await?;

        tx.batch_execute(
            "ALTER TABLE lore_fragment_schema_state DISABLE TRIGGER lore_clean_state_permanent",
        )
        .await
        .map_err(pg("fragment schema upgrade fence lift"))?;
        if revision == CatalogRevision::PreStage {
            tx.batch_execute(STAGE_CUSTODY_SCHEMA)
                .await
                .map_err(pg("fragment schema upgrade stage custody DDL"))?;
            tx.batch_execute(STAGE_POLICY_ROTATION_SCHEMA)
                .await
                .map_err(pg("fragment schema upgrade stage rotation DDL"))?;
        }
        tx.batch_execute(STAGE_CHARGE_COUNTER_SCHEMA)
            .await
            .map_err(pg("fragment schema upgrade stage charge counter DDL"))?;
        tx.batch_execute(
            "ALTER TABLE lore_fragment_schema_state ENABLE ALWAYS TRIGGER lore_clean_state_permanent",
        )
        .await
        .map_err(pg("fragment schema upgrade fence restore"))?;

        verify_upgraded(
            &tx,
            &state_before,
            &triggers_before,
            stage_before.as_deref(),
        )
        .await?;
        self.refuse_unclean(&tx).await?;
        // A replica that connected during the step is blocked on our locks now
        // and would write current-revision tables with an old binary after commit.
        self.refuse_other_backends(&tx).await?;
        tx.commit().await.map_err(|e| {
            DomainError::OutcomeUnknown(format!(
                "fragment schema upgrade commit: {e}; rerun to reconcile"
            ))
        })?;
        Ok(FragmentSchemaUpgradeOutcome::Upgraded {
            from_version: revision.version(),
        })
    }

    /// Refuse while any backend outside this coordinator's pool is connected
    /// to the cell database.
    ///
    /// `numbackends` counts every backend on the database whatever its role,
    /// where `pg_stat_activity` hides other roles' sessions from an
    /// unprivileged caller (CR-038 measured this on `PostgreSQL` 16). Every
    /// connection this pool holds is this process's, so the pool's size is
    /// subtracted. A backend that is still exiting gets a short bounded wait.
    async fn refuse_other_backends(&self, tx: &Transaction<'_>) -> Result<(), DomainError> {
        let mut others = 0;
        for attempt in 0..BACKEND_SETTLE_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(BACKEND_SETTLE_INTERVAL).await;
            }
            // Statistics are snapshotted per transaction; take a fresh one.
            tx.batch_execute("SELECT pg_catalog.pg_stat_clear_snapshot()")
                .await
                .map_err(pg("fragment schema upgrade statistics snapshot"))?;
            let connected: i64 = tx
                .query_one(
                    "SELECT numbackends::bigint FROM pg_catalog.pg_stat_database \
                      WHERE datname = pg_catalog.current_database()",
                    &[],
                )
                .await
                .map_err(pg("fragment schema upgrade backend count"))?
                .get(0);
            let own = i64::try_from(self.pool.status().size).unwrap_or(i64::MAX);
            others = connected.saturating_sub(own);
            if others <= 0 {
                return Ok(());
            }
        }
        Err(DomainError::Contention(format!(
            "fragment schema upgrade refused: {others} other backend(s) are connected to the \
             cell database; stop every loreserver replica and other client, then rerun"
        )))
    }

    /// The clean record, its fences and standing readiness must hold on both
    /// sides of the step. A backfill-route or damaged cell is not on the list.
    async fn refuse_unclean(&self, tx: &Transaction<'_>) -> Result<(), DomainError> {
        let row = tx
            .query_one(
                "SELECT (to_jsonb(s)->>'clean_initialized_at') IS NOT NULL AS clean, \
                        backfill_state, lifecycle_enabled, write_capability, database_identity \
                   FROM lore_fragment_schema_state s WHERE id = 1",
                &[],
            )
            .await
            .map_err(pg("fragment schema upgrade state"))?;
        if !row.get::<_, bool>("clean")
            || row.get::<_, i16>("backfill_state") != schema::BACKFILL_NOT_STARTED
            || !row.get::<_, bool>("lifecycle_enabled")
            || row.get::<_, i16>("write_capability") != schema::WRITE_CAPABILITY_CLAIMS_REQUIRED
        {
            return Err(DomainError::NotReady(
                "fragment schema upgrade supports only a clean-initialized cell with lifecycle \
                 enabled and write claims required"
                    .into(),
            ));
        }
        if row.get::<_, String>("database_identity") != self.database_identity {
            return Err(DomainError::NotReady(
                "fragment schema upgrade refuses a database identity mismatch".into(),
            ));
        }
        initialization::attest_clean_fences(tx).await?;
        if !initialization::clean_readiness_holds(tx).await? {
            return Err(DomainError::NotReady(
                "fragment schema upgrade refuses a cell whose enforcement, fencing, sequence \
                 headroom or readable heads do not hold"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// The stored revision of a clean-initialized cell behind the compiled one.
///
/// `bootstrap` consults this before any DDL, so an old cell gets a named
/// remedy instead of the fence's raw refusal, and nothing is written.
pub(super) async fn clean_cell_needs_upgrade(
    client: &tokio_postgres::Client,
) -> Result<Option<i64>, DomainError> {
    let row = client
        .query_opt(
            "SELECT s.schema_version FROM lore_fragment_schema_state s \
              WHERE s.id = 1 \
                AND (to_jsonb(s)->>'clean_initialized_at') IS NOT NULL",
            &[],
        )
        .await;
    let row = match row {
        Ok(row) => row,
        // No schema-state relation yet: a fresh cell, nothing to upgrade.
        Err(error) if error.code() == Some(&SqlState::UNDEFINED_TABLE) => return Ok(None),
        Err(error) => return Err(pg("fragment schema upgrade probe")(error)),
    };
    Ok(row
        .map(|row| row.get::<_, i64>(0))
        .filter(|version| *version < schema::FRAGMENT_SCHEMA_VERSION))
}

async fn stage_catalog(tx: &Transaction<'_>) -> Result<StageCatalog, DomainError> {
    let row = tx
        .query_one(
            "SELECT \
               (SELECT COALESCE(array_agg(c.relname::text), '{}') FROM pg_class c \
                  JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE n.nspname = current_schema() \
                   AND starts_with(c.relname, 'lore_fragment_')) AS classes, \
               (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
                 WHERE n.nspname = current_schema() AND p.proname = ANY($1))::bigint, \
               (SELECT count(*) FROM pg_attribute WHERE attrelid = to_regclass('lore_fragment_stage_policy') \
                 AND attname IN ('previous_revision', 'previous_digest') AND attnum > 0 \
                 AND NOT attisdropped)::bigint, \
               (SELECT count(*) FROM pg_attribute WHERE attrelid = to_regclass('lore_fragment_write_claims') \
                 AND attname IN ('kind', 'source_epoch', 'source_manifest_id') AND attnum > 0 \
                 AND NOT attisdropped)::bigint, \
               EXISTS (SELECT 1 FROM pg_constraint \
                 WHERE conrelid = to_regclass('lore_fragment_write_claims') \
                   AND conname = 'lore_fragment_write_claim_promotion_shape' AND convalidated), \
               (SELECT count(*) FROM pg_attribute WHERE attrelid = to_regclass('lore_fragment_stage_usage') \
                 AND attname = ANY($2) AND attnum > 0 AND NOT attisdropped)::bigint",
            &[&STAGE_FUNCTIONS.as_slice(), &CHARGE_COLUMNS.as_slice()],
        )
        .await
        .map_err(pg("fragment schema upgrade catalog"))?;
    let mut classes: Vec<String> = row.get(0);
    classes.sort();
    Ok(StageCatalog {
        classes,
        stage_functions: row.get(1),
        rotation_columns: row.get(2),
        charge_columns: row.get(5),
        promotion_claim_columns: row.get(3),
        promotion_shape: row.get(4),
    })
}

/// A revision-6 cell's stage rows: the usage row without the columns the step
/// adds, every policy row, and a digest of every custody row. The step adds two
/// columns and must change nothing else.
async fn stage_snapshot(tx: &Transaction<'_>) -> Result<String, DomainError> {
    let charge = CHARGE_COLUMNS.as_slice();
    tx.query_one(
        "SELECT COALESCE((SELECT string_agg((to_jsonb(u) - $1::text[])::text, ',') \
                            FROM lore_fragment_stage_usage u), '') || '|' || \
                COALESCE((SELECT string_agg(to_jsonb(p)::text, ',' ORDER BY p.singleton) \
                            FROM lore_fragment_stage_policy p), '') || '|' || \
                (SELECT count(*)::text || ':' || \
                        COALESCE(md5(string_agg(to_jsonb(c)::text, ',' ORDER BY c.hash, c.epoch)), '') \
                   FROM lore_fragment_stage_custody c)",
        &[&charge],
    )
    .await
    .map(|row| row.get(0))
    .map_err(pg("fragment schema upgrade stage snapshot"))
}

/// Every column of the singleton except `schema_version`, as canonical jsonb
/// text, plus the row count. Timestamps and bytea render exactly.
async fn state_snapshot(tx: &Transaction<'_>) -> Result<String, DomainError> {
    tx.query_one(
        "SELECT count(*)::text || ':' || COALESCE(string_agg((to_jsonb(s) - 'schema_version')::text, ''), '') \
           FROM lore_fragment_schema_state s",
        &[],
    )
    .await
    .map(|row| row.get(0))
    .map_err(pg("fragment schema upgrade state snapshot"))
}

/// Every non-internal trigger on a fragment relation: its full definition
/// (`pg_get_triggerdef` carries timing, events, columns, `WHEN` qualifier and
/// arguments), its enablement, and an md5 of its function's body.
async fn trigger_snapshot(tx: &Transaction<'_>) -> Result<String, DomainError> {
    tx.query_one(
        "SELECT COALESCE(string_agg(format('%s|%s|%s|%s', pg_get_triggerdef(t.oid), t.tgenabled, \
                    t.tgfoid::regprocedure, md5(p.prosrc)), E'\\n' \
                    ORDER BY t.tgrelid::regclass::text, t.tgname), '') \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
           JOIN pg_proc p ON p.oid = t.tgfoid \
          WHERE NOT t.tgisinternal AND starts_with(c.relname, 'lore_fragment')",
        &[],
    )
    .await
    .map(|row| row.get(0))
    .map_err(pg("fragment schema upgrade trigger snapshot"))
}

/// Refuse state the stage custody accounting cannot represent after the fact.
///
/// A revision-4 cell never recorded custody or usage for a staged file. Any
/// `PreparingStage`/`Staged` head, or a live staged-reader lease, would leave
/// the new counters understating what is on disk. Reconstructing them is out
/// of scope (CR-039); the operator drains or resolves those first.
async fn refuse_staged_work(tx: &Transaction<'_>) -> Result<(), DomainError> {
    let row = tx
        .query_one(
            "SELECT (SELECT count(*) FROM lore_fragment_lifecycle WHERE state = ANY($1))::bigint, \
                    (SELECT count(*) FROM lore_fragment_staged_leases WHERE NOT terminal)::bigint",
            &[&[
                FragmentLifecycleState::PreparingStage.bits(),
                FragmentLifecycleState::Staged.bits(),
            ]
            .as_slice()],
        )
        .await
        .map_err(pg("fragment schema upgrade staged work"))?;
    let (heads, leases): (i64, i64) = (row.get(0), row.get(1));
    if heads != 0 {
        return Err(DomainError::NotReady(format!(
            "fragment schema upgrade refuses {heads} PreparingStage/Staged lifecycle head(s): \
             revision {PRE_STAGE_SCHEMA_VERSION} kept no stage custody for them"
        )));
    }
    if leases != 0 {
        return Err(DomainError::NotReady(format!(
            "fragment schema upgrade refuses {leases} non-terminal staged-reader lease(s)"
        )));
    }
    Ok(())
}

/// `stage_before` is a revision-6 cell's [`stage_snapshot`]; `None` for a
/// revision-4 cell, whose stage tables must hold a fresh cell's seed.
async fn verify_upgraded(
    tx: &Transaction<'_>,
    state_before: &str,
    triggers_before: &str,
    stage_before: Option<&str>,
) -> Result<(), DomainError> {
    let fail = |what: &str| {
        Err(DomainError::Internal(format!(
            "fragment schema upgrade verification failed: {what}; nothing was committed"
        )))
    };
    if state_snapshot(tx).await? != state_before {
        return fail("a schema-state column other than schema_version changed");
    }
    let version: i64 = tx
        .query_one(
            "SELECT schema_version FROM lore_fragment_schema_state WHERE id = 1",
            &[],
        )
        .await
        .map_err(pg("fragment schema upgrade verify version"))?
        .get(0);
    if version != schema::FRAGMENT_SCHEMA_VERSION {
        return fail("schema_version did not reach the compiled revision");
    }
    if trigger_snapshot(tx).await? != triggers_before {
        return fail("a fragment trigger's definition, enablement or function body changed");
    }
    let after = stage_catalog(tx).await?;
    if !after.is_current() {
        return fail(&format!(
            "the catalog is not an exact revision-{} catalog ({})",
            schema::FRAGMENT_SCHEMA_VERSION,
            after.describe()
        ));
    }
    let counters_zero: bool = tx
        .query_one(
            "SELECT count(*) = 1 AND COALESCE(bool_and(charged_bytes = 0 AND charged_files = 0), false) \
               FROM lore_fragment_stage_usage",
            &[],
        )
        .await
        .map_err(pg("fragment schema upgrade verify counters"))?
        .get(0);
    if !counters_zero {
        return fail("the stage charge counters do not start at zero");
    }
    if let Some(stage_before) = stage_before {
        if stage_snapshot(tx).await? != stage_before {
            return fail("a stage usage, policy or custody row changed");
        }
        return Ok(());
    }
    let seeded: bool = tx
        .query_one(
            "SELECT (SELECT count(*) = 1 AND COALESCE(bool_and(singleton AND live_bytes = 0 \
                       AND live_files = 0 AND metadata_bytes = 0 AND metadata_rows = 0), false) \
                       FROM lore_fragment_stage_usage) \
                AND NOT EXISTS (SELECT 1 FROM lore_fragment_stage_policy) \
                AND NOT EXISTS (SELECT 1 FROM lore_fragment_stage_custody) \
                AND (SELECT count(*) = cardinality($1::text[]) \
                            AND bool_and(i.indisvalid AND i.indisready) \
                       FROM pg_index i WHERE i.indexrelid = ANY(ARRAY( \
                         SELECT to_regclass(name)::oid FROM unnest($1::text[]) AS name)))",
            &[&STAGE_INDEXES.as_slice()],
        )
        .await
        .map_err(pg("fragment schema upgrade verify seed"))?
        .get(0);
    if !seeded {
        return fail("the stage tables do not hold a fresh cell's seed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_lists_partition_the_probe() {
        let mut composed: Vec<&str> = PRE_STAGE_RELATIONS.to_vec();
        composed.extend(STAGE_RELATIONS);
        assert_eq!(composed, schema::FRAGMENT_SCHEMA_RELATIONS.to_vec());
    }

    #[test]
    fn class_sets_cover_the_relations_and_do_not_overlap() {
        for relation in PRE_STAGE_RELATIONS {
            assert!(PRE_STAGE_CLASSES.contains(&relation), "{relation}");
        }
        for relation in STAGE_RELATIONS.iter().chain(&STAGE_INDEXES) {
            assert!(STAGE_CLASSES.contains(relation), "{relation}");
        }
        for name in STAGE_CLASSES {
            assert!(!PRE_STAGE_CLASSES.contains(&name), "{name}");
        }
        let mut sorted = PRE_STAGE_CLASSES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), PRE_STAGE_CLASSES.len());
    }

    #[test]
    fn stage_ddl_names_every_object_the_classifier_checks() {
        let ddl = format!("{STAGE_CUSTODY_SCHEMA}{STAGE_POLICY_ROTATION_SCHEMA}");
        for name in STAGE_RELATIONS
            .iter()
            .chain(&STAGE_FUNCTIONS)
            .chain(&STAGE_INDEXES)
        {
            assert!(ddl.contains(name), "{name} is not created by the stage DDL");
        }
        for column in CHARGE_COLUMNS {
            assert!(
                STAGE_CHARGE_COUNTER_SCHEMA.contains(&format!("ADD COLUMN IF NOT EXISTS {column}")),
                "{column} is not added by the charge counter DDL"
            );
        }
        assert_eq!(schema::FRAGMENT_SCHEMA_VERSION, 7);
        assert_eq!(
            UPGRADABLE_SCHEMA_VERSIONS,
            [PRE_STAGE_SCHEMA_VERSION, PRE_CHARGE_SCHEMA_VERSION]
        );
    }

    fn catalog(revision: CatalogRevision) -> StageCatalog {
        let staged = revision != CatalogRevision::PreStage;
        StageCatalog {
            classes: StageCatalog::expected(staged),
            stage_functions: if staged { 3 } else { 0 },
            rotation_columns: if staged { 2 } else { 0 },
            charge_columns: if revision == CatalogRevision::Current {
                2
            } else {
                0
            },
            promotion_claim_columns: 3,
            promotion_shape: true,
        }
    }

    #[test]
    fn the_classifier_names_each_supported_revision_and_nothing_between() {
        for revision in [
            CatalogRevision::PreStage,
            CatalogRevision::PreCharge,
            CatalogRevision::Current,
        ] {
            assert_eq!(catalog(revision).revision(), Some(revision));
        }
        // One counter column without the other is no supported revision.
        let mut half = catalog(CatalogRevision::Current);
        half.charge_columns = 1;
        assert_eq!(half.revision(), None);
        // Counters on a cell without the stage tables are no supported revision.
        let mut early = catalog(CatalogRevision::PreStage);
        early.charge_columns = 2;
        assert_eq!(early.revision(), None);
        assert_eq!(CatalogRevision::PreCharge.version(), 6);
        assert_eq!(CatalogRevision::Current.version(), 7);
    }
}
