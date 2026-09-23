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
//! 1. take the schema advisory lock and `ACCESS EXCLUSIVE NOWAIT` on every
//!    fragment table, so a live replica makes it refuse instead of queueing;
//! 2. snapshot the schema-state row and every fragment trigger's enablement;
//! 3. disable only `lore_clean_state_permanent`, apply the same stage DDL a
//!    fresh cell runs, and re-enable the trigger `ALWAYS`;
//! 4. prove that only `schema_version` moved (4 -> 6), that every trigger is
//!    exactly as before, that the stage objects exist with a fresh cell's
//!    seed, and that clean readiness still holds; then commit.
//!
//! The trigger disable is transactional and never visible to another session.
//! It needs table ownership, which can already drop the trigger, so the fence
//! is not weakened. The fence's purpose, that no writer changes the clean
//! record, is what step 4 re-proves before the commit.

use tokio_postgres::Transaction;
use tokio_postgres::error::SqlState;

use super::coordinator::PostgresFragmentCoordinator;
use super::initialization;
use super::schema;
use super::stage_rotation_schema::STAGE_POLICY_ROTATION_SCHEMA;
use super::stage_schema::STAGE_CUSTODY_SCHEMA;
use super::states::FragmentLifecycleState;
use crate::domain::errors::DomainError;

/// The revision a clean cell initialized before WP-122's stage custody holds.
pub const PRE_STAGE_SCHEMA_VERSION: i64 = 4;

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

const STAGE_FUNCTIONS: [&str; 3] = [
    "stage_policy_publish_v1",
    "stage_policy_verify_v1",
    "stage_policy_rotate_v1",
];

const STAGE_INDEXES: [&str; 2] = [
    "lore_fragment_stage_custody_cleanup",
    "lore_fragment_stage_drain_recovery",
];

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
    pre_stage_relations: i64,
    stage_relations: i64,
    stage_functions: i64,
    stage_indexes: i64,
    rotation_columns: i64,
    promotion_claim_columns: i64,
}

impl StageCatalog {
    fn is_pre_stage(&self) -> bool {
        self.pre_stage_relations == PRE_STAGE_RELATIONS.len() as i64
            && self.promotion_claim_columns == 3
            && self.stage_relations == 0
            && self.stage_functions == 0
            && self.stage_indexes == 0
            && self.rotation_columns == 0
    }

    fn is_current(&self) -> bool {
        self.pre_stage_relations == PRE_STAGE_RELATIONS.len() as i64
            && self.promotion_claim_columns == 3
            && self.stage_relations == STAGE_RELATIONS.len() as i64
            && self.stage_functions == STAGE_FUNCTIONS.len() as i64
            && self.stage_indexes == STAGE_INDEXES.len() as i64
            && self.rotation_columns == 2
    }
}

impl PostgresFragmentCoordinator {
    /// Upgrade a clean-initialized revision-4 cell to the compiled revision.
    ///
    /// The caller must stop every replica first; `NOWAIT` turns a missed one
    /// into a prompt refusal, not proof of absence. Rerunning after a crash or
    /// a lost commit reply is safe: an upgraded cell reports `AlreadyCurrent`.
    pub async fn upgrade_clean_schema(&self) -> Result<FragmentSchemaUpgradeOutcome, DomainError> {
        let mut client =
            self.pool.get().await.map_err(|e| {
                DomainError::Internal(format!("fragment schema upgrade checkout: {e}"))
            })?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("fragment schema upgrade begin", e))?;
        tx.batch_execute("SET LOCAL lock_timeout = '5s'; SET LOCAL statement_timeout = '120s'")
            .await
            .map_err(|e| DomainError::from_pg("fragment schema upgrade bounds", e))?;
        tx.execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&crate::pool::SCHEMA_LOCK_KEY],
        )
        .await
        .map_err(|e| DomainError::from_pg("fragment schema upgrade schema lock", e))?;

        let before = stage_catalog(&tx).await?;
        let current = before.is_current();
        if !current && !before.is_pre_stage() {
            return Err(DomainError::NotReady(format!(
                "fragment schema upgrade refuses an unknown catalog state {before:?}; \
                 only an exact revision-{PRE_STAGE_SCHEMA_VERSION} or revision-{} cell is supported",
                schema::FRAGMENT_SCHEMA_VERSION
            )));
        }
        let mut locked: Vec<&str> = PRE_STAGE_RELATIONS.to_vec();
        locked.extend(["lore_fragment_state", "lore_fragment_metering"]);
        if current {
            locked.extend(STAGE_RELATIONS);
        }
        let lock = format!(
            "LOCK TABLE {} IN ACCESS EXCLUSIVE MODE NOWAIT",
            locked.join(", ")
        );
        if let Err(error) = tx.batch_execute(&lock).await {
            if error.code() == Some(&SqlState::LOCK_NOT_AVAILABLE) {
                return Err(DomainError::Contention(
                    "fragment schema upgrade refused: a live session holds a fragment table; \
                     stop every loreserver replica first"
                        .into(),
                ));
            }
            return Err(DomainError::from_pg("fragment schema upgrade drain", error));
        }

        let state_before = state_snapshot(&tx).await?;
        let version: i64 = tx
            .query_one(
                "SELECT schema_version FROM lore_fragment_schema_state WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DomainError::from_pg("fragment schema upgrade version", e))?
            .get(0);
        self.refuse_unclean(&tx).await?;
        if current {
            if version != schema::FRAGMENT_SCHEMA_VERSION {
                return Err(DomainError::NotReady(format!(
                    "fragment schema upgrade refuses a revision-{} catalog recording \
                     schema_version {version}",
                    schema::FRAGMENT_SCHEMA_VERSION
                )));
            }
            // Read-only. The transaction rolls back on drop.
            return Ok(FragmentSchemaUpgradeOutcome::AlreadyCurrent);
        }
        if version != PRE_STAGE_SCHEMA_VERSION {
            return Err(DomainError::NotReady(format!(
                "fragment schema upgrade refuses a revision-{PRE_STAGE_SCHEMA_VERSION} catalog \
                 recording schema_version {version}"
            )));
        }
        refuse_staged_work(&tx).await?;
        let triggers_before = trigger_snapshot(&tx).await?;

        tx.batch_execute(
            "ALTER TABLE lore_fragment_schema_state DISABLE TRIGGER lore_clean_state_permanent",
        )
        .await
        .map_err(|e| DomainError::from_pg("fragment schema upgrade fence lift", e))?;
        tx.batch_execute(STAGE_CUSTODY_SCHEMA)
            .await
            .map_err(|e| DomainError::from_pg("fragment schema upgrade stage custody DDL", e))?;
        tx.batch_execute(STAGE_POLICY_ROTATION_SCHEMA)
            .await
            .map_err(|e| DomainError::from_pg("fragment schema upgrade stage rotation DDL", e))?;
        tx.batch_execute(
            "ALTER TABLE lore_fragment_schema_state ENABLE ALWAYS TRIGGER lore_clean_state_permanent",
        )
        .await
        .map_err(|e| DomainError::from_pg("fragment schema upgrade fence restore", e))?;

        verify_upgraded(&tx, &state_before, &triggers_before).await?;
        self.refuse_unclean(&tx).await?;
        tx.commit().await.map_err(|e| {
            DomainError::OutcomeUnknown(format!(
                "fragment schema upgrade commit: {e}; rerun to reconcile"
            ))
        })?;
        Ok(FragmentSchemaUpgradeOutcome::Upgraded {
            from_version: PRE_STAGE_SCHEMA_VERSION,
        })
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
            .map_err(|e| DomainError::from_pg("fragment schema upgrade state", e))?;
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

/// Whether a clean-initialized cell is behind the compiled revision.
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
        Err(error) => return Err(DomainError::from_pg("fragment schema upgrade probe", error)),
    };
    Ok(row
        .map(|row| row.get::<_, i64>(0))
        .filter(|version| *version < schema::FRAGMENT_SCHEMA_VERSION))
}

async fn stage_catalog(tx: &Transaction<'_>) -> Result<StageCatalog, DomainError> {
    let row = tx
        .query_one(
            "SELECT \
               (SELECT count(*) FROM unnest($1::text[]) r WHERE to_regclass(r) IS NOT NULL)::bigint, \
               (SELECT count(*) FROM unnest($2::text[]) r WHERE to_regclass(r) IS NOT NULL)::bigint, \
               (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
                 WHERE n.nspname = current_schema() AND p.proname = ANY($3))::bigint, \
               (SELECT count(*) FROM unnest($4::text[]) r WHERE to_regclass(r) IS NOT NULL)::bigint, \
               (SELECT count(*) FROM pg_attribute WHERE attrelid = to_regclass('lore_fragment_stage_policy') \
                 AND attname IN ('previous_revision', 'previous_digest') AND attnum > 0 \
                 AND NOT attisdropped)::bigint, \
               (SELECT count(*) FROM pg_attribute WHERE attrelid = to_regclass('lore_fragment_write_claims') \
                 AND attname IN ('kind', 'source_epoch', 'source_manifest_id') AND attnum > 0 \
                 AND NOT attisdropped)::bigint",
            &[
                &PRE_STAGE_RELATIONS.as_slice(),
                &STAGE_RELATIONS.as_slice(),
                &STAGE_FUNCTIONS.as_slice(),
                &STAGE_INDEXES.as_slice(),
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("fragment schema upgrade catalog", e))?;
    Ok(StageCatalog {
        pre_stage_relations: row.get(0),
        stage_relations: row.get(1),
        stage_functions: row.get(2),
        stage_indexes: row.get(3),
        rotation_columns: row.get(4),
        promotion_claim_columns: row.get(5),
    })
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
    .map_err(|e| DomainError::from_pg("fragment schema upgrade state snapshot", e))
}

/// Every non-internal trigger on a fragment relation, with its enablement.
async fn trigger_snapshot(tx: &Transaction<'_>) -> Result<String, DomainError> {
    tx.query_one(
        "SELECT COALESCE(string_agg(format('%s/%s/%s/%s/%s', t.tgrelid::regclass, t.tgname, \
                    t.tgenabled, t.tgtype, t.tgfoid::regprocedure), ',' \
                    ORDER BY t.tgrelid::regclass::text, t.tgname), '') \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND starts_with(c.relname, 'lore_fragment')",
        &[],
    )
    .await
    .map(|row| row.get(0))
    .map_err(|e| DomainError::from_pg("fragment schema upgrade trigger snapshot", e))
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
        .map_err(|e| DomainError::from_pg("fragment schema upgrade staged work", e))?;
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

async fn verify_upgraded(
    tx: &Transaction<'_>,
    state_before: &str,
    triggers_before: &str,
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
        .map_err(|e| DomainError::from_pg("fragment schema upgrade verify version", e))?
        .get(0);
    if version != schema::FRAGMENT_SCHEMA_VERSION {
        return fail("schema_version did not reach the compiled revision");
    }
    if trigger_snapshot(tx).await? != triggers_before {
        return fail("a fragment trigger's definition or enablement changed");
    }
    if !stage_catalog(tx).await?.is_current() {
        return fail("the stage catalog is incomplete");
    }
    let seeded: bool = tx
        .query_one(
            "SELECT (SELECT count(*) = 1 AND COALESCE(bool_and(singleton AND live_bytes = 0 \
                       AND live_files = 0 AND metadata_bytes = 0 AND metadata_rows = 0), false) \
                       FROM lore_fragment_stage_usage) \
                AND NOT EXISTS (SELECT 1 FROM lore_fragment_stage_policy) \
                AND NOT EXISTS (SELECT 1 FROM lore_fragment_stage_custody) \
                AND (SELECT count(*) = 2 AND bool_and(i.indisvalid AND i.indisready) \
                       FROM pg_index i WHERE i.indexrelid = ANY(ARRAY[ \
                         to_regclass('lore_fragment_stage_custody_cleanup'), \
                         to_regclass('lore_fragment_stage_drain_recovery')]::oid[]))",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("fragment schema upgrade verify seed", e))?
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
    fn stage_ddl_names_every_object_the_classifier_checks() {
        let ddl = format!("{STAGE_CUSTODY_SCHEMA}{STAGE_POLICY_ROTATION_SCHEMA}");
        for name in STAGE_RELATIONS
            .iter()
            .chain(&STAGE_FUNCTIONS)
            .chain(&STAGE_INDEXES)
        {
            assert!(ddl.contains(name), "{name} is not created by the stage DDL");
        }
        assert_eq!(schema::FRAGMENT_SCHEMA_VERSION, 6);
    }
}
