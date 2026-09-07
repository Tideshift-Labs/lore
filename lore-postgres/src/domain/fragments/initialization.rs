// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Explicit clean-cell initialization. Provider inspection and credential
//! exclusion are caller prerequisites; this module performs database I/O only.

use tokio_postgres::Transaction;

use super::coordinator::FragmentWriteCapabilityCutover;
use super::coordinator::PostgresFragmentCoordinator;
use super::membership;
use super::schema;
use crate::domain::errors::DomainError;

/// Non-secret binding to the inspected namespace and excluded old writers.
#[derive(Debug, Clone)]
pub struct CleanCellInitialization {
    namespace_identity: String,
    provider_write_authority_revision: String,
}

impl CleanCellInitialization {
    pub fn new(
        namespace_identity: String,
        provider_write_authority_revision: String,
    ) -> Result<Self, DomainError> {
        if namespace_identity.is_empty()
            || namespace_identity.len() > 512
            || namespace_identity.chars().any(char::is_control)
        {
            return Err(DomainError::InvalidInput(
                "clean namespace identity must contain 1..=512 bytes without control characters"
                    .into(),
            ));
        }
        FragmentWriteCapabilityCutover::new(&provider_write_authority_revision)?;
        Ok(Self {
            namespace_identity,
            provider_write_authority_revision,
        })
    }

    pub fn namespace_identity(&self) -> &str {
        &self.namespace_identity
    }
    pub fn provider_write_authority_revision(&self) -> &str {
        &self.provider_write_authority_revision
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanCellInitializationOutcome {
    Initialized,
    AlreadyInitialized,
}

impl PostgresFragmentCoordinator {
    /// Exact retries can recognize initialization after real uploads begin.
    /// This is not permission to skip provider configuration/credential checks.
    pub async fn initialization_status(
        &self,
        input: &CleanCellInitialization,
    ) -> Result<bool, DomainError> {
        let readiness = self.readiness().await?;
        if !readiness.provisioned {
            return Ok(false);
        }
        if readiness.clean_initialized && !readiness.ready_for_lifecycle() {
            return Err(DomainError::NotReady(
                "clean initialization lifecycle readiness lost".into(),
            ));
        }
        let mut client =
            self.pool.get().await.map_err(|e| {
                DomainError::Internal(format!("clean initialization checkout: {e}"))
            })?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("clean initialization status begin", e))?;
        completed(&tx, input, &self.database_identity).await
    }

    /// Initialize only an empty cell after the supported domain/lock cutover.
    ///
    /// The operator must first prove the whole configured object namespace empty
    /// (including multipart uploads), attest never-enabled versioning, and exclude
    /// all legacy provider credentials/in-flight writers. This API cannot prove
    /// external credential revocation, just as `require_write_claims` cannot.
    /// There is no object I/O, deletion, data backfill, or readiness hand-patch here.
    /// Empty checks, schema readiness, claims, and permanent writer fences commit
    /// together. An interrupted/unacknowledged commit is reconciled by an exact retry.
    pub async fn initialize_empty(
        &self,
        input: &CleanCellInitialization,
    ) -> Result<CleanCellInitializationOutcome, DomainError> {
        let mut client =
            self.pool.get().await.map_err(|e| {
                DomainError::Internal(format!("clean initialization checkout: {e}"))
            })?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("clean initialization begin", e))?;
        tx.batch_execute("SET LOCAL lock_timeout = '5s'; SET LOCAL statement_timeout = '10s'")
            .await
            .map_err(|e| DomainError::from_pg("clean initialization bounds", e))?;
        // Serialize with supported bootstrap so its table inventory cannot grow
        // between our catalog read and the emptiness/fence transaction.
        tx.execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&crate::pool::SCHEMA_LOCK_KEY],
        )
        .await
        .map_err(|e| DomainError::from_pg("clean initialization schema lock", e))?;

        // This is an offline maintenance transaction, not a domain mutation's
        // row-lock order. Drain table writers before taking singleton row locks.
        // Catalog-generated identifiers are quoted by PostgreSQL, never interpolated
        // from caller input. New data tables are included rather than silently missed.
        let tables = tx
            .query(
                "SELECT c.relname, format('%I.%I', n.nspname, c.relname) AS qualified \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') \
               AND starts_with(c.relname, 'lore_') ORDER BY c.relname LIMIT 129",
                &[],
            )
            .await
            .map_err(|e| DomainError::from_pg("clean initialization inventory", e))?;
        if tables.is_empty() || tables.len() > 128 {
            return Err(DomainError::NotReady(
                "clean initialization schema inventory outside bounds".into(),
            ));
        }
        let qualified = tables
            .iter()
            .map(|r| r.get::<_, String>("qualified"))
            .collect::<Vec<_>>();
        tx.batch_execute(&format!(
            "LOCK TABLE {} IN ACCESS EXCLUSIVE MODE",
            qualified.join(", ")
        ))
        .await
        .map_err(|e| DomainError::from_pg("clean initialization drain", e))?;
        if completed(&tx, input, &self.database_identity).await? {
            return Ok(CleanCellInitializationOutcome::AlreadyInitialized);
        }

        let armed: bool = tx
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM lore_domain_schema_state WHERE enforcement_enabled) \
             AND EXISTS (SELECT 1 FROM lore_domain_lock_schema_state WHERE fencing_enabled)",
                &[],
            )
            .await
            .map_err(|e| DomainError::from_pg("clean initialization enforcement", e))?
            .get(0);
        if !armed {
            return Err(DomainError::NotReady(
                "clean initialization requires supported domain and lock cutover first".into(),
            ));
        }
        for table in &tables {
            let name: String = table.get("relname");
            if name == "lore_domain_proof_global_counters" {
                let unused_seed: bool = tx
                    .query_one(
                        "SELECT count(*) = 1 AND COALESCE(bool_and(id = 1 AND counter_revision = 0 \
                     AND quota_revision = 1 AND represented_namespace_rows = 0 \
                     AND retained_marker_count = 0 AND outstanding_proof_claims = 0 \
                     AND fragment_count = 0 AND fragment_bytes = 0 AND marker_bytes = 0 \
                     AND reconciled_at IS NULL), false) FROM lore_domain_proof_global_counters",
                        &[],
                    )
                    .await
                    .map_err(|e| {
                        DomainError::from_pg("clean initialization proof counter seed", e)
                    })?
                    .get(0);
                if !unused_seed {
                    return Err(DomainError::NotReady(format!(
                        "clean initialization refuses used counter seed {name}"
                    )));
                }
                continue;
            }
            // These four rows are schema/control seeds, not retained repository
            // content. All other Lore tables must be empty, including receipts,
            // tombstones, legacy rows, claims, membership, and outbox records.
            if matches!(
                name.as_str(),
                "lore_domain_schema_state"
                    | "lore_domain_lock_schema_state"
                    | "lore_fragment_schema_state"
                    | "lore_outbox_schema_state"
            ) {
                continue;
            }
            let q: String = table.get("qualified");
            let populated: bool = tx
                .query_one(&format!("SELECT EXISTS (SELECT 1 FROM {q} LIMIT 1)"), &[])
                .await
                .map_err(|e| DomainError::from_pg("clean initialization empty check", e))?
                .get(0);
            if populated {
                return Err(DomainError::NotReady(format!(
                    "clean initialization refuses populated table {name}"
                )));
            }
        }
        let row = tx
            .query_one(
                "SELECT schema_version, backfill_state, backfill_version, backfill_cursor, \
             verified_fragments, lifecycle_enabled, write_capability, database_identity \
             FROM lore_fragment_schema_state WHERE id = 1 FOR UPDATE",
                &[],
            )
            .await
            .map_err(|e| DomainError::from_pg("clean initialization state", e))?;
        let version: i64 = row.get("schema_version");
        if !(1..=schema::FRAGMENT_SCHEMA_VERSION).contains(&version)
            || row.get::<_, i16>("backfill_state") != schema::BACKFILL_NOT_STARTED
            || row.get::<_, i64>("backfill_version") != 0
            || row.get::<_, Option<Vec<u8>>>("backfill_cursor").is_some()
            || row.get::<_, i64>("verified_fragments") != 0
            || row.get::<_, bool>("lifecycle_enabled")
            || row.get::<_, i16>("write_capability") != schema::WRITE_CAPABILITY_OPTIONAL
            || row.get::<_, String>("database_identity") != self.database_identity
        {
            return Err(DomainError::NotReady(
                "clean initialization refuses existing lifecycle or migration state".into(),
            ));
        }
        let seq = tx
            .query_one(
                "SELECT last_value, is_called FROM lore_fragment_fence_seq",
                &[],
            )
            .await
            .map_err(|e| DomainError::from_pg("clean initialization sequence", e))?;
        let value: i64 = seq.get("last_value");
        if value < 1 || (seq.get::<_, bool>("is_called") && value.checked_add(1).is_none()) {
            return Err(DomainError::NotReady(
                "clean initialization needs fence sequence headroom".into(),
            ));
        }
        tx.execute(
            "UPDATE lore_fragment_schema_state SET schema_version = $1, \
             clean_initialized_at = clock_timestamp(), clean_namespace_identity = $2, \
             residue_classified = true, sequence_headroom_fence = $3, lifecycle_enabled = true, \
             write_capability = 1, provider_write_authority_revision = $4, \
             write_claims_required_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = 1",
            &[&schema::FRAGMENT_SCHEMA_VERSION, &input.namespace_identity, &value, &input.provider_write_authority_revision],
        ).await.map_err(|e| DomainError::from_pg("clean initialization publish", e))?;
        membership::activate(&tx).await?;
        tx.batch_execute(CLEAN_FENCES)
            .await
            .map_err(|e| DomainError::from_pg("clean initialization permanent fences", e))?;
        if !completed(&tx, input, &self.database_identity).await? {
            return Err(DomainError::Internal(
                "clean initialization did not establish readiness".into(),
            ));
        }
        // Commit transport failure is ambiguous. Never report it as a decisive
        // refusal; the operator reconciles the persisted exact record on rerun.
        tx.commit().await.map_err(|e| {
            DomainError::OutcomeUnknown(format!("clean initialization commit: {e}"))
        })?;
        Ok(CleanCellInitializationOutcome::Initialized)
    }
}

async fn completed(
    tx: &Transaction<'_>,
    input: &CleanCellInitialization,
    identity: &str,
) -> Result<bool, DomainError> {
    let row = tx
        .query_one(
            "SELECT s.*, (to_jsonb(s)->>'clean_initialized_at') IS NOT NULL AS initialized, \
         to_jsonb(s)->>'clean_namespace_identity' AS namespace \
         FROM lore_fragment_schema_state s WHERE id = 1",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("clean initialization record", e))?;
    if !row.get::<_, bool>("initialized") {
        return Ok(false);
    }
    if row.get::<_, Option<String>>("namespace").as_deref()
        != Some(input.namespace_identity.as_str())
        || row
            .get::<_, Option<String>>("provider_write_authority_revision")
            .as_deref()
            != Some(input.provider_write_authority_revision.as_str())
        || row.get::<_, String>("database_identity") != identity
        || row.get::<_, i64>("schema_version") != schema::FRAGMENT_SCHEMA_VERSION
        || !row.get::<_, bool>("lifecycle_enabled")
        || row.get::<_, i16>("write_capability") != schema::WRITE_CAPABILITY_CLAIMS_REQUIRED
        || row.get::<_, i16>("backfill_state") != schema::BACKFILL_NOT_STARTED
    {
        return Err(DomainError::NotReady(
            "clean initialization identity or readiness mismatch".into(),
        ));
    }
    attest_clean_fences(tx).await?;
    let ready: bool = tx
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM lore_domain_schema_state WHERE enforcement_enabled) \
         AND EXISTS (SELECT 1 FROM lore_domain_lock_schema_state WHERE fencing_enabled) \
         AND EXISTS (SELECT 1 FROM lore_fragment_fence_seq WHERE last_value >= 1 \
           AND last_value < 9223372036854775807 \
           AND last_value + CASE WHEN is_called THEN 1 ELSE 0 END > GREATEST( \
             COALESCE((SELECT max(last_fence) FROM lore_fragment_lifecycle), 0), \
             COALESCE((SELECT max(fence) FROM lore_fragment_epochs), 0), \
             COALESCE((SELECT max(reader_fence) FROM lore_fragment_staged_leases), 0))) \
         AND NOT EXISTS (SELECT 1 FROM lore_fragment_lifecycle l WHERE l.state = ANY($1) \
           AND NOT EXISTS (SELECT 1 FROM lore_fragment_epochs e \
             WHERE e.hash = l.hash AND e.epoch = l.current_epoch AND e.manifest_id = l.manifest_id))",
            &[&super::states::FragmentLifecycleState::readable_bits().as_slice()],
        )
        .await
        .map_err(|e| DomainError::from_pg("clean initialization current readiness", e))?
        .get(0);
    if !ready {
        return Err(DomainError::NotReady(
            "clean initialization enforcement or sequence headroom lost".into(),
        ));
    }
    Ok(true)
}

pub(super) async fn attest_clean_fences(tx: &Transaction<'_>) -> Result<(), DomainError> {
    if !membership::enabled(tx).await? {
        return Err(DomainError::NotReady(
            "clean initialization membership fence missing".into(),
        ));
    }
    let guards: i64 = tx.query_one(
        "SELECT count(*)::bigint FROM pg_trigger WHERE tgenabled = 'A' AND tgqual IS NULL \
         AND tgnargs = 0 AND tgattr = ''::int2vector \
         AND tgfoid = 'lore_clean_initialization_guard()'::regprocedure \
         AND ((tgrelid = 'lore_fragment_schema_state'::regclass \
               AND tgname = 'lore_clean_state_permanent' AND tgtype = 27) \
           OR (tgrelid = ANY(ARRAY['lore_fragment_schema_state'::regclass, \
                 'lore_fragment_state'::regclass, 'lore_fragment_metering'::regclass]) \
               AND tgname = 'lore_clean_no_truncate' AND tgtype = 34) \
           OR (tgrelid = ANY(ARRAY['lore_fragment_state'::regclass, 'lore_fragment_metering'::regclass]) \
               AND tgname = 'lore_clean_legacy_fence' AND tgtype = 31))", &[],
    ).await.map_err(|e| DomainError::from_pg("clean initialization fence attestation", e))?.get(0);
    if guards != 6 {
        return Err(DomainError::NotReady(
            "clean initialization permanent fence missing or disabled".into(),
        ));
    }
    Ok(())
}

const CLEAN_FENCES: &str = r#"
CREATE OR REPLACE FUNCTION lore_clean_initialization_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'lore_fragment_schema_state' AND TG_OP = 'UPDATE' THEN
        IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
    END IF;
    RAISE EXCEPTION 'clean_initialization_permanent_fence' USING ERRCODE = '55000';
END $$;
CREATE OR REPLACE TRIGGER lore_clean_state_permanent
BEFORE UPDATE OR DELETE ON lore_fragment_schema_state
FOR EACH ROW EXECUTE FUNCTION lore_clean_initialization_guard();
ALTER TABLE lore_fragment_schema_state ENABLE ALWAYS TRIGGER lore_clean_state_permanent;
DO $$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['lore_fragment_schema_state', 'lore_fragment_state', 'lore_fragment_metering'] LOOP
        EXECUTE format('CREATE OR REPLACE TRIGGER lore_clean_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION lore_clean_initialization_guard()', relation_name);
        EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER lore_clean_no_truncate', relation_name);
    END LOOP;
    FOREACH relation_name IN ARRAY ARRAY['lore_fragment_state', 'lore_fragment_metering'] LOOP
        EXECUTE format('CREATE OR REPLACE TRIGGER lore_clean_legacy_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION lore_clean_initialization_guard()', relation_name);
        EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER lore_clean_legacy_fence', relation_name);
    END LOOP;
END $$;
"#;
