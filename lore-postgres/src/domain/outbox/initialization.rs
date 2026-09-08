// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Offline fresh event initialization, distinct from a retained-data cutover.
//! Broker observations and writer exclusion are operator attestations. No receiver is made ready.
use super::membership::MembershipCas;
use super::membership::ensure_membership_state;
use super::membership::set_current_placement;
use super::membership::validate_cell_id;
use super::membership::validate_stream;
use super::schema::OUTBOX_BASE_API_VERSION;
use super::schema::OUTBOX_RELAY_SCHEMA_VERSION;
use super::schema::RETENTION_POLICY_VERSION;
use crate::domain::errors::DomainError;
use crate::pool::Pool;

#[derive(Debug, Clone)]
pub struct FreshEventInitialization {
    cell_id: String,
    stream_identity: String,
    stream_epoch: i64,
    broker_last_sequence: i64,
}
impl FreshEventInitialization {
    pub fn new(
        cell_id: String,
        stream_identity: String,
        stream_epoch: i64,
        broker_last_sequence: i64,
    ) -> Result<Self, DomainError> {
        validate_cell_id(&cell_id)?;
        validate_stream(&stream_identity, stream_epoch)?;
        if broker_last_sequence < 0 || stream_identity.chars().any(char::is_control) {
            return Err(DomainError::InvalidInput(
                "invalid broker observation".into(),
            ));
        }
        Ok(Self {
            cell_id,
            stream_identity,
            stream_epoch,
            broker_last_sequence,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshEventInitializationOutcome {
    Initialized,
    AlreadyInitialized,
}

/// Takes schema and bounded table locks before inspecting emptiness. Exact retries
/// after committed activity verify provenance and placement without changing either.
pub async fn initialize_empty(
    pool: &Pool,
    input: &FreshEventInitialization,
) -> Result<FreshEventInitializationOutcome, DomainError> {
    let mut client = pool
        .get()
        .await
        .map_err(|e| DomainError::Internal(format!("event initialization checkout: {e}")))?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("event initialization begin", e))?;
    tx.batch_execute("SET LOCAL lock_timeout = '5s'; SET LOCAL statement_timeout = '10s'")
        .await
        .map_err(|e| DomainError::from_pg("event initialization bounds", e))?;
    tx.execute(
        "SELECT pg_advisory_xact_lock($1)",
        &[&crate::pool::SCHEMA_LOCK_KEY],
    )
    .await
    .map_err(|e| DomainError::from_pg("event initialization schema lock", e))?;
    let tables = tx.query("SELECT c.relname, format('%I.%I', n.nspname, c.relname) AS qualified FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND starts_with(c.relname, 'lore_') ORDER BY c.relname LIMIT 129", &[])
        .await.map_err(|e| DomainError::from_pg("event initialization inventory", e))?;
    if tables.is_empty() || tables.len() > 128 {
        return Err(DomainError::NotReady(
            "event initialization schema inventory outside bounds".into(),
        ));
    }
    let qualified = tables
        .iter()
        .map(|row| row.get::<_, String>("qualified"))
        .collect::<Vec<_>>();
    tx.batch_execute(&format!(
        "LOCK TABLE {} IN ACCESS EXCLUSIVE MODE",
        qualified.join(", ")
    ))
    .await
    .map_err(|e| DomainError::from_pg("event initialization writer drain", e))?;
    let database_identity: String = tx.query_one("SELECT c.system_identifier::text || ':' || d.oid::text || ':' || current_database() FROM pg_control_system() c JOIN pg_database d ON d.datname = current_database()", &[])
        .await.map_err(|e| DomainError::from_pg("event initialization identity", e))?.get(0);
    let armed: bool = tx.query_one("SELECT EXISTS (SELECT 1 FROM lore_domain_schema_state WHERE enforcement_enabled) AND EXISTS (SELECT 1 FROM lore_domain_lock_schema_state WHERE fencing_enabled) AND EXISTS (SELECT 1 FROM lore_fragment_schema_state WHERE id = 1 AND lifecycle_enabled AND clean_initialized_at IS NOT NULL AND write_capability = 1 AND database_identity = $1)", &[&database_identity])
        .await.map_err(|e| DomainError::from_pg("event initialization guards", e))?.get(0);
    if !armed {
        return Err(DomainError::NotReady("fresh event initialization requires clean fragment initialization and domain/lock fences".into()));
    }
    let pristine_protocol: bool = tx.query_one(
        "SELECT count(*) = 1 AND COALESCE(bool_and(id = 1 AND revision = 1), false) FROM lore_fragment_membership_protocol", &[],
    ).await.map_err(|e| DomainError::from_pg("event initialization membership seed", e))?.get(0);
    if !pristine_protocol || !crate::domain::fragments::membership::enabled(&tx).await? {
        return Err(DomainError::NotReady(
            "event initialization requires the exact fragment membership protocol and fences"
                .into(),
        ));
    }
    let state = tx
        .query_one("SELECT * FROM lore_outbox_schema_state WHERE id = 1", &[])
        .await
        .map_err(|e| DomainError::from_pg("event initialization schema state", e))?;
    if state.get::<_, i32>("producer_compat_floor") > OUTBOX_BASE_API_VERSION
        || state.get::<_, i32>("relay_compat_floor") > OUTBOX_RELAY_SCHEMA_VERSION
        || state.get::<_, i32>("consumer_compat_floor") > OUTBOX_RELAY_SCHEMA_VERSION
    {
        return Err(DomainError::NotReady(
            "event initialization incompatible contract floors".into(),
        ));
    }
    let receipt = tx
        .query_opt(
            "SELECT * FROM lore_outbox_fresh_initialization WHERE id = 1",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("event initialization receipt", e))?;
    if let Some(receipt) = receipt {
        let matches = receipt.get::<_, i32>("contract_version") == 1
            && receipt.get::<_, String>("cell_id") == input.cell_id
            && receipt.get::<_, String>("stream_identity") == input.stream_identity
            && receipt.get::<_, i64>("stream_epoch") == input.stream_epoch
            && receipt.get::<_, String>("database_identity") == database_identity
            && state.get::<_, Option<std::time::SystemTime>>("cutover_at")
                == Some(receipt.get("initialized_at"))
            && state.get::<_, Option<i32>>("retention_policy_version")
                == Some(RETENTION_POLICY_VERSION);
        let placement: bool = tx.query_one("SELECT count(*) = 1 AND COALESCE(bool_and(cell_id = $1 AND current_stream_identity = $2 AND current_stream_epoch = $3 AND current_placement_revision = 1 AND reset_generation = 0), false) FROM lore_outbox_membership_state", &[&input.cell_id, &input.stream_identity, &input.stream_epoch])
            .await.map_err(|e| DomainError::from_pg("event initialization placement verify", e))?.get(0);
        if !matches || !placement {
            return Err(DomainError::NotReady("fresh event initialization receipt or current placement drifted; reset/cutover requires its own procedure".into()));
        }
        return Ok(FreshEventInitializationOutcome::AlreadyInitialized);
    }
    if input.broker_last_sequence != 0
        || state
            .get::<_, Option<std::time::SystemTime>>("cutover_at")
            .is_some()
    {
        return Err(DomainError::NotReady("fresh event initialization refuses retained broker history or an existing cutover without provenance".into()));
    }
    for table in &tables {
        let name: String = table.get("relname");
        if matches!(
            name.as_str(),
            "lore_domain_schema_state"
                | "lore_domain_lock_schema_state"
                | "lore_fragment_schema_state"
                | "lore_outbox_schema_state"
                | "lore_fragment_membership_protocol"
        ) {
            continue;
        }
        if name == "lore_domain_proof_global_counters" {
            let unused: bool = tx.query_one("SELECT count(*) = 1 AND COALESCE(bool_and(id = 1 AND counter_revision = 0 AND quota_revision = 1 AND represented_namespace_rows = 0 AND retained_marker_count = 0 AND outstanding_proof_claims = 0 AND fragment_count = 0 AND fragment_bytes = 0 AND marker_bytes = 0 AND reconciled_at IS NULL), false) FROM lore_domain_proof_global_counters", &[])
                .await.map_err(|e| DomainError::from_pg("event initialization counter seed", e))?.get(0);
            if !unused {
                return Err(DomainError::NotReady(
                    "event initialization refuses used domain counters".into(),
                ));
            }
            continue;
        }
        let qualified: String = table.get("qualified");
        let populated: bool = tx
            .query_one(
                &format!("SELECT EXISTS (SELECT 1 FROM {qualified} LIMIT 1)"),
                &[],
            )
            .await
            .map_err(|e| DomainError::from_pg("event initialization empty check", e))?
            .get(0);
        if populated {
            return Err(DomainError::NotReady(format!(
                "event initialization refuses populated table {name}"
            )));
        }
    }
    let membership = ensure_membership_state(&*tx, &input.cell_id).await?;
    if !matches!(
        set_current_placement(
            &*tx,
            &input.cell_id,
            &input.stream_identity,
            input.stream_epoch,
            1,
            membership.membership_version
        )
        .await?,
        MembershipCas::Applied { .. }
    ) {
        return Err(DomainError::Contention(
            "event initialization placement changed".into(),
        ));
    }
    // This fresh marker permits receiver bootstrap; it asserts no receiver readiness.
    let stamped = tx.execute("WITH stamped AS (UPDATE lore_outbox_schema_state SET cutover_at = clock_timestamp(), retention_policy_version = $1, updated_at = clock_timestamp() WHERE id = 1 AND cutover_at IS NULL RETURNING cutover_at) INSERT INTO lore_outbox_fresh_initialization (id, contract_version, cell_id, stream_identity, stream_epoch, placement_revision, initial_broker_last_sequence, database_identity, initialized_at) SELECT 1, 1, $2, $3, $4, 1, 0, $5, cutover_at FROM stamped", &[&RETENTION_POLICY_VERSION, &input.cell_id, &input.stream_identity, &input.stream_epoch, &database_identity])
        .await.map_err(|e| DomainError::from_pg("event initialization stamp", e))?;
    if stamped != 1 {
        return Err(DomainError::Contention(
            "event initialization stamp changed".into(),
        ));
    }
    tx.commit().await.map_err(|e| {
        DomainError::from_pg(
            "event initialization commit; exact retry reconciles an unknown acknowledgement",
            e,
        )
    })?;
    Ok(FreshEventInitializationOutcome::Initialized)
}
