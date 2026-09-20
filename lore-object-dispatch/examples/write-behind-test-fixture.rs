// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Test-only setup for the lore-postgres adapter tier. Requires a fresh owned DB.
use lore_object_dispatch::cell_budget_configure::LOCAL_BUDGET_REVISION;
use lore_object_dispatch::cell_budget_configure::LocalBudgetConfiguration;
use lore_object_dispatch::drain_policy::DrainPolicy;
use lore_object_dispatch::drain_policy::DrainStagePolicy;

#[path = "../tests/common/local_budget_fixture.rs"]
mod local_budget_fixture;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("LORE_TEST_PG_URL")?;
    assert!(
        url.starts_with("postgresql://postgres@"),
        "owned disposable fixture only"
    );
    let (admin, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    let task = lore_base::lore_spawn!(connection);
    admin.batch_execute("DO $$ BEGIN
      IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_owner') THEN CREATE ROLE object_dispatch_retention_owner NOLOGIN; END IF;
      IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_runtime') THEN CREATE ROLE object_dispatch_retention_runtime LOGIN; END IF;
      IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance LOGIN; END IF;
      IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_migrator') THEN CREATE ROLE object_dispatch_retention_migrator LOGIN; END IF;
      END $$;
      GRANT object_dispatch_retention_owner TO object_dispatch_retention_migrator WITH INHERIT FALSE, SET TRUE;").await?;
    let database: String = admin
        .query_one("SELECT current_database()", &[])
        .await?
        .get(0);
    admin.batch_execute(&format!("GRANT CREATE ON DATABASE \"{}\" TO object_dispatch_retention_owner; SET SESSION AUTHORIZATION object_dispatch_retention_migrator;", database.replace('"', "\"\""))).await?;
    lore_object_dispatch::cell_schema_install::install_cell_schema(&admin).await?;
    admin.batch_execute("RESET SESSION AUTHORIZATION;
      CREATE EXTENSION IF NOT EXISTS plpython3u;
      CREATE OR REPLACE FUNCTION public.blake3(payload bytea) RETURNS bytea LANGUAGE plpython3u IMMUTABLE STRICT AS $$
import blake3
return blake3.blake3(bytes(payload)).digest()
$$;").await?;
    let row = admin.query_one("SELECT s.system_identifier::text,d.oid::bigint,floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM pg_control_system() s,pg_database d WHERE d.datname=current_database()", &[]).await?;
    let system: String = row.get(0);
    let oid = u32::try_from(row.get::<_, i64>(1))?;
    let now: i64 = row.get(2);
    let budget = LocalBudgetConfiguration {
        schema_revision: LOCAL_BUDGET_REVISION.into(),
        provenance: "operator-selected-local-development-limit-v1".into(),
        cell_id: "adapter-cell".into(),
        provider_boundary_id: "adapter-boundary".into(),
        provider_endpoint: "http://minio:9000".into(),
        provider_bucket: "adapter-fragments".into(),
        evidence_reference: "disposable adapter test".into(),
        system_identifier: system.clone(),
        database_oid: oid,
        allocation_revision: "adapter-budget-v1".into(),
        allocation_fence: 1,
        issued_at_unix_ms: now - 1000,
        hard_expires_at_unix_ms: now + 3600000,
        shared_units: 10000,
        class_units: 1000,
        list_units: 5,
        refill_interval_ms: 1000,
        predecessor: None,
    };
    local_budget_fixture::publish(&admin, &budget).await?;
    let policy = DrainPolicy {
        boundary: "adapter-boundary".into(),
        cell: "adapter-cell".into(),
        service: "adapter-service".into(),
        revision: "adapter-policy-v1".into(),
        quota_revision: 1,
        quotas: [[100_000_000, 1000, 1000, 0, 0, 0]; 3],
        maximum_ttl_ms: 60000,
        expires_at_ms: u64::try_from(now + 3600000)?,
        metadata_max_rows: 1000,
        metadata_max_bytes: 100_000_000,
        stage: DrainStagePolicy {
            max_bytes: 30_000_000,
            max_files: 3000,
            max_metadata_bytes: 100_000_000,
            max_metadata_rows: 10000,
            prepare_ttl_ms: 60000,
        },
    };
    let digest = policy.digest()?;
    admin.batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_maintenance; BEGIN ISOLATION LEVEL SERIALIZABLE").await?;
    admin
        .query_one(
            "SELECT object_store_retention.drain_policy_publish_v1($1::text::jsonb,$2,$3)",
            &[
                &serde_json::to_string(&policy)?,
                &policy.canonical_bytes()?,
                &&digest[..],
            ],
        )
        .await?;
    admin
        .batch_execute("COMMIT; RESET SESSION AUTHORIZATION")
        .await?;
    println!(
        "{}",
        serde_json::json!({"system": system, "oid": oid, "digest": lore_object_dispatch::drain_policy::hex(&digest), "expiry": policy.expires_at_ms})
    );
    drop(admin);
    task.await??;
    Ok(())
}
