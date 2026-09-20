// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
// Fixture publisher for a disposable local database. It uses the real guarded
// maintenance procedure. Production configure_budget retains its TLS requirement.
use lore_object_dispatch::cell_budget_configure::LocalBudgetConfiguration;

pub async fn publish(
    client: &tokio_postgres::Client,
    config: &LocalBudgetConfiguration,
) -> Result<(), Box<dyn std::error::Error>> {
    config.validate()?;
    assert!(
        config.predecessor.is_none(),
        "fixture supports first publication only"
    );
    assert_eq!(config.allocation_fence, 1);
    fn digest(label: &str, bytes: &[u8]) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new_derive_key(label);
        hasher.update(bytes);
        hasher.finalize()
    }
    let core = digest(
        "Commit0 local development budget core v1",
        &serde_json::to_vec(config)?,
    );
    let disposition = digest(
        "Commit0 local development no-cache disposition v1",
        core.as_bytes(),
    );
    let envelope = digest(
        "Commit0 local development budget envelope v1",
        disposition.as_bytes(),
    );
    let disposition_id = uuid::Uuid::from_slice(&disposition.as_bytes()[..16])?;
    let dimensions = serde_json::json!([{"dimensionId":"local-policy-requests", "effectiveBound":config.shared_units,
        "measuredLoad":0, "targetDemand":0, "failureReserve":0, "preCacheHeadroom":config.shared_units, "finalBudget":config.shared_units}]).to_string();
    let vector = digest(
        "Commit0 local development budget vector v1",
        dimensions.as_bytes(),
    );
    let caps = serde_json::to_string(&(1..=7).map(|class| {
        let units = match class { 1 => config.shared_units, 7 => config.list_units, _ => config.class_units };
        serde_json::json!({"capClass":class,"capacityUnits":units,"refillUnits":units,"refillIntervalMs":config.refill_interval_ms})
    }).collect::<Vec<_>>())?;
    client.batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_maintenance; BEGIN ISOLATION LEVEL SERIALIZABLE").await?;
    let row = client
        .query_one(
            PUBLISH_SQL,
            &[
                &config.provider_boundary_id,
                &config.allocation_revision,
                &"1",
                &config.hard_expires_at_unix_ms,
                &config.cell_id,
                &core.as_bytes().as_slice(),
                &disposition_id,
                &disposition.as_bytes().as_slice(),
                &Option::<uuid::Uuid>::None,
                &Option::<Vec<u8>>::None,
                &"0",
                &Option::<Vec<u8>>::None,
                &envelope.as_bytes().as_slice(),
                &vector.as_bytes().as_slice(),
                &dimensions,
                &caps,
            ],
        )
        .await?;
    let code: String = row.get("result_code");
    assert_eq!(code, "PUBLISHED", "fresh fixture must publish once");
    client
        .batch_execute("COMMIT; RESET SESSION AUTHORIZATION")
        .await?;
    Ok(())
}

const PUBLISH_SQL: &str = "SELECT r.result_code FROM
object_store_retention.object_store_dispatch_publish_budget_configuration_v1(
'object-store-dispatch-budget-limiter-v1', $1, $2, $3::text::object_store_retention.uint64, $4,
'object-store-frozen-capacity-budget-core-v1', 'object-store-exact-target-cache-disposition-v1',
'object-store-budget-frozen-envelope-v1', 1::smallint, $5, $3::text::object_store_retention.uint64,
1::smallint, $5, $3::text::object_store_retention.uint64,
1::smallint, $5, $3::text::object_store_retention.uint64, $5, $5, $1, $1,
$3::text::object_store_retention.uint64, $3::text::object_store_retention.uint64,
$3::text::object_store_retention.uint64, $3::text::object_store_retention.uint64,
$3::text::object_store_retention.uint64, $3::text::object_store_retention.uint64,
$6, $7, $8, $6, $3::text::object_store_retention.uint64,
$9, $10, $11::text::object_store_retention.uint64, $12,
$13, $6, $8, $14, $3::text::object_store_retention.uint64, 1::smallint,
NULL::text, NULL::text, NULL::bytea, NULL::bytea, $14, $15::text::jsonb, $16::text::jsonb) AS r";
