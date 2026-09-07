// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Supported cell install and actual published budget for the clean-init construction test.
use tokio_util::task::AbortOnDropHandle;
const BOUNDARY: &str = "cell.clean-init";
const REVISION: &str = "test-budget-v1";
const INTERVAL_MS: u64 = 1_000_000_000;
pub(super) async fn install(url: &str) {
    let parsed: tokio_postgres::Config = url.parse().unwrap();
    let mut migrator = parsed.clone();
    migrator.user("object_dispatch_retention_migrator");
    let (admin, admin_connection) = parsed.connect(tokio_postgres::NoTls).await.unwrap();
    let _admin_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "clean-init-dispatch-admin",
        async move {
            let _ = admin_connection.await;
        }
    ));
    let database = parsed.get_dbname().unwrap();
    assert!(
        database
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    );
    admin
        .batch_execute(&format!(
            "GRANT CREATE ON DATABASE {database} TO object_dispatch_retention_owner"
        ))
        .await
        .unwrap();
    let (client, connection) = migrator.connect(tokio_postgres::NoTls).await.unwrap();
    let _task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "clean-init-dispatch-install",
        async move {
            let _ = connection.await;
        }
    ));
    lore_object_dispatch::cell_schema_install::install_cell_schema(&client)
        .await
        .unwrap();
    admin
        .batch_execute(&first_publication_sql(i64::MAX, 1))
        .await
        .unwrap();
}
fn first_publication_sql(hard_expiry: i64, allocation_fence: u64) -> String {
    let caps = cap_json();
    format!(
        "SET SESSION AUTHORIZATION object_dispatch_retention_maintenance;\
         BEGIN ISOLATION LEVEL SERIALIZABLE;\
         SELECT object_store_retention.object_store_dispatch_publish_budget_configuration_v1(\
           'object-store-dispatch-budget-limiter-v1', '{BOUNDARY}', '{REVISION}',\
           {allocation_fence}::bigint::object_store_retention.uint64,\
           {hard_expiry}, 'object-store-frozen-capacity-budget-core-v1',\
           'object-store-exact-target-cache-disposition-v1',\
           'object-store-budget-frozen-envelope-v1', 1::smallint, 'target',\
           1::bigint::object_store_retention.uint64, 1::smallint, 'target',\
           1::bigint::object_store_retention.uint64, 1::smallint, 'target',\
           1::bigint::object_store_retention.uint64, 'cell-test', 'cell-test', '{BOUNDARY}',\
           '{BOUNDARY}', 1::bigint::object_store_retention.uint64,\
           1::bigint::object_store_retention.uint64, 1::bigint::object_store_retention.uint64,\
           1::bigint::object_store_retention.uint64, 1::bigint::object_store_retention.uint64,\
           1::bigint::object_store_retention.uint64, decode(repeat('11',32),'hex'),\
           '018f3e12-a456-7abc-8def-000000000001'::uuid, decode(repeat('22',32),'hex'),\
           decode(repeat('11',32),'hex'), 1::bigint::object_store_retention.uint64,\
           NULL::uuid, NULL::bytea, 0::bigint::object_store_retention.uint64, NULL::bytea,\
           decode(repeat('33',32),'hex'), decode(repeat('11',32),'hex'),\
           decode(repeat('22',32),'hex'), decode(repeat('44',32),'hex'),\
           1::bigint::object_store_retention.uint64, 1::smallint,\
           NULL::text, NULL::text, NULL::bytea, NULL::bytea, decode(repeat('44',32),'hex'),\
           '[{{\"dimensionId\":\"all\",\"effectiveBound\":10,\"measuredLoad\":1,\"targetDemand\":1,\"failureReserve\":1,\"preCacheHeadroom\":7,\"finalBudget\":7}}]'::jsonb,\
           '{caps}'::jsonb);\
         COMMIT; RESET SESSION AUTHORIZATION;"
    )
}

fn cap_json() -> String {
    let entries = (1..=7)
        .map(|class| {
            let capacity = if class == 1 { 8 } else if class == 7 { 1 } else { 7 };
            format!(
                "{{\"capClass\":{class},\"capacityUnits\":{capacity},\"refillUnits\":{capacity},\"refillIntervalMs\":{INTERVAL_MS}}}"
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{entries}]")
}
