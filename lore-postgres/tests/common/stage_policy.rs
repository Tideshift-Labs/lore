// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_postgres::domain::fragments::PostgresFragmentCoordinator;

/// Publish a generous, fixed fixture policy through the maintenance procedure.
/// Fixed expiry makes reconnecting a second coordinator an exact policy replay.
pub async fn initialize(url: &str, coordinator: &PostgresFragmentCoordinator) {
    initialize_with_capacity(url, coordinator, 1_073_741_824, 100_000).await;
}

pub async fn initialize_with_capacity(
    url: &str,
    coordinator: &PostgresFragmentCoordinator,
    bytes: i64,
    files: i64,
) {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = lore_base::lore_spawn!(async move { connection.await.unwrap() });
    client.batch_execute(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance; END IF; END $$;"
    ).await.unwrap();
    coordinator.bootstrap().await.unwrap();
    client
        .batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_maintenance")
        .await
        .unwrap();
    client.execute(
        "SELECT stage_policy_publish_v1('fixture-cell','fixture-policy-v1',decode(repeat('aa',32),'hex'),$1,$2,1073741824,100000,60000,4102444800000)",
        &[&bytes, &files],
    ).await.unwrap();
    client
        .batch_execute("RESET SESSION AUTHORIZATION")
        .await
        .unwrap();
    drop(client);
    connection.await.unwrap();
}
