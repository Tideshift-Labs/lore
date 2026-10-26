// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_postgres::domain::fragments::PostgresFragmentCoordinator;

/// Publish a generous, fixed fixture policy through the maintenance procedure.
/// Fixed expiry makes reconnecting a second coordinator an exact policy replay.
#[allow(dead_code)] // tests that fix their own limits include this module without it
pub async fn initialize(url: &str, coordinator: &PostgresFragmentCoordinator) {
    initialize_with_capacity(url, coordinator, 1_073_741_824, 100_000).await;
}

#[allow(dead_code)]
pub async fn initialize_with_capacity(
    url: &str,
    coordinator: &PostgresFragmentCoordinator,
    bytes: i64,
    files: i64,
) {
    initialize_with_limits(url, coordinator, bytes, files, 1_073_741_824, 100_000).await;
}

/// As `initialize_with_capacity`, also fixing the metadata ledger limits. A tiny
/// `metadata_rows` makes a lifetime row leak reachable in a handful of rounds.
pub async fn initialize_with_limits(
    url: &str,
    coordinator: &PostgresFragmentCoordinator,
    bytes: i64,
    files: i64,
    metadata_bytes: i64,
    metadata_rows: i64,
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
        "SELECT stage_policy_publish_v1('fixture-cell','fixture-policy-v1',decode(repeat('aa',32),'hex'),$1,$2,$3,$4,60000,4102444800000)",
        &[&bytes, &files, &metadata_bytes, &metadata_rows],
    ).await.unwrap();
    client
        .batch_execute("RESET SESSION AUTHORIZATION")
        .await
        .unwrap();
    drop(client);
    connection.await.unwrap();
}
