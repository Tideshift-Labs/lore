// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Read the actual preflight facts needed by the delete coordinator.

use lore_postgres::domain::coordinator::RepositoryDeleteBranchObservation;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;

pub async fn repository_delete_input(repository_id: &[u8]) -> RepositoryDeleteInput {
    let url = std::env::var("LORE_TEST_PG_URL").expect("owned test Postgres URL required");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect delete observation reader");
    lore_base::lore_spawn!(async move {
        connection.await.expect("delete observation connection");
    });
    let repository = client
        .query_opt(
            "SELECT name, metadata_hash FROM lore_domain_repositories WHERE repository_id=$1",
            &[&repository_id],
        )
        .await
        .expect("read repository preflight");
    let branches = client.query(
        "SELECT branch_id, name, metadata_hash FROM lore_domain_branches WHERE repository_id=$1 AND state=0 ORDER BY branch_id",
        &[&repository_id],
    ).await.expect("read live branch preflight").into_iter().map(|row| RepositoryDeleteBranchObservation {
        branch_id: row.get(0), name: row.get(1), metadata_hash: row.get(2),
    }).collect();
    RepositoryDeleteInput {
        repository_id: repository_id.to_vec(),
        expected_generation: None,
        expected_name: repository
            .as_ref()
            .map(|row| row.get(0))
            .unwrap_or_default(),
        expected_metadata_hash: repository
            .as_ref()
            .map(|row| row.get(1))
            .unwrap_or_default(),
        branches,
        projection: Vec::new(),
        events: Vec::new(),
    }
}
