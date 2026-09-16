// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Read the actual preflight facts needed by the delete coordinator.

use lore_postgres::domain::coordinator::RepositoryDeleteBranchObservation;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;

#[allow(dead_code)]
pub async fn repository_delete_input(repository_id: &[u8]) -> RepositoryDeleteInput {
    let url = std::env::var("LORE_TEST_PG_URL").expect("owned test Postgres URL required");
    repository_delete_input_at(&url, repository_id).await
}

/// As [`repository_delete_input`], but against a caller-supplied URL.
///
/// A suite whose case owns a schema namespace rather than a whole database must
/// pass that namespace's URL. `LORE_TEST_PG_URL` names the base database, whose
/// `search_path` never reaches the case's schema, so reading the preflight from
/// it fails with `42P01` on `lore_domain_repositories`.
#[allow(dead_code)]
pub async fn repository_delete_input_at(url: &str, repository_id: &[u8]) -> RepositoryDeleteInput {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
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

/// Shared by suites which may use only one delete family.
#[allow(dead_code)]
pub async fn branch_delete_input(
    repository_id: &[u8],
    branch_id: &[u8],
) -> lore_postgres::domain::coordinator::BranchDeleteInput {
    let url = std::env::var("LORE_TEST_PG_URL").expect("owned test Postgres URL required");
    branch_delete_input_at(&url, repository_id, branch_id).await
}

/// As [`branch_delete_input`], but against a caller-supplied URL. Same
/// namespace rule as [`repository_delete_input_at`].
///
/// No call site yet. It exists so the next namespaced case needing a branch
/// delete finds the namespaced reader instead of re-deriving the 42P01.
#[allow(dead_code)]
pub async fn branch_delete_input_at(
    url: &str,
    repository_id: &[u8],
    branch_id: &[u8],
) -> lore_postgres::domain::coordinator::BranchDeleteInput {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect branch delete observation reader");
    lore_base::lore_spawn!(async move {
        connection
            .await
            .expect("branch delete observation connection");
    });
    let branch = client.query_opt("SELECT name,metadata_hash,latest_hash FROM lore_domain_branches WHERE repository_id=$1 AND branch_id=$2", &[&repository_id,&branch_id]).await.unwrap();
    lore_postgres::domain::coordinator::BranchDeleteInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        expected_generation: None,
        expected_name: branch.as_ref().map(|r| r.get(0)).unwrap_or_default(),
        expected_metadata_hash: branch.as_ref().map(|r| r.get(1)).unwrap_or_default(),
        expected_latest_hash: branch.as_ref().map(|r| r.get(2)).unwrap_or_default(),
        delete_protected: false,
        legacy_default: false,
        projection: vec![],
        events: vec![],
    }
}
