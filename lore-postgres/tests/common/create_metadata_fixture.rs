// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Empty database prerequisite setup reused from domain_fragment_clean_init.rs.

use async_trait::async_trait;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::backfill::BranchFacts;
use lore_postgres::domain::backfill::DomainBackfill;
use lore_postgres::domain::backfill::DomainBackfillSource;
use lore_postgres::domain::backfill::OrphanKey;
use lore_postgres::domain::backfill::RepositoryFacts;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::locks::BackfillIssuerMap;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use tokio_postgres::Client;

async fn client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .unwrap();
    lore_base::lore_spawn!(async move {
        connection.await.unwrap();
    });
    client
}

// The metadata source is synthetic at this crate boundary. Its emptiness is checked against
// the actual database before the supported domain/lock transitions are invoked.
struct EmptySource;

#[async_trait]
impl DomainBackfillSource for EmptySource {
    async fn list_repositories(&self) -> Result<Vec<RepositoryFacts>, DomainError> {
        Ok(vec![])
    }
    async fn list_branches(&self, _: &[u8]) -> Result<Vec<BranchFacts>, DomainError> {
        unreachable!()
    }
    async fn snapshot_token(&self, _: &[u8]) -> Result<Vec<u8>, DomainError> {
        unreachable!()
    }
    async fn orphan_projection_keys(&self) -> Result<Vec<OrphanKey>, DomainError> {
        Ok(vec![])
    }
}

pub(super) async fn fixture(arm: bool) -> (String, PostgresDomainStore, Client) {
    let url = std::env::var("LORE_TEST_PG_URL").expect("isolated empty PostgreSQL required");
    let direct = client(&url).await;
    direct
        .batch_execute(include_str!("../../migrations/0001_init.sql"))
        .await
        .unwrap();
    let store = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
        .await
        .unwrap();
    store.lock_coordinator().bootstrap().await.unwrap();
    store.fragment_coordinator().bootstrap().await.unwrap();
    if arm {
        assert_eq!(direct.query_one("SELECT (SELECT count(*) FROM lore_mutable) + (SELECT count(*) FROM lore_domain_repositories)", &[]).await.unwrap().get::<_, i64>(0), 0);
        let pool = build_pool(&url, 2, &TlsConfig::default()).unwrap();
        let backfill = DomainBackfill::new(&pool, &EmptySource);
        assert_eq!(backfill.run().await.unwrap(), 0);
        let verified = backfill.verify().await.unwrap();
        assert!(verified.passed());
        backfill.complete(&verified).await.unwrap();
        store
            .lock_coordinator()
            .backfill(&BackfillIssuerMap::new())
            .await
            .unwrap();
        store
            .lock_coordinator()
            .enable_fencing(false)
            .await
            .unwrap();
        store.enable_enforcement().await.unwrap();
    }
    (url, store, direct)
}
