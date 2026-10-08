// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! FORK-LOCAL (Tideshift): the repository list keeps mapping a store
//! `SlowDown` to `RESOURCE_EXHAUSTED`. Upstream 75d3b220 moved the local
//! enumeration (and its `filter_slow_down`) from this handler into
//! `BaselineRepositoryCatalog::list_held`; this pins that the mapping
//! survived the move.

use std::sync::Arc;
use std::time::Duration;

use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_proto::RepositoryListRequest;
use lore_server::authnz::repository_catalog::BaselineRepositoryCatalog;
use lore_server::authnz::repository_catalog::RepositoryCatalog;
use lore_server::grpc::handlers::repository_list::handler;
use lore_server::settings::BaselineAccess;
use lore_storage::KeyValueStream;
use lore_storage::MutableStore;
use lore_storage::Partition;
use lore_storage::StoreError;
use lore_storage::errors::SlowDown;
use tonic::Code;
use tonic::Request;

use crate::store::test_support::test_store_create;

/// Delegates everything except `list`, which answers `SlowDown`.
struct SlowListMutableStore {
    inner: Arc<dyn MutableStore>,
}

#[async_trait::async_trait]
impl MutableStore for SlowListMutableStore {
    async fn load(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        self.inner.clone().load(partition, key, key_type).await
    }

    async fn store(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), StoreError> {
        self.inner
            .clone()
            .store(partition, key, value, key_type)
            .await
    }

    async fn compare_and_swap(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        self.inner
            .clone()
            .compare_and_swap(partition, key, expected, value, key_type)
            .await
    }

    async fn list(
        self: Arc<Self>,
        _partition: Partition,
        _key_type: KeyType,
    ) -> Result<KeyValueStream, StoreError> {
        Err(StoreError::from(SlowDown))
    }

    async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
        self.inner.clone().flush(sync_data).await
    }
}

#[tokio::test]
async fn a_slow_down_on_the_catalog_listing_is_resource_exhausted() {
    let (immutable_store, mutable_store, _execution) =
        test_store_create().await.expect("test stores");
    let slow: Arc<dyn MutableStore> = Arc::new(SlowListMutableStore {
        inner: mutable_store,
    });
    let catalog: Arc<dyn RepositoryCatalog> = Arc::new(BaselineRepositoryCatalog::new(
        BaselineAccess::Reachable,
        immutable_store.clone(),
        slow.clone(),
    ));

    let error = handler(
        Request::new(RepositoryListRequest::default()),
        catalog,
        Duration::from_secs(5),
        immutable_store,
        slow,
    )
    .await
    .expect_err("a SlowDown listing must fail the request");

    assert_eq!(error.code(), Code::ResourceExhausted, "{error:?}");
}
