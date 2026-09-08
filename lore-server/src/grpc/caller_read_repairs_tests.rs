// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_revision::lore::RepositoryId;
use lore_storage::KeyValueStream;
use lore_storage::MutableStore;
use lore_storage::Partition;
use lore_storage::StoreError;

use crate::grpc::caller_capabilities::CallerCapabilityPolicy;
use crate::grpc::handlers::repository_query::authz_test_support::new_test_stores;
use crate::grpc::handlers::repository_query::authz_test_support::seed_repository_metadata;

#[tokio::test]
async fn both_repository_handlers_refuse_stale_names_without_deleting_in_required_mode() {
    for v1 in [false, true] {
        for required in [true, false] {
            let (immutable, mutable) = new_test_stores().await;
            let id: RepositoryId = Context::from([43; 16]).into();
            seed_repository_metadata(
                immutable.clone(),
                mutable.clone(),
                id,
                "current",
                "description",
            )
            .await;
            let context = Arc::new(
                lore_revision::repository::RepositoryContext::new_server_context(
                    immutable.clone(),
                    mutable.clone(),
                    id,
                ),
            );
            lore_revision::repository::store_name_to_id(context, "stale", id)
                .await
                .unwrap();
            let writes = Arc::new(AtomicUsize::new(0));
            let store: Arc<dyn MutableStore> = Arc::new(CountWritesMutableStore {
                inner: mutable,
                writes: writes.clone(),
            });
            let policy = if required {
                CallerCapabilityPolicy::RequireOutcomeUnknownV1
            } else {
                CallerCapabilityPolicy::CompatibleSingleReplica
            };
            let error = if v1 {
                use lore_proto::lore::repository::v1::RepositoryGetRequest;
                use lore_proto::lore::repository::v1::repository_get_request::Query;
                let mut request = tonic::Request::new(RepositoryGetRequest {
                    query: Some(Query::Name("stale".into())),
                });
                request.extensions_mut().insert(policy);
                crate::grpc::repository::v1::repository_get::handler(
                    request, None, immutable, store,
                )
                .await
                .unwrap_err()
            } else {
                use lore_proto::RepositoryQueryRequest;
                use lore_proto::repository_query_request::Query;
                let mut request = tonic::Request::new(RepositoryQueryRequest {
                    query: Some(Query::Name("stale".into())),
                });
                request.extensions_mut().insert(policy);
                crate::grpc::handlers::repository_query::handler(request, None, immutable, store)
                    .await
                    .unwrap_err()
            };
            assert_eq!(error.code(), tonic::Code::NotFound);
            assert_eq!(
                writes.load(Ordering::SeqCst),
                usize::from(!required),
                "v1={v1},required={required}"
            );
        }
    }
}

#[tokio::test]
async fn both_repository_handlers_return_missing_mapping_reads_without_repair_in_required_mode() {
    for v1 in [false, true] {
        for by_name in [false, true] {
            for required in [true, false] {
                let (immutable, mutable) = new_test_stores().await;
                let id: RepositoryId = Context::from([42; 16]).into();
                seed_repository_metadata(
                    immutable.clone(),
                    mutable.clone(),
                    id,
                    "readable",
                    "description",
                )
                .await;
                let writes = Arc::new(AtomicUsize::new(0));
                let store: Arc<dyn MutableStore> = Arc::new(CountWritesMutableStore {
                    inner: mutable,
                    writes: writes.clone(),
                });
                let policy = if required {
                    CallerCapabilityPolicy::RequireOutcomeUnknownV1
                } else {
                    CallerCapabilityPolicy::CompatibleSingleReplica
                };
                if v1 {
                    use lore_proto::lore::repository::v1::RepositoryGetRequest;
                    use lore_proto::lore::repository::v1::repository_get_request::Query;
                    let query = if by_name {
                        Query::Name(id.to_string())
                    } else {
                        Query::Id(id.into())
                    };
                    let mut request =
                        tonic::Request::new(RepositoryGetRequest { query: Some(query) });
                    request.extensions_mut().insert(policy);
                    let result = crate::grpc::repository::v1::repository_get::handler(
                        request, None, immutable, store,
                    )
                    .await
                    .unwrap()
                    .into_inner();
                    assert_eq!(result.repository.unwrap().name, "readable");
                } else {
                    use lore_proto::RepositoryQueryRequest;
                    use lore_proto::repository_query_request::Query;
                    let query = if by_name {
                        Query::Name(id.to_string())
                    } else {
                        Query::Id(id.into())
                    };
                    let mut request =
                        tonic::Request::new(RepositoryQueryRequest { query: Some(query) });
                    request.extensions_mut().insert(policy);
                    let result = crate::grpc::handlers::repository_query::handler(
                        request, None, immutable, store,
                    )
                    .await
                    .unwrap()
                    .into_inner();
                    assert_eq!(result.repository.unwrap().name, "readable");
                }
                assert_eq!(
                    writes.load(Ordering::SeqCst),
                    usize::from(!required),
                    "v1={v1},by_name={by_name},required={required}"
                );
            }
        }
    }
}
pub(crate) struct CountWritesMutableStore {
    pub(crate) inner: Arc<dyn MutableStore>,
    pub(crate) writes: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl MutableStore for CountWritesMutableStore {
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
        _partition: Partition,
        _key: Hash,
        _value: Hash,
        _key_type: KeyType,
    ) -> Result<(), StoreError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Err(StoreError::internal(
            "simulated domain-key bypass guard rejection",
        ))
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
        partition: Partition,
        key_type: KeyType,
    ) -> Result<KeyValueStream, StoreError> {
        self.inner.clone().list(partition, key_type).await
    }

    async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
        self.inner.clone().flush(sync_data).await
    }
}
