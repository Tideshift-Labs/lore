// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Server-only, bounded metadata upload capability. Never mounted as a serving store.
use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use lore_storage::Address;
use lore_storage::Context;
use lore_storage::Fragment;
use lore_storage::ImmutableStore;
use lore_storage::Partition;
use lore_storage::StoreGetData;
use lore_storage::StoreMatchResult;
use lore_storage::StoreObliterateStats;
use lore_storage::gc_event::GcEventSinkRef;
use lore_storage::immutable_store::StoreError;

use super::CoordinatedProvider;
use super::FragmentLifecycleRoute;
use super::PostgresImmutableStore;
use crate::domain::fragments::EpochWitness;

/// Retains the original metadata serializers while delaying repository visibility until create.
/// The server constructs this only inside its admitted, authorized repository-create handler.
/// At most two metadata representations in context zero may be uploaded through one capability.
pub struct CreationMetadataStore {
    store: Arc<PostgresImmutableStore>,
    repository: [u8; 16],
    witnesses: tokio::sync::Mutex<BTreeMap<Vec<u8>, EpochWitness>>,
}

impl PostgresImmutableStore {
    pub fn creation_metadata_store(
        self: Arc<Self>,
        repository: [u8; 16],
        expected: &crate::domain::fragments::PostgresFragmentCoordinator,
    ) -> Result<Arc<CreationMetadataStore>, StoreError> {
        if !matches!(&self.fragment_route, FragmentLifecycleRoute::Coordinated { coordinator, .. } if coordinator.database_identity() == expected.database_identity())
            || repository == [0; 16]
        {
            return Err(StoreError::internal(
                "creation metadata requires a coordinated store and repository identity",
            ));
        }
        Ok(Arc::new(CreationMetadataStore {
            store: self,
            repository,
            witnesses: tokio::sync::Mutex::new(BTreeMap::new()),
        }))
    }
}

impl CreationMetadataStore {
    pub async fn witnesses(&self) -> Vec<EpochWitness> {
        self.witnesses.lock().await.values().cloned().collect()
    }

    fn validate(&self, partition: Partition, address: Address) -> Result<(), StoreError> {
        if partition.data() != &self.repository || address.context != Context::default() {
            return Err(StoreError::internal(
                "creation metadata capability repository/context mismatch",
            ));
        }
        Ok(())
    }
}

fn unsupported() -> StoreError {
    StoreError::internal("creation metadata capability only uploads unpublished metadata")
}

#[async_trait::async_trait]
impl ImmutableStore for CreationMetadataStore {
    fn isolates_partitions(&self) -> bool {
        true
    }

    async fn query(
        self: Arc<Self>,
        partition: Partition,
        addresses: &[Address],
        results: &mut [StoreMatchResult],
    ) -> Result<(), StoreError> {
        if addresses.len() != results.len() || addresses.len() > 2 {
            return Err(unsupported());
        }
        for (address, result) in addresses.iter().zip(results) {
            self.validate(partition, *address)?;
            // No association has been published. Force the serializer through the upload path,
            // including deduplication, so every returned pointer has a retained epoch witness.
            *result = StoreMatchResult::default();
        }
        Ok(())
    }

    async fn put(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
        _force: bool,
    ) -> Result<(), StoreError> {
        self.validate(partition, address)?;
        let payload = payload.ok_or_else(unsupported)?;
        let mut witnesses = self.witnesses.lock().await;
        if witnesses.len() >= 2 && !witnesses.contains_key(address.hash.data().as_slice()) {
            return Err(unsupported());
        }
        let FragmentLifecycleRoute::Coordinated {
            coordinator,
            provider,
            budget_pin,
            late_effect_bound,
            ..
        } = &self.store.fragment_route
        else {
            return Err(unsupported());
        };
        let witness = self
            .store
            .upload_coordinated_representation(
                coordinator,
                CoordinatedProvider {
                    entry: provider.as_ref(),
                    budget_pin,
                    late_effect_bound: *late_effect_bound,
                },
                address,
                fragment,
                payload,
            )
            .await?;
        if witness.state != crate::domain::fragments::states::FragmentLifecycleState::Remote {
            return Err(unsupported());
        }
        witnesses.insert(witness.hash.clone(), witness);
        Ok(())
    }

    async fn get(self: Arc<Self>, _: Partition, _: Address) -> Result<StoreGetData, StoreError> {
        Err(unsupported())
    }
    async fn get_metadata(
        self: Arc<Self>,
        _: Partition,
        _: Address,
    ) -> Result<StoreGetData, StoreError> {
        Err(unsupported())
    }
    async fn obliterate(
        self: Arc<Self>,
        _: Partition,
        _: Address,
        _: Arc<StoreObliterateStats>,
    ) -> Result<(), StoreError> {
        Err(unsupported())
    }
    async fn evict(
        self: Arc<Self>,
        _: usize,
        _: bool,
        _: Option<GcEventSinkRef>,
    ) -> Result<usize, StoreError> {
        Err(unsupported())
    }
    async fn compact(
        self: Arc<Self>,
        _: usize,
        _: Option<usize>,
        _: bool,
        _: Option<GcEventSinkRef>,
    ) -> Result<Option<usize>, StoreError> {
        Err(unsupported())
    }
    async fn compact_resume_at(self: Arc<Self>) -> Option<usize> {
        None
    }
    async fn compact_stop(self: Arc<Self>) {}
    fn max_query_batch(&self) -> Option<usize> {
        Some(2)
    }
    async fn flush(self: Arc<Self>, _: bool) -> Result<(), StoreError> {
        Ok(())
    }
    async fn verify(self: Arc<Self>, _: bool) -> Result<(), StoreError> {
        Err(unsupported())
    }
    async fn copy(
        self: Arc<Self>,
        _: Partition,
        _: Address,
        _: Partition,
        _: Context,
        _: bool,
    ) -> Result<(), StoreError> {
        Err(unsupported())
    }
}
